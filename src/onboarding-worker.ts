import { hostname } from "node:os";
import { config } from "./config.js";
import { digitProvisionerConfigured, withDigitProvisioner } from "./digit-admin-token.js";
import { DigitUnauthorizedError, DigitUnavailableError } from "./digit-user-service.js";
import {
  ensureOrganization,
  ensureOrganizationMembership,
  ensureOrganizationRoleAssignment,
  IdentityAdminError,
} from "./identity-admin.js";
import { syncSubject } from "./identity-provisioning.js";
import { clearTenantCaches, isActiveDigitTenant } from "./identity-tenants.js";
import { ManagedAccountError } from "./managed-digit-users.js";

/**
 * Optional in-process worker for submitted PGR onboarding signups.
 *
 * It leases PENDING operations through PGR's workload API (never its
 * database) and provisions, idempotently:
 *   TENANT_FOUNDATION  DIGIT `tenant.tenants` record (MDMS) when a provisioner
 *                      credential is configured; otherwise the tenant must exist
 *   ORGANIZATION       Keycloak Organization mapped to the tenant
 *   FOUNDER_MEMBERSHIP founder added to the Organization
 *   FOUNDER_ROLES      founder group with ONBOARDING_FOUNDER_ROLES
 *   DIGIT_ACCOUNT      founder's BFF-managed DIGIT account and projected roles
 * then reports success, retryable failure or terminal failure back to PGR.
 * Other tenant masters (boundaries, departments, service definitions,
 * localization) are not provisioned here.
 */

interface ClaimedOperation {
  Operation: { id: string; completedSteps?: string[] };
  leaseToken: string;
  Signup: {
    id: string;
    ownerIssuer: string;
    ownerSubject: string;
    accountName: string;
    accountCode: string;
    organizationAlias: string;
    requestedTenantId: string;
    tenantMetadata?: Record<string, unknown>;
  };
}

export class ProvisioningFailure extends Error {
  constructor(readonly code: string, message: string, readonly retryable: boolean) {
    super(message);
  }
}

const workerId = `identity-bff:${hostname()}:${process.pid}`;

async function pgr(path: string, body: unknown): Promise<Response> {
  const base = config.pgrOnboardingWorkerUrl.replace(/\/$/, "");
  return fetch(`${base}/v2/onboarding/internal/operations/${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.pgrOnboardingWorkerToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(config.digitTimeoutMs),
  });
}

async function claim(): Promise<ClaimedOperation | null> {
  const response = await pgr("_claim", { workerId, leaseSeconds: config.onboardingWorkerLeaseSeconds });
  if (response.status === 204) return null;
  if (!response.ok) throw new Error(`PGR claim returned ${response.status}`);
  return await response.json() as ClaimedOperation;
}

async function settle(path: "_complete" | "_fail", body: Record<string, unknown>): Promise<void> {
  const response = await pgr(path, body);
  if (!response.ok) throw new Error(`PGR ${path} returned ${response.status}`);
}

async function ensureTenantFoundation(signup: ClaimedOperation["Signup"]): Promise<void> {
  const tenantId = signup.requestedTenantId;
  if (await isActiveDigitTenant(tenantId)) return;
  if (!digitProvisionerConfigured()) {
    throw new ProvisioningFailure("TENANT_FOUNDATION_UNAVAILABLE",
      "The DIGIT tenant does not exist and no tenant provisioner is configured", true);
  }
  const root = tenantId.split(".")[0];
  const status = await withDigitProvisioner(async (token) => {
    const response = await fetch(`${config.digitMdmsCreateUrl.replace(/\/$/, "")}/tenant.tenants`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        RequestInfo: { apiId: "digit-identity-bff", authToken: token },
        Mdms: {
          tenantId: root,
          schemaCode: "tenant.tenants",
          isActive: true,
          data: {
            code: tenantId,
            name: signup.accountName,
            type: "CITY",
            city: { code: signup.accountCode, name: signup.accountName, districtTenantCode: tenantId },
            description: "Provisioned by DIGIT identity BFF onboarding",
          },
        },
      }),
      signal: AbortSignal.timeout(config.digitTimeoutMs),
    });
    await response.body?.cancel();
    if (response.status === 401 || response.status === 403) {
      throw new DigitUnauthorizedError("DIGIT tenant create was not authorized");
    }
    if (!response.ok) {
      throw new DigitUnavailableError(`DIGIT tenant create returned ${response.status}`);
    }
    return response.status;
  });

  // MDMS v2 acknowledges writes before its Kafka-backed read model is updated.
  // Wait briefly for visibility so a successful create is not reported to PGR
  // as a retryable failure that the founder then has to submit again.
  let visible = false;
  for (let attempt = 0; attempt < 20 && !visible; attempt += 1) {
    clearTenantCaches();
    visible = await isActiveDigitTenant(tenantId);
    if (!visible) await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!visible) {
    throw new ProvisioningFailure("TENANT_FOUNDATION_UNAVAILABLE",
      `DIGIT tenant create returned ${status} and the tenant is not visible yet`, true);
  }
}

function classify(error: unknown, step: string): ProvisioningFailure {
  if (error instanceof ProvisioningFailure) return error;
  if (error instanceof ManagedAccountError) {
    return new ProvisioningFailure("FOUNDER_ACCOUNT_REJECTED", error.message, false);
  }
  if (error instanceof IdentityAdminError && (error.status === 400 || error.status === 409)) {
    return new ProvisioningFailure(`${step}_CONFLICT`, error.message, false);
  }
  if (error instanceof DigitUnavailableError) {
    return new ProvisioningFailure("DIGIT_UNAVAILABLE", error.message, error.status !== 409);
  }
  if (error instanceof IdentityAdminError) {
    return new ProvisioningFailure("KEYCLOAK_UNAVAILABLE", error.message, true);
  }
  return new ProvisioningFailure("PROVISIONING_ERROR", "Unexpected provisioning error", true);
}

export async function processOnboardingOperation(claimed: ClaimedOperation): Promise<"SUCCEEDED" | "FAILED"> {
  const { Signup: signup } = claimed;
  const completed = new Set(claimed.Operation.completedSteps || []);
  let step = "IDENTITY";
  const run = async (name: string, action: () => Promise<void>) => {
    step = name;
    await action();
    completed.add(name);
  };
  try {
    if (signup.ownerIssuer !== config.keycloakIssuer) {
      throw new ProvisioningFailure("IDENTITY_ISSUER_MISMATCH", "Signup owner is from another issuer", false);
    }
    let organizationId = "";
    await run("TENANT_FOUNDATION", () => ensureTenantFoundation(signup));
    await run("ORGANIZATION", async () => {
      organizationId = (await ensureOrganization({
        tenantId: signup.requestedTenantId, alias: signup.organizationAlias, name: signup.accountName,
      })).id;
      clearTenantCaches();
    });
    await run("FOUNDER_MEMBERSHIP", () => ensureOrganizationMembership({
      organizationId, userId: signup.ownerSubject,
    }));
    await run("FOUNDER_ROLES", async () => {
      await ensureOrganizationRoleAssignment({
        organizationId, userId: signup.ownerSubject, groupName: config.onboardingFounderGroup,
        clientId: config.digitRoleClientId, roles: config.onboardingFounderRoles,
      });
    });
    await run("DIGIT_ACCOUNT", async () => {
      const founder = signup.tenantMetadata?.founder as { mobileNumber?: unknown } | undefined;
      await syncSubject(signup.ownerSubject,
        typeof founder?.mobileNumber === "string" ? founder.mobileNumber : "");
    });
    await settle("_complete", {
      id: claimed.Operation.id, leaseToken: claimed.leaseToken, completedSteps: [...completed],
    });
    console.log("Onboarding operation succeeded:", claimed.Operation.id);
    return "SUCCEEDED";
  } catch (error) {
    const failure = classify(error, step);
    console.warn(`Onboarding operation ${claimed.Operation.id} failed at ${step}:`, failure.code);
    await settle("_fail", {
      id: claimed.Operation.id, leaseToken: claimed.leaseToken, retryable: failure.retryable,
      errorCode: failure.code, errorMessage: failure.message, currentStep: step,
      completedSteps: [...completed],
    });
    return "FAILED";
  }
}

/** Processes available operations once. Never throws; returns how many were handled. */
export async function runOnboardingWorkerOnce(maxOperations = 10): Promise<number> {
  let handled = 0;
  try {
    while (handled < maxOperations) {
      const claimed = await claim();
      if (!claimed) break;
      handled += 1;
      await processOnboardingOperation(claimed);
    }
  } catch (error) {
    console.warn("Onboarding worker cycle stopped:", (error as Error).message);
  }
  return handled;
}

/** Starts the worker when ONBOARDING_WORKER_ENABLED=true. Returns a stop function. */
export function startOnboardingWorker(): () => void {
  if (!config.onboardingWorkerEnabled) return () => undefined;
  if (!config.pgrOnboardingWorkerUrl || !config.pgrOnboardingWorkerToken) {
    console.warn("Onboarding worker enabled but PGR_ONBOARDING_WORKER_URL/TOKEN are not set; not starting");
    return () => undefined;
  }
  let running = false;
  const tick = () => {
    if (running) return;
    running = true;
    void runOnboardingWorkerOnce().finally(() => {
      running = false;
    });
  };
  const timer = setInterval(tick, config.onboardingWorkerIntervalSeconds * 1000);
  timer.unref();
  tick();
  console.log("Onboarding worker started:", workerId);
  return () => clearInterval(timer);
}
