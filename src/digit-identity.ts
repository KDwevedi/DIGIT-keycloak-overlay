import { config } from "./config.js";
import type { DigitLoginResponse, KCClaims } from "./types.js";
import type { TenantOption } from "./tenant-options.js";

export class DigitIdentityUnavailableError extends Error {}

interface OrganizationMembership {
  organizationId: string;
  organizationAlias: string;
}

export interface DigitReconciliationMember {
  issuer: string;
  subject: string;
  active: boolean;
}

export interface DigitReconciliationOrganization {
  organizationId: string;
  organizationAlias: string;
  tenantId: string;
  name: string;
  active: boolean;
  members: DigitReconciliationMember[];
}

function endpoint(path: string): string {
  const base = config.digitIdentityServiceUrl.replace(/\/$/, "");
  if (!base) {
    throw new DigitIdentityUnavailableError(
      "DIGIT identity service is not configured",
    );
  }
  return `${base}${path}`;
}

async function post(path: string, body: unknown): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.digitIdentityServiceToken) {
    headers.Authorization = `Bearer ${config.digitIdentityServiceToken}`;
  }

  let response: Response;
  try {
    response = await fetch(endpoint(path), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(config.digitIdentityTimeoutMs),
    });
  } catch (error) {
    throw new DigitIdentityUnavailableError(
      `DIGIT identity service request failed: ${(error as Error).message}`,
    );
  }
  if (!response.ok) {
    throw new DigitIdentityUnavailableError(
      `DIGIT identity service returned ${response.status}`,
    );
  }
  try {
    return await response.json() as Record<string, unknown>;
  } catch {
    throw new DigitIdentityUnavailableError(
      "DIGIT identity service returned invalid JSON",
    );
  }
}

async function postAssertion(
  path: string,
  assertion: string,
  body: unknown,
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(endpoint(path), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${assertion}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(config.digitIdentityTimeoutMs),
    });
  } catch (error) {
    throw new DigitIdentityUnavailableError(
      `DIGIT identity service request failed: ${(error as Error).message}`,
    );
  }
  if (!response.ok) {
    throw new DigitIdentityUnavailableError(
      `DIGIT identity service returned ${response.status}`,
    );
  }
  try {
    return await response.json() as Record<string, unknown>;
  } catch {
    throw new DigitIdentityUnavailableError(
      "DIGIT identity service returned invalid JSON",
    );
  }
}

function identity(claims: KCClaims) {
  return { issuer: config.keycloakIssuer, subject: claims.sub };
}

function organizationMemberships(claims: KCClaims): OrganizationMembership[] {
  return Object.entries(claims.organization || {}).flatMap(
    ([organizationAlias, organization]) => organization?.id ? [{
      organizationId: organization.id,
      organizationAlias,
    }] : [],
  );
}

export async function resolveActiveTenantOptions(
  claims: KCClaims,
): Promise<TenantOption[]> {
  const organizations = organizationMemberships(claims);
  if (organizations.length === 0) return [];

  const byId = new Map(
    organizations.map((organization) => [organization.organizationId, organization]),
  );
  const result = await post("/contexts/_resolve", {
    identity: identity(claims),
    clientId: config.digitIdentityClientId,
    organizations: organizations.map(({ organizationId }) => ({ organizationId })),
  });
  if (!Array.isArray(result.contexts)) {
    throw new DigitIdentityUnavailableError(
      "DIGIT identity service returned invalid contexts",
    );
  }

  const seenOrganizations = new Set<string>();
  const seenTenants = new Set<string>();
  const contexts: TenantOption[] = [];
  for (const entry of result.contexts) {
    if (!entry || typeof entry !== "object") continue;
    const context = entry as Record<string, unknown>;
    if (context.active !== true ||
        typeof context.organizationId !== "string" ||
        typeof context.tenantId !== "string" || !context.tenantId.trim() ||
        typeof context.name !== "string" || !context.name.trim() ||
        !Array.isArray(context.roles) ||
        !context.roles.every((role) => typeof role === "string")) {
      continue;
    }
    const organization = byId.get(context.organizationId);
    if (!organization) continue;
    if (seenOrganizations.has(context.organizationId) ||
        seenTenants.has(context.tenantId)) {
      throw new DigitIdentityUnavailableError(
        "DIGIT identity service returned an ambiguous context mapping",
      );
    }
    seenOrganizations.add(context.organizationId);
    seenTenants.add(context.tenantId);
    contexts.push({
      organizationId: context.organizationId,
      organizationAlias: organization.organizationAlias,
      tenantId: context.tenantId,
      name: context.name,
      roles: [...new Set(context.roles as string[])].sort(),
    });
  }
  return contexts.sort((left, right) => left.name.localeCompare(right.name));
}

export async function ensureDigitOrganization(input: {
  organizationId: string;
  alias: string;
  tenantId: string;
  name: string;
}): Promise<void> {
  await post("/organizations/_ensure", input);
}

export async function ensureDigitSubject(input: {
  issuer: string;
  subject: string;
  digitUserUuid: string;
}): Promise<void> {
  await post("/subjects/_ensure", input);
}

export async function reconcileDigitMembership(input: {
  issuer: string;
  subject: string;
  organizationId: string;
  roles: string[];
  active?: boolean;
}): Promise<void> {
  await post("/memberships/_reconcile", input);
}

export async function digitReconciliationSnapshot(): Promise<
  DigitReconciliationOrganization[]
> {
  const result = await post("/reconciliation/_snapshot", {});
  if (!Array.isArray(result.organizations)) {
    throw new DigitIdentityUnavailableError(
      "DIGIT identity service returned an invalid reconciliation snapshot",
    );
  }
  return result.organizations as DigitReconciliationOrganization[];
}

export async function issueDigitContext(
  assertion: string,
  context: TenantOption,
): Promise<DigitLoginResponse> {
  const result = await postAssertion("/sessions/_exchange", assertion, {
    clientId: config.digitIdentityClientId,
    context: {
      organizationId: context.organizationId,
      tenantId: context.tenantId,
    },
  });
  const user = result.UserRequest as Record<string, unknown> | undefined;
  const roles = user?.roles;
  if (typeof result.access_token !== "string" || !result.access_token ||
      result.token_type !== "bearer" ||
      typeof result.expires_in !== "number" || result.expires_in <= 0 ||
      result.expires_in > config.digitAccessTokenMaxTtlSeconds ||
      !user || typeof user.uuid !== "string" || !user.uuid ||
      typeof user.userName !== "string" ||
      typeof user.name !== "string" ||
      typeof user.emailId !== "string" ||
      typeof user.mobileNumber !== "string" ||
      user.tenantId !== context.tenantId ||
      (user.type !== "EMPLOYEE" && user.type !== "CITIZEN") ||
      !Array.isArray(roles) || !roles.every((role) => {
        if (!role || typeof role !== "object") return false;
        const candidate = role as Record<string, unknown>;
        return typeof candidate.code === "string" &&
          typeof candidate.name === "string" &&
          candidate.tenantId === context.tenantId;
      })) {
    throw new DigitIdentityUnavailableError(
      "DIGIT identity service returned an invalid session",
    );
  }
  // Keep the browser response deliberately narrow. A backing identity service
  // may use its own refresh credential internally; it is not a browser API.
  return {
    access_token: result.access_token,
    token_type: "bearer",
    expires_in: result.expires_in,
    UserRequest: {
      uuid: user.uuid,
      userName: user.userName,
      name: user.name,
      emailId: user.emailId,
      mobileNumber: user.mobileNumber,
      tenantId: context.tenantId,
      type: user.type,
      roles: (roles as Array<Record<string, unknown>>).map((role) => ({
        code: role.code as string,
        name: role.name as string,
        tenantId: context.tenantId,
      })),
    },
  };
}
