import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { config } from "../../src/config.js";
import { resetDigitAdminToken } from "../../src/digit-admin-token.js";
import { clearTenantCaches } from "../../src/identity-tenants.js";
import { runOnboardingWorkerOnce } from "../../src/onboarding-worker.js";
import { createFakeDigitUser } from "../../mocks/fake-digit-user.js";
import { getIssuer } from "../helpers.js";
import { startIdentityTestApp, stopIdentityTestApp, getIdentityAppPort } from "./identity-test-app.js";

const REALM = "worker-realm";
const digit = createFakeDigitUser({ tenants: ["pg"] });

/** Minimal stand-in for PGR's worker lease API. */
function fakePgr() {
  const app = express();
  app.use(express.json());
  const queue: any[] = [];
  const settled: Record<string, any> = {};
  app.use((req, res, next) => req.get("authorization") === "Bearer worker-secret"
    ? next() : res.status(401).json({ error: "unauthorized" }));
  app.post("/pgr-services/v2/onboarding/internal/operations/_claim", (_req, res) => {
    const next = queue.shift();
    return next ? res.json(next) : res.status(204).end();
  });
  for (const outcome of ["_complete", "_fail"]) {
    app.post(`/pgr-services/v2/onboarding/internal/operations/${outcome}`, (req, res) => {
      settled[req.body.id] = { outcome, ...req.body };
      return res.json({ status: outcome });
    });
  }
  let server: Server;
  return {
    queue, settled,
    async start() {
      server = app.listen(0);
      await new Promise((resolve) => server.once("listening", resolve));
      return `http://localhost:${(server.address() as AddressInfo).port}/pgr-services`;
    },
    async stop() { await new Promise((resolve) => server.close(resolve)); },
  };
}
const pgr = fakePgr();

async function kcUser(username: string): Promise<string> {
  const response = await fetch(`${config.keycloakAdminUrl}/admin/realms/${REALM}/users`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email: `${username}@example.org`, firstName: "New", lastName: "Founder", emailVerified: true }),
  });
  return response.headers.get("location")!.split("/").pop()!;
}

function operation(id: string, subject: string, slug: string, mobileNumber?: string) {
  return {
    Operation: { id, status: "RUNNING", completedSteps: [] },
    leaseToken: `lease-${id}`,
    Signup: {
      id: `signup-${id}`, ownerIssuer: getIssuer(), ownerSubject: subject,
      accountName: `${slug} council`, accountCode: slug.toUpperCase(), organizationAlias: slug,
      requestedTenantId: `pg.${slug}`, tenantMetadata: mobileNumber ? { founder: { mobileNumber } } : {},
    },
  };
}

beforeAll(async () => {
  const digitBase = await digit.start();
  const pgrBase = await pgr.start();
  for (const [userName, role] of [["BFF-ADMIN", "ACCOUNT_ADMIN"], ["BFF-PROVISIONER", "MDMS_ADMIN"]]) {
    digit.addAccount({
      userName, name: userName, mobileNumber: "9800000000", emailId: null, tenantId: "pg", type: "EMPLOYEE",
      active: true, identificationMark: null, roles: [{ code: role, tenantId: "pg" }], password: "Adm1n@Secret",
    });
  }
  Object.assign(config as any, {
    keycloakIssuer: getIssuer(),
    keycloakOrganizationRealm: REALM,
    keycloakAllowedOrganizationRoleClients: ["digit-ui"],
    cachePrefix: `worker-e2e-${process.pid}`,
    digitUserServiceUrl: `${digitBase}/user`,
    digitMdmsSearchUrl: `${digitBase}/mdms-v2/v1/_search`,
    digitMdmsCreateUrl: `${digitBase}/mdms-v2/v2/_create`,
    digitAdminUsername: "BFF-ADMIN", digitAdminPassword: "Adm1n@Secret", digitAdminTenantId: "pg",
    digitProvisionerUsername: "BFF-PROVISIONER", digitProvisionerPassword: "Adm1n@Secret", digitProvisionerTenantId: "pg",
    digitManagedUserTenantId: "pg",
    digitManagedBaseRoles: ["EMPLOYEE"],
    digitManagedRoleAllowlist: ["EMPLOYEE", "GRO", "PGR_VIEWER"],
    digitRoleClientId: "digit-ui",
    pgrOnboardingWorkerUrl: pgrBase,
    pgrOnboardingWorkerToken: "worker-secret",
    onboardingFounderGroup: "founders",
    onboardingFounderRoles: ["GRO"],
  });
  resetDigitAdminToken();
  clearTenantCaches();
  await startIdentityTestApp();
});

afterAll(async () => {
  await stopIdentityTestApp();
  await pgr.stop();
  await digit.stop();
});

describe("onboarding worker", () => {
  it("provisions tenant foundation, Organization, founder membership, roles and DIGIT account", async () => {
    const founder = await kcUser("founder-one");
    pgr.queue.push(operation("op-1", founder, "riverside", "9812345678"));

    expect(await runOnboardingWorkerOnce()).toBe(1);

    expect(pgr.settled["op-1"]).toMatchObject({
      outcome: "_complete", leaseToken: "lease-op-1",
      completedSteps: ["TENANT_FOUNDATION", "ORGANIZATION", "FOUNDER_MEMBERSHIP", "FOUNDER_ROLES", "DIGIT_ACCOUNT"],
    });
    const account = [...digit.accounts.values()].find((candidate) => candidate.name === "New Founder")!;
    expect(account.identificationMark).toMatch(/^keycloak-bff:v1:/);
    expect(account.roles.map((role) => `${role.tenantId}:${role.code}`).sort())
      .toEqual(["pg.riverside:EMPLOYEE", "pg.riverside:GRO"]);

    // Replaying the same operation (e.g. after a lost lease) is idempotent.
    pgr.queue.push(operation("op-1b", founder, "riverside", "9812345678"));
    await runOnboardingWorkerOnce();
    expect(pgr.settled["op-1b"].outcome).toBe("_complete");
    expect([...digit.accounts.values()].filter((candidate) => candidate.name === "New Founder")).toHaveLength(1);
  });

  it("reports a terminal failure when the founder account cannot be created", async () => {
    const founder = await kcUser("founder-two");
    pgr.queue.push(operation("op-2", founder, "hillview"));

    await runOnboardingWorkerOnce();

    expect(pgr.settled["op-2"]).toMatchObject({
      outcome: "_fail", retryable: false, errorCode: "FOUNDER_ACCOUNT_REJECTED", currentStep: "DIGIT_ACCOUNT",
      completedSteps: ["TENANT_FOUNDATION", "ORGANIZATION", "FOUNDER_MEMBERSHIP", "FOUNDER_ROLES"],
    });
  });

  it("reports a retryable failure when the tenant foundation cannot be provisioned", async () => {
    const founder = await kcUser("founder-three");
    (config as any).digitProvisionerUsername = "";
    pgr.queue.push(operation("op-3", founder, "lakeside", "9812345679"));

    await runOnboardingWorkerOnce();

    (config as any).digitProvisionerUsername = "BFF-PROVISIONER";
    expect(pgr.settled["op-3"]).toMatchObject({
      outcome: "_fail", retryable: true, errorCode: "TENANT_FOUNDATION_UNAVAILABLE", completedSteps: [],
    });
  });

  it("keeps serving sign-in when PGR is unreachable", async () => {
    (config as any).pgrOnboardingWorkerUrl = "http://127.0.0.1:1/pgr-services";
    expect(await runOnboardingWorkerOnce()).toBe(0);
    const methods = await fetch(`http://localhost:${getIdentityAppPort()}/identity/v1/auth-methods`);
    expect(methods.status).toBe(200);
  });
});
