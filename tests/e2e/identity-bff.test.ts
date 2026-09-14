import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { config } from "../../src/config.js";
import { getIssuer } from "../helpers.js";
import { createFakeDigitUser } from "../../mocks/fake-digit-user.js";
import {
  getIdentityAppPort as getAppPort,
  startIdentityTestApp as startTestApp,
  stopIdentityTestApp as stopTestApp,
} from "./identity-test-app.js";

const digit = createFakeDigitUser({
  tenants: ["ke", "ke.bomet", "ke.kisumu", "ke.nakuru", "ke.nyeri"],
});

async function kcAdmin(path: string, body: unknown): Promise<Response> {
  return fetch(`${config.keycloakAdminUrl}/admin/realms/${config.keycloakOrganizationRealm}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

beforeAll(async () => {
  const digitBase = await digit.start();
  digit.addAccount({
    userName: "BFF-ADMIN", name: "BFF admin", mobileNumber: "0700000000", emailId: null,
    tenantId: "ke", type: "EMPLOYEE", active: true, identificationMark: null,
    roles: [{ code: "ACCOUNT_ADMIN", tenantId: "ke" }], password: "Adm1n@Secret",
  });
  (config as any).keycloakIssuer = getIssuer();
  (config as any).keycloakBffClientId = "digit-identity-bff";
  (config as any).keycloakBffClientSecret = "test-bff-secret";
  (config as any).keycloakBffAudience = "digit-identity-bff";
  (config as any).identityRedirectUri =
    "http://localhost:18200/identity/v1/callback";
  (config as any).identityPostLoginRedirect = "/after-login";
  (config as any).identityAllowedOrigin = "http://localhost:3000";
  (config as any).identityCookieSecure = false;
  (config as any).identityAuthMethods = [
    { id: "password", label: "Password", type: "password" },
    { id: "google", label: "Google", type: "oauth", idpHint: "google" },
  ];
  Object.assign(config as any, {
    cachePrefix: `identity-e2e-${process.pid}`,
    digitUserServiceUrl: `${digitBase}/user`,
    digitMdmsSearchUrl: `${digitBase}/mdms-v2/v1/_search`,
    digitAdminUsername: "BFF-ADMIN",
    digitAdminPassword: "Adm1n@Secret",
    digitAdminTenantId: "ke",
    digitManagedUserTenantId: "ke",
    digitManagedBaseRoles: ["EMPLOYEE"],
    digitManagedRoleAllowlist: ["EMPLOYEE", "GRO", "PGR_VIEWER"],
    digitRoleClientId: "digit-ui",
  });
  (config as any).identityControlPlaneToken = "test-control-plane";
  (config as any).identitySessionIntrospectionToken = "test-session-introspection";
  (config as any).identityReconciliationLeaseSeconds = 30;
  (config as any).keycloakOrganizationRealm = "digit-sandbox";
  (config as any).keycloakAllowedOrganizationRoleClients = ["digit-ui"];
  await startTestApp();
  for (const [id, alias, tenantId, name] of [
    ["org-bomet-id", "bomet", "ke.bomet", "Bomet County"],
    ["org-kisumu-id", "kisumu", "ke.kisumu", "Kisumu County"],
  ]) {
    await kcAdmin("/organizations", {
      id, alias, name, enabled: true, attributes: { "digit.rootTenantId": [tenantId] },
    });
    await fetch(
      `${config.keycloakAdminUrl}/admin/realms/${config.keycloakOrganizationRealm}/organizations/${id}/members`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify("identity-user-1") },
    );
  }
});

afterAll(async () => {
  await stopTestApp();
  await digit.stop();
});

describe("identity BFF", () => {
  it("provisions Organizations and BFF-managed DIGIT accounts through the control plane", async () => {
    const base = `http://localhost:${getAppPort()}/internal/identity/v1`;
    const unauthorized = await fetch(`${base}/organizations/_ensure`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenantId: "ke.nakuru", alias: "nakuru", name: "Nakuru" }),
    });
    expect(unauthorized.status).toBe(401);

    const headers = {
      Authorization: "Bearer test-control-plane",
      "Content-Type": "application/json",
    };
    const post = (path: string, body: unknown) => fetch(`${base}${path}`, {
      method: "POST", headers, body: JSON.stringify(body),
    });

    expect((await post("/organizations/_ensure", {
      tenantId: "ke.missing", alias: "missing", name: "Missing",
    })).status).toBe(409);

    const ensureOrganization = async (tenantId: string, alias: string) => {
      const response = await post("/organizations/_ensure", { tenantId, alias, name: alias });
      expect(response.status).toBe(200);
      return (await response.json()).organization.id as string;
    };
    const nakuru = await ensureOrganization("ke.nakuru", "nakuru");
    expect(await ensureOrganization("ke.nakuru", "nakuru")).toBe(nakuru);

    const created = await kcAdmin("/users", {
      username: "founder@example.org", email: "founder@example.org",
      firstName: "New", lastName: "Founder", emailVerified: true,
    });
    const founderId = created.headers.get("location")!.split("/").pop()!;

    expect((await post("/memberships/_ensure", {
      organizationId: nakuru, userId: founderId, digitUserUuid: "legacy-employee",
    })).status).toBe(400);
    expect((await post("/memberships/_ensure", { organizationId: nakuru, userId: founderId })).status)
      .toBe(409);

    const first = await post("/memberships/_ensure", {
      organizationId: nakuru, userId: founderId, mobileNumber: "0712345678",
    });
    expect(first.status).toBe(200);
    const firstBody = await first.json();
    expect(firstBody).toMatchObject({ created: true });
    const repeat = await post("/memberships/_ensure", { organizationId: nakuru, userId: founderId });
    expect(await repeat.json()).toEqual({ digitUserUuid: firstBody.digitUserUuid, created: false });

    const roles = await post("/role-assignments/_ensure", {
      organizationId: nakuru, userId: founderId, groupName: "officers", clientId: "digit-ui", roles: ["GRO"],
    });
    expect(roles.status).toBe(200);
    expect(await roles.json()).toMatchObject({
      assignment: { roles: ["GRO"] }, digitUserUuid: firstBody.digitUserUuid,
    });

    const nyeri = await ensureOrganization("ke.nyeri", "nyeri");
    const second = await post("/memberships/_ensure", { organizationId: nyeri, userId: founderId });
    expect(await second.json()).toEqual({ digitUserUuid: firstBody.digitUserUuid, created: false });

    const account = digit.accounts.get(firstBody.digitUserUuid)!;
    expect(account.userName).toMatch(/^kcbff-/);
    expect(account.identificationMark).toMatch(/^keycloak-bff:v1:/);
    expect(account.roles.map((role) => `${role.tenantId}:${role.code}`).sort()).toEqual([
      "ke.nakuru:EMPLOYEE", "ke.nakuru:GRO", "ke.nyeri:EMPLOYEE",
    ]);
    expect(digit.accounts.size).toBe(2);

    const reconciliation = await post("/reconciliation/_run", {});
    expect(reconciliation.status).toBe(200);
    expect(await reconciliation.json()).toMatchObject({
      acquired: true, organizations: 4, unchanged: 1, unprovisioned: 1, failures: [],
    });
  });

  it("exposes configured methods and rejects unknown methods", async () => {
    const methods = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/auth-methods`,
    );
    expect(methods.status).toBe(200);
    expect(await methods.json()).toEqual({ methods: [
      { id: "password", label: "Password", type: "password" },
      { id: "google", label: "Google", type: "oauth", idpHint: "google" },
    ] });

    const unknown = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/authorize?method=unknown`,
      { redirect: "manual" },
    );
    expect(unknown.status).toBe(400);
  });

  it("does not accept a browser-supplied Keycloak token as a session", async () => {
    const response = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/tenants`,
      { headers: { Authorization: "Bearer browser-token" } },
    );
    expect(response.status).toBe(401);
  });

  it("completes sign-in, refreshes server-side, lists tenants, and logs out", async () => {
    const authorize = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/authorize?method=google`,
      {
        redirect: "manual",
        headers: { Origin: "http://localhost:3000" },
      },
    );
    expect(authorize.status).toBe(302);
    expect(authorize.headers.get("access-control-allow-origin")).toBe(
      "http://localhost:3000",
    );
    expect(authorize.headers.get("access-control-allow-credentials")).toBe("true");
    const authorizeUrl = new URL(authorize.headers.get("location")!);
    expect(authorizeUrl.origin).toBe("http://localhost:9999");
    expect(authorizeUrl.searchParams.get("client_id")).toBe("digit-identity-bff");
    expect(authorizeUrl.searchParams.get("scope")).toContain("organization:*");
    expect(authorizeUrl.searchParams.get("kc_idp_hint")).toBe("google");
    expect(authorizeUrl.searchParams.get("nonce")).toBeTruthy();
    expect(authorizeUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizeUrl.searchParams.has("client_secret")).toBe(false);
    const state = authorizeUrl.searchParams.get("state")!;
    const loginCookie = authorize.headers.get("set-cookie")!.split(";", 1)[0];

    const unboundCallback = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/callback?code=valid-code:${encodeURIComponent(authorizeUrl.searchParams.get("nonce")!)}&state=${encodeURIComponent(state)}`,
      { redirect: "manual" },
    );
    expect(unboundCallback.status).toBe(400);

    const callback = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/callback?code=valid-code:${encodeURIComponent(authorizeUrl.searchParams.get("nonce")!)}&state=${encodeURIComponent(state)}`,
      { redirect: "manual", headers: { Cookie: loginCookie } },
    );
    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toBe("/after-login");
    const setCookies = callback.headers.getSetCookie();
    const sessionSetCookie = setCookies.find((value) =>
      value.startsWith("digit_identity_session="),
    )!;
    expect(sessionSetCookie).toContain("HttpOnly");
    expect(sessionSetCookie).toContain("SameSite=Lax");
    expect(setCookies.join(";")).not.toContain("eyJ");
    const cookie = sessionSetCookie.split(";", 1)[0];

    const replay = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/callback?code=valid-code:${encodeURIComponent(authorizeUrl.searchParams.get("nonce")!)}&state=${encodeURIComponent(state)}`,
      { redirect: "manual", headers: { Cookie: loginCookie } },
    );
    expect(replay.status).toBe(400);

    // The first token expires immediately in the mock. Reading the session
    // exercises refresh without exposing either Keycloak token to the browser.
    const session = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/session`,
      { headers: { Cookie: cookie } },
    );
    expect(session.status).toBe(200);
    expect(await session.json()).toMatchObject({
      authenticated: true,
      user: {
        id: "identity-user-1",
        email: "person@example.com",
        name: "Demo Person",
      },
      context: null,
    });

    const introspection = await fetch(
      `http://localhost:${getAppPort()}/internal/identity/v1/sessions/_introspect`,
      {
        method: "POST",
        headers: {
          Authorization: "Bearer test-session-introspection",
          Cookie: cookie,
        },
      },
    );
    expect(introspection.status).toBe(200);
    expect(await introspection.json()).toEqual({
      active: true,
      identity: {
        issuer: getIssuer(),
        subject: "identity-user-1",
        email: "person@example.com",
        name: "Demo Person",
        preferredUsername: "demo.person",
      },
    });

    const tenants = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/tenants`,
      {
        headers: {
          Cookie: cookie,
          Origin: "http://localhost:3000",
        },
      },
    );
    expect(tenants.status).toBe(200);
    expect(tenants.headers.get("access-control-allow-credentials")).toBe("true");
    expect(await tenants.json()).toEqual({
      tenants: [
        {
          tenantId: "ke.bomet",
          name: "Bomet County",
          organizationAlias: "bomet",
          roles: ["EMPLOYEE", "GRO"],
        },
        {
          tenantId: "ke.kisumu",
          name: "Kisumu County",
          organizationAlias: "kisumu",
          roles: ["EMPLOYEE", "PGR_VIEWER"],
        },
      ],
      selectionRequired: true,
      onboardingRequired: false,
    });

    const crossOriginSelect = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/contexts/_select`,
      {
        method: "POST",
        headers: {
          Cookie: cookie,
          Origin: "https://attacker.example",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ tenantId: "ke.bomet" }),
      },
    );
    expect(crossOriginSelect.status).toBe(403);

    const unavailable = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/contexts/_select`,
      {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId: "ke.unmapped" }),
      },
    );
    expect(unavailable.status).toBe(403);

    const selected = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/contexts/_select`,
      {
        method: "POST",
        headers: {
          Cookie: cookie,
          Origin: "http://localhost:3000",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ tenantId: "ke.bomet" }),
      },
    );
    expect(selected.status).toBe(200);
    const selectedBody = await selected.json();
    const managed = [...digit.accounts.values()].find((candidate) =>
      candidate.userName !== "BFF-ADMIN" && candidate.name === "Demo Person")!;
    expect(managed.identificationMark).toMatch(/^keycloak-bff:v1:/);
    expect(digit.tokens.get(selectedBody.access_token)?.uuid).toBe(managed.uuid);
    expect(Object.keys(selectedBody).sort()).toEqual(
      ["UserRequest", "access_token", "expires_in", "scope", "token_type"],
    );
    expect(selectedBody).toMatchObject({
      token_type: "bearer",
      UserRequest: { uuid: managed.uuid, userName: managed.userName, type: "EMPLOYEE" },
    });
    expect(JSON.stringify(selectedBody)).not.toMatch(/eyJ[A-Za-z0-9_-]+\./);
    expect(selectedBody.expires_in).toBeGreaterThan(0);
    expect(JSON.stringify(selectedBody)).not.toContain("refresh_token");
    expect(JSON.stringify(selectedBody)).not.toContain("must-not-leak");
    expect(digit.stats.passwordUpdates).toBe(0);

    const selectedSession = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/session`,
      { headers: { Cookie: cookie } },
    );
    expect(await selectedSession.json()).toMatchObject({
      context: { tenantId: "ke.bomet", name: "Bomet County", organizationAlias: "bomet" },
    });

    // Membership is rechecked live in Keycloak, not only from session claims.
    await fetch(
      `${config.keycloakAdminUrl}/admin/realms/${config.keycloakOrganizationRealm}/organizations/org-kisumu-id/members/identity-user-1`,
      { method: "DELETE" },
    );
    const revoked = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/contexts/_select`,
      {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId: "ke.kisumu" }),
      },
    );
    expect(revoked.status).toBe(403);

    // Re-selecting the same tenant is the renewal operation.
    const renewed = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/contexts/_select`,
      {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId: "ke.bomet" }),
      },
    );
    expect(renewed.status).toBe(200);
    expect((await renewed.json()).access_token).toBe(selectedBody.access_token);

    const logout = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/logout`,
      { method: "POST", headers: { Cookie: cookie } },
    );
    expect(logout.status).toBe(204);
    expect(logout.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(digit.tokens.has(selectedBody.access_token)).toBe(false);

    const afterLogout = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/session`,
      { headers: { Cookie: cookie } },
    );
    expect(afterLogout.status).toBe(401);
  });
});
