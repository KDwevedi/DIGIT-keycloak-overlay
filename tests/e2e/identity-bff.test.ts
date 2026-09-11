import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { config } from "../../src/config.js";
import { getIssuer } from "../helpers.js";
import {
  getIdentityAppPort as getAppPort,
  startIdentityTestApp as startTestApp,
  stopIdentityTestApp as stopTestApp,
} from "./identity-test-app.js";

beforeAll(async () => {
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
  (config as any).digitIdentityServiceUrl =
    "http://localhost:9999/internal/identity/v1";
  (config as any).digitIdentityServiceToken = "test-identity-workload";
  (config as any).digitAccessTokenMaxTtlSeconds = 900;
  (config as any).identityControlPlaneToken = "test-control-plane";
  (config as any).keycloakOrganizationRealm = "digit-sandbox";
  (config as any).keycloakAllowedOrganizationRoleClients = ["digit-ui"];
  (config as any).organizationTenantMappings = [
    {
      organizationId: "org-bomet-id",
      tenantId: "ke.bomet",
      name: "Bomet County",
    },
    {
      organizationId: "org-kisumu-id",
      tenantId: "ke.kisumu",
      name: "Kisumu County",
    },
  ];
  await startTestApp();
});

afterAll(async () => {
  await stopTestApp();
});

describe("identity BFF", () => {
  it("owns idempotent Keycloak Organization provisioning for callers such as PGR", async () => {
    const base = `http://localhost:${getAppPort()}/internal/identity/v1`;
    const unauthorized = await fetch(`${base}/organizations/_ensure`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenantId: "ke.bomet", alias: "bomet", name: "Bomet" }),
    });
    expect(unauthorized.status).toBe(401);

    const headers = {
      Authorization: "Bearer test-control-plane",
      "Content-Type": "application/json",
    };
    const ensureOrganization = () => fetch(`${base}/organizations/_ensure`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        tenantId: "ke.bomet",
        alias: "bomet",
        name: "Bomet County",
      }),
    });
    const first = await ensureOrganization();
    expect(first.status).toBe(200);
    const organization = (await first.json()).organization;
    const repeated = await ensureOrganization();
    expect(repeated.status).toBe(200);
    expect((await repeated.json()).organization.id).toBe(organization.id);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const membership = await fetch(`${base}/memberships/_ensure`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          organizationId: organization.id,
          userId: "identity-user-1",
        }),
      });
      expect(membership.status).toBe(204);
    }

    const ensureRoles = () => fetch(`${base}/role-assignments/_ensure`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        organizationId: organization.id,
        userId: "identity-user-1",
        groupName: "tenant-admins",
        clientId: "digit-ui",
        roles: ["TENANT_ADMIN"],
      }),
    });
    const roles = await ensureRoles();
    expect(roles.status).toBe(200);
    expect(await roles.json()).toMatchObject({
      assignment: { roles: ["TENANT_ADMIN"] },
    });
    expect((await (await ensureRoles()).json()).assignment.roles).toEqual([
      "TENANT_ADMIN",
    ]);
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
          roles: ["TENANT_ADMIN"],
        },
        {
          tenantId: "ke.kisumu",
          name: "Kisumu County",
          organizationAlias: "kisumu",
          roles: ["VIEWER"],
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
    expect(selectedBody).toMatchObject({
      access_token: "digit-token-ke.bomet",
      token_type: "bearer",
      expires_in: 900,
      UserRequest: {
        uuid: "digit-user-1",
        tenantId: "ke.bomet",
        type: "EMPLOYEE",
        roles: [{ code: "TENANT_ADMIN", tenantId: "ke.bomet" }],
      },
    });
    expect(JSON.stringify(selectedBody)).not.toContain("refresh_token");

    const selectedSession = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/session`,
      { headers: { Cookie: cookie } },
    );
    expect(await selectedSession.json()).toMatchObject({
      context: { tenantId: "ke.bomet", name: "Bomet County" },
    });

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

    const logout = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/logout`,
      { method: "POST", headers: { Cookie: cookie } },
    );
    expect(logout.status).toBe(204);
    expect(logout.headers.get("set-cookie")).toContain("Max-Age=0");

    const afterLogout = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/session`,
      { headers: { Cookie: cookie } },
    );
    expect(afterLogout.status).toBe(401);
  });
});
