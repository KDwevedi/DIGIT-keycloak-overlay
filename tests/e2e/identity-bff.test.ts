import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { config } from "../../src/config.js";
import { getIssuer } from "../helpers.js";
import {
  getAppPort,
  startTestApp,
  stopTestApp,
} from "./test-app.js";

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
  it("does not accept a browser-supplied Keycloak token as a session", async () => {
    const response = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/tenants`,
      { headers: { Authorization: "Bearer browser-token" } },
    );
    expect(response.status).toBe(401);
  });

  it("completes sign-in, refreshes server-side, lists tenants, and logs out", async () => {
    const authorize = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/authorize`,
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
    expect(authorizeUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizeUrl.searchParams.has("client_secret")).toBe(false);
    const state = authorizeUrl.searchParams.get("state")!;
    const loginCookie = authorize.headers.get("set-cookie")!.split(";", 1)[0];

    const unboundCallback = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/callback?code=valid-code&state=${encodeURIComponent(state)}`,
      { redirect: "manual" },
    );
    expect(unboundCallback.status).toBe(400);

    const callback = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/callback?code=valid-code&state=${encodeURIComponent(state)}`,
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
    expect(setCookies.join(";")).not.toContain("server-side-id-token");
    const cookie = sessionSetCookie.split(";", 1)[0];

    const replay = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/callback?code=valid-code&state=${encodeURIComponent(state)}`,
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
    });

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
