import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { config } from "../../src/config.js";
import { getIssuer, signJwt } from "../helpers.js";
import {
  getAppPort,
  startTestApp,
  stopTestApp,
} from "./test-app.js";

beforeAll(async () => {
  (config as any).keycloakIssuer = getIssuer();
  (config as any).keycloakAudience = "digit-ui";
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

describe("GET /identity/v1/tenants", () => {
  it("returns 401 without a verified Keycloak access token", async () => {
    const response = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/tenants`,
    );
    expect(response.status).toBe(401);
  });

  it("returns only mapped memberships and their organization-specific roles", async () => {
    const token = await signJwt({
      sub: "user-1",
      email: "person@example.com",
      aud: "digit-ui",
      organization: {
        bomet: {
          id: "org-bomet-id",
          realm_access: { roles: ["TENANT_ADMIN"] },
        },
        kisumu: {
          id: "org-kisumu-id",
          realm_access: { roles: ["VIEWER"] },
        },
        hidden: {
          id: "org-hidden-id",
          realm_access: { roles: ["SUPERUSER"] },
        },
      },
    });

    const response = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/tenants`,
      { headers: { Authorization: `Bearer ${token}` } },
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
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
  });

  it("rejects a token issued for another audience", async () => {
    const token = await signJwt({
      sub: "user-1",
      email: "person@example.com",
      aud: "another-client",
      organization: { bomet: { id: "org-bomet-id" } },
    });
    const response = await fetch(
      `http://localhost:${getAppPort()}/identity/v1/tenants`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    expect(response.status).toBe(401);
  });
});
