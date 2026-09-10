import { describe, expect, it } from "vitest";
import { parseOrganizationTenantMappings } from "../../src/config.js";
import { tenantOptionsFromClaims } from "../../src/tenant-options.js";

describe("parseOrganizationTenantMappings", () => {
  it("parses the server-owned organization ID mapping", () => {
    expect(parseOrganizationTenantMappings(JSON.stringify([
      {
        organizationId: "org-bomet-id",
        tenantId: "ke.bomet",
        name: "Bomet County",
      },
    ]))).toEqual([
      {
        organizationId: "org-bomet-id",
        tenantId: "ke.bomet",
        name: "Bomet County",
      },
    ]);
  });

  it("rejects an invalid mapping at startup", () => {
    expect(() => parseOrganizationTenantMappings(
      '[{"organizationId":"org-bomet-id","tenantId":"ke.bomet"}]',
    )).toThrow(".name must be a non-empty string");
  });
});

describe("tenantOptionsFromClaims", () => {
  it("returns mapped memberships with roles isolated by organization", () => {
    const options = tenantOptionsFromClaims({
      sub: "user-1",
      email: "person@example.com",
      organization: {
        bomet: {
          id: "org-bomet-id",
          groups: ["/Administrators"],
          realm_access: { roles: ["TENANT_ADMIN", "TENANT_ADMIN"] },
        },
        kisumu: {
          id: "org-kisumu-id",
          groups: ["/Viewers"],
          realm_access: { roles: ["VIEWER"] },
        },
        unmapped: {
          id: "org-unmapped-id",
          realm_access: { roles: ["SUPERUSER"] },
        },
      },
    }, [
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
    ]);

    expect(options).toEqual([
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
    ]);
  });

  it("does not trust an alias without the mapped immutable organization ID", () => {
    expect(tenantOptionsFromClaims({
      sub: "user-1",
      email: "person@example.com",
      organization: { bomet: { realm_access: { roles: ["TENANT_ADMIN"] } } },
    }, [{
      organizationId: "org-bomet-id",
      tenantId: "ke.bomet",
      name: "Bomet County",
    }])).toEqual([]);
  });
});
