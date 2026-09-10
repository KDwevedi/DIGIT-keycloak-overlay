import type {
  KCClaims,
  OrganizationTenantMapping,
} from "./types.js";

export interface TenantOption {
  tenantId: string;
  name: string;
  organizationAlias: string;
  roles: string[];
}

export function tenantOptionsFromClaims(
  claims: KCClaims,
  mappings: OrganizationTenantMapping[],
): TenantOption[] {
  const mappingsByOrganizationId = new Map(
    mappings.map((mapping) => [mapping.organizationId, mapping]),
  );

  return Object.entries(claims.organization || {})
    .flatMap(([organizationAlias, organization]) => {
      if (!organization?.id) return [];
      const mapping = mappingsByOrganizationId.get(organization.id);
      if (!mapping) return [];

      return [{
        tenantId: mapping.tenantId,
        name: mapping.name,
        organizationAlias,
        roles: [...new Set(organization.realm_access?.roles || [])].sort(),
      }];
    })
    .sort((left, right) => left.name.localeCompare(right.name));
}
