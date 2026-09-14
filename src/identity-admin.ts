import { config } from "./config.js";
import { getAdminToken } from "./keycloak-admin.js";

interface OrganizationRepresentation {
  id?: string;
  name?: string;
  alias?: string;
  enabled?: boolean;
  attributes?: Record<string, string[]>;
}

interface GroupRepresentation {
  id: string;
  name: string;
}

interface RoleRepresentation {
  id: string;
  name: string;
}

interface UserRepresentation {
  id?: string;
  username?: string;
  email?: string;
  emailVerified?: boolean;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;
}

export interface IdentityUserProfile {
  name: string;
  emailId?: string;
}

export interface OrganizationReconciliationState {
  organizationId: string;
  enabled: boolean;
  memberRoles: Map<string, string[]>;
}

export class IdentityAdminError extends Error {
  constructor(message: string, readonly status = 502) {
    super(message);
  }
}

export async function enabledIdentityProviderAliases(): Promise<Set<string>> {
  const response = await request(
    "/identity-provider/instances?briefRepresentation=true&max=100",
  );
  const providers = await response.json() as Array<{
    alias?: string;
    enabled?: boolean;
  }>;
  return new Set(providers.flatMap((provider) =>
    provider.enabled !== false && provider.alias ? [provider.alias] : [],
  ));
}

function realmPath(path: string): string {
  return `/admin/realms/${encodeURIComponent(config.keycloakOrganizationRealm)}${path}`;
}

async function request(
  path: string,
  init: RequestInit = {},
  accepted = [200, 204],
): Promise<Response> {
  let token: string;
  try {
    token = await getAdminToken();
  } catch (error) {
    throw new IdentityAdminError(
      `Keycloak Admin authentication failed: ${(error as Error).message}`,
    );
  }
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  let response: Response;
  try {
    response = await fetch(`${config.keycloakAdminUrl}${realmPath(path)}`, {
      ...init,
      headers,
    });
  } catch (error) {
    throw new IdentityAdminError(
      `Keycloak Admin request failed: ${(error as Error).message}`,
    );
  }
  if (!accepted.includes(response.status)) {
    const detail = await response.text().catch(() => "");
    throw new IdentityAdminError(
      `Keycloak Admin API returned ${response.status}${detail ? `: ${detail}` : ""}`,
      response.status === 400 || response.status === 404 || response.status === 409
        ? response.status
        : 502,
    );
  }
  return response;
}

async function paged<T>(path: string): Promise<T[]> {
  const values: T[] = [];
  for (let first = 0; ; first += 100) {
    const separator = path.includes("?") ? "&" : "?";
    const response = await request(`${path}${separator}first=${first}&max=100`);
    const page = await response.json() as T[];
    values.push(...page);
    if (page.length < 100) return values;
  }
}

function mappedTenant(organization: OrganizationRepresentation): string | null {
  const values = organization.attributes?.["digit.rootTenantId"];
  return Array.isArray(values) && values.length === 1 ? values[0] : null;
}

async function organizationsForTenant(
  tenantId: string,
): Promise<OrganizationRepresentation[]> {
  const query = new URLSearchParams({
    q: `digit.rootTenantId:${tenantId}`,
    briefRepresentation: "false",
    max: "20",
  });
  const response = await request(`/organizations?${query}`);
  const organizations = await response.json() as OrganizationRepresentation[];
  return organizations.filter((organization) => mappedTenant(organization) === tenantId);
}

export async function ensureOrganization(input: {
  tenantId: string;
  alias: string;
  name: string;
}): Promise<{ id: string; tenantId: string; alias: string; name: string }> {
  let matches = await organizationsForTenant(input.tenantId);
  if (matches.length > 1) {
    throw new IdentityAdminError("Multiple Organizations map to this tenant", 409);
  }

  let organization = matches[0];
  if (!organization) {
    const response = await request("/organizations", {
      method: "POST",
      body: JSON.stringify({
        name: input.name,
        alias: input.alias,
        enabled: true,
        attributes: { "digit.rootTenantId": [input.tenantId] },
      }),
    }, [201]);
    const location = response.headers.get("location");
    const id = location?.split("/").filter(Boolean).pop();
    if (id) {
      organization = { id, name: input.name, alias: input.alias };
    } else {
      matches = await organizationsForTenant(input.tenantId);
      organization = matches[0];
    }
  }

  if (!organization?.id) {
    throw new IdentityAdminError("Keycloak did not identify the Organization it created");
  }
  if (organization.alias && organization.alias !== input.alias) {
    throw new IdentityAdminError(
      "The tenant is already mapped to another Organization alias",
      409,
    );
  }

  if (organization.name !== input.name || organization.enabled === false) {
    await request(`/organizations/${encodeURIComponent(organization.id)}`, {
      method: "PUT",
      body: JSON.stringify({
        ...organization,
        name: input.name,
        alias: input.alias,
        enabled: true,
        attributes: {
          ...organization.attributes,
          "digit.rootTenantId": [input.tenantId],
        },
      }),
    });
  }
  return {
    id: organization.id,
    tenantId: input.tenantId,
    alias: input.alias,
    name: input.name,
  };
}

/**
 * Profile facts used when DIGIT must create an employee for a new founder.
 * Only a verified email is passed on; the subject itself is the link key.
 */
export async function readIdentityUserProfile(userId: string): Promise<IdentityUserProfile> {
  const response = await request(`/users/${encodeURIComponent(userId)}`);
  const user = await response.json() as UserRepresentation;
  if (user.id !== userId || user.enabled === false) {
    throw new IdentityAdminError("Keycloak user is not active", 404);
  }
  const name = [user.firstName, user.lastName]
    .map((part) => part?.trim())
    .filter(Boolean)
    .join(" ") || user.username?.trim() || "";
  if (!name) throw new IdentityAdminError("Keycloak user has no name", 400);
  return {
    name,
    ...(user.emailVerified === true && user.email ? { emailId: user.email } : {}),
  };
}

export async function ensureOrganizationMembership(input: {
  organizationId: string;
  userId: string;
}): Promise<void> {
  await request(
    `/organizations/${encodeURIComponent(input.organizationId)}/members`,
    { method: "POST", body: JSON.stringify(input.userId) },
    [201, 409],
  );
}

async function ensureOrganizationGroup(
  organizationId: string,
  name: string,
): Promise<GroupRepresentation> {
  const base = `/organizations/${encodeURIComponent(organizationId)}/groups`;
  const query = new URLSearchParams({ search: name, exact: "true", max: "20" });
  let response = await request(`${base}?${query}`);
  let groups = await response.json() as GroupRepresentation[];
  let group = groups.find((candidate) => candidate.name === name);
  if (group) return group;

  response = await request(base, {
    method: "POST",
    body: JSON.stringify({ name }),
  }, [201, 204, 409]);
  const id = response.headers.get("location")?.split("/").filter(Boolean).pop();
  if (id) return { id, name };
  response = await request(`${base}?${query}`);
  groups = await response.json() as GroupRepresentation[];
  group = groups.find((candidate) => candidate.name === name);
  if (!group) throw new IdentityAdminError("Keycloak did not create the Organization group");
  return group;
}

async function clientUuid(clientId: string): Promise<string> {
  const query = new URLSearchParams({ clientId });
  const response = await request(`/clients?${query}`);
  const clients = await response.json() as Array<{ id?: string; clientId?: string }>;
  const client = clients.find((candidate) => candidate.clientId === clientId);
  if (!client?.id) throw new IdentityAdminError("Keycloak client was not found", 404);
  return client.id;
}

async function clientRole(
  clientId: string,
  roleName: string,
): Promise<RoleRepresentation> {
  const response = await request(
    `/clients/${encodeURIComponent(clientId)}/roles/${encodeURIComponent(roleName)}`,
  );
  const role = await response.json() as RoleRepresentation;
  if (!role.id || role.name !== roleName) {
    throw new IdentityAdminError(`Keycloak client role was not found: ${roleName}`, 404);
  }
  return role;
}

export async function ensureOrganizationRoleAssignment(input: {
  organizationId: string;
  userId: string;
  groupName: string;
  clientId: string;
  roles: string[];
}): Promise<{ groupId: string; roles: string[] }> {
  if (!config.keycloakAllowedOrganizationRoleClients.includes(input.clientId)) {
    throw new IdentityAdminError("Keycloak client is not allowed for Organization roles", 400);
  }
  const group = await ensureOrganizationGroup(input.organizationId, input.groupName);
  await request(
    `/organizations/${encodeURIComponent(input.organizationId)}` +
      `/groups/${encodeURIComponent(group.id)}/members/${encodeURIComponent(input.userId)}`,
    { method: "PUT" },
    [204, 409],
  );

  const uuid = await clientUuid(input.clientId);
  const desired = await Promise.all(input.roles.map((role) => clientRole(uuid, role)));
  const mappingPath =
    `/organizations/${encodeURIComponent(input.organizationId)}` +
    `/groups/${encodeURIComponent(group.id)}/role-mappings/clients/${encodeURIComponent(uuid)}`;
  const currentResponse = await request(mappingPath);
  const current = await currentResponse.json() as RoleRepresentation[];
  const desiredNames = new Set(desired.map((role) => role.name));
  const currentNames = new Set(current.map((role) => role.name));
  const add = desired.filter((role) => !currentNames.has(role.name));
  const remove = current.filter((role) => !desiredNames.has(role.name));
  if (add.length) {
    await request(mappingPath, {
      method: "POST",
      body: JSON.stringify(add),
    });
  }
  if (remove.length) {
    await request(mappingPath, {
      method: "DELETE",
      body: JSON.stringify(remove),
    });
  }
  return { groupId: group.id, roles: desired.map((role) => role.name).sort() };
}

export async function readOrganizationReconciliation(
  organizationId: string,
  roleClientId: string,
): Promise<OrganizationReconciliationState | null> {
  if (!config.keycloakAllowedOrganizationRoleClients.includes(roleClientId)) {
    throw new IdentityAdminError("Keycloak client is not allowed for Organization roles", 400);
  }
  let organization: OrganizationRepresentation;
  try {
    const response = await request(`/organizations/${encodeURIComponent(organizationId)}`);
    organization = await response.json() as OrganizationRepresentation;
  } catch (error) {
    if (error instanceof IdentityAdminError && error.status === 404) return null;
    throw error;
  }

  const members = await paged<UserRepresentation>(
    `/organizations/${encodeURIComponent(organizationId)}/members`,
  );
  const memberRoles = new Map<string, Set<string>>();
  for (const member of members) {
    if (member.id) memberRoles.set(member.id, new Set());
  }
  if (organization.enabled === false) {
    return { organizationId, enabled: false, memberRoles: new Map() };
  }

  const uuid = await clientUuid(roleClientId);
  const groups = await paged<GroupRepresentation>(
    `/organizations/${encodeURIComponent(organizationId)}/groups`,
  );
  for (const group of groups) {
    const mappingPath =
      `/organizations/${encodeURIComponent(organizationId)}` +
      `/groups/${encodeURIComponent(group.id)}/role-mappings/clients/${encodeURIComponent(uuid)}`;
    const rolesResponse = await request(mappingPath);
    const roles = await rolesResponse.json() as RoleRepresentation[];
    if (roles.length === 0) continue;
    const groupMembers = await paged<UserRepresentation>(
      `/organizations/${encodeURIComponent(organizationId)}` +
      `/groups/${encodeURIComponent(group.id)}/members`,
    );
    for (const member of groupMembers) {
      if (!member.id || !memberRoles.has(member.id)) continue;
      const desired = memberRoles.get(member.id)!;
      for (const role of roles) desired.add(role.name);
    }
  }
  return {
    organizationId,
    enabled: true,
    memberRoles: new Map([...memberRoles].map(([subject, roles]) => [
      subject,
      [...roles].sort(),
    ])),
  };
}
