import { config } from "./config.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export interface KcGroup {
  id: string;
  name: string;
  path: string;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const templatePath = join(__dirname, "..", "keycloak", "realm-template.json");
const realmTemplate = readFileSync(templatePath, "utf-8");

let adminToken: string | null = null;
let refreshTimer: ReturnType<typeof setInterval> | null = null;

function adminUrl(path: string): string {
  return `${config.keycloakAdminUrl}${path}`;
}

function authHeaders(): Record<string, string> {
  if (!adminToken) throw new Error("KC admin token not initialized");
  return {
    Authorization: `Bearer ${adminToken}`,
    "Content-Type": "application/json",
  };
}

// ─── Auth ────────────────────────────────────────────────────────────────────

export async function initKcAdmin(): Promise<void> {
  const tokenUrl = adminUrl(
    `/realms/${config.keycloakAdminRealm}/protocol/openid-connect/token`,
  );
  const params = new URLSearchParams({
    grant_type: "password",
    client_id: config.keycloakAdminClientId,
    username: config.keycloakAdminUsername,
    password: config.keycloakAdminPassword,
  });

  const resp = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  if (!resp.ok) {
    throw new Error(`KC admin auth failed: ${resp.status}`);
  }
  const data = (await resp.json()) as { access_token: string; expires_in: number };
  adminToken = data.access_token;

  // Refresh every 50 seconds
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    initKcAdmin().catch(console.error);
  }, 50_000);
}

export function stopKcAdminRefresh(): void {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

// ─── Realm ───────────────────────────────────────────────────────────────────

export async function createRealm(
  realmName: string,
  cities: string[],
): Promise<void> {
  // Build realm payload from template
  const payload = JSON.parse(realmTemplate.replace(/__REALM_NAME__/g, realmName));
  const bffClient = payload.clients?.find(
    (client: { clientId?: string }) => client.clientId === "digit-identity-bff",
  );
  if (bffClient) {
    bffClient.clientId = config.keycloakBffClientId;
    bffClient.secret = config.keycloakBffClientSecret;
    bffClient.redirectUris = [config.identityRedirectUri];
    const audienceMapper = bffClient.protocolMappers?.find(
      (mapper: { protocolMapper?: string }) =>
        mapper.protocolMapper === "oidc-audience-mapper",
    );
    if (audienceMapper) {
      audienceMapper.config["included.client.audience"] =
        config.keycloakBffAudience;
    }
  }
  payload.groups = cities.map((c) => ({ name: c }));

  const resp = await fetch(adminUrl("/admin/realms"), {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify(payload),
  });

  if (resp.status === 409) {
    // Realm already exists — ensure groups are created individually
    console.log(`Realm "${realmName}" already exists, syncing groups...`);
    const existingGroups = await getGroupsInRealm(realmName);
    const existingNames = new Set(existingGroups.map((g) => g.name));
    for (const city of cities) {
      if (!existingNames.has(city)) {
        try {
          await createGroupInRealm(realmName, city);
        } catch {
          // Ignore 409 from individual group creation
        }
      }
    }
    return;
  }

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to create realm "${realmName}": ${resp.status} ${text}`);
  }
  console.log(`Created realm "${realmName}" with ${cities.length} city group(s)`);
}

export async function listRealms(): Promise<string[]> {
  const resp = await fetch(adminUrl("/admin/realms"), {
    method: "GET",
    headers: authHeaders(),
  });
  if (!resp.ok) throw new Error(`Failed to list realms: ${resp.status}`);
  const data = (await resp.json()) as Array<{ realm: string }>;
  return data.map((r) => r.realm);
}

// ─── Groups ──────────────────────────────────────────────────────────────────

export async function createGroupInRealm(
  realm: string,
  name: string,
): Promise<string> {
  const resp = await fetch(adminUrl(`/admin/realms/${realm}/groups`), {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ name }),
  });
  if (resp.status === 409) {
    // Group already exists — find its ID
    const groups = await getGroupsInRealm(realm);
    const existing = groups.find((g) => g.name === name);
    if (existing) return existing.id;
    throw new Error(`Group "${name}" reported as duplicate but not found`);
  }
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to create group "${name}" in realm "${realm}": ${resp.status} ${text}`);
  }
  // Extract group ID from Location header
  const location = resp.headers.get("Location") || "";
  const id = location.split("/").pop() || "";
  return id;
}

export async function getGroupsInRealm(realm: string): Promise<KcGroup[]> {
  const resp = await fetch(adminUrl(`/admin/realms/${realm}/groups`), {
    method: "GET",
    headers: authHeaders(),
  });
  if (!resp.ok) throw new Error(`Failed to list groups in realm "${realm}": ${resp.status}`);
  return (await resp.json()) as KcGroup[];
}

// ─── User-group ──────────────────────────────────────────────────────────────

export async function addUserToGroupInRealm(
  realm: string,
  userId: string,
  groupId: string,
): Promise<void> {
  const resp = await fetch(
    adminUrl(`/admin/realms/${realm}/users/${userId}/groups/${groupId}`),
    {
      method: "PUT",
      headers: authHeaders(),
    },
  );
  if (!resp.ok) {
    throw new Error(
      `Failed to add user "${userId}" to group "${groupId}" in realm "${realm}": ${resp.status}`,
    );
  }
}

export async function getUserGroupsInRealm(
  realm: string,
  userId: string,
): Promise<KcGroup[]> {
  const resp = await fetch(
    adminUrl(`/admin/realms/${realm}/users/${userId}/groups`),
    {
      method: "GET",
      headers: authHeaders(),
    },
  );
  if (!resp.ok) throw new Error(`Failed to get user groups: ${resp.status}`);
  return (await resp.json()) as KcGroup[];
}

// ─── User-role ───────────────────────────────────────────────────────────────

/**
 * Patch a single user attribute on a KC user (e.g. phoneNumber).
 *
 * KC's user PUT is a full-rep replace, so we GET → mutate → PUT to
 * avoid clobbering other attributes / role mappings / credentials.
 * This is intentionally for `attributes.<key>` writes only; for top-
 * level fields like email / firstName, use a different helper.
 *
 * KC's `phone` client scope (built-in since KC 24) reads from
 * `attributes.phoneNumber` and surfaces it as the `phone_number` JWT
 * claim — so writing this attribute is what makes the next-minted
 * JWT carry the phone, which is what SPAs read into `auth.user.mobileNumber`.
 *
 * Idempotent: if the existing attribute value already matches, the
 * PUT is still issued (KC has no compare-and-set), but it's a no-op
 * for downstream behavior.
 */
export async function setUserAttributeInRealm(
  realm: string,
  userId: string,
  key: string,
  value: string,
): Promise<void> {
  const get = await fetch(adminUrl(`/admin/realms/${realm}/users/${userId}`), {
    headers: authHeaders(),
  });
  if (!get.ok) {
    throw new Error(
      `setUserAttributeInRealm: GET user ${userId} in realm ${realm} failed: ${get.status}`,
    );
  }
  const user = (await get.json()) as {
    attributes?: Record<string, string[]>;
    [k: string]: unknown;
  };
  user.attributes = user.attributes || {};
  // KC stores attribute values as string arrays even for single values.
  user.attributes[key] = [value];

  const put = await fetch(adminUrl(`/admin/realms/${realm}/users/${userId}`), {
    method: "PUT",
    headers: authHeaders(),
    body: JSON.stringify(user),
  });
  if (!put.ok) {
    throw new Error(
      `setUserAttributeInRealm: PUT user ${userId} attribute ${key} failed: ${put.status} ${await put.text()}`,
    );
  }
}

export async function assignRealmRoles(
  realm: string,
  userId: string,
  roleCodes: string[],
): Promise<void> {
  // Resolve each role code to its full representation (with id)
  const roleRepresentations: Array<{ id: string; name: string }> = [];
  for (const code of roleCodes) {
    const resp = await fetch(
      adminUrl(`/admin/realms/${realm}/roles/${code}`),
      {
        method: "GET",
        headers: authHeaders(),
      },
    );
    if (!resp.ok) {
      throw new Error(
        `Role "${code}" not found in realm "${realm}": ${resp.status}`,
      );
    }
    const role = (await resp.json()) as { id: string; name: string };
    roleRepresentations.push({ id: role.id, name: role.name });
  }

  // Assign all roles in one request
  const resp = await fetch(
    adminUrl(`/admin/realms/${realm}/users/${userId}/role-mappings/realm`),
    {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(roleRepresentations),
    },
  );
  if (!resp.ok) {
    throw new Error(
      `Failed to assign roles to user "${userId}" in realm "${realm}": ${resp.status}`,
    );
  }
}

export async function getUserRealmRoles(
  realm: string,
  userId: string,
): Promise<Array<{ name: string }>> {
  const resp = await fetch(
    adminUrl(`/admin/realms/${realm}/users/${userId}/role-mappings/realm`),
    {
      method: "GET",
      headers: authHeaders(),
    },
  );
  if (!resp.ok) throw new Error(`Failed to get user realm roles: ${resp.status}`);
  return (await resp.json()) as Array<{ name: string }>;
}

// ─── Sync ────────────────────────────────────────────────────────────────────

export function _parseTenantEnv(envStr: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  if (!envStr || !envStr.trim()) return result;

  const trimmed = envStr.trim();

  // Structured format: "pg:pg.citya,pg.cityb;mz:mz.chimoio"
  if (trimmed.includes(":")) {
    const segments = trimmed.split(";");
    for (const segment of segments) {
      const [root, citiesPart] = segment.split(":");
      if (!root || !citiesPart) continue;
      const cities = citiesPart.split(",").map((c) => c.trim()).filter(Boolean);
      result.set(root.trim(), cities);
    }
    return result;
  }

  // Flat format: "pg.citya,pg.cityb,mz.chimoio" — group by first segment
  const entries = trimmed.split(",").map((e) => e.trim()).filter(Boolean);
  for (const entry of entries) {
    const root = entry.split(".")[0];
    const existing = result.get(root) || [];
    existing.push(entry);
    result.set(root, existing);
  }

  return result;
}

export async function syncTenantRealms(): Promise<void> {
  const tenantMap = _parseTenantEnv(config.digitTenants);
  if (tenantMap.size === 0) {
    console.log("No tenants configured (DIGIT_TENANTS is empty), skipping sync");
    return;
  }

  console.log(`Syncing ${tenantMap.size} tenant realm(s)...`);
  for (const [root, cities] of tenantMap) {
    try {
      await createRealm(root, cities);
      console.log(`  ${root}: ${cities.length} city group(s) synced`);
    } catch (err) {
      console.error(`  ${root}: failed —`, err);
    }
  }
  console.log("Tenant realm sync complete");
}
