import { randomUUID } from "node:crypto";
import { getRedis } from "./cache.js";
import { config } from "./config.js";
import {
  listOrganizationMappings,
  readOrganizationReconciliation,
} from "./identity-admin.js";
import { isActiveDigitTenant } from "./identity-tenants.js";
import {
  type DesiredRoles,
  ensureManagedAccount,
  managedIdentity,
  managedSubjectsKey,
} from "./managed-digit-users.js";

export interface IdentityReconciliationResult {
  acquired: boolean;
  organizations: number;
  subjects: number;
  updated: number;
  deactivated: number;
  unchanged: number;
  /** Keycloak members without a managed DIGIT account yet (not failures). */
  unprovisioned: number;
  failures: Array<{ subject: string; error: string }>;
}

const leaseKey = () => `${config.cachePrefix}:identity-reconciliation-lease`;

function allowlisted(roles: string[]): string[] {
  return roles.filter((role) => config.digitManagedRoleAllowlist.includes(role));
}

/** Desired DIGIT roles per Keycloak subject from enabled, DIGIT-mapped Organizations. */
export async function desiredRolesBySubject(): Promise<{
  organizations: number;
  bySubject: Map<string, DesiredRoles>;
}> {
  const bySubject = new Map<string, DesiredRoles>();
  let organizations = 0;
  for (const mapping of await listOrganizationMappings()) {
    if (!await isActiveDigitTenant(mapping.tenantId)) continue;
    const state = await readOrganizationReconciliation(mapping.organizationId, config.digitRoleClientId);
    if (!state?.enabled) continue;
    organizations += 1;
    for (const [subject, roles] of state.memberRoles) {
      const desired = bySubject.get(subject) || new Map<string, string[]>();
      desired.set(mapping.tenantId, allowlisted(roles));
      bySubject.set(subject, desired);
    }
  }
  return { organizations, bySubject };
}

async function releaseLease(value: string): Promise<void> {
  await getRedis().eval(
    "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
    1, leaseKey(), value,
  );
}

/**
 * Projects Keycloak Organization membership and allowlisted group roles onto
 * managed DIGIT accounts through egov-user. Accounts are never created here
 * (creation needs a mobile number) and unmanaged DIGIT users are never read
 * as candidates. Former members that this BFF provisioned are deactivated.
 */
export async function runIdentityReconciliation(): Promise<IdentityReconciliationResult> {
  const lease = randomUUID();
  const acquired = await getRedis().set(
    leaseKey(), lease, "EX", config.identityReconciliationLeaseSeconds, "NX",
  );
  const result: IdentityReconciliationResult = {
    acquired: acquired === "OK",
    organizations: 0,
    subjects: 0,
    updated: 0,
    deactivated: 0,
    unchanged: 0,
    unprovisioned: 0,
    failures: [],
  };
  if (!result.acquired) return result;

  try {
    const { organizations, bySubject } = await desiredRolesBySubject();
    result.organizations = organizations;
    const managed = await getRedis().hgetall(managedSubjectsKey());
    const subjects = new Set([
      ...bySubject.keys(),
      ...Object.entries(managed)
        .filter(([, issuer]) => issuer === config.keycloakIssuer)
        .map(([subject]) => subject),
    ]);
    result.subjects = subjects.size;
    for (const subject of subjects) {
      const desired = bySubject.get(subject) || new Map<string, string[]>();
      try {
        const outcome = await ensureManagedAccount(managedIdentity(config.keycloakIssuer, subject), desired);
        if (!outcome.account) {
          if (desired.size > 0) result.unprovisioned += 1;
          else result.unchanged += 1;
        } else if (!outcome.changed) {
          result.unchanged += 1;
        } else if (desired.size === 0) {
          result.deactivated += 1;
        } else {
          result.updated += 1;
        }
      } catch (error) {
        result.failures.push({ subject, error: (error as Error).message });
      }
    }
    return result;
  } finally {
    await releaseLease(lease);
  }
}
