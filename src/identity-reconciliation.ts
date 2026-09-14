import { randomUUID } from "node:crypto";
import { getRedis } from "./cache.js";
import { config } from "./config.js";
import {
  digitReconciliationSnapshot,
  reconcileDigitMembership,
} from "./digit-identity.js";
import { readOrganizationReconciliation } from "./identity-admin.js";

export interface IdentityReconciliationResult {
  acquired: boolean;
  organizations: number;
  activated: number;
  deactivated: number;
  unchanged: number;
  failures: Array<{ organizationId: string; subject?: string; error: string }>;
}

const leaseKey = () => `${config.cachePrefix}:identity-reconciliation-lease`;

async function releaseLease(value: string): Promise<void> {
  await getRedis().eval(
    "if redis.call('get', KEYS[1]) == ARGV[1] then " +
      "return redis.call('del', KEYS[1]) else return 0 end",
    1,
    leaseKey(),
    value,
  );
}

export async function runIdentityReconciliation(): Promise<IdentityReconciliationResult> {
  const lease = randomUUID();
  const acquired = await getRedis().set(
    leaseKey(),
    lease,
    "EX",
    config.identityReconciliationLeaseSeconds,
    "NX",
  );
  const result: IdentityReconciliationResult = {
    acquired: acquired === "OK",
    organizations: 0,
    activated: 0,
    deactivated: 0,
    unchanged: 0,
    failures: [],
  };
  if (!result.acquired) return result;

  try {
    const organizations = await digitReconciliationSnapshot();
    result.organizations = organizations.length;
    for (const organization of organizations) {
      let desired;
      try {
        desired = organization.active
          ? await readOrganizationReconciliation(
            organization.organizationId,
            config.digitIdentityClientId,
          )
          : null;
      } catch (error) {
        result.failures.push({
          organizationId: organization.organizationId,
          error: (error as Error).message,
        });
        continue;
      }

      const current = new Map(
        organization.members
          .filter((member) => member.issuer === config.keycloakIssuer)
          .map((member) => [member.subject, member.active]),
      );
      const desiredMembers = desired?.enabled ? desired.memberRoles : new Map();
      const subjects = new Set([...current.keys(), ...desiredMembers.keys()]);
      for (const subject of subjects) {
        const active = desiredMembers.has(subject);
        if (!active && current.get(subject) !== true) {
          result.unchanged += 1;
          continue;
        }
        try {
          await reconcileDigitMembership({
            issuer: config.keycloakIssuer,
            subject,
            organizationId: organization.organizationId,
            roles: active ? desiredMembers.get(subject)! : [],
            active,
          });
          if (active) result.activated += 1;
          else result.deactivated += 1;
        } catch (error) {
          result.failures.push({
            organizationId: organization.organizationId,
            subject,
            error: (error as Error).message,
          });
        }
      }
    }
    return result;
  } finally {
    await releaseLease(lease);
  }
}
