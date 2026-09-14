import { config } from "./config.js";
import { readIdentityUserProfile } from "./identity-admin.js";
import { desiredRolesBySubject } from "./identity-reconciliation.js";
import { ensureManagedAccount, managedIdentity } from "./managed-digit-users.js";

/**
 * Re-derives a Keycloak subject's DIGIT roles from live Keycloak Organization
 * state and applies them to its managed account. Passing `mobileNumber`
 * (possibly empty) allows creating a missing account from the Keycloak profile.
 */
export async function syncSubject(userId: string, mobileNumber?: string) {
  const desired = (await desiredRolesBySubject()).bySubject.get(userId) || new Map<string, string[]>();
  const profile = mobileNumber === undefined
    ? undefined
    : { ...await readIdentityUserProfile(userId), mobileNumber };
  return ensureManagedAccount(managedIdentity(config.keycloakIssuer, userId), desired, profile);
}
