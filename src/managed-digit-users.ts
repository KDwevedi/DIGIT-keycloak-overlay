import { createHash, randomInt, randomUUID } from "node:crypto";
import { getRedis } from "./cache.js";
import { config } from "./config.js";
import { withDigitAdmin } from "./digit-admin-token.js";
import {
  createAccount,
  type DigitAccount,
  type DigitAccountInput,
  type DigitLogin,
  type DigitRole,
  DigitUnavailableError,
  passwordLogin,
  revokeToken,
  searchAccounts,
  updateAccount,
} from "./digit-user-service.js";

/**
 * DIGIT accounts owned by this Keycloak-BFF flow.
 *
 * An account is managed only when BOTH its username and its
 * identificationMark are derived from the verified Keycloak (issuer, subject).
 * Anything else, including every locally managed legacy employee, is never
 * updated, rotated or deactivated here.
 *
 * Passwords are one-time plaintext values: generated, sent once to egov-user
 * (create/update) and once to /oauth/token, then dropped. egov-user still
 * stores the resulting BCrypt hash, and JavaScript strings cannot be zeroed,
 * so "discarded" means never persisted, logged, cached or returned.
 */
export const MANAGED_USER_TYPE = "EMPLOYEE";

export interface ManagedIdentity {
  issuer: string;
  subject: string;
  key: string;
  username: string;
  marker: string;
}

export interface ManagedProfile {
  name: string;
  emailId?: string;
  mobileNumber?: string;
}

/** tenantId -> DIGIT role codes the managed account should hold there. */
export type DesiredRoles = Map<string, string[]>;

export class ManagedAccountError extends Error {
  constructor(message: string, readonly status = 409) {
    super(message);
  }
}

export function managedIdentity(issuer: string, subject: string): ManagedIdentity {
  const key = createHash("sha256").update(`${issuer}\n${subject}`).digest("hex");
  return {
    issuer,
    subject,
    key,
    username: `kcbff-${key.slice(0, 40)}`,
    marker: `keycloak-bff:v1:${key}`,
  };
}

const LOWER = "abcdefghijkmnopqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const SPECIAL = "@#$%";

/** Random password satisfying egov-user's default policy (digit, lower, upper, @#$%, 8-15). */
export function oneTimePassword(length = config.digitPasswordLength): string {
  if (length < 8 || length > 15) throw new Error("DIGIT password length must be 8-15");
  const all = LOWER + UPPER + DIGITS + SPECIAL;
  const chars = [LOWER, UPPER, DIGITS, SPECIAL].map((set) => set[randomInt(set.length)]);
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swap = randomInt(index + 1);
    [chars[index], chars[swap]] = [chars[swap], chars[index]];
  }
  return chars.join("");
}

const tokenKey = (identity: ManagedIdentity) =>
  `${config.cachePrefix}:digit-user-token:${identity.key}`;
const leaseKey = (identity: ManagedIdentity) =>
  `${config.cachePrefix}:digit-user-lease:${identity.key}`;
export const managedSubjectsKey = () => `${config.cachePrefix}:digit-managed-subjects`;

async function withUserLease<T>(identity: ManagedIdentity, operation: () => Promise<T>): Promise<T> {
  const value = randomUUID();
  const deadline = Date.now() + config.digitUserLeaseWaitMs;
  while ((await getRedis().set(
    leaseKey(identity), value, "EX", config.digitUserLeaseSeconds, "NX",
  )) !== "OK") {
    if (Date.now() >= deadline) {
      throw new DigitUnavailableError("DIGIT account is busy; retry");
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  try {
    return await operation();
  } finally {
    await getRedis().eval(
      "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
      1, leaseKey(identity), value,
    );
  }
}

function requireManagedTenant(): string {
  if (!config.digitManagedUserTenantId) {
    throw new DigitUnavailableError("DIGIT managed-user tenant is not configured");
  }
  return config.digitManagedUserTenantId;
}

async function findAccount(adminToken: string, identity: ManagedIdentity): Promise<DigitAccount | null> {
  const tenantId = requireManagedTenant();
  for (const active of [true, false]) {
    const accounts = await searchAccounts(adminToken, {
      userName: identity.username, tenantId, userType: MANAGED_USER_TYPE, active,
    });
    const account = accounts.find((candidate) => candidate.userName === identity.username);
    if (!account) continue;
    if (account.identificationMark !== identity.marker) {
      throw new ManagedAccountError("A DIGIT account with this username is not managed by the identity BFF");
    }
    return account;
  }
  return null;
}

export function desiredDigitRoles(desired: DesiredRoles): DigitRole[] {
  const roles = new Map<string, DigitRole>();
  for (const [tenantId, codes] of desired) {
    for (const code of [...config.digitManagedBaseRoles, ...codes]) {
      if (!config.digitManagedRoleAllowlist.includes(code) &&
          !config.digitManagedBaseRoles.includes(code)) continue;
      roles.set(`${tenantId}:${code}`, { code, name: code, tenantId });
    }
  }
  return [...roles.values()].sort((left, right) =>
    `${left.tenantId}:${left.code}`.localeCompare(`${right.tenantId}:${right.code}`));
}

function roleSet(roles: DigitRole[]): string {
  return [...new Set(roles.map((role) => `${role.tenantId}:${role.code}`))].sort().join(",");
}

/** Fields written back on update. Managed accounts carry no other profile data. */
function editable(account: DigitAccount): DigitAccountInput {
  return {
    id: account.id,
    uuid: account.uuid,
    userName: account.userName,
    name: account.name,
    mobileNumber: account.mobileNumber,
    emailId: account.emailId,
    tenantId: account.tenantId,
    type: account.type,
    active: account.active,
    identificationMark: account.identificationMark,
    roles: account.roles,
  };
}

async function cachedLogin(identity: ManagedIdentity): Promise<DigitLogin | null> {
  const raw = await getRedis().get(tokenKey(identity));
  if (!raw) return null;
  try {
    const login = JSON.parse(raw) as DigitLogin;
    return login.expiresAt - config.digitTokenRefreshSkewSeconds * 1000 > Date.now() ? login : null;
  } catch {
    return null;
  }
}

async function cacheLogin(identity: ManagedIdentity, login: DigitLogin): Promise<void> {
  const ttl = Math.floor((login.expiresAt - Date.now()) / 1000) - config.digitTokenRefreshSkewSeconds;
  if (ttl > 0) await getRedis().set(tokenKey(identity), JSON.stringify(login), "EX", ttl);
}

async function dropCachedLogin(identity: ManagedIdentity): Promise<void> {
  const raw = await getRedis().get(tokenKey(identity));
  await getRedis().del(tokenKey(identity));
  if (!raw) return;
  try {
    await revokeToken((JSON.parse(raw) as DigitLogin).accessToken);
  } catch (error) {
    console.warn("DIGIT token revocation failed:", (error as Error).message);
  }
}

export interface EnsureResult {
  account: DigitAccount | null;
  created: boolean;
  changed: boolean;
}

/**
 * Resolves the subject's managed DIGIT account and makes its roles and active
 * state match `desired`. Creates the account only when `profile` is supplied
 * and there is at least one desired tenant. Role or activation changes revoke
 * the cached user token so the next issuance reflects DIGIT's new grants.
 */
export async function ensureManagedAccount(
  identity: ManagedIdentity,
  desired: DesiredRoles,
  profile?: ManagedProfile,
): Promise<EnsureResult> {
  return withUserLease(identity, () => withDigitAdmin(async (adminToken) => {
    const account = await findAccount(adminToken, identity);
    const roles = desiredDigitRoles(desired);

    if (!account) {
      if (roles.length === 0 || !profile) return { account: null, created: false, changed: false };
      if (!profile.name.trim() || !profile.mobileNumber?.trim()) {
        throw new ManagedAccountError("A name and mobile number are required to create the DIGIT account");
      }
      const password = oneTimePassword();
      const created = await createAccount(adminToken, {
        userName: identity.username,
        name: profile.name.trim().slice(0, 50),
        mobileNumber: profile.mobileNumber.trim(),
        emailId: profile.emailId || null,
        tenantId: requireManagedTenant(),
        type: MANAGED_USER_TYPE,
        active: true,
        identificationMark: identity.marker,
        roles,
        password,
      });
      const login = await passwordLogin({
        username: identity.username, password, tenantId: created.tenantId, userType: MANAGED_USER_TYPE,
      });
      await cacheLogin(identity, login);
      await getRedis().hset(managedSubjectsKey(), identity.subject, identity.issuer);
      return { account: created, created: true, changed: true };
    }

    await getRedis().hset(managedSubjectsKey(), identity.subject, identity.issuer);
    if (roles.length === 0) {
      if (!account.active) return { account, created: false, changed: false };
      const updated = await updateAccount(adminToken, { ...editable(account), active: false });
      await dropCachedLogin(identity);
      return { account: updated, created: false, changed: true };
    }
    if (account.active && roleSet(account.roles) === roleSet(roles)) {
      return { account, created: false, changed: false };
    }
    const updated = await updateAccount(adminToken, { ...editable(account), active: true, roles });
    await dropCachedLogin(identity);
    return { account: updated, created: false, changed: true };
  }));
}

/**
 * Returns a normal user-scoped DIGIT token for an active managed account.
 * A valid cached token is reused. Otherwise, under the per-user lease, the
 * account's password is rotated to a new one-time value and the BFF logs in
 * once as that user.
 */
export async function managedUserLogin(identity: ManagedIdentity): Promise<DigitLogin> {
  const cached = await cachedLogin(identity);
  if (cached) return cached;
  return withUserLease(identity, async () => {
    const again = await cachedLogin(identity);
    if (again) return again;
    return withDigitAdmin(async (adminToken) => {
      const account = await findAccount(adminToken, identity);
      if (!account || !account.active) {
        throw new ManagedAccountError("No active DIGIT account is managed for this identity", 403);
      }
      const password = oneTimePassword();
      await updateAccount(adminToken, { ...editable(account), password });
      const login = await passwordLogin({
        username: identity.username, password, tenantId: account.tenantId, userType: MANAGED_USER_TYPE,
      });
      await cacheLogin(identity, login);
      return login;
    });
  });
}

/** Revokes and forgets the managed user's cached DIGIT token (logout). */
export async function revokeManagedUserLogin(identity: ManagedIdentity): Promise<void> {
  await withUserLease(identity, () => dropCachedLogin(identity));
}

export async function findManagedAccount(identity: ManagedIdentity): Promise<DigitAccount | null> {
  return withDigitAdmin((adminToken) => findAccount(adminToken, identity));
}
