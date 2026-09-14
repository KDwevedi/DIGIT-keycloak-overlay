import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { closeCache, getRedis, initCache } from "../../src/cache.js";
import { config } from "../../src/config.js";
import { resetDigitAdminToken } from "../../src/digit-admin-token.js";
import {
  ensureManagedAccount,
  ManagedAccountError,
  managedIdentity,
  managedUserLogin,
  oneTimePassword,
  revokeManagedUserLogin,
} from "../../src/managed-digit-users.js";
import { createFakeDigitUser } from "../../mocks/fake-digit-user.js";

const ISSUER = "https://issuer.example/realms/digit";
const fake = createFakeDigitUser({ tenants: ["pg", "pg.citya"] });
let run = 0;

beforeAll(async () => {
  const base = await fake.start();
  Object.assign(config as any, {
    cachePrefix: `managed-test-${process.pid}`,
    digitUserServiceUrl: `${base}/user`,
    digitAdminUsername: "BFF-ADMIN",
    digitAdminPassword: "Adm1n@Secret",
    digitAdminTenantId: "pg",
    digitManagedUserTenantId: "pg",
    digitManagedBaseRoles: ["EMPLOYEE"],
    digitManagedRoleAllowlist: ["EMPLOYEE", "GRO", "PGR_VIEWER"],
    digitTokenRefreshSkewSeconds: 60,
    digitUserLeaseWaitMs: 5000,
  });
  initCache(`redis://localhost:${process.env.REDIS_PORT || "16379"}`);
  fake.addAccount({
    userName: "BFF-ADMIN", name: "BFF admin", mobileNumber: "0700000000", emailId: null,
    tenantId: "pg", type: "EMPLOYEE", active: true, identificationMark: null,
    roles: [{ code: "ACCOUNT_ADMIN", tenantId: "pg" }], password: "Adm1n@Secret",
  });
});

afterAll(async () => {
  const keys = await getRedis().keys(`${config.cachePrefix}:*`);
  if (keys.length) await getRedis().del(...keys);
  await closeCache();
  await fake.stop();
});

beforeEach(() => {
  run += 1;
  fake.setTokenTtlSeconds(604800);
});

const subject = () => `subject-${run}`;
const desired = (entries: Array<[string, string[]]>) => new Map(entries);
const profile = { name: "New Founder", emailId: "founder@example.org", mobileNumber: "0712345678" };

describe("managed DIGIT accounts", () => {
  it("generates policy-compliant, non-repeating one-time passwords", () => {
    const values = new Set(Array.from({ length: 200 }, () => oneTimePassword()));
    expect(values.size).toBe(200);
    for (const value of values) {
      expect(value).toMatch(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%])\S{15}$/);
    }
  });

  it("creates a marked account, logs in as that user, and never stores the password", async () => {
    const identity = managedIdentity(ISSUER, subject());
    const adminLogins = fake.stats.adminLogins;
    const result = await ensureManagedAccount(identity, desired([["pg", ["GRO"]]]), profile);
    expect(result.created).toBe(true);
    expect(result.account).toMatchObject({
      userName: identity.username, identificationMark: identity.marker, tenantId: "pg", type: "EMPLOYEE",
    });
    expect(result.account!.roles.map((role) => `${role.tenantId}:${role.code}`).sort())
      .toEqual(["pg:EMPLOYEE", "pg:GRO"]);

    const login = await managedUserLogin(identity);
    expect(fake.tokens.get(login.accessToken)?.uuid).toBe(result.account!.uuid);
    expect(fake.accounts.get(result.account!.uuid)!.roles.some((role) => role.code === "ACCOUNT_ADMIN")).toBe(false);
    expect(fake.stats.passwordUpdates).toBe(0);

    const stored = await Promise.all((await getRedis().keys(`${config.cachePrefix}:*`))
      .map(async (key) => `${key}=${await getRedis().type(key) === "hash"
        ? JSON.stringify(await getRedis().hgetall(key)) : await getRedis().get(key)}`));
    for (const password of fake.receivedPasswords) {
      expect(stored.join("\n")).not.toContain(password);
    }
    expect(stored.join("\n")).not.toContain("Adm1n@Secret");
    expect(stored.join("\n")).not.toContain("must-not-leak");
    expect(Object.keys(login.user)).not.toContain("password");
    expect(fake.stats.adminLogins - adminLogins).toBeLessThanOrEqual(1);
  });

  it("reuses a cached user token and rotates the password only when it must be regenerated", async () => {
    const identity = managedIdentity(ISSUER, subject());
    fake.setTokenTtlSeconds(3600);
    await ensureManagedAccount(identity, desired([["pg", []]]), profile);
    const first = await managedUserLogin(identity);
    const second = await managedUserLogin(identity);
    expect(second.accessToken).toBe(first.accessToken);
    const passwordsBefore = fake.receivedPasswords.length;

    fake.expireAllTokens();
    await getRedis().del(`${config.cachePrefix}:digit-user-token:${identity.key}`);
    const rotated = await managedUserLogin(identity);
    expect(rotated.accessToken).not.toBe(first.accessToken);
    expect(fake.receivedPasswords.length).toBe(passwordsBefore + 1);
    expect(new Set(fake.receivedPasswords).size).toBe(fake.receivedPasswords.length);
  });

  it("serializes concurrent regeneration for one user behind the Redis lease", async () => {
    const identity = managedIdentity(ISSUER, subject());
    await ensureManagedAccount(identity, desired([["pg", []]]), profile);
    fake.expireAllTokens();
    await getRedis().del(`${config.cachePrefix}:digit-user-token:${identity.key}`);
    const rotations = fake.stats.passwordUpdates;
    const logins = await Promise.all(Array.from({ length: 6 }, () => managedUserLogin(identity)));
    expect(new Set(logins.map((login) => login.accessToken)).size).toBe(1);
    expect(fake.stats.passwordUpdates - rotations).toBe(1);
  });

  it("never updates or rotates a legacy account that only shares the username", async () => {
    const identity = managedIdentity(ISSUER, subject());
    fake.addAccount({
      userName: identity.username, name: "Legacy", mobileNumber: "0711111111", emailId: null,
      tenantId: "pg", type: "EMPLOYEE", active: true, identificationMark: null,
      roles: [{ code: "EMPLOYEE", tenantId: "pg" }], password: "Legacy@1234",
    });
    const updates = fake.stats.updates;
    await expect(ensureManagedAccount(identity, desired([["pg", ["GRO"]]]), profile))
      .rejects.toBeInstanceOf(ManagedAccountError);
    await expect(managedUserLogin(identity)).rejects.toBeInstanceOf(ManagedAccountError);
    expect(fake.stats.updates).toBe(updates);
  });

  it("projects role changes, revokes the stale token, and deactivates former members", async () => {
    const identity = managedIdentity(ISSUER, subject());
    await ensureManagedAccount(identity, desired([["pg", []]]), profile);
    const before = await managedUserLogin(identity);

    const changed = await ensureManagedAccount(identity, desired([["pg", ["GRO"]], ["pg.citya", ["PGR_VIEWER"]]]));
    expect(changed.changed).toBe(true);
    expect(fake.tokens.has(before.accessToken)).toBe(false);
    expect(changed.account!.roles.map((role) => `${role.tenantId}:${role.code}`).sort()).toEqual([
      "pg.citya:EMPLOYEE", "pg.citya:PGR_VIEWER", "pg:EMPLOYEE", "pg:GRO",
    ]);
    expect((await ensureManagedAccount(identity, desired([["pg", ["GRO"]], ["pg.citya", ["PGR_VIEWER", "NOT_ALLOWED"]]]))).changed)
      .toBe(false);

    const renewed = await managedUserLogin(identity);
    const removed = await ensureManagedAccount(identity, new Map());
    expect(removed.account!.active).toBe(false);
    expect(fake.tokens.has(renewed.accessToken)).toBe(false);
    await expect(managedUserLogin(identity)).rejects.toMatchObject({ status: 403 });
  });

  it("requires a mobile number to create an account and does not create without a profile", async () => {
    const identity = managedIdentity(ISSUER, subject());
    await expect(ensureManagedAccount(identity, desired([["pg", []]]), { name: "No Phone" }))
      .rejects.toBeInstanceOf(ManagedAccountError);
    expect((await ensureManagedAccount(identity, desired([["pg", []]]))).account).toBeNull();
  });

  it("refreshes the cached admin token from environment credentials after DIGIT rejects it", async () => {
    resetDigitAdminToken();
    const identity = managedIdentity(ISSUER, subject());
    await ensureManagedAccount(identity, desired([["pg", []]]), profile);
    const adminLogins = fake.stats.adminLogins;
    for (const [token, entry] of fake.tokens) {
      const account = fake.accounts.get(entry.uuid);
      if (account?.roles.some((role) => role.code === "ACCOUNT_ADMIN")) fake.tokens.delete(token);
    }
    await ensureManagedAccount(identity, desired([["pg", ["GRO"]]]));
    expect(fake.stats.adminLogins).toBe(adminLogins + 1);
  });

  it("logout revokes the user's DIGIT token", async () => {
    const identity = managedIdentity(ISSUER, subject());
    await ensureManagedAccount(identity, desired([["pg", []]]), profile);
    const login = await managedUserLogin(identity);
    await revokeManagedUserLogin(identity);
    expect(fake.tokens.has(login.accessToken)).toBe(false);
  });
});
