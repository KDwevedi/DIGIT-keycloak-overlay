import { createHash, randomUUID } from "node:crypto";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

interface Role { code: string; name?: string; tenantId: string }
interface Account {
  id: number;
  uuid: string;
  userName: string;
  name: string;
  mobileNumber: string | null;
  emailId: string | null;
  tenantId: string;
  type: string;
  active: boolean;
  identificationMark: string | null;
  roles: Role[];
  passwordHash: string;
}

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const POLICY = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%])\S{8,15}$/;

/**
 * Stateful stand-in for egov-user's user-service contract plus MDMS tenant
 * search. Stores only password hashes, like egov-user, and records every
 * plaintext it received so tests can prove none leaked into BFF storage.
 */
export function createFakeDigitUser(options: { tenants: string[] }) {
  const app = express();
  app.use(express.json());
  const accounts = new Map<string, Account>();
  const tokens = new Map<string, { uuid: string; expiresAt: number }>();
  const stats = { adminLogins: 0, userLogins: 0, creates: 0, updates: 0, passwordUpdates: 0, logouts: 0 };
  const receivedPasswords: string[] = [];
  let nextId = 1;
  let tokenTtlSeconds = 604800;

  function addAccount(input: Omit<Account, "id" | "uuid" | "passwordHash"> & { password: string }) {
    const { password, ...fields } = input;
    const account: Account = { ...fields, id: nextId++, uuid: randomUUID(), passwordHash: hash(password) };
    accounts.set(account.uuid, account);
    return account;
  }
  const publicAccount = ({ passwordHash: _hash, ...account }: Account) => account;
  const bearer = (req: express.Request) => {
    const token = req.body?.RequestInfo?.authToken as string | undefined;
    const entry = token ? tokens.get(token) : undefined;
    return entry && entry.expiresAt > Date.now() ? accounts.get(entry.uuid) : undefined;
  };
  const requireAdmin = (req: express.Request, res: express.Response) => {
    const caller = bearer(req);
    if (!caller) { res.status(401).json({ error: "invalid token" }); return null; }
    if (!caller.roles.some((role) => role.code === "ACCOUNT_ADMIN")) {
      res.status(403).json({ error: "forbidden" }); return null;
    }
    return caller;
  };

  app.post("/user/oauth/token", express.urlencoded({ extended: false }), (req, res) => {
    const account = [...accounts.values()].find((candidate) =>
      candidate.userName === req.body.username && candidate.tenantId === req.body.tenantId &&
      candidate.type === req.body.userType);
    if (!account || !account.active || account.passwordHash !== hash(String(req.body.password))) {
      return res.status(400).json({ error: "invalid_request", error_description: "Invalid login credentials" });
    }
    if (account.roles.some((role) => role.code === "ACCOUNT_ADMIN")) stats.adminLogins += 1;
    else stats.userLogins += 1;
    const existing = [...tokens.entries()].find(([, entry]) =>
      entry.uuid === account.uuid && entry.expiresAt > Date.now());
    const token = existing?.[0] || randomUUID();
    const expiresAt = existing?.[1].expiresAt || Date.now() + tokenTtlSeconds * 1000;
    tokens.set(token, { uuid: account.uuid, expiresAt });
    return res.json({
      access_token: token,
      token_type: "bearer",
      refresh_token: randomUUID(),
      expires_in: Math.floor((expiresAt - Date.now()) / 1000),
      // Deliberately noisy: the BFF must not pass unexpected fields through.
      UserRequest: { ...publicAccount(account), password: "must-not-leak" },
    });
  });

  app.post("/user/_search", (req, res) => {
    if (!requireAdmin(req, res)) return;
    const matches = [...accounts.values()].filter((account) =>
      account.userName === req.body.userName && account.tenantId === req.body.tenantId &&
      account.type === req.body.userType && account.active === (req.body.active !== false));
    return res.json({ user: matches.map(publicAccount) });
  });

  app.post("/user/users/_createnovalidate", (req, res) => {
    if (!requireAdmin(req, res)) return;
    const user = req.body.user;
    if (!POLICY.test(user.password || "") || !user.mobileNumber || !user.roles?.length) {
      return res.status(400).json({ error: "invalid user" });
    }
    if ([...accounts.values()].some((account) => account.userName === user.userName && account.tenantId === user.tenantId)) {
      return res.status(400).json({ error: "duplicate" });
    }
    receivedPasswords.push(user.password);
    stats.creates += 1;
    const account = addAccount({ ...user, password: user.password });
    return res.json({ user: [publicAccount(account)] });
  });

  app.post("/user/users/_updatenovalidate", (req, res) => {
    if (!requireAdmin(req, res)) return;
    const user = req.body.user;
    const account = accounts.get(user.uuid);
    if (!account) return res.status(400).json({ error: "not found" });
    if (!user.roles?.length) return res.status(400).json({ error: "roles required" });
    if (user.password) {
      if (!POLICY.test(user.password)) return res.status(400).json({ error: "INVALID_PWD_PATTERN" });
      receivedPasswords.push(user.password);
      account.passwordHash = hash(user.password);
      stats.passwordUpdates += 1;
    }
    stats.updates += 1;
    Object.assign(account, {
      name: user.name, mobileNumber: user.mobileNumber ?? account.mobileNumber, emailId: user.emailId,
      active: user.active ?? account.active, identificationMark: user.identificationMark, roles: user.roles,
    });
    return res.json({ user: [publicAccount(account)] });
  });

  app.post("/user/_logout", (req, res) => {
    const token = req.body?.RequestInfo?.authToken;
    if (!token || !tokens.delete(token)) return res.status(401).json({ error: "invalid token" });
    stats.logouts += 1;
    return res.json({ status: "ok" });
  });

  app.post("/mdms-v2/v1/_search", (req, res) => {
    const root = req.body?.MdmsCriteria?.tenantId;
    return res.json({ MdmsRes: { tenant: { tenants: options.tenants
      .filter((tenant) => tenant.split(".")[0] === root).map((code) => ({ code })) } } });
  });

  let server: Server;
  return {
    accounts, tokens, stats, receivedPasswords, addAccount,
    setTokenTtlSeconds(seconds: number) { tokenTtlSeconds = seconds; },
    expireAllTokens() { for (const entry of tokens.values()) entry.expiresAt = Date.now() - 1; },
    async start(): Promise<string> {
      server = app.listen(0);
      await new Promise((resolve) => server.once("listening", resolve));
      return `http://localhost:${(server.address() as AddressInfo).port}`;
    },
    async stop() { await new Promise((resolve) => server.close(resolve)); },
  };
}
