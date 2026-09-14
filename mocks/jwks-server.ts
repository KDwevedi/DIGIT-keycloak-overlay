import {
  exportJWK,
  exportPKCS8,
  importPKCS8,
  generateKeyPair,
  SignJWT,
  type KeyLike,
} from "jose";
import express from "express";
import { writeFileSync, readFileSync, existsSync, unlinkSync } from "node:fs";
import { join } from "node:path";

let privateKey: KeyLike;
let publicJwk: any;
const KID = "test-key-1";
const ISSUER = "http://localhost:9999/realms/digit-sandbox";
const KEY_FILE = join(
  import.meta.dirname || process.cwd(),
  ".test-private-key.pem",
);
const PUB_FILE = join(
  import.meta.dirname || process.cwd(),
  ".test-public-key.json",
);

export async function initKeys() {
  if (existsSync(KEY_FILE) && existsSync(PUB_FILE)) {
    // Load existing keys (shared between globalSetup and worker)
    const pem = readFileSync(KEY_FILE, "utf-8");
    privateKey = await importPKCS8(pem, "RS256");
    publicJwk = JSON.parse(readFileSync(PUB_FILE, "utf-8"));
  } else {
    // Generate new keys and persist for sharing
    const keys = await generateKeyPair("RS256");
    privateKey = keys.privateKey;
    const pem = await exportPKCS8(keys.privateKey);
    writeFileSync(KEY_FILE, pem);
    const pub = await exportJWK(keys.publicKey);
    publicJwk = { ...pub, kid: KID, use: "sig", alg: "RS256" };
    writeFileSync(PUB_FILE, JSON.stringify(publicJwk));
  }
}

export function cleanupKeys() {
  try {
    if (existsSync(KEY_FILE)) unlinkSync(KEY_FILE);
    if (existsSync(PUB_FILE)) unlinkSync(PUB_FILE);
  } catch {}
}

export function getIssuer() {
  return ISSUER;
}

export async function signJwt(
  claims: Record<string, unknown>,
  opts?: { expiresIn?: string },
) {
  return new SignJWT(claims as any)
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime(opts?.expiresIn || "1h")
    .sign(privateKey);
}

export function createJwksApp() {
  const app = express();
  app.use(express.json());
  const digitOrganizations = new Map<string, Record<string, unknown>>();
  const digitMemberships = new Map<string, {
    issuer: string;
    subject: string;
    organizationId: string;
    active: boolean;
  }>();
  app.get(
    "/realms/digit-sandbox/protocol/openid-connect/certs",
    (_req, res) => {
      res.json({ keys: [publicJwk] });
    },
  );
  app.post(
    "/realms/digit-sandbox/protocol/openid-connect/token",
    express.urlencoded({ extended: false }),
    async (req, res) => {
      const grantType = req.body.grant_type;
      const validClient =
        req.body.client_id === "digit-identity-bff" &&
        req.body.client_secret === "test-bff-secret";
      const code = String(req.body.code || "");
      const nonce = code.startsWith("valid-code:")
        ? code.slice("valid-code:".length)
        : "";
      const validGrant = grantType === "authorization_code"
        ? Boolean(nonce) && Boolean(req.body.code_verifier)
        : grantType === "refresh_token"
          ? req.body.refresh_token === "refresh-1"
          : grantType === "urn:ietf:params:oauth:grant-type:token-exchange" &&
            Boolean(req.body.subject_token) &&
            req.body.audience === "digit-identity-exchange" &&
            (req.body.scope === "organization:bomet" ||
              req.body.scope === "organization:kisumu");
      if (!validClient || !validGrant) {
        return res.status(400).json({ error: "invalid_grant" });
      }

      const selectedAlias = grantType ===
        "urn:ietf:params:oauth:grant-type:token-exchange"
        ? String(req.body.scope).slice("organization:".length)
        : null;
      const organizations = {
        bomet: {
          id: "org-bomet-id",
          realm_access: { roles: ["TENANT_ADMIN"] },
        },
        kisumu: {
          id: "org-kisumu-id",
          realm_access: { roles: ["VIEWER"] },
        },
      };
      const accessToken = await signJwt({
        sub: "identity-user-1",
        email: "person@example.com",
        name: "Demo Person",
        preferred_username: "demo.person",
        azp: "digit-identity-bff",
        aud: selectedAlias ? "digit-identity-exchange" : "digit-identity-bff",
        organization: selectedAlias
          ? { [selectedAlias]: organizations[selectedAlias as keyof typeof organizations] }
          : organizations,
      });
      const idToken = await signJwt({
        sub: "identity-user-1",
        email: "person@example.com",
        name: "Demo Person",
        aud: "digit-identity-bff",
        nonce: grantType === "authorization_code" ? nonce : undefined,
      });
      return res.json({
        access_token: accessToken,
        refresh_token: "refresh-1",
        id_token: idToken,
        expires_in: grantType === "authorization_code" ? 1 : 300,
        refresh_expires_in: 3600,
        token_type: "Bearer",
      });
    },
  );
  app.post(
    "/realms/digit-sandbox/protocol/openid-connect/logout",
    express.urlencoded({ extended: false }),
    (_req, res) => res.status(204).end(),
  );

  const requireWorkload = (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => req.get("authorization") === "Bearer test-identity-workload"
    ? next()
    : res.status(401).json({ error: "unauthorized" });

  app.post("/internal/identity/v1/contexts/_resolve", requireWorkload, (req, res) => {
    if (req.body?.identity?.subject !== "identity-user-1") {
      return res.json({ contexts: [] });
    }
    const requested = new Set(
      (req.body?.organizations || []).map(
        (organization: { organizationId?: string }) => organization.organizationId,
      ),
    );
    const contexts = [
      {
        organizationId: "org-bomet-id",
        tenantId: "ke.bomet",
        name: "Bomet County",
        roles: ["TENANT_ADMIN"],
        active: true,
      },
      {
        organizationId: "org-kisumu-id",
        tenantId: "ke.kisumu",
        name: "Kisumu County",
        roles: ["VIEWER"],
        active: true,
      },
    ].filter((context) => requested.has(context.organizationId));
    return res.json({ contexts });
  });

  app.post("/internal/identity/v1/organizations/_ensure", requireWorkload, (req, res) => {
    digitOrganizations.set(req.body?.organizationId, {
      ...req.body,
      active: true,
    });
    return res.json({ tenantId: req.body?.tenantId });
  });

  app.post("/internal/identity/v1/subjects/_ensure", requireWorkload, (req, res) => {
    return res.json({ digitUserUuid: req.body?.digitUserUuid });
  });

  app.post("/internal/identity/v1/memberships/_reconcile", requireWorkload, (req, res) => {
    const key = `${req.body?.organizationId}:${req.body?.issuer}:${req.body?.subject}`;
    digitMemberships.set(key, {
      issuer: req.body?.issuer,
      subject: req.body?.subject,
      organizationId: req.body?.organizationId,
      active: req.body?.active !== false,
    });
    return res.json({ membershipId: "membership-1" });
  });

  app.post("/internal/identity/v1/reconciliation/_snapshot", requireWorkload, (_req, res) => {
    return res.json({
      organizations: [...digitOrganizations.values()].map((organization) => ({
        ...organization,
        members: [...digitMemberships.values()].filter(
          (member) => member.organizationId === organization.organizationId,
        ),
      })),
    });
  });

  app.post("/internal/identity/v1/sessions/_exchange", (req, res) => {
    const assertion = req.get("authorization")?.replace(/^Bearer /, "");
    if (!assertion) return res.status(401).json({ error: "missing assertion" });
    const payload = JSON.parse(
      Buffer.from(assertion.split(".")[1], "base64url").toString("utf8"),
    );
    const context = req.body?.context;
    const rolesByTenant: Record<string, string[]> = {
      "ke.bomet": ["TENANT_ADMIN"],
      "ke.kisumu": ["VIEWER"],
    };
    const roleCodes = rolesByTenant[context?.tenantId];
    const organization = payload.organization || {};
    const aliases = Object.keys(organization);
    const selectedAlias = context?.tenantId === "ke.bomet" ? "bomet" : "kisumu";
    if (!roleCodes || payload.sub !== "identity-user-1" ||
        payload.aud !== "digit-identity-exchange" ||
        aliases.length !== 1 || aliases[0] !== selectedAlias) {
      return res.status(403).json({ error: "not eligible" });
    }
    return res.json({
      access_token: `digit-token-${context.tenantId}`,
      refresh_token: "identity-service-secret-that-must-not-reach-the-browser",
      token_type: "bearer",
      expires_in: 900,
      UserRequest: {
        uuid: "digit-user-1",
        userName: "person@example.com",
        name: "Demo Person",
        emailId: "person@example.com",
        mobileNumber: "0700000001",
        tenantId: context.tenantId,
        type: "EMPLOYEE",
        roles: roleCodes.map((code) => ({
          code,
          name: code,
          tenantId: context.tenantId,
        })),
      },
    });
  });
  return app;
}
