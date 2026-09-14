import { timingSafeEqual } from "node:crypto";
import type express from "express";
import { config } from "./config.js";
import {
  ensureOrganization,
  ensureOrganizationMembership,
  ensureOrganizationRoleAssignment,
  IdentityAdminError,
} from "./identity-admin.js";
import { currentSession } from "./identity-routes.js";
import {
  ensureDigitOrganization,
  ensureDigitSubject,
  reconcileDigitMembership,
} from "./digit-identity.js";
import { runIdentityReconciliation } from "./identity-reconciliation.js";

function asyncRoute(
  handler: (req: express.Request, res: express.Response) => Promise<unknown>,
): express.RequestHandler {
  return (req, res, next) => void handler(req, res).catch(next);
}

function sameSecret(actual: string, expected: string): boolean {
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new IdentityAdminError(`${name} is required`, 400);
  }
  return value.trim();
}

function handleAdminError(error: unknown, res: express.Response) {
  if (error instanceof IdentityAdminError) {
    return res.status(error.status).json({ error: error.message });
  }
  throw error;
}

export function registerIdentityControlRoutes(app: express.Application): void {
  app.use("/internal/identity/v1", (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    const introspection = req.path === "/sessions/_introspect";
    const expected = introspection
      ? config.identitySessionIntrospectionToken
      : config.identityControlPlaneToken;
    if (!expected) {
      return res.status(503).json({ error: "Identity control plane is not configured" });
    }
    const authorization = req.get("authorization") || "";
    const supplied = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : "";
    if (!supplied || !sameSecret(supplied, expected)) {
      return res.status(401).json({ error: "Invalid workload credential" });
    }
    next();
  });

  app.post("/internal/identity/v1/organizations/_ensure", asyncRoute(async (req, res) => {
    try {
      const tenantId = requiredString(req.body?.tenantId, "tenantId");
      const alias = requiredString(req.body?.alias, "alias");
      const name = requiredString(req.body?.name, "name");
      if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(alias)) {
        throw new IdentityAdminError("alias is invalid", 400);
      }
      const organization = await ensureOrganization({ tenantId, alias, name });
      await ensureDigitOrganization({
        organizationId: organization.id,
        alias,
        tenantId,
        name,
      });
      return res.json({ organization });
    } catch (error) {
      return handleAdminError(error, res);
    }
  }));

  app.post("/internal/identity/v1/sessions/_introspect", asyncRoute(async (req, res) => {
    const current = await currentSession(req.headers.cookie);
    if (!current) {
      return res.status(401).json({ error: "Invalid or missing identity session" });
    }
    const { claims } = current.session;
    return res.json({
      active: true,
      identity: {
        issuer: config.keycloakIssuer,
        subject: claims.sub,
        email: claims.email,
        name: claims.name,
        preferredUsername: claims.preferred_username,
      },
    });
  }));

  app.post("/internal/identity/v1/memberships/_ensure", asyncRoute(async (req, res) => {
    try {
      const organizationId = requiredString(req.body?.organizationId, "organizationId");
      const userId = requiredString(req.body?.userId, "userId");
      const digitUserUuid = requiredString(req.body?.digitUserUuid, "digitUserUuid");
      await ensureOrganizationMembership({ organizationId, userId });
      await ensureDigitSubject({
        issuer: config.keycloakIssuer,
        subject: userId,
        digitUserUuid,
      });
      return res.status(204).end();
    } catch (error) {
      return handleAdminError(error, res);
    }
  }));

  app.post("/internal/identity/v1/role-assignments/_ensure", asyncRoute(async (req, res) => {
    try {
      const organizationId = requiredString(req.body?.organizationId, "organizationId");
      const userId = requiredString(req.body?.userId, "userId");
      const groupName = requiredString(req.body?.groupName, "groupName");
      const clientId = requiredString(req.body?.clientId, "clientId");
      if (!Array.isArray(req.body?.roles) || req.body.roles.length === 0 ||
          !req.body.roles.every((role: unknown) => typeof role === "string" && role.trim())) {
        throw new IdentityAdminError("roles must be a non-empty string array", 400);
      }
      const roles = [...new Set<string>(
        req.body.roles.map((role: string) => role.trim()),
      )].sort();
      const assignment = await ensureOrganizationRoleAssignment({
        organizationId,
        userId,
        groupName,
        clientId,
        roles,
      });
      await reconcileDigitMembership({
        issuer: config.keycloakIssuer,
        subject: userId,
        organizationId,
        roles,
      });
      return res.json({ assignment });
    } catch (error) {
      return handleAdminError(error, res);
    }
  }));

  app.post("/internal/identity/v1/reconciliation/_run", asyncRoute(async (_req, res) => {
    const result = await runIdentityReconciliation();
    return res.status(result.acquired ? 200 : 202).json(result);
  }));
}
