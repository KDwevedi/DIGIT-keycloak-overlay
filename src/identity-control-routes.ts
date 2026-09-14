import { timingSafeEqual } from "node:crypto";
import type express from "express";
import { config } from "./config.js";
import {
  ensureOrganization,
  ensureOrganizationMembership,
  ensureOrganizationRoleAssignment,
  IdentityAdminError,
  readOrganizationMapping,
} from "./identity-admin.js";
import { currentSession } from "./identity-routes.js";
import { DigitUnavailableError } from "./digit-user-service.js";
import { runIdentityReconciliation } from "./identity-reconciliation.js";
import { syncSubject } from "./identity-provisioning.js";
import { clearTenantCaches, isActiveDigitTenant } from "./identity-tenants.js";
import { ManagedAccountError } from "./managed-digit-users.js";

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

function optionalString(value: unknown, name: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  return requiredString(value, name);
}

function handleAdminError(error: unknown, res: express.Response) {
  if (error instanceof IdentityAdminError || error instanceof ManagedAccountError) {
    return res.status(error.status).json({ error: error.message });
  }
  if (error instanceof DigitUnavailableError) {
    return res.status(error.status === 409 ? 409 : 502).json({ error: error.message });
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
      clearTenantCaches();
      if (!await isActiveDigitTenant(tenantId)) {
        throw new IdentityAdminError("The DIGIT tenant foundation does not exist yet", 409);
      }
      const organization = await ensureOrganization({ tenantId, alias, name });
      clearTenantCaches();
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

  // Adds Keycloak Organization membership, then resolves the member's managed
  // DIGIT account: created when absent (requires mobileNumber) and given the
  // Organization tenant's base and allowlisted group roles. Existing
  // locally managed DIGIT employees are never linked or modified.
  app.post("/internal/identity/v1/memberships/_ensure", asyncRoute(async (req, res) => {
    try {
      const organizationId = requiredString(req.body?.organizationId, "organizationId");
      const userId = requiredString(req.body?.userId, "userId");
      if (req.body?.digitUserUuid !== undefined) {
        throw new IdentityAdminError(
          "digitUserUuid is not supported: only BFF-managed DIGIT accounts are linked",
          400,
        );
      }
      const mobileNumber = optionalString(req.body?.mobileNumber, "mobileNumber") || "";
      const mapping = await readOrganizationMapping(organizationId);
      if (!mapping) {
        throw new IdentityAdminError("Organization is not mapped to a DIGIT tenant", 404);
      }
      await ensureOrganizationMembership({ organizationId, userId });
      const outcome = (await syncSubject(userId, mobileNumber)).get(mapping.tenantId);
      return res.json({
        tenantId: mapping.tenantId,
        digitUserUuid: outcome?.account?.uuid ?? null,
        created: outcome?.created ?? false,
      });
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
      const mapping = await readOrganizationMapping(organizationId);
      const outcome = (await syncSubject(userId)).get(mapping?.tenantId || "");
      return res.json({ assignment, digitUserUuid: outcome?.account?.uuid ?? null });
    } catch (error) {
      return handleAdminError(error, res);
    }
  }));

  app.post("/internal/identity/v1/reconciliation/_run", asyncRoute(async (_req, res) => {
    const result = await runIdentityReconciliation();
    return res.status(result.acquired ? 200 : 202).json(result);
  }));
}
