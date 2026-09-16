import express from "express";
import { getRedis } from "./cache.js";
import { config } from "./config.js";
import { registerIdentityControlRoutes } from "./identity-control-routes.js";
import { registerIdentityRoutes } from "./identity-routes.js";

/**
 * The standalone identity boundary. Keep this application free of DIGIT
 * domain-service imports: PGR and other onboarding services are callers, not
 * dependencies.
 */
export function createIdentityApp(): express.Application {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.get("/livez", (_req, res) => res.json({ status: "ok" }));

  app.get("/healthz", async (_req, res) => {
    try {
      await getRedis().ping();
      return res.json({ status: "ok", redis: "connected" });
    } catch {
      return res.status(503).json({ status: "unhealthy", redis: "disconnected" });
    }
  });

  app.get("/readyz", async (_req, res) => {
    const checks: Record<string, string> = {};
    try {
      await getRedis().ping();
      checks.redis = "connected";
      const jwks = await fetch(config.keycloakJwksUri, {
        signal: AbortSignal.timeout(config.digitTimeoutMs),
      });
      if (!jwks.ok) throw new Error(`JWKS ${jwks.status}`);
      checks.keycloak = "connected";
      if (config.digitMdmsSearchUrl) {
        const mdms = await fetch(config.digitMdmsSearchUrl, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            RequestInfo: { apiId: "digit-identity-bff-readiness" },
            MdmsCriteria: {
              tenantId: config.digitFoundationSourceTenant,
              moduleDetails: [{ moduleName: "tenant", masterDetails: [{ name: "tenants" }] }],
            },
          }),
          signal: AbortSignal.timeout(config.digitTimeoutMs),
        });
        if (!mdms.ok) throw new Error(`MDMS ${mdms.status}`);
        checks.mdms = "connected";
      }
      if (config.digitUserServiceUrl) {
        const users = await fetch(`${config.digitUserServiceUrl.replace(/\/$/, "")}/_search`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ RequestInfo: { apiId: "digit-identity-bff-readiness" } }),
          signal: AbortSignal.timeout(config.digitTimeoutMs),
        });
        // 4xx still proves the user service/gateway is reachable; readiness is
        // not allowed to use or mint an admin credential.
        if (users.status >= 500) throw new Error(`egov-user ${users.status}`);
        await users.body?.cancel();
        checks.userService = "connected";
      }
      return res.json({ status: "ready", checks });
    } catch (error) {
      return res.status(503).json({
        status: "not_ready", checks, error: (error as Error).message,
      });
    }
  });

  app.use((req, res, next) => {
    const origin = req.get("origin");
    if (req.path.startsWith("/identity/v1") && origin && config.identityAllowedOrigins.includes(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Vary", "Origin");
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });

  registerIdentityRoutes(app);
  registerIdentityControlRoutes(app);
  return app;
}
