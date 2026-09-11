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

  app.get("/healthz", async (_req, res) => {
    try {
      await getRedis().ping();
      return res.json({ status: "ok", redis: "connected" });
    } catch {
      return res.status(503).json({ status: "unhealthy", redis: "disconnected" });
    }
  });

  app.use((req, res, next) => {
    const origin = req.get("origin");
    if (req.path.startsWith("/identity/v1") && origin === config.identityAllowedOrigin) {
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
