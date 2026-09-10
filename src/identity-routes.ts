import type express from "express";
import { config } from "./config.js";
import {
  authorizationUrl,
  exchangeAuthorizationCode,
  logoutFromKeycloak,
  refreshIdentityTokens,
  verifyIdentityAccessToken,
} from "./identity-oidc.js";
import {
  clearedLoginCookie,
  clearedSessionCookie,
  consumeLoginAttempt,
  createIdentitySession,
  createLoginAttempt,
  deleteIdentitySession,
  getIdentitySession,
  loginCookie,
  loginStateFromCookie,
  saveIdentitySession,
  sessionCookie,
  sessionIdFromCookie,
} from "./identity-session.js";
import { tenantOptionsFromClaims } from "./tenant-options.js";
import type { IdentitySession } from "./types.js";

function asyncRoute(
  handler: (req: express.Request, res: express.Response) => Promise<unknown>,
): express.RequestHandler {
  return (req, res, next) => {
    void handler(req, res).catch(next);
  };
}

async function currentSession(
  cookieHeader?: string,
): Promise<{ sessionId: string; session: IdentitySession } | null> {
  const sessionId = sessionIdFromCookie(cookieHeader);
  if (!sessionId) return null;
  let session = await getIdentitySession(sessionId);
  if (!session) return null;

  if (session.accessExpiresAt > Date.now() + 30_000) {
    return { sessionId, session };
  }
  if (!session.refreshToken ||
      (session.refreshExpiresAt && session.refreshExpiresAt <= Date.now())) {
    await deleteIdentitySession(sessionId);
    return null;
  }

  try {
    const tokens = await refreshIdentityTokens(session.refreshToken);
    const claims = await verifyIdentityAccessToken(tokens.accessToken);
    if (claims.sub !== session.claims.sub) {
      throw new Error("Refreshed token changed subject");
    }
    tokens.refreshToken ||= session.refreshToken;
    if (!tokens.refreshExpiresIn && session.refreshExpiresAt) {
      tokens.refreshExpiresIn = Math.max(
        1,
        Math.floor((session.refreshExpiresAt - Date.now()) / 1000),
      );
    }
    await saveIdentitySession(sessionId, tokens, claims);
    session = (await getIdentitySession(sessionId))!;
    return { sessionId, session };
  } catch (error) {
    console.warn("Identity session refresh failed:", (error as Error).message);
    await deleteIdentitySession(sessionId);
    return null;
  }
}

export function registerIdentityRoutes(app: express.Application): void {
  app.use("/identity/v1", (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  app.get("/identity/v1/authorize", asyncRoute(async (_req, res) => {
    const { state, codeChallenge } = await createLoginAttempt();
    res.setHeader("Set-Cookie", loginCookie(state));
    return res.redirect(302, authorizationUrl(state, codeChallenge));
  }));

  app.get("/identity/v1/callback", asyncRoute(async (req, res) => {
    const code = typeof req.query.code === "string" ? req.query.code : null;
    const state = typeof req.query.state === "string" ? req.query.state : null;
    if (!state || loginStateFromCookie(req.headers.cookie) !== state) {
      res.setHeader("Set-Cookie", clearedLoginCookie());
      return res.status(400).json({ error: "Invalid sign-in callback" });
    }

    const attempt = await consumeLoginAttempt(state);
    if (!attempt || !code || req.query.error) {
      res.setHeader("Set-Cookie", clearedLoginCookie());
      return res.status(400).json({ error: "Sign-in attempt expired or was already used" });
    }

    try {
      const tokens = await exchangeAuthorizationCode(code, attempt.codeVerifier);
      const claims = await verifyIdentityAccessToken(tokens.accessToken);
      const { sessionId, maxAge } = await createIdentitySession(tokens, claims);
      res.setHeader("Set-Cookie", [
        sessionCookie(sessionId, maxAge),
        clearedLoginCookie(),
      ]);
      return res.redirect(303, config.identityPostLoginRedirect);
    } catch (error) {
      console.error("Identity callback failed:", (error as Error).message);
      res.setHeader("Set-Cookie", clearedLoginCookie());
      return res.status(502).json({ error: "Sign-in failed" });
    }
  }));

  app.get("/identity/v1/session", asyncRoute(async (req, res) => {
    const current = await currentSession(req.headers.cookie);
    if (!current) return res.status(401).json({ authenticated: false });
    const { claims } = current.session;
    return res.json({
      authenticated: true,
      user: {
        id: claims.sub,
        email: claims.email,
        name: claims.name,
        preferredUsername: claims.preferred_username,
      },
      expiresAt: current.session.accessExpiresAt,
    });
  }));

  app.get("/identity/v1/tenants", asyncRoute(async (req, res) => {
    const current = await currentSession(req.headers.cookie);
    if (!current) {
      return res.status(401).json({ error: "Invalid or missing identity session" });
    }
    const tenants = tenantOptionsFromClaims(
      current.session.claims,
      config.organizationTenantMappings,
    );
    return res.json({ tenants, selectionRequired: tenants.length > 1 });
  }));

  app.post("/identity/v1/logout", asyncRoute(async (req, res) => {
    const sessionId = sessionIdFromCookie(req.headers.cookie);
    if (sessionId) {
      const session = await getIdentitySession(sessionId);
      await deleteIdentitySession(sessionId);
      await logoutFromKeycloak(session?.refreshToken).catch((error) => {
        console.warn("Keycloak logout failed:", (error as Error).message);
      });
    }
    res.setHeader("Set-Cookie", clearedSessionCookie());
    return res.status(204).end();
  }));
}
