import type express from "express";
import { config } from "./config.js";
import {
  authorizationUrl,
  exchangeAuthorizationCode,
  logoutFromKeycloak,
  refreshIdentityTokens,
  verifyIdentityAccessToken,
  verifyIdentityIdToken,
} from "./identity-oidc.js";
import {
  clearedLoginCookie,
  clearedSessionCookie,
  consumeLoginAttempt,
  createIdentitySession,
  createLoginAttempt,
  deleteIdentitySession,
  getIdentitySession,
  getSelectedIdentityContext,
  loginCookie,
  loginStateFromCookie,
  saveIdentitySession,
  saveSelectedIdentityContext,
  sessionCookie,
  sessionIdFromCookie,
} from "./identity-session.js";
import { DigitUnavailableError } from "./digit-user-service.js";
import {
  liveMembershipsForSubject,
  membershipsFromClaims,
  tenantOption,
  type TenantOption,
} from "./identity-tenants.js";
import {
  ensureManagedAccount,
  ManagedAccountError,
  managedIdentity,
  managedUserLogin,
  revokeManagedUserLogins,
} from "./managed-digit-users.js";
import type { IdentitySession, KCClaims } from "./types.js";
import { enabledIdentityMethods } from "./identity-methods.js";
import { IdentityAdminError, isOrganizationMember } from "./identity-admin.js";

function asyncRoute(
  handler: (req: express.Request, res: express.Response) => Promise<unknown>,
): express.RequestHandler {
  return (req, res, next) => {
    void handler(req, res).catch(next);
  };
}

function publicTenant({ organizationId: _organizationId, ...tenant }: TenantOption) {
  return tenant;
}

/**
 * Tenants present in both the session's Organization memberships and the
 * managed DIGIT account's grants. A missing account is created from these
 * claims (fresh at sign-in). An existing account's roles are never changed
 * here: session claims can be stale, so role projection comes only from live
 * Keycloak state through the control plane and reconciliation.
 */
async function resolveTenantContexts(claims: KCClaims, live = false): Promise<TenantOption[]> {
  const signedMemberships = await membershipsFromClaims(claims);
  const signedRoles = new Map(signedMemberships.map((membership) => [membership.tenantId, membership.roles]));
  const memberships = live
    ? await liveMembershipsForSubject(claims.sub)
    : signedMemberships;
  const profile = {
    name: claims.name || claims.preferred_username || "",
    emailId: claims.email_verified ? claims.email : undefined,
    mobileNumber: claims.phone_number,
  };
  const options: TenantOption[] = [];
  for (const membership of memberships) {
    // One managed DIGIT account per tenant: DIGIT's gateway authorizes a token
    // only for its account's home tenant.
    const identity = managedIdentity(config.keycloakIssuer, claims.sub, membership.tenantId);
    const { account } = await ensureManagedAccount(
      identity, signedRoles.get(membership.tenantId) ?? [], profile, { createOnly: true },
    ).catch((error) => {
      // A tenant lacking account prerequisites (e.g. no mobile yet) must not hide the others.
      if (error instanceof ManagedAccountError) return { account: null };
      throw error;
    });
    const option = tenantOption(membership, account);
    if (option) options.push(option);
  }
  return options;
}

function digitFailure(error: unknown, res: express.Response, message: string) {
  if (error instanceof ManagedAccountError) {
    return res.status(error.status).json({ error: error.message });
  }
  if (error instanceof DigitUnavailableError) {
    console.warn(`${message}:`, error.message);
    return res.status(503).json({ error: message });
  }
  throw error;
}

function trustedWriteOrigin(req: express.Request): boolean {
  const origin = req.get("origin");
  return !origin || config.identityAllowedOrigins.includes(origin);
}

export async function currentSession(
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

  app.get("/identity/v1/auth-methods", asyncRoute(async (_req, res) => {
    try {
      return res.json({ methods: await enabledIdentityMethods() });
    } catch (error) {
      if (error instanceof IdentityAdminError) {
        return res.status(503).json({ error: "Sign-in methods are temporarily unavailable" });
      }
      throw error;
    }
  }));

  app.get("/identity/v1/authorize", asyncRoute(async (req, res) => {
    const requestedMethod = typeof req.query.method === "string"
      ? req.query.method
      : "password";
    let methods;
    try {
      methods = await enabledIdentityMethods();
    } catch (error) {
      if (error instanceof IdentityAdminError) {
        return res.status(503).json({ error: "Sign-in methods are temporarily unavailable" });
      }
      throw error;
    }
    const method = methods.find((candidate) => candidate.id === requestedMethod);
    if (!method) return res.status(400).json({ error: "Unsupported sign-in method" });

    const { state, codeChallenge, nonce } = await createLoginAttempt();
    res.setHeader("Set-Cookie", loginCookie(state));
    return res.redirect(
      302,
      authorizationUrl(state, codeChallenge, nonce, method.idpHint),
    );
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
      const idClaims = await verifyIdentityIdToken(tokens.idToken, attempt.nonce);
      if (idClaims.sub !== claims.sub) {
        throw new Error("Keycloak token subjects do not match");
      }
      const { sessionId, maxAge } = await createIdentitySession(tokens, claims);
      await resolveTenantContexts(claims).catch((error) => {
        console.warn("DIGIT account resolution after sign-in failed:", (error as Error).message);
      });
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
    const context = await getSelectedIdentityContext(current.sessionId);
    return res.json({
      authenticated: true,
      user: {
        id: claims.sub,
        email: claims.email,
        name: claims.name,
        preferredUsername: claims.preferred_username,
      },
      context: context ? {
        tenantId: context.tenantId,
        name: context.name,
        organizationAlias: context.organizationAlias,
      } : null,
      expiresAt: current.session.accessExpiresAt,
    });
  }));

  app.get("/identity/v1/tenants", asyncRoute(async (req, res) => {
    const current = await currentSession(req.headers.cookie);
    if (!current) {
      return res.status(401).json({ error: "Invalid or missing identity session" });
    }
    try {
      // Use live membership because onboarding can add an Organization after
      // this browser session's access token was issued.
      const tenants = await resolveTenantContexts(current.session.claims, true);
      return res.json({
        tenants: tenants.map(publicTenant),
        selectionRequired: tenants.length > 1,
        onboardingRequired: tenants.length === 0,
      });
    } catch (error) {
      return digitFailure(error, res, "Tenant options are temporarily unavailable");
    }
  }));

  app.post("/identity/v1/contexts/_select", asyncRoute(async (req, res) => {
    if (!trustedWriteOrigin(req)) {
      return res.status(403).json({ error: "Untrusted request origin" });
    }
    const current = await currentSession(req.headers.cookie);
    if (!current) {
      return res.status(401).json({ error: "Invalid or missing identity session" });
    }
    const tenantId = typeof req.body?.tenantId === "string"
      ? req.body.tenantId.trim()
      : "";
    if (!tenantId) return res.status(400).json({ error: "tenantId is required" });

    try {
      const tenants = await resolveTenantContexts(current.session.claims, true);
      const selected = tenants.find((tenant) => tenant.tenantId === tenantId);
      if (!selected) {
        return res.status(403).json({ error: "Tenant context is not available" });
      }
      // Session claims can be up to one access-token lifetime old; confirm the
      // membership is still live in Keycloak before issuing DIGIT credentials.
      const subject = current.session.claims.sub;
      if (!await isOrganizationMember(selected.organizationId, subject)) {
        return res.status(403).json({ error: "Tenant context is not available" });
      }
      const login = await managedUserLogin(managedIdentity(config.keycloakIssuer, subject, selected.tenantId));
      const saved = await saveSelectedIdentityContext(current.sessionId, {
        organizationId: selected.organizationId,
        organizationAlias: selected.organizationAlias,
        tenantId: selected.tenantId,
        name: selected.name,
      });
      if (!saved) {
        return res.status(401).json({ error: "Identity session expired" });
      }
      // The normal egov-user login response, minus its refresh token, so existing
      // frontends keep sending RequestInfo.authToken unchanged. Keycloak tokens
      // and the admin token never leave the BFF.
      return res.json({
        access_token: login.accessToken,
        token_type: "bearer",
        expires_in: Math.max(1, Math.floor((login.expiresAt - Date.now()) / 1000)),
        scope: "read",
        UserRequest: login.user,
      });
    } catch (error) {
      return digitFailure(error, res, "Sign-in context is temporarily unavailable");
    }
  }));

  app.post("/identity/v1/logout", asyncRoute(async (req, res) => {
    if (!trustedWriteOrigin(req)) {
      return res.status(403).json({ error: "Untrusted request origin" });
    }
    const sessionId = sessionIdFromCookie(req.headers.cookie);
    if (sessionId) {
      const session = await getIdentitySession(sessionId);
      await deleteIdentitySession(sessionId);
      if (session) {
        // The browser held a copy of the DIGIT token; revoke it with the session.
        await revokeManagedUserLogins(config.keycloakIssuer, session.claims.sub)
          .catch((error: Error) => {
            console.warn("DIGIT token revocation failed:", (error as Error).message);
          });
      }
      await logoutFromKeycloak(session?.refreshToken).catch((error) => {
        console.warn("Keycloak logout failed:", (error as Error).message);
      });
    }
    res.setHeader("Set-Cookie", clearedSessionCookie());
    return res.status(204).end();
  }));
}
