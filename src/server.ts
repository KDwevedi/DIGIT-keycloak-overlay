import express from "express";
import { config } from "./config.js";
import { initJwks, validateJwt } from "./jwt.js";
import { initCache, getRedis, closeCache, setCached } from "./cache.js";
import {
  initSystemToken,
  startTokenRefresh,
  stopTokenRefresh,
} from "./digit-client.js";
import { resolveUser } from "./user-resolver.js";
import { initRoutes } from "./routes.js";
import { proxyRequest, forwardToGateway } from "./proxy.js";
import { searchKeycloakUser, createKeycloakUser, getAdminToken, deriveKcPassword } from "./keycloak-admin.js";
import { initKcAdmin, stopKcAdminRefresh, syncTenantRealms } from "./kc-admin.js";
import { searchUserByUserName, getSystemToken } from "./digit-client.js";
import { registerPlatformAdminRoutes } from "./platform-admin.js";
import { tenantOptionsFromClaims } from "./tenant-options.js";

// Decode JWT payload without verification (for extracting sub from KC access tokens)
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[1], "base64url").toString());
  } catch { return null; }
}

// Pre-cache DIGIT user mapping after successful login so proxy calls resolve correctly.
// Without this, the resolver can't map KC JWT claims back to the DIGIT user
// (KC preferred_username is lowercase, DIGIT userName may be uppercase, and
// KC JWT realm_access.roles don't include DIGIT roles).
async function preCacheDigitUser(
  accessToken: string,
  digitUser: { uuid: string; userName: string; name: string; emailId: string; mobileNumber: string; tenantId: string; type: string; roles: Array<{ code: string; name: string; tenantId?: string }> },
  tenantId: string,
) {
  const payload = decodeJwtPayload(accessToken);
  if (!payload?.sub) return;
  const sub = payload.sub as string;
  const session = {
    user: digitUser,
    cachedAt: Date.now(),
    token: getSystemToken(),
    tokenExpiry: Date.now() + 24 * 60 * 60 * 1000,
  };
  // Cache at the provided tenant level
  await setCached(sub, tenantId, session);
  // Also cache at state and default tenant levels so proxy calls
  // with different tenantId values still resolve correctly
  const stateTenant = config.digitSystemTenant;
  const defaultTenant = config.digitDefaultTenant;
  const extras = [stateTenant, defaultTenant].filter(t => t && t !== tenantId);
  for (const t of extras) {
    await setCached(sub, t, session);
  }
  console.log(`[KC-TOKEN] Pre-cached: sub=${sub} → ${digitUser.userName} (${digitUser.type}, tenants=${[tenantId, ...extras].join(",")})`);
}

// Forward a request to Keycloak as-is (for non-password-grant flows)
async function forwardToKeycloak(
  req: express.Request,
  res: express.Response,
  realm: string,
) {
  const kcUrl = `${config.keycloakAdminUrl}/realms/${realm}/protocol/openid-connect/token`;
  const kcResp = await fetch(kcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(req.body as Record<string, string>).toString(),
  });
  const data = await kcResp.text();
  res.status(kcResp.status).type("json").send(data);
}

export async function createApp() {
  const app = express();
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: true, limit: "10mb" }));

  app.get("/healthz", async (_req, res) => {
    try {
      const redis = getRedis();
      await redis.ping();
      res.json({ status: "ok", redis: "connected" });
    } catch {
      res.status(503).json({ status: "unhealthy", redis: "disconnected" });
    }
  });

  // Request logger — every request gets logged
  app.use((req, _res, next) => {
    const authHeader = req.headers.authorization ? "yes" : "no";
    const bodyToken = req.body?.RequestInfo?.authToken ? "yes" : "no";
    console.log(`[REQ] ${req.method} ${req.originalUrl} | Auth header: ${authHeader} | Body authToken: ${bodyToken}`);
    next();
  });

  // Boundary request rewrite — the generic DIGIT UI boundary component uses
  // state-level tenantId (e.g. "pg") but boundary data is seeded at city
  // level (e.g. "pg.citya"). It also omits boundaryType which the API requires
  // to return actual boundary nodes. Fix both issues in the proxy layer.
  app.use((req, _res, next) => {
    if (!req.path.startsWith("/boundary-service/")) return next();

    const stateTenant = config.digitSystemTenant;  // "pg"
    const cityTenant = config.digitDefaultTenant;   // "pg.citya"
    let urlChanged = false;

    // Fix URL query param: tenantId=pg → tenantId=pg.citya for relationship searches
    if (req.query.tenantId === stateTenant) {
      req.query.tenantId = cityTenant;
      urlChanged = true;
    }

    // Add missing boundaryType for relationship searches (API returns 0 results without it)
    if (req.path.includes("boundary-relationships") && !req.query.boundaryType) {
      req.query.boundaryType = "City";
      urlChanged = true;
    }

    // Rebuild URL if any query params changed
    if (urlChanged) {
      const url = new URL(req.originalUrl, `http://${req.headers.host || "localhost"}`);
      for (const [k, v] of Object.entries(req.query)) {
        if (typeof v === "string") url.searchParams.set(k, v);
      }
      const newPath = url.pathname + url.search;
      console.log(`[BOUNDARY-FIX] ${req.originalUrl} → ${newPath}`);
      req.url = newPath;
      req.originalUrl = newPath;
    }

    // Fix POST body: BoundaryTypeHierarchySearchCriteria.tenantId (often hardcoded as "dev")
    const criteria = req.body?.BoundaryTypeHierarchySearchCriteria;
    if (criteria?.tenantId && criteria.tenantId !== stateTenant && criteria.tenantId !== cityTenant) {
      console.log(`[BOUNDARY-FIX] Body tenantId: ${criteria.tenantId} → ${stateTenant}`);
      criteria.tenantId = stateTenant;
    }
    next();
  });

  // PGR create payload sanitizer.
  //
  // egov-persister maps the incoming kafka message via JsonPath. The rule
  // for the PGR address row extracts `$.service.address.geoLocation.latitude`
  // / `.longitude` directly — a JsonPath defaults-or-null helper isn't
  // configured, so a `geoLocation: null` (which the citizen SPA sends when
  // the user doesn't / can't pick a map pin) causes the persister to throw
  // PathNotFoundException, roll back the INSERT, and seek back to the same
  // offset forever. Net effect: no PGR complaint can persist until the
  // poison message is skipped, AND every future complaint without geo data
  // hits the same wall.
  //
  // Fix at the proxy: when forwarding a PGR _create with a null
  // geoLocation, substitute a sentinel `{latitude: 0, longitude: 0}` so
  // the persister's JsonPath query resolves. The downstream is unaffected
  // (egov-pgr-services itself doesn't validate this field) and the row
  // lands cleanly. SPA stays unchanged.
  app.use((req, _res, next) => {
    if (!req.path.endsWith("/pgr-services/v2/request/_create")) return next();
    const svc = req.body?.service;
    if (svc && svc.address && svc.address.geoLocation === null) {
      svc.address.geoLocation = { latitude: 0, longitude: 0 };
      console.log(
        `[PGR-FIX] Substituted null geoLocation with {0,0} on _create to avoid persister PathNotFoundException`,
      );
    }

    next();
  });

  // CORS for browser requests
  app.use((_req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (_req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });

  // Register endpoint: create user in Keycloak
  app.post("/register", async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ error: "email, password, and name are required" });
    }
    try {
      await createKeycloakUser({ email, password, name });
      res.status(201).json({ success: true, email });
    } catch (err: any) {
      if (err.message === "User already exists") {
        return res.status(409).json({ error: "User already exists" });
      }
      console.error("Register error:", err);
      res.status(500).json({ error: "Registration failed", message: String(err) });
    }
  });

  // Check if email exists in Keycloak
  app.get("/check-email", async (req, res) => {
    const email = req.query.email as string;
    if (!email) {
      return res.status(400).json({ error: "email query param required" });
    }
    try {
      const exists = await searchKeycloakUser(email);
      res.json({ exists });
    } catch (err) {
      console.error("Check email error:", err);
      res.status(500).json({ error: "Check failed", exists: false });
    }
  });

  // Resolve KC JWT → DIGIT user profile.
  // The UI calls this after Keycloak login to learn the user's type (CITIZEN/EMPLOYEE),
  // roles, and tenantId — so it can route to the correct portal and set storage keys.
  app.get("/userinfo", async (req, res) => {
    try {
      const claims = await validateJwt(req.headers.authorization).catch(() => null);
      if (!claims) {
        console.log(`[USERINFO] 401 — no valid KC JWT in Authorization header`);
        return res.status(401).json({ error: "Invalid or missing Keycloak token" });
      }

      console.log(`[USERINFO] Resolving KC user: ${claims.email} (sub=${claims.sub})`);
      const tenantId = (req.query.tenantId as string) || config.digitDefaultTenant;
      const { user, token } = await resolveUser(claims, tenantId);
      console.log(`[USERINFO] → ${user.userName} (${user.type}, uuid=${user.uuid})`);

      // Return BOTH the OIDC-standard claim names (sub, email, phone_number,
      // preferred_username) AND the DIGIT-native field names (uuid, emailId,
      // mobileNumber, userName). The citizen SPA reads phone_number / email
      // following the OIDC contract; older DIGIT call sites read the
      // DIGIT-native shape. Returning both keeps the overlay backward-
      // compatible without forcing every consumer to migrate at once.
      res.json({
        // OIDC-standard claim names
        sub: user.uuid,
        preferred_username: user.userName,
        name: user.name,
        email: user.emailId,
        phone_number: user.mobileNumber,
        // DIGIT-native field names (existing consumers)
        uuid: user.uuid,
        userName: user.userName,
        emailId: user.emailId,
        mobileNumber: user.mobileNumber,
        tenantId: user.tenantId,
        type: user.type,
        roles: user.roles,
      });
    } catch (err) {
      console.error("Userinfo error:", err);
      res.status(500).json({ error: "Failed to resolve user" });
    }
  });

  // Return only tenant choices proven by this realm's signed Organization
  // claim and the server-owned Organization ID -> DIGIT tenant mapping.
  // The browser cannot add a tenant or role by submitting its own values.
  app.get("/identity/v1/tenants", async (req, res) => {
    const claims = await validateJwt(req.headers.authorization, {
      issuer: config.keycloakIssuer,
      audience: config.keycloakAudience,
    }).catch(() => null);

    if (!claims) {
      return res.status(401).json({ error: "Invalid or missing Keycloak token" });
    }

    const tenants = tenantOptionsFromClaims(
      claims,
      config.organizationTenantMappings,
    );
    return res.json({ tenants, selectionRequired: tenants.length > 1 });
  });

  // Keycloak token endpoint with lazy DIGIT→KC user provisioning.
  // When a user logs in with DIGIT credentials that KC doesn't know about,
  // we verify against DIGIT first, then auto-create the KC account.
  app.post("/realms/:realm/protocol/openid-connect/token", async (req, res) => {
    const { realm } = req.params;
    const grantType = req.body?.grant_type;
    const username = req.body?.username;
    const password = req.body?.password;
    // Tenant can come from form body (UI sends it) or default
    const tenantId = req.body?.tenantId || config.digitSystemTenant;

    // Only intercept password grants — other flows (refresh, code) go straight to KC
    if (grantType !== "password" || !username || !password) {
      return forwardToKeycloak(req, res, realm);
    }

    // Step 1: Try KC auth first
    const kcUrl = `${config.keycloakAdminUrl}/realms/${realm}/protocol/openid-connect/token`;
    const kcBody = new URLSearchParams(req.body as Record<string, string>);
    // Remove tenantId from KC request — KC doesn't understand it
    kcBody.delete("tenantId");
    const kcResp = await fetch(kcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: kcBody.toString(),
    });

    if (kcResp.ok) {
      const data = await kcResp.json();
      // Look up DIGIT user so the frontend gets correct type + roles
      let userType = "CITIZEN";
      let digitRoles: Array<{ code: string; name: string; tenantId?: string }> = [];
      let foundDigitUser: any = null;
      try {
        for (const tryType of ["EMPLOYEE", "CITIZEN"]) {
          const u = await searchUserByUserName(username, tenantId, tryType);
          if (u) {
            userType = tryType;
            digitRoles = u.roles || [];
            foundDigitUser = u;
            break;
          }
        }
      } catch {}
      (data as any).digit_user_type = userType;
      (data as any).digit_roles = digitRoles;
      console.log(`[KC-TOKEN] ${username} — KC auth OK (${userType}, ${digitRoles.length} roles)`);
      // Pre-cache so proxy calls resolve this KC user → DIGIT user correctly
      if (foundDigitUser && (data as any).access_token) {
        preCacheDigitUser((data as any).access_token, foundDigitUser, tenantId).catch(() => {});
      }
      return res.json(data);
    }

    const kcErrBody = await kcResp.text();

    // KC auth failed — try DIGIT lazy provisioning
    console.log(`[KC-TOKEN] ${username} — KC auth failed (${kcResp.status}), trying DIGIT fallback (tenant=${tenantId})`);

    // Step 2: Try DIGIT auth (employee first, then citizen)
    let digitToken: string | null = null;
    let digitUserType: string | null = null;
    for (const userType of ["EMPLOYEE", "CITIZEN"]) {
      const digitResp = await fetch(`${config.digitUserHost}/user/oauth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: "Basic ZWdvdi11c2VyLWNsaWVudDo=",
        },
        body: new URLSearchParams({
          username,
          password,
          tenantId,
          userType,
          grant_type: "password",
          scope: "read",
        }).toString(),
      });
      if (digitResp.ok) {
        const data = (await digitResp.json()) as { access_token: string };
        digitToken = data.access_token;
        digitUserType = userType;
        break;
      }
    }

    if (!digitToken || !digitUserType) {
      console.log(`[KC-TOKEN] ${username} — DIGIT auth also failed, returning KC error`);
      return res.status(kcResp.status).type("json").send(kcErrBody);
    }

    console.log(`[KC-TOKEN] ${username} — DIGIT auth OK as ${digitUserType}, provisioning KC user`);

    // Step 3: Get DIGIT user details
    const digitUser = await searchUserByUserName(username, tenantId, digitUserType);
    if (!digitUser) {
      console.error(`[KC-TOKEN] ${username} — DIGIT auth OK but user search failed`);
      return res.status(kcResp.status).type("json").send(kcErrBody);
    }

    const email = digitUser.emailId || `${username.toLowerCase()}@digit.local`;
    const displayName = digitUser.name || username;

    // DIGIT remains the credential source of truth (OTP for citizens, real
    // password for employees). KC's stored password is internal plumbing —
    // we derive a strong deterministic value so the realm's password policy
    // is satisfied (citizens' 6-digit OTP would be rejected) AND the retry
    // step below can reproduce it without state.
    const kcPassword = deriveKcPassword(digitUser.uuid || username);

    // Step 4: Create KC user — use DIGIT username as KC username (not email)
    // so the login form username matches what KC expects
    try {
      await createKeycloakUser({ email, password: kcPassword, name: displayName, username });
      console.log(`[KC-TOKEN] ${username} — KC user created (email=${email})`);
    } catch (err: any) {
      if (err.message !== "User already exists") {
        console.error(`[KC-TOKEN] ${username} — KC user creation failed:`, err.message);
        return res.status(500).json({ error: "KC provisioning failed" });
      }
      // User exists — reset KC password to the derived value so the retry
      // below can authenticate. (Existing accounts may have stale passwords
      // from previous provisioning attempts or manual creation.)
      console.log(`[KC-TOKEN] ${username} — KC user exists, resetting to derived password`);
      try {
        const adminToken = await getAdminToken();
        const searchResp = await fetch(
          `${config.keycloakAdminUrl}/admin/realms/${realm}/users?username=${encodeURIComponent(username)}&exact=true`,
          { headers: { Authorization: `Bearer ${adminToken}` } }
        );
        const kcUsers = (await searchResp.json()) as Array<{ id: string }>;
        if (kcUsers.length > 0) {
          await fetch(
            `${config.keycloakAdminUrl}/admin/realms/${realm}/users/${kcUsers[0].id}/reset-password`,
            {
              method: "PUT",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${adminToken}`,
              },
              body: JSON.stringify({ type: "password", value: kcPassword, temporary: false }),
            }
          );
        }
      } catch (pwErr) {
        console.error(`[KC-TOKEN] ${username} — password reset failed:`, (pwErr as Error).message);
      }
    }

    // Step 4b: Assign DIGIT roles in KC (fire-and-forget)
    if (digitUser.roles?.length) {
      (async () => {
        try {
          const adminToken = await getAdminToken();
          const searchResp = await fetch(
            `${config.keycloakAdminUrl}/admin/realms/${realm}/users?username=${encodeURIComponent(username)}&exact=true`,
            { headers: { Authorization: `Bearer ${adminToken}` } }
          );
          const kcUsers = (await searchResp.json()) as Array<{ id: string }>;
          if (kcUsers.length === 0) return;
          const kcUserId = kcUsers[0].id;

          const rolesResp = await fetch(
            `${config.keycloakAdminUrl}/admin/realms/${realm}/roles`,
            { headers: { Authorization: `Bearer ${adminToken}` } }
          );
          const availableRoles = (await rolesResp.json()) as Array<{ id: string; name: string }>;
          const availableMap = new Map(availableRoles.map(r => [r.name, r]));

          const rolesToAssign = digitUser.roles
            .map(r => availableMap.get(r.code))
            .filter(Boolean);
          if (rolesToAssign.length > 0) {
            await fetch(
              `${config.keycloakAdminUrl}/admin/realms/${realm}/users/${kcUserId}/role-mappings/realm`,
              {
                method: "POST",
                headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
                body: JSON.stringify(rolesToAssign),
              }
            );
            console.log(`[KC-TOKEN] ${username} — assigned ${rolesToAssign.length} KC realm roles`);
          }
        } catch (err) {
          console.warn(`[KC-TOKEN] ${username} — role sync failed (non-fatal):`, (err as Error).message);
        }
      })();
    }

    // Step 5: Retry KC auth using the derived password we just wrote to KC.
    // The user's submitted password (OTP / DIGIT password) is intentionally
    // NOT used here — KC never sees it.
    const retryBody = new URLSearchParams(kcBody);
    retryBody.set("password", kcPassword);
    const retryResp = await fetch(kcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: retryBody.toString(),
    });

    if (retryResp.ok) {
      const data = await retryResp.json();
      (data as any).digit_user_type = digitUserType;
      (data as any).digit_roles = digitUser.roles || [];
      console.log(`[KC-TOKEN] ${username} — KC retry OK, lazy provisioning complete (${digitUserType}, ${(digitUser.roles || []).length} roles)`);
      // Pre-cache so proxy calls resolve this KC user → DIGIT user correctly
      if (digitUser && (data as any).access_token) {
        preCacheDigitUser((data as any).access_token, digitUser, tenantId).catch(() => {});
      }
      return res.json(data);
    }

    console.error(`[KC-TOKEN] ${username} — KC retry failed: ${retryResp.status}`);
    const retryErr = await retryResp.text();
    return res.status(retryResp.status).type("json").send(retryErr);
  });

  // Platform admin routes (gated on master-realm JWT, proxy to MCP).
  // Registered BEFORE the catch-all so /platform-admin/* matches here, not
  // there.
  registerPlatformAdminRoutes(app);

  // Main proxy handler
  app.all("*", async (req, res) => {
    const start = Date.now();
    const method = req.method;
    const path = req.path;

    // Check Authorization header first, then fall back to RequestInfo.authToken
    let claims = await validateJwt(req.headers.authorization).catch(() => null);
    let jwtSource: string | null = null;

    if (claims) {
      jwtSource = "Authorization header";
    } else if (req.body?.RequestInfo?.authToken) {
      // UI sends KC JWT as authToken in RequestInfo body (not in Authorization header)
      const bodyToken = req.body.RequestInfo.authToken;
      claims = await validateJwt(`Bearer ${bodyToken}`).catch(() => null);
      if (claims) {
        jwtSource = "RequestInfo.authToken";
      }
    }

    if (!claims) {
      // No KC JWT — forward to gateway unchanged (DIGIT token / no auth)
      const hasDigitToken = !!req.body?.RequestInfo?.authToken;
      console.log(`[PROXY] ${method} ${path} → gateway (no KC JWT, DIGIT token: ${hasDigitToken}) [${Date.now() - start}ms]`);
      return forwardToGateway(req, res, config.digitGatewayHost);
    }

    // KC JWT detected
    console.log(`[PROXY] ${method} ${path} — KC JWT detected via ${jwtSource} (sub=${claims.sub}, email=${claims.email})`);

    // KC JWT — resolve user, get citizen token, proxy via gateway
    const tenantId =
      req.body?.RequestInfo?.userInfo?.tenantId ||
      req.body?.tenantId ||
      config.digitDefaultTenant;

    try {
      const { user, token } = await resolveUser(claims, tenantId);
      console.log(`[PROXY] ${method} ${path} — resolved: ${user.userName} (${user.type}, uuid=${user.uuid}, tenant=${tenantId}) [${Date.now() - start}ms]`);
      await proxyRequest(req, res, user, token, config.digitGatewayHost);
    } catch (err) {
      console.error(`[PROXY] ${method} ${path} — user resolution FAILED:`, err);
      res
        .status(500)
        .json({ error: "Internal error", message: "Failed to resolve user" });
    }
  });

  return app;
}

const isMain =
  process.argv[1]?.endsWith("server.ts") ||
  process.argv[1]?.endsWith("server.js");
if (isMain) {
  (async () => {
    initJwks();
    initCache();
    initRoutes();
    await initSystemToken();
    startTokenRefresh();

    if (config.tenantSyncEnabled) {
      try {
        await initKcAdmin();
        await syncTenantRealms();
      } catch (err) {
        console.warn("KC Admin init failed (non-fatal):", (err as Error).message);
      }
    }

    const app = await createApp();
    app.listen(config.port, () => {
      console.log(`token-exchange-svc listening on :${config.port}`);
    });

    process.on("SIGTERM", async () => {
      stopTokenRefresh();
      stopKcAdminRefresh();
      await closeCache();
      process.exit(0);
    });
  })();
}
