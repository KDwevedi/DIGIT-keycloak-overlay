import type { IdentityAuthMethod } from "./types.js";

const keycloakBffClientId =
  process.env.KEYCLOAK_BFF_CLIENT_ID || "digit-identity-bff";

function csv(value: string): string[] {
  return [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
}

export function parseIdentityAuthMethods(raw: string): IdentityAuthMethod[] {
  const value: unknown = JSON.parse(raw);
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("IDENTITY_AUTH_METHODS must be a non-empty JSON array");
  }

  const seen = new Set<string>();
  return value.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`IDENTITY_AUTH_METHODS[${index}] must be an object`);
    }
    const candidate = entry as Record<string, unknown>;
    const id = typeof candidate.id === "string" ? candidate.id.trim() : "";
    const label = typeof candidate.label === "string" ? candidate.label.trim() : "";
    const type = candidate.type;
    if (!id || !/^[a-z0-9_-]+$/.test(id)) {
      throw new Error(`IDENTITY_AUTH_METHODS[${index}].id is invalid`);
    }
    if (seen.has(id)) {
      throw new Error(`IDENTITY_AUTH_METHODS contains duplicate id: ${id}`);
    }
    if (!label) {
      throw new Error(`IDENTITY_AUTH_METHODS[${index}].label is required`);
    }
    if (type !== "password" && type !== "oauth" && type !== "magic_link") {
      throw new Error(`IDENTITY_AUTH_METHODS[${index}].type is invalid`);
    }
    const idpHint = typeof candidate.idpHint === "string"
      ? candidate.idpHint.trim()
      : undefined;
    if (type !== "password" && !idpHint) {
      throw new Error(`IDENTITY_AUTH_METHODS[${index}].idpHint is required`);
    }
    seen.add(id);
    return { id, label, type, ...(idpHint && { idpHint }) };
  });
}

function keycloakIssuerRealm(): string {
  const issuer = process.env.KEYCLOAK_ISSUER ||
    "http://localhost:8180/auth/realms/digit-sandbox";
  return issuer.split("/realms/").pop() || "digit-sandbox";
}

export const config = {
  port: parseInt(process.env.PORT || "3000"),

  // DIGIT egov-user
  digitUserHost: process.env.DIGIT_USER_HOST || "http://localhost:8107",
  digitSystemUsername: process.env.DIGIT_SYSTEM_USERNAME || "ADMIN",
  digitSystemPassword: process.env.DIGIT_SYSTEM_PASSWORD || "eGov@123",
  digitSystemUserType: process.env.DIGIT_SYSTEM_USER_TYPE || "EMPLOYEE",
  digitSystemTenant: process.env.DIGIT_SYSTEM_TENANT || "pg",
  digitDefaultTenant: process.env.DIGIT_DEFAULT_TENANT || "pg.citya",

  // DIGIT gateway
  digitGatewayHost: process.env.DIGIT_GATEWAY_HOST || "http://gateway:8080",

  // Keycloak
  keycloakIssuer: process.env.KEYCLOAK_ISSUER || "http://localhost:8180/auth/realms/digit-sandbox",
  keycloakOidcBackchannelUrl:
    process.env.KEYCLOAK_OIDC_BACKCHANNEL_URL ||
    process.env.KEYCLOAK_ISSUER ||
    "http://localhost:8180/auth/realms/digit-sandbox",
  keycloakJwksUri: process.env.KEYCLOAK_JWKS_URI || "http://localhost:8180/auth/realms/digit-sandbox/protocol/openid-connect/certs",
  keycloakAudience: process.env.KEYCLOAK_AUDIENCE || "digit-ui",
  keycloakBffClientId,
  keycloakBffClientSecret:
    process.env.KEYCLOAK_BFF_CLIENT_SECRET || "dev-only-change-me",
  keycloakBffAudience:
    process.env.KEYCLOAK_BFF_AUDIENCE || keycloakBffClientId,

  // Identity BFF
  identityRedirectUri:
    process.env.IDENTITY_REDIRECT_URI ||
    "http://localhost:18200/identity/v1/callback",
  identityPostLoginRedirect:
    process.env.IDENTITY_POST_LOGIN_REDIRECT || "/",
  identityAllowedOrigin:
    process.env.IDENTITY_ALLOWED_ORIGIN || "http://localhost:3000",
  identityScope:
    process.env.IDENTITY_SCOPE || "openid profile email organization:*",
  identityAuthMethods: parseIdentityAuthMethods(
    process.env.IDENTITY_AUTH_METHODS ||
      '[{"id":"password","label":"Password","type":"password"}]',
  ),
  identityCookieName:
    process.env.IDENTITY_COOKIE_NAME || "digit_identity_session",
  identityCookieSecure: process.env.IDENTITY_COOKIE_SECURE !== "false",
  identityLoginTtlSeconds: parseInt(
    process.env.IDENTITY_LOGIN_TTL_SECONDS || "300",
  ),
  identitySessionTtlSeconds: parseInt(
    process.env.IDENTITY_SESSION_TTL_SECONDS || "604800",
  ),
  identityControlPlaneToken:
    process.env.IDENTITY_CONTROL_PLANE_TOKEN || "",
  identitySessionIntrospectionToken:
    process.env.IDENTITY_SESSION_INTROSPECTION_TOKEN || "",
  identityReconcileOnStartup:
    process.env.IDENTITY_RECONCILE_ON_STARTUP === "true",
  identityReconciliationLeaseSeconds: parseInt(
    process.env.IDENTITY_RECONCILIATION_LEASE_SECONDS || "300",
  ),
  identityReconciliationIntervalSeconds: parseInt(
    process.env.IDENTITY_RECONCILIATION_INTERVAL_SECONDS || "0",
  ),

  // Existing DIGIT user-service contract. The BFF owns only the accounts it
  // created (see managed-digit-users.ts); the admin credential is used solely
  // for those accounts' lifecycle, never for business calls.
  digitUserServiceUrl: process.env.DIGIT_USER_SERVICE_URL || "",
  digitMdmsSearchUrl: process.env.DIGIT_MDMS_SEARCH_URL || "",
  // egov-user reached directly (internal network) for token revocation only:
  // Kong's RBAC evaluates the principal's home tenant, which a BFF-managed
  // account may hold no roles in. Defaults to DIGIT_USER_SERVICE_URL.
  digitUserLogoutUrl: process.env.DIGIT_USER_LOGOUT_URL || "",
  digitOauthClientAuthorization:
    process.env.DIGIT_OAUTH_CLIENT_AUTHORIZATION || "Basic ZWdvdi11c2VyLWNsaWVudDo=",
  digitAdminUsername: process.env.DIGIT_ADMIN_USERNAME || "",
  digitAdminPassword: process.env.DIGIT_ADMIN_PASSWORD || "",
  digitAdminTenantId: process.env.DIGIT_ADMIN_TENANT_ID || "",
  digitAdminUserType: process.env.DIGIT_ADMIN_USER_TYPE || "EMPLOYEE",
  // Optional MDMS_ADMIN credential for onboarding tenant-foundation writes.
  digitProvisionerUsername: process.env.DIGIT_PROVISIONER_USERNAME || "",
  digitProvisionerPassword: process.env.DIGIT_PROVISIONER_PASSWORD || "",
  digitProvisionerTenantId: process.env.DIGIT_PROVISIONER_TENANT_ID || "",
  digitMdmsCreateUrl: process.env.DIGIT_MDMS_CREATE_URL || "",
  // Idempotent egov-enc-service key creation for a new tenant (internal URL).
  digitEncGenerateKeyUrl: process.env.DIGIT_ENC_GENERATE_KEY_URL || "",
  // Optional in-process worker that provisions submitted PGR onboarding operations.
  onboardingWorkerEnabled: process.env.ONBOARDING_WORKER_ENABLED === "true",
  pgrOnboardingWorkerUrl: process.env.PGR_ONBOARDING_WORKER_URL || "",
  pgrOnboardingWorkerToken: process.env.PGR_ONBOARDING_WORKER_TOKEN || "",
  onboardingWorkerIntervalSeconds: parseInt(process.env.ONBOARDING_WORKER_INTERVAL_SECONDS || "15"),
  onboardingWorkerLeaseSeconds: parseInt(process.env.ONBOARDING_WORKER_LEASE_SECONDS || "120"),
  onboardingFounderGroup: process.env.ONBOARDING_FOUNDER_GROUP || "founders",
  onboardingFounderRoles: csv(process.env.ONBOARDING_FOUNDER_ROLES || "GRO"),
  digitManagedBaseRoles: csv(process.env.DIGIT_MANAGED_BASE_ROLES || "EMPLOYEE"),
  digitManagedRoleAllowlist: csv(
    process.env.DIGIT_MANAGED_ROLE_ALLOWLIST ||
      "EMPLOYEE,GRO,PGR_LME,DGRO,CSR,SUPERVISOR,AUTO_ESCALATE,PGR_VIEWER,TICKET_REPORT_VIEWER",
  ),
  digitRoleClientId:
    process.env.DIGIT_ROLE_CLIENT_ID || process.env.DIGIT_IDENTITY_CLIENT_ID || "digit-ui",
  digitTimeoutMs: parseInt(process.env.DIGIT_TIMEOUT_MS || "10000"),
  digitTokenRefreshSkewSeconds: parseInt(
    process.env.DIGIT_TOKEN_REFRESH_SKEW_SECONDS || "60",
  ),
  digitUserLeaseSeconds: parseInt(process.env.DIGIT_USER_LEASE_SECONDS || "30"),
  digitUserLeaseWaitMs: parseInt(process.env.DIGIT_USER_LEASE_WAIT_MS || "15000"),
  digitPasswordLength: parseInt(process.env.DIGIT_PASSWORD_LENGTH || "15"),
  keycloakOrganizationRealm:
    process.env.KEYCLOAK_ORGANIZATION_REALM || keycloakIssuerRealm(),
  keycloakAllowedOrganizationRoleClients: (
    process.env.KEYCLOAK_ALLOWED_ORG_ROLE_CLIENTS || "digit-ui"
  ).split(",").map((value) => value.trim()).filter(Boolean),

  // Keycloak Admin
  keycloakAdminUrl: process.env.KEYCLOAK_ADMIN_URL || "http://localhost:8180",
  keycloakAdminRealm: process.env.KEYCLOAK_ADMIN_REALM || "master",
  keycloakAdminClientId: process.env.KEYCLOAK_ADMIN_CLIENT_ID || "admin-cli",
  keycloakAdminClientSecret:
    process.env.KEYCLOAK_ADMIN_CLIENT_SECRET || "",
  keycloakAdminUsername: process.env.KEYCLOAK_ADMIN_USERNAME || "admin",
  keycloakAdminPassword: process.env.KEYCLOAK_ADMIN_PASSWORD || "admin",
  // HMAC secret used to derive a strong KC-internal password for users provisioned
  // via the DIGIT-fallback path. The derived password lives only in KC (KC's stored
  // hash + the overlay's HMAC) — users never see it, can't log in with it. DIGIT
  // remains the source of truth for credentials (OTP for citizens, real password
  // for employees). Falls back to the admin password so existing deployments don't
  // need new wiring, but operators should set a dedicated secret in production.
  keycloakProvisioningSecret:
    process.env.KEYCLOAK_PROVISIONING_SECRET ||
    process.env.KEYCLOAK_ADMIN_PASSWORD ||
    "overlay-provisioning-default-secret",
  keycloakUserRealm: process.env.KEYCLOAK_USER_REALM || "digit-sandbox",

  // Placeholder mobile prefix for citizens provisioned via SSO who have no
  // phone_number claim in their KC JWT. The overlay synthesizes a 10-digit
  // mobile as `<prefix><5-digit-hash-of-sub>`. Default `90000` produces
  // `90000XXXXX` which fits standard 10-digit (India) regexes. Deployments
  // with different tenant validation regexes must override — e.g. Bomet's
  // Kenya regex `^0?[17][0-9]{8}$` needs prefix `07000` to produce
  // `07000XXXXX` (valid 10-digit Kenya mobile shape). The hash is derived
  // from the user's KC sub, so it stays stable across re-provisioning.
  overlaySyntheticMobilePrefix:
    process.env.OVERLAY_SYNTHETIC_MOBILE_PREFIX || "90000",
  tenantSyncEnabled: process.env.TENANT_SYNC_ENABLED !== "false",

  // DIGIT MDMS (for tenant sync)
  digitMdmsHost: process.env.DIGIT_MDMS_HOST || "",
  digitTenants: process.env.DIGIT_TENANTS || "",

  // Redis
  redisHost: process.env.REDIS_HOST || "localhost",
  redisPort: parseInt(process.env.REDIS_PORT || "6379"),
  cachePrefix: process.env.CACHE_PREFIX || "keycloak",
  cacheTtlSeconds: parseInt(process.env.CACHE_TTL_SECONDS || "604800"),

  // Upstream routing
  upstreamServices: process.env.UPSTREAM_SERVICES || "",
};
