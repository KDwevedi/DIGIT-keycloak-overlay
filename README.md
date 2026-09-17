# DIGIT Identity BFF

An identity boundary between browsers, DIGIT services, and Keycloak. It owns
OIDC login, server-side Keycloak sessions, Organization-based tenant selection,
issuance of the signed-in person's own DIGIT login through existing egov-user
APIs, and the small Keycloak provisioning
API used by onboarding or reconciliation workers.

The BFF has **no hard dependency on PGR**: it builds, starts and serves sign-in
without PGR. PGR calls its session-introspection API. An optional in-process
onboarding worker (`ONBOARDING_WORKER_ENABLED=true`) leases submitted PGR
onboarding operations through PGR's workload API and provisions them; see
[docs/identity-bff.md](docs/identity-bff.md#onboarding-worker-optional).

**Design doc:** [docs/plans/2026-03-05-keycloak-acl-design.md](docs/plans/2026-03-05-keycloak-acl-design.md)
**Identity BFF v1:** [docs/identity-bff.md](docs/identity-bff.md)
**Architecture gist:** [github.com/ChakshuGautam/dcd9b7f5...](https://gist.github.com/ChakshuGautam/dcd9b7f561016016dd455607f7927f94)

## How It Works

```text
Browser ── OIDC/session/tenant choice ──> Identity BFF ──> Keycloak
                                              │
                                              └──> existing egov-user API (via Kong)

PGR or another onboarding worker ── workload auth ──> Identity BFF ──> Keycloak Admin API

Browser ── normal DIGIT RequestInfo.authToken ──> Kong ──> PGR and other DIGIT APIs
```

Only the identity BFF talks to Keycloak. Normal application requests do not
pass through it, and no Keycloak access or refresh token is exposed to the
browser.

## Quick Start

### Organization tenant-list demo

The bundled Keycloak 26.7.3 realm has Organizations enabled. Configure the
confidential BFF client, its browser origin, and the existing DIGIT user service:

```bash
export KEYCLOAK_AUDIENCE=digit-ui
export KEYCLOAK_BFF_CLIENT_SECRET='<same-secret-configured-on-the-bff-client>'
export IDENTITY_ALLOWED_ORIGINS='http://localhost:3000,http://localhost:5173'
export IDENTITY_COOKIE_SAME_SITE='None' # only for cross-site dev; requires Secure
export DIGIT_USER_SERVICE_URL='http://kong:8000/user'
export DIGIT_MDMS_SEARCH_URL='http://kong:8000/mdms-v2/v1/_search'
export DIGIT_ADMIN_USERNAME='<dedicated ACCOUNT_ADMIN employee>'
export DIGIT_ADMIN_PASSWORD='<its password>'
export DIGIT_ADMIN_TENANT_ID='pg'
export DIGIT_USER_LOGOUT_URL='http://egov-user:8107/user/_logout'
export IDENTITY_CONTROL_PLANE_TOKEN='<workload-token>'
export IDENTITY_SESSION_INTROSPECTION_TOKEN='<pgr-session-only-token>'
export IDENTITY_RECONCILE_ON_STARTUP='true'
export IDENTITY_RECONCILIATION_INTERVAL_SECONDS='3600'
```

Browser API:

```http
GET  /identity/v1/auth-methods
GET  /identity/v1/authorize?method=password
GET  /identity/v1/callback
GET  /identity/v1/session
GET  /identity/v1/tenants
POST /identity/v1/contexts/_select
POST /identity/v1/organization-members/_invite
POST /identity/v1/logout
```

`GET /identity/v1/tenants` returns only tenants present in both the signed
Keycloak Organization memberships and the managed DIGIT account's grants.
Selecting one returns the normal egov-user login response (no refresh token)
for that person's own BFF-managed DIGIT account, so existing frontends keep
using `RequestInfo.authToken`. See [docs/identity-bff.md](docs/identity-bff.md)
for the account lifecycle and its limits.

Internal control-plane API (workload bearer token required):

```http
POST /internal/identity/v1/organizations/_ensure
POST /internal/identity/v1/memberships/_ensure
POST /internal/identity/v1/role-assignments/_ensure
POST /internal/identity/v1/reconciliation/_run
POST /internal/identity/v1/sessions/_introspect
POST /internal/identity/v1/identifiers/_check
```

The three ensure routes are suitable for PGR onboarding, another domain's
onboarding, or a startup/scheduled reconciliation worker. Session introspection
uses a separate, narrower credential so PGR never receives Keycloak admin
authority. These routes contain no PGR model or URL.

### Run Tests (requires Redis)

```bash
# If you have Redis already running (e.g., DIGIT stack on port 16379):
REDIS_PORT=16379 npm test

# Or start a fresh Redis:
docker compose -f docker-compose.test.yml up -d
npm test
```

### Run Full Stack

```bash
# Starts Keycloak, Redis, and the identity BFF
docker compose up -d

# Keycloak admin: http://localhost:18180 (admin/admin)
# Identity BFF: http://localhost:18201
```

### Integrate with DIGIT (tilt-demo)

Point `DIGIT_USER_SERVICE_URL` at the running egov-user service:

```bash
DIGIT_USER_SERVICE_URL=http://localhost:8107/user \
KEYCLOAK_ISSUER=http://localhost:18180/realms/digit-sandbox \
KEYCLOAK_JWKS_URI=http://localhost:18180/realms/digit-sandbox/protocol/openid-connect/certs \
REDIS_HOST=localhost \
REDIS_PORT=16379 \
npm run dev
```

## Test Summary

`npm test` is the release suite for OIDC/session and tenant selection, managed
DIGIT accounts, the onboarding worker, Keycloak admin credentials, token
verification, and Redis-backed coordination.

## Project Structure

```
src/
  app/                       # Composition root and the only executable
  infrastructure/            # Typed configuration and Redis connection
  integrations/keycloak/     # Keycloak admin-session adapter
  modules/
    authentication/          # OIDC, method catalogue, token verification
    sessions/                # Opaque session lifecycle and browser routes
    access-context/          # Tenant discovery and context selection
    organizations/           # Organization, membership and role operations
    managed-accounts/        # egov-user compatibility accounts and tokens
    onboarding/              # PGR operation worker and tenant foundation
    reconciliation/          # Targeted and full identity synchronization
    control-plane/           # Workload-authenticated internal API
    operations/              # Liveness, health and readiness
mocks/
  jwks-server.ts    # RSA key pair + JWKS endpoint for tests
  egov-user.ts      # In-memory egov-user mock
keycloak/
  realm-export.json # digit-sandbox realm config
```

## Key Design Decisions

- **One Keycloak boundary**: browsers and backend provisioning callers use the
  identity service; neither PGR nor the frontend receives Keycloak credentials
- **Anti-corruption layer** (DDD pattern): Keycloak handles auth UX, DIGIT internals stay untouched
- **Organization tenancy**: immutable Keycloak Organization IDs map to durable
  DIGIT tenant identities; client roles are kept inside Organization groups
- **Server-side Keycloak session**: the browser gets only an opaque HttpOnly
  cookie, while the BFF manages Keycloak access/refresh token lifetime in Redis
- **PGR-independent control plane**: idempotent ensure operations can be driven
  by PGR, any other onboarding workflow, or reconciliation
- **Compatibility bridge, not a proxy**: the BFF creates/rotates a marked DIGIT
  account through existing egov-user APIs using an
  env-configured `ACCOUNT_ADMIN` credential (one account per tenant, because
  DIGIT's gateway authorizes tokens at the account's home tenant), logs in as
  that user, and returns
  the normal DIGIT login response. Legacy locally managed employees are never
  touched, and the admin token is never used for business calls
- **One runtime**: the package builds and deploys only the narrow identity BFF;
  generic DIGIT proxying and realm-per-tenant synchronization are not present.
