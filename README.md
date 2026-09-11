# DIGIT Identity BFF / Keycloak Overlay

An identity boundary between browsers, DIGIT services, and Keycloak. It owns
OIDC login, server-side Keycloak sessions, Organization-based tenant selection,
issuance of tenant-scoped DIGIT sessions, and the small Keycloak provisioning
API used by onboarding or reconciliation workers.

The BFF has **no dependency on PGR**. PGR can call its internal APIs during an
onboarding saga, but the BFF builds and starts without PGR and never calls PGR.

**Design doc:** [docs/plans/2026-03-05-keycloak-acl-design.md](docs/plans/2026-03-05-keycloak-acl-design.md)
**Identity BFF v1:** [docs/identity-bff.md](docs/identity-bff.md)
**Architecture gist:** [github.com/ChakshuGautam/dcd9b7f5...](https://gist.github.com/ChakshuGautam/dcd9b7f561016016dd455607f7927f94)

## How It Works

```text
Browser ── OIDC/session/tenant choice ──> Identity BFF ──> Keycloak
                                              │
                                              └──> durable DIGIT identity API

PGR or another onboarding worker ── workload auth ──> Identity BFF ──> Keycloak Admin API

Browser ── tenant-scoped DIGIT token ──> Kong ──> PGR and other DIGIT APIs
```

Only the identity BFF talks to Keycloak. Normal application requests do not
pass through it, and no Keycloak access or refresh token is exposed to the
browser.

## Quick Start

### Organization tenant-list demo

The bundled Keycloak 26.7.3 realm has Organizations enabled. Configure the
confidential BFF client, its browser origin, and the durable DIGIT identity API:

```bash
export KEYCLOAK_AUDIENCE=digit-ui
export KEYCLOAK_BFF_CLIENT_SECRET='<same-secret-configured-on-the-bff-client>'
export IDENTITY_ALLOWED_ORIGIN='http://localhost:3000'
export DIGIT_IDENTITY_SERVICE_URL='http://digit-identity:8080/internal/identity/v1'
export DIGIT_IDENTITY_SERVICE_TOKEN='<workload-token>'
export IDENTITY_CONTROL_PLANE_TOKEN='<different-workload-token>'
```

Browser API:

```http
GET  /identity/v1/auth-methods
GET  /identity/v1/authorize?method=password
GET  /identity/v1/callback
GET  /identity/v1/session
GET  /identity/v1/tenants
POST /identity/v1/contexts/_select
POST /identity/v1/logout
```

`GET /identity/v1/tenants` returns only the intersection of signed Keycloak
Organization memberships and active durable DIGIT memberships. Selecting one
returns a short-lived, tenant-scoped DIGIT login response. The browser then uses
that DIGIT access token through Kong for PGR and all other normal APIs.

Internal control-plane API (workload bearer token required):

```http
POST /internal/identity/v1/organizations/_ensure
POST /internal/identity/v1/memberships/_ensure
POST /internal/identity/v1/role-assignments/_ensure
```

These idempotent routes are suitable for PGR onboarding, another domain's
onboarding, or a startup/scheduled reconciliation worker. They contain no PGR
model or URL.

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
# Starts Keycloak, Redis, standalone identity BFF, and the legacy exchange proxy
docker compose up -d

# Keycloak admin: http://localhost:18180 (admin/admin)
# Standalone identity BFF: http://localhost:18201
# Legacy token exchange: http://localhost:18200
```

### Integrate with DIGIT (tilt-demo)

Point `DIGIT_USER_HOST` at the running egov-user service:

```bash
DIGIT_USER_HOST=http://localhost:8107 \
KEYCLOAK_ISSUER=http://localhost:18180/realms/digit-sandbox \
KEYCLOAK_JWKS_URI=http://localhost:18180/realms/digit-sandbox/protocol/openid-connect/certs \
REDIS_HOST=localhost \
REDIS_PORT=16379 \
npm run dev
```

## Test Summary

35 tests across 10 files:

| Suite | Tests | Coverage |
|-------|-------|----------|
| JWT validation | 6 | Valid, expired, missing, garbage tokens |
| Redis cache | 4 | Set/get, delete, tenant scoping |
| User resolver | 9 | Provision, cache hit, existing user, sync, tenant scope, role provisioning, role sync |
| Route mapping | 4 | Path matching, unknown paths |
| Auth flow (E2E) | 3 | Happy path, no auth, expired |
| User provisioning (E2E) | 3 | New user, unique mobile numbers, JWT role provisioning |
| Cache behavior (E2E) | 2 | Cache hit, pre-populated cache |
| User sync (E2E) | 1 | Name change propagation |
| Error handling (E2E) | 2 | Garbage token, unknown upstream |
| Health check (E2E) | 1 | Redis connectivity |

## Project Structure

```
src/
  config.ts         # Environment config with defaults
  types.ts          # TypeScript interfaces
  jwt.ts            # JWKS-based JWT validation (jose)
  identity-routes.ts         # Browser-facing identity BFF
  identity-session.ts        # Opaque cookie and Redis-backed KC session
  digit-identity.ts          # Durable identity/membership/session client
  identity-control-routes.ts # Workload-authenticated provisioning API
  identity-admin.ts          # Keycloak Organization/member/role operations
  cache.ts          # Redis cache with TTL
  digit-client.ts   # egov-user HTTP client
  user-resolver.ts  # KC claims -> DIGIT user (core logic)
  routes.ts         # Path prefix -> upstream mapping
  proxy.ts          # Content-type-aware request forwarding
  server.ts         # Express app entry point
mocks/
  jwks-server.ts    # RSA key pair + JWKS endpoint for tests
  egov-user.ts      # In-memory egov-user mock
  digit-backend.ts  # Echo server for upstream verification
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
- **System token**: Uses `INTERNAL_MICROSERVICE_ROLE` to forward requests, no shadow passwords
- **Lazy provisioning**: DIGIT users created on first API call, not at signup
- **Content-type-aware proxy**: JSON bodies get RequestInfo rewritten, multipart streams through
- **Hash-derived mobile**: `90000XXXXX` from SHA256 of Keycloak subject UUID
