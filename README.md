# DIGIT Keycloak Overlay

An anti-corruption layer that bridges Keycloak authentication to DIGIT's internal auth system. Users sign up and log in via Keycloak; the overlay transparently provisions them in DIGIT and injects the correct `RequestInfo` into every API request.

**Design doc:** [docs/plans/2026-03-05-keycloak-acl-design.md](docs/plans/2026-03-05-keycloak-acl-design.md)
**Architecture gist:** [github.com/ChakshuGautam/dcd9b7f5...](https://gist.github.com/ChakshuGautam/dcd9b7f561016016dd455607f7927f94)

## How It Works

1. User authenticates with Keycloak (email/password, Google SSO, etc.)
2. Frontend sends requests with `Authorization: Bearer <keycloak-jwt>`
3. Token-exchange-svc validates the JWT via Keycloak's JWKS endpoint
4. Resolves/provisions a DIGIT user (lazy creation on first API call)
5. Injects a system token + user info into `RequestInfo`
6. Proxies to upstream DIGIT services (PGR, workflow, MDMS, etc.)

DIGIT services see a normal authenticated request — no code changes needed.

## Quick Start

### Organization tenant-list demo

The bundled Keycloak 26.7.3 realm has Organizations enabled. Request
`scope=openid profile email organization:*` during Authorization Code + PKCE
login, then configure the immutable Organization IDs that may become DIGIT
tenant choices:

```bash
export KEYCLOAK_AUDIENCE=digit-ui
export KEYCLOAK_ORG_TENANT_MAPPINGS='[
  {"organizationId":"<bomet-org-uuid>","tenantId":"ke.bomet","name":"Bomet County"},
  {"organizationId":"<kisumu-org-uuid>","tenantId":"ke.kisumu","name":"Kisumu County"}
]'
```

The transitional demo API accepts the Keycloak access token directly:

```http
GET /identity/v1/tenants
Authorization: Bearer <keycloak-access-token>
```

It returns only mapped Organizations present in the verified token, with roles
from each Organization's groups kept separate. The target BFF flow will replace
the bearer header with an opaque `HttpOnly` session cookie and additionally
intersect these choices with persisted active DIGIT memberships.

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
# Starts Keycloak + Redis + token-exchange-svc
docker compose up -d

# Keycloak admin: http://localhost:18180 (admin/admin)
# Token exchange: http://localhost:18200
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

- **Anti-corruption layer** (DDD pattern): Keycloak handles auth UX, DIGIT internals stay untouched
- **System token**: Uses `INTERNAL_MICROSERVICE_ROLE` to forward requests, no shadow passwords
- **Lazy provisioning**: DIGIT users created on first API call, not at signup
- **Content-type-aware proxy**: JSON bodies get RequestInfo rewritten, multipart streams through
- **Hash-derived mobile**: `90000XXXXX` from SHA256 of Keycloak subject UUID
