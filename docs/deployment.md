# Keycloak Deployment & Operations Guide

This guide covers the production deployment of Keycloak with the DIGIT stack, including Google SSO setup, role mapping, and administration.

## Architecture Overview

```
Browser
  │
  │  https://api.egov.theflywheel.in/auth/*
  │  https://api.egov.theflywheel.in/kc/*
  ▼
┌─────────────────────────────────────────────────────────┐
│  Nginx (port 443)                                       │
│  api.egov.theflywheel.in → localhost:18000              │
└──────────────────────┬──────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────┐
│  Kong Gateway (port 18000)                              │
│                                                         │
│  /auth/*  → keycloak:8180         (Keycloak login/admin)│
│  /kc/*    → token-exchange-svc:3000  (JWT→DIGIT proxy)  │
│  /user/*  → egov-user:8107        (existing DIGIT auth) │
│  /pgr-services/* → pgr:8080      (direct DIGIT access)  │
└──────────────────────┬──────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Keycloak    token-exchange    DIGIT backends
   (port 8180)  -svc (port 3000)  (unchanged)
```

**Two auth paths coexist:**
- **Existing**: `/user/oauth/token` → DIGIT's native auth (used by MCP, DIGIT UI, internal services)
- **New**: `/auth/*` → Keycloak login → `/kc/*` → token-exchange-svc → DIGIT backends

Neither path affects the other. The existing DIGIT auth is fully preserved.

## Endpoints

| URL | Purpose |
|-----|---------|
| `https://api.egov.theflywheel.in/auth/admin/` | Keycloak admin console (all realms) |
| `https://api.egov.theflywheel.in/auth/realms/{realm}/account/` | User self-service portal (per realm) |
| `https://api.egov.theflywheel.in/auth/realms/{realm}/.well-known/openid-configuration` | OIDC discovery (per realm) |
| `https://api.egov.theflywheel.in/kc/healthz` | Token-exchange-svc health |
| `https://api.egov.theflywheel.in/kc/<digit-path>` | JWT-protected DIGIT API proxy |

Replace `{realm}` with the state root code (e.g. `pg`, `mz`). The `digit-sandbox` realm
from the initial import still exists but new tenants use realm-per-state-root.

**Admin credentials**: `admin` / `admin` (change in production via `KEYCLOAK_ADMIN_PASSWORD` env var)

## Docker Compose Services

Three new services in `tilt-demo/docker-compose.deploy.yaml`:

### keycloak-db-init
One-shot container that creates the `keycloak` database in PostgreSQL. Idempotent — safe to run multiple times. Connects directly to `postgres-db:5432` (not pgbouncer, because DDL statements can't run through transaction-mode pgbouncer).

### keycloak
Keycloak 26.7.3 running in dev mode with realm auto-import. On first boot, imports `keycloak/realm-export.json` which creates the `digit-sandbox` realm.

Key environment variables:
| Variable | Value | Purpose |
|----------|-------|---------|
| `KC_HOSTNAME_URL` | `https://api.egov.theflywheel.in/auth` | Sets issuer URL in JWTs |
| `KC_HOSTNAME_ADMIN_URL` | `https://api.egov.theflywheel.in/auth` | Sets admin console URLs |
| `KC_HTTP_RELATIVE_PATH` | `/auth` | All endpoints served under /auth/* |
| `KC_PROXY_HEADERS` | `xforwarded` | Trust X-Forwarded-* from Kong/nginx |
| `KC_DB_URL` | `jdbc:postgresql://postgres-db:5432/keycloak` | Direct DB (not pgbouncer) |
| `KEYCLOAK_ADMIN_PASSWORD` | `admin` (override via env) | Admin password |

### token-exchange-svc
Node.js service that validates Keycloak JWTs and proxies requests to DIGIT backends with injected system auth. Supports multi-realm JWT validation and bidirectional role sync.

Key environment variables:
| Variable | Value | Purpose |
|----------|-------|---------|
| `KEYCLOAK_ISSUER` | `https://api.egov.theflywheel.in/auth/realms/digit-sandbox` | Default realm issuer (fallback for single-realm mode) |
| `KEYCLOAK_JWKS_URI` | `http://keycloak:8180/auth/realms/...` | Internal URL for fetching signing keys |
| `KEYCLOAK_AUDIENCE` | `digit-ui` | Expected audience for legacy direct Keycloak-token validation |
| `KEYCLOAK_BFF_CLIENT_ID` | `digit-identity-bff` | Confidential Authorization Code client used by the identity BFF |
| `KEYCLOAK_BFF_CLIENT_SECRET` | `dev-only-change-me` | BFF client secret; must be overridden outside local development |
| `KEYCLOAK_BFF_AUDIENCE` | BFF client ID | Required audience for BFF access tokens |
| `KEYCLOAK_ORG_TENANT_MAPPINGS` | `[]` | JSON array mapping immutable Keycloak Organization IDs to DIGIT tenants and display names |
| `IDENTITY_REDIRECT_URI` | `http://localhost:18200/identity/v1/callback` | Exact Keycloak callback URI |
| `IDENTITY_POST_LOGIN_REDIRECT` | `/` | Fixed browser destination after successful callback |
| `IDENTITY_ALLOWED_ORIGIN` | `http://localhost:3000` | Browser origin allowed to send the identity cookie |
| `IDENTITY_COOKIE_SECURE` | `true` | Set `false` only for local HTTP development |
| `DIGIT_USER_HOST` | `http://egov-user:8107` | DIGIT user service |
| `DIGIT_SYSTEM_USERNAME` | `ADMIN` | System account for forwarding requests |
| `REDIS_HOST` | `redis` | Cache for resolved users |

#### KC Admin / Tenant Sync environment variables:
| Variable | Default | Purpose |
|----------|---------|---------|
| `KEYCLOAK_ADMIN_URL` | `http://localhost:8180` | Keycloak base URL for Admin API calls |
| `KEYCLOAK_ADMIN_USERNAME` | `admin` | Admin username for KC Admin API authentication |
| `KEYCLOAK_ADMIN_PASSWORD` | `admin` | Admin password (override via env or Docker secret) |
| `KEYCLOAK_ADMIN_REALM` | `master` | Realm used for admin token acquisition |
| `KEYCLOAK_ADMIN_CLIENT_ID` | `admin-cli` | Client ID for admin token requests |
| `TENANT_SYNC_ENABLED` | `true` | Enable realm-per-tenant provisioning and bidirectional role sync |
| `DIGIT_MDMS_HOST` | `""` | DIGIT MDMS host for dynamic tenant discovery (empty = use `DIGIT_TENANTS`) |
| `DIGIT_TENANTS` | `""` | Static tenant map: `"pg:pg.citya,pg.cityb;mz:mz.maputo"` |

## Startup Order

```
postgres-db (healthy)
├── keycloak-db-init (runs CREATE DATABASE, exits)
│   └── keycloak (starts, imports realm, ~30-45s to healthy)
├── pgbouncer → egov-user (healthy)
└── redis (healthy)
    └── token-exchange-svc (needs keycloak + redis + egov-user)
```

Kong doesn't depend on the Keycloak services — it handles 502s gracefully until they're ready.

## Setting Up Google SSO

### Step 1: Create Google OAuth Credentials

1. Go to [Google Cloud Console -> APIs & Services -> Credentials](https://console.cloud.google.com/apis/credentials)
2. Click **Create Credentials** -> **OAuth client ID**
3. Application type: **Web application**
4. Name: `DIGIT Keycloak - {realm}` (e.g. `DIGIT Keycloak - pg`)
5. Authorized redirect URIs -- add one for each realm that needs Google SSO:
   ```
   https://api.egov.theflywheel.in/auth/realms/pg/broker/google/endpoint
   https://api.egov.theflywheel.in/auth/realms/mz/broker/google/endpoint
   ```
6. Click **Create** and note the **Client ID** and **Client Secret**

Note: You can use the same Google OAuth app for multiple realms (add multiple
redirect URIs), or create separate apps per realm for isolation.

### Step 2: Configure in Keycloak

1. Open [Keycloak Admin Console](https://api.egov.theflywheel.in/auth/admin/)
2. Select the target realm (e.g. **pg**) from the dropdown in the sidebar
3. Go to **Identity providers** -> **Add provider** -> **Google**
4. Fill in:
   - **Client ID**: from Google Cloud Console
   - **Client Secret**: from Google Cloud Console
   - Leave other defaults (scopes: `openid email profile`)
5. Click **Save**
6. Repeat for each realm that needs Google SSO

The Keycloak login page for that realm will now show a **"Login with Google"** button.

### Step 3: Test

1. Open: `https://api.egov.theflywheel.in/auth/realms/pg/account/` (replace `pg` with your realm)
2. Click **Sign in** -- you should see the Google SSO option
3. After Google login, the user appears in Keycloak under **Users** in that realm

### Other SSO Providers

The same process works for GitHub, Microsoft, Apple, or any OIDC/SAML provider:
- **Identity providers** -> **Add provider** -> choose provider
- Each provider needs its own OAuth app and redirect URI:
  ```
  https://api.egov.theflywheel.in/auth/realms/{realm}/broker/<provider-id>/endpoint
  ```
- Each realm can have different IdP configurations (e.g. `pg` uses Google, `mz` uses Microsoft)

## Role Mapping

Roles exist at two levels:

### Keycloak Roles (Identity Layer)

Keycloak roles answer: **"Who is this person?"**

**Create a realm role:**
1. Admin console → **Realm roles** → **Create role**
2. Name: e.g., `grievance-officer`, `admin`, `field-worker`
3. Save

**Assign to a user:**
1. **Users** → select user → **Role mapping** tab
2. Click **Assign role** → filter by realm roles → select → **Assign**

**Auto-assign via Identity Provider Mapper** (e.g., all Google SSO users get a role):
1. **Identity providers** → **Google** → **Mappers** tab → **Add mapper**
2. Mapper type: **Hardcoded Role**
3. Role: select the role to auto-assign
4. This applies to all users who log in via that provider

**Auto-assign based on email domain** (e.g., `@yourdomain.com` → `admin`):
1. **Identity providers** → **Google** → **Mappers** tab → **Add mapper**
2. Mapper type: **Attribute Importer** (import email)
3. Then create a **Client scope** with a **Script mapper** or use **Authentication → Flows** to conditionally assign roles

### DIGIT Roles (Application Layer)

DIGIT roles answer: **"What can this person do in DIGIT?"**

Examples: `CITIZEN`, `EMPLOYEE`, `GRO` (Grievance Routing Officer), `PGR_LME` (Last Mile Employee)

### Bidirectional Role Sync (Implemented)

Role sync works in both directions between Keycloak and DIGIT:

**KC -> DIGIT (on every API request):**
- token-exchange-svc reads `realm_access.roles` from the JWT (issued by the state root's realm)
- Only known DIGIT roles are synced; unknown Keycloak roles (like `default-roles-pg`) are ignored
- `CITIZEN` is always included
- On first login: DIGIT user is created with roles from the JWT
- On subsequent logins: roles are compared with cache; if changed, DIGIT user is updated

**DIGIT -> KC (on role change, when `TENANT_SYNC_ENABLED=true`):**
- After resolving a user, token-exchange-svc syncs their DIGIT roles back to the KC realm
- Calls `assignRealmRoles(root, sub, roleCodes)` to mirror roles to the correct realm
- Adds user to the city group (e.g. `pg.citya`) via `addUserToGroupInRealm()`
- This is fire-and-forget -- failures are logged but do not block the request

21 DIGIT roles are recognized (see [role-management.md](role-management.md) for the full list).

See [role-management.md](role-management.md) for detailed role management documentation.

## Realm Configuration

### Legacy Realm-per-Tenant Provisioning

The existing startup synchronizer provisions **one realm per DIGIT state root**
using a template. This remains during migration. The target identity-BFF model
uses one shared realm with Keycloak Organizations mapped to DIGIT root tenants.
The `digit-sandbox` realm export
(`keycloak/realm-export.json`) is used for Keycloak's initial import on first boot.
Subsequent realms are created dynamically from `keycloak/realm-template.json`.

### Realm Template

The template (`keycloak/realm-template.json`) defines the baseline configuration for
every realm. The `__REALM_NAME__` placeholder is replaced with the state root code:

| Setting | Value | Notes |
|---------|-------|-------|
| Registration | Disabled | Users are provisioned via SSO or admin |
| Login with email | Enabled | Email is the primary identifier |
| Password policy | `length(8)` | Minimum 8 characters |
| Access token lifespan | 15 minutes | Short-lived for security |
| SSO session idle | 30 minutes | Session expires after inactivity |
| SSO session max | 7 days | Maximum session duration |
| Brute force protection | Enabled | 5 failures before lockout |
| Default role | `CITIZEN` | All users get CITIZEN automatically |
| Roles | 21 DIGIT roles | Full set from DIGIT access-control |
| PKCE | Required (S256) | For the `digit-ui` client |

### Client: digit-ui

Each realm gets a `digit-ui` public OIDC client (from the template):
- **Client ID**: `digit-ui`
- **Flow**: Authorization Code + PKCE (no client secret)
- **Redirect URIs**: `http://localhost:*`, `https://*.egov.theflywheel.in/*`
- **Web Origins**: `http://localhost:3000`, `http://localhost:5173`, `https://*.egov.theflywheel.in`

### Organizations and tenant choices

The realm templates enable Organizations and attach the built-in optional
`organization` scope to the UI client. The Organization membership mapper emits
the immutable Organization ID. The Organization group mapper emits group paths
and their realm/client roles inside each Organization claim.

Clients must request `organization:*` to obtain every Organization membership
needed by the chooser. `GET /identity/v1/tenants` then intersects that signed
claim with `KEYCLOAK_ORG_TENANT_MAPPINGS`. Mapping entries use this shape:

```json
[
  {
    "organizationId": "4bb42b7e-...",
    "tenantId": "ke.bomet",
    "name": "Bomet County"
  }
]
```

The BFF handles `/authorize`, `/callback`, `/session`, `/tenants`, and `/logout`.
Keycloak access, refresh, and ID tokens remain in Redis; the browser receives
only an opaque `HttpOnly`, `SameSite=Lax` session cookie. Access tokens refresh
server-side when needed, and logout deletes the Redis session and revokes the
Keycloak refresh token. Persisted active DIGIT membership still needs to be
added as a further tenant-options filter before production cutover.

### Groups (City Tenants)

City tenants are created as groups within the realm. For example, with
`DIGIT_TENANTS="pg:pg.citya,pg.cityb"`, realm `pg` gets two groups:
`pg.citya` and `pg.cityb`. A `groups` client scope mapper includes group
membership in the JWT's `groups` claim.

### Provisioning Flow

On startup (when `TENANT_SYNC_ENABLED=true`):

1. token-exchange-svc authenticates with KC Admin API (master realm)
2. Parses `DIGIT_TENANTS` into `{root -> [cities]}` map
3. For each root:
   - Creates realm from template (or skips if 409 = already exists)
   - Creates city groups within the realm (idempotent)
4. Logs sync summary

If `DIGIT_MDMS_HOST` is set, tenants can alternatively be loaded from DIGIT MDMS
at startup (not yet implemented -- `DIGIT_TENANTS` is the current mechanism).

## Operations

### Check Health

```bash
# Keycloak
curl https://api.egov.theflywheel.in/auth/health/ready

# Token-exchange-svc
curl https://api.egov.theflywheel.in/kc/healthz

# Existing DIGIT auth (should still work)
curl -X POST https://api.egov.theflywheel.in/user/oauth/token \
  -H "Authorization: Basic ZWdvdi11c2VyLWNsaWVudDo=" \
  -d "grant_type=password&username=ADMIN&password=eGov%40123&tenantId=pg&scope=read&userType=EMPLOYEE"
```

### View Logs

```bash
cd ~/code/tilt-demo

# Keycloak logs
docker compose -f docker-compose.deploy.yaml logs -f keycloak

# Token-exchange-svc logs
docker compose -f docker-compose.deploy.yaml logs -f token-exchange-svc
```

### Restart Services

```bash
cd ~/code/tilt-demo

# Restart just Keycloak (token-exchange-svc auto-reconnects)
docker compose -f docker-compose.deploy.yaml restart keycloak

# Restart token-exchange-svc
docker compose -f docker-compose.deploy.yaml restart token-exchange-svc

# Restart both (and reload Kong routes)
docker compose -f docker-compose.deploy.yaml restart keycloak token-exchange-svc kong
```

### Update Realm Configuration

To modify the realm after initial import:
1. Make changes in the Keycloak admin console
2. Export: **Realm settings** → **Action** → **Partial export** (include clients, roles)
3. Save the export to `keycloak/realm-export.json`
4. Commit to git

Note: `--import-realm` only imports on **first boot** (empty database). To re-import after changes, either:
- Delete the keycloak database: `docker exec docker-postgres psql -U egov -c "DROP DATABASE keycloak"`
- Or make changes directly in the admin console (they persist in the database)

### Run Integration Tests

```bash
cd /root/DIGIT-keycloak-overlay

# Unit tests (requires Redis on port 16379)
REDIS_PORT=16379 npm test

# Live integration tests (requires full DIGIT stack running)
npx tsx tests/integration/verify-live.ts

# Manual cleanup of test artifacts
npx tsx tests/integration/cleanup.ts
```

## Kong Routes

Two routes added to `kong/kong.yml`:

```yaml
# Keycloak — passthrough, strip_path: false
# /auth/realms/digit-sandbox/... → keycloak:8180/auth/realms/digit-sandbox/...
- name: keycloak-service
  url: http://keycloak:8180
  routes:
    - paths: [/auth]
      strip_path: false

# Token exchange — strip /kc prefix before forwarding
# /kc/pgr-services/v2/request/_search → token-exchange-svc:3000/pgr-services/v2/request/_search
- name: token-exchange-service
  url: http://token-exchange-svc:3000
  routes:
    - paths: [/kc]
      strip_path: true
```

## Port Reference

| Service | Internal Port | Host Port | External URL |
|---------|--------------|-----------|--------------|
| Keycloak | 8180 | 18180 | `https://api.egov.theflywheel.in/auth/` |
| token-exchange-svc | 3000 | 18200 | `https://api.egov.theflywheel.in/kc/` |
| Kong | 8000 | 18000 | `https://api.egov.theflywheel.in/` |
| egov-user | 8107 | 18107 | `https://api.egov.theflywheel.in/user/` |

## Troubleshooting

### JWT issuer mismatch (401 from token-exchange-svc)

With realm-per-tenant, the JWT `iss` claim includes the realm name (e.g.
`https://api.egov.theflywheel.in/auth/realms/pg`). The token-exchange-svc
validates JWTs by extracting the realm from the issuer and fetching the
corresponding JWKS. Verify:

```bash
# Check what Keycloak reports as the issuer for a realm
curl -s https://api.egov.theflywheel.in/auth/realms/pg/.well-known/openid-configuration | jq .issuer

# Check that the realm exists
curl -s https://api.egov.theflywheel.in/auth/realms/pg/.well-known/openid-configuration | jq .jwks_uri

# For fallback/single-realm mode, check the configured issuer
docker inspect digit-token-exchange --format '{{range .Config.Env}}{{println .}}{{end}}' | grep KEYCLOAK_ISSUER
```

If using a single-realm setup, `KEYCLOAK_ISSUER` must exactly match the `iss`
claim. With multi-realm, the service dynamically resolves the JWKS endpoint from
the JWT issuer.

### Keycloak admin console redirects to wrong port

If the admin console redirects to `localhost:8000` or another wrong URL, check that `KC_HOSTNAME_ADMIN_URL` is set:

```yaml
KC_HOSTNAME_URL: https://api.egov.theflywheel.in/auth
KC_HOSTNAME_ADMIN_URL: https://api.egov.theflywheel.in/auth
```

Both are needed — `KC_HOSTNAME_URL` controls realm/token URLs, `KC_HOSTNAME_ADMIN_URL` controls admin console URLs.

### Keycloak not starting (database issues)

Keycloak connects directly to `postgres-db:5432` (not pgbouncer). If the `keycloak` database doesn't exist:

```bash
# Check if keycloak DB exists
docker exec docker-postgres psql -U egov -lqt | grep keycloak

# Manually create if needed
docker exec docker-postgres psql -U egov -c "CREATE DATABASE keycloak OWNER egov;"

# Restart keycloak
docker compose -f docker-compose.deploy.yaml restart keycloak
```

### Redis cache stale after changes

If user resolution returns stale data after changing Keycloak user attributes:

```bash
# Clear all keycloak cache keys
docker exec digit-redis redis-cli KEYS 'keycloak:*'
docker exec digit-redis redis-cli DEL $(docker exec digit-redis redis-cli KEYS 'keycloak:*' | tr '\n' ' ')
```

Or run the cleanup script:
```bash
cd /root/DIGIT-keycloak-overlay && npx tsx tests/integration/cleanup.ts
```

### Realm not created on startup

If `syncTenantRealms` logs "No tenants configured", check:

```bash
# Verify DIGIT_TENANTS is set
docker inspect digit-token-exchange --format '{{range .Config.Env}}{{println .}}{{end}}' | grep DIGIT_TENANTS

# Verify TENANT_SYNC_ENABLED is not "false"
docker inspect digit-token-exchange --format '{{range .Config.Env}}{{println .}}{{end}}' | grep TENANT_SYNC

# Check token-exchange-svc startup logs for sync output
docker compose -f docker-compose.deploy.yaml logs token-exchange-svc | grep -i "realm\|sync\|tenant"
```

The format must be `root:city1,city2;root2:city3` (colon separates root from cities,
semicolon separates roots, comma separates cities).

### KC Admin API authentication failure

If realm creation fails with "KC admin auth failed: 401":

```bash
# Verify admin credentials work against the master realm
curl -s -X POST 'http://localhost:18180/realms/master/protocol/openid-connect/token' \
  -d 'client_id=admin-cli&grant_type=password&username=admin&password=admin'

# Check KEYCLOAK_ADMIN_URL points to the correct host
docker inspect digit-token-exchange --format '{{range .Config.Env}}{{println .}}{{end}}' | grep KEYCLOAK_ADMIN
```

### User appears in wrong realm

Users are resolved based on the JWT issuer. If a user logged into realm `pg` but
sends a request with `tenantId: "mz.maputo"`, the JWT validation will still use
the `pg` realm JWKS. The user needs to authenticate against realm `mz` to
operate on `mz.*` tenants.

### Groups not appearing in JWT

Verify the `groups` client scope is configured in the realm:

```bash
KC_TOKEN=$(curl -s -X POST \
  'http://localhost:18180/realms/master/protocol/openid-connect/token' \
  -d 'client_id=admin-cli&grant_type=password&username=admin&password=admin' \
  | jq -r .access_token)

# Check client scopes for the digit-ui client in realm "pg"
curl -s "http://localhost:18180/admin/realms/pg/clients" \
  -H "Authorization: Bearer $KC_TOKEN" | jq '.[] | select(.clientId=="digit-ui") | .defaultClientScopes'
```

The `groups` scope should be listed. If missing, the realm template may not have
been applied correctly -- delete and recreate the realm, or add the scope manually.
