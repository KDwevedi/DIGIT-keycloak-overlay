# Identity BFF v1 — DIGIT compatibility bridge

## Boundary

The identity BFF is a standalone executable (`npm run start:identity`). Its
runtime dependencies are Redis, Keycloak, and DIGIT's **existing** egov-user and
MDMS APIs. It needs no egov-user code change. PGR is not required to start or
sign in; only the optional onboarding worker calls PGR.

```text
Browser ── OIDC redirect / opaque cookie ──> Identity BFF ──> Keycloak (OIDC + Admin API)
                                                 │
                                                 └──> egov-user user-service API (via Kong)
Browser ── normal DIGIT RequestInfo.authToken ──> Kong ──> PGR and other DIGIT APIs
Onboarding worker / reconciler ── workload token ──> Identity BFF control plane
```

The BFF is not a universal proxy. After sign-in and tenant selection it returns
the normal egov-user login response, so an existing frontend keeps calling DIGIT
business APIs with `RequestInfo.authToken` unchanged. The browser never calls
egov-user login/create/update endpoints and never receives a Keycloak access,
ID or refresh token, a DIGIT refresh token, the DIGIT admin token, or any
password.

## Browser API

| Method | Route | Result |
|---|---|---|
| `GET` | `/identity/v1/auth-methods` | Methods configured here and enabled in Keycloak |
| `GET` | `/identity/v1/authorize?method=...` | Starts Authorization Code + PKCE with state and nonce |
| `GET` | `/identity/v1/callback` | Validates the callback and creates an opaque cookie session |
| `GET` | `/identity/v1/session` | Authentication state and selected tenant, never tokens |
| `GET` | `/identity/v1/tenants` | Tenants in both Keycloak membership and DIGIT grants |
| `POST` | `/identity/v1/contexts/_select` | Records the tenant and returns the normal DIGIT login response |
| `POST` | `/identity/v1/logout` | Revokes the DIGIT token and Keycloak session, clears the cookie |

Password, magic link, Google, and GitHub all enter the same Keycloak browser
flow (brokered methods use `kc_idp_hint`) and converge on one callback. Keycloak
tokens stay in Redis behind a random `HttpOnly; Secure; SameSite=Lax` cookie.

`contexts/_select` response:

```json
{ "access_token": "<user-scoped DIGIT token>", "token_type": "bearer",
  "expires_in": 604000, "scope": "read", "UserRequest": { "uuid": "...", "userName": "kcbff-...", "roles": [...] } }
```

The token belongs to the signed-in person's own DIGIT account, so Kong's normal
`/user/_details` resolution and RBAC apply. `UserRequest` is narrowed to the
documented profile fields.

## Organization → tenant mapping

A Keycloak Organization maps to one DIGIT tenant through its
`digit.rootTenantId` attribute, set by `organizations/_ensure` only after the
tenant exists in DIGIT MDMS `tenant.tenants`. A tenant is offered only when:

1. the signed session claims include that Organization;
2. the Organization is enabled and mapped, and the tenant exists in DIGIT; and
3. the managed DIGIT account is active and holds roles for that tenant.

Session claims can be one access-token lifetime old, so they never change an
existing account's roles. Sign-in only creates a missing account from them.
Role and membership projection comes from live Keycloak state through the
control plane and reconciliation, and selection re-checks membership live
through the Keycloak Admin API.

## Managed DIGIT accounts

The BFF owns one DIGIT `EMPLOYEE` per Keycloak `(issuer, subject)` **per tenant**,
stored at that tenant. DIGIT's gateway (Kong + egov-accesscontrol) authorizes a
token only against its account's home tenant. On a live stack, a role at
another tenant is rejected with 403, so one account cannot serve several
tenants. Each account has:

- username `kcbff-<sha256(issuer\nsubject\ntenant)[:40]>`;
- `identificationMark` `keycloak-bff:v1:<sha256(issuer\nsubject)>:<tenantId>`;
- roles at its tenant only: `DIGIT_MANAGED_BASE_ROLES` plus the
  Organization-group client roles of `DIGIT_ROLE_CLIENT_ID` that are in
  `DIGIT_MANAGED_ROLE_ALLOWLIST`.

An account is treated as managed only when both username and marker match.
Locally managed legacy employees, including one that happens to share the
username, are never updated, rotated or deactivated.

### Lifecycle (existing egov-user APIs only)

| Step | Call | Credential |
|---|---|---|
| Admin token | `POST /user/oauth/token` with `DIGIT_ADMIN_*` env credentials; cached in memory, re-obtained before expiry or after a 401 | env |
| Resolve | `POST /user/_search` (active, then inactive) | admin token |
| Create when absent | `POST /user/users/_createnovalidate` with a cryptographically random one-time password | admin token |
| First user token | `POST /user/oauth/token` as that user, once | one-time password |
| Regenerate after expiry | `POST /user/users/_updatenovalidate` with a new random password, then one login | admin token, then new one-time password |
| Role/membership change | `_updatenovalidate` roles or `active=false`, then `POST /user/_logout` on the cached token | admin token |
| Logout | `POST /user/_logout` on the cached user token | user token |

Every create/rotate/role change for one subject runs under a Redis lease
(`DIGIT_USER_LEASE_SECONDS`), so concurrent requests produce one rotation and
share the resulting token. The user token is cached in Redis until shortly
before egov-user's `expires_in`.

The admin token is used only for these account operations, never for business
calls.

### Honest limits

- **Password hash retained:** egov-user stores the BCrypt hash of the latest
  generated password. The BFF never persists, logs, caches or returns the
  plaintext, and never reuses it, but JavaScript strings cannot be zeroed.
  "Discarded" therefore means unreferenced after the single create/update and
  login calls.
- **Mobile required:** egov-user requires a mobile number to create an employee.
  Login-time creation uses a `phone_number` claim. The worker uses
  `tenantMetadata.founder.mobileNumber`. `memberships/_ensure` takes
  `mobileNumber` and otherwise reuses the mobile on the subject's existing
  managed account. Without one, that tenant's account is not created and the
  tenant is not offered.
- **Separate accounts per tenant:** a person in two Organizations has two DIGIT
  accounts (different UUIDs) and receives the account matching the selected
  tenant. Cross-tenant work under one DIGIT identity would need gateway changes.
- **Per-tenant encryption key:** creating an account at a new tenant needs its
  egov-enc-service key; the worker ensures it via `DIGIT_ENC_GENERATE_KEY_URL`.
- **Token lifetime is DIGIT's:** tokens follow `access.token.validity.in.minutes`
  (7 days by default). Rotation does not revoke the previous token; the BFF
  revokes explicitly on logout, role change and deactivation.
- **One token per account:** logout from one browser revokes the DIGIT tokens
  shared with that person's other BFF sessions. Their next selection mints new
  ones. Revocation calls egov-user `/user/_logout` directly
  (`DIGIT_USER_LOGOUT_URL`), because Kong would evaluate RBAC at the account's
  home tenant.
- **Reconciliation index:** former members are found through Redis
  `digit-managed-accounts` (`subject|tenant`). If that key is lost, a removed member is deactivated
  only when next seen, and cannot be offered the tenant in the meantime.

## Control-plane API

Provisioning routes require `IDENTITY_CONTROL_PLANE_TOKEN` and are idempotent:

- `POST /internal/identity/v1/organizations/_ensure` — `{tenantId, alias, name}`; `409` until the DIGIT tenant exists.
- `POST /internal/identity/v1/memberships/_ensure` — `{organizationId, userId, mobileNumber?}` → `{tenantId, digitUserUuid, created}` for that tenant's account. Adds Keycloak membership, then creates or updates the managed account. `digitUserUuid` input is rejected: legacy employees are not linked.
- `POST /internal/identity/v1/role-assignments/_ensure` — sets an Organization group's allowlisted client roles and projects them to DIGIT.
- `POST /internal/identity/v1/reconciliation/_run`

PGR authenticates an onboarding founder through the narrower
`POST /internal/identity/v1/sessions/_introspect` with its own
`IDENTITY_SESSION_INTROSPECTION_TOKEN`, which cannot provision anything.

A provisioning worker should call `organizations/_ensure` →
`memberships/_ensure` → `role-assignments/_ensure` after it has created the
tenant foundation.

Startup (`IDENTITY_RECONCILE_ON_STARTUP=true`) and periodic
(`IDENTITY_RECONCILIATION_INTERVAL_SECONDS`) reconciliation take a Redis lease,
read enabled mapped Organizations and their group roles from Keycloak, and apply
them to managed accounts through egov-user. Former members are deactivated.
Members without an account yet are reported as `unprovisioned`, not failures.

## Onboarding worker (optional)

Enabled only with `ONBOARDING_WORKER_ENABLED=true` plus `PGR_ONBOARDING_WORKER_URL`
(internal PGR base, e.g. `http://pgr-services:8080/pgr-services`) and
`PGR_ONBOARDING_WORKER_TOKEN`. Every `ONBOARDING_WORKER_INTERVAL_SECONDS` it:

1. leases a `PENDING` operation with `POST /v2/onboarding/internal/operations/_claim`
   (PGR uses `FOR UPDATE SKIP LOCKED`; an expired lease is re-claimable);
2. runs idempotent steps, recording each in `completedSteps`:
   - `TENANT_FOUNDATION`: creates the `tenant.tenants` MDMS record for
     `requestedTenantId`, using a separate `DIGIT_PROVISIONER_*` credential (an
     `MDMS_ADMIN` employee, `DIGIT_MDMS_CREATE_URL`), waits for MDMS v2 read-model
     visibility, and ensures the tenant's encryption key
     (`DIGIT_ENC_GENERATE_KEY_URL`, idempotent). Without the provisioner
     credential the tenant must already exist;
   - `ORGANIZATION`: Keycloak Organization `organizationAlias` mapped to the tenant;
   - `FOUNDER_MEMBERSHIP`: adds the signup owner to it;
   - `FOUNDER_ROLES`: `ONBOARDING_FOUNDER_GROUP` with `ONBOARDING_FOUNDER_ROLES`;
   - `DIGIT_ACCOUNT`: the founder's managed DIGIT account at the new tenant,
     created with `tenantMetadata.founder.mobileNumber` (or the founder's
     existing managed mobile), and its projected roles;
3. reports `_complete` (operation `SUCCEEDED`, signup `ACTIVE`) or `_fail` with
   `retryable` (`RETRYABLE_FAILED`; the owner may `_retry`) or terminal
   (`TERMINAL_FAILED`, identifiers released).

Transient Keycloak/DIGIT/tenant-visibility errors are retryable. Conflicts
(alias taken, colliding legacy account, missing founder mobile) are terminal.
Only `tenant.tenants` is provisioned; boundaries, departments, service
definitions, roles/actions and localization for a new tenant are not.
A PGR outage only logs a skipped worker cycle.

## Docker Compose deployment

`deploy/digit-compose/` layers Keycloak 26.7.3 and the BFF onto a DIGIT
local-setup Compose project without changing egov-user. Secrets live only in
`0600` env files (see `identity-bff.env.example`). `configure-keycloak.sh`
creates a temporary master admin with `kc.sh bootstrap-admin`, configures the
Organizations realm, BFF client, mappers, service account and role client, then
deletes that admin. `nginx-identity.conf` exposes only realm endpoints, login
resources and `/identity/`. The dedicated DIGIT admin should be a normal
employee holding only `ACCOUNT_ADMIN`.

## Failure behavior

- Missing Redis or Keycloak prevents the relevant identity operation.
- Missing PGR has no effect on BFF startup or sign-in.
- Unavailable egov-user or MDMS still permits OIDC login, but tenant listing and
  selection fail closed with `503`, and no DIGIT token is issued.
