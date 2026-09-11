# Identity BFF v1

## Boundary

The identity BFF is a standalone executable (`npm run start:identity`). Its
runtime dependencies are Redis, Keycloak, and the durable DIGIT
identity/membership/session API. It does not import, call, start, or health-check
PGR. PGR is only one possible workload-authenticated client of the control-plane
API.

```text
Browser -> Identity BFF -> Keycloak OIDC
                      \-> durable DIGIT identity API

PGR/onboarding/reconciler -> Identity BFF -> Keycloak Admin API

Browser -> Kong -> PGR/other DIGIT APIs  (tenant-scoped DIGIT token)
```

## Browser API

| Method | Route | Result |
|---|---|---|
| `GET` | `/identity/v1/auth-methods` | Methods configured here and enabled in Keycloak |
| `GET` | `/identity/v1/authorize?method=...` | Starts Authorization Code + PKCE with state and nonce |
| `GET` | `/identity/v1/callback` | Validates the callback and creates an opaque cookie session |
| `GET` | `/identity/v1/session` | Authentication state and selected tenant, never Keycloak tokens |
| `GET` | `/identity/v1/tenants` | Active tenant choices for the signed-in identity |
| `POST` | `/identity/v1/contexts/_select` | Rechecks membership and issues a tenant-scoped DIGIT login response |
| `POST` | `/identity/v1/logout` | Revokes the Keycloak session and clears local state |

Password, magic link, Google, and GitHub all enter the same Keycloak browser
flow. Brokered methods use `kc_idp_hint`; their availability is checked against
enabled Keycloak identity providers. All methods converge on the same callback,
session, tenant chooser, and DIGIT-token issuance path.

The Keycloak access, ID, and refresh tokens stay in Redis. The cookie contains
only a random session identifier. The selected DIGIT access token is returned
to the frontend because existing DIGIT clients put it in `RequestInfo.authToken`;
no DIGIT refresh credential is returned.

## Durable identity API dependency

The service URL is deliberately named `DIGIT_IDENTITY_SERVICE_URL`, not a PGR
URL. The BFF sends only the verified Keycloak `(issuer, subject)`, client ID,
and immutable Organization IDs.

- `POST /contexts/_resolve` returns active Organization-to-tenant contexts and
  tenant-local roles.
- `POST /sessions/_issue` returns a short-lived DIGIT login response for one
  revalidated context.

This API is the authority for durable account and membership state. Keycloak
claims alone never create a DIGIT session.

## Control-plane API

All routes are protected by `IDENTITY_CONTROL_PLANE_TOKEN` and are idempotent:

- `POST /internal/identity/v1/organizations/_ensure`
- `POST /internal/identity/v1/memberships/_ensure`
- `POST /internal/identity/v1/role-assignments/_ensure`

An onboarding workflow calls these after its durable writes succeed. A startup
or scheduled reconciliation worker can call the same routes from its own source
of desired state. Neither mode gives PGR Keycloak admin credentials.

Roles are client roles assigned through a group inside an Organization. The
role-assignment route accepts only clients in
`KEYCLOAK_ALLOWED_ORG_ROLE_CLIENTS` and makes that managed group's client-role
set exact.

## Failure behavior

- Missing Redis or Keycloak prevents the relevant identity operation.
- Missing PGR has no effect on BFF startup or sign-in.
- Missing durable identity API still permits OIDC login, but tenant resolution
  fails closed with `503` and no DIGIT token is issued.
- Closing a tab after a magic-link callback leaves only the normal server-side
  session lifetime. Signing out revokes and deletes it. An unused magic link is
  governed by Keycloak's one-time-link expiry.
