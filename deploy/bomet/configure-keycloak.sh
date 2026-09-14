#!/usr/bin/env bash
set -euo pipefail

readonly REALM=ke
readonly KC_CONFIG=/tmp/identity-bff-kcadm.config
readonly BFF_CLIENT=digit-identity-bff
readonly ASSERTION_AUDIENCE=digit-identity-exchange
readonly ADMIN_CLIENT=digit-identity-admin

set -a
. /opt/digit/identity-bff.env
if [ -f /opt/digit/identity-bff-bootstrap.env ]; then
  . /opt/digit/identity-bff-bootstrap.env
fi
set +a

: "${KC_BOOTSTRAP_ADMIN_USERNAME:?set KC_BOOTSTRAP_ADMIN_USERNAME for this run}"
: "${KC_BOOTSTRAP_ADMIN_PASSWORD:?set KC_BOOTSTRAP_ADMIN_PASSWORD for this run}"

docker exec \
  -e KCADM_USERNAME="$KC_BOOTSTRAP_ADMIN_USERNAME" \
  -e KCADM_PASSWORD="$KC_BOOTSTRAP_ADMIN_PASSWORD" \
  keycloak sh -lc \
  '/opt/keycloak/bin/kcadm.sh config credentials --config /tmp/identity-bff-kcadm.config --server http://127.0.0.1:8180 --realm master --user "$KCADM_USERNAME" --password "$KCADM_PASSWORD" >/dev/null'

kc() {
  docker exec keycloak /opt/keycloak/bin/kcadm.sh "$@" --config "$KC_CONFIG"
}

client_uuid() {
  kc get clients -r "$REALM" -q "clientId=$1" --fields id |
    jq -r '.[0].id // empty'
}

ensure_client() {
  local client_id=$1
  local secret=$2
  local service_accounts=$3
  local client_uuid_value
  client_uuid_value=$(client_uuid "$client_id")
  if [ -z "$client_uuid_value" ]; then
    kc create clients -r "$REALM" \
      -s "clientId=$client_id" \
      -s enabled=true \
      -s publicClient=false \
      -s "secret=$secret" \
      -s standardFlowEnabled=false \
      -s directAccessGrantsEnabled=false \
      -s "serviceAccountsEnabled=$service_accounts" >/dev/null
    client_uuid_value=$(client_uuid "$client_id")
  else
    kc update "clients/$client_uuid_value" -r "$REALM" \
      -s enabled=true \
      -s publicClient=false \
      -s "secret=$secret" \
      -s directAccessGrantsEnabled=false \
      -s "serviceAccountsEnabled=$service_accounts" >/dev/null
  fi
  printf '%s' "$client_uuid_value"
}

ensure_mapper() {
  local owner=$1
  local name=$2
  local mapper=$3
  shift 3
  local mapper_id
  mapper_id=$(kc get "$owner/protocol-mappers/models" -r "$REALM" |
    jq -r --arg name "$name" '.[] | select(.name == $name) | .id' | head -1)
  if [ -z "$mapper_id" ]; then
    kc create "$owner/protocol-mappers/models" -r "$REALM" \
      -s "name=$name" -s protocol=openid-connect \
      -s "protocolMapper=$mapper" "$@" >/dev/null
  else
    kc update "$owner/protocol-mappers/models/$mapper_id" -r "$REALM" \
      -s "name=$name" -s protocol=openid-connect \
      -s "protocolMapper=$mapper" "$@" >/dev/null
  fi
}

kc update "realms/$REALM" -s organizationsEnabled=true >/dev/null

bff_uuid=$(ensure_client "$BFF_CLIENT" "$KEYCLOAK_BFF_CLIENT_SECRET" false)
kc update "clients/$bff_uuid" -r "$REALM" \
  -s standardFlowEnabled=true \
  -s "redirectUris=[\"$IDENTITY_REDIRECT_URI\"]" \
  -s "webOrigins=[\"$IDENTITY_ALLOWED_ORIGIN\"]" \
  -s 'attributes."pkce.code.challenge.method"=S256' \
  -s 'attributes."standard.token.exchange.enabled"=true' >/dev/null

assertion_uuid=$(client_uuid "$ASSERTION_AUDIENCE")
if [ -z "$assertion_uuid" ]; then
  kc create clients -r "$REALM" \
    -s "clientId=$ASSERTION_AUDIENCE" \
    -s enabled=true -s bearerOnly=true \
    -s standardFlowEnabled=false \
    -s directAccessGrantsEnabled=false >/dev/null
fi

ensure_mapper "clients/$bff_uuid" digit-identity-bff-audience \
  oidc-audience-mapper \
  -s "config.\"included.client.audience\"=$BFF_CLIENT" \
  -s 'config."id.token.claim"=false' \
  -s 'config."access.token.claim"=true'

ensure_mapper "clients/$bff_uuid" digit-identity-exchange-audience \
  oidc-audience-mapper \
  -s "config.\"included.client.audience\"=$ASSERTION_AUDIENCE" \
  -s 'config."id.token.claim"=false' \
  -s 'config."access.token.claim"=true'

organization_scope=$(kc get client-scopes -r "$REALM" |
  jq -r '.[] | select(.name == "organization") | .id' | head -1)
if [ -z "$organization_scope" ]; then
  kc create client-scopes -r "$REALM" \
    -s name=organization -s protocol=openid-connect \
    -s 'attributes."include.in.token.scope"=true' \
    -s 'attributes."display.on.consent.screen"=false' >/dev/null
  organization_scope=$(kc get client-scopes -r "$REALM" |
    jq -r '.[] | select(.name == "organization") | .id' | head -1)
fi

ensure_mapper "client-scopes/$organization_scope" organization \
  oidc-organization-membership-mapper \
  -s 'config."id.token.claim"=true' \
  -s 'config."access.token.claim"=true' \
  -s 'config."userinfo.token.claim"=true' \
  -s 'config."introspection.token.claim"=true' \
  -s 'config."claim.name"=organization' \
  -s 'config."jsonType.label"=String' \
  -s 'config."multivalued"=true' \
  -s 'config."addOrganizationId"=true'

ensure_mapper "client-scopes/$organization_scope" 'organization groups' \
  oidc-organization-group-membership-mapper \
  -s 'config."id.token.claim"=true' \
  -s 'config."access.token.claim"=true' \
  -s 'config."userinfo.token.claim"=true' \
  -s 'config."introspection.token.claim"=true' \
  -s 'config."addGroupRoleMappings"=true'

kc update "clients/$bff_uuid/optional-client-scopes/$organization_scope" \
  -r "$REALM" -n >/dev/null

admin_uuid=$(ensure_client "$ADMIN_CLIENT" "$KEYCLOAK_ADMIN_CLIENT_SECRET" true)
service_user=$(kc get "clients/$admin_uuid/service-account-user" -r "$REALM" |
  jq -r '.id')
management_uuid=$(client_uuid realm-management)
kc get "clients/$management_uuid/roles" -r "$REALM" |
  jq '[.[] | select(.name == "manage-organizations" or
                    .name == "query-organizations" or
                    .name == "view-organizations" or
                    .name == "manage-users" or
                    .name == "query-users" or
                    .name == "view-users" or
                    .name == "query-clients" or
                    .name == "view-clients" or
                    .name == "view-identity-providers")]' |
  docker exec -i keycloak /opt/keycloak/bin/kcadm.sh \
    create "users/$service_user/role-mappings/clients/$management_uuid" \
    -r "$REALM" -f - --config "$KC_CONFIG" >/dev/null

digit_ui_uuid=$(client_uuid digit-ui)
for role in CITIZEN EMPLOYEE SUPERUSER GRO PGR_LME DGRO CSR SUPERVISOR \
  AUTO_ESCALATE PGR_VIEWER TICKET_REPORT_VIEWER TENANT_ADMIN VIEWER; do
  if ! kc get "clients/$digit_ui_uuid/roles/$role" -r "$REALM" >/dev/null 2>&1; then
    kc create "clients/$digit_ui_uuid/roles" -r "$REALM" \
      -s "name=$role" >/dev/null
  fi
done

printf 'realm=%s organizations=enabled bff_client=%s admin_client=%s\n' \
  "$REALM" "$BFF_CLIENT" "$ADMIN_CLIENT"
