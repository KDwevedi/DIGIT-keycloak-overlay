import { config } from "./config.js";
import { validateJwt } from "./jwt.js";
import type { IdentityTokenSet, KCClaims } from "./types.js";

function oidcUrl(path: string): string {
  return `${config.keycloakIssuer}/protocol/openid-connect/${path}`;
}

export function authorizationUrl(state: string, codeChallenge: string): string {
  const url = new URL(oidcUrl("auth"));
  url.search = new URLSearchParams({
    client_id: config.keycloakBffClientId,
    redirect_uri: config.identityRedirectUri,
    response_type: "code",
    scope: config.identityScope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  }).toString();
  return url.toString();
}

async function tokenRequest(params: URLSearchParams): Promise<IdentityTokenSet> {
  params.set("client_id", config.keycloakBffClientId);
  params.set("client_secret", config.keycloakBffClientSecret);

  const response = await fetch(oidcUrl("token"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  if (!response.ok) {
    throw new Error(`Keycloak token request failed: ${response.status}`);
  }

  const body = await response.json() as Record<string, unknown>;
  if (typeof body.access_token !== "string" ||
      typeof body.expires_in !== "number") {
    throw new Error("Keycloak returned an invalid token response");
  }

  return {
    accessToken: body.access_token,
    refreshToken:
      typeof body.refresh_token === "string" ? body.refresh_token : undefined,
    accessExpiresIn: body.expires_in,
    refreshExpiresIn:
      typeof body.refresh_expires_in === "number"
        ? body.refresh_expires_in
        : undefined,
  };
}

export function exchangeAuthorizationCode(
  code: string,
  codeVerifier: string,
): Promise<IdentityTokenSet> {
  return tokenRequest(new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.identityRedirectUri,
    code_verifier: codeVerifier,
  }));
}

export function refreshIdentityTokens(
  refreshToken: string,
): Promise<IdentityTokenSet> {
  return tokenRequest(new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  }));
}

export async function verifyIdentityAccessToken(
  accessToken: string,
): Promise<KCClaims> {
  const claims = await validateJwt(`Bearer ${accessToken}`, {
    issuer: config.keycloakIssuer,
    audience: config.keycloakBffAudience,
  });
  if (!claims) throw new Error("Keycloak returned an invalid access token");
  return claims;
}

export async function logoutFromKeycloak(refreshToken?: string): Promise<void> {
  if (!refreshToken) return;
  const response = await fetch(oidcUrl("logout"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: config.keycloakBffClientId,
      client_secret: config.keycloakBffClientSecret,
      refresh_token: refreshToken,
    }).toString(),
  });
  if (!response.ok) {
    throw new Error(`Keycloak logout failed: ${response.status}`);
  }
}
