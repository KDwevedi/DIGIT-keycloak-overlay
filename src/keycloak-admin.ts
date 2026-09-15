import { createHmac } from "node:crypto";
import { config } from "./config.js";

let cachedAdminToken: string | null = null;
let tokenExpiry = 0;

/**
 * Derive a strong, deterministic KC-internal password for a user.
 *
 * Users authenticate with their DIGIT credentials (OTP for citizens, real
 * password for employees) which the overlay validates against egov-user.
 * KC's stored password is plumbing — we just need a value that satisfies
 * the realm's password policy and that the overlay can reproduce on retry.
 *
 * Using HMAC(secret, userKey) gives us:
 *   - A value that passes any reasonable password policy (length, charset).
 *   - Determinism so the lazy-provision flow can write it and then re-use
 *     it for the immediate retry against KC.
 *   - No persistence requirement — we recompute it from the user's key
 *     every time.
 *
 * userKey should be the user's DIGIT UUID (stable, tenant-scoped). Falls
 * back to username if UUID isn't available — still strong, just rotates
 * if username ever changes.
 */
export function deriveKcPassword(userKey: string): string {
  return createHmac("sha256", config.keycloakProvisioningSecret)
    .update(userKey)
    .digest("base64url");
}

export async function getAdminToken(): Promise<string> {
  if (cachedAdminToken && Date.now() < tokenExpiry) {
    return cachedAdminToken;
  }

  const credentials = new URLSearchParams({
    grant_type: config.keycloakAdminClientSecret
      ? "client_credentials"
      : "password",
    client_id: config.keycloakAdminClientId,
  });
  if (config.keycloakAdminClientSecret) {
    credentials.set("client_secret", config.keycloakAdminClientSecret);
  } else {
    credentials.set("username", config.keycloakAdminUsername);
    credentials.set("password", config.keycloakAdminPassword);
  }
  const resp = await fetch(
    `${config.keycloakAdminUrl}/realms/${encodeURIComponent(config.keycloakAdminRealm)}` +
      "/protocol/openid-connect/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: credentials.toString(),
    }
  );

  if (!resp.ok) {
    throw new Error(`Keycloak admin login failed: ${resp.status}`);
  }

  const data = (await resp.json()) as { access_token: string; expires_in: number };
  cachedAdminToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in - 10) * 1000;
  return cachedAdminToken;
}

export async function searchKeycloakUser(email: string): Promise<boolean> {
  const token = await getAdminToken();
  const resp = await fetch(
    `${config.keycloakAdminUrl}/admin/realms/${config.keycloakUserRealm}/users?email=${encodeURIComponent(email)}&exact=true`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!resp.ok) return false;
  const users = (await resp.json()) as Array<{ email: string }>;
  return users.length > 0;
}

export async function createKeycloakUser(params: {
  email: string;
  password: string;
  name: string;
  username?: string;  // KC username — defaults to email if not provided
}): Promise<void> {
  const token = await getAdminToken();
  const kcUsername = params.username || params.email;
  // KC requires both firstName and lastName for "account fully set up"
  const nameParts = (params.name || kcUsername).split(/\s+/);
  const firstName = nameParts[0] || kcUsername;
  const lastName = nameParts.slice(1).join(" ") || "-";
  const resp = await fetch(
    `${config.keycloakAdminUrl}/admin/realms/${config.keycloakUserRealm}/users`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        username: kcUsername,
        email: params.email,
        firstName,
        lastName,
        enabled: true,
        emailVerified: true,
        credentials: [{ type: "password", value: params.password, temporary: false }],
      }),
    }
  );

  if (resp.status === 409) {
    throw new Error("User already exists");
  }
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Keycloak user creation failed: ${resp.status} ${err}`);
  }
}
