import { config } from "./config.js";
import {
  DigitUnauthorizedError,
  DigitUnavailableError,
  passwordLogin,
} from "./digit-user-service.js";

let cached: { token: string; expiresAt: number } | null = null;
let pending: Promise<string> | null = null;

async function adminToken(): Promise<string> {
  const skewMs = config.digitTokenRefreshSkewSeconds * 1000;
  if (cached && cached.expiresAt - skewMs > Date.now()) return cached.token;
  if (pending) return pending;
  if (!config.digitAdminUsername || !config.digitAdminPassword || !config.digitAdminTenantId) {
    throw new DigitUnavailableError("DIGIT admin credentials are not configured");
  }
  pending = passwordLogin({
    username: config.digitAdminUsername,
    password: config.digitAdminPassword,
    tenantId: config.digitAdminTenantId,
    userType: config.digitAdminUserType,
  }).then((login) => {
    cached = { token: login.accessToken, expiresAt: login.expiresAt };
    return login.accessToken;
  }).finally(() => {
    pending = null;
  });
  return pending;
}

/**
 * Runs a managed-account lifecycle operation with the cached DIGIT admin
 * token, logging in again from the environment credentials once if DIGIT
 * rejects it. Never use this for business API calls.
 */
export async function withDigitAdmin<T>(operation: (token: string) => Promise<T>): Promise<T> {
  const token = await adminToken();
  try {
    return await operation(token);
  } catch (error) {
    if (!(error instanceof DigitUnauthorizedError)) throw error;
    if (cached?.token === token) cached = null;
    return operation(await adminToken());
  }
}

export function resetDigitAdminToken(): void {
  cached = null;
  pending = null;
}
