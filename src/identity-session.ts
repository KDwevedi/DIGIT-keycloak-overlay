import { createHash, randomBytes } from "node:crypto";
import { config } from "./config.js";
import { getRedis } from "./cache.js";
import type { IdentitySession, IdentityTokenSet, KCClaims } from "./types.js";

interface LoginAttempt {
  codeVerifier: string;
}

function randomId(): string {
  return randomBytes(32).toString("base64url");
}

function loginKey(state: string): string {
  return `${config.cachePrefix}:identity:login:${state}`;
}

function sessionKey(sessionId: string): string {
  return `${config.cachePrefix}:identity:session:${sessionId}`;
}

export async function createLoginAttempt(): Promise<{
  state: string;
  codeVerifier: string;
  codeChallenge: string;
}> {
  const state = randomId();
  const codeVerifier = randomId();
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  await getRedis().set(
    loginKey(state),
    JSON.stringify({ codeVerifier } satisfies LoginAttempt),
    "EX",
    config.identityLoginTtlSeconds,
  );
  return { state, codeVerifier, codeChallenge };
}

export async function consumeLoginAttempt(
  state: string,
): Promise<LoginAttempt | null> {
  const raw = await getRedis().getdel(loginKey(state));
  if (!raw) return null;
  try {
    const attempt = JSON.parse(raw) as LoginAttempt;
    return typeof attempt.codeVerifier === "string" ? attempt : null;
  } catch {
    return null;
  }
}

function sessionTtl(tokens: IdentityTokenSet): number {
  const tokenTtl = tokens.refreshExpiresIn || tokens.accessExpiresIn;
  return Math.max(1, Math.min(config.identitySessionTtlSeconds, tokenTtl));
}

export async function createIdentitySession(
  tokens: IdentityTokenSet,
  claims: KCClaims,
): Promise<{ sessionId: string; maxAge: number }> {
  const sessionId = randomId();
  const maxAge = sessionTtl(tokens);
  await saveIdentitySession(sessionId, tokens, claims, maxAge);
  return { sessionId, maxAge };
}

export async function saveIdentitySession(
  sessionId: string,
  tokens: IdentityTokenSet,
  claims: KCClaims,
  ttl = sessionTtl(tokens),
): Promise<void> {
  const now = Date.now();
  const session: IdentitySession = {
    claims,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    accessExpiresAt: now + tokens.accessExpiresIn * 1000,
    refreshExpiresAt: tokens.refreshExpiresIn
      ? now + tokens.refreshExpiresIn * 1000
      : undefined,
  };
  await getRedis().set(
    sessionKey(sessionId),
    JSON.stringify(session),
    "EX",
    ttl,
  );
}

export async function getIdentitySession(
  sessionId: string,
): Promise<IdentitySession | null> {
  const raw = await getRedis().get(sessionKey(sessionId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as IdentitySession;
  } catch {
    return null;
  }
}

export async function deleteIdentitySession(sessionId: string): Promise<void> {
  await getRedis().del(sessionKey(sessionId));
}

function cookieValue(cookieHeader: string | undefined, cookieName: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (name === cookieName) {
      return valueParts.join("=") || null;
    }
  }
  return null;
}

export function sessionIdFromCookie(cookieHeader?: string): string | null {
  return cookieValue(cookieHeader, config.identityCookieName);
}

export function loginStateFromCookie(cookieHeader?: string): string | null {
  return cookieValue(cookieHeader, `${config.identityCookieName}_login`);
}

export function sessionCookie(sessionId: string, maxAge: number): string {
  const secure = config.identityCookieSecure ? "; Secure" : "";
  return `${config.identityCookieName}=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export function clearedSessionCookie(): string {
  const secure = config.identityCookieSecure ? "; Secure" : "";
  return `${config.identityCookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

export function loginCookie(state: string): string {
  const secure = config.identityCookieSecure ? "; Secure" : "";
  return `${config.identityCookieName}_login=${state}; Path=/identity/v1/callback; HttpOnly; SameSite=Lax; Max-Age=${config.identityLoginTtlSeconds}${secure}`;
}

export function clearedLoginCookie(): string {
  const secure = config.identityCookieSecure ? "; Secure" : "";
  return `${config.identityCookieName}_login=; Path=/identity/v1/callback; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}
