export interface KCClaims {
  sub: string;
  email: string;
  name?: string;
  preferred_username?: string;
  email_verified?: boolean;
  phone_number?: string;
  realm_access?: {
    roles: string[];
  };
  groups?: string[];
  organization?: Record<string, KCOrganizationClaim>;
  nonce?: string;
  azp?: string;
  realm?: string;  // extracted from iss claim
}

export interface KCOrganizationClaim {
  id?: string;
  groups?: string[];
  realm_access?: {
    roles?: string[];
  };
  resource_access?: Record<string, { roles?: string[] }>;
  [attribute: string]: unknown;
}

export interface IdentityTokenSet {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  accessExpiresIn: number;
  refreshExpiresIn?: number;
}

export interface IdentityAuthMethod {
  id: string;
  label: string;
  type: "password" | "oauth" | "magic_link";
  idpHint?: string;
}

export interface SelectedIdentityContext {
  organizationId: string;
  organizationAlias: string;
  tenantId: string;
  name: string;
}

export interface IdentitySession {
  claims: KCClaims;
  /** OIDC client that created this session; absent on sessions created before multi-flow support. */
  oidcClientId?: string;
  accessToken: string;
  refreshToken?: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
}

export interface DigitUser {
  uuid: string;
  userName: string;
  name: string;
  emailId: string;
  mobileNumber: string;
  tenantId: string;
  type: string;
  roles: Array<{ code: string; name: string; tenantId?: string }>;
}

export interface CachedSession {
  user: DigitUser;
  cachedAt: number;
  token?: string;
  tokenExpiry?: number;
}

export interface DigitLoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  UserRequest: DigitUser;
}
