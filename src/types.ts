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

export interface OrganizationTenantMapping {
  organizationId: string;
  tenantId: string;
  name: string;
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
