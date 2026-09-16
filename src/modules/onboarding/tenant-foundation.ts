import { config } from "../../infrastructure/config.js";
import { withDigitProvisioner } from "../managed-accounts/digit-admin-session.js";
import { DigitUnauthorizedError, DigitUnavailableError } from "../managed-accounts/digit-user-client.js";
import { clearTenantCaches, isActiveDigitTenant } from "../access-context/tenant-directory.js";

export interface TenantFoundationSignup {
  requestedTenantId: string;
  accountName: string;
}

interface SchemaDefinition {
  code: string;
  description?: string;
  definition: Record<string, unknown>;
}

function requestInfo(token: string) {
  return { apiId: "digit-identity-bff", ver: "1.0", ts: Date.now(), authToken: token };
}

async function post(url: string, body: unknown, operation: string): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(config.digitTimeoutMs),
    });
  } catch {
    throw new DigitUnavailableError(`DIGIT ${operation} request failed`);
  }
  if (response.status === 401 || response.status === 403) {
    await response.body?.cancel();
    throw new DigitUnauthorizedError(`DIGIT ${operation} was not authorized`);
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new DigitUnavailableError(`DIGIT ${operation} returned ${response.status}`,
      response.status === 400 || response.status === 409 ? 409 : 503);
  }
  try {
    return await response.json() as Record<string, unknown>;
  } catch {
    return {};
  }
}

async function tenantSchema(token: string, tenantId: string): Promise<SchemaDefinition | null> {
  const body = await post(config.digitMdmsSchemaSearchUrl, {
    RequestInfo: requestInfo(token),
    SchemaDefCriteria: { tenantId, codes: ["tenant.tenants"], limit: 10 },
  }, "tenant schema search");
  const schemas = Array.isArray(body.SchemaDefinitions)
    ? body.SchemaDefinitions as SchemaDefinition[]
    : [];
  return schemas.find((schema) => schema.code === "tenant.tenants") || null;
}

async function ensureTenantSchema(token: string, target: string): Promise<void> {
  if (await tenantSchema(token, target)) return;
  const source = await tenantSchema(token, config.digitFoundationSourceTenant);
  if (!source) {
    throw new DigitUnavailableError(
      `Foundation source ${config.digitFoundationSourceTenant} has no tenant.tenants schema`, 409,
    );
  }
  try {
    await post(config.digitMdmsSchemaCreateUrl, {
      RequestInfo: requestInfo(token),
      SchemaDefinition: {
        tenantId: target,
        code: source.code,
        description: source.description || source.code,
        definition: source.definition,
        isActive: true,
      },
    }, "tenant schema create");
  } catch (error) {
    if (!(error instanceof DigitUnavailableError) || error.status !== 409 ||
        !await tenantSchema(token, target)) throw error;
  }
}

async function ensureTenantRecord(token: string, signup: TenantFoundationSignup): Promise<void> {
  if (await isActiveDigitTenant(signup.requestedTenantId)) return;
  const tenantId = signup.requestedTenantId;
  try {
    await post(`${config.digitMdmsCreateUrl.replace(/\/$/, "")}/tenant.tenants`, {
      RequestInfo: requestInfo(token),
      Mdms: {
        tenantId,
        schemaCode: "tenant.tenants",
        uniqueIdentifier: tenantId,
        isActive: true,
        data: {
          tenantId,
          code: tenantId,
          name: signup.accountName,
          description: `Independent root tenant for ${signup.accountName}`,
          imageId: null,
        },
      },
    }, "tenant record create");
  } catch (error) {
    if (!(error instanceof DigitUnavailableError) || error.status !== 409) throw error;
  }
  for (let attempt = 0; attempt < 20; attempt += 1) {
    clearTenantCaches();
    if (await isActiveDigitTenant(tenantId)) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new DigitUnavailableError("DIGIT accepted the tenant record but it is not visible yet");
}

/** egov-user writes PII, so even an otherwise empty tenant needs an encryption key. */
async function ensureEncryptionKey(signup: TenantFoundationSignup): Promise<void> {
  if (!config.digitEncGenerateKeyUrl) return;
  await post(config.digitEncGenerateKeyUrl, {
    RequestInfo: { apiId: "digit-identity-bff" },
    tenantId: signup.requestedTenantId,
  }, "encryption key generation");
}

/**
 * Creates only what is required for an independent root tenant to appear in
 * identity and own an egov-user account. Application configuration is deferred.
 */
export async function ensureTenantFoundation(signup: TenantFoundationSignup): Promise<void> {
  await withDigitProvisioner(async (token) => {
    await ensureTenantSchema(token, signup.requestedTenantId);
    await ensureTenantRecord(token, signup);
  });
  await ensureEncryptionKey(signup);
}
