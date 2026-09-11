import { config } from "./config.js";
import { enabledIdentityProviderAliases } from "./identity-admin.js";
import type { IdentityAuthMethod } from "./types.js";

export async function enabledIdentityMethods(): Promise<IdentityAuthMethod[]> {
  const providerAliases = await enabledIdentityProviderAliases();
  return config.identityAuthMethods.filter((method) =>
    method.type === "password" ||
    Boolean(method.idpHint && providerAliases.has(method.idpHint)),
  );
}
