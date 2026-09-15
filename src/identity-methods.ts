import { config } from "./config.js";
import {
  enabledIdentityClientIds,
  enabledIdentityProviderAliases,
} from "./identity-admin.js";
import type { IdentityAuthMethod } from "./types.js";

export async function enabledIdentityMethods(): Promise<IdentityAuthMethod[]> {
  const needsProviders = config.identityAuthMethods.some((method) => method.type === "oauth");
  const needsMagicLink = config.identityAuthMethods.some((method) => method.type === "magic_link");
  const [providerAliases, clientIds] = await Promise.all([
    needsProviders ? enabledIdentityProviderAliases() : Promise.resolve(new Set<string>()),
    needsMagicLink
      ? enabledIdentityClientIds([config.keycloakMagicLinkClientId])
      : Promise.resolve(new Set<string>()),
  ]);
  return config.identityAuthMethods.filter((method) =>
    method.type === "password" ||
    (method.type === "oauth" && Boolean(method.idpHint && providerAliases.has(method.idpHint))) ||
    (method.type === "magic_link" &&
      Boolean(config.keycloakMagicLinkClientSecret) &&
      clientIds.has(config.keycloakMagicLinkClientId)),
  );
}
