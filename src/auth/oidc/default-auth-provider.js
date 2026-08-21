/** @import { OidcProvider } from './types.js' */

/**
 * Builds the client_secret_post auth provider used when a provider config
 * doesn't supply its own `authProvider`.
 * @param {OidcProvider} provider
 * @returns {{ type: 'client_secret', getCredentials: () => Promise<string> }}
 *   An `@defra/hapi-auth-oidc` auth provider.
 */
export function defaultAuthProvider(provider) {
  return {
    type: 'client_secret',
    getCredentials: async () => provider.clientSecret
  }
}
