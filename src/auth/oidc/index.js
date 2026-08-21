/** @import { OidcProvider, OidcOperations } from './types.js' */
import { createOidcConfig } from '@defra/hapi-auth-oidc'

import { buildAuthorizationUrl } from './build-authorization-url.js'
import { buildLogoutUrl } from './build-logout-url.js'
import { completeAuthorizationCodeGrant } from './complete-authorization-code-grant.js'
import { defaultAuthProvider } from './default-auth-provider.js'

/**
 * Creates the OIDC operations used by the hub authentication plugin, for a
 * single, statically-configured provider. Discovery happens once, here,
 * before the client is returned - the hub awaits this at server boot.
 *
 * Client authentication defaults to client_secret_post. The provider config
 * can opt into federated credentials instead by supplying its own
 * `authProvider: { type: 'federated', getCredentials }` (e.g. an
 * `@defra/hapi-auth-oidc` WebIdentityTokenProvider or MockProvider) - this
 * package just passes it through to createOidcConfig unchanged.
 *
 * @param {object} options
 * @param {OidcProvider} options.provider
 * @param {string} options.hubOrigin
 *   The hub's own public origin, used to build redirect/logout URIs.
 * @param {(claims: object, context: { providerConfig: OidcProvider }) => object} options.mapUser
 *   Maps verified ID token claims to the hub's user shape.
 * @returns {Promise<OidcOperations>}
 */
export async function createOidcClient({ provider, hubOrigin, mapUser }) {
  const oidcConfig = await createOidcConfig({
    discoveryUri: provider.discoveryUrl,
    clientId: provider.clientId,
    authProvider: provider.authProvider ?? defaultAuthProvider(provider)
  })
  const metadata = oidcConfig.serverMetadata()

  return {
    buildAuthorizationUrl: (request) =>
      buildAuthorizationUrl({ oidcConfig, provider, hubOrigin, request }),

    completeAuthorizationCodeGrant: (request) =>
      completeAuthorizationCodeGrant({
        oidcConfig,
        provider,
        hubOrigin,
        mapUser,
        request
      }),

    buildLogoutUrl: (request) =>
      buildLogoutUrl({ metadata, hubOrigin, request })
  }
}
