/** @import { HubJwtConfig, HubCookieOptions } from '../tokens.js' */
/** @import { OidcProvider } from '../oidc/types.js' */
import { createOidcClient } from '../oidc/index.js'
import { createCallbackController } from './create-callback-controller.js'
import { createLoginController } from './create-login-controller.js'
import { createLogoutController } from './create-logout-controller.js'
import { preAuthExtension } from './pre-auth-extension.js'

export { createHubCookieOptions } from './create-hub-cookie-options.js'

/**
 * Creates a Hapi plugin for hub authentication with OIDC support. Builds its
 * own OIDC client from the given provider config - see createOidcClient's
 * JSDoc for what `provider`/`hubOrigin`/`mapUser` should look like.
 *
 * @param {object} options - Plugin configuration options.
 * @param {string} [options.pluginName='auth'] - Name of the plugin.
 * @param {string} options.hubJwtCookieName - Name of the hub JWT cookie.
 * @param {HubCookieOptions} options.cookieOptions - Hapi state options for the hub JWT cookie.
 * @param {HubJwtConfig} options.hubJwtConfig - Config passed to issueHubJwt.
 * @param {Function} options.resolveAuthSession - Function to resolve and enrich auth session with authorization data.
 * @param {OidcProvider} options.provider - The OIDC provider config passed to createOidcClient.
 * @param {string} options.hubOrigin - The hub's own public origin, passed to createOidcClient.
 * @param {Function} options.mapUser - Maps verified ID token claims to the hub's user shape.
 * @param {string} options.loginPath - Path to register the login route on.
 * @returns {Promise<{plugin: {name: string, register: Function}}>} Hapi plugin object with registration function.
 */
export async function createHubAuthPlugin({
  pluginName = 'auth',
  hubJwtCookieName,
  cookieOptions,
  hubJwtConfig,
  resolveAuthSession,
  provider,
  hubOrigin,
  mapUser,
  loginPath
}) {
  const {
    buildAuthorizationUrl,
    completeAuthorizationCodeGrant,
    buildLogoutUrl
  } = await createOidcClient({ provider, hubOrigin, mapUser })

  const loginController = createLoginController({
    cookieOptions,
    hubJwtConfig,
    hubJwtCookieName,
    buildAuthorizationUrl
  })
  const callbackController = createCallbackController({
    cookieOptions,
    hubJwtConfig,
    hubJwtCookieName,
    completeAuthorizationCodeGrant,
    resolveAuthSession
  })
  const logoutController = createLogoutController({
    cookieOptions,
    hubJwtCookieName,
    buildLogoutUrl
  })

  return {
    plugin: {
      name: pluginName,
      register(server) {
        server.state(hubJwtCookieName, cookieOptions)
        server.ext('onPreAuth', preAuthExtension)

        server.route([
          {
            method: 'GET',
            path: loginPath,
            ...loginController
          },
          {
            method: 'GET',
            path: '/sso',
            ...callbackController
          },
          {
            method: 'GET',
            path: '/auth/logout',
            ...logoutController
          }
        ])
      }
    }
  }
}
