import {
  clearHubAuthSession,
  getHubAuthSession,
  setHubAuthSession
} from './session.js'
import {
  getHubJwtCookieOptions,
  getReturnUrlFromRequest,
  issueHubJwt
} from './tokens.js'
import { getAuthorizedSpecies } from '../module-access.js'
import { hydrateAuthorization } from '../authorization.js'

const ServiceUnavailable = 503

function createLoginController({
  getCookieOptions,
  getHubJwtConfig,
  getHubJwtCookieName,
  providerId,
  buildAuthorizationUrl
}) {
  return {
    options: {
      auth: false
    },
    async handler(request, h) {
      const authSession = getHubAuthSession(request)
      const returnUrl = getReturnUrlFromRequest(request)

      if (authSession) {
        const jwt = await issueHubJwt(authSession, getHubJwtConfig())

        return h
          .redirect(returnUrl)
          .state(getHubJwtCookieName(), jwt, getCookieOptions())
      }

      const resolvedProviderId =
        typeof providerId === 'function' ? providerId() : providerId
      let authorizationUrl

      try {
        authorizationUrl = await buildAuthorizationUrl(
          request,
          resolvedProviderId
        )
      } catch (error) {
        request.logger?.error?.(error)

        return h
          .response(
            'Authentication is not available. Check the hub OIDC configuration.'
          )
          .code(ServiceUnavailable)
      }

      return h.redirect(authorizationUrl)
    }
  }
}

function createCallbackController({
  getCookieOptions,
  getHubJwtConfig,
  getHubJwtCookieName,
  completeAuthorizationCodeGrant,
  resolveAuthSession
}) {
  return {
    options: {
      auth: false
    },
    async handler(request, h) {
      if (request.query?.error) {
        throw new Error(request.query?.error_description ?? request.query.error)
      }

      const { user, authSession, accessToken, returnUrl } =
        await completeAuthorizationCodeGrant(request)
      const authorization = await resolveAuthSession({
        user,
        authSession,
        accessToken
      })
      const enrichedAuthSession = {
        ...authSession,
        ...authorization
      }
      const jwt = await issueHubJwt(enrichedAuthSession, getHubJwtConfig())

      setHubAuthSession(request, enrichedAuthSession)

      return h
        .redirect(returnUrl)
        .state(getHubJwtCookieName(), jwt, getCookieOptions())
    }
  }
}

function createLogoutController({
  getCookieOptions,
  getHubJwtCookieName,
  buildLogoutUrl
}) {
  return {
    options: {
      auth: false
    },
    async handler(request, h) {
      const logoutUrl = await buildLogoutUrl(request)

      clearHubAuthSession(request)

      return h
        .redirect(logoutUrl)
        .unstate(getHubJwtCookieName(), getCookieOptions())
    }
  }
}

/**
 * Creates cookie options for hub JWT authentication.
 *
 * @param {object} options - Cookie configuration options.
 * @param {number} options.ttlSeconds - Time to live in seconds for the cookie.
 * @param {boolean} options.isSecure - Whether the cookie should be secure (HTTPS only).
 * @returns {object} Cookie options compatible with Hapi server state configuration.
 */
export function createHubCookieOptions({ ttlSeconds, isSecure }) {
  return getHubJwtCookieOptions({
    ttlSeconds,
    isSecure
  })
}

/**
 * Creates a Hapi plugin for hub authentication with OIDC support.
 *
 * @param {object} options - Plugin configuration options.
 * @param {string} [options.pluginName='auth'] - Name of the plugin.
 * @param {Function} options.getHubJwtCookieName - Function that returns the JWT cookie name.
 * @param {Function} options.getCookieOptions - Function that returns cookie options.
 * @param {Function} options.getHubJwtConfig - Function that returns JWT configuration.
 * @param {Function} options.resolveAuthSession - Function to resolve and enrich auth session with authorization data.
 * @param {Function} options.buildAuthorizationUrl - Function to build OIDC authorization URL.
 * @param {Function} options.completeAuthorizationCodeGrant - Function to complete OIDC authorization code flow.
 * @param {Function} options.buildLogoutUrl - Function to build logout URL.
 * @param {Array<{path: string, providerId: string|Function}>} options.loginRoutes - Array of login route configurations.
 * @returns {{plugin: {name: string, register: Function}}} Hapi plugin object with registration function.
 */
export function createHubAuthPlugin({
  pluginName = 'auth',
  getHubJwtCookieName,
  getCookieOptions,
  getHubJwtConfig,
  resolveAuthSession,
  buildAuthorizationUrl,
  completeAuthorizationCodeGrant,
  buildLogoutUrl,
  loginRoutes
}) {
  const callbackController = createCallbackController({
    getCookieOptions,
    getHubJwtConfig,
    getHubJwtCookieName,
    completeAuthorizationCodeGrant,
    resolveAuthSession
  })
  const logoutController = createLogoutController({
    getCookieOptions,
    getHubJwtCookieName,
    buildLogoutUrl
  })

  return {
    plugin: {
      name: pluginName,
      register(server) {
        server.state(getHubJwtCookieName(), getCookieOptions())
        server.ext('onPreAuth', (request, h) => {
          const authSession = getHubAuthSession(request)
          request.app.hubAuth = authSession
            ? hydrateAuthorization(authSession)
            : null
          request.app.authorizedSpecies = getAuthorizedSpecies(
            request.app.hubAuth
          )

          return h.continue
        })

        server.route([
          ...loginRoutes.map(({ path, providerId }) => ({
            method: 'GET',
            path,
            ...createLoginController({
              getCookieOptions,
              getHubJwtConfig,
              getHubJwtCookieName,
              providerId,
              buildAuthorizationUrl
            })
          })),
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
