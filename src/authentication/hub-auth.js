import Boom from '@hapi/boom'
import { logger } from '@defra/lis-hubs-infra-core'

import {
  clearHubAuthSession,
  getHubAuthSession,
  setHubAuthSession
} from './session.js'
import {
  getHubJwtCookieOptions,
  getReturnUrlFromRequest,
  issueHubJwt
} from './tokens/index.js'
import { getAuthorizedSpecies } from '../authorization/modules/species.js'
import { hydrateAuthorization } from '../authorization/permissions/hydrate.js'

export const HUB_AUTH_STRATEGY = 'lis-hub-session'

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
        const cause =
          error?.cause?.message ?? error?.cause?.code ?? error?.cause
        logger.error(
          error,
          `Failed to build OIDC authorization URL [cause=${cause}]`
        )

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
  resolveAuthSession,
  buildLogoutUrl,
  loginPath,
  accessDeniedPath
}) {
  return {
    options: {
      auth: false
    },
    async handler(request, h) {
      if (request.query?.error) {
        throw new Error(request.query?.error_description ?? request.query.error)
      }

      const grant = await completeAuthorizationCodeGrant(request)

      // A replayed identity provider page (e.g. browser back button after
      // signing in) returns a state the hub no longer holds. Restarting
      // login sends an already-authenticated user straight on and gives
      // anyone else a fresh flow, instead of failing the callback.
      if (grant?.stale) {
        return h.redirect(loginPath)
      }

      const { user, authSession, accessToken, returnUrl } = grant
      const authorization = await resolveAuthSession({
        user,
        authSession,
        accessToken
      })

      // The hub refused this identity (e.g. not on an allow-list): no session
      // or JWT is issued, any earlier one is dropped, and the user is signed
      // out of the identity provider so the next login asks for credentials.
      if (authorization?.denied) {
        clearHubAuthSession(request)

        const logoutUrl = await buildLogoutUrl(request, {
          authSession,
          returnPath: accessDeniedPath
        })

        return h
          .redirect(logoutUrl)
          .unstate(getHubJwtCookieName(), getCookieOptions())
      }

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
 * Builds the hub JWT cookie state and the login, `/sso`, `/auth/logout` and
 * `/signout` routes (all `auth: false`).
 *
 * @param {object} options - `createHubAuth` options, minus `pluginName` and `authorize`.
 * @returns {(server: object) => void} Registers the cookie state and routes on a server.
 */
function createHubAuthRegistration(options) {
  const {
    getHubJwtCookieName,
    getCookieOptions,
    getHubJwtConfig,
    resolveAuthSession,
    buildAuthorizationUrl,
    completeAuthorizationCodeGrant,
    buildLogoutUrl,
    loginRoutes,
    accessDeniedPath
  } = options
  const callbackController = createCallbackController({
    getCookieOptions,
    getHubJwtConfig,
    getHubJwtCookieName,
    completeAuthorizationCodeGrant,
    resolveAuthSession,
    buildLogoutUrl,
    loginPath: loginRoutes[0].path,
    accessDeniedPath
  })
  const logoutController = createLogoutController({
    getCookieOptions,
    getHubJwtCookieName,
    buildLogoutUrl
  })
  const routes = [
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
    },
    {
      // The shared nunjucks layout's header nav links here (see
      // createNunjucksContextBuilder's logoutUrl default).
      method: 'GET',
      path: '/signout',
      options: {
        auth: false
      },
      handler(_request, h) {
        return h.redirect('/auth/logout')
      }
    }
  ]

  return (server) => {
    server.state(getHubJwtCookieName(), getCookieOptions())
    server.route(routes)
  }
}

function createHubSessionScheme(loginPath) {
  return () => ({
    authenticate(request, h) {
      const authSession = getHubAuthSession(request)

      if (authSession) {
        const user = hydrateAuthorization(authSession)

        return h.authenticated({
          credentials: { user, authorizedSpecies: getAuthorizedSpecies(user) }
        })
      }

      if (request.auth.mode === 'required') {
        const returnUrl = encodeURIComponent(
          `${request.path}${request.url.search}`
        )

        return h.redirect(`${loginPath}?returnUrl=${returnUrl}`).takeover()
      }

      return h.unauthenticated(Boom.unauthorized(null, HUB_AUTH_STRATEGY))
    }
  })
}

/**
 * Creates a Hapi plugin for hub authentication built on a Hapi auth scheme.
 *
 * Registers the hub JWT cookie state, the login, `/sso`, `/auth/logout` and
 * `/signout` routes (all `auth: false`), and the `lis-hub-session` scheme and
 * strategy, made the server's default. Signed-out requests to `required`
 * routes redirect to the first login route with a `returnUrl`; `try` routes
 * run unauthenticated. Identity is on `request.auth.credentials`
 * (`{ user, authorizedSpecies }`).
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
 * @param {Array<{path: string, providerId: string|Function}>} options.loginRoutes - Login route configurations; the first is where signed-out users are sent.
 * @param {string} [options.accessDeniedPath] - Where the identity provider returns a user after `resolveAuthSession` refuses them with `{ denied: true }` (they are signed out of the provider first); defaults to the hub origin. The hub registers this route itself.
 * @param {(user: object, request: object) => boolean | Promise<boolean>} [options.authorize] - Optional hub-wide rule for authenticated requests; `false` gives a 403.
 * @returns {{plugin: {name: string, register: Function}}} Hapi plugin object with registration function.
 */
export function createHubAuth({ pluginName = 'auth', authorize, ...options }) {
  const register = createHubAuthRegistration(options)
  const loginPath = options.loginRoutes[0].path

  return {
    plugin: {
      name: pluginName,
      register(server) {
        server.auth.scheme(HUB_AUTH_STRATEGY, createHubSessionScheme(loginPath))
        server.auth.strategy(HUB_AUTH_STRATEGY, HUB_AUTH_STRATEGY)
        server.auth.default(HUB_AUTH_STRATEGY)

        register(server)

        if (authorize) {
          server.ext('onPostAuth', async (request, h) => {
            if (
              request.auth.isAuthenticated &&
              !(await authorize(request.auth.credentials.user, request))
            ) {
              return Boom.forbidden()
            }

            return h.continue
          })
        }
      }
    }
  }
}
