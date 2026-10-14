import Boom from '@hapi/boom'
import { logger } from '@defra/lis-hubs-infra-core'
import { HUBS } from '@defra/lis-hubs-infra-registry'

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
const Forbidden = 403

const DEFAULT_NOT_AUTHORISED_PATH = '/auth/not-authorised'

/**
 * Builds the shared response for a hub-level refusal: the user is signed out
 * of the hub and the identity provider and lands on the not-authorised page.
 * With single sign-on, sending them back to login instead could loop.
 *
 * @param {object} options
 * @param {Function} options.buildLogoutUrl - Builds the identity provider's end-session URL.
 * @param {Function} options.getHubJwtCookieName - Returns the hub JWT cookie name.
 * @param {Function} options.getCookieOptions - Returns the hub JWT cookie options.
 * @param {string} options.notAuthorisedPath - Hub path the provider returns the user to.
 * @returns {(request: object, h: object, authSession?: object) => Promise<object>} Clears the session and returns the redirect.
 */
function createRefuseAccess({
  buildLogoutUrl,
  getHubJwtCookieName,
  getCookieOptions,
  notAuthorisedPath
}) {
  return async function refuseAccess(
    request,
    h,
    authSession = getHubAuthSession(request)
  ) {
    let logoutUrl

    // An unavailable identity provider must not leave a refused user signed
    // in, so they are still signed out of the hub and sent to the landing page.
    try {
      logoutUrl = await buildLogoutUrl(request, {
        authSession,
        returnPath: notAuthorisedPath
      })
    } catch (error) {
      logger.warn(
        `Failed to build OIDC logout URL for a refused user [cause=${error?.message}]`
      )
      logoutUrl = notAuthorisedPath
    }

    clearHubAuthSession(request)

    return h
      .redirect(logoutUrl)
      .unstate(getHubJwtCookieName(), getCookieOptions())
  }
}

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
  refuseAccess,
  loginPath
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
      // The refused login was never stored, so its session is passed in.
      if (authorization?.denied) {
        return refuseAccess(request, h, authSession)
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

function createNotAuthorisedRoute({ path, loginPath }) {
  return {
    method: 'GET',
    path,
    options: {
      auth: false
    },
    handler(_request, h) {
      // The view comes from @defra/lis-infra-ui-services, which every hub registers.
      return h
        .view('error/not-authorised', {
          pageTitle: 'Sorry, you are not authorised to view this page',
          signInHref: loginPath
        })
        .code(Forbidden)
    }
  }
}

/**
 * Builds the hub JWT cookie state and the login, `/sso`, `/auth/logout` and
 * `/signout` routes (all `auth: false`), plus the shared not-authorised route
 * when the hub uses the default not-authorised path.
 *
 * @param {object} options - `createHubAuth` options, minus `pluginName` and `authorize`.
 * @param {Function} options.refuseAccess - Shared hub-level refusal response.
 * @param {boolean} options.registerNotAuthorisedRoute - Whether to register the shared not-authorised route.
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
    notAuthorisedPath,
    registerNotAuthorisedRoute,
    refuseAccess
  } = options
  const loginPath = loginRoutes[0].path
  const callbackController = createCallbackController({
    getCookieOptions,
    getHubJwtConfig,
    getHubJwtCookieName,
    completeAuthorizationCodeGrant,
    resolveAuthSession,
    refuseAccess,
    loginPath
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
    },
    ...(registerNotAuthorisedRoute
      ? [createNotAuthorisedRoute({ path: notAuthorisedPath, loginPath })]
      : [])
  ]

  return (server) => {
    server.state(getHubJwtCookieName(), getCookieOptions())
    server.route(routes)
  }
}

function createHubSessionScheme({ loginPath, caller }) {
  return () => ({
    authenticate(request, h) {
      const authSession = getHubAuthSession(request)

      if (authSession) {
        const user = hydrateAuthorization(authSession)

        return h.authenticated({
          credentials: {
            user,
            authorizedSpecies: getAuthorizedSpecies(user),
            caller
          }
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
 * `/signout` routes (all `auth: false`), the shared not-authorised route
 * (`auth: false`, unless the hub sets its own `notAuthorisedPath`), and the
 * `lis-hub-session` scheme and
 * strategy, made the server's default. Signed-out requests to `required`
 * routes redirect to the first login route with a `returnUrl`; `try` routes
 * run unauthenticated. Identity is on `request.auth.credentials`
 * (`{ user, authorizedSpecies, caller }`), where `caller` is the hub's own
 * service name (`lis-hubs-<hubId>`) so views and handlers can read which hub
 * a request belongs to the same way in a hub as in a spoke.
 *
 * @param {object} options - Plugin configuration options.
 * @param {string} [options.pluginName='auth'] - Name of the plugin.
 * @param {string} options.hubId - Registry id of this hub: 'front-office' or 'back-office'.
 * @param {Function} options.getHubJwtCookieName - Function that returns the JWT cookie name.
 * @param {Function} options.getCookieOptions - Function that returns cookie options.
 * @param {Function} options.getHubJwtConfig - Function that returns JWT configuration.
 * @param {Function} options.resolveAuthSession - Function to resolve and enrich auth session with authorization data.
 * @param {Function} options.buildAuthorizationUrl - Function to build OIDC authorization URL.
 * @param {Function} options.completeAuthorizationCodeGrant - Function to complete OIDC authorization code flow.
 * @param {Function} options.buildLogoutUrl - Function to build logout URL.
 * @param {Array<{path: string, providerId: string|Function}>} options.loginRoutes - Login route configurations; the first is where signed-out users are sent.
 * @param {string} [options.notAuthorisedPath='/auth/not-authorised'] - Where a user lands after a hub-level refusal (`resolveAuthSession` returning `{ denied: true }`, or `authorize` returning `false`). They are signed out of the hub and the identity provider first, which returns them here. The default path is registered by this plugin and renders the `error/not-authorised` view with a 403 and a Sign in link to the first login route; a hub that sets its own path registers that route itself.
 * @param {(user: object, request: object) => boolean | Promise<boolean>} [options.authorize] - Optional hub-wide rule for authenticated requests; `false` signs the user out to `notAuthorisedPath`.
 * @returns {{plugin: {name: string, register: Function}}} Hapi plugin object with registration function.
 */
export function createHubAuth({
  pluginName = 'auth',
  hubId,
  authorize,
  notAuthorisedPath,
  ...options
}) {
  if (!HUBS.includes(hubId)) {
    throw new Error(`createHubAuth() requires a hubId of ${HUBS.join(' or ')}`)
  }

  if ('accessDeniedPath' in options) {
    throw new TypeError(
      'createHubAuth() accessDeniedPath was renamed to notAuthorisedPath'
    )
  }

  if (
    notAuthorisedPath !== undefined &&
    !(
      typeof notAuthorisedPath === 'string' &&
      notAuthorisedPath.startsWith('/') &&
      !notAuthorisedPath.startsWith('//')
    )
  ) {
    throw new TypeError(
      "createHubAuth() requires notAuthorisedPath to be a hub path starting with '/'"
    )
  }

  const landingPath = notAuthorisedPath ?? DEFAULT_NOT_AUTHORISED_PATH
  const refuseAccess = createRefuseAccess({
    buildLogoutUrl: options.buildLogoutUrl,
    getHubJwtCookieName: options.getHubJwtCookieName,
    getCookieOptions: options.getCookieOptions,
    notAuthorisedPath: landingPath
  })
  const register = createHubAuthRegistration({
    ...options,
    notAuthorisedPath: landingPath,
    registerNotAuthorisedRoute: notAuthorisedPath === undefined,
    refuseAccess
  })
  const loginPath = options.loginRoutes[0].path
  const caller = `lis-hubs-${hubId}`

  return {
    plugin: {
      name: pluginName,
      register(server) {
        server.auth.scheme(
          HUB_AUTH_STRATEGY,
          createHubSessionScheme({ loginPath, caller })
        )
        server.auth.strategy(HUB_AUTH_STRATEGY, HUB_AUTH_STRATEGY)
        server.auth.default(HUB_AUTH_STRATEGY)

        register(server)

        if (authorize) {
          server.ext('onPostAuth', async (request, h) => {
            if (
              request.auth.isAuthenticated &&
              !(await authorize(request.auth.credentials.user, request))
            ) {
              const response = await refuseAccess(request, h)

              return response.takeover()
            }

            return h.continue
          })
        }
      }
    }
  }
}
