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
 * Builds the shared response for a hub-level refusal. Authentication and
 * authorisation are kept apart: the user stays signed in to the hub, but no
 * spoke JWT is issued and they land on the not-authorised page, which offers
 * Sign out. A refused sign-in stores its session flagged `refused` so every
 * later request is sent to the same page without re-running the hub's checks.
 *
 * @param {object} options
 * @param {Function} options.getHubJwtCookieName - Returns the hub JWT cookie name.
 * @param {Function} options.getCookieOptions - Returns the hub JWT cookie options.
 * @param {string} options.notAuthorisedPath - Hub path the user lands on.
 * @returns {(request: object, h: object, authSession?: object) => object} Returns the redirect.
 */
function createRefuseAccess({
  getHubJwtCookieName,
  getCookieOptions,
  notAuthorisedPath
}) {
  return function refuseAccess(request, h, authSession) {
    if (authSession) {
      setHubAuthSession(request, { ...authSession, refused: true })
    }

    return h
      .redirect(notAuthorisedPath)
      .unstate(getHubJwtCookieName(), getCookieOptions())
  }
}

function isRefusedSession(authSession) {
  return authSession?.refused === true
}

function createLoginController({
  getCookieOptions,
  getHubJwtConfig,
  getHubJwtCookieName,
  providerId,
  buildAuthorizationUrl,
  notAuthorisedPath,
  isAuthorized,
  refuseAccess
}) {
  return {
    options: {
      auth: false
    },
    async handler(request, h) {
      const authSession = getHubAuthSession(request)
      const returnUrl = getReturnUrlFromRequest(request)

      if (isRefusedSession(authSession)) {
        return h.redirect(notAuthorisedPath)
      }

      // A JWT is only ever issued to an authorised session: this route is
      // auth: false, so the onPostAuth hook does not guard it.
      if (authSession) {
        if (!(await isAuthorized(authSession, request))) {
          return refuseAccess(request, h)
        }

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
  isAuthorized,
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

      // The hub refused this identity (e.g. not on an allow-list): the user
      // stays signed in to the hub so they can sign out from the
      // not-authorised page, but the session is stored flagged refused and no
      // JWT is issued, so no spoke is reachable.
      if (authorization?.denied) {
        return refuseAccess(request, h, authSession)
      }

      const enrichedAuthSession = {
        ...authSession,
        ...authorization
      }

      setHubAuthSession(request, enrichedAuthSession)

      // The hub-wide rule runs before the JWT is minted, so a user it refuses
      // never reaches a spoke, and lands on the not-authorised page signed in.
      if (!(await isAuthorized(enrichedAuthSession, request))) {
        return refuseAccess(request, h)
      }

      const jwt = await issueHubJwt(enrichedAuthSession, getHubJwtConfig())

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
      auth: { mode: 'try' }
    },
    handler(request, h) {
      // The view comes from @defra/lis-infra-ui-services, which every hub
      // registers. A signed-in visitor is offered Sign out, anyone else Sign in.
      const action = request.auth.isAuthenticated
        ? { signOutHref: '/signout' }
        : { signInHref: loginPath }

      return h
        .view('error/not-authorised', {
          pageTitle: 'Sorry, you are not authorised to view this page',
          ...action
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
    refuseAccess,
    isAuthorized
  } = options
  const loginPath = loginRoutes[0].path
  const callbackController = createCallbackController({
    getCookieOptions,
    getHubJwtConfig,
    getHubJwtCookieName,
    completeAuthorizationCodeGrant,
    resolveAuthSession,
    refuseAccess,
    isAuthorized,
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
        buildAuthorizationUrl,
        notAuthorisedPath,
        isAuthorized,
        refuseAccess
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
            caller,
            ...(isRefusedSession(authSession) ? { refused: true } : {})
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
 * @param {string} [options.notAuthorisedPath='/auth/not-authorised'] - Where a user lands after a hub-level refusal (`resolveAuthSession` returning `{ denied: true }`, or `authorize` returning `false`). They stay signed in to the hub, with no spoke JWT, and every other authenticated request is redirected here until they sign out. The default path is registered by this plugin with `auth: try` and renders the `error/not-authorised` view with a 403, offering Sign out to a signed-in visitor and Sign in (to the first login route) to anyone else. A hub that sets its own path registers that route itself and should do the same.
 * @param {(user: object, request: object) => boolean | Promise<boolean>} [options.authorize] - Optional hub-wide rule for authenticated requests; `false` redirects the user to `notAuthorisedPath` without signing them out.
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
    getHubJwtCookieName: options.getHubJwtCookieName,
    getCookieOptions: options.getCookieOptions,
    notAuthorisedPath: landingPath
  })
  // The hub-wide rule, applied wherever a JWT is issued and on every
  // authenticated request. Without a rule every signed-in user is authorised.
  const isAuthorized = async (authSession, request) =>
    !authorize || (await authorize(hydrateAuthorization(authSession), request))
  const register = createHubAuthRegistration({
    ...options,
    notAuthorisedPath: landingPath,
    registerNotAuthorisedRoute: notAuthorisedPath === undefined,
    refuseAccess,
    isAuthorized
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

        server.ext('onPostAuth', async (request, h) => {
          if (!request.auth.isAuthenticated || request.path === landingPath) {
            return h.continue
          }

          const { user, refused } = request.auth.credentials

          if (refused || (authorize && !(await authorize(user, request)))) {
            return refuseAccess(request, h).takeover()
          }

          return h.continue
        })
      }
    }
  }
}
