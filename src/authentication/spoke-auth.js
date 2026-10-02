/** @import { Module, ModuleAccess } from '../authorization/modules/module-access.js' */
import Boom from '@hapi/boom'

import { hydrateAuthorization } from '../authorization/permissions/hydrate.js'
import {
  hasModuleAccess,
  normalizeModuleAccess
} from '../authorization/modules/module-access.js'
import { logInvalidServiceToken, logMissingServiceToken } from './logging.js'
import { createServiceTokenVerifier } from './service-token/verifier.js'
import { getSpokeAccessMode, getSpokeById } from './tokens/access-mode.js'
import {
  getAuthorizationBearerToken,
  getHubJwtPayloadFromRequest
} from './tokens/jwt.js'
import {
  buildHubLoginUrl,
  buildMicrositeReturnUrl,
  resolveHubOrigin
} from './tokens/urls.js'

export const SPOKE_AUTH_STRATEGY = 'lis-spoke'

const UNAUTHORIZED = 401

function rejectService(h) {
  return h
    .response({ message: 'Service authentication required' })
    .code(UNAUTHORIZED)
    .takeover()
}

function createCallerVerifier(spokeId) {
  const verifier = createServiceTokenVerifier({
    audience: `lis-apps-${spokeId}`
  })

  return async (request) => {
    const token = getAuthorizationBearerToken(request)

    if (!token) {
      logMissingServiceToken(request)
      return null
    }

    try {
      const { serviceName } = await verifier.verify(token)
      return serviceName
    } catch (error) {
      logInvalidServiceToken(error)
      return null
    }
  }
}

function createAuthenticate({
  verifyCaller,
  isPublic,
  hubOrigins,
  cookieName,
  port,
  basePath,
  secret,
  audience
}) {
  return async (request, h) => {
    const caller = await verifyCaller(request)

    if (!caller) {
      return rejectService(h)
    }

    const payload = await getHubJwtPayloadFromRequest(request, {
      cookieName,
      secret,
      issuer: hubOrigins,
      audience
    })

    if (!payload && !isPublic) {
      if (request.auth.mode === 'required') {
        const loginUrl = buildHubLoginUrl({
          hubOrigin: resolveHubOrigin(request, hubOrigins),
          returnUrl: buildMicrositeReturnUrl(request, { port, basePath })
        })

        return h.redirect(loginUrl).takeover()
      }

      return h.unauthenticated(Boom.unauthorized(null, SPOKE_AUTH_STRATEGY))
    }

    const user = payload ? hydrateAuthorization(payload) : null

    return h.authenticated({ credentials: { user, caller } })
  }
}

function createAccessCheck({ isPublic, moduleAccess, authorize }) {
  return async (request, h) => {
    if (!request.auth.isAuthenticated) {
      return h.continue
    }

    const { user } = request.auth.credentials

    if (!isPublic && !hasModuleAccess(user, moduleAccess)) {
      return Boom.forbidden()
    }

    if (authorize && !(await authorize(user, request))) {
      return Boom.forbidden()
    }

    return h.continue
  }
}

/**
 * Creates a Hapi plugin that registers the `lis-spoke` auth scheme as the
 * server's default strategy. Every authenticated request needs a valid hub
 * service token (`Authorization: Bearer`) and, unless the spoke is public, a
 * valid hub JWT cookie. Routes opt out with `auth: false`, or accept signed-out
 * users with `auth: { mode: 'try' }` or `auth: { mode: 'optional' }`.
 *
 * @param {object} options
 * @param {string} options.spokeId - Registry id of this spoke; the service token audience is `lis-apps-<spokeId>`.
 * @param {string[]} options.hubOrigins - Accepted hub JWT issuers; the first is the default login origin.
 * @param {string} options.cookieName - Hub JWT cookie name.
 * @param {object} options.cookieOptions - Hapi state options for the hub JWT cookie.
 * @param {number} options.port - Spoke port, used to build the login return URL.
 * @param {string} [options.basePath] - Spoke base path, used to build the login return URL.
 * @param {string} options.secret - Hub JWT signing secret.
 * @param {string} options.audience - Hub JWT audience.
 * @param {ModuleAccess|Module} options.moduleAccess - Module access requirements or module object.
 * @param {(user: object | null, request: object) => boolean | Promise<boolean>} [options.authorize] - Optional spoke-wide rule; `false` gives a 403.
 * @returns {{ plugin: { name: string, register: Function } }}
 */
export function createSpokeAuth({
  spokeId,
  hubOrigins,
  cookieName,
  cookieOptions,
  port,
  basePath,
  secret,
  audience,
  moduleAccess,
  authorize
}) {
  const spoke = getSpokeById(spokeId)

  if (!spoke) {
    throw new Error(`Unable to resolve spoke configuration for ${spokeId}`)
  }

  const resolvedModuleAccess = normalizeModuleAccess(moduleAccess)

  if (!resolvedModuleAccess) {
    throw new Error('Unable to resolve module access configuration')
  }

  const isPublic = getSpokeAccessMode(spoke) === 'public'
  const authenticate = createAuthenticate({
    verifyCaller: createCallerVerifier(spokeId),
    isPublic,
    hubOrigins,
    cookieName,
    port,
    basePath,
    secret,
    audience
  })
  const accessCheck = createAccessCheck({
    isPublic,
    moduleAccess: resolvedModuleAccess,
    authorize
  })

  return {
    plugin: {
      name: 'spokeAuth',
      register(server) {
        server.state(cookieName, cookieOptions)
        server.auth.scheme(SPOKE_AUTH_STRATEGY, () => ({ authenticate }))
        server.auth.strategy(SPOKE_AUTH_STRATEGY, SPOKE_AUTH_STRATEGY)
        server.auth.default(SPOKE_AUTH_STRATEGY)
        server.ext('onPostAuth', accessCheck)
      }
    }
  }
}
