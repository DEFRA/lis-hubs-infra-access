/** @import { Request } from '@hapi/hapi' */
import { hydrateAuthorization } from '../../authorization/index.js'
import { statusCodes } from '../../constants/status-codes.js'
import { getSpokeAccessMode, getSpokeById } from './access-mode.js'
import { HUB_SERVICE_SUBJECT } from './constants.js'
import {
  getHubJwtPayloadFromRequest,
  getHubServiceJwtPayloadFromRequest
} from './jwt.js'
import {
  buildHubLoginUrl,
  buildMicrositeReturnUrl,
  isPublicRequest,
  resolveHubOrigin
} from './urls.js'

/**
 * @param {{ name: string, assetPath: string, registerState?: Function, authenticate: Function }} options
 * @returns {object}
 */
function createRequestGuard({ name, assetPath, registerState, authenticate }) {
  return {
    plugin: {
      name,
      register(server) {
        registerState?.(server)

        server.ext('onPreAuth', async (request, h) => {
          if (isPublicRequest(request, assetPath)) {
            return h.continue
          }

          return authenticate(request, h)
        })
      }
    }
  }
}

/**
 * @param {{ hubOrigins: string[], cookieName: string, cookieOptions: object, assetPath: string, port: number, secret: string, audience: string }} options
 * @returns {object}
 */
export function createAuthGuard({
  hubOrigins,
  cookieName,
  cookieOptions,
  assetPath,
  port,
  basePath,
  secret,
  audience
}) {
  return createRequestGuard({
    name: 'authGuard',
    assetPath,
    registerState(server) {
      server.state(cookieName, cookieOptions)
    },
    async authenticate(request, h) {
      const hubJwtPayload = await getHubJwtPayloadFromRequest(request, {
        cookieName,
        secret,
        issuer: hubOrigins,
        audience
      })

      if (!hubJwtPayload) {
        const loginUrl = buildHubLoginUrl({
          hubOrigin: resolveHubOrigin(request, hubOrigins),
          returnUrl: buildMicrositeReturnUrl(request, { port, basePath })
        })

        return h.redirect(loginUrl).takeover()
      }

      request.app.hubAuth = hydrateAuthorization(hubJwtPayload)
      request.app.hubOrigin = resolveHubOrigin(request, hubOrigins)
      return h.continue
    }
  })
}

/**
 * @param {{ assetPath: string, secret: string, hubOrigins: string[], audience: string, taxonomyId: string, spokeId: string }} options
 * @returns {object}
 */
export function createHubServiceGuard({
  assetPath,
  secret,
  hubOrigins,
  audience,
  taxonomyId,
  spokeId
}) {
  return createRequestGuard({
    name: 'hubServiceGuard',
    assetPath,
    async authenticate(request, h) {
      const hubServiceJwtPayload = await getHubServiceJwtPayloadFromRequest(
        request,
        {
          secret,
          issuer: hubOrigins,
          audience,
          taxonomyId,
          spokeId
        }
      )

      if (!hubServiceJwtPayload) {
        return h
          .response({ message: 'Hub service authentication required' })
          .code(statusCodes.unauthorized)
          .takeover()
      }

      hydrateHubServiceActor(request, hubServiceJwtPayload)

      return h.continue
    }
  })
}

function hydrateHubServiceActor(request, hubServiceJwtPayload) {
  request.app.hubServiceAuth = hubServiceJwtPayload
  request.app.hubAuth = hydrateAuthorization({
    sub: hubServiceJwtPayload.actorSub,
    email: hubServiceJwtPayload.actorEmail,
    firstName: hubServiceJwtPayload.actorFirstName,
    lastName: hubServiceJwtPayload.actorLastName,
    statements: Array.isArray(hubServiceJwtPayload.actorStatements)
      ? hubServiceJwtPayload.actorStatements
      : []
  })
}

function createRouteAwareAuthGuard({
  hubOrigins,
  cookieName,
  cookieOptions,
  assetPath,
  port,
  basePath,
  secret,
  audience,
  taxonomyId,
  spokeId
}) {
  return createRequestGuard({
    name: 'routeAwareAuthGuard',
    assetPath,
    registerState(server) {
      server.state(cookieName, cookieOptions)
    },
    async authenticate(request, h) {
      if (request.route?.settings?.app?.authMode === HUB_SERVICE_SUBJECT) {
        const hubServiceJwtPayload = await getHubServiceJwtPayloadFromRequest(
          request,
          { secret, issuer: hubOrigins, audience, taxonomyId, spokeId }
        )

        if (!hubServiceJwtPayload) {
          return h
            .response({ message: 'Hub service authentication required' })
            .code(statusCodes.unauthorized)
            .takeover()
        }

        hydrateHubServiceActor(request, hubServiceJwtPayload)
        return h.continue
      }

      const hubJwtPayload = await getHubJwtPayloadFromRequest(request, {
        cookieName,
        secret,
        issuer: hubOrigins,
        audience
      })

      if (!hubJwtPayload) {
        const loginUrl = buildHubLoginUrl({
          hubOrigin: resolveHubOrigin(request, hubOrigins),
          returnUrl: buildMicrositeReturnUrl(request, { port, basePath })
        })

        return h.redirect(loginUrl).takeover()
      }

      request.app.hubAuth = hydrateAuthorization(hubJwtPayload)
      request.app.hubOrigin = resolveHubOrigin(request, hubOrigins)
      return h.continue
    }
  })
}

/**
 * @param {{ spokeId: string, hubOrigins: string[], cookieName: string, cookieOptions: object, assetPath: string, port: number, secret: string, audience: string, allowHubServiceRoutes?: boolean }} options
 * @returns {object | null}
 */
export function createSpokeGuard({
  spokeId,
  hubOrigins,
  cookieName,
  cookieOptions,
  assetPath,
  port,
  basePath,
  secret,
  audience,
  allowHubServiceRoutes = false
}) {
  const spoke = getSpokeById(spokeId)

  if (!spoke) {
    throw new Error(`Unable to resolve spoke configuration for ${spokeId}`)
  }

  const accessMode = getSpokeAccessMode(spoke)

  if (accessMode === 'public') {
    return null
  }

  if (accessMode === HUB_SERVICE_SUBJECT) {
    return createHubServiceGuard({
      assetPath,
      secret,
      hubOrigins,
      audience,
      taxonomyId: spoke.taxonomy.id,
      spokeId: spoke.id
    })
  }

  if (allowHubServiceRoutes) {
    return createRouteAwareAuthGuard({
      hubOrigins,
      cookieName,
      cookieOptions,
      assetPath,
      port,
      basePath,
      secret,
      audience,
      taxonomyId: spoke.taxonomy.id,
      spokeId: spoke.id
    })
  }

  return createAuthGuard({
    hubOrigins,
    cookieName,
    cookieOptions,
    assetPath,
    port,
    basePath,
    secret,
    audience
  })
}
