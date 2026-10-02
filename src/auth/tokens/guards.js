/** @import { Request } from '@hapi/hapi' */
import { hydrateAuthorization } from '../../authorization/index.js'
import { getSpokeAccessMode, getSpokeById } from './access-mode.js'
import { getHubJwtPayloadFromRequest } from './jwt.js'
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
 * @param {{ spokeId: string, hubOrigins: string[], cookieName: string, cookieOptions: object, assetPath: string, port: number, secret: string, audience: string }} options
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
  audience
}) {
  const spoke = getSpokeById(spokeId)

  if (!spoke) {
    throw new Error(`Unable to resolve spoke configuration for ${spokeId}`)
  }

  const accessMode = getSpokeAccessMode(spoke)

  if (accessMode === 'public') {
    return null
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
