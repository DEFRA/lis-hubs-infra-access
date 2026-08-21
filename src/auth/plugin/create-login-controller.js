/** @import { HubJwtConfig, HubCookieOptions } from '../tokens.js' */
import { getHubAuthSession } from '../session.js'
import { getReturnUrlFromRequest, issueHubJwt } from '../tokens.js'

const ServiceUnavailable = 503

/**
 * Creates the hub login route controller: redirects an already-authenticated
 * user straight back with a refreshed JWT, or starts a new OIDC login.
 * @param {object} options
 * @param {HubCookieOptions} options.cookieOptions - Hapi state options for the hub JWT cookie.
 * @param {HubJwtConfig} options.hubJwtConfig - Config passed to issueHubJwt.
 * @param {string} options.hubJwtCookieName - Name of the hub JWT cookie.
 * @param {Function} options.buildAuthorizationUrl - Builds the OIDC authorization URL.
 * @returns {{options: {auth: boolean}, handler: Function}} A Hapi route controller.
 */
export function createLoginController({
  cookieOptions,
  hubJwtConfig,
  hubJwtCookieName,
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
        const jwt = await issueHubJwt(authSession, hubJwtConfig)

        return h.redirect(returnUrl).state(hubJwtCookieName, jwt, cookieOptions)
      }

      let authorizationUrl

      try {
        authorizationUrl = await buildAuthorizationUrl(request)
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
