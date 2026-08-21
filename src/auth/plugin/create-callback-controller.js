/** @import { HubJwtConfig, HubCookieOptions } from '../tokens.js' */
import { setHubAuthSession } from '../session.js'
import { issueHubJwt } from '../tokens.js'

/**
 * Creates the hub SSO callback route controller: completes the OIDC
 * authorization code grant, resolves the hub's authorization for the user,
 * and mints a fresh hub JWT.
 * @param {object} options
 * @param {HubCookieOptions} options.cookieOptions - Hapi state options for the hub JWT cookie.
 * @param {HubJwtConfig} options.hubJwtConfig - Config passed to issueHubJwt.
 * @param {string} options.hubJwtCookieName - Name of the hub JWT cookie.
 * @param {Function} options.completeAuthorizationCodeGrant - Completes the OIDC token exchange.
 * @param {Function} options.resolveAuthSession - Resolves and enriches the auth session with authorization data.
 * @returns {{options: {auth: boolean}, handler: Function}} A Hapi route controller.
 */
export function createCallbackController({
  cookieOptions,
  hubJwtConfig,
  hubJwtCookieName,
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
      const jwt = await issueHubJwt(enrichedAuthSession, hubJwtConfig)

      setHubAuthSession(request, enrichedAuthSession)

      return h.redirect(returnUrl).state(hubJwtCookieName, jwt, cookieOptions)
    }
  }
}
