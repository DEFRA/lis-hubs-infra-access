/** @import { HubCookieOptions } from '../tokens.js' */
import { clearHubAuthSession } from '../session.js'

/**
 * Creates the hub logout route controller: builds the provider's logout
 * URL, clears the hub session, and removes the hub JWT cookie.
 * @param {object} options
 * @param {HubCookieOptions} options.cookieOptions - Hapi state options for the hub JWT cookie.
 * @param {string} options.hubJwtCookieName - Name of the hub JWT cookie.
 * @param {Function} options.buildLogoutUrl - Builds the provider's logout URL.
 * @returns {{options: {auth: boolean}, handler: Function}} A Hapi route controller.
 */
export function createLogoutController({
  cookieOptions,
  hubJwtCookieName,
  buildLogoutUrl
}) {
  return {
    options: {
      auth: false
    },
    async handler(request, h) {
      const logoutUrl = await buildLogoutUrl(request)

      clearHubAuthSession(request)

      return h.redirect(logoutUrl).unstate(hubJwtCookieName, cookieOptions)
    }
  }
}
