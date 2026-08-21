/** @import { HubCookieOptions } from '../tokens.js' */
import { getHubJwtCookieOptions } from '../tokens.js'

/**
 * Creates cookie options for hub JWT authentication.
 * @param {object} options - Cookie configuration options.
 * @param {number} options.ttlSeconds - Time to live in seconds for the cookie.
 * @param {boolean} options.isSecure - Whether the cookie should be secure (HTTPS only).
 * @returns {HubCookieOptions}
 */
export function createHubCookieOptions({ ttlSeconds, isSecure }) {
  return getHubJwtCookieOptions({
    ttlSeconds,
    isSecure
  })
}
