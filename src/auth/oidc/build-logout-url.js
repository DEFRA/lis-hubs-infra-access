/** @import { Request } from '@hapi/hapi' */
/** @import { ServerMetadata } from 'openid-client' */
import { getHubAuthSession } from '../session.js'

/**
 * Builds the provider's logout URL for the current hub session.
 * @param {object} options
 * @param {ServerMetadata} options.metadata - The resolved OIDC server metadata.
 * @param {string} options.hubOrigin - The hub's public origin.
 * @param {Request} options.request - The Hapi request, for its session.
 * @returns {string} The provider's end-session URL.
 */
export function buildLogoutUrl({ metadata, hubOrigin, request }) {
  const authSession = getHubAuthSession(request)
  const logoutUrl = new URL(metadata.end_session_endpoint)

  logoutUrl.searchParams.set('post_logout_redirect_uri', hubOrigin)

  if (authSession?.idToken) {
    logoutUrl.searchParams.set('id_token_hint', authSession.idToken)
  }

  return logoutUrl.toString()
}
