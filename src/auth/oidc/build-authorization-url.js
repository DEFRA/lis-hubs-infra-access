/** @import { Request } from '@hapi/hapi' */
/** @import { Configuration } from 'openid-client' */
/** @import { OidcProvider } from './types.js' */
import * as openidClient from 'openid-client'

import { createHubAuthFlow, setHubAuthFlow } from '../session.js'
import { getReturnUrlFromRequest } from '../tokens.js'

function getRedirectUri(provider, hubOrigin) {
  return new URL(provider.redirectPath, hubOrigin).toString()
}

/**
 * Starts a hub login: stores a fresh PKCE/state/nonce flow in the session
 * and builds the provider's authorization URL to redirect the user to.
 * @param {object} options
 * @param {Configuration} options.oidcConfig - The resolved `openid-client` config.
 * @param {OidcProvider} options.provider
 * @param {string} options.hubOrigin - The hub's public origin.
 * @param {Request} options.request - The Hapi request, for its session.
 * @returns {Promise<string>} The provider's authorization URL.
 */
export async function buildAuthorizationUrl({
  oidcConfig,
  provider,
  hubOrigin,
  request
}) {
  const authFlow = createHubAuthFlow({
    returnUrl: getReturnUrlFromRequest(request)
  })

  setHubAuthFlow(request, authFlow)

  const codeChallenge = await openidClient.calculatePKCECodeChallenge(
    authFlow.codeVerifier
  )
  const parameters = {
    redirect_uri: getRedirectUri(provider, hubOrigin),
    scope: 'openid',
    state: authFlow.state,
    nonce: authFlow.nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  }

  if (provider.serviceId) {
    parameters.serviceId = provider.serviceId
  }

  const authorizationUrl = openidClient.buildAuthorizationUrl(
    oidcConfig,
    parameters
  )

  return authorizationUrl.toString()
}
