/** @import { Request } from '@hapi/hapi' */
/** @import { Configuration } from 'openid-client' */
/** @import { OidcProvider, AuthorizationGrantResult } from './types.js' */
import * as openidClient from 'openid-client'

import { clearHubAuthFlow, getHubAuthFlow } from '../session.js'
import { sanitizeReturnUrl } from '../tokens.js'

function getCurrentCallbackUrl(request, hubOrigin) {
  const url = new URL(hubOrigin)
  url.pathname = request.path
  url.search = request.url.search

  return url
}

function validateServiceIdClaim(claims, provider) {
  if (
    provider.serviceId &&
    claims.serviceId &&
    claims.serviceId !== provider.serviceId
  ) {
    throw new Error('Unexpected serviceId claim')
  }
}

function exchangeAuthorizationCode({
  oidcConfig,
  request,
  hubOrigin,
  provider,
  authFlow
}) {
  const tokenEndpointParameters = provider.serviceId
    ? { serviceId: provider.serviceId }
    : undefined

  return openidClient.authorizationCodeGrant(
    oidcConfig,
    getCurrentCallbackUrl(request, hubOrigin),
    {
      pkceCodeVerifier: authFlow.codeVerifier,
      expectedState: authFlow.state,
      expectedNonce: authFlow.nonce,
      idTokenExpected: true
    },
    tokenEndpointParameters
  )
}

/**
 * Completes a hub login: exchanges the authorization code for tokens,
 * validates the flow and serviceId claim, and maps the user.
 * @param {object} options
 * @param {Configuration} options.oidcConfig - The resolved `openid-client` config.
 * @param {OidcProvider} options.provider
 * @param {string} options.hubOrigin - The hub's public origin.
 * @param {(claims: object, context: { providerConfig: OidcProvider }) => object} options.mapUser
 *   Maps verified ID token claims to the hub's user shape.
 * @param {Request} options.request - The Hapi request, for its session.
 * @returns {Promise<AuthorizationGrantResult>}
 */
export async function completeAuthorizationCodeGrant({
  oidcConfig,
  provider,
  hubOrigin,
  mapUser,
  request
}) {
  const authFlow = getHubAuthFlow(request)

  if (!authFlow?.state || !authFlow?.nonce || !authFlow?.codeVerifier) {
    throw new Error('Authentication flow session was not found')
  }

  const tokenSet = await exchangeAuthorizationCode({
    oidcConfig,
    request,
    hubOrigin,
    provider,
    authFlow
  })

  const claims = tokenSet.claims()
  validateServiceIdClaim(claims, provider)

  const user = mapUser(claims, { providerConfig: provider })
  const authSession = {
    ...user,
    idToken: tokenSet.id_token,
    authenticatedAt: new Date().toISOString()
  }

  clearHubAuthFlow(request)

  return {
    user,
    authSession,
    accessToken: tokenSet.access_token ?? null,
    returnUrl: sanitizeReturnUrl(authFlow.returnUrl)
  }
}
