import crypto from 'node:crypto'

import { createRemoteJWKSet, jwtVerify } from 'jose'

import {
  clearHubAuthFlow,
  createHubAuthFlow,
  getHubAuthFlow,
  getHubAuthSession,
  setHubAuthFlow
} from './session.js'
import { getReturnUrlFromRequest, sanitizeReturnUrl } from './tokens.js'

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options)

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${response.status}`)
  }

  return response.json()
}

function createProviderResolver({ getProviderConfig, getPrimaryProviderId }) {
  function resolveProviderId(providerId) {
    const resolvedProviderId = providerId ?? getPrimaryProviderId?.()

    if (!resolvedProviderId) {
      throw new Error('Authentication provider id is required')
    }

    return resolvedProviderId
  }

  return function resolveProviderConfig(providerId) {
    const resolvedProviderId = resolveProviderId(providerId)
    const providerConfig = getProviderConfig(resolvedProviderId)

    if (!providerConfig?.discoveryUrl) {
      throw new Error(
        `OIDC discovery URL is not configured for provider ${resolvedProviderId}`
      )
    }

    return { providerId: resolvedProviderId, ...providerConfig }
  }
}

function createMetadataLoader(resolveProviderConfig) {
  const providerMetadata = new Map()

  return async function getOidcMetadata(providerId) {
    const providerConfig = resolveProviderConfig(providerId)

    if (!providerMetadata.has(providerConfig.providerId)) {
      providerMetadata.set(
        providerConfig.providerId,
        fetchJson(providerConfig.discoveryUrl)
      )
    }

    return providerMetadata.get(providerConfig.providerId)
  }
}

function createRedirectUriResolver(resolveProviderConfig, getHubOrigin) {
  return function getRedirectUri(providerId) {
    const providerConfig = resolveProviderConfig(providerId)
    return new URL(providerConfig.redirectPath, getHubOrigin()).toString()
  }
}

function createCodeExchanger({
  resolveProviderConfig,
  getOidcMetadata,
  getRedirectUri
}) {
  return async function exchangeCodeForTokens(providerId, code, codeVerifier) {
    const providerConfig = resolveProviderConfig(providerId)
    const metadata = await getOidcMetadata(providerConfig.providerId)
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: getRedirectUri(providerConfig.providerId),
      client_id: providerConfig.clientId,
      client_secret: providerConfig.clientSecret,
      code_verifier: codeVerifier
    })

    if (providerConfig.serviceId) {
      body.set('serviceId', providerConfig.serviceId)
    }

    return fetchJson(metadata.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body
    })
  }
}

function addAuthorizationParameters(
  authorizationUrl,
  { providerConfig, redirectUri, authFlow }
) {
  const parameters = {
    client_id: providerConfig.clientId,
    response_type: 'code',
    scope: providerConfig.scope ?? 'openid',
    redirect_uri: redirectUri,
    state: authFlow.state,
    nonce: authFlow.nonce,
    code_challenge: crypto
      .createHash('sha256')
      .update(authFlow.codeVerifier)
      .digest('base64url'),
    code_challenge_method: 'S256'
  }

  for (const [name, value] of Object.entries(parameters)) {
    authorizationUrl.searchParams.set(name, value)
  }

  if (providerConfig.serviceId) {
    authorizationUrl.searchParams.set('serviceId', providerConfig.serviceId)
  }
}

function createAuthorizationUrlBuilder({
  resolveProviderConfig,
  getOidcMetadata,
  getRedirectUri
}) {
  return async function buildAuthorizationUrl(request, providerId) {
    const providerConfig = resolveProviderConfig(providerId)
    const metadata = await getOidcMetadata(providerConfig.providerId)
    const authFlow = {
      ...createHubAuthFlow({ returnUrl: getReturnUrlFromRequest(request) }),
      providerId: providerConfig.providerId
    }

    setHubAuthFlow(request, authFlow)

    const authorizationUrl = new URL(metadata.authorization_endpoint)
    addAuthorizationParameters(authorizationUrl, {
      providerConfig,
      redirectUri: getRedirectUri(providerConfig.providerId),
      authFlow
    })
    return authorizationUrl.toString()
  }
}

function resolveAuthorizationFlow(request, getPrimaryProviderId) {
  const authFlow = getHubAuthFlow(request)
  const providerId = authFlow?.providerId ?? getPrimaryProviderId?.()

  if (
    !authFlow?.state ||
    !authFlow?.nonce ||
    !authFlow?.codeVerifier ||
    !providerId
  ) {
    throw new Error('Authentication flow session was not found')
  }

  return { authFlow, providerId }
}

function validateAuthorizationResponse(request, authFlow) {
  if (request.query?.state !== authFlow.state) {
    throw new Error('State mismatch')
  }

  if (!request.query?.code) {
    throw new Error('Authorization code was not returned')
  }
}

function validateTokenResponse(tokens) {
  if (!tokens.id_token) {
    throw new Error('Token response did not include an ID token')
  }
}

function validateIdTokenClaims(payload, authFlow, providerConfig) {
  if (payload.nonce !== authFlow.nonce) {
    throw new Error('Nonce mismatch')
  }

  if (
    providerConfig.serviceId &&
    payload.serviceId &&
    payload.serviceId !== providerConfig.serviceId
  ) {
    throw new Error('Unexpected serviceId claim')
  }
}

function createIdTokenVerifier() {
  const providerJwks = new Map()

  return async function verifyIdToken(tokens, providerConfig, metadata) {
    if (!providerJwks.has(providerConfig.providerId)) {
      providerJwks.set(
        providerConfig.providerId,
        createRemoteJWKSet(new URL(metadata.jwks_uri))
      )
    }

    return jwtVerify(
      tokens.id_token,
      providerJwks.get(providerConfig.providerId),
      { issuer: metadata.issuer, audience: providerConfig.clientId }
    )
  }
}

function createAuthorizationCodeCompleter({
  getPrimaryProviderId,
  resolveProviderConfig,
  getOidcMetadata,
  exchangeCodeForTokens,
  verifyIdToken,
  mapUser
}) {
  return async function completeAuthorizationCodeGrant(request) {
    const { authFlow, providerId } = resolveAuthorizationFlow(
      request,
      getPrimaryProviderId
    )
    validateAuthorizationResponse(request, authFlow)

    const providerConfig = resolveProviderConfig(providerId)
    const metadata = await getOidcMetadata(providerConfig.providerId)
    const tokens = await exchangeCodeForTokens(
      providerConfig.providerId,
      request.query.code,
      authFlow.codeVerifier
    )
    validateTokenResponse(tokens)

    const { payload } = await verifyIdToken(tokens, providerConfig, metadata)
    validateIdTokenClaims(payload, authFlow, providerConfig)

    const user = mapUser(payload, {
      providerId: providerConfig.providerId,
      providerConfig
    })
    const authSession = {
      ...user,
      idToken: tokens.id_token,
      authenticatedAt: new Date().toISOString()
    }

    clearHubAuthFlow(request)

    return {
      user,
      authSession,
      accessToken: tokens.access_token ?? null,
      providerId: providerConfig.providerId,
      returnUrl: sanitizeReturnUrl(authFlow.returnUrl)
    }
  }
}

function createLogoutUrlBuilder({
  getPrimaryProviderId,
  getOidcMetadata,
  getHubOrigin
}) {
  return async function buildLogoutUrl(request) {
    const authSession = getHubAuthSession(request)
    const providerId = authSession?.authProvider ?? getPrimaryProviderId?.()
    const metadata = await getOidcMetadata(providerId)
    const logoutUrl = new URL(metadata.end_session_endpoint)

    logoutUrl.searchParams.set('post_logout_redirect_uri', getHubOrigin())

    if (authSession?.idToken) {
      logoutUrl.searchParams.set('id_token_hint', authSession.idToken)
    }

    return logoutUrl.toString()
  }
}

/**
 * Creates the OIDC operations used by the hub authentication plugin.
 * @param {object} options OIDC client dependencies.
 * @returns {object} OIDC client operations.
 */
export function createOidcClient(options) {
  const { getProviderConfig, getPrimaryProviderId, getHubOrigin, mapUser } =
    options
  const resolveProviderConfig = createProviderResolver({
    getProviderConfig,
    getPrimaryProviderId
  })
  const getOidcMetadata = createMetadataLoader(resolveProviderConfig)
  const getRedirectUri = createRedirectUriResolver(
    resolveProviderConfig,
    getHubOrigin
  )
  const sharedDependencies = {
    resolveProviderConfig,
    getOidcMetadata,
    getRedirectUri
  }
  const exchangeCodeForTokens = createCodeExchanger(sharedDependencies)

  return {
    buildAuthorizationUrl: createAuthorizationUrlBuilder(sharedDependencies),
    buildLogoutUrl: createLogoutUrlBuilder({
      getPrimaryProviderId,
      getOidcMetadata,
      getHubOrigin
    }),
    completeAuthorizationCodeGrant: createAuthorizationCodeCompleter({
      getPrimaryProviderId,
      resolveProviderConfig,
      getOidcMetadata,
      exchangeCodeForTokens,
      verifyIdToken: createIdTokenVerifier(),
      mapUser
    }),
    getOidcMetadata
  }
}
