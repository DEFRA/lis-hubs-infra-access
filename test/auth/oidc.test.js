import assert from 'node:assert/strict'
import { afterEach, test, vi } from 'vitest'

const jose = vi.hoisted(() => ({
  createRemoteJWKSet: vi.fn(() => 'remote-jwks'),
  jwtVerify: vi.fn()
}))

vi.mock('jose', () => jose)

import { createOidcClient } from '../../src/auth/oidc.js'

const providerConfig = {
  discoveryUrl: 'https://identity.example/.well-known/openid-configuration',
  redirectPath: '/sso',
  clientId: 'hub-client',
  clientSecret: 'secret',
  serviceId: 'livestock-hub'
}

const metadata = {
  issuer: 'https://identity.example',
  authorization_endpoint: 'https://identity.example/authorize',
  token_endpoint: 'https://identity.example/token',
  jwks_uri: 'https://identity.example/keys',
  end_session_endpoint: 'https://identity.example/logout'
}

function createRequest(values = new Map()) {
  return {
    query: {},
    yar: {
      clear: (key) => values.delete(key),
      get: (key) => values.get(key),
      set: (key, value) => values.set(key, value)
    }
  }
}

function createClient(overrides = {}) {
  return createOidcClient({
    getProviderConfig: () => providerConfig,
    getHubOrigin: () => 'https://hub.example',
    getPrimaryProviderId: () => 'entra',
    mapUser: (payload) => payload,
    ...overrides
  })
}

function mockDiscovery(response = metadata) {
  const fetch = vi.fn(async () => ({
    ok: true,
    json: async () => response
  }))
  vi.stubGlobal('fetch', fetch)
  return fetch
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

test('fetches and caches provider discovery metadata', async () => {
  const fetch = mockDiscovery()
  const client = createClient()

  assert.equal(await client.getOidcMetadata('entra'), metadata)
  assert.equal(await client.getOidcMetadata('entra'), metadata)
  assert.equal(fetch.mock.calls.length, 1)
  assert.equal(fetch.mock.calls[0][0], providerConfig.discoveryUrl)
})

test('rejects failed discovery responses', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: false, status: 503 }))
  )

  await assert.rejects(
    createClient().getOidcMetadata('entra'),
    /Failed to fetch .*: 503/
  )
})

test('requires a provider id and discovery URL', async () => {
  await assert.rejects(
    createClient({ getPrimaryProviderId: () => null }).getOidcMetadata(),
    /Authentication provider id is required/
  )
  await assert.rejects(
    createClient({ getProviderConfig: () => ({}) }).getOidcMetadata('entra'),
    /OIDC discovery URL is not configured for provider entra/
  )
})

test('builds an authorization URL and stores its flow state', async () => {
  mockDiscovery()
  const request = createRequest()
  request.query.returnUrl = '/cattle/status'

  const authorizationUrl = new URL(
    await createClient().buildAuthorizationUrl(request, 'entra')
  )
  const flow = request.yar.get('hub-auth-flow')

  assert.equal(authorizationUrl.origin, 'https://identity.example')
  assert.equal(authorizationUrl.pathname, '/authorize')
  assert.equal(authorizationUrl.searchParams.get('client_id'), 'hub-client')
  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code')
  assert.equal(authorizationUrl.searchParams.get('scope'), 'openid')
  assert.equal(
    authorizationUrl.searchParams.get('redirect_uri'),
    'https://hub.example/sso'
  )
  assert.equal(authorizationUrl.searchParams.get('state'), flow.state)
  assert.equal(authorizationUrl.searchParams.get('nonce'), flow.nonce)
  assert.equal(authorizationUrl.searchParams.get('serviceId'), 'livestock-hub')
  assert.equal(
    authorizationUrl.searchParams.get('code_challenge_method'),
    'S256'
  )
  assert.ok(authorizationUrl.searchParams.get('code_challenge'))
  assert.equal(flow.returnUrl, '/cattle/status')
  assert.equal(flow.providerId, 'entra')
})

test('omits provider-specific parameters when no service id is configured', async () => {
  const fetch = mockDiscovery()
  const client = createClient({
    getProviderConfig: () => ({ ...providerConfig, serviceId: undefined })
  })
  const request = createRequest()

  const authorizationUrl = new URL(
    await client.buildAuthorizationUrl(request, 'entra')
  )

  assert.equal(authorizationUrl.searchParams.has('serviceId'), false)

  request.query = {
    state: request.yar.get('hub-auth-flow').state,
    code: 'authorization-code'
  }
  jose.jwtVerify.mockResolvedValue({
    payload: { sub: 'user-1', nonce: request.yar.get('hub-auth-flow').nonce }
  })
  fetch.mockResolvedValueOnce({
    ok: true,
    json: async () => ({ id_token: 'id-token' })
  })

  await client.completeAuthorizationCodeGrant(request)

  const tokenRequest = fetch.mock.calls.find(
    ([url]) => url === metadata.token_endpoint
  )[1]
  assert.equal(tokenRequest.body.has('serviceId'), false)
})

test('validates an authorization callback before exchanging tokens', async () => {
  const client = createClient()

  await assert.rejects(
    client.completeAuthorizationCodeGrant(createRequest()),
    /Authentication flow session was not found/
  )

  const values = new Map([
    [
      'hub-auth-flow',
      {
        state: 'expected-state',
        nonce: 'nonce',
        codeVerifier: 'verifier',
        providerId: 'entra'
      }
    ]
  ])
  const request = createRequest(values)
  request.query.state = 'wrong-state'
  await assert.rejects(
    client.completeAuthorizationCodeGrant(request),
    /State mismatch/
  )

  request.query.state = 'expected-state'
  await assert.rejects(
    client.completeAuthorizationCodeGrant(request),
    /Authorization code was not returned/
  )
})

test('completes an authorization code grant and clears the flow', async () => {
  const fetch = mockDiscovery()
  const values = new Map([
    [
      'hub-auth-flow',
      {
        state: 'expected-state',
        nonce: 'expected-nonce',
        codeVerifier: 'verifier',
        providerId: 'entra',
        returnUrl: '/cattle/status'
      }
    ]
  ])
  const request = createRequest(values)
  request.query = { state: 'expected-state', code: 'authorization-code' }
  fetch.mockResolvedValueOnce({ ok: true, json: async () => metadata })
  fetch.mockResolvedValueOnce({
    ok: true,
    json: async () => ({
      id_token: 'id-token',
      access_token: 'access-token'
    })
  })
  jose.jwtVerify.mockResolvedValue({
    payload: {
      sub: 'user-1',
      nonce: 'expected-nonce',
      serviceId: 'livestock-hub'
    }
  })

  const result = await createClient().completeAuthorizationCodeGrant(request)

  assert.deepEqual(result.user, {
    sub: 'user-1',
    nonce: 'expected-nonce',
    serviceId: 'livestock-hub'
  })
  assert.equal(result.authSession.idToken, 'id-token')
  assert.ok(result.authSession.authenticatedAt)
  assert.equal(result.accessToken, 'access-token')
  assert.equal(result.providerId, 'entra')
  assert.equal(result.returnUrl, '/cattle/status')
  assert.equal(values.has('hub-auth-flow'), false)
  assert.deepEqual(jose.createRemoteJWKSet.mock.calls[0], [
    new URL(metadata.jwks_uri)
  ])
  assert.deepEqual(jose.jwtVerify.mock.calls[0], [
    'id-token',
    'remote-jwks',
    { issuer: metadata.issuer, audience: providerConfig.clientId }
  ])
})

test('rejects invalid token responses and identity claims', async () => {
  async function completeWith(tokenResponse, payload) {
    const fetch = mockDiscovery()
    const request = createRequest(
      new Map([
        [
          'hub-auth-flow',
          {
            state: 'expected-state',
            nonce: 'expected-nonce',
            codeVerifier: 'verifier',
            providerId: 'entra'
          }
        ]
      ])
    )
    request.query = { state: 'expected-state', code: 'authorization-code' }
    fetch.mockResolvedValueOnce({ ok: true, json: async () => metadata })
    fetch.mockResolvedValueOnce({ ok: true, json: async () => tokenResponse })
    jose.jwtVerify.mockResolvedValue({ payload })

    return createClient().completeAuthorizationCodeGrant(request)
  }

  await assert.rejects(
    completeWith({}, {}),
    /Token response did not include an ID token/
  )
  await assert.rejects(
    completeWith({ id_token: 'id-token' }, { nonce: 'wrong-nonce' }),
    /Nonce mismatch/
  )
  await assert.rejects(
    completeWith(
      { id_token: 'id-token' },
      { nonce: 'expected-nonce', serviceId: 'other-service' }
    ),
    /Unexpected serviceId claim/
  )
})

test('builds a logout URL from the authenticated provider session', async () => {
  mockDiscovery()
  const request = createRequest(
    new Map([
      [
        'hub-auth-session',
        { authProvider: 'entra', idToken: 'signed-id-token' }
      ]
    ])
  )

  const logoutUrl = new URL(await createClient().buildLogoutUrl(request))

  assert.equal(logoutUrl.origin, 'https://identity.example')
  assert.equal(logoutUrl.pathname, '/logout')
  assert.equal(
    logoutUrl.searchParams.get('post_logout_redirect_uri'),
    'https://hub.example'
  )
  assert.equal(logoutUrl.searchParams.get('id_token_hint'), 'signed-id-token')
})

test('omits the ID token hint when logging out without a session', async () => {
  mockDiscovery()

  const logoutUrl = new URL(
    await createClient().buildLogoutUrl(createRequest())
  )

  assert.equal(logoutUrl.searchParams.has('id_token_hint'), false)
})
