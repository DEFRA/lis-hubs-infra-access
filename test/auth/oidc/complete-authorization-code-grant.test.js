import * as openidClient from 'openid-client'
import { afterEach, describe, expect, test, vi } from 'vitest'

import { completeAuthorizationCodeGrant } from '../../../src/auth/oidc/complete-authorization-code-grant.js'

vi.mock('openid-client')

const mocks = {
  authorizationCodeGrant: vi.mocked(openidClient.authorizationCodeGrant)
}

const oidcConfig = {}
const provider = { serviceId: 'livestock-hub' }
const mapUser = (payload) => payload

function createRequest(values = new Map()) {
  return {
    query: {},
    path: '/sso',
    url: new URL('https://hub.example/sso'),
    yar: {
      clear: (key) => values.delete(key),
      get: (key) => values.get(key),
      set: (key, value) => values.set(key, value)
    }
  }
}

describe('completeAuthorizationCodeGrant()', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  test('requires an established auth flow before exchanging tokens', async () => {
    // Arrange
    const request = createRequest()

    // Act
    let result, error
    try {
      result = await completeAuthorizationCodeGrant({
        oidcConfig,
        provider,
        hubOrigin: 'https://hub.example',
        mapUser,
        request
      })
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).not.toBeDefined()
    expect(error.message).toBe('Authentication flow session was not found')
  })

  test('completes an authorization code grant and clears the flow', async () => {
    // Arrange
    const values = new Map([
      [
        'hub-auth-flow',
        {
          state: 'expected-state',
          nonce: 'expected-nonce',
          codeVerifier: 'verifier',
          returnUrl: '/cattle/status'
        }
      ]
    ])
    const request = createRequest(values)
    request.query = { state: 'expected-state', code: 'authorization-code' }
    mocks.authorizationCodeGrant.mockResolvedValue({
      id_token: 'id-token',
      access_token: 'access-token',
      claims: () => ({ sub: 'user-1', serviceId: 'livestock-hub' })
    })

    // Act
    let result, error
    try {
      result = await completeAuthorizationCodeGrant({
        oidcConfig,
        provider,
        hubOrigin: 'https://hub.example',
        mapUser,
        request
      })
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result.user).toEqual({ sub: 'user-1', serviceId: 'livestock-hub' })
    expect(result.authSession.idToken).toBe('id-token')
    expect(result.authSession.authenticatedAt).toBeTruthy()
    expect(result.accessToken).toBe('access-token')
    expect(result.returnUrl).toBe('/cattle/status')
    expect(values.has('hub-auth-flow')).toBe(false)

    const [oidcConfigArg, currentUrl, checks, tokenEndpointParameters] =
      mocks.authorizationCodeGrant.mock.calls[0]
    expect(oidcConfigArg).toBe(oidcConfig)
    expect(currentUrl.toString()).toBe('https://hub.example/sso')
    expect(checks.pkceCodeVerifier).toBe('verifier')
    expect(checks.expectedState).toBe('expected-state')
    expect(checks.expectedNonce).toBe('expected-nonce')
    expect(checks.idTokenExpected).toBe(true)
    expect(tokenEndpointParameters).toEqual({ serviceId: 'livestock-hub' })
  })

  test('omits token endpoint parameters when no service id is configured', async () => {
    // Arrange
    const request = createRequest(
      new Map([
        [
          'hub-auth-flow',
          {
            state: 'expected-state',
            nonce: 'expected-nonce',
            codeVerifier: 'v'
          }
        ]
      ])
    )
    request.query = { state: 'expected-state', code: 'authorization-code' }
    mocks.authorizationCodeGrant.mockResolvedValue({
      id_token: 'id-token',
      access_token: 'access-token',
      claims: () => ({ sub: 'user-1' })
    })

    // Act
    let error
    try {
      await completeAuthorizationCodeGrant({
        oidcConfig,
        provider: { ...provider, serviceId: undefined },
        hubOrigin: 'https://hub.example',
        mapUser,
        request
      })
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    const tokenEndpointParameters =
      mocks.authorizationCodeGrant.mock.calls[0][3]
    expect(tokenEndpointParameters).toBeUndefined()
  })

  test('rejects an unexpected serviceId claim', async () => {
    // Arrange
    const request = createRequest(
      new Map([
        [
          'hub-auth-flow',
          {
            state: 'expected-state',
            nonce: 'expected-nonce',
            codeVerifier: 'verifier'
          }
        ]
      ])
    )
    request.query = { state: 'expected-state', code: 'authorization-code' }
    mocks.authorizationCodeGrant.mockResolvedValue({
      id_token: 'id-token',
      claims: () => ({ serviceId: 'other-service' })
    })

    // Act
    let result, error
    try {
      result = await completeAuthorizationCodeGrant({
        oidcConfig,
        provider,
        hubOrigin: 'https://hub.example',
        mapUser,
        request
      })
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).not.toBeDefined()
    expect(error.message).toBe('Unexpected serviceId claim')
  })
})
