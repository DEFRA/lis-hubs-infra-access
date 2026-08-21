import * as openidClient from 'openid-client'
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest'

import { buildAuthorizationUrl } from '../../../src/auth/oidc/build-authorization-url.js'

vi.mock('openid-client')

const mocks = {
  calculatePKCECodeChallenge: vi.mocked(
    openidClient.calculatePKCECodeChallenge
  ),
  buildAuthorizationUrl: vi.mocked(openidClient.buildAuthorizationUrl)
}

const oidcConfig = { serverMetadata: () => ({}) }
const provider = {
  redirectPath: '/sso',
  serviceId: 'livestock-hub'
}

function createRequest() {
  return {
    query: {},
    path: '/sso',
    url: new URL('https://hub.example/sso'),
    yar: {
      clear: vi.fn(),
      get: vi.fn(),
      set: vi.fn()
    }
  }
}

describe('buildAuthorizationUrl()', () => {
  beforeAll(() => {
    mocks.calculatePKCECodeChallenge.mockImplementation(
      async (verifier) => `challenge-for-${verifier}`
    )
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  test('builds an authorization URL and stores its flow state', async () => {
    // Arrange
    mocks.buildAuthorizationUrl.mockReturnValue(
      new URL('https://identity.example/authorize?state=stub')
    )
    const request = createRequest()
    request.query.returnUrl = '/cattle/status'

    // Act
    let result, error
    try {
      result = await buildAuthorizationUrl({
        oidcConfig,
        provider,
        hubOrigin: 'https://hub.example',
        request
      })
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    const [flowKey, flow] = request.yar.set.mock.calls[0]
    const [oidcConfigArg, parameters] =
      mocks.buildAuthorizationUrl.mock.calls[0]

    expect(result).toBe('https://identity.example/authorize?state=stub')
    expect(flowKey).toBe('hub-auth-flow')
    expect(oidcConfigArg).toBe(oidcConfig)
    expect(parameters.redirect_uri).toBe('https://hub.example/sso')
    expect(parameters.scope).toBe('openid')
    expect(parameters.state).toBe(flow.state)
    expect(parameters.nonce).toBe(flow.nonce)
    expect(parameters.serviceId).toBe('livestock-hub')
    expect(parameters.code_challenge_method).toBe('S256')
    expect(parameters.code_challenge).toBe(`challenge-for-${flow.codeVerifier}`)
    expect(flow.returnUrl).toBe('/cattle/status')
  })

  test('omits the service id parameter when no service id is configured', async () => {
    // Arrange
    mocks.buildAuthorizationUrl.mockReturnValue(
      new URL('https://identity.example/authorize')
    )
    const request = createRequest()

    // Act
    let error
    try {
      await buildAuthorizationUrl({
        oidcConfig,
        provider: { ...provider, serviceId: undefined },
        hubOrigin: 'https://hub.example',
        request
      })
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    const [, parameters] = mocks.buildAuthorizationUrl.mock.calls[0]
    expect('serviceId' in parameters).toBe(false)
  })
})
