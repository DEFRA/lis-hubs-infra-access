import { createOidcConfig } from '@defra/hapi-auth-oidc'
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest'

import { buildAuthorizationUrl } from '../../../src/auth/oidc/build-authorization-url.js'
import { buildLogoutUrl } from '../../../src/auth/oidc/build-logout-url.js'
import { completeAuthorizationCodeGrant } from '../../../src/auth/oidc/complete-authorization-code-grant.js'
import { createOidcClient } from '../../../src/auth/oidc/index.js'

vi.mock('@defra/hapi-auth-oidc')
vi.mock('../../../src/auth/oidc/build-authorization-url.js')
vi.mock('../../../src/auth/oidc/build-logout-url.js')
vi.mock('../../../src/auth/oidc/complete-authorization-code-grant.js')

const mocks = {
  createOidcConfig: vi.mocked(createOidcConfig),
  buildAuthorizationUrl: vi.mocked(buildAuthorizationUrl),
  buildLogoutUrl: vi.mocked(buildLogoutUrl),
  completeAuthorizationCodeGrant: vi.mocked(completeAuthorizationCodeGrant)
}

const provider = {
  discoveryUrl: 'https://identity.example/.well-known/openid-configuration',
  redirectPath: '/sso',
  clientId: 'hub-client',
  clientSecret: 'secret',
  serviceId: 'livestock-hub'
}

const metadata = {
  issuer: 'https://identity.example',
  end_session_endpoint: 'https://identity.example/logout'
}

const mapUser = (payload) => payload

function createClient(overrides = {}) {
  return createOidcClient({
    provider,
    hubOrigin: 'https://hub.example',
    mapUser,
    ...overrides
  })
}

describe('createOidcClient()', () => {
  beforeAll(() => {
    mocks.createOidcConfig.mockResolvedValue({
      serverMetadata: () => metadata
    })
    mocks.buildAuthorizationUrl.mockResolvedValue(
      'https://identity.example/authorize'
    )
    mocks.completeAuthorizationCodeGrant.mockResolvedValue({})
    mocks.buildLogoutUrl.mockReturnValue('https://identity.example/logout')
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  test('resolves the OIDC config once during construction', async () => {
    // Arrange
    mocks.createOidcConfig.mockResolvedValueOnce({
      serverMetadata: () => metadata
    })

    // Act
    let error
    try {
      await createClient()
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(mocks.createOidcConfig).toHaveBeenCalledTimes(1)
    expect(mocks.createOidcConfig.mock.calls[0][0].discoveryUri).toBe(
      provider.discoveryUrl
    )
  })

  test('defaults to a client_secret auth provider', async () => {
    // Arrange
    mocks.createOidcConfig.mockResolvedValueOnce({
      serverMetadata: () => metadata
    })

    // Act
    let error
    try {
      await createClient()
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    const { authProvider } = mocks.createOidcConfig.mock.calls[0][0]
    expect(authProvider.type).toBe('client_secret')
    expect(await authProvider.getCredentials()).toBe(provider.clientSecret)
  })

  test('passes through a provider-supplied auth provider unchanged', async () => {
    // Arrange
    mocks.createOidcConfig.mockResolvedValueOnce({
      serverMetadata: () => metadata
    })
    const federatedAuthProvider = {
      type: 'federated',
      getCredentials: async () => 'federated-token'
    }

    // Act
    let error
    try {
      await createClient({
        provider: { ...provider, authProvider: federatedAuthProvider }
      })
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(mocks.createOidcConfig.mock.calls[0][0].authProvider).toBe(
      federatedAuthProvider
    )
  })

  test('rejects when discovery fails', async () => {
    // Arrange
    mocks.createOidcConfig.mockRejectedValueOnce(new Error('offline'))

    // Act
    let result, error
    try {
      result = await createClient()
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).not.toBeDefined()
    expect(error.message).toBe('offline')
  })

  test('delegates buildAuthorizationUrl to the extracted operation with the resolved config', async () => {
    // Arrange
    const oidcConfig = { serverMetadata: () => metadata }
    mocks.createOidcConfig.mockResolvedValueOnce(oidcConfig)
    const request = {}

    // Act
    let result, error
    try {
      const client = await createClient()
      result = await client.buildAuthorizationUrl(request)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result).toBe('https://identity.example/authorize')
    expect(mocks.buildAuthorizationUrl.mock.calls[0][0]).toEqual({
      oidcConfig,
      provider,
      hubOrigin: 'https://hub.example',
      request
    })
  })

  test('delegates completeAuthorizationCodeGrant to the extracted operation with the resolved config', async () => {
    // Arrange
    const oidcConfig = { serverMetadata: () => metadata }
    mocks.createOidcConfig.mockResolvedValueOnce(oidcConfig)
    const request = {}
    const grantResult = { user: { sub: 'user-1' } }
    mocks.completeAuthorizationCodeGrant.mockResolvedValueOnce(grantResult)

    // Act
    let result, error
    try {
      const client = await createClient()
      result = await client.completeAuthorizationCodeGrant(request)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result).toBe(grantResult)
    expect(mocks.completeAuthorizationCodeGrant.mock.calls[0][0]).toEqual({
      oidcConfig,
      provider,
      hubOrigin: 'https://hub.example',
      mapUser,
      request
    })
  })

  test('delegates buildLogoutUrl to the extracted operation with the resolved metadata', async () => {
    // Arrange
    const oidcConfig = { serverMetadata: () => metadata }
    mocks.createOidcConfig.mockResolvedValueOnce(oidcConfig)
    const request = {}

    // Act
    let result, error
    try {
      const client = await createClient()
      result = client.buildLogoutUrl(request)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result).toBe('https://identity.example/logout')
    expect(mocks.buildLogoutUrl.mock.calls[0][0]).toEqual({
      metadata,
      hubOrigin: 'https://hub.example',
      request
    })
  })
})
