import { afterEach, describe, expect, test, vi } from 'vitest'

vi.mock('jose', () => ({ createRemoteJWKSet: vi.fn(), jwtVerify: vi.fn() }))

import { createOidcClient } from '../../src/authentication/oidc.js'

const providerConfig = {
  discoveryUrl: 'https://identity.example/.well-known/openid-configuration',
  redirectPath: '/sso',
  clientId: 'hub-client',
  clientSecret: 'secret'
}

function createClient(hubOrigin = 'https://hub.example') {
  return createOidcClient({
    getProviderConfig: () => providerConfig,
    getHubOrigin: () => hubOrigin,
    getPrimaryProviderId: () => 'entra',
    mapUser: (payload) => payload
  })
}

function createRequest() {
  return { yar: { get: () => undefined } }
}

function mockDiscovery(metadata) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: true, json: async () => metadata }))
  )
}

describe('getLogoutOrigins()', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  test('gives the end-session, issuer and post-logout redirect origins, without paths', async () => {
    // Arrange
    mockDiscovery({
      issuer: 'https://dcidm.b2clogin.com/tenant/v2.0/',
      end_session_endpoint:
        'https://your-account.example:8443/idphub/b2c/policy/signout'
    })

    // Act
    const origins = await createClient().getLogoutOrigins(createRequest())

    // Assert
    expect(origins).toEqual([
      'https://your-account.example:8443',
      'https://dcidm.b2clogin.com',
      'https://hub.example'
    ])
  })

  test('gives each origin once', async () => {
    // Arrange
    mockDiscovery({
      issuer: 'https://login.example/tenant/v2.0',
      end_session_endpoint: 'https://login.example/tenant/oauth2/v2.0/logout'
    })

    // Act
    const origins = await createClient(
      'https://login.example'
    ).getLogoutOrigins(createRequest())

    // Assert
    expect(origins).toEqual(['https://login.example'])
  })

  test('gives only the post-logout redirect origin when the provider has no end-session endpoint', async () => {
    // Arrange
    mockDiscovery({ issuer: 'https://login.example' })

    // Act
    const origins = await createClient().getLogoutOrigins(createRequest())

    // Assert
    expect(origins).toEqual(['https://hub.example'])
  })

  test('drops an issuer that is not an http(s) URL', async () => {
    // Arrange
    mockDiscovery({
      issuer: 'urn:example:issuer',
      end_session_endpoint: 'https://login.example/logout'
    })

    // Act
    const origins = await createClient().getLogoutOrigins(createRequest())

    // Assert
    expect(origins).toEqual(['https://login.example', 'https://hub.example'])
  })

  test('takes the post-logout origin from the same URI buildLogoutUrl sends', async () => {
    // Arrange
    mockDiscovery({
      issuer: 'https://login.example',
      end_session_endpoint: 'https://login.example/logout'
    })
    const client = createClient('https://hub.cdp.example:8443')

    // Act
    const origins = await client.getLogoutOrigins(createRequest(), {
      returnPath: '/auth/not-authorised'
    })
    const logoutUrl = new URL(
      await client.buildLogoutUrl(createRequest(), {
        returnPath: '/auth/not-authorised'
      })
    )

    // Assert
    expect(origins).toEqual([
      'https://login.example',
      'https://hub.cdp.example:8443'
    ])
    expect(
      new URL(logoutUrl.searchParams.get('post_logout_redirect_uri')).origin
    ).toBe('https://hub.cdp.example:8443')
  })

  test('rejects a hub origin that is not an http(s) URL', async () => {
    // Arrange
    mockDiscovery({ end_session_endpoint: 'https://login.example/logout' })

    // Act
    let error
    try {
      await createClient('javascript:alert(1)').getLogoutOrigins(
        createRequest()
      )
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).toBeInstanceOf(TypeError)
  })

  test.each([['javascript:alert(1)'], ['*'], ['not a url']])(
    'rejects an end-session endpoint of %s',
    async (endSessionEndpoint) => {
      // Arrange
      mockDiscovery({ end_session_endpoint: endSessionEndpoint })

      // Act
      let error
      try {
        await createClient().getLogoutOrigins(createRequest())
      } catch (e) {
        error = e
      }

      // Assert
      expect(error).toBeInstanceOf(TypeError)
    }
  )
})
