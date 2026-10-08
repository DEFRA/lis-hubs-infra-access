import { afterEach, describe, expect, test, vi } from 'vitest'

const { logger } = vi.hoisted(() => ({
  logger: { error: vi.fn() }
}))

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger }))

import {
  createHubAuth,
  createHubCookieOptions
} from '../../src/authentication/hub-auth.js'

afterEach(() => {
  vi.clearAllMocks()
})

const jwtConfig = {
  secret: 'test-hub-secret-please-change-1234567890',
  issuer: 'http://localhost:3000',
  audience: 'livestock-spokes',
  ttlSeconds: 3600
}

function createRequest(values = new Map()) {
  return {
    app: {},
    query: {},
    yar: {
      clear: (key) => values.delete(key),
      get: (key) => values.get(key),
      set: (key, value) => values.set(key, value)
    }
  }
}

function createToolkit() {
  const response = {
    code: vi.fn(() => response),
    state: vi.fn(() => response),
    takeover: vi.fn(() => response),
    unstate: vi.fn(() => response)
  }

  return {
    continue: Symbol('continue'),
    redirect: vi.fn(() => response),
    response: vi.fn(() => response),
    result: response
  }
}

function registerPlugin(overrides = {}) {
  let routes
  const state = vi.fn()
  const plugin = createHubAuth({
    getHubJwtCookieName: () => 'hub-jwt',
    getCookieOptions: () => ({ isSecure: false }),
    getHubJwtConfig: () => jwtConfig,
    resolveAuthSession: async () => ({}),
    buildAuthorizationUrl: async () => 'https://identity.example/authorize',
    completeAuthorizationCodeGrant: async () => ({}),
    buildLogoutUrl: async () => 'https://identity.example/logout',
    loginRoutes: [{ path: '/auth/login', providerId: 'entra' }],
    ...overrides
  })

  plugin.plugin.register({
    auth: { scheme: vi.fn(), strategy: vi.fn(), default: vi.fn() },
    state,
    ext: vi.fn(),
    route(registeredRoutes) {
      routes = registeredRoutes
    }
  })

  return { plugin, routes, state }
}

describe('createHubAuth()', () => {
  test('creates standard hub cookie options', () => {
    // Arrange / Act
    const options = createHubCookieOptions({ ttlSeconds: 60, isSecure: true })

    // Assert
    expect(options).toEqual({
      encoding: 'none',
      ttl: 60000,
      isHttpOnly: true,
      isSecure: true,
      isSameSite: 'Lax',
      clearInvalid: true,
      path: '/'
    })
  })

  test('registers auth state and login lifecycle routes', () => {
    // Arrange / Act
    const { plugin, routes, state } = registerPlugin({
      pluginName: 'hub-auth'
    })

    // Assert
    expect(plugin.plugin.name).toBe('hub-auth')
    expect(routes.map(({ path }) => path)).toEqual([
      '/auth/login',
      '/sso',
      '/auth/logout',
      '/signout'
    ])
    expect(state.mock.calls[0]).toEqual(['hub-jwt', { isSecure: false }])
  })

  test('login redirects unauthenticated users to their identity provider', async () => {
    // Arrange
    const buildAuthorizationUrl = vi.fn(
      async () => 'https://identity.example/authorize'
    )
    const { routes } = registerPlugin({
      buildAuthorizationUrl,
      loginRoutes: [{ path: '/auth/login', providerId: () => 'entra' }]
    })
    const request = createRequest()
    request.query.returnUrl = '/cattle'
    const h = createToolkit()

    // Act
    await routes[0].handler(request, h)

    // Assert
    expect(buildAuthorizationUrl.mock.calls[0]).toEqual([request, 'entra'])
    expect(h.redirect.mock.calls[0][0]).toBe(
      'https://identity.example/authorize'
    )
  })

  test('login returns 503 when the identity provider is unavailable', async () => {
    // Arrange
    const error = new Error('offline')
    error.cause = new Error('getaddrinfo ENOTFOUND identity.example')
    const { routes } = registerPlugin({
      buildAuthorizationUrl: async () => {
        throw error
      }
    })
    const request = createRequest()
    const h = createToolkit()

    // Act
    await routes[0].handler(request, h)

    // Assert
    expect(logger.error.mock.calls[0]).toEqual([
      error,
      'Failed to build OIDC authorization URL [cause=getaddrinfo ENOTFOUND identity.example]'
    ])
    expect(h.result.code.mock.calls[0]).toEqual([503])
  })

  test('callback enriches and stores the session before setting its JWT', async () => {
    // Arrange
    const authSession = { sub: 'user-1', email: 'user@example.com' }
    const resolveAuthSession = vi.fn(async () => ({
      statements: [{ role: 'lis-role-reader', cphs: '*' }]
    }))
    const { routes } = registerPlugin({
      completeAuthorizationCodeGrant: async () => ({
        user: { sub: 'user-1' },
        authSession,
        accessToken: 'access-token',
        returnUrl: '/cattle'
      }),
      resolveAuthSession
    })
    const request = createRequest(
      new Map([['hub-auth-flow', { state: 'state-1' }]])
    )
    request.query = { code: 'code-1', state: 'state-1' }
    const h = createToolkit()

    // Act
    await routes[1].handler(request, h)

    // Assert
    expect(h.redirect.mock.calls[0][0]).toBe('/cattle')
    expect(h.result.state.mock.calls[0][0]).toBe('hub-jwt')
    expect(request.yar.get('hub-auth-session')).toEqual({
      ...authSession,
      statements: [{ role: 'lis-role-reader', cphs: '*' }]
    })
  })

  test('callback restarts login when the grant reports a stale response', async () => {
    // Arrange
    const resolveAuthSession = vi.fn(async () => ({}))
    const { routes } = registerPlugin({
      completeAuthorizationCodeGrant: async () => ({ stale: true }),
      resolveAuthSession
    })
    const request = createRequest()
    request.query = { code: 'code-1', state: 'stale-state' }
    const h = createToolkit()

    // Act
    await routes[1].handler(request, h)

    // Assert
    expect(h.redirect.mock.calls[0][0]).toBe('/auth/login')
    expect(resolveAuthSession).not.toHaveBeenCalled()
  })

  test('callback signs a denied user out of the provider without issuing a session or JWT', async () => {
    // Arrange
    const authSession = { sub: 'user-1', idToken: 'id-token' }
    const buildLogoutUrl = vi.fn(
      async () => 'https://identity.example/logout?denied'
    )
    const { routes } = registerPlugin({
      completeAuthorizationCodeGrant: async () => ({
        user: { sub: 'user-1' },
        authSession,
        returnUrl: '/cattle'
      }),
      resolveAuthSession: async () => ({ denied: true }),
      buildLogoutUrl,
      accessDeniedPath: '/auth/access-denied'
    })
    const request = createRequest(
      new Map([
        ['hub-auth-session', { sub: 'previous-user' }],
        ['hub-auth-flow', { state: 'state-1' }]
      ])
    )
    const h = createToolkit()

    // Act
    await routes[1].handler(request, h)

    // Assert
    expect(buildLogoutUrl.mock.calls[0]).toEqual([
      request,
      { authSession, returnPath: '/auth/access-denied' }
    ])
    expect(h.redirect.mock.calls[0][0]).toBe(
      'https://identity.example/logout?denied'
    )
    expect(h.result.state).not.toHaveBeenCalled()
    expect(h.result.unstate.mock.calls[0]).toEqual([
      'hub-jwt',
      { isSecure: false }
    ])
    expect(request.yar.get('hub-auth-session')).toBeUndefined()
  })

  test('callback signs a denied user out to the hub origin when no access denied path is set', async () => {
    // Arrange
    const buildLogoutUrl = vi.fn(async () => 'https://identity.example/logout')
    const { routes } = registerPlugin({
      completeAuthorizationCodeGrant: async () => ({
        user: { sub: 'user-1' },
        authSession: { sub: 'user-1' },
        returnUrl: '/cattle'
      }),
      resolveAuthSession: async () => ({ denied: true }),
      buildLogoutUrl
    })
    const request = createRequest()
    const h = createToolkit()

    // Act
    await routes[1].handler(request, h)

    // Assert
    expect(buildLogoutUrl.mock.calls[0][1].returnPath).toBeUndefined()
    expect(h.redirect.mock.calls[0][0]).toBe('https://identity.example/logout')
    expect(request.yar.get('hub-auth-session')).toBeUndefined()
  })

  test('callback surfaces errors returned by the identity provider', async () => {
    // Arrange
    const { routes } = registerPlugin()
    const request = createRequest()
    request.query = { error: 'access_denied', error_description: 'Denied' }

    // Act
    let error
    try {
      await routes[1].handler(request, createToolkit())
    } catch (e) {
      error = e
    }

    // Assert
    expect(error.message).toMatch(/Denied/)
  })

  test('logout clears auth state and removes the JWT cookie', async () => {
    // Arrange
    const request = createRequest(
      new Map([
        ['hub-auth-session', { sub: 'user-1' }],
        ['hub-auth-flow', { state: 'state-id' }]
      ])
    )
    const h = createToolkit()
    const { routes } = registerPlugin()

    // Act
    await routes[2].handler(request, h)

    // Assert
    expect(h.redirect.mock.calls[0][0]).toBe('https://identity.example/logout')
    expect(h.result.unstate.mock.calls[0]).toEqual([
      'hub-jwt',
      { isSecure: false }
    ])
    expect(request.yar.get('hub-auth-session')).toBeUndefined()
    expect(request.yar.get('hub-auth-flow')).toBeUndefined()
  })

  test('signout redirects to the logout route', () => {
    // Arrange
    const request = createRequest()
    const h = createToolkit()
    const { routes } = registerPlugin()

    // Act
    routes[3].handler(request, h)

    // Assert
    expect(h.redirect.mock.calls[0][0]).toBe('/auth/logout')
  })
})
