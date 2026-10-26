import { afterEach, describe, expect, test, vi } from 'vitest'

const { logger } = vi.hoisted(() => ({
  logger: { error: vi.fn(), warn: vi.fn() }
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
      reset: () => values.clear(),
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
    view: vi.fn(() => response),
    result: response
  }
}

function registerPlugin(overrides = {}) {
  let routes
  const state = vi.fn()
  const plugin = createHubAuth({
    hubId: 'front-office',
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
    const options = createHubCookieOptions({ ttlSeconds: 60 })

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
      '/signout',
      '/auth/not-authorised'
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

  test('login refuses a signed-in session that fails authorize without issuing a JWT', async () => {
    // Arrange
    const authorize = vi.fn(async () => false)
    const { routes } = registerPlugin({ authorize })
    const request = createRequest(
      new Map([['hub-auth-session', { sub: 'user-1', statements: [] }]])
    )
    const h = createToolkit()

    // Act
    await routes[0].handler(request, h)

    // Assert
    expect(authorize).toHaveBeenCalledWith(
      expect.objectContaining({ sub: 'user-1' }),
      request
    )
    expect(h.redirect.mock.calls[0][0]).toBe('/auth/not-authorised')
    expect(h.result.state).not.toHaveBeenCalled()
    expect(h.result.unstate.mock.calls[0][0]).toBe('hub-jwt')
  })

  test('callback stores the session but refuses a user that fails authorize without issuing a JWT', async () => {
    // Arrange
    const authorize = vi.fn(async () => false)
    const { routes } = registerPlugin({
      authorize,
      completeAuthorizationCodeGrant: async () => ({
        user: { sub: 'user-1' },
        authSession: { sub: 'user-1' },
        returnUrl: '/cattle'
      }),
      resolveAuthSession: async () => ({ statements: [] })
    })
    const request = createRequest(
      new Map([['hub-auth-flow', { state: 'state-1' }]])
    )
    const h = createToolkit()

    // Act
    await routes[1].handler(request, h)

    // Assert
    expect(request.yar.get('hub-auth-session')).toEqual({
      sub: 'user-1',
      statements: []
    })
    expect(h.redirect.mock.calls[0][0]).toBe('/auth/not-authorised')
    expect(h.result.state).not.toHaveBeenCalled()
    expect(h.result.unstate.mock.calls[0][0]).toBe('hub-jwt')
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

  test('callback keeps a denied user signed in, flagged refused, and sends them to the not-authorised page without a JWT', async () => {
    // Arrange
    const authSession = { sub: 'user-1', idToken: 'id-token' }
    const buildLogoutUrl = vi.fn(async () => 'https://identity.example/logout')
    const { routes } = registerPlugin({
      completeAuthorizationCodeGrant: async () => ({
        user: { sub: 'user-1' },
        authSession,
        returnUrl: '/cattle'
      }),
      resolveAuthSession: async () => ({ denied: true }),
      buildLogoutUrl
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
    expect(buildLogoutUrl).not.toHaveBeenCalled()
    expect(h.redirect.mock.calls[0][0]).toBe('/auth/not-authorised')
    expect(h.result.state).not.toHaveBeenCalled()
    expect(h.result.unstate.mock.calls[0]).toEqual([
      'hub-jwt',
      { isSecure: false }
    ])
    expect(request.yar.get('hub-auth-session')).toEqual({
      ...authSession,
      refused: true
    })
  })

  test('callback sends a denied user to a custom not-authorised path when one is set', async () => {
    // Arrange
    const { routes } = registerPlugin({
      completeAuthorizationCodeGrant: async () => ({
        user: { sub: 'user-1' },
        authSession: { sub: 'user-1' },
        returnUrl: '/cattle'
      }),
      resolveAuthSession: async () => ({ denied: true }),
      notAuthorisedPath: '/auth/access-denied'
    })
    const request = createRequest(
      new Map([['hub-auth-session', { sub: 'previous-user' }]])
    )
    const h = createToolkit()

    // Act
    await routes[1].handler(request, h)

    // Assert
    expect(h.redirect.mock.calls[0][0]).toBe('/auth/access-denied')
    expect(h.result.unstate.mock.calls[0]).toEqual([
      'hub-jwt',
      { isSecure: false }
    ])
    expect(request.yar.get('hub-auth-session')).toEqual({
      sub: 'user-1',
      refused: true
    })
  })

  test('login sends a refused user to the not-authorised page without issuing a JWT', async () => {
    // Arrange
    const { routes } = registerPlugin()
    const request = createRequest(
      new Map([['hub-auth-session', { sub: 'user-1', refused: true }]])
    )
    request.query.returnUrl = '/cattle'
    const h = createToolkit()

    // Act
    await routes[0].handler(request, h)

    // Assert
    expect(h.redirect.mock.calls[0][0]).toBe('/auth/not-authorised')
    expect(h.result.state).not.toHaveBeenCalled()
  })

  async function callbackError(query) {
    const { routes } = registerPlugin()
    const request = createRequest()
    request.query = query

    try {
      await routes[1].handler(request, createToolkit())
    } catch (e) {
      return e
    }
  }

  test('callback rejects a known identity provider error code', async () => {
    // Act
    const error = await callbackError({ error: 'access_denied' })

    // Assert
    expect(error.output.statusCode).toBe(400)
    expect(error.message).toBe('Identity provider returned access_denied')
    expect(logger.warn).not.toHaveBeenCalled()
  })

  test('callback reports an unknown identity provider error as unknown', async () => {
    // Act
    const error = await callbackError({
      error: '<script>x',
      error_description: 'Denied <script>craft</script>'
    })

    // Assert
    expect(error.output.statusCode).toBe(400)
    expect(error.message).toBe('Identity provider returned unknown')
    expect(error.message).not.toContain('script')
    expect(JSON.stringify(logger.warn.mock.calls)).not.toContain('script')
  })

  test('callback treats an array error value as unknown', async () => {
    // Act
    const error = await callbackError({ error: ['access_denied', 'a'] })

    // Assert
    expect(error.message).toBe('Identity provider returned unknown')
  })

  test('callback keeps only the provider code from error_description', async () => {
    // Act
    const error = await callbackError({
      error: 'access_denied',
      error_description: 'AADB2C90091: The user has cancelled'
    })

    // Assert
    expect(error.message).toBe(
      'Identity provider returned access_denied (AADB2C90091)'
    )
    expect(error.message).not.toContain('cancelled')
    expect(logger.warn).not.toHaveBeenCalled()
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

  test('logout still invalidates the session when building the logout URL fails', async () => {
    // Arrange
    const request = createRequest(
      new Map([['hub-auth-session', { sub: 'user-1' }]])
    )
    const h = createToolkit()
    const buildLogoutUrl = vi.fn(async () => {
      throw new Error('discovery failed')
    })
    const { routes } = registerPlugin({ buildLogoutUrl })

    // Act
    let error
    try {
      await routes[2].handler(request, h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).toBeInstanceOf(Error)
    expect(request.yar.get('hub-auth-session')).toBeUndefined()
  })

  test('not-authorised renders the shared view with a 403 and a sign in link for a signed-out visitor', () => {
    // Arrange
    const request = { ...createRequest(), auth: { isAuthenticated: false } }
    const h = createToolkit()
    const { routes } = registerPlugin({
      loginRoutes: [{ path: '/auth/sign-in', providerId: 'entra' }]
    })

    // Act
    routes[4].handler(request, h)

    // Assert
    expect(routes[4].path).toBe('/auth/not-authorised')
    expect(routes[4].options.auth).toEqual({ mode: 'try' })
    expect(h.view.mock.calls[0]).toEqual([
      'error/not-authorised',
      {
        pageTitle: 'Sorry, you are not authorised to view this page',
        signInHref: '/auth/sign-in'
      }
    ])
    expect(h.result.code.mock.calls[0][0]).toBe(403)
  })

  test('not-authorised offers sign out to a signed-in visitor', () => {
    // Arrange
    const request = { ...createRequest(), auth: { isAuthenticated: true } }
    const h = createToolkit()
    const { routes } = registerPlugin()

    // Act
    routes[4].handler(request, h)

    // Assert
    expect(h.view.mock.calls[0]).toEqual([
      'error/not-authorised',
      {
        pageTitle: 'Sorry, you are not authorised to view this page',
        signOutHref: '/signout'
      }
    ])
    expect(h.result.code.mock.calls[0][0]).toBe(403)
  })

  test('does not register the shared not-authorised route when the hub sets its own path', () => {
    // Arrange / Act
    const { routes } = registerPlugin({
      notAuthorisedPath: '/auth/access-denied'
    })

    // Assert
    expect(routes.map(({ path }) => path)).toEqual([
      '/auth/login',
      '/sso',
      '/auth/logout',
      '/signout'
    ])
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
