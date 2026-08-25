import assert from 'node:assert/strict'
import { test, vi } from 'vitest'

import {
  createHubAuthPlugin,
  createHubCookieOptions
} from '../../src/auth/plugin.js'

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
  let preAuth
  let routes
  const state = vi.fn()
  const plugin = createHubAuthPlugin({
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
    state,
    ext(event, handler) {
      assert.equal(event, 'onPreAuth')
      preAuth = handler
    },
    route(registeredRoutes) {
      routes = registeredRoutes
    }
  })

  return { plugin, preAuth, routes, state }
}

test('creates standard hub cookie options', () => {
  assert.deepEqual(createHubCookieOptions({ ttlSeconds: 60, isSecure: true }), {
    encoding: 'none',
    ttl: 60000,
    isHttpOnly: true,
    isSecure: true,
    isSameSite: 'Lax',
    clearInvalid: true,
    path: '/'
  })
})

test('registers auth state, middleware and login lifecycle routes', () => {
  const { plugin, routes, state } = registerPlugin({ pluginName: 'hub-auth' })

  assert.equal(plugin.plugin.name, 'hub-auth')
  assert.deepEqual(
    routes.map(({ path }) => path),
    ['/auth/login', '/sso', '/auth/logout']
  )
  assert.deepEqual(state.mock.calls[0], ['hub-jwt', { isSecure: false }])
})

test('pre-auth middleware hydrates the session and authorized species', () => {
  const values = new Map([
    [
      'hub-auth-session',
      { statements: [{ role: 'lis-role-caseworker', cphs: '*' }] }
    ]
  ])
  const request = createRequest(values)
  const h = createToolkit()
  const { preAuth } = registerPlugin()

  assert.equal(preAuth(request, h), h.continue)
  assert.ok(
    request.app.hubAuth.statements.some((statement) =>
      statement.permissions.includes('lis-perm-cattle-read')
    )
  )
  assert.ok(request.app.authorizedSpecies.some(({ id }) => id === 'cattle'))
})

test('login redirects unauthenticated users to their identity provider', async () => {
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

  await routes[0].handler(request, h)

  assert.deepEqual(buildAuthorizationUrl.mock.calls[0], [request, 'entra'])
  assert.equal(
    h.redirect.mock.calls[0][0],
    'https://identity.example/authorize'
  )
})

test('login returns 503 when the identity provider is unavailable', async () => {
  const error = new Error('offline')
  const logger = { error: vi.fn() }
  const { routes } = registerPlugin({
    buildAuthorizationUrl: async () => {
      throw error
    }
  })
  const request = { ...createRequest(), logger }
  const h = createToolkit()

  await routes[0].handler(request, h)

  assert.deepEqual(logger.error.mock.calls[0], [error])
  assert.deepEqual(h.result.code.mock.calls[0], [503])
})

test('callback enriches and stores the session before setting its JWT', async () => {
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
  const request = createRequest()
  const h = createToolkit()

  await routes[1].handler(request, h)

  assert.equal(h.redirect.mock.calls[0][0], '/cattle')
  assert.equal(h.result.state.mock.calls[0][0], 'hub-jwt')
  assert.deepEqual(request.yar.get('hub-auth-session'), {
    ...authSession,
    statements: [{ role: 'lis-role-reader', cphs: '*' }]
  })
})

test('callback surfaces errors returned by the identity provider', async () => {
  const { routes } = registerPlugin()
  const request = createRequest()
  request.query = { error: 'access_denied', error_description: 'Denied' }

  await assert.rejects(routes[1].handler(request, createToolkit()), /Denied/)
})

test('logout clears auth state and removes the JWT cookie', async () => {
  const request = createRequest(
    new Map([
      ['hub-auth-session', { sub: 'user-1' }],
      ['hub-auth-flow', { state: 'state-id' }]
    ])
  )
  const h = createToolkit()
  const { routes } = registerPlugin()

  await routes[2].handler(request, h)

  assert.equal(h.redirect.mock.calls[0][0], 'https://identity.example/logout')
  assert.deepEqual(h.result.unstate.mock.calls[0], [
    'hub-jwt',
    { isSecure: false }
  ])
  assert.equal(request.yar.get('hub-auth-session'), undefined)
  assert.equal(request.yar.get('hub-auth-flow'), undefined)
})
