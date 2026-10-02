import Hapi from '@hapi/hapi'
import { afterEach, describe, expect, test, vi } from 'vitest'

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger: { error: vi.fn() } }))

import { createHubAuth } from '../../src/authentication/hub-auth.js'

const signedInSession = {
  sub: 'user-1',
  statements: [{ role: 'lis-role-caseworker', cphs: '*' }]
}

async function createServer(overrides = {}) {
  const server = Hapi.server()

  // Stands in for @hapi/yar: the test session comes from a header.
  server.ext('onRequest', (request, h) => {
    const session = request.headers['x-test-session']
    const values = new Map(
      session ? [['hub-auth-session', JSON.parse(session)]] : []
    )
    request.yar = {
      get: (key) => values.get(key),
      set: (key, value) => values.set(key, value),
      clear: (key) => values.delete(key)
    }

    return h.continue
  })

  await server.register(
    createHubAuth({
      getHubJwtCookieName: () => 'hub-jwt',
      getCookieOptions: () => ({ isSecure: false }),
      getHubJwtConfig: () => ({}),
      resolveAuthSession: async () => ({}),
      buildAuthorizationUrl: async () => 'https://identity.example/authorize',
      completeAuthorizationCodeGrant: async () => ({}),
      buildLogoutUrl: async () => 'https://identity.example/logout',
      loginRoutes: [{ path: '/auth/login', providerId: 'entra' }],
      ...overrides
    })
  )

  const handler = (request) => ({
    credentials: request.auth.credentials,
    isAuthenticated: request.auth.isAuthenticated,
    hasLegacyFields:
      'hubAuth' in request.app || 'authorizedSpecies' in request.app
  })

  server.route([
    { method: 'GET', path: '/page', handler },
    {
      method: 'GET',
      path: '/',
      options: { auth: { mode: 'try' } },
      handler
    },
    {
      method: 'GET',
      path: '/optional',
      options: { auth: { mode: 'optional' } },
      handler
    }
  ])

  return server
}

function sessionHeaders(session = signedInSession) {
  return { 'x-test-session': JSON.stringify(session) }
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('lis-hub-session scheme', () => {
  test('redirects signed-out users on required routes with a returnUrl', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({ url: '/page?cph=10%2F081' })

    // Assert
    expect(server.auth.settings.default.strategies).toEqual(['lis-hub-session'])
    expect(response.statusCode).toBe(302)
    expect(response.headers.location).toBe(
      '/auth/login?returnUrl=%2Fpage%3Fcph%3D10%252F081'
    )
  })

  test('lets signed-out users through optional routes unauthenticated', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({ url: '/optional' })

    // Assert
    expect(response.statusCode).toBe(200)
    expect(response.result.isAuthenticated).toBe(false)
  })

  test('lets signed-out users through try routes unauthenticated', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({ url: '/' })

    // Assert
    expect(response.statusCode).toBe(200)
    expect(response.result.isAuthenticated).toBe(false)
    expect(response.result.hasLegacyFields).toBe(false)
  })

  test('authenticates signed-in users with hydrated credentials', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({
      url: '/page',
      headers: sessionHeaders()
    })

    // Assert
    const { credentials } = response.result
    expect(response.statusCode).toBe(200)
    expect(credentials.user.sub).toBe('user-1')
    expect(credentials.user.statements[0].permissions).toContain(
      'lis-perm-cattle-read'
    )
    expect(
      credentials.authorizedSpecies.some(({ id }) => id === 'cattle')
    ).toBe(true)
    expect(response.result.hasLegacyFields).toBe(false)
  })

  test('returns 403 when authorize returns false', async () => {
    // Arrange
    const authorize = vi.fn(async () => false)
    const server = await createServer({ authorize })

    // Act
    const response = await server.inject({
      url: '/page',
      headers: sessionHeaders()
    })

    // Assert
    expect(response.statusCode).toBe(403)
    expect(authorize).toHaveBeenCalledWith(
      expect.objectContaining({ sub: 'user-1' }),
      expect.objectContaining({ path: '/page' })
    )
  })

  test('allows the request when authorize returns true', async () => {
    // Arrange
    const server = await createServer({ authorize: () => true })

    // Act
    const response = await server.inject({
      url: '/page',
      headers: sessionHeaders()
    })

    // Assert
    expect(response.statusCode).toBe(200)
  })

  test('does not run authorize for signed-out try requests or auth: false routes', async () => {
    // Arrange
    const authorize = vi.fn(() => false)
    const server = await createServer({ authorize })

    // Act
    const tryResponse = await server.inject({ url: '/' })
    const signoutResponse = await server.inject({ url: '/signout' })

    // Assert
    expect(tryResponse.statusCode).toBe(200)
    expect(signoutResponse.statusCode).toBe(302)
    expect(signoutResponse.headers.location).toBe('/auth/logout')
    expect(authorize).not.toHaveBeenCalled()
  })

  test('the plugin routes all have auth: false', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const routes = server
      .table()
      .filter(({ path }) => !['/', '/page', '/optional'].includes(path))

    // Assert
    expect(routes.map(({ path }) => path).sort()).toEqual([
      '/auth/login',
      '/auth/logout',
      '/signout',
      '/sso'
    ])
    expect(routes.every(({ settings }) => settings.auth === false)).toBe(true)
  })
})
