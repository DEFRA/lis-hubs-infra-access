import Hapi from '@hapi/hapi'
import { afterEach, describe, expect, test, vi } from 'vitest'

const { logger } = vi.hoisted(() => ({
  logger: { error: vi.fn(), warn: vi.fn() }
}))

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger }))

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
      hubId: 'back-office',
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
    expect(credentials.caller).toBe('lis-hubs-back-office')
    expect(response.result.hasLegacyFields).toBe(false)
  })

  test('throws when no hubId is given', async () => {
    // Arrange
    const overrides = { hubId: undefined }

    // Act
    let server, error
    try {
      server = await createServer(overrides)
    } catch (e) {
      error = e
    }

    // Assert
    expect(server).toBeUndefined()
    expect(error.message).toBe(
      'createHubAuth() requires a hubId of front-office or back-office'
    )
  })

  test('throws when the hubId is not a registry hub', async () => {
    // Arrange
    const overrides = { hubId: 'cattle-home' }

    // Act
    let server, error
    try {
      server = await createServer(overrides)
    } catch (e) {
      error = e
    }

    // Assert
    expect(server).toBeUndefined()
    expect(error.message).toBe(
      'createHubAuth() requires a hubId of front-office or back-office'
    )
  })

  test('throws when the renamed accessDeniedPath option is given', async () => {
    // Arrange
    const overrides = { accessDeniedPath: '/auth/access-denied' }

    // Act
    let server, error
    try {
      server = await createServer(overrides)
    } catch (e) {
      error = e
    }

    // Assert
    expect(server).toBeUndefined()
    expect(error).toBeInstanceOf(TypeError)
    expect(error.message).toBe(
      'createHubAuth() accessDeniedPath was renamed to notAuthorisedPath'
    )
  })

  test.each([
    'https://evil.example/not-authorised',
    '//evil.example/not-authorised',
    'auth/not-authorised',
    '',
    42
  ])('throws when notAuthorisedPath is not a hub path (%s)', async (path) => {
    // Arrange
    const overrides = { notAuthorisedPath: path }

    // Act
    let server, error
    try {
      server = await createServer(overrides)
    } catch (e) {
      error = e
    }

    // Assert
    expect(server).toBeUndefined()
    expect(error).toBeInstanceOf(TypeError)
    expect(error.message).toBe(
      "createHubAuth() requires notAuthorisedPath to be a hub path starting with '/'"
    )
  })

  test('signs the user out of the hub to the not-authorised page when the logout URL cannot be built', async () => {
    // Arrange
    const buildLogoutUrl = vi.fn(async () => {
      throw new Error('discovery unavailable')
    })
    const server = await createServer({
      authorize: () => false,
      buildLogoutUrl
    })

    // Act
    const response = await server.inject({
      url: '/page',
      headers: sessionHeaders()
    })

    // Assert
    expect(response.statusCode).toBe(302)
    expect(response.headers.location).toBe('/auth/not-authorised')
    expect(response.headers['set-cookie'][0]).toMatch(/^hub-jwt=;/)
    expect(response.request.yar.get('hub-auth-session')).toBeUndefined()
    expect(logger.warn).toHaveBeenCalledWith(
      'Failed to build OIDC logout URL for a refused user [cause=discovery unavailable]'
    )
  })

  test('signs the user out to the not-authorised page when authorize returns false', async () => {
    // Arrange
    const authorize = vi.fn(async () => false)
    const buildLogoutUrl = vi.fn(
      async () => 'https://identity.example/logout?refused'
    )
    const server = await createServer({ authorize, buildLogoutUrl })

    // Act
    const response = await server.inject({
      url: '/page',
      headers: sessionHeaders()
    })

    // Assert
    expect(response.statusCode).toBe(302)
    expect(response.headers.location).toBe(
      'https://identity.example/logout?refused'
    )
    expect(response.headers['set-cookie'][0]).toMatch(/^hub-jwt=;/)
    expect(buildLogoutUrl.mock.calls[0][1]).toEqual({
      authSession: signedInSession,
      returnPath: '/auth/not-authorised'
    })
    expect(response.request.yar.get('hub-auth-session')).toBeUndefined()
    expect(authorize).toHaveBeenCalledWith(
      expect.objectContaining({ sub: 'user-1' }),
      expect.objectContaining({ path: '/page' })
    )
  })

  test('signs the user out to a custom not-authorised path when authorize returns false', async () => {
    // Arrange
    const buildLogoutUrl = vi.fn(async () => 'https://identity.example/logout')
    const server = await createServer({
      authorize: () => false,
      buildLogoutUrl,
      notAuthorisedPath: '/auth/access-denied'
    })

    // Act
    const response = await server.inject({
      url: '/page',
      headers: sessionHeaders()
    })

    // Assert
    expect(response.statusCode).toBe(302)
    expect(buildLogoutUrl.mock.calls[0][1].returnPath).toBe(
      '/auth/access-denied'
    )
  })

  test('renders the not-authorised view with a 403 without running authorize', async () => {
    // Arrange
    const authorize = vi.fn(() => false)
    const server = await createServer({ authorize })
    // Stands in for @hapi/vision and the ui-services error views.
    server.decorate('toolkit', 'view', function (template, context) {
      return this.response({ template, context })
    })

    // Act
    const response = await server.inject({
      url: '/auth/not-authorised',
      headers: sessionHeaders()
    })

    // Assert
    expect(response.statusCode).toBe(403)
    expect(response.result).toEqual({
      template: 'error/not-authorised',
      context: {
        pageTitle: 'Sorry, you are not authorised to view this page',
        signInHref: '/auth/login'
      }
    })
    expect(authorize).not.toHaveBeenCalled()
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
      '/auth/not-authorised',
      '/signout',
      '/sso'
    ])
    expect(routes.every(({ settings }) => settings.auth === false)).toBe(true)
  })
})
