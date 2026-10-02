import Hapi from '@hapi/hapi'
import { afterEach, describe, expect, test, vi } from 'vitest'

const { logger, verify } = vi.hoisted(() => ({
  logger: { warn: vi.fn() },
  verify: vi.fn(async (token) => {
    if (token !== 'valid-service-token') {
      throw new Error('signature verification failed')
    }

    return { serviceName: 'lis-hubs-front-office' }
  })
}))

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger }))

vi.mock('../../src/authentication/service-token/verifier.js', () => ({
  createServiceTokenVerifier: vi.fn(() => ({ verify }))
}))

vi.mock(
  '../../src/authentication/tokens/access-mode.js',
  async (importOriginal) => {
    const actual = await importOriginal()

    return { ...actual, getSpokeAccessMode: vi.fn(actual.getSpokeAccessMode) }
  }
)

import { createServiceTokenVerifier } from '../../src/authentication/service-token/verifier.js'
import { createSpokeAuth } from '../../src/authentication/spoke-auth.js'
import { getSpokeAccessMode } from '../../src/authentication/tokens/access-mode.js'
import { issueHubJwt } from '../../src/authentication/tokens/jwt.js'

const hubOrigin = 'http://localhost:3000'
const jwtConfig = {
  secret: 'test-hub-secret-please-change-1234567890',
  issuer: hubOrigin,
  audience: 'livestock-spokes',
  ttlSeconds: 3600
}
const cookieName = 'livestock_hub_jwt'
const serviceHeaders = { authorization: 'Bearer valid-service-token' }
const caseworker = {
  sub: 'user-1',
  statements: [{ role: 'lis-role-caseworker', cphs: '*' }]
}

function createOptions(overrides = {}) {
  return {
    spokeId: 'cattle-home',
    hubOrigins: [hubOrigin],
    cookieName,
    cookieOptions: { encoding: 'none', isSecure: false },
    assetPath: '/public',
    port: 3201,
    basePath: '/cattle',
    secret: jwtConfig.secret,
    audience: jwtConfig.audience,
    moduleAccess: { species: 'cattle', scope: 'species', minLevel: 'read' },
    ...overrides
  }
}

async function createServer(overrides = {}) {
  const server = Hapi.server()

  await server.register(createSpokeAuth(createOptions(overrides)))

  const handler = (request) => ({
    credentials: request.auth.credentials,
    isAuthenticated: request.auth.isAuthenticated,
    hasLegacyFields: 'hubAuth' in request.app
  })

  server.route([
    { method: 'GET', path: '/page', handler },
    {
      method: 'GET',
      path: '/maybe',
      options: { auth: { mode: 'try' } },
      handler
    },
    {
      method: 'GET',
      path: '/optional',
      options: { auth: { mode: 'optional' } },
      handler
    },
    {
      method: 'GET',
      path: '/health',
      options: { auth: false },
      handler: () => ({ message: 'success' })
    }
  ])

  return server
}

async function cookieFor(session) {
  return `${cookieName}=${await issueHubJwt(session, jwtConfig)}`
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('createSpokeAuth()', () => {
  test('lets signed-out users through optional routes unauthenticated', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({
      url: '/optional',
      headers: serviceHeaders
    })

    // Assert
    expect(response.statusCode).toBe(200)
    expect(response.result.isAuthenticated).toBe(false)
  })

  test('builds the service token verifier with the spoke audience', async () => {
    // Arrange / Act
    await createServer()

    // Assert
    expect(createServiceTokenVerifier).toHaveBeenCalledExactlyOnceWith({
      audience: 'lis-apps-cattle-home'
    })
  })

  test.each([
    ['required', '/page'],
    ['try', '/maybe']
  ])(
    'rejects a missing service token with 401 on a %s route',
    async (_mode, url) => {
      // Arrange
      const server = await createServer()

      // Act
      const response = await server.inject({
        url,
        headers: { cookie: await cookieFor(caseworker) }
      })

      // Assert
      expect(response.statusCode).toBe(401)
      expect(response.result).toEqual({
        message: 'Service authentication required'
      })
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringMatching(/^Service token missing/)
      )
    }
  )

  test.each([
    ['required', '/page'],
    ['try', '/maybe']
  ])(
    'rejects an invalid service token with 401 on a %s route',
    async (_mode, url) => {
      // Arrange
      const server = await createServer()

      // Act
      const response = await server.inject({
        url,
        headers: { authorization: 'Bearer forged' }
      })

      // Assert
      expect(response.statusCode).toBe(401)
      expect(verify).toHaveBeenCalledWith('forged')
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringMatching(/^Service token validation failed/)
      )
    }
  )

  test('redirects to hub login when a required route has no user', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({
      url: '/page?x=1',
      headers: serviceHeaders
    })

    // Assert
    expect(response.statusCode).toBe(302)
    expect(response.headers.location).toBe(
      `${hubOrigin}/auth/login?returnUrl=%2Fcattle%2Fpage%3Fx%3D1`
    )
  })

  test('redirects to hub login when the user cookie is invalid', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({
      url: '/page',
      headers: { ...serviceHeaders, cookie: `${cookieName}=not-a-jwt` }
    })

    // Assert
    expect(response.statusCode).toBe(302)
  })

  test('lets a try route through unauthenticated when there is no user', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({
      url: '/maybe',
      headers: serviceHeaders
    })

    // Assert
    expect(response.statusCode).toBe(200)
    expect(response.result.isAuthenticated).toBe(false)
  })

  test('leaves auth: false routes untouched', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({ url: '/health' })

    // Assert
    expect(response.statusCode).toBe(200)
    expect(verify).not.toHaveBeenCalled()
  })

  test('authenticates a valid service token and user cookie', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({
      url: '/page',
      headers: { ...serviceHeaders, cookie: await cookieFor(caseworker) }
    })

    // Assert
    expect(response.statusCode).toBe(200)
    expect(response.result.isAuthenticated).toBe(true)
    expect(response.result.credentials.caller).toBe('lis-hubs-front-office')
    expect(response.result.credentials.user.sub).toBe('user-1')
    expect(
      response.result.credentials.user.statements[0].permissions
    ).toContain('lis-perm-cattle-read')
    expect(response.result.hasLegacyFields).toBe(false)
  })

  test('returns 403 when the user lacks module access', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({
      url: '/page',
      headers: {
        ...serviceHeaders,
        cookie: await cookieFor({ sub: 'user-2', statements: [] })
      }
    })

    // Assert
    expect(response.statusCode).toBe(403)
  })

  test('returns 403 when authorize returns false', async () => {
    // Arrange
    const authorize = vi.fn(async () => false)
    const server = await createServer({ authorize })

    // Act
    const response = await server.inject({
      url: '/page',
      headers: { ...serviceHeaders, cookie: await cookieFor(caseworker) }
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
      headers: { ...serviceHeaders, cookie: await cookieFor(caseworker) }
    })

    // Assert
    expect(response.statusCode).toBe(200)
  })

  test('does not run authorize for unauthenticated try requests', async () => {
    // Arrange
    const authorize = vi.fn(() => false)
    const server = await createServer({ authorize })

    // Act
    const response = await server.inject({
      url: '/maybe',
      headers: serviceHeaders
    })

    // Assert
    expect(response.statusCode).toBe(200)
    expect(authorize).not.toHaveBeenCalled()
  })

  test('accepts injected credentials without a service token', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const response = await server.inject({
      url: '/page',
      auth: {
        strategy: 'lis-spoke',
        credentials: {
          user: {
            statements: [
              { role: 'test', cphs: '*', permissions: ['lis-perm-cattle-read'] }
            ]
          },
          caller: 'lis-hubs-back-office'
        }
      }
    })

    // Assert
    expect(response.statusCode).toBe(200)
    expect(response.result.credentials.caller).toBe('lis-hubs-back-office')
  })

  test('a public spoke authenticates without a user but still needs the service token', async () => {
    // Arrange
    vi.mocked(getSpokeAccessMode).mockReturnValueOnce('public')
    const server = await createServer()

    // Act
    const withToken = await server.inject({
      url: '/page',
      headers: serviceHeaders
    })
    const withoutToken = await server.inject({ url: '/page' })

    // Assert
    expect(withToken.statusCode).toBe(200)
    expect(withToken.result.credentials).toEqual({
      user: null,
      caller: 'lis-hubs-front-office'
    })
    expect(withoutToken.statusCode).toBe(401)
  })

  test('rejects an unknown spoke', () => {
    expect(() =>
      createSpokeAuth(createOptions({ spokeId: 'unknown' }))
    ).toThrow(/Unable to resolve spoke configuration for unknown/)
  })

  test('rejects an invalid module access configuration', () => {
    expect(() => createSpokeAuth(createOptions({ moduleAccess: {} }))).toThrow(
      /Unable to resolve module access configuration/
    )
  })
})
