import Hapi from '@hapi/hapi'
import { afterEach, describe, expect, test, vi } from 'vitest'

const { logger } = vi.hoisted(() => ({ logger: { error: vi.fn() } }))

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger }))

import { createHubAuth } from '../../src/authentication/hub-auth.js'

const sessions = new Map()

// Stands in for @hapi/yar: the session is picked by the x-test-session
// header, and kept here across requests.
const sessionStub = {
  name: 'session-stub',
  register(server) {
    server.ext('onRequest', (request, h) => {
      const id = request.headers['x-test-session']
      const values = sessions.get(id) ?? new Map()
      sessions.set(id, values)
      request.yar = {
        get: (key) => values.get(key),
        set: (key, value) => values.set(key, value),
        clear: (key) => values.delete(key),
        reset: () => values.clear()
      }

      return h.continue
    })
  }
}

// Keeps to the CSRF plugin's contract as hub sign-out relies on it: the token
// is the session's `lis-csrf-token`, published at request.plugins['lis-csrf'],
// and an unsafe request without it in `_csrf` gets the route's failAction, or
// a 403. The origin check is left to the plugin's own tests.
const csrfStandIn = {
  name: 'lis-csrf',
  register(server) {
    server.ext('onPostAuth', async (request, h) => {
      const token = request.yar.get('lis-csrf-token')
      request.plugins['lis-csrf'] = { token }

      if (request.method === 'get' || request.payload?._csrf === token) {
        return h.continue
      }

      const failAction = request.route.settings.plugins['lis-csrf']?.failAction

      return failAction
        ? (await failAction(request, h)).takeover()
        : h.response().code(403).takeover()
    })
  }
}

async function createServer(buildLogoutUrl) {
  const server = Hapi.server()
  await server.register([
    sessionStub,
    csrfStandIn,
    createHubAuth({
      hubId: 'front-office',
      getHubJwtConfig: () => ({}),
      resolveAuthSession: async () => ({}),
      buildAuthorizationUrl: async () => 'https://identity.example/authorize',
      completeAuthorizationCodeGrant: async () => ({}),
      buildLogoutUrl,
      getLogoutOrigins: async () => ['https://identity.example'],
      loginRoutes: [{ path: '/auth/login', providerId: 'entra' }]
    })
  ])
  await server.initialize()

  return server
}

function signIn(id) {
  sessions.set(
    id,
    new Map([
      ['hub-auth-session', { sub: 'user-1', idToken: 'id-token' }],
      ['hub-jwt', 'hub-jwt'],
      ['lis-csrf-token', 'csrf-token']
    ])
  )
}

describe('POST /signout', () => {
  afterEach(() => {
    sessions.clear()
    vi.clearAllMocks()
  })

  test('signs the user out and redirects to the identity provider when the token matches', async () => {
    // Arrange
    const buildLogoutUrl = vi.fn(async () => 'https://identity.example/logout')
    const server = await createServer(buildLogoutUrl)
    signIn('user-1')

    // Act
    const response = await server.inject({
      method: 'POST',
      url: '/signout',
      headers: { 'x-test-session': 'user-1' },
      payload: { _csrf: 'csrf-token' }
    })

    // Assert
    expect(response.statusCode).toBe(302)
    expect(response.headers.location).toBe('https://identity.example/logout')
    expect(buildLogoutUrl).toHaveBeenCalledTimes(1)
    expect([...sessions.get('user-1').keys()]).toEqual([])
  })

  test('signs nothing out and sends the user home when the token does not match', async () => {
    // Arrange
    const buildLogoutUrl = vi.fn(async () => 'https://identity.example/logout')
    const server = await createServer(buildLogoutUrl)
    signIn('user-1')

    // Act
    const response = await server.inject({
      method: 'POST',
      url: '/signout',
      headers: { 'x-test-session': 'user-1' },
      payload: { _csrf: 'forged' }
    })

    // Assert
    expect(response.statusCode).toBe(302)
    expect(response.headers.location).toBe('/')
    expect(buildLogoutUrl).not.toHaveBeenCalled()
    expect(sessions.get('user-1').get('hub-auth-session')).toEqual({
      sub: 'user-1',
      idToken: 'id-token'
    })
  })

  test('sends an expired session home', async () => {
    // Arrange
    const buildLogoutUrl = vi.fn(async () => 'https://identity.example/logout')
    const server = await createServer(buildLogoutUrl)

    // Act
    const response = await server.inject({
      method: 'POST',
      url: '/signout',
      headers: { 'x-test-session': 'expired' },
      payload: { _csrf: 'csrf-token' }
    })

    // Assert
    expect(response.statusCode).toBe(302)
    expect(response.headers.location).toBe('/')
    expect(buildLogoutUrl).not.toHaveBeenCalled()
  })

  test('still resets the session when the logout URL cannot be built', async () => {
    // Arrange
    const buildLogoutUrl = vi.fn(async () => {
      throw new Error('discovery failed')
    })
    const server = await createServer(buildLogoutUrl)
    signIn('user-1')

    // Act
    const response = await server.inject({
      method: 'POST',
      url: '/signout',
      headers: { 'x-test-session': 'user-1' },
      payload: { _csrf: 'csrf-token' }
    })

    // Assert
    expect(response.statusCode).toBe(500)
    expect([...sessions.get('user-1').keys()]).toEqual([])
  })
})
