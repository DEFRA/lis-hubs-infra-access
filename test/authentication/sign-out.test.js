import Hapi from '@hapi/hapi'
import { afterEach, describe, expect, test, vi } from 'vitest'

const { logger } = vi.hoisted(() => ({ logger: { error: vi.fn() } }))

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger }))

import { createHubAuth } from '../../src/authentication/hub-auth.js'
import {
  addFormActionSources,
  createSignOutRoutes
} from '../../src/authentication/sign-out.js'

const hubAuthOptions = {
  hubId: 'front-office',
  getHubJwtConfig: () => ({}),
  resolveAuthSession: async () => ({}),
  buildAuthorizationUrl: async () => 'https://identity.example/authorize',
  completeAuthorizationCodeGrant: async () => ({}),
  buildLogoutUrl: async () => 'https://identity.example/logout',
  getLogoutOrigins: async () => [
    'https://identity.example',
    'https://issuer.example'
  ],
  loginRoutes: [{ path: '/auth/login', providerId: 'entra' }]
}

const policy =
  "base-uri 'self';default-src 'self';form-action 'self';object-src 'none'"

function createRequest({ values = new Map(), csrfToken } = {}) {
  return {
    plugins:
      csrfToken === undefined ? {} : { 'lis-csrf': { token: csrfToken } },
    yar: {
      get: (key) => values.get(key),
      reset: () => values.clear()
    }
  }
}

function createToolkit() {
  const response = { code: vi.fn(() => response), plugins: {} }

  return {
    redirect: vi.fn(() => response),
    view: vi.fn(() => response),
    result: response
  }
}

function findRoute(method, path, overrides = {}) {
  return createSignOutRoutes({
    buildLogoutUrl: async () => 'https://identity.example/logout',
    getLogoutOrigins: async () => ['https://identity.example'],
    ...overrides
  }).find((route) => route.method === method && route.path === path)
}

// Stands in for Blankie 5, which the hubs register after hub auth, and which
// assigns the header into response.headers under a title-case name.
const cspPlugin = {
  name: 'blankie',
  register(server) {
    server.ext('onPreResponse', (request, h) => {
      if (!request.response.isBoom) {
        request.response.headers['Content-Security-Policy'] = policy
      }

      return h.continue
    })
  }
}

// Stands in for the CSRF plugin and the view engine.
const csrfStub = {
  name: 'lis-csrf',
  register(server) {
    server.ext('onPostAuth', (request, h) => {
      request.plugins['lis-csrf'] = {
        token: request.headers['x-test-token']
      }

      return h.continue
    })
    server.decorate('toolkit', 'view', function view(template) {
      return this.response(template)
    })
  }
}

async function createServer(options = {}) {
  const server = Hapi.server()
  await server.register([
    csrfStub,
    createHubAuth({ ...hubAuthOptions, ...options }),
    cspPlugin
  ])
  server.route({
    method: 'GET',
    path: '/other',
    options: { auth: false },
    handler: () => 'other'
  })
  await server.initialize()

  return server
}

describe('createSignOutRoutes()', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  test('sends a POST /signout that fails a CSRF check home in place of a 403', () => {
    // Arrange
    const route = findRoute('POST', '/signout')
    const h = createToolkit()

    // Act
    route.options.plugins['lis-csrf'].failAction({}, h)

    // Assert
    expect(route.options.auth).toBe(false)
    expect(Object.keys(route.options.plugins['lis-csrf'])).toEqual([
      'failAction'
    ])
    expect(h.redirect).toHaveBeenCalledWith('/')
  })

  test('asks a signed-in user to confirm on a GET /signout without signing them out', async () => {
    // Arrange
    const route = findRoute('GET', '/signout')
    const request = createRequest({
      values: new Map([['hub-auth-session', { sub: 'user-1' }]]),
      csrfToken: 'csrf-token'
    })
    const h = createToolkit()

    // Act
    await route.handler(request, h)

    // Assert
    expect(route.options.auth).toBe(false)
    expect(h.view).toHaveBeenCalledWith('auth/sign-out', {
      pageTitle: 'Are you sure you want to sign out?',
      signOutHref: '/signout'
    })
    expect(h.result.plugins['lis-hub-auth-sign-out']).toEqual({
      logoutOrigins: ['https://identity.example']
    })
    expect(h.redirect).not.toHaveBeenCalled()
    expect(request.yar.get('hub-auth-session')).toEqual({ sub: 'user-1' })
  })

  test('sends a GET /signout home when there is no CSRF token, as no one is signed in', async () => {
    // Arrange
    const getLogoutOrigins = vi.fn()
    const route = findRoute('GET', '/signout', { getLogoutOrigins })
    const h = createToolkit()

    // Act
    await route.handler(createRequest(), h)

    // Assert
    expect(h.redirect).toHaveBeenCalledWith('/')
    expect(h.view).not.toHaveBeenCalled()
    expect(getLogoutOrigins).not.toHaveBeenCalled()
  })

  test('still renders the confirmation page, logging the error and not widening the policy, when discovery fails', async () => {
    // Arrange
    const discoveryError = new Error('discovery failed')
    const route = findRoute('GET', '/signout', {
      getLogoutOrigins: async () => {
        throw discoveryError
      }
    })
    const h = createToolkit()

    // Act
    let error
    try {
      await route.handler(createRequest({ csrfToken: 'csrf-token' }), h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).toBeUndefined()
    expect(h.view).toHaveBeenCalledWith('auth/sign-out', {
      pageTitle: 'Are you sure you want to sign out?',
      signOutHref: '/signout'
    })
    expect(h.result.plugins['lis-hub-auth-sign-out']).toEqual({
      logoutOrigins: []
    })
    expect(logger.error).toHaveBeenCalledWith(
      discoveryError,
      'Sign-out origins unavailable, so the sign-out page CSP is not widened'
    )
  })

  test('redirects the old GET /auth/logout to the sign-out confirmation', () => {
    // Arrange
    const route = findRoute('GET', '/auth/logout')
    const h = createToolkit()

    // Act
    route.handler(createRequest(), h)

    // Assert
    expect(route.options.auth).toBe(false)
    expect(h.redirect).toHaveBeenCalledWith('/signout')
  })
})

describe('addFormActionSources()', () => {
  test('appends the sources to form-action only, keeping the rest of the policy', () => {
    // Act
    const result = addFormActionSources(policy, [
      'https://identity.example',
      'https://issuer.example'
    ])

    // Assert
    expect(result).toBe(
      "base-uri 'self';default-src 'self';form-action 'self' https://identity.example https://issuer.example;object-src 'none'"
    )
  })

  test('leaves a policy without form-action alone', () => {
    // Act
    const result = addFormActionSources("default-src 'self'", [
      'https://identity.example'
    ])

    // Assert
    expect(result).toBe("default-src 'self'")
  })
})

describe('sign-out page CSP', () => {
  test('allows the sign-out origins in form-action on GET /signout only, after the CSP plugin', async () => {
    // Arrange
    const server = await createServer()

    // Act
    const signOutResponse = await server.inject({
      url: '/signout',
      headers: { 'x-test-token': 'csrf-token' }
    })
    const otherResponse = await server.inject({ url: '/other' })

    // Assert
    expect(signOutResponse.statusCode).toBe(200)
    expect(signOutResponse.headers['content-security-policy']).toBe(
      "base-uri 'self';default-src 'self';form-action 'self' https://identity.example https://issuer.example;object-src 'none'"
    )
    expect(
      Object.keys(signOutResponse.request.response.headers).filter(
        (name) => name.toLowerCase() === 'content-security-policy'
      )
    ).toEqual(['Content-Security-Policy'])
    expect(otherResponse.headers['content-security-policy']).toBe(policy)
  })

  test('requires the CSRF plugin, which protects POST /signout', async () => {
    // Arrange
    const server = Hapi.server()
    await server.register([createHubAuth(hubAuthOptions), cspPlugin])

    // Act
    let error
    try {
      await server.initialize()
    } catch (e) {
      error = e
    }

    // Assert
    expect(error.message).toContain('lis-csrf')
  })

  test('requires getLogoutOrigins', () => {
    // Arrange
    const { getLogoutOrigins, ...options } = hubAuthOptions

    // Act
    let error
    try {
      createHubAuth(options)
    } catch (e) {
      error = e
    }

    // Assert
    expect(getLogoutOrigins).toBeTypeOf('function')
    expect(error).toBeInstanceOf(TypeError)
  })
})
