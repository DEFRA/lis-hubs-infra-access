import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest'

import { createOidcClient } from '../../../src/auth/oidc/index.js'
import { createCallbackController } from '../../../src/auth/plugin/create-callback-controller.js'
import { createLoginController } from '../../../src/auth/plugin/create-login-controller.js'
import { createLogoutController } from '../../../src/auth/plugin/create-logout-controller.js'
import { createHubAuthPlugin } from '../../../src/auth/plugin/index.js'
import { preAuthExtension } from '../../../src/auth/plugin/pre-auth-extension.js'

vi.mock('../../../src/auth/oidc/index.js')
vi.mock('../../../src/auth/plugin/create-login-controller.js')
vi.mock('../../../src/auth/plugin/create-callback-controller.js')
vi.mock('../../../src/auth/plugin/create-logout-controller.js')
vi.mock('../../../src/auth/plugin/pre-auth-extension.js')

const mocks = {
  createOidcClient: vi.mocked(createOidcClient),
  createLoginController: vi.mocked(createLoginController),
  createCallbackController: vi.mocked(createCallbackController),
  createLogoutController: vi.mocked(createLogoutController)
}

const provider = { discoveryUrl: 'https://identity.example/.well-known' }
const hubOrigin = 'https://hub.example'
const mapUser = (payload) => payload
const resolveAuthSession = async () => ({})
const hubJwtCookieName = 'hub-jwt'
const cookieOptions = { isSecure: false }
const hubJwtConfig = { secret: 'test-hub-secret-please-change-1234567890' }

const oidcOperations = {
  buildAuthorizationUrl: vi.fn(),
  completeAuthorizationCodeGrant: vi.fn(),
  buildLogoutUrl: vi.fn()
}

function createPlugin(overrides = {}) {
  return createHubAuthPlugin({
    hubJwtCookieName,
    cookieOptions,
    hubJwtConfig,
    resolveAuthSession,
    provider,
    hubOrigin,
    mapUser,
    loginPath: '/auth/login',
    ...overrides
  })
}

describe('createHubAuthPlugin()', () => {
  beforeAll(() => {
    mocks.createOidcClient.mockResolvedValue(oidcOperations)
    mocks.createLoginController.mockReturnValue({ loginController: true })
    mocks.createCallbackController.mockReturnValue({ callbackController: true })
    mocks.createLogoutController.mockReturnValue({ logoutController: true })
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  test('builds its OIDC client from the given provider config', async () => {
    // Act
    let error
    try {
      await createPlugin()
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(mocks.createOidcClient.mock.calls[0][0]).toEqual({
      provider,
      hubOrigin,
      mapUser
    })
  })

  test('wires each controller with the resolved OIDC operations', async () => {
    // Act
    let error
    try {
      await createPlugin()
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(mocks.createLoginController.mock.calls[0][0]).toEqual({
      cookieOptions,
      hubJwtConfig,
      hubJwtCookieName,
      buildAuthorizationUrl: oidcOperations.buildAuthorizationUrl
    })
    expect(mocks.createCallbackController.mock.calls[0][0]).toEqual({
      cookieOptions,
      hubJwtConfig,
      hubJwtCookieName,
      completeAuthorizationCodeGrant:
        oidcOperations.completeAuthorizationCodeGrant,
      resolveAuthSession
    })
    expect(mocks.createLogoutController.mock.calls[0][0]).toEqual({
      cookieOptions,
      hubJwtCookieName,
      buildLogoutUrl: oidcOperations.buildLogoutUrl
    })
  })

  test('registers auth state, pre-auth middleware and login lifecycle routes', async () => {
    // Arrange
    let extEvent
    let extHandler
    let routes
    const state = vi.fn()

    // Act
    let error
    try {
      const plugin = await createPlugin({ pluginName: 'hub-auth' })

      plugin.plugin.register({
        state,
        ext(event, handler) {
          extEvent = event
          extHandler = handler
        },
        route(registeredRoutes) {
          routes = registeredRoutes
        }
      })

      // Assert
      expect(plugin.plugin.name).toBe('hub-auth')
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(state.mock.calls[0]).toEqual([hubJwtCookieName, cookieOptions])
    expect(extEvent).toBe('onPreAuth')
    expect(extHandler).toBe(preAuthExtension)
    expect(routes.map(({ method, path }) => ({ method, path }))).toEqual([
      { method: 'GET', path: '/auth/login' },
      { method: 'GET', path: '/sso' },
      { method: 'GET', path: '/auth/logout' }
    ])
    expect(routes[0].loginController).toBe(true)
    expect(routes[1].callbackController).toBe(true)
    expect(routes[2].logoutController).toBe(true)
  })

  test('defaults the plugin name to auth', async () => {
    // Act
    let result, error
    try {
      result = await createPlugin()
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result.plugin.name).toBe('auth')
  })
})
