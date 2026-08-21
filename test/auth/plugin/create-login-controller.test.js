import { describe, expect, test, vi } from 'vitest'

import { createLoginController } from '../../../src/auth/plugin/create-login-controller.js'

const cookieOptions = { isSecure: false }
const hubJwtConfig = {
  secret: 'test-hub-secret-please-change-1234567890',
  issuer: 'http://localhost:3000',
  audience: 'livestock-spokes',
  ttlSeconds: 3600
}
const hubJwtCookieName = 'hub-jwt'

function createRequest(values = new Map()) {
  return {
    query: {},
    yar: {
      get: (key) => values.get(key),
      set: (key, value) => values.set(key, value)
    }
  }
}

function createToolkit() {
  const response = {
    code: vi.fn(() => response),
    state: vi.fn(() => response)
  }

  return {
    redirect: vi.fn(() => response),
    response: vi.fn(() => response),
    result: response
  }
}

describe('createLoginController()', () => {
  test('redirects an already-authenticated user with a refreshed JWT', async () => {
    // Arrange
    const values = new Map([
      ['hub-auth-session', { sub: 'user-1', roles: ['lis-role-reader'] }]
    ])
    const buildAuthorizationUrl = vi.fn()
    const controller = createLoginController({
      cookieOptions,
      hubJwtConfig,
      hubJwtCookieName,
      buildAuthorizationUrl
    })
    const request = createRequest(values)
    request.query.returnUrl = '/cattle'
    const h = createToolkit()

    // Act
    let error
    try {
      await controller.handler(request, h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(buildAuthorizationUrl).not.toHaveBeenCalled()
    expect(h.redirect.mock.calls[0][0]).toBe('/cattle')
    expect(h.result.state.mock.calls[0][0]).toBe(hubJwtCookieName)
    expect(h.result.state.mock.calls[0][2]).toBe(cookieOptions)
  })

  test('redirects unauthenticated users to their identity provider', async () => {
    // Arrange
    const buildAuthorizationUrl = vi.fn(
      async () => 'https://identity.example/authorize'
    )
    const controller = createLoginController({
      cookieOptions,
      hubJwtConfig,
      hubJwtCookieName,
      buildAuthorizationUrl
    })
    const request = createRequest()
    request.query.returnUrl = '/cattle'
    const h = createToolkit()

    // Act
    let error
    try {
      await controller.handler(request, h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(buildAuthorizationUrl.mock.calls[0]).toEqual([request])
    expect(h.redirect.mock.calls[0][0]).toBe(
      'https://identity.example/authorize'
    )
  })

  test('returns 503 when the identity provider is unavailable', async () => {
    // Arrange
    const providerError = new Error('offline')
    const logger = { error: vi.fn() }
    const controller = createLoginController({
      cookieOptions,
      hubJwtConfig,
      hubJwtCookieName,
      buildAuthorizationUrl: async () => {
        throw providerError
      }
    })
    const request = { ...createRequest(), logger }
    const h = createToolkit()

    // Act
    let error
    try {
      await controller.handler(request, h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(logger.error.mock.calls[0]).toEqual([providerError])
    expect(h.result.code.mock.calls[0]).toEqual([503])
  })
})
