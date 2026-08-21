import { describe, expect, test, vi } from 'vitest'

import { createCallbackController } from '../../../src/auth/plugin/create-callback-controller.js'

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
    state: vi.fn(() => response)
  }

  return {
    redirect: vi.fn(() => response),
    result: response
  }
}

describe('createCallbackController()', () => {
  test('enriches and stores the session before setting its JWT', async () => {
    // Arrange
    const authSession = { sub: 'user-1', email: 'user@example.com' }
    const resolveAuthSession = vi.fn(async () => ({
      roles: ['lis-role-reader']
    }))
    const controller = createCallbackController({
      cookieOptions,
      hubJwtConfig,
      hubJwtCookieName,
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

    // Act
    let error
    try {
      await controller.handler(request, h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(h.redirect.mock.calls[0][0]).toBe('/cattle')
    expect(h.result.state.mock.calls[0][0]).toBe(hubJwtCookieName)
    expect(h.result.state.mock.calls[0][2]).toBe(cookieOptions)
    expect(request.yar.get('hub-auth-session')).toEqual({
      ...authSession,
      roles: ['lis-role-reader']
    })
    expect(resolveAuthSession.mock.calls[0][0]).toEqual({
      user: { sub: 'user-1' },
      authSession,
      accessToken: 'access-token'
    })
  })

  test('surfaces errors returned by the identity provider', async () => {
    // Arrange
    const controller = createCallbackController({
      cookieOptions,
      hubJwtConfig,
      hubJwtCookieName,
      completeAuthorizationCodeGrant: vi.fn(),
      resolveAuthSession: vi.fn()
    })
    const request = createRequest()
    request.query = { error: 'access_denied', error_description: 'Denied' }

    // Act
    let result, error
    try {
      result = await controller.handler(request, createToolkit())
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).not.toBeDefined()
    expect(error.message).toBe('Denied')
  })
})
