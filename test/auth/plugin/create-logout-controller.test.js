import { describe, expect, test, vi } from 'vitest'

import { createLogoutController } from '../../../src/auth/plugin/create-logout-controller.js'

const cookieOptions = { isSecure: false }
const hubJwtCookieName = 'hub-jwt'

function createRequest(values = new Map()) {
  return {
    yar: {
      clear: (key) => values.delete(key),
      get: (key) => values.get(key)
    }
  }
}

function createToolkit() {
  const response = {
    unstate: vi.fn(() => response)
  }

  return {
    redirect: vi.fn(() => response),
    result: response
  }
}

describe('createLogoutController()', () => {
  test('clears auth state and removes the JWT cookie', async () => {
    // Arrange
    const request = createRequest(
      new Map([
        ['hub-auth-session', { sub: 'user-1' }],
        ['hub-auth-flow', { state: 'state-id' }]
      ])
    )
    const h = createToolkit()
    const controller = createLogoutController({
      cookieOptions,
      hubJwtCookieName,
      buildLogoutUrl: async () => 'https://identity.example/logout'
    })

    // Act
    let error
    try {
      await controller.handler(request, h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(h.redirect.mock.calls[0][0]).toBe('https://identity.example/logout')
    expect(h.result.unstate.mock.calls[0]).toEqual([
      hubJwtCookieName,
      cookieOptions
    ])
    expect(request.yar.get('hub-auth-session')).toBeUndefined()
    expect(request.yar.get('hub-auth-flow')).toBeUndefined()
  })
})
