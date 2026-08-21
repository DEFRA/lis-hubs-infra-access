import { describe, expect, test } from 'vitest'

import { preAuthExtension } from '../../../src/auth/plugin/pre-auth-extension.js'

function createRequest(values = new Map()) {
  return {
    app: {},
    yar: {
      get: (key) => values.get(key)
    }
  }
}

function createToolkit() {
  return { continue: Symbol('continue') }
}

describe('preAuthExtension()', () => {
  test('hydrates the session and authorized species onto the request', () => {
    // Arrange
    const values = new Map([
      [
        'hub-auth-session',
        { roles: ['lis-role-caseworker'], permissions: ['untrusted'] }
      ]
    ])
    const request = createRequest(values)
    const h = createToolkit()

    // Act
    let result, error
    try {
      result = preAuthExtension(request, h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result).toBe(h.continue)
    expect(
      request.app.hubAuth.permissions.includes('lis-perm-cattle-read')
    ).toBe(true)
    expect(
      request.app.authorizedSpecies.some(({ id }) => id === 'cattle')
    ).toBe(true)
  })

  test('leaves hubAuth null and authorizedSpecies empty without a session', () => {
    // Arrange
    const request = createRequest()
    const h = createToolkit()

    // Act
    let error
    try {
      preAuthExtension(request, h)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(request.app.hubAuth).toBeNull()
    expect(request.app.authorizedSpecies).toEqual([])
  })
})
