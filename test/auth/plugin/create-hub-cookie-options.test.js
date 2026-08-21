import { describe, expect, test } from 'vitest'

import { createHubCookieOptions } from '../../../src/auth/plugin/create-hub-cookie-options.js'

describe('createHubCookieOptions()', () => {
  test('creates standard hub cookie options', () => {
    // Arrange
    const options = { ttlSeconds: 60, isSecure: true }

    // Act
    let result, error
    try {
      result = createHubCookieOptions(options)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result).toEqual({
      encoding: 'none',
      ttl: 60000,
      isHttpOnly: true,
      isSecure: true,
      isSameSite: 'Lax',
      clearInvalid: true,
      path: '/'
    })
  })
})
