import { describe, expect, test } from 'vitest'

import { defaultAuthProvider } from '../../../src/auth/oidc/default-auth-provider.js'

describe('defaultAuthProvider()', () => {
  test('builds a client_secret auth provider around the provider config secret', async () => {
    // Arrange
    const provider = { clientSecret: 'secret' }

    // Act
    let result, error
    try {
      result = defaultAuthProvider(provider)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result.type).toBe('client_secret')
    expect(await result.getCredentials()).toBe('secret')
  })
})
