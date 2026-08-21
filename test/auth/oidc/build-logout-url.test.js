import { describe, expect, test } from 'vitest'

import { buildLogoutUrl } from '../../../src/auth/oidc/build-logout-url.js'

const metadata = { end_session_endpoint: 'https://identity.example/logout' }

function createRequest(values = new Map()) {
  return {
    yar: {
      get: (key) => values.get(key)
    }
  }
}

describe('buildLogoutUrl()', () => {
  test('builds a logout URL with the id token hint from the session', () => {
    // Arrange
    const request = createRequest(
      new Map([['hub-auth-session', { idToken: 'signed-id-token' }]])
    )

    // Act
    let result, error
    try {
      result = new URL(
        buildLogoutUrl({ metadata, hubOrigin: 'https://hub.example', request })
      )
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result.origin).toBe('https://identity.example')
    expect(result.pathname).toBe('/logout')
    expect(result.searchParams.get('post_logout_redirect_uri')).toBe(
      'https://hub.example'
    )
    expect(result.searchParams.get('id_token_hint')).toBe('signed-id-token')
  })

  test('omits the ID token hint when logging out without a session', () => {
    // Arrange
    const request = createRequest()

    // Act
    let result, error
    try {
      result = new URL(
        buildLogoutUrl({ metadata, hubOrigin: 'https://hub.example', request })
      )
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).not.toBeDefined()
    expect(result.searchParams.has('id_token_hint')).toBe(false)
  })
})
