import { expect, test } from 'vitest'

import { createProfileService } from '../src/profile-service.js'

test('createProfileService returns source roles without trusting source permissions', async () => {
  // Arrange
  const fetchUserProfile = createProfileService({
    config: {
      get(path) {
        const values = {
          'profileService.url': 'http://localhost:4000/api/profile',
          'profileService.apiKey': '',
          'profileService.apiKeyHeader': 'x-api-key'
        }

        return values[path]
      }
    },
    fetchImpl: async () => ({
      ok: true,
      async json() {
        return {
          roles: ['lis-role-cattle-editor', 'lis-role-cattle-editor'],
          permissions: [
            'lis-perm-front-office',
            'lis-perm-cattle-write',
            'lis-perm-cattle-write'
          ],
          holdings: ['holding-1']
        }
      }
    })
  })

  // Act
  const profile = await fetchUserProfile({
    sub: 'user-1'
  })

  // Assert
  expect(profile).toEqual({
    roles: ['lis-role-cattle-editor'],
    roleAssignments: [],
    holdings: ['holding-1']
  })
  expect('groups' in profile).toBe(false)
})

test('createProfileService safely handles a missing profile', async () => {
  // Arrange
  const fetchUserProfile = createProfileService({
    config: {
      get(path) {
        return path === 'profileService.url'
          ? 'http://localhost:4000/api/profile'
          : ''
      }
    },
    fetchImpl: async () => ({
      ok: true,
      async json() {
        return null
      }
    })
  })

  // Act
  const profile = await fetchUserProfile({ sub: 'missing-user' })

  // Assert
  expect(profile).toEqual({
    roles: [],
    roleAssignments: [],
    holdings: []
  })
})

test('rejects invalid service construction', () => {
  // Arrange
  // Act
  let noConfigError
  try {
    createProfileService({})
  } catch (e) {
    noConfigError = e
  }
  let noFetchError
  try {
    createProfileService({
      config: {
        get() {
          return null
        }
      },
      fetchImpl: false
    })
  } catch (e) {
    noFetchError = e
  }

  // Assert
  expect(noConfigError).toBeInstanceOf(Error)
  expect(noConfigError?.message).toMatch(
    /requires a config object with a get method/
  )
  expect(noFetchError).toBeInstanceOf(Error)
  expect(noFetchError?.message).toMatch(/requires a fetch implementation/)
})

test('returns an empty profile when the service URL is not configured', async () => {
  // Arrange
  const fetchUserProfile = createProfileService({
    config: { get: () => '' },
    fetchImpl: async () => {
      throw new Error('fetch should not be called')
    }
  })

  // Act
  const profile = await fetchUserProfile({ sub: 'user-1' })

  // Assert
  expect(profile).toEqual({
    roles: [],
    roleAssignments: [],
    holdings: []
  })
})

test('sends user identifiers, bearer token and default API key header', async () => {
  // Arrange
  let request
  const fetchUserProfile = createProfileService({
    config: {
      get(path) {
        const values = {
          'profileService.url': 'http://localhost:4000/profile',
          'profileService.apiKey': 'api-secret'
        }
        return values[path]
      }
    },
    fetchImpl: async (...args) => {
      request = args
      return {
        ok: true,
        json: async () => ({
          roles: ['valid', '', null, 'valid'],
          roleAssignments: 'invalid',
          holdings: 'invalid'
        })
      }
    }
  })

  // Act
  const profile = await fetchUserProfile(
    { sub: 'user/1', email: 'user@example.com' },
    'access-token'
  )

  // Assert
  expect(request[0]).toBe(
    'http://localhost:4000/profile?user_sub=user%2F1&user_email=user%40example.com'
  )
  expect(request[1].headers).toEqual({
    accept: 'application/json',
    'x-api-key': 'api-secret',
    authorization: 'Bearer access-token'
  })
  expect(profile).toEqual({
    roles: ['valid'],
    roleAssignments: [],
    holdings: []
  })
})

test('surfaces unsuccessful profile service responses', async () => {
  // Arrange
  const fetchUserProfile = createProfileService({
    config: {
      get(path) {
        return path === 'profileService.url'
          ? 'http://localhost:4000/profile'
          : ''
      }
    },
    fetchImpl: async () => ({
      ok: false,
      status: 401,
      text: async () => 'Unauthorized'
    })
  })

  // Act
  let result, error
  try {
    result = await fetchUserProfile({})
  } catch (e) {
    error = e
  }

  // Assert
  expect(result).not.toBeDefined()
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toMatch(/request failed with 401: Unauthorized/)
})
