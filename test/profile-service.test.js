import assert from 'node:assert/strict'
import { test } from 'vitest'

import { createProfileService } from '../src/profile-service.js'

test('createProfileService returns source roles without trusting source permissions', async () => {
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

  const profile = await fetchUserProfile({
    sub: 'user-1'
  })

  assert.deepEqual(profile, {
    roles: ['lis-role-cattle-editor'],
    roleAssignments: [],
    holdings: ['holding-1']
  })
  assert.equal('groups' in profile, false)
})

test('createProfileService safely handles a missing profile', async () => {
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

  assert.deepEqual(await fetchUserProfile({ sub: 'missing-user' }), {
    roles: [],
    roleAssignments: [],
    holdings: []
  })
})

test('rejects invalid service construction', () => {
  assert.throws(
    () => createProfileService({}),
    /requires a config object with a get method/
  )
  assert.throws(
    () =>
      createProfileService({
        config: {
          get() {
            return null
          }
        },
        fetchImpl: false
      }),
    /requires a fetch implementation/
  )
})

test('returns an empty profile when the service URL is not configured', async () => {
  const fetchUserProfile = createProfileService({
    config: { get: () => '' },
    fetchImpl: async () => {
      throw new Error('fetch should not be called')
    }
  })

  assert.deepEqual(await fetchUserProfile({ sub: 'user-1' }), {
    roles: [],
    roleAssignments: [],
    holdings: []
  })
})

test('sends user identifiers, bearer token and default API key header', async () => {
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

  const profile = await fetchUserProfile(
    { sub: 'user/1', email: 'user@example.com' },
    'access-token'
  )

  assert.equal(
    request[0],
    'http://localhost:4000/profile?user_sub=user%2F1&user_email=user%40example.com'
  )
  assert.deepEqual(request[1].headers, {
    accept: 'application/json',
    'x-api-key': 'api-secret',
    authorization: 'Bearer access-token'
  })
  assert.deepEqual(profile, {
    roles: ['valid'],
    roleAssignments: [],
    holdings: []
  })
})

test('surfaces unsuccessful profile service responses', async () => {
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

  await assert.rejects(
    fetchUserProfile({}),
    /request failed with 401: Unauthorized/
  )
})
