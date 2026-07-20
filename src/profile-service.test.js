import assert from 'node:assert/strict'
import test from 'node:test'

import { createProfileService } from './profile-service.js'

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
