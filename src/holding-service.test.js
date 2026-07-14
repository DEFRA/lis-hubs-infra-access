import assert from 'node:assert/strict'
import test from 'node:test'

import { createHoldingService } from './holding-service.js'

test('createHoldingService fetches a holding by CPH', async () => {
  let request
  const fetchHoldingProfile = createHoldingService({
    config: {
      get(path) {
        const values = {
          'holdingService.url': 'http://localhost:4000/api/holding',
          'holdingService.apiKey': 'secret',
          'holdingService.apiKeyHeader': 'x-api-key'
        }

        return values[path]
      }
    },
    fetchImpl: async (...args) => {
      request = args
      return {
        ok: true,
        async json() {
          return { ctt: [{ id: 'animal-1' }] }
        }
      }
    }
  })

  const profile = await fetchHoldingProfile('12/345/6789')

  assert.deepEqual(profile, { ctt: [{ id: 'animal-1' }] })
  assert.deepEqual(request, [
    'http://localhost:4000/api/holding?holding=12%2F345%2F6789',
    {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'x-api-key': 'secret'
      }
    }
  ])
})
