/* eslint-disable no-empty-function */
import assert from 'node:assert/strict'
import { test } from 'vitest'

import { createHoldingService } from '../src/holding-service.js'

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

test('rejects invalid service construction', () => {
  assert.throws(
    () => createHoldingService({}),
    /requires a config object with a get method/
  )
  assert.throws(
    () => createHoldingService({ config: { get() {} }, fetchImpl: null }),
    /requires a fetch implementation/
  )
})

test('rejects requests when the holding service URL is not configured', async () => {
  const fetchHolding = createHoldingService({
    config: { get: () => undefined },
    fetchImpl: async () => ({ ok: true })
  })

  await assert.rejects(fetchHolding('12/345/6789'), /is not configured/)
})

test('uses the default API key header and omits it when no key exists', async () => {
  const requests = []
  const fetchHolding = createHoldingService({
    config: {
      get(path) {
        return path === 'holdingService.url'
          ? 'http://localhost:4000/holding'
          : ''
      }
    },
    fetchImpl: async (...args) => {
      requests.push(args)
      return { ok: true, json: async () => ({}) }
    }
  })

  await fetchHolding('holding-1')
  assert.deepEqual(requests[0][1].headers, { accept: 'application/json' })
})

test('surfaces unsuccessful holding service responses', async () => {
  const fetchHolding = createHoldingService({
    config: {
      get(path) {
        return path === 'holdingService.url'
          ? 'http://localhost:4000/holding'
          : ''
      }
    },
    fetchImpl: async () => ({
      ok: false,
      status: 404,
      text: async () => 'Holding not found'
    })
  })

  await assert.rejects(
    fetchHolding('missing'),
    /request failed with 404: Holding not found/
  )
})
