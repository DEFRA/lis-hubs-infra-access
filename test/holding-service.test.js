/* eslint-disable no-empty-function */
import { expect, test } from 'vitest'

import { createHoldingService } from '../src/holding-service.js'

test('createHoldingService fetches a holding by CPH', async () => {
  // Arrange
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

  // Act
  const profile = await fetchHoldingProfile('12/345/6789')

  // Assert
  expect(profile).toEqual({ ctt: [{ id: 'animal-1' }] })
  expect(request).toEqual([
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
  // Arrange
  // Act
  let noConfigError
  try {
    createHoldingService({})
  } catch (e) {
    noConfigError = e
  }
  let noFetchError
  try {
    createHoldingService({ config: { get() {} }, fetchImpl: null })
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

test('rejects requests when the holding service URL is not configured', async () => {
  // Arrange
  const fetchHolding = createHoldingService({
    config: { get: () => undefined },
    fetchImpl: async () => ({ ok: true })
  })

  // Act
  let result, error
  try {
    result = await fetchHolding('12/345/6789')
  } catch (e) {
    error = e
  }

  // Assert
  expect(result).not.toBeDefined()
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toMatch(/is not configured/)
})

test('uses the default API key header and omits it when no key exists', async () => {
  // Arrange
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

  // Act
  await fetchHolding('holding-1')

  // Assert
  expect(requests[0][1].headers).toEqual({ accept: 'application/json' })
})

test('surfaces unsuccessful holding service responses', async () => {
  // Arrange
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

  // Act
  let result, error
  try {
    result = await fetchHolding('missing')
  } catch (e) {
    error = e
  }

  // Assert
  expect(result).not.toBeDefined()
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toMatch(/request failed with 404: Holding not found/)
})
