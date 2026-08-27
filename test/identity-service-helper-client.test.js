import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import Wreck from '@hapi/wreck'
import { requestContext } from '@defra/lis-hubs-infra-core'
import { IdentityServiceHelperClient } from '../src/identity-service-helper-client.js'

vi.mock('@defra/lis-hubs-infra-core')

const mocks = {
  requestContextGet: vi.mocked(requestContext.get)
}

beforeEach(() => {
  mocks.requestContextGet.mockReturnValue('correlation-1')
})

afterEach(() => {
  vi.restoreAllMocks()
})

test('fetchUserProfile requests the profile and forwards the api key and correlation id', async () => {
  // Arrange
  const ishClient = new IdentityServiceHelperClient(
    'http://localhost:3000/identity-service-helper/',
    'local-dev-identity-service-helper-key'
  )
  const get = vi.spyOn(Wreck, 'get').mockResolvedValue({
    res: { statusCode: 200 },
    payload: { sub: 'user-1', email: 'user-1@example.com' }
  })

  // Act
  const profile = await ishClient.fetchUserProfile('user-1')

  // Assert
  expect(get).toHaveBeenCalledTimes(1)
  const [path, options] = get.mock.calls[0]
  expect(path).toBe('users/user-1/profile')
  expect(options.baseUrl).toBe('http://localhost:3000/identity-service-helper/')
  expect(options.headers['x-api-key']).toBe(
    'local-dev-identity-service-helper-key'
  )
  expect(options.headers['x-correlation-id']).toBe('correlation-1')
  expect(options.headers['x-cdp-request-id']).toBe('correlation-1')
  expect(profile).toEqual({ sub: 'user-1', email: 'user-1@example.com' })
})

test('fetchUserProfile throws using the response payload when Wreck returns a non-2xx response', async () => {
  // Arrange
  const ishClient = new IdentityServiceHelperClient(
    'http://localhost:3000/identity-service-helper/',
    'local-dev-identity-service-helper-key'
  )
  vi.spyOn(Wreck, 'get').mockResolvedValue({
    res: { statusCode: 404 },
    payload: { error: { code: 'not_found', message: 'User not found' } }
  })

  // Act
  let error
  try {
    await ishClient.fetchUserProfile('missing-user')
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toBe('not_found - User not found')
})

test('fetchUserProfile throws using the ProblemDetails payload when Wreck returns a non-2xx response', async () => {
  // Arrange
  const ishClient = new IdentityServiceHelperClient(
    'http://localhost:3000/identity-service-helper/',
    'local-dev-identity-service-helper-key'
  )
  vi.spyOn(Wreck, 'get').mockResolvedValue({
    res: { statusCode: 404 },
    payload: { status: 404, title: 'Not Found', detail: 'User not found' }
  })

  // Act
  let error
  try {
    await ishClient.fetchUserProfile('missing-user')
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toBe('404 - User not found')
})

test('fetchUserProfile throws a generic validation error for a 422 response', async () => {
  // Arrange
  const ishClient = new IdentityServiceHelperClient(
    'http://localhost:3000/identity-service-helper/',
    'local-dev-identity-service-helper-key'
  )
  vi.spyOn(Wreck, 'get').mockResolvedValue({
    res: { statusCode: 422 },
    payload: { PropertyName: ['must not be empty'] }
  })

  // Act
  let error
  try {
    await ishClient.fetchUserProfile('user-1')
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toBe('Validation failed')
})

test('fetchUserProfile throws when Wreck itself throws', async () => {
  // Arrange
  const ishClient = new IdentityServiceHelperClient(
    'http://localhost:3000/identity-service-helper/',
    'local-dev-identity-service-helper-key'
  )
  const wreckError = new Error('http error')
  wreckError.output = { statusCode: 503 }
  wreckError.data = { payload: null }
  vi.spyOn(Wreck, 'get').mockRejectedValue(wreckError)

  // Act
  let error
  try {
    await ishClient.fetchUserProfile('user-1')
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toBe('Request failed - 503')
})
