import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import Wreck from '@hapi/wreck'
import { requestContext } from '@defra/lis-hubs-infra-core'
import { KrdsClient } from '../src/krds-client.js'

vi.mock('@defra/lis-hubs-infra-core')

const mocks = {
  requestContextGet: vi.mocked(requestContext.get)
}

const CLIENT_ID = 'local-dev-krds-client'
const CLIENT_SECRET = 'local-dev-krds-secret'
const credentials = `${CLIENT_ID}:${CLIENT_SECRET}`
const EXPECTED_AUTH_HEADER = `Basic ${Buffer.from(credentials).toString('base64')}`

beforeEach(() => {
  mocks.requestContextGet.mockReturnValue('correlation-1')
})

afterEach(() => {
  vi.restoreAllMocks()
})

test('ensureAccount posts the claims and forwards Basic auth and correlation id', async () => {
  // Arrange
  const krdsClient = new KrdsClient(
    'http://localhost:3000/krds/',
    CLIENT_ID,
    CLIENT_SECRET
  )
  const claims = { sub: 'user-1', email: 'user-1@example.com' }
  const post = vi.spyOn(Wreck, 'post').mockResolvedValue({
    res: { statusCode: 200 },
    payload: { id: 'account-1', subject: 'user-1', email: claims.email }
  })

  // Act
  const account = await krdsClient.ensureAccount(claims)

  // Assert
  expect(post).toHaveBeenCalledTimes(1)
  const [path, options] = post.mock.calls[0]
  expect(path).toBe('api/v2/user-accounts')
  expect(options.baseUrl).toBe('http://localhost:3000/krds/')
  expect(options.payload).toBe(claims)
  expect(options.headers.authorization).toBe(EXPECTED_AUTH_HEADER)
  expect(options.headers['x-correlation-id']).toBe('correlation-1')
  expect(options.headers['x-cdp-request-id']).toBe('correlation-1')
  expect(account).toEqual({
    id: 'account-1',
    subject: 'user-1',
    email: claims.email
  })
})

test('ensureAccount throws using the ProblemDetails payload when Wreck returns a non-2xx response', async () => {
  // Arrange
  const krdsClient = new KrdsClient(
    'http://localhost:3000/krds/',
    CLIENT_ID,
    CLIENT_SECRET
  )
  vi.spyOn(Wreck, 'post').mockResolvedValue({
    res: { statusCode: 409 },
    payload: {
      status: 409,
      title: 'Conflict',
      detail:
        'The supplied email is already associated with a different account.'
    }
  })

  // Act
  let error
  try {
    await krdsClient.ensureAccount({ email: 'taken@example.com' })
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toBe(
    '409 - The supplied email is already associated with a different account.'
  )
})

test('ensureAccount throws a generic validation error for a 422 response', async () => {
  // Arrange
  const krdsClient = new KrdsClient(
    'http://localhost:3000/krds/',
    CLIENT_ID,
    CLIENT_SECRET
  )
  vi.spyOn(Wreck, 'post').mockResolvedValue({
    res: { statusCode: 422 },
    payload: {}
  })

  // Act
  let error
  try {
    await krdsClient.ensureAccount({ email: '' })
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toBe('Validation failed')
})

test('ensureAccount throws when Wreck itself throws', async () => {
  // Arrange
  const krdsClient = new KrdsClient(
    'http://localhost:3000/krds/',
    CLIENT_ID,
    CLIENT_SECRET
  )
  const wreckError = new Error('http error')
  wreckError.output = { statusCode: 503 }
  wreckError.data = { payload: null }
  vi.spyOn(Wreck, 'post').mockRejectedValue(wreckError)

  // Act
  let error
  try {
    await krdsClient.ensureAccount({ email: 'user-1@example.com' })
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toBe('Request failed - 503')
})

test('fetchUserAccount requests the account and forwards Basic auth and correlation id', async () => {
  // Arrange
  const krdsClient = new KrdsClient(
    'http://localhost:3000/krds/',
    CLIENT_ID,
    CLIENT_SECRET
  )
  const get = vi.spyOn(Wreck, 'get').mockResolvedValue({
    res: { statusCode: 200 },
    payload: { id: 'account-1', subject: 'user-1' }
  })

  // Act
  const account = await krdsClient.fetchUserAccount('user-1')

  // Assert
  expect(get).toHaveBeenCalledTimes(1)
  const [path, options] = get.mock.calls[0]
  expect(path).toBe('api/v2/user-accounts/user-1')
  expect(options.baseUrl).toBe('http://localhost:3000/krds/')
  expect(options.headers.authorization).toBe(EXPECTED_AUTH_HEADER)
  expect(account).toEqual({ id: 'account-1', subject: 'user-1' })
})

test('fetchUserAccount percent-encodes the subject', async () => {
  // Arrange
  const krdsClient = new KrdsClient(
    'http://localhost:3000/krds/',
    CLIENT_ID,
    CLIENT_SECRET
  )
  const get = vi.spyOn(Wreck, 'get').mockResolvedValue({
    res: { statusCode: 200 },
    payload: {}
  })

  // Act
  await krdsClient.fetchUserAccount('sub/with slash')

  // Assert
  const [path] = get.mock.calls[0]
  expect(path).toBe('api/v2/user-accounts/sub%2Fwith%20slash')
})

test('fetchUserAccount throws using the ProblemDetails payload when Wreck returns a non-2xx response', async () => {
  // Arrange
  const krdsClient = new KrdsClient(
    'http://localhost:3000/krds/',
    CLIENT_ID,
    CLIENT_SECRET
  )
  vi.spyOn(Wreck, 'get').mockResolvedValue({
    res: { statusCode: 404 },
    payload: {
      status: 404,
      title: 'Not Found',
      detail: 'The subject is not recognised.'
    }
  })

  // Act
  let error
  try {
    await krdsClient.fetchUserAccount('missing-subject')
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toBe('404 - The subject is not recognised.')
})
