import { afterEach, expect, test, vi } from 'vitest'

const { logger } = vi.hoisted(() => ({ logger: { warn: vi.fn() } }))

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger }))

import {
  logInvalidServiceToken,
  logMissingServiceToken
} from '../../src/authentication/logging.js'

afterEach(() => {
  vi.clearAllMocks()
})

test('logMissingServiceToken reports only whether the header is present', () => {
  // Arrange
  const request = { headers: { authorization: 'Basic sensitive' } }

  // Act
  logMissingServiceToken(request)

  // Assert
  expect(logger.warn).toHaveBeenCalledWith(
    'Service token missing or bearer authorization header is malformed [authorizationHeaderPresent=true]'
  )
})

test('logInvalidServiceToken logs safe diagnostics only', () => {
  // Arrange
  const error = Object.assign(new Error('expired'), { code: 'ERR_EXPIRED' })

  // Act
  logInvalidServiceToken(error)

  // Assert
  expect(logger.warn).toHaveBeenCalledWith(
    'Service token validation failed [code=ERR_EXPIRED | message=expired]'
  )
})
