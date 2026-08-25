import { expect, test } from 'vitest'

import { hasPermission } from '../../src/authorization/checks.js'

test('CPH-scoped statements match only their own CPH', () => {
  // Arrange
  const authorization = {
    statements: [{ role: 'lis-role-cattle-read', cphs: ['10/081/1234'] }]
  }

  // Act
  const matchingCphResult = hasPermission(authorization, {
    permission: 'lis-perm-cattle-read',
    cph: '10/081/1234'
  })
  const mismatchedCphResult = hasPermission(authorization, {
    permission: 'lis-perm-cattle-read',
    cph: '10/081/9999'
  })

  // Assert
  expect(matchingCphResult).toBe(true)
  expect(mismatchedCphResult).toBe(false)
})

test('global statements match regardless of the CPH asked about', () => {
  // Arrange
  const authorization = {
    statements: [{ role: 'lis-role-cattle-read', cphs: '*' }]
  }

  // Act
  const withCphResult = hasPermission(authorization, {
    permission: 'lis-perm-cattle-read',
    cph: '10/081/1234'
  })
  const withoutCphResult = hasPermission(authorization, {
    permission: 'lis-perm-cattle-read'
  })

  // Assert
  expect(withCphResult).toBe(true)
  expect(withoutCphResult).toBe(true)
})

test('does not grant an unknown permission', () => {
  // Arrange
  const authorization = {
    statements: [
      { role: 'lis-role-reader', cphs: '*' },
      { role: 'lis-role-cattle-read', cphs: ['10/081/1234'] }
    ]
  }

  // Act
  const hasUnknownPermission = hasPermission(authorization, {
    permission: 'unknown-permission'
  })

  // Assert
  expect(hasUnknownPermission).toBe(false)
})

test('does not grant a scoped permission for a missing or different CPH', () => {
  // Arrange
  const authorization = {
    statements: [{ role: 'lis-role-cattle-read', cphs: ['10/081/1234'] }]
  }

  // Act
  const mismatchedCphResult = hasPermission(authorization, {
    permission: 'lis-perm-cattle-read',
    cph: '10/081/9999'
  })
  const missingCphResult = hasPermission(authorization, {
    permission: 'lis-perm-cattle-read'
  })

  // Assert
  expect(mismatchedCphResult).toBe(false)
  expect(missingCphResult).toBe(false)
})
