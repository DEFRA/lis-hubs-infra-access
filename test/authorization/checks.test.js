import { expect, test } from 'vitest'

import { hasPermission, hasRole } from '../../src/authorization/checks.js'

test('CPH-scoped permission demands use scoped role assignments', () => {
  // Arrange
  const authorization = {
    roles: ['lis-role-reader'],
    roleAssignments: [
      {
        role: 'lis-role-cattle-read',
        cph: '10/081/1234'
      }
    ]
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

test('does not grant an unknown role or permission', () => {
  // Arrange
  const authorization = {
    roles: ['lis-role-reader'],
    roleAssignments: [{ role: 'lis-role-cattle-read', cph: '10/081/1234' }]
  }

  // Act
  const hasUnknownRole = hasRole(authorization, { role: 'unknown-role' })
  const hasUnknownPermission = hasPermission(authorization, {
    permission: 'unknown-permission'
  })

  // Assert
  expect(hasUnknownRole).toBe(false)
  expect(hasUnknownPermission).toBe(false)
})

test('does not grant a scoped role for a missing or different CPH', () => {
  // Arrange
  const authorization = {
    roleAssignments: [{ role: 'lis-role-cattle-read', cph: '10/081/1234' }]
  }

  // Act
  const mismatchedCphResult = hasRole(authorization, {
    role: 'lis-role-cattle-read',
    cph: '10/081/9999'
  })
  const missingCphResult = hasRole(authorization, {
    role: 'lis-role-cattle-read'
  })

  // Assert
  expect(mismatchedCphResult).toBe(false)
  expect(missingCphResult).toBe(false)
})
