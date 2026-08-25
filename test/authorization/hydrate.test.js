import { expect, test } from 'vitest'

import { hydrateAuthorization } from '../../src/authorization/hydrate.js'
import { hasPermission, hasRole } from '../../src/authorization/checks.js'

test('permissions are rehydrated locally from LIS roles', () => {
  // Arrange
  const authorization = hydrateAuthorization({
    statements: [{ role: 'lis-role-caseworker', cphs: '*' }]
  })

  // Act
  const hasReadPermission = hasPermission(authorization, {
    permission: 'lis-perm-cattle-read'
  })
  const hasCaseworkerRole = hasRole(authorization, {
    role: 'lis-role-caseworker'
  })

  // Assert
  expect(hasReadPermission).toBe(true)
  expect(hasCaseworkerRole).toBe(true)
})

test('attaches a permissions array to each statement', () => {
  // Arrange
  const options = {
    statements: [{ role: 'lis-role-cattle-write', cphs: ['10/081/1234'] }]
  }

  // Act
  const authorization = hydrateAuthorization(options)

  // Assert
  expect(authorization.statements).toEqual([
    {
      role: 'lis-role-cattle-write',
      cphs: ['10/081/1234'],
      permissions: ['lis-perm-cattle-read', 'lis-perm-cattle-write']
    }
  ])
})

test('rejects unknown roles and malformed statements', () => {
  // Arrange
  const options = {
    statements: [
      { role: 'lis-role-caseworker', cphs: '*' },
      { role: 'unknown-role', cphs: '*' },
      { role: 'lis-role-cattle-read', cphs: ['10/081/1234'] },
      { role: 'unknown-role', cphs: ['10/081/1234'] },
      { role: 'lis-role-cattle-read', cphs: [] },
      { role: 'lis-role-cattle-read' },
      null
    ]
  }

  // Act
  const authorization = hydrateAuthorization(options)

  // Assert
  expect(authorization.statements).toEqual([
    {
      role: 'lis-role-caseworker',
      cphs: '*',
      permissions: [
        'lis-perm-cattle-read',
        'lis-perm-cattle-register-write',
        'lis-perm-sheep-read'
      ]
    },
    {
      role: 'lis-role-cattle-read',
      cphs: ['10/081/1234'],
      permissions: ['lis-perm-cattle-read']
    }
  ])
})

test('uses safe defaults for a non-array statements value', () => {
  // Arrange
  const authorization = hydrateAuthorization({ statements: 'not-an-array' })

  // Assert
  expect(authorization.statements).toEqual([])
})

test('does not trust an injected permissions array without a valid role', () => {
  // Arrange
  const authorization = hydrateAuthorization({
    statements: [
      {
        role: 'unknown-role',
        cphs: '*',
        permissions: ['lis-perm-back-office']
      }
    ]
  })

  // Act
  const hasBackOfficePermission = hasPermission(authorization, {
    permission: 'lis-perm-back-office'
  })

  // Assert
  expect(authorization.statements).toEqual([])
  expect(hasBackOfficePermission).toBe(false)
})
