import { expect, test } from 'vitest'

import { hydrateAuthorization } from '../../src/authorization/hydrate.js'
import { hasPermission, hasRole } from '../../src/authorization/checks.js'

test('permissions are rehydrated locally from LIS roles', () => {
  // Arrange
  const authorization = hydrateAuthorization({
    roles: ['lis-role-caseworker']
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

test('rejects unknown roles and malformed authorization input', () => {
  // Arrange
  const options = {
    roles: ['lis-role-caseworker', 'unknown-role', null, 'lis-role-caseworker'],
    roleAssignments: [
      { role: 'lis-role-cattle-read', cph: '10/081/1234' },
      { role: 'unknown-role', cph: '10/081/1234' },
      { role: 'lis-role-cattle-read' },
      null
    ]
  }

  // Act
  const authorization = hydrateAuthorization(options)

  // Assert
  expect(authorization.roles).toEqual(['lis-role-caseworker'])
  expect(authorization.roleAssignments).toEqual([
    { role: 'lis-role-cattle-read', cph: '10/081/1234' }
  ])
  expect(
    authorization.permissionAssignments.some(
      ({ permission }) => permission === 'lis-perm-cattle-read'
    )
  ).toBe(true)
})

test('does not trust supplied permissions without a valid role', () => {
  // Arrange
  const authorization = hydrateAuthorization({
    roles: ['unknown-role'],
    permissions: ['lis-perm-back-office'],
    permissionAssignments: [
      { permission: 'lis-perm-cattle-write', cph: '10/081/1234' }
    ]
  })

  // Act
  const hasBackOfficePermission = hasPermission(authorization, {
    permission: 'lis-perm-back-office'
  })

  // Assert
  expect(authorization.permissions).toEqual([])
  expect(authorization.permissionAssignments).toEqual([])
  expect(hasBackOfficePermission).toBe(false)
})
