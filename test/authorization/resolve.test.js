import { expect, test } from 'vitest'

import { resolveAuthorization } from '../../src/authorization/resolve.js'

test('unknown source roles receive only the default reader role', () => {
  // Arrange
  const options = { source: 'entra', sourceRoles: ['unknown-role'] }

  // Act
  const result = resolveAuthorization(options)

  // Assert
  expect(result).toEqual({
    authzVersion: 1,
    roles: ['lis-role-reader'],
    permissions: [],
    roleAssignments: [],
    permissionAssignments: [],
    holdings: []
  })
})

test('preserves LIS roles already translated by the identity provider', () => {
  // Arrange
  const options = {
    source: 'entra',
    sourceRoles: ['lis-role-back-office']
  }

  // Act
  const result = resolveAuthorization(options)

  // Assert
  expect(result).toEqual({
    authzVersion: 1,
    roles: ['lis-role-reader', 'lis-role-back-office'],
    permissions: ['lis-perm-back-office'],
    roleAssignments: [],
    permissionAssignments: [],
    holdings: []
  })
})

test('Entra roles are translated and expanded to permissions', () => {
  // Arrange
  const options = {
    source: 'entra',
    sourceRoles: ['bcms_user']
  }

  // Act
  const authorization = resolveAuthorization(options)

  // Assert
  expect(authorization.roles).toEqual([
    'lis-role-reader',
    'lis-role-back-office',
    'lis-role-cattle-write',
    'lis-role-cattle-register-write',
    'lis-role-cattle-home-write',
    'lis-role-cattle-death-write',
    'lis-role-cattle-move-write'
  ])
  expect(authorization.permissions).toEqual([
    'lis-perm-back-office',
    'lis-perm-cattle-read',
    'lis-perm-cattle-write',
    'lis-perm-cattle-register-read',
    'lis-perm-cattle-register-write',
    'lis-perm-cattle-home-read',
    'lis-perm-cattle-home-write',
    'lis-perm-cattle-death-read',
    'lis-perm-cattle-death-write',
    'lis-perm-cattle-move-read',
    'lis-perm-cattle-move-write'
  ])
})

test('profile role assignments retain their CPH scope', () => {
  // Arrange
  const options = {
    source: 'profile',
    roleAssignments: [{ role: 'livestockowner', cph: '10/081/1234' }]
  }

  // Act
  const authorization = resolveAuthorization(options)

  // Assert
  expect(
    authorization.roleAssignments.every(
      (assignment) => assignment.cph === '10/081/1234'
    )
  ).toBe(true)
  expect(
    authorization.roleAssignments.some(
      (assignment) => assignment.role === 'lis-role-sheep-read'
    )
  ).toBe(true)
  expect(authorization.roles).toEqual(['lis-role-reader'])
  expect(authorization.permissions).toEqual([])
  expect(
    authorization.permissionAssignments.some(
      (assignment) =>
        assignment.permission === 'lis-perm-sheep-read' &&
        assignment.cph === '10/081/1234'
    )
  ).toBe(true)
})

test('uses safe defaults for non-array roles, assignments and holdings', () => {
  // Arrange
  const options = {
    source: 'unknown',
    sourceRoles: 'bcms_user',
    roleAssignments: { role: 'livestockowner', cph: '10/081/1234' },
    holdings: 'not-an-array'
  }

  // Act
  const resolved = resolveAuthorization(options)

  // Assert
  expect(resolved.roles).toEqual(['lis-role-reader'])
  expect(resolved.permissions).toEqual([])
  expect(resolved.roleAssignments).toEqual([])
  expect(resolved.permissionAssignments).toEqual([])
  expect(resolved.holdings).toEqual([])
})
