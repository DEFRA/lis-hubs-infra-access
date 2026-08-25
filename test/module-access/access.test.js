import { expect, test } from 'vitest'

import { hasModuleAccess } from '../../src/module-access/access.js'

test('hasModuleAccess allows higher levels within the same scope', () => {
  // Arrange
  const user = {
    permissions: ['lis-perm-cattle-move-admin']
  }
  const access = {
    species: 'cattle',
    scope: 'app',
    app: 'move',
    minLevel: 'read'
  }

  // Act
  const result = hasModuleAccess(user, access)

  // Assert
  expect(result).toBe(true)
})

test('hasModuleAccess denies a role without a matching module permission', () => {
  // Arrange
  const user = {
    roles: ['lis-role-back-office'],
    permissions: ['lis-perm-cattle-register-write']
  }
  const access = {
    species: 'sheep',
    scope: 'app',
    app: 'register',
    minLevel: 'read'
  }

  // Act
  const result = hasModuleAccess(user, access)

  // Assert
  expect(result).toBe(false)
})

test('denies malformed, insufficient and mismatched permissions', () => {
  // Arrange
  const access = {
    species: 'cattle',
    scope: 'app',
    app: 'move',
    minLevel: 'write'
  }
  const invalidPermissions = [
    null,
    '',
    'not-a-lis-permission',
    'lis-perm-cattle',
    'lis-perm-cattle-move-owner',
    'lis-perm-cattle-read',
    'lis-perm-sheep-move-write',
    'lis-perm-cattle-death-write',
    'lis-perm-cattle-move-read'
  ]

  // Act
  const results = invalidPermissions.map((permission) =>
    hasModuleAccess({ permissions: [permission] }, access)
  )
  const noPermissionsResult = hasModuleAccess({}, access)
  const emptyAccessResult = hasModuleAccess({ permissions: [] }, {})

  // Assert
  for (const result of results) {
    expect(result).toBe(false)
  }
  expect(noPermissionsResult).toBe(false)
  expect(emptyAccessResult).toBe(false)
})

test('supports user-scoped permissions', () => {
  // Arrange
  const userScopedUser = { permissions: ['LIS-PERM-USER-WRITE'] }
  const userScopedAccess = { scope: 'user', minLevel: 'read' }

  // Act
  const userScopedResult = hasModuleAccess(userScopedUser, userScopedAccess)

  // Assert
  expect(userScopedResult).toBe(true)
})
