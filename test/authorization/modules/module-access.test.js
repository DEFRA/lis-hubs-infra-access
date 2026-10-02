import { expect, test } from 'vitest'

import {
  hasModuleAccess,
  normalizeModuleAccess
} from '../../../src/authorization/modules/module-access.js'

function userWithPermissions(permissions) {
  return { statements: [{ role: 'test-role', cphs: '*', permissions }] }
}

test('hasModuleAccess allows higher levels within the same scope', () => {
  // Arrange
  const user = userWithPermissions(['lis-perm-cattle-move-admin'])
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
  const user = userWithPermissions(['lis-perm-cattle-register-write'])
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
    hasModuleAccess(userWithPermissions([permission]), access)
  )
  const noPermissionsResult = hasModuleAccess({}, access)
  const emptyAccessResult = hasModuleAccess(userWithPermissions([]), {})

  // Assert
  for (const result of results) {
    expect(result).toBe(false)
  }
  expect(noPermissionsResult).toBe(false)
  expect(emptyAccessResult).toBe(false)
})

test('supports user-scoped permissions', () => {
  // Arrange
  const userScopedUser = userWithPermissions(['LIS-PERM-USER-WRITE'])
  const userScopedAccess = { scope: 'user', minLevel: 'read' }

  // Act
  const userScopedResult = hasModuleAccess(userScopedUser, userScopedAccess)

  // Assert
  expect(userScopedResult).toBe(true)
})

test('normalizeModuleAccess infers species-scoped access for status modules', () => {
  // Arrange
  const module = {
    path: '/cattle/status',
    taxonomy: 'status'
  }

  // Act
  const result = normalizeModuleAccess(module)

  // Assert
  expect(result).toEqual({
    species: 'cattle',
    scope: 'species',
    minLevel: 'read'
  })
})

test('normalizeModuleAccess infers app-scoped access for transactional modules', () => {
  // Arrange
  const module = {
    path: '/cattle/move',
    taxonomy: 'move'
  }

  // Act
  const result = normalizeModuleAccess(module)

  // Assert
  expect(result).toEqual({
    species: 'cattle',
    scope: 'app',
    app: 'move',
    minLevel: 'read'
  })
})

test('resolves explicit access and rejects incomplete module metadata', () => {
  // Arrange
  const access = { species: 'cattle', scope: 'species', minLevel: 'read' }

  // Act
  const explicitAccessResult = normalizeModuleAccess({ access })
  const noPathResult = normalizeModuleAccess({ path: '/', taxonomy: 'status' })
  const noTaxonomyResult = normalizeModuleAccess({ path: '/cattle' })
  const nullResult = normalizeModuleAccess(null)

  // Assert
  expect(explicitAccessResult).toBe(access)
  expect(noPathResult).toBeNull()
  expect(noTaxonomyResult).toBeNull()
  expect(nullResult).toBeNull()
})
