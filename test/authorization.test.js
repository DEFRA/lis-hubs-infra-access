import { expect, test } from 'vitest'

import {
  demandPermission,
  demandRole,
  hasPermission,
  hasRole,
  hydrateAuthorization,
  resolveAuthorization
} from '../src/authorization.js'

function createToolkit() {
  const response = {
    code(statusCode) {
      response.statusCode = statusCode
      return response
    },
    takeover() {
      response.takenOver = true
      return response
    }
  }

  return {
    continue: Symbol('continue'),
    response(payload) {
      response.payload = payload
      return response
    },
    result: response
  }
}

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
    'lis-role-caseworker',
    'lis-role-cattle-write',
    'lis-role-cattle-register-write',
    'lis-role-sheep-write',
    'lis-role-sheep-register-write'
  ])
  expect(authorization.permissions).toEqual([
    'lis-perm-back-office',
    'lis-perm-cattle-read',
    'lis-perm-cattle-register-write',
    'lis-perm-sheep-read',
    'lis-perm-cattle-write',
    'lis-perm-cattle-register-read',
    'lis-perm-sheep-write',
    'lis-perm-sheep-register-read',
    'lis-perm-sheep-register-write'
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

test('permission demand rejects missing permission configuration', () => {
  // Arrange
  // Act
  let noOptionsError
  try {
    demandPermission()
  } catch (e) {
    noOptionsError = e
  }
  let emptyPermissionError
  try {
    demandPermission({ permission: '' })
  } catch (e) {
    emptyPermissionError = e
  }
  let invalidPermissionError
  try {
    demandPermission({ permission: 123 })
  } catch (e) {
    invalidPermissionError = e
  }

  // Assert
  expect(noOptionsError).toBeInstanceOf(Error)
  expect(noOptionsError?.message).toMatch(/requires a permission/)
  expect(emptyPermissionError).toBeInstanceOf(Error)
  expect(emptyPermissionError?.message).toMatch(/requires a permission/)
  expect(invalidPermissionError).toBeInstanceOf(Error)
  expect(invalidPermissionError?.message).toMatch(/requires a permission/)
})

test('role demand rejects missing role configuration', () => {
  // Arrange
  // Act
  let noOptionsError
  try {
    demandRole()
  } catch (e) {
    noOptionsError = e
  }
  let emptyRoleError
  try {
    demandRole({ role: '' })
  } catch (e) {
    emptyRoleError = e
  }
  let invalidRoleError
  try {
    demandRole({ role: 123 })
  } catch (e) {
    invalidRoleError = e
  }

  // Assert
  expect(noOptionsError).toBeInstanceOf(Error)
  expect(noOptionsError?.message).toMatch(/requires a role/)
  expect(emptyRoleError).toBeInstanceOf(Error)
  expect(emptyRoleError?.message).toMatch(/requires a role/)
  expect(invalidRoleError).toBeInstanceOf(Error)
  expect(invalidRoleError?.message).toMatch(/requires a role/)
})

test('permission demand denies a user without the required permission', () => {
  // Arrange
  const h = createToolkit()
  const request = {
    app: { hubAuth: { roles: ['lis-role-reader'] } },
    params: { cph: '10/081/1234' }
  }
  const demand = demandPermission({
    permission: 'lis-perm-cattle-write',
    getCph: ({ params }) => params.cph
  })

  // Act
  const result = demand(request, h)

  // Assert
  expect(result).toBe(h.result)
  expect(h.result.payload).toEqual({ message: 'Permission denied' })
  expect(h.result.statusCode).toBe(403)
  expect(h.result.takenOver).toBe(true)
})

test('role demand denies a user with the role assigned to another CPH', () => {
  // Arrange
  const h = createToolkit()
  const request = {
    app: {
      hubAuth: {
        roleAssignments: [{ role: 'lis-role-cattle-read', cph: '10/081/1234' }]
      }
    },
    params: { cph: '10/081/9999' }
  }
  const demand = demandRole({
    role: 'lis-role-cattle-read',
    getCph: ({ params }) => params.cph
  })

  // Act
  const result = demand(request, h)

  // Assert
  expect(result).toBe(h.result)
  expect(h.result.payload).toEqual({ message: 'Role denied' })
  expect(h.result.statusCode).toBe(403)
  expect(h.result.takenOver).toBe(true)
})

test('permission and role demands continue when requirements are met', () => {
  // Arrange
  const h = createToolkit()
  const request = {
    app: { hubAuth: { roles: ['lis-role-caseworker'] } }
  }

  // Act
  const permissionResult = demandPermission({
    permission: 'lis-perm-cattle-read'
  })(request, h)
  const roleResult = demandRole({ role: 'lis-role-caseworker' })(request, h)

  // Assert
  expect(permissionResult).toBe(h.continue)
  expect(roleResult).toBe(h.continue)
})
