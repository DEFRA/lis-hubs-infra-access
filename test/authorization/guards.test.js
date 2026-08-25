import { expect, test } from 'vitest'

import { demandPermission, demandRole } from '../../src/authorization/guards.js'

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
