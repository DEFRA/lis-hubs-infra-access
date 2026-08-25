import { expect, test } from 'vitest'

import { demandPermission } from '../../src/authorization/guards.js'

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

test('permission demand denies a user without the required permission', () => {
  // Arrange
  const h = createToolkit()
  const request = {
    app: { hubAuth: { statements: [{ role: 'lis-role-reader', cphs: '*' }] } },
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

test('permission demand denies a user with the permission granted for another CPH', () => {
  // Arrange
  const h = createToolkit()
  const request = {
    app: {
      hubAuth: {
        statements: [{ role: 'lis-role-cattle-read', cphs: ['10/081/1234'] }]
      }
    },
    params: { cph: '10/081/9999' }
  }
  const demand = demandPermission({
    permission: 'lis-perm-cattle-read',
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

test('permission demand continues when the requirement is met', () => {
  // Arrange
  const h = createToolkit()
  const request = {
    app: {
      hubAuth: { statements: [{ role: 'lis-role-caseworker', cphs: '*' }] }
    }
  }

  // Act
  const permissionResult = demandPermission({
    permission: 'lis-perm-cattle-read'
  })(request, h)

  // Assert
  expect(permissionResult).toBe(h.continue)
})
