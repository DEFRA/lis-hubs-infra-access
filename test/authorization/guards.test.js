import { expect, test } from 'vitest'

import { demandPermission } from '../../src/authorization/guards.js'

function createToolkit() {
  return {
    continue: Symbol('continue')
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
    app: {
      hubAuth: {
        statements: [{ role: 'lis-role-reader', cphs: '*', permissions: [] }]
      }
    },
    params: { cph: '10/081/1234' }
  }
  const demand = demandPermission({
    permission: 'lis-perm-cattle-write',
    getCph: ({ params }) => params.cph
  })

  // Act
  const result = demand(request, h)

  // Assert
  expect(result.isBoom).toBe(true)
  expect(result.output.statusCode).toBe(403)
})

test('permission demand denies a user with the permission granted for another CPH', () => {
  // Arrange
  const h = createToolkit()
  const request = {
    app: {
      hubAuth: {
        statements: [
          {
            role: 'lis-role-cattle-read',
            cphs: ['10/081/1234'],
            permissions: ['lis-perm-cattle-read']
          }
        ]
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
  expect(result.isBoom).toBe(true)
  expect(result.output.statusCode).toBe(403)
})

test('permission demand denies an unauthenticated request', () => {
  // Arrange
  const h = createToolkit()
  const request = { app: { hubAuth: null } }
  const demand = demandPermission({ permission: 'lis-perm-cattle-read' })

  // Act
  const result = demand(request, h)

  // Assert
  expect(result.isBoom).toBe(true)
  expect(result.output.statusCode).toBe(403)
})

test('permission demand continues when the requirement is met', () => {
  // Arrange
  const h = createToolkit()
  const request = {
    app: {
      hubAuth: {
        statements: [
          {
            role: 'lis-role-caseworker',
            cphs: '*',
            permissions: ['lis-perm-cattle-read']
          }
        ]
      }
    }
  }

  // Act
  const permissionResult = demandPermission({
    permission: 'lis-perm-cattle-read'
  })(request, h)

  // Assert
  expect(permissionResult).toBe(h.continue)
})
