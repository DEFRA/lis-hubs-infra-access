import { expect, test } from 'vitest'

import { createModuleAccessGuard } from '../../src/module-access/guard.js'

function registerGuardHandler(guard) {
  let handler = null

  guard.plugin.register({
    ext(eventName, registeredHandler) {
      expect(eventName).toBe('onPreAuth')
      handler = registeredHandler
    }
  })

  expect(handler).toBeTruthy()
  return handler
}

function createToolkit() {
  return {
    continue: Symbol('continue'),
    response(payload) {
      return {
        code(statusCode) {
          return {
            takeover() {
              return {
                payload,
                statusCode,
                takeover: true
              }
            }
          }
        }
      }
    }
  }
}

test('createModuleAccessGuard allows authorised requests through', () => {
  // Arrange
  const handler = registerGuardHandler(
    createModuleAccessGuard({
      assetPath: '/assets',
      moduleAccess: {
        species: 'cattle',
        scope: 'app',
        app: 'register',
        minLevel: 'read'
      }
    })
  )
  const h = createToolkit()
  const request = {
    path: '/calf',
    app: {
      hubAuth: {
        statements: [
          {
            role: 'test-role',
            cphs: '*',
            permissions: ['lis-perm-cattle-register-write']
          }
        ]
      }
    }
  }

  // Act
  const response = handler(request, h)

  // Assert
  expect(response).toBe(h.continue)
})

test('createModuleAccessGuard blocks unauthorised requests with 403', () => {
  // Arrange
  const handler = registerGuardHandler(
    createModuleAccessGuard({
      assetPath: '/assets',
      moduleAccess: {
        species: 'cattle',
        scope: 'app',
        app: 'register',
        minLevel: 'read'
      }
    })
  )
  const h = createToolkit()
  const request = {
    path: '/calf',
    app: {
      hubAuth: {
        statements: [
          {
            role: 'test-role',
            cphs: '*',
            permissions: ['lis-perm-cattle-read']
          }
        ]
      }
    }
  }

  // Act
  const response = handler(request, h)

  // Assert
  expect(response).toEqual({
    payload: { message: 'Module access denied' },
    statusCode: 403,
    takeover: true
  })
})

test('rejects a guard without resolvable module access', () => {
  // Arrange
  const options = { assetPath: '/assets', moduleAccess: {} }

  // Act
  let error
  try {
    createModuleAccessGuard(options)
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toMatch(
    /Unable to resolve module access configuration/
  )
})

test('allows public asset and health requests without authorization', () => {
  // Arrange
  const handler = registerGuardHandler(
    createModuleAccessGuard({
      assetPath: '/assets',
      moduleAccess: { scope: 'species', species: 'cattle', minLevel: 'read' }
    })
  )
  const h = createToolkit()

  // Act
  const healthResponse = handler({ path: '/health', app: {} }, h)
  const assetResponse = handler({ path: '/assets/app.css', app: {} }, h)

  // Assert
  expect(healthResponse).toBe(h.continue)
  expect(assetResponse).toBe(h.continue)
})
