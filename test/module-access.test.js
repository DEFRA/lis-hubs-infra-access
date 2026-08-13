import { expect, test } from 'vitest'

import {
  createModuleAccessGuard,
  getAuthorizedSpecies,
  getAccessibleModulesForHub,
  hasModuleAccess,
  resolveModuleAccess
} from '../src/module-access.js'

test('resolveModuleAccess infers species-scoped access for status modules', () => {
  // Arrange
  const module = {
    path: '/cattle/status',
    taxonomy: 'status'
  }

  // Act
  const result = resolveModuleAccess(module)

  // Assert
  expect(result).toEqual({
    species: 'cattle',
    scope: 'species',
    minLevel: 'read'
  })
})

test('resolveModuleAccess infers app-scoped access for transactional modules', () => {
  // Arrange
  const module = {
    path: '/cattle/move',
    taxonomy: 'move'
  }

  // Act
  const result = resolveModuleAccess(module)

  // Assert
  expect(result).toEqual({
    species: 'cattle',
    scope: 'app',
    app: 'move',
    minLevel: 'read'
  })
})

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

test('hasModuleAccess allows the back-office role across all modules', () => {
  // Arrange
  const user = {
    roles: ['lis-role-back-office'],
    permissions: ['lis-perm-back-office']
  }
  const access = {
    species: 'cattle',
    scope: 'app',
    app: 'register',
    minLevel: 'read'
  }

  // Act
  const result = hasModuleAccess(user, access)

  // Assert
  expect(result).toBe(true)
})

test('getAccessibleModulesForHub filters by portal and module permissions', () => {
  // Arrange
  const options = {
    hubId: 'front-office',
    user: {
      permissions: [
        'lis-perm-front-office',
        'lis-perm-cattle-read',
        'lis-perm-cattle-move-write'
      ]
    },
    modules: [
      {
        id: 'status-cattle',
        path: '/cattle/status',
        taxonomy: 'status',
        hubs: ['front-office', 'back-office']
      },
      {
        id: 'move-cattle',
        path: '/cattle/move',
        taxonomy: 'move',
        hubs: ['front-office', 'back-office']
      },
      {
        id: 'death-cattle',
        path: '/cattle/death',
        taxonomy: 'death',
        hubs: ['front-office', 'back-office']
      }
    ]
  }

  // Act
  const modules = getAccessibleModulesForHub(options)

  // Assert
  expect(modules.map(({ id }) => id)).toEqual(['status-cattle', 'move-cattle'])
})

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
        permissions: ['lis-perm-cattle-register-write']
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
        permissions: ['lis-perm-cattle-read']
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

test('returns no modules without portal access or valid membership', () => {
  // Arrange
  const noHubOptions = { hubId: '', user: {}, modules: [{}] }
  const mismatchedOptions = {
    hubId: 'front-office',
    user: { permissions: ['lis-perm-front-office'] },
    taxonomy: 'move',
    modules: [
      { taxonomy: 'status', hubs: ['front-office'] },
      { taxonomy: 'move', hubs: 'front-office' },
      { taxonomy: 'move', hubs: ['back-office'] }
    ]
  }

  // Act
  const noHubResult = getAccessibleModulesForHub(noHubOptions)
  const mismatchedResult = getAccessibleModulesForHub(mismatchedOptions)

  // Assert
  expect(noHubResult).toEqual([])
  expect(mismatchedResult).toEqual([])
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

test('supports user-scoped permissions and species codes', () => {
  // Arrange
  const userScopedUser = { permissions: ['LIS-PERM-USER-WRITE'] }
  const userScopedAccess = { scope: 'user', minLevel: 'read' }
  const mixedSpeciesUser = {
    permissions: ['lis-perm-ctt-read', 'lis-perm-sheep-move-write']
  }
  const invalidUser = { permissions: 'invalid' }

  // Act
  const userScopedResult = hasModuleAccess(userScopedUser, userScopedAccess)
  const authorizedSpecies = getAuthorizedSpecies(mixedSpeciesUser)
  const invalidSpecies = getAuthorizedSpecies(invalidUser)

  // Assert
  expect(userScopedResult).toBe(true)
  expect(authorizedSpecies.map(({ id }) => id)).toEqual(['cattle', 'sheep'])
  expect(invalidSpecies).toEqual([])
})

test('resolves explicit access and rejects incomplete module metadata', () => {
  // Arrange
  const access = { species: 'cattle', scope: 'species', minLevel: 'read' }

  // Act
  const explicitAccessResult = resolveModuleAccess({ access })
  const noPathResult = resolveModuleAccess({ path: '/', taxonomy: 'status' })
  const noTaxonomyResult = resolveModuleAccess({ path: '/cattle' })
  const nullResult = resolveModuleAccess(null)

  // Assert
  expect(explicitAccessResult).toBe(access)
  expect(noPathResult).toBeNull()
  expect(noTaxonomyResult).toBeNull()
  expect(nullResult).toBeNull()
})

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
