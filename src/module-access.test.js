import assert from 'node:assert/strict'
import test from 'node:test'

import {
  createModuleAccessGuard,
  getAccessibleModulesForHub,
  hasModuleAccess,
  resolveModuleAccess
} from './module-access.js'

test('resolveModuleAccess infers species-scoped access for status modules', () => {
  assert.deepEqual(
    resolveModuleAccess({
      path: '/cattle/status',
      taxonomy: 'status'
    }),
    {
      species: 'cattle',
      scope: 'species',
      minLevel: 'read'
    }
  )
})

test('resolveModuleAccess infers app-scoped access for transactional modules', () => {
  assert.deepEqual(
    resolveModuleAccess({
      path: '/cattle/move',
      taxonomy: 'move'
    }),
    {
      species: 'cattle',
      scope: 'app',
      app: 'move',
      minLevel: 'read'
    }
  )
})

test('hasModuleAccess allows higher levels within the same scope', () => {
  assert.equal(
    hasModuleAccess(
      {
        permissions: ['lis-perm-cattle-move-admin']
      },
      {
        species: 'cattle',
        scope: 'app',
        app: 'move',
        minLevel: 'read'
      }
    ),
    true
  )
})

test('hasModuleAccess allows the back-office role across all modules', () => {
  assert.equal(
    hasModuleAccess(
      {
        roles: ['lis-role-back-office'],
        permissions: ['lis-perm-back-office']
      },
      {
        species: 'cattle',
        scope: 'app',
        app: 'register',
        minLevel: 'read'
      }
    ),
    true
  )
})

test('getAccessibleModulesForHub filters by portal and module permissions', () => {
  const modules = getAccessibleModulesForHub({
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
  })

  assert.deepEqual(
    modules.map(({ id }) => id),
    ['status-cattle', 'move-cattle']
  )
})

test('createModuleAccessGuard allows authorised requests through', () => {
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

  const response = handler(
    {
      path: '/calf',
      app: {
        hubAuth: {
          permissions: ['lis-perm-cattle-register-write']
        }
      }
    },
    h
  )

  assert.equal(response, h.continue)
})

test('createModuleAccessGuard blocks unauthorised requests with 403', () => {
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

  const response = handler(
    {
      path: '/calf',
      app: {
        hubAuth: {
          permissions: ['lis-perm-cattle-read']
        }
      }
    },
    h
  )

  assert.deepEqual(response, {
    payload: { message: 'Module access denied' },
    statusCode: 403,
    takeover: true
  })
})

function registerGuardHandler(guard) {
  let handler = null

  guard.plugin.register({
    ext(eventName, registeredHandler) {
      assert.equal(eventName, 'onPreAuth')
      handler = registeredHandler
    }
  })

  assert.ok(handler)
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
