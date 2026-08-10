import assert from 'node:assert/strict'
import { test } from 'vitest'

import {
  createModuleAccessGuard,
  getAuthorizedSpecies,
  getAccessibleModulesForHub,
  hasModuleAccess,
  resolveModuleAccess
} from '../src/module-access.js'

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

test('rejects a guard without resolvable module access', () => {
  assert.throws(
    () => createModuleAccessGuard({ assetPath: '/assets', moduleAccess: {} }),
    /Unable to resolve module access configuration/
  )
})

test('allows public asset and health requests without authorization', () => {
  const handler = registerGuardHandler(
    createModuleAccessGuard({
      assetPath: '/assets',
      moduleAccess: { scope: 'species', species: 'cattle', minLevel: 'read' }
    })
  )
  const h = createToolkit()

  assert.equal(handler({ path: '/health', app: {} }, h), h.continue)
  assert.equal(handler({ path: '/assets/app.css', app: {} }, h), h.continue)
})

test('returns no modules without portal access or valid membership', () => {
  assert.deepEqual(
    getAccessibleModulesForHub({ hubId: '', user: {}, modules: [{}] }),
    []
  )
  assert.deepEqual(
    getAccessibleModulesForHub({
      hubId: 'front-office',
      user: { permissions: ['lis-perm-front-office'] },
      taxonomy: 'move',
      modules: [
        { taxonomy: 'status', hubs: ['front-office'] },
        { taxonomy: 'move', hubs: 'front-office' },
        { taxonomy: 'move', hubs: ['back-office'] }
      ]
    }),
    []
  )
})

test('denies malformed, insufficient and mismatched permissions', () => {
  const access = {
    species: 'cattle',
    scope: 'app',
    app: 'move',
    minLevel: 'write'
  }

  for (const permission of [
    null,
    '',
    'not-a-lis-permission',
    'lis-perm-cattle',
    'lis-perm-cattle-move-owner',
    'lis-perm-cattle-read',
    'lis-perm-sheep-move-write',
    'lis-perm-cattle-death-write',
    'lis-perm-cattle-move-read'
  ]) {
    assert.equal(hasModuleAccess({ permissions: [permission] }, access), false)
  }
  assert.equal(hasModuleAccess({}, access), false)
  assert.equal(hasModuleAccess({ permissions: [] }, {}), false)
})

test('supports user-scoped permissions and species codes', () => {
  assert.equal(
    hasModuleAccess(
      { permissions: ['LIS-PERM-USER-WRITE'] },
      { scope: 'user', minLevel: 'read' }
    ),
    true
  )
  assert.deepEqual(
    getAuthorizedSpecies({
      permissions: ['lis-perm-ctt-read', 'lis-perm-sheep-move-write']
    }).map(({ id }) => id),
    ['cattle', 'sheep']
  )
  assert.deepEqual(getAuthorizedSpecies({ permissions: 'invalid' }), [])
})

test('resolves explicit access and rejects incomplete module metadata', () => {
  const access = { species: 'cattle', scope: 'species', minLevel: 'read' }

  assert.equal(resolveModuleAccess({ access }), access)
  assert.equal(resolveModuleAccess({ path: '/', taxonomy: 'status' }), null)
  assert.equal(resolveModuleAccess({ path: '/cattle' }), null)
  assert.equal(resolveModuleAccess(null), null)
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
