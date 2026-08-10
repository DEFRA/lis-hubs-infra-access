import assert from 'node:assert/strict'
import { test } from 'vitest'

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
  assert.deepEqual(
    resolveAuthorization({ source: 'entra', sourceRoles: ['unknown-role'] }),
    {
      authzVersion: 1,
      roles: ['lis-role-reader'],
      permissions: [],
      roleAssignments: [],
      permissionAssignments: [],
      holdings: []
    }
  )
})

test('preserves LIS roles already translated by the identity provider', () => {
  assert.deepEqual(
    resolveAuthorization({
      source: 'entra',
      sourceRoles: ['lis-role-back-office']
    }),
    {
      authzVersion: 1,
      roles: ['lis-role-reader', 'lis-role-back-office'],
      permissions: ['lis-perm-back-office'],
      roleAssignments: [],
      permissionAssignments: [],
      holdings: []
    }
  )
})

test('permissions are rehydrated locally from LIS roles', () => {
  const authorization = hydrateAuthorization({
    roles: ['lis-role-caseworker']
  })

  assert.equal(
    hasPermission(authorization, { permission: 'lis-perm-cattle-read' }),
    true
  )
  assert.equal(hasRole(authorization, { role: 'lis-role-caseworker' }), true)
})

test('CPH-scoped permission demands use scoped role assignments', () => {
  const authorization = {
    roles: ['lis-role-reader'],
    roleAssignments: [
      {
        role: 'lis-role-cattle-read',
        cph: '10/081/1234'
      }
    ]
  }

  assert.equal(
    hasPermission(authorization, {
      permission: 'lis-perm-cattle-read',
      cph: '10/081/1234'
    }),
    true
  )
  assert.equal(
    hasPermission(authorization, {
      permission: 'lis-perm-cattle-read',
      cph: '10/081/9999'
    }),
    false
  )
})

test('Entra roles are translated and expanded to permissions', () => {
  const authorization = resolveAuthorization({
    source: 'entra',
    sourceRoles: ['bcms_user']
  })

  assert.deepEqual(authorization.roles, [
    'lis-role-reader',
    'lis-role-back-office',
    'lis-role-caseworker',
    'lis-role-cattle-write',
    'lis-role-cattle-register-write',
    'lis-role-sheep-write',
    'lis-role-sheep-register-write'
  ])
  assert.deepEqual(authorization.permissions, [
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
  const authorization = resolveAuthorization({
    source: 'profile',
    roleAssignments: [{ role: 'livestockowner', cph: '10/081/1234' }]
  })

  assert.equal(
    authorization.roleAssignments.every(
      (assignment) => assignment.cph === '10/081/1234'
    ),
    true
  )
  assert.equal(
    authorization.roleAssignments.some(
      (assignment) => assignment.role === 'lis-role-sheep-read'
    ),
    true
  )
  assert.deepEqual(authorization.roles, ['lis-role-reader'])
  assert.deepEqual(authorization.permissions, [])
  assert.equal(
    authorization.permissionAssignments.some(
      (assignment) =>
        assignment.permission === 'lis-perm-sheep-read' &&
        assignment.cph === '10/081/1234'
    ),
    true
  )
})

test('rejects unknown roles and malformed authorization input', () => {
  const authorization = hydrateAuthorization({
    roles: ['lis-role-caseworker', 'unknown-role', null, 'lis-role-caseworker'],
    roleAssignments: [
      { role: 'lis-role-cattle-read', cph: '10/081/1234' },
      { role: 'unknown-role', cph: '10/081/1234' },
      { role: 'lis-role-cattle-read' },
      null
    ]
  })

  assert.deepEqual(authorization.roles, ['lis-role-caseworker'])
  assert.deepEqual(authorization.roleAssignments, [
    { role: 'lis-role-cattle-read', cph: '10/081/1234' }
  ])
  assert.equal(
    authorization.permissionAssignments.some(
      ({ permission }) => permission === 'lis-perm-cattle-read'
    ),
    true
  )
})

test('uses safe defaults for non-array roles, assignments and holdings', () => {
  const resolved = resolveAuthorization({
    source: 'unknown',
    sourceRoles: 'bcms_user',
    roleAssignments: { role: 'livestockowner', cph: '10/081/1234' },
    holdings: 'not-an-array'
  })

  assert.deepEqual(resolved.roles, ['lis-role-reader'])
  assert.deepEqual(resolved.permissions, [])
  assert.deepEqual(resolved.roleAssignments, [])
  assert.deepEqual(resolved.permissionAssignments, [])
  assert.deepEqual(resolved.holdings, [])
})

test('does not grant an unknown role or permission', () => {
  const authorization = {
    roles: ['lis-role-reader'],
    roleAssignments: [{ role: 'lis-role-cattle-read', cph: '10/081/1234' }]
  }

  assert.equal(hasRole(authorization, { role: 'unknown-role' }), false)
  assert.equal(
    hasPermission(authorization, { permission: 'unknown-permission' }),
    false
  )
})

test('does not grant a scoped role for a missing or different CPH', () => {
  const authorization = {
    roleAssignments: [{ role: 'lis-role-cattle-read', cph: '10/081/1234' }]
  }

  assert.equal(
    hasRole(authorization, {
      role: 'lis-role-cattle-read',
      cph: '10/081/9999'
    }),
    false
  )
  assert.equal(hasRole(authorization, { role: 'lis-role-cattle-read' }), false)
})

test('does not trust supplied permissions without a valid role', () => {
  const authorization = hydrateAuthorization({
    roles: ['unknown-role'],
    permissions: ['lis-perm-back-office'],
    permissionAssignments: [
      { permission: 'lis-perm-cattle-write', cph: '10/081/1234' }
    ]
  })

  assert.deepEqual(authorization.permissions, [])
  assert.deepEqual(authorization.permissionAssignments, [])
  assert.equal(
    hasPermission(authorization, { permission: 'lis-perm-back-office' }),
    false
  )
})

test('permission demand rejects missing permission configuration', () => {
  assert.throws(() => demandPermission(), /requires a permission/)
  assert.throws(
    () => demandPermission({ permission: '' }),
    /requires a permission/
  )
  assert.throws(
    () => demandPermission({ permission: 123 }),
    /requires a permission/
  )
})

test('role demand rejects missing role configuration', () => {
  assert.throws(() => demandRole(), /requires a role/)
  assert.throws(() => demandRole({ role: '' }), /requires a role/)
  assert.throws(() => demandRole({ role: 123 }), /requires a role/)
})

test('permission demand denies a user without the required permission', () => {
  const h = createToolkit()
  const request = {
    app: { hubAuth: { roles: ['lis-role-reader'] } },
    params: { cph: '10/081/1234' }
  }
  const demand = demandPermission({
    permission: 'lis-perm-cattle-write',
    getCph: ({ params }) => params.cph
  })

  assert.equal(demand(request, h), h.result)
  assert.deepEqual(h.result.payload, { message: 'Permission denied' })
  assert.equal(h.result.statusCode, 403)
  assert.equal(h.result.takenOver, true)
})

test('role demand denies a user with the role assigned to another CPH', () => {
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

  assert.equal(demand(request, h), h.result)
  assert.deepEqual(h.result.payload, { message: 'Role denied' })
  assert.equal(h.result.statusCode, 403)
  assert.equal(h.result.takenOver, true)
})

test('permission and role demands continue when requirements are met', () => {
  const h = createToolkit()
  const request = {
    app: { hubAuth: { roles: ['lis-role-caseworker'] } }
  }

  assert.equal(
    demandPermission({ permission: 'lis-perm-cattle-read' })(request, h),
    h.continue
  )
  assert.equal(
    demandRole({ role: 'lis-role-caseworker' })(request, h),
    h.continue
  )
})
