import assert from 'node:assert/strict'
import test from 'node:test'

import {
  hasPermission,
  hasRole,
  hydrateAuthorization,
  resolveAuthorization
} from './authorization.js'

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
    'lis-role-cattle-write'
  ])
  assert.deepEqual(authorization.permissions, [
    'lis-perm-back-office',
    'lis-perm-cattle-read',
    'lis-perm-sheep-read',
    'lis-perm-cattle-write'
  ])
})

test('profile role assignments retain their CPH scope', () => {
  const authorization = resolveAuthorization({
    source: 'profile',
    roleAssignments: [{ role: 'livestockowner', cph: '10/081/1234' }]
  })

  assert.deepEqual(authorization.roleAssignments, [
    {
      role: 'lis-role-front-office',
      cph: '10/081/1234'
    },
    {
      role: 'lis-role-cattle-read',
      cph: '10/081/1234'
    }
  ])
  assert.deepEqual(authorization.roles, ['lis-role-reader'])
  assert.deepEqual(authorization.permissions, [])
  assert.deepEqual(authorization.permissionAssignments, [
    { permission: 'lis-perm-front-office', cph: '10/081/1234' },
    { permission: 'lis-perm-cattle-read', cph: '10/081/1234' }
  ])
})
