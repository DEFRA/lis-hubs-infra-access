import { describe, expect, test } from 'vitest'

import {
  getAccessibleModulesForHub,
  getModuleCapabilitiesForHub,
  HUB_ACCESS_REASONS,
  HUB_ACCESS_STATUS,
  resolveModuleAccess
} from './index.js'

const registerCattleModule = {
  id: 'register-cattle',
  label: 'Register for Cattle',
  path: '/cattle/register',
  port: 3201,
  taxonomy: 'register',
  species: 'ctt',
  hubs: ['front-office', 'back-office']
}

const statusCattleModule = {
  id: 'status-cattle',
  label: 'Status for Cattle',
  path: '/cattle/status',
  port: 3210,
  taxonomy: 'status',
  species: 'ctt',
  hubs: ['front-office', 'back-office']
}

const permissionsModule = {
  id: 'permissions-admin',
  label: 'Permissions admin',
  path: '/system/permissions',
  hubs: ['back-office'],
  type: 'permissions'
}

describe('#hubAccess', () => {
  test('Should report the access package as active', () => {
    expect(HUB_ACCESS_STATUS).toBe('active')
  })

  test('Should allow a front-office transaction module for a species-level write permission', () => {
    expect(
      resolveModuleAccess({
        hubId: 'front-office',
        user: {
          permissions: ['lis-perm-front-office', 'lis-perm-cattle-write']
        },
        module: registerCattleModule
      })
    ).toEqual({
      visible: true,
      allowed: true,
      reason: null,
      capabilities: ['create', 'park', 'resume', 'submit', 'view']
    })
  })

  test('Should allow read-only front-office access for an app-specific read permission', () => {
    expect(
      resolveModuleAccess({
        hubId: 'front-office',
        user: {
          permissions: [
            'lis-perm-front-office',
            'lis-perm-cattle-register-read'
          ]
        },
        module: registerCattleModule
      })
    ).toEqual({
      visible: true,
      allowed: true,
      reason: null,
      capabilities: ['view']
    })
  })

  test('Should deny access when the user lacks the current hub portal permission', () => {
    expect(
      resolveModuleAccess({
        hubId: 'front-office',
        user: {
          permissions: ['lis-perm-cattle-write']
        },
        module: registerCattleModule
      })
    ).toEqual({
      visible: false,
      allowed: false,
      reason: HUB_ACCESS_REASONS.missingPermission,
      capabilities: []
    })
  })

  test('Should allow a front-office status module for any app permission on the species', () => {
    expect(
      getModuleCapabilitiesForHub({
        hubId: 'front-office',
        user: {
          permissions: [
            'lis-perm-front-office',
            'lis-perm-cattle-register-read'
          ]
        },
        module: statusCattleModule
      })
    ).toEqual(['view'])
  })

  test('Should give base back-office capabilities for a species-level read permission', () => {
    expect(
      getModuleCapabilitiesForHub({
        hubId: 'back-office',
        user: {
          permissions: ['lis-perm-back-office', 'lis-perm-cattle-read']
        },
        module: registerCattleModule
      })
    ).toEqual(['view'])
  })

  test('Should elevate back-office transactional capabilities for an admin permission', () => {
    expect(
      resolveModuleAccess({
        hubId: 'back-office',
        user: {
          permissions: [
            'lis-perm-back-office',
            'lis-perm-cattle-register-admin'
          ]
        },
        module: registerCattleModule
      })
    ).toEqual({
      visible: true,
      allowed: true,
      reason: null,
      capabilities: ['view', 'assist', 'amend', 'resubmit']
    })
  })

  test('Should allow a back-office permissions module for user-write access', () => {
    expect(
      resolveModuleAccess({
        hubId: 'back-office',
        user: {
          permissions: ['lis-perm-back-office', 'lis-perm-user-write']
        },
        module: permissionsModule
      })
    ).toEqual({
      visible: true,
      allowed: true,
      reason: null,
      capabilities: ['view', 'manage-permissions']
    })
  })

  test('Should deny a module that does not belong to the current hub', () => {
    expect(
      resolveModuleAccess({
        hubId: 'front-office',
        user: {
          permissions: ['lis-perm-front-office', 'lis-perm-user-admin']
        },
        module: permissionsModule
      })
    ).toEqual({
      visible: false,
      allowed: false,
      reason: HUB_ACCESS_REASONS.notInHub,
      capabilities: []
    })
  })

  test('Should return only allowed modules from the convenience module list helper', () => {
    const modules = getAccessibleModulesForHub({
      hubId: 'back-office',
      user: {
        permissions: ['lis-perm-back-office', 'lis-perm-cattle-read']
      },
      modules: [registerCattleModule, statusCattleModule, permissionsModule]
    })

    expect(modules).toEqual([registerCattleModule, statusCattleModule])
  })
})
