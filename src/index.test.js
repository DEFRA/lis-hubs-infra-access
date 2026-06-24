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

  test('Should allow a front-office transaction module for an exact species taxonomy permission', () => {
    expect(
      resolveModuleAccess({
        hubId: 'front-office',
        user: {
          permissions: ['ctt.register']
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

  test('Should deny a front-office transaction module for a manage-only permission', () => {
    expect(
      resolveModuleAccess({
        hubId: 'front-office',
        user: {
          permissions: ['ctt.manage']
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

  test('Should allow a front-office status module for any species-scoped permission', () => {
    expect(
      getModuleCapabilitiesForHub({
        hubId: 'front-office',
        user: {
          permissions: ['ctt.register']
        },
        module: statusCattleModule
      })
    ).toEqual(['view'])
  })

  test('Should give base back-office capabilities for a transactional permission', () => {
    expect(
      getModuleCapabilitiesForHub({
        hubId: 'back-office',
        user: {
          permissions: ['ctt.register']
        },
        module: registerCattleModule
      })
    ).toEqual(['view', 'assist'])
  })

  test('Should elevate back-office transactional capabilities for a manage permission', () => {
    expect(
      resolveModuleAccess({
        hubId: 'back-office',
        user: {
          permissions: ['ctt.manage']
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

  test('Should allow a back-office permissions module for system.user', () => {
    expect(
      resolveModuleAccess({
        hubId: 'back-office',
        user: {
          permissions: ['system.user']
        },
        module: permissionsModule
      })
    ).toEqual({
      visible: true,
      allowed: true,
      reason: null,
      capabilities: ['manage-permissions']
    })
  })

  test('Should deny a module that does not belong to the current hub', () => {
    expect(
      resolveModuleAccess({
        hubId: 'front-office',
        user: {
          permissions: ['system.user']
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
        permissions: ['ctt.register']
      },
      modules: [registerCattleModule, statusCattleModule, permissionsModule]
    })

    expect(modules).toEqual([registerCattleModule, statusCattleModule])
  })
})
