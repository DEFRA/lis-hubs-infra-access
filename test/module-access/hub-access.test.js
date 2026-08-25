import { expect, test } from 'vitest'

import { getAccessibleModulesForHub } from '../../src/module-access/hub-access.js'

function userWithPermissions(permissions) {
  return { statements: [{ role: 'test-role', cphs: '*', permissions }] }
}

test('getAccessibleModulesForHub filters by portal and module permissions', () => {
  // Arrange
  const options = {
    hubId: 'front-office',
    user: userWithPermissions([
      'lis-perm-front-office',
      'lis-perm-cattle-read',
      'lis-perm-cattle-move-write'
    ]),
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

test('returns no modules without portal access or valid membership', () => {
  // Arrange
  const noHubOptions = { hubId: '', user: {}, modules: [{}] }
  const mismatchedOptions = {
    hubId: 'front-office',
    user: userWithPermissions(['lis-perm-front-office']),
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
