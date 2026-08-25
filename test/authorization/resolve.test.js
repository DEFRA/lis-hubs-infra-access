import { expect, test } from 'vitest'

import { resolveAuthorization } from '../../src/authorization/resolve.js'

test('unknown source roles receive only the default reader role', () => {
  // Arrange
  const options = { source: 'entra', sourceRoles: ['unknown-role'] }

  // Act
  const result = resolveAuthorization(options)

  // Assert
  expect(result).toEqual({
    authzVersion: 1,
    statements: [{ role: 'lis-role-reader', cphs: '*' }],
    holdings: []
  })
})

test('preserves LIS roles already translated by the identity provider', () => {
  // Arrange
  const options = {
    source: 'entra',
    sourceRoles: ['lis-role-back-office']
  }

  // Act
  const result = resolveAuthorization(options)

  // Assert
  expect(result).toEqual({
    authzVersion: 1,
    statements: [
      { role: 'lis-role-reader', cphs: '*' },
      { role: 'lis-role-back-office', cphs: '*' }
    ],
    holdings: []
  })
})

test('Entra roles are translated to a single bundled internal role', () => {
  // Arrange
  const options = {
    source: 'entra',
    sourceRoles: ['bcms_user']
  }

  // Act
  const authorization = resolveAuthorization(options)

  // Assert
  expect(authorization.statements).toEqual([
    { role: 'lis-role-reader', cphs: '*' },
    { role: 'lis-role-bcms-user', cphs: '*' }
  ])
})

test('profile role assignments retain their CPH scope', () => {
  // Arrange
  const options = {
    source: 'profile',
    roleAssignments: [{ role: 'livestockowner', cph: '10/081/1234' }]
  }

  // Act
  const authorization = resolveAuthorization(options)

  // Assert
  expect(authorization.statements).toEqual([
    { role: 'lis-role-reader', cphs: '*' },
    { role: 'lis-role-keeper', cphs: ['10/081/1234'] }
  ])
})

test('groups multiple CPHs for the same role into one statement', () => {
  // Arrange
  const options = {
    source: 'profile',
    roleAssignments: [
      { role: 'cphholder', cph: '10/081/1234' },
      { role: 'cphholder', cph: '10/081/5678' }
    ]
  }

  // Act
  const authorization = resolveAuthorization(options)

  // Assert
  expect(authorization.statements).toEqual([
    { role: 'lis-role-reader', cphs: '*' },
    { role: 'lis-role-keeper', cphs: ['10/081/1234', '10/081/5678'] }
  ])
})

test('uses safe defaults for non-array roles, assignments and holdings', () => {
  // Arrange
  const options = {
    source: 'unknown',
    sourceRoles: 'bcms_user',
    roleAssignments: { role: 'livestockowner', cph: '10/081/1234' },
    holdings: 'not-an-array'
  }

  // Act
  const resolved = resolveAuthorization(options)

  // Assert
  expect(resolved.statements).toEqual([{ role: 'lis-role-reader', cphs: '*' }])
  expect(resolved.holdings).toEqual([])
})
