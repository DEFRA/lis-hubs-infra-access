import { expect, test } from 'vitest'

import { resolveAuthorization } from '../../src/authorization/resolve.js'

test('unknown holding roles receive only the default reader role', () => {
  // Arrange
  const options = {
    source: 'entra',
    holdingRoles: [{ role: 'unknown-role', cph: '*' }]
  }

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
    holdingRoles: [{ role: 'lis-role-back-office', cph: '*' }]
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

test('source roles are translated to a single bundled internal role', () => {
  // Arrange
  const options = {
    source: 'entra',
    holdingRoles: [{ role: 'bcms_user', cph: '*' }]
  }

  // Act
  const authorization = resolveAuthorization(options)

  // Assert
  expect(authorization.statements).toEqual([
    { role: 'lis-role-reader', cphs: '*' },
    { role: 'lis-role-bcms-user', cphs: '*' }
  ])
})

test('CPH-scoped holding roles retain their CPH scope', () => {
  // Arrange
  const options = {
    source: 'profile',
    holdingRoles: [{ role: 'livestockowner', cph: '10/081/1234' }]
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
    holdingRoles: [
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

test('a global grant for a role subsumes CPH-specific grants for the same role', () => {
  // Arrange
  const options = {
    source: 'profile',
    holdingRoles: [
      { role: 'cphholder', cph: '*' },
      { role: 'cphholder', cph: '10/081/1234' }
    ]
  }

  // Act
  const authorization = resolveAuthorization(options)

  // Assert
  expect(authorization.statements).toEqual([
    { role: 'lis-role-reader', cphs: '*' },
    { role: 'lis-role-keeper', cphs: '*' }
  ])
})

test('uses safe defaults for non-array holding roles and holdings', () => {
  // Arrange
  const options = {
    source: 'unknown',
    holdingRoles: { role: 'livestockowner', cph: '10/081/1234' },
    holdings: 'not-an-array'
  }

  // Act
  const resolved = resolveAuthorization(options)

  // Assert
  expect(resolved.statements).toEqual([{ role: 'lis-role-reader', cphs: '*' }])
  expect(resolved.holdings).toEqual([])
})
