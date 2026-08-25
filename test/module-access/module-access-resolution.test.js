import { expect, test } from 'vitest'

import { resolveModuleAccess } from '../../src/module-access/module-access-resolution.js'

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
