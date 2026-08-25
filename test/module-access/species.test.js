import { expect, test } from 'vitest'

import { getAuthorizedSpecies } from '../../src/module-access/species.js'

test('supports species codes and ignores malformed permissions', () => {
  // Arrange
  const mixedSpeciesUser = {
    permissions: ['lis-perm-ctt-read', 'lis-perm-sheep-move-write']
  }
  const invalidUser = { permissions: 'invalid' }

  // Act
  const authorizedSpecies = getAuthorizedSpecies(mixedSpeciesUser)
  const invalidSpecies = getAuthorizedSpecies(invalidUser)

  // Assert
  expect(authorizedSpecies.map(({ id }) => id)).toEqual(['cattle', 'sheep'])
  expect(invalidSpecies).toEqual([])
})
