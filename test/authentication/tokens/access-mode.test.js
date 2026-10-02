import { expect, test } from 'vitest'

import {
  getSpokeAccessMode,
  getSpokeById,
  resolveAccessMode
} from '../../../src/authentication/tokens/access-mode.js'

test('resolveAccessMode returns the most restrictive mode', () => {
  const publicVsUserSession = resolveAccessMode({
    taxonomyAccessMode: 'public',
    spokeAccessMode: 'user-session'
  })

  expect(publicVsUserSession).toBe('user-session')
})

test('resolveAccessMode rejects hub-service as an unknown access mode', () => {
  // Arrange
  let error

  // Act
  try {
    resolveAccessMode({
      taxonomyAccessMode: 'user-session',
      spokeAccessMode: 'hub-service'
    })
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toMatch(/Unknown access mode: hub-service/)
})

test('rejects unknown access modes and defaults unknown spokes', () => {
  expect(() => resolveAccessMode({ spokeAccessMode: 'unknown' })).toThrow(
    /Unknown access mode: unknown/
  )
  expect(getSpokeById('unknown')).toBeNull()
  expect(getSpokeAccessMode({ taxonomy: { id: 'unknown' } })).toBe(
    'user-session'
  )
})
