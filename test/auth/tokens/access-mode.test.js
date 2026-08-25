import { expect, test } from 'vitest'

import {
  getCurrentSpokeAccessMode,
  getSpokeAccessMode,
  getSpokeById,
  resolveAccessMode
} from '../../../src/auth/tokens/access-mode.js'

test('resolveAccessMode returns the most restrictive mode', () => {
  const publicVsUserSession = resolveAccessMode({
    taxonomyAccessMode: 'public',
    spokeAccessMode: 'user-session'
  })
  const userSessionVsHubService = resolveAccessMode({
    taxonomyAccessMode: 'user-session',
    spokeAccessMode: 'hub-service'
  })
  const hubServiceVsPublic = resolveAccessMode({
    taxonomyAccessMode: 'hub-service',
    spokeAccessMode: 'public'
  })

  expect(publicVsUserSession).toBe('user-session')
  expect(userSessionVsHubService).toBe('hub-service')
  expect(hubServiceVsPublic).toBe('hub-service')
})

test('getCurrentSpokeAccessMode resolves the current status spoke to hub-service', () => {
  expect(getCurrentSpokeAccessMode('cattle-status')).toBe('hub-service')
  expect(getCurrentSpokeAccessMode('cattle-move')).toBe('user-session')
})

test('rejects unknown access modes and defaults unknown spokes', () => {
  expect(() => resolveAccessMode({ spokeAccessMode: 'unknown' })).toThrow(
    /Unknown access mode: unknown/
  )
  expect(getSpokeById('unknown')).toBeNull()
  expect(getCurrentSpokeAccessMode('unknown')).toBe('user-session')
  expect(getSpokeAccessMode({ taxonomy: { id: 'unknown' } })).toBe(
    'user-session'
  )
})
