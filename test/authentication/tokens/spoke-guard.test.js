import { expect, test } from 'vitest'

import { MODULES } from '@defra/lis-hubs-infra-registry'

import { getHubJwtCookieOptions } from '../../../src/authentication/tokens/jwt.js'
import { getSpokeAccessMode } from '../../../src/authentication/tokens/access-mode.js'
import { createSpokeGuard } from '../../../src/authentication/tokens/guards.js'

const SPOKES = MODULES.map((module) => ({
  ...module,
  taxonomy: { id: module.taxonomy }
}))

const jwtConfig = {
  secret: 'test-hub-secret-please-change-1234567890',
  issuer: 'http://localhost:3000',
  audience: 'livestock-spokes',
  ttlSeconds: 3600
}

test('createSpokeGuard returns a user-session guard for move spokes', () => {
  const guard = createSpokeGuard({
    spokeId: 'cattle-move',
    hubOrigins: ['http://localhost:3000'],
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3204,
    secret: jwtConfig.secret,
    audience: jwtConfig.audience
  })

  expect(guard.plugin.name).toBe('authGuard')
})

test('rejects an unknown spoke configuration', () => {
  expect(() => createSpokeGuard({ spokeId: 'unknown' })).toThrow(
    /Unable to resolve spoke configuration for unknown/
  )
})

test('all current spokes default to user-session authentication', () => {
  const guardByAccessMode = {
    public: 'none',
    'user-session': 'authGuard'
  }

  const rows = SPOKES.map((spoke) => ({
    spokeId: spoke.id,
    taxonomyId: spoke.taxonomy.id,
    accessMode: getSpokeAccessMode(spoke),
    guard: guardByAccessMode[getSpokeAccessMode(spoke)]
  }))

  console.table(rows)

  expect(rows).not.toHaveLength(0)
  expect([...new Set(rows.map(({ accessMode }) => accessMode))]).toEqual([
    'user-session'
  ])
  expect([...new Set(rows.map(({ guard }) => guard))]).toEqual(['authGuard'])
})
