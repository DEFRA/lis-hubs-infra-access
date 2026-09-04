import { expect, test } from 'vitest'

import { MODULES } from '@defra/lis-hubs-infra-registry'

import {
  createSpokeAuthToken,
  getHubJwtCookieOptions
} from '../../../src/auth/tokens/jwt.js'
import { getCurrentSpokeAccessMode } from '../../../src/auth/tokens/access-mode.js'
import { createSpokeGuard } from '../../../src/auth/tokens/guards.js'

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

test('createSpokeGuard supports hub-service authentication on marked user-session routes (hubOrigins array)', async () => {
  const guard = createSpokeGuard({
    spokeId: 'cattle-home',
    hubOrigins: ['http://localhost:3000'],
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3221,
    basePath: '/cattle/home',
    secret: jwtConfig.secret,
    audience: jwtConfig.audience,
    allowHubServiceRoutes: true
  })
  const bearerToken = await createSpokeAuthToken(
    {
      taxonomyId: 'home',
      spokeId: 'cattle-home',
      user: {
        sub: 'test-user',
        email: 'test.user@example.com',
        statements: [
          { role: 'lis-role-front-office', cphs: '*' },
          { role: 'lis-role-cattle-read', cphs: '*' }
        ]
      }
    },
    jwtConfig
  )

  let onPreAuthHandler
  await guard.plugin.register({
    state(cookieName) {
      expect(cookieName).toBe('livestock_hub_jwt')
    },
    ext(event, handler) {
      expect(event).toBe('onPreAuth')
      onPreAuthHandler = handler
    }
  })

  const request = {
    path: '/summary',
    route: { settings: { app: { authMode: 'hub-service' } } },
    headers: { authorization: bearerToken },
    app: {}
  }
  const h = {
    continue: Symbol('continue'),
    response() {
      throw new Error('response should not be called')
    }
  }

  const result = await onPreAuthHandler(request, h)

  expect(result).toBe(h.continue)
  expect(request.app.hubAuth.email).toBe('test.user@example.com')
  expect(
    request.app.hubAuth.statements.flatMap((statement) => statement.permissions)
  ).toEqual(['lis-perm-front-office', 'lis-perm-cattle-read'])
})

test('createSpokeGuard hydrates a minimal actor on a marked hub-service route', async () => {
  const guard = createSpokeGuard({
    spokeId: 'cattle-home',
    hubOrigins: ['http://localhost:3000'],
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3221,
    basePath: '/cattle/home',
    secret: jwtConfig.secret,
    audience: jwtConfig.audience,
    allowHubServiceRoutes: true
  })
  const bearerToken = await createSpokeAuthToken(
    {
      taxonomyId: 'home',
      spokeId: 'cattle-home',
      user: {
        sub: 'test-user',
        email: 'test.user@example.com',
        statements: [
          { role: 'lis-role-front-office', cphs: '*' },
          { role: 'lis-role-cattle-read', cphs: '*' }
        ]
      }
    },
    jwtConfig
  )
  let onPreAuthHandler
  await guard.plugin.register({
    state(cookieName) {
      expect(cookieName).toBe('livestock_hub_jwt')
    },
    ext(event, handler) {
      expect(event).toBe('onPreAuth')
      onPreAuthHandler = handler
    }
  })
  const request = {
    path: '/summary',
    route: { settings: { app: { authMode: 'hub-service' } } },
    headers: { authorization: bearerToken },
    app: {}
  }
  const h = {
    continue: Symbol('continue'),
    response() {
      throw new Error('response should not be called')
    }
  }

  const result = await onPreAuthHandler(request, h)

  expect(result).toBe(h.continue)
  expect(request.app.hubAuth.email).toBe('test.user@example.com')
  expect(
    request.app.hubAuth.statements.flatMap((statement) => statement.permissions)
  ).toEqual(['lis-perm-front-office', 'lis-perm-cattle-read'])
})

test('createSpokeGuard returns a route-aware guard only when enabled', () => {
  const options = {
    spokeId: 'cattle-home',
    hubOrigins: ['http://localhost:3000'],
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3221,
    basePath: '/cattle/home',
    secret: jwtConfig.secret,
    audience: jwtConfig.audience,
    allowHubServiceRoutes: true
  }

  const guard = createSpokeGuard(options)

  expect(guard.plugin.name).toBe('routeAwareAuthGuard')
})

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
    'user-session': 'authGuard',
    'hub-service': 'hubServiceGuard'
  }

  const rows = SPOKES.map((spoke) => ({
    spokeId: spoke.id,
    taxonomyId: spoke.taxonomy.id,
    accessMode: getCurrentSpokeAccessMode(spoke.id),
    guard: guardByAccessMode[getCurrentSpokeAccessMode(spoke.id)]
  }))

  console.table(rows)

  expect(rows).not.toHaveLength(0)
  expect([...new Set(rows.map(({ accessMode }) => accessMode))]).toEqual([
    'user-session'
  ])
  expect([...new Set(rows.map(({ guard }) => guard))]).toEqual(['authGuard'])
})
