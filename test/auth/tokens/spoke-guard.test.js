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

test('createSpokeGuard rehydrates permissions from hub-service JWT roles (hubOrigins array)', async () => {
  const guard = createSpokeGuard({
    spokeId: 'cattle-status',
    hubOrigins: ['http://localhost:3000'],
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3210,
    secret: jwtConfig.secret,
    audience: jwtConfig.audience
  })

  const bearerToken = await createSpokeAuthToken(
    {
      taxonomyId: 'status',
      spokeId: 'cattle-status',
      user: {
        sub: 'test-user',
        email: 'test.user@example.com',
        firstName: 'Test',
        lastName: 'User',
        roles: ['lis-role-caseworker'],
        permissions: ['lis-perm-front-office', 'lis-perm-cattle-read']
      }
    },
    jwtConfig
  )

  let onPreAuthHandler
  await guard.plugin.register(
    {
      ext(event, handler) {
        expect(event).toBe('onPreAuth')
        onPreAuthHandler = handler
      }
    },
    {}
  )

  const request = {
    path: '/',
    headers: {
      authorization: bearerToken
    },
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
  expect(request.app.hubAuth).toEqual({
    sub: 'test-user',
    email: 'test.user@example.com',
    firstName: 'Test',
    lastName: 'User',
    authzVersion: 1,
    roles: ['lis-role-caseworker'],
    permissions: [
      'lis-perm-cattle-read',
      'lis-perm-cattle-register-write',
      'lis-perm-sheep-read'
    ],
    roleAssignments: [],
    permissionAssignments: []
  })
})

test('createSpokeGuard rehydrates permissions from hub-service JWT roles (single hubOrigin)', async () => {
  const guard = createSpokeGuard({
    spokeId: 'cattle-status',
    hubOrigin: 'http://localhost:3000',
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3210,
    secret: jwtConfig.secret,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience
  })
  const bearerToken = await createSpokeAuthToken(
    {
      taxonomyId: 'status',
      spokeId: 'cattle-status',
      user: {
        sub: 'test-user',
        email: 'test.user@example.com',
        firstName: 'Test',
        lastName: 'User',
        roles: ['lis-role-caseworker'],
        permissions: ['lis-perm-front-office', 'lis-perm-cattle-read']
      }
    },
    jwtConfig
  )
  let onPreAuthHandler
  await guard.plugin.register(
    {
      ext(event, handler) {
        expect(event).toBe('onPreAuth')
        onPreAuthHandler = handler
      }
    },
    {}
  )
  const request = {
    path: '/',
    headers: {
      authorization: bearerToken
    },
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
  expect(request.app.hubAuth).toEqual({
    sub: 'test-user',
    email: 'test.user@example.com',
    firstName: 'Test',
    lastName: 'User',
    authzVersion: 1,
    roles: ['lis-role-caseworker'],
    permissions: [
      'lis-perm-cattle-read',
      'lis-perm-cattle-register-write',
      'lis-perm-sheep-read'
    ],
    roleAssignments: [],
    permissionAssignments: []
  })
})

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
        roles: ['lis-role-front-office', 'lis-role-cattle-read']
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
  expect(request.app.hubAuth.permissions).toEqual([
    'lis-perm-front-office',
    'lis-perm-cattle-read'
  ])
})

test('createSpokeGuard supports hub-service authentication on marked user-session routes (single hubOrigin)', async () => {
  const guard = createSpokeGuard({
    spokeId: 'cattle-home',
    hubOrigin: 'http://localhost:3000',
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3221,
    basePath: '/cattle/home',
    secret: jwtConfig.secret,
    issuer: jwtConfig.issuer,
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
        roles: ['lis-role-front-office', 'lis-role-cattle-read']
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
  expect(request.app.hubAuth.permissions).toEqual([
    'lis-perm-front-office',
    'lis-perm-cattle-read'
  ])
})

test('createSpokeGuard returns a hub-service guard for status spokes', () => {
  const options = {
    spokeId: 'cattle-status',
    hubOrigins: ['http://localhost:3000'],
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3210,
    secret: jwtConfig.secret,
    audience: jwtConfig.audience
  }

  const guard = createSpokeGuard(options)

  expect(guard.plugin.name).toBe('hubServiceGuard')
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

test('prints the effective auth guard for each spoke', () => {
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

  const statusGuards = rows
    .filter(({ taxonomyId }) => taxonomyId === 'status')
    .map(({ guard }) => guard)
  const nonStatusGuards = rows
    .filter(({ taxonomyId }) => taxonomyId !== 'status')
    .map(({ guard }) => guard)

  expect([...new Set(statusGuards)]).toEqual(['hubServiceGuard'])
  expect([...new Set(nonStatusGuards)]).toEqual(['authGuard'])
})
