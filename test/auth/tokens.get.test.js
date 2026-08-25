import assert from 'node:assert/strict'
import { test, vi } from 'vitest'

import {
  createSpokeGuard,
  createSpokeAuthToken,
  getCurrentSpokeAccessMode,
  getReturnUrlFromRequest,
  getSpokeAccessMode,
  getSpokeById,
  getHubJwtPayloadFromRequest,
  getHubJwtCookieOptions,
  getHubServiceJwtPayloadFromRequest,
  resolveAccessMode,
  sanitizeReturnUrl
} from '../../src/auth/tokens.js'
import { MODULES } from '@defra/lis-hubs-infra-registry'

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

test('getHubJwtPayloadFromRequest only accepts the hub session cookie', async () => {
  const payload = await getHubJwtPayloadFromRequest(
    {
      headers: {
        authorization: 'Bearer not-used-here'
      },
      state: {}
    },
    {
      cookieName: 'livestock_hub_jwt',
      secret: jwtConfig.secret,
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience
    }
  )

  assert.equal(payload, null)
})

test('getHubServiceJwtPayloadFromRequest accepts bearer tokens for fetch-based requests', async () => {
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

  const payload = await getHubServiceJwtPayloadFromRequest(
    {
      headers: {
        authorization: bearerToken
      }
    },
    {
      secret: jwtConfig.secret,
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience,
      taxonomyId: 'status',
      spokeId: 'cattle-status'
    }
  )

  assert.equal(payload.sub, 'hub-service')
  assert.equal(payload.actorEmail, 'test.user@example.com')
  assert.equal('actorPermissions' in payload, false)
})

test('createSpokeGuard rehydrates permissions from hub-service JWT roles', async () => {
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
        assert.equal(event, 'onPreAuth')
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

  assert.equal(result, h.continue)
  assert.deepEqual(request.app.hubAuth, {
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

test('createSpokeGuard supports hub-service authentication on marked user-session routes', async () => {
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
      assert.equal(cookieName, 'livestock_hub_jwt')
    },
    ext(event, handler) {
      assert.equal(event, 'onPreAuth')
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

  assert.equal(result, h.continue)
  assert.equal(request.app.hubAuth.email, 'test.user@example.com')
  assert.deepEqual(request.app.hubAuth.permissions, [
    'lis-perm-front-office',
    'lis-perm-cattle-read'
  ])
})

test('getCurrentSpokeAccessMode resolves the current status spoke to hub-service', () => {
  assert.equal(getCurrentSpokeAccessMode('cattle-status'), 'hub-service')
  assert.equal(getCurrentSpokeAccessMode('cattle-move'), 'user-session')
})

test('createSpokeGuard returns a hub-service guard for status spokes', () => {
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

  assert.equal(guard.plugin.name, 'hubServiceGuard')
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

  assert.equal(guard.plugin.name, 'authGuard')
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

  assert.deepEqual([...new Set(statusGuards)], ['hubServiceGuard'])
  assert.deepEqual([...new Set(nonStatusGuards)], ['authGuard'])
})

test('sanitizes unsafe return URLs', () => {
  assert.equal(sanitizeReturnUrl(), '/')
  assert.equal(sanitizeReturnUrl('/safe/path'), '/safe/path')
  assert.equal(sanitizeReturnUrl('//evil.example/path'), '/')
  assert.equal(sanitizeReturnUrl('https://evil.example/path'), '/')
  assert.equal(sanitizeReturnUrl('not a URL'), '/')
  assert.equal(
    sanitizeReturnUrl('http://localhost:3000/local'),
    'http://localhost:3000/local'
  )
  assert.equal(
    sanitizeReturnUrl('http://127.0.0.1:3000/local'),
    'http://127.0.0.1:3000/local'
  )
  assert.equal(
    getReturnUrlFromRequest({ query: { returnUrl: '//evil.example' } }),
    '/'
  )
})

test('rejects unknown access modes and defaults unknown spokes', () => {
  assert.throws(
    () => resolveAccessMode({ spokeAccessMode: 'unknown' }),
    /Unknown access mode: unknown/
  )
  assert.equal(getSpokeById('unknown'), null)
  assert.equal(getCurrentSpokeAccessMode('unknown'), 'user-session')
  assert.equal(
    getSpokeAccessMode({ taxonomy: { id: 'unknown' } }),
    'user-session'
  )
  assert.throws(
    () => createSpokeGuard({ spokeId: 'unknown' }),
    /Unable to resolve spoke configuration for unknown/
  )
})

test('returns null for missing and invalid hub session cookies', async () => {
  const options = {
    cookieName: 'hub-jwt',
    secret: jwtConfig.secret,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience
  }

  assert.equal(await getHubJwtPayloadFromRequest({ state: {} }, options), null)
  assert.equal(
    await getHubJwtPayloadFromRequest(
      { state: { 'hub-jwt': 'not-a-jwt' } },
      options
    ),
    null
  )
})

test('rejects malformed bearer headers and invalid service tokens', async () => {
  const options = {
    secret: jwtConfig.secret,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
    taxonomyId: 'status',
    spokeId: 'cattle-status'
  }

  for (const authorization of [undefined, 'Basic token', 'Bearer', '']) {
    assert.equal(
      await getHubServiceJwtPayloadFromRequest(
        { headers: { authorization } },
        options
      ),
      null
    )
  }
  assert.equal(
    await getHubServiceJwtPayloadFromRequest(
      { headers: { authorization: 'Bearer invalid' } },
      options
    ),
    null
  )
})

test('logs safe diagnostics when hub-service authentication fails', async () => {
  const options = {
    secret: jwtConfig.secret,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
    taxonomyId: 'status',
    spokeId: 'cattle-status'
  }
  const missingLogger = { warn: vi.fn() }

  await getHubServiceJwtPayloadFromRequest(
    { headers: {}, logger: missingLogger },
    options
  )

  assert.deepEqual(missingLogger.warn.mock.calls[0], [
    { authorizationHeaderPresent: false },
    'Hub service JWT missing or bearer authorization header is malformed'
  ])

  const invalidLogger = { warn: vi.fn() }
  await getHubServiceJwtPayloadFromRequest(
    {
      headers: { authorization: 'Bearer sensitive-invalid-token' },
      logger: invalidLogger
    },
    options
  )

  const [diagnostics, message] = invalidLogger.warn.mock.calls[0]
  assert.equal(message, 'Hub service JWT validation failed')
  assert.equal(diagnostics.code, 'ERR_JWS_INVALID')
  assert.equal(
    JSON.stringify(diagnostics).includes('sensitive-invalid-token'),
    false
  )
})
