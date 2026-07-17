import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildCurrentRequestUrl,
  buildMicrositeReturnUrl,
  createSpokeGuard,
  createSpokeAuthToken,
  getCurrentSpokeAccessMode,
  getHubJwtPayloadFromRequest,
  getHubJwtCookieOptions,
  getHubServiceJwtPayloadFromRequest,
  resolveAccessMode,
  verifyHubJwt
} from './tokens.js'
import { MODULES } from '@livestock/hubs-infra-registry'

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

test('buildCurrentRequestUrl reapplies the forwarded prefix for mounted spokes', () => {
  const url = buildCurrentRequestUrl(
    {
      headers: {
        host: 'localhost:3000',
        'x-forwarded-prefix': '/chicken/move'
      },
      raw: {
        req: {
          url: '/about?step=1'
        }
      },
      path: '/about'
    },
    3206
  )

  assert.equal(
    url.toString(),
    'http://localhost:3000/chicken/move/about?step=1'
  )
})

test('buildMicrositeReturnUrl preserves a proxied deep link as a relative hub path', () => {
  const returnUrl = buildMicrositeReturnUrl(
    {
      headers: {
        host: 'front-office.lis.defra',
        'x-forwarded-proto': 'https',
        'x-forwarded-prefix': '/cattle/register'
      },
      raw: { req: { url: '/check?reference=123' } },
      path: '/check'
    },
    { port: 3201, basePath: '/cattle/register' }
  )

  assert.equal(returnUrl, '/cattle/register/check?reference=123')
})

test('buildMicrositeReturnUrl canonicalizes direct-port access to its public mount path', () => {
  const returnUrl = buildMicrositeReturnUrl(
    {
      headers: { host: 'localhost:3201' },
      raw: { req: { url: '/' } },
      path: '/'
    },
    { port: 3201, basePath: '/cattle/register' }
  )

  assert.equal(returnUrl, '/cattle/register')
})

test('createSpokeAuthToken returns a bearer token value', async () => {
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

  assert.match(bearerToken, /^Bearer\s.+$/)
})

test('createSpokeAuthToken signs a JWT with the expected hub service claims', async () => {
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

  const [, token] = bearerToken.split(' ')
  const payload = await verifyHubJwt(token, jwtConfig)

  assert.equal(payload.sub, 'hub-service')
  assert.equal(payload.taxonomy, 'status')
  assert.equal(payload.spokeId, 'cattle-status')
  assert.equal(payload.actorEmail, 'test.user@example.com')
  assert.deepEqual(payload.actorRoles, ['lis-role-caseworker'])
  assert.deepEqual(payload.actorPermissions, [
    'lis-perm-front-office',
    'lis-perm-cattle-read'
  ])
})

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
  assert.deepEqual(payload.actorPermissions, [
    'lis-perm-front-office',
    'lis-perm-cattle-read'
  ])
})

test('createSpokeGuard hydrates hub auth permissions from hub-service JWTs', async () => {
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
    roles: ['lis-role-caseworker'],
    permissions: ['lis-perm-front-office', 'lis-perm-cattle-read']
  })
})

test('createSpokeGuard supports hub-service authentication on marked user-session routes', async () => {
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
        permissions: ['lis-perm-front-office', 'lis-perm-cattle-read']
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

test('resolveAccessMode returns the most restrictive mode', () => {
  assert.equal(
    resolveAccessMode({
      taxonomyAccessMode: 'public',
      spokeAccessMode: 'user-session'
    }),
    'user-session'
  )
  assert.equal(
    resolveAccessMode({
      taxonomyAccessMode: 'user-session',
      spokeAccessMode: 'hub-service'
    }),
    'hub-service'
  )
  assert.equal(
    resolveAccessMode({
      taxonomyAccessMode: 'hub-service',
      spokeAccessMode: 'public'
    }),
    'hub-service'
  )
})

test('getCurrentSpokeAccessMode resolves the current status spoke to hub-service', () => {
  assert.equal(getCurrentSpokeAccessMode('cattle-status'), 'hub-service')
  assert.equal(getCurrentSpokeAccessMode('cattle-move'), 'user-session')
})

test('createSpokeGuard returns a hub-service guard for status spokes', () => {
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

  assert.equal(guard.plugin.name, 'hubServiceGuard')
})

test('createSpokeGuard returns a user-session guard for move spokes', () => {
  const guard = createSpokeGuard({
    spokeId: 'cattle-move',
    hubOrigin: 'http://localhost:3000',
    cookieName: 'livestock_hub_jwt',
    cookieOptions: getHubJwtCookieOptions({
      ttlSeconds: jwtConfig.ttlSeconds,
      isSecure: false
    }),
    assetPath: '/public',
    port: 3204,
    secret: jwtConfig.secret,
    issuer: jwtConfig.issuer,
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
