import assert from 'node:assert/strict'
import { test } from 'vitest'

import {
  buildCurrentRequestUrl,
  buildHubLoginUrl,
  buildMicrositeReturnUrl,
  createAuthGuard,
  createHubServiceGuard,
  createSpokeGuard,
  createSpokeAuthToken,
  getHubJwtCookieOptions,
  issueHubJwt,
  isPublicRequest,
  resolveAccessMode,
  verifyHubServiceJwt,
  verifyHubJwt
} from '../../src/auth/tokens.js'

const jwtConfig = {
  secret: 'test-hub-secret-please-change-1234567890',
  issuer: 'http://localhost:3000',
  audience: 'livestock-spokes',
  ttlSeconds: 3600
}

test('issueHubJwt carries holdings into the spoke session', async () => {
  const holdings = [
    {
      group_name: 'My farm',
      cphs: [{ cph: '10/081/1234' }]
    }
  ]
  const token = await issueHubJwt(
    {
      sub: 'holding-user',
      roles: ['lis-role-front-office'],
      holdings
    },
    jwtConfig
  )

  const payload = await verifyHubJwt(token, jwtConfig)

  assert.deepEqual(payload.holdings, holdings)
})

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
  assert.equal('actorPermissions' in payload, false)
})

test('createSpokeGuard rehydrates permissions from hub-service JWT roles', async () => {
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

test('builds a hub login URL with a sanitized return path', () => {
  assert.equal(
    buildHubLoginUrl({
      hubOrigin: 'https://hub.example',
      returnUrl: '/cattle/move?step=1'
    }),
    'https://hub.example/auth/login?returnUrl=%2Fcattle%2Fmove%3Fstep%3D1'
  )
})

test('recognizes only known public request paths', () => {
  for (const path of [
    '/favicon.ico',
    '/health',
    '/assets',
    '/assets/app.css',
    '/mounted/assets/app.css'
  ]) {
    assert.equal(isPublicRequest({ path }, '/assets'), true)
  }
  assert.equal(isPublicRequest({ path: '/private' }, '/assets'), false)
})

test('uses request defaults when reconstructing direct request URLs', () => {
  const url = buildCurrentRequestUrl(
    {
      headers: { 'x-forwarded-prefix': 'cattle/home' },
      raw: { req: {} },
      path: '/summary'
    },
    3221
  )

  assert.equal(url.toString(), 'http://localhost:3221/cattle/home/summary')
})

test('service-token verification rejects the wrong subject, taxonomy and spoke', async () => {
  const userToken = await issueHubJwt({ sub: 'user-1' }, jwtConfig)
  await assert.rejects(
    verifyHubServiceJwt(userToken, {
      ...jwtConfig,
      taxonomyId: 'status',
      spokeId: 'cattle-status'
    }),
    /Unexpected service token subject/
  )

  const bearerToken = await createSpokeAuthToken(
    { taxonomyId: 'status', spokeId: 'cattle-status', user: {} },
    jwtConfig
  )
  const token = bearerToken.slice('Bearer '.length)
  await assert.rejects(
    verifyHubServiceJwt(token, {
      ...jwtConfig,
      taxonomyId: 'move',
      spokeId: 'cattle-status'
    }),
    /Unexpected service token taxonomy/
  )
  await assert.rejects(
    verifyHubServiceJwt(token, {
      ...jwtConfig,
      taxonomyId: 'status',
      spokeId: 'sheep-status'
    }),
    /Unexpected service token spoke/
  )
})

test('auth guard redirects unauthenticated requests and registers its cookie', async () => {
  const stateCalls = []
  const guard = createAuthGuard({
    hubOrigin: 'https://hub.example',
    hubOrigins: ['https://alternate.example'],
    cookieName: 'hub-jwt',
    cookieOptions: { isSecure: true },
    assetPath: '/assets',
    port: 3204,
    basePath: '/cattle/move',
    ...jwtConfig
  })
  const handler = registerRequestGuard(guard, (name, options) =>
    stateCalls.push([name, options])
  )
  const h = createGuardToolkit()
  const request = {
    path: '/summary',
    headers: { host: 'alternate.example' },
    raw: { req: { url: '/summary' } },
    state: {},
    app: {}
  }

  assert.equal(await handler(request, h), h.result)
  assert.deepEqual(stateCalls, [['hub-jwt', { isSecure: true }]])
  assert.match(
    h.result.location,
    /^https:\/\/alternate\.example\/auth\/login\?returnUrl=/
  )
  assert.equal(h.result.takenOver, true)
})

test('hub-service guard denies missing credentials and bypasses public routes', async () => {
  const guard = createHubServiceGuard({
    assetPath: '/assets',
    taxonomyId: 'status',
    spokeId: 'cattle-status',
    ...jwtConfig
  })
  const handler = registerRequestGuard(guard)
  const h = createGuardToolkit()

  assert.equal(
    await handler({ path: '/health', headers: {}, app: {} }, h),
    h.continue
  )
  assert.equal(
    await handler({ path: '/private', headers: {}, app: {} }, h),
    h.result
  )
  assert.deepEqual(h.result.payload, {
    message: 'Hub service authentication required'
  })
  assert.equal(h.result.statusCode, 401)
})

function registerRequestGuard(
  guard,
  state = () => {
    return null
  }
) {
  let handler
  guard.plugin.register({
    state,
    ext(event, registeredHandler) {
      assert.equal(event, 'onPreAuth')
      handler = registeredHandler
    }
  })
  return handler
}

function createGuardToolkit() {
  const result = {
    code(statusCode) {
      result.statusCode = statusCode
      return result
    },
    takeover() {
      result.takenOver = true
      return result
    }
  }

  return {
    continue: Symbol('continue'),
    result,
    redirect(location) {
      result.location = location
      return result
    },
    response(payload) {
      result.payload = payload
      return result
    }
  }
}
