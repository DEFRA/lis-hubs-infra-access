import { expect, test } from 'vitest'

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
  // Arrange
  const holdings = [
    {
      group_name: 'My farm',
      cphs: [{ cph: '10/081/1234' }]
    }
  ]

  // Act
  const token = await issueHubJwt(
    {
      sub: 'holding-user',
      roles: ['lis-role-front-office'],
      holdings
    },
    jwtConfig
  )
  const payload = await verifyHubJwt(token, jwtConfig)

  // Assert
  expect(payload.holdings).toEqual(holdings)
})

test('buildCurrentRequestUrl reapplies the forwarded prefix for mounted spokes', () => {
  // Arrange
  const request = {
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
  }

  // Act
  const url = buildCurrentRequestUrl(request, 3206)

  // Assert
  expect(url.toString()).toBe('http://localhost:3000/chicken/move/about?step=1')
})

test('buildMicrositeReturnUrl preserves a proxied deep link as a relative hub path', () => {
  // Arrange
  const request = {
    headers: {
      host: 'front-office.lis.defra',
      'x-forwarded-proto': 'https',
      'x-forwarded-prefix': '/cattle/register'
    },
    raw: { req: { url: '/check?reference=123' } },
    path: '/check'
  }
  const options = { port: 3201, basePath: '/cattle/register' }

  // Act
  const returnUrl = buildMicrositeReturnUrl(request, options)

  // Assert
  expect(returnUrl).toBe('/cattle/register/check?reference=123')
})

test('buildMicrositeReturnUrl canonicalizes direct-port access to its public mount path', () => {
  // Arrange
  const request = {
    headers: { host: 'localhost:3201' },
    raw: { req: { url: '/' } },
    path: '/'
  }
  const options = { port: 3201, basePath: '/cattle/register' }

  // Act
  const returnUrl = buildMicrositeReturnUrl(request, options)

  // Assert
  expect(returnUrl).toBe('/cattle/register')
})

test('createSpokeAuthToken returns a bearer token value', async () => {
  // Arrange
  const options = {
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
  }

  // Act
  const bearerToken = await createSpokeAuthToken(options, jwtConfig)

  // Assert
  expect(bearerToken).toMatch(/^Bearer\s.+$/)
})

test('createSpokeAuthToken signs a JWT with the expected hub service claims', async () => {
  // Arrange
  const options = {
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
  }

  // Act
  const bearerToken = await createSpokeAuthToken(options, jwtConfig)
  const [, token] = bearerToken.split(' ')
  const payload = await verifyHubJwt(token, jwtConfig)

  // Assert
  expect(payload.sub).toBe('hub-service')
  expect(payload.taxonomy).toBe('status')
  expect(payload.spokeId).toBe('cattle-status')
  expect(payload.actorEmail).toBe('test.user@example.com')
  expect(payload.actorRoles).toEqual(['lis-role-caseworker'])
  expect('actorPermissions' in payload).toBe(false)
})

test('createSpokeGuard rehydrates permissions from hub-service JWT roles', async () => {
  // Arrange
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

  // Act
  const result = await onPreAuthHandler(request, h)

  // Assert
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

test('createSpokeGuard supports hub-service authentication on marked user-session routes', async () => {
  // Arrange
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

  // Act
  const result = await onPreAuthHandler(request, h)

  // Assert
  expect(result).toBe(h.continue)
  expect(request.app.hubAuth.email).toBe('test.user@example.com')
  expect(request.app.hubAuth.permissions).toEqual([
    'lis-perm-front-office',
    'lis-perm-cattle-read'
  ])
})

test('resolveAccessMode returns the most restrictive mode', () => {
  // Arrange
  // Act
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

  // Assert
  expect(publicVsUserSession).toBe('user-session')
  expect(userSessionVsHubService).toBe('hub-service')
  expect(hubServiceVsPublic).toBe('hub-service')
})

test('createSpokeGuard returns a hub-service guard for status spokes', () => {
  // Arrange
  const options = {
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
  }

  // Act
  const guard = createSpokeGuard(options)

  // Assert
  expect(guard.plugin.name).toBe('hubServiceGuard')
})

test('builds a hub login URL with a sanitized return path', () => {
  // Arrange
  const options = {
    hubOrigin: 'https://hub.example',
    returnUrl: '/cattle/move?step=1'
  }

  // Act
  const url = buildHubLoginUrl(options)

  // Assert
  expect(url).toBe(
    'https://hub.example/auth/login?returnUrl=%2Fcattle%2Fmove%3Fstep%3D1'
  )
})

test('recognizes only known public request paths', () => {
  // Arrange
  const publicPaths = [
    '/favicon.ico',
    '/health',
    '/assets',
    '/assets/app.css',
    '/mounted/assets/app.css'
  ]

  // Act
  const results = publicPaths.map((path) =>
    isPublicRequest({ path }, '/assets')
  )
  const privateResult = isPublicRequest({ path: '/private' }, '/assets')

  // Assert
  for (const result of results) {
    expect(result).toBe(true)
  }
  expect(privateResult).toBe(false)
})

test('uses request defaults when reconstructing direct request URLs', () => {
  // Arrange
  const request = {
    headers: { 'x-forwarded-prefix': 'cattle/home' },
    raw: { req: {} },
    path: '/summary'
  }

  // Act
  const url = buildCurrentRequestUrl(request, 3221)

  // Assert
  expect(url.toString()).toBe('http://localhost:3221/cattle/home/summary')
})

test('service-token verification rejects the wrong subject, taxonomy and spoke', async () => {
  // Arrange
  const userToken = await issueHubJwt({ sub: 'user-1' }, jwtConfig)
  const bearerToken = await createSpokeAuthToken(
    { taxonomyId: 'status', spokeId: 'cattle-status', user: {} },
    jwtConfig
  )
  const token = bearerToken.slice('Bearer '.length)

  // Act
  let subjectError
  try {
    await verifyHubServiceJwt(userToken, {
      ...jwtConfig,
      taxonomyId: 'status',
      spokeId: 'cattle-status'
    })
  } catch (e) {
    subjectError = e
  }
  let taxonomyError
  try {
    await verifyHubServiceJwt(token, {
      ...jwtConfig,
      taxonomyId: 'move',
      spokeId: 'cattle-status'
    })
  } catch (e) {
    taxonomyError = e
  }
  let spokeError
  try {
    await verifyHubServiceJwt(token, {
      ...jwtConfig,
      taxonomyId: 'status',
      spokeId: 'sheep-status'
    })
  } catch (e) {
    spokeError = e
  }

  // Assert
  expect(subjectError).toBeInstanceOf(Error)
  expect(subjectError?.message).toMatch(/Unexpected service token subject/)
  expect(taxonomyError).toBeInstanceOf(Error)
  expect(taxonomyError?.message).toMatch(/Unexpected service token taxonomy/)
  expect(spokeError).toBeInstanceOf(Error)
  expect(spokeError?.message).toMatch(/Unexpected service token spoke/)
})

test('auth guard redirects unauthenticated requests and registers its cookie', async () => {
  // Arrange
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

  // Act
  const result = await handler(request, h)

  // Assert
  expect(result).toBe(h.result)
  expect(stateCalls).toEqual([['hub-jwt', { isSecure: true }]])
  expect(h.result.location).toMatch(
    /^https:\/\/alternate\.example\/auth\/login\?returnUrl=/
  )
  expect(h.result.takenOver).toBe(true)
})

test('hub-service guard denies missing credentials and bypasses public routes', async () => {
  // Arrange
  const guard = createHubServiceGuard({
    assetPath: '/assets',
    taxonomyId: 'status',
    spokeId: 'cattle-status',
    ...jwtConfig
  })
  const handler = registerRequestGuard(guard)
  const h = createGuardToolkit()

  // Act
  const healthResult = await handler(
    { path: '/health', headers: {}, app: {} },
    h
  )
  const privateResult = await handler(
    { path: '/private', headers: {}, app: {} },
    h
  )

  // Assert
  expect(healthResult).toBe(h.continue)
  expect(privateResult).toBe(h.result)
  expect(h.result.payload).toEqual({
    message: 'Hub service authentication required'
  })
  expect(h.result.statusCode).toBe(401)
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
      expect(event).toBe('onPreAuth')
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
