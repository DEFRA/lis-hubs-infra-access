import { expect, test } from 'vitest'

import { issueHubJwt } from '../../../src/auth/tokens/jwt.js'
import {
  createAuthGuard,
  createHubServiceGuard,
  createSpokeGuard
} from '../../../src/auth/tokens/guards.js'

const jwtConfig = {
  secret: 'test-hub-secret-please-change-1234567890',
  issuer: 'http://localhost:3000',
  audience: 'livestock-spokes',
  ttlSeconds: 3600
}

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

  const result = await handler(request, h)

  expect(result).toBe(h.result)
  expect(stateCalls).toEqual([['hub-jwt', { isSecure: true }]])
  expect(h.result.location).toMatch(
    /^https:\/\/alternate\.example\/auth\/login\?returnUrl=/
  )
  expect(h.result.takenOver).toBe(true)
})

test('auth guard hydrates authenticated requests', async () => {
  const token = await issueHubJwt(
    { sub: 'user-1', roles: ['lis-role-caseworker'] },
    jwtConfig
  )
  const handler = registerRequestGuard(
    createAuthGuard({
      hubOrigins: [jwtConfig.issuer],
      cookieName: 'hub-jwt',
      cookieOptions: { isSecure: false },
      assetPath: '/assets',
      port: 3204,
      basePath: '/cattle/move',
      secret: jwtConfig.secret,
      audience: jwtConfig.audience
    })
  )
  const h = createGuardToolkit()
  const request = {
    path: '/summary',
    headers: { host: 'localhost:3000' },
    raw: { req: { url: '/summary' } },
    state: { 'hub-jwt': token },
    app: {}
  }

  expect(await handler(request, h)).toBe(h.continue)
  expect(request.app.hubAuth.sub).toBe('user-1')
  expect(request.app.hubOrigin).toBe(jwtConfig.issuer)
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

  const healthResult = await handler(
    { path: '/health', headers: {}, app: {} },
    h
  )
  const privateResult = await handler(
    { path: '/private', headers: {}, app: {} },
    h
  )

  expect(healthResult).toBe(h.continue)
  expect(privateResult).toBe(h.result)
  expect(h.result.payload).toEqual({
    message: 'Hub service authentication required'
  })
  expect(h.result.statusCode).toBe(401)
})

function createRouteAwareGuard() {
  return createSpokeGuard({
    spokeId: 'cattle-home',
    hubOrigins: [jwtConfig.issuer],
    cookieName: 'hub-jwt',
    cookieOptions: { isSecure: false },
    assetPath: '/assets',
    port: 3221,
    basePath: '/cattle/home',
    secret: jwtConfig.secret,
    audience: jwtConfig.audience,
    allowHubServiceRoutes: true
  })
}

test('route-aware guard applies user-session behavior to unmarked routes', async () => {
  const handler = registerRequestGuard(createRouteAwareGuard())
  const h = createGuardToolkit()
  const request = {
    path: '/summary',
    route: { settings: { app: {} } },
    headers: { host: 'localhost:3000' },
    raw: { req: { url: '/summary' } },
    state: {},
    app: {}
  }

  expect(await handler(request, h)).toBe(h.result)
  expect(h.result.location).toMatch(/\/auth\/login\?returnUrl=/)
  expect(h.result.takenOver).toBe(true)
})

test('route-aware guard rejects missing credentials on hub-service routes', async () => {
  const handler = registerRequestGuard(createRouteAwareGuard())
  const h = createGuardToolkit()
  const request = {
    path: '/summary',
    route: { settings: { app: { authMode: 'hub-service' } } },
    headers: {},
    app: {}
  }

  expect(await handler(request, h)).toBe(h.result)
  expect(h.result.payload).toEqual({
    message: 'Hub service authentication required'
  })
  expect(h.result.statusCode).toBe(401)
})
