import assert from 'node:assert/strict'
import { test } from 'vitest'

import {
  buildCurrentRequestUrl,
  createAuthGuard,
  createSpokeGuard,
  issueHubJwt,
  resolveHubOrigin,
  verifyHubJwt
} from '../../src/auth/tokens.js'

const jwtConfig = {
  secret: 'test-hub-secret-please-change-1234567890',
  issuer: 'http://localhost:3000',
  audience: 'livestock-spokes',
  ttlSeconds: 3600
}

test('ignores empty and root forwarded prefixes', () => {
  for (const prefix of ['', '   ', '/']) {
    const url = buildCurrentRequestUrl(
      {
        headers: {
          host: 'hub.example',
          'x-forwarded-proto': 'https',
          'x-forwarded-prefix': prefix
        },
        raw: { req: { url: '/summary' } },
        path: '/summary'
      },
      3221
    )

    assert.equal(url.toString(), 'https://hub.example/summary')
  }
})

test('resolves hub origins from host, referer and configured fallback', () => {
  const hubOrigins = ['https://primary.example', 'https://secondary.example']

  assert.equal(
    resolveHubOrigin(
      {
        headers: {
          'x-forwarded-host': 'secondary.example, proxy.internal'
        }
      },
      hubOrigins
    ),
    'https://secondary.example'
  )
  assert.equal(
    resolveHubOrigin(
      {
        headers: {
          host: 'spoke.internal',
          referer: 'https://secondary.example/cattle'
        }
      },
      hubOrigins
    ),
    'https://secondary.example'
  )
  assert.equal(
    resolveHubOrigin({ headers: { host: 'spoke.internal' } }, hubOrigins),
    'https://primary.example'
  )
})

test('issueHubJwt preserves optional authorization and assurance claims', async () => {
  const token = await issueHubJwt(
    {
      sub: 'fully-populated-user',
      email: 'user@example.com',
      firstName: 'Test',
      lastName: 'User',
      roles: ['lis-role-caseworker'],
      roleAssignments: [{ role: 'lis-role-caseworker', scope: 'cattle' }],
      holdings: [],
      serviceId: 'livestock-hub',
      loa: '2',
      amr: ['pwd', 'mfa']
    },
    jwtConfig
  )
  const payload = await verifyHubJwt(token, jwtConfig)

  assert.deepEqual(payload.roleAssignments, [
    { role: 'lis-role-caseworker', scope: 'cattle' }
  ])
  assert.equal(payload.serviceId, 'livestock-hub')
  assert.equal(payload.loa, '2')
  assert.deepEqual(payload.amr, ['pwd', 'mfa'])
})

test('auth guard hydrates authenticated requests', async () => {
  const token = await issueHubJwt(
    { sub: 'user-1', roles: ['lis-role-caseworker'] },
    jwtConfig
  )
  const handler = registerGuard(
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
  const h = createToolkit()
  const request = {
    path: '/summary',
    headers: { host: 'localhost:3000' },
    raw: { req: { url: '/summary' } },
    state: { 'hub-jwt': token },
    app: {}
  }

  assert.equal(await handler(request, h), h.continue)
  assert.equal(request.app.hubAuth.sub, 'user-1')
  assert.equal(request.app.hubOrigin, jwtConfig.issuer)
})

test('route-aware guard applies user-session behavior to unmarked routes', async () => {
  const handler = registerGuard(createRouteAwareGuard())
  const h = createToolkit()
  const request = {
    path: '/summary',
    route: { settings: { app: {} } },
    headers: { host: 'localhost:3000' },
    raw: { req: { url: '/summary' } },
    state: {},
    app: {}
  }

  assert.equal(await handler(request, h), h.result)
  assert.match(h.result.location, /\/auth\/login\?returnUrl=/)
  assert.equal(h.result.takenOver, true)
})

test('route-aware guard rejects missing credentials on hub-service routes', async () => {
  const handler = registerGuard(createRouteAwareGuard())
  const h = createToolkit()
  const request = {
    path: '/summary',
    route: { settings: { app: { authMode: 'hub-service' } } },
    headers: {},
    app: {}
  }

  assert.equal(await handler(request, h), h.result)
  assert.deepEqual(h.result.payload, {
    message: 'Hub service authentication required'
  })
  assert.equal(h.result.statusCode, 401)
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

function registerGuard(guard) {
  let handler
  guard.plugin.register({
    state() {
      return null
    },
    ext(event, registeredHandler) {
      assert.equal(event, 'onPreAuth')
      handler = registeredHandler
    }
  })
  return handler
}

function createToolkit() {
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
