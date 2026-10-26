import { SignJWT } from 'jose'
import { beforeEach, expect, test, vi } from 'vitest'

const { logger } = vi.hoisted(() => ({ logger: { warn: vi.fn() } }))

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger }))

import {
  getAuthorizationBearerToken,
  getHubJwtPayloadFromRequest,
  issueHubJwt,
  verifyHubJwt
} from '../../../src/authentication/tokens/jwt.js'

beforeEach(() => {
  logger.warn.mockClear()
})

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
      statements: [{ role: 'lis-role-front-office', cphs: '*' }],
      holdings
    },
    jwtConfig
  )
  const payload = await verifyHubJwt(token, jwtConfig)

  expect(payload.holdings).toEqual(holdings)
})

test('issueHubJwt preserves optional authorization and assurance claims', async () => {
  const token = await issueHubJwt(
    {
      sub: 'fully-populated-user',
      email: 'user@example.com',
      firstName: 'Test',
      lastName: 'User',
      statements: [{ role: 'lis-role-caseworker', cphs: ['10/081/1234'] }],
      holdings: [],
      serviceId: 'livestock-hub',
      loa: '2',
      amr: ['pwd', 'mfa']
    },
    jwtConfig
  )
  const payload = await verifyHubJwt(token, jwtConfig)

  expect(payload.statements).toEqual([
    { role: 'lis-role-caseworker', cphs: ['10/081/1234'] }
  ])
  expect(payload.serviceId).toBe('livestock-hub')
  expect(payload.loa).toBe('2')
  expect(payload.amr).toEqual(['pwd', 'mfa'])
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

  expect(payload).toBeNull()
})

test('returns null for missing and invalid hub session cookies', async () => {
  const options = {
    cookieName: 'hub-jwt',
    secret: jwtConfig.secret,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience
  }

  expect(await getHubJwtPayloadFromRequest({ state: {} }, options)).toBeNull()
  expect(
    await getHubJwtPayloadFromRequest(
      { state: { 'hub-jwt': 'not-a-jwt' } },
      options
    )
  ).toBeNull()
})

test('expired hub session cookies return null without logging', async () => {
  const token = await issueHubJwt(
    { sub: 'user-1' },
    { ...jwtConfig, ttlSeconds: -60 }
  )

  const payload = await getHubJwtPayloadFromRequest(
    { state: { 'hub-jwt': token } },
    { cookieName: 'hub-jwt', ...jwtConfig }
  )

  expect(payload).toBeNull()
  expect(logger.warn).not.toHaveBeenCalled()
})

test('invalid signature logs a warning without the token', async () => {
  const token = await issueHubJwt({ sub: 'user-1' }, jwtConfig)
  const tampered = `${token.slice(0, -4)}AAAA`

  const payload = await getHubJwtPayloadFromRequest(
    { state: { 'hub-jwt': tampered } },
    { cookieName: 'hub-jwt', ...jwtConfig }
  )

  expect(payload).toBeNull()
  expect(logger.warn).toHaveBeenCalledTimes(1)
  const [logged, message] = logger.warn.mock.calls[0]
  expect(message).toBe('Hub JWT verification failed')
  expect(logged).toHaveProperty('code')
  expect(logged).not.toHaveProperty('payload')
  expect(logged).not.toHaveProperty('err')
  const serialised = JSON.stringify(logger.warn.mock.calls)
  expect(serialised).not.toContain(tampered)
  expect(serialised).not.toContain('user-1')
})

test('authorization version mismatch returns null without logging', async () => {
  const token = await new SignJWT({ authzVersion: -1 })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(jwtConfig.issuer)
    .setAudience(jwtConfig.audience)
    .setExpirationTime('1h')
    .sign(new TextEncoder().encode(jwtConfig.secret))

  const payload = await getHubJwtPayloadFromRequest(
    { state: { 'hub-jwt': token } },
    { cookieName: 'hub-jwt', ...jwtConfig }
  )

  expect(payload).toBeNull()
  expect(logger.warn).not.toHaveBeenCalled()
})

test('getAuthorizationBearerToken returns the token from a bearer header', () => {
  expect(
    getAuthorizationBearerToken({
      headers: { authorization: 'bearer abc.def' }
    })
  ).toBe('abc.def')
})

test('getAuthorizationBearerToken returns null for missing or malformed headers', () => {
  const tokens = [undefined, 'Basic token', 'Bearer', ''].map((authorization) =>
    getAuthorizationBearerToken({ headers: { authorization } })
  )

  expect(tokens).toEqual([null, null, null, null])
})

test('verifyHubJwt rejects a token signed with a different HMAC algorithm', async () => {
  // Arrange
  const token = await new SignJWT({ authzVersion: 1 })
    .setProtectedHeader({ alg: 'HS512' })
    .setIssuer(jwtConfig.issuer)
    .setAudience(jwtConfig.audience)
    .setExpirationTime('1h')
    .sign(new TextEncoder().encode(jwtConfig.secret))

  // Act
  let result, error
  try {
    result = await verifyHubJwt(token, jwtConfig)
  } catch (e) {
    error = e
  }

  // Assert
  expect(result).toBeUndefined()
  expect(error.code).toBe('ERR_JOSE_ALG_NOT_ALLOWED')
})
