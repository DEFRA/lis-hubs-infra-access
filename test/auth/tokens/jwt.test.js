import { afterEach, expect, test, vi } from 'vitest'

const { logger } = vi.hoisted(() => ({
  logger: { warn: vi.fn() }
}))

vi.mock('@defra/lis-hubs-infra-core', () => ({ logger }))

import {
  createSpokeAuthToken,
  getHubJwtPayloadFromRequest,
  getHubServiceJwtPayloadFromRequest,
  issueHubJwt,
  verifyHubJwt,
  verifyHubServiceJwt
} from '../../../src/auth/tokens/jwt.js'

afterEach(() => {
  vi.clearAllMocks()
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

test('createSpokeAuthToken returns a bearer token value', async () => {
  const options = {
    taxonomyId: 'status',
    spokeId: 'cattle-status',
    user: {
      sub: 'test-user',
      email: 'test.user@example.com',
      firstName: 'Test',
      lastName: 'User',
      statements: [{ role: 'lis-role-caseworker', cphs: '*' }]
    }
  }

  const bearerToken = await createSpokeAuthToken(options, jwtConfig)

  expect(bearerToken).toMatch(/^Bearer\s.+$/)
})

test('createSpokeAuthToken signs a JWT with the expected hub service claims', async () => {
  const options = {
    taxonomyId: 'status',
    spokeId: 'cattle-status',
    user: {
      sub: 'test-user',
      email: 'test.user@example.com',
      firstName: 'Test',
      lastName: 'User',
      statements: [{ role: 'lis-role-caseworker', cphs: '*' }]
    }
  }

  const bearerToken = await createSpokeAuthToken(options, jwtConfig)
  const [, token] = bearerToken.split(' ')
  const payload = await verifyHubJwt(token, jwtConfig)

  expect(payload.sub).toBe('hub-service')
  expect(payload.taxonomy).toBe('status')
  expect(payload.spokeId).toBe('cattle-status')
  expect(payload.actorEmail).toBe('test.user@example.com')
  expect(payload.actorStatements).toEqual([
    { role: 'lis-role-caseworker', cphs: '*' }
  ])
  expect('actorPermissions' in payload).toBe(false)
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
        statements: [{ role: 'lis-role-caseworker', cphs: '*' }]
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

  expect(payload.sub).toBe('hub-service')
  expect(payload.actorEmail).toBe('test.user@example.com')
  expect('actorPermissions' in payload).toBe(false)
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
    expect(
      await getHubServiceJwtPayloadFromRequest(
        { headers: { authorization } },
        options
      )
    ).toBeNull()
  }
  expect(
    await getHubServiceJwtPayloadFromRequest(
      { headers: { authorization: 'Bearer invalid' } },
      options
    )
  ).toBeNull()
})

test('logs safe diagnostics when hub-service authentication fails', async () => {
  const options = {
    secret: jwtConfig.secret,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
    taxonomyId: 'status',
    spokeId: 'cattle-status'
  }
  await getHubServiceJwtPayloadFromRequest({ headers: {} }, options)

  expect(logger.warn).toHaveBeenCalledWith(
    'Hub service JWT missing or bearer authorization header is malformed [authorizationHeaderPresent=false]'
  )
  logger.warn.mockClear()

  await getHubServiceJwtPayloadFromRequest(
    { headers: { authorization: 'Bearer sensitive-invalid-token' } },
    options
  )

  const [message] = logger.warn.mock.calls[0]
  expect(message).toMatch(
    /Hub service JWT validation failed \[code=ERR_JWS_INVALID \| message=/
  )
  expect(message).not.toContain('sensitive-invalid-token')
})

test('service-token verification rejects the wrong subject, taxonomy and spoke', async () => {
  const userToken = await issueHubJwt({ sub: 'user-1' }, jwtConfig)
  const bearerToken = await createSpokeAuthToken(
    { taxonomyId: 'status', spokeId: 'cattle-status', user: {} },
    jwtConfig
  )
  const token = bearerToken.slice('Bearer '.length)

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

  expect(subjectError).toBeInstanceOf(Error)
  expect(subjectError?.message).toMatch(/Unexpected service token subject/)
  expect(taxonomyError).toBeInstanceOf(Error)
  expect(taxonomyError?.message).toMatch(/Unexpected service token taxonomy/)
  expect(spokeError).toBeInstanceOf(Error)
  expect(spokeError?.message).toMatch(/Unexpected service token spoke/)
})
