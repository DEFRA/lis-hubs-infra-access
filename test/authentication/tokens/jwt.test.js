import { expect, test } from 'vitest'

import {
  getHubJwtPayloadFromRequest,
  issueHubJwt,
  verifyHubJwt
} from '../../../src/authentication/tokens/jwt.js'

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
