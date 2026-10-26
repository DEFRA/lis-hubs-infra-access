/** @import { Request } from '@hapi/hapi' */
import { TextEncoder } from 'node:util'

import { SignJWT, jwtVerify } from 'jose'
import { logger } from '@defra/lis-hubs-infra-core'

import { AUTHORIZATION_VERSION } from '../../authorization/constants.js'

const encoder = new TextEncoder()
const MILLISECONDS_PER_SECOND = 1000
const JWT_EXPIRED_CODE = 'ERR_JWT_EXPIRED'
const AUTHZ_VERSION_UNSUPPORTED_CODE = 'ERR_AUTHZ_VERSION_UNSUPPORTED'
const ROUTINE_FAILURE_CODES = new Set([
  JWT_EXPIRED_CODE,
  AUTHZ_VERSION_UNSUPPORTED_CODE
])

function getHubJwtSecret(secret) {
  return encoder.encode(secret)
}

/**
 * @param {{ ttlSeconds: number }} options
 * @returns {object}
 */
export function getHubJwtCookieOptions({ ttlSeconds }) {
  return {
    encoding: 'none',
    ttl: ttlSeconds * MILLISECONDS_PER_SECOND,
    isHttpOnly: true,
    // Secure is a fixed invariant: the browser always reaches the app over
    // HTTPS (Caddy locally, the CDP edge deployed).
    isSecure: true,
    isSameSite: 'Lax',
    clearInvalid: true,
    path: '/'
  }
}

/**
 * @param {object} user
 * @param {{ secret: string, issuer: string, audience: string, ttlSeconds: number }} options
 * @returns {Promise<string>}
 */
export async function issueHubJwt(
  user,
  { secret, issuer, audience, ttlSeconds }
) {
  return new SignJWT({
    email: user.email ?? '',
    firstName: user.firstName ?? '',
    lastName: user.lastName ?? '',
    statements: Array.isArray(user.statements) ? user.statements : [],
    holdings: Array.isArray(user.holdings) ? user.holdings : [],
    authzVersion: AUTHORIZATION_VERSION,
    serviceId: user.serviceId ?? '',
    loa: user.loa ?? '',
    amr: Array.isArray(user.amr) ? user.amr : []
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(user.sub)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .sign(getHubJwtSecret(secret))
}

/**
 * @param {string} token
 * @param {{ secret: string, issuer: string, audience: string }} options
 * @returns {Promise<object>}
 */
export async function verifyHubJwt(token, { secret, issuer, audience }) {
  const { payload } = await jwtVerify(token, getHubJwtSecret(secret), {
    issuer,
    audience,
    algorithms: ['HS256']
  })

  if (payload.authzVersion !== AUTHORIZATION_VERSION) {
    const error = new Error('Unsupported authorization model version')
    error.code = AUTHZ_VERSION_UNSUPPORTED_CODE
    throw error
  }

  return payload
}

/**
 * @param {Request} request
 * @returns {string | null}
 */
export function getAuthorizationBearerToken(request) {
  const authorizationHeader = request.headers?.authorization

  if (typeof authorizationHeader !== 'string') {
    return null
  }

  const [scheme, token] = authorizationHeader.split(/\s+/)

  return scheme?.toLowerCase() === 'bearer' && token ? token : null
}

/**
 * @param {Request} request
 * @param {{ cookieName: string, secret: string, issuer: string, audience: string }} options
 * @returns {Promise<object | null>}
 */
export async function getHubJwtPayloadFromRequest(
  request,
  { cookieName, secret, issuer, audience }
) {
  const token = request.state?.[cookieName]

  if (!token) {
    return null
  }

  try {
    return await verifyHubJwt(token, { secret, issuer, audience })
  } catch (error) {
    if (!ROUTINE_FAILURE_CODES.has(error?.code)) {
      // error.payload carries the decoded token, so the error is never logged whole
      logger.warn(
        {
          code: error?.code,
          claim: error?.claim,
          reason: error?.reason,
          name: error?.name
        },
        'Hub JWT verification failed'
      )
    }
    return null
  }
}
