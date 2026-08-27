/** @import { Request } from '@hapi/hapi' */
import { TextEncoder } from 'node:util'

import { SignJWT, jwtVerify } from 'jose'

import { AUTHORIZATION_VERSION } from '../../authorization/index.js'
import { logInvalidHubServiceJwt, logMissingHubServiceJwt } from '../logging.js'
import { HUB_SERVICE_SUBJECT } from './constants.js'

const encoder = new TextEncoder()
const MILLISECONDS_PER_SECOND = 1000

function getHubJwtSecret(secret) {
  return encoder.encode(secret)
}

/**
 * @param {{ ttlSeconds: number, isSecure: boolean }} options
 * @returns {object}
 */
export function getHubJwtCookieOptions({ ttlSeconds, isSecure }) {
  return {
    encoding: 'none',
    ttl: ttlSeconds * MILLISECONDS_PER_SECOND,
    isHttpOnly: true,
    isSecure,
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
 * @param {{ taxonomyId: string, spokeId: string, user: object }} subject
 * @param {{ secret: string, issuer: string, audience: string, ttlSeconds: number }} options
 * @returns {Promise<string>}
 */
export async function createSpokeAuthToken(
  { taxonomyId, spokeId, user },
  { secret, issuer, audience, ttlSeconds }
) {
  const token = await new SignJWT({
    taxonomy: taxonomyId,
    spokeId,
    actorSub: user?.sub ?? '',
    actorEmail: user?.email ?? '',
    actorFirstName: user?.firstName ?? '',
    actorLastName: user?.lastName ?? '',
    actorStatements: Array.isArray(user?.statements) ? user.statements : [],
    authzVersion: AUTHORIZATION_VERSION
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(HUB_SERVICE_SUBJECT)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .sign(getHubJwtSecret(secret))

  return `Bearer ${token}`
}

/**
 * @param {string} token
 * @param {{ secret: string, issuer: string, audience: string }} options
 * @returns {Promise<object>}
 */
export async function verifyHubJwt(token, { secret, issuer, audience }) {
  const { payload } = await jwtVerify(token, getHubJwtSecret(secret), {
    issuer,
    audience
  })

  if (payload.authzVersion !== AUTHORIZATION_VERSION) {
    throw new Error('Unsupported authorization model version')
  }

  return payload
}

/**
 * @param {string} token
 * @param {{ secret: string, issuer: string, audience: string, taxonomyId: string, spokeId: string }} options
 * @returns {Promise<object>}
 */
export async function verifyHubServiceJwt(
  token,
  { secret, issuer, audience, taxonomyId, spokeId }
) {
  const payload = await verifyHubJwt(token, { secret, issuer, audience })

  if (payload.sub !== HUB_SERVICE_SUBJECT) {
    throw new Error('Unexpected service token subject')
  }

  if (payload.taxonomy !== taxonomyId) {
    throw new Error('Unexpected service token taxonomy')
  }

  if (payload.spokeId !== spokeId) {
    throw new Error('Unexpected service token spoke')
  }

  return payload
}

/**
 * @param {Request} request
 * @returns {string | null}
 */
function getAuthorizationBearerToken(request) {
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
  } catch {
    return null
  }
}

/**
 * @param {Request} request
 * @param {{ secret: string, issuer: string, audience: string, taxonomyId: string, spokeId: string }} options
 * @returns {Promise<object | null>}
 */
export async function getHubServiceJwtPayloadFromRequest(
  request,
  { secret, issuer, audience, taxonomyId, spokeId }
) {
  const token = getAuthorizationBearerToken(request)

  if (!token) {
    logMissingHubServiceJwt(request)
    return null
  }

  try {
    return await verifyHubServiceJwt(token, {
      secret,
      issuer,
      audience,
      taxonomyId,
      spokeId
    })
  } catch (error) {
    logInvalidHubServiceJwt(error)
    return null
  }
}
