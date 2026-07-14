/** @import { Request } from '@hapi/hapi' */
import { TextEncoder } from 'node:util'

import { SignJWT, jwtVerify } from 'jose'

import { MODULES, TAXONOMIES } from '@livestock/hubs-infra-registry'

const statusCodes = {
  unauthorized: 401
}

const SUPPORTED_TAXONOMIES = TAXONOMIES
const SPOKES = MODULES.map((module) => ({
  ...module,
  taxonomy: {
    id: module.taxonomy
  }
}))

const encoder = new TextEncoder()
const HUB_SERVICE_SUBJECT = 'hub-service'
const MILLISECONDS_PER_SECOND = 1000
const accessModeRanks = {
  public: 0,
  'user-session': 1,
  [HUB_SERVICE_SUBJECT]: 2
}
const defaultAccessMode = 'user-session'

function getHubJwtSecret(secret) {
  return encoder.encode(secret)
}

function normalizeAccessMode(accessMode) {
  const normalizedAccessMode = accessMode ?? defaultAccessMode

  if (!(normalizedAccessMode in accessModeRanks)) {
    throw new Error(`Unknown access mode: ${normalizedAccessMode}`)
  }

  return normalizedAccessMode
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
 * @param {string} value
 * @returns {string}
 */
export function sanitizeReturnUrl(value) {
  if (!value) {
    return '/'
  }

  if (value.startsWith('/') && !value.startsWith('//')) {
    return value
  }

  try {
    const url = new URL(value)

    if (['localhost', '127.0.0.1'].includes(url.hostname)) {
      return url.toString()
    }
  } catch {
    return '/'
  }

  return '/'
}

/**
 * @param {Request} request
 * @returns {string}
 */
export function getReturnUrlFromRequest(request) {
  return sanitizeReturnUrl(request.query?.returnUrl ?? '/')
}

function normalizeForwardedPrefix(prefix) {
  if (typeof prefix !== 'string') {
    return ''
  }

  const trimmedPrefix = prefix.trim()

  if (!trimmedPrefix || trimmedPrefix === '/') {
    return ''
  }

  return trimmedPrefix.startsWith('/') ? trimmedPrefix : `/${trimmedPrefix}`
}

/**
 * @param {Request} request
 * @param {number} port
 * @returns {URL}
 */
export function buildCurrentRequestUrl(request, port) {
  const protocol = request.headers['x-forwarded-proto'] ?? 'http'
  const host = request.headers.host ?? `localhost:${port}`
  const currentUrl = new URL(
    request.raw.req.url ?? request.path,
    `${protocol}://${host}`
  )
  const forwardedPrefix = normalizeForwardedPrefix(
    request.headers['x-forwarded-prefix']
  )

  if (forwardedPrefix) {
    currentUrl.pathname =
      currentUrl.pathname === '/'
        ? forwardedPrefix
        : `${forwardedPrefix}${currentUrl.pathname}`
  }

  return currentUrl
}

export function buildMicrositeReturnUrl(request, { port, basePath = '' }) {
  const currentUrl = buildCurrentRequestUrl(request, port)
  const forwardedPrefix = normalizeForwardedPrefix(
    request.headers['x-forwarded-prefix']
  )
  const normalizedBasePath = normalizeForwardedPrefix(basePath)

  if (normalizedBasePath && !forwardedPrefix) {
    currentUrl.pathname =
      currentUrl.pathname === '/'
        ? normalizedBasePath
        : `${normalizedBasePath}${currentUrl.pathname}`
  }

  return `${currentUrl.pathname}${currentUrl.search}${currentUrl.hash}`
}

/**
 * @param {{ hubOrigin: string, returnUrl: string }} options
 * @returns {string}
 */
export function buildHubLoginUrl({ hubOrigin, returnUrl }) {
  const loginUrl = new URL('/auth/login', hubOrigin)
  loginUrl.searchParams.set('returnUrl', sanitizeReturnUrl(returnUrl))
  return loginUrl.toString()
}

/**
 * @param {Request} request
 * @param {string} assetPath
 * @returns {boolean}
 */
export function isPublicRequest(request, assetPath) {
  return (
    request.path === '/favicon.ico' ||
    request.path === '/health' ||
    request.path === assetPath ||
    request.path.startsWith(`${assetPath}/`) ||
    request.path.includes(`${assetPath}/`)
  )
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
    roles: Array.isArray(user.roles) ? user.roles : [],
    permissions: Array.isArray(user.permissions) ? user.permissions : [],
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
    actorRoles: Array.isArray(user?.roles) ? user.roles : [],
    actorPermissions: Array.isArray(user?.permissions) ? user.permissions : []
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

  return payload
}

/**
 * @param {{ taxonomyAccessMode: string, spokeAccessMode: string }} options
 * @returns {string}
 */
export function resolveAccessMode({ taxonomyAccessMode, spokeAccessMode }) {
  const resolvedTaxonomyAccessMode = normalizeAccessMode(taxonomyAccessMode)
  const resolvedSpokeAccessMode = normalizeAccessMode(
    spokeAccessMode ?? taxonomyAccessMode
  )

  return accessModeRanks[resolvedTaxonomyAccessMode] >=
    accessModeRanks[resolvedSpokeAccessMode]
    ? resolvedTaxonomyAccessMode
    : resolvedSpokeAccessMode
}

/**
 * @param {string} spokeId
 * @returns {object | null}
 */
export function getSpokeById(spokeId) {
  return SPOKES.find((spoke) => spoke.id === spokeId) ?? null
}

/**
 * @param {object} spoke
 * @returns {string}
 */
export function getSpokeAccessMode(spoke) {
  const taxonomy = SUPPORTED_TAXONOMIES.find(
    ({ id }) => id === spoke?.taxonomy?.id
  )

  return resolveAccessMode({
    taxonomyAccessMode: taxonomy?.accessMode,
    spokeAccessMode: spoke?.accessMode
  })
}

/**
 * @param {string} spokeId
 * @returns {string}
 */
export function getCurrentSpokeAccessMode(spokeId) {
  const spoke = getSpokeById(spokeId)

  if (!spoke) {
    return defaultAccessMode
  }

  return getSpokeAccessMode(spoke)
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
 * @param {{ secret: string, issuer: string, audience: string, taxonomyId: string, spokeId: string }} options
 * @returns {Promise<object | null>}
 */
export async function getHubServiceJwtPayloadFromRequest(
  request,
  { secret, issuer, audience, taxonomyId, spokeId }
) {
  const token = getAuthorizationBearerToken(request)

  if (!token) {
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
  } catch {
    return null
  }
}

/**
 * @param {{ name: string, assetPath: string, registerState?: Function, authenticate: Function }} options
 * @returns {object}
 */
function createRequestGuard({ name, assetPath, registerState, authenticate }) {
  return {
    plugin: {
      name,
      register(server) {
        registerState?.(server)

        server.ext('onPreAuth', async (request, h) => {
          if (isPublicRequest(request, assetPath)) {
            return h.continue
          }

          return authenticate(request, h)
        })
      }
    }
  }
}

/**
 * @param {{ hubOrigin: string, cookieName: string, cookieOptions: object, assetPath: string, port: number, secret: string, issuer: string, audience: string }} options
 * @returns {object}
 */
export function createAuthGuard({
  hubOrigin,
  cookieName,
  cookieOptions,
  assetPath,
  port,
  basePath,
  secret,
  issuer,
  audience
}) {
  return createRequestGuard({
    name: 'authGuard',
    assetPath,
    registerState(server) {
      server.state(cookieName, cookieOptions)
    },
    async authenticate(request, h) {
      const hubJwtPayload = await getHubJwtPayloadFromRequest(request, {
        cookieName,
        secret,
        issuer,
        audience
      })

      if (!hubJwtPayload) {
        const loginUrl = buildHubLoginUrl({
          hubOrigin,
          returnUrl: buildMicrositeReturnUrl(request, { port, basePath })
        })

        return h.redirect(loginUrl).takeover()
      }

      request.app.hubAuth = hubJwtPayload
      return h.continue
    }
  })
}

/**
 * @param {{ assetPath: string, secret: string, issuer: string, audience: string, taxonomyId: string, spokeId: string }} options
 * @returns {object}
 */
export function createHubServiceGuard({
  assetPath,
  secret,
  issuer,
  audience,
  taxonomyId,
  spokeId
}) {
  return createRequestGuard({
    name: 'hubServiceGuard',
    assetPath,
    async authenticate(request, h) {
      const hubServiceJwtPayload = await getHubServiceJwtPayloadFromRequest(
        request,
        {
          secret,
          issuer,
          audience,
          taxonomyId,
          spokeId
        }
      )

      if (!hubServiceJwtPayload) {
        return h
          .response({ message: 'Hub service authentication required' })
          .code(statusCodes.unauthorized)
          .takeover()
      }

      request.app.hubServiceAuth = hubServiceJwtPayload
      request.app.hubAuth = {
        sub: hubServiceJwtPayload.actorSub,
        email: hubServiceJwtPayload.actorEmail,
        firstName: hubServiceJwtPayload.actorFirstName,
        lastName: hubServiceJwtPayload.actorLastName,
        roles: Array.isArray(hubServiceJwtPayload.actorRoles)
          ? hubServiceJwtPayload.actorRoles
          : [],
        permissions: Array.isArray(hubServiceJwtPayload.actorPermissions)
          ? hubServiceJwtPayload.actorPermissions
          : []
      }

      return h.continue
    }
  })
}

/**
 * @param {{ spokeId: string, hubOrigin: string, cookieName: string, cookieOptions: object, assetPath: string, port: number, secret: string, issuer: string, audience: string }} options
 * @returns {object | null}
 */
export function createSpokeGuard({
  spokeId,
  hubOrigin,
  cookieName,
  cookieOptions,
  assetPath,
  port,
  basePath,
  secret,
  issuer,
  audience
}) {
  const spoke = getSpokeById(spokeId)

  if (!spoke) {
    throw new Error(`Unable to resolve spoke configuration for ${spokeId}`)
  }

  const accessMode = getSpokeAccessMode(spoke)

  if (accessMode === 'public') {
    return null
  }

  if (accessMode === HUB_SERVICE_SUBJECT) {
    return createHubServiceGuard({
      assetPath,
      secret,
      issuer,
      audience,
      taxonomyId: spoke.taxonomy.id,
      spokeId: spoke.id
    })
  }

  return createAuthGuard({
    hubOrigin,
    cookieName,
    cookieOptions,
    assetPath,
    port,
    basePath,
    secret,
    issuer,
    audience
  })
}
