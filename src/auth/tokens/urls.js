/** @import { Request } from '@hapi/hapi' */

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

/**
 * Creates the return URL for a microsite.
 * @param {Request} request
 * @param {{ port: number, basePath?: string }} options
 * @returns {string}
 */
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
 * @param {Request} request
 * @param {string[]} hubOrigins
 * @returns {string}
 */
export function resolveHubOrigin(request, hubOrigins = []) {
  const requestHost =
    request.headers?.['x-forwarded-host'] ?? request.headers?.host ?? ''
  const requestHostname = requestHost.split(',')[0].trim()
  const referer = request.headers?.referer

  return (
    hubOrigins.find((origin) => new URL(origin).host === requestHostname) ??
    hubOrigins.find((origin) => referer?.startsWith(`${origin}/`)) ??
    hubOrigins[0]
  )
}
