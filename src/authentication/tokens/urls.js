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
 * Reduces a requested return URL to a safe, same-origin path. Anything that
 * is not an absolute path on the current origin - absolute URLs, and the
 * protocol-relative "//host" and backslash "/\host" variants that browsers
 * resolve off-site - collapses to "/".
 * @param {string} value
 * @returns {string}
 */
export function sanitizeReturnUrl(value) {
  if (typeof value !== 'string' || !value.startsWith('/')) {
    return '/'
  }

  try {
    // Resolve against a throwaway origin; the WHATWG parser normalises
    // backslashes exactly as browsers do, so any off-site target changes the
    // origin and is rejected.
    const base = 'https://x.invalid'
    const { origin, pathname, search, hash } = new URL(value, base)

    if (origin === base) {
      return `${pathname}${search}${hash}`
    }
  } catch {
    // Not parseable - fall through to the safe default.
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
  const forwardedProto = request.headers['x-forwarded-proto']
  const protocol = typeof forwardedProto === 'string' ? forwardedProto : 'http'
  const hostHeader = request.headers.host
  const host = typeof hostHeader === 'string' ? hostHeader : `localhost:${port}`
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
