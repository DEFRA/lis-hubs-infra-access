import { logger } from '@defra/lis-hubs-infra-core'

/**
 * Logs the absence of a usable service token without logging credentials.
 * @param {object} request Hapi request.
 */
export function logMissingServiceToken(request) {
  const headerPresent = typeof request.headers?.authorization === 'string'

  logger.warn(
    `Service token missing or bearer authorization header is malformed [authorizationHeaderPresent=${headerPresent}]`
  )
}

/**
 * Logs safe service token validation diagnostics without logging credentials or claims.
 * @param {Error & { code?: string, claim?: string, reason?: string }} error Validation error.
 */
export function logInvalidServiceToken(error) {
  const diagnostics = [
    ['code', error?.code],
    ['claim', error?.claim],
    ['reason', error?.reason],
    ['message', error?.message]
  ]
    .filter(([, value]) => value !== undefined)
    .map(([name, value]) => `${name}=${value}`)
    .join(' | ')

  logger.warn(`Service token validation failed [${diagnostics}]`)
}
