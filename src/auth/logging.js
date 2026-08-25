/**
 * Logs the absence of a usable hub-service bearer token without logging credentials.
 * @param {object} request Hapi request.
 */
export function logMissingHubServiceJwt(request) {
  request.logger?.warn?.(
    {
      authorizationHeaderPresent:
        typeof request.headers?.authorization === 'string'
    },
    'Hub service JWT missing or bearer authorization header is malformed'
  )
}

/**
 * Logs safe JWT validation diagnostics without logging credentials or claims.
 * @param {object} request Hapi request.
 * @param {Error & { code?: string, claim?: string, reason?: string }} error Validation error.
 */
export function logInvalidHubServiceJwt(request, error) {
  const diagnostics = [
    ['code', error?.code],
    ['claim', error?.claim],
    ['reason', error?.reason],
    ['message', error?.message]
  ]
    .filter(([, value]) => value !== undefined)
    .map(([name, value]) => `${name}=${value}`)
    .join(' | ')

  request.logger?.warn?.(`Hub service JWT validation failed [${diagnostics}]`)
}
