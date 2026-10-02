import crypto from 'node:crypto'

const authFlowKey = 'hub-auth-flow'
const authSessionKey = 'hub-auth-session'
const keyLength = 32

/**
 * Creates a new hub authentication flow object with state, nonce, code verifier, and return URL.
 * @param {object} options - Configuration options for the auth flow.
 * @param {string} options.returnUrl - The URL to return to after authentication completes.
 * @param {Function} [options.generateId] - Optional function to generate unique identifiers (defaults to crypto.randomUUID).
 * @param {Function} [options.generateCodeVerifier] - Optional function to generate PKCE code verifier (defaults to base64url-encoded random bytes).
 * @returns {object} Auth flow object containing state, nonce, codeVerifier, and returnUrl properties.
 */
export function createHubAuthFlow({
  returnUrl,
  generateId = crypto.randomUUID,
  generateCodeVerifier = () =>
    crypto.randomBytes(keyLength).toString('base64url')
}) {
  return {
    state: generateId(),
    nonce: generateId(),
    codeVerifier: generateCodeVerifier(),
    returnUrl
  }
}

/**
 * Retrieves the current hub authentication flow from the request session.
 * @param {object} request - The Hapi request object with yar session support.
 * @returns {object|null} The stored auth flow object or null if not found.
 */
export function getHubAuthFlow(request) {
  return request?.yar?.get ? (request.yar.get(authFlowKey) ?? null) : null
}

/**
 * Stores the hub authentication flow in the request session.
 * @param {object} request - The Hapi request object with yar session support.
 * @param {object} authFlow - The auth flow object to store.
 */
export function setHubAuthFlow(request, authFlow) {
  request?.yar?.set?.(authFlowKey, authFlow)
}

/**
 * Clears the hub authentication flow from the request session.
 * @param {object} request - The Hapi request object with yar session support.
 */
export function clearHubAuthFlow(request) {
  request?.yar?.clear?.(authFlowKey)
}

/**
 * Retrieves the current hub authentication session from the request.
 * @param {object} request - The Hapi request object with yar session support.
 * @returns {object|null} The stored auth session object or null if not found.
 */
export function getHubAuthSession(request) {
  return request?.yar?.get ? (request.yar.get(authSessionKey) ?? null) : null
}

/**
 * Stores the hub authentication session in the request.
 * @param {object} request - The Hapi request object with yar session support.
 * @param {object} authSession - The auth session object to store.
 */
export function setHubAuthSession(request, authSession) {
  request?.yar?.set?.(authSessionKey, authSession)
}

/**
 * Clears both the hub authentication session and flow from the request.
 * @param {object} request - The Hapi request object with yar session support.
 */
export function clearHubAuthSession(request) {
  request.yar.clear(authSessionKey)
  clearHubAuthFlow(request)
}
