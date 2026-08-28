/** @import { Authorization, HydratedAuthorization } from './types.js' */
import { AUTHORIZATION_VERSION } from './constants.js'
import { normalizeStatements } from './normalize.js'
import { resolvedRoleDefinitions } from './roles-loader.js'
import { logger } from '@defra/lis-hubs-infra-core'

/**
 * Rehydrates an authorization object with current role definitions.
 * Validates each statement's role and cphs, and attaches a permissions
 * array to each one, expanded from the current roles.json. Runs on every
 * guarded request, so also hashes the user's email into logger.context as
 * user_email_hash when present, keeping it set for the lifetime of the
 * request rather than only at the initial login.
 * @param {Authorization} [authorization={}] - The authorization object to hydrate.
 * @returns {HydratedAuthorization} Hydrated authorization object with each statement carrying its permissions.
 */
export function hydrateAuthorization(authorization = {}) {
  const statements = normalizeStatements(authorization.statements).map(
    (statement) => ({
      ...statement,
      permissions: [...(resolvedRoleDefinitions.get(statement.role) ?? [])]
    })
  )
  if (authorization.email) {
    logger.context.set('user_email_hash', authorization.email, true)
  }

  return {
    ...authorization,
    authzVersion: AUTHORIZATION_VERSION,
    statements
  }
}
