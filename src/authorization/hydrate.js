import { AUTHORIZATION_VERSION } from './constants.js'
import { normalizeStatements } from './normalize.js'
import { resolvedRoleDefinitions } from './roles-loader.js'

/**
 * Rehydrates an authorization object with current role definitions.
 * Validates each statement's role and cphs, and attaches a permissions
 * array to each one, expanded from the current roles.json.
 * @param {object} [authorization={}] - The authorization object to hydrate.
 * @param {Array<{role: string, cphs: '*'|string[]}>} [authorization.statements] - Statements to rehydrate.
 * @returns {object} Hydrated authorization object with each statement carrying its permissions.
 */
export function hydrateAuthorization(authorization = {}) {
  const statements = normalizeStatements(authorization.statements).map(
    (statement) => ({
      ...statement,
      permissions: [...(resolvedRoleDefinitions.get(statement.role) ?? [])]
    })
  )

  return {
    ...authorization,
    authzVersion: AUTHORIZATION_VERSION,
    statements
  }
}
