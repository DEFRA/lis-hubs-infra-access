/** @import { Permission } from '../constants/permissions.js' */
import { GLOBAL_CPH_SCOPE } from './constants.js'
import { hydrateAuthorization } from './hydrate.js'

/**
 * @param {'*'|string[]} cphs
 * @param {string} [cph]
 * @returns {boolean}
 */
function matchesCphScope(cphs, cph) {
  if (cphs === GLOBAL_CPH_SCOPE) {
    return true
  }

  return typeof cph === 'string' && cphs.includes(cph)
}

/**
 * Checks whether the authorization grants a specific permission, optionally scoped to a CPH.
 * @param {object} authorization - The authorization object to check.
 * @param {object} [params={}] - Permission check parameters.
 * @param {Permission} [params.permission] - The LIS permission to check for.
 * @param {string} [params.cph] - The CPH scope for the permission check (if applicable).
 * @returns {boolean} True if the permission is granted, false otherwise.
 */
export function hasPermission(authorization, { permission, cph } = {}) {
  const hydrated = hydrateAuthorization(authorization)

  return hydrated.statements.some(
    (statement) =>
      statement.permissions.includes(permission) &&
      matchesCphScope(statement.cphs, cph)
  )
}
