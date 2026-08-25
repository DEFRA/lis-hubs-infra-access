/** @import { Permission } from '../constants/permissions.js' */
import { GLOBAL_CPH_SCOPE } from './constants.js'

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
 * Checks whether an already-hydrated authorization grants a specific
 * permission, optionally scoped to a CPH. Expects statements to already
 * carry a `permissions` array, as attached by hydrateAuthorization() at
 * the session/JWT boundary - callers should not re-hydrate per check.
 * @param {object} authorization - A hydrated authorization object.
 * @param {object} [params={}] - Permission check parameters.
 * @param {Permission} [params.permission] - The LIS permission to check for.
 * @param {string} [params.cph] - The CPH scope for the permission check (if applicable).
 * @returns {boolean} True if the permission is granted, false otherwise.
 */
export function hasPermission(authorization, { permission, cph } = {}) {
  return (authorization?.statements ?? []).some(
    (statement) =>
      statement.permissions.includes(permission) &&
      matchesCphScope(statement.cphs, cph)
  )
}
