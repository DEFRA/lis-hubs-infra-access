import { hydrateAuthorization } from './hydrate.js'

/**
 * Checks whether the authorization grants a specific role, optionally scoped to a CPH.
 * @param {object} authorization - The authorization object to check.
 * @param {object} [params={}] - Role check parameters.
 * @param {string} [params.role] - The LIS role to check for.
 * @param {string} [params.cph] - The CPH scope for the role check (if applicable).
 * @returns {boolean} True if the role is granted, false otherwise.
 */
export function hasRole(authorization, { role, cph } = {}) {
  const hydrated = hydrateAuthorization(authorization)

  if (!cph && hydrated.roles.includes(role)) {
    return true
  }

  return hydrated.roleAssignments.some(
    (assignment) => assignment.role === role && assignment.cph === cph
  )
}

/**
 * Checks whether the authorization grants a specific permission, optionally scoped to a CPH.
 * @param {object} authorization - The authorization object to check.
 * @param {object} [params={}] - Permission check parameters.
 * @param {string} [params.permission] - The LIS permission to check for.
 * @param {string} [params.cph] - The CPH scope for the permission check (if applicable).
 * @returns {boolean} True if the permission is granted, false otherwise.
 */
export function hasPermission(authorization, { permission, cph } = {}) {
  const hydrated = hydrateAuthorization(authorization)

  if (hydrated.permissions.includes(permission)) {
    return true
  }

  return hydrated.permissionAssignments.some(
    (assignment) =>
      assignment.permission === permission && assignment.cph === cph
  )
}
