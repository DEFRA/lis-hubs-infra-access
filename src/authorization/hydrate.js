import { AUTHORIZATION_VERSION } from './constants.js'
import { normalizeLisRoles, normalizeRoleAssignments } from './normalize.js'
import {
  resolvePermissionAssignments,
  resolvePermissions
} from './permissions.js'
import { resolvedRoleDefinitions } from './roles-loader.js'

/**
 * Rehydrates an authorization object with current role definitions and permissions.
 * Ensures the authorization structure is up-to-date with the current authorization version
 * and expands permissions from roles.
 * @param {object} [authorization={}] - The authorization object to hydrate.
 * @param {string[]} [authorization.roles] - LIS roles to rehydrate.
 * @param {Array<{role: string, cph: string}>} [authorization.roleAssignments] - Role assignments to rehydrate.
 * @returns {object} Hydrated authorization object with expanded permissions and validated assignments.
 */
export function hydrateAuthorization(authorization = {}) {
  const roles = normalizeLisRoles(authorization.roles)
  const roleAssignments = normalizeRoleAssignments(
    authorization.roleAssignments
  ).filter((assignment) => resolvedRoleDefinitions.has(assignment.role))

  return {
    ...authorization,
    authzVersion: AUTHORIZATION_VERSION,
    roles,
    permissions: resolvePermissions(roles),
    roleAssignments,
    permissionAssignments: resolvePermissionAssignments(roleAssignments)
  }
}
