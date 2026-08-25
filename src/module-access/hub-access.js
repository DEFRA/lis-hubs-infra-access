/** @import { User } from './statements.js' */
/** @import { Module } from './module-access-resolution.js' */
import { PERMISSION_PREFIX } from './permission-parsing.js'
import { hasModuleAccess } from './access.js'
import { resolveModuleAccess } from './module-access-resolution.js'
import { getFlatPermissions } from './statements.js'

/**
 * Checks if a user has portal-level access to a specific hub.
 * Requires a permission matching 'lis-perm-{hubId}'.
 *
 * @param {User} user - Hydrated authorization object
 * @param {string} hubId - Hub identifier to check access for
 * @returns {boolean} True if user has hub portal access, false otherwise
 * @private
 */
function hasPortalAccess(user, hubId) {
  const permissions = getFlatPermissions(user)

  return permissions.some(
    (permission) =>
      permission?.toLowerCase?.() === `${PERMISSION_PREFIX}${hubId}`
  )
}

/**
 * Filters a list of modules to those accessible by a user within a specific hub.
 * Checks hub membership, portal access, taxonomy match, and module permissions.
 *
 * @param {object} options - Filter options
 * @param {string} options.hubId - Hub identifier (e.g., 'front-office', 'back-office')
 * @param {User} options.user - Hydrated authorization object
 * @param {Module[]} [options.modules=[]] - Array of modules to filter
 * @param {string} [options.taxonomy] - Optional taxonomy filter
 * @returns {Module[]} Array of modules the user can access
 */
export function getAccessibleModulesForHub({
  hubId,
  user,
  modules = [],
  taxonomy
}) {
  if (!hubId || !hasPortalAccess(user, hubId)) {
    return []
  }

  return modules.filter((module) => {
    if (!Array.isArray(module?.hubs) || !module.hubs.includes(hubId)) {
      return false
    }

    if (taxonomy && module.taxonomy !== taxonomy) {
      return false
    }

    return hasModuleAccess(user, resolveModuleAccess(module))
  })
}
