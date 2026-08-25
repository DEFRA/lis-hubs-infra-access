/** @import { ModuleAccess } from './module-access-resolution.js' */
import { ACCESS_LEVEL_RANKS, parsePermission } from './permission-parsing.js'

/**
 * @typedef {object} User
 * @property {string[]} [permissions] - Array of LIS permission strings
 * @property {string[]} [roles] - Array of LIS role strings
 */

/**
 * Checks whether a user has the required permissions to access a module.
 * Compares user permissions against module scope, species, app, and
 * minimum access level.
 *
 * @param {User} user - User object with permissions and roles
 * @param {ModuleAccess} moduleAccess - Module access requirements
 * @returns {boolean} True if user has sufficient access, false otherwise
 */
export function hasModuleAccess(user, moduleAccess) {
  if (!moduleAccess?.minLevel) {
    return false
  }

  const permissions = Array.isArray(user?.permissions) ? user.permissions : []
  const requiredRank = ACCESS_LEVEL_RANKS[moduleAccess.minLevel] ?? 0

  return permissions.some((permission) => {
    const parsedPermission = parsePermission(permission)

    if (parsedPermission?.scope !== moduleAccess.scope) {
      return false
    }

    if (parsedPermission.levelRank < requiredRank) {
      return false
    }

    if (moduleAccess.scope === 'user') {
      return true
    }

    if (parsedPermission.species !== moduleAccess.species) {
      return false
    }

    if (moduleAccess.scope === 'species') {
      return true
    }

    return parsedPermission.app === moduleAccess.app
  })
}
