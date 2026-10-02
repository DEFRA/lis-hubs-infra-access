/** @import { User } from '../permissions/statements.js' */
import {
  ACCESS_LEVEL_RANKS,
  parsePermission
} from '../permissions/permission-parsing.js'
import { getFlatPermissions } from '../permissions/statements.js'

/**
 * @typedef {object} ModuleAccess
 * @property {string} [species] - Species identifier (e.g., 'cattle', 'pigs')
 * @property {string} scope - Access scope: 'user', 'species', or 'app'
 * @property {string} [app] - Application/taxonomy identifier
 * @property {string} minLevel - Minimum access level required: 'read', 'write', or 'admin'
 */

/**
 * @typedef {object} Module
 * @property {string} [path] - Module path (e.g., '/cattle/register')
 * @property {string} [taxonomy] - Module taxonomy/app identifier
 * @property {string[]} [hubs] - Array of hub IDs this module belongs to
 * @property {ModuleAccess} [access] - Explicit access configuration
 */

/**
 * Set of taxonomies that require only species-level permissions.
 * @type {Set<string>}
 */
const SPECIES_SCOPED_TAXONOMIES = new Set(['home', 'status', 'events'])

/**
 * Extracts the species identifier from a module object.
 * First checks explicit access.species, then parses from module.path.
 *
 * @param {Module} module - Module object to extract species from
 * @returns {string|null} Species identifier in lowercase or null if not found
 * @private
 */
function getModuleSpecies(module) {
  if (
    typeof module?.access?.species === 'string' &&
    module.access.species.length > 0
  ) {
    return module.access.species
  }

  if (typeof module?.path === 'string') {
    const species = module.path.split('/')[1]

    if (species) {
      return species.toLowerCase()
    }
  }

  return null
}

/**
 * Derives module access requirements from a module object.
 * Returns explicit access if defined, otherwise infers from taxonomy and path.
 * Species-scoped taxonomies require species-level permissions.
 * Other taxonomies require app-level permissions.
 *
 * @param {Module} module - Module object to resolve access for
 * @returns {ModuleAccess|null} Resolved module access configuration or null if unresolvable
 */
function resolveModuleAccess(module) {
  if (module?.access) {
    return module.access
  }

  const species = getModuleSpecies(module)

  if (!species) {
    return null
  }

  if (SPECIES_SCOPED_TAXONOMIES.has(module?.taxonomy)) {
    return {
      species,
      scope: 'species',
      minLevel: 'read'
    }
  }

  if (module?.taxonomy) {
    return {
      species,
      scope: 'app',
      app: module.taxonomy,
      minLevel: 'read'
    }
  }

  return null
}

/**
 * Normalizes module access input to a standard ModuleAccess object.
 * If already normalized (has minLevel), returns as-is.
 * Otherwise resolves it as if it were a module object.
 *
 * @param {ModuleAccess|Module} moduleAccess - Module access or module object
 * @returns {ModuleAccess|null} Normalized module access configuration or null
 */
export function normalizeModuleAccess(moduleAccess) {
  if (moduleAccess?.minLevel) {
    return moduleAccess
  }

  return resolveModuleAccess(moduleAccess)
}

/**
 * Checks whether a user has the required permissions to access a module.
 * Compares user permissions against module scope, species, app, and
 * minimum access level.
 *
 * @param {User} user - Hydrated authorization object
 * @param {ModuleAccess} moduleAccess - Module access requirements
 * @returns {boolean} True if user has sufficient access, false otherwise
 */
export function hasModuleAccess(user, moduleAccess) {
  if (!moduleAccess?.minLevel) {
    return false
  }

  const permissions = getFlatPermissions(user)
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
