/**
 * @file Module access guard and permission resolution for hub-based access control.
 * Provides functions to validate user permissions against module requirements,
 * resolve accessible modules for users, and parse LIS permission strings.
 */

import { isPublicRequest } from './auth/tokens.js'
import { SPECIES } from '@defra/lis-hubs-infra-registry'

const statusCodes = {
  forbidden: 403
}

const ACCESS_LEVEL_RANKS = {
  read: 1,
  write: 2,
  admin: 3
}

/**
 * Common prefix for all LIS permission strings.
 * @type {string}
 */
const PERMISSION_PREFIX = 'lis-perm-'

/**
 * Set of taxonomies that require only species-level permissions.
 * @type {Set<string>}
 */
const SPECIES_SCOPED_TAXONOMIES = new Set(['home', 'status', 'events'])

/**
 * Minimum number of parts required in a valid permission string.
 * @type {number}
 */
const MIN_PERMISSION_PARTS = 2

/**
 * @typedef {object} ModuleAccess
 * @property {string} [species] - Species identifier (e.g., 'cattle', 'pigs')
 * @property {string} scope - Access scope: 'user', 'species', or 'app'
 * @property {string} [app] - Application/taxonomy identifier
 * @property {string} minLevel - Minimum access level required: 'read', 'write', or 'admin'
 */

/**
 * @typedef {object} User
 * @property {string[]} [permissions] - Array of LIS permission strings
 * @property {string[]} [roles] - Array of LIS role strings
 */

/**
 * @typedef {object} Module
 * @property {string} [path] - Module path (e.g., '/cattle/register')
 * @property {string} [taxonomy] - Module taxonomy/app identifier
 * @property {string[]} [hubs] - Array of hub IDs this module belongs to
 * @property {ModuleAccess} [access] - Explicit access configuration
 */

/**
 * @typedef {object} ParsedPermission
 * @property {string} scope - Permission scope: 'portal', 'user', 'species', or 'app'
 * @property {string} [species] - Species identifier if scope is 'species' or 'app'
 * @property {string} [app] - Application identifier if scope is 'app'
 * @property {string} [level] - Access level: 'read', 'write', or 'admin'
 * @property {number} [levelRank] - Numerical rank of the access level
 */

/**
 * Creates a Hapi plugin that guards module access based on user permissions.
 * Blocks requests that lack sufficient module-level permissions.
 *
 * @param {object} options - Configuration options
 * @param {string} options.assetPath - Path prefix for public assets that bypass authentication
 * @param {ModuleAccess|Module} options.moduleAccess - Module access requirements or module object
 * @returns {object} Hapi plugin object with moduleAccessGuard
 * @throws {Error} When module access configuration cannot be resolved
 */
export function createModuleAccessGuard({ assetPath, moduleAccess }) {
  const resolvedModuleAccess = normalizeModuleAccess(moduleAccess)

  if (!resolvedModuleAccess) {
    throw new Error('Unable to resolve module access configuration')
  }

  return {
    plugin: {
      name: 'moduleAccessGuard',
      register(server) {
        server.ext('onPreAuth', (request, h) => {
          if (isPublicRequest(request, assetPath)) {
            return h.continue
          }

          if (hasModuleAccess(request.app?.hubAuth, resolvedModuleAccess)) {
            return h.continue
          }

          return h
            .response({ message: 'Module access denied' })
            .code(statusCodes.forbidden)
            .takeover()
        })
      }
    }
  }
}

/**
 * Filters a list of modules to those accessible by a user within a specific hub.
 * Checks hub membership, portal access, taxonomy match, and module permissions.
 *
 * @param {object} options - Filter options
 * @param {string} options.hubId - Hub identifier (e.g., 'front-office', 'back-office')
 * @param {User} options.user - User object with permissions and roles
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

/**
 * Extracts all species the user has permissions for from their permission set.
 * Matches permissions against known species IDs and codes.
 *
 * @param {User} user - User object with permissions
 * @returns {Array<object>} Array of species objects from the registry that the user is authorized for
 */
export function getAuthorizedSpecies(user) {
  const permissions = Array.isArray(user?.permissions) ? user.permissions : []
  const allowedSpecies = new Set()

  for (const permission of permissions) {
    const parsedPermission = parsePermission(permission)

    if (parsedPermission?.species) {
      allowedSpecies.add(parsedPermission.species)
    }
  }

  return SPECIES.filter(
    ({ id, code }) => allowedSpecies.has(id) || allowedSpecies.has(code)
  )
}

/**
 * Checks whether a user has the required permissions to access a module.
 * Back-office roles bypass permission checks. Compares user permissions
 * against module scope, species, app, and minimum access level.
 *
 * @param {User} user - User object with permissions and roles
 * @param {ModuleAccess} moduleAccess - Module access requirements
 * @returns {boolean} True if user has sufficient access, false otherwise
 */
export function hasModuleAccess(user, moduleAccess) {
  if (!moduleAccess?.minLevel) {
    return false
  }

  if (
    user?.roles?.includes('lis-role-back-office') ||
    user?.permissions?.includes('lis-perm-back-office')
  ) {
    return true
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

/**
 * Derives module access requirements from a module object.
 * Returns explicit access if defined, otherwise infers from taxonomy and path.
 * Species-scoped taxonomies require species-level permissions.
 * Other taxonomies require app-level permissions.
 *
 * @param {Module} module - Module object to resolve access for
 * @returns {ModuleAccess|null} Resolved module access configuration or null if unresolvable
 */
export function resolveModuleAccess(module) {
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
 * @private
 */
function normalizeModuleAccess(moduleAccess) {
  if (moduleAccess?.minLevel) {
    return moduleAccess
  }

  return resolveModuleAccess(moduleAccess)
}

/**
 * Checks if a user has portal-level access to a specific hub.
 * Requires a permission matching 'lis-perm-{hubId}'.
 *
 * @param {User} user - User object with permissions
 * @param {string} hubId - Hub identifier to check access for
 * @returns {boolean} True if user has hub portal access, false otherwise
 * @private
 */
function hasPortalAccess(user, hubId) {
  const permissions = Array.isArray(user?.permissions) ? user.permissions : []

  return permissions.some(
    (permission) =>
      permission?.toLowerCase?.() === `${PERMISSION_PREFIX}${hubId}`
  )
}

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
 * Determines the permission scope and extracts species/app identifiers
 * from the non-level parts of a parsed permission string.
 * - Single part 'user' → user scope
 * - Single part otherwise → species scope
 * - Multiple parts → app scope with species and app identifier
 *
 * @param {string[]} scopeParts - Permission parts excluding the access level
 * @returns {object} Object with scope, and optionally species and app
 * @private
 */
function resolvePermissionScope(scopeParts) {
  if (scopeParts.length === 1 && scopeParts[0] === 'user') {
    return { scope: 'user' }
  }

  if (scopeParts.length === 1) {
    return { scope: 'species', species: scopeParts[0] }
  }

  return {
    scope: 'app',
    species: scopeParts[0],
    app: scopeParts.slice(1).join('-')
  }
}

/**
 * Parses a LIS permission string into its component parts.
 * Expected format: 'lis-perm-{scope-parts}-{level}'
 * Portal permissions: 'lis-perm-front-office' or 'lis-perm-back-office'
 * Species permissions: 'lis-perm-{species}-{level}'
 * App permissions: 'lis-perm-{species}-{app-parts}-{level}'
 * User permissions: 'lis-perm-user-{level}'
 *
 * @param {string} permission - Raw permission string
 * @returns {ParsedPermission|null} Parsed permission object or null if invalid
 * @private
 */
function parsePermission(permission) {
  if (typeof permission !== 'string' || permission.length === 0) {
    return null
  }

  const normalizedPermission = permission.toLowerCase().trim()

  if (!normalizedPermission.startsWith(PERMISSION_PREFIX)) {
    return null
  }

  const body = normalizedPermission.slice(PERMISSION_PREFIX.length)

  if (body === 'front-office' || body === 'back-office') {
    return {
      scope: 'portal'
    }
  }

  const parts = body.split('-').filter(Boolean)

  if (parts.length < MIN_PERMISSION_PARTS) {
    return null
  }

  const level = parts.at(-1)
  const levelRank = ACCESS_LEVEL_RANKS[level] ?? 0

  if (!levelRank) {
    return null
  }

  return {
    ...resolvePermissionScope(parts.slice(0, -1)),
    level,
    levelRank
  }
}
