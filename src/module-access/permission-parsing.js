/**
 * Common prefix for all LIS permission strings.
 * @type {string}
 */
export const PERMISSION_PREFIX = 'lis-perm-'

/**
 * Minimum number of parts required in a valid permission string.
 * @type {number}
 */
const MIN_PERMISSION_PARTS = 2

export const ACCESS_LEVEL_RANKS = {
  read: 1,
  write: 2,
  admin: 3
}

/**
 * @typedef {object} ParsedPermission
 * @property {string} scope - Permission scope: 'portal', 'user', 'species', or 'app'
 * @property {string} [species] - Species identifier if scope is 'species' or 'app'
 * @property {string} [app] - Application identifier if scope is 'app'
 * @property {string} [level] - Access level: 'read', 'write', or 'admin'
 * @property {number} [levelRank] - Numerical rank of the access level
 */

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
 */
export function parsePermission(permission) {
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
