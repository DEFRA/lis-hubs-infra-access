import { isPublicRequest } from './auth/tokens.js'
import { SPECIES } from '@livestock/hubs-infra-registry'

const statusCodes = {
  forbidden: 403
}

const ACCESS_LEVEL_RANKS = {
  read: 1,
  write: 2,
  admin: 3
}

const PERMISSION_PREFIX = 'lis-perm-'
const SPECIES_SCOPED_TAXONOMIES = new Set(['home', 'status', 'events'])
const MIN_PERMISSION_PARTS = 2

/**
 * @param {{ assetPath: string, moduleAccess: object }} options
 * @returns {object}
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
 * @param {{ hubId: string, user: object, modules?: object[], taxonomy?: string }} options
 * @returns {object[]}
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
 * @param {object} user
 * @param {object} moduleAccess
 * @returns {boolean}
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

    if (!parsedPermission || parsedPermission.scope !== moduleAccess.scope) {
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
 * @param {object} module
 * @returns {object | null}
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

function normalizeModuleAccess(moduleAccess) {
  if (moduleAccess?.minLevel) {
    return moduleAccess
  }

  return resolveModuleAccess(moduleAccess)
}

function hasPortalAccess(user, hubId) {
  const permissions = Array.isArray(user?.permissions) ? user.permissions : []

  return permissions.some(
    (permission) => permission?.toLowerCase?.() === `${PERMISSION_PREFIX}${hubId}`
  )
}

function getModuleSpecies(module) {
  if (typeof module?.access?.species === 'string' && module.access.species.length > 0) {
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
