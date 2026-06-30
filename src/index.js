import { SPECIES } from '@livestock/hub-registry'

const PERMISSION_PREFIX = 'lis-perm-'
const ACCESS_LEVEL_RANKS = {
  none: 0,
  read: 1,
  write: 2,
  admin: 3
}

const HUB_CAPABILITY_MATRIX = {
  'front-office': {
    transaction: {
      read: ['view'],
      write: ['create', 'park', 'resume', 'submit', 'view'],
      admin: ['create', 'park', 'resume', 'submit', 'view']
    },
    status: {
      read: ['view'],
      write: ['view'],
      admin: ['view']
    },
    home: {
      read: ['view'],
      write: ['view'],
      admin: ['view']
    },
    support: {
      read: ['view'],
      write: ['view'],
      admin: ['view']
    },
    permissions: {
      read: [],
      write: [],
      admin: []
    }
  },
  'back-office': {
    transaction: {
      read: ['view'],
      write: ['view', 'assist'],
      admin: ['view', 'assist', 'amend', 'resubmit']
    },
    status: {
      read: ['view'],
      write: ['view', 'assist'],
      admin: ['view', 'assist']
    },
    home: {
      read: ['view'],
      write: ['view'],
      admin: ['view']
    },
    support: {
      read: ['view'],
      write: ['view', 'assist'],
      admin: ['view', 'assist']
    },
    permissions: {
      read: ['view'],
      write: ['view', 'manage-permissions'],
      admin: ['view', 'manage-permissions']
    }
  }
}

const TRANSACTION_TAXONOMIES = new Set(['register', 'move', 'death'])
const SUPPORT_TAXONOMIES = new Set(['status', 'home'])

const HUB_CAPABILITIES_SET = new Set()

for (const hubCapabilities of Object.values(HUB_CAPABILITY_MATRIX)) {
  for (const moduleCapabilities of Object.values(hubCapabilities)) {
    for (const capabilities of Object.values(moduleCapabilities)) {
      for (const capability of capabilities) {
        HUB_CAPABILITIES_SET.add(capability)
      }
    }
  }
}

export const HUB_CAPABILITIES = [...HUB_CAPABILITIES_SET]

export const HUB_ACCESS_STATUS = 'active'

export const HUB_ACCESS_REASONS = {
  missingContext: 'missing-context',
  notInHub: 'not-in-hub',
  taxonomyMismatch: 'taxonomy-mismatch',
  missingPermission: 'missing-permission'
}

const HUB_ACCESS_DEFAULT = {
  visible: false,
  allowed: false,
  reason: HUB_ACCESS_REASONS.missingPermission,
  capabilities: []
}

export function getAccessibleModulesForHub({
  hubId,
  user,
  modules = [],
  taxonomy
}) {
  return resolveAccessibleModulesForHub({
    hubId,
    user,
    modules,
    taxonomy
  }).map(({ module }) => module)
}

export function resolveAccessibleModulesForHub({
  hubId,
  user,
  modules = [],
  taxonomy
}) {
  return modules
    .map((module) => ({
      module,
      access: resolveModuleAccess({
        hubId,
        user,
        module,
        taxonomy
      })
    }))
    .filter(({ access }) => access.visible && access.allowed)
}

export function isModuleAccessibleForHub({ hubId, user, module, taxonomy }) {
  return resolveModuleAccess({
    hubId,
    user,
    module,
    taxonomy
  }).allowed
}

export function getModuleCapabilitiesForHub({ hubId, user, module, taxonomy }) {
  return resolveModuleAccess({
    hubId,
    user,
    module,
    taxonomy
  }).capabilities
}

export function resolveModuleAccess({ hubId, user, module, taxonomy }) {
  if (!hubId || !module) {
    return {
      ...HUB_ACCESS_DEFAULT,
      reason: HUB_ACCESS_REASONS.missingContext
    }
  }

  if (!Array.isArray(module.hubs) || !module.hubs.includes(hubId)) {
    return {
      ...HUB_ACCESS_DEFAULT,
      reason: HUB_ACCESS_REASONS.notInHub
    }
  }

  if (taxonomy && module.taxonomy !== taxonomy) {
    return {
      ...HUB_ACCESS_DEFAULT,
      reason: HUB_ACCESS_REASONS.taxonomyMismatch
    }
  }

  const moduleType = getModuleType(module)
  const permissionContext = getPermissionContext(user)
  const accessLevel = getModuleAccessLevel({
    hubId,
    module,
    moduleType,
    permissionContext
  })

  if (accessLevel === ACCESS_LEVEL_RANKS.none) {
    return {
      ...HUB_ACCESS_DEFAULT,
      reason: HUB_ACCESS_REASONS.missingPermission
    }
  }

  return {
    visible: true,
    allowed: true,
    reason: null,
    capabilities: getCapabilitiesForModule({
      hubId,
      moduleType,
      accessLevel
    })
  }
}

function getModuleAccessLevel({
  hubId,
  module,
  moduleType,
  permissionContext
}) {
  if (!permissionContext.portalPermissions.has(hubId)) {
    return ACCESS_LEVEL_RANKS.none
  }

  if (moduleType === 'permissions') {
    return permissionContext.userPermissionLevel
  }

  const speciesId = getModuleSpeciesId(module)

  if (!speciesId) {
    return ACCESS_LEVEL_RANKS.none
  }

  if (
    moduleType === 'status' ||
    moduleType === 'home' ||
    moduleType === 'support'
  ) {
    return getSpeciesAccessLevel(permissionContext, speciesId)
  }

  return getScopedModuleAccessLevel(
    permissionContext,
    speciesId,
    module.taxonomy
  )
}

function getCapabilitiesForModule({ hubId, moduleType, accessLevel }) {
  const accessLevelName = getAccessLevelName(accessLevel)

  if (!accessLevelName) {
    return []
  }

  return HUB_CAPABILITY_MATRIX[hubId]?.[moduleType]?.[accessLevelName] ?? []
}

function getSpeciesAccessLevel(permissionContext, speciesId) {
  return Math.max(
    permissionContext.speciesPermissionLevels.get(speciesId) ??
      ACCESS_LEVEL_RANKS.none,
    permissionContext.speciesAppPermissionLevels.get(speciesId) ??
      ACCESS_LEVEL_RANKS.none
  )
}

function getScopedModuleAccessLevel(permissionContext, speciesId, taxonomyId) {
  return Math.max(
    permissionContext.speciesPermissionLevels.get(speciesId) ??
      ACCESS_LEVEL_RANKS.none,
    permissionContext.appPermissionLevels.get(
      buildAppPermissionKey(speciesId, taxonomyId)
    ) ?? ACCESS_LEVEL_RANKS.none
  )
}

function buildAppPermissionKey(speciesId, taxonomyId) {
  return `${speciesId}:${taxonomyId}`
}

function getModuleType(module) {
  if (module.type) {
    return module.type
  }

  if (TRANSACTION_TAXONOMIES.has(module.taxonomy)) {
    return 'transaction'
  }

  if (module.taxonomy === 'status') {
    return 'status'
  }

  if (module.taxonomy === 'home') {
    return 'home'
  }

  if (SUPPORT_TAXONOMIES.has(module.taxonomy)) {
    return 'support'
  }

  return 'transaction'
}

function getPermissionContext(user = {}) {
  const permissions = Array.isArray(user?.permissions) ? user.permissions : []
  const portalPermissions = new Set()
  const speciesPermissionLevels = new Map()
  const speciesAppPermissionLevels = new Map()
  const appPermissionLevels = new Map()
  let userPermissionLevel = ACCESS_LEVEL_RANKS.none

  for (const permission of permissions) {
    const parsedPermission = parsePermission(permission)

    if (!parsedPermission) {
      continue
    }

    if (parsedPermission.type === 'portal') {
      portalPermissions.add(parsedPermission.portalId)
      continue
    }

    if (parsedPermission.type === 'user') {
      userPermissionLevel = Math.max(
        userPermissionLevel,
        parsedPermission.accessLevel
      )
      continue
    }

    if (parsedPermission.type === 'species') {
      updateLevelMap(
        speciesPermissionLevels,
        parsedPermission.speciesId,
        parsedPermission.accessLevel
      )
      continue
    }

    if (parsedPermission.type === 'app') {
      updateLevelMap(
        appPermissionLevels,
        buildAppPermissionKey(
          parsedPermission.speciesId,
          parsedPermission.appId
        ),
        parsedPermission.accessLevel
      )
      updateLevelMap(
        speciesAppPermissionLevels,
        parsedPermission.speciesId,
        parsedPermission.accessLevel
      )
    }
  }

  return {
    portalPermissions,
    speciesPermissionLevels,
    speciesAppPermissionLevels,
    appPermissionLevels,
    userPermissionLevel
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
      type: 'portal',
      portalId: body
    }
  }

  const parts = body.split('-').filter(Boolean)

  if (parts.length < 2) {
    return null
  }

  const accessLevel =
    ACCESS_LEVEL_RANKS[parts.at(-1)] ?? ACCESS_LEVEL_RANKS.none

  if (accessLevel === ACCESS_LEVEL_RANKS.none) {
    return null
  }

  const scopeParts = parts.slice(0, -1)

  if (scopeParts.length === 1 && scopeParts[0] === 'user') {
    return {
      type: 'user',
      accessLevel
    }
  }

  if (scopeParts.length === 1) {
    return {
      type: 'species',
      speciesId: scopeParts[0],
      accessLevel
    }
  }

  return {
    type: 'app',
    speciesId: scopeParts[0],
    appId: scopeParts.slice(1).join('-'),
    accessLevel
  }
}

function updateLevelMap(levelMap, key, accessLevel) {
  levelMap.set(
    key,
    Math.max(levelMap.get(key) ?? ACCESS_LEVEL_RANKS.none, accessLevel)
  )
}

function getModuleSpeciesId(module) {
  const normalizedSpecies = module?.species?.toLowerCase()

  if (!normalizedSpecies) {
    return null
  }

  const matchingSpecies = SPECIES.find(
    ({ code, id }) => code === normalizedSpecies || id === normalizedSpecies
  )

  return matchingSpecies?.id ?? normalizedSpecies
}

function getAccessLevelName(accessLevel) {
  return (
    Object.entries(ACCESS_LEVEL_RANKS).find(
      ([name, rank]) => name !== 'none' && rank === accessLevel
    )?.[0] ?? null
  )
}
