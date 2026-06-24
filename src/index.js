export const HUB_CAPABILITIES = [
  'create',
  'park',
  'resume',
  'submit',
  'view',
  'assist',
  'amend',
  'resubmit',
  'manage-permissions',
  'manage-reference-data',
  'view-audit'
]

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

const HUB_CAPABILITY_MATRIX = {
  'front-office': {
    transaction: ['create', 'park', 'resume', 'submit', 'view'],
    status: ['view'],
    home: ['view'],
    support: ['view'],
    permissions: [],
    'reference-data': [],
    audit: []
  },
  'back-office': {
    transaction: ['view', 'assist'],
    status: ['view'],
    home: ['view'],
    support: ['view', 'assist'],
    permissions: ['manage-permissions'],
    'reference-data': ['manage-reference-data'],
    audit: ['view-audit']
  }
}

const HUB_ELEVATED_CAPABILITIES = {
  'front-office': {
    transaction: [],
    status: [],
    home: [],
    support: [],
    permissions: [],
    'reference-data': [],
    audit: []
  },
  'back-office': {
    transaction: ['amend', 'resubmit'],
    status: ['assist'],
    home: [],
    support: ['amend', 'resubmit'],
    permissions: [],
    'reference-data': [],
    audit: []
  }
}

const MODULE_SYSTEM_PERMISSION_MAP = {
  permissions: 'system.user',
  'reference-data': 'system.reference',
  audit: 'system.audit'
}

const TRANSACTION_TAXONOMIES = new Set(['register', 'move', 'death'])
const SUPPORT_TAXONOMIES = new Set(['status', 'home'])

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

export function isModuleAccessibleForHub({
  hubId,
  user,
  module,
  taxonomy
}) {
  return resolveModuleAccess({
    hubId,
    user,
    module,
    taxonomy
  }).allowed
}

export function getModuleCapabilitiesForHub({
  hubId,
  user,
  module,
  taxonomy
}) {
  return resolveModuleAccess({
    hubId,
    user,
    module,
    taxonomy
  }).capabilities
}

export function resolveModuleAccess({
  hubId,
  user,
  module,
  taxonomy
}) {
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
  const hasAccess = hasModuleAccess({
    hubId,
    module,
    moduleType,
    permissionContext
  })

  if (!hasAccess) {
    return {
      ...HUB_ACCESS_DEFAULT,
      reason: HUB_ACCESS_REASONS.missingPermission
    }
  }

  const capabilities = getCapabilitiesForModule({
    hubId,
    module,
    moduleType,
    permissionContext
  })

  return {
    visible: true,
    allowed: true,
    reason: null,
    capabilities
  }
}

function hasModuleAccess({
  hubId,
  module,
  moduleType,
  permissionContext
}) {
  if (moduleType === 'permissions' || moduleType === 'reference-data' || moduleType === 'audit') {
    return permissionContext.systemPermissions.has(
      MODULE_SYSTEM_PERMISSION_MAP[moduleType]
    )
  }

  if (moduleType === 'transaction') {
    const exactPermission = buildModulePermission(module)

    if (hubId === 'front-office') {
      return permissionContext.exactPermissions.has(exactPermission)
    }

    return (
      permissionContext.exactPermissions.has(exactPermission) ||
      permissionContext.managePermissions.has(module.species)
    )
  }

  if (moduleType === 'status' || moduleType === 'home' || moduleType === 'support') {
    return hasSpeciesScopedAccess(permissionContext, module.species)
  }

  return hasSpeciesScopedAccess(permissionContext, module.species)
}

function getCapabilitiesForModule({
  hubId,
  module,
  moduleType,
  permissionContext
}) {
  const baseCapabilities = HUB_CAPABILITY_MATRIX[hubId]?.[moduleType] ?? []
  const elevatedCapabilities = HUB_ELEVATED_CAPABILITIES[hubId]?.[moduleType] ?? []
  const capabilities = new Set(baseCapabilities)

  if (permissionContext.managePermissions.has(module.species)) {
    for (const capability of elevatedCapabilities) {
      capabilities.add(capability)
    }
  }

  return [...capabilities]
}

function hasSpeciesScopedAccess(permissionContext, speciesCode) {
  return (
    permissionContext.speciesPermissions.has(speciesCode) ||
    permissionContext.managePermissions.has(speciesCode)
  )
}

function buildModulePermission(module) {
  return `${module.species}.${module.taxonomy}`.toLowerCase()
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
  const groups = Array.isArray(user?.groups) ? user.groups : []
  const exactPermissions = new Set()
  const systemPermissions = new Set()
  const speciesPermissions = new Set()
  const managePermissions = new Set()

  for (const permission of permissions) {
    if (typeof permission !== 'string' || permission.length === 0) {
      continue
    }

    const normalizedPermission = permission.toLowerCase()
    exactPermissions.add(normalizedPermission)

    const [scope, action] = normalizedPermission.split('.')

    if (!scope || !action) {
      continue
    }

    if (scope === 'system') {
      systemPermissions.add(normalizedPermission)
      continue
    }

    speciesPermissions.add(scope)

    if (action === 'manage') {
      managePermissions.add(scope)
    }
  }

  for (const group of groups) {
    if (typeof group !== 'string' || group.length === 0) {
      continue
    }

    speciesPermissions.add(group.toLowerCase())
  }

  return {
    exactPermissions,
    systemPermissions,
    speciesPermissions,
    managePermissions
  }
}
