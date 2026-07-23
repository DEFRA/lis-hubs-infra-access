import roleMappings from './role-mappings.json' with { type: 'json' }
import roleDefinitions from './roles.json' with { type: 'json' }

const DEFAULT_ROLE = 'lis-role-reader'
export const AUTHORIZATION_VERSION = 1

export function resolveAuthorization({
  source,
  sourceRoles = [],
  roleAssignments = [],
  holdings = []
}) {
  const roles = new Set([DEFAULT_ROLE])
  const mappings = roleMappings[source] ?? {}

  for (const sourceRole of normalizeSourceRoles(sourceRoles)) {
    if (roleDefinitions[sourceRole]) {
      roles.add(sourceRole)
    }

    for (const role of mappings[sourceRole.toLowerCase()] ?? []) {
      if (roleDefinitions[role]) {
        roles.add(role)
      }
    }
  }

  const translatedAssignments = normalizeRoleAssignments(roleAssignments)
    .flatMap((assignment) =>
      (mappings[assignment.role.toLowerCase()] ?? []).map((role) => ({
        ...assignment,
        role
      }))
    )
    .filter((assignment) => roleDefinitions[assignment.role])

  return {
    authzVersion: AUTHORIZATION_VERSION,
    roles: [...roles],
    permissions: resolvePermissions(roles),
    roleAssignments: translatedAssignments,
    permissionAssignments: translatedAssignments.flatMap((assignment) =>
      (roleDefinitions[assignment.role]?.permissions ?? []).map(
        (permission) => ({
          permission,
          cph: assignment.cph
        })
      )
    ),
    holdings: Array.isArray(holdings) ? holdings : []
  }
}

export function hydrateAuthorization(authorization = {}) {
  const roles = normalizeLisRoles(authorization.roles)
  const roleAssignments = normalizeRoleAssignments(
    authorization.roleAssignments
  ).filter((assignment) => roleDefinitions[assignment.role])

  return {
    ...authorization,
    authzVersion: AUTHORIZATION_VERSION,
    roles,
    permissions: resolvePermissions(roles),
    roleAssignments,
    permissionAssignments: resolvePermissionAssignments(roleAssignments)
  }
}

export function hasRole(authorization, { role, cph } = {}) {
  const hydrated = hydrateAuthorization(authorization)

  if (!cph && hydrated.roles.includes(role)) {
    return true
  }

  return hydrated.roleAssignments.some(
    (assignment) => assignment.role === role && assignment.cph === cph
  )
}

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

export function demandPermission({ permission, getCph } = {}) {
  if (typeof permission !== 'string' || permission.length === 0) {
    throw new Error('A permission demand requires a permission')
  }

  return function permissionDemand(request, h) {
    const cph = getCph?.(request)

    if (hasPermission(request.app?.hubAuth, { permission, cph })) {
      return h.continue
    }

    return h.response({ message: 'Permission denied' }).code(403).takeover()
  }
}

export function demandRole({ role, getCph } = {}) {
  if (typeof role !== 'string' || role.length === 0) {
    throw new Error('A role demand requires a role')
  }

  return function roleDemand(request, h) {
    const cph = getCph?.(request)

    if (hasRole(request.app?.hubAuth, { role, cph })) {
      return h.continue
    }

    return h.response({ message: 'Role denied' }).code(403).takeover()
  }
}

function normalizeSourceRoles(sourceRoles) {
  if (!Array.isArray(sourceRoles)) {
    return []
  }

  return [...new Set(sourceRoles.filter((role) => typeof role === 'string'))]
}

function normalizeLisRoles(roles) {
  return normalizeSourceRoles(roles).filter((role) => roleDefinitions[role])
}

function normalizeRoleAssignments(assignments) {
  if (!Array.isArray(assignments)) {
    return []
  }

  return assignments.filter(
    (assignment) =>
      assignment &&
      typeof assignment.role === 'string' &&
      typeof assignment.cph === 'string'
  )
}

function resolvePermissions(roles) {
  return [
    ...new Set(
      [...roles].flatMap((role) => roleDefinitions[role]?.permissions ?? [])
    )
  ]
}

function resolvePermissionAssignments(roleAssignments) {
  return roleAssignments.flatMap((assignment) =>
    (roleDefinitions[assignment.role]?.permissions ?? []).map((permission) => ({
      permission,
      cph: assignment.cph
    }))
  )
}
