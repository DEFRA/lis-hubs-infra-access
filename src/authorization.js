import roleMappings from './role-mappings.json' with { type: 'json' }
import roleDefinitions from './roles.json' with { type: 'json' }

const DEFAULT_ROLE = 'lis-role-reader'
const accessDenied = 403

/**
 * The current authorization model version.
 * Used to track compatibility between hub tokens and application authorization logic.
 * @type {number}
 * @constant
 */
export const AUTHORIZATION_VERSION = 1

/**
 * Resolves authorization from source identity provider roles and role assignments.
 * Translates external roles into LIS roles and permissions, applies CPH-scoped assignments,
 * and includes holdings data.
 * @param {object} params - Authorization resolution parameters.
 * @param {string} params.source - The identity provider source (e.g., 'defra-ci', 'entra-id').
 * @param {string[]} [params.sourceRoles=[]] - Roles from the identity provider.
 * @param {Array<{role: string, cph: string}>} [params.roleAssignments=[]] - CPH-scoped role assignments.
 * @param {Array} [params.holdings=[]] - Holdings associated with the user.
 * @returns {object} Resolved authorization object containing roles, permissions, assignments, and holdings.
 */
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

/**
 * Checks whether the authorization grants a specific role, optionally scoped to a CPH.
 * @param {object} authorization - The authorization object to check.
 * @param {object} [params={}] - Role check parameters.
 * @param {string} [params.role] - The LIS role to check for.
 * @param {string} [params.cph] - The CPH scope for the role check (if applicable).
 * @returns {boolean} True if the role is granted, false otherwise.
 */
export function hasRole(authorization, { role, cph } = {}) {
  const hydrated = hydrateAuthorization(authorization)

  if (!cph && hydrated.roles.includes(role)) {
    return true
  }

  return hydrated.roleAssignments.some(
    (assignment) => assignment.role === role && assignment.cph === cph
  )
}

/**
 * Checks whether the authorization grants a specific permission, optionally scoped to a CPH.
 * @param {object} authorization - The authorization object to check.
 * @param {object} [params={}] - Permission check parameters.
 * @param {string} [params.permission] - The LIS permission to check for.
 * @param {string} [params.cph] - The CPH scope for the permission check (if applicable).
 * @returns {boolean} True if the permission is granted, false otherwise.
 */
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

/**
 * Creates a Hapi pre-handler that demands a specific permission.
 * Returns a 403 response if the permission is not granted.
 * @param {object} [params={}] - Permission demand parameters.
 * @param {string} [params.permission] - The LIS permission to demand.
 * @param {Function} [params.getCph] - Optional function to extract CPH scope from the request.
 * @returns {Function} A Hapi pre-handler function that enforces the permission.
 * @throws {Error} If no permission is provided.
 */
export function demandPermission({ permission, getCph } = {}) {
  if (typeof permission !== 'string' || permission.length === 0) {
    throw new Error('A permission demand requires a permission')
  }

  return function permissionDemand(request, h) {
    const cph = getCph?.(request)

    if (hasPermission(request.app?.hubAuth, { permission, cph })) {
      return h.continue
    }

    return h
      .response({ message: 'Permission denied' })
      .code(accessDenied)
      .takeover()
  }
}

/**
 * Creates a Hapi pre-handler that demands a specific role.
 * Returns a 403 response if the role is not granted.
 * @param {object} [params={}] - Role demand parameters.
 * @param {string} [params.role] - The LIS role to demand.
 * @param {Function} [params.getCph] - Optional function to extract CPH scope from the request.
 * @returns {Function} A Hapi pre-handler function that enforces the role.
 * @throws {Error} If no role is provided.
 */
export function demandRole({ role, getCph } = {}) {
  if (typeof role !== 'string' || role.length === 0) {
    throw new Error('A role demand requires a role')
  }

  return function roleDemand(request, h) {
    const cph = getCph?.(request)

    if (hasRole(request.app?.hubAuth, { role, cph })) {
      return h.continue
    }

    return h.response({ message: 'Role denied' }).code(accessDenied).takeover()
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
