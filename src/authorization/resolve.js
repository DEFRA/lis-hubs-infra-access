import roleMappings from '../role-mappings.json' with { type: 'json' }
import roleDefinitions from '../roles.json' with { type: 'json' }
import { AUTHORIZATION_VERSION, DEFAULT_ROLE } from './constants.js'
import { normalizeRoleAssignments, normalizeSourceRoles } from './normalize.js'
import {
  resolvePermissionAssignments,
  resolvePermissions
} from './permissions.js'

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
    permissionAssignments: resolvePermissionAssignments(translatedAssignments),
    holdings: Array.isArray(holdings) ? holdings : []
  }
}
