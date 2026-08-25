import { resolvedRoleDefinitions } from './roles-loader.js'

/**
 * @param {Iterable<string>} roles
 * @returns {string[]}
 */
export function resolvePermissions(roles) {
  return [
    ...new Set(
      [...roles].flatMap((role) => [
        ...(resolvedRoleDefinitions.get(role) ?? [])
      ])
    )
  ]
}

/**
 * @param {Array<{role: string, cph: string}>} roleAssignments
 * @returns {Array<{permission: string, cph: string}>}
 */
export function resolvePermissionAssignments(roleAssignments) {
  return roleAssignments.flatMap((assignment) =>
    [...(resolvedRoleDefinitions.get(assignment.role) ?? [])].map(
      (permission) => ({
        permission,
        cph: assignment.cph
      })
    )
  )
}
