import roleDefinitions from '../roles.json' with { type: 'json' }

/**
 * @param {Iterable<string>} roles
 * @returns {string[]}
 */
export function resolvePermissions(roles) {
  return [
    ...new Set(
      [...roles].flatMap((role) => roleDefinitions[role]?.permissions ?? [])
    )
  ]
}

/**
 * @param {Array<{role: string, cph: string}>} roleAssignments
 * @returns {Array<{permission: string, cph: string}>}
 */
export function resolvePermissionAssignments(roleAssignments) {
  return roleAssignments.flatMap((assignment) =>
    (roleDefinitions[assignment.role]?.permissions ?? []).map((permission) => ({
      permission,
      cph: assignment.cph
    }))
  )
}
