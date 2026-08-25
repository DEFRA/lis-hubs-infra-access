import { resolvedRoleDefinitions } from './roles-loader.js'

/**
 * @param {unknown} sourceRoles
 * @returns {string[]}
 */
export function normalizeSourceRoles(sourceRoles) {
  if (!Array.isArray(sourceRoles)) {
    return []
  }

  return [...new Set(sourceRoles.filter((role) => typeof role === 'string'))]
}

/**
 * @param {unknown} roles
 * @returns {string[]}
 */
export function normalizeLisRoles(roles) {
  return normalizeSourceRoles(roles).filter((role) =>
    resolvedRoleDefinitions.has(role)
  )
}

/**
 * @param {unknown} assignments
 * @returns {Array<{role: string, cph: string}>}
 */
export function normalizeRoleAssignments(assignments) {
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
