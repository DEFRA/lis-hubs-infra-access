import roleMappings from '../constants/role-mappings.json' with { type: 'json' }
import {
  AUTHORIZATION_VERSION,
  DEFAULT_ROLE,
  GLOBAL_CPH_SCOPE
} from './constants.js'
import { normalizeRoleAssignments, normalizeSourceRoles } from './normalize.js'
import { resolvedRoleDefinitions } from './roles-loader.js'

/**
 * Groups translated {role, cph} pairs into one statement per role, with
 * that role's cphs collected into a single list.
 * @param {Array<{role: string, cph: string}>} assignments
 * @returns {Array<{role: string, cphs: string[]}>}
 */
function groupAssignmentsIntoStatements(assignments) {
  const cphsByRole = new Map()

  for (const { role, cph } of assignments) {
    if (!cphsByRole.has(role)) {
      cphsByRole.set(role, new Set())
    }

    cphsByRole.get(role).add(cph)
  }

  return [...cphsByRole].map(([role, cphs]) => ({ role, cphs: [...cphs] }))
}

/**
 * Resolves authorization from source identity provider roles and role assignments.
 * Translates external roles into LIS roles and groups them into statements -
 * one per role, scoped to the CPHs it applies to (or '*' for everywhere).
 * @param {object} params - Authorization resolution parameters.
 * @param {string} params.source - The identity provider source (e.g., 'defra-ci', 'entra-id').
 * @param {string[]} [params.sourceRoles=[]] - Roles from the identity provider, granted everywhere.
 * @param {Array<{role: string, cph: string}>} [params.roleAssignments=[]] - CPH-scoped role assignments.
 * @param {Array} [params.holdings=[]] - Holdings associated with the user.
 * @returns {{authzVersion: number, statements: Array<{role: string, cphs: '*'|string[]}>, holdings: Array}} Resolved authorization object.
 */
export function resolveAuthorization({
  source,
  sourceRoles = [],
  roleAssignments = [],
  holdings = []
}) {
  const mappings = roleMappings[source] ?? {}
  const globalRoles = new Set([DEFAULT_ROLE])

  for (const sourceRole of normalizeSourceRoles(sourceRoles)) {
    if (resolvedRoleDefinitions.has(sourceRole)) {
      globalRoles.add(sourceRole)
    }

    const mappedRole = mappings[sourceRole.toLowerCase()]

    if (mappedRole && resolvedRoleDefinitions.has(mappedRole)) {
      globalRoles.add(mappedRole)
    }
  }

  const globalStatements = [...globalRoles].map((role) => ({
    role,
    cphs: GLOBAL_CPH_SCOPE
  }))

  const translatedAssignments = normalizeRoleAssignments(roleAssignments)
    .map((assignment) => ({
      role: mappings[assignment.role.toLowerCase()],
      cph: assignment.cph
    }))
    .filter(
      (assignment) =>
        assignment.role && resolvedRoleDefinitions.has(assignment.role)
    )

  return {
    authzVersion: AUTHORIZATION_VERSION,
    statements: [
      ...globalStatements,
      ...groupAssignmentsIntoStatements(translatedAssignments)
    ],
    holdings: Array.isArray(holdings) ? holdings : []
  }
}
