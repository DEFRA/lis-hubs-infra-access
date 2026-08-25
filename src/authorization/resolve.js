import roleMappings from '../constants/role-mappings.json' with { type: 'json' }
import {
  AUTHORIZATION_VERSION,
  DEFAULT_ROLE,
  GLOBAL_CPH_SCOPE
} from './constants.js'
import { normalizeHoldingRoles } from './normalize.js'
import { resolvedRoleDefinitions } from './roles-loader.js'

/**
 * Translates a single source-provider role into its internal LIS role -
 * either it's already a valid LIS role name (some identity adapters pass
 * these through directly), or it's a source-specific name mapped via
 * role-mappings.json.
 * @param {string} sourceRole
 * @param {Record<string, string>} mappings
 * @returns {string|null}
 */
function translateRole(sourceRole, mappings) {
  if (resolvedRoleDefinitions.has(sourceRole)) {
    return sourceRole
  }

  const mappedRole = mappings[sourceRole.toLowerCase()]

  return mappedRole && resolvedRoleDefinitions.has(mappedRole)
    ? mappedRole
    : null
}

/**
 * Groups translated {role, cph} grants into one statement per role. A role
 * granted globally (cph '*') anywhere subsumes any CPH-specific grants for
 * that same role, since the global grant already covers them.
 * @param {Array<{role: string, cph: string}>} grants
 * @returns {Array<{role: string, cphs: '*'|string[]}>}
 */
function groupHoldingRolesIntoStatements(grants) {
  const cphsByRole = new Map()

  for (const { role, cph } of grants) {
    if (!cphsByRole.has(role)) {
      cphsByRole.set(role, new Set())
    }

    cphsByRole.get(role).add(cph)
  }

  return [...cphsByRole].map(([role, cphs]) => ({
    role,
    cphs: cphs.has(GLOBAL_CPH_SCOPE) ? GLOBAL_CPH_SCOPE : [...cphs]
  }))
}

/**
 * Resolves authorization from a source identity provider's role grants.
 * Translates external roles into LIS roles and groups them into one
 * statement per role, scoped to the CPHs it applies to (or '*' for
 * everywhere).
 * @param {object} params - Authorization resolution parameters.
 * @param {string} params.source - The identity provider source (e.g., 'defra-ci', 'entra-id').
 * @param {Array<{role: string, cph: string}>} [params.holdingRoles=[]] - Role grants, each scoped to a CPH or '*' for everywhere.
 * @param {Array} [params.holdings=[]] - Holdings associated with the user.
 * @returns {{authzVersion: number, statements: Array<{role: string, cphs: '*'|string[]}>, holdings: Array}} Resolved authorization object.
 */
export function resolveAuthorization({
  source,
  holdingRoles = [],
  holdings = []
}) {
  const mappings = roleMappings[source] ?? {}

  const grants = [
    { role: DEFAULT_ROLE, cph: GLOBAL_CPH_SCOPE },
    ...normalizeHoldingRoles(holdingRoles)
  ]
    .map(({ role, cph }) => ({ role: translateRole(role, mappings), cph }))
    .filter((grant) => grant.role !== null)

  return {
    authzVersion: AUTHORIZATION_VERSION,
    statements: groupHoldingRolesIntoStatements(grants),
    holdings: Array.isArray(holdings) ? holdings : []
  }
}
