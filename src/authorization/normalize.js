import { GLOBAL_CPH_SCOPE } from './constants.js'
import { resolvedRoleDefinitions } from './roles-loader.js'

/**
 * @param {unknown} holdingRoles
 * @returns {Array<{role: string, cph: string}>}
 */
export function normalizeHoldingRoles(holdingRoles) {
  if (!Array.isArray(holdingRoles)) {
    return []
  }

  return holdingRoles.filter(
    (grant) =>
      grant && typeof grant.role === 'string' && typeof grant.cph === 'string'
  )
}

/**
 * @param {unknown} cphs
 * @returns {'*'|string[]|null}
 */
function normalizeCphScope(cphs) {
  if (cphs === GLOBAL_CPH_SCOPE) {
    return GLOBAL_CPH_SCOPE
  }

  if (!Array.isArray(cphs)) {
    return null
  }

  const normalizedCphs = cphs.filter((cph) => typeof cph === 'string')

  return normalizedCphs.length > 0 ? normalizedCphs : null
}

/**
 * @param {unknown} statement
 * @returns {{role: string, cphs: '*'|string[]}|null}
 */
function normalizeStatement(statement) {
  if (!statement || typeof statement.role !== 'string') {
    return null
  }

  if (!resolvedRoleDefinitions.has(statement.role)) {
    return null
  }

  const cphs = normalizeCphScope(statement.cphs)

  return cphs === null ? null : { role: statement.role, cphs }
}

/**
 * @param {unknown} statements
 * @returns {Array<{role: string, cphs: '*'|string[]}>}
 */
export function normalizeStatements(statements) {
  if (!Array.isArray(statements)) {
    return []
  }

  return statements
    .map((statement) => normalizeStatement(statement))
    .filter((statement) => statement !== null)
}
