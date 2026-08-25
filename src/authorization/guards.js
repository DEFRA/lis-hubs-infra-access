import { statusCodes } from '../status-codes.js'
import { hasPermission, hasRole } from './checks.js'

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
      .code(statusCodes.forbidden)
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

    return h
      .response({ message: 'Role denied' })
      .code(statusCodes.forbidden)
      .takeover()
  }
}
