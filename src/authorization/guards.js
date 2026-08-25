/** @import { Permission } from '../constants/permissions.js' */
import Boom from '@hapi/boom'
import { hasPermission } from './checks.js'

/**
 * Creates a Hapi pre-handler that demands a specific permission.
 * Returns a Boom 403 if the permission is not granted, so a host app's
 * own onPreResponse error handling can render it consistently.
 * @param {object} [params={}] - Permission demand parameters.
 * @param {Permission} [params.permission] - The LIS permission to demand.
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

    return Boom.forbidden()
  }
}
