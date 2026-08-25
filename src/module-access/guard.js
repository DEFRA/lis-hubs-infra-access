/** @import { Module, ModuleAccess } from './module-access-resolution.js' */
import { isPublicRequest } from '../auth/tokens/index.js'
import { statusCodes } from '../status-codes.js'
import { hasModuleAccess } from './access.js'
import { normalizeModuleAccess } from './module-access-resolution.js'

/**
 * Creates a Hapi plugin that guards module access based on user permissions.
 * Blocks requests that lack sufficient module-level permissions.
 *
 * @param {object} options - Configuration options
 * @param {string} options.assetPath - Path prefix for public assets that bypass authentication
 * @param {ModuleAccess|Module} options.moduleAccess - Module access requirements or module object
 * @returns {object} Hapi plugin object with moduleAccessGuard
 * @throws {Error} When module access configuration cannot be resolved
 */
export function createModuleAccessGuard({ assetPath, moduleAccess }) {
  const resolvedModuleAccess = normalizeModuleAccess(moduleAccess)

  if (!resolvedModuleAccess) {
    throw new Error('Unable to resolve module access configuration')
  }

  return {
    plugin: {
      name: 'moduleAccessGuard',
      register(server) {
        server.ext('onPreAuth', (request, h) => {
          if (isPublicRequest(request, assetPath)) {
            return h.continue
          }

          if (hasModuleAccess(request.app?.hubAuth, resolvedModuleAccess)) {
            return h.continue
          }

          return h
            .response({ message: 'Module access denied' })
            .code(statusCodes.forbidden)
            .takeover()
        })
      }
    }
  }
}
