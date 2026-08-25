/** @import { User } from './statements.js' */
import { SPECIES } from '@defra/lis-hubs-infra-registry'
import { parsePermission } from './permission-parsing.js'
import { getFlatPermissions } from './statements.js'

/**
 * Extracts all species the user has permissions for from their permission set.
 * Matches permissions against known species IDs and codes.
 *
 * @param {User} user - Hydrated authorization object
 * @returns {Array<object>} Array of species objects from the registry that the user is authorized for
 */
export function getAuthorizedSpecies(user) {
  const permissions = getFlatPermissions(user)
  const allowedSpecies = new Set()

  for (const permission of permissions) {
    const parsedPermission = parsePermission(permission)

    if (parsedPermission?.species) {
      allowedSpecies.add(parsedPermission.species)
    }
  }

  return SPECIES.filter(
    ({ id, code }) => allowedSpecies.has(id) || allowedSpecies.has(code)
  )
}
