import roleDefinitions from '../roles.json' with { type: 'json' }

/**
 * Recursively expands a role's own permissions plus the permissions of
 * every role it extends. Throws on an unknown role or a circular
 * extends chain, since both are authoring mistakes in static config.
 *
 * @param {string} role
 * @param {string[]} path - roles visited so far, for cycle detection
 * @returns {Set<string>}
 */
function resolveRolePermissions(role, path = []) {
  if (path.includes(role)) {
    throw new Error(
      `Circular role extends chain detected: ${[...path, role].join(' -> ')}`
    )
  }

  const definition = roleDefinitions[role]

  if (!definition) {
    throw new Error(`Unknown role in extends chain: ${role}`)
  }

  const ownPermissions = definition.permissions ?? []
  const extendedPermissions = (definition.extends ?? []).flatMap(
    (extendedRole) => [...resolveRolePermissions(extendedRole, [...path, role])]
  )

  return new Set([...ownPermissions, ...extendedPermissions])
}

/**
 * roles.json with each role's extends chain eagerly resolved into a flat
 * permissions list, so downstream lookups are a single map access rather
 * than a recursive walk on every request.
 *
 * @type {Map<string, Set<string>>}
 */
export const resolvedRoleDefinitions = new Map()

for (const role of Object.keys(roleDefinitions)) {
  resolvedRoleDefinitions.set(role, resolveRolePermissions(role))
}
