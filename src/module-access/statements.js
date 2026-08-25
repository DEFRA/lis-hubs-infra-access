/**
 * @typedef {object} User
 * @property {Array<{role: string, cphs: '*'|string[], permissions: string[]}>} [statements] - Hydrated authorization statements
 */

/**
 * Flattens a hydrated authorization's statements into a single deduplicated
 * permissions list, regardless of which CPHs each statement applies to.
 * Used for CPH-agnostic "does the user have this anywhere" checks, such as
 * module visibility.
 *
 * @param {User} user - Hydrated authorization object
 * @returns {string[]} All permissions granted anywhere
 */
export function getFlatPermissions(user) {
  const statements = Array.isArray(user?.statements) ? user.statements : []

  return [
    ...new Set(
      statements.flatMap((statement) =>
        Array.isArray(statement?.permissions) ? statement.permissions : []
      )
    )
  ]
}
