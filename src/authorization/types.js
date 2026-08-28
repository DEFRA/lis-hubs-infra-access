/**
 * @typedef {object} Statement
 * @property {string} role
 * @property {'*'|string[]} cphs
 */

/**
 * An authorization object before hydration - the shape a hub's own mapUser()
 * returns (see e.g. front-office/back-office's oidc.js), read from a hub
 * session, or read from a hub-issued JWT. statements is only present once a
 * hub has resolved it via resolveAuthorization() and attached it before
 * issuing the JWT - roles carries the raw, unresolved provider roles until
 * then. Every other property here passes through hydrateAuthorization()
 * untouched.
 * @typedef {object} Authorization
 * @property {string} [sub]
 * @property {string} [email] - The authenticated user's email, if known.
 * @property {string} [firstName]
 * @property {string} [lastName]
 * @property {string} [serviceId]
 * @property {string[]} [roles] - Raw, unresolved provider roles.
 * @property {string} [loa]
 * @property {string[]} [amr]
 * @property {string} [authProvider]
 * @property {Statement[]} [statements] - Resolved statements, once attached.
 */

/**
 * An Authorization after hydrateAuthorization() - every other property
 * passes through unchanged, but statements is now guaranteed present with
 * each one carrying its expanded permissions, and authzVersion reflects
 * the current roles.json.
 * @typedef {Authorization & { statements: Array<Statement & { permissions: string[] }>, authzVersion: number }} HydratedAuthorization
 */

export {}
