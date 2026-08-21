/** @import { Request } from '@hapi/hapi' */

/**
 * @typedef {object} OidcProvider
 * @property {string} discoveryUrl
 * @property {string} clientId
 * @property {string} clientSecret
 * @property {string} redirectPath
 * @property {string} [serviceId]
 * @property {{ type: string, getCredentials: () => Promise<string> }} [authProvider]
 */

/**
 * @typedef {object} AuthorizationGrantResult
 * @property {object} user
 * @property {object} authSession
 * @property {string|null} accessToken
 * @property {string} returnUrl
 */

/**
 * @typedef {object} OidcOperations
 * @property {(request: Request) => Promise<string>} buildAuthorizationUrl
 * @property {(request: Request) => Promise<AuthorizationGrantResult>} completeAuthorizationCodeGrant
 * @property {(request: Request) => string} buildLogoutUrl
 */
