import Wreck from '@hapi/wreck'
import { requestContext } from '@defra/lis-hubs-infra-core'
import { statusCodes } from './constants/status-codes.js'

/**
 * @typedef {object} UserDetails
 * @property {string} id
 * @property {string} email
 * @property {string} firstName
 * @property {string} lastName
 * @property {string} displayName
 * @property {boolean} active
 */

/**
 * @typedef {object} CphAssignment
 * @property {string} id
 * @property {string} countyParishHoldingId
 * @property {string} countyParishHoldingNumber
 * @property {string} userId
 * @property {string} roleId
 * @property {string} roleName
 * @property {string} email
 * @property {string} displayName
 */

/**
 * @typedef {object} CphDelegation
 * @property {string} id
 * @property {string} countyParishHoldingId
 * @property {string} countyParishHoldingNumber
 * @property {string} delegatingUserId
 * @property {string} delegatingUserName
 * @property {string | null} delegatedUserId
 * @property {string | null} delegatedUserName
 * @property {string} delegatedUserRoleId
 * @property {string} delegatedUserRoleName
 * @property {string} delegatedUserEmail
 * @property {string | null} invitationExpiresAt
 * @property {string | null} invitationAcceptedAt
 * @property {string | null} invitationRejectedAt
 * @property {string | null} revokedAt
 * @property {string | null} revokedById
 * @property {string | null} revokedByName
 * @property {string | null} expiresAt
 * @property {boolean} active
 */

/**
 * @typedef {object} UserProfile
 * @property {UserDetails} userDetails
 * @property {CphAssignment[]} directAssignments
 * @property {CphDelegation[]} inboundDelegations
 * @property {CphDelegation[]} outboundDelegations
 */

export class IdentityServiceHelperClient {
  #baseUrl
  #apiKey

  /**
   * @param {string} baseUrl
   * @param {string} apiKey
   */
  constructor(baseUrl, apiKey) {
    this.#baseUrl = baseUrl
    this.#apiKey = apiKey
  }

  /**
   * Fetches a user's profile from identity-service-helper.
   *
   * @param {string} userId
   * @returns {Promise<UserProfile>}
   */
  async fetchUserProfile(userId) {
    let result

    try {
      result = await Wreck.get(`users/${userId}/profile`, {
        baseUrl: this.#baseUrl,
        json: true,
        headers: this.#getHeaders()
      })
    } catch (err) {
      throw this.#parseError(err.output?.statusCode, err.data?.payload)
    }

    if (result.res.statusCode >= statusCodes.badRequest) {
      throw this.#parseError(result.res.statusCode, result.payload)
    }

    return result.payload
  }

  #getHeaders() {
    return {
      'x-api-key': this.#apiKey,
      'x-correlation-id': requestContext.get('correlation_id'),
      'x-cdp-request-id': requestContext.get('correlation_id')
    }
  }

  #parseError(statusCode, payload) {
    if (payload?.error?.code) {
      return new Error(`${payload.error.code} - ${payload.error.message}`)
    }
    if (payload?.detail || payload?.title) {
      return new Error(`${payload.status} - ${payload.detail || payload.title}`)
    }
    if (statusCode === statusCodes.unprocessableEntity) {
      return new Error('Validation failed')
    }
    return new Error(`Request failed - ${statusCode}`)
  }
}
