import Wreck from '@hapi/wreck'
import { requestContext } from '@defra/lis-hubs-infra-core'
import { statusCodes } from './constants/status-codes.js'

/**
 * @typedef {object} CphAssociation
 * @property {string} id
 * @property {string} cphNumber
 * @property {string} role
 * @property {string | null} partyId
 * @property {string | null} holdingId
 * @property {string | null} holdingName
 */

/**
 * @typedef {object} UserAccount
 * @property {string} id
 * @property {string | null} subject
 * @property {string} email
 * @property {string | null} firstName
 * @property {string | null} lastName
 * @property {string | null} displayName
 * @property {CphAssociation[]} cphAssociations
 * @property {string | null} associationsRefreshedDate
 * @property {string} lastUpdatedDate
 */

export class KrdsClient {
  #baseUrl
  #clientId
  #clientSecret

  /**
   * @param {string} baseUrl
   * @param {string} clientId
   * @param {string} clientSecret
   */
  constructor(baseUrl, clientId, clientSecret) {
    this.#baseUrl = baseUrl
    this.#clientId = clientId
    this.#clientSecret = clientSecret
  }

  /**
   * Ensures a user account exists for the supplied identity provider
   * claims, called on every successful logon.
   *
   * @param {{ sub?: string | null, email: string, given_name?: string | null, family_name?: string | null }} claims
   * @returns {Promise<UserAccount>}
   */
  async ensureAccount(claims) {
    let result

    try {
      result = await Wreck.post('api/v2/user-accounts', {
        baseUrl: this.#baseUrl,
        json: true,
        payload: claims,
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

  /**
   * Reads a user account by identity provider subject. Read only - no
   * association refresh is performed.
   *
   * @param {string} subject
   * @returns {Promise<UserAccount>}
   */
  async fetchUserAccount(subject) {
    let result

    try {
      result = await Wreck.get(
        `api/v2/user-accounts/${encodeURIComponent(subject)}`,
        {
          baseUrl: this.#baseUrl,
          json: true,
          headers: this.#getHeaders()
        }
      )
    } catch (err) {
      throw this.#parseError(err.output?.statusCode, err.data?.payload)
    }

    if (result.res.statusCode >= statusCodes.badRequest) {
      throw this.#parseError(result.res.statusCode, result.payload)
    }

    return result.payload
  }

  #getHeaders() {
    const credentials = Buffer.from(
      `${this.#clientId}:${this.#clientSecret}`
    ).toString('base64')

    return {
      authorization: `Basic ${credentials}`,
      'x-correlation-id': requestContext.get('correlation_id'),
      'x-cdp-request-id': requestContext.get('correlation_id')
    }
  }

  #parseError(statusCode, payload) {
    if (payload?.detail || payload?.title) {
      return new Error(`${payload.status} - ${payload.detail || payload.title}`)
    }
    if (statusCode === statusCodes.unprocessableEntity) {
      return new Error('Validation failed')
    }
    return new Error(`Request failed - ${statusCode}`)
  }
}
