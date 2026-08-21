/** @import { Request, ResponseToolkit } from '@hapi/hapi' */
import { getHubAuthSession } from '../session.js'
import { getAuthorizedSpecies } from '../../module-access.js'
import { hydrateAuthorization } from '../../authorization.js'

/**
 * The onPreAuth server extension that hydrates the hub's authorization
 * and authorized species onto every request.
 * @param {Request} request
 * @param {ResponseToolkit} h
 * @returns {symbol} h.continue
 */
export function preAuthExtension(request, h) {
  const authSession = getHubAuthSession(request)
  request.app.hubAuth = authSession ? hydrateAuthorization(authSession) : null
  request.app.authorizedSpecies = getAuthorizedSpecies(request.app.hubAuth)

  return h.continue
}
