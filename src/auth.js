export { createOidcClient } from './authentication/oidc.js'

export {
  createHubAuthPlugin,
  createHubCookieOptions
} from './authentication/plugin.js'

export {
  clearHubAuthFlow,
  clearHubAuthSession,
  createHubAuthFlow,
  getHubAuthFlow,
  getHubAuthSession,
  setHubAuthFlow,
  setHubAuthSession
} from './authentication/session.js'

export {
  buildCurrentRequestUrl,
  buildMicrositeReturnUrl,
  buildHubLoginUrl,
  createAuthGuard,
  createSpokeGuard,
  getCurrentSpokeAccessMode,
  getHubJwtCookieOptions,
  getHubJwtPayloadFromRequest,
  getSpokeAccessMode,
  getSpokeById,
  getReturnUrlFromRequest,
  issueHubJwt,
  isPublicRequest,
  resolveAccessMode,
  resolveHubOrigin,
  sanitizeReturnUrl,
  verifyHubJwt
} from './authentication/tokens/index.js'

export {
  AUTHORIZATION_VERSION,
  demandPermission,
  GLOBAL_CPH_SCOPE,
  hasPermission,
  hydrateAuthorization,
  PERMISSIONS,
  resolveAuthorization
} from './authorization/index.js'

export { createModuleAccessGuard } from './module-access/index.js'
