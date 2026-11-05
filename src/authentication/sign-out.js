import { logger } from '@defra/lis-hubs-infra-core'

import { clearHubAuthSession } from './session.js'

// The CSRF plugin's name, which keys its route options and request.plugins.
// Must match CSRF_PLUGIN_NAME in @defra/lis-infra-ui-services/csrf, which
// depends on this package, so this one cannot import it.
export const CSRF_PLUGIN_NAME = 'lis-csrf'

// The hubs set their CSP with Blankie (registered under this name), which
// cannot widen one directive for one route: its route options replace the
// whole policy, and are fixed when the route is registered.
const CSP_PLUGIN_NAME = 'blankie'
const CSP_HEADER = 'content-security-policy'
// Keys the sign-out origins on the confirmation page's response.
const RESPONSE_PLUGIN_KEY = 'lis-hub-auth-sign-out'

// The shared layout's header Sign out links here, as does the not-authorised
// page (see createNunjucksContextBuilder's logoutUrl default).
export const SIGN_OUT_PATH = '/signout'
// The sign-out path before the confirmation page, which old links may still
// point at.
const LEGACY_SIGN_OUT_PATH = '/auth/logout'

/**
 * Sign out is a POST, so another site cannot sign a user out with a link or
 * an image. It is `auth: false`, so the hub-wide refusal check does not send
 * a refused user away from it, and the CSRF plugin's default checks (origin
 * and token, the token read from the session) apply.
 * @param {object} options
 * @param {Function} options.buildLogoutUrl - Builds the identity provider's end-session URL.
 * @returns {object} the route's options and handler
 */
function createLogoutController({ buildLogoutUrl }) {
  return {
    options: {
      auth: false,
      plugins: {
        // A failed check is a session that has already ended (no token left)
        // or a forged request: either way nothing is signed out, and the
        // user lands on the home page rather than a 403.
        [CSRF_PLUGIN_NAME]: { failAction: (_request, h) => h.redirect('/') }
      }
    },
    async handler(request, h) {
      // Build the logout URL while the session is still alive (it reads the
      // id token for id_token_hint), but invalidate the session in `finally`
      // so a failure building the URL cannot leave the session replayable.
      // Resetting the session also drops the hub JWT and CSRF token it holds.
      try {
        const logoutUrl = await buildLogoutUrl(request)

        return h.redirect(logoutUrl)
      } finally {
        clearHubAuthSession(request)
      }
    }
  }
}

/**
 * A GET never signs out, as any site could send one. A signed-in user (the
 * plugin issues a token only to a signed-in session, and signing out resets
 * the session) is asked to confirm with the POST form; anyone else goes home.
 * The page's CSP form-action also allows the origins the sign-out redirects
 * through, as browsers hold each redirect after the form post to it.
 * @param {object} options
 * @param {(request: object) => Promise<string[]>} options.getLogoutOrigins - The origins the sign-out passes through.
 * @returns {object} the hapi route
 */
function createSignOutConfirmationRoute({ getLogoutOrigins }) {
  return {
    method: 'GET',
    path: SIGN_OUT_PATH,
    options: {
      auth: false
    },
    async handler(request, h) {
      if (!request.plugins[CSRF_PLUGIN_NAME]?.token) {
        return h.redirect('/')
      }

      const logoutOrigins = await getLogoutOriginsOrNone(
        getLogoutOrigins,
        request
      )
      // The view comes from @defra/lis-infra-ui-services, which every hub
      // registers, and reads csrfToken from the view context.
      const response = h.view('auth/sign-out', {
        pageTitle: 'Are you sure you want to sign out?',
        signOutHref: SIGN_OUT_PATH
      })
      response.plugins[RESPONSE_PLUGIN_KEY] = { logoutOrigins }

      return response
    }
  }
}

/**
 * The page still renders when discovery fails, with form-action left as
 * 'self'. The sign-out post then resets the session as usual; only the
 * browser's redirect to the identity provider may be refused.
 * @param {(request: object) => Promise<string[]>} getLogoutOrigins
 * @param {object} request
 * @returns {Promise<string[]>}
 */
async function getLogoutOriginsOrNone(getLogoutOrigins, request) {
  try {
    return await getLogoutOrigins(request)
  } catch (error) {
    logger.error(
      error,
      'Sign-out origins unavailable, so the sign-out page CSP is not widened'
    )

    return []
  }
}

/**
 * Appends sources to a policy's form-action directive, leaving every other
 * directive as it is. A policy without form-action does not restrict form
 * posts (it does not fall back to default-src), so it is left alone.
 * @param {string} policy
 * @param {string[]} sources
 * @returns {string}
 */
export function addFormActionSources(policy, sources) {
  return policy
    .split(';')
    .map((directive) =>
      directive.trim().split(/\s+/)[0].toLowerCase() === 'form-action'
        ? [directive.trimEnd(), ...sources].join(' ')
        : directive
    )
    .join(';')
}

/**
 * Widens form-action on the confirmation page only, once the hub's CSP
 * plugin has set the header.
 * @param {object} server - The hapi server (or plugin realm) to extend.
 */
export function allowSignOutFormAction(server) {
  server.ext(
    'onPreResponse',
    (request, h) => {
      const { response } = request
      const logoutOrigins =
        response?.plugins?.[RESPONSE_PLUGIN_KEY]?.logoutOrigins

      if (response.isBoom || !logoutOrigins?.length) {
        return h.continue
      }

      // response.header() stores names lowercased, but Blankie 5 assigns
      // `Content-Security-Policy` into response.headers directly, so the
      // name is looked up in any case and the value replaced under that same
      // name: response.header() would add a second, lowercased entry.
      const headerName = Object.keys(response.headers).find(
        (name) => name.toLowerCase() === CSP_HEADER
      )
      const policy = headerName && response.headers[headerName]

      if (typeof policy !== 'string') {
        return h.continue
      }

      response.headers[headerName] = addFormActionSources(policy, logoutOrigins)

      return h.continue
    },
    { after: [CSP_PLUGIN_NAME] }
  )
}

/**
 * @param {object} options
 * @param {Function} options.buildLogoutUrl - Builds the identity provider's end-session URL.
 * @param {(request: object) => Promise<string[]>} options.getLogoutOrigins - The origins the sign-out passes through.
 * @returns {object[]} `POST /signout`, its `GET` confirmation, and `GET /auth/logout`, which redirects to it
 */
export function createSignOutRoutes({ buildLogoutUrl, getLogoutOrigins }) {
  return [
    {
      method: 'POST',
      path: SIGN_OUT_PATH,
      ...createLogoutController({ buildLogoutUrl })
    },
    createSignOutConfirmationRoute({ getLogoutOrigins }),
    {
      method: 'GET',
      path: LEGACY_SIGN_OUT_PATH,
      options: {
        auth: false
      },
      handler(_request, h) {
        return h.redirect(SIGN_OUT_PATH)
      }
    }
  ]
}
