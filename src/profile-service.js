/**
 * @param {{ config: object, fetchImpl?: Function }} options
 * @returns {Function}
 */
export function createProfileService({ config, fetchImpl = globalThis.fetch }) {
  if (!config?.get) {
    throw new Error(
      'Profile service requires a config object with a get method'
    )
  }

  if (typeof fetchImpl !== 'function') {
    throw new Error('Profile service requires a fetch implementation')
  }

  return async function fetchUserProfile(user, accessToken = null) {
    const profileService = getProfileServiceConfig(config)

    if (!profileService.url) {
      // TODO: no profile service exists yet, so return an empty profile to let
      // the hubs run locally. Once the profile service exists, an unconfigured
      // URL should be an error again:
      // throw new Error('Profile service is enabled but not configured')
      return buildProfileResponse()
    }

    const headers = {
      accept: 'application/json'
    }

    if (profileService.apiKey) {
      headers[profileService.apiKeyHeader] = profileService.apiKey
    }

    if (accessToken) {
      headers.authorization = `Bearer ${accessToken}`
    }

    const profileUrl = new URL(profileService.url)

    if (user?.sub) {
      profileUrl.searchParams.set('user_sub', user.sub)
    }

    if (user?.email) {
      profileUrl.searchParams.set('user_email', user.email)
    }

    const response = await fetchImpl(profileUrl.toString(), {
      method: 'GET',
      headers
    })

    if (!response.ok) {
      const responseText = await response.text()
      throw new Error(
        `Profile service request failed with ${response.status}: ${responseText}`
      )
    }

    return buildProfileResponse(await response.json())
  }
}

function buildProfileResponse(profile = {}) {
  const roles = normalizeStringArray(profile.roles)
  const permissions = normalizeStringArray(profile.permissions)
  const holdings = Array.isArray(profile.holdings) ? profile.holdings : []

  return {
    roles,
    permissions,
    holdings
  }
}

function normalizeStringArray(values) {
  if (!Array.isArray(values)) {
    return []
  }

  return [
    ...new Set(
      values.filter((value) => typeof value === 'string' && value.length > 0)
    )
  ]
}

function getProfileServiceConfig(config) {
  return {
    url: config.get('profileService.url'),
    apiKey: config.get('profileService.apiKey'),
    apiKeyHeader: config.get('profileService.apiKeyHeader') || 'x-api-key'
  }
}
