/**
 * @param {{ config: object, fetchImpl?: Function }} options
 * @returns {Function}
 */
export function createHoldingService({ config, fetchImpl = globalThis.fetch }) {
  if (!config?.get) {
    throw new Error('Holding service requires a config object with a get method')
  }

  if (typeof fetchImpl !== 'function') {
    throw new Error('Holding service requires a fetch implementation')
  }

  return async function fetchHoldingProfile(holding) {
    const holdingService = getHoldingServiceConfig(config)

    if (!holdingService.url) {
      throw new Error('Holding service is not configured')
    }

    const headers = { accept: 'application/json' }

    if (holdingService.apiKey) {
      headers[holdingService.apiKeyHeader] = holdingService.apiKey
    }

    const holdingUrl = new URL(holdingService.url)
    holdingUrl.searchParams.set('holding', holding)

    const response = await fetchImpl(holdingUrl.toString(), {
      method: 'GET',
      headers
    })

    if (!response.ok) {
      const responseText = await response.text()
      throw new Error(
        `Holding service request failed with ${response.status}: ${responseText}`
      )
    }

    return response.json()
  }
}

function getHoldingServiceConfig(config) {
  return {
    url: config.get('holdingService.url'),
    apiKey: config.get('holdingService.apiKey'),
    apiKeyHeader: config.get('holdingService.apiKeyHeader') || 'x-api-key'
  }
}
