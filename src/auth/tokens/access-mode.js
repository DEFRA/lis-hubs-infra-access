import { MODULES, TAXONOMIES } from '@defra/lis-hubs-infra-registry'
import { HUB_SERVICE_SUBJECT } from './constants.js'

const SUPPORTED_TAXONOMIES = TAXONOMIES
const SPOKES = MODULES.map((module) => ({
  ...module,
  taxonomy: {
    id: module.taxonomy
  }
}))

const accessModeRanks = {
  public: 0,
  'user-session': 1,
  [HUB_SERVICE_SUBJECT]: 2
}
const defaultAccessMode = 'user-session'

function normalizeAccessMode(accessMode) {
  const normalizedAccessMode = accessMode ?? defaultAccessMode

  if (!(normalizedAccessMode in accessModeRanks)) {
    throw new Error(`Unknown access mode: ${normalizedAccessMode}`)
  }

  return normalizedAccessMode
}

/**
 * @param {{ taxonomyAccessMode: string, spokeAccessMode: string }} options
 * @returns {string}
 */
export function resolveAccessMode({ taxonomyAccessMode, spokeAccessMode }) {
  const resolvedTaxonomyAccessMode = normalizeAccessMode(taxonomyAccessMode)
  const resolvedSpokeAccessMode = normalizeAccessMode(
    spokeAccessMode ?? taxonomyAccessMode
  )

  return accessModeRanks[resolvedTaxonomyAccessMode] >=
    accessModeRanks[resolvedSpokeAccessMode]
    ? resolvedTaxonomyAccessMode
    : resolvedSpokeAccessMode
}

/**
 * @param {string} spokeId
 * @returns {object | null}
 */
export function getSpokeById(spokeId) {
  return SPOKES.find((spoke) => spoke.id === spokeId) ?? null
}

/**
 * @param {object} spoke
 * @returns {string}
 */
export function getSpokeAccessMode(spoke) {
  const taxonomy = SUPPORTED_TAXONOMIES.find(
    ({ id }) => id === spoke?.taxonomy?.id
  )

  return resolveAccessMode({
    taxonomyAccessMode: taxonomy?.accessMode,
    spokeAccessMode: spoke?.accessMode
  })
}

/**
 * @param {string} spokeId
 * @returns {string}
 */
export function getCurrentSpokeAccessMode(spokeId) {
  const spoke = getSpokeById(spokeId)

  if (!spoke) {
    return defaultAccessMode
  }

  return getSpokeAccessMode(spoke)
}
