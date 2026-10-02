import { createRemoteJWKSet, jwtVerify } from 'jose'

const SIGNING_ALGORITHM = 'RS256'

function assertNonEmptyString(value, name) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${name} must be a non-empty string`)
  }
}

const STS_CLAIM = 'https://sts.amazonaws.com/'

// Only the hubs are accepted as callers.
const ALLOWED_CALLERS = new Set([
  'lis-hubs-front-office',
  'lis-hubs-back-office'
])

/**
 * The issuer and keys come from the platform-provided CDP_JWT_ISSUER and
 * CDP_JWT_JWKS_URI env vars; the audience is the target service's name.
 * Only the two hubs are accepted as callers, by their CDP `ServiceName` tag.
 * @param {{ audience: string }} options
 * @returns {{ verify: (token: string) => Promise<{ serviceName: string }> }}
 */
export function createServiceTokenVerifier({ audience }) {
  assertNonEmptyString(audience, 'audience')

  const issuer = process.env.CDP_JWT_ISSUER
  const jwksUri = process.env.CDP_JWT_JWKS_URI
  if (!issuer?.trim() || !jwksUri?.trim()) {
    throw new Error('CDP_JWT_ISSUER and CDP_JWT_JWKS_URI must be set')
  }
  const jwks = createRemoteJWKSet(new URL(jwksUri))

  return {
    async verify(token) {
      const { payload } = await jwtVerify(token, jwks, {
        issuer,
        audience,
        algorithms: [SIGNING_ALGORITHM],
        requiredClaims: ['exp'],
        maxTokenAge: '15m'
      })

      const serviceName = payload[STS_CLAIM]?.principal_tags?.ServiceName
      if (!ALLOWED_CALLERS.has(serviceName)) {
        throw new Error(`Service token caller '${serviceName}' is not allowed`)
      }

      return { serviceName }
    }
  }
}
