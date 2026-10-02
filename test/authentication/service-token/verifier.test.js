import {
  SignJWT,
  createLocalJWKSet,
  createRemoteJWKSet,
  exportJWK,
  generateKeyPair
} from 'jose'
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
  vi
} from 'vitest'

import { createServiceTokenVerifier } from '../../../src/authentication/service-token/verifier.js'

vi.mock('jose', async (importOriginal) => ({
  ...(await importOriginal()),
  createRemoteJWKSet: vi.fn()
}))

const issuer = 'https://123456789012.tokens.sts.global.api.aws'
const jwksUri = 'https://123456789012.tokens.sts.global.api.aws/jwks'
const audience = 'lis-apps-spoke'
const serviceName = 'lis-hubs-front-office'

describe('createServiceTokenVerifier()', () => {
  let rsa
  let ec
  let otherRsa
  let keySet

  async function sign({
    useOtherKey = false,
    keys = useOtherKey ? otherRsa : rsa,
    alg = 'RS256',
    kid = alg,
    claims = { principal_tags: { ServiceName: serviceName } },
    iss = issuer,
    aud = audience,
    exp = '5m'
  } = {}) {
    const jwt = new SignJWT({ 'https://sts.amazonaws.com/': claims })
      .setProtectedHeader({ alg, kid })
      .setIssuer(iss)
      .setAudience(aud)
      .setIssuedAt()
    if (exp !== null) {
      jwt.setExpirationTime(exp)
    }
    return jwt.sign(keys.privateKey)
  }

  function createVerifier(overrides = {}) {
    return createServiceTokenVerifier({ audience, ...overrides })
  }

  beforeAll(async () => {
    rsa = await generateKeyPair('RS256')
    ec = await generateKeyPair('ES384')
    otherRsa = await generateKeyPair('RS256')

    keySet = createLocalJWKSet({
      keys: [
        { ...(await exportJWK(rsa.publicKey)), kid: 'RS256', alg: 'RS256' },
        { ...(await exportJWK(ec.publicKey)), kid: 'ES384', alg: 'ES384' }
      ]
    })
  })

  beforeEach(() => {
    vi.stubEnv('CDP_JWT_ISSUER', issuer)
    vi.stubEnv('CDP_JWT_JWKS_URI', jwksUri)
    vi.mocked(createRemoteJWKSet).mockImplementation(() => keySet)
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    vi.mocked(createRemoteJWKSet).mockReset()
  })

  test('accepts a valid RS256 token', async () => {
    // Arrange
    const verifier = createVerifier()
    const token = await sign()

    // Act
    let result, error
    try {
      result = await verifier.verify(token)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).toBeUndefined()
    expect(result).toEqual({ serviceName })
  })

  test('accepts a token from the back-office hub', async () => {
    // Arrange
    const verifier = createVerifier()
    const token = await sign({
      claims: { principal_tags: { ServiceName: 'lis-hubs-back-office' } }
    })

    // Act
    const result = await verifier.verify(token)

    // Assert
    expect(result).toEqual({ serviceName: 'lis-hubs-back-office' })
  })

  test('rejects a token signed with an algorithm other than RS256', async () => {
    // Arrange
    const verifier = createVerifier()
    const token = await sign({ keys: ec, alg: 'ES384' })

    // Act
    let result, error
    try {
      result = await verifier.verify(token)
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).toBeUndefined()
    expect(error.message).toMatch(
      /"alg" \(Algorithm\) Header Parameter value not allowed/
    )
  })

  test('rejects a token without an exp claim', async () => {
    // Arrange
    const verifier = createVerifier()
    const token = await sign({ exp: null })

    // Act
    let result, error
    try {
      result = await verifier.verify(token)
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).toBeUndefined()
    expect(error.message).toBe('missing required "exp" claim')
  })

  test.each([
    ['wrong issuer', { iss: 'https://other.example.test' }],
    ['wrong audience', { aud: 'someone-else' }],
    ['expired', { exp: Math.floor(Date.now() / 1000) - 60 }],
    ['bad signature', { useOtherKey: true }]
  ])('rejects a token with %s', async (_name, signOptions) => {
    // Arrange
    const verifier = createVerifier()
    const token = await sign(signOptions)

    // Act
    let result, error
    try {
      result = await verifier.verify(token)
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).toBeUndefined()
    expect(error).toBeInstanceOf(Error)
  })

  test('rejects a token older than 15 minutes', async () => {
    // Arrange
    const verifier = createVerifier()
    const token = await new SignJWT({
      'https://sts.amazonaws.com/': {
        principal_tags: { ServiceName: serviceName }
      }
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'RS256' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 20 * 60)
      .setExpirationTime('1h')
      .sign(rsa.privateKey)

    // Act
    let result, error
    try {
      result = await verifier.verify(token)
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).toBeUndefined()
    expect(error.code).toBe('ERR_JWT_EXPIRED')
  })

  test('creates one JWKS from CDP_JWT_JWKS_URI', async () => {
    // Arrange
    const verifier = createVerifier()

    // Act
    await verifier.verify(await sign())
    await verifier.verify(await sign())

    // Assert
    expect(createRemoteJWKSet).toHaveBeenCalledExactlyOnceWith(new URL(jwksUri))
  })

  test.each([
    ['no sts claim', null, "Service token caller 'undefined' is not allowed"],
    [
      'missing principal tags',
      {},
      "Service token caller 'undefined' is not allowed"
    ],
    [
      'missing ServiceName',
      { principal_tags: {} },
      "Service token caller 'undefined' is not allowed"
    ],
    [
      'caller not allowed',
      { principal_tags: { ServiceName: 'lis-other' } },
      "Service token caller 'lis-other' is not allowed"
    ]
  ])('rejects a token with %s', async (_name, claims, message) => {
    // Arrange
    const verifier = createVerifier()
    const token = await sign({ claims })

    // Act
    let result, error
    try {
      result = await verifier.verify(token)
    } catch (e) {
      error = e
    }

    // Assert
    expect(result).toBeUndefined()
    expect(error.message).toBe(message)
  })

  test.each([
    ['CDP_JWT_ISSUER missing', 'CDP_JWT_ISSUER', undefined],
    ['CDP_JWT_ISSUER empty', 'CDP_JWT_ISSUER', ''],
    ['CDP_JWT_JWKS_URI missing', 'CDP_JWT_JWKS_URI', undefined],
    ['CDP_JWT_JWKS_URI empty', 'CDP_JWT_JWKS_URI', '']
  ])('throws at creation when %s', (_name, variable, value) => {
    // Arrange
    vi.stubEnv(variable, value)

    // Act
    let error
    try {
      createVerifier()
    } catch (e) {
      error = e
    }

    // Assert
    expect(error.message).toBe(
      'CDP_JWT_ISSUER and CDP_JWT_JWKS_URI must be set'
    )
  })

  test('throws at creation when CDP_JWT_JWKS_URI is not a URL', () => {
    // Arrange
    vi.stubEnv('CDP_JWT_JWKS_URI', 'not a url')

    // Act
    let error
    try {
      createVerifier()
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).toBeInstanceOf(TypeError)
    expect(error.message).toMatch(/Invalid URL/)
  })

  test.each([
    ['audience empty', { audience: '' }],
    ['audience missing', {}]
  ])('throws at creation when %s', (_name, options) => {
    // Arrange

    // Act
    let error
    try {
      createServiceTokenVerifier(options)
    } catch (e) {
      error = e
    }

    // Assert
    expect(error).toBeInstanceOf(TypeError)
    expect(error.message).toMatch(/must be a non-empty/)
  })
})
