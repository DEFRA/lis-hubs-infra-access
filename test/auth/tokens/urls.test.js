import { expect, test } from 'vitest'

import {
  buildCurrentRequestUrl,
  buildHubLoginUrl,
  buildMicrositeReturnUrl,
  getReturnUrlFromRequest,
  isPublicRequest,
  resolveHubOrigin,
  sanitizeReturnUrl
} from '../../../src/auth/tokens/urls.js'

test('buildCurrentRequestUrl reapplies the forwarded prefix for mounted spokes', () => {
  const request = {
    headers: {
      host: 'localhost:3000',
      'x-forwarded-prefix': '/chicken/move'
    },
    raw: {
      req: {
        url: '/about?step=1'
      }
    },
    path: '/about'
  }

  const url = buildCurrentRequestUrl(request, 3206)

  expect(url.toString()).toBe('http://localhost:3000/chicken/move/about?step=1')
})

test('uses request defaults when reconstructing direct request URLs', () => {
  const request = {
    headers: { 'x-forwarded-prefix': 'cattle/home' },
    raw: { req: {} },
    path: '/summary'
  }

  const url = buildCurrentRequestUrl(request, 3221)

  expect(url.toString()).toBe('http://localhost:3221/cattle/home/summary')
})

test('ignores empty and root forwarded prefixes', () => {
  for (const prefix of ['', '   ', '/']) {
    const url = buildCurrentRequestUrl(
      {
        headers: {
          host: 'hub.example',
          'x-forwarded-proto': 'https',
          'x-forwarded-prefix': prefix
        },
        raw: { req: { url: '/summary' } },
        path: '/summary'
      },
      3221
    )

    expect(url.toString()).toBe('https://hub.example/summary')
  }
})

test('buildMicrositeReturnUrl preserves a proxied deep link as a relative hub path', () => {
  const request = {
    headers: {
      host: 'front-office.lis.defra',
      'x-forwarded-proto': 'https',
      'x-forwarded-prefix': '/cattle/register'
    },
    raw: { req: { url: '/check?reference=123' } },
    path: '/check'
  }
  const options = { port: 3201, basePath: '/cattle/register' }

  const returnUrl = buildMicrositeReturnUrl(request, options)

  expect(returnUrl).toBe('/cattle/register/check?reference=123')
})

test('buildMicrositeReturnUrl canonicalizes direct-port access to its public mount path', () => {
  const request = {
    headers: { host: 'localhost:3201' },
    raw: { req: { url: '/' } },
    path: '/'
  }
  const options = { port: 3201, basePath: '/cattle/register' }

  const returnUrl = buildMicrositeReturnUrl(request, options)

  expect(returnUrl).toBe('/cattle/register')
})

test('builds a hub login URL with a sanitized return path', () => {
  const options = {
    hubOrigin: 'https://hub.example',
    returnUrl: '/cattle/move?step=1'
  }

  const url = buildHubLoginUrl(options)

  expect(url).toBe(
    'https://hub.example/auth/login?returnUrl=%2Fcattle%2Fmove%3Fstep%3D1'
  )
})

test('recognizes only known public request paths', () => {
  const publicPaths = [
    '/favicon.ico',
    '/health',
    '/assets',
    '/assets/app.css',
    '/mounted/assets/app.css'
  ]

  const results = publicPaths.map((path) =>
    isPublicRequest({ path }, '/assets')
  )
  const privateResult = isPublicRequest({ path: '/private' }, '/assets')

  for (const result of results) {
    expect(result).toBe(true)
  }
  expect(privateResult).toBe(false)
})

test('resolves hub origins from host, referer and configured fallback', () => {
  const hubOrigins = ['https://primary.example', 'https://secondary.example']

  expect(
    resolveHubOrigin(
      {
        headers: {
          'x-forwarded-host': 'secondary.example, proxy.internal'
        }
      },
      hubOrigins
    )
  ).toBe('https://secondary.example')
  expect(
    resolveHubOrigin(
      {
        headers: {
          host: 'spoke.internal',
          referer: 'https://secondary.example/cattle'
        }
      },
      hubOrigins
    )
  ).toBe('https://secondary.example')
  expect(
    resolveHubOrigin({ headers: { host: 'spoke.internal' } }, hubOrigins)
  ).toBe('https://primary.example')
})

test('sanitizes unsafe return URLs', () => {
  expect(sanitizeReturnUrl()).toBe('/')
  expect(sanitizeReturnUrl('/safe/path')).toBe('/safe/path')
  expect(sanitizeReturnUrl('//evil.example/path')).toBe('/')
  expect(sanitizeReturnUrl('https://evil.example/path')).toBe('/')
  expect(sanitizeReturnUrl('not a URL')).toBe('/')
  expect(sanitizeReturnUrl('http://localhost:3000/local')).toBe(
    'http://localhost:3000/local'
  )
  expect(sanitizeReturnUrl('http://127.0.0.1:3000/local')).toBe(
    'http://127.0.0.1:3000/local'
  )
  expect(
    getReturnUrlFromRequest({ query: { returnUrl: '//evil.example' } })
  ).toBe('/')
})
