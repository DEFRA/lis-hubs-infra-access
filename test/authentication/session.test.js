import assert from 'node:assert/strict'
import { test, vi } from 'vitest'

import {
  clearHubAuthFlow,
  clearHubAuthSession,
  createHubAuthFlow,
  getHubAuthFlow,
  getHubAuthSession,
  setHubAuthFlow,
  setHubAuthSession
} from '../../src/authentication/session.js'

function createRequest() {
  const values = new Map()

  return {
    values,
    yar: {
      clear(key) {
        values.delete(key)
      },
      reset: vi.fn(() => values.clear()),
      get(key) {
        return values.get(key)
      },
      set(key, value) {
        values.set(key, value)
      }
    }
  }
}

test('creates an authentication flow using injectable generators', () => {
  const ids = ['state-id', 'nonce-id']
  const flow = createHubAuthFlow({
    returnUrl: '/cattle',
    generateId: () => ids.shift(),
    generateCodeVerifier: () => 'verifier'
  })

  assert.deepEqual(flow, {
    state: 'state-id',
    nonce: 'nonce-id',
    codeVerifier: 'verifier',
    returnUrl: '/cattle'
  })
})

test('stores, retrieves and clears authentication flow state', () => {
  const request = createRequest()
  const flow = { state: 'state-id' }

  assert.equal(getHubAuthFlow(request), null)
  setHubAuthFlow(request, flow)
  assert.equal(getHubAuthFlow(request), flow)
  clearHubAuthFlow(request)
  assert.equal(getHubAuthFlow(request), null)
})

test('stores and retrieves an authenticated session', () => {
  const request = createRequest()
  const session = { sub: 'user-1' }

  assert.equal(getHubAuthSession(request), null)
  setHubAuthSession(request, session)
  assert.equal(getHubAuthSession(request), session)
})

test('clearing a session resets the yar session, including any in-progress flow', () => {
  const request = createRequest()

  setHubAuthSession(request, { sub: 'user-1' })
  setHubAuthFlow(request, { state: 'state-id' })
  clearHubAuthSession(request)

  assert.equal(request.yar.reset.mock.calls.length, 1)
  assert.equal(getHubAuthSession(request), null)
  assert.equal(getHubAuthFlow(request), null)
})

test('clearing a session tolerates requests without yar', () => {
  assert.doesNotThrow(() => clearHubAuthSession({}))
})

test('session helpers tolerate requests without yar where supported', () => {
  assert.equal(getHubAuthFlow({}), null)
  assert.equal(getHubAuthSession({}), null)
  assert.doesNotThrow(() => setHubAuthFlow({}, {}))
  assert.doesNotThrow(() => setHubAuthSession({}, {}))
  assert.doesNotThrow(() => clearHubAuthFlow({}))
})
