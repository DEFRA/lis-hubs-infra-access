import { afterEach, expect, test, vi } from 'vitest'

afterEach(() => {
  vi.doUnmock('../../src/roles.json')
  vi.resetModules()
})

test('throws on a circular extends chain', async () => {
  // Arrange
  vi.doMock('../../src/roles.json', () => ({
    default: {
      'role-a': { extends: ['role-b'] },
      'role-b': { extends: ['role-a'] }
    }
  }))

  // Act
  let error
  try {
    await import('../../src/authorization/roles-loader.js')
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toMatch(/Circular role extends chain detected/)
})

test('throws on an unknown role in an extends chain', async () => {
  // Arrange
  vi.doMock('../../src/roles.json', () => ({
    default: {
      'role-a': { extends: ['unknown-role'] }
    }
  }))

  // Act
  let error
  try {
    await import('../../src/authorization/roles-loader.js')
  } catch (e) {
    error = e
  }

  // Assert
  expect(error).toBeInstanceOf(Error)
  expect(error?.message).toMatch(/Unknown role in extends chain: unknown-role/)
})
