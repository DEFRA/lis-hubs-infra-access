import { afterEach, expect, test, vi } from 'vitest'

afterEach(() => {
  vi.doUnmock('../../src/constants/roles.json')
  vi.resetModules()
})

test('throws on a circular extends chain', async () => {
  // Arrange
  vi.doMock('../../src/constants/roles.json', () => ({
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
  vi.doMock('../../src/constants/roles.json', () => ({
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

test('throws when a role grants a permission not registered in PERMISSIONS', async () => {
  // Arrange
  vi.doMock('../../src/constants/roles.json', () => ({
    default: {
      'role-a': { permissions: ['lis-perm-not-registered'] }
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
  expect(error?.message).toMatch(
    /Role 'role-a' grants a permission not registered in PERMISSIONS: lis-perm-not-registered/
  )
})
