/**
 * @typedef {typeof PERMISSIONS[keyof typeof PERMISSIONS]} Permission
 */

/**
 * Every LIS permission string, keyed by a camelCase name - use these
 * instead of raw permission strings so a typo fails immediately
 * (PERMISSIONS.x is undefined) rather than silently never matching.
 * @type {Record<string, string>}
 */
export const PERMISSIONS = {
  backOffice: 'lis-perm-back-office',
  frontOffice: 'lis-perm-front-office',
  passportApprover: 'lis-perm-passport-approver',

  cattleRead: 'lis-perm-cattle-read',
  cattleWrite: 'lis-perm-cattle-write',
  cattleRegisterRead: 'lis-perm-cattle-register-read',
  cattleRegisterWrite: 'lis-perm-cattle-register-write',
  cattleRegisterAdmin: 'lis-perm-cattle-register-admin',
  cattleHomeRead: 'lis-perm-cattle-home-read',
  cattleHomeWrite: 'lis-perm-cattle-home-write',
  cattleHomeAdmin: 'lis-perm-cattle-home-admin',
  cattleDeathRead: 'lis-perm-cattle-death-read',
  cattleDeathWrite: 'lis-perm-cattle-death-write',
  cattleDeathAdmin: 'lis-perm-cattle-death-admin',
  cattleMoveRead: 'lis-perm-cattle-move-read',
  cattleMoveWrite: 'lis-perm-cattle-move-write',
  cattleMoveAdmin: 'lis-perm-cattle-move-admin',
  cattleNorRead: 'lis-perm-cattle-nor-read',
  cattleNorWrite: 'lis-perm-cattle-nor-write',

  sheepRead: 'lis-perm-sheep-read',
  sheepWrite: 'lis-perm-sheep-write',
  sheepRegisterRead: 'lis-perm-sheep-register-read',
  sheepRegisterWrite: 'lis-perm-sheep-register-write',
  sheepRegisterAdmin: 'lis-perm-sheep-register-admin',
  sheepHomeRead: 'lis-perm-sheep-home-read',
  sheepHomeWrite: 'lis-perm-sheep-home-write',
  sheepHomeAdmin: 'lis-perm-sheep-home-admin',
  sheepDeathRead: 'lis-perm-sheep-death-read',
  sheepDeathWrite: 'lis-perm-sheep-death-write',
  sheepDeathAdmin: 'lis-perm-sheep-death-admin',
  sheepMoveRead: 'lis-perm-sheep-move-read',
  sheepMoveWrite: 'lis-perm-sheep-move-write',
  sheepMoveAdmin: 'lis-perm-sheep-move-admin'
}
