# lis-hubs-infra-access

Part of the Livestock Information Service (LIS), which lets livestock keepers, owners, agents and
delegates record and manage their animals.

`@defra/lis-hubs-infra-access` is a shared npm package that provides the hapi auth schemes,
sessions and access decisions for LIS hubs and spokes. It handles sign-in with OpenID Connect
(OIDC), the hub session, the hub and service tokens passed to spokes, and the translation of
identity provider roles into LIS roles and permissions.

It deliberately does not hold provider-specific configuration or claim mapping. Each hub keeps its
own: the front office uses Defra CI roles and the back office uses Microsoft Entra ID roles. It
does not decide which modules a hub serves (see
[lis-hubs-infra-registry](https://github.com/DEFRA/lis-hubs-infra-registry)) or forward requests to
spokes (see [lis-hubs-infra-core](https://github.com/DEFRA/lis-hubs-infra-core)).

Used by:

- hubs: [lis-hubs-front-office](https://github.com/DEFRA/lis-hubs-front-office), [lis-hubs-back-office](https://github.com/DEFRA/lis-hubs-back-office)
- spokes: [lis-apps-cattle-home](https://github.com/DEFRA/lis-apps-cattle-home), [lis-apps-cattle-register](https://github.com/DEFRA/lis-apps-cattle-register), [lis-apps-cattle-move](https://github.com/DEFRA/lis-apps-cattle-move), [lis-apps-cattle-death](https://github.com/DEFRA/lis-apps-cattle-death), [lis-apps-sheep-home](https://github.com/DEFRA/lis-apps-sheep-home)
- packages: [lis-infra-ui-services](https://github.com/DEFRA/lis-infra-ui-services)

## Installation

```bash
npm install @defra/lis-hubs-infra-access @defra/lis-hubs-infra-core @defra/lis-hubs-infra-registry @hapi/boom
```

`@defra/lis-hubs-infra-core`, `@defra/lis-hubs-infra-registry` and `@hapi/boom` are peer
dependencies, so the consuming app must install them too. See `package.json` for the supported
versions.

## Usage

### Hapi auth schemes

Hubs and spokes authenticate through two Hapi auth schemes, each registered as
the server's default strategy. Identity is on `request.auth.credentials.user`
(`request.app` carries no auth state); `@defra/lis-infra-ui-services`' nunjucks
context and `demandPermission` read it from there. Routes opt out with
`auth: false` (assets, `/health`) or accept signed-out users with
`auth: { mode: 'try' }` or `auth: { mode: 'optional' }`. A signed-out
`try`/`optional` request, in a hub or a spoke, carries no credentials, so
`caller` isn't available on those requests.

Entry points:

| Import                                        | Exports                                                                                                                                                                               |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@defra/lis-hubs-infra-access/authentication` | `createHubAuth`, `HUB_AUTH_STRATEGY`, `createSpokeAuth`, `SPOKE_AUTH_STRATEGY`, `createOidcClient`, `createHubCookieOptions`, `getHubJwtCookieOptions`, `issueHubJwt`, `verifyHubJwt` |
| `@defra/lis-hubs-infra-access/authorization`  | `PERMISSIONS`, `hasPermission`, `demandPermission`, `resolveAuthorization`, `GLOBAL_CPH_SCOPE`, `AUTHORIZATION_VERSION`                                                               |
| `@defra/lis-hubs-infra-access`                | both of the above as `authentication` and `authorization` namespaces                                                                                                                  |

Prefer the subpath imports: they give plain named imports and simple mocks
(`vi.mock('@defra/lis-hubs-infra-access/authorization')`).

```js
import {
  createSpokeAuth,
  getHubJwtCookieOptions
} from '@defra/lis-hubs-infra-access/authentication'
import {
  hasPermission,
  PERMISSIONS
} from '@defra/lis-hubs-infra-access/authorization'
```

#### Spoke: `createSpokeAuth`

```js
await server.register(
  createSpokeAuth({
    spokeId: 'cattle-home',
    hubOrigins,
    cookieName,
    cookieOptions,
    port,
    basePath,
    secret,
    audience,
    moduleAccess,
    authorize: async (user, request) => true // optional
  })
)
```

Registers the `lis-spoke` scheme as the default strategy. A request:

1. must carry a valid service token in `Authorization: Bearer <token>`, else
   `401 { message: 'Service authentication required' }` in every route mode,
   `public` spokes included;
2. must carry a valid hub JWT cookie, unless the spoke is `public`. Without one,
   a required route redirects to `<hubOrigin>/auth/login?returnUrl=…`, and a
   `try` route continues unauthenticated;
3. then gets `credentials: { user, caller }`, where `caller` is the hub's
   service name.

Authenticated requests are then checked against `moduleAccess` (non-public
spokes) and the optional `authorize` predicate; failing either gives a 403.
The factory throws for an unknown `spokeId` or an invalid `moduleAccess`.

The service token is an AWS STS web identity token, attached by the hub's
proxy in `@defra/lis-hubs-infra-core`. It must:

- be an RS256 JWT signed by a key from `CDP_JWT_JWKS_URI`, issued by
  `CDP_JWT_ISSUER`, with an `exp` claim
- have the audience `lis-apps-<spokeId>`
- name the caller as `lis-hubs-front-office` or `lis-hubs-back-office` in the
  `https://sts.amazonaws.com/` claim's `principal_tags.ServiceName`

`CDP_JWT_ISSUER` and `CDP_JWT_JWKS_URI` must be set when `createSpokeAuth` is
called; the CDP platform provides them. The JWKS is fetched with the built-in
`fetch`, which goes via the CDP proxy through the global dispatcher that
`setupProxy` (`@defra/lis-infra-ui-services`) installs.

#### Hub: `createHubAuth`

```js
await server.register(
  createHubAuth({
    hubId: 'front-office',
    getHubJwtCookieName,
    getCookieOptions,
    getHubJwtConfig,
    resolveAuthSession,
    buildAuthorizationUrl,
    completeAuthorizationCodeGrant,
    buildLogoutUrl,
    loginRoutes,
    notAuthorisedPath: '/auth/access-denied', // optional, defaults to '/auth/not-authorised'
    authorize: async (user, request) => true // optional
  })
)
```

Registers the hub JWT cookie state, the login, `/sso`, `/auth/logout` and
`/signout` routes (all `auth: false`) and the not-authorised route (`auth: try`), plus the `lis-hub-session`
scheme as the default strategy, backed by the yar hub session. A signed-out
user on a required route is redirected to the first login route with
`?returnUrl=<path+search>`; a `try` route continues unauthenticated.
Credentials are `{ user, authorizedSpecies, caller }`, where `caller` is the
hub's own service name (`lis-hubs-<hubId>`), matching the `caller` a spoke
sees. `hubId` is required and must be a registry hub id. The optional `authorize`
predicate runs for authenticated requests only; `false` refuses the request
(see below).

A hub-level refusal keeps authentication and authorisation apart: the user
stays signed in to the hub but is not authorised to use it. `resolveAuthSession`
refuses a login (e.g. a user not on an allow-list) by returning
`{ denied: true }`, and `authorize` refuses a signed-in user by returning
`false`. `authorize` runs on every authenticated request and also in the login
and `/sso` routes before a JWT is minted. Either way no JWT cookie is issued
(any existing one is unset), so no spoke is reachable, and the user is
redirected to `notAuthorisedPath`. A refused
login is stored as a session flagged `refused`, and every later authenticated
request, including the login route, is sent to `notAuthorisedPath` without
re-running the hub's checks, until the user signs out through the normal
`/signout` flow. The identity provider is not involved in the refusal, so no
post-logout redirect URI is needed for it. `notAuthorisedPath` must be a hub
path starting with `/`, and the old `accessDeniedPath` option is rejected.

By default `notAuthorisedPath` is `/auth/not-authorised`, registered by this
plugin with `auth: try`: it renders the `error/not-authorised` view (from
`@defra/lis-infra-ui-services`) with a 403 and `pageTitle`, plus a
`signOutHref` of `/signout` for a signed-in visitor or a `signInHref` of the
first login route for anyone else. A hub that sets its own `notAuthorisedPath`
registers that route itself and should do the same. Spoke-level 403s and
record-level 404s are not affected.

#### Testing routes

Route tests need neither cookies nor service tokens; inject credentials:

```js
await server.inject({
  url: '/',
  auth: {
    strategy: SPOKE_AUTH_STRATEGY,
    credentials: { user, caller }
  }
})
```

The package checks hub facts against `@defra/lis-hubs-infra-registry`. It does not hold hub policy.

When a hub signs a user in, it translates the provider roles into LIS roles. This package turns
those roles into permissions.

### How access decisions work

- role definitions live in `src/authorization/roles/roles.json` and source mappings live in
  `src/authorization/roles/role-mappings.json`
- permissions are derived from translated LIS roles, not trusted from identity
  providers
- hub and hub-to-app JWTs carry LIS roles and an authorization model version,
  but do not carry expanded permissions or holdings
- apps rehydrate permissions locally from the versioned role definitions before
  evaluating `hasPermission` or `demandPermission`
- CPH-scoped role assignments remain scoped when permissions are rehydrated
- `lis-perm-front-office` and `lis-perm-back-office` gate access to the corresponding hub
- species permissions such as `lis-perm-cattle-read` apply across that species
- app permissions such as `lis-perm-cattle-register-admin` apply to a specific species app
- `status` and `home` resolve from the best permission found anywhere on the species
- back-office permission management modules can be modeled with a `type` and unlocked by `lis-perm-user-read`, `lis-perm-user-write`, or `lis-perm-user-admin`

### Environment variables

`createSpokeAuth` reads these. The CDP platform sets them. In lis-dev, the compose files set them.

| Variable           | Used for                                                     |
| ------------------ | ------------------------------------------------------------ |
| `CDP_JWT_ISSUER`   | Expected issuer of service tokens                            |
| `CDP_JWT_JWKS_URI` | Where to fetch the keys that verify service token signatures |

## Prerequisites

- Node.js 24 (see `.nvmrc`, use `nvm use`)
- To check changes against a consuming app: a local clone of [lis-dev](https://github.com/DEFRA/lis-dev) with its one-time setup done

## Setup

### Development

```bash
nvm use
npm install
```

### Test

There are no tools to install beyond `npm install`. Tests use [Vitest](https://vitest.dev/).

## Running in development

This is a library, so it has no server of its own. To try a change in a consuming app without
publishing, link the local copy into the lis-dev stack:

```bash
cd lis-dev
.bin/sideload link hubs/infra-access # every installed copy now points at this repo
.bin/sideload up cattle-home        # optional: run a consumer locally with hot reload
.bin/sideload unlink hubs/infra-access # when done
```

## Running tests

```bash
npm test                 # unit tests
npm run test:coverage    # with coverage
npm run lint             # ESLint
npm run format:check     # Prettier
```

Before releasing a change, also run the tests of each consuming repo against the linked package.

## Pipelines

Build, versioning and publishing run in GitHub Actions (`.github/workflows`) using Cake scripts (`*.cake`):

- **Pull request to `main`**: validate (format, lint, test), Sonar analysis, version check
- **Push to a `feature/` or `hotfix/` branch**: prerelease version and tag
- **Merge to `main`**: release tag, then publish to [npm](https://www.npmjs.com/package/@defra/lis-hubs-infra-access)

Versions come from git tags (SemVer). After a merge, wait for the publish job to finish before bumping the package in consuming repos.

## Branching policy

The repo uses mainline development. Branch from `main` and name the branch:

- `feature/LREG-<ticket>-<short-kebab-description>`
- `hotfix/LREG-<ticket>-<short-kebab-description>`

`LREG` must be uppercase, because the GitHub ruleset rejects other branch names. Rebase onto `main`
rather than merging `main` in.

## Contributing to this project

- Follow the [Defra software development standards](https://github.com/DEFRA/software-development-standards).
- `npm install` sets up a pre-commit hook (Husky) that runs the security audit, format check and lint.
- Open a pull request against `main` using the PR template. CI must pass and the Sonar quality gate must be green before merge.
- Feature branches bump the minor version and hotfix branches the patch version. While the package is on 0.x, a breaking change to the public API ships as a minor version, so call it out in the PR so consumers can update.

## Licence

THIS INFORMATION IS LICENSED UNDER THE CONDITIONS OF THE OPEN GOVERNMENT LICENCE found at:

<http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3>

The following attribution statement MUST be cited in your products and applications when using this information.

> Contains public sector information licensed under the Open Government licence v3

### About the licence

The Open Government Licence (OGL) was developed by the Controller of His Majesty's Stationery Office (HMSO) to enable information providers in the public sector to license the use and re-use of their information under a common open licence.

It is designed to encourage use and re-use of information freely and flexibly, with only a few conditions.
