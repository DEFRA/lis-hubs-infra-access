# Hub Access

The single shared security package for hubs and livestock modules.

Responsibilities:

- OIDC authentication and provider-neutral callback handling
- authentication flow and user session storage
- hub and hub-to-module token handling
- secure cookie and return URL handling
- provider-role translation and LIS permission expansion
- resolve capabilities for an allowed module
- map raw permissions into runtime capabilities

Provider-specific configuration and claim mapping remain in each deployable
hub. Front office uses Defra CI roles. Back office uses Microsoft Entra ID
roles. Both role sources are translated into LIS roles and permissions by this package.

For direct public microsite access, the spoke auth scheme canonicalizes both proxied and
direct-port requests to the microsite's configured `basePath` and sends that
relative path to the front-office login route. Relative return URLs prevent an
untrusted host header from becoming an authentication redirect target.

## Hapi auth schemes

Hubs and spokes authenticate through two Hapi auth schemes, each registered as
the server's default strategy. Identity is on `request.auth.credentials.user`
(`request.app` carries no auth state); `@defra/lis-infra-ui-services`' nunjucks
context and `demandPermission` read it from there. Routes opt out with
`auth: false` (assets, `/health`) or accept signed-out users with
`auth: { mode: 'try' }` or `auth: { mode: 'optional' }`. A signed-out
`try`/`optional` spoke request carries no credentials, so `caller` isn't
available on those requests.

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

### Spoke: `createSpokeAuth`

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

### Hub: `createHubAuth`

```js
await server.register(
  createHubAuth({
    getHubJwtCookieName,
    getCookieOptions,
    getHubJwtConfig,
    resolveAuthSession,
    buildAuthorizationUrl,
    completeAuthorizationCodeGrant,
    buildLogoutUrl,
    loginRoutes,
    accessDeniedPath: '/auth/access-denied', // optional
    authorize: async (user, request) => true // optional
  })
)
```

Registers the hub JWT cookie state, the login, `/sso`, `/auth/logout` and
`/signout` routes, all with `auth: false`, plus the `lis-hub-session`
scheme as the default strategy, backed by the yar hub session. A signed-out
user on a required route is redirected to the first login route with
`?returnUrl=<path+search>`; a `try` route continues unauthenticated.
Credentials are `{ user, authorizedSpecies }`. The optional `authorize`
predicate runs for authenticated requests only; `false` gives a 403.

`resolveAuthSession` can refuse a login (e.g. a user not on an allow-list) by
returning `{ denied: true }`: the callback then sets no session or JWT and
signs the user out of the identity provider, which returns them to
`accessDeniedPath` (or the hub origin when that isn't set). The hub registers
the `accessDeniedPath` route itself, and the provider must accept it as a
post-logout redirect URI.

### Testing routes

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

This package should depend on hub facts from `@defra/lis-hubs-infra-registry`, not on deployable hub policy.

Current implementation notes:

- role definitions live in `src/authorization/roles/roles.json` and source mappings live in
  `src/authorization/roles/role-mappings.json`
- permissions are derived from translated LIS roles, not trusted from identity
  providers
- hub and hub-to-app JWTs carry LIS roles and an authorization model version,
  but do not carry expanded permissions or holdings
- apps rehydrate permissions locally from the versioned role definitions before
  evaluating `hasPermission`, `hasRole`, `demandPermission`, or `demandRole`
- CPH-scoped role assignments remain scoped when permissions are rehydrated
- `lis-perm-front-office` and `lis-perm-back-office` gate access to the corresponding hub
- species permissions such as `lis-perm-cattle-read` apply across that species
- app permissions such as `lis-perm-cattle-register-admin` apply to a specific species app
- `status` and `home` resolve from the best permission found anywhere on the species
- back-office permission management modules can be modeled with a `type` and unlocked by `lis-perm-user-read`, `lis-perm-user-write`, or `lis-perm-user-admin`
