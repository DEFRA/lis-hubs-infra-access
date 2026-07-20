# Hub Access

The single shared security package for hubs and livestock modules.

Responsibilities:

- OIDC authentication and provider-neutral callback handling
- authentication flow and user session storage
- hub and hub-to-module token handling
- secure cookie and return URL handling
- profile lookup and normalized external identity data
- provider-role translation and LIS permission expansion
- resolve which modules a user may access in a hub
- resolve capabilities for an allowed module
- map raw permissions into runtime capabilities
- enforce least-privilege filtering for hub discovery and navigation

Provider-specific configuration and claim mapping remain in each deployable
hub. Front office uses Defra CI and profile-service roles. Back office uses
Microsoft Entra ID roles and does not call the profile service. Both role
sources are translated into LIS roles and permissions by this package.

For direct public microsite access, the guard canonicalizes both proxied and
direct-port requests to the microsite's configured `basePath` and sends that
relative path to the front-office login route. Relative return URLs prevent an
untrusted host header from becoming an authentication redirect target.

This package should depend on hub facts from `@livestock/hubs-infra-registry`, not on deployable hub policy.

Current implementation notes:

- role definitions live in `src/roles.json` and source mappings live in
  `src/role-mappings.json`
- permissions are derived from translated LIS roles, not trusted from identity
  providers or profile responses
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
