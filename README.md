# Hub Access

Shared package for hub access and capability resolution.

Responsibilities:

- resolve which modules a user may access in a hub
- resolve capabilities for an allowed module
- map raw permissions into runtime capabilities
- enforce least-privilege filtering for hub discovery and navigation

This package should depend on hub facts from `@livestock/hubs-infra-registry`, not on deployable hub policy.

Current implementation notes:

- raw permissions are expected in the `lis-perm-*` format
- `lis-perm-front-office` and `lis-perm-back-office` gate access to the corresponding hub
- species permissions such as `lis-perm-cattle-read` apply across that species
- app permissions such as `lis-perm-cattle-register-admin` apply to a specific species app
- `status` and `home` resolve from the best permission found anywhere on the species
- back-office permission management modules can be modeled with a `type` and unlocked by `lis-perm-user-read`, `lis-perm-user-write`, or `lis-perm-user-admin`
