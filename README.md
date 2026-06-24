# Hub Access

Shared package for hub access and capability resolution.

Responsibilities:

- resolve which modules a user may access in a hub
- resolve capabilities for an allowed module
- map raw permissions into runtime capabilities
- enforce least-privilege filtering for hub discovery and navigation

This package should depend on hub facts from `@livestock/hub-registry`, not on deployable hub policy.

Current implementation notes:

- transactional modules such as `register`, `move`, and `death` resolve differently in `front-office` and `back-office`
- `front-office` requires the exact species taxonomy permission, for example `ctt.register`
- `back-office` allows either the exact permission or an elevated `*.manage` permission
- `status` and `home` modules are species-scoped surfaces, so any permission for the species grants access
- platform modules such as permission administration can be modeled with a `type` and unlocked by system permissions such as `system.user`
