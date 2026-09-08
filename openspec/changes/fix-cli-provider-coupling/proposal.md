# fix-cli-provider-coupling

## Why

The CLI drifted from the foundation spec's facade decision: `ops.rs` and
`main.rs` named `VaultwardenProvider` concretely, and token refresh lived as
an inherent backend method rather than on the `Provider` trait. Adding a
second backend would have touched every ops signature.

## What Changes

- `Provider` trait (core) gains `refresh_session`; moved off the VW inherent
  impl so trait-object callers can rotate tokens.
- `cli/src/registry.rs` becomes the composition root: the ONLY file that
  imports backend crates; `open(scheme, server)` -> `Box<dyn Provider>`.
- `ops.rs` signatures: `&VaultwardenProvider` -> `&dyn Provider` (7 sites).
- `main.rs` dispatches via `registry::open` on ref scheme / session provider.
- `backends` subcommand now lists linked backends (`vw`).

## Impact

No behavior change; pure architecture conformance. All 11 suites green,
clippy clean.
