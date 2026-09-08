# Tasks

- [x] 1.1 `Provider::session_expiry` default trait method (core), returning `None`
- [x] 1.2 `VwSession.expires_at: Option<u64>` (`#[serde(default)]`), set at login and refresh; VW implements `session_expiry`
- [x] 1.3 `ops::ensure_fresh` — 300s margin, refresh once, non-fatal on failure; wired into get/list/list-items/export
- [x] 1.4 Tests: refresh sets `expires_at`; legacy handle (no `expires_at`) reports `None`; e2e proves a near-expiry sealed session triggers a refresh grant before sync
- [x] 1.5 Spec deltas (Token lifecycle scenarios; redaction amendment) + delete `core::Redaction`
- [x] 1.6 Gates: fmt, clippy -D warnings, cargo test --workspace, openspec validate --strict
