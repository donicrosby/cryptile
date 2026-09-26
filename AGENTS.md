# AGENTS.md — cryptile

One CLI, many secret backends. Rust workspace: `crates/cli` (binary `cryptile`),
`crates/core` (backend-neutral provider traits), `crates/vaultwarden`
(Vaultwarden backend, optional `webauthn` + `fidoh` features).

## Non-negotiables

- **NEVER push.** The push remote is deliberately disabled during agent waves.
  Commit to your lane branch only; the orchestrator lands. If a gate needs a
  push (it doesn't — everything runs locally), report instead of pushing.
- **NEVER commit to `main`.** Lane branches only.
- Never `git add -A`. Stage your files explicitly — siblings may have dirty
  files in shared checkouts.
- Work only in your assigned worktree. Never cd into the main checkout,
  sibling worktrees, or `/workspace/fidoh*`.

## Gates (all must pass before you report done; capture rc WITHOUT pipes)

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace                                  # default features
cargo test --workspace --features cryptile-vaultwarden/fidoh
cargo test --workspace --features cryptile-vaultwarden/webauthn,fidoh
openspec validate --strict                              # when touching openspec/
```

Report each rc verbatim. A gate you didn't run is a gate that failed.

## Spec-first

Behavior changes start as `openspec/changes/<change-id>/` (proposal.md,
specs/ delta, tasks.md), validated `--strict` BEFORE the code lands in the
same change. `openspec/specs/*/spec.md` is the compiled truth — update via
archive, never by hand-editing.

## House style

- Conventional commits, scoped, **em-dash payload**: `feat(cli): fidoh
  passthrough — product binaries can build the fidoh backend`. A hook
  enforces the format.
- MSRV: 1.75 (`rust-version` in the workspace Cargo.toml — keep this line
  and that field in sync when it changes).
- CLI crate must NEVER name fidoh types (backend-neutral seam): zero
  `fidoh` references in `crates/cli/` outside doc comments that say so.
- `crates/vaultwarden` does NO interactive I/O — PIN/secret acquisition is a
  caller-supplied closure (`PinSource`).
- Foreground command cap is 600s — longer runs must go to tracked background
  processes. Never pipe cargo through anything that masks its exit code.

## Environment

- Sandbox toolchain: rustc/clippy current stable; sandbox may be NEWER than
  CI. Don't add features CI's toolchain can't parse; check CI config if unsure.
- Use lane-unique scratch paths (`/tmp/lane-b-*.log`), never generic
  `/tmp/test.log` — sibling agents share this filesystem.
- Avoid parallel `cargo` invocations across worktrees when a sibling is
  mid-gate (file-lock contention). Retry-on-lock is fine; stagger big suites.
- Live Vaultwarden creds live in `/opt/data/.env` (`CRYPTILE_PASSPHRASE`).
  You do NOT need them — never touch the live server, live state dirs
  (`/opt/data/.config/cryptile`), or deployed binaries (`/opt/data/bin/`).
  Your worktree tests use wiremock fixtures only.
