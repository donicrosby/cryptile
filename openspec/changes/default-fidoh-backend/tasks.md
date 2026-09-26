# Tasks: default-fidoh-backend

## 1. Spec

- [x] 1.1 Author proposal.md, specs/two-factor-login/spec.md (MODIFIED
      requirements + ADDED requirement), tasks.md
- [x] 1.2 `openspec validate default-fidoh-backend --strict` exits 0

## 2. Capability seam (core)

- [x] 2.1 `crates/core/src/provider.rs`: `Provider` trait gains
      `answers_two_factor(&self, tag: &str) -> bool` with a default
      `false` (code-carrying factors stay resolver-side; only
      hardware/ceremony tags are backend knowledge) — trait stays
      object-safe
- [x] 2.2 `crates/vaultwarden/src/provider.rs`: override returns
      `cfg!(any(feature = "webauthn", feature = "fidoh"))`; unit test
      pins the three-configuration truth table (compile-time cfg, no
      runtime dep added)

## 3. CLI flip

- [x] 3.1 `crates/cli/Cargo.toml`: `default = ["fidoh"]`; `webauthn`
      and bare `fidoh` passthroughs keep their names and semantics;
      comments updated to describe the new default and the escape
      hatch
- [x] 3.2 `crates/cli/src/main.rs` resolver: webauthn answerability
      consults `provider.answers_two_factor("webauthn")` instead of
      `cfg!(feature = "webauthn")`; zero fidoh/webauthn feature tokens
      remain on the decision path (`grep -rn 'cfg(feature' crates/cli/src/`
      clean)
- [x] 3.3 Non-hardware behavior unchanged: all existing CLI tests green
      unmodified (fixture offers totp only; PIN source stays `None`
      headless, lazy prompt on tty)

## 4. Lock test + docs

- [x] 4.1 `crates/cli/tests/default_backend.rs`: single test parses
      `Cargo.toml` (raw string, toml crate NOT added) and asserts
      `default = ["fidoh"]`; failure message names the drift and the
      legacy escape-hatch build command
- [x] 4.2 README: fidoh described as the default stack (plain
      build/install), `webauthn` documented as the legacy escape hatch
      (`--no-default-features --features webauthn`); stage caveat
      paragraph replaced
- [x] 4.3 `.github/workflows/ci.yml`: default `check` job installs
      `libpcsclite-dev libudev-dev pkg-config` (the default build now
      embeds fidoh's pcsc transport); featured matrix legs unchanged

## 5. Gates

- [x] 5.1 `cargo fmt --all` then `cargo fmt --all -- --check` rc=0
- [x] 5.2 `cargo clippy --workspace --all-targets --all-features -- -D warnings` rc=0
- [x] 5.3 Test matrix rc=0: `cargo test --workspace`;
      `--features cryptile-vaultwarden/fidoh`;
      `--features cryptile-vaultwarden/webauthn,fidoh`
- [x] 5.4 `openspec validate default-fidoh-backend --strict` rc=0

## Tasks notes

- Deliberately NOT done here: archiving the change (orchestrator lands
  it after merge); deleting `webauthn-authenticator-rs` (named later
  change); touching the vaultwarden library's own `default = []`
  (library stays feature-neutral; only the CLI binary flips).
- The CI default job needs the CTAP2 system headers from this change
  on; until the workflow file lands, a local default-feature gate run
  needs `libpcsclite-dev libudev-dev pkg-config` present.
