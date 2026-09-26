# Proposal: default-fidoh-backend

## Why

Stage 1 (add-fidoh-ceremony-provider) landed the fidoh CTAP2 path as an
opt-in feature with wiremock parity proof that it answers provider 7 with
the exact default-path wire shape. The follow-ups closed the behavioral
gaps the owner's hardware smoke found: add-fidoh-uv-passthrough honors
the server-requested verification posture, and add-fidoh-pin-provider
supplies the PIN provider with typed failure instead of a silent
no-PIN proceed. The named stage-2 follow-up — flip the default ceremony
backend — is this change.

Until the flip, every plain `cargo install cryptile` produces a binary
running the legacy `webauthn-authenticator-rs` stack, the dependency the
project distrusts on design grounds (its unbounded keepalive loop is the
hang class fidoh's budget specifies out of existence). Making the CLI's
default feature set carry fidoh puts the hardened path in every user's
binary while the legacy stack stays reachable as an explicit escape
hatch rather than being deleted before its deprecation window.

## What Changes

- `crates/cli/Cargo.toml`: `[features]` gains `default = ["fidoh"]` —
  plain `cargo build` / `cargo install` produces the fidoh-backed
  binary. The `webauthn` and `fidoh` passthrough features keep their
  names and additve semantics; the legacy stack moves to
  `--no-default-features --features webauthn`.
- Answerability seam: whether an offered `webauthn` second-factor tag
  can be answered moves behind a backend-neutral capability probe on the
  object-safe `Provider` trait (`answers_two_factor`), so the CLI
  resolves hardware offers without naming a backend feature matrix or
  type. The default (fidoh) build answers provider 7; builds with
  neither CTAP2 backend keep today's skip-and-hint behavior.
- Zero behavior change for non-hardware users: every flow that never
  meets a hardware challenge runs identical code, wire shape, and exit
  codes as the pre-flip default build; the PIN source is `None` on a
  non-tty and prompts only when a ceremony's clientPIN acquisition
  demands it (the add-fidoh-pin-provider contract, unchanged).
- Collateral: CI's default gate gains the CTAP2 system-header deps (the
  default build now embeds fidoh's pcsc transport); README documents
  fidoh as the default stack and `webauthn` as the legacy escape hatch;
  one feature-presence test locks the new default with a drift-naming
  failure.

## Impact

- **Specs**: `two-factor-login` MODIFIED (`fidoh-backed WebAuthn
  ceremony provider`, `CLI second-factor flag surface`, `Licensing for
  CTAP2 dependency`) + ADDED (`Default fidoh backend with legacy escape
  hatch`).
- **Code** (when implemented): `crates/cli/Cargo.toml` (the flip),
  `crates/core/src/provider.rs` (default probe on the trait),
  `crates/vaultwarden/src/provider.rs` (probe override + unit test),
  `crates/cli/src/main.rs` (resolver consults the probe),
  `crates/cli/tests/default_backend.rs` (lock test),
  `.github/workflows/ci.yml` (default-job header deps), `README.md`.
- **Invariants preserved**: the CLI never names fidoh or backend
  concrete types (the probe is the seam — no new backend tokens in cli
  source); the legacy path stays byte-identical while fidoh is off;
  fidoh remains self-sufficient and authoritative when both features
  are on; headless runs get `pin_source: None` → typed failure, never a
  hang; the UV-passthrough mapping is unchanged; the `Provider` trait
  stays object-safe; `deny.toml` needs no new entries (fidoh's
  Apache-2.0 git edges are already allow-listed from stage 1, and the
  MPL-2.0 entry still governs the escape hatch).
- **Non-goals**: deleting `webauthn-authenticator-rs` or the `webauthn`
  feature (a later change; the escape hatch is deliberate); unifying
  the no-device exit-code divergence between the paths (explicitly
  deferred in add-fidoh-ceremony-provider's non-goals); changing the
  vaultwarden library's own feature defaults (the lib stays
  feature-neutral; the CLI opts in); any live-server or hardware proof
  (wiremock fixtures only; hardware stays with the manual runbook).
