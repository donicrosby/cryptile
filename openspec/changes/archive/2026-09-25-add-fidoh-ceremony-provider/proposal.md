# Proposal: add-fidoh-ceremony-provider

## Why

The WebAuthn second factor (provider 7) currently rides
`webauthn-authenticator-rs`, which the project distrusts on design grounds:
an unbounded keepalive loop (`// TODO: maybe time out at some point` in its
`usb/mod.rs`) that can hang the CLI forever on a wedged device,
parallel-transport races where the wrong device can win the ceremony, and
no first-class FIDO-over-CCID. Cryptile works around these from outside
(the `tokio::time::timeout` wrap in `perform_assertion`, the hardware
runbook's LED triage) rather than fixing them — the fixes live in a
dependency we do not control.

`fidoh` (github.com/donicrosby/fidoh) is the owner's own cleanroom CTAP2.1
client library — MSRV 1.75, no_std core, typed errors, a single
ceremony-wide Deadline budget where an unbounded wait is a spec violation,
and getAssertion-only v1 scoped exactly to cryptile's need. Its spec set is
complete and validator-green; implementation is landing crate by crate.

This change is **stage 1 of a two-stage cutover**: fidoh lands as an
opt-in cargo feature alongside the existing path, with wiremock e2e parity
proof that the fidoh path answers the same challenge with the same wire
shape. The default path is untouched; no user-visible behavior moves until
stage 2 flips the default and deletes `webauthn-authenticator-rs`.

## What Changes

- New opt-in cargo feature `fidoh` on `cryptile-vaultwarden`, off by
  default, self-sufficient (buildable with or without the existing
  `webauthn` feature). When enabled, the provider-7 ceremony is served by
  the fidoh-backed path; when both features are enabled, the fidoh path is
  authoritative.
- On the fidoh path, `webauthn.rs` keeps only what cryptile owns:
  provider-7 challenge decode, RP ID/origin derivation, clientDataJSON
  assembly (it stays in cryptile; fidoh receives only a clientDataHash),
  and VW wire-shape assembly of the assertion token. Device selection,
  transport handling, keepalives, and touch move into fidoh; cryptile
  consumes typed results.
- Every fidoh ceremony call carries an explicit budget (fidoh's single
  Deadline). A wedged device yields a typed timeout mapped to exit 4 —
  the unbounded-keepalive hang class is specified out of existence rather
  than wrapped around.
- Typed error mapping pinned: fidoh ceremony outcomes map onto cryptile's
  exit-code classes — user decline / wrong credential → 3 (auth); no
  device, transport I/O, budget expiry, internal assembly → 4 (transport).
- Wiremock e2e parity: `provider_e2e.rs` (through the existing
  `with_assertion_hook` debug-only seam) gains coverage proving the fidoh
  path emits the exact `twoFactorProvider=7` / `twoFactorToken` form
  fields with the token-endpoint call count pinned (exactly two per
  webauthn login, inside one `login()`), the same contract the default
  path is already held to.
- `deny.toml` records the deliberate dependency-policy deviation: an
  in-house git dependency (Apache-2.0) replacing an ecosystem crate.

## Impact

- **Specs**: extends `two-factor-login` (ADDED requirements only — the
  existing WebAuthn requirement, its round-trip budget, and the CTAP2
  licensing requirement keep governing the default path unchanged).
- **Code** (when implemented): `crates/vaultwarden/Cargo.toml` (feature +
  optional dep), `crates/vaultwarden/src/webauthn.rs` (fidoh-backed
  ceremony entry), `crates/vaultwarden/src/provider.rs` (routing),
  `deny.toml`, `crates/vaultwarden/tests/provider_e2e.rs` (parity tests),
  README feature notes.
- **Invariants preserved**: fidoh rides inside `cryptile-vaultwarden`
  only; the `Provider` trait stays object-safe and untouched; the CLI
  never names fidoh types; the assertion blob stays a `SecretString`;
  the no-soft-token policy carries over (hardware transports only —
  fidoh's soft-token transport is never enabled by the product feature);
  tokio current_thread compatibility holds via fidoh-tokio (tokio 1.x).
- **CI**: `cargo deny check` gains one allow-listed git source with
  rationale; the gate matrix adds `--features fidoh` runs alongside the
  unchanged default runs.

## Non-goals

- **Stage 2 (named follow-up change, not authored here)**: flip the
  default ceremony path to fidoh, delete `webauthn-authenticator-rs` and
  the old `webauthn` feature shape, unify the no-device exit-code mapping
  (stage 1 intentionally diverges — see design.md), and retire the
  MPL-2.0 deny.toml entry.
- Any change to the default path's behavior, wire shape, or exit codes;
  the no-device divergence on the fidoh path is additive only.
- CLI surface changes: `--2fa-provider webauthn` selection, remediation
  hints, and the single-resubmit budget are untouched.
- Any non-getAssertion fidoh surface (clientPIN, credential management,
  large blobs, hmac-secret) — fidoh v1 scope, cited from its own spec
  set, not restated here.
- Live-hardware proof: stays with the manual hardware runbook; stage-1 CI
  proof is the wiremock seam parity suite.
- Dropping the outer-timeout wrap on the legacy path: that is stage 2's
  deletion, not stage 1's business.
