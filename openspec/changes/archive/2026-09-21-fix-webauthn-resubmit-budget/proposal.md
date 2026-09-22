# Proposal: fix-webauthn-resubmit-budget

## Why

WebAuthn login is broken end-to-end: `cryptile login` on a webauthn-only
account exits 3 with "server still demands a second factor after the
resubmit; refusing to retry" and the hardware key never performs a ceremony.

Root cause is a round-trip budget mismatch between the CLI and the
vaultwarden provider:

- The CLI's login contract is one challenge → one resubmit. A second
  `TwoFactorRequired` is a hard stop (by design, anti-loop).
- The provider, on a `login()` call carrying a webauthn `SecondFactor`,
  strips the factor (`Some((7, _)) → None`) and sends the password grant
  bare "so the challenge reaches the ceremony". The server answers with a
  fresh challenge; only then does the provider run the CTAP2 ceremony and
  resubmit. When that bare grant comes from the CLI's resubmit call, the
  fresh challenge surfaces to the CLI as a *second* `TwoFactorRequired` —
  the budget is burned and the CLI refuses before/when the ceremony path
  returns.

WebAuthn needs two token round-trips (bare grant → challenge → assertion
resubmit); the CLI only allows one. One side has to absorb the extra
round-trip.

## What Changes

- `cryptile-vaultwarden`: when `login()` is called with a webauthn
  `SecondFactor` AND the password grant returns a provider-7 challenge, the
  provider SHALL run the CTAP2 ceremony and resubmit the assertion **within
  the same `login()` call**, returning either a `Session` or a typed error.
  It SHALL NOT surface a `TwoFactorRequired` to the caller for a webauthn
  challenge it was already primed to answer.
- Tests: wiremock e2e asserting the full webauthn login (with the ceremony
  stubbed behind a feature-gated seam) performs exactly two token calls and
  returns a session without the caller resubmitting.
- No CLI changes: the single-resubmit budget stays as-is for code factors.

## Impact

- Specs: `two-factor-login` — MODIFIED requirement "WebAuthn second factor
  via CTAP2 hardware" (round-trip budget pinned) plus one ADDED scenario.
- Code: `crates/vaultwarden/src/provider.rs` login/challenge handling only.
- Users: webauthn login works; totp/email login byte-identical.

## Non-goals

- Threading the challenge body through `TwoFactorRequired` into
  `LoginParams` (the larger core-type change — rejected: it changes
  `cryptile-core` public types and the CLI contract to save one HTTP
  round-trip per login).
- Soft-token/software authenticator support (policy: hardware root of
  trust only).
