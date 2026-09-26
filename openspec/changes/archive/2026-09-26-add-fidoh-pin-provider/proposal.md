# Proposal: add-fidoh-pin-provider

## Why

fidoh beta.1 (435a774) shipped clientPIN acquisition for getAssertion:
when the server asks for user verification (`preferred`/`required` via
add-fidoh-uv-passthrough) and the plugged key has a PIN set, the ceremony
now demands a PIN through the `PinProvider` seam — and returns typed
`PinRequired` when no provider is wired. The owner's hardware smoke bug
("webauthn didn't ask pin when I tapped my key") is therefore half-fixed
on the fidoh side: bumping cryptile's rev pin without wiring a provider
would turn the silent no-PIN proceed into a typed `PinRequired` failure.
This change completes the other half: cryptile supplies the provider and
classifies the new typed errors.

## What Changes

- `crates/vaultwarden/src/webauthn.rs` (fidoh path only):
  `fidoh_perform_assertion` accepts an optional
  `PinProviderHandle` and threads it into the v2
  `GetAssertionExchange` (`pin_provider`; `pin_uv_auth` and
  `pin_uv_auth_protocol` stay `None` — acquisition is fidoh's job,
  protocol preference order is the authenticator's). The library stays
  I/O-free: it never prompts, it only invokes the caller's closure.
- Error mapping (keeps the total mapping contract): fidoh v2's PIN-class
  ceremony errors map to exit-code classes —
  `PinRequired`, `PinNotSet`, `PinTooLong`, `IncorrectPin` (retries
  exhausted), `PinBlocked`, `PinAuthBlocked` → AUTH class (exit 3,
  remediation hint in the message); `PinProviderFailed` → TRANSPORT
  class (exit 4; caller-side I/O, not the user's authentication).
- `crates/cli` login flow: when the fidoh path runs interactively
  (a tty is available), construct the provider from the existing
  `rpassword` prompt helper ("YubiKey PIN: "); headless runs (no tty)
  pass `None` — acquisition then fails typed `PinRequired` → AUTH
  instead of blocking on an unreadable prompt. The closure is lazy:
  `Discouraged` flows and PIN-less keys never invoke it, so agent
  workflows (`--passphrase-env` style) never see a prompt.
- `crates/vaultwarden/Cargo.toml`: fidoh git deps `7dd03e8` → `435a774`,
  `0.1.0-alpha.1` → `0.1.0-beta.1`.
- Tests: the mapping function gains unit tests for every new variant
  (totality lock); the existing wiremock parity e2e stays green
  (its challenge is `discouraged`, provider never invoked).

## Impact

- Affected specs: `two-factor-login` (MODIFIED:
  `fidoh-backed WebAuthn ceremony provider`,
  `fidoh ceremony error mapping`)
- Affected code: `crates/vaultwarden/src/webauthn.rs`, the CLI login
  flow that calls it, `crates/vaultwarden/Cargo.toml` (+lock)
