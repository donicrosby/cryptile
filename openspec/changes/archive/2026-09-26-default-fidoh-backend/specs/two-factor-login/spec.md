# two-factor-login Delta — default-fidoh-backend

## MODIFIED Requirements

### Requirement: CLI second-factor flag surface

The CLI SHALL provide `login --2fa-provider totp|email|webauthn`,
`--2fa-code CODE`, and `--2fa-env VAR` such that: an interactive TTY is
prompted for the code; a non-TTY context with no resolution path fails
with exit 3 and a remediation hint naming the flags; selection of
`webauthn` requires no code flag; and the provider choice falls back to
the preference order webauthn → totp → email when unspecified and
offered. Whether an offered `webauthn` tag is answerable SHALL be
decided by asking the linked backend (a backend-neutral capability
probe on the `Provider` trait), never by the CLI naming a backend
feature matrix or backend concrete type; a build linked to a backend
with no CTAP2 support keeps the skip-and-remediate behavior for
hardware offers. The hardware answer path SHALL carry no code source:
when the probe answers yes, the CLI produces the webauthn second factor
without consulting `--2fa-code`, `--2fa-env`, or the tty.

#### Scenario: interactive prompt

- WHEN a challenge arrives during interactive `cryptile login` with no
  flags
- THEN the CLI prompts for the code on the TTY, resubmits once, and
  either seals a session or fails with the typed AUTH error

#### Scenario: non-TTY without resolution

- WHEN a challenge arrives in a non-TTY context with neither
  `--2fa-code` nor `--2fa-env`, and no offered provider is a
  code-carrying factor the build can answer
- THEN the CLI exits 3 with a remediation hint naming the flags
- AND no network resubmission occurs

#### Scenario: machine path

- WHEN `--2fa-env TOTP_CODE` is set and the var holds a valid code
- THEN login completes without any TTY prompt

#### Scenario: provider selection

- WHEN multiple providers are offered and `--2fa-provider` is absent
- THEN the CLI selects webauthn over totp over email when the linked
  backend answers each

#### Scenario: answerability is probed, not named

- WHEN the resolver evaluates an offered `webauthn` tag in any build
  (default fidoh, legacy webauthn, or neither backend)
- THEN the decision comes from the backend capability probe and the
  CLI source names no backend feature or type in that decision

### Requirement: Licensing for CTAP2 dependency

The workspace SHALL keep the CTAP2 client dependency
(`webauthn-authenticator-rs`, MPL-2.0) gated behind the `webauthn`
cargo feature (the legacy escape hatch after default-fidoh-backend),
pin its version exactly per the 0.x dependency policy, and keep the
MPL-2.0 allowance with rationale in `deny.toml`, such that
`cargo deny check licenses` passes with the feature enabled. The
default CLI build SHALL pull the fidoh stack (Apache-2.0, already
allow-listed from add-fidoh-ceremony-provider) and no MPL-2.0 code;
the default vaultwarden-library build SHALL pull neither CTAP2 stack.

#### Scenario: default build unchanged

- WHEN the vaultwarden crate builds with its own default features
- THEN no MPL-2.0 code is compiled in and the license manifest is
  unchanged from before this change

#### Scenario: featured build license-checked

- WHEN the webauthn feature is enabled and `cargo deny check licenses`
  runs
- THEN the check passes with the recorded MPL-2.0 clarification

### Requirement: fidoh-backed WebAuthn ceremony provider

When built with the `fidoh` cargo feature — now the CLI binary's
default — the vaultwarden backend SHALL serve the provider-7 CTAP2
ceremony through the fidoh library (getAssertion-only v1) instead of
`webauthn-authenticator-rs`: cryptile SHALL retain only provider-7
challenge decoding, RP ID/origin derivation, clientDataJSON assembly,
and VW wire-shape assembly of the assertion token, handing fidoh a
clientDataHash and receiving typed results; device selection,
transport handling, keepalives, and touch semantics SHALL live inside
fidoh. The feature SHALL be self-sufficient (buildable with or without
the legacy `webauthn` feature) and, when both are enabled, the fidoh
path SHALL be authoritative. The legacy `webauthn` feature and
`webauthn-authenticator-rs` path SHALL remain available as the escape
hatch (`--no-default-features --features webauthn` for the CLI
binary), byte-identical while fidoh is off, pending its named
deletion follow-up. The CLI SHALL never name fidoh or backend concrete
types — fidoh rides inside cryptile-vaultwarden only, and the CLI
learns CTAP2 answerability only through the backend-neutral capability
probe. The no-soft-token policy carries over: the product feature
enables hardware transports only, never fidoh's soft-token transport.

With fidoh beta.1 (add-client-pin), the provider SHALL accept an
optional PIN provider (`fidoh_core::pin::PinProviderHandle`) on the
assertion entry point and thread it into the ceremony input; the
vaultwarden library itself SHALL NOT perform I/O to obtain a PIN. The
provider SHALL be invoked only when the ceremony's clientPIN
acquisition demands it (server-requested verification with a PIN-set
key); flows that never acquire a PIN (`Discouraged` posture, PIN-less
keys) SHALL NOT invoke it. When no provider is supplied and
acquisition is demanded, the ceremony SHALL fail typed (`PinRequired`)
rather than degrade to an unverified assertion. A default-CLI (fidoh)
build changes none of this: the CLI supplies the PIN source from the
tty when interactive, `None` when headless — exactly as the opt-in
builds already did.

#### Scenario: fidoh feature serves provider-7 with identical wire shape

- WHEN the crate is built with `--features fidoh` and `login()` is
  called with a webauthn second factor against a provider-7 challenge
- THEN the assertion resubmit carries exactly `twoFactorProvider=7`
  and `twoFactorToken` in the same web-vault connector token-JSON form
  the default path produces (per the CAPTURES.md / gauntlet wire
  contract)
- AND the challenge decode, origin derivation, and clientDataJSON are
  byte-identical to the legacy path's

#### Scenario: feature matrix builds

- WHEN the crate builds with `--features fidoh` alone, with
  `--features webauthn,fidoh`, and with default features
- THEN all three configurations compile and test green
- AND the vaultwarden library's default build still pulls no fidoh
  code (the library's own default features stay empty; only the CLI
  binary opts in by default)

#### Scenario: CLI never names fidoh

- WHEN the workspace builds with the `fidoh` feature enabled
- THEN `crates/cli` contains no reference to fidoh or any backend
  concrete type and resolves webauthn logins through the object-safe
  `Provider` trait exactly as before

#### Scenario: parity against the default path at the ceremony seam

- WHEN the wiremock e2e suite runs the same provider-7 challenge
  through the legacy path and the fidoh path (each standing in for the
  ceremony at the `with_assertion_hook` debug-only seam)
- THEN both paths emit the same exact two form fields
  (`twoFactorProvider=7`, `twoFactorToken`) on the assertion resubmit,
  with the token-endpoint call count pinned at exactly two inside one
  `login()` and no `TwoFactorRequired` surfaced to the caller

#### Scenario: provider threads into the ceremony input

- WHEN the fidoh path builds the beta.1 `GetAssertionExchange`
- THEN the optional PIN provider field carries the caller-supplied
  handle (or `None`), and the raw pinUvAuth fields stay `None`
  (acquisition is fidoh's job; protocol preference order is the
  authenticator's)

#### Scenario: provider is lazy

- WHEN the server's challenge says `discouraged`, or the plugged key
  advertises no PIN capability
- THEN the provider closure is never invoked and no prompt appears

#### Scenario: no provider and PIN demanded fails typed

- WHEN clientPIN acquisition is demanded and no provider is wired
  (headless run on the default-CLI build)
- THEN login fails with the AUTH-class error and a remediation hint
  naming `PinRequired` (set a key PIN, or run interactively)

#### Scenario: default build is the fidoh build

- WHEN the CLI binary is built with plain `cargo build` /
  `cargo install` (no feature flags)
- THEN the fidoh path is compiled in and answers provider-7
  challenges, per the capability probe
- AND a non-hardware login (no challenge, or code-based factors) is
  wire- and exit-code-identical to the pre-flip default build

#### Scenario: legacy escape hatch builds and stays byte-identical

- WHEN the CLI binary is built with
  `--no-default-features --features webauthn`
- THEN the legacy `webauthn-authenticator-rs` ceremony is the provider-7
  path, byte-identical to the pre-flip opt-in builds
- AND the CLI feature list still carries bare `fidoh` as a working
  passthrough (`--no-default-features --features fidoh`)
