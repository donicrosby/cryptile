# two-factor-login Delta — add-fidoh-ceremony-provider

## ADDED Requirements

### Requirement: fidoh-backed WebAuthn ceremony provider

When built with the off-by-default `fidoh` cargo feature, the vaultwarden
backend SHALL serve the provider-7 CTAP2 ceremony through the fidoh
library (getAssertion-only v1) instead of `webauthn-authenticator-rs`:
cryptile SHALL retain only provider-7 challenge decoding, RP ID/origin
derivation, clientDataJSON assembly, and VW wire-shape assembly of the
assertion token, handing fidoh a clientDataHash and receiving typed
results; device selection, transport handling, keepalives, and touch
semantics SHALL live inside fidoh. The feature SHALL be self-sufficient
(buildable with or without the `webauthn` feature) and, when both are
enabled, the fidoh path SHALL be authoritative. The existing `webauthn`
feature and `webauthn-authenticator-rs` default path SHALL remain
unchanged until the named stage-2 follow-up flips the default. The CLI
SHALL never name fidoh or backend concrete types — fidoh rides inside
cryptile-vaultwarden only. The no-soft-token policy carries over: the
product feature enables hardware transports only, never fidoh's
soft-token transport.

#### Scenario: fidoh feature serves provider-7 with identical wire shape

- WHEN the crate is built with `--features fidoh` and `login()` is called
  with a webauthn second factor against a provider-7 challenge
- THEN the assertion resubmit carries exactly
  `twoFactorProvider=7` and `twoFactorToken` in the same web-vault
  connector token-JSON form the default path produces (per the
  CAPTURES.md / gauntlet wire contract)
- AND the challenge decode, origin derivation, and clientDataJSON are
  byte-identical to the default path's

#### Scenario: feature matrix builds

- WHEN the crate builds with `--features fidoh` alone, with
  `--features webauthn,fidoh`, and with default features
- THEN all three configurations compile and test green
- AND the default build pulls no fidoh code (feature off by default,
  `webauthn-authenticator-rs` still the default path)

#### Scenario: CLI never names fidoh

- WHEN the workspace builds with the `fidoh` feature enabled
- THEN `crates/cli` contains no reference to fidoh or any backend
  concrete type and resolves webauthn logins through the object-safe
  `Provider` trait exactly as before

#### Scenario: parity against the default path at the ceremony seam

- WHEN the wiremock e2e suite runs the same provider-7 challenge through
  the default path and the fidoh path (each standing in for the ceremony
  at the `with_assertion_hook` debug-only seam)
- THEN both paths emit the same exact two form fields
  (`twoFactorProvider=7`, `twoFactorToken`) on the assertion resubmit,
  with the token-endpoint call count pinned at exactly two inside one
  `login()` and no `TwoFactorRequired` surfaced to the caller

### Requirement: fidoh ceremony budget and hang-freedom

Every fidoh ceremony invocation SHALL carry an explicit, finite budget
(fidoh's single ceremony Deadline) handed in by the cryptile side; the
provider SHALL NOT wrap the ceremony in an indefinite wait. A device
that wedges — never answers, never completes touch — SHALL exhaust the
budget and surface as a typed error within that budget, never as an
indefinite hang. The unbounded-keepalive hang class of the replaced
dependency SHALL be a spec violation of the fidoh path: there is no
code path in which the ceremony waits without bound.

#### Scenario: wedged device fails typed within budget

- WHEN a ceremony starts against a device that never completes (no
  touch, no response) and the ceremony budget elapses
- THEN the fidoh path returns a typed timeout error mapped to the
  transport class (exit 4) with a remediation hint naming the budget
- AND the call returns within a bounded interval, never hanging the CLI

#### Scenario: budget consumes, not extends

- WHEN the ceremony spans multiple fidoh hops (device selection,
  keepalives, touch wait)
- THEN the hops consume the single handed-in budget's remainder
- AND no hop may wait longer than the budget that remains, so total
  ceremony time is bounded by the cryptile-supplied budget

#### Scenario: successful ceremony unaffected

- WHEN the device completes the assertion well within the budget
- THEN the ceremony behaves identically to an unbudgeted one and the
  assertion is submitted as normal

### Requirement: fidoh ceremony error mapping

Fidoh ceremony outcomes SHALL map onto cryptile's exit-code classes:
user decline / user-presence rejection / wrong-credential mismatch and
cryptile-side challenge-decode failures map to the AUTH class (exit 3);
no device found, transport open/enumeration/I-O failure, and ceremony
budget expiry map to the TRANSPORT class (exit 4); internal assembly
failure and ceremony-thread panic map to the SERVER class (exit 4); a
successful assertion maps to exit 0. The mapping SHALL be total over
fidoh's typed ceremony errors — no fidoh error surfaces as an
unclassified string without an exit-code class. The server's rejection
of the assertion resubmit remains AUTH class per the existing
resubmission requirement, unchanged by this mapping.

#### Scenario: user decline maps to auth

- WHEN the fidoh ceremony returns a user-decline outcome (touch refused,
  UP rejected, or the credential in the allowList does not match the
  plugged key)
- THEN login fails with the AUTH-class error (exit 3) and a remediation
  hint naming the expected credential

#### Scenario: device and timeout failures map to transport

- WHEN the fidoh ceremony returns no-device-found, a transport I/O
  error, or budget expiry
- THEN login fails with the TRANSPORT-class error (exit 4) and a
  remediation hint distinguishing missing key from dead key where the
  typed outcome allows

#### Scenario: internal failure maps to server

- WHEN the ceremony thread panics or the assertion blob fails VW
  wire-shape assembly after a successful CTAP2 result
- THEN login fails with the SERVER-class error (exit 4) — never AUTH,
  since credentials and device state were not at fault

#### Scenario: mapping is total

- WHEN any fidoh typed ceremony error variant reaches the provider
- THEN the provider maps it to exactly one exit-code class per the
  mapping above, with no variant falling through to an unclassified
  error
