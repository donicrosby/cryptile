# two-factor-login Specification

## Purpose
TBD - created by archiving change 2026-09-17-add-two-factor-login. Update Purpose after archive.

## Requirements

### Requirement: Two-factor challenge detection

The vaultwarden backend SHALL detect the identity endpoint's two-factor
rejection (HTTP 400, `invalid_grant`, error description `"Two factor
required."`, with offered providers in both the `TwoFactorProviders` array
and `TwoFactorProviders2` map spellings and either key casing) and surface
it to the CLI as a typed `TwoFactorRequired { providers }` error carrying
the decoded provider kinds, never as a generic AUTH failure.

#### Scenario: challenge surfaces typed

- WHEN the password grant is rejected with the two-factor challenge body
- THEN the provider returns `TwoFactorRequired` listing the offered
  providers as core-level tags (totp, email, webauthn, unknown(n))
- AND no retry is attempted by the provider

#### Scenario: unknown provider id decodes safely

- WHEN the challenge body lists a provider id outside the supported set
- THEN the provider decodes it as `unknown(n)` and login fails with a
  remediation hint listing what the CLI supports, without panicking or
  failing to parse the body

#### Scenario: no second factor configured

- WHEN the account has no 2FA enabled and the password grant succeeds
- THEN login completes exactly as before this change, with no new request
  fields sent

### Requirement: Code-based second factor resubmission

The backend SHALL complete login by resubmitting the password grant with
`twoFactorToken` set to the operator-supplied code and `twoFactorProvider`
set to the matching numeric provider id (0 authenticator, 1 email), exactly
once per login attempt, mapping failure to the existing AUTH error class.

#### Scenario: resubmit succeeds

- WHEN `LoginParams` carries a second factor and the resubmitted grant is
  accepted
- THEN the session is sealed with access/refresh tokens and the user key
  exactly as a plain password login

#### Scenario: wrong code fails typed

- WHEN the resubmitted code is rejected
- THEN login fails with the AUTH-class error and exit code 3 and a
  remediation hint naming `--2fa-provider`, `--2fa-code`, and `--2fa-env`
- AND no further resubmission is attempted

### Requirement: WebAuthn second factor via CTAP2 hardware

When built with the `webauthn` cargo feature, the backend SHALL answer a
provider-7 challenge by parsing `challenge` and `allowCredentials` from the
providers2 map entry, deriving RP ID and origin from the configured server
base URL, assembling clientDataJSON per W3C WebAuthn L3, obtaining a CTAP2
assertion over USB or NFC from a hardware authenticator (never a software
passkey), and submitting the assertion JSON as `twoFactorToken` with
`twoFactorProvider=7`. The feature SHALL be off by default and the crate
SHALL build and test identically with and without it; device I/O itself is
exercised only by the manual hardware runbook, not CI.

Round-trip budget: a `login()` call carrying a webauthn second factor MAY
send the password grant bare (to obtain the live challenge) but SHALL then
run the ceremony and resubmit the assertion **within that same call**. The
caller (CLI) has a single-resubmit budget and SHALL never see a
`TwoFactorRequired` for a webauthn challenge it already primed the provider
to answer. Net wire: exactly two token-endpoint calls per successful
webauthn login (bare grant → challenge, assertion resubmit → session), all
inside one `login()` invocation.

#### Scenario: challenge decodes

- WHEN a provider-7 challenge carries `challenge` and `allowCredentials`
- THEN the webauthn module decodes both, derives RP ID and origin from the
  configured server base URL, and assembles clientDataJSON matching the
  W3C WebAuthn L3 shape captured in the pre-implementation fixture

#### Scenario: malformed challenge fails typed

- WHEN the provider-7 map entry lacks `challenge` or `allowCredentials`
- THEN login fails with the AUTH-class error and a remediation hint,
  without panicking

#### Scenario: feature-off build unaffected

- WHEN the crate builds without the `webauthn` feature and the account
  offers only provider 7
- THEN the CLI fails with a remediation hint stating the build lacks
  hardware-key support, and all other login paths behave identically

#### Scenario: webauthn resubmit completes inside one login call

- WHEN `login()` is called with a webauthn second factor and the bare
  password grant returns a provider-7 challenge
- THEN the provider runs the ceremony (or the test seam's stand-in),
  resubmits with `twoFactorProvider=7` and the assertion as
  `twoFactorToken`, and returns a sealed session
- AND the token endpoint sees exactly two calls: the first without 2FA
  fields, the second carrying provider 7 and the token
- AND no `TwoFactorRequired` is returned to the caller for that challenge

#### Scenario: assertion rejected fails typed, not re-challenged

- WHEN the assertion resubmit is rejected with a fresh two-factor challenge
  (e.g. ceremony answered with the wrong credential or a stale challenge)
- THEN login fails with the typed AUTH error identifying the webauthn
  provider leg
- AND no further resubmission is attempted

### Requirement: CLI second-factor flag surface

The CLI SHALL provide `login --2fa-provider totp|email|webauthn`,
`--2fa-code CODE`, and `--2fa-env VAR` such that: an interactive TTY is
prompted for the code; a non-TTY context with no resolution path fails with
exit 3 and a remediation hint naming the flags; webauthn selection requires
no code flag; and the provider choice falls back to the preference order
webauthn → totp → email when unspecified and offered.

#### Scenario: interactive prompt

- WHEN a challenge arrives during interactive `cryptile login` with no
  flags
- THEN the CLI prompts for the code on the TTY, resubmits once, and either
  seals a session or fails with the typed AUTH error

#### Scenario: non-TTY without resolution

- WHEN a challenge arrives in a non-TTY context with neither `--2fa-code`
  nor `--2fa-env`
- THEN the CLI exits 3 with a remediation hint naming the flags
- AND no network resubmission occurs

#### Scenario: machine path

- WHEN `--2fa-env TOTP_CODE` is set and the var holds a valid code
- THEN login completes without any TTY prompt

#### Scenario: provider selection

- WHEN multiple providers are offered and `--2fa-provider` is absent
- THEN the CLI selects webauthn over totp over email when each is
  available in the build

### Requirement: Live two-factor proof stage

The live integration harness SHALL provide a stage that enables
authenticator 2FA on the provisioned service account through the public API
(pyotp-generated seed, never printed beyond length+sha12), proves
`login --2fa-env` end-to-end against the live server, restores the fixture
by disabling 2FA and re-proving plain login, and degrades to a noticed
skip (`SKIP_2FA_LIVE=1`, or server-side rejection of harness enablement)
rather than failing or fabricating a pass.

#### Scenario: live 2FA login

- WHEN the stage runs against the live provisioned Vaultwarden
- THEN `cryptile login --2fa-env` seals a session whose get/export results
  match the plain-login fixture
- AND teardown disables 2FA and plain login works again

#### Scenario: skip path

- WHEN `SKIP_2FA_LIVE=1` is set or the server rejects harness enablement
- THEN the stage logs a notice and overall pass/fail is unaffected

### Requirement: Licensing for CTAP2 dependency

The workspace SHALL gate the CTAP2 client dependency (`webauthn-authenticator-rs`,
MPL-2.0) behind the off-by-default `webauthn` feature, pin its version
exactly per the 0.x dependency policy, and record the MPL-2.0 allowance with
rationale in `deny.toml`, such that `cargo deny check licenses` passes with
the feature enabled and the default build pulls no new license.

#### Scenario: default build unchanged

- WHEN the workspace builds without the webauthn feature
- THEN no MPL-2.0 code is compiled in and the license manifest is unchanged
  from before this change

#### Scenario: featured build license-checked

- WHEN the webauthn feature is enabled and `cargo deny check licenses` runs
- THEN the check passes with the recorded MPL-2.0 clarification

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
