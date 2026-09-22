# Delta for two-factor-login

## MODIFIED Requirements

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
