# Proposal: add-two-factor-login

## Why

The Vaultwarden service account cryptile authenticates as currently **cannot
have 2FA enabled** — the password grant is rejected with a two-factor
challenge the CLI cannot answer, so the account runs single-factor on an
internet-reachable server (bw.jeansburger.net). This change makes `cryptile
login` able to complete the second-factor leg, closing that gap:

- TOTP (provider 0) and email (provider 1) codes via TTY prompt, `--2fa-code`,
  or `--2fa-env VAR` (machine provisioning, symmetric with `--passphrase-env`).
- WebAuthn (provider 7) via a USB/NFC CTAP2 security key, compile-time featured.

Clean-room note: wire shapes in this change are pinned exclusively to the
repo's sanctioned gold sources — rbw (MIT), goldwarden (MIT), RFC 6238, W3C
WebAuthn L3 — plus byte-level captures of our own live server. No Vaultwarden
AGPL implementation code was consulted (an earlier session briefly fetched
Vaultwarden sources into agent context before being stopped; that material is
excluded from this spec and every wire claim below re-pins to a gold source or
a live-capture task).

## What Changes

- `cryptile-core`: `LoginParams` gains an optional second-factor payload
  (`TwoFactor { provider_tag, code }`, code as `SecretString`); provider error
  taxonomy gains a typed `TwoFactorRequired { providers }` carrying decoded
  provider kinds. Core stays backend-agnostic (tags like `totp`/`email`, not
  VW provider numbers).
- `cryptile-vaultwarden`: parse the identity 400 `invalid_grant` /
  `"Two factor required."` body (both `TwoFactorProviders` array and
  `TwoFactorProviders2` config-map spellings, both key casings), resubmit the
  password grant with `twoFactorToken` + `twoFactorProvider`; new `webauthn`
  cargo feature adding challenge parsing + assertion assembly + device I/O
  via the `webauthn-authenticator-rs` crate (MPL-2.0).
- `cryptile` CLI: `login` retry loop — on `TwoFactorRequired` resolve the
  factor (provider preference webauthn→totp→email, overridable with
  `--2fa-provider`), prompt on TTY, else require `--2fa-code`/`--2fa-env`,
  else exit 3 with a remediation hint naming the flags.
- Tests/fixtures: Python oracle emits 2FA error bodies; wiremock e2e for
  detect/resubmit/reject paths; live harness gains a final stage that enables
  authenticator 2FA on the provisioned account via the public API and proves
  `--2fa-env` login end-to-end. Manual hardware-key stage documented.
- `deny.toml`: allow MPL-2.0 (currently unmapped; policy excludes GPL only).

## Impact

- Specs: new capability `two-factor-login` (all ADDED requirements). No
  MODIFIED deltas — foundation requirements (token lifecycle, redaction,
  exit codes, passphrase env) are extended, not replaced.
- Code: crates/core (login params, errors), crates/vaultwarden (api.rs error
  parse, provider.rs login, new webauthn module), crates/cli (login op flags),
  crates/vaultwarden/tests (oracle + wiremock), integration harness.
- Users: `get`/`list`/`export` and the Hermes plugin are untouched (sealed
  sessions + refresh grant never require a second factor). Only initial
  `login` behavior changes; accounts without 2FA log in exactly as before.
- Ops: the VW service account can now have authenticator 2FA enforced
  server-side without breaking automation.

## Non-goals

- Duo (2/6), U2F legacy (4), organization providers — no gold-source pin, no
  demand.
- Remember-me (provider 5) and recovery codes (provider 8): rbw and
  goldwarden both omit them; no pinned wire contract. Recovery codes may work
  incidentally as a provider-8 code resubmit but are unspecified and untested.
- SSO / email-2fa session tokens (`SsoEmail2faSessionToken`).
- Storing or generating TOTP seeds inside cryptile (RFC 6238 generation,
  otpauth URI management). Codes are supplied per login; seed custody stays
  with the operator's authenticator.
- Bitwarden `bitwarden-sdk` / any Bitwarden-licensed server code (banned).
- CTAP2 hybrid transport (phone passkeys via QR / caBLE) — deferred, not
  dropped; see design.md for the follow-up gate. Same-vault and same-host
  soft passkeys are permanent non-goals (factor collapse).
