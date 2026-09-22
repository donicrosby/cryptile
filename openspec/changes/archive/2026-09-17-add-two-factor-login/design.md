# Design: add-two-factor-login

## Context

`cryptile login` does prelogin → master-key derive → password grant → unwrap
user key. If the identity endpoint rejects the grant with a two-factor
challenge, login aborts with a generic AUTH error. The CLI is the only
interactive surface; the provider (library surface) must stay non-interactive
and testable in CI without hardware. All second-factor flows are
login-scoped: sealed sessions and the refresh grant never hit 2FA, so
`get`/`list`/`export`/plugin are out of blast radius by construction.

## Goals and Non-Goals

Goals: answer a 2FA challenge during `login` (TOTP/email codes and CTAP2
security keys); machine-friendly flag surface symmetric with
`--passphrase-env`; provider purity preserved (no device I/O or prompts in
the provider layer); every wire claim pinned to a sanctioned gold source.

Non-goals per proposal: Duo/U2F/recovery/remember, TOTP seed custody, SSO.
Also deferred, deliberately:

- CTAP2 hybrid transport (phone passkeys via QR / caBLE). Cleanroom-clean to
  spec later (defined in CTAP2.2 / W3C L3) but unverified in
  `webauthn-authenticator-rs` at our pinned version; if absent it is a
  multi-week client implementation (QR pairing, HPKE tunnel, relay protocol,
  CTAP framing) against conformance-strict phone stacks. USB+NFC hardware
  keys ship now; phone-based second factor is served today by TOTP
  (provider 0). Follow-up change must start by (a) verifying crate hybrid
  support at the pinned version, (b) a Pixel hardware probe against the
  harness VW, then (c) enable-vs-implement with real data.
- Passkeys stored inside the very vault being unlocked (circular: reading
  the key requires already passing the challenge the key answers) and
  same-host software-vault passkeys (soft-credential collapse — file read
  yields both factors). These are non-goals permanently, not sequencing.

## Actual Design

Layering follows the existing passphrase pattern exactly.

### 1. Wire contract (pinned to gold sources)

Challenge shape (rbw api.rs `ConnectErrorRes`, goldwarden
`TwoFactorResponse`): identity `/connect/token` returns HTTP 400 with body
`{"error":"invalid_grant","error_description":"Two factor required.",
"TwoFactorProviders":[0,1],"TwoFactorProviders2":{"0":{"Authenticator":true,
"object":"twoFactorU2f"}}}` — keys may arrive in either casing and the
providers2 map is `map[string-provider-id → provider config object]`. The
decode accepts the array, the map, or both; unknown provider ids decode as
`Unknown(n)` rather than failing.

Resubmit: same password-grant form plus `twoFactorToken=<code-or-assertion>`
and `twoFactorProvider=<0|1|7>` (rbw `ConnectTokenReq` twoFactorToken/
twoFactorProvider fields). For WebAuthn (7), `twoFactorToken` is the JSON
`Fido2Response` blob goldwarden builds: `{id, rawId, type:"public-key",
extensions:{appid:false}, response:{authenticatorData, clientDataJSON,
signature}}` — base64-URL-family encodings, `clientDataJSON` built from the
challenge with `type=webauthn.get`, origin `https://<rp-id>`, `crossOrigin:
false`.

WebAuthn challenge fields (goldwarden twofactor.go): provider 7 entry of
`TwoFactorProviders2` carries `challenge` (base64url string) and
`allowCredentials` (array of `{id, ...}` credential descriptors) — parse
defensively, treat missing fields as empty set → login fails with a typed
error. Every shape above is re-confirmed byte-level against the harness VW
in the pre-implementation capture task before code lands.

### 2. cryptile-core

- `LoginParams { account, secret, second_factor: Option<TwoFactor> }` where
  `TwoFactor { provider_tag: SmolStr-ish String, code: SecretString }`. Tags:
  `"totp" | "email" | "webauthn"`. Core knows nothing of VW numeric ids.
- `ProviderError::TwoFactorRequired { providers: Vec<ProviderTag> }` (new
  variant). `AuthExpired` semantics unchanged. This is the only core surface
  change; `login()` signature change is breaking for in-repo callers only
  (registry, CLI) — both updated in this change.

### 3. cryptile-vaultwarden (api.rs, provider.rs, webauthn/)

- `ApiError::Status` gains the decoded `TwoFactorProviders` when op was
  `token_password` and the body matches the challenge signature
  (`invalid_grant` + `"Two factor required."`); mapping to
  `ProviderError::TwoFactorRequired` happens in provider.rs `map_api`.
- `provider.rs login()`: after `token_password` fails with the challenge
  error, if `LoginParams.second_factor` is `Some`, resubmit with
  `twoFactorToken`/`twoFactorProvider` once; no silent retry loops (auth-error
  rule: one answer, one resubmit).

- webauthn module behind `#[cfg(feature = "webauthn")]`: challenge decode →
  clientDataJSON assembly → CTAP2 getAssertion via `webauthn-authenticator-rs`
  (MPL-2.0) USB transport → Fido2Response JSON → return as the code
  `SecretString`. No soft passkey support (hard ban on software credentials —
  the whole point is a hardware root of trust; only `usb` + `nfc` transport
  features enabled). RP ID derived from the configured server base URL
  host, origin `https://<host>` — derived, not hard-configured, since rp-id
  must equal the effective registration origin's domain (W3C WebAuthn L3
  §5.7.8 semantics; exact spelling verified against live server in
  Task 8). RP name must also support ports if base URL carries one
  (non-443 deployments), verified in the same live-capture task.

### 4. CLI

`cryptile login [ACCOUNT] [--passphrase-env VAR] [--2fa-provider totp|email|webauthn]
[--2fa-code CODE | --2fa-env VAR]`.

Flow: initial grant → on `TwoFactorRequired`, pick provider (flag > preference
webauthn→totp→email > fail listing the server's offered set), resolve code
(TTY prompt / `--2fa-code` / `--2fa-env`), call `provider.login()` again with
`second_factor` set. Wrong code → typed AUTH error, exit 3, remediation hint
names `--2fa-provider/--2fa-code/--2fa-env`. WebAuthn needs no code flag; the
key itself is the ceremony. Exit codes unchanged: challenge/answer failures
are exit 3, unchanged usage contract.

Wait-for-user (TOTP next-window): when interactive and the operator knows the
authenticator window is exhausted, Ctrl-C exits; no built-in timer (YAGNI,
both gold-source CLIs also prompt once).

### 5. Tests / fixtures

- Oracle fixture generator (Python) emits: challenge body (both key casings,
  array/map spellings, unknown id), success-after-2FA token response (for
  resubmit verification), and wrong-code rejection body. Fixture bump →
  `assert_eq!(metas.len(), N)` count in provider_e2e.rs per skill.
- wiremock provider_e2e: (a) challenge → CLI-supplied code → success; (b)
  challenge → wrong code → typed error exit-path; (c) no 2FA configured →
  login exactly as today (regression). Scenarios (a)/(b) exercised through
  the CLI binary (assertexit) for the flag surface, and through provider API
  for pure-variant error typing.
- Live harness stage: after existing stages, enable authenticator 2FA on the
  provisioned service account via the public API (enable-authenticator flow:
  get-authenticator → activate with key+token, as observed on our own live
  server; exact enable-endpoint wire captured in Task 8), then run `cryptile
  login --2fa-env` and get/export parity checks. Teardown disables 2FA and
  re-proves plain login so the fixture stays reusable.
- Harness TOTP activation detail: completing activation requires answering a
  TOTP challenge, so the harness generates the seed with `pyotp` (MIT) and
  answers with it; the seed lives only in harness-local state and is never
  printed (len+sha12 discipline). If the server rejects harness-driven 2FA
  enablement, the stage asserts graceful typed failure and is skip-degradable
  via `SKIP_2FA_LIVE=1` — never a fabricated pass.

### 6. License / supply chain

- `webauthn-authenticator-rs` MPL-2.0: file-level copyleft on its own files
  only; as an unmodified Apache-2.0 dependency it does not extend to cryptile
  code. Cargo-deny gains `MPL-2.0 = "< MPL-2.0 text URL >>" clarification
  entry. The crate itself is pre-1.0 — version-pinned exact (`=0.5.x`) per
  dependency policy (one minor at 0.x), recorded in deny.toml comment.
- Alternatives considered and discarded:
  - `authenticator-rs` (Mozilla rust crate) — MPL-2.0 too, less maintained,
    heavier deps, CTAP transport choice inferior for our USB+NFC-only scope.
  - Hand-rolled CTAP2 over hidapi — violates RustCrypto-only-style ecosystem
    preference and gold-source precedent (goldwarden uses go-libfido2, rbw
    defers to its own device crates); sharp edges without audit.
  - CLI-text protocol for hardware keys (passkey file) — no hardware root of
    trust, contradicts the security purpose. Rejected.
  - provider-internal interactive prompt loop — breaks provider purity and
    CI testability; matches no gold source (rbw prompts at its CLI layer
    too).
- Also discarded: treating the challenge as retry-until-success (auth-error
  rule: work around or ask — one resubmit, typed failure on miss).

### 7. Invariant callouts (config.yaml rules)

- Provider purity: device I/O lives behind cfg-gated module in vaultwarden
  crate only; core never sees hardware types.
- Secrets typed: TOTP code and webauthn assertion blob are `SecretString`.
- Exit-code contract unchanged: 2/3/4/5 semantics preserved; new failure
  modes map onto existing AUTH (3) bucket.
- Composition root unchanged: CLI imports backend types only for the 2FA tag
  mapping (a small `From` in vaultwarden crate, CLI stays concrete-type-free
  except through core enums — registry unchanged).

## Risks / Trade-offs

- MPL-2.0 dep in an Apache-2.0 project: acceptable as unmodified dependency;
  file-level copyleft doesn't propagate. Recorded in deny.toml.
- Pre-1.0 authenticator crate: pinned exact + vendored review at bump time.
- VW server version drift on `TwoFactorProviders2` shape: mitigated by
  defensive parse + live-capture task before code lands.
- Account lockout from repeated wrong codes: single resubmit design + typed
  error; no retry loop by design.
- Harness enable-2FA stage may not be automatable against live VW (public
  API surface may differ from client-observed behavior): stage designed
  skip-degradable, never fabricating pass.

## Migration Path

Additive. Existing sealed sessions, config, and plugin behavior unchanged.
`LoginParams` struct gains a field (compile-time break in-repo only). Users
see one new flag family on `login` only.

## Open Questions

- Should `--2fa-env` also be accepted by `login` when no challenge arrived
  (ignored) or error? Current design: ignored, matches `--passphrase-env`
  symmetry and gold-source behavior (rbw passes provider/token only when
  the user chose a provider).
- Recovery-code (8) incidentally-works status: leave as non-goal or add one
  e2e fixture asserting it fails with a typed error rather than silently
  succeeding? (Design leans: add the fixture; cheap, pins the boundary.)
