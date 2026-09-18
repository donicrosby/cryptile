# Tasks: add-two-factor-login

- [x] 1. Core surface: add `TwoFactor { provider_tag, code: SecretString }`
  to `LoginParams` (as `second_factor: Option<...>`) and
  `ProviderError::TwoFactorRequired { providers: Vec<String> }`; update the
  in-repo callers (CLI ops, registry). Verify: `cargo test -p cryptile-core`.
- [x] 2. Pre-implementation live capture: boot the harness Vaultwarden
  (pinned VW version), enable authenticator 2FA on the provisioned test
  account via the public API, capture the byte-level challenge response
  (both key casings if version-dependent) and a successful resubmit; commit
  captures under `crates/vaultwarden/tests/fixtures/` with sha256 recorded.
  Verify: capture files exist + shas recorded in the fixture README.
- [x] 3. Oracle + fixtures: extend `oracle_fixture.py` to emit the 2FA
  challenge bodies (array spelling, map spelling, unknown provider id) and
  the success-after-resubmit token response; regenerate
  `wiremock_fixture.json`; bump the `metas.len()` count in
  `provider_e2e.rs` per fixture-item rule. Verify: `python3
  crates/vaultwarden/tests/oracle_fixture.py && cargo test -p
  cryptile-vaultwarden`.
- [x] 4. Provider e2e (wiremock): challenge → detect → typed
  `TwoFactorRequired`; resubmit with `twoFactorToken`/`twoFactorProvider`
  → session sealed; wrong code → typed AUTH error; no-2FA login unchanged
  (regression scenario). Verify: `cargo test -p cryptile-vaultwarden
  --test provider_e2e`.
- [x] 5. CLI: `--2fa-provider totp|email|webauthn`, `--2fa-code`,
  `--2fa-env VAR` on `login`; TTY prompt when interactive; exit 3 +
  remediation hint naming the flags when a challenge arrives with no
  resolution path; single resubmit, no loops. Verify: CLI-level tests
  asserting exit codes (`assertexit` style) in `crates/cli`.
- [ ] 6. WebAuthn feature: `webauthn` cargo feature on cryptile-vaultwarden
  (default off) adding challenge parse → clientDataJSON assembly → CTAP2
  assertion via `webauthn-authenticator-rs` (usb + nfc transports only, no
  soft tokens), assertion JSON as `SecretString`; unit tests for challenge
  decode + clientDataJSON assembly against the Task 2 capture; device I/O
  untestable in CI, exercised by the manual hardware stage (Task 9).
  Verify: `cargo build -p cryptile-vaultwarden --features webauthn &&
  cargo test -p cryptile-vaultwarden --features webauthn`.
- [ ] 7. License gate: pin `webauthn-authenticator-rs = "=0.5.x"` (exact, per
  0.x policy), add MPL-2.0 clarification to `deny.toml` with rationale
  comment. Verify: `cargo deny check licenses` green in CI job.
- [ ] 8. Live harness stage: enable authenticator 2FA (pyotp seed, len+sha12
  discipline, never printed), `cryptile login --2fa-env TOTP_CODE` →
  get/export parity, teardown disables 2FA + re-proves plain login;
  `SKIP_2FA_LIVE=1` skip path asserts notice not failure. Verify: `CRYPTILE_VW_BIND=1
  integration/run_live_tests.sh` (staged run, harness env flags).
- [ ] 9. Manual hardware-key runbook: README section documenting `cryptile
  login --2fa-provider webauthn` against a real CTAP2 key (operator-run;
  records make/model + outcome in `docs/webauthn-notes.md`, explicitly not
  CI-gated). Verify: section exists + one recorded manual run.
- [ ] 10. Gates: `cargo fmt --all`; `cargo clippy --workspace --all-targets
  --all-features` zero warnings; `cargo test --workspace --all-features`.
  Verify: all three commands exit 0.
- [ ] 11. Commit (conventional: `feat(cli): two-factor login (totp, email,
  webauthn)`), push with gh credential helper, watch CI to green, `openspec
  validate --strict`, archive the change, commit the archive. Verify: CI
  green on main + `openspec list` shows no active change.
