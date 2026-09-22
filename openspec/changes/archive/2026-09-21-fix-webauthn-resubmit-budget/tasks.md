# Tasks: fix-webauthn-resubmit-budget

- [ ] 1. RED test: wiremock e2e `webauthn_resubmit_within_one_login_call`
  in `crates/vaultwarden/tests/provider_e2e.rs` — token mock challenges on
  the bare grant, expects `twoFactorProvider=7` + `twoFactorToken` on the
  resubmit, returns a session; test calls `login()` once with a webauthn
  `SecondFactor` and asserts Ok(session) + exactly two token posts. The
  ceremony is seam-stubbed (feature-gated `assertion_hook` override or
  equivalent) so CI needs no USB device. Verify: `cargo test -p
  cryptile-vaultwarden --features webauthn --test provider_e2e` shows the
  new test RED against current code (second challenge surfaces as
  `TwoFactorRequired`).
- [ ] 2. Fix: in `crates/vaultwarden/src/provider.rs` `login()`, keep the
  bare-grant strip for wire 7, but when the challenge leg answers with
  wire 7 selected, run `answer_two_factor` and resubmit inside the same
  call; a challenge on the *resubmit* maps to typed Auth (not
  `TwoFactorRequired`). Verify: new test GREEN, full
  `cargo test --workspace` + `--features webauthn` green.
- [ ] 3. Gates: `cargo fmt --all`; `cargo clippy --workspace --all-targets`
  zero warnings (both feature sets); `cargo test --workspace` and
  `cargo test --workspace --features webauthn` green.
- [ ] 4. Deploy: `cargo build --release --features webauthn && cp
  target/release/cryptile /opt/data/bin/cryptile`; verify
  `/opt/data/bin/cryptile --version` shows the new version (bump to
  0.2.2).
- [ ] 5. Live verify against bw.jeansburger.net: hardware-key login via
  the plugin-exact argv shape; the key blinks/touches and login seals a
  session. Verify: `cryptile list` over the fresh session returns
  namespaces (no secret values printed).
- [ ] 6. Archive the change (`openspec archive`) and commit the archive.
