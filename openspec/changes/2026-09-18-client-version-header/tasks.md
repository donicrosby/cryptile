# Tasks: client-version-header

- [x] 1. `api.rs`: add named const `CLIENT_VERSION` (`2024.12.0`, rationale
  comment citing rbw pin + harness probe result) and `CLIENT_NAME` (`web`);
  apply both via `reqwest::header::{HeaderMap, HeaderValue}` +
  `.default_headers()` in `Client::new`; remove the per-request literals from
  `post_form`; add `pub fn bare_client()` building a `reqwest::Client` with the
  same default headers for debug tooling. Verify: `cargo build
  -p cryptile-vaultwarden`.
- [x] 2. Examples `raw-sync.rs` + `raw-cipher.rs`: replace bare
  `reqwest::Client::new()` with `cryptile_vaultwarden::api bare_client()`
  equivalent (pub helper). Verify: `cargo build -p cryptile-vaultwarden
  --examples`.
- [x] 3. Wiremock e2e: add `.and(header("Bitwarden-Client-Name", "web"))` and
  `.and(header("Bitwarden-Client-Version", CLIENT_VERSION))` matchers to the
  identity-token, sync, and cipher-get mocks. Verify: `cargo test
  -p cryptile-vaultwarden --test provider_e2e`.
- [x] 4. Live proof end-to-end (harness): boot-path parity — provision fresh
  state, login, `list` shows the type-5 org cipher, `get` returns
  len+sha12 matching the seeded value (never printed). Verify: scripted run
  against `http://172.17.0.3:80` harness with exit code 0.
- [x] 5. Live proof against PROD (own account, read-only): redeploy binary to
  `/opt/data/bin/cryptile`, re-run `raw-sync` (now headered) — type-5 ciphers
  must appear in the raw payload; then plugin-exact `cryptile get` on the
  previously-failing ref, value verified by len+sha12 only. Verify: raw-sync
  count > 4 and get exit 0.
- [x] 6. Gates: `cargo fmt --all`; `cargo clippy --workspace --all-targets`
  zero warnings; `cargo test --workspace` green. Verify: all three exit 0.
- [ ] 7. Commit (conventional: `fix(vaultwarden): send client identification
  headers so sync delivers type-5 ciphers`), push via gh credential helper,
  watch CI green, `openspec validate --strict`, archive the change, commit the
  archive. Verify: CI green on main + `openspec list` shows no active
  client-version-header change.
