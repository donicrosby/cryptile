# Tasks

- [x] 1.1 Compose stack: `integration/docker-compose.yml` with pinned `vaultwarden/server:1.37.2`, loopback port 8222, named volume, SIGNUPS_ALLOWED=true; `up -d` verified (server answers `/alive`), `down -v` verified clean
- [x] 1.2 `integration/provision.py`: full bootstrap (prelogin, register with harness-side KDF+keys, login, org "hermes", collection "shared", org cipher with known plaintext, personal cipher as noise); prints org/cipher UUIDs JSON to stdout; never prints secrets
- [x] 1.3 `integration/run_live_tests.sh`: orchestrator (compose up → wait /alive → provision → build cryptile → run assertions D6 → compose down); failure count exit code; safe-to-paste output (no plaintext)
- [x] 1.4 Live run green end-to-end: login → get → list → export env → export json → not-found → wrong-passphrase exit 5 → backends
- [x] 1.5 README: how to run, what it proves, failure modes, how to poke VW manually
- [x] 1.6 Spec delta: ADDED "Live integration harness" requirement; MODIFIED "Non-interactive keyring passphrase" adds live-proven scenario
- [x] 1.7 Gates: fmt/clippy/test workspace (unchanged, still green), `openspec validate add-live-integration-harness --strict`
- [x] 1.8 Commit, push, CI green, archive change
