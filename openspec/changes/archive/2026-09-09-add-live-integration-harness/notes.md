# add-live-integration-harness Change Notes

## What

Add a Vaultwarden **live integration harness**: a `docker-compose` stack (legitimate, in-repo, committed) that boots a real Vaultwarden server, provisions a service account + org "hermes" + collection "shared" through the public API (harness-side crypto in Python, same protocol as cryptile itself — clean-room safe since it's Bitwarden protocol, not VW code), seeds test data (org item with known plaintext + personal item as noise), then runs the real `cryptile` binary against it:

- `cryptile login` (env-passphrase paths)
- `cryptile get vw:shared/<item>:password`
- `cryptile list vw:shared`
- `cryptile export --namespace shared --format env` (+ json)
- Keyring tamper/wrong-passphrase check (exit 3)

## Why

- The wiremock fixtures cover protocol shape, but only a live server exercises the real VW version currently shipping (1.37.x) — real SQLite, real Rocket, real endpoint behavior at the edges (register accept-shapes, sync shape drift, token TTLs).
- Cryptile's target deployment is "point at your own VW" — the harness doubles as a **reproducible integration environment** for humans: `docker compose -f integration/docker-compose.yml up -d` gives a disposable VW for manual poking.
- Keeps CI unblocked (live tests stay behind an env flag; CI continues to run wiremock suites) while giving a one-command live-fire proof before crates.io publish.

## Non-goals

- No new cryptile CLI features or subcommands.
- No CI wiring for the live suite (manual/scheduled local runs only, for now — adding to CI would need a docker-in-docker or hosted VW service container; deliberate non-goal here).
- No reading of VW source in the cryptile binary beyond what's already grounded (harness only relies on the public Bitwarden API contract).
- Harness bootstrap crypto is Python (`cryptography` lib for AES/HKDF/PBKDF2), not Rust — it's test tooling, not shipping code.

## Impact

New files only:

- `integration/docker-compose.yml` — vaultwarden service (pinned 1.37.x tag, not :latest), bind-mounted data dir, published port
- `integration/README.md` — how to run, what it proves, failure modes
- `integration/provision.py` — API bootstrap (register, org+collection, seed ciphers) with own crypto
- `integration/run_live_tests.sh` — orchestrator: compose up → wait healthy → provision → run cryptile assertions → compose down; exit code reflects the suite

Modified:

- `openspec/specs/foundation/spec.md` — one new requirement ("Live integration harness") + scenario under Non-interactive keyring passphrase (env-var path proven live)
- `crates/cli/src/ops.rs` + `main.rs` — product bugs the live server exposed (below), fixed in-tree

Live-fire findings that changed `crates/` (all caught by the live server, all missed by wiremock):

1. **Prelogin body**: VW 1.37's Rocket route takes `Json<PreloginData>`; cryptile sent urlencoded form → bare 400. Fixed: prelogin POSTs JSON.
2. **Token response `Key` casing**: VW returns capital-K `"Key"`; the struct had `#[serde(default)]` with no alias → key silently empty → "malformed EncString". Fixed: `#[serde(alias = "Key")]`.
3. **Exit-code mapping**: ops stringified `ProviderError` and main mapped everything to exit 4, so a missing item reported as transport error. Fixed: ops return typed `ProviderError` end-to-end; main derives exit code by kind (`BadRef`→2, `Auth`/`AuthExpired`/`NoSession`/`Forbidden`→3, `Transport`/`Server`/`Crypto`→4, `NotFound`→5).
4. **Login env flags**: `cryptile login` was TTY-only; harness (and agents) need non-interactive paths. Added `--passphrase-env`/`--master-password-env` (login only, per TTY-only passphrase policy).

