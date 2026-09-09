# add-live-integration-harness Design

## Context

Cryptile's VW backend is verified against wiremock fixtures generated from an
rbw/goldwarden-verified protocol oracle. That proves wire-shape correctness.
What it cannot prove: current-VW-version endpoint behavior (register
accept-shapes, sync drift, real Rocket form parsing quirks, token TTLs,
error bodies). A live server also exercises the CLI's real TTY/env paths,
keyring sealing, and the full happy path a human runs.

Constraint: cryptile's terminal sandbox talks to the *host* docker daemon
(docker.sock passthrough). Published ports bind on the host. The sandbox
reaches them via the docker bridge gateway (172.17.0.1), verified working
pattern from the docker skill.

## Goals / Non-goals

**Goals**

1. In-repo `docker-compose` stack booting pinned Vaultwarden, usable both as
   automated harness backend and as a manual integration environment.
2. Fully-API-driven bootstrap (no web UI, no admin token): register service
   account, create org + collection, seed ciphers. All crypto harness-side.
3. Exercise the *existing* cryptile binary end-to-end against the live
   server; assert on stdout/exit codes.
4. Reproducible: fixed seeds/UUIDs where visible, pinned image tag, scratch
   state dir under `integration/.run/` (gitignored).

**Non-goals**

- CI wiring (docker-in-docker nonstarter; revisit if/when the repo gets a
  hosted VW service container).
- Any change to cryptile's Rust code. If the live run exposes a real bug,
  the bug gets fixed in its own change, not folded into the harness change.
- Performance/load anything.

## Decisions

### D1: Compose project isolation

Project name `cryptile-vw` (compose `-p`), network `cryptile-vw_default`,
port `127.0.0.1:8222:80` (host-loopback bind only; VW listens 80 in-container).
Data: named volume `cryptile-vw_data` (not bind mount) — avoids host-path
resolution issues with the daemon-side path rules, wipes clean on `down -v`.

### D2: Pinned image

`vaultwarden/server:1.37.2` (latest stable line per releases page; 1.37.2
supports web-vault 2026.7.0+ clients). Environment: `SIGNUPS_ALLOWED=false`
after bootstrap? No — bootstrap *needs* open signups to register the service
account, so keep `SIGNUPS_ALLOWED=true` (it's a loopback-bound throwaway).

Domain: `ROCKET_PORT=80`, `ROCKET_ADDRESS=0.0.0.0` (so the compose port
mapping works), `SHOW_PASSWORD_HINT=false`, `INVITATIONALS_ALLOWED=false`,
`WEB_VAULT_ENABLED=true` (harmless, useful for manual poking).

Env `DOMAIN` is NOT set: VW builds absolute URLs from the request host when
unset. The cryptile CLI will use `http://127.0. must match what VW sees
`Host: 127.0.0.1:8222`. Verified acceptable in rbw-style clients (rbw passes
the base URL straight through).

### D3: Harness crypto = Python `cryptography` (same protocol, own code)

The harness performs the *same* client-side crypto cryptile does:

- `normalize identity` (trim+lowercase email)
- KDF: PBKDF2-SHA256 (iterations from prelogin; VW default 600_000 — harness
  pins 100_000 for speed; VW accepts client-declared kdf params at register,
  they become the account's params, prelogin returns them back)
- `master key` = PBKDF2(password, salt=email-normalized, iterations)
- `auth hash` = PBKDF2(master_key, password, 1) → base64
- user key: random 64 bytes → EncString type 2 (AES-256-CBC + HMAC, iv/mac
  ct) sealed under stretched user key (HKDF-expand enc/mac subkeys from
  master key)
- org key: random 32 bytes → EncString type 2 sealed under user key
  (stretched? no — org key sealed under *user* key enc/mac keys directly;
  same SymmetricKey {enc, mac} material)
- collection name + cipher name/fields/notes encrypted under org key
- cipher login fields (username/password) under org key

All of this mirrors `/tmp/rbw` + `/tmp/gw` verified flows and the Bitwarden
whitepaper; zero VW implementation code copied. The harness is Apache-2.0
repo test tooling.

### D3b: Why Python and not a Rust helper

The harness must run against the *released* cryptile binary, not a test
crate; a second Rust helper would duplicate the very crypto under test —
using the same code to validate itself proves nothing. Independent
implementation (Python) is an actual cross-check (the whole point of the
earlier Python oracle fixture work).

cross-check: if the Python implementation and the Rust implementation
disagree, the live run fails loudly — that's the signal, not a blocker.

### D4: Login form fields

`grant_type=password`, `scope=api offline_access`, `client_id=web`,
`password=<auth_hash_b64>`, `username=<email>`, `deviceType=14`,
`deviceIdentifier=<uuid4>`, `deviceName=cryptile-live-harness`.

(`deviceIdentifier` randomness is fine — VW doesn't require prior device
knowledge.)

### D5: Cipher seeding shape

Org item (in "shared" collection, org "hermes"):

```json
POST /api/ciphers/create
{
  "cipher": {
    "type": 1,
    "name": "2.xxx|yyy|zzz|www",           // EncString under org key
    "login": {"username": "2...", "password": "2...", "uris": []},
    "organizationId": "<org uuid>",
    "secureNote": null, "card": null, "identity": null
  },
  "collectionIds": ["<collection uuid>"]
}
```

Personal item (noise, tests namespace filtering): same minus org/collection
fields, directly to `POST /api/ciphers`.

Personal item names/fields under *user* key (same enc/mac pair), org items
under *org* key.

**Login URI shape check**: sync `login.uris` may be null/[] in VW's response
— cryptile's `ApiCipherLogin` (api.rs) needs `uris: Option<Vec<...>>` or
default. Confirmed handled: existing wiremock fixtures already ship null
`uris` for some ciphers and cryptile parses fine (fixtures cover this).

**Rust-side risk register** (live-run may expose; each gets its own fix change if hit):

- `ApiCipherLogin.uris` null/missing → parse failure (mitigated: existing
  fixtures already cover null uris; but live 1.37 sync response may add new
  fields — serde `deny_unknown_fields` is NOT used in api.rs, extra fields
  ignored by default, safe)
- token TTL: VW access token TTL is 3600s and refresh grants return new
  refresh tokens; refresh path already covered by wiremock; live just
- proactively-refreshing-earlier-than-3600
- register → org → collection → cipher: each hop must surface errors with
  the failing hop's name in the harness (not silent pass-through), or
  debugging a failing bootstrap is hell

### D6: Test assertions (run_live_tests.sh)

Env: `CRYPTILE_PASSPHRASE=test-passphrase-123`. Scratch state dir
`integration/.run/state` (wiped each run).

1. `cryptile --state-dir ... login --server http://127.0.0.1:8222 --account svc-hermes@<domain>` → exit 0, stderr contains "logged in; session sealed"
2. `cryptile get vw:shared/Postgres HQ:password` → exit 0, stdout == the
   exact plaintext we sealed at provision time
3. `cryptile list vw:shared` → exit 0, metadata only, contains item name,
   does NOT contain plaintext password
4. `cryptile export --namespace shared --format env` → exit 1: wrong passphrase env var (CRYPTILE_PASSPHRASE=wrong) → exit 5, non-zero, "tampered"/"invalid passphrase" hint
5. Same export with correct passphrase → exit 0, `POSTGRES_HQ_PASSWORD=<plaintext>` present (mangled keys per spec)
5b. `--format json` → valid JSON containing the secret
6. `cryptile get vw:shared/nonexistent:password` → exit 5 not-found
7. Wrong-account ref (`vw:shared2/...`) → exit 2 parse ok / list empty → covered by 6-style not-found
7b. `cryptile backends` sanity → prints `vw`

Exit code contract: harness exits with number of failures (0 = all pass).

Do NOT log plaintexts in harness output. Assert equality silently; on
mismatch print only "value mismatch" + length. (Redaction principle: the
harness output must be safe to paste.)



## Risks / Trade-offs

- **Nested-docker reachability**: sandbox→host published port via bridge
  gateway works (docker skill verified pattern); if a future environment
  blocks it, the compose file alone still works for any human on the host.
- **Image pull**: sandbox pulls from Docker Hub through the host daemon —
  normal egress, no proxy needed (image pull is not target probing).
- **register email verification**: VW ≥1.33 *requires* email verification for
  signup when SMTP configured; without SMTP (our case), `SIGNUPS_ALLOWED=true`
  alone suffices. Verified against register handler: without SMTP, no
  verification token needed (plain register succeeds).
### Migration

N/A — new files only, plus spec delta applying on archive.

## Open Questions

None blocking. (Config knobs like org name / port are constants in
provision.py, not user-facing config — deliberately; YAGNI.)
