# Design: add-sync-cache

## Context

`get_secret` today: full `GET /sync` + `GET /collections` on every call
(`provider.rs: sync_and_keys`), then linear scan of every cipher to
match one name. Measured p50 2393 ms; the network dominates.

## Goals / Non-Goals

Goals: one-round-trip `get` on the warm path; zero new trusted inputs;
no CLI/Provider-trait surface changes beyond one opt-in flag; cache
never weaker than the keyring at rest.

Non-Goals: batch get, list/export caching, revision tracking, writes.

## Decisions

### D1: cache the name→UUID index + org keys, not ciphers

Caching decrypted cipher payloads would duplicate the vault at rest and
go stale per-field. Caching only the index (names, ids) + org keys
keeps the sealed blob small and the targeted fetch always returns the
*current* cipher body from the server. Org keys change only when org
membership/key rotation happens — rare, and handled by the miss path
(mac-fail on unwrap → treat cipher key as unusable → resync).

### D2: seal with HKDF(user key, "cryptile-sync-cache-v1")

The `Provider` methods receive only `&Session` — no passphrase — so the
keyring's Argon2 path cannot be reused. The user key is already in
scope, already only at rest inside the passphrase-sealed keyring, and
HKDF label separation means the derived cache key is useless for
protocol operations (and vice versa). Wrong account → user key differs
→ MAC fails → cold rebuild. This keeps the `Provider` trait untouched.

### D3: sealed format mirrors the keyring (`crc1`)

Same encrypt-then-MAC construction (AES-256-CBC + HMAC-SHA256, Argon2
NOT needed here — the sealing key is a full-entropy 32B HKDF output, so
the KDF step is skipped; salt+HKDF-info prefix the MAC input). Corrupt
or foreign cache → `Tamper` → cold path, never surfaced as an error.

### D4: freshness by self-healing miss, not TTL/revision

Every mutation converges on the miss path (see proposal). Added: the
warm path verifies the fetched cipher's decrypted name matches the
requested item — closes the rename race at the cost of one name decrypt
we already perform inside `map_cipher`.

### D5: `--refresh-cache` is wire-only

No config, no env var, no persistence. `get --refresh-cache` forces the
miss path exactly once.

## Risks / Trade-offs

- Cache file grows with vault size (names only): ~100 B/item. 10k items
  ≈ 1 MB sealed. Acceptable; no eviction in v1.
- Org key rotation between warm fetches: targeted cipher decrypt fails
  MAC → falls to miss path. Correct, just slower once.
- `login` for a different account deletes the cache; same account
  re-login keeps it (tokens may have refreshed but the user key is
  account-stable).

## Migration Plan

Additive: no existing file changes interpretation. First run with no
cache file = today's behavior, then writes the cache.

## Open Questions

None blocking. Batch mode deliberately deferred (needs a partial-failure
error model; separate change).
