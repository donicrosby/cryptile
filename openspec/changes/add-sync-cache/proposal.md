# Change Proposal: add-sync-cache

## Why

Live measurement (`BENCHMARKS.md`, harness bench stage, 2026-09-09): a
single `cryptile get` costs p50 2393 ms against a local Vaultwarden, and
the phase trace shows the time is the per-call full-vault
`GET /sync` (profile + orgs + every cipher) plus `GET /collections`
needed just to resolve one `collection/item` ref to a cipher UUID. Argon2
keyring unlock is 78 ms and cipher decrypt is 357 ns — this is not a
crypto problem. The Hermes plugin fires one `cryptile get` subprocess per
bound env var serially, so N secrets cost N×2.4 s.

Vaultwarden 1.37.2 exposes `GET /api/ciphers/<uuid>` (single-cipher
fetch; 404 for unknown UUID — verified in VW source). Clients in the
wild (rbw, goldwarden) do exactly this dance: keep a local index of
names → UUIDs plus org keys, fetch the one cipher that is asked for.

## What Changes

Add a sealed sync cache under the CLI state dir that lets `get` serve
from a single targeted cipher fetch instead of full-vault sync:

1. **Vaultwarden backend**: `get_secret` becomes cache-aware.
   - Cache hit (collection + item name → cipher UUID resolved locally):
     `GET /ciphers/<uuid>`, decrypt name with the cached key, verify the
     decrypted name matches the requested item (case-insensitive), then
     map and return — one round-trip. Name mismatch or 404 from the
     targeted fetch → fall through to the miss path.
   - Cache miss or cold cache: full `sync_and_keys` (today's behavior),
     serve from it, then write the cache.
   - `list_*` and `export` still full-sync — they enumerate everything
     anyway; unchanged behavior, and they refresh the cache as a side
     effect.
2. **New module `crates/vaultwarden/src/cache.rs`**: on-disk sealed
   cache at `<state-dir>/cache/cipher-index`, format
   `crc1.<salt>.<iv>.<ct>.<mac>` — AES-256-CBC + HMAC-SHA256
   encrypt-then-MAC, MAC-fail indistinguishable from wrong-key (same
   construction as the keyring). Sealing key derived from the user key
   via HKDF-SHA256 with the fixed label `cryptile-sync-cache-v1`
   (label-scoped so it is not a protocol key; the user key itself is
   only ever at rest inside the passphrase-sealed keyring).
   Account-scoping is free: different account → different user key →
   MAC fails → treated as cold cache and rebuilt.
3. **Cache contents**: collection index (id, org id, decrypted name),
   cipher index (cipher id, org id, decrypted name, collection ids),
   org keys (wrapped org-id → key — the reason the cache must be
   sealed), and the account email for diagnostics. No secret material
   beyond org keys; no tokens.
4. **CLI flag** `--refresh-cache` on `get` (skips the cache read, forces
   full sync, rewrites cache). Escape hatch and test surface; no other
   CLI surface change.
5. **Cache lifecycle**: `login` deletes any cache belonging to a
   different account (belt-and-braces on top of MAC-fail scoping);
   corrupt/truncated cache = cold cache, never an error to the user.

Staleness reasoning (why no TTL/revision tracking is needed): every
mutation a user can make (add, delete, rename, move) either leaves the
index lookup failing (add/move → miss → resync), the targeted fetch
404ing (delete → miss → resync), or the name check failing (rename →
miss → resync). All paths converge on full sync + cache rewrite. The
rename race (old name reused by a new item) is closed by the
decrypted-name verification in step 1.

## Impact

- `crates/vaultwarden`: new `cache.rs`, provider `get_secret` rework,
  `api.rs` gains `get_cipher(uuid)`.
- `crates/cli`: `--refresh-cache` flag; delete stale cache on `login`.
- Specs: new requirement `Sealed sync cache` under foundation.
- Security review items: cache at-rest confidentiality (org keys
  sealed), HKDF label separation, cache deletion on account switch.
- Risk: none to correctness paths — miss path is byte-for-byte today's
  code. Worst case the cache adds one wasted round-trip before a resync.

Risk of NOT doing it: every Hermes env bootstrap stays N×2.4 s serial
wall-clock, and any future batch mode multiplies the same cost.

## Non-Goals

Batch `get`, caching for `list`/`export` (they already pay one sync),
multi-account cache reuse, writing any cipher ever, revision-date
tracking (self-healing miss paths make it unnecessary).
