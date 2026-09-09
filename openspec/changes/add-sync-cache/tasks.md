# Tasks — add-sync-cache

## 1. Backend cache module

- [x] 1.1 `crates/vaultwarden/src/cache.rs`: `crc1` seal/open (AES-256-CBC + HMAC-SHA256, HKDF(user key, label `cryptile-sync-cache-v1`), salt random per seal); unit tests roundtrip, tamper → Tamper, wrong user key → Tamper
- [x] 1.2 Index model: collections (id, org_id, name), ciphers (id, org_id, name, collection_ids), org_keys (org_id → 64B key), account email; serde JSON payload inside the seal
- [x] 1.3 `api.rs`: `get_cipher(uuid)` via `GET /api/ciphers/<uuid>` (404 → `ProviderError::NotFound` via existing `map_api`)
- [x] 1.4 Provider `get_secret` warm path: resolve collection + item name → cipher uuid from cache; targeted fetch; verify decrypted name matches (case-insensitive); mismatch or 404 → miss path
- [x] 1.5 Provider `get_secret` miss path: full `sync_and_keys`, serve, then write cache (write failures non-fatal, `tracing::warn`)
- [x] 1.6 `get_warm` tracing span with hit/miss outcome recorded

## 2. CLI wiring

- [x] 2.1 `get --refresh-cache` flag: skip cache read, force miss path, rewrite
- [x] 2.2 `login` different account → delete `cache/cipher-index`; same account → keep
- [x] 2.3 Docs note: cache file purpose + manual nuke (`rm cache/cipher-index`)

## 3. Harness + spec

- [x] 3.1 Live harness: cold get writes cache; warm get succeeds with no full-sync (assert via RUST_LOG span absence or server log grep)
- [x] 3.2 Live harness: self-heal — after warm get, corrupt cache bytes on disk, get again → still correct (miss resync)
- [x] 3.3 Bench: rerun bench stage, record before/after get p50 in BENCHMARKS.md
- [x] 3.4 Spec delta: ADDED `Sealed sync cache` requirement + scenarios (warm hit, cold write, tamper cold, foreign-account cold); validate --strict

## 4. Ship

- [x] 4.1 Gates: fmt, clippy -D warnings, workspace tests, pytest integrations, openspec validate --strict
- [x] 4.2 Commit + push, CI green
- [ ] 4.3 Archive
