# Tasks: fix-cipher-level-key

- [x] 1. `api.rs`: `Cipher` gains `#[serde(default)] key: Option<String>`
- [x] 2. `provider.rs`: `effective_key()` helper; route all five decrypt sites through it (`list_secrets`, `get_namespace_secrets`, `get_secret` miss path, `get_secret_warm`, `write_cache`); unwrap failure surfaces (miss path reports crypto error with count when item not found)
- [x] 3. `oracle_fixture.py` + `wiremock_fixture.json`: org item sealed under a per-cipher key (wrapped under org key)
- [x] 4. `provider_e2e.rs`: `get` round-trip on the per-cipher-key item
- [x] 5. `cargo fmt && cargo clippy --workspace --all-targets` clean, `cargo test --workspace` green (14 suites ok)
- [x] 6. Release build, deploy `/opt/data/bin/cryptile`, live probe `vw://RJ-45/Dolos Lemonade Key#notes` — exit 0, 52 bytes, sha12 a4445379eb6f (matches raw-cipher dissection); warm path exit 0; `list RJ-45` shows the item
- [x] 7. `openspec validate --strict` both changes, commit, push, archive `fix-cipher-level-key`; archive `support-all-cipher-types` (its deploy/probe folded here)
- [x] 8. Update config ref to `#notes` in `/opt/data/config.yaml` + note VW_MASTER_PASSWORD cleanup for user
