# Tasks: support-all-cipher-types

- [x] 1. `api.rs`: add `CardData`, `IdentityData`, `SshKeyData` structs (camelCase serde), wire into `Cipher`; replace `LoginData.uri` with `uris: Vec<LoginUri>` array shape
- [x] 2. `mapping.rs`: map card / identity / ssh-key / login-uris fields per the design table; skip absent/empty
- [x] 3. `oracle_fixture.py`: add org card, identity, SSH-key, and secure-note items with expects; regenerate `wiremock_fixture.json`
- [x] 4. `provider_e2e.rs`: e2e `get` round-trip per new type (number, passport_number, private_key, notes) through real login+sync+decrypt
- [x] 5. `cargo fmt && cargo clippy -D warnings && cargo test --workspace` green
- [x] 6. README: field-name table per item type
- Note (not counted): tasks 7-8 (release build, deploy, live probe) are folded into the follow-up change `fix-cipher-level-key` — the live target item is sealed under a cipher-level key, so the probe cannot pass until that fix lands. Fixed en route: Python comprehension syntax had leaked into `provider_e2e.rs` `json!` (compile error).
