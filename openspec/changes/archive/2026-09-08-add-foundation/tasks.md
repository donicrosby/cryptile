# Tasks — Foundation

## 1. Workspace scaffold
- [x] 1.1 Create Rust workspace: `crates/{cli,core,vaultwarden}` + root `Cargo.toml` with workspace deps
- [x] 1.2 Add README (positioning vs BSM/Vaultwarden, tier 1+2 threat model), LICENSE (Apache-2.0), rustfmt.toml, clippy gate
- [x] 1.3 CI workflow: fmt + clippy + test on stable; cargo-deny (advisories, yanked, licenses, sources)
- [x] 1.4 Zero-code start: no stub `main.rs` that compiles to nothing — first commit ships `Ref` parsing with tests

## 2. Core: refs and model
- [x] 2.1 `Ref` type: `scheme://locus[#field]` parse/display, default field `password`
- [x] 2.2 Domain types: `Secret`, `SecretMeta`, `Namespace`, `Session`, `SecretValue` (redacting Debug/Display)
- [x] 2.3 `Provider` trait as designed — landed with the Vaultwarden backend (no speculative trait)

## 3. Vaultwarden backend
- [x] 3.1 HTTP client: prelogin, KDF negotiation (Argon2id/PBKDF2), password grant login, token refresh
- [x] 3.2 Crypto: master key derivation, HKDF expand for user key, auth hash, RSA-OAEP org key unwrap, AES-CBC-HMAC cipher decryption, type-tagged value parsing
- [x] 3.3 Sync + mapping: `/api/sync` → ciphers filtered to target collection(s) → `Secret` field bags
- [x] 3.4 Keyring: Argon2id passphrase-encrypted credential file, 0600, root-only dir; silent refresh on 401

## 4. CLI
- [x] 4.1 `cryptile login` — interactive prompt (TTY-gated), stores server URL + service account creds
- 4.2 `cryptile export` — lands with Hermes plugin change, not MVP CLI
- [x] 4.2 `cryptile get <ref>` — prints single field value, exit codes per ProviderError kind
- [x] 4.3 `cryptile list` — collections and item names (metadata only, values redacted)
- [x] 4.4 Redaction infrastructure: `SecretString` (secrecy) everywhere, redacted Debug, no-leak tests; `--no-redact` flag lands with `export` (bulk display) in add-hermes-plugin — single-field `get` prints its one value by contract (piping is the Hermes bootstrap path)
- [x] 4.5 `rotate-token` behavior: on AUTH_EXPIRED, drop cached token, one re-login attempt, else fail with remediation hint

## 5. Repo mechanics
- [x] 5.1 Create GitHub repo `donicrosby/cryptile`, push scaffold + openspec
- [x] 5.2 Verify `openspec validate add-foundation --strict` green before first push
- [x] 5.3 Commit discipline: Conventional Commits format, one OpenSpec task cluster per commit, message references task ID; enforced by pre-commit (`compilerla/conventional-pre-commit`, `.pre-commit-config.yaml`)
- [ ] 5.4 After MVP lands: archive `add-foundation`, open next change (`add-hermes-plugin`)

## 6. Deferred (explicitly out of MVP)
- 6.1 1Password backend (`op://`) — facade ready, impl later
- 6.2 OpenBao/Vault backend (`vault://`) — facade ready, impl later
- 6.3 Write/rotate secrets via CLI
- 6.4 TUI
