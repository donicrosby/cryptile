# Change Proposal: Foundation — scope, facade crate layout, Vaultwarden MVP backend

## Why

Doni needs a Secrets-Manager-style way to share secrets with his Hermes agent (RJ) such that
the agent gets scoped, decrypt-capable access to exactly one collection — without the agent
ever holding the human's master password. Bitwarden Secrets Manager is licensed/proprietary
server-side code that Vaultwarden will never implement, so the tool must implement its own
machine-access layer as a client of the public Bitwarden/Vaultwarden API. The result will be
released open source, so multi-user concerns (arbitrary collections, pluggable backends) are
first-class from day one, not retrofitted.

## What Changes

- Establish the `cryptile` Rust workspace: `cryptile` (portable CLI), `cryptile-core`
  (backend-agnostic domain model + Provider trait facade), `cryptile-vaultwarden`
  (first backend), later `cryptile-hermes` (Hermes SecretSource plugin).
- Secret values are carried in `secrecy::SecretString` (redacted Debug, zeroize on
  drop) — no hand-rolled value wrapper. Dependency policy: pull ecosystem crates
  (secrecy, argon2, etc.) rather than implementing in-house; keep deps within one
  major version of current (one minor while major is 0); cargo-deny enforces
  advisories, yanked, licenses (GPL deliberately excluded), and sources in CI.
- Define the `Provider` facade trait (async, object-safe) with a normalized resource model:
  `Secret`, `Namespace` (collection/project/folder), `Ref` (cross-backend stable reference).
- Define the normalized reference format `provider:path/to/secret#field` used by CLI flags,
  config, and the Hermes plugin — every backend resolves the same shape.
  - `vw://<collection>/<item-name>#<field>` — Vaultwarden/Bitwarden
  - `op://<vault>/<item>/<field>` (1Password-compatible view) — future backend
  - `vault://<mount>/<path>#<field>` — OpenBao/Vault KV-v2 — future backend
- Build the Vaultwarden MVP backend: dedicated service account, login (prelogin → KDF →
  identity/connect/token), `/api/sync` pull, decrypt of org-key-wrapped ciphers
  (RSA-OAEP unwrap of org key, AES-CBC-HMAC item fields) into a key-value view.
- CLI subcommands (start minimal): `login` (store server URL + service-account credentials
  in a root-only keyring file), `export` (print `KEY=VALUE` lines for Hermes' command
  secret source), `get <ref>`, `list` (collections/items, metadata only — values never
  printed), `rotate-token` (drop stale BWS-style access tokens on 401).
- Security posture: no plaintext caching to disk ever; credentials at rest encrypted with a
  passphrase-derived key (Argon2id) — zero-knowledge at rest, master password never stored;
  values redacted from all logs; `--no-redact` flag is interactive-TTY-gated.
- OpenSpec-first workflow: implementation only under active changes; archive on completion.

## Impact

- New repo `donicrosby/cryptile`, Apache-2.0, Rust workspace crate structure.
- Hermes integration arrives as a later change (cryptile-hermes plugin) once CLI + core are real.
- Explicitly out of scope for MVP: writing/creating secrets via CLI, TUI, machine-account
  asymmetric crypto (BSM-style), non-VW backends (facade is built for them, they land later).
