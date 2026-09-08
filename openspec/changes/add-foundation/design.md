# Design Notes — Foundation

## Architecture (three crates + plugin later)

```
cryptile/               workspace root
  crates/cli/           binary: `cryptile` — clap, redaction, output formatting
  crates/core/          domain model, Ref parsing, Provider trait, keyring store
  crates/vaultwarden/   first Provider impl: Bitwarden client API + crypto
  (later: crates/hermes/  Hermes SecretSource plugin, Python, thin wrapper on CLI)
```

Dependency direction: `cli` → `core` + `vaultwarden`; `vaultwarden` → `core` only.
Backends never depend on each other; new backends = new crate + Provider impl + entry in
the registry.

## The facade (the whole point)

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &'static str;                 // "vw", "op", "vault"
    async fn login(&self, params: LoginParams) -> Result<Session, ProviderError>;
    async fn list_namespaces(&self, s: &Session) -> Result<Vec<Namespace>, ProviderError>;
    async fn list_secrets(&self, s: &Session, ns: &Namespace) -> Result<Vec<SecretMeta>, ProviderError>;
    async fn get_secret(&self, s: &Session, r: &Ref) -> Result<Secret, ProviderError>;
}
```

- Async because every real backend is network I/O. Object-safe (no generics on methods) so
  the CLI can hold `Box<dyn Provider>` and dispatch on the scheme of the parsed `Ref`.
- `Secret` = `{ metadata, fields: BTreeMap<String, SecretValue> }` — Bitwarden items are
  field-bags (login + custom fields + notes + attachments), not single strings. The facade
  models that as a bag; `#field` selectors pick one; `#password` is the canonical shorthand.
  1Password's `op://vault/item/field` and Vault's KV `path#key` map onto the same shape.
- Resource IDs: backends get opaque string IDs (`Namespace.id`, `SecretMeta.id`). Refs
  store names, not IDs — names are stable for humans, IDs are server-internal.

## Ref format

`scheme://locus[#field]` where locus is backend-defined (VW: `collection/item-name`,
op: `vault/item`, vault: `mount/path`). Field default = `password` (matches `op` muscle
memory). Refs are the single currency: CLI args, config files, Hermes `env:` maps, docs.

## Vaultwarden backend — how machine access works

1. Service account = a real VW user whose vault contains ONLY what the owning org
   collection grants. Scoping is server-side (org/collection ACLs), not client-side.
2. Prelogin (`/identity/accounts/prelogin`) → KDF params → Argon2id/PBKDF2 master key →
   HKDF-expand (if server advertises `forcePasswordEncryptionKeyCreation` / KDF version ≥ 1)
   → auth key hash. Login via `/identity/connect/token` (password grant, scope api).
3. Access token (2h) + refresh token persisted in the keyring (passphrase-encrypted,
   root-only file, 0600). This replaces BSM's machine-account access token: same UX
   (long-lived bootstrap credential in Hermes `.env`? No — see below), none of the
   licensed crypto.
4. `/api/sync` pulls ciphers + collection metadata. Org key arrives RSA-OAEP-wrapped with
   the service account's public key → unwrap with account private key → AES key for all
   ciphers in that org. Item fields: `encKeyValidation`-style MAC check + AES-CBC
  decryption, type-tagged values (`2.xxx|yyy|zzz`).
5. Values exist in memory only. `export`/`get` write to stdout; the CLI never writes
  plaintext to disk. Hermes consumes stdout via the bundled command secret source until
  the plugin change lands.

## Hermes bootstrap credential placement

Tier 1+2 model: Hermes holds NO vault credential at rest. Flow: Doni runs `cryptile login`
interactively on the host (or the CLI runs from `.env` bootstrap). VW password grant gives
us a 2h access + 30d refresh token; the refresh token is what the keyring persists. Hermes
command-source runs `cryptile export --collection hermes` on each startup; the CLI silently
refreshes on 401/expiry. Rotating the service account password never invalidates the agent.

## Security decisions (already made with Doni)

- Tier 1 (server-side scoping via dedicated service account + collection ACL) +
  tier 2 (context isolation: values land in Hermes env, never in conversation) —
  explicitly NOT tier 3 (broker). If tier 3 is ever wanted, it's a separate consumer
  proxy service, out of scope.
- No plaintext cache on disk, ever. Cache (if ever added) is encrypted with the same
  keyring passphrase.
- Redaction: `KEY=<redacted>` in every log/audit line; `--no-redact` requires
  `stdin.isatty() && stdout.isatty()`.
- Zero Bitwarden code: crypto implemented from the public Bitwarden Security Whitepaper
  and `bitwarden/specs`, same clean-room position as Vaultwarden itself. `bitwarden-sdk`
  is GPLv3 — deliberately not used, not linked, not read for implementation.

## Licensing

Apache-2.0 (MIT-optional dual later). No GPL contamination: no bitwarden-sdk, no BSM code.
