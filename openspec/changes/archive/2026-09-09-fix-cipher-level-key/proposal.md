# Proposal: fix-cipher-level-key

## Why

Live failure (2026-09-09): `cryptile get vw://RJ-45/Dolos Lemonade Key` exits 5
"not found" on an item that exists, is readable by the account, and decrypts
fine in the VW web UI. Forensic dissection (`raw-cipher` example) proved the
server emits a **cipher-level `key` field** — a type-2 EncString wrapping a
per-cipher 64-byte symmetric key under the container key (org key for
org-owned items, user key otherwise). The cipher's `name`/`notes`/fields are
sealed under that per-cipher key, NOT under the container key directly:

- under per-cipher key: name MAC matches, decrypts to "Dolos Lemonade Key";
  notes MAC matches
- under org key / user key directly: MAC mismatch, CBC padding breaks

cryptile's `Cipher` struct doesn't deserialize `key` at all, so every decrypt
uses the wrong key, MAC-fails, and the item is silently dropped — from `get`,
from `list`, and from the sync-cache index (`write_cache` skips
undecryptable names). The user sees "not found" on an item they can read in
the web UI.

This is the Vaultwarden/Bitwarden per-cipher key feature (flexible
cipher sharing / key rotation without re-encrypting the org). Any vault with
it enabled is entirely invisible to cryptile today.

## What Changes

- `api.rs`: `Cipher` gains `#[serde(default)] key: Option<String>` (the
  cipher-level EncString; absent/empty on older items).
- `provider.rs`: new `effective_key()` helper — when `cipher.key` is present,
  parse + decrypt it under the container key (org key when org-owned, else
  user key) and use the resulting `SymmetricKey` for that cipher; otherwise
  today's container-key behavior, unchanged.
- All cipher decrypt sites route through it: `list_secrets`,
  `get_namespace_secrets`, `get_secret` miss path, `get_secret_warm`,
  `write_cache` name decryption.
- Oracle fixture + wiremock e2e: one org item sealed under a per-cipher key
  (key wrapped under org key), asserting `get` round-trips the plaintext.
- README: one line in the field table section noting per-cipher-key items
  are transparently unwrapped.

## Impact

- Items with cipher-level keys become visible and readable. No behavior
  change for items without them. No core-model change; no ref syntax change.
- Failure mode upgrades from silent drop to surfaceable error: a present
  `cipher.key` that fails to unwrap is a real per-cipher error (wrong
  container key / rotation race), reported as `ProviderError::Crypto`, not
  a skip.
- Deploy: release build → `/opt/data/bin/cryptile` → live probe of the RJ-45
  item (the original failing ref, with `#notes`).

## Non-goals

- Writing/re-encrypting ciphers (cryptile is read-only).
- Handling `key` on upload/restore paths the sync API also carries —
  read surface only.
