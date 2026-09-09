# Design: fix-cipher-level-key

## Context

Proven by dissection against the live server (`raw-cipher` example, kept in
`crates/vaultwarden/examples/`): cipher `bcdd9ac8-…` carries
`key: "2.Eff3lB…"` (180 chars, type-2 EncString). Unwrapped under the org
key it yields a 64-byte SymmetricKey; under it, `name` and `notes` MAC-match
and decrypt. Under the org key or user key directly, both fields MAC-fail
and CBC padding breaks — wrong key, wrong crypto path is not in play.

## Approach

Single helper in `provider.rs`:

```rust
fn effective_key(
    cipher: &Cipher,
    container: &SymmetricKey,      // org key or user key, per key_for()
) -> Result<SymmetricKey, CryptoError> {
    match cipher.key.as_deref().filter(|k| !k.is_empty()) {
        None => Ok(container.clone()),
        Some(k) => {
            let es = EncString::parse(k)?;
            SymmetricKey::from_64(&es.decrypt_symmetric(container)?)
        }
    }
}
```

`SymmetricKey` is `Clone` (Zeroizing fields) — the None arm clones the
container key reference. Every site that today does
`key_for(...) -> map_cipher / decrypt_str` instead does
`effective_key(c, key_for(...))` and propagates real errors.

### Why error, not skip, on unwrap failure

Pre-fix behavior skipped undecryptable ciphers so one corrupt item couldn't
break `list` — reasonable for a wrong-container-key edge. But a present
`cipher.key` that fails MAC under the container key means the container key
itself is wrong/stale — every org item would misbehave. Surfacing it beats
silently returning "empty vault", which is exactly the confusing failure we
just spent a day diagnosing. `list_secrets`/`get_namespace_secrets` keep
per-cipher skip semantics for non-`key` decrypt failures (unchanged), but a
`key`-bearing cipher with a failed unwrap returns `Crypto` from the whole
call — fail loud, not empty.

## Alternatives considered

- **Unwrap in `map_cipher`** — mapping doesn't know org keys; would need a
  signature change through the pure mapping layer. Rejected.
- **Cache per-cipher keys in the sync cache** — unnecessary: the warm path
  already fetches the full cipher (which carries `key`) and holds container
  keys; unwrapping is one AES op. Cache format untouched, no migration.

## Invariants

- `SymmetricKey` stays Zeroizing; unwrapped per-cipher keys drop with scope.
- No plaintext in logs; `raw-cipher` example keeps printing name plaintext
  only, notes as length+hash.
- Old servers / old items (no `key` field): byte-for-byte today's behavior.
