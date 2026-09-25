# Proposal: fix-sync-null-tolerance

## Why

A live owner run of `cryptile list` crashed with
`network/transport error: malformed response: invalid type: null, expected
a sequence at line 1 column 26325`. Root cause: the sync-path serde models
use bare `Vec<T>` with `#[serde(default)]`, which covers members that are
ABSENT but not members PRESENT-AS-NULL — and real Vaultwarden emits JSON
`null` for empty collections (e.g. a cipher with no custom `fields`). One
null in any of the five sequence members cryptile deserializes is enough
to fail the entire sync parse, taking down `list` (and any `get` that
falls to the miss path) against a perfectly healthy server.

## What Changes

- `crates/vaultwarden/src/api.rs` only: a null-tolerant sequence
  deserializer (`null_to_default`, deserialize_with) applied to exactly
  the five vulnerable members — `SyncResponse.ciphers`,
  `Profile.organizations`, `Cipher.fields`, `LoginData.uris`, and the
  `/api/collections` list envelope's `data`. Null decodes to the empty
  default; absent keeps the existing `#[serde(default)]` behavior; no
  other field changes.
- Unit tests pinning fixture-style sync/collections bodies with
  `"ciphers": null`, `"fields": null`, `"uris": null`, `"organizations":
  null`, and `"data": null` parsing fully.

## Impact

- **Specs**: extends `cipher-field-mapping` with one ADDED requirement
  (sync payload null tolerance) — this capability already owns how the
  sync payload is parsed into the field bag.
- **Code**: `crates/vaultwarden/src/api.rs` (serde models + unit tests).
  No provider, cache, mapping, CLI, or wire changes: the deserialized
  domain values are identical to what an absent member yields today.
- **Invariants preserved**: no crypto, no transport, no exit-code change;
  a null member can no longer turn a healthy server into a
  malformed-response failure (exit 4).

## Non-goals

- No tolerance for nulls in required scalars (profile id/email/key,
  cipher id/name) — those stay hard errors; a server failing them is
  genuinely broken.
- No schema-wide `Option<Vec<T>>` refactor of the models; only the five
  members the real server has shown (or the envelope implies) null for.
- No challenge-body/2FA parsing changes (separate change).
- No live-harness stage: the wire-level proof is the pinned unit
  fixtures; the live harness already covers null-free servers.
