## Why

cryptile only maps Login ciphers (and notes/custom fields incidentally).
Vaultwarden/Bitwarden items come in five server types — Login, Secure Note,
Card, Identity, SSH Key — and any of them can carry the secret an agent
needs (keys live in notes or SSH private-key fields more often than in
passwords). Today those items are invisible: `list` shows nothing useful
and `get` cannot select their fields, which reads as "cryptile lost my
item" (live case: secure note in an org collection). Additionally,
`LoginData.uri` parses a singular `uri` key that real servers never send
(the API emits a `uris` array), so URI extraction is dead on real vaults.

## What Changes

- `Cipher` API model gains optional `card`, `identity`, and `sshKey` data
  blocks; `LoginData.uri` is replaced by the real `uris` array shape.
- `map_cipher` maps every type's fields into the flat field bag with
  stable, documented, collision-free names (`number`, `private_key`,
  `first_name`, ...). Notes and custom fields keep working for all types.
- Python oracle fixture gains one org item per new type; wiremock e2e
  asserts a `get` round-trip for each mapped field.
- README documents the field-name table per item type.

## Impact

- Refs for non-Login items become usable (`vw://RJ-45/Lease#notes`,
  `vw://ops/bootstrap-node#private_key`, ...). Existing Login refs are
  unchanged; `#password` stays the default field.
- No core-model changes: Secret stays a field bag, SecretMeta.fields now
  reflects the real shape of each item type.
- Binary at /opt/data/bin/cryptile gets rebuilt/redeployed after CI-green.

## Non-goals

- Per-type default fields in the ref grammar (e.g. defaulting to `notes`
  for secure notes) — `#field` stays explicit, `password` stays the
  global default.
- Attachments, " Sends", and fido2 credentials — not part of the field
  bag model.
- Write path (creating/editing items) — read-only CLI stays read-only.
