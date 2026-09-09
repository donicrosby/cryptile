# Design: support-all-cipher-types

## Context

The Vaultwarden/Bitwarden sync payload types each cipher with a `type`
integer and a matching data block (`login`, `securenote`/`notes`,
`card`, `identity`, `sshKey`). cryptile's value proposition is the flat
`vw://collection/item#field` bag; the only question is the field-name
contract per type.

## Field-name contract (the deliverable)

Flat, lowercase, snake_case, stable. A name is owned by exactly one
source so custom fields can never shadow built-ins (custom field names
that collide are still inserted last-wins as today — documented, not
silently dropped).

| Type | Fields |
|---|---|
| Login | `username`, `password`, `totp`, `uri` (first), `uris` (newline-joined, only when >1) |
| Secure Note | `notes` |
| Card | `cardholder_name`, `number`, `brand`, `exp_month`, `exp_year`, `code` |
| Identity | `title`, `first_name`, `middle_name`, `last_name`, `address1`, `address2`, `address3`, `city`, `state`, `postal_code`, `country`, `phone`, `email`, `ssn`, `username`, `company`, `license_number`, `passport_number` |
| SSH Key | `private_key`, `public_key`, `key_fingerprint` |
| All | custom `fields`, `notes` (any type can carry notes) |

## Decisions

1. **No `type` synthetic field.** The server `type` int is not a secret;
   leaking it into a SecretString bag adds noise for scripts that iterate
   fields. `list` (SecretMeta.fields) already reveals item shape.
2. **URIs: `uri` = first, `uris` = newline-joined all (only if >1).**
   Mirrors what users see in clients; avoids `uri_2..uri_N` sprawl.
   The singular `uri` JSON key is dropped — real servers send the array.
3. **Identity `username` collides with Login `username`** — intentional:
   an item is exactly one type, so within any item the name is
   unambiguous.
4. **Empty/absent encrypted strings are skipped**, not inserted empty —
   a field name in the bag always means "there is a value".
5. **Undecryptable items are still skipped silently in list** (existing
   behavior for wrong-key items, e.g. moved-without-re-encryption). That
   is a data-integrity signal, not a type-mapping concern; revisiting it
   is out of scope here.

## Discarded alternatives

- **Nested field paths (`#card.number`)** — breaks the one-level ref
  grammar and every consumer that treats fields as a flat map.
- **Type-prefixed names (`card_number`)** — verbose, and Card items don't
  need qualification since names are unique per item.
- **Per-type default field in Ref** — touches core for cosmetic gain;
  `#notes` / `#private_key` are explicit and grep-able.

## Testing strategy

- Oracle fixture (Python, real AES/HMAC/RSA) gains: org card item, org
  identity item, org SSH-key item, org secure note. Regenerated fixture
  feeds wiremock e2e: login once, `get` one representative field per type
  (number, passport_number, private_key, notes) and assert plaintext.
- Existing tests keep passing unchanged (same fixture keys, same
  expectations) — proves no regression to Login mapping.
