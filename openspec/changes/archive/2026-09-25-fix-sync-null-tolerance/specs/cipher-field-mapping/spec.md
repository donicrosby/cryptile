# cipher-field-mapping Delta — fix-sync-null-tolerance

## ADDED Requirements

### Requirement: Sync payload tolerates null collections and fields

The sync-path deserialization SHALL treat a JSON `null` present where a
sequence is expected — sync `ciphers`, profile `organizations`, cipher
`fields`, login `uris`, and the `/api/collections` envelope's `data` — as
that sequence's empty default instead of failing the response parse,
because Vaultwarden emits present-as-null for empty collections where the
shape implies an array. Members that are absent keep the existing empty
default. A null in these members SHALL NOT surface as a
malformed-response error.

#### Scenario: sync body with null collections parses fully

- WHEN a sync body carries `"ciphers": null`, a profile with
  `"organizations": null`, a cipher with `"fields": null`, and a login
  with `"uris": null`
- THEN the payload parses fully and each null member is the empty
  default, exactly as if it were absent

#### Scenario: collections envelope with null data

- WHEN `/api/collections` returns `{"data": null}`
- THEN the parse yields an empty collection list instead of a
  malformed-response error

#### Scenario: absent members unchanged

- WHEN any of these members is absent rather than null
- THEN deserialization behaves exactly as before this requirement
