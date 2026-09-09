# cipher-field-mapping Specification

## Purpose
TBD - created by archiving change support-all-cipher-types. Update Purpose after archive.

## Requirements

### Requirement: Map all Vaultwarden cipher types

The system SHALL map every cipher type the Vaultwarden sync API emits —
Login (1), Secure Note (2), Card (3), Identity (4), SSH Key (5) — into
the flat secret field bag, such that a `get` ref can select each field
by the documented stable name.

#### Scenario: Card item fields
- WHEN the sync payload contains a Card cipher
- THEN the mapped secret exposes `cardholder_name`, `number`, `brand`,
  `exp_month`, `exp_year`, and `code` fields with decrypted values

#### Scenario: Identity item fields
- WHEN the sync payload contains an Identity cipher
- THEN the mapped secret exposes `title`, `first_name`, `middle_name`,
  `last_name`, `address1`, `address2`, `address3`, `city`, `state`,
  `postal_code`, `country`, `phone`, `email`, `ssn`, `username`,
  `company`, `license_number`, and `passport_number` fields

#### Scenario: SSH key item fields
- WHEN the sync payload contains an SSH Key cipher
- THEN the mapped secret exposes `private_key`, `public_key`, and
  `key_fingerprint` fields

#### Scenario: Secure note item
- WHEN the sync payload contains a Secure Note cipher
- THEN the mapped secret exposes `notes`

### Requirement: Login URI array handling

The system SHALL parse the `uris` array the API emits (not the singular
`uri` key), expose the first entry as field `uri`, and when more than
one entry exists expose `uris` as all entries joined by newlines.

#### Scenario: Single URI
- WHEN a Login cipher has exactly one URI entry
- THEN field `uri` holds its decrypted value and no `uris` field exists

#### Scenario: Multiple URIs
- WHEN a Login cipher has three URI entries
- THEN field `uri` holds the first and `uris` holds all three joined by
  newline in order

### Requirement: Notes and custom fields for every type

The system SHALL map `notes` and decrypted custom fields for ciphers of
every type, not only Login ciphers.

#### Scenario: Custom field on a card
- WHEN a Card cipher carries a custom field named `pin`
- THEN the mapped secret exposes field `pin` alongside the built-in card
  fields

### Requirement: Field presence implies value

The system SHALL omit a field from the mapped secret when the source
data block is absent or its encrypted string is empty; a present field
name always denotes a decrypted, non-empty value.

#### Scenario: Card without brand
- WHEN a Card cipher omits the encrypted brand string
- THEN the mapped secret has no `brand` field
