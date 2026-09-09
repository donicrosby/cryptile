# foundation Delta — type-aware-default-field

## MODIFIED Requirements

### Requirement: Normalized reference format

The system SHALL parse and display refs of the form `scheme://locus[#field]` with
`password` as the default field, as the single cross-backend addressing currency in CLI
arguments, configuration, and integration maps.

#### Scenario: default field
- WHEN a ref omits the fragment
- THEN resolution treats the field selector as `password`

#### Scenario: field selection
- WHEN a ref specifies `#field`
- THEN only that field's value is returned, never the whole field bag

## ADDED Requirements

### Requirement: Type-aware default field resolution

When a ref carries no field fragment, the system SHALL resolve the value by
walking a fixed fallback chain over the resolved secret's field bag —
`password`, then `notes`, then `private_key`, then `number` — returning the
first present non-empty field. Explicitly selected fields SHALL NOT fall back.

#### Scenario: Secure note via bare ref
- WHEN a ref names a Secure Note item without a fragment
- THEN the value returned is the item's `notes` field

#### Scenario: Card via bare ref
- WHEN a ref names a Card item without a fragment and the item has no
  password or notes
- THEN the value returned is the item's `number` field

#### Scenario: Explicit field keeps exact semantics
- WHEN a ref selects `#password` on an item that has no password field
- THEN resolution fails with the field-not-present error, exactly as before

#### Scenario: Empty fields are skipped
- WHEN the first chain field exists but is empty
- THEN resolution moves to the next chain field rather than returning empty
