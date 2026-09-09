# cipher-key-unwrap Delta — fix-cipher-level-key

## ADDED Requirements

### Requirement: Unwrap cipher-level encryption keys

The system SHALL parse the cipher-level `key` field when the sync payload
carries one, decrypt it under the cipher's container key (organization key
for org-owned ciphers, user key otherwise), and use the resulting symmetric
key for all field decryption of that cipher. When the field is absent or
empty, the system SHALL use the container key directly.

#### Scenario: Org item with cipher-level key

- WHEN the sync payload contains an org-owned cipher whose `key` field wraps
  a 64-byte symmetric key under the organization key
- THEN `get` decrypts the cipher's name and fields with the unwrapped
  per-cipher key and returns the secret
- AND the sync-cache index includes the cipher under its decrypted name

#### Scenario: Item without cipher-level key

- WHEN a cipher carries no `key` field
- THEN field decryption uses the container key exactly as before, with no
  behavior change

#### Scenario: Unwrap failure surfaces as error

- WHEN a cipher carries a `key` field that fails decryption under the
  container key
- THEN the provider returns a crypto error rather than silently omitting
  the cipher from results
