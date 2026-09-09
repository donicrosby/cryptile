## ADDED Requirements

### Requirement: Sealed sync cache

The Vaultwarden backend SHALL maintain a sealed on-disk cache of the
vault index (collection and cipher names → ids, org keys) under the CLI
state directory, sealed with a key derived from the account's user key
via HKDF-SHA256 under the label `cryptile-sync-cache-v1`, so that
secret fetches can resolve refs via a single targeted cipher request
instead of a full-vault sync. The cache SHALL contain no access tokens
and no cipher field values. A corrupt, foreign-account, or missing
cache SHALL be treated as a cold cache and rebuilt, never surfaced to
the user as an error.

#### Scenario: warm hit resolves with one round-trip

- **WHEN** `get` runs and the cache resolves the ref's collection and
  item name to a cipher id
- **THEN** the backend issues `GET /api/ciphers/<uuid>` only, verifies
  the decrypted cipher name matches the requested item, and returns the
  secret without calling `/sync`

#### Scenario: cold miss does full sync and writes the cache

- **WHEN** the cache is absent, corrupt, sealed for another account, or
  fails to resolve the ref (unknown name, stale after rename/delete)
- **THEN** the backend falls back to today's full sync + collections
  fetch, serves the secret, and writes a fresh cache; cache write
  failures are non-fatal

#### Scenario: cache file is sealed at rest

- **WHEN** the cache file is inspected
- **THEN** it is a `crc1.<salt>.<iv>.<ct>.<mac>` line whose plaintext
  contains org keys and names but no tokens and no cipher field values,
  and a wrong user key fails the MAC indistinguishably from corruption

#### Scenario: login rotates the cache correctly

- **WHEN** `login` is run for a different account than the cache holds
- **THEN** the cache file is deleted before any rebuild; re-login for
  the same account keeps it
