# foundation Specification

## Purpose
TBD - created by archiving change add-foundation. Update Purpose after archive.

## Requirements

### Requirement: Provider facade trait

The system SHALL expose a single async, object-safe `Provider` trait in `cryptile-core`
that every backend implements, such that CLI, config, and future integrations (Hermes
plugin) consume backends through one uniform interface.

#### Scenario: dispatch by ref scheme
- WHEN a ref with scheme `vw` is resolved
- THEN the registry selects the vaultwarden `Provider` implementation without CLI-level
  backend-specific branching

#### Scenario: new backend without CLI changes
- WHEN a new backend crate implementing `Provider` is added to the registry
- THEN existing CLI subcommands resolve refs of the new scheme with no CLI code changes

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

### Requirement: Zero-plaintext-at-rest

The CLI SHALL NOT write secret values to disk in plaintext under any circumstances.
Persisted credentials (tokens) SHALL be encrypted with a key derived from a
passphrase via Argon2id.

#### Scenario: export writes stdout only
- WHEN `export` or `get` produces values
- THEN values are written to stdout only and no file on disk receives plaintext

#### Scenario: keyring at rest
- WHEN credentials are persisted
- THEN the credential file is encrypted (Argon2id-derived key) and mode 0600 in a
  user-owned directory

### Requirement: Log and output redaction

The system SHALL redact secret values in all log output, debug formatting, and error
messages. An explicit `--no-redact` flag SHALL only take effect when both stdin and
stdout are interactive TTYs.

#### Scenario: redaction by default
- WHEN a `SecretValue` is formatted via Debug or Display in a non-TTY context
- THEN the output shows a placeholder, not the underlying value

#### Scenario: no-redact gating
- WHEN `--no-redact` is passed but stdout is piped (non-TTY)
- THEN the flag is refused with a non-zero exit and no value is printed

### Requirement: Vaultwarden machine access via service account

The vaultwarden backend SHALL authenticate as a dedicated service-account user whose
vault contains only organization-granted collections, using the public Bitwarden client
API (prelogin, password grant, sync), with scoping enforced server-side by
organization/collection ACLs.

#### Scenario: scoped vault
- WHEN the service account authenticates and syncs
- THEN only ciphers in collections granted to the service account's organization are
  visible to the backend

#### Scenario: no master password storage
- WHEN login completes
- THEN only derived tokens (access/refresh) are persisted, never the account password
  or master key

### Requirement: Token lifecycle

The backend SHALL cache access tokens, refresh them silently before expiry or on a 401
response, and on refresh failure SHALL surface a remediation hint rather than retry
loops.

#### Scenario: silent refresh
- WHEN a token expires mid-session and a valid refresh token exists
- THEN the next request succeeds without user interaction

#### Scenario: refresh failure
- WHEN the refresh token is revoked or invalid
- THEN the CLI exits non-zero with a remediation hint naming the re-login command
  and performs no further network retries
