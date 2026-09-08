# foundation Specification

## Purpose
Defines the cross-backend contract cryptile depends on: the `Provider` facade trait (auth, refresh, namespaces, items, values), scoped machine access semantics, at-rest session sealing, and CLI-visible behaviors (exit codes, redaction-free output, export key mangling) that every backend must satisfy.

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

The backend SHALL cache access tokens, record their expiry, refresh them
silently before expiry (within a 300-second margin) or on a 401 response,
and on refresh failure SHALL surface a remediation hint rather than retry
loops.

#### Scenario: silent refresh

- WHEN a token expires mid-session and a valid refresh token exists
- THEN the next request succeeds without user interaction

#### Scenario: proactive refresh within margin

- WHEN a sealed session's access token expires within the 300-second margin
- THEN the next command refreshes the token via the refresh grant before
  issuing backend requests and persists the rotated session on success

#### Scenario: refresh failure

- WHEN the refresh token is revoked or invalid
- THEN the CLI exits non-zero with a remediation hint naming the re-login
  command and performs no further network retries

#### Scenario: legacy sealed session

- WHEN a sealed session predates expiry tracking and records no expiry
- THEN commands proceed without proactive refresh and remain covered by the
  401-triggered refresh path

### Requirement: Export command

The CLI SHALL provide `export --namespace <name>` as the bulk raw-value
surface, emitting one `KEY=value` line per field on stdout with keys mangled
to `[A-Z0-9_]+` (collision suffix `__1`), values newline/backslash escaped,
NUL refused, and renames reported to stderr.

#### Scenario: export emits env lines

- WHEN `cryptile export --namespace hermes` runs with a valid sealed session
- THEN stdout contains one `KEY=value` line per field of every item in the
  namespace and no item or namespace names

#### Scenario: newline escaping

- WHEN a field value contains a newline
- THEN the emitted line escapes it as `\n` and the line count stays correct

#### Scenario: NUL refusal

- WHEN a field value contains a NUL byte
- THEN export fails with a nonzero exit and no partial output

### Requirement: Non-interactive keyring passphrase

The CLI SHALL support `--passphrase-env VAR` to read the keyring passphrase
from an environment variable for non-TTY contexts, and SHALL fail with a
remediation hint when neither that flag nor a TTY is available, never reading
stdin blindly.

#### Scenario: agent bootstrap

- WHEN `--passphrase-env CRYPTILE_PASSPHRASE` is given and the var is set
- THEN the keyring unseals without any TTY prompt

#### Scenario: no passphrase path

- WHEN no `--passphrase-env` is given and stdin is not a TTY
- THEN the command fails with a remediation hint and nonzero exit

### Requirement: Structural redaction

The system SHALL redact secret values in all log output, debug formatting,
and error messages. Secret values SHALL carry no `Display` implementation;
their `Debug` output SHALL show a placeholder. Raw values SHALL leave the
process only at the explicit stdout output boundary of `get` and `export`,
and there SHALL be no flag or configuration that weakens this boundary.

#### Scenario: redaction by default

- WHEN a `SecretValue` is formatted via Debug or Display in a non-TTY context
- THEN the output shows a placeholder, not the underlying value

#### Scenario: no display path

- WHEN library code outside the CLI stdout boundary attempts to print a
  secret value
- THEN no such code path compiles, because the value type exposes no
  Display and requires an explicit expose call
