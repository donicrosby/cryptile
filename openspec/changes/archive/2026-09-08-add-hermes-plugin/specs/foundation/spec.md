# Foundation — Spec Delta

## ADDED Requirements

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
