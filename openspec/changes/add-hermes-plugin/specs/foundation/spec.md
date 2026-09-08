# Foundation — Spec Delta

## MODIFIED Requirements

### Requirement: CLI value surface

The `cryptile` CLI SHALL expose exactly one raw-value surface, `get <ref>`
(single field to stdout) and `export --namespace <name>` (bulk KEY=value),
with all metadata paths (Debug, `list`, logs, errors) redacting values via
`secrecy::SecretString`.

#### Scenario: export emits env lines

- WHEN `cryptile export --namespace hermes` runs with a valid sealed session
- THEN stdout contains one `KEY=value` line per field of every item in the
  namespace, keys mangled to `[A-Z0-9_]+`, and no metadata lines

#### Scenario: non-interactive passphrase

- WHEN `--passphrase-env VAR` is set and the var is present in the environment
- THEN the keyring unseals without any TTY prompt

#### Scenario: no passphrase path available

- WHEN no `--passphrase-env` is given and stdin is not a TTY
- THEN export fails with a remediation hint and never reads stdin

## ADDED Requirements

### Requirement: Export value safety

The export command SHALL escape newlines in values as `\n` (and backslash as
`\\`), refuse values containing NUL, and print the key-mangling map to stderr.

#### Scenario: newline escaping

- WHEN a field value contains a newline
- THEN the emitted line escapes it as `\n` and the line count stays correct
