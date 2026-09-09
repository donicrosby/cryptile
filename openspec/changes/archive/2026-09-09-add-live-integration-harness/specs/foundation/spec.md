## ADDED Requirements

### Requirement: Live integration harness

The repository SHALL provide a docker-compose-based harness that boots a real
Vaultwarden server, provisions a service account, organization, collection,
and seeded ciphers entirely through the public Bitwarden-compatible API, and
runs the released `cryptile` binary against it.

#### Scenario: full happy path against live Vaultwarden

- **WHEN** the harness orchestrator is run against a freshly started stack
- **THEN** `cryptile login`, `get`, `list`, and `export` (env and json) all
  succeed against the live server
- **AND** the value returned by `get vw:shared/<item>:password` equals the
  plaintext sealed by the harness at provision time

#### Scenario: failure paths

- **WHEN** the keyring passphrase is wrong
- **THEN** export exits 3 and does not leak the vault
- **WHEN** the referenced item does not exist
- **THEN** get exits 5 (not-found) without stack trace

#### Scenario: reproducible teardown

- **WHEN** the orchestrator finishes (pass or fail)
- **THEN** compose `down -v` removes the server, network, and volume
- **AND** no plaintext secret appears in harness stdout/stderr

## MODIFIED Requirements

### Requirement: Non-interactive keyring passphrase

The CLI SHALL support `--passphrase-env VAR` to read the keyring passphrase
from an environment variable for non-TTY contexts, and SHALL fail with a
remediation hint when neither that flag nor a TTY is available, never reading
stdin blindly. The live integration harness SHALL exercise this env-var path
end-to-end against a live Vaultwarden.

#### Scenario: agent bootstrap

- WHEN `--passphrase-env CRYPTILE_PASSPHRASE` is given and the var is set
- THEN the keyring unseals without any TTY prompt

#### Scenario: no passphrase path

- WHEN no `--passphrase-env` is given and stdin is not a TTY
- THEN the command fails with a remediation hint and nonzero exit

#### Scenario: live proof of the env-var path

- WHEN the live integration harness runs `export --passphrase-env` against a
  live Vaultwarden
- THEN the unseal succeeds using only the environment variable
