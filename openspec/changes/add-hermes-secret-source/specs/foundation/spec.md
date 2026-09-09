## MODIFIED Requirements

### Requirement: Non-interactive keyring passphrase

The CLI SHALL support `--passphrase-env VAR` on `get`, `list`, `export`,
and `login` to read the keyring passphrase from an environment variable
for non-TTY contexts, and SHALL fail with a remediation hint when neither
that flag nor a TTY is available, never reading stdin blindly. The live
integration harness SHALL exercise this env-var path end-to-end against a
live Vaultwarden.

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

## ADDED Requirements

### Requirement: Hermes secret source plugin

A Hermes directory plugin under `integrations/hermes/` SHALL register a
mapped secret source named `cryptile` (scheme `vw`) that resolves each
`env: {VAR: vw://...}` binding by invoking `cryptile get` with an
allowlisted environment and stdin closed, translating the CLI's typed exit
codes onto Hermes' `ErrorKind` taxonomy (2→REF_INVALID, 3→AUTH_FAILED,
4→NETWORK, 5→EMPTY_VALUE). The plugin SHALL NOT implement Vaultwarden
protocol or keyring logic itself.

#### Scenario: mapped binding resolves

- WHEN `secrets.cryptile.env` binds `VAR` to `vw://collection/item#field`
  and the sealed session is valid
- THEN `fetch()` returns the field's plaintext under `VAR` without
  prompting or raising, using only the allowlisted passphrase env var in
  the child process

#### Scenario: auth failure maps to AUTH_FAILED

- WHEN `cryptile get` exits 3 (stale or wrong passphrase / no session)
- THEN `fetch()` reports `error_kind=AUTH_FAILED` with a remediation hint
  pointing at `cryptile login`

#### Scenario: missing item maps to EMPTY_VALUE

- WHEN `cryptile get` exits 5 for a bound ref
- THEN `fetch()` reports `error_kind=EMPTY_VALUE` and contributes no value
  for that var

#### Scenario: conformance

- WHEN the conformance kit from the Hermes repository runs against the
  plugin source
- THEN all contract checks pass (never-raises, no-prompt, disabled by
  default, identity attrs, orchestrator round trip)

#### Scenario: live end-to-end proof

- WHEN the live harness runs with a provisioned Vaultwarden, a real
  `cryptile login`, the plugin registered, and `apply_all()` invoked
- THEN the bound env var holds the seeded plaintext and the value's
  provenance names the cryptile source
