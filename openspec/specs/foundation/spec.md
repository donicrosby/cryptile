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

### Requirement: Live-harness bench stage

The live integration harness SHALL provide a bench stage that, after
correctness stages pass, times N end-to-end `get` fetches (and login)
against the provisioned Vaultwarden fixture and reports p50/p95/pmax
wall-clock per phase to the stage log and summary JSON. The stage SHALL
be skippable (`SKIP_BENCH=1`) and its sample count configurable
(`CRYPTILE_BENCH_N`). Baseline numbers from a prior run on the same host
SHALL be displayed as a delta when present.

#### Scenario: bench stage reports latency percentiles

- **WHEN** the harness runs with the bench stage enabled
- **THEN** the log contains per-phase p50/p95/pmax for login and get
- **AND** those numbers are folded into the harness summary JSON

#### Scenario: bench baseline delta

- **WHEN** `integration/.run/bench-baseline.json` exists from a prior run
- **THEN** the stage prints per-phase deltas against that baseline
- **AND** the baseline file is never committed to the repository

#### Scenario: skip

- **WHEN** `SKIP_BENCH=1` is set
- **THEN** the harness skips the bench stage with a notice and overall
  pass/fail is unaffected

### Requirement: Phase tracing without secret leakage

The CLI SHALL emit phase-duration spans (ref parse, keyring unlock,
backend request per endpoint, decrypt, total) via the `tracing` crate,
gated at runtime by `RUST_LOG`, disabled by default with negligible cost
when disabled. Spans and events SHALL carry only counts, durations, byte
lengths, and endpoint paths — never secret values, keys, or passphrase
material — and a test SHALL capture subscriber output and assert the
absence of fixture secrets.

#### Scenario: spans appear when enabled

- **WHEN** `RUST_LOG=cryptile=debug` is set during a `get` against the
  live fixture
- **THEN** stderr shows per-phase durations (parse, unlock, request,
  total) for the run

#### Scenario: silence when disabled

- **WHEN** `RUST_LOG` is unset
- **THEN** a `get` produces no trace output beyond normal CLI output

#### Scenario: no secret material in spans

- **WHEN** a fetch runs with tracing enabled against the fixture
- **THEN** captured subscriber output contains neither the passphrase
  nor any seeded plaintext value

### Requirement: Criterion micro-benchmarks

The workspace SHALL include criterion benches for keyring seal/unseal
(Argon2id t=3/m=64MiB/p=4 + AES-256-CBC+HMAC) and EncString type-2
decrypt, tuned so the full suite runs in roughly two minutes on commodity
hardware. Benches SHALL NOT run in CI; results SHALL be recorded in
`BENCHMARKS.md` alongside harness-stage baselines with rerun
instructions.

#### Scenario: local bench run

- **WHEN** `cargo bench` is run in the workspace
- **THEN** criterion executes the keyring and EncString benches and
  completes within ~2 minutes
- **AND** CI runs unchanged (no bench jobs)

#### Scenario: recorded baselines

- **WHEN** a meaningful hot-path change lands
- **THEN** `BENCHMARKS.md` gains or updates rows with date, host, and
  measured numbers
