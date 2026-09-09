## ADDED Requirements

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
