# Design — add-observability

## Context

Two measured facts drive this change (deployment host, 2026-09-09):
cold spawn ~1 ms; keyring unlock (Argon2id t=3/m=64MiB/p=4) 76 ms. The
Hermes plugin fetch loop is one `cryptile get` subprocess per env var,
sequential — N secrets cost N×(76 ms + spawn + VW round-trip) with no
data to say when that crosses into refactor territory. Bug reproduction
today means re-deriving token lifecycle state by hand from stderr text.

OTEL was evaluated and rejected: single-binary CLI, one HTTPS peer, no
distributed system to trace; Hermes' OTLP layer is opt-in and off by
default; a collector is deployment tax with no payoff here.

## Key decisions

- **Wall-clock stages before criterion.** The question "does anything
  need refactoring" is about end-to-end latency, which only the live
  harness can answer (includes VW round-trips + Argon2). Criterion
  benches micro-measure crypto ops; useful for regression detection,
  not for architecture decisions.
- **Bench stage reuses the existing harness, not a new rig.** The
  docker-compose VW + provision.py stack already recreates server state
  deterministically. A new stage fires timed `get` fetches post-provision
  and reports p50/p95/pmax per phase (login, get, refresh-if-any).
  Baseline JSON cached in `integration/.run/` between runs for delta
  display; never committed (machine-specific).
- **`tracing` crate, not `log` + hand timing.** Ecosystem standard,
  tokio-rs, MIT/Apache-2.0 dual (passes cargo-deny), spans nest naturally
  (total → phase → request), RUST_LOG gate stays off by default. When
  disabled, the static-filter overhead is a handful of ns per span —
  noise against 76 ms Argon2.
- **Spans never carry secret material.** Fields are counts, durations,
  byte-lengths, endpoint paths — never values, keys, or refs' field
  fragments. Enforced by a unit test that captures subscriber output and
  asserts absence of fixture secrets.
- **Criterion is local tooling, not a CI gate.** `cargo bench` adds
  minutes to CI for data nobody reads per-commit. Argon2 benches use
  reduced sample_size/warm-up (76 ms/op × default 100 samples ≈ 8 s
  each, fine; the full bench suite stays under ~2 min total).
  `BENCHMARKS.md` holds hand-recorded numbers with each meaningful
  hot-path change.
- **No metric aggregation, no dashboards.** Numbers print to the stage
  log; summary JSON already exists (`CRYPTILE_LIVE_SUMMARY`). If we ever
  need trend lines, that's when OTEL/OTLP is worth revisiting.

## Non-goals

- Batch mode (`get --batch`) — that's a refactor driven by bench data,
  this change only gathers the data. Separate change if numbers justify.
- Tracing the Hermes plugin (Python side). The plugin is a thin argv
  translator; its cost is the CLI's cost, which we now measure.
- Log persistence / structured log files. RUST_LOG=debug to stderr is
  the 2 AM interface; nothing else to install.
