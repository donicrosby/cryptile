# Change Proposal: add-observability

## Why

We have zero performance data on the hot path. Two measured baselines on
the deployment host (2026-09-09): cold spawn ~1 ms, keyring unlock
(Argon2id t=3/m=64MiB/p=4) 76 ms per invocation. The Hermes plugin fires
one `cryptile get` subprocess per env var, sequentially, so N secrets
cost N×(76 ms Argon2 + spawn + VW round-trip), all serial. Nothing tells
us when that crosses into "refactor now" territory, and there is no
reproducible way to time end-to-end fetches against a real Vaultwarden.

Separately, when something breaks at 2 AM we currently have CLI stderr
text and nothing else. Reproducing "what did the token lifecycle actually
do" means re-deriving it by hand.

OTEL was evaluated and rejected for now: single-binary CLI talking to one
HTTPS peer — no distributed system to trace; Hermes' OTLP export layer
(`agent/monitoring/*`) is opt-in and disabled by default, and deploying a
collector just for cryptile is infra tax with no payoff. All
observability here is local: benches + harness stage + phase tracing.

## What Changes

Three deliverables in priority order (user-approved 2026-09-09):

1. **Live-harness bench stage** (priority 1). New stage in
   `integration/run_live_tests.sh` running after correctness stages:
   fires N end-to-end fetches (login → get) against the docker-compose
   Vaultwarden fixture and reports p50/p95/pmax wall-clock per phase.
   Numbers land in the stage log and the summary JSON. Baseline captured
   on first run; subsequent runs print delta vs baseline file.
   Parameterized: N via env (`CRYPTILE_BENCH_N`, default 10). Skippable
   with `SKIP_BENCH=1` like other stages.

2. **Phase tracing** (priority 2). RUST_LOG-gated `tracing`-crate spans
   across CLI phases: ref parse, keyring unlock, VW request (per
   endpoint), decrypt, total. New workspace deps `tracing` +
   `tracing-subscriber` (tokio-rs, MIT/Apache-2.0 — consistent with the
   dependency policy; cargo-deny verifies). Default off via runtime
   filter, zero cost when disabled. Never logs secret material — spans
   record counts and durations, not values (enforced by test).

3. **Criterion benches** (priority 3). `benches/` in cryptile-core and
   cryptile-vaultwarden: keyring unlock (Argon2), keyring seal/unseal
   (AES-CBC+HMAC), EncString type-2 decrypt. Argon2 at ~76 ms/op means
   reduced sample_size and warm-up so total `cargo bench` stays under
   ~2 min. Not in CI by default — bench mode is a tool you run when
   touching hot paths, not a gate; results checked into `BENCHMARKS.md`
   at repo root with each meaningful hot-path change.

## Impact

- `integration/run_live_tests.sh` + new `integration/bench_stage.py`
- `Cargo.toml` (workspace): `tracing`, `tracing-subscriber` workspace deps
- `crates/cli/Cargo.toml` + phase spans in CLI code paths
- `crates/vaultwarden/Cargo.toml` + spans around VW request phases
- `crates/{core,vaultwarden}/benches/*.rs`
- Spec delta: `foundation` gains observability requirements
- docs: `BENCHMARKS.md` at repo root (baseline table + rerun instructions)

Delivery order is the priority order: bench stage → tracing → criterion.
Criterion-out-of-CI is deliberate: keeps `cargo test --workspace` fast.
