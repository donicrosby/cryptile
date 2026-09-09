# Benchmarks

Numbers are host-specific. Record host, date, and command with every
update; rerun before/after when touching hot paths.

## Live-harness stage (end-to-end, includes VW round-trips)

Command: `CRYPTILE_VW_BIND=0.0.0.0 CRYPTILE_LIVE_BASE=http://172.17.0.1:8222 ./integration/run_live_tests.sh`
(bench stage runs after correctness stages; `SKIP_BENCH=1` skips;
sample counts via `CRYPTILE_BENCH_N`, default 10 `get` / 3 `login`).

| Date | Host | login p50/p95/pmax (ms) | get p50/p95/pmax (ms) | Notes |
|------|------|------------------------|----------------------|-------|
| 2026-09-09 | c3b2b5e3acfd (deploy sandbox) | 1626 / 1672 / 1672 | 2401 / 2605 / 2605 | first baseline; get ≫ Argon2 (76 ms) — per-invocation full-vault sync suspected, refactor lead |

Baseline JSON lives at `integration/.run/bench-baseline.json`
(gitignored); reruns print per-phase deltas against it.

## Host micro-measurements (deployment sandbox, 2026-09-09)

- Cold process spawn, parse + fail-fast (`get`, no session): ~1 ms
- Keyring unlock, Argon2id t=3/m=64MiB/p=4 (exact cryptile params,
  4-run median of a standalone `argon2.hash_password_into` loop): 76 ms
- Implication: per-ref cost in the Hermes plugin fetch loop is dominated
  by Argon2 + VW round-trip, not process spawn. N secrets = N× that,
  serial — batch mode becomes attractive when N grows.

## Criterion benches (crypto ops only)

Command: `cargo bench` (not in CI; ~2 min budget).

| Date | Bench | p50 | Notes |
|------|-------|-----|-------|
| TBD  | keyring seal/unseal | | |
| TBD  | EncString type-2 decrypt | | |
