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
| 2026-09-09 | c3b2b5e3acfd | 1619 / 1621 / 1621 | 2326 / – / – | sync-cache change in tree but bench still resealed every get (2× Argon2); sync avoided |
| 2026-09-09 | c3b2b5e3acfd | 1619 / 1681 / 1681 | 1178 / 1331 / 1331 | warm cache + reseal-only-on-change; get is now Argon2-bound (unlock ~1.17 s, all network < 10 ms) |

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

Command: `cargo bench` (not in CI; ~40 s total: 2×Argon2-bound benches at
sample_size 10 + 1 fast decrypt bench).

| Date | Bench | Median | Notes |
|------|-------|-----|-------|
| 2026-09-09 | keyring/seal | 78.8 ms | Argon2id t=3/m=64MiB/p=4 dominates; salt+iv fresh per call |
| 2026-09-09 | keyring/open | 78.0 ms | same KDF cost; AES+HMAC afterward is µs-scale |
| 2026-09-09 | encstring/decrypt_type2_64b | 357 ns | MAC-verify + AES-CBC decrypt of a 64-byte payload |

Reading: per-secret crypto overhead in a `get` is ~78 ms Argon2 (once per
CLI invocation) plus sub-µs field decrypts — the 2.4 s live `get` p50 is
network/sync-bound, not crypto-bound. Any `get` latency refactor targets
the sync path (targeted cipher fetch or caching), not the crypto.
