# Tasks — add-observability

- [x] 1.1 Bench stage: `integration/bench_stage.py` — post-provision timed `get` fetches (default N=10, `CRYPTILE_BENCH_N`), per-phase p50/p95/pmax, PASS/FAIL lines + JSON fold into summary; `SKIP_BENCH=1` skip
- [x] 1.2 Wire stage into `integration/run_live_tests.sh` after correctness stages; baseline JSON cached in `integration/.run/bench-baseline.json`, delta printed on rerun
- [x] 1.3 Baseline run against live VW; record numbers in `BENCHMARKS.md` (host, date, p50/p95/pmax per phase)
- [x] 2.1 Workspace deps `tracing` + `tracing-subscriber` (env-filter feature); `fmt` gate still clean
- [x] 2.2 Spans in `crates/cli` (ref parse, keyring unlock, total) + `crates/vaultwarden` (per-endpoint request); RUST_LOG runtime gate, default off
- [x] 2.3 Secret-redaction test: captured span output contains no fixture passphrase/secret values (fields are counts/durations/lengths only)
- [x] 2.4 Verify spans fire: `RUST_LOG=cryptile=debug` run shows phase durations on a live fetch; absent when unset (unit test `tracing_gates` + permanent check in bench stage)
- [x] 3.1 Criterion `benches/` in cryptile-core (keyring seal/unseal, Argon2 unlock) + cryptile-vaultwarden (EncString type-2 decrypt); sample_size/warm-up tuned so full suite < 2 min
- [x] 3.2 `BENCHMARKS.md`: criterion table + harness-stage table + rerun instructions
- [x] 3.3 Gates: fmt/clippy/test workspace, `cargo bench` compiles, `openspec validate add-observability --strict`
- [x] 3.4 Commit, push, CI green, archive
