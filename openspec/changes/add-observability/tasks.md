# Tasks — add-observability

- [ ] 1.1 Bench stage: `integration/bench_stage.py` — post-provision timed `get` fetches (default N=10, `CRYPTILE_BENCH_N`), per-phase p50/p95/pmax, PASS/FAIL lines + JSON fold into summary; `SKIP_BENCH=1` skip
- [ ] 1.2 Wire stage into `integration/run_live_tests.sh` after correctness stages; baseline JSON cached in `integration/.run/bench-baseline.json`, delta printed on rerun
- [ ] 1.3 Baseline run against live VW; record numbers in `BENCHMARKS.md` (host, date, p50/p95/pmax per phase)
- [ ] 2.1 Workspace deps `tracing` + `tracing-subscriber` (env-filter feature); `fmt` gate still clean
- [ ] 2.2 Spans in `crates/cli` (ref parse, keyring unlock, total) + `crates/vaultwarden` (per-endpoint request); RUST_LOG runtime gate, default off
- [ ] 2.3 Secret-redaction test: captured span output contains no fixture passphrase/secret values (fields are counts/durations/lengths only)
- [ ] 2.4 Verify spans fire: `RUST_LOG=cryptile=debug` run shows phase durations on a live fetch; absent when unset
- [ ] 3.1 Criterion `benches/` in cryptile-core (keyring seal/unseal, Argon2 unlock) + cryptile-vaultwarden (EncString type-2 decrypt); sample_size/warm-up tuned so full suite < 2 min
- [ ] 3.2 `BENCHMARKS.md`: criterion table + harness-stage table + rerun instructions
- [ ] 3.3 Gates: fmt/clippy/test workspace, `cargo bench` compiles, `openspec validate add-observability --strict`
- [ ] 3.4 Commit, push, CI green, archive
