#!/usr/bin/env python3

# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Bench stage for the cryptile live harness.

Times end-to-end `login` (3 samples) and `get` (N samples, default 10,
CRYPTILE_BENCH_N) against the provisioned Vaultwarden fixture using the
non-interactive --passphrase-env path — the exact argv shape the Hermes
plugin uses. Reports p50/p95/pmax wall-clock per phase, prints deltas
against the previous run's baseline, and folds the numbers into the
provision summary JSON.

Safety: only timings and exit codes are ever printed or persisted. Secret
values stay in the child's stdout, which is captured and discarded.
"""

import json
import math
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BIN = os.environ.get("CRYPTILE_BIN", str(Path(__file__).resolve().parent.parent / "target" / "debug" / "cryptile"))
STATE_DIR = os.environ.get("CRYPTILE_STATE_DIR", "")
PASSPHRASE = os.environ.get("CRYPTILE_PASSPHRASE", "")
MASTER_PASSWORD = os.environ.get("CRYPTILE_MASTER_PASSWORD", "harness-master-password")
SUMMARY_PATH = os.environ.get("CRYPTILE_LIVE_SUMMARY", "")
BASE_URL = os.environ.get("CRYPTILE_LIVE_BASE", "http://127.0.0.1:8222")
EMAIL = os.environ.get("CRYPTILE_BENCH_EMAIL", "svc-hermes@live.test")
GET_REF = os.environ.get("CRYPTILE_BENCH_REF", "vw://shared/Postgres HQ#password")
GET_N = int(os.environ.get("CRYPTILE_BENCH_N", "10"))
LOGIN_N = int(os.environ.get("CRYPTILE_BENCH_LOGIN_N", "3"))
RUN_DIR = Path(__file__).resolve().parent / ".run"
BASELINE_PATH = RUN_DIR / "bench-baseline.json"

# Sanity ceilings only — catches pathological regressions, not
# performance policing. Live VW over compose is allowed to be slow.
SANITY_MS = {"login": 30_000, "get": 15_000}


def timed_run(argv, extra_env):
    env = dict(os.environ)
    env.update(extra_env)
    t0 = time.perf_counter()
    proc = subprocess.run(
        argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return proc.returncode, elapsed_ms


def percentile(samples, q):
    """Nearest-rank percentile; samples must be non-empty."""
    ordered = sorted(samples)
    idx = max(0, min(len(ordered) - 1, math.ceil(q / 100.0 * len(ordered)) - 1))
    return ordered[idx]


def stats(samples):
    return {
        "p50": round(percentile(samples, 50), 1),
        "p95": round(percentile(samples, 95), 1),
        "pmax": round(max(samples), 1),
    }


def bench_phase(label, argv, extra_env, n):
    print(f"-- bench {label}: {n} samples --")
    times, bad_rc = [], 0
    for i in range(n):
        rc, ms = timed_run(argv, extra_env)
        if rc != 0:
            bad_rc += 1
            print(f"FAIL: bench {label} run {i + 1}/{n} exited {rc}")
        else:
            times.append(ms)
    if bad_rc:
        print(f"FAIL: bench {label} completed {len(times)}/{n} runs rc=0")
        return None
    print(f"PASS: bench {label} completed {n}/{n} runs rc=0")
    s = stats(times)
    print(f"bench {label}: p50={s['p50']:.0f}ms p95={s['p95']:.0f}ms pmax={s['pmax']:.0f}ms")
    if s["p50"] > SANITY_MS[label]:
        print(f"FAIL: bench {label} p50 {s['p50']:.0f}ms exceeds sanity ceiling {SANITY_MS[label]}ms")
    else:
        print(f"PASS: bench {label} p50 {s['p50']:.0f}ms within sanity ceiling {SANITY_MS[label]}ms")
    return s


def print_delta(label, current, baseline):
    prev = baseline.get(label)
    if not prev:
        return
    for key in ("p50", "p95", "pmax"):
        old, new = prev.get(key), current.get(key)
        if old is None or new is None:
            continue
        delta = new - old
        pct = (delta / old * 100.0) if old else 0.0
        print(f"bench {label} {key} vs baseline: {delta:+.0f}ms ({pct:+.0f}%)")


def main():
    if not STATE_DIR or not PASSPHRASE:
        print("FAIL: bench needs CRYPTILE_STATE_DIR and CRYPTILE_PASSPHRASE")
        return 1
    if not Path(BIN).exists():
        print(f"FAIL: bench binary not found at {BIN}")
        return 1

    common = [BIN, "--state-dir", STATE_DIR]
    login_argv = common + [
        "login", "--server", BASE_URL, "--account", EMAIL,
        "--passphrase-env", "CRYPTILE_PASSPHRASE",
        "--master-password-env", "CRYPTILE_MASTER_PASSWORD",
    ]
    get_argv = common + ["get", "--passphrase-env", "CRYPTILE_PASSPHRASE", "--", GET_REF]
    child_env = {"CRYPTILE_PASSPHRASE": PASSPHRASE, "CRYPTILE_MASTER_PASSWORD": MASTER_PASSWORD}

    baseline = {}
    if BASELINE_PATH.exists():
        try:
            baseline = json.loads(BASELINE_PATH.read_text()).get("phases", {})
        except (json.JSONDecodeError, OSError):
            print("note: unreadable bench baseline ignored")

    print("bench: N=%d get, %d login (phase wall-clock, ms)" % (GET_N, LOGIN_N))
    login_stats = bench_phase("login", login_argv, child_env, LOGIN_N)
    get_stats = bench_phase("get", get_argv, child_env, GET_N)

    ok = login_stats is not None and get_stats is not None
    if ok:
        for label, s in (("login", login_stats), ("get", get_stats)):
            print_delta(label, s, baseline)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "host": platform.node(),
            "get_n": GET_N,
            "login_n": LOGIN_N,
            "phases": {"login": login_stats, "get": get_stats},
        }
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(json.dumps(record, indent=2) + "\n")
        if SUMMARY_PATH:
            try:
                summary = json.loads(Path(SUMMARY_PATH).read_text())
                summary["bench"] = record
                Path(SUMMARY_PATH).write_text(json.dumps(summary, indent=2) + "\n")
            except (json.JSONDecodeError, OSError) as exc:
                print(f"note: could not fold bench into summary ({exc})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
