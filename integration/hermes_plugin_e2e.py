# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Live E2E: CryptileSource.fetch() + Hermes apply_all() against live VW.

Runs AFTER run_live_tests.sh has provisioned VW, logged in, and left the
sealed state at $STATE_DIR. This script:
  1. puts the hermes-agent checkout + repo root on sys.path
  2. registers CryptileSource the way the plugin loader would
  3. runs fetch() directly (mapped binding to the seeded item)
  4. runs the REAL orchestrator apply_all() over a fresh env dict
  5. asserts: value matches seeded plaintext, provenance names cryptile,
     wrong-passphrase maps AUTH_FAILED, missing item maps EMPTY_VALUE

Prints PASS/FAIL lines only (no plaintext). Exit code = failure count.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HERMES_REPO = Path(os.environ.get("HERMES_REPO", "/tmp/hermes"))

passed = failed = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"PASS: {label}")
    else:
        failed += 1
        print(f"FAIL: {label}{(' — ' + detail) if detail else ''}")


def main() -> int:
    for p in (str(HERMES_REPO), str(REPO)):
        if Path(p).is_dir() and p not in sys.path:
            sys.path.insert(0, p)

    from integrations.hermes import CryptileSource  # noqa: E402
    from agent.secret_sources import registry  # noqa: E402

    summary = json.loads(Path(os.environ["CRYPTILE_LIVE_SUMMARY"]).read_text())
    item_password = summary["item_password"]
    item_name = summary["item_name"]
    state_dir = os.environ["CRYPTILE_STATE_DIR"]
    passphrase = os.environ["CRYPTILE_PASSPHRASE"]
    os.environ["CRYPTILE_PASSPHRASE"] = passphrase  # for run_secret_cli allow_env

    src = CryptileSource()
    cfg = {
        "enabled": True,
        "env": {"LIVE_TEST_SECRET": f"vw://shared/{item_name}#password"},
        "state_dir": state_dir,
        # harness: pin the just-built binary; installed setups use PATH
        "binary_path": str(REPO / "target" / "debug" / "cryptile"),
    }

    # --- direct fetch -----------------------------------------------------
    r = src.fetch(cfg, Path(state_dir))
    check("plugin fetch ok", r.ok, r.error or "")
    if r.ok:
        got = r.secrets.get("LIVE_TEST_SECRET", "")
        check("plugin fetch returns seeded plaintext", got == item_password,
              f"len {len(got)} vs {len(item_password)}")

    # --- real orchestrator ------------------------------------------------
    registry._reset_registry_for_tests()
    assert registry.register_source(src)
    env: dict = {}
    report = registry.apply_all({"cryptile": cfg}, Path(state_dir), environ=env)
    check("apply_all applied LIVE_TEST_SECRET", env.get("LIVE_TEST_SECRET") == item_password,
          "value mismatch")
    names = [s.name for s in report.sources]
    check("apply_all saw cryptile source", "cryptile" in names, f"sources={names}")
    applied_var = report.provenance.get("LIVE_TEST_SECRET")
    check("provenance names cryptile",
          applied_var is not None and getattr(applied_var, "source", "") == "cryptile",
          f"provenance={applied_var}")

    # --- failure modes ----------------------------------------------------
    bad_pp = dict(cfg, env={"LIVE_TEST_SECRET": f"vw://shared/{item_name}#nosuchfield"})
    r2 = src.fetch(bad_pp, Path(state_dir))
    check("missing field maps EMPTY_VALUE", r2.error_kind is not None and
          "empty" in r2.error_kind.value, str(r2.error_kind))

    os.environ["CRYPTILE_PASSPHRASE"] = "wrong-passphrase"
    r3 = src.fetch(cfg, Path(state_dir))
    check("wrong passphrase maps AUTH_FAILED", r3.error_kind is not None and
          "auth" in r3.error_kind.value, str(r3.error_kind))
    os.environ["CRYPTILE_PASSPHRASE"] = passphrase

    print(f"\nplugin e2e: {passed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    sys.exit(main())
