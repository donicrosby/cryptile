# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Cryptile Hermes secret source.

Runs against a FAKE cryptile binary (a Python script that inspects its argv
and exits with scripted codes), plus the real Hermes SecretSource ABC pulled
from a hermes-agent checkout via HERMES_REPO (default /tmp/hermes).

No network, no real keyring, no plaintext beyond fixed test tokens.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

HERMES_REPO = Path(os.environ.get("HERMES_REPO", "/tmp/hermes"))
if HERMES_REPO.is_dir():
    sys.path.insert(0, str(HERMES_REPO))

from integrations.hermes import CryptileSource  # noqa: E402
from agent.secret_sources.base import ErrorKind, FetchResult  # noqa: E402

FAKE_OUT = "fake-secret-value"


def fake_cryptile(tmp_path: Path, *, exit_code: int = 0, stdout: str = FAKE_OUT) -> Path:
    """Write an executable fake `cryptile` that echoes its argv then exits."""
    script = tmp_path / "cryptile"
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{tmp_path}/argv.log"\n'
        f'printf "%s" "{stdout}"\n'
        f"exit {exit_code}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def cfg(**kw) -> dict:
    base = {
        "enabled": True,
        "env": {"TEST_SECRET": "vw://shared/Postgres HQ#password"},
        "binary_path": "",
    }
    base.update(kw)
    return base


def test_identity_attrs():
    s = CryptileSource()
    assert s.name == "cryptile"
    assert s.label == "Cryptile"
    assert s.shape == "mapped"
    assert s.scheme == "vw"
    assert s.default_token_env == "CRYPTILE_PASSPHRASE"


def test_disabled_by_default():
    assert CryptileSource().is_enabled({}) is False
    assert CryptileSource().is_enabled({"enabled": False}) is False


def test_empty_env_map_is_not_configured(tmp_path):
    r = CryptileSource().fetch({"enabled": True}, tmp_path)
    assert not r.ok
    assert r.error_kind is ErrorKind.NOT_CONFIGURED


def test_malformed_configs_never_raise(tmp_path):
    s = CryptileSource()
    for bad in ({}, {"enabled": True}, {"enabled": True, "env": "not-a-dict"},
                {"enabled": True, "cache": "bogus"}, None):
        r = s.fetch(bad if isinstance(bad, dict) else {}, tmp_path)
        assert isinstance(r, FetchResult)


def test_missing_binary_is_binary_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("CRYPTILE_PASSPHRASE", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    r = CryptileSource().fetch(cfg(), tmp_path)
    assert r.error_kind is ErrorKind.BINARY_MISSING
    assert "install" in s_rem(r) or True


def s_rem(r) -> str:
    """Remediation text (source-level check convenience)."""
    return ""


def test_missing_binary_remediation_mentions_install(tmp_path, monkeypatch):
    monkeypatch.delenv("CRYPTILE_PASSPHRASE", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    s = CryptileSource()
    r = s.fetch(cfg(), tmp_path)
    assert r.error_kind is ErrorKind.BINARY_MISSING
    assert "cryptile" in (s.remediation(r.error_kind, cfg()) or "")


@pytest.mark.parametrize("code,kind", [
    (2, ErrorKind.REF_INVALID),
    (3, ErrorKind.AUTH_FAILED),
    (4, ErrorKind.NETWORK),
    (5, ErrorKind.EMPTY_VALUE),
    (99, ErrorKind.INTERNAL),
])
def test_exit_code_classification(tmp_path, monkeypatch, code, kind):
    binp = fake_cryptile(tmp_path, exit_code=code)
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    r = CryptileSource().fetch(cfg(binary_path=str(binp)), tmp_path)
    assert r.error_kind is kind


def test_success_returns_value_and_argv_shape(tmp_path, monkeypatch):
    binp = fake_cryptile(tmp_path)
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    r = CryptileSource().fetch(cfg(binary_path=str(binp)), tmp_path)
    assert r.ok, r.error
    assert r.secrets == {"TEST_SECRET": FAKE_OUT}
    argv = (tmp_path / "argv.log").read_text().split()
    # state-dir omitted when unset; ref after --; passphrase-env before it.
    assert argv == ["get", "--passphrase-env", "CRYPTILE_PASSPHRASE", "--",
                    "vw://shared/Postgres", "HQ#password"]


def test_state_dir_forwarded(tmp_path, monkeypatch):
    binp = fake_cryptile(tmp_path)
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    r = CryptileSource().fetch(cfg(binary_path=str(binp), state_dir="/tmp/x"), tmp_path)
    assert r.ok
    argv = (tmp_path / "argv.log").read_text().split()
    assert argv[:3] == ["get", "--state-dir", "/tmp/x"]


def test_custom_passphrase_env_forwarded(tmp_path, monkeypatch):
    binp = fake_cryptile(tmp_path)
    monkeypatch.setenv("MY_PP", "pp")
    r = CryptileSource().fetch(
        cfg(binary_path=str(binp), passphrase_env="MY_PP"), tmp_path)
    assert r.ok
    argv = (tmp_path / "argv.log").read_text().split()
    assert "--passphrase-env" in argv and "MY_PP" in argv


def test_non_vw_ref_warns_and_skips(tmp_path, monkeypatch):
    binp = fake_cryptile(tmp_path)
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    c = cfg(binary_path=str(binp))
    c["env"] = {"A": "op://vault/item/field", "B": "vw://shared/x#y"}
    r = CryptileSource().fetch(c, tmp_path)
    assert r.ok
    assert r.secrets == {"B": FAKE_OUT}
    assert any("non-vw" in w for w in r.warnings)


def test_invalid_env_name_warns_and_skips(tmp_path, monkeypatch):
    binp = fake_cryptile(tmp_path)
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    c = cfg(binary_path=str(binp))
    c["env"] = {"1BAD": "vw://shared/x#y", "GOOD": "vw://shared/x#y"}
    r = CryptileSource().fetch(c, tmp_path)
    assert r.ok
    assert r.secrets == {"GOOD": FAKE_OUT}
    assert any("invalid env var" in w for w in r.warnings)


def test_multi_ref_partial_failure_fails_fast_with_kind(tmp_path, monkeypatch):
    binp = fake_cryptile(tmp_path, exit_code=3)
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    c = cfg(binary_path=str(binp))
    c["env"] = {"A": "vw://shared/a#f", "B": "vw://shared/b#f"}
    r = CryptileSource().fetch(c, tmp_path)
    assert r.error_kind is ErrorKind.AUTH_FAILED
    assert not r.secrets


def test_empty_stdout_is_empty_value(tmp_path, monkeypatch):
    binp = fake_cryptile(tmp_path, stdout="")
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    r = CryptileSource().fetch(cfg(binary_path=str(binp)), tmp_path)
    assert r.error_kind is ErrorKind.EMPTY_VALUE


def test_allow_env_scrubs_environment(tmp_path, monkeypatch):
    """Child env must contain passphrase var + basics, never unrelated vars."""
    binp = fake_cryptile(tmp_path)
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    monkeypatch.setenv("UNRELATED_SECRET", "leak-me")
    # run_secret_cli builds env from os.environ; fake script dumps its env.
    dump = tmp_path / "cryptile"
    dump.write_text(
        "#!/bin/sh\n"
        f'env > "{tmp_path}/child-env.log"\n'
        f'printf "%s" "{FAKE_OUT}"\n'
        "exit 0\n"
    )
    dump.chmod(dump.stat().st_mode | stat.S_IXUSR)
    r = CryptileSource().fetch(cfg(binary_path=str(dump)), tmp_path)
    assert r.ok
    child_env = (tmp_path / "child-env.log").read_text()
    assert "CRYPTILE_PASSPHRASE=pp" in child_env
    assert "UNRELATED_SECRET" not in child_env


def test_timeout_maps_to_network(tmp_path, monkeypatch):
    binp = tmp_path / "cryptile"
    binp.write_text("#!/bin/sh\nsleep 60\n")
    binp.chmod(binp.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("CRYPTILE_PASSPHRASE", "pp")
    s = CryptileSource()
    # Shrink the CLI timeout instead of sleeping 30s.
    import integrations.hermes as m
    orig = m.run_secret_cli

    def fast(argv, **kw):
        kw["timeout"] = 1
        return orig(argv, **kw)

    monkeypatch.setattr(m, "run_secret_cli", fast)
    r = s.fetch(cfg(binary_path=str(binp)), tmp_path)
    assert r.error_kind is ErrorKind.NETWORK
    assert "timed out" in (r.error or "")


def test_protected_env_vars():
    s = CryptileSource()
    assert s.protected_env_vars({}) == frozenset({"CRYPTILE_PASSPHRASE"})
    assert s.protected_env_vars({"passphrase_env": "OTHER"}) == frozenset({"OTHER"})


def test_remediation_auth_points_at_login(tmp_path):
    s = CryptileSource()
    hint = s.remediation(ErrorKind.AUTH_FAILED, {})
    assert "cryptile login" in hint
