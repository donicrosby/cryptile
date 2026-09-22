#!/usr/bin/env python3

# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Live two-factor stage for the cryptile harness (openspec
add-two-factor-login, task 8).

Enables authenticator (TOTP) 2FA on the provisioned service account through
the public API — the exact flow captured in tests/fixtures/CAPTURES.md —
then proves the real binary can log in with `--2fa-env`, and restores the
fixture by disabling 2FA and re-proving plain login.

Safety: the TOTP seed and codes never reach stdout; only lengths and
pass/fail do. `SKIP_2FA_LIVE=1` degrades the whole stage to a noticed skip,
never a fabricated pass.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BIN = os.environ.get(
    "CRYPTILE_BIN",
    str(Path(__file__).resolve().parent.parent / "target" / "debug" / "cryptile"),
)
STATE_DIR = os.environ.get("CRYPTILE_STATE_DIR", "")
PASSPHRASE = os.environ.get("CRYPTILE_PASSPHRASE", "")
MASTER_PASSWORD = os.environ.get("CRYPTILE_MASTER_PASSWORD", "harness-master-password")
BASE_URL = os.environ.get("CRYPTILE_LIVE_BASE", "http://127.0.0.1:8222")
EMAIL = "svc-hermes@live.test"
ITEM_REF = os.environ.get("CRYPTILE_BENCH_REF", "vw://shared/Postgres HQ#password")

if os.environ.get("SKIP_2FA_LIVE", "") == "1":
    print("SKIP: 2fa live stage (SKIP_2FA_LIVE=1)")
    sys.exit(0)

PASS_COUNT = 0
FAIL_COUNT = 0


def pass_(label):
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"PASS: {label}")


def fail(label):
    global FAIL_COUNT
    FAIL_COUNT += 1
    print(f"FAIL: {label}")


def b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode()


def master_key(email: str, password: str, iterations: int) -> bytes:
    salt = email.strip().lower().encode()
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def auth_hash(password: str, mk: bytes) -> str:
    return b64(hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1))


def totp(seed_b32: str) -> str:
    seed = base64.b32decode(seed_b32 + "=" * ((8 - len(seed_b32) % 8) % 8))
    counter = int(time.time() // 30)
    d = hmac.new(seed, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[off:off+4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def api(method: str, path: str, body: dict, token: str = ""):
    """JSON API call against the harness. Returns (status, parsed-or-raw)."""
    url = f"{BASE_URL}/api{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Bitwarden-Client-Name", "web")
    req.add_header("Bitwarden-Client-Version", "2026.6.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def prelogin_kdf(base: str, email: str) -> int:
    """Ask the server for the account's KDF (real clients must — VW clamps
    PBKDF2 to its 600k minimum at registration regardless of what was sent).
    Returns iterations; falls back to 600000 if the shape is unexpected."""
    url = f"{base}/identity/accounts/prelogin"
    data = json.dumps({"email": email}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError):
        return 600_000
    iters = body.get("kdfIterations") or (
        (body.get("kdfSettings") or {}).get("iterations")
    )
    if not isinstance(iters, int) or iters <= 0:
        return 600_000
    return iters


def cli(argv, extra_env):
    """Run the real binary non-interactively. Returns (rc, out, err)."""
    env = dict(os.environ)
    env.update(extra_env)
    proc = subprocess.run(
        [BIN, "--state-dir", STATE_DIR, *argv],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def main() -> int:
    global FAIL_COUNT
    if not STATE_DIR or not PASSPHRASE:
        print("FAIL: 2fa stage needs CRYPTILE_STATE_DIR and CRYPTILE_PASSPHRASE")
        return 1
    if not Path(BIN).exists():
        print(f"FAIL: 2fa binary not found at {BIN}")
        return 1

    iterations = prelogin_kdf(BASE_URL, EMAIL)
    print(f"prelogin: kdfIterations={iterations}")
    mk = master_key(EMAIL, MASTER_PASSWORD, iterations)
    ah = auth_hash(MASTER_PASSWORD, mk)

    # --- login (pre-2FA baseline) to obtain the bearer for enablement ---
    login_argv = [
        "login", "--server", BASE_URL, "--account", EMAIL,
        "--passphrase-env", "CRYPTILE_PASSPHRASE",
        "--master-password-env", "CRYPTILE_MASTER_PASSWORD",
    ]
    rc, out, err = cli(login_argv, {
        "CRYPTILE_PASSPHRASE": PASSPHRASE,
        "CRYPTILE_MASTER_PASSWORD": MASTER_PASSWORD,
    })
    if rc != 0:
        print("FAIL: 2fa stage baseline login failed (rc != 0)")
        return 1
    pass_("2fa: baseline plain login")

    # Baseline read of the fixture item under the plain session — the value
    # the challenged-login session must reproduce (compared in memory only).
    rc, baseline_value, _ = cli(
        ["get", "--passphrase-env", "CRYPTILE_PASSPHRASE", "--", ITEM_REF],
        {"CRYPTILE_PASSPHRASE": PASSPHRASE},
    )
    if rc != 0 or not baseline_value.strip():
        print("FAIL: 2fa stage baseline get failed; fixture item unreadable")
        return 1

    # Enablement needs a bearer; mint one from the freshly sealed session by
    # re-running the grant here (API-level, same wire the CLI uses).
    form = urllib.parse.urlencode({
        "grant_type": "password",
        "username": EMAIL,
        "password": ah,
        "scope": "api offline_access",
        "client_id": "web",
        "deviceType": "14",
        "deviceIdentifier": "cryptile-2fa-stage",
        "deviceName": "cryptile-2fa-stage",
    }).encode()
    req = urllib.request.Request(f"{BASE_URL}/identity/connect/token", data=form)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Bitwarden-Client-Name", "web")
    req.add_header("Bitwarden-Client-Version", "2026.6.0")
    try:
        with urllib.request.urlopen(req) as resp:
            access = json.loads(resp.read().decode())["access_token"]
    except urllib.error.HTTPError as e:
        print(f"FAIL: 2fa stage could not mint bearer for enablement ({e.code})")
        return 1

    enabled = False
    seed_len = 0
    try:
        # --- enable authenticator 2FA (captured enable flow) ---
        status, body = api(
            "POST", "/two-factor/get-authenticator",
            {"masterPasswordHash": ah}, token=access,
        )
        if status != 200 or "key" not in body:
            print(f"FAIL: get-authenticator rejected ({status}); cannot stage 2FA")
            FAIL_COUNT += 1
            return FAIL_COUNT
        seed = body["key"]
        seed_len = len(seed)
        status, body = api(
            "PUT", "/two-factor/authenticator",
            {"key": seed, "masterPasswordHash": ah, "token": totp(seed)},
            token=access,
        )
        if status != 200 or body.get("enabled") is not True:
            print(f"FAIL: enable authenticator rejected ({status})")
            FAIL_COUNT += 1
            return FAIL_COUNT
        enabled = True
        pass_(f"2fa: authenticator enabled (seed len {seed_len}, never printed)")

        # Replay protection: enable consumed this window's code. Wait out the
        # window, THEN let the CLI read a fresh code from the env var.
        wait = 30 - (time.time() % 30) + 1.5
        time.sleep(wait)
        code = totp(seed)

        rc, out, err = cli(
            [*login_argv, "--2fa-env", "CRYPTILE_TOTP_CODE"],
            {
                "CRYPTILE_PASSPHRASE": PASSPHRASE,
                "CRYPTILE_MASTER_PASSWORD": MASTER_PASSWORD,
                "CRYPTILE_TOTP_CODE": code,
            },
        )
        if rc == 0:
            pass_("2fa: login --2fa-env sealed a session under challenge")
        else:
            fail(f"2fa: login --2fa-env failed rc={rc}")
            print(err.strip().splitlines()[-1] if err.strip() else "(no stderr)")

        # get parity: the challenged-login session must read the fixture item
        # exactly as the baseline session did (compared in memory).
        rc2, out2, _ = cli(
            ["get", "--passphrase-env", "CRYPTILE_PASSPHRASE", "--", ITEM_REF],
            {"CRYPTILE_PASSPHRASE": PASSPHRASE},
        )
        if rc2 == 0 and out2 == baseline_value:
            pass_("2fa: get after challenged login matches baseline (parity ok)")
        else:
            fail("2fa: get after challenged login failed or mismatched")
    finally:
        # --- teardown: disable 2FA and re-prove plain login ---
        if enabled:
            status, body = api(
                "DELETE", "/two-factor/authenticator",
                # VW 1.37.x: disable-authenticator requires the recorded key
                # plus the numeric provider type, not a path id.
                {"masterPasswordHash": ah, "key": seed, "type": 0}, token=access,
            )
            if status == 200:
                pass_("2fa: teardown disabled authenticator")
            else:
                fail(f"2fa: teardown disable returned {status} (fixture is disposable)")
        rc, _, _ = cli(login_argv, {
            "CRYPTILE_PASSPHRASE": PASSPHRASE,
            "CRYPTILE_MASTER_PASSWORD": MASTER_PASSWORD,
        })
        if rc == 0:
            pass_("2fa: plain login restored")
        else:
            fail("2fa: plain login still challenged after teardown")

    print(f"2fa stage: {PASS_COUNT} passed, {FAIL_COUNT} failed")
    return FAIL_COUNT


if __name__ == "__main__":
    sys.exit(main())
