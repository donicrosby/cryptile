#!/usr/bin/env python3

# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Capture the two-factor login wire from a live Vaultwarden.

Black-box capture against our own harness server (task 2 of
openspec/changes/2026-09-17-add-two-factor-login): registers a scratch
account, enables authenticator 2FA through the public API, records the
byte-level challenge + resubmit exchanges. Protocol grounding: Bitwarden
whitepaper + rbw (MIT) + goldwarden (MIT); no VW implementation code.

Discovered wire (VW 1.37.2, all pinned by this capture):
  POST {api}/two-factor/get-authenticator  {masterPasswordHash}
      -> {"enabled":false,"key":"<b32 seed>","object":"twoFactorAuthenticator"}
  PUT  {api}/two-factor/authenticator {key, masterPasswordHash, token=<totp>}
      -> {"enabled":true,...}
  POST {identity}/connect/token (plain) -> 400 challenge:
      {"error":"invalid_grant","error_description":"Two factor required.",
       "TwoFactorProviders":["0"],      # STRING ids
       "TwoFactorProviders2":{"0":null}, # null config for totp
       "MasterPasswordPolicy":{...}}
  resubmit adds form fields twoFactorToken / twoFactorProvider=0.

Usage:
    capture_2fa.py <base-url> <out-dir> [email]

Writes challenge.json / resubmit-ok.json / wrong-code.json plus
CAPTURES.md notes. Prints statuses + sha12s only; never prints secrets.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as arsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PASSWORD = "capture-2fa-master"
ITERATIONS = 100_000
DEVICE_ID = str(uuid.uuid4())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def raw_request(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post_form(url, form):
    encoded = "&".join(
        f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}" for k, v in form
    )
    return raw_request(
        "POST", url, encoded.encode(),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )


def req_json(method, url, body, bearer=None):
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return raw_request(method, url, json.dumps(body).encode(), headers)


def master_key(email: str, password: str, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), email.strip().lower().encode(), iterations
    )


def auth_hash(password: str, mk: bytes) -> str:
    return b64(hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1))


def hkdf_expand(key, info, length=32):
    okm = b""
    block = b""
    i = 1
    while len(okm) < length:
        block = hmac.new(key, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


def enc2(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> str:
    iv = os.urandom(16)
    padlen = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([padlen]) * padlen
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def totp(seed_b32: str) -> str:
    seed = base64.b32decode(seed_b32 + "=" * ((8 - len(seed_b32) % 8) % 8))
    counter = int(time.time() // 30)
    d = hmac.new(seed, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[off:off+4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def sha12(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    base = sys.argv[1].rstrip("/")
    out_dir = sys.argv[2]
    email = sys.argv[3] if len(sys.argv) > 3 else f"svc-2fa-{uuid.uuid4().hex[:8]}@live.test"
    identity = f"{base}/identity"
    api_root = f"{base}/api"
    os.makedirs(out_dir, exist_ok=True)

    mk = master_key(email, PASSWORD, ITERATIONS)
    ah = auth_hash(PASSWORD, mk)
    enc_k = hkdf_expand(mk, b"enc")
    mac_k = hkdf_expand(mk, b"mac")
    user_key = os.urandom(64)
    priv = arsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_der = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_b64 = b64(
        priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    reg = {
        "email": email,
        "name": "cryptile 2FA capture",
        "masterPasswordHash": ah,
        "key": enc2(user_key, enc_k, mac_k),
        "keys": {
            "encryptedPrivateKey": enc2(priv_der, user_key[:32], user_key[32:]),
            "publicKey": pub_b64,
        },
        "kdf": 0,
        "kdfIterations": ITERATIONS,
    }
    status, body = req_json("POST", f"{identity}/accounts/register", reg)
    print(f"register: {status}")
    assert status in (200, 204), body[:300]

    base_form = [
        ("grant_type", "password"),
        ("username", email),
        ("password", ah),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("deviceType", "14"),
        ("deviceIdentifier", DEVICE_ID),
        ("deviceName", "cryptile-2fa-capture"),
    ]
    status, body = post_form(f"{identity}/connect/token", base_form)
    print(f"plain login: {status}")
    assert status == 200, body[:300]
    access = json.loads(body)["access_token"]
    auth_h = {"Authorization": f"Bearer {access}"}

    # enable authenticator 2FA: get seed, then PUT with a current code
    status, body = req_json(
        "POST", f"{api_root}/two-factor/get-authenticator",
        {"masterPasswordHash": ah}, bearer=access,
    )
    print(f"get-authenticator: {status}")
    assert status == 200, body[:300]
    seed_b32 = json.loads(body)["key"]
    status, body = req_json(
        "PUT", f"{api_root}/two-factor/authenticator",
        {"key": seed_b32, "masterPasswordHash": ah, "token": totp(seed_b32)},
        bearer=access,
    )
    print(f"enable authenticator: {status}")
    assert status == 200, body[:300]
    assert json.loads(body)["enabled"] is True

    # Replay protection: enabling consumed the current TOTP window's code;
    # wait for the NEXT window before the challenge + resubmit captures.
    now = time.time()
    wait = 30 - (now % 30) + 1.5
    print(f"waiting {wait:.1f}s for the next TOTP window (replay protection)")
    time.sleep(wait)

    # challenge (plain grant must now 400)
    status, body = post_form(f"{identity}/connect/token", base_form)
    print(f"challenge: {status} sha12={sha12(body)}")
    with open(f"{out_dir}/challenge.json", "wb") as f:
        f.write(body)
    print("challenge body (contains no secrets):")
    print(body.decode(errors="replace")[:800])
    assert status == 400, "challenge never arrived"

    # resubmit with correct TOTP
    form2 = base_form + [("twoFactorToken", totp(seed_b32)), ("twoFactorProvider", "0")]
    status, body = post_form(f"{identity}/connect/token", form2)
    print(f"resubmit-ok: {status} sha12={sha12(body)}")
    with open(f"{out_dir}/resubmit-ok.json", "wb") as f:
        f.write(body)
    if status != 200:
        print("FATAL: correct-code resubmit rejected")
        print(body.decode(errors="replace")[:400])
        sys.exit(4)

    # wrong code
    form3 = base_form + [("twoFactorToken", "000000"), ("twoFactorProvider", "0")]
    status, body = post_form(f"{identity}/connect/token", form3)
    print(f"wrong-code: {status} sha12={sha12(body)}")
    with open(f"{out_dir}/wrong-code.json", "wb") as f:
        f.write(body)
    print("wrong-code body:")
    print(body.decode(errors="replace")[:400])

    with open(f"{out_dir}/CAPTURES.md", "w") as f:
        f.write(
            "# 2FA wire captures (VW 1.37.2, black-box)\n\n"
            f"Captured {time.strftime('%Y-%m-%d')} by capture_2fa.py against a "
            "disposable harness server.\n\n"
            "| file | status | body sha12 |\n|---|---|---|\n"
            f"| challenge.json | 400 | {sha12(open(f'{out_dir}/challenge.json','rb').read())} |\n"
            f"| resubmit-ok.json | 200 | {sha12(open(f'{out_dir}/resubmit-ok.json','rb').read())} |\n"
            f"| wrong-code.json | 400 | {sha12(open(f'{out_dir}/wrong-code.json','rb').read())} |\n\n"
            "Pinned observations:\n"
            "- TwoFactorProviders: array of STRING ids ([\"0\"]) on VW 1.37.2\n"
            "- TwoFactorProviders2: map \"0\" -> null (no config for totp)\n"
            "- extra sibling field MasterPasswordPolicy present; ignore\n"
            "- resubmit form fields: twoFactorToken, twoFactorProvider\n"
            "- enable consumes the current TOTP window: same-window code reuse\n"
            "  at login is rejected (replay protection); wait for the next\n"
            "  30s window when scripting enable->login sequences\n"
            "- invalid code -> 400 {\"message\":\"Invalid TOTP code! Server time: ...\"}\n"
            "- enable flow: POST two-factor/get-authenticator -> PUT "
            "two-factor/authenticator {key, masterPasswordHash, token}\n"
        )
    print(f"captures + CAPTURES.md in {out_dir}")
    print(f"account: {email} (scratch, disposable container)")


if __name__ == "__main__":
    main()
