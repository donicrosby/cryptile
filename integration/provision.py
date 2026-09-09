#!/usr/bin/env python3

# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Vaultwarden bootstrap for the cryptile live integration harness.

Implements the client side of the Bitwarden protocol (KDF, auth hash,
EncString sealing, org key wrap) independently of cryptile's Rust code, so
the live run is a genuine cross-check rather than self-validation.

Protocol grounding: Bitwarden security whitepaper, cross-verified against
rbw (MIT) and goldwarden (MIT). No Vaultwarden implementation code.

Usage:
    provision.py <base-url> <email> <password>

Prints a JSON summary (uuids only) on stdout. Never prints secrets.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITERATIONS = 100_000  # pinned low for harness speed; VW stores what we send

ORG_NAME = "hermes"
COLLECTION = "shared"
ITEM_NAME = "Postgres HQ"
ITEM_USERNAME = "svc_dashboard"
# Random per-run: printed nowhere. The harness script re-derives it from the
# provision summary written to the scratch dir (not stdout).
ITEM_PASSWORD = "live-" + uuid.uuid4().hex

DEVICE_ID = str(uuid.uuid4())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def api(method: str, url: str, body=None, token: str | None = None,
        form: list[tuple[str, str]] | None = None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if form is not None:
        # urlencoded form for identity endpoints
        encoded = "&".join(
            f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}" for k, v in form
        )
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = encoded.encode()
    elif body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
            return resp.status, json.loads(payload) if payload else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        # surface the failing hop's name loudly; body may contain the reason
        raise RuntimeError(f"HTTP {e.code} {method} {url}: {detail[:300]}") from e


def normalize_identity(email: str) -> str:
    return email.strip().lower()


def master_key(email: str, password: str, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), normalize_identity(email).encode(), iterations
    )


def auth_hash(password: str, mk: bytes) -> str:
    # PBKDF2(mk, password, 1) -> b64 (single iteration, per whitepaper)
    return b64(hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1))


def hkdf_expand(key: bytes, info: bytes, length: int = 32) -> bytes:
    # HKDF-Expand only (extract skipped: master key IS high-entropy key material)
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(key, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def enc_string_type2(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> str:
    """AES-256-CBC + HMAC-SHA256 encrypt-then-MAC, Bitwarden EncString type 2."""
    iv = os.urandom(16)
    # PKCS7 pad
    padlen = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([padlen]) * padlen
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def enc_string_type4(plaintext: bytes, public_key) -> str:
    """RSA-2048 OAEP-SHA1 wrap, Bitwarden EncString type 4 (org keys)."""
    ct = public_key.encrypt(
        plaintext,
        apadding.OAEP(
            mgf=apadding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return f"4.{b64(ct)}"


def main() -> None:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    base, email, password = sys.argv[1], sys.argv[2], sys.argv[3]
    base = base.rstrip("/")
    identity = f"{base}/identity"
    api_root = f"{base}/api"

    # --- prelogin (VW returns the defaults; we register with our own KDF) ---
    _, pre = api("POST", f"{identity}/accounts/prelogin", {"email": email})
    # NOTE: prelogin for a not-yet-existing account returns default params;
    # registration declares the account's actual KDF.

    # --- register ---
    mk = master_key(email, password, ITERATIONS)
    ah = auth_hash(password, mk)
    enc_k = hkdf_expand(mk, b"enc", 32)
    mac_k = hkdf_expand(mk, b"mac", 32)
    user_key = os.urandom(64)  # 64 bytes: [enc 32 | mac 32]
    protected_user_key = enc_string_type2(user_key, enc_k, mac_k)

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_der = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    protected_private_key = enc_string_type2(priv_der, user_key[:32], user_key[32:])
    pub_b64 = b64(
        priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    reg = {
        "email": email,
        "name": "cryptile harness",
        "masterPasswordHash": ah,
        "key": protected_user_key,
        "keys": {
            "encryptedPrivateKey": protected_private_key,
            "publicKey": pub_b64,
        },
        "kdf": 0,
        "kdfIterations": ITERATIONS,
    }
    api("POST", f"{identity}/accounts/register", reg)

    # --- login ---
    _, tok = api("POST", f"{identity}/connect/token", form=[
        ("grant_type", "password"),
        ("username", email),
        ("password", ah),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("deviceType", "14"),
        ("deviceIdentifier", DEVICE_ID),
        ("deviceName", "cryptile-live-harness"),
    ])
    access = tok["access_token"]

    # --- org + collection (create_organization makes both) ---
    org_key = os.urandom(64)
    # Real Bitwarden clients wrap the org key for the user with the user's
    # RSA PUBLIC key (EncString type 4, RSA-OAEP-SHA1), not the symmetric
    # user key. Cryptile unwraps type 4 with the account private key.
    org_key_wrapped_for_user = enc_string_type4(
        org_key,
        priv.public_key(),
    )
    # The initial collection name is stored verbatim by VW, so it must be
    # sent already encrypted with the org key (type 2), like a real client.
    ok_enc, ok_mac = org_key[:32], org_key[32:]
    def seal(pt: str) -> str:
        return enc_string_type2(pt.encode(), ok_enc, ok_mac)

    org = api("POST", f"{api_root}/organizations", {
        "billingEmail": email,
        "collectionName": seal(COLLECTION),
        "key": org_key_wrapped_for_user,
        "name": ORG_NAME,
        "planType": "0",
    }, token=access)[1]
    org_id = org["id"]

    # --- fetch collections to get the collection uuid ---
    _, colls = api("GET", f"{api_root}/organizations/{org_id}/collections", token=access)
    coll_id = colls["data"][0]["id"]

    # --- seed org cipher in the shared collection ---
    api("POST", f"{api_root}/ciphers/create", token=access, body={
        "cipher": {
            "type": 1,
            "organizationId": org_id,
            "name": seal(ITEM_NAME),
            "notes": None,
            "login": {
                "username": seal(ITEM_USERNAME),
                "password": seal(ITEM_PASSWORD),
                "uris": [],
            },
            "secureNote": None,
            "card": None,
    "identity": None,
        },
        "collectionIds": [coll_id],
    })

    # --- seed personal cipher (namespace noise) ---
    uk_enc, uk_mac = user_key[:32], user_key[32:]
    api("POST", f"{api_root}/ciphers", token=access, body={
        "type": 1,
        "name": enc_string_type2("Personal Noise".encode(), uk_enc, uk_mac),
        "notes": None,
        "login": {
            "username": enc_string_type2("me".encode(), uk_enc, uk_mac),
            "password": enc_string_type2("personal-noise-pass".encode(), uk_enc, uk_mac),
            "uris": [],
        },
        "secureNote": None,
        "card": None,
        "identity": None,
    })

    # --- summary (uuids + the plaintext the runner will assert on) ---
    # The plaintext goes to the scratch summary file, not stdout.
    summary = {
        "org_id": org_id,
        "collection_id": coll_id,
        "item_name": ITEM_NAME,
        "item_username": ITEM_USERNAME,
        "email": email,
    }
    with open(os.environ["CRYPTILE_LIVE_SUMMARY"], "w") as f:
        json.dump({**summary, "item_password": ITEM_PASSWORD}, f)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
