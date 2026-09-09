#!/usr/bin/env python3

# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Independent crypto oracle: generates test vectors via Python `cryptography`
+ hashlib (independent of the RustCrypto chain). Rust tests consume them."""
import base64
import hashlib
import hmac as _hmac
import json
import os


def b64(b):
    return base64.b64encode(b).decode()


def encstring_type2(enc_key, mac_key, plaintext):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    padlen = 16 - (len(plaintext) % 16)
    ct = enc.update(plaintext + bytes([padlen]) * padlen) + enc.finalize()
    tag = _hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return "2.%s|%s|%s" % (b64(iv), b64(ct), b64(tag))


def hkdf_expand(prk, info, length=32):
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def main():
    email = "oracle@example.com"
    password = "correct horse battery staple"
    mk = hashlib.pbkdf2_hmac("sha256", password.encode(), email.encode(), 100000, 32)
    auth = hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1, 32)
    out = {
        "email": email,
        "password": password,
        "iterations": 100000,
        "master_key": b64(mk),
        "auth_hash": b64(auth),
        "stretch_enc": b64(hkdf_expand(mk, b"enc")),
        "stretch_mac": b64(hkdf_expand(mk, b"mac")),
        "type2": encstring_type2(b"\x11" * 32, b"\x22" * 32, b"oracle-round-trip"),
    }
    d = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(d, "oracle_vectors.json"), "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(d, "oracle_type2.txt"), "w") as f:
        f.write(out["type2"])
    print("wrote", d)


if __name__ == "__main__":
    main()
