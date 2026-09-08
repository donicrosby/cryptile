#!/usr/bin/env python3
"""Full-fixture oracle: builds a complete VW login+sync scenario with real
crypto (Python cryptography lib) for the Rust wiremock integration test.
The Rust side must derive the same keys and decrypt everything."""
import base64
import hashlib
import hmac as _hmac
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def b64(b):
    return base64.b64encode(b).decode()


def enc2(enc_key, mac_key, plaintext):
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
    email = "svc-hermes@oracle.test"
    password = "hunter2 but actually good"
    iterations = 10000

    # Master key + auth hash + stretch (identical to Rust kdf.rs chain).
    mk = hashlib.pbkdf2_hmac("sha256", password.encode(), email.encode(), iterations, 32)
    auth = base64.b64encode(
        hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1, 32)
    ).decode()
    s_enc = hkdf_expand(mk, b"enc")
    s_mac = hkdf_expand(mk, b"mac")

    # User key + protected blob.
    user_enc = os.urandom(32)
    user_mac = os.urandom(32)
    protected_user_key = enc2(s_enc, s_mac, user_enc + user_mac)

    # RSA keypair: private key protected by the user key.
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pkcs8 = sk.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    protected_private_key = enc2(user_enc, user_mac, pkcs8)

    # Org key, wrapped via RSA-OAEP-SHA1 with the account public key.
    org_enc = os.urandom(32)
    org_mac = os.urandom(32)
    wrapped = sk.public_key().encrypt(
        org_enc + org_mac,
        apad.OAEP(
            mgf=apad.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    org_key_encstring = "4." + b64(wrapped)

    # Ciphers: one personal, one org item in collection "shared".
    personal_name = enc2(user_enc, user_mac, b"personal-item")
    personal_pw = enc2(user_enc, user_mac, b"personal-secret")
    org_name = enc2(org_enc, org_mac, b"smtp")
    org_pw = enc2(org_enc, org_mac, b" hunter2-org")
    coll_name = enc2(org_enc, org_mac, b"shared")

    fixture = {
        "email": email,
        "password": password,
        "iterations": iterations,
        "auth_hash": auth,
        "protected_user_key": protected_user_key,
        "protected_private_key": protected_private_key,
        "org_key": org_key_encstring,
        "personal": {
            "name": personal_name,
            "password": personal_pw,
            "id": "c1",
        },
        "org": {
            "name": org_name,
            "password": org_pw,
            "id": "c2",
            "collection": "coll-shared-uuid",
            "org_id": "org-uuid",
            "coll_name": coll_name,
        },
        "expect": {
            "personal_item_password": "personal-secret",
            "org_item_password": " hunter2-org",
            "coll_name": "shared",
        },
    }
    d = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(d, "wiremock_fixture.json"), "w") as f:
        json.dump(fixture, f, indent=2)
    print("fixture written")


if __name__ == "__main__":
    main()
