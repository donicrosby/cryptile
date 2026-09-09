#!/usr/bin/env python3

# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
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
    # Org notes carry a newline + backslash to pin export escaping.
    personal_name = enc2(user_enc, user_mac, b"personal-item")
    personal_pw = enc2(user_enc, user_mac, b"personal-secret")
    org_name = enc2(org_enc, org_mac, b"smtp")
    org_pw = enc2(org_enc, org_mac, b" hunter2-org")
    org_notes = enc2(org_enc, org_mac, b"line1\nline2\\tail")
    coll_name = enc2(org_enc, org_mac, b"shared")

    # One item per remaining cipher type, all org-owned in "shared".
    note_name = enc2(org_enc, org_mac, b"lease-key")
    note_notes = enc2(org_enc, org_mac, b"ssh-ed25519 AAAAC3... lease@node")

    card_name = enc2(org_enc, org_mac, b"corp-card")
    cardholder = enc2(org_enc, org_mac, b"Doni Crosby")
    card_brand = enc2(org_enc, org_mac, b"visa")
    card_number = enc2(org_enc, org_mac, b"4024007138346631")
    card_exp_month = enc2(org_enc, org_mac, b"12")
    card_exp_year = enc2(org_enc, org_mac, b"2030")
    card_code = enc2(org_enc, org_mac, b"417")

    id_name = enc2(org_enc, org_mac, b"passport")
    id_title = enc2(org_enc, org_mac, b"Mr")
    id_first = enc2(org_enc, org_mac, b"Doni")
    id_last = enc2(org_enc, org_mac, b"Crosby")
    id_passport = enc2(org_enc, org_mac, b"P1234567")
    id_ssn = enc2(org_enc, org_mac, b"123-45-6789")

    ssh_name = enc2(org_enc, org_mac, b"bootstrap-node")
    ssh_priv = enc2(org_enc, org_mac, b"-----BEGIN OPENSSH PRIVATE KEY-----\n...")
    ssh_pub = enc2(org_enc, org_mac, b"ssh-ed25519 AAAAC3Nz... bootstrap")
    ssh_fp = enc2(org_enc, org_mac, b"SHA256:abc123")

    # Login with a multi-uri array to pin the uris mapping.
    multi_name = enc2(org_enc, org_mac, b"multi-uri")
    multi_pw = enc2(org_enc, org_mac, b"multi-secret")
    multi_u1 = enc2(org_enc, org_mac, b"https://a.example.com")
    multi_u2 = enc2(org_enc, org_mac, b"https://b.example.com")
    multi_u3 = enc2(org_enc, org_mac, b"https://c.example.com")

    # Cipher-level key: per-cipher 64B key wrapped under the org key; the
    # cipher's fields are sealed under the per-cipher key, not the org key.
    cipher_k_enc = os.urandom(32)
    cipher_k_mac = os.urandom(32)
    wrapped_cipher_key = enc2(org_enc, org_mac, cipher_k_enc + cipher_k_mac)
    ckey_name = enc2(cipher_k_enc, cipher_k_mac, b"per-cipher-key-note")
    ckey_notes = enc2(cipher_k_enc, cipher_k_mac, b"sealed under its own key")

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
            "notes": org_notes,
            "id": "c2",
            "collection": "coll-shared-uuid",
            "org_id": "org-uuid",
            "coll_name": coll_name,
        },
        "note": {
            "name": note_name,
            "notes": note_notes,
            "id": "c3",
        },
        "card": {
            "name": card_name,
            "cardholder_name": cardholder,
            "brand": card_brand,
            "number": card_number,
            "exp_month": card_exp_month,
            "exp_year": card_exp_year,
            "code": card_code,
            "id": "c4",
        },
        "identity": {
            "name": id_name,
            "title": id_title,
            "first_name": id_first,
            "last_name": id_last,
            "passport_number": id_passport,
            "ssn": id_ssn,
            "id": "c5",
        },
        "sshkey": {
            "name": ssh_name,
            "private_key": ssh_priv,
            "public_key": ssh_pub,
            "key_fingerprint": ssh_fp,
            "id": "c6",
        },
        "multiuri": {
            "name": multi_name,
            "password": multi_pw,
            "uris": [multi_u1, multi_u2, multi_u3],
            "id": "c7",
        },
        "cipherkey": {
            "key": wrapped_cipher_key,
            "name": ckey_name,
            "notes": ckey_notes,
            "id": "c8",
        },
        "expect": {
            "personal_item_password": "personal-secret",
            "org_item_password": " hunter2-org",
            "org_item_notes": "line1\nline2\\tail",
            "coll_name": "shared",
            "note_notes": "ssh-ed25519 AAAAC3... lease@node",
            "card_number": "4024007138346631",
            "card_code": "417",
            "identity_passport_number": "P1234567",
            "identity_ssn": "123-45-6789",
            "sshkey_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
            "sshkey_public_key": "ssh-ed25519 AAAAC3Nz... bootstrap",
            "sshkey_key_fingerprint": "SHA256:abc123",
            "multiuri_uri": "https://a.example.com",
            "multiuri_uris": "https://a.example.com\nhttps://b.example.com\nhttps://c.example.com",
            "cipherkey_notes": "sealed under its own key",
        },
    }
    d = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(d, "wiremock_fixture.json"), "w") as f:
        json.dump(fixture, f, indent=2)
    print("fixture written")


if __name__ == "__main__":
    main()
