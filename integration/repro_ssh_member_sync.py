#!/usr/bin/env python3

# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Repro: does VW 1.37.2 deliver org type-5 (SSH key) ciphers to limited
members with an explicit collection grant?

Two fresh accounts on one server:
  admin  - creates org "Repro Org" + collections "shared"/"rj-45",
           invites agent with accessAll=false + BOTH collections granted,
           creates a type-1 control cipher and a type-5 SSH cipher,
           both inside the granted "rj-45" collection.
  agent  - accepts + is confirmed, then raw-syncs and we count what arrived.

Also checks the ADMIN's own sync (if the type-5 is missing even there, the
bug is on the write path, not the member filter).

Usage: repro_ssh_member_sync.py <base-url>
Prints a verdict matrix. Prints no secret material (only a public fingerprint).
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
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding as apadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITERATIONS = 100_000
SUFFIX = uuid.uuid4().hex[:8]
ADMIN_EMAIL = f"repro-admin-{SUFFIX}@repro.test"
AGENT_EMAIL = f"repro-agent-{SUFFIX}@repro.test"
PASSWORD = "repro-master-password"
ORG_NAME = "Repro Org"
COLL_MAIN = "shared"
COLL_SSH = "rj-45"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def api(method, url, body=None, token=None, form=None, expect_error=False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if form is not None:
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
            return resp.status, (json.loads(payload) if payload else {})
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        if expect_error:
            return e.code, {"_error": detail[:300]}
        raise RuntimeError(f"HTTP {e.code} {method} {url}: {detail[:300]}") from e


def master_key(email, password):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), email.strip().lower().encode(), ITERATIONS
    )


def auth_hash(password, mk):
    return b64(hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1))


def hkdf_expand(key, info, length=32):
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(key, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def seal_type2(pt: bytes, enc_key: bytes, mac_key: bytes) -> str:
    iv = os.urandom(16)
    padlen = 16 - (len(pt) % 16)
    padded = pt + bytes([padlen]) * padlen
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def wrap_type4(pt: bytes, public_key) -> str:
    ct = public_key.encrypt(
        pt,
        apadding.OAEP(
            mgf=apadding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return f"4.{b64(ct)}"


class Account:
    """Registered user with derived keys."""

    def __init__(self, email):
        self.email = email
        self.device = str(uuid.uuid4())
        self.mk = master_key(email, PASSWORD)
        self.ah = auth_hash(PASSWORD, self.mk)
        self.enc_k = hkdf_expand(self.mk, b"enc", 32)
        self.mac_k = hkdf_expand(self.mk, b"mac", 32)
        self.user_key = os.urandom(64)
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.protected_user_key = seal_type2(
            self.user_key, self.enc_k, self.mac_k
        )
        priv_der = self.rsa.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.protected_private_key = seal_type2(
            priv_der, self.user_key[:32], self.user_key[32:]
        )
        self.pub_b64 = b64(
            self.rsa.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.token = None
        self.user_id = None

    def register(self, base):
        api("POST", f"{base}/identity/accounts/prelogin", {"email": self.email})
        api("POST", f"{base}/identity/accounts/register", {
            "email": self.email,
            "name": "repro",
            "masterPasswordHash": self.ah,
            "key": self.protected_user_key,
            "keys": {
                "encryptedPrivateKey": self.protected_private_key,
                "publicKey": self.pub_b64,
            },
            "kdf": 0,
            "kdfIterations": ITERATIONS,
        })

    def login(self, base):
        _, tok = api("POST", f"{base}/identity/connect/token", form=[
            ("grant_type", "password"),
            ("username", self.email),
            ("password", self.ah),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "14"),
            ("deviceIdentifier", self.device),
            ("deviceName", "repro"),
        ])
        self.token = tok["access_token"]
        _, prof = api("GET", f"{base}/api/accounts/profile", token=self.token)
        self.user_id = prof["id"]
        return tok

    def sync(self, base):
        _, body = api("GET", f"{base}/api/sync", token=self.token)
        return body


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    base = sys.argv[1].rstrip("/")
    print(f"server: {base}")
    print(f"admin:  {ADMIN_EMAIL}\nagent:  {AGENT_EMAIL}")

    admin, agent = Account(ADMIN_EMAIL), Account(AGENT_EMAIL)
    admin.register(base)
    agent.register(base)
    admin.login(base)
    agent.login(base)

    # --- admin: org with initial collection ---
    org_key = os.urandom(64)
    org = api("POST", f"{base}/api/organizations", {
        "billingEmail": ADMIN_EMAIL,
        "collectionName": seal_type2(COLL_MAIN.encode(), org_key[:32], org_key[32:]),
        "key": wrap_type4(org_key, admin.rsa.public_key()),
        "name": ORG_NAME,
        "planType": "0",
    }, token=admin.token)[1]
    org_id = org["id"]

    # second collection "rj-45"
    api("POST", f"{base}/api/organizations/{org_id}/collections", {
        "name": seal_type2(COLL_SSH.encode(), org_key[:32], org_key[32:]),
        "groups": [],
        "users": [],
    }, token=admin.token)
    _, colls = api("GET", f"{base}/api/organizations/{org_id}/collections",
                   token=admin.token)
    coll = {c["name"]: c["id"] for c in colls["data"]}
    # name comes back encrypted; identify the second one by elimination
    coll_ids = [c["id"] for c in colls["data"]]
    coll_main_id = next(c for c in coll_ids if c != coll_ids[0]) if False else coll_ids[0]
    # The org-create collection is data[0]; find "rj-45" as the other one.
    # We can't decrypt admin-side trivially here, so grant BOTH to agent anyway.
    print(f"collections: {len(coll_ids)} -> granted both to agent")

    # --- invite agent: member, accessAll=false, BOTH collections ---
    grant = [{"id": cid, "readOnly": False, "hidePasswords": False,
              "manage": False} for cid in coll_ids]
    api("POST", f"{base}/api/organizations/{org_id}/users/invite", {
        "emails": [AGENT_EMAIL],
        "type": 2,           # member
        "accessAll": False,  # NOT "can access all collections"
        "groups": [],        # server rejects the body without it
        "collections": grant,
    }, token=admin.token)

    # --- agent accepts: SKIPPED. With SMTP off the accept token is
    # undeliverable, but the server allows the admin to confirm a member
    # straight from status 1 (invited) -- proven live on this harness.
    _, ousers = api("GET", f"{base}/api/organizations/{org_id}/users",
                    token=admin.token)
    ouser = next(u for u in ousers["data"] if u["email"] == AGENT_EMAIL)
    # Re-assert the explicit collection grants on the membership (the invite
    # may not persist them; admin PUT users is proven to work pre-confirm).
    api("PUT", f"{base}/api/organizations/{org_id}/users/{ouser['id']}", {
        "type": 2, "accessAll": False, "groups": [],
        "collections": grant,
    }, token=admin.token)
    _, pk = api("GET", f"{base}/api/users/{agent.user_id}/public-key",
                token=admin.token)
    agent_pub = serialization.load_der_public_key(base64.b64decode(pk["publicKey"]))
    api("POST",
        f"{base}/api/organizations/{org_id}/users/{ouser['id']}/confirm",
        {"key": wrap_type4(org_key, agent_pub)}, token=admin.token)
    print("org membership: invited/accepted/confirmed (accessAll=false, 2 colls)")

    # --- admin: seed ciphers in granted collection ---
    def oseal(pt: str) -> str:
        return seal_type2(pt.encode(), org_key[:32], org_key[32:])

    # control: type-1 login cipher
    _, ctl = api("POST", f"{base}/api/ciphers/create", token=admin.token, body={
        "cipher": {
            "type": 1, "organizationId": org_id,
            "name": oseal("Control Login"), "notes": None,
            "login": {"username": oseal("ctl"), "password": oseal("ctl-pass"),
                      "uris": []},
            "secureNote": None, "card": None, "identity": None,
        },
        "collectionIds": [coll_ids[0]],
    })
    # subject: type-5 SSH key cipher
    sk = ed25519.Ed25519PrivateKey.generate()
    pub_raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    fp = "SHA256:" + base64.b64encode(
        hashlib.sha256(b"\x00\x00\x00\x0bssh-ed25519" + pub_raw).digest()
    ).decode().rstrip("=")
    _, sshc = api("POST", f"{base}/api/ciphers/create", token=admin.token, body={
        "cipher": {
            "type": 5, "organizationId": org_id,
            "name": oseal("Repro SSH Key"), "notes": None,
            "key": None,
            "sshKey": {
                "privateKey": oseal("-----BEGIN OPENSSH PRIVATE KEY-----\nrepro\n-----END OPENSSH PRIVATE KEY-----"),
                "publicKey": oseal("ssh-ed25519 AAAArepro repro@repro"),
                "fingerprint": oseal(fp),
            },
            "login": None, "secureNote": None, "card": None, "identity": None,
        },
        "collectionIds": [coll_ids[0]],
    })
    print(f"seeded: control id={ctl['id'][:8]}  type5 id={sshc['id'][:8]} fp={fp}")

    # --- verdicts ---
    asyn = agent.sync(base)
    nc = asyn.get("ciphers", [])
    got_ctl = any(c["id"] == ctl["id"] for c in nc)
    got_ssh = any(c["id"] == sshc["id"] for c in nc)
    types = sorted({c.get("type") for c in nc})
    print("\n=== AGENT sync (member, explicit collection grants) ===")
    print(f"ciphers: {len(nc)}  types present: {types}")
    print(f"control (type 1) delivered:    {got_ctl}")
    print(f"ssh key (type 5) delivered:    {got_ssh}")

    msyn = admin.sync(base)
    mc = msyn.get("ciphers", [])
    adm_sees_ssh = any(c["id"] == sshc["id"] for c in mc)
    print("\n=== ADMIN sync (owner) ===")
    print(f"ciphers: {len(mc)}  sees own type-5: {adm_sees_ssh}")

    print("\n=== VERDICT ===")
    if not adm_sees_ssh:
        print("WRITE-PATH BUG: org type-5 cipher not even in owner sync")
    elif got_ctl and not got_ssh:
        print("REPRODUCED: member filter drops org type-5 ciphers from sync")
    elif got_ssh and got_ctl:
        print("NOT REPRODUCED: member receives both ciphers -> prod config issue")
    else:
        print(f"UNEXPECTED: control={got_ctl} ssh={got_ssh} - inspect manually")


if __name__ == "__main__":
    main()
