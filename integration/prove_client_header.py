#!/usr/bin/env python3
# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Live proof: with the client-version header fix, cryptile end-to-end sees
a type-5 (SSH key) org cipher on the harness VW (which withholds type-5
from header-less clients).

Seeds a fresh org (admin + agent, explicit collection grants, no accessAll)
with a type-1 control and a type-5 SSH cipher in the granted collection,
then drives the freshly built cryptile binary as the AGENT account:
login -> list -> get. Values verified by len+sha12, never printed.

Usage: prove_client_header.py <base-url> <cryptile-binary>
Exit 0 = proof passed.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import repro_ssh_member_sync as R  # noqa: E402

MARKER = "proof-" + uuid.uuid4().hex + "-private-key-material\n"


def sha12(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def main():
    base = sys.argv[1].rstrip("/")
    binary = sys.argv[2]
    sfx = uuid.uuid4().hex[:8]
    admin_email = f"proof-admin-{sfx}@repro.test"
    agent_email = f"proof-agent-{sfx}@repro.test"

    admin, agent = R.Account(admin_email), R.Account(agent_email)
    for a in (admin, agent):
        a.register(base)
        a.login(base)

    org_key = R.os.urandom(64)
    org = R.api("POST", f"{base}/api/organizations", {
        "billingEmail": admin.email,
        "collectionName": R.seal_type2(b"rj-45", org_key[:32], org_key[32:]),
        "key": R.wrap_type4(org_key, admin.rsa.public_key()),
        "name": "Proof Org", "planType": "0",
    }, token=admin.token)[1]
    oid = org["id"]
    _, colls = R.api("GET", f"{base}/api/organizations/{oid}/collections",
                     token=admin.token)
    coll_ids = [c["id"] for c in colls["data"]]

    grant = [{"id": cid, "readOnly": False, "hidePasswords": False,
              "manage": False} for cid in coll_ids]
    R.api("POST", f"{base}/api/organizations/{oid}/users/invite", {
        "emails": [agent.email], "type": 2, "accessAll": False,
        "groups": [], "collections": grant,
    }, token=admin.token)
    _, users = R.api("GET", f"{base}/api/organizations/{oid}/users",
                     token=admin.token)
    ou = next(u for u in users["data"] if u["email"] == agent.email)
    R.api("PUT", f"{base}/api/organizations/{oid}/users/{ou['id']}", {
        "type": 2, "accessAll": False, "groups": [],
        "collections": grant,
    }, token=admin.token)
    _, pk = R.api("GET", f"{base}/api/users/{agent.user_id}/public-key",
                  token=admin.token)
    agent_pub = R.serialization.load_der_public_key(
        R.base64.b64decode(pk["publicKey"]))
    R.api("POST", f"{base}/api/organizations/{oid}/users/{ou['id']}/confirm",
          {"key": R.wrap_type4(org_key, agent_pub)}, token=admin.token)

    def oseal(pt: str) -> str:
        return R.seal_type2(pt.encode(), org_key[:32], org_key[32:])

    R.api("POST", f"{base}/api/ciphers/create", token=admin.token, body={
        "cipher": {"type": 1, "organizationId": oid,
                   "name": oseal("Proof Control"), "notes": None,
                   "login": {"username": oseal("u"), "password": oseal("p"),
                             "uris": []},
                   "secureNote": None, "card": None, "identity": None,
                   "sshKey": None, "key": None},
        "collectionIds": coll_ids,
    })
    R.api("POST", f"{base}/api/ciphers/create", token=admin.token, body={
        "cipher": {"type": 5, "organizationId": oid,
                   "name": oseal("Proof SSH Key"), "notes": None,
                   "login": None, "secureNote": None, "card": None,
                   "identity": None, "key": None,
                   "sshKey": {
                       "privateKey": oseal(MARKER),
                       "publicKey": oseal("ssh-ed25519 AAAAproof"),
                       "fingerprint": oseal("SHA256:proof"),
                   }},
        "collectionIds": coll_ids,
    })
    print(f"seeded org {oid[:8]}: control + type-5, grants explicit "
          f"(accessAll=false)")

    # --- drive the real binary as the agent account ---
    state = tempfile.mkdtemp(prefix="cryptile-proof-")
    env = dict(os.environ, CRYPTILE_PROOF_KPP="proof-kpp",
               CRYPTILE_PROOF_MP=R.PASSWORD)
    base_cmd = [binary, "--state-dir", state]

    def run(args, expect=0):
        p = subprocess.run(base_cmd + args, env=env, capture_output=True,
                           text=True)
        if p.returncode != expect:
            print(f"FAIL: {' '.join(args[:2])} -> rc={p.returncode} "
                  f"(want {expect})\nstdout: {p.stdout[:400]}\n"
                  f"stderr: {p.stderr[:400]}")
            sys.exit(1)
        return p.stdout

    run(["login", "--server", base, "--account", agent.email,
         "--passphrase-env", "CRYPTILE_PROOF_KPP",
         "--master-password-env", "CRYPTILE_PROOF_MP"])
    print("login: ok (agent account)")

    listing = run(["list", "--passphrase-env", "CRYPTILE_PROOF_KPP", "rj-45"])
    assert "Proof SSH Key" in listing, f"type-5 item missing from list:\n{listing}"
    assert "Proof Control" in listing, f"control missing from list:\n{listing}"
    print("list rj-45: shows control (type-1) AND Proof SSH Key (type-5)")

    out = run(["get", "--passphrase-env", "CRYPTILE_PROOF_KPP", "--",
               "vw://rj-45/Proof Control#password"])
    got = out.encode()
    want = b"p"
    print(f"get control #password: len={len(got)} sha12={sha12(got.rstrip(b'  '))}")
    if got.rstrip(b"\n") != want:
        print(f"expected    len={len(want)} sha12={sha12(want)}")
        sys.exit(1)
    print("value match on delivered org cipher: PASS (len+sha12, never printed)")

    # type-5 sub-object: VW 1.37.2 (harness pin) stores the sshKey sub-object
    # (verified in the harness DB) but serializes it as null in EVERY response
    # at EVERY client version -- a server serialization gap, not a client one
    # (prod runs 2026.6.0, whose web vault renders sshKey data). cryptile must
    # report the field as not present (exit 5), never crash or hang.
    p = subprocess.run(base_cmd + ["get", "--passphrase-env",
                                   "CRYPTILE_PROOF_KPP", "--",
                                   "vw://rj-45/Proof SSH Key#private_key"],
                       env=env, capture_output=True, text=True)
    if p.returncode != 5 or "not present" not in (p.stderr + p.stdout):
        print(f"FAIL: expected exit 5 'not present' for the 1.37.2 "
              f"serialization gap, got rc={p.returncode} "
              f"stderr={p.stderr[:200]}")
        sys.exit(1)
    print("type-5 on harness: item delivered + resolved; sub-object absent "
          "is the documented VW 1.37.2 server gap (exit 5, clean)")

    print("\nPROOF PASSED: header-carrying cryptile receives the type-5 org "
          "cipher (list + resolution) and fetches delivered values "
          "end-to-end; value-level sshKey proof happens against prod "
          "(VW 2026.6.0) in the prod stage")


if __name__ == "__main__":
    main()
