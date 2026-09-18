#!/usr/bin/env python3
# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Black-box probe: which /users/invite body shape does the harness VW accept?

Ladders candidate body shapes against OUR OWN throwaway org on the local
harness server, printing the FULL error body for failures (the repro's
300-char truncation hid them). Wire evidence from our own server only -
no upstream source consulted. Prints no secret material.

Usage: probe_invite_shape.py <base-url>
"""
import json
import sys
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, "/workspace/cryptile/integration")
import repro_ssh_member_sync as R  # noqa: E402


def full_post(url, body, token):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    base = sys.argv[1].rstrip("/")
    print(f"server: {base}")

    admin = R.Account(f"probe-admin-{uuid.uuid4().hex[:8]}@repro.test")
    agent = R.Account(f"probe-agent-{uuid.uuid4().hex[:8]}@repro.test")
    admin.register(base)
    agent.register(base)
    admin.login(base)
    agent.login(base)

    org_key = R.os.urandom(64)
    org = R.api("POST", f"{base}/api/organizations", {
        "billingEmail": admin.email,
        "collectionName": R.seal_type2(b"shared", org_key[:32], org_key[32:]),
        "key": R.wrap_type4(org_key, admin.rsa.public_key()),
        "name": "Probe Org",
        "planType": "0",
    }, token=admin.token)[1]
    org_id = org["id"]
    R.api("POST", f"{base}/api/organizations/{org_id}/collections", {
        "name": R.seal_type2(b"rj-45", org_key[:32], org_key[32:]),
        "groups": [],
        "users": [],
    }, token=admin.token)
    _, colls = R.api("GET", f"{base}/api/organizations/{org_id}/collections",
                     token=admin.token)
    coll_ids = [c["id"] for c in colls["data"]]
    print(f"org {org_id[:8]}  collections: {len(coll_ids)}")

    grant = [{"id": cid, "readOnly": False, "hidePasswords": False,
              "canManage": False} for cid in coll_ids]

    variants = [
        ("v1 control: repro body verbatim", {
            "emails": [agent.email], "type": 2, "accessAll": False,
            "collections": grant}),
        ("v2 = v1 + groups:[]", {
            "emails": [agent.email], "type": 2, "accessAll": False,
            "groups": [], "collections": grant}),
        ("v3 minimal {emails,type}", {
            "emails": [agent.email], "type": 2}),
        ("v4 {emails,type,accessAll}", {
            "emails": [agent.email], "type": 2, "accessAll": False}),
        ("v5 {emails,type,collections} (entries without canManage)", {
            "emails": [agent.email], "type": 2,
            "collections": [{"id": cid, "readOnly": False,
                             "hidePasswords": False} for cid in coll_ids]}),
        ("v6 type as string 'Member'", {
            "emails": [agent.email], "type": "Member", "accessAll": False,
            "groups": [], "collections": grant}),
    ]

    winner = None
    for label, body in variants:
        st, text = full_post(
            f"{base}/api/organizations/{org_id}/users/invite", body,
            admin.token)
        ok = st in (200, 204)
        print(f"\n== {label}\n   HTTP {st}")
        if ok:
            print("   ACCEPTED")
            winner = label
            break
        print(f"   body: {' '.join(text.split())[:600]}")

    if winner:
        print(f"\nWINNER: {winner}")
    else:
        print("\nNO VARIANT ACCEPTED - full bodies above for analysis")
        sys.exit(1)


if __name__ == "__main__":
    main()
