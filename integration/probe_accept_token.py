#!/usr/bin/env python3
# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Black-box probe: where does OUR harness VW expose the invite-accept token?

Invites a throwaway agent, then dumps the candidate payloads the invited
account can read (profile org list, sync, member endpoints) plus the admin
member object. Ephemeral accounts; nothing secret involved.

Usage: probe_accept_token.py <base-url>
"""
import json
import sys
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, "/workspace/cryptile/integration")
import repro_ssh_member_sync as R  # noqa: E402


def dump(label, st, body):
    print(f"\n== {label} -> HTTP {st}")
    if isinstance(body, dict):
        print(json.dumps(body, indent=1)[:2500])
    else:
        print(str(body)[:600])


def get(url, token=None):
    req = urllib.request.Request(
        url, method="GET",
        headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"_error": e.read().decode(errors="replace")[:400]}


def main():
    base = sys.argv[1].rstrip("/")
    suffix = uuid.uuid4().hex[:8]
    admin = R.Account(f"probe2-admin-{suffix}@repro.test")
    agent = R.Account(f"probe2-agent-{suffix}@repro.test")
    for a in (admin, agent):
        a.register(base)
        a.login(base)

    org_key = R.os.urandom(64)
    org = R.api("POST", f"{base}/api/organizations", {
        "billingEmail": admin.email,
        "collectionName": R.seal_type2(b"shared", org_key[:32], org_key[32:]),
        "key": R.wrap_type4(org_key, admin.rsa.public_key()),
        "name": "Probe2 Org", "planType": "0",
    }, token=admin.token)[1]
    org_id = org["id"]

    api_st, _ = R.api("POST", f"{base}/api/organizations/{org_id}/users/invite", {
        "emails": [agent.email], "type": 2, "accessAll": False,
        "groups": [], "collections": [],
    }, token=admin.token)
    print(f"invite -> HTTP {api_st}")

    st, users = R.api("GET", f"{base}/api/organizations/{org_id}/users",
                      token=admin.token)
    ouser = next(u for u in users["data"] if u["email"] == agent.email)
    dump("admin member object", st, ouser)

    st, orgs = get(f"{base}/api/users/{agent.user_id}/organizations",
                   agent.token)
    dump("agent GET users/{id}/organizations", st, orgs)

    st, org_one = get(f"{base}/api/organizations/{org_id}", agent.token)
    dump("agent GET organizations/{id}", st, org_one)

    st, syn = get(f"{base}/api/sync", agent.token)
    dump("agent sync keys", st, {k: (v if not isinstance(v, list) else f"[{len(v)} items]") for k, v in syn.items()})


if __name__ == "__main__":
    main()
