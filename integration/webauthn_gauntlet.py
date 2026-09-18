#!/usr/bin/env python3
"""WebAuthn (passkey) 2FA gauntlet against the harness Vaultwarden.

Black-box derived wire contract, verified end-to-end against
vaultwarden/server:1.37.2 (docker `cryptile-vw`, host port 8222):

  enable:  POST /api/two-factor/get-webauthn-challenge {masterPasswordHash}
           -> PublicKeyCredentialCreationOptions (b64url STRINGS, rp.id = VW
              `DOMAIN`, default `localhost`)
           authenticator creates credential (soft-webauthn plays the key)
           PUT  /api/two-factor/webauthn
                {masterPasswordHash, id: 0, name,
                 deviceResponse: {id, rawId, type, extensions,
                   response: {AttestationObject, clientDataJson}}}   <- padded std b64
  login:   POST /identity/connect/token (no 2fa fields) -> 400 challenge,
           TwoFactorProviders2["7"] = {challenge, rpId, allowCredentials, ...}
           authenticator signs (webauthn.get)
           same token grant + twoFactorProvider=7, twoFactorToken=JSON
           where the token JSON mimics the web vault connector exactly:
             keys are lowercase: authenticData / clientDataJson / signature
             base64 is urlsafe UNPADDED
             NO userHandle field
             id == rawId == b64url(cred id) (browser credential.id form)

soft-webauthn interop notes (observed behavior of its .create()/.get()):
  - returned `id` is bytes containing ALREADY-b64url TEXT, with padding.
    Strip `=` and use as-is; do NOT decode-then-re-encode (double encoding).
  - response fields (attestationObject, clientDataJSON, authenticatorData,
    signature) are raw bytes -> standard urlsafe-encode yourself.
  - origin passed to create/get must match the rp id VW advertises
    (http://localhost with default DOMAIN), even though the wire goes to
    the container IP.

Run from integration/: python3 webauthn_gauntlet.py
Requires: `pip install soft-webauthn`, harness VW up, requests-free
(uses capture_2fa's urllib plumbing).
"""

import base64
import json
import sys
import uuid

import capture_2fa as c2f
import soft_webauthn

BASE = "http://172.17.0.3"
ORIGIN = "http://localhost"  # must match VW rp id (DOMAIN default)
identity, api = f"{BASE}/identity", f"{BASE}/api"
MP = "capture-2fa-master"


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(x) -> str:
    if isinstance(x, str):
        x = x.encode()
    return base64.urlsafe_b64encode(x).decode().rstrip("=")


def b64std(x) -> str:
    if isinstance(x, str):
        x = x.encode()
    return base64.standard_b64encode(x).decode()


def api_call(method, path, payload, bearer):
    h = {"Content-Type": "application/json", "Origin": ORIGIN}
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    return c2f.raw_request(method, f"{api}{path}", json.dumps(payload).encode(), h)


def main() -> int:
    email = f"svc-wa-{uuid.uuid4().hex[:8]}@live.test"
    mk = c2f.master_key(email, MP, c2f.ITERATIONS)
    ah = c2f.auth_hash(MP, mk)
    enc_k, mac_k = c2f.hkdf_expand(mk, b"enc"), c2f.hkdf_expand(mk, b"mac")
    s, _ = c2f.req_json("POST", f"{identity}/accounts/register", {
        "email": email, "name": "webauthn-gauntlet", "masterPasswordHash": ah,
        "key": c2f.enc2(bytes(64), enc_k, mac_k),
        "keys": {"encryptedPrivateKey": c2f.enc2(bytes(32), bytes(64)[:32], bytes(64)[32:]),
                 "publicKey": c2f.b64(bytes(16))},
        "kdf": 0, "kdfIterations": c2f.ITERATIONS})
    print("register:", s)
    assert s == 200

    form = [("grant_type", "password"), ("username", email), ("password", ah),
            ("scope", "api offline_access"), ("client_id", "web"),
            ("deviceType", "14"), ("deviceIdentifier", str(uuid.uuid4())),
            ("deviceName", "wa-gauntlet")]
    s, body = c2f.post_form(f"{identity}/connect/token", form)
    access = json.loads(body)["access_token"]
    print("plain login:", s)
    assert s == 200

    # ---- enable: challenge -> credential -> PUT ----
    s, b = api_call("POST", "/two-factor/get-webauthn-challenge",
                    {"masterPasswordHash": ah}, access)
    print("challenge:", s)
    assert s == 200
    o = json.loads(b)
    opts = {"publicKey": {
        "challenge": b64d(o["challenge"]), "rp": o["rp"],
        "user": {**o["user"], "id": b64d(o["user"]["id"])},
        "pubKeyCredParams": o["pubKeyCredParams"],
        "timeout": o.get("timeout", 60000),
        "excludeCredentials": [{"id": b64d(c["id"]), "type": c["type"]}
                               for c in o.get("excludeCredentials", [])],
        "authenticatorSelection": o.get("authenticatorSelection", {}),
        "attestation": o.get("attestation", "none"),
    }}
    device = soft_webauthn.SoftWebauthnDevice()
    att = device.create(opts, ORIGIN)
    cred_id = att["id"].decode().rstrip("=")  # b64url text w/ padding from soft-webauthn
    dr = att["response"]
    s, b = api_call("PUT", "/two-factor/webauthn", {
        "id": 0, "name": "gauntlet-key", "masterPasswordHash": ah,
        "deviceResponse": {
            "id": cred_id, "rawId": b64std(cred_id), "type": att["type"],
            "extensions": {},
            "response": {"AttestationObject": b64std(dr["attestationObject"]),
                         "clientDataJson": b64std(dr["clientDataJSON"])},
        }}, access)
    print("PUT enable:", s, "enabled:", json.loads(b).get("enabled"))
    assert s == 200 and json.loads(b).get("enabled") is True

    # ---- challenge appears on plain login ----
    s, body = c2f.post_form(f"{identity}/connect/token", form)
    ch = json.loads(body)
    providers = ch.get("TwoFactorProviders", [])
    print("plain login now:", s, "| providers:", providers)
    assert s == 400 and "7" in providers

    # ---- assert back in ----
    inner = ch["TwoFactorProviders2"]["7"]
    get_opts = {"publicKey": {
        "challenge": b64d(inner["challenge"]), "rpId": inner["rpId"],
        "timeout": inner.get("timeout", 60000),
        "userVerification": inner.get("userVerification", "discouraged"),
        "allowCredentials": [{"id": b64d(c["id"]), "type": c.get("type", "public-key")}
                             for c in inner.get("allowCredentials", [])],
    }}
    assertion = device.get(get_opts, ORIGIN)
    aid = assertion["id"].decode().rstrip("=")
    ar = assertion["response"]
    tok = json.dumps({
        "id": aid, "rawId": aid, "type": "public-key", "extensions": {},
        "response": {"authenticatorData": b64u(ar["authenticatorData"]),
                     "clientDataJson": b64u(ar["clientDataJSON"]),
                     "signature": b64u(ar["signature"])},
    })
    form2 = list(form) + [("twoFactorProvider", "7"), ("twoFactorToken", tok),
                          ("twoFactorRemember", "0")]
    s2, body2 = c2f.post_form(f"{identity}/connect/token", form2)
    print("assertion login:", s2)
    ok = s2 == 200 and b"access_token" in body2
    print("PASS" if ok else "FAIL", "| account:", email)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
