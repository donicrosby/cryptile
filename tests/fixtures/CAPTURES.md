# WebAuthn challenge capture — Vaultwarden 1.37.2 (harness fixture)

Source of truth for `crates/vaultwarden/src/webauthn.rs` unit tests.

Observed live during the webauthn gauntlet's login leg against the harness
Vaultwarden 1.37.2 (same fixture as `integration/provision.py`):

```json
{
  "error": "invalid_grant",
  "error_version": 3,
  "error_description": "Two factor required.",
  "TwoFactorProviders": ["7"],
  "TwoFactorProviders2": {
    "7": {
      "challenge": "Rk9PQmFy",
      "rpId": "localhost",
      "allowCredentials": [{"id": "Y3JlZC1pZA", "type": "public-key"}],
      "timeout": 60000,
      "userVerification": "discouraged"
    }
  }
}
```

Decoded: challenge = `FOOBar` (test fixture value, not a secret), rpId
`localhost`, one allow-listed credential id `cred-id`, timeout 60 s,
user verification `discouraged`. Provider id `7` = WebAuthn in Bitwarden's
numbering (0 authenticator TOTP, 1 email, 2 Duo, 3 YubiKey, 4 U2F
(legacy), 7 WebAuthn, 6 remember). None of these values are secrets; the
challenge bytes were replaced with the ASCII fixture `FOOBar` before
storage.

## Test mapping

The tests in `crates/vaultwarden/src/webauthn.rs` against this capture:

- `challenge_decodes_from_body` — full body decodes (b64url challenge, rpId,
  allow-list).
- `challenge_lower_casing_decodes` — the same body with `twoFactorProviders2`
  (lower-camel) also decodes.
- `malformed_challenges_fail_typed` — missing provider-7 entry, missing
  `challenge` field, empty `allowCredentials`, and non-JSON bodies each
  produce typed errors (`WebauthnError::Challenge`), never panics.
- `fido2_response_matches_gauntlet_shape` — the serialized assertion token
  uses Bitwarden's lowercase-J wire keys (`clientDataJson`, not the crate's
  serde `clientDataJSON`), unpadded b64url, and drops `userHandle` when null.
- `origin_matches_harness_rp_ids` — origin derivation accepts `localhost`,
  `127.0.0.1` (http), `bw.jeansburger.net` (https), and rejects empty or
  malformed rpIds with `None`.
- `request_options_fit_the_ceremony_input` — request options carry the
  challenge and default user verification (`discouraged`) through serde.
- `b64url_decode_tolerates_padding` — the challenge decoder accepts both
  padded and unpadded base64url.

This capture is the live response shape only. WebAuthn enablement on real
accounts is documented in `docs/webauthn-notes.md` (manual, hardware-gated).
