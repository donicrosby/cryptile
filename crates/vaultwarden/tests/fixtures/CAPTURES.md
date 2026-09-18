# 2FA wire captures (VW 1.37.2, black-box)

Captured 2026-09-17 by capture_2fa.py against a disposable harness server.

| file | status | body sha12 |
|---|---|---|
| challenge.json | 400 | 0562939e222a |
| resubmit-ok.json | 200 | a569c7bc0352 (raw; on-disk file redacted: live tokens of a scratch account stripped post-capture) |
| wrong-code.json | 400 | ae50a1bfe132 |

Pinned observations:
- TwoFactorProviders: array of STRING ids (["0"]) on VW 1.37.2
- TwoFactorProviders2: map "0" -> null (no config for totp)
- extra sibling field MasterPasswordPolicy present; ignore
- resubmit form fields: twoFactorToken, twoFactorProvider
- enable consumes the current TOTP window: same-window code reuse
  at login is rejected (replay protection); wait for the next
  30s window when scripting enable->login sequences
- invalid code -> 400 {"message":"Invalid TOTP code! Server time: ..."}
- enable flow: POST two-factor/get-authenticator -> PUT two-factor/authenticator {key, masterPasswordHash, token}
