# WebAuthn hardware-key runbook (manual, operator-run)

Not CI-gated. Run this with a real CTAP2 key in hand; record the outcome
below so the next operator knows what was verified and against what.

## Prerequisites

- cryptile built with the feature: `cargo build -p cryptile-vaultwarden
  --features webauthn` (needs `pkg-config` + `libudev-dev`).
- A CTAP2-capable hardware key (usb or nfc transport only).
- A Vaultwarden server with WebAuthn 2FA enabled for your account.

## Procedure

1. Plain login and observe the challenge:

   ```sh
   cryptile login --server https://vw.internal --account you@corp.com \
       --passphrase-env CRYPTILE_PASSPHRASE \
       --master-password-env CRYPTILE_MASTER_PASSWORD
   # expect: exit 3, "two factor required", providers listing includes webauthn
   ```

2. Run the assertion:

   ```sh
   cryptile login --server https://vw.internal --account you@corp.com \
       --passphrase-env CRYPTILE_PASSPHRASE \
       --master-password-env CRYPTILE_MASTER_PASSWORD \
       --2fa-provider webauthn
   # touch the key when it blinks
   ```

3. Confirm the session works: `cryptile get --passphrase-env
   CRYPTILE_PASSPHRASE -- 'vw://collection/item#password'`.

## Recorded runs

| Date | Key (make/model) | Transport | Result | Notes |
|------|------------------|-----------|--------|-------|
| — | | | | no operator run recorded yet |
