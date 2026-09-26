# cryptile

One CLI, many secret backends. Scoped machine access to your password vault for
agents and humans — without handing anyone your master password.

`cryptile` gives non-human consumers (your agent, CI, scripts) a narrow,
server-enforced window into a password manager: one dedicated service account,
one collection, values that exist only in memory and stdout. Built open source
from day one, with a facade so every backend speaks the same shape.

## Why

Bitwarden Secrets Manager does exactly this, but its server-side code is
licensed (not FOSS) and [Vaultwarden will never implement it][vw-sm]. Rather
than port licensed code, cryptile is a clean-room client of the public
Bitwarden/Vaultwarden API: a dedicated service account whose vault contains
only what an organization collection grants. Scoping is enforced by the
server's ACLs, not by promises in a client.

[vw-sm]: https://github.com/dani-garcia/vaultwarden/discussions/3368

## Design in one breath

- **Rust, one workspace.** `cryptile-core` (model + refs + redaction), backend
  crates (`cryptile-vaultwarden` first; 1Password and OpenBao shaped by the
  same facade), `cryptile` CLI.
- **One reference format.** `vw://collection/item#field` today, `op://vault/item`,
  `vault://mount/path` tomorrow. Refs are the currency everywhere: CLI args,
  config, agent secret maps.
- **Values are wrapped, logs are redacted.** Secret material only leaves the
  process at the stdout boundary; `Debug`/`Display` print `<redacted>`.
  `--no-redact` requires an interactive TTY on both ends.
- **Nothing plaintext at rest.** Tokens are encrypted under an Argon2id-derived
  key in a 0600 keyring file. No caches, no dumps, no master password stored.

## Status

Pre-alpha. The core crate (refs, redaction, model) and CLI skeleton exist; the
Vaultwarden backend is under active development — see `openspec/changes/`.

Spec-driven: every feature lands as an OpenSpec change proposal before code.
`openspec/` in this repo is the source of truth for what cryptile is becoming.

## Field names by item type

`vw://collection/item#field` — every item type maps into one flat field bag.
Custom fields join the bag under their own (decrypted) name. Items sealed
under a cipher-level key (servers with per-cipher encryption) are unwrapped
transparently.

A ref with no fragment resolves to the item's primary value by walking a
fixed chain over the field bag — the bag's shape stands in for the item
type: `password → notes → private_key → number`, first non-empty hit wins.

| Bare ref resolves to | Item shape |
|---|---|
| `password` | Login (any item that has one) |
| `notes` | Secure Note; anything whose payload lives in notes |
| `private_key` | SSH Key |
| `number` | Card |

An explicit `#field` is honored exactly as written — no substitution, a
missing field fails with the field-not-present error.

| Item type | Fields |
|---|---|
| Login | `username`, `password`, `totp`, `uri`, `uris` (newline-joined when >1) |
| Secure Note | `notes` |
| Card | `cardholder_name`, `brand`, `number`, `exp_month`, `exp_year`, `code` |
| Identity | `title`, `first_name`, `middle_name`, `last_name`, `address1`–`address3`, `city`, `state`, `postal_code`, `country`, `company`, `email`, `phone`, `ssn`, `username`, `passport_number`, `license_number` |
| SSH Key | `private_key`, `public_key`, `key_fingerprint` |
| any | `notes`, custom fields |

## SSH agent hand-off

```sh
cryptile get vw://shared/Deploy Key#private_key --agent
```

`--agent` pipes a fetched SSH private key to a running ssh-agent
(`ssh-add -` over stdin — the key never touches disk). Only values that
look like SSH private keys are offered; passwords and other fields are
never piped anywhere. Best effort by design: no agent, a dead socket, or
a refusal never fails the fetch — the value still prints, with at most a
one-line stderr note.

## Development

```sh
cargo test --workspace
pip install pre-commit && pre-commit install --hook-type commit-msg
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org),
enforced by the commit-msg hook above.

## Hermes integration (tier 2)

Give an agent scoped, decrypt-capable access to exactly one collection
without it ever seeing your master password:

1. On the Vaultwarden server: org + collection (e.g. `hermes` / `shared`),
   dedicated service account invited to that collection only. The ACL is the
   real boundary — the account physically cannot sync anything else.
2. On the agent host: `cryptile login --server ... --account ...` once,
   with a keyring passphrase (agent contexts: keep it in the agent's `.env`
   as the bootstrap credential).
3. Hermes secret source (command type), runs at startup:

```yaml
secrets:
  command:
    - name: cryptile
      command: cryptile export --namespace shared --passphrase-env CRYPTILE_PASSPHRASE
      format: env
```

Values land in the agent process env (tier 2): available to tools, never in
conversation. Rotating the service-account password does not invalidate the
agent (refresh-token grant survives it).

### Rotation runbook

- Service-account password: rotate in VW, then `cryptile login` again on the
  agent host. The keyring passphrase does not need to change.
- Keyring passphrase: `cryptile export > /dev/null` to verify the current one,
  then re-run `cryptile login` (fresh seal) with the new passphrase and update
  `CRYPTILE_PASSPHRASE` in the agent `.env`.

## Two-factor logins

`login` handles servers that require a second factor. The server decides what
is required — cryptile does not guess. Both stage types are supported where
your build supports them:

**Authenticator (TOTP).** Export the code through the environment, never as an
argv flag:

```sh
read -rs CRYPTILE_TOTP_CODE   # or any TOTP source you trust
cryptile login --server https://vw.internal --account you@corp.com \
    --passphrase-env CRYPTILE_PASSPHRASE \
    --master-password-env CRYPTILE_MASTER_PASSWORD \
    --2fa-env CRYPTILE_TOTP_CODE
```

If the server answers a plain login with a two-factor challenge, cryptile
exits `3` (the auth-error code), prints the required stage type(s), and
names the missing flag — so scripts and agents can react instead of hanging. Supplying the code completes
the login; the response's `TwoFactorToken` is reused automatically for
subsequent `get`/`list`/`export` calls in that session, and one automatic
resubmit handles servers that require re-presenting the token on the very
next request.

**FIDO2 / WebAuthn (hardware keys).** Available only when cryptile was built
with the `webauthn` cargo feature (off by default; the legacy escape
hatch, see below; usb + nfc transports). The
feature needs `pkg-config` and `libudev` headers to build (`apt install
pkg-config libudev-dev` on Debian/Ubuntu). A challenge of type `webauthn`
with the feature built in runs a CTAP2 assertion against your plugged-in
key — touch it when it blinks:

```sh
cryptile login --server https://vw.internal --account you@corp.com \
    --passphrase-env CRYPTILE_PASSPHRASE \
    --master-password-env CRYPTILE_MASTER_PASSWORD \
    --2fa-provider webauthn
```

Without either CTAP2 backend (a `--no-default-features` build), the same
challenge fails with a remediation hint. Soft tokens are deliberately not supported: no browser pops up,
no phone app is consulted.

**CTAP2 hardware stack (default, `fidoh` feature).** The default build
(`cargo build` / `cargo install`, no feature flags) serves the provider-7
ceremony through the owner's cleanroom CTAP2.1 client
([github.com/donicrosby/fidoh](https://github.com/donicrosby/fidoh),
rev-pinned). It honors the server-requested user-verification posture,
acquires the key PIN on the tty only when the ceremony demands it
(headless runs fail typed instead of prompting), and carries an explicit
60 s ceremony budget: a wedged key or a touch never given fails with a
typed "budget expired" error (exit 4, with a remediation hint) instead
of an unbounded wait. Hardware transports only (usb HID + PC/SC); no-device
and transport failures map to exit 4 rather than exit 3.

**Legacy escape hatch (`webauthn` feature).** The replaced
`webauthn-authenticator-rs` stack stays reachable one more cycle: build
with `--no-default-features --features webauthn` (it needs `pkg-config`
and `libudev` headers). Its provider-7 wire shape is identical and it
keeps the hardcoded discouraged posture; a later change deletes it and
unifies the paths' exit codes. Bare `--no-default-features --features
fidoh` also remains a valid way to opt in explicitly.

## License

Apache-2.0. No Bitwarden code, no `bitwarden-sdk` (GPLv3) — crypto implemented
from the public Bitwarden security whitepaper, cross-checked against
independent MIT-licensed clients (rbw, goldwarden). Same clean-room
position Vaultwarden itself took.
