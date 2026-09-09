# Onboarding: cryptile + Hermes + your Vaultwarden

This guide wires a Hermes agent to a real Vaultwarden instance so provider
API keys live in the vault, not in `~/.hermes/.env`. Machine path only:
the agent never holds your master password.

## 0. Threat model in one paragraph

You create a dedicated VW **organization** ("hermes") with one **collection**
("shared"). The Hermes host logs in as a dedicated **service account**
(`svc-hermes@…`) that is a member of that org and can see *only* that
collection. cryptile seals the service account's session under a keyring
passphrase (Argon2id + AES-256-GCM envelope, 0600 file). Hermes receives
the passphrase through its `.env` at startup and uses it to resolve
individual secrets on demand. The VW master password is typed once, at
`cryptile login`, on the Hermes host's console — never stored, never in
Hermes.

## 1. Vaultwarden server prep

Any Vaultwarden ≥ 1.33 with HTTPS (behind your usual reverse proxy) works;
the reference stack here is VW 1.37.2. Requirements:

- `SIGNUPS_ALLOWED=true` long enough to register the service account (or use
  an invite), then lock signups back down.
- Admin panel → Organizations → create org **hermes** (or use an existing one;
  the org name is the namespace in refs).
- Create collection **shared** inside the org.
- Register a user `svc-hermes@yourdomain` (email+master password you control;
  this is *not* your personal login).
- Invite that user to the org, confirm membership, grant access to the
  **shared** collection only (Access Control: "This collection" role).

> VW note: an org owner must *confirm* the new member before org ciphers
> sync. In the admin panel or web vault, check the member shows confirmed.

## 2. Put secrets in the shared collection

In the web vault, org **hermes** → collection **shared** → New item. Item
name becomes the middle of the ref; fields become the fragment:

```
vw://shared/Postgres HQ#password
       └─collection   └─item name  └─field
```

Standard login items expose `username` / `password`; custom fields expose
their names. Refs are case-sensitive in the item-name segment.

## 3. Install cryptile on the Hermes host

```sh
cargo install --git https://github.com/donicrosby/cryptile
cryptile backends        # prints: vw
```

State lives at `~/.config/cryptile` (`config.json` + sealed `keyring`,
0600/0700). For other locations pass `--state-dir`.

## 4. Login (once, on the Hermes host console)

```sh
cryptile login --server https://vault.yourdomain.com \
               --account svc-hermes@yourdomain
```

Prompts: VW master password (typed, never stored), keyring passphrase
(choose one; this is the value Hermes will hold). Successful login prints
`logged in; session sealed in ~/.config/cryptile`.

## 5. Wire Hermes

Add to `~/.hermes/.env` (bootstrap slot — the only secret Hermes keeps):

```
CRYPTILE_PASSPHRASE=<the keyring passphrase>
```

Install the plugin:

```sh
mkdir -p ~/.hermes/plugins/cryptile
cp integrations/hermes/plugin.yaml integrations/hermes/__init__.py \
   ~/.hermes/plugins/cryptile/
```

Bind env vars to refs in `~/.hermes/config.yaml`:

```yaml
secrets:
  cryptile:
    enabled: true
    env:
      OPENROUTER_API_KEY: vw://shared/Postgres HQ#password
```

(Yes, really — bind your real secrets; the example ref is just the live-test
item.)

Restart Hermes. `hermes model` or setup flows show `(from Cryptile)` next to
keys the source resolved. That's the whole loop.

## 6. Rotation & recovery

- **Rotate a secret**: edit the item in the VW web vault. Next Hermes start
  picks it up (no cryptile action — session persists, value fetched fresh).
- **Rotate the keyring passphrase**: currently means `cryptile login` again
  (new seal) + update `CRYPTILE_PASSPHRASE` in `.env`. (A dedicated
  `cryptile rekey` is a future change.)
- **Access token expired**: cryptile auto-refreshes; refresh token expired
  (VW default 30 days idle) → re-run `cryptile login`. Remediation hints in
  Hermes startup output point here.
- **Wrong passphrase in `.env`**: source reports `auth_failed` with a
  re-login hint; Hermes startup continues without the secret (fail-open by
  design — check startup lines).

## 7. What the live harness proves (and how to run it)

`integration/run_live_tests.sh` boots a disposable Vaultwarden 1.37.2,
provisions org/collection/service-account/item through the public API, and
runs the real binary: login, get, list, export env/json, not-found exit 5,
wrong-passphrase exit 3, backends — plus the Hermes plugin e2e (real
`fetch()` + real `apply_all()`, provenance labels). Requires docker and a
hermes-agent checkout at `$HERMES_REPO` (default `/tmp/hermes`) for the
plugin stage; it skips cleanly otherwise.

```sh
git clone --depth 1 https://github.com/NousResearch/hermes-agent /tmp/hermes
CRYPTILE_VW_BIND=0.0.0.0 CRYPTILE_LIVE_BASE=http://172.17.0.1:8222 \
  ./integration/run_live_tests.sh
```
