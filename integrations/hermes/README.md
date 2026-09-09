# cryptile Hermes plugin

Maps Hermes secret-source bindings onto the `cryptile` CLI:

```yaml
secrets:
  cryptile:
    enabled: true
    env:
      POSTGRES_PASSWORD: vw://shared/Postgres HQ#password
```

At startup Hermes calls `fetch()`; the plugin invokes, per binding,
`cryptile get --passphrase-env CRYPTILE_PASSPHRASE -- vw://…` with an
allowlisted child env (PATH/HOME/locale basics + the passphrase var only),
stdin closed. cryptile's typed exit codes map 1:1 onto Hermes' ErrorKind
taxonomy:

| cryptile exit | ErrorKind | Meaning |
|---|---|---|
| 2 | REF_INVALID | ref failed to parse / bad usage |
| 3 | AUTH_FAILED | no session, wrong passphrase, or refresh dead |
| 4 | NETWORK | transport / backend failure |
| 5 | EMPTY_VALUE | item or field not found |
| other | INTERNAL | bug |

## Install

```sh
mkdir -p ~/.hermes/plugins/cryptile
cp plugin.yaml __init__.py ~/.hermes/plugins/cryptile/
# bootstrap slot in ~/.hermes/.env:
echo 'CRYPTILE_PASSPHRASE=…' >> ~/.hermes/.env
```

cryptile itself must be on PATH (`cargo install --git …`, see
`docs/onboarding.md`) with a logged-in session (`cryptile login`).

## Config keys (`secrets.cryptile.*`)

| key | default | notes |
|---|---|---|
| `enabled` | false | master switch |
| `env` | {} | VAR → `vw://collection/item#field` |
| `binary_path` | "" | pin the binary; empty = PATH |
| `state_dir` | "" | forward `--state-dir` to cryptile |
| `passphrase_env` | CRYPTILE_PASSPHRASE | bootstrap var; protected from all sources |
| `timeout_seconds` | 120 | wall-clock budget for the whole fetch |
| `override_existing` | true | explicit binding beats stale `.env` |

## Behavior

- Mapped shape: explicit bindings outrank bulk sources on contested vars.
- One `cryptile get` per ref; fails fast on first error (no partial applies —
  the orchestrator only ever sees a clean FetchResult).
- `CRYPTILE_PASSPHRASE` is protected: no source (including this one) can
  overwrite it.
- Provenance: resolved vars show `(from Cryptile)`.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `not_configured` | enabled with empty `env:` map | add bindings |
| `binary_missing` | cryptile not on PATH | install / set `binary_path` |
| `auth_failed` | stale session or wrong passphrase | `cryptile login …`; check `.env` |
| `empty_value` | ref points at missing item/field | fix the ref or add the item |
| `network` | VW unreachable | check server/proxy |

## Command-helper alternative (no plugin)

Hermes' generic command source also works, at the cost of generic error
reporting and a 3 s default timeout:

```yaml
secrets:
  command:
    enabled: true
    command: "cryptile export --namespace shared --format env --passphrase-env CRYPTILE_PASSPHRASE"
    helper_timeout_seconds: 15
```

Prefer the plugin when you want per-ref bindings, typed errors, and
provenance labels.

## Tests

- `integrations/hermes/test_source.py` — fake-binary unit tests (22).
- `integrations/hermes/test_conformance.py` — the real Hermes conformance
  kit (needs `$HERMES_REPO` checkout; skips without it).
- `integration/hermes_plugin_e2e.py` — live VW round trip via the real
  orchestrator (run by `run_live_tests.sh`).
