# Design — Hermes secret source plugin

## Context

Hermes resolves provider credentials at startup through secret sources.
Bundled set (Bitwarden, 1Password, command helper) is closed; everything
else is a directory plugin: `~/.hermes/plugins/<name>/plugin.yaml` +
`__init__.py:register(ctx)`. Verified against hermes-agent source
(`agent/secret_sources/base.py`, `registry.py`, `hermes_cli/plugins.py`,
`tests/secret_sources/conformance.py`), not just docs.

## Key decisions

- **Plugin wraps cryptile; it implements no crypto, no VW protocol.** All
  trust boundaries stay inside cryptile: sealed keyring, session refresh,
  typed exit codes. The plugin is an argv → FetchResult translator.
- **`mapped` shape.** Explicit `env: {VAR: vw://collection/item#field}`
  bindings — strongest intent, beats bulk sources on contested vars, and
  mirrors how the service account's collection scoping already limits
  blast radius.
- **`get`, not `export`.** One subprocess per ref, single value on stdout.
  Export would dump the whole namespace into every Hermes process even
  when one var is bound. Per-ref cost is one CLI spawn + one VW roundtrip
  + Argon2 unseal (~1s); env maps are small; fetch runs once per process.
- **Passphrase = bootstrap token.** `token_env_key: passphrase_env`,
  default `CRYPTILE_PASSPHRASE` — same .env slot pattern as
  `BWS_ACCESS_TOKEN`. `protected_env_vars()` then stops any source
  (including ours) overwriting it. Passed to the child ONLY via
  `run_secret_cli(allow_env=[...])`, never the full post-dotenv
  environment.
- **Classify by exit code, not stderr text.** Our typed exit codes are the
  contract: 2→REF_INVALID, 3→AUTH_FAILED, 4→NETWORK, 5→EMPTY_VALUE,
  else→INTERNAL. String matching on stderr is brittle and stderr may
  carry hints that change wording.
- **No cache in v1.** Hermes fetches once per process; the orchestrator
  owns re-pull timing. Revisit only if per-process startup cost shows up.
- **`--` terminator before the ref** so a ref can never parse as a flag;
  `--passphrase-env VAR` goes before the terminator.

## Config surface (secrets.cryptile)

```yaml
secrets:
  cryptile:
    enabled: true
    env:
      POSTGRES_PASSWORD: vw://shared/Postgres HQ#password
    binary_path: ""    # pin cryptile; empty = PATH lookup
    state_dir: ""      # cryptile --state-dir; empty = ~/.config/cryptile
    passphrase_env: CRYPTILE_PASSPHRASE
```

## Remediation hints

All auth-shaped failures point at `cryptile login --server ... ` (re-seal
the session); BINARY_MISSING points at install; NOT_CONFIGURED at the
env map.

## Risks / edge cases

- **Hermes API drift**: plugin pins nothing; `api_version` gating means a
  future Hermes that changes the contract skips us with a warning instead
  of crashing startup. Conformance kit run in our harness against real
  Hermes source catches drift on our side.
- **Cloned-Hermes test dependency**: conformance imports
  `agent.secret_sources.registry`; we shallow-sparse-clone the repo in
  the harness (agent/secret_sources, tests/secret_sources,
  hermes_constants.py) — not vendored, so we always test the real kit.
- **Wrong-passphrase at fetch time** → exit 3 → AUTH_FAILED with
  re-login hint; orchestrator never applies stale values over good ones.
- **Command-helper alternative** stays documented for users who want zero
  plugin install: `command: "cryptile export --namespace hermes
  --format env --passphrase-env CRYPTILE_PASSPHRASE"` (needs its 3s
  timeout raised).
