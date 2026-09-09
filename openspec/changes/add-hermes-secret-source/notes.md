# Notes — add-hermes-secret-source

## Verified against hermes-agent source (not docs alone)

- `agent/secret_sources/base.py`: SecretSource ABC, FetchResult, ErrorKind,
  `run_secret_cli` (argv-only, allowlist env, NO_COLOR, stdin /dev/null,
  timeout→RuntimeError), token_env_key/protected_env_vars machinery.
- `agent/secret_sources/registry.py`: apply_all(environ=…), ApplyReport
  with `provenance: Dict[str, AppliedVar]` (`.source` holds source name),
  `_reset_registry_for_tests`.
- `hermes_cli/plugins.py` `_SCOPED_PROVIDER_REGISTRARS`:
  `register_secret_source` validates isinstance SecretSource + forwards to
  `register_source`; bundled set closed; `vw` scheme free (bws/op taken).
- `tests/secret_sources/conformance.py`: subclass + `source` fixture.
- 1Password source used as the architectural template (mapped + CLI +
  token_env_key + override_existing_default=True rationale).

## Implementation notes

- Plugin at `integrations/hermes/` — `plugin.yaml` + `__init__.py`
  (CryptileSource + `register(ctx)`). Identity: name `cryptile`, label
  `Cryptile`, shape mapped, scheme `vw`, token_env_key `passphrase_env`,
  default `CRYPTILE_PASSPHRASE`.
- Fail-fast per fetch: first failing ref aborts (clean FetchResult, no
  partial secrets) — orchestrator-side precedence stays sound.
- `_find_binary` uses mode-bits (0o111), NOT `os.access(X_OK)`: tmpfs
  idmapping in container sandboxes makes access(X) unreliable for
  root-owned files while running as non-root (and vice versa).
- Repo pytest: `pytest.ini` (--basetemp=.pytest-tmp) because `/tmp` is
  mounted noexec in dev sandboxes — fake helper binaries must live on
  exec-capable fs (workspace ext4). `conftest.py` puts `$HERMES_REPO`
  (default /tmp/hermes) on sys.path BEFORE importing the plugin package,
  and skips plugin tests when the checkout is absent.
- Live e2e (`integration/hermes_plugin_e2e.py`, wired into
  run_live_tests.sh after `backends`): direct fetch + real apply_all +
  provenance label + wrong-passphrase→AUTH_FAILED + missing-field→
  EMPTY_VALUE. Harness pins `binary_path` to target/debug/cryptile
  (sandbox PATH has no install; real installs resolve via PATH).
- CLI: `get`/`list` gained `--passphrase-env` (login/export already had
  it). New cli tests pin: unset var→exit 3, wrong passphrase→3, valid
  session unseals + valid VwSession handle deserializes → reaches
  transport → exit 4 against refused 127.0.0.1:1. Keyring stores the BARE
  VwSession JSON as Session.handle (state.rs load_session hardcodes
  provider:"vw").
- Version policy (user, 2026-09-09): stay 0.1.0 pre-alpha; no crates.io
  publish, no minor bumps until battle-tested; 1.0.0 only after rough
  edges settled.

## Live-fire findings

- Run 7: 17/17 CLI + plugin stage 1/6 — e2e cfg omitted `binary_path`,
  sandbox PATH has no cryptile → BINARY_MISSING cascade. Fixed by pinning
  the just-built binary in the harness cfg. Run 8: all green (see below).
