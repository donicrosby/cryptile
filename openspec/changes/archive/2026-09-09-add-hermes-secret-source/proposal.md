## Why

Cryptile's stated purpose is Hermes consuming VW secrets without holding the
master credential. Hermes has a first-class plugin surface for exactly this
(`SecretSource` + `register_secret_source`); wiring cryptile as a mapped
secret source closes the loop and gives us a real E2E test: Hermes
orchestrator → plugin → `cryptile get` → live Vaultwarden → plaintext lands
in an env var the agent can use.

## What Changes

- `integrations/hermes/` — a Hermes directory plugin (`plugin.yaml`,
  `__init__.py`): `CryptileSource`, mapped shape, name `cryptile`, scheme
  `vw`, resolves each bound ref via `cryptile get --passphrase-env`
  using Hermes' `run_secret_cli()` (allowlisted env, stdin closed).
- Exit-code → `ErrorKind` mapping: 2→REF_INVALID, 3→AUTH_FAILED,
  4→NETWORK, 5→EMPTY_VALUE, other→INTERNAL.
- `crates/cli`: `get` and `list` gain `--passphrase-env VAR` (the machine
  path the plugin needs; today only login/export have it).
- Tests: conformance kit run against real Hermes source, unit tests with a
  fake binary, live e2e in the integration harness (apply_all → env var
  holds seeded plaintext).
- Docs: `docs/onboarding.md` (VW server prep → service account → login →
  Hermes wiring → rotation), plugin README, note on the zero-code
  command-helper alternative.
- Repo-level pytest (`pytest.ini`, `conftest.py`) for the plugin tests;
  `/tmp` is noexec in dev sandboxes so the tmp base sits in-workspace.

## Capabilities

### Capability: foundation

- MODIFIED `Non-interactive keyring passphrase`: `get`/`list` also accept
  `--passphrase-env VAR`.
- ADDED `Hermes secret source plugin`: the plugin contract, config keys,
  subprocess posture, error mapping, conformance, live proof.
