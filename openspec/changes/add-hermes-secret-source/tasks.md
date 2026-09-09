# Tasks — add-hermes-secret-source

- [x] 1.1 CLI: `get`/`list` accept `--passphrase-env VAR`; unit tests for env path + non-TTY failure hint
- [x] 1.2 Plugin skeleton `integrations/hermes/` (plugin.yaml, `__init__.py`): CryptileSource identity attrs (name `cryptile`, label `Cryptile`, scheme `vw`, mapped, token_env_key `passphrase_env`, default `CRYPTILE_PASSPHRASE`)
- [x] 1.3 `fetch()`: validate env map (vw:// refs only), resolve binary, per-ref `run_secret_cli(["cryptile","get","--passphrase-env",VAR,"--","<ref>"])`, exit-code→ErrorKind map (2→REF_INVALID, 3→AUTH_FAILED, 4→NETWORK, 5→EMPTY_VALUE, else INTERNAL); never raise/prompt
- [x] 1.4 Optional hooks: `config_schema()`, `remediation_hints` (auth→re-login, binary→install), `protected_env_vars`, `fetch_timeout_seconds` default via ABC
- [x] 1.5 Unit tests (fake cryptile binary): per-kind classification, malformed config shapes, empty env map, non-vw ref warning+skip, multi-ref partial success, allow_env verified
- [x] 1.6 Conformance kit vs real Hermes source (shallow sparse clone in harness; skipped with notice if clone unavailable)
- [x] 1.7 Live e2e in harness: provision VW, real `cryptile login`+`get` through plugin `fetch()` and real `apply_all()`; assert env var holds seeded plaintext, provenance labels source
- [x] 1.8 Onboarding docs: end-user guide for hooking cryptile to a real Vaultwarden (server requirements, org/collection + service-account setup, `cryptile login`, Hermes config.yaml wiring, rotation/recovery)
- [x] 1.9 Plugin README: install, config, failure modes, command-helper alternative
- [x] 1.10 Gates: fmt/clippy/test workspace, `openspec validate --strict`
- [ ] 1.11 Commit, push, CI green, archive
