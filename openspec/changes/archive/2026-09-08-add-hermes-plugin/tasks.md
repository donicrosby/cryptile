# Tasks — Hermes plugin change

## 1. Export command
- [x] 1.1 `cryptile export --namespace <name>`: KEY=value lines on stdout, metadata never
- [x] 1.2 `--format json`: `{"key": "value"}` object for programmatic consumers
- [x] 1.3 Field-name mangling for env safety: uppercase, non-[A-Z0-9_] -> `_`, collisions get `__1` suffix, mapping printed to stderr
- [x] 1.4 Values with newlines/NUL escaped or refused (decide + test) — newlines escaped `\n`/`\\`, NUL refused with exit 6; pinned by fixture-backed e2e (multiline notes through the full crypto chain)
- [x] 1.5 Refresh-retry semantics identical to get/list (4.5 pattern)

## 2. Non-interactive auth
- [x] 2.1 `--passphrase-env VAR`: read keyring passphrase from env (never TTY in agent contexts)
- [x] 2.2 Refuse BOTH `--passphrase-env` and a TTY absent: hard error with remediation hint
- [x] 2.3 Zeroize the env-passphrase copy on drop (secrecy already does)

## 3. Hermes wiring (docs, config snippet)
- [x] 3.1 README "Hermes integration" section: command secret-source config, tier-2 boundary explanation
- [x] 3.2 Document rotation runbook: service-account password + keyring passphrase rotation steps

## 4. Repo mechanics
- [x] 4.1 Conventional commits (enforced), CI green, branch protection requires check+deny
