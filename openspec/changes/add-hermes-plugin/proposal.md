# Change Proposal: Hermes plugin — `cryptile export` + SecretSource integration

## Why

The foundation change gave cryptile a working CLI (`login`/`get`/`list` against
Vaultwarden with sealed sessions). The reason cryptile exists is the Hermes side:
RJ needs secrets at startup without a human pasting values, and without the agent
ever seeing them in conversation. Hermes already supports command-based secret
sources; cryptile's job is to be that command, cleanly.

## What Changes

- New `crates/hermes/` (`cryptile-hermes`): a thin Python-side integration is NOT
  built here — the MVP is the Hermes `command` secret source running `cryptile`.
  This change ships the CLI surface that makes that safe and useful:
  - `cryptile export --namespace <name>`: writes `KEY=value` lines (shell/env
    source-able) for every item in one namespace, values only, no metadata.
  - `--format json` alternative for programmatic consumers.
  - `--no-redact` is NOT added: export IS the raw-value surface, gated by the
    sealed keyring (passphrase prompt is TTY-gated, so cron/agent contexts use
    `--passphrase-env CRYPTILE_PASSPHRASE` instead, never a TTY prompt).
- Hermes side (documented in README, wired in Doni's Hermes config, not in this
  repo): a `cryptile` secret-source entry that runs
  `cryptile export --namespace hermes --passphrase-env CRYPTILE_PASSPHRASE`
  and consumes the stdout as env values. Tier-2 boundary: values land in Hermes
  env, never in conversation.
- Non-interactive passphrase: `--passphrase-env VAR` reads the keyring passphrase
  from an environment variable. This is the bootstrap credential Doni already
  places in Hermes `.env` (the BWS_ACCESS_TOKEN-equivalent slot from the
  original design discussion).
- Exit codes and stderr discipline preserved: nothing but `KEY=value` lines on
  stdout; all diagnostics to stderr.

## Capabilities

### Modified

- `spec:foundation` — CLI gains `export` with non-interactive passphrase input.
  No changes to Provider/keyring semantics.

## Impact

- Security: the Hermes process env gains decrypt-capable access scoped to ONE
  collection (server-side ACL on the service account). The agent's model context
  never contains values (they are env-only). Rotating the service-account
  password never invalidates the agent (refresh-token grant).
- Docs: README gains a "Hermes integration" section with the exact secret-source
  config snippet.
- Scope guard: no broker proxy (tier 3), no 1Password/OpenBao backends here.
