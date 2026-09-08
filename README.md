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

## Development

```sh
cargo test --workspace
pip install pre-commit && pre-commit install --hook-type commit-msg
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org),
enforced by the commit-msg hook above.

## License

Apache-2.0. No Bitwarden code, no `bitwarden-sdk` (GPLv3) — crypto implemented
from the public Bitwarden security whitepaper, cross-checked against
independent MIT-licensed clients (rbw, goldwarden). Same clean-room
position Vaultwarden itself took.
