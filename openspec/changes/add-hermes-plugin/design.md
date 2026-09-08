# Design — Hermes plugin change

## Context

Foundation landed: login/get/list, sealed keyring, refresh retry. This change
adds the export surface Hermes consumes. Architecture unchanged; this is a CLI
surface + docs change riding on the existing Provider/keyring.

## Key decisions

- **Export IS the raw-value surface.** No `--no-redact` flag: redaction applies
  to metadata/display paths (Debug, list, logs), and export exists precisely to
  emit values. The gate is authentication: sealed keyring + passphrase.
- **Passphrase via env var for agents.** `--passphrase-env VAR` is the
  non-interactive path. Hermes `.env` already holds the bootstrap credential
  slot (design: "the BWS_ACCESS_TOKEN-equivalent slot"). TTY prompt remains the
  human path; when neither works, hard error (never read stdin blindly).
- **Env-format safety.** Keys mangled to `[A-Z0-9_]+`; collisions disambiguated
  `__1`; values with newlines escaped `\n` (and `\\`), NUL refused outright.
  The key-mangling map prints to stderr so a human can see what changed.
- **JSON format** for programmatic consumers; same values, no mangling needed.
- **Refresh semantics** reuse the ops pattern: one refresh, one retry, hint.

## Risks / edge cases

- Env-passphrase leaks into `ps(1)`? No — env vars are not argv; Hermes env is
  the threat model Doni already accepted for the bootstrap slot.
- Export of a wrong namespace = scope leak? The server-side ACL (service
  account sees only its collection) is the real boundary; export adds nothing.
- Newline-in-value breaking the line format: escaped, tested.
