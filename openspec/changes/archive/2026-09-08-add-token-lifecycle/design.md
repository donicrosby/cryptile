# Design: add-token-lifecycle

## Context

Bitwarden identity tokens are JWTs with ~1h TTL. The CLI seals the whole
session handle; nothing currently records when the access token dies, so
every command gambles on the token still being valid and eats a 401 + retry
round-trip when it isn't.

## Goals / Non-Goals

- Goals: proactive refresh with a margin; backward compat with sealed
  keyrings; backend-agnostic CLI (no VW types leak into ops).
- Non-Goals: background refresh daemons, clock-skew negotiation, refreshing
  during long-running streaming ops (none exist).

## Decisions

- **Expiry lives in the backend handle, not the core Session.** `Session` is
  the opaque capability marker; adding a typed `expires_at` field to it
  would force every backend to fake one. Instead the trait grows
  `session_expiry(&Session) -> Option<u64>` with a default `None`; VW parses
  its own handle. CLI stays dyn-Provider clean.
- **`Option<u64>` unix seconds + `#[serde(default)]`.** Old sealed keyrings
  deserialize with `None` → `ensure_fresh` is a no-op → reactive 401 path
  still covers them. No migration, no forced re-login.
- **300s margin.** Tokens are ~3600s; 300s covers clock skew and a slow
  command without refreshing on every invocation.
- **Pre-op refresh failure is non-fatal.** If the refresh endpoint is
  unreachable, the op itself will fail with a transport error anyway; if the
  refresh token is dead, the op's 401 → refresh → retry path surfaces the
  remediation hint. One code path produces user-facing auth errors.
- **`--no-redact` removed from spec, `Redaction` deleted.** Redaction is
  structural: `SecretString` has no Display and Debug prints `[REDACTED]`;
  raw values can only leave via `expose_secret()` at the CLI stdout
  boundary. A flag that gates *that* boundary on TTY-ness would break
  `export > .env`, which is the product. The spec now states the structural
  guarantee instead of promising a flag nobody can use.

## Risks / Trade-offs

- Wall-clock dependency: a system clock set backwards skips proactive
  refresh; the reactive path absorbs it.
- Refresh grant rotates the refresh token; if the process dies between
  grant and re-seal, the sealed refresh token is stale → next refresh fails
  → remediation hint → re-login. Same failure mode already existed for the
  401 path; not new.

## Migration Plan

None required: serde defaults handle old handles; CI + full test suite gate
the change.
