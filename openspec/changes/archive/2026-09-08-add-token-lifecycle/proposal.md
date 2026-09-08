# add-token-lifecycle

## Why

The audit of shipped code vs `foundation/spec.md` found two gaps:

1. **Token lifecycle**: the spec requires refresh "silently before expiry or on
   a 401 response". Only the 401 half exists — `expires_in` is parsed and then
   dropped; no expiry is recorded in the session, so every op runs on a stale
   token until the server rejects it.
2. **`--no-redact`**: the spec promises a flag that was never implemented, and
   `core::Redaction` is dead scaffolding nothing constructs. Worse, the
   promised semantics (refuse raw output when piped) would break
   `export > .env` — the primary agent-bootstrap use case. The flag is
   wrong, not missing.

## What Changes

- `Provider` trait gains `session_expiry(&Session) -> Option<u64>` (default
  `None`); backends that know their token TTL report unix-seconds expiry.
- VW session handle records `expires_at` at login/refresh (`expires_in` +
  wall clock), `#[serde(default)]` so already-sealed keyrings load unchanged.
- CLI ops call `ensure_fresh` before every backend operation: if expiry is
  within a 300s margin, refresh once and use the rotated session. Refresh
  failure pre-op is non-fatal; the reactive 401 path remains the fallback
  and produces the remediation hint.
- Spec: Token lifecycle requirement gains proactive-margin and
  legacy-session scenarios.
- Spec: Log and output redaction requirement is amended to what is actually
  enforced — structural redaction (secrecy `[REDACTED]`, no Display impl on
  secrets, raw values only at the stdout boundary). The `--no-redact` flag
  and its TTY-gating scenario are removed; `core::Redaction` is deleted.

## Impact

No CLI surface changes. Sealed sessions from before this change keep working
(reactive path). One extra token round-trip at most per command when a token
is near expiry.
