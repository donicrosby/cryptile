# foundation Specification Delta: add-token-lifecycle

## MODIFIED Requirements

### Requirement: Token lifecycle

The backend SHALL cache access tokens, record their expiry, refresh them
silently before expiry (within a 300-second margin) or on a 401 response,
and on refresh failure SHALL surface a remediation hint rather than retry
loops.

#### Scenario: silent refresh

- WHEN a token expires mid-session and a valid refresh token exists
- THEN the next request succeeds without user interaction

#### Scenario: proactive refresh within margin

- WHEN a sealed session's access token expires within the 300-second margin
- THEN the next command refreshes the token via the refresh grant before
  issuing backend requests and persists the rotated session on success

#### Scenario: refresh failure

- WHEN the refresh token is revoked or invalid
- THEN the CLI exits non-zero with a remediation hint naming the re-login
  command and performs no further network retries

#### Scenario: legacy sealed session

- WHEN a sealed session predates expiry tracking and records no expiry
- THEN commands proceed without proactive refresh and remain covered by the
  401-triggered refresh path

## REMOVED Requirements

### Requirement: Log and output redaction

(Removed and re-added as "Structural redaction": the `--no-redact` flag this
requirement promised was never implemented, is dead scaffolding in core, and
its TTY-gating semantics would break `export > .env` — the primary
agent-bootstrap path. The re-added requirement states the structural
guarantee that is actually enforced.)

## ADDED Requirements

### Requirement: Structural redaction

The system SHALL redact secret values in all log output, debug formatting,
and error messages. Secret values SHALL carry no `Display` implementation;
their `Debug` output SHALL show a placeholder. Raw values SHALL leave the
process only at the explicit stdout output boundary of `get` and `export`,
and there SHALL be no flag or configuration that weakens this boundary.

#### Scenario: redaction by default

- WHEN a `SecretValue` is formatted via Debug or Display in a non-TTY context
- THEN the output shows a placeholder, not the underlying value

#### Scenario: no display path

- WHEN library code outside the CLI stdout boundary attempts to print a
  secret value
- THEN no such code path compiles, because the value type exposes no
  Display and requires an explicit expose call
