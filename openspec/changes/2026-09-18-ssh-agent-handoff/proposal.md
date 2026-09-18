# Proposal: ssh-agent-handoff

## Why

Cryptile's audience is agents and humans who then *use* SSH keys. After a
`get` of a `private_key` field, the key exists only in the caller's pipeline
or the agent host's disk-bound tooling. Every consumer currently re-imports
the key by hand (`cryptile get ... | ssh-add -`) or worse, via temp files.
The CLI already owns the decrypted value at the stdout boundary — offering
it to a running ssh-agent there is one flag, zero new trust boundaries
(the agent belongs to the same user), and removes the temp-file footgun.

## What Changes

- `get` grows an opt-in `--agent` flag: when the fetched value is an SSH
  private key (marker-sniffed, first line), pipe it to `ssh-add -` over
  stdin — never to disk, never for non-key values.
- Best-effort semantics: missing `SSH_AUTH_SOCK`, missing binary, or an
  `ssh-add` refusal degrade to a stderr note and a successful fetch.
- Never fatal, never on stdout: value printing is unchanged; agent notes
  go to stderr only.

## Impact

- Affected specs: `foundation` (CLI-visible behavior contract)
- Affected code: `crates/cli` (new `agent` module, `Get` flag, dispatch)
- Tests: unit (sniffing, no-agent skip, live-agent roundtrip where an
  agent exists) + wiremock e2e with a fake `ssh-add` shim (piped bytes
  captured and compared; degradation; non-key never piped)
- Ships in 0.2.0 together with the client-version-header fix.
