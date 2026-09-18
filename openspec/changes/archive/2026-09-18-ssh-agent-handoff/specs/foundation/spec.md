# foundation Specification

## ADDED Requirements

### Requirement: SSH agent hand-off on get

The CLI SHALL accept an opt-in `--agent` flag on `get` that offers the
fetched value to the user's running ssh-agent (via `ssh-add` reading
standard input) when and only when the value is an SSH private key.

#### Scenario: key piped to agent without disk contact

- WHEN `get --agent` resolves a ref whose value is an SSH private key and
  `SSH_AUTH_SOCK` is set with a reachable agent
- THEN the key is piped to `ssh-add` over stdin (never written to a file)
  and the fetched value still prints on stdout unchanged

#### Scenario: non-key values are never offered

- WHEN `get --agent` resolves a ref whose value is not an SSH private key
- THEN no child process is spawned and the value prints as usual

#### Scenario: best-effort degradation

- WHEN the agent is absent, unreachable, or refuses the key
- THEN the fetch still succeeds with its normal exit code and the value
  still prints, with at most a one-line stderr note
