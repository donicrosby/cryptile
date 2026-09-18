# Tasks: ssh-agent-handoff

- [x] 1. `crates/cli/src/agent.rs`: `looks_like_ssh_private_key` (first-line
  marker sniff) + `add_to_agent` (`ssh-add -`, stdin-only, best-effort,
  stderr-only notes). Verify: `cargo test -p cryptile --lib`.
- [x] 2. Wire `--agent` flag into `Get` (arg + dispatch); key offered before
  the stdout print, refusal never fatal. Verify: e2e below.
- [x] 3. Unit tests: sniff accept/reject (incl. public PEM), no-agent silent
  skip, live-agent add/list/cleanup when `SSH_AUTH_SOCK` exists. Verify:
  `cargo test -p cryptile`.
- [x] 4. E2e (fake `ssh-add` shim on PATH capturing stdin): key bytes arrive
  intact and value still prints; missing agent degrades silently; password
  values never reach the shim. Verify: `cargo test -p cryptile --test
  ssh_agent`.
- [x] 5. Gates: fmt, clippy zero warnings, workspace tests green. Verify:
  all three exit 0.
- [x] 6. README section (SSH agent hand-off) + 0.2.0 version bump (shared
  with client-version-header). Verify: README renders, `--version` shows
  0.2.0.
- [x] 7. Commit, push, CI green, archive change.
