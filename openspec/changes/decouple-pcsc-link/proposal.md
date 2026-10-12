# Proposal: decouple-pcsc-link

## Why

The deployed Hermes binary (`/opt/data/bin/cryptile`, built with the default
`fidoh` feature) dies at exec on any host without `libpcsclite.so.1`:

```
/opt/data/bin/cryptile: error while loading shared libraries:
libpcsclite.so.1: cannot open shared object file: No such file or directory
```

Exit 127 for every invocation — `get`, `list`, even `--version` — because the
loader kills the process before `main()`. No application code can fail
gracefully: a link-time `DT_NEEDED` is not an error the CLI can handle. The
Hermes desktop host has no pcsclite, so every `secrets.cryptile` env var
injection currently fails.

Root cause: cli `default = ["fidoh"]` → vaultwarden `fidoh` feature →
`dep:fidoh-transport-pcsc` (features `std`, `pcsc`) → the `pcsc` crate →
pkg-config link of `libpcsclite` at build time → hard NEEDED at load time.
The pcsc transport serves CCID/NFC ceremonies only; USB HID (the dominant
path, and the only one a headless agent uses) links clean. One optional
transport poisons the whole binary.

## What Changes

- vaultwarden: the `fidoh` feature no longer pulls
  `fidoh-transport-pcsc` at all. A new `fidoh-pcsc` feature
  (implying `fidoh`) owns the dep with its `std`,`pcsc` binding for
  hosts that have pcsclite and want CCID/NFC. Default builds do not
  require pcsclite at build time or load time (no pcsc crate in the
  default dependency tree at all).
- vaultwarden `webauthn.rs`: pcsc imports, the `establish()` call, and
  the pcsc connect arm move behind `#[cfg(feature = "fidoh-pcsc")]`;
  the default build reports the pcsc transport as not-built through the
  existing typed discovery diagnostic (fidoh-core D2: collect, never
  short-circuit). USB HID ceremonies are unaffected.
- cli: `fidoh-pcsc` passthrough feature alongside the existing `fidoh`
  passthrough. CLI still never names fidoh or backend types.
- CI: the default `check` job drops `libpcsclite-dev` (proving the
  decoupling at the gate level) and gains a `ldd`-assertion step; the
  featured matrix gains a `fidoh,fidoh-pcsc` leg that keeps the binding
  compiled and tested.
- Version bump (workspace 0.3.0 → 0.3.1), release build, deploy to
  `/opt/data/bin/cryptile`, live verification by `ldd` + hash (never
  printed secrets), plugin-exact argv.

## Delta vs existing specs

Extends `two-factor-login` (the only spec naming fidoh). The
"Licensing for CTAP2 dependency" requirement ("the default CLI build SHALL
pull the fidoh stack, Apache-2.0") is unchanged — the stack is still
pulled, minus one transport binding. The "fidoh-backed WebAuthn ceremony
provider" requirement ("device selection, transport handling … SHALL live
inside fidoh") is unchanged — fidoh still owns all of it. One ADDED
requirement pins the new exec-compatibility contract and the opt-in
flavor. Pure ADDED delta; no requirement text is modified or dropped.

## Non-goals

- **No dlopen change in fidoh.** The runtime-loaded-pcsclite `PcscLibrary`
  (typed `library-unavailable` instead of a link-time NEEDED) remains the
  better end-state — CCID/NFC without any opt-in — but it is owner-owned
  upstream: fidoh's workspace-wide `deny(unsafe_code)` (no exceptions) and
  its agent-wave push freeze both block it from here. Recorded as the
  fidoh follow-up; this change is forward-compatible with it (the
  `fidoh-pcsc` flavor already isolates the loading choice to one type).
- **The active `ssh-agent-serve` change is untouched.** Its in-flight
  work was stashed unmerged; this change lands without it and does not
  advance its tasks.
- No NFC/CCID behavior change in builds that enable `fidoh-pcsc` — that
  flavor is byte-for-byte today's behavior.
- No new exit codes, CLI surface, or ref grammar changes.

## Impact

- `crates/vaultwarden/Cargo.toml`, `crates/vaultwarden/src/webauthn.rs`
  (cfg structure + diagnostic text), `crates/cli/Cargo.toml`,
  `.github/workflows/ci.yml`, `README.md`, workspace version.
- Hermes deployments: default binary execs on pcsclite-less hosts; USB
  HID security-key logins work everywhere; CCID/NFC requires the opt-in.
- CI: default job loses a system dependency; featured matrix gains a leg.
