# Design: decouple-pcsc-link

## Constraint analysis

The failure is at the ELF loader (exit 127, before `main()`), so the fix
must remove the link-time dependency, not handle it. Three shapes were
considered:

### 1. Runtime-load pcsclite inside fidoh (`dlopen` via `libloading`)

`PcscLibrary::establish()` dlopens `libpcsclite.so.1`; absent library
becomes a typed `library-unavailable` cause. Strictly the best end-state
(CCID/NFC everywhere, zero opt-ins), but **not landable from this repo**:

- fidoh's `AGENTS.md` hard fence: `deny(unsafe_code)` workspace-wide,
  "no `unsafe` anywhere, no exceptions, no `#[allow]`". dlopen FFI
  (symbol resolution, transmute of the loaded symbol, calling the
  `SCard*` functions) is inherently unsafe; `libloading` itself exposes
  `unsafe` at every call site.
- fidoh's push remote is deliberately disabled (`NEVER push` during
  agent waves; `NO-PUSH-DURING-AGENT-WAVE.invalid`), so even a
  fence-compliant implementation cannot be published for cryptile to
  pin. The owner lands it upstream; cryptile follows in a later change.

### 2. Drop pcsc from the product entirely

Removes real capability (NFC ceremonies, CCID-only keys on fw 5.8+).
Discarded: the capability is wanted on hosts that have pcsclite, and the
`Library` trait already isolates the binding behind one feature flag, so
keeping it costs nothing.

### 3. Feature-split the binding (CHOSEN)

The `pcsc` crate is already `optional = true` inside
`fidoh-transport-pcsc`, and every `pcsc::` reference sits in one module
(`library.rs`) behind the always-compiled `Library` trait. The generic
`PcscTransport<L: Library>` engine is pure and stays. So:

- vaultwarden `fidoh` = hid + tokio + core (no pcsc crate at all →
  no NEEDED);
- vaultwarden `fidoh-pcsc` (implies `fidoh`) = adds
  `dep:fidoh-transport-pcsc` with its `pcsc` feature (today's shape);
- the no-binding build feeds discovery a build-aware typed diagnostic
  directly through the existing `None`-transport channel
  (`DiscoveryDiagnostic` naming `TransportKind::Pcsc` with the
  not-linked cause) — the same per-transport channel a dead pcscd
  already uses (D2 collect-never-short-circuit). An earlier draft had
  the default build compile `fidoh-transport-pcsc` (pure engine) with a
  stub `Library` impl feeding the engine; discarded as pointless
  machinery — the stub never touches a reader, so bouncing its error
  through the engine adds a dependency edge for zero information. The
  direct diagnostic is the same type, shape, and channel.

No unsafe, no fidoh change, both flavors exercised by the test matrix.

## Spec compliance notes

- "device selection, transport handling … SHALL live inside fidoh":
  preserved — the stub is a `Library` impl consumed by fidoh's engine;
  fidoh still decides what a failed transport means (typed skip into the
  diagnostics list).
- Licensing requirement: default build still pulls the fidoh stack
  (Apache-2.0); only the pcsclite binding leaves the default flavor.
- Architecture invariants: provider seam untouched; CLI gains only a
  feature name passthrough, never a fidoh type.

## Test strategy

- Default-feature suite: unchanged green (the cfg'd stub + generic
  discovery must compile and behave under `cargo test --workspace`).
- Featured legs locally: `--features fidoh` (no pcsc: probe the
  diagnostic), `--features fidoh,fidoh-pcsc` (binding on: today's
  behavior), plus clippy `--all-targets` on both (the stub module and
  the establish site are cfg-paired; each leg must lint clean).
- CI: default `check` job drops `libpcsclite-dev` and asserts the built
  binary has no `libpcsclite` NEEDED (exec-compatibility pinned at the
  gate); matrix gains `fidoh,fidoh-pcsc`.
- Deploy proof: `/opt/data/bin/cryptile --version` stamps 0.3.1;
  `ldd` shows no pcsc entry; live `get` verified by length + sha12
  against the provider, never printed secrets.
