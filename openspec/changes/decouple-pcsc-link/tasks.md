# Tasks: decouple-pcsc-link

- [x] 1. vaultwarden: restructure features in `crates/vaultwarden/Cargo.toml`
      — `fidoh` drops `dep:fidoh-transport-pcsc`; new `fidoh-pcsc` feature
      (implies `fidoh`) owns the dep with `std`,`pcsc`; verify feature
      resolution with `cargo tree -e features -i pcsc` (pcsc appears only
      under `fidoh-pcsc`).
- [x] 2. vaultwarden: cfg-split `webauthn.rs` — pcsc imports,
      `PcscLibrary::establish()`, and the pcsc connect arm behind
      `#[cfg(feature = "fidoh-pcsc")]`; default build emits the
      build-aware not-linked `DiscoveryDiagnostic` for pcsc in the
      existing `discover()` channel; add the default-build unit test
      asserting the diagnostic (scenario exec-compat-pcsc-diagnostic).
- [x] 3. cli: add `fidoh-pcsc` passthrough feature in `crates/cli/Cargo.toml`
      implying `fidoh`; clippy both flavors zero warnings.
- [x] 4. CI: default `check` job drops `libpcsclite-dev`, adds the
      `ldd`-assertion step (no `libpcsclite` in the release/default binary's
      NEEDED); featured matrix gains `cryptile-vaultwarden/fidoh,fidoh-pcsc`.
- [x] 5. README: pcsc flavor documented under the CTAP2 stack section
      (opt-in `fidoh-pcsc`, why, who needs it);`fidoh-pcsc` noted for
      packagers.
- [x] 6. Gates: `cargo fmt --all`; `cargo clippy --workspace --all-targets`
      (default) AND `--features fidoh,fidoh-pcsc` zero warnings;
      `cargo test --workspace` (default) AND featured leg green;
      `openspec validate decouple-pcsc-link --strict`.
- [ ] 7. Ship: bump workspace version 0.3.0 → 0.3.1, release build (default
      features), deploy to `/opt/data/bin/cryptile`, confirm deployed
      `--version` stamp 0.3.1, `ldd` shows no pcsclite, sealed live `get`
      verified by len + sha12, plugin-exact argv (`HOME=/opt/data` bare
      CLI) verified; commit (conventional), push, CI green, archive the
      change, commit the archive.
