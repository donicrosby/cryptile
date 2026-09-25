# Tasks: add-fidoh-ceremony-provider

## Feature wiring

- [ ] 1.1 `crates/vaultwarden/Cargo.toml`: add optional `fidoh` dependency
      (git, per design) + off-by-default `fidoh = ["dep:fidoh", "dep:secrecy",
      "dep:tokio"]` feature; `cargo build -p cryptile-vaultwarden --features
      fidoh` succeeds and `cargo build -p cryptile-vaultwarden` (default)
      builds without pulling fidoh (`cargo tree -e features -p
      cryptile-vaultwarden | grep -c fidoh` is 0 on default).
- [ ] 1.2 Same crate: `cargo build -p cryptile-vaultwarden --features
      webauthn,fidoh` succeeds (both features on, fidoh authoritative —
      precedence proven by the 2.2 test, not just a compile).
- [ ] 1.3 `deny.toml`: add the fidoh git source to the allow-list with the
      in-house-deviation rationale (design.md §invariant-touching);
      `cargo deny check sources licenses` green with `--features fidoh`,
      and default-build `cargo deny check` output unchanged.

## Ceremony provider (webauthn.rs shrink)

- [ ] 2.1 `webauthn.rs` gating widened to
      `any(feature = "webauthn", feature = "fidoh")` for challenge decode +
      origin + wire assembly; fidoh-backed ceremony entry added behind
      `feature = "fidoh"` taking challenge + clientDataHash + budget,
      returning the assertion components as typed results;
      `cargo test -p cryptile-vaultwarden --features fidoh` green (pure
      decode/assembly units run under the fidoh feature).
- [ ] 2.2 Provider routing: `answer_two_factor`'s provider-7 arm dispatches
      to the fidoh entry when `feature = "fidoh"` (legacy path otherwise
      byte-identical); wiremock e2e parity test proves the fidoh path
      answers the same challenge with the same wire shape — exact
      `twoFactorProvider=7` + `twoFactorToken` form fields, exactly two
      token-endpoint calls inside one `login()`, no `TwoFactorRequired`
      surfaced — via the `with_assertion_hook` seam, matching the existing
      default-path e2e assertions.
- [ ] 2.3 Budget + error mapping: e2e/unit tests pin the mapping table
      (design.md §error mapping) — decline/mismatch/decode → Auth (3),
      no-device/transport/budget-expiry → Transport (4), assembly
      failure/panic → Server (4); a test drives the ceremony budget to
      expiry (hook stand-in blocked past the budget) and asserts typed
      Transport, never an indefinite hang (test itself carries a timeout
      guard).

## Gates + docs

- [ ] 3.1 Full gate matrix green: `cargo fmt --all --check`; `cargo clippy
      --workspace --all-targets -- -D warnings`; `cargo test --workspace`;
      plus each gate re-run with `--features fidoh` and with
      `--features webauthn,fidoh` (zero warnings in every configuration).
- [ ] 3.2 CLI composition-root invariant: `grep -rn 'fidoh' crates/cli/`
      returns nothing (CLI never names the backend type); `cargo tree`
      confirms fidoh is a `cryptile-vaultwarden`-only edge.
- [ ] 3.3 Docs: README feature notes updated (`--features fidoh`
      opt-in flag, stage-2 caveat), SKILL-referenced hardware runbook
      gains a one-line note that the fidoh path carries an explicit
      budget (runbook's outer-timeout triage stays legacy-path-only).
- [ ] 3.4 Manual hardware smoke (documented, not CI): with a real key and
      a webauthn-2FA account, `cargo run -p cryptile -- login --features
      fidoh` (or the built binary) completes the ceremony via fidoh;
      result recorded in the change's tasks notes — the wiremock suite
      cannot prove device I/O.
- [ ] 3.5 Commit (conventional, e.g. `feat(vaultwarden): add fidoh
      CTAP2 ceremony provider behind opt-in feature`), push, CI green,
      `openspec archive 2026-09-25-add-fidoh-ceremony-provider --yes`,
      commit the archive move, push, watch CI to green.
