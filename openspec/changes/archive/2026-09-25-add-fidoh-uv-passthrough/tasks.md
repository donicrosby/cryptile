# Tasks: add-fidoh-uv-passthrough

- [x] 2.1 `webauthn.rs`: parse `userVerification` in
      `challenge_from_body` (absent → discouraged, case-insensitive),
      extend `WebauthnChallenge`, map to `UvPolicy` in the fidoh
      `exchange()`; unit tests for preferred/required/absent green under
      `--features fidoh` and `--features webauthn,fidoh`.
- [x] 2.2 Parity e2e `fidoh_webauthn_resubmit_matches_default_path_wire_shape`
      stays green; legacy-path units unchanged and green.
- [x] 2.3 Gates: fmt, clippy (-D warnings, all three feature configs),
      `cargo test --workspace` in all three configs, `cargo deny check`.
- [x] 2.4 `openspec validate add-fidoh-uv-passthrough --strict` green;
      archived with `--yes` (spec delta applied).
- [ ] 2.5 Commit (conventional), push, CI green — landed by the
      orchestrator; this agent makes no commits.
