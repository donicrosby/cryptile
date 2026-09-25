# Tasks: fix-sync-null-tolerance

- [x] 1.1 `api.rs`: add `null_to_default` deserialize_with helper; apply
      to the five sequence members (ciphers, organizations, fields,
      uris, collections envelope `data`); default build unit tests
      green (`cargo test -p cryptile-vaultwarden`).
- [x] 1.2 Gates: fmt, clippy (-D warnings, default + fidoh +
      webauthn,fidoh), `cargo test --workspace` in all three configs,
      `cargo deny check` — all green.
- [x] 1.3 `openspec validate fix-sync-null-tolerance --strict` green;
      archived with `--yes` (spec delta applied).
- [ ] 1.4 Commit (conventional), push, CI green — landed by the
      orchestrator; this agent makes no commits.
