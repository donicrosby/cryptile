# Tasks: type-aware-default-field

- [x] 1. `reference.rs`: `field_explicit` on `Ref`; set in `parse`; unit tests for explicit/defaulted
- [x] 2. `model.rs`: `Secret::primary_value()` walking `PRIMARY_FIELD_CHAIN` (`password → notes → private_key → number`), skipping empties; unit tests incl. empty-skip and no-hit
- [x] 3. `ops.rs`: `get` selects by `field_explicit`; defaulted refs report the chain in the not-present error
- [x] 4. e2e: bare ref on note / per-cipher-key note / card / login items resolves via chain; explicit selection unchanged
- [x] 5. README default-field section update
- [x] 6. gates: fmt, clippy clean (0 warnings), workspace tests green (14 suites)
- [x] 7. release build, deploy, live probe: bare `vw://RJ-45/Dolos Lemonade Key` exit 0, sha12 a4445379eb6f (== `#notes` value); explicit `#password` still exit 5 with same error
- [x] 8. validate --strict, commit, push, archive
