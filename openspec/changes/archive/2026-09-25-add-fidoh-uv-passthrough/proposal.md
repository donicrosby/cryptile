# Proposal: add-fidoh-uv-passthrough

## Why

The owner's hardware smoke on their PIN-set YubiKey found the fidoh-path
login never asked for the PIN, while the legacy path does. Cause: the
server's provider-7 challenge carries `userVerification`, but
`challenge_from_body` drops it and the fidoh exchange builder hardcodes
`UvPolicy::Discouraged` — so the key is never asked to verify the user,
and the server-requested verification posture is silently ignored. (The
legacy path also hardcodes `discouraged`; that is stage-2 territory and
stays byte-identical.)

## What Changes

- `crates/vaultwarden/src/webauthn.rs`, fidoh path only:
  `challenge_from_body` parses `userVerification` from the provider-7
  entry (absent → `discouraged`; accepted values `discouraged`,
  `preferred`, `required`, case-insensitive per the server wire spelling),
  `WebauthnChallenge` carries it, and the fidoh exchange maps
  `discouraged` → `UvPolicy::Discouraged`, `preferred`/`required` →
  `UvPolicy::Preferred`. Fidoh degrades `Preferred` gracefully to the
  `Discouraged` wire shape when the plugged key advertises no `uv`
  capability (its own documented getInfo-probe contract, reported in the
  ceremony outcome) — full PIN flow arrives with fidoh beta.1's clientPIN
  work, not here.
- Unit tests: challenge fixture with `preferred` decodes to Preferred;
  `required` likewise; absent decodes to Discouraged. The existing
  wiremock parity e2e (`fidoh_webauthn_resubmit_matches_default_path_wire_shape`)
  stays green — its harness challenge says `discouraged`.

## Impact

- **Specs**: extends `two-factor-login` with one ADDED requirement (the
  fidoh path honors the server-requested user-verification posture) — the
  capability that already owns the fidoh ceremony.
- **Code**: `crates/vaultwarden/src/webauthn.rs` only (shared challenge
  decode gains the field; only the fidoh exchange consumes it). The
  legacy `request_options` string is untouched byte-for-byte.
- **Invariants preserved**: the legacy path keeps its exact wire shape
  and behavior; fidoh stays inside the vaultwarden crate; the CLI never
  names fidoh; nothing PIN-related is wired (no pinUvAuth acquisition).

## Non-goals

- No legacy-path change: `request_options` keeps its hardcoded
  `discouraged` until stage 2 flips the default ceremony path.
- No PIN acquisition or pinUvAuthToken work (fidoh v1 cannot acquire a
  token; beta.1's clientPIN is the named follow-up) — this change moves
  the request posture only.
- No challenge-shape changes beyond the one added field; unknown or
  malformed `userVerification` values are not invented into a policy.
