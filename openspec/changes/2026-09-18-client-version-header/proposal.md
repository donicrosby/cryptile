# Proposal: client-version-header

## Why

`cryptile get` on the shared SSH-key items exits 5 (not found) while the items are
plainly visible in the Vaultwarden web UI. Live capture of our own accounts
(`raw-sync` against prod on 2026-09-18) shows the account's `/api/sync` payload
contains zero type-5 (SSH key) ciphers — the items are never delivered to any
client the agent runs. A black-box probe ladder against our own harness server
(VW 1.37.2, docker `cryptile-vw`, throwaway accounts) isolated the mechanism:

- An org type-5 cipher persists server-side (direct `GET /api/ciphers/<id>` → 200)
  but is omitted from `/api/sync` for every account, the owner included.
- Adding `Bitwarden-Client-Version: 2024.12.x` (or `2026.6.0`) to the sync request
  makes the server include type-5 ciphers; no header, an old version (`1.37.2`),
  a made-up low version (`4.0.0`), or a wrong spelling does not.
- The server gates on a minimum client version (semver compare) before serializing
  type-5 ciphers into sync responses. cryptile sends no client headers on GET
  paths, so it classifies as a pre-SSH-key client.

Gold-source corroboration: rbw (MIT, sanctioned per `openspec/config.yaml`)
pins `Bitwarden-Client-Version: 2024.12.0` on its requests (`src/api.rs`).
`2024.12.0` is the pinned value this change adopts.

Clean-room note: every wire claim above comes from probes against our own
harness/prod servers, our own server's runtime logs (Rocket data-guard WARN
lines), our own harness database, and rbw. No Vaultwarden/Bitwarden source was
consulted for this change. (A prior session's tainted reading of Vaultwarden
server source is explicitly excluded; none of its content is used here.)

## What Changes

- `crates/vaultwarden/src/api.rs`: define the client identification headers once —
  `Bitwarden-Client-Name: web` and `Bitwarden-Client-Version: 2024.12.0` (named
  const with rationale comment) — and apply them via reqwest `default_headers` so
  every request issued through `Client` carries them; remove the per-request
  header literals in `post_form`; add a small `bare_client()` helper that builds a
  header-carrying `reqwest::Client` for debug tooling.
- Debug examples `raw-sync.rs` and `raw-cipher.rs`: replace bare
  `reqwest::Client::new()` with `bare_client()` — bare clients are exactly why
  `dump-sync`/`raw-sync` reported a false "item is not in the account" this
  morning.
- Wiremock e2e: the identity, sync, and cipher-get mocks require the client
  headers, so a regression fails the suite instead of silently degrading.
- No request/response body shapes change; the Python oracle and fixtures are
  untouched.

## Impact

- Specs: ADDED requirement `Bitwarden client identification headers` on the
  `foundation` capability. No MODIFIED/REMOVED deltas.
- Code: `crates/vaultwarden/src/api.rs`, two examples, `provider_e2e.rs`.
- Users: `get`/`list`/`export` against version-gating servers now receive the
  full cipher payload; servers that don't gate are unaffected (extra headers are
  ignored). No CLI surface change, no state-format change, no exit-code change.
- Ops: the previously-"missing" shared SSH keys become fetchable immediately
  after deploy, without any server-side or sharing-config change.

## Non-goals

- No support for the notification/push channel, no org-member management in
  cryptile itself (the harness repro tooling stays an integration-script
  concern).
- No dynamic version negotiation: the pinned const is a config-level decision;
  bumping it is a one-line change with a rationale comment.
- The 2FA change (`2026-09-17-add-two-factor-login`) is a separate in-flight
  change; this change does not touch its tasks or code paths.
