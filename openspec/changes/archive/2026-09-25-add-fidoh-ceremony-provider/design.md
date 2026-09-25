# Design: add-fidoh-ceremony-provider

## Context

Today `answer_two_factor` (provider.rs, `Some((7, _))` arm) decodes the
challenge via `webauthn::challenge_from_body`, then either takes the
debug-only `with_assertion_hook` stand-in or runs
`webauthn::perform_assertion` on a blocking thread: a dedicated
current_thread runtime hosts `webauthn-authenticator-rs` transports, and
an outer `tokio::time::timeout` (60 s) bounds the whole thing because the
crate's keepalive loop is unbounded. Every ceremony error maps to
`ProviderError::Auth` (exit 3) except thread panic → `Server` (exit 4).
The wire contract is pinned by `tests/fixtures/CAPTURES.md` and the
live-verified gauntlet: web-vault-connector token JSON (lowercase
`clientDataJson`, unpadded base64url, no `userHandle`,
`id == rawId`), `twoFactorProvider=7`, exactly two token-endpoint calls
per login.

fidoh already owns the ceremony: device selection, transport, keepalives,
touch, and a single ceremony-wide Deadline where unbounded wait is a spec
violation. It takes a clientDataHash (clientDataJSON stays with the
caller) and returns typed results. That boundary is exactly the cryptile
side this change keeps.

## Alternatives considered

1. **Big-bang flip (land fidoh as the default in one change).** Discarded:
   no parity safety net for a hardware path CI cannot exercise; the owner
   chose a staged cutover. Stage 2 is the named follow-up.
2. **Keep `webauthn-authenticator-rs`, improve only the outer timeout
   wrap.** Discarded: treats the symptom (hang) not the cause (unbounded
   keepalive design, parallel-transport races); leaves the distrusted
   dependency in place indefinitely.
3. **Drive the parity e2e through fidoh's soft-token transport
   (dev-dependency) instead of the assertion hook.** Attractive — it
   would exercise the real fidoh ceremony in CI — but it widens stage 1
   with a dev-dep on the soft transport and assumptions about its
   registration API. Deferred as a stage-2 candidate; stage 1 keeps the
   proven `with_assertion_hook` seam. The no-soft-token policy is
   unaffected either way (soft transport never enters the product
   feature).
4. **Feature mutual exclusion via `compile_error!` when both `webauthn`
   and `fidoh` are on.** Discarded: additive cargo features are the
   workspace norm and a deterministic precedence (fidoh authoritative)
   is simpler to test and document than an error users must untangle.
5. **Wait for fidoh on crates.io.** Discarded: fidoh stays
   0.1.0-alpha.N until its specs stabilize (owner policy); a git
   dependency with a deny.toml source allow-list is the honest channel
   and matches how the harness already gates unusual sources.
6. **Grow a cryptile-owned ceremony crate instead.** Discarded: duplicates
   what fidoh exists to be; the grievance ledger (unbounded keepalive,
   transport races) is already designed out of fidoh's spec set.

## Invariant-touching decisions (explicit, owner-approved)

- **Dependency-policy deviation ("ecosystem crates over in-house"):**
  intentional and recorded. fidoh replaces a distrusted ecosystem dep;
  `deny.toml` carries the rationale next to the git-source allow-list
  (mirroring how the MPL-2.0 exception is documented there). This is a
  replacement, not a stealth in-house build-out: fidoh's scope is
  getAssertion-only v1, and cryptile stays a consumer.
- **No-device exit-code divergence:** the fidoh path maps no-device-found
  to the transport class (exit 4); the legacy path keeps its current
  Auth(3). Exit 3 means "credentials/state wrong" — a missing key is not
  that. Unifying is stage 2 (when the legacy path dies); until then the
  divergence is feature-scoped and documented, not a regression.
- **`webauthn` module gating widens:** `challenge decode + wire assembly`
  must compile under `any(feature = "webauthn", feature = "fidoh")` so
  the fidoh feature is self-sufficient. No behavior change for existing
  builds.
- **Verified preserved, untouched by this change:** Provider trait
  object safety (fidoh never crosses the trait — it lives inside
  cryptile-vaultwarden); CLI composition root (CLI never names fidoh
  types; gate: grep over `crates/cli`); secret typing (assertion blob is
  a `SecretString` end to end); tokio current_thread (the blocking-thread
  + dedicated current_thread runtime call pattern is kept; fidoh-tokio is
  tokio 1.x compatible); no-soft-token policy (product feature enables
  hardware transports only); cleanroom rules (fidoh's own provenance is
  the owner's cleanroom project — its repo, not a licensed source).

## Seam: what crosses cryptile → fidoh

In: challenge bytes (decoded from the provider-7 entry), RP ID, allowed
credential IDs, origin derived by `origin_for_rp_id`, clientDataHash
(clientDataJSON assembled in cryptile), explicit ceremony budget.
Out: typed result — assertion components for the VW wire-shape assembly,
or a typed error per the mapping below. Cryptile performs no CTAPHID,
PC/SC, or keepalive work itself; device-selection/keepalive/touch
semantics are fidoh's contract (its own spec set — cited, not restated).

## Error mapping (pinned by the delta)

| fidoh outcome | ProviderError | Exit |
|---|---|---|
| assertion obtained | (token blob, `SecretString`) | 0 |
| user declined / UP rejected / PIN-consent failure | Auth | 3 |
| credential mismatch (wrong credential vs allowList) | Auth | 3 |
| malformed challenge / unusable RP ID (cryptile-side decode) | Auth | 3 |
| server rejects the assertion resubmit | Auth | 3 |
| no device found | Transport | 4 |
| transport open/enum/I-O failure | Transport | 4 |
| budget expiry (wedged device, touch never given) | Transport | 4 |
| token JSON assembly failure (internal) | Server | 4 |
| ceremony thread panicked | Server | 4 |

## Open questions

None for stage 1. Stage-2 candidates recorded as non-goals in the
proposal (soft-transport e2e, default flip, dep deletion, exit-code
unification).
