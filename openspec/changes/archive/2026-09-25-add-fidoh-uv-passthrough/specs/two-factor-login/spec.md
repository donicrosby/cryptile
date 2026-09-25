# two-factor-login Delta — add-fidoh-uv-passthrough

## ADDED Requirements

### Requirement: fidoh path honors the server-requested user verification posture

When built with the `fidoh` feature, the backend SHALL parse
`userVerification` from the provider-7 challenge entry (absent →
`discouraged`; accepted values `discouraged`, `preferred`, `required`,
matched case-insensitively) and carry it on the decoded challenge, and
the fidoh getAssertion exchange SHALL map `discouraged` to
`UvPolicy::Discouraged` and `preferred`/`required` to
`UvPolicy::Preferred`. Fidoh MAY degrade `Preferred` to the `Discouraged`
wire shape when the device's getInfo probe advertises no `uv` capability,
per fidoh's own degradation contract. The legacy path SHALL keep its
current hardcoded posture unchanged. No PIN acquisition SHALL be wired by
this requirement — `Preferred` with a verifier key is fidoh's graceful
degradation contract, with the full clientPIN flow arriving in a later
fidoh revision.

#### Scenario: challenge posture decodes

- WHEN a provider-7 challenge carries
  `"userVerification": "preferred"` (or `"required"`)
- THEN the decoded challenge carries the Preferred posture and the fidoh
  exchange requests it
- WHEN the entry carries no `userVerification`
- THEN the decoded challenge carries Discouraged exactly as before this
  requirement

#### Scenario: discouraged posture keeps wire parity

- WHEN the provider-7 challenge says `"userVerification": "discouraged"`
- THEN the fidoh exchange uses `UvPolicy::Discouraged` and the assertion
  resubmit wire shape is unchanged (the parity e2e stays green)

#### Scenario: legacy path byte-identical

- WHEN any provider-7 challenge is answered on the default (`webauthn`
  feature) path
- THEN the request options carry the same hardcoded
  `"userVerification": "discouraged"` as before this requirement
