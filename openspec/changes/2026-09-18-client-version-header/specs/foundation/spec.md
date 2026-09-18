## ADDED Requirements

### Requirement: Bitwarden client identification headers

The vaultwarden backend SHALL send `Bitwarden-Client-Name: web` and
`Bitwarden-Client-Version: 2024.12.0` on every HTTP request it issues to the
server, including requests from in-crate debug tooling, because servers gate
sync payload completeness (notably type-5 SSH-key ciphers) on a minimum client
version. The version value SHALL be a single named constant with a rationale
comment citing the sanctioned gold source (rbw) that pins it.

#### Scenario: every request carries the headers

- **WHEN** any request is issued through the provider's HTTP client, including
  identity token calls, sync, cipher get, and collection list
- **THEN** the request carries both client identification headers

#### Scenario: version-gated ciphers are delivered

- **WHEN** the server's sync payload omits type-5 (SSH key) ciphers for
  unversioned clients
- **THEN** the same server includes them in the payload for cryptile's requests,
  and `get` on a shared SSH-key item succeeds end-to-end

#### Scenario: debug tooling inherits the headers

- **WHEN** an in-crate debug example issues a raw request outside the provider
  client
- **THEN** it uses a client built by the crate's helper so the captured wire
  state matches what the provider itself sees

#### Scenario: header regression fails the suite

- **WHEN** the wiremock e2e mock for a request class receives a call missing
  either client identification header
- **THEN** the match fails and the test suite reports the regression
