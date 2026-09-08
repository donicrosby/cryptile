//! Backend registry. Backends register here as they land; the CLI dispatches
//! on ref scheme and never branches on backend specifics.

/// Ids of backends linked into this build, in registration order.
/// cryptile-vaultwarden lands next; slots are reserved by scheme in refs:
/// `vw` (vaultwarden/bitwarden), `op` (1password), `vault` (openbao/vault).
pub fn backends() -> Vec<&'static str> {
    // No backend crates are linked yet; this grows as they land.
    Vec::new()
}
