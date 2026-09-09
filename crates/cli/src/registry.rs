// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Backend registry = the CLI's composition root. Backend crates are linked
//! HERE and nowhere else: ops/main speak `dyn Provider` only, dispatching on
//! ref scheme. Adding a backend = one match arm here plus its crate dep.

use cryptile_core::provider::Provider;

/// Build the provider for a ref scheme / stored backend id. `cache_path`
/// enables the backend's sealed sync cache when it supports one.
pub fn open(
    scheme: &str,
    server: Option<&str>,
    cache_path: Option<&std::path::Path>,
) -> Result<Box<dyn Provider>, String> {
    match scheme {
        "vw" => {
            use cryptile_vaultwarden::VaultwardenProvider;
            let server = server.ok_or_else(|| {
                "vw backend needs a server URL (run `cryptile login`)".to_string()
            })?;
            let mut p = VaultwardenProvider::new(server).map_err(|e| e.to_string())?;
            if let Some(path) = cache_path {
                p = p.with_cache_path(path);
            }
            Ok(Box::new(p))
        }
        other => Err(format!(
            "no backend linked for '{other}'; registered: {}",
            backends().join(", ")
        )),
    }
}

/// Ids of backends linked into this build, in registration order.
pub fn backends() -> Vec<String> {
    vec!["vw".into()]
}
