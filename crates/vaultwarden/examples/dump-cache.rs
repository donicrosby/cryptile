// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Debug example: dump the sealed sync-cache metadata (cipher index).
//! Usage: cargo run -p cryptile-vaultwarden --example dump-cache -- \
//!   <state_dir> <passphrase_env>
//! Prints collection names/ids, org ids, and cipher name/org/collection_ids.
//! Never prints secret field values (the cache stores none).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use cryptile_core::SecretString;
use cryptile_vaultwarden::cache::unseal;
use cryptile_vaultwarden::crypto::SymmetricKey;
use std::fs;

fn main() {
    let mut args = std::env::args().skip(1);
    let state_dir = args.next().expect("state dir arg");
    let env_name = args.next().expect("passphrase env arg");
    let passphrase = std::env::var(&env_name).unwrap_or_else(|_| panic!("env {env_name} not set"));

    // 1. Unseal keyring -> session JSON (serde_json::Value; no need for
    //    private VwSession struct fields beyond user_key_b64).
    let session_json = cryptile_core::keyring::open(
        &fs::read_to_string(format!("{state_dir}/keyring")).expect("read keyring"),
        &SecretString::new(passphrase.clone().into()),
    )
    .expect("keyring open");

    let sess: serde_json::Value = serde_json::from_str(&session_json).expect("session json parse");

    // Try both naming conventions for the user key field.
    let uk = sess
        .get("userKeyB64")
        .or_else(|| sess.get("user_key_b64"))
        .and_then(|v| v.as_str())
        .expect("user key field in session");

    let blob = B64.decode(uk).expect("user key b64 decode");
    let user_key = SymmetricKey::from_64(&blob).expect("user key from 64 bytes");

    // 2. Unseal the sync cache.
    let line = fs::read_to_string(format!("{state_dir}/cache/cipher-index"))
        .expect("read cache/cipher-index");
    let data = unseal(&user_key, &line).expect("cache unseal");

    println!("account: {:?}", data.account);
    println!("collections ({}):", data.collections.len());
    for c in &data.collections {
        println!("  id={} org={} name={:?}", c.id, c.org_id, c.name);
    }
    println!("ciphers ({}):", data.ciphers.len());
    for c in &data.ciphers {
        println!(
            "  id={} org={:?} name={:?} collection_ids={:?}",
            c.id, c.org_id, c.name, c.collection_ids
        );
    }
}
