// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Debug example: dump raw sync payload cipher metadata (no field values).
//! Usage: cargo run -p cryptile-vaultwarden --example dump-sync -- \
//!   <state_dir> <passphrase_env>
//! For each cipher: id, organizationId, collectionIds, name decrypt attempt
//! under user key vs org key (reports which key works, never plaintext).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use cryptile_core::SecretString;
use cryptile_vaultwarden::api::Client;
use cryptile_vaultwarden::crypto::{unwrap_org_key, EncString, SymmetricKey};
use std::fs;

fn main() {
    let mut args = std::env::args().skip(1);
    let state_dir = args.next().expect("state dir arg");
    let env_name = args.next().expect("passphrase env arg");
    let passphrase = std::env::var(&env_name).unwrap_or_else(|_| panic!("env {env_name} not set"));

    let session_json = cryptile_core::keyring::open(
        &fs::read_to_string(format!("{state_dir}/keyring")).expect("read keyring"),
        &SecretString::new(passphrase.clone().into()),
    )
    .expect("keyring open");
    let cfg: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(format!("{state_dir}/config.json")).expect("read config"),
    )
    .expect("config parse");
    let sess: serde_json::Value = serde_json::from_str(&session_json).expect("session parse");

    let tok = sess
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("token");
    let tok = tok.split(' ').next_back().unwrap_or(tok).to_string();
    let server = cfg.get("server").and_then(|v| v.as_str()).expect("server");

    let uk = sess
        .get("userKeyB64")
        .or_else(|| sess.get("user_key_b64"))
        .and_then(|v| v.as_str())
        .expect("user key field");
    let user_key =
        SymmetricKey::from_64(&B64.decode(uk).expect("user key decode")).expect("user key");

    let client =
        Client::new(server.to_string(), format!("{server}/api"), uuid_v4()).expect("api client");

    let sync = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(client.sync(&tok))
        .expect("sync call");

    println!("orgs in profile: {}", sync.profile.organizations.len());
    // RSA private key bytes: decrypt profile.private_key with the user key.
    let private_key = EncString::parse(&sync.profile.private_key)
        .and_then(|es| es.decrypt_symmetric(&user_key))
        .expect("profile private key decrypt");
    let mut org_keys: Vec<(String, SymmetricKey)> = Vec::new();
    for org in &sync.profile.organizations {
        if org.key.is_empty() {
            println!("  org id={} (no key)", org.id);
            continue;
        }
        let es = EncString::parse(&org.key).expect("org key parse");
        match unwrap_org_key(&es, &private_key) {
            Ok(k) => {
                println!("  org id={} key_len={} unwrap=OK", org.id, org.key.len());
                org_keys.push((org.id.clone(), k));
            }
            Err(e) => println!(
                "  org id={} key_len={} unwrap=FAIL ({e})",
                org.id,
                org.key.len()
            ),
        }
    }
    println!("ciphers in sync: {}", sync.ciphers.len());
    // Collection name EncString types for comparison (via /api/collections).
    let colls = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(client.collections(&tok))
        .expect("collections call");
    println!("collections via API: {}", colls.len());
    for c in &colls {
        let typ = c.name.split('.').next().unwrap_or("?");
        let segs = c.name.split('|').count();
        println!(
            "  coll id={} org={} enc_type={} mac_segs={}",
            c.id, c.organization_id, typ, segs
        );
    }
    for c in &sync.ciphers {
        println!(
            "  cipher id={} org={:?} collection_ids={:?} login_some={} fields={} name_type={} notes_some={}",
            c.id,
            c.organization_id,
            c.collection_ids,
            c.login.is_some(),
            c.fields.len(),
            c.name.split('.').next().unwrap_or("?"),
            c.notes.is_some()
        );
        // Name decrypt attempts: user key first, then each org key.
        let name_brief = |k: &SymmetricKey| -> String {
            match EncString::parse(&c.name).and_then(|es| es.decrypt_symmetric(k)) {
                Ok(pt) => format!(
                    "OK ({} bytes, starts {:?})",
                    pt.len(),
                    String::from_utf8_lossy(&pt)
                        .chars()
                        .take(12)
                        .collect::<String>()
                ),
                Err(e) => format!("FAIL ({e})"),
            }
        };
        println!("    name under user key: {}", name_brief(&user_key));
        for (oid, k) in &org_keys {
            println!("    name under org {}: {}", oid, name_brief(k));
        }
        // Notes decrypt check under org keys (length only; notes may hold the secret).
        if let Some(n) = &c.notes {
            if !n.is_empty() {
                for (oid, k) in &org_keys {
                    let r = EncString::parse(n).and_then(|es| es.decrypt_symmetric(k));
                    match r {
                        Ok(pt) => println!("    notes under org {}: OK ({} bytes)", oid, pt.len()),
                        Err(e) => println!("    notes under org {}: FAIL ({e})", oid),
                    }
                }
            }
        }
    }
}

fn uuid_v4() -> String {
    use rand_core::{OsRng, TryRngCore};
    let mut b = [0u8; 16];
    let _ = OsRng.try_fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = |s: &[u8]| -> String { s.iter().map(|c| format!("{c:02x}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}
