// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Debug example: decrypt custom field NAMES (and value lengths) for one cipher.
//! Usage: cargo run -p cryptile-vaultwarden --example dump-fields -- \
//!   <state_dir> <passphrase_env> <cipher_id>
//! Prints field names (not secret values) plus value length + sha12.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use cryptile_core::SecretString;
use cryptile_vaultwarden::api::Client;
use cryptile_vaultwarden::crypto::{unwrap_org_key, EncString, SymmetricKey};
use std::fs;

fn sha12(b: &[u8]) -> String {
    use sha2::Digest;
    let h = sha2::Sha256::digest(b);
    h[..6].iter().map(|c| format!("{c:02x}")).collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let state_dir = args.next().expect("state dir arg");
    let env_name = args.next().expect("passphrase env arg");
    let cipher_id = args.next().expect("cipher id arg");
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

    let private_key = EncString::parse(&sync.profile.private_key)
        .and_then(|es| es.decrypt_symmetric(&user_key))
        .expect("profile private key decrypt");
    let mut org_keys: Vec<(String, SymmetricKey)> = Vec::new();
    for org in &sync.profile.organizations {
        if org.key.is_empty() {
            continue;
        }
        let es = EncString::parse(&org.key).expect("org key parse");
        if let Ok(k) = unwrap_org_key(&es, &private_key) {
            org_keys.push((org.id.clone(), k));
        }
    }

    let cipher = sync
        .ciphers
        .iter()
        .find(|c| c.id == cipher_id)
        .expect("cipher not found");

    // Pick the key that decrypts the name.
    let mut key: Option<&SymmetricKey> = None;
    for (_, k) in &org_keys {
        if EncString::parse(&cipher.name)
            .and_then(|es| es.decrypt_symmetric(k))
            .is_ok()
        {
            key = Some(k);
            break;
        }
    }
    if key.is_none()
        && EncString::parse(&cipher.name)
            .and_then(|es| es.decrypt_symmetric(&user_key))
            .is_ok()
    {
        key = Some(&user_key);
    }
    let key = key.expect("no key decrypts cipher name");

    println!("cipher {} fields: {}", cipher.id, cipher.fields.len());
    for f in &cipher.fields {
        let name = f.name.as_deref().map(|n| {
            EncString::parse(n)
                .and_then(|es| es.decrypt_symmetric(key))
                .map(|pt| String::from_utf8_lossy(&pt).into_owned())
                .unwrap_or_else(|e| format!("<undecryptable: {e}>"))
        });
        let val = f.value.as_deref().map(|v| {
            EncString::parse(v)
                .and_then(|es| es.decrypt_symmetric(key))
                .map(|pt| format!("len={} sha12={}", pt.len(), sha12(&pt)))
                .unwrap_or_else(|e| format!("<undecryptable: {e}>"))
        });
        println!("  name={:?} value={:?}", name, val);
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
