// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Debug example: count ciphers in the RAW /api/sync JSON payload (no typed
//! parse, no decryption). Usage: cargo run -p cryptile-vaultwarden --example
//! raw-sync -- <state_dir> <passphrase_env>
//! Prints per-cipher: id, type, orgId, collectionIds, presence of sshKey/key
//! fields. Field VALUES are never printed.

use base64::engine::general_purpose::STANDARD as B64;
use cryptile_core::SecretString;
use cryptile_vaultwarden::api::bare_client;
use std::fs;

fn main() {
    let mut args = std::env::args().skip(1);
    let state_dir = args.next().expect("state dir arg");
    let env_name = args.next().expect("passphrase env arg");
    let passphrase = std::env::var(&env_name).unwrap_or_else(|_| panic!("env {env_name} not set"));

    let session_json = cryptile_core::keyring::open(
        &fs::read_to_string(format!("{state_dir}/keyring")).expect("read keyring"),
        &SecretString::new(passphrase.into()),
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

    let rt = tokio::runtime::Runtime::new().unwrap();
    let body: serde_json::Value = rt.block_on(async {
        let client = bare_client();
        client
            .get(format!("{server}/api/sync"))
            .bearer_auth(&tok)
            .send()
            .await
            .expect("sync http")
            .error_for_status()
            .expect("sync status")
            .json()
            .await
            .expect("sync json")
    });

    let profile_email = body
        .pointer("/profile/email")
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");
    let profile_name = body
        .pointer("/profile/name")
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");
    println!("token identity: email={profile_email} name={profile_name}");

    let ciphers = body.get("ciphers").and_then(|v| v.as_array());
    match ciphers {
        None => println!(
            "NO 'ciphers' array in raw payload; top-level keys: {:?}",
            body.as_object().map(|o| o.keys().collect::<Vec<_>>())
        ),
        Some(cs) => {
            println!("RAW ciphers in sync payload: {}", cs.len());
            for c in cs {
                let id = c
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();
                let typ = c.get("type").map(|v| v.to_string()).unwrap_or("?".into());
                let org = c
                    .get("organizationId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(personal)");
                let cids = c
                    .get("collectionIds")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let has_key = c.get("key").map(|v| !v.is_null()).unwrap_or(false);
                let has_ssh = c.get("sshKey").map(|v| !v.is_null()).unwrap_or(false);
                let has_login = c.get("login").map(|v| !v.is_null()).unwrap_or(false);
                let deleted = c.get("deletedDate").map(|v| !v.is_null()).unwrap_or(false);
                let edited = c
                    .get("revisionDate")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                println!(
                    "  id={}.. type={} org={} collectionIds={} cipherKey={} sshKey={} login={} deleted={} rev={}",
                    &id[..8.min(id.len())], typ, &org[..8.min(org.len())], cids, has_key, has_ssh, has_login, deleted, edited
                );
            }
        }
    }
    let colls = body.get("collections").and_then(|v| v.as_array());
    if let Some(cs) = colls {
        println!("RAW collections: {}", cs.len());
        for c in cs {
            let id = c
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            println!("  coll id={}.. ", &id[..8.min(id.len())]);
        }
    }
    let _ = B64; // keep import parity with sibling examples
}
