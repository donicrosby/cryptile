// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Debug example: verify a candidate master password against the live
//! profile key WITHOUT attempting login. Unseals the stored session (its
//! access token is used read-only for /api/sync), derives the master key
//! from the candidate, stretches it, and attempts profile.key decrypt.
//! Prints fingerprints only — never key material or plaintext.
//!
//! Usage: cargo run -p cryptile-vaultwarden --example check-master -- \
//!   <state_dir> <passphrase_env> <candidate_env>

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use cryptile_core::SecretString;
use cryptile_vaultwarden::api::Client;
use cryptile_vaultwarden::crypto::{
    derive_master_key, stretch_master_key, EncString, KdfParams, SymmetricKey,
};
use std::fs;

fn fp(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex(&h.finalize()[..6]).to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let state_dir = args.next().expect("state dir arg");
    let env_name = args.next().expect("passphrase env arg");
    let cand_env = args.next().expect("candidate env arg");
    let passphrase = std::env::var(&env_name).unwrap_or_else(|_| panic!("env {env_name} not set"));
    let candidate = std::env::var(&cand_env).unwrap_or_else(|_| panic!("env {cand_env} not set"));

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
        .expect("token")
        .to_string();
    let server = cfg
        .get("server")
        .and_then(|v| v.as_str())
        .expect("server")
        .to_string();
    let email = cfg
        .get("account")
        .and_then(|v| v.as_str())
        .expect("account")
        .to_string();

    let client =
        Client::new(server.clone(), format!("{server}/api"), uuid_v4()).expect("api client");
    let sync = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(client.sync(&tok))
        .expect("sync");
    let profile_key_es = sync.profile.key.clone();
    println!(
        "sync ok: email={} ciphers={}",
        sync.profile.email,
        sync.ciphers.len()
    );

    // Session user key fingerprint (ground truth from the working session).
    let uk = sess
        .get("user_key_b64")
        .or_else(|| sess.get("userKeyB64"))
        .and_then(|v| v.as_str())
        .expect("user key field");
    let session_user_key =
        SymmetricKey::from_64(&B64.decode(uk).expect("decode")).expect("user key");
    println!(
        "session user_key fp: {}",
        fp(&user_key_bytes(&session_user_key))
    );

    // Candidate master key (pbkdf2 600k per prelogin for this account).
    let kdf = KdfParams::pbkdf2(600_000);
    let mk = derive_master_key(&candidate, &email, &kdf).expect("derive master key");
    println!("candidate master_key fp: {}", fp(&mk.expose_secret_copy()));

    let (enc, mac) = stretch_master_key(&mk).expect("stretch");
    let stretched = SymmetricKey::from_parts(*enc, *mac);
    match EncString::parse(&profile_key_es).and_then(|es| es.decrypt_symmetric(&stretched)) {
        Ok(user_key_raw) => {
            let cand_user_key = SymmetricKey::from_64(&user_key_raw).expect("64B user key");
            println!("profile.key DECRYPTS under candidate master password");
            println!(
                "candidate user_key fp: {}",
                fp(&user_key_bytes(&cand_user_key))
            );
            let match_ =
                fp(&user_key_bytes(&cand_user_key)) == fp(&user_key_bytes(&session_user_key));
            println!("candidate user_key == session user_key: {match_}");
            println!("VERDICT: candidate master password is CORRECT for this account");
        }
        Err(e) => {
            println!("profile.key decrypt FAILS under candidate master password ({e})");
            // Control: the session's own user key must decrypt profile.key.
            match EncString::parse(&profile_key_es)
                .and_then(|es| es.decrypt_symmetric(&session_user_key))
            {
                Ok(_) => {
                    println!("control: profile.key decrypts under session user key (sanity OK)")
                }
                Err(e2) => println!("control ALSO failed ({e2}) — unexpected"),
            }
            println!("VERDICT: candidate master password is WRONG for this account");
        }
    }
}

trait Expose {
    fn expose_secret_copy(&self) -> [u8; 32];
}
impl Expose for zeroize::Zeroizing<[u8; 32]> {
    fn expose_secret_copy(&self) -> [u8; 32] {
        **self
    }
}

fn user_key_bytes(k: &SymmetricKey) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(k.enc_bytes());
    out[32..].copy_from_slice(k.mac_bytes());
    out
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
