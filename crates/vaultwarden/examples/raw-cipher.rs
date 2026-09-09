// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Debug example: fetch one cipher's raw JSON (direct GET + sync copy),
//! and dissect its EncStrings: MAC-check decrypt vs MAC-bypass CBC decrypt
//! under user key and org key. Tells "wrong enc key" (garbage plaintext)
//! apart from "enc key right, MAC path differs" (readable plaintext).
//! Prints the NAME plaintext only; notes as len+hash. Never prints keys.
//!
//! Usage: cargo run -p cryptile-vaultwarden --example raw-cipher -- \
//!   <state_dir> <passphrase_env> <cipher_uuid>

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use cryptile_core::SecretString;
use cryptile_vaultwarden::api::Client;
use cryptile_vaultwarden::crypto::{unwrap_org_key, EncString, SymmetricKey};
use std::fs;

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn sha12(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex(&h.finalize()[..6])
}

/// Split a type-2 EncString into (iv, ct, mac) raw bytes.
type Split2 = (Vec<u8>, Vec<u8>, Vec<u8>);

fn split2(es: &str) -> Result<Split2, String> {
    let parts: Vec<&str> = es.split('|').collect();
    if parts.len() != 3 || !parts[0].starts_with("2.") {
        return Err(format!("not a 3-seg type-2 string (segs={})", parts.len()));
    }
    let iv = B64
        .decode(parts[0].trim_start_matches("2."))
        .map_err(|e| e.to_string())?;
    let ct = B64.decode(parts[1]).map_err(|e| e.to_string())?;
    let mac = B64.decode(parts[2]).map_err(|e| e.to_string())?;
    Ok((iv, ct, mac))
}

fn cbc_dec(enc: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    use aes::Aes256;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
    type D = cbc::Decryptor<Aes256>;
    let mut buf = ct.to_vec();
    let pt = D::new_from_slices(enc, iv)
        .map_err(|e| e.to_string())?
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|e| format!("pad fail: {e}"))?
        .to_vec();
    Ok(pt)
}

fn mac_of(mac_key: &[u8], iv: &[u8], ct: &[u8]) -> [u8; 32] {
    use hmac::{KeyInit, Mac, SimpleHmac};
    use sha2::Sha256;
    let mut m = SimpleHmac::<Sha256>::new_from_slice(mac_key).unwrap();
    m.update(iv);
    m.update(ct);
    m.finalize().into_bytes().into()
}

fn show(label: &str, es: &str, enc: &[u8], mac_k: &[u8], secret: bool) {
    let (iv, ct, want_mac) = match split2(es) {
        Ok(v) => v,
        Err(e) => {
            println!("  {label}: {e}");
            return;
        }
    };
    let calc = mac_of(mac_k, &iv, &ct);
    let mac_ok = calc.as_slice() == want_mac.as_slice();
    println!(
        "  {label}: segs ok | ct_len={} | stored_mac={}.. calc_mac={}.. | MAC {}",
        ct.len(),
        hex(&want_mac[..4]),
        hex(&calc[..4]),
        if mac_ok { "MATCH" } else { "MISMATCH" }
    );
    match cbc_dec(enc, &iv, &ct) {
        Ok(pt) => {
            let printable = pt.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b));
            if printable {
                if secret {
                    println!(
                        "    bypass-CBC plaintext: PRINTABLE, {} bytes, sha12={}",
                        pt.len(),
                        sha12(&pt)
                    );
                } else {
                    println!(
                        "    bypass-CBC plaintext: PRINTABLE -> {:?}",
                        String::from_utf8_lossy(&pt)
                    );
                }
            } else {
                println!(
                    "    bypass-CBC plaintext: NON-PRINTABLE ({} bytes, head={}) — wrong enc key",
                    pt.len(),
                    hex(&pt[..8.min(pt.len())])
                );
            }
        }
        Err(e) => println!("    bypass-CBC: {e} — wrong enc key (padding broke)"),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let state_dir = args.next().expect("state dir");
    let env_name = args.next().expect("passphrase env");
    let cipher_id = args.next().expect("cipher uuid");

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
        .expect("token")
        .to_string();
    let server = cfg
        .get("server")
        .and_then(|v| v.as_str())
        .expect("server")
        .to_string();
    let uk = sess
        .get("user_key_b64")
        .or_else(|| sess.get("userKeyB64"))
        .and_then(|v| v.as_str())
        .expect("user key field");
    let user_key = SymmetricKey::from_64(&B64.decode(uk).expect("decode")).expect("user key");

    let client =
        Client::new(server.clone(), format!("{server}/api"), uuid_v4()).expect("api client");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let cipher = rt
        .block_on(client.get_cipher(&tok, &cipher_id))
        .expect("direct cipher fetch");
    let sync = rt.block_on(client.sync(&tok)).expect("sync");

    // Raw JSON of the same cipher: fields the typed struct drops.
    {
        let http = reqwest::Client::new();
        let resp = rt
            .block_on(
                http.get(format!("{server}/api/ciphers/{cipher_id}"))
                    .header("Authorization", format!("Bearer {tok}"))
                    .send(),
            )
            .expect("raw fetch");
        let raw: serde_json::Value = rt
            .block_on(resp.json::<serde_json::Value>())
            .expect("raw parse");
        println!(
            "raw cipher JSON keys: {:?}",
            raw.as_object().map(|m| m.keys().collect::<Vec<_>>())
        );
        let mut redacted = raw.clone();
        for k in [
            "name", "notes", "key", "fields", "login", "identity", "card", "sshKey",
        ] {
            if redacted.get(k).is_some() {
                let s = redacted[k].to_string();
                redacted[k] = serde_json::json!(format!("<{} chars>", s.len()));
            }
        }
        println!(
            "raw (values elided): {}",
            serde_json::to_string_pretty(&redacted).unwrap_or_default()
        );
        if raw.get("key").map(|v| !v.is_null()).unwrap_or(false) {
            let s = raw["key"].as_str().unwrap_or("");
            println!(
                "cipher-level key field present: {} chars, starts {:?}",
                s.len(),
                s.get(..8.min(s.len()))
            );
        } else {
            println!("cipher-level key field: ABSENT");
        }
        println!("revisionDate: {:?}", raw.get("revisionDate"));
        println!("createdAt: {:?}", raw.get("createdAt"));
        println!("userId: {:?}", raw.get("userId"));
        println!("type: {:?}", raw.get("type"));
    }

    println!(
        "direct GET ok: id={} org={:?}",
        cipher.id, cipher.organization_id
    );
    let sync_copy = sync.ciphers.iter().find(|c| c.id == cipher.id);
    println!("sync copy present: {}", sync_copy.is_some());
    if let Some(sc) = sync_copy {
        println!("direct name == sync name: {}", sc.name == cipher.name);
        println!("direct notes == sync notes: {}", sc.notes == cipher.notes);
        println!(
            "direct collection_ids == sync: {:?}",
            sc.collection_ids == cipher.collection_ids
        );
    }

    // private key -> org key (unwrap_org_key takes the PKCS8 DER itself)
    let priv_der = EncString::parse(&sync.profile.private_key)
        .and_then(|es| es.decrypt_symmetric(&user_key))
        .expect("profile private key");
    let mut org_key: Option<SymmetricKey> = None;
    for org in &sync.profile.organizations {
        if org.key.is_empty() {
            continue;
        }
        let es = EncString::parse(&org.key).expect("org key parse");
        let k = unwrap_org_key(&es, &priv_der).expect("org key unwrap");
        println!("org {} key unwrap OK", org.id);
        org_key = Some(k);
    }
    let ok = org_key.expect("org key");

    println!("\n== dissection under ORG key ==");
    show("name", &cipher.name, ok.enc_bytes(), ok.mac_bytes(), false);
    if let Some(n) = &cipher.notes {
        if !n.is_empty() {
            show("notes", n, ok.enc_bytes(), ok.mac_bytes(), true);
        }
    }
    println!("\n== dissection under USER key ==");
    show(
        "name",
        &cipher.name,
        user_key.enc_bytes(),
        user_key.mac_bytes(),
        false,
    );

    // Per-cipher key: raw JSON "key" field, wrapped under the container key.
    {
        let http = reqwest::Client::new();
        let resp = rt
            .block_on(
                http.get(format!("{server}/api/ciphers/{cipher_id}"))
                    .header("Authorization", format!("Bearer {tok}"))
                    .send(),
            )
            .expect("raw fetch 2");
        let raw: serde_json::Value = rt
            .block_on(resp.json::<serde_json::Value>())
            .expect("raw parse 2");
        if let Some(k) = raw.get("key").and_then(|v| v.as_str()) {
            if !k.is_empty() {
                println!("\n== per-cipher key unwrap ==");
                for (label, container) in [("org", &ok), ("user", &user_key)] {
                    match EncString::parse(k).and_then(|es| es.decrypt_symmetric(container)) {
                        Ok(raw_key) => match SymmetricKey::from_64(&raw_key) {
                            Ok(ck) => {
                                println!("cipher.key unwraps under {label} key: OK");
                                show("name", &cipher.name, ck.enc_bytes(), ck.mac_bytes(), false);
                                if let Some(n) = &cipher.notes {
                                    if !n.is_empty() {
                                        show("notes", n, ck.enc_bytes(), ck.mac_bytes(), true);
                                    }
                                }
                            }
                            Err(e) => println!("unwrapped but not 64B under {label}: {e}"),
                        },
                        Err(e) => println!("cipher.key FAIL under {label} key ({e})"),
                    }
                }
            }
        }
    }

    println!("\n== control: collection names under ORG key ==");
    let colls = rt.block_on(client.collections(&tok)).expect("collections");
    for c in &colls {
        show(
            &format!("coll {}", &c.id[..8]),
            &c.name,
            ok.enc_bytes(),
            ok.mac_bytes(),
            false,
        );
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
