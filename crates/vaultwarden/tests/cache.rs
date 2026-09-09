// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Sync-cache seal/open unit tests: roundtrip, tamper, wrong user key,
//! filesystem roundtrip with atomic write, and clear().

use cryptile_vaultwarden::cache::{seal, unseal, CacheData, SyncCache};

fn user_key(seed: u8) -> cryptile_vaultwarden::crypto::SymmetricKey {
    // Deterministic 64B: 32 enc || 32 mac.
    let mut b = [0u8; 64];
    b[..32].fill(seed);
    b[32..].fill(seed.wrapping_add(1));
    cryptile_vaultwarden::crypto::SymmetricKey::from_64(&b).unwrap()
}

fn sample() -> CacheData {
    CacheData {
        v: 1,
        account: Some("svc@x.test".into()),
        collections: vec![cryptile_vaultwarden::cache::CollectionIndexEntry {
            id: "coll-1".into(),
            org_id: "org-1".into(),
            name: "shared".into(),
        }],
        ciphers: vec![cryptile_vaultwarden::cache::CipherIndexEntry {
            id: "cipher-1".into(),
            org_id: Some("org-1".into()),
            name: "Postgres HQ".into(),
            collection_ids: vec!["coll-1".into()],
        }],
        org_keys: vec![cryptile_vaultwarden::cache::OrgKeyEntry {
            org_id: "org-1".into(),
            key_b64: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([7u8; 64])
            },
        }],
    }
}

#[test]
fn seal_open_roundtrip() {
    let k = user_key(1);
    let line = seal(&k, &sample()).unwrap();
    assert!(line.starts_with("crc1."));
    let back = unseal(&k, &line).unwrap();
    assert_eq!(back.account.as_deref(), Some("svc@x.test"));
    assert_eq!(back.ciphers.len(), 1);
    assert_eq!(back.ciphers[0].name, "Postgres HQ");
    assert_eq!(back.collections[0].name, "shared");
    assert!(back.org_key("org-1").is_some());
    assert!(back.org_key("org-nope").is_none());
}

#[test]
fn wrong_user_key_is_cold() {
    let line = seal(&user_key(1), &sample()).unwrap();
    assert!(unseal(&user_key(2), &line).is_none());
}

#[test]
fn bitflip_tamper_is_cold() {
    let k = user_key(1);
    let line = seal(&k, &sample()).unwrap();
    // Flip a char in the ct segment (3rd).
    let parts: Vec<&str> = line.split('.').collect();
    let mut ct = parts[3].to_string();
    let flip = if ct.ends_with('A') { 'B' } else { 'A' };
    ct.replace_range(ct.len() - 1.., &flip.to_string());
    let tampered = format!("{}.{}.{}.{}.{}", parts[0], parts[1], parts[2], ct, parts[4]);
    assert!(unseal(&k, &tampered).is_none());
}

#[test]
fn garbage_line_is_cold() {
    let k = user_key(1);
    assert!(unseal(&k, "").is_none());
    assert!(unseal(&k, "crk1.a.b.c.d").is_none()); // wrong magic
    assert!(unseal(&k, "crc1.notbase64!!").is_none());
}

#[test]
fn fs_roundtrip_and_clear() {
    let dir = std::env::temp_dir().join(format!("cryptile-cache-test-{}", std::process::id()));
    let path = dir.join("cache").join("cipher-index");
    let cache = SyncCache::at(&path);
    let k = user_key(1);
    cache.store(&k, &sample()).unwrap();
    assert!(path.is_file());
    let back = cache.load(&k).unwrap();
    assert_eq!(back.ciphers[0].id, "cipher-1");
    // Foreign key cannot read it.
    assert!(cache.load(&user_key(2)).is_none());
    cache.clear();
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn store_creates_0600_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("cryptile-cache-mode-{}", std::process::id()));
    let path = dir.join("cache").join("cipher-index");
    let cache = SyncCache::at(&path);
    cache.store(&user_key(1), &sample()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let _ = std::fs::remove_dir_all(&dir);
}
