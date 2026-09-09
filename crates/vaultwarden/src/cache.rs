// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Sealed sync cache: the vault index (names -> ids, org keys) at rest.
//!
//! Lets `get` resolve refs with one targeted cipher fetch instead of a
//! full-vault sync. Sealed like the keyring (AES-256-CBC + HMAC-SHA256,
//! encrypt-then-MAC) but keyed by HKDF-SHA256 from the account's user
//! key under the label below — the Provider never sees a passphrase.
//! Different account => different user key => MAC fails => cold cache.
//! File format, one line: `crc1.<salt_b64>.<iv_b64>.<ct_b64>.<mac_b64>`.

use std::fs;
use std::path::{Path, PathBuf};

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hkdf::Hkdf;
use hmac::{KeyInit, Mac, SimpleHmac};
use rand_core::{OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::crypto::SymmetricKey;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const MAGIC: &str = "crc1";
const LABEL: &[u8] = b"cryptile-sync-cache-v1";
const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;

/// One collection: id, owning org, decrypted name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionIndexEntry {
    pub id: String,
    pub org_id: String,
    pub name: String,
}

/// One cipher: id, owning org (None = personal), decrypted name, and the
/// collections it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherIndexEntry {
    pub id: String,
    #[serde(default)]
    pub org_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub collection_ids: Vec<String>,
}

/// Org key material, base64(64B). The reason the cache must be sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgKeyEntry {
    pub org_id: String,
    pub key_b64: String,
}

/// Everything the warm path needs; no tokens, no cipher field values.
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheData {
    pub v: u32,
    #[serde(default)]
    pub account: Option<String>,
    pub collections: Vec<CollectionIndexEntry>,
    pub ciphers: Vec<CipherIndexEntry>,
    pub org_keys: Vec<OrgKeyEntry>,
}

impl CacheData {
    /// Adapt to the tuple shape `resolve_collection` consumes.
    pub fn collection_tuples(&self) -> Vec<(String, String, String)> {
        self.collections
            .iter()
            .map(|c| (c.id.clone(), c.org_id.clone(), c.name.clone()))
            .collect()
    }

    /// Look up the org key for an org id.
    pub fn org_key(&self, org_id: &str) -> Option<SymmetricKey> {
        use base64::Engine as _;
        self.org_keys
            .iter()
            .find(|o| o.org_id == org_id)
            .and_then(|o| B64.decode(&o.key_b64).ok())
            .and_then(|b| SymmetricKey::from_64(&b).ok())
    }
}

/// HKDF-SHA256(user key, salt, label) -> 64B, split enc||mac. The user
/// key is full entropy, so no slow KDF is needed here (unlike keyring).
fn derive_keys(user_key: &SymmetricKey, salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(user_key.enc_bytes());
    ikm[32..].copy_from_slice(user_key.mac_bytes());
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 64];
    hk.expand(LABEL, &mut okm).expect("64B okm fits");
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&okm[..32]);
    mac.copy_from_slice(&okm[32..]);
    (enc, mac)
}

fn tag(mac_k: &[u8; 32], aad: &[u8]) -> [u8; MAC_LEN] {
    let mut m = SimpleHmac::<Sha256>::new_from_slice(mac_k).expect("any key len");
    m.update(aad);
    m.finalize().into_bytes().into()
}

/// Seal `data` to the one-line format (no i/o).
pub fn seal(user_key: &SymmetricKey, data: &CacheData) -> Result<String, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    OsRng.try_fill_bytes(&mut salt).map_err(|e| e.to_string())?;
    OsRng.try_fill_bytes(&mut iv).map_err(|e| e.to_string())?;
    let (enc_k, mac_k) = derive_keys(user_key, &salt);
    let pt = serde_json::to_vec(data).map_err(|e| e.to_string())?;
    let ct = Aes256CbcEnc::new_from_slices(&enc_k, &iv)
        .expect("32B key + 16B iv")
        .encrypt_padded_vec::<aes::cipher::block_padding::Pkcs7>(&pt);
    // AAD binds label + salt so a blob cannot be replayed under another
    // derivation; iv+ct are covered as in the keyring.
    let mut aad = Vec::with_capacity(LABEL.len() + SALT_LEN + IV_LEN + ct.len());
    aad.extend_from_slice(LABEL);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&iv);
    aad.extend_from_slice(&ct);
    let t = tag(&mac_k, &aad);
    Ok(format!(
        "{MAGIC}.{}.{}.{}.{}",
        B64.encode(salt),
        B64.encode(iv),
        B64.encode(&ct),
        B64.encode(t)
    ))
}

/// Open + parse a `crc1` line. Any failure (missing fields, MAC mismatch
/// under this user key, bad UTF-8/JSON) is None: a cold cache, never an
/// error surfaced to the user.
pub fn unseal(user_key: &SymmetricKey, line: &str) -> Option<CacheData> {
    let parts: Vec<&str> = line.trim().split('.').collect();
    if parts.len() != 5 || parts[0] != MAGIC {
        return None;
    }
    let salt = B64.decode(parts[1]).ok()?;
    let iv: [u8; IV_LEN] = B64.decode(parts[2]).ok()?.try_into().ok()?;
    let ct = B64.decode(parts[3]).ok()?;
    let t: [u8; MAC_LEN] = B64.decode(parts[4]).ok()?.try_into().ok()?;
    let (enc_k, mac_k) = derive_keys(user_key, &salt);
    let mut aad = Vec::with_capacity(LABEL.len() + salt.len() + IV_LEN + ct.len());
    aad.extend_from_slice(LABEL);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&iv);
    aad.extend_from_slice(&ct);
    let expect = tag(&mac_k, &aad);
    if !bool::from(expect.ct_eq(&t)) {
        return None;
    }
    let pt = Aes256CbcDec::new_from_slices(&enc_k, &iv)
        .ok()?
        .decrypt_padded_vec::<aes::cipher::block_padding::Pkcs7>(&ct)
        .ok()?;
    serde_json::from_slice(&pt).ok()
}

/// Filesystem handle for the cache under `<state>/cache/cipher-index`.
#[derive(Debug, Clone)]
pub struct SyncCache {
    path: PathBuf,
}

impl SyncCache {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load for this user key; None when absent, corrupt, or foreign.
    /// Debug-level span only: cold cache is routine, not a failure.
    pub fn load(&self, user_key: &SymmetricKey) -> Option<CacheData> {
        let raw = fs::read_to_string(&self.path).ok()?;
        let data = unseal(user_key, &raw)?;
        tracing::debug!(
            cache = %self.path.display(),
            ciphers = data.ciphers.len(),
            "sync cache loaded"
        );
        Some(data)
    }

    /// Persist atomically (temp + rename, 0600, dir 0700).
    pub fn store(&self, user_key: &SymmetricKey, data: &CacheData) -> Result<(), String> {
        let line = seal(user_key, data)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let tmp = self.path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| e.to_string())?;
            f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&tmp, line).map_err(|e| e.to_string())?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    /// Best-effort delete (login rotation, --refresh-cache).
    pub fn clear(&self) {
        let _ = fs::remove_file(&self.path);
    }
}
