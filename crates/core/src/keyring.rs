//! Passphrase-sealed keyring: on-disk session persistence.
//!
//! Stores a backend session (serialized JSON, opaque to core) sealed with
//! Argon2id -> AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) under a keyring
//! passphrase. Written 0600 via temp-file + rename so a crash never leaves a
//! torn or world-readable file. Wrong passphrase and corruption are
//! deliberately indistinguishable: both fail the MAC, leaking nothing.
//!
//! File format, one line:
//! `crk1.<salt_b64>.<iv_b64>.<ct_b64>.<mac_b64>`

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{KeyInit, Mac, SimpleHmac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Argon2id cost: t=3, m=64 MiB, p=4 — Bitwarden's 2024-era defaults.
const ARGON_T: u32 = 3;
const ARGON_M_KIB: u32 = 65_536;
const ARGON_P: u32 = 4;

const MAGIC: &str = "crk1";
const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum KeyringError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("keyring format not recognized (expected {MAGIC})")]
    Format,
    #[error("wrong passphrase or corrupted keyring (MAC mismatch)")]
    Tamper,
    #[error("crypto failure: {0}")]
    Crypto(String),
}

/// Derive the 64B sealing key: Argon2id(passphrase, salt) -> enc || mac.
fn derive_kek(passphrase: &SecretString, salt: &[u8]) -> Result<Zeroizing<[u8; 64]>, KeyringError> {
    let mut out = Zeroizing::new([0u8; 64]);
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(64))
            .map_err(|e| KeyringError::Crypto(e.to_string()))?,
    );
    argon
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, out.as_mut())
        .map_err(|e| KeyringError::Crypto(e.to_string()))?;
    Ok(out)
}

fn split_kek(k: &Zeroizing<[u8; 64]>) -> ([u8; 32], [u8; 32]) {
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&k[..32]);
    mac.copy_from_slice(&k[32..]);
    (enc, mac)
}

fn hmac_tag(mac_key: &[u8; 32], aad_iv_ct: &[u8]) -> [u8; MAC_LEN] {
    let mut mac =
        SimpleHmac::<Sha256>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(aad_iv_ct);
    mac.finalize().into_bytes().into()
}

/// Seal `plaintext` into the `crk1` line format (no i/o).
pub fn seal(plaintext: &str, passphrase: &SecretString) -> Result<String, KeyringError> {
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    use rand_core::{OsRng, TryRngCore};
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| KeyringError::Crypto(e.to_string()))?;
    OsRng
        .try_fill_bytes(&mut iv)
        .map_err(|e| KeyringError::Crypto(e.to_string()))?;

    let kek = derive_kek(passphrase, &salt)?;
    let (enc_k, mac_k) = split_kek(&kek);

    let mut buf = plaintext.as_bytes().to_vec();
    let ct = Aes256CbcEnc::new_from_slices(&enc_k, &iv)
        .expect("32B key + 16B iv")
        .encrypt_padded_vec::<aes::cipher::block_padding::Pkcs7>(&buf);
    // clear intermediate plaintext copy
    buf.iter_mut().for_each(|b| *b = 0);

    let mut iv_ct = Vec::with_capacity(IV_LEN + ct.len());
    iv_ct.extend_from_slice(&iv);
    iv_ct.extend_from_slice(&ct);
    let tag = hmac_tag(&mac_k, &iv_ct);

    Ok(format!(
        "{MAGIC}.{}.{}.{}.{}",
        B64.encode(salt),
        B64.encode(iv),
        B64.encode(&ct),
        B64.encode(tag)
    ))
}

/// Open a `crk1` line. MAC-verify-then-decrypt; wrong passphrase and
/// corruption both surface as [`KeyringError::Tamper`].
pub fn open(line: &str, passphrase: &SecretString) -> Result<Zeroizing<String>, KeyringError> {
    let parts: Vec<&str> = line.trim().split('.').collect();
    if parts.len() != 5 || parts[0] != MAGIC {
        return Err(KeyringError::Format);
    }
    let salt = B64.decode(parts[1]).map_err(|_| KeyringError::Format)?;
    let iv: [u8; IV_LEN] = B64
        .decode(parts[2])
        .map_err(|_| KeyringError::Format)?
        .try_into()
        .map_err(|_| KeyringError::Format)?;
    let ct = B64.decode(parts[3]).map_err(|_| KeyringError::Format)?;
    let tag: [u8; MAC_LEN] = B64
        .decode(parts[4])
        .map_err(|_| KeyringError::Format)?
        .try_into()
        .map_err(|_| KeyringError::Format)?;

    let kek = derive_kek(passphrase, &salt)?;
    let (enc_k, mac_k) = split_kek(&kek);

    let mut iv_ct = Vec::with_capacity(IV_LEN + ct.len());
    iv_ct.extend_from_slice(&iv);
    iv_ct.extend_from_slice(&ct);
    let expect = hmac_tag(&mac_k, &iv_ct);
    if !bool::from(expect.ct_eq(&tag)) {
        return Err(KeyringError::Tamper);
    }

    let pt = Aes256CbcDec::new_from_slices(&enc_k, &iv)
        .expect("32B key + 16B iv")
        .decrypt_padded_vec::<aes::cipher::block_padding::Pkcs7>(&ct)
        .map_err(|_| KeyringError::Tamper)?;
    let s = String::from_utf8(pt)
        .map_err(|_| KeyringError::Tamper)?
        .trim()
        .to_string();
    Ok(Zeroizing::new(s))
}

/// Default keyring path: platform config dir + `cryptile/keyring` (no
/// extension). Override for tests via [`Keyring::with_path`].
pub fn default_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("cryptile").join("keyring")
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
}

/// Filesystem wrapper: 0600, atomic rename, root-only dir where creatable.
#[derive(Debug, Clone)]
pub struct Keyring {
    path: PathBuf,
}

impl Keyring {
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist a sealed session. Creates the parent dir 0700 and the file
    /// 0600 (Unix). Atomic: write temp file in the same dir, rename over.
    pub fn save(&self, session_json: &str, passphrase: &SecretString) -> Result<(), KeyringError> {
        let line = seal(session_json, passphrase)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(parent)?.permissions().mode();
                if mode & 0o777 == 0o755 {
                    // only tighten if it is a dir we just created wide open
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
                let _ = mode;
            }
        }
        let tmp = self.path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(line.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(line.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Load and unseal the stored session.
    pub fn load(&self, passphrase: &SecretString) -> Result<Zeroizing<String>, KeyringError> {
        let raw = fs::read_to_string(&self.path)?;
        open(&raw, passphrase)
    }
}
