// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Vaultwarden/Bitwarden zero-knowledge crypto.
//!
//! Implemented from the public Bitwarden Security Whitepaper, cross-verified
//! against independent MIT-licensed clients (rbw, goldwarden). No Bitwarden,
//! bitwarden_license, bitwarden-sdk, or Vaultwarden code is used or read for
//! implementation — protocol facts only.
//!
//! Key hierarchy:
//!
//! ```text
//! master password ──(KDF: PBKDF2-SHA256 | Argon2id)──▶ 32B master key
//! master key ──(HKDF-Expand-SHA256 "enc"/"mac")──▶ stretched (64B)
//! stretched key ──(EncString 2)──▶ user symmetric key (64B)
//! user key ──(EncString 2)──▶ RSA private key (PKCS8 DER)
//! user private key ──(RSA-OAEP-SHA1, EncString 4)──▶ org key (64B)
//! org key or user key ──(EncString 2)──▶ cipher fields
//! ```
//!
//! All key material lives in [`Zeroizing`] buffers.

mod encstring;
mod kdf;

pub use encstring::{unwrap_org_key, EncString, EncStringType};
pub use kdf::{auth_hash, derive_master_key, normalize_identity, stretch_master_key, KdfParams};

use zeroize::Zeroizing;

/// Errors from the crypto layer. Coarse by design: never carries key
/// material or plaintext, and parse failures don't reveal where the input
/// went wrong (no padding-oracle-style detail).
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported KDF type {0}")]
    UnsupportedKdf(u8),
    #[error("unsupported EncString type {0}")]
    UnsupportedEncString(u8),
    #[error("malformed EncString")]
    MalformedEncString,
    #[error("message authentication failed")]
    MacMismatch,
    #[error("invalid padding")]
    BadPadding,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("asymmetric decrypt failed")]
    AsymmetricDecrypt,
    #[error("private key not valid PKCS8")]
    InvalidPrivateKey,
    #[error("argon2 failure")]
    Argon2,
    #[error("pbkdf2 failure")]
    Pbkdf2,
    #[error("hkdf failure")]
    Hkdf,
    #[error("os randomness unavailable")]
    OsRng,
}

/// A 64-byte symmetric key: 32B enc ‖ 32B mac. Zeroized on drop.
#[derive(Clone)]
pub struct SymmetricKey {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl SymmetricKey {
    pub fn from_parts(enc: [u8; 32], mac: [u8; 32]) -> Self {
        Self {
            enc: Zeroizing::new(enc),
            mac: Zeroizing::new(mac),
        }
    }

    /// Split a 64B blob into enc‖mac halves.
    pub fn from_64(blob: &[u8]) -> Result<Self, CryptoError> {
        if blob.len() != 64 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&blob[..32]);
        mac.copy_from_slice(&blob[32..]);
        Ok(Self::from_parts(enc, mac))
    }

    /// Random fresh key (used for the local keyring's wrapping key).
    pub fn random() -> Result<Self, CryptoError> {
        use rand_core::{OsRng, TryRngCore};
        let mut raw = Zeroizing::new([0u8; 64]);
        OsRng
            .try_fill_bytes(raw.as_mut())
            .map_err(|_| CryptoError::OsRng)?;
        Self::from_64(raw.as_ref())
    }

    pub fn enc_bytes(&self) -> &[u8; 32] {
        &self.enc
    }

    pub fn mac_bytes(&self) -> &[u8; 32] {
        &self.mac
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymmetricKey([REDACTED])")
    }
}
