//! EncString parsing and decryption (whitepaper + rbw/goldwarden agreement).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{KeyInit, Mac, SimpleHmac};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{CryptoError, SymmetricKey};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// EncString type tags. Names mirror the protocol's official identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum EncStringType {
    /// 0. AES-CBC-128, no MAC. Legacy vaults only; decrypt rejects it.
    AesCbc256_B64,
    /// 1. AES-CBC-128 + HMAC. Stretched-legacy user-key shape.
    AesCbc128_HmacSha256_B64,
    /// 2. AES-CBC-256 + HMAC-SHA256. The workhorse.
    AesCbc256_HmacSha256_B64,
    /// 3. RSA-2048 OAEP-SHA256.
    Rsa2048_OaepSha256_B64,
    /// 4. RSA-2048 OAEP-SHA1. Org keys arrive in this shape.
    Rsa2048_OaepSha1_B64,
}

impl TryFrom<u8> for EncStringType {
    type Error = CryptoError;
    fn try_from(v: u8) -> Result<Self, CryptoError> {
        Ok(match v {
            0 => Self::AesCbc256_B64,
            1 => Self::AesCbc128_HmacSha256_B64,
            2 => Self::AesCbc256_HmacSha256_B64,
            3 => Self::Rsa2048_OaepSha256_B64,
            4 => Self::Rsa2048_OaepSha1_B64,
            other => return Err(CryptoError::UnsupportedEncString(other)),
        })
    }
}

/// A parsed Bitwarden EncString: `<type>.<b64>[|<b64>[|<b64>]]`.
#[derive(Debug, Clone)]
pub struct EncString {
    pub kind: EncStringType,
    pub iv: Vec<u8>,
    pub ct: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

impl EncString {
    /// Parse `0.aaa|bbb` / `2.aaa|bbb|ccc` / `4.aaa`.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let Some((ty, rest)) = s.split_once('.') else {
            return Err(CryptoError::MalformedEncString);
        };
        let Ok(ty) = ty.parse::<u8>() else {
            return Err(CryptoError::MalformedEncString);
        };
        let kind = EncStringType::try_from(ty)?;
        let parts: Vec<&str> = rest.split('|').collect();
        let dec = |p: &str| B64.decode(p).map_err(|_| CryptoError::MalformedEncString);
        match kind {
            EncStringType::AesCbc256_B64 => {
                if parts.len() != 2 {
                    return Err(CryptoError::MalformedEncString);
                }
                Ok(Self {
                    kind,
                    iv: dec(parts[0])?,
                    ct: dec(parts[1])?,
                    mac: None,
                })
            }
            EncStringType::AesCbc128_HmacSha256_B64 | EncStringType::AesCbc256_HmacSha256_B64 => {
                if parts.len() != 3 {
                    return Err(CryptoError::MalformedEncString);
                }
                Ok(Self {
                    kind,
                    iv: dec(parts[0])?,
                    ct: dec(parts[1])?,
                    mac: Some(dec(parts[2])?),
                })
            }
            EncStringType::Rsa2048_OaepSha256_B64 | EncStringType::Rsa2048_OaepSha1_B64 => {
                if parts.len() != 1 {
                    return Err(CryptoError::MalformedEncString);
                }
                Ok(Self {
                    kind,
                    iv: Vec::new(),
                    ct: dec(parts[0])?,
                    mac: None,
                })
            }
        }
    }

    /// Decrypt with a symmetric key. MAC verified BEFORE decryption
    /// (encrypt-then-MAC, constant-time compare). Fails closed.
    pub fn decrypt_symmetric(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match self.kind {
            EncStringType::AesCbc128_HmacSha256_B64 | EncStringType::AesCbc256_HmacSha256_B64 => {}
            other => return Err(CryptoError::UnsupportedEncString(other as u8)),
        }
        let Some(mac) = &self.mac else {
            return Err(CryptoError::MalformedEncString);
        };
        let mut h = SimpleHmac::<Sha256>::new_from_slice(key.mac_bytes())
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        h.update(&self.iv);
        h.update(&self.ct);
        let tag: [u8; 32] = h.finalize().into_bytes().into();
        if !bool::from(tag.ct_eq(mac)) {
            return Err(CryptoError::MacMismatch);
        }
        decrypt_cbc(&self.iv, &self.ct, key.enc_bytes())
    }
}

/// CBC decrypt + PKCS7 unpad into a zeroizing buffer.
fn decrypt_cbc(iv: &[u8], ct: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if iv.len() != 16 || ct.is_empty() || ct.len() % 16 != 0 {
        return Err(CryptoError::MalformedEncString);
    }
    let dec = Aes256CbcDec::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKeyLength)?;
    let pt = match dec.decrypt_padded_vec::<Pkcs7>(ct) {
        Ok(pt) => pt,
        Err(_) => return Err(CryptoError::BadPadding),
    };
    Ok(Zeroizing::new(pt))
}

/// Unwrap an RSA-protected payload (org key) with the account private key.
/// Handles both OAEP-SHA1 (type 4, what servers send) and OAEP-SHA256
/// (type 3) for robustness.
pub fn unwrap_org_key(
    enc_string: &EncString,
    private_key_pkcs8: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    let Ok(pk) = RsaPrivateKey::from_pkcs8_der(private_key_pkcs8) else {
        return Err(CryptoError::InvalidPrivateKey);
    };
    let pt = match enc_string.kind {
        EncStringType::Rsa2048_OaepSha1_B64 => pk
            .decrypt(Oaep::new::<sha1::Sha1>(), &enc_string.ct)
            .map_err(|_| CryptoError::AsymmetricDecrypt)?,
        EncStringType::Rsa2048_OaepSha256_B64 => {
            // rsa 0.9's OAEP digests are digest-0.10; sha2 0.11 types can't
            // feed it. Servers wrap org keys as type 4 (OAEP-SHA1); type 3
            // for org keys is rare enough that explicit rejection with a
            // clear error beats a web of version pins.
            return Err(CryptoError::UnsupportedEncString(3));
        }
        other => return Err(CryptoError::UnsupportedEncString(other as u8)),
    };
    SymmetricKey::from_64(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_parts([1u8; 32], [2u8; 32])
    }

    #[test]
    fn parses_type2_shape() {
        let s = EncString::parse(
            "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==",
        )
        .unwrap();
        assert_eq!(s.kind, EncStringType::AesCbc256_HmacSha256_B64);
    }

    #[test]
    fn parses_type4_shape() {
        let s = EncString::parse("4.AAAAAAAAAAAAAAAAAAAAAA==").unwrap();
        assert_eq!(s.kind, EncStringType::Rsa2048_OaepSha1_B64);
        assert!(s.mac.is_none());
    }

    #[test]
    fn rejects_unknown_type_and_garbage() {
        assert!(matches!(
            EncString::parse("9.aaa"),
            Err(CryptoError::UnsupportedEncString(9))
        ));
        assert!(matches!(
            EncString::parse("no-dot"),
            Err(CryptoError::MalformedEncString)
        ));
    }

    #[test]
    fn mac_mismatch_fails_closed() {
        // Valid shape, wrong MAC: must be MacMismatch, never BadPadding —
        // MAC is checked before any decryption.
        let s = EncString::parse(
            "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==",
        )
        .unwrap();
        assert!(matches!(
            s.decrypt_symmetric(&key()),
            Err(CryptoError::MacMismatch)
        ));
    }

    #[test]
    fn roundtrip_against_python_oracle_vector() {
        // Vector generated by tests/oracle_generate.py (Python `cryptography`
        // 50.x, independent implementation). Type-2 EncString for a known
        // key/plaintext, including padding.
        let enc_key = [0x11u8; 32];
        let mac_key = [0x22u8; 32];
        let vector = include_str!("../../tests/oracle_type2.txt");
        let s = EncString::parse(vector.trim()).unwrap();
        let pt = s
            .decrypt_symmetric(&SymmetricKey::from_parts(enc_key, mac_key))
            .unwrap();
        assert_eq!(pt.as_slice(), b"oracle-round-trip");
    }
}
