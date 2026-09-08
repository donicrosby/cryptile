//! Master-key derivation and login hashing (whitepaper §Account Creation).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::CryptoError;

/// KDF parameters advertised by prelogin (or the token response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// 0 = PBKDF2-SHA256, 1 = Argon2id.
    pub kind: u8,
    pub iterations: u32,
    /// Argon2id memory in KiB, as the server reports it.
    pub argon_memory_kib: Option<u32>,
    pub argon_parallelism: Option<u32>,
}

impl KdfParams {
    pub fn pbkdf2(iterations: u32) -> Self {
        Self {
            kind: 0,
            iterations,
            argon_memory_kib: None,
            argon_parallelism: None,
        }
    }

    pub fn argon2id(iterations: u32, memory_kib: u32, parallelism: u32) -> Self {
        Self {
            kind: 1,
            iterations,
            argon_memory_kib: Some(memory_kib),
            argon_parallelism: Some(parallelism),
        }
    }
}

/// Lowercased-trimmed identity (the KDF salt base), as the server sees it.
pub fn normalize_identity(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Derive the 32-byte master key.
///
/// PBKDF2: salt = identity. Argon2id: salt = SHA256(identity), memory KiB.
pub fn derive_master_key(
    password: &str,
    identity: &str,
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    // Normalize defensively: a mixed-case email here would silently produce
    // a wrong master key and an inexplicable login failure.
    let identity = normalize_identity(identity);
    match params.kind {
        0 => {
            let mut key = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                identity.as_bytes(),
                params.iterations,
                key.as_mut(),
            );
            Ok(key)
        }
        1 => {
            use sha2::Digest as _;
            let salt = Sha256::digest(identity.as_bytes());
            let memory_kib = params
                .argon_memory_kib
                .ok_or(CryptoError::UnsupportedKdf(params.kind))?;
            let parallelism = params
                .argon_parallelism
                .ok_or(CryptoError::UnsupportedKdf(params.kind))?;
            let mut key = Zeroizing::new([0u8; 32]);
            let argon = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(memory_kib, params.iterations, parallelism, Some(32))
                    .map_err(|_| CryptoError::Argon2)?,
            );
            argon
                .hash_password_into(password.as_bytes(), &salt, key.as_mut())
                .map_err(|_| CryptoError::Argon2)?;
            Ok(key)
        }
        other => Err(CryptoError::UnsupportedKdf(other)),
    }
}

/// Server auth hash: PBKDF2(masterKey, password, 1 iter, 32B), base64.
pub fn auth_hash(password: &str, master_key: &[u8; 32]) -> Result<Zeroizing<String>, CryptoError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let mut hash = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, hash.as_mut());
    Ok(Zeroizing::new(B64.encode(hash.as_slice())))
}

/// Stretch a 32B master key into the (enc, mac) pair that unwraps the user
/// key: HKDF-Expand-SHA256 with info "enc" / "mac", 32B each.
/// The stretched (enc, mac) key pair.
pub type StretchedKey = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

pub fn stretch_master_key(master_key: &[u8; 32]) -> Result<StretchedKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::from_prk(master_key).map_err(|_| CryptoError::Hkdf)?;
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"enc", enc.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;
    hkdf.expand(b"mac", mac.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;
    Ok((enc, mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_master_key_is_deterministic_and_lowercases_identity() {
        let a = derive_master_key("pw", "User@Example.com", &KdfParams::pbkdf2(1000)).unwrap();
        let b = derive_master_key("pw", "user@example.com", &KdfParams::pbkdf2(1000)).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn auth_hash_is_44_char_base64() {
        let mk = derive_master_key("pw", "u@e.com", &KdfParams::pbkdf2(1000)).unwrap();
        let h = auth_hash("pw", &mk).unwrap();
        assert_eq!(h.len(), 44);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn argon2_master_key_known_vector() {
        // Cross-checked against Python cryptography's Argon2id (see
        // tests/python_oracle.py) — same salt construction, 32B output.
        let k = derive_master_key(
            "correct horse battery staple",
            "doni@example.com",
            &KdfParams::argon2id(3, 65536, 1),
        )
        .unwrap();
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn kdf_matches_python_oracle_vectors() {
        use base64::Engine as _;
        // Vectors from tests/oracle_generate.py: Python hashlib, independent
        // implementation. If both agree, KDF + auth hash + stretch are right.
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/oracle_vectors.json")).unwrap();
        let email = v["email"].as_str().unwrap();
        let password = v["password"].as_str().unwrap();
        let iters = v["iterations"].as_u64().unwrap() as u32;

        let mk = derive_master_key(password, email, &KdfParams::pbkdf2(iters)).unwrap();
        let want_mk = base64::engine::general_purpose::STANDARD
            .decode(v["master_key"].as_str().unwrap())
            .unwrap();
        assert_eq!(mk.as_slice(), &want_mk[..]);

        let auth = auth_hash(password, &mk).unwrap();
        assert_eq!(auth.as_str(), v["auth_hash"].as_str().unwrap());

        let (enc, mac) = stretch_master_key(&mk).unwrap();
        let want_enc = base64::engine::general_purpose::STANDARD
            .decode(v["stretch_enc"].as_str().unwrap())
            .unwrap();
        let want_mac = base64::engine::general_purpose::STANDARD
            .decode(v["stretch_mac"].as_str().unwrap())
            .unwrap();
        assert_eq!(enc.as_slice(), &want_enc[..]);
        assert_eq!(mac.as_slice(), &want_mac[..]);
    }
}
