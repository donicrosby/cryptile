// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Cipher → cryptile-core Secret mapping, and collection-name resolution.

use cryptile_core::model::Secret;
use cryptile_core::SecretString;
use std::collections::BTreeMap;

use crate::api::Cipher;
use crate::crypto::{EncString, SymmetricKey};

/// Decrypt one EncString field to plaintext (empty string stays empty).
fn dec(enc: &str, key: &SymmetricKey) -> Result<String, crate::crypto::CryptoError> {
    if enc.is_empty() {
        return Ok(String::new());
    }
    let es = EncString::parse(enc)?;
    let pt = es.decrypt_symmetric(key)?;
    Ok(String::from_utf8_lossy(&pt).into_owned())
}

fn dec_value(enc: &str, key: &SymmetricKey) -> Result<SecretString, crate::crypto::CryptoError> {
    Ok(SecretString::new(dec(enc, key)?.into()))
}

/// Map an API cipher into a Secret field-bag. Fails if the name field is
/// undecryptable (wrong key); individual field failures are skipped.
pub fn map_cipher(
    cipher: &Cipher,
    key: &SymmetricKey,
) -> Result<Secret, crate::crypto::CryptoError> {
    let name = dec(&cipher.name, key)?;
    let mut fields: BTreeMap<String, SecretString> = BTreeMap::new();
    if let Some(login) = &cipher.login {
        for (k, v) in [
            ("username", &login.username),
            ("password", &login.password),
            ("totp", &login.totp),
            ("uri", &login.uri),
        ] {
            if let Some(enc) = v {
                if !enc.is_empty() {
                    fields.insert(k.into(), dec_value(enc, key)?);
                }
            }
        }
    }
    if let Some(n) = &cipher.notes {
        if !n.is_empty() {
            fields.insert("notes".into(), dec_value(n, key)?);
        }
    }
    for f in &cipher.fields {
        let (Some(n), Some(v)) = (&f.name, &f.value) else {
            continue;
        };
        if n.is_empty() || v.is_empty() {
            continue;
        }
        let fname = dec(n, key)?;
        if fname.is_empty() {
            continue;
        }
        fields.insert(fname, dec_value(v, key)?);
    }
    Ok(Secret {
        meta: cryptile_core::SecretMeta {
            id: cipher.id.clone(),
            name,
            namespace_id: cipher.organization_id.clone().unwrap_or_default(),
            fields: fields.keys().cloned().collect(),
        },
        fields,
    })
}

/// Resolve the collection segment of a ref locus to a collection id.
/// Returns None for the personal vault (id "").
/// Accepts the collection NAME (case-insensitive) or a raw UUID.
pub fn resolve_collection(coll: &str, collections: &[(String, String, String)]) -> Option<String> {
    if coll.eq_ignore_ascii_case("personal") {
        return Some(String::new());
    }
    collections
        .iter()
        .find(|(id, _, name)| name.eq_ignore_ascii_case(coll) || id.eq_ignore_ascii_case(coll))
        .map(|(id, _, _)| id.clone())
}
