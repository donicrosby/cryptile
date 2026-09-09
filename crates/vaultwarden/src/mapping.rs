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

/// Insert k→v unless the encrypted string is absent/empty.
fn insert_if(
    fields: &mut BTreeMap<String, SecretString>,
    key: &str,
    enc: &Option<String>,
    key_mat: &SymmetricKey,
) -> Result<(), crate::crypto::CryptoError> {
    if let Some(e) = enc {
        if !e.is_empty() {
            fields.insert(key.into(), dec_value(e, key_mat)?);
        }
    }
    Ok(())
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
        ] {
            insert_if(&mut fields, k, v, key)?;
        }
        let uris: Vec<&str> = login
            .uris
            .iter()
            .filter_map(|u| u.uri.as_deref())
            .filter(|u| !u.is_empty())
            .collect();
        if let Some(first) = uris.first() {
            fields.insert("uri".into(), dec_value(first, key)?);
        }
        if uris.len() > 1 {
            let joined = uris
                .iter()
                .map(|u| dec(u, key))
                .collect::<Result<Vec<_>, _>>()?
                .join("\n");
            fields.insert("uris".into(), SecretString::new(joined.into()));
        }
    }
    if let Some(card) = &cipher.card {
        for (k, v) in [
            ("cardholder_name", &card.cardholder_name),
            ("brand", &card.brand),
            ("number", &card.number),
            ("exp_month", &card.exp_month),
            ("exp_year", &card.exp_year),
            ("code", &card.code),
        ] {
            insert_if(&mut fields, k, v, key)?;
        }
    }
    if let Some(id) = &cipher.identity {
        for (k, v) in [
            ("title", &id.title),
            ("first_name", &id.first_name),
            ("middle_name", &id.middle_name),
            ("last_name", &id.last_name),
            ("address1", &id.address1),
            ("address2", &id.address2),
            ("address3", &id.address3),
            ("city", &id.city),
            ("state", &id.state),
            ("postal_code", &id.postal_code),
            ("country", &id.country),
            ("company", &id.company),
            ("email", &id.email),
            ("phone", &id.phone),
            ("ssn", &id.ssn),
            ("username", &id.username),
            ("passport_number", &id.passport_number),
            ("license_number", &id.license_number),
        ] {
            insert_if(&mut fields, k, v, key)?;
        }
    }
    if let Some(ssh) = &cipher.ssh_key {
        for (k, v) in [
            ("private_key", &ssh.private_key),
            ("public_key", &ssh.public_key),
            ("key_fingerprint", &ssh.key_fingerprint),
        ] {
            insert_if(&mut fields, k, v, key)?;
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
