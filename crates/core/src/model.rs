// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Resource model every backend maps into.
//!
//! Backends are field-bag shaped (Bitwarden items, 1Password items, Vault KV
//! documents), so a [`Secret`] is a bag of named fields plus metadata, and refs
//! select one field via `#field`.

use std::collections::BTreeMap;

use crate::value::SecretString;

/// A container of secrets (Bitwarden collection, 1Password vault, Vault mount).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    /// Opaque backend id, server-internal. Not used in refs.
    pub id: String,
    /// Human name; the first path segment of a ref locus addresses this.
    pub name: String,
}

/// Metadata for one secret item, no values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    /// Opaque backend id.
    pub id: String,
    /// Human name; second segment of a ref locus.
    pub name: String,
    /// Owning namespace id.
    pub namespace_id: String,
    /// Field names present, sorted. Lets `list` show shape without values.
    pub fields: Vec<String>,
}

/// A resolved secret item with its field values.
#[derive(Debug, Clone)]
pub struct Secret {
    pub meta: SecretMeta,
    /// Field name -> value. BTreeMap so iteration order is deterministic.
    pub fields: BTreeMap<String, SecretString>,
}

impl Secret {
    /// Look up one field by the selector from a ref.
    pub fn field(&self, name: &str) -> Option<&SecretString> {
        self.fields.get(name)
    }

    /// The value a fragment-less ref resolves to: first present non-empty
    /// field along [`PRIMARY_FIELD_CHAIN`]. Providers map every item type
    /// into the bag, so the bag's shape stands in for the item type —
    /// password for logins, notes for secure notes, private_key for SSH
    /// keys, number for cards.
    pub fn primary_value(&self) -> Option<&SecretString> {
        use crate::ExposeSecret;
        PRIMARY_FIELD_CHAIN
            .iter()
            .filter_map(|f| self.fields.get(*f))
            .find(|v| !v.expose_secret().is_empty())
    }
}

/// Fallback order for fragment-less refs. Fixed, shared by every backend;
/// the field bag is the type.
pub const PRIMARY_FIELD_CHAIN: &[&str] = &["password", "notes", "private_key", "number"];

/// An authenticated backend session. Backends keep their own token state; the
/// core type is just the capability marker passed between Provider calls.
#[derive(Debug, Clone)]
pub struct Session {
    /// Backend id this session belongs to.
    pub provider: String,
    /// Opaque backend handle (serialized token bundle reference, etc.).
    pub handle: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExposeSecret;

    #[test]
    fn secret_debug_output_contains_no_values() {
        let sec = Secret {
            meta: SecretMeta {
                id: "1".into(),
                name: "smtp".into(),
                namespace_id: "10".into(),
                fields: vec!["password".into(), "username".into()],
            },
            fields: BTreeMap::from([
                ("password".into(), SecretString::from("hunter2")),
                ("username".into(), SecretString::from("doni")),
            ]),
        };
        let dbg = format!("{sec:?}");
        assert!(!dbg.contains("hunter2") && !dbg.contains("doni"));
        assert_eq!(sec.field("password").unwrap().expose_secret(), "hunter2");
        assert!(sec.field("totp").is_none());
        // Login shape: password wins the chain.
        assert_eq!(sec.primary_value().unwrap().expose_secret(), "hunter2");
    }

    fn bag(fields: &[(&str, &str)]) -> Secret {
        Secret {
            meta: SecretMeta {
                id: "1".into(),
                name: "item".into(),
                namespace_id: "10".into(),
                fields: fields.iter().map(|(k, _)| k.to_string()).collect(),
            },
            fields: BTreeMap::from_iter(
                fields
                    .iter()
                    .map(|(k, v)| (k.to_string(), SecretString::from(*v))),
            ),
        }
    }

    #[test]
    fn primary_value_chain_order() {
        // Secure note shape: no password, notes wins.
        let note = bag(&[("notes", "the payload")]);
        assert_eq!(note.primary_value().unwrap().expose_secret(), "the payload");
        // SSH key shape: private_key.
        let key = bag(&[("private_key", "-----BEGIN-----")]);
        assert_eq!(
            key.primary_value().unwrap().expose_secret(),
            "-----BEGIN-----"
        );
        // Card shape: number.
        let card = bag(&[("number", "4024007138346631"), ("code", "417")]);
        assert_eq!(
            card.primary_value().unwrap().expose_secret(),
            "4024007138346631"
        );
        // Password outranks notes when both exist (login with notes).
        let both = bag(&[("password", "pw"), ("notes", "note text")]);
        assert_eq!(both.primary_value().unwrap().expose_secret(), "pw");
        // Nothing in the chain.
        let none = bag(&[("uri", "https://x"), ("username", "u")]);
        assert!(none.primary_value().is_none());
    }

    #[test]
    fn primary_value_skips_empty_fields() {
        let sec = bag(&[("password", ""), ("notes", "real value")]);
        assert_eq!(sec.primary_value().unwrap().expose_secret(), "real value");
    }
}
