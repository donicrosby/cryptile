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
}

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
    }
}
