//! Normalized secret reference: `scheme://locus[#field]`.
//!
//! The single addressing currency across CLI args, config files, and the Hermes
//! secret-source integration. Examples:
//!
//! - `vw://hermes-shared/smtp#password`
//! - `op://Private/github` (field defaults to `password`)
//! - `vault://kv/prod/db#username`

use std::fmt;

/// Error kinds for ref parsing. Cheap, no strings attached to secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseRefError {
    MissingScheme,
    UnsupportedScheme(String),
    EmptyLocus,
    EmptyField,
}

impl fmt::Display for ParseRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseRefError::MissingScheme => write!(f, "ref must start with scheme://"),
            ParseRefError::UnsupportedScheme(s) => {
                write!(f, "unsupported scheme {s:?} (known: vw, op, vault)")
            }
            ParseRefError::EmptyLocus => write!(f, "ref locus must not be empty"),
            ParseRefError::EmptyField => write!(f, "ref field fragment must not be empty"),
        }
    }
}

impl std::error::Error for ParseRefError {}

/// Schemes cryptile knows about. The registry maps these to Provider impls; the
/// list grows as backends land. Parsing accepts exactly these, lowercase.
pub const KNOWN_SCHEMES: &[&str] = &["vw", "op", "vault"];

/// A parsed cross-backend reference.
///
/// Field selectors are case-sensitive as given; loci are used verbatim — backends
/// define their own locus grammar and matching rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ref {
    /// Backend id, e.g. `vw`. Always lowercase.
    pub scheme: String,
    /// Backend-defined path, e.g. `hermes-shared/smtp`.
    pub locus: String,
    /// Field selector; defaults to `password`.
    pub field: String,
}

impl Ref {
    /// The field used when a ref carries no fragment.
    pub const DEFAULT_FIELD: &'static str = "password";

    /// Parse `scheme://locus[#field]` against the known scheme list.
    pub fn parse(s: &str) -> Result<Self, ParseRefError> {
        let (scheme_part, rest) = s.split_once("://").ok_or(ParseRefError::MissingScheme)?;
        let scheme = scheme_part.to_ascii_lowercase();
        if !KNOWN_SCHEMES.contains(&scheme.as_str()) {
            return Err(ParseRefError::UnsupportedScheme(scheme_part.to_string()));
        }
        let (locus, field) = match rest.split_once('#') {
            Some((l, f)) => (l, f),
            None => (rest, Self::DEFAULT_FIELD),
        };
        if locus.is_empty() {
            return Err(ParseRefError::EmptyLocus);
        }
        if field.is_empty() {
            return Err(ParseRefError::EmptyField);
        }
        Ok(Self {
            scheme,
            locus: locus.to_string(),
            field: field.to_string(),
        })
    }
}

impl fmt::Display for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}#{}", self.scheme, self.locus, self.field)
    }
}

impl std::str::FromStr for Ref {
    type Err = ParseRefError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_form() {
        let r = Ref::parse("vw://hermes-shared/smtp#password").unwrap();
        assert_eq!(r.scheme, "vw");
        assert_eq!(r.locus, "hermes-shared/smtp");
        assert_eq!(r.field, "password");
        assert_eq!(r.to_string(), "vw://hermes-shared/smtp#password");
    }

    #[test]
    fn defaults_field_to_password() {
        let r = Ref::parse("op://Private/github").unwrap();
        assert_eq!(r.field, Ref::DEFAULT_FIELD);
        // Round-trips with the explicit fragment.
        let explicit = Ref::parse(&r.to_string()).unwrap();
        assert_eq!(explicit, r);
    }

    #[test]
    fn accepts_all_known_schemes() {
        for s in KNOWN_SCHEMES {
            assert!(
                Ref::parse(&format!("{s}://a/b")).is_ok(),
                "scheme {s} rejected"
            );
        }
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(
            Ref::parse("hermes-shared/smtp"),
            Err(ParseRefError::MissingScheme)
        );
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(matches!(
            Ref::parse("kp://vault/file"),
            Err(ParseRefError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn rejects_empty_locus_and_field() {
        assert_eq!(Ref::parse("vw://"), Err(ParseRefError::EmptyLocus));
        assert_eq!(Ref::parse("vw://a#"), Err(ParseRefError::EmptyField));
    }
}
