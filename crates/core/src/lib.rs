//! cryptile-core — backend-agnostic domain model for cryptile.
//!
//! Three things live here and nothing else:
//! - [`Ref`]: the cross-backend addressing currency (`scheme://locus#field`)
//! - [`SecretValue`]: a redaction-enforcing value wrapper
//! - the resource types every backend maps into ([`Secret`], [`SecretMeta`], [`Namespace`])
//!
//! Backends (cryptile-vaultwarden, future cryptile-op, cryptile-vault) depend on this
//! crate and never on each other. The Provider trait lands with the first backend.

pub mod model;
pub mod reference;
pub mod value;

pub use model::{Namespace, Secret, SecretMeta, Session};
pub use reference::{ParseRefError, Ref};
pub use value::{Redaction, SecretValue};
