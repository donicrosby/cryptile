// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! cryptile-core — backend-agnostic domain model for cryptile.
//!
//! Three things live here and nothing else:
//! - [`Ref`]: the cross-backend addressing currency (`scheme://locus#field`)
//! - [`SecretString`]: secrecy's redaction + zeroize-on-drop value wrapper
//! - the resource types every backend maps into ([`Secret`], [`SecretMeta`], [`Namespace`])
//!
//! Backends (cryptile-vaultwarden, future cryptile-op, cryptile-vault) depend on this
//! crate and never on each other. The Provider trait lands with the first backend.

pub mod keyring;
pub mod model;
pub mod provider;
pub mod reference;
pub mod value;

pub use keyring::{Keyring, KeyringError};
pub use model::{Namespace, Secret, SecretMeta, Session, PRIMARY_FIELD_CHAIN};
pub use provider::{LoginParams, Provider, ProviderError};
pub use reference::{ParseRefError, Ref};
pub use secrecy::{ExposeSecret, SecretString};
