//! cryptile-vaultwarden — the first Provider backend for cryptile.
//!
//! Implements the Bitwarden client protocol against Vaultwarden servers:
//! password-grant auth, zero-knowledge key hierarchy, and sync mapping into
//! cryptile-core's domain model. Clean-room from the public Security
//! Whitepaper and cross-verified against independent MIT clients (rbw,
//! goldwarden); no Bitwarden/Vaultwarden code used or read for
//! implementation.

pub mod api;
pub mod crypto;
pub mod mapping;
pub mod provider;

pub use provider::VaultwardenProvider;
