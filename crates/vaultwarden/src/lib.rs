// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! cryptile-vaultwarden — the first Provider backend for cryptile.
//!
//! Implements the Bitwarden client protocol against Vaultwarden servers:
//! password-grant auth, zero-knowledge key hierarchy, and sync mapping into
//! cryptile-core's domain model. Clean-room from the public Security
//! Whitepaper and cross-verified against independent MIT clients (rbw,
//! goldwarden); no Bitwarden/Vaultwarden code used or read for
//! implementation.

pub mod api;
pub mod cache;
pub mod crypto;
pub mod mapping;
pub mod provider;
// Gate widened by add-fidoh-ceremony-provider: the webauthn module now holds
// the shared provider-7 decode/origin/wire-assembly plus both ceremony
// backends (legacy `webauthn`, fidoh `fidoh`), so it exists under either
// feature.
#[cfg(any(feature = "webauthn", feature = "fidoh"))]
pub mod webauthn;

pub use provider::VaultwardenProvider;
