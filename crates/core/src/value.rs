// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Secret-carrying values with enforced redaction — delegated to `secrecy`.
//!
//! [`secrecy::SecretString`] (backed by its `zeroize` dependency) provides:
//! - `Debug` that prints `[REDACTED]`
//! - zeroization on drop: plaintext is wiped from the heap when the value
//!   leaves scope, which a plain `String` wrapper cannot guarantee
//!
//! This module adds only the re-export and the output-boundary rule: raw
//! values leave the process exclusively via `expose_secret()` at the CLI
//! stdout writer — never during logging or intermediate formatting. There
//! is no opt-out flag and no runtime policy object; the guarantee is
//! structural (no `Display` impl, explicit expose call required).

pub use secrecy::{ExposeSecret, SecretString};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_debug_redacts() {
        let v = SecretString::from("hunter2");
        assert_eq!(format!("{v:?}"), "SecretBox<str>([REDACTED])");
        assert!(!format!("{v:?}").contains("hunter2"));
    }

    #[test]
    fn expose_returns_raw() {
        let v = SecretString::from("hunter2");
        assert_eq!(v.expose_secret(), "hunter2");
    }
}
