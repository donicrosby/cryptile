//! Secret-carrying values with enforced redaction — delegated to `secrecy`.
//!
//! [`secrecy::SecretString`] (backed by its `zeroize` dependency) provides:
//! - `Debug` that prints `[REDACTED]`
//! - zeroization on drop: plaintext is wiped from the heap when the value
//!   leaves scope, which a plain `String` wrapper cannot guarantee
//!
//! This module adds only the re-export, the redaction policy type, and the
//! output-boundary rule: raw values leave the process exclusively via
//! `expose_secret()` at the CLI stdout writer — never during logging or
//! intermediate formatting.

pub use secrecy::{ExposeSecret, SecretString};

/// Placeholder secrecy's `Debug` impl prints for secret values.
pub const REDACTED: &str = "[REDACTED]";

/// Whether raw value output is allowed. Derived once at startup from
/// `--no-redact AND stdin.isatty() AND stdout.isatty()` and threaded through
/// explicitly — never read from ambient state at print time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redaction {
    pub allow_raw_output: bool,
}

impl Redaction {
    /// Default posture: redacted everywhere.
    pub fn strict() -> Self {
        Self {
            allow_raw_output: false,
        }
    }
}

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
