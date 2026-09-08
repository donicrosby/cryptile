//! Secret-carrying values with enforced redaction.
//!
//! The one rule of cryptile: secret material only ever exists inside a
//! [`SecretValue`]. Its `Debug` and `Display` impls print a placeholder; the real
//! value leaves the process exclusively via [`SecretValue::expose`] at the final
//! output boundary (CLI stdout writer), which is TTY/redaction-policy checked by
//! the caller — never during logging or formatting.

use std::fmt;

/// Redaction placeholder used by Debug/Display.
pub const REDACTED: &str = "<redacted>";

/// A wrapper around secret material that refuses to print itself.
#[derive(Clone)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wrap raw secret material.
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// Raw access. Callers at the output boundary only — this is the single
    /// escape hatch and is intentionally loud in code review.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes. Safe to log; leaky only for lengths, which we accept
    /// for error messages ("value was empty").
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Whether value output is allowed. Derived once at startup from
/// `--no-redact AND stdin.isatty() AND stdout.isatty()` and threaded through
/// explicitly — never read from ambient state at print time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redaction {
    pub allow_raw_output: bool,
}

impl Redaction {
    /// Default posture: redacted everywhere.
    pub const fn strict() -> Self {
        Self {
            allow_raw_output: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_redact() {
        let v = SecretValue::new("hunter2");
        assert_eq!(format!("{v:?}"), REDACTED);
        assert_eq!(format!("{v}"), REDACTED);
    }

    #[test]
    fn expose_returns_raw() {
        let v = SecretValue::new("hunter2");
        assert_eq!(v.expose(), "hunter2");
        assert_eq!(v.len(), 7);
        assert!(!v.is_empty());
    }
}
