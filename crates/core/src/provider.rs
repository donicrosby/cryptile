// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
use crate::model::{Namespace, Secret, SecretMeta};
use crate::SecretString;
use thiserror::Error;

/// Errors every backend maps its failures into. The CLI derives exit codes
/// and remediation hints from these kinds.
#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("authorization failed (scope/collection access): {0}")]
    Forbidden(String),
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("network/transport error: {0}")]
    Transport(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("bad reference: {0}")]
    BadRef(String),
    #[error("crypto failure: {0}")]
    Crypto(String),
    #[error("no session; run `cryptile login`")]
    NoSession,
    #[error("session expired; re-login required")]
    AuthExpired,
    /// The login path was challenged for a second factor. `providers`
    /// carries backend-agnostic tags (`totp`, `email`, `webauthn`,
    /// `unknown(n)`); the CLI resolves one and calls `login` again with
    /// `LoginParams::second_factor` set.
    #[error("two-factor required; providers offered: {}", providers.join(", "))]
    TwoFactorRequired { providers: Vec<String> },
}

/// A second-factor answer for [`Provider::login`]. Backend-agnostic:
/// `provider_tag` is `totp` / `email` / `webauthn`; the VW backend maps
/// tags to its wire-level provider ids.
#[derive(Debug, Clone)]
pub struct SecondFactor {
    pub provider_tag: String,
    pub code: SecretString,
}

/// Parameters for [`Provider::login`]. Backend-agnostic fields only; VW
/// specifics (server URL) live in the backend's constructor.
pub struct LoginParams {
    pub account: String,
    pub secret: SecretString,
    /// Second-factor answer, present only on the challenge retry call.
    /// `None` = plain password grant.
    pub second_factor: Option<SecondFactor>,
    /// Lazy PIN source for hardware-key user verification (clientPIN
    /// acquisition in the CTAP2 ceremony). Invoked at most once per
    /// ceremony, ONLY when verification demands a PIN; `None` means
    /// acquisition fails typed instead of prompting (headless-safe).
    /// Return the PIN bytes; `Err(())` surfaces as a provider-I/O
    /// failure, never as a wrong-PIN authentication outcome.
    pub pin_source: Option<PinSource>,
}

/// A caller-supplied PIN prompt, kept backend-neutral by design: the
/// CLI never names the hardware library, the library never does I/O.
pub type PinSource = Box<dyn FnMut() -> Result<Vec<u8>, ()> + Send>;

/// The backend facade: one trait, every secret backend the same shape.
/// Object-safe so the CLI holds `Box<dyn Provider>` and dispatches on the
/// ref scheme. Async because every real backend is network I/O.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// Backend id; must match a ref scheme (`"vw"`).
    fn id(&self) -> &'static str;

    async fn login(&self, params: LoginParams) -> Result<Session, ProviderError>;

    /// Can this build answer a hardware (provider-7 CTAP2) two-factor
    /// offer? Backend knowledge by design: whether a CTAP2 ceremony
    /// backend is compiled in (and which) is the provider's business —
    /// the CLI asks instead of naming backend feature matrices. Returns
    /// `false` for code-carrying factors (totp/email); the resolver
    /// owns those. Default `false`: backends without a ceremony path
    /// keep the skip-and-remediate behavior.
    fn answers_two_factor(&self, provider_tag: &str) -> bool {
        let _ = provider_tag;
        false
    }

    /// Rotate the session's access token using its refresh token. The new
    /// session replaces the old; `AuthExpired` means no refresh token (or it
    /// was rejected) — the caller must re-login with the master secret.
    async fn refresh_session(&self, s: &Session) -> Result<Session, ProviderError>;

    /// Unix-seconds expiry of the session's access token, if the backend
    /// tracks one. `None` (the default) means unknown: callers fall back to
    /// reactive refresh on auth failure.
    fn session_expiry(&self, s: &Session) -> Option<u64> {
        let _ = s;
        None
    }

    async fn list_namespaces(&self, s: &Session) -> Result<Vec<Namespace>, ProviderError>;
    async fn list_secrets(
        &self,
        s: &Session,
        ns: &Namespace,
    ) -> Result<Vec<SecretMeta>, ProviderError>;

    /// Full values for every item in a namespace (export path). Backends
    /// SHOULD implement this as one round trip, not N `get_secret` calls.
    async fn get_namespace_secrets(
        &self,
        s: &Session,
        ns: &Namespace,
    ) -> Result<Vec<Secret>, ProviderError>;
    async fn get_secret(&self, s: &Session, r: &Ref) -> Result<Secret, ProviderError>;
}

pub use crate::model::Session;
pub use crate::Ref;

/// Convenience: the field names a decrypted login-type cipher exposes.
pub fn login_field_names() -> Vec<String> {
    vec![
        "password".into(),
        "username".into(),
        "totp".into(),
        "uri".into(),
        "notes".into(),
    ]
}
