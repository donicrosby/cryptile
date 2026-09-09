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
}

/// Parameters for [`Provider::login`]. Backend-agnostic fields only; VW
/// specifics (server URL) live in the backend's constructor.
pub struct LoginParams {
    pub account: String,
    pub secret: SecretString,
}

/// The backend facade: one trait, every secret backend the same shape.
/// Object-safe so the CLI holds `Box<dyn Provider>` and dispatches on the
/// ref scheme. Async because every real backend is network I/O.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// Backend id; must match a ref scheme (`"vw"`).
    fn id(&self) -> &'static str;

    async fn login(&self, params: LoginParams) -> Result<Session, ProviderError>;

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
