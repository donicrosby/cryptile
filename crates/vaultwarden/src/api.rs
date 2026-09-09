// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! HTTP client for the Bitwarden/Vaultwarden identity + API endpoints.
//! Transport only — no crypto here, no secrets in logs.

use serde::Deserialize;
use thiserror::Error;

/// Transport-layer failures mapped from reqwest.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("server returned {status} for {op}: {detail}")]
    Status {
        op: &'static str,
        status: u16,
        detail: String,
    },
    #[error("malformed response: {0}")]
    Malformed(String),
}

impl ApiError {
    /// True when a retry after re-auth would plausibly help.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Status { status: 401, .. })
    }
}

/// Prelogin response: kept as raw JSON — VW and upstream disagree on exact
/// field casing; parsed defensively at the call site.
#[derive(Debug, Deserialize)]
pub struct PreloginResponse(pub serde_json::Value);

/// Parsed KDF parameters (the crypto module's type, built from either the
/// prelogin or token response shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKdf {
    /// 0 = PBKDF2, 1 = Argon2id.
    pub kind: u8,
    pub iterations: u32,
    pub memory_kib: Option<u32>,
    pub parallelism: Option<u32>,
}

/// OAuth token response from `/identity/connect/token`.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
    #[serde(default, alias = "Key")]
    pub key: String,
    #[serde(default, alias = "Kdf")]
    pub kdf: Option<u8>,
    #[serde(default, alias = "KdfIterations")]
    pub kdf_iterations: Option<u32>,
    #[serde(default, alias = "KdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(default, alias = "KdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

fn default_expires_in() -> u64 {
    3600
}

/// The identity + API surface, parameterized by base URLs.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    pub identity_url: String,
    pub api_url: String,
    device_id: String,
}

impl Client {
    pub fn new(identity_url: String, api_url: String, device_id: String) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("cryptile/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            identity_url,
            api_url,
            device_id,
        })
    }

    pub fn from_base(base: &str) -> Result<Self, ApiError> {
        let base = base.trim_end_matches('/');
        Self::new(
            format!("{base}/identity"),
            format!("{base}/api"),
            new_device_id(),
        )
    }

    async fn post_form<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        op: &'static str,
        form: &[(&str, &str)],
    ) -> Result<T, ApiError> {
        let resp = self
            .http
            .post(url)
            .header("Bitwarden-Client-Name", "web")
            .header(
                "Bitwarden-Client-Version",
                option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.0"),
            )
            .form(form)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        Self::parse(resp, op).await
    }

    async fn parse<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
        op: &'static str,
    ) -> Result<T, ApiError> {
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(ApiError::Status {
                op,
                status,
                detail: sanitize(&body),
            });
        }
        serde_json::from_str(&body).map_err(|e| ApiError::Malformed(e.to_string()))
    }

    /// Prelogin: fetch per-account KDF parameters. JSON body: both VW and
    /// upstream expect `{"email": ...}`; VW's Rocket rejects form-encoded
    /// prelogin with a bare 400.
    #[tracing::instrument(skip(self), fields(op = "prelogin"))]
    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, ApiError> {
        let resp = self
            .http
            .post(format!("{}/accounts/prelogin", self.identity_url))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        Self::parse(resp, "prelogin").await
    }

    /// Password grant. `auth_hash_b64` is the base64 auth hash, never plaintext.
    #[tracing::instrument(skip(self, auth_hash_b64), fields(op = "token_password"))]
    pub async fn token_password(
        &self,
        email: &str,
        auth_hash_b64: &str,
    ) -> Result<TokenResponse, ApiError> {
        self.post_form(
            &format!("{}/connect/token", self.identity_url),
            "login",
            &[
                ("grant_type", "password"),
                ("username", email),
                ("password", auth_hash_b64),
                ("scope", "api offline_access"),
                ("client_id", "web"),
                ("deviceType", "14"),
                ("deviceIdentifier", &self.device_id),
                ("deviceName", "cryptile"),
            ],
        )
        .await
    }

    /// Refresh-token grant.
    #[tracing::instrument(skip(self, refresh_token), fields(op = "token_refresh"))]
    pub async fn token_refresh(&self, refresh_token: &str) -> Result<TokenResponse, ApiError> {
        self.post_form(
            &format!("{}/connect/token", self.identity_url),
            "refresh",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", "web"),
            ],
        )
        .await
    }

    /// Full sync: profile (keys, orgs) + ciphers.
    #[tracing::instrument(skip(self, access_token), fields(op = "sync"))]
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse, ApiError> {
        let resp = self
            .http
            .get(format!("{}/sync", self.api_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        Self::parse(resp, "sync").await
    }

    /// User-visible collections (Namespace mapping).
    #[tracing::instrument(skip(self, access_token), fields(op = "collections"))]
    pub async fn collections(&self, access_token: &str) -> Result<Vec<ApiCollection>, ApiError> {
        let resp = self
            .http
            .get(format!("{}/collections", self.api_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        #[derive(Deserialize)]
        struct List<T> {
            data: Vec<T>,
        }
        let List { data } = Self::parse(resp, "collections").await?;
        Ok(data)
    }
}

/// Strip anything resembling credentials from error bodies before they
/// reach logs or Display.
fn sanitize(body: &str) -> String {
    let mut out = String::with_capacity(body.len().min(512));
    for ch in body.chars().take(512) {
        out.push(if ch.is_control() { '?' } else { ch });
    }
    out
}

fn new_device_id() -> String {
    use rand_core::{OsRng, TryRngCore};
    let mut b = [0u8; 16];
    let _ = OsRng.try_fill_bytes(&mut b);
    uuid_v4(&b)
}

fn uuid_v4(b: &[u8; 16]) -> String {
    let mut x = *b;
    x[6] = (x[6] & 0x0f) | 0x40;
    x[8] = (x[8] & 0x3f) | 0x80;
    let hex = |s: &[u8]| -> String { s.iter().map(|c| format!("{c:02x}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&x[0..4]),
        hex(&x[4..6]),
        hex(&x[6..8]),
        hex(&x[8..10]),
        hex(&x[10..16])
    )
}

/// Sync payload subset cryptile consumes.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub email: String,
    pub key: String,
    pub private_key: String,
    #[serde(default)]
    pub organizations: Vec<Org>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Org {
    pub id: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub collection_ids: Option<Vec<String>>,
    pub login: Option<LoginData>,
    pub notes: Option<String>,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub name: Option<String>,
    pub value: Option<String>,
}

/// `/api/collections` entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiCollection {
    pub id: String,
    pub organization_id: String,
    pub name: String,
}
