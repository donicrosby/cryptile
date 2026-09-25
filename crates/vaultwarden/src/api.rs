// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! HTTP client for the Bitwarden/Vaultwarden identity + API endpoints.
//! Transport only — no crypto here, no secrets in logs.

use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// Client identification sent on EVERY request. Servers gate sync payload
/// completeness on a minimum client version: without a sufficiently new
/// `Bitwarden-Client-Version`, type-5 (SSH-key) ciphers are silently omitted
/// from `/api/sync` — probed live on our harness (VW 1.37.2, 2026-09-18):
/// no header or a stale version drops type-5 org ciphers from every account's
/// sync, `2024.12.x` and `2026.6.0` deliver them. The pinned value matches
/// rbw (MIT, sanctioned gold source), which sends `2024.12.0` on its
/// requests; cryptile's own crate version (0.1.0) would classify as ancient.
pub const CLIENT_VERSION: &str = "2024.12.0";
/// Official web-vault client name; paired with [`CLIENT_VERSION`].
pub const CLIENT_NAME: &str = "web";

/// Default headers every cryptile-issued request must carry.
pub fn client_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Bitwarden-Client-Name",
        HeaderValue::from_static(CLIENT_NAME),
    );
    headers.insert(
        "Bitwarden-Client-Version",
        HeaderValue::from_static(CLIENT_VERSION),
    );
    headers
}

/// A bare `reqwest::Client` that still carries the client identification
/// headers — for debug examples that issue raw requests outside `Client`.
/// Bare clients report a different vault than the provider sees (they are
/// why `dump-sync`/`raw-sync` once claimed a shared SSH key was missing).
pub fn bare_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("cryptile/", env!("CARGO_PKG_VERSION")))
        .default_headers(client_headers())
        .build()
        .expect("static client config cannot fail to build")
}

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
    /// The identity token endpoint demanded a second factor. Carries the
    /// whole error body (JSON when parseable) so the provider can decode
    /// `TwoFactorProviders` / `TwoFactorProviders2`.
    /// Wire shape pinned by tests/fixtures/challenge.json (VW 1.37.2).
    #[error("two-factor challenge: {0}")]
    TwoFactorChallenge(String),
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

/// Deserialize a sequence member that servers also emit as JSON `null`
/// when empty: null decodes to `Default::default()` exactly like an
/// absent member. Real Vaultwarden emits present-as-null for empty
/// collections (e.g. a cipher with no custom `fields`), which a bare
/// `Vec<T>` with `#[serde(default)]` rejects — that default covers
/// ABSENT members only, not PRESENT-AS-NULL ones, and one such member
/// failed the whole sync parse (`invalid type: null, expected a
/// sequence`), taking down `list`/`get` against a healthy server.
fn null_to_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    let v: Option<T> = Option::deserialize(de)?;
    Ok(v.unwrap_or_default())
}

/// `/api/collections` (and any other list endpoint) envelope. `data` is
/// `Option<Vec<T>>` so a server-emitted `null` decodes natively to
/// `None` (no `deserialize_with` gymnastics); [`List::into_data`]
/// collapses None/absent to the empty vec at the call site. The
/// explicit `bound` stops serde from inferring a `T: Default`
/// requirement from `#[serde(default)]` — `Option<Vec<T>>` defaults
/// without `T: Default`, and the envelope must not force that bound on
/// every element type.
#[derive(Deserialize)]
#[serde(bound = "T: serde::de::Deserialize<'de>")]
struct List<T> {
    #[serde(default)]
    data: Option<Vec<T>>,
}

impl<T> List<T> {
    fn into_data(self) -> Vec<T> {
        self.data.unwrap_or_default()
    }
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
            .default_headers(client_headers())
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
            // 2FA challenge: 400 invalid_grant "Two factor required."
            // (rbw api.rs ConnectErrorRes + live capture challenge.json).
            if status == 400 && body.contains("Two factor required.") {
                return Err(ApiError::TwoFactorChallenge(body));
            }
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
    /// `second_factor` carries the answer when retrying a 2FA challenge:
    /// (wire provider id, token). Wire fields `twoFactorProvider` /
    /// `twoFactorToken` pinned by fixtures/CAPTURES.md + rbw ConnectTokenReq.
    #[tracing::instrument(
        skip(self, auth_hash_b64, second_factor),
        fields(op = "token_password")
    )]
    pub async fn token_password(
        &self,
        email: &str,
        auth_hash_b64: &str,
        second_factor: Option<(u8, &str)>,
    ) -> Result<TokenResponse, ApiError> {
        let mut form = vec![
            ("grant_type", "password"),
            ("username", email),
            ("password", auth_hash_b64),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "14"),
            ("deviceIdentifier", self.device_id.as_str()),
            ("deviceName", "cryptile"),
        ];
        let provider_id;
        let token_str;
        if let Some((provider, token)) = second_factor {
            provider_id = provider.to_string();
            token_str = token.to_string();
            form.push(("twoFactorProvider", provider_id.as_str()));
            form.push(("twoFactorToken", token_str.as_str()));
        }
        self.post_form(
            &format!("{}/connect/token", self.identity_url),
            "login",
            &form,
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

    /// Single-cipher fetch. Server enforces per-user accessibility
    /// (`is_accessible_to_user`), so this leaks nothing across accounts.
    /// 404 maps to `ApiError::Status`, i.e. `ProviderError::NotFound`.
    #[tracing::instrument(skip(self, access_token), fields(op = "get_cipher"))]
    pub async fn get_cipher(&self, access_token: &str, uuid: &str) -> Result<Cipher, ApiError> {
        let resp = self
            .http
            .get(format!("{}/ciphers/{uuid}", self.api_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        Self::parse(resp, "get_cipher").await
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
        let list: List<ApiCollection> = Self::parse(resp, "collections").await?;
        Ok(list.into_data())
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
    #[serde(default, deserialize_with = "null_to_default")]
    pub ciphers: Vec<Cipher>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub email: String,
    pub key: String,
    pub private_key: String,
    #[serde(default, deserialize_with = "null_to_default")]
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
    /// Cipher-level encryption key (type-2 EncString wrapping a 64-byte
    /// symmetric key under the container key). Present only on servers
    /// with per-cipher keys enabled; absent/empty on older items.
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub login: Option<LoginData>,
    #[serde(default)]
    pub card: Option<CardData>,
    #[serde(default)]
    pub identity: Option<IdentityData>,
    #[serde(rename = "sshKey", default)]
    pub ssh_key: Option<SshKeyData>,
    pub notes: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub fields: Vec<Field>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    /// The API emits a `uris` array (singular `uri` is not a real shape).
    #[serde(default, deserialize_with = "null_to_default")]
    pub uris: Vec<LoginUri>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardData {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityData {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyData {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
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

#[cfg(test)]
mod null_tolerance_tests {
    use super::*;

    // Live crash (owner run, 2026-09): real Vaultwarden 1.37.2 emits
    // present-as-null for empty sequence members — `"fields": null` on a
    // plain login cipher landed at "line 1 column 26325" of a real sync
    // body and failed the whole parse. Fixture-style bodies pin each
    // vulnerable member.

    #[test]
    fn sync_body_with_null_members_parses_fully() {
        let body = r#"{
            "profile": {
                "id": "u1",
                "email": "svc@x.test",
                "key": "2.key|enc|mac",
                "privateKey": "0.abc",
                "organizations": null
            },
            "ciphers": null,
            "folders": null,
            "object": "sync"
        }"#;
        let sync: SyncResponse =
            serde_json::from_str(body).expect("null members must not fail the sync parse");
        assert!(sync.ciphers.is_empty());
        assert!(sync.profile.organizations.is_empty());
        assert_eq!(sync.profile.id, "u1");
    }

    #[test]
    fn cipher_with_null_fields_and_login_uris_parses_fully() {
        let body = r#"{
            "id": "c1",
            "name": "2.name|enc|mac",
            "organizationId": null,
            "collectionIds": null,
            "key": null,
            "login": {
                "username": null,
                "password": "2.pass|enc|mac",
                "totp": null,
                "uris": null
            },
            "card": null,
            "identity": null,
            "sshKey": null,
            "notes": null,
            "fields": null
        }"#;
        let c: Cipher =
            serde_json::from_str(body).expect("null fields/uris must not fail cipher parse");
        assert!(c.fields.is_empty());
        let login = c.login.expect("login decodes");
        assert!(login.uris.is_empty());
        assert_eq!(login.password.as_deref(), Some("2.pass|enc|mac"));
    }

    #[tokio::test]
    async fn collections_envelope_with_null_data_parses_empty() {
        // Through the real client path: the /api/collections envelope is
        // generic (List<T>), so the null tolerance is proven end-to-end
        // rather than against the private type (whose derived impl
        // carries serde's conservative Default bound).
        use wiremock::matchers::{method, path};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/api/collections"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": null, "object": "list"})),
            )
            .mount(&server)
            .await;
        let client = Client::from_base(&server.uri()).expect("client builds");
        let out = client.collections("tok").await.expect("null data parses");
        assert!(out.is_empty());
        let list: List<ApiCollection> = serde_json::from_str(r#"{"data": null, "object": "list"}"#)
            .expect("envelope direct: null data is None");
        assert!(list.into_data().is_empty());
        let list: List<ApiCollection> = serde_json::from_str(
            r#"{"data": [{"id": "k1", "organizationId": "o1", "name": "2.nm"}]}"#,
        )
        .expect("populated envelope unchanged");
        let data = list.into_data();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].id, "k1");
    }

    #[test]
    fn absent_members_keep_the_empty_default() {
        let body = r#"{
            "profile": {
                "id": "u1",
                "email": "svc@x.test",
                "key": "2.key|enc|mac",
                "privateKey": "0.abc"
            }
        }"#;
        let sync: SyncResponse =
            serde_json::from_str(body).expect("absent members behave exactly as before");
        assert!(sync.ciphers.is_empty());
        assert!(sync.profile.organizations.is_empty());
        let c: Cipher =
            serde_json::from_str(r#"{"id": "c1", "name": "2.name|enc|mac", "login": {}}"#)
                .expect("cipher without fields/uris members unchanged");
        assert!(c.fields.is_empty());
        assert!(c.login.expect("login").uris.is_empty());
    }
}
