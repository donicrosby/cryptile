// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! `VaultwardenProvider`: the Provider facade over api + crypto.

use async_trait::async_trait;
use cryptile_core::model::{Namespace, Secret, SecretMeta, Session};
use cryptile_core::provider::{LoginParams, PinSource, Provider, ProviderError};
use cryptile_core::{ExposeSecret, Ref};
use zeroize::Zeroizing;

use crate::api::{ApiError, Client};
use crate::cache::{CacheData, SyncCache};
use crate::crypto::{
    auth_hash, derive_master_key, stretch_master_key, unwrap_org_key, EncString, KdfParams,
    SymmetricKey,
};
use crate::mapping::{map_cipher, resolve_collection};

/// Test seam for the CTAP2 ceremony (tests only — compiled out of release
/// builds). The closure receives the decoded challenge and returns the
/// `twoFactorToken` blob, exactly as the ceremony (legacy or fidoh) would
/// against a hardware key.
#[cfg(all(any(feature = "webauthn", feature = "fidoh"), debug_assertions))]
type AssertionHook = std::sync::Arc<
    dyn Fn(
            &crate::webauthn::WebauthnChallenge,
        ) -> Result<secrecy::SecretString, crate::webauthn::WebauthnError>
        + Send
        + Sync,
>;

/// Persistent provider handle. Cheap to clone; reqwest client is pooled.
#[derive(Clone)]
pub struct VaultwardenProvider {
    client: Client,
    /// Optional sync-cache path. `None` disables the warm path entirely
    /// (library use without a state dir).
    cache_path: Option<std::path::PathBuf>,
    /// When set, this hook produces the `twoFactorToken` blob instead of
    /// touching a hardware key. CI has no USB device; the manual hardware
    /// runbook exercises the real path. Never user-facing.
    #[cfg(all(any(feature = "webauthn", feature = "fidoh"), debug_assertions))]
    assertion_hook: Option<AssertionHook>,
}

#[cfg(not(all(any(feature = "webauthn", feature = "fidoh"), debug_assertions)))]
impl std::fmt::Debug for VaultwardenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultwardenProvider")
            .field("cache_path", &self.cache_path)
            .finish_non_exhaustive()
    }
}

#[cfg(all(any(feature = "webauthn", feature = "fidoh"), debug_assertions))]
impl std::fmt::Debug for VaultwardenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultwardenProvider")
            .field("cache_path", &self.cache_path)
            .field(
                "assertion_hook",
                &self.assertion_hook.as_ref().map(|_| "<hook>"),
            )
            .finish_non_exhaustive()
    }
}

/// The VW session state carried inside `Session.handle` (opaque JSON).
/// Key material is runtime-only; the on-disk keyring (task 3.4) stores it
/// passphrase-encrypted, never plaintext.
#[derive(serde::Serialize, serde::Deserialize)]
struct VwSession {
    access_token: String,
    refresh_token: Option<String>,
    /// 64B user key, base64. Present only while the process runs; the
    /// keyring wraps this whole struct when persisting.
    user_key_b64: String,
    /// Account email (diagnostics + cache scoping). Absent in sessions
    /// sealed before the sync cache existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    /// Access-token expiry, unix seconds. Absent in sessions sealed before
    /// expiry tracking existed; those fall back to reactive 401 refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

/// What `sync_and_keys` produces: the raw sync payload plus the decrypted
/// org keys and plaintext collection names needed for ref resolution.
type SyncBundle = (
    crate::api::SyncResponse,
    Vec<(String, SymmetricKey)>,
    Vec<(String, String, String)>,
);

impl VaultwardenProvider {
    pub fn new(base_url: &str) -> Result<Self, ProviderError> {
        Ok(Self {
            client: Client::from_base(base_url).map_err(map_api)?,
            cache_path: None,
            #[cfg(all(any(feature = "webauthn", feature = "fidoh"), debug_assertions))]
            assertion_hook: None,
        })
    }

    /// Install a ceremony stand-in (tests only — the hook is compiled out
    /// of release builds). The closure receives the decoded challenge and
    /// returns the `twoFactorToken` blob, exactly as the ceremony (legacy
    /// or fidoh) would against a hardware key.
    #[cfg(all(any(feature = "webauthn", feature = "fidoh"), debug_assertions))]
    pub fn with_assertion_hook(
        mut self,
        hook: impl Fn(
                &crate::webauthn::WebauthnChallenge,
            ) -> Result<secrecy::SecretString, crate::webauthn::WebauthnError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.assertion_hook = Some(std::sync::Arc::new(hook));
        self
    }

    /// Enable the sealed sync cache at this path (`<state>/cache/cipher-index`).
    pub fn with_cache_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.cache_path = Some(path.into());
        self
    }

    #[tracing::instrument(
        skip(self, access_token, user_key),
        fields(ciphers = tracing::field::Empty, orgs = tracing::field::Empty, collections = tracing::field::Empty)
    )]
    async fn sync_and_keys(
        &self,
        access_token: &str,
        user_key: &SymmetricKey,
    ) -> Result<SyncBundle, ProviderError> {
        let sync = self.client.sync(access_token).await.map_err(map_api)?;
        let private_key = EncString::parse(&sync.profile.private_key)
            .and_then(|es| es.decrypt_symmetric(user_key))
            .map_err(crypto_err)?;
        let mut org_keys = Vec::new();
        for org in &sync.profile.organizations {
            if org.key.is_empty() {
                continue;
            }
            let es = EncString::parse(&org.key).map_err(crypto_err)?;
            let k = unwrap_org_key(&es, &private_key).map_err(crypto_err)?;
            org_keys.push((org.id.clone(), k));
        }
        // Collections with plaintext names for ref resolution.
        let mut collections = Vec::new();
        for c in self
            .client
            .collections(access_token)
            .await
            .map_err(map_api)?
        {
            let key = org_keys
                .iter()
                .find(|(id, _)| *id == c.organization_id)
                .map(|(_, k)| k);
            if let Some(k) = key {
                if let Ok(name) = decrypt_str(&c.name, k) {
                    collections.push((c.id, c.organization_id, name));
                }
            }
        }
        tracing::Span::current().record("ciphers", tracing::field::display(sync.ciphers.len()));
        tracing::Span::current().record("orgs", tracing::field::display(org_keys.len()));
        tracing::Span::current().record("collections", tracing::field::display(collections.len()));
        Ok((sync, org_keys, collections))
    }
}

fn decrypt_str(enc: &str, key: &SymmetricKey) -> Result<String, crate::crypto::CryptoError> {
    if enc.is_empty() {
        return Ok(String::new());
    }
    let es = EncString::parse(enc)?;
    let pt = es.decrypt_symmetric(key)?;
    Ok(String::from_utf8_lossy(&pt).into_owned())
}

fn crypto_err(e: crate::crypto::CryptoError) -> ProviderError {
    ProviderError::Crypto(e.to_string())
}

fn map_api(e: ApiError) -> ProviderError {
    match e {
        ApiError::TwoFactorChallenge(body) => {
            // Decode offered providers into backend-agnostic tags. The wire
            // body keys are numbers-as-strings (["0"]) per the VW 1.37.2
            // capture; rbw's deserializer accepts numbers and strings.
            ProviderError::TwoFactorRequired {
                providers: decode_two_factor_providers(&body),
            }
        }
        ApiError::Status { op, status, detail } => match status {
            401 => ProviderError::AuthExpired,
            403 => ProviderError::Forbidden(detail),
            404 => ProviderError::NotFound(detail),
            400..=499 => ProviderError::Auth(format!("{op}: {detail}")),
            _ => ProviderError::Server(format!("{op}: {detail}")),
        },
        other => ProviderError::Transport(other.to_string()),
    }
}

/// Inverse of the id→tag mapping in [`decode_two_factor_providers`]:
/// resolve a backend-agnostic tag to its VW wire provider id. Accepts
/// the bare tags or an `unknown(n)` passthrough.
pub(crate) fn tag_to_wire_id(tag: &str) -> Option<u8> {
    match tag {
        "totp" => Some(0),
        "email" => Some(1),
        "webauthn" => Some(7),
        other => other
            .strip_prefix("unknown(")
            .and_then(|rest| rest.strip_suffix(')'))
            .and_then(|n| n.parse().ok()),
    }
}

/// Decode the providers offered by a two-factor challenge body into
/// backend-agnostic tags: `totp` (0), `email` (1), `webauthn` (7), else
/// `unknown(n)`. Accepts `TwoFactorProviders` (array) and
/// `TwoFactorProviders2` (map), either key casing, ids as numbers or
/// strings; unknown ids never fail the parse.
pub(crate) fn decode_two_factor_providers(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let id_to_tag = |n: u64| -> String {
        match n {
            0 => "totp".into(),
            1 => "email".into(),
            7 => "webauthn".into(),
            other => format!("unknown({other})"),
        }
    };
    let mut out: Vec<String> = Vec::new();
    // TwoFactorProviders array: ["0"] (string ids on VW 1.37.2) or [0].
    for key in ["TwoFactorProviders", "twoFactorProviders"] {
        if let Some(list) = v.get(key).and_then(|x| x.as_array()) {
            for item in list {
                let id = item
                    .as_u64()
                    .or_else(|| item.as_str().and_then(|s| s.parse::<u64>().ok()));
                if let Some(n) = id {
                    let tag = id_to_tag(n);
                    if !out.contains(&tag) {
                        out.push(tag);
                    }
                }
            }
        }
    }
    // TwoFactorProviders2 map: {"0": null} — string keys, any value.
    for key in ["TwoFactorProviders2", "twoFactorProviders2"] {
        if let Some(map) = v.get(key).and_then(|x| x.as_object()) {
            for k in map.keys() {
                if let Ok(n) = k.parse::<u64>() {
                    let tag = id_to_tag(n);
                    if !out.contains(&tag) {
                        out.push(tag);
                    }
                }
            }
        }
    }
    out
}

/// KDF params from either prelogin JSON or the token response.
fn kdf_from_json(v: &serde_json::Value) -> KdfParams {
    let g = |k: &str| v.get(k).and_then(|x| x.as_u64()).map(|x| x as u32);
    let kind = g("kdf").or_else(|| g("KDF"));
    let iters = g("kdfIterations").or_else(|| g("KdfIterations"));
    match kind {
        Some(1) => KdfParams::argon2id(
            iters.unwrap_or(3),
            g("kdfMemory").or_else(|| g("KdfMemory")).unwrap_or(64) * 1024, // MiB -> KiB
            g("kdfParallelism")
                .or_else(|| g("KdfParallelism"))
                .unwrap_or(4),
        ),
        _ => KdfParams::pbkdf2(iters.unwrap_or(600_000)),
    }
}

fn unwrap_user_key(
    enc_user_key: &str,
    master_key: &Zeroizing<[u8; 32]>,
) -> Result<SymmetricKey, ProviderError> {
    let es = EncString::parse(enc_user_key).map_err(crypto_err)?;
    let (enc, mac) = stretch_master_key(master_key).map_err(crypto_err)?;
    let stretched = SymmetricKey::from_parts(*enc, *mac);
    let blob = es.decrypt_symmetric(&stretched).map_err(crypto_err)?;
    SymmetricKey::from_64(&blob).map_err(crypto_err)
}

#[async_trait]
impl Provider for VaultwardenProvider {
    fn id(&self) -> &'static str {
        "vw"
    }

    /// Refresh via the refresh-token grant. The user key outlives tokens (it
    /// is unrelated to them), so the new session keeps it. `AuthExpired` when
    /// no refresh token was stored — callers re-login with the master password.
    async fn refresh_session(&self, s: &Session) -> Result<Session, ProviderError> {
        let sess: VwSession = parse_session(s)?;
        let Some(rt) = sess.refresh_token.as_ref() else {
            return Err(ProviderError::AuthExpired);
        };
        let token = self.client.token_refresh(rt).await.map_err(map_api)?;
        let out = VwSession {
            access_token: token.access_token,
            refresh_token: token.refresh_token.or_else(|| sess.refresh_token.clone()),
            user_key_b64: sess.user_key_b64.clone(),
            account: sess.account.clone(),
            expires_at: now_unix().map(|t| t + token.expires_in),
        };
        Ok(Session {
            provider: "vw".into(),
            handle: serde_json::to_string(&out)
                .map_err(|e| ProviderError::Server(e.to_string()))?,
        })
    }

    fn session_expiry(&self, s: &Session) -> Option<u64> {
        parse_session(s).ok().and_then(|h| h.expires_at)
    }

    async fn login(&self, params: LoginParams) -> Result<Session, ProviderError> {
        let email = params.account.clone();
        let password = params.secret;
        // Consumed only by the fidoh ceremony path (moved into the
        // ceremony thread if the server challenges with provider-7;
        // without the fidoh feature the helper ignores it).
        let pin_source = params.pin_source;
        let second = params
            .second_factor
            .as_ref()
            .map(|sf| {
                tag_to_wire_id(&sf.provider_tag)
                    .map(|id| (id, sf.code.expose_secret().to_string()))
                    .ok_or_else(|| {
                        ProviderError::Server(format!(
                            "unsupported two-factor provider tag: {}",
                            sf.provider_tag
                        ))
                    })
            })
            .transpose()?;

        #[cfg(any(feature = "webauthn", feature = "fidoh"))]
        let (second, webauthn_selected) = match second {
            // WebAuthn (wire 7) has no operator-supplied code: the answer is
            // produced in `answer_two_factor` from the live challenge, so the
            // first grant always goes out plain. The selection is remembered
            // so a provider-7 challenge on this call is answered in-place —
            // the caller's single-resubmit budget never sees it.
            Some((7u8, _)) => (None, true),
            other => (other, false),
        };
        #[cfg(not(any(feature = "webauthn", feature = "fidoh")))]
        let webauthn_selected = false;

        let pre_raw: serde_json::Value = self.client.prelogin(&email).await.map_err(map_api)?.0;
        let kdf = kdf_from_json(&pre_raw);
        let master_key =
            derive_master_key(password.expose_secret(), &email, &kdf).map_err(crypto_err)?;
        let hash = auth_hash(password.expose_secret(), &master_key).map_err(crypto_err)?;
        let token = self
            .client
            .token_password(
                &email,
                hash.as_str(),
                second.as_ref().map(|(p, t)| (*p, t.as_str())),
            )
            .await;
        // One answer, one resubmit: a 2FA challenge here is either answered
        // (device ceremony or code) and resubmitted exactly once, or fails
        // typed. No retry loops. A webauthn-selected login answers a
        // provider-7 challenge inside this call; a challenge on the
        // *resubmit* means the assertion/code was rejected and surfaces as
        // typed Auth — never as a second TwoFactorRequired the CLI's
        // single-resubmit budget would refuse.
        let token = match token {
            Err(ApiError::TwoFactorChallenge(body)) => {
                let answered = if webauthn_selected {
                    self.answer_two_factor(&body, Some((7u8, "")), pin_source)?
                } else {
                    self.answer_two_factor(
                        &body,
                        second.as_ref().map(|(p, t)| (*p, t.as_str())),
                        pin_source,
                    )?
                };
                match answered {
                    Some((provider, token_value)) => self
                        .client
                        .token_password(
                            &email,
                            hash.as_str(),
                            Some((provider, token_value.as_str())),
                        )
                        .await
                        .map_err(|e| match e {
                            ApiError::TwoFactorChallenge(_) => ProviderError::Auth(format!(
                                "two-factor {provider} answer rejected: server re-challenged"
                            )),
                            other => map_api(other),
                        })?,
                    None => return Err(map_api(ApiError::TwoFactorChallenge(body))),
                }
            }
            Err(e) => return Err(map_api(e)),
            Ok(t) => t,
        };
        // Unwrap now: wrong password must fail at login, not first sync.
        let user_key = unwrap_user_key(&token.key, &master_key)?;
        let user_key_b64 = base64_encode(user_key_bytes(&user_key));
        drop(user_key);
        let sess = VwSession {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            user_key_b64,
            account: Some(email),
            expires_at: now_unix().map(|t| t + token.expires_in),
        };
        Ok(Session {
            provider: "vw".into(),
            handle: serde_json::to_string(&sess)
                .map_err(|e| ProviderError::Server(e.to_string()))?,
        })
    }

    async fn list_namespaces(&self, s: &Session) -> Result<Vec<Namespace>, ProviderError> {
        let sess: VwSession = parse_session(s)?;
        let user_key = sess_user_key(&sess)?;
        let (sync, _org_keys, collections) =
            self.sync_and_keys(&sess.access_token, &user_key).await?;
        // One namespace per organization (name from collections), plus the
        // personal vault as the empty-id namespace.
        let mut out = Vec::new();
        for (id, _org, name) in &collections {
            out.push(Namespace {
                id: id.clone(),
                name: name.clone(),
            });
        }
        let _ = &sync;
        out.push(Namespace {
            id: String::new(),
            name: "personal".into(),
        });
        Ok(out)
    }

    async fn list_secrets(
        &self,
        s: &Session,
        ns: &Namespace,
    ) -> Result<Vec<SecretMeta>, ProviderError> {
        let sess: VwSession = parse_session(s)?;
        let user_key = sess_user_key(&sess)?;
        let (sync, org_keys, collections) =
            self.sync_and_keys(&sess.access_token, &user_key).await?;
        // Resolve the namespace to a collection id (empty = personal).
        let coll_id: Option<String> = if ns.id.is_empty() {
            Some(String::new())
        } else {
            resolve_collection(&ns.id, &collections)
        };
        let Some(coll_id) = coll_id else {
            return Err(ProviderError::NotFound(format!("namespace {}", ns.id)));
        };
        let mut metas = Vec::new();
        for c in &sync.ciphers {
            let belongs = match (&c.organization_id, coll_id.is_empty()) {
                (None, true) => true,
                (Some(_), true) => false,
                (None, false) => false,
                (Some(_), false) => c
                    .collection_ids
                    .as_ref()
                    .is_some_and(|ids| ids.contains(&coll_id)),
            };
            if !belongs {
                continue;
            }
            let container = key_for(&c.organization_id, &org_keys, &user_key);
            let key = match effective_key(c.key.as_deref(), container) {
                Ok(k) => k,
                Err(_) => continue, // key-bearing but unwrap failed: undecryptable; list survives
            };
            match map_cipher(c, &key) {
                Ok(sec) => metas.push(sec.meta),
                Err(_) => continue, // skip undecryptable; list survives
            }
        }
        self.write_cache(&sess, &user_key, &sync, &org_keys, &collections);
        ok_metas(metas)
    }

    async fn get_namespace_secrets(
        &self,
        s: &Session,
        ns: &Namespace,
    ) -> Result<Vec<Secret>, ProviderError> {
        let sess: VwSession = parse_session(s)?;
        let user_key = sess_user_key(&sess)?;
        let (sync, org_keys, collections) =
            self.sync_and_keys(&sess.access_token, &user_key).await?;
        let coll_id: Option<String> = if ns.id.is_empty() {
            Some(String::new())
        } else {
            resolve_collection(&ns.id, &collections)
        };
        let Some(coll_id) = coll_id else {
            return Err(ProviderError::NotFound(format!("namespace {}", ns.id)));
        };
        let mut out = Vec::new();
        for c in &sync.ciphers {
            let belongs = match (&c.organization_id, coll_id.is_empty()) {
                (None, true) => true,
                (Some(_), true) => false,
                (None, false) => false,
                (Some(_), false) => c
                    .collection_ids
                    .as_ref()
                    .is_some_and(|ids| ids.contains(&coll_id)),
            };
            if !belongs {
                continue;
            }
            let container = key_for(&c.organization_id, &org_keys, &user_key);
            let key = match effective_key(c.key.as_deref(), container) {
                Ok(k) => k,
                Err(_) => continue, // key-bearing but unwrap failed: undecryptable; list survives
            };
            if let Ok(sec) = map_cipher(c, &key) {
                out.push(sec);
            }
        }
        self.write_cache(&sess, &user_key, &sync, &org_keys, &collections);
        Ok(out)
    }

    async fn get_secret(&self, s: &Session, r: &Ref) -> Result<Secret, ProviderError> {
        if r.scheme != "vw" {
            return Err(ProviderError::BadRef(format!("not a vw ref: {r}")));
        }
        let sess: VwSession = parse_session(s)?;
        let user_key = sess_user_key(&sess)?;
        let Some((coll, item)) = r.locus.split_once('/') else {
            return Err(ProviderError::BadRef(format!(
                "vw locus must be collection/item: {}",
                r.locus
            )));
        };

        // Warm path: resolve collection + item name -> cipher uuid locally,
        // then one targeted fetch. Any doubt (no cache, unknown name, 404,
        // rename) falls through to the full-sync miss path.
        if let Some(path) = self.cache_path.as_deref() {
            let span = tracing::info_span!("get_warm", hit = tracing::field::Empty);
            let _g = span.enter();
            if let Some(cache) = SyncCache::at(path).load(&user_key) {
                if let Some(sec) = self.get_secret_warm(&sess, &cache, coll, item).await? {
                    span.record("hit", "true");
                    return Ok(sec);
                }
            }
            span.record("hit", "false");
        }

        // Miss path: today's behavior exactly — full sync, linear scan.
        let (sync, org_keys, collections) =
            self.sync_and_keys(&sess.access_token, &user_key).await?;
        let Some(coll_id) = resolve_collection(coll, &collections) else {
            return Err(ProviderError::NotFound(format!("collection {coll}")));
        };
        let mut unwrap_failures = 0usize;
        for c in &sync.ciphers {
            let belongs = match (&c.organization_id, coll_id.is_empty()) {
                (None, true) => true,
                (Some(_), true) => false,
                (None, false) => false,
                (Some(_), false) => c
                    .collection_ids
                    .as_ref()
                    .is_some_and(|ids| ids.contains(&coll_id)),
            };
            if !belongs {
                continue;
            }
            let container = key_for(&c.organization_id, &org_keys, &user_key);
            let key = match effective_key(c.key.as_deref(), container) {
                Ok(k) => k,
                Err(e) => {
                    // Key-bearing cipher we cannot unwrap (stale/wrong
                    // container key). Can't read its name, can't match;
                    // remember it so a no-match scan reports the real
                    // problem instead of a ghost "not found".
                    tracing::debug!(error = %e, id = %c.id, "cipher-level key unwrap failed");
                    unwrap_failures += 1;
                    continue;
                }
            };
            let Ok(name) = decrypt_str(&c.name, &key) else {
                continue;
            };
            if !name.eq_ignore_ascii_case(item) {
                continue;
            }
            let secret = map_cipher(c, &key).map_err(crypto_err)?;
            self.write_cache(&sess, &user_key, &sync, &org_keys, &collections);
            return Ok(secret);
        }
        if unwrap_failures > 0 {
            return Err(ProviderError::Crypto(format!(
                "{unwrap_failures} cipher(s) in collection {coll} carry cipher-level \
                 keys that fail to unwrap under the available container keys"
            )));
        }
        Err(ProviderError::NotFound(format!("vw://{coll}/{item}")))
    }
}

impl VaultwardenProvider {
    /// Choose the second-factor answer for the wire and run it. Code-based
    /// factors (totp/email) pass through; webauthn (wire 7) triggers the
    /// CTAP2 device ceremony: decode the challenge, drive the hardware key,
    /// assemble the web-vault connector token JSON, resubmit exactly once.
    #[allow(unused_variables)] // challenge body unused with the feature off
    fn answer_two_factor(
        &self,
        challenge_body: &str,
        second: Option<(u8, &str)>,
        pin_source: Option<PinSource>,
    ) -> Result<Option<(u8, String)>, ProviderError> {
        #[cfg(not(feature = "fidoh"))]
        let _ = pin_source;
        match second {
            // Code factors already carry their answer.
            answer @ (Some((0, _)) | Some((1, _))) => Ok(answer.map(|(p, t)| (p, t.to_string()))),
            // WebAuthn selected.
            Some((7, _)) => {
                // fidoh-backed ceremony (stage 1 of add-fidoh-ceremony-
                // provider): authoritative whenever the fidoh feature is
                // compiled in — including alongside `webauthn` (design:
                // deterministic precedence, fidoh wins). Challenge decode,
                // origin, clientDataJSON, and the wire shape are byte-
                // identical to the legacy path; the ceremony runs inside
                // fidoh's single handed-in budget (no outer timeout wrap —
                // the unbounded-keepalive hang class is specified out of
                // existence), and errors map per design.md §error mapping:
                // decline/mismatch → Auth (3), no-device/transport/budget
                // → Transport (4), assembly/panic → Server (4).
                #[cfg(feature = "fidoh")]
                {
                    use crate::webauthn::FidohCeremonyError;
                    let ch = crate::webauthn::challenge_from_body(challenge_body)
                        .map_err(|e| ProviderError::Auth(format!("{e}")))?;
                    #[cfg(debug_assertions)]
                    if let Some(hook) = &self.assertion_hook {
                        let token = hook(&ch).map_err(|e| ProviderError::Auth(format!("{e}")))?;
                        return Ok(Some((7, token.expose_secret().to_string())));
                    }
                    // The ceremony runs on its own thread (blocking device
                    // I/O, dedicated current_thread runtime inside). The
                    // ceremony budget bounds the result-channel wait too: a
                    // wedged ceremony surfaces typed Transport within the
                    // budget — never an indefinite join. (The budget bounds
                    // both sides: inside fidoh every wait consumes the same
                    // handed-in Deadline's remainder.)
                    let budget = crate::webauthn::ceremony_budget();
                    let (tx, rx) = std::sync::mpsc::channel();
                    let ch = std::clone::Clone::clone(&ch);
                    // The PIN source rides in from `LoginParams`; fidoh
                    // invokes it at most once, only if acquisition demands
                    // a PIN (`&mut` is the one-prompt-per-ceremony contract).
                    std::thread::spawn(move || {
                        let _ = tx.send(crate::webauthn::fidoh_perform_assertion(&ch, pin_source));
                    });
                    let token = rx
                        .recv_timeout(budget)
                        .map_err(|_| FidohCeremonyError::BudgetExpired {
                            phase: "ceremony-thread",
                            budget: budget.as_secs(),
                        })
                        .and_then(|inner| inner)
                        .map_err(|e| match e.exit_class() {
                            "auth" => ProviderError::Auth(e.to_string()),
                            "transport" => ProviderError::Transport(e.to_string()),
                            _ => ProviderError::Server(e.to_string()),
                        })?;
                    Ok(Some((7, token.expose_secret().to_string())))
                }
                // Legacy webauthn-authenticator-rs ceremony: byte-identical
                // while the fidoh feature is off (stage-1 fence).
                #[cfg(not(feature = "fidoh"))]
                {
                    #[cfg(feature = "webauthn")]
                    {
                        let ch = crate::webauthn::challenge_from_body(challenge_body)
                            .map_err(|e| ProviderError::Auth(format!("{e}")))?;
                        #[cfg(debug_assertions)]
                        if let Some(hook) = &self.assertion_hook {
                            let token =
                                hook(&ch).map_err(|e| ProviderError::Auth(format!("{e}")))?;
                            return Ok(Some((7, token.expose_secret().to_string())));
                        }
                        let ch = std::clone::Clone::clone(&ch);
                        let token =
                            std::thread::spawn(move || crate::webauthn::perform_assertion(&ch))
                                .join()
                                .map_err(|_| {
                                    ProviderError::Server("webauthn thread panicked".into())
                                })?
                                .map_err(|e| ProviderError::Auth(format!("{e}")))?;
                        Ok(Some((7, token.expose_secret().to_string())))
                    }
                    #[cfg(not(feature = "webauthn"))]
                    Err(ProviderError::Auth(
                        "server demanded webauthn (security-key) two-factor but this build \
                         lacks hardware-key support; rebuild with --features webauthn"
                            .into(),
                    ))
                }
            }
            Some((n, _)) => Err(ProviderError::Auth(format!(
                "no answerable code for two-factor provider {n}"
            ))),
            None => Ok(None),
        }
    }
    /// Warm-path resolution. Ok(None) = fall through to full sync.
    #[tracing::instrument(skip(self, sess, cache), fields(op = "warm_lookup"))]
    async fn get_secret_warm(
        &self,
        sess: &VwSession,
        cache: &CacheData,
        coll: &str,
        item: &str,
    ) -> Result<Option<Secret>, ProviderError> {
        let coll_id = resolve_collection(coll, &cache.collection_tuples());
        let Some(coll_id) = coll_id else {
            return Ok(None);
        };
        // Candidate ciphers: name match within the collection. Could be
        // more than one (same name in two collections of one org);
        // try each until one fetch verifies.
        let candidates: Vec<&crate::cache::CipherIndexEntry> = cache
            .ciphers
            .iter()
            .filter(|c| {
                c.name.eq_ignore_ascii_case(item)
                    && match coll_id.is_empty() {
                        true => c.org_id.is_none(),
                        false => c.collection_ids.contains(&coll_id),
                    }
            })
            .collect();
        for entry in candidates {
            let cipher = match self.client.get_cipher(&sess.access_token, &entry.id).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "warm: targeted fetch failed");
                    continue; // 404/stale -> try next candidate, else miss path
                }
            };
            let Ok(container) = self.cipher_key(cache, &cipher, sess) else {
                tracing::debug!("warm: org key missing from cache");
                return Ok(None); // org key rotated out of cache -> resync
            };
            let key = match effective_key(cipher.key.as_deref(), &container) {
                Ok(k) => k,
                Err(e) => {
                    tracing::debug!(error = %e, "warm: cipher-level key unwrap failed");
                    return Ok(None); // container key stale -> resync, miss path reports
                }
            };
            // Verify the name still matches — closes the rename race.
            let name = match decrypt_str(&cipher.name, &key) {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(error = %e, "warm: name decrypt failed");
                    return Ok(None);
                }
            };
            if !name.eq_ignore_ascii_case(item) {
                tracing::debug!(got = %name, "warm: name mismatch");
                continue;
            }
            // Name verified: this is the cipher the ref asked for. A field
            // failure now is a real error, not a cache miss.
            return map_cipher(&cipher, &key).map(Some).map_err(crypto_err);
        }
        Ok(None)
    }

    /// Key for one cipher: org key from the cache when org-owned, else
    /// the user key. Cache org-key miss (rotation) -> miss path.
    fn cipher_key(
        &self,
        cache: &CacheData,
        cipher: &crate::api::Cipher,
        sess: &VwSession,
    ) -> Result<SymmetricKey, ProviderError> {
        match cipher.organization_id.as_deref() {
            Some(org) => cache.org_key(org).ok_or(ProviderError::Crypto(
                "org key missing from cache; resync needed".into(),
            )),
            None => sess_user_key(sess),
        }
    }

    /// Build + persist the cache after a successful full sync. Best-effort.
    #[tracing::instrument(skip(self, sess, user_key, sync, org_keys, collections))]
    fn write_cache(
        &self,
        sess: &VwSession,
        user_key: &SymmetricKey,
        sync: &crate::api::SyncResponse,
        org_keys: &[(String, SymmetricKey)],
        collections: &[(String, String, String)],
    ) {
        let Some(path) = self.cache_path.as_deref() else {
            return;
        };
        let mut coll_entries = Vec::new();
        for (id, org_id, name) in collections {
            coll_entries.push(crate::cache::CollectionIndexEntry {
                id: id.clone(),
                org_id: org_id.clone(),
                name: name.clone(),
            });
        }
        let mut cipher_entries = Vec::new();
        for c in &sync.ciphers {
            let container = key_for(&c.organization_id, org_keys, user_key);
            let Ok(key) = effective_key(c.key.as_deref(), container) else {
                continue; // undecryptable: leave out of the index
            };
            let name = match decrypt_str(&c.name, &key) {
                Ok(n) => n,
                Err(_) => continue, // undecryptable: leave out of the index
            };
            cipher_entries.push(crate::cache::CipherIndexEntry {
                id: c.id.clone(),
                org_id: c.organization_id.clone(),
                name,
                collection_ids: c.collection_ids.clone().unwrap_or_default(),
            });
        }
        let mut org_entries = Vec::new();
        for (org_id, k) in org_keys {
            let mut b64 = [0u8; 64];
            b64[..32].copy_from_slice(k.enc_bytes());
            b64[32..].copy_from_slice(k.mac_bytes());
            use base64::Engine as _;
            org_entries.push(crate::cache::OrgKeyEntry {
                org_id: org_id.clone(),
                key_b64: base64::engine::general_purpose::STANDARD.encode(b64),
            });
        }
        let data = CacheData {
            v: 1,
            account: sess.account.clone(),
            collections: coll_entries,
            ciphers: cipher_entries,
            org_keys: org_entries,
        };
        let file = SyncCache::at(path);
        if let Err(e) = file.store(user_key, &data) {
            tracing::warn!(error = %e, "sync cache write failed (non-fatal)");
        }
    }
}

fn ok_metas(m: Vec<SecretMeta>) -> Result<Vec<SecretMeta>, ProviderError> {
    Ok(m)
}

fn parse_session(s: &Session) -> Result<VwSession, ProviderError> {
    serde_json::from_str(&s.handle)
        .map_err(|e| ProviderError::Auth(format!("corrupt session: {e}")))
}

/// Wall clock, unix seconds. `None` only if the platform has no clock
/// (never on supported targets); expiry tracking degrades to reactive.
fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn sess_user_key(sess: &VwSession) -> Result<SymmetricKey, ProviderError> {
    let raw = base64_decode(&sess.user_key_b64).ok_or(ProviderError::AuthExpired)?;
    SymmetricKey::from_64(&raw).map_err(crypto_err)
}

fn key_for<'a>(
    org: &Option<String>,
    org_keys: &'a [(String, SymmetricKey)],
    user_key: &'a SymmetricKey,
) -> &'a SymmetricKey {
    match org {
        Some(o) => org_keys
            .iter()
            .find(|(id, _)| id == o)
            .map(|(_, k)| k)
            .unwrap_or(user_key),
        None => user_key,
    }
}

/// The key a cipher's fields are actually sealed under. Ciphers that carry
/// a cipher-level `key` (type-2 EncString) wrap a per-cipher symmetric key
/// under the container key; unwrap and use it. Everything else uses the
/// container key directly. A present-but-failing unwrap is a real error
/// (wrong/stale container key), not a skip.
fn effective_key(
    cipher_key_field: Option<&str>,
    container: &SymmetricKey,
) -> Result<SymmetricKey, crate::crypto::CryptoError> {
    match cipher_key_field.filter(|k| !k.is_empty()) {
        None => Ok(container.clone()),
        Some(k) => {
            let es = EncString::parse(k)?;
            SymmetricKey::from_64(&es.decrypt_symmetric(container)?)
        }
    }
}

fn user_key_bytes(k: &SymmetricKey) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(k.enc_bytes());
    out[32..].copy_from_slice(k.mac_bytes());
    out
}

fn base64_encode(b: [u8; 64]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

#[cfg(test)]
mod two_factor_tests {
    use super::*;

    // Live-capture challenge shape (fixtures/challenge.json): array of
    // STRING ids + map spelling, plus a sibling policy field to ignore.
    #[test]
    fn decodes_capture_array_and_map_spellings() {
        let body = r#"{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["0"],"TwoFactorProviders2":{"0":null},"MasterPasswordPolicy":{"Object":"masterPasswordPolicy"}}"#;
        assert_eq!(decode_two_factor_providers(body), vec!["totp"]);
    }

    // Numbers (rbw accepts both), lowercase keys, and unknown ids all decode;
    // duplicates across spellings collapse.
    #[test]
    fn decodes_numbers_lowercase_and_unknown_ids() {
        let body = r#"{"twoFactorProviders":[0,1,7],"twoFactorProviders2":{"7":null,"9":null}}"#;
        assert_eq!(
            decode_two_factor_providers(body),
            vec!["totp", "email", "webauthn", "unknown(9)"]
        );
    }

    #[test]
    fn garbage_body_yields_empty() {
        assert!(decode_two_factor_providers("not json").is_empty());
        assert!(decode_two_factor_providers("{}").is_empty());
    }

    #[test]
    fn tag_roundtrip_matches_id_to_tag() {
        for (tag, id) in [("totp", 0u8), ("email", 1), ("webauthn", 7)] {
            assert_eq!(tag_to_wire_id(tag), Some(id));
        }
        assert_eq!(tag_to_wire_id("unknown(12)"), Some(12));
        assert_eq!(tag_to_wire_id("yubikey"), None);
        assert_eq!(tag_to_wire_id("unknown()"), None);
        assert_eq!(tag_to_wire_id("unknown(-1)"), None);
    }
}
