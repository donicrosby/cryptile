// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! `VaultwardenProvider`: the Provider facade over api + crypto.

use async_trait::async_trait;
use cryptile_core::model::{Namespace, Secret, SecretMeta, Session};
use cryptile_core::provider::{LoginParams, Provider, ProviderError};
use cryptile_core::{ExposeSecret, Ref};
use zeroize::Zeroizing;

use crate::api::{ApiError, Client};
use crate::cache::{CacheData, SyncCache};
use crate::crypto::{
    auth_hash, derive_master_key, stretch_master_key, unwrap_org_key, EncString, KdfParams,
    SymmetricKey,
};
use crate::mapping::{map_cipher, resolve_collection};

/// Persistent provider handle. Cheap to clone; reqwest client is pooled.
#[derive(Debug, Clone)]
pub struct VaultwardenProvider {
    client: Client,
    /// Optional sync-cache path. `None` disables the warm path entirely
    /// (library use without a state dir).
    cache_path: Option<std::path::PathBuf>,
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
        })
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

/// KDF params from either prelogin JSON or the token response.
fn kdf_from_json(v: &serde_json::Value) -> KdfParams {
    let g = |k: &str| v.get(k).and_then(|x| x.as_u64()).map(|x| x as u32);
    let kind = g("kdf").or_else(|| g("KDF"));
    let iters = g("kdfIterations").or_else(|| g("KdfIterations"));
    match kind {
        Some(1) => KdfParams::argon2id(
            iters.unwrap_or(3),
            g("kdfMemory").or_else(|| g("KdfMemory")).unwrap_or(64),
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
        let pre_raw: serde_json::Value = self.client.prelogin(&email).await.map_err(map_api)?.0;
        let kdf = kdf_from_json(&pre_raw);
        let master_key =
            derive_master_key(password.expose_secret(), &email, &kdf).map_err(crypto_err)?;
        let hash = auth_hash(password.expose_secret(), &master_key).map_err(crypto_err)?;
        let token = self
            .client
            .token_password(&email, hash.as_str())
            .await
            .map_err(map_api)?;
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
