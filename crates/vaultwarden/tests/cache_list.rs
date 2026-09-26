// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Bare `list_namespaces` cache-persistence contract: a full sync through
//! the bare list must rewrite the sealed cache like every other full-sync
//! path, the persisted blob must unseal under the session's user key, and
//! a list alone must warm get's targeted-fetch path (no second /sync).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use cryptile_core::provider::{LoginParams, Provider};
use cryptile_core::{ExposeSecret, Ref, SecretString};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use cryptile_vaultwarden::VaultwardenProvider;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("wiremock_fixture.json")).unwrap()
}

/// Full /sync payload: profile (user key, private key, org key) + two
/// ciphers (personal login + org login in the "shared" collection).
fn sync_body() -> serde_json::Value {
    let fx = fixture();
    json!({
        "profile": {
            "id": "u1",
            "email": fx["email"],
            "key": fx["protected_user_key"],
            "privateKey": fx["protected_private_key"],
            "organizations": [{
                "id": fx["org"]["org_id"],
                "key": fx["org_key"],
            }],
        },
        "ciphers": [
            {
                "id": fx["personal"]["id"],
                "name": fx["personal"]["name"],
                "login": {"password": fx["personal"]["password"]},
                "collectionIds": null,
            },
            {
                "id": fx["org"]["id"],
                "name": fx["org"]["name"],
                "login": {"password": fx["org"]["password"]},
                "organizationId": fx["org"]["org_id"],
                "collectionIds": [fx["org"]["collection"]],
            },
        ],
    })
}

/// Mock VW: prelogin + token + sync (first `sync_cap` syncs, then 404 when
/// capped) + collections + the targeted single-cipher warm fetch.
async fn mock_vw(sync_cap: Option<usize>) -> MockServer {
    let fx = fixture();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kdf": 0,
            "kdfIterations": fx["iterations"],
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at-token",
            "refresh_token": "rt-token",
            "expires_in": 7200,
            "key": fx["protected_user_key"],
            "Kdf": 0,
            "KdfIterations": fx["iterations"],
        })))
        .mount(&server)
        .await;

    // Capped /sync: answers the first `sync_cap` syncs 200, then 404 —
    // any later full sync fails, so a passing get proves it rode the
    // cache the bare list must have persisted. Unbounded when `None`.
    if let Some(n) = sync_cap {
        let syncs = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(move |_req: &Request| {
                let seen = syncs.fetch_add(1, Ordering::SeqCst);
                if seen < n {
                    ResponseTemplate::new(200).set_body_json(sync_body())
                } else {
                    ResponseTemplate::new(404)
                }
            })
            .mount(&server)
            .await;
    } else {
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(move |_req: &Request| {
                ResponseTemplate::new(200).set_body_json(sync_body())
            })
            .mount(&server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/api/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": fx["org"]["collection"],
                "organizationId": fx["org"]["org_id"],
                "name": fx["org"]["coll_name"],
            }],
            "object": "list",
        })))
        .mount(&server)
        .await;

    // Targeted single-cipher fetch (get's warm path): same body as the
    // sync entry for the org cipher.
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/ciphers/{}",
            fx["org"]["id"].as_str().unwrap()
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": fx["org"]["id"],
            "name": fx["org"]["name"],
            "login": {"password": fx["org"]["password"]},
            "organizationId": fx["org"]["org_id"],
            "collectionIds": [fx["org"]["collection"]],
        })))
        .mount(&server)
        .await;

    server
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vw-cache-list-{}-{tag}", std::process::id()))
}

/// THE REPRO (red before the fix): bare list_namespaces full-syncs but
/// never writes `<cache>/cipher-index`, so the vault index earned by that
/// sync is thrown away.
#[tokio::test]
async fn list_namespaces_persists_warm_loadable_cache() {
    let fx = fixture();
    let server = mock_vw(None).await;
    let dir = temp_dir("list_persists");
    let provider = VaultwardenProvider::new(&server.uri())
        .unwrap()
        .with_cache_path(dir.join("cache").join("cipher-index"));
    let session = provider
        .login(LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: SecretString::new(fx["password"].as_str().unwrap().into()),
            second_factor: None,
            pin_source: None,
        })
        .await
        .unwrap();

    let nss = provider.list_namespaces(&session).await.unwrap();
    assert!(nss.iter().any(|n| n.name == "shared"));
    assert!(nss.iter().any(|n| n.name == "personal"));

    let cache_path = dir.join("cache").join("cipher-index");
    let line = std::fs::read_to_string(&cache_path)
        .expect("bare list must persist the sealed cache after its full sync");
    assert!(line.starts_with("crc1."), "cache must be the sealed format");

    // The persisted blob must unseal under THIS session's user key — the
    // exact key path a later warm read takes.
    let sess: serde_json::Value = serde_json::from_str(&session.handle).unwrap();
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sess["user_key_b64"].as_str().unwrap())
        .unwrap();
    let key = cryptile_vaultwarden::crypto::SymmetricKey::from_64(&raw).unwrap();
    let data = cryptile_vaultwarden::cache::unseal(&key, &line).unwrap();
    assert!(data.collections.iter().any(|c| c.name == "shared"));
    assert!(data.ciphers.iter().any(|c| c.name == "smtp"));
    assert!(data.ciphers.iter().any(|c| c.name == "personal-item"));
    assert!(data
        .org_keys
        .iter()
        .any(|o| o.org_id == fx["org"]["org_id"].as_str().unwrap()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The payoff of persistence: a bare list ALONE (no prior get) must warm
/// the cache enough that a following get resolves via one targeted fetch,
/// never a second /sync. Red before the fix: the get cold-syncs.
#[tokio::test]
async fn list_alone_warms_get_targeted_fetch() {
    let fx = fixture();
    let server = mock_vw(Some(1)).await; // /sync answers exactly once
    let dir = temp_dir("list_warms_get");
    let provider = VaultwardenProvider::new(&server.uri())
        .unwrap()
        .with_cache_path(dir.join("cache").join("cipher-index"));
    let session = provider
        .login(LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: SecretString::new(fx["password"].as_str().unwrap().into()),
            second_factor: None,
            pin_source: None,
        })
        .await
        .unwrap();

    // Consumes the single /sync quota; must leave a usable cache behind.
    provider.list_namespaces(&session).await.unwrap();

    let r = Ref::parse("vw://shared/smtp#password").unwrap();
    let sec = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        sec.field("password").unwrap().expose_secret(),
        fx["expect"]["org_item_password"].as_str().unwrap()
    );

    let reqs = server.received_requests().await.unwrap();
    let syncs = reqs.iter().filter(|q| q.url.path() == "/api/sync").count();
    assert_eq!(
        syncs, 1,
        "get after a bare list must ride the cache: no second /sync"
    );
    let targeted = reqs
        .iter()
        .filter(|q| q.url.path().starts_with("/api/ciphers/"))
        .count();
    assert_eq!(targeted, 1, "warm get must be exactly one targeted fetch");
    let _ = std::fs::remove_dir_all(&dir);
}
