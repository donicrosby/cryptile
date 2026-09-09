// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Sync-cache warm-path e2e against a wiremock VW (Python-oracle fixture):
//! cold get full-syncs and writes the cache; the second get resolves
//! locally + one targeted cipher fetch, never calling /sync again;
//! renames and 404s fall back to the miss path; --refresh semantics are
//! covered by the CLI layer (delete before open).

use cryptile_core::provider::{LoginParams, Provider};
use cryptile_core::{ExposeSecret, Ref, SecretString};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use cryptile_vaultwarden::VaultwardenProvider;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("wiremock_fixture.json")).unwrap()
}

struct Env {
    server: MockServer,
    provider: VaultwardenProvider,
    session: cryptile_core::Session,
    fx: serde_json::Value,
    dir: std::path::PathBuf,
}

async fn env(cache: bool) -> Env {
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

    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
        })))
        .mount(&server)
        .await;

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

    // Targeted single-cipher fetch (warm path). Same body as the sync
    // entry for the org cipher.
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

    let mut provider = VaultwardenProvider::new(&server.uri()).unwrap();
    let dir = std::env::temp_dir().join(format!("vw-cache-e2e-{}", std::process::id()));
    if cache {
        provider = provider.with_cache_path(dir.join("cache").join("cipher-index"));
    }
    let session = provider
        .login(LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: SecretString::new(fx["password"].as_str().unwrap().into()),
        })
        .await
        .unwrap();
    Env {
        server,
        provider,
        session,
        fx,
        dir,
    }
}

#[tokio::test]
async fn warm_second_get_skips_sync() {
    let e = env(true).await;
    let r = Ref::parse("vw://shared/smtp#password").unwrap();

    // Cold: full sync + collections, cache written.
    let s1 = e.provider.get_secret(&e.session, &r).await.unwrap();
    let s1v = s1.field("password").unwrap().expose_secret().to_string();
    assert!(!s1v.is_empty());
    assert!(e.dir.join("cache").join("cipher-index").is_file());

    // Warm: same value, no additional /sync calls.
    let s2 = e.provider.get_secret(&e.session, &r).await.unwrap();
    assert_eq!(s2.field("password").unwrap().expose_secret(), s1v);
    let reqs = e.server.received_requests().await.unwrap();
    let syncs = reqs.iter().filter(|q| q.url.path() == "/api/sync").count();
    assert_eq!(syncs, 1, "warm get must not call /sync");
    let targeted = reqs
        .iter()
        .filter(|q| q.url.path().starts_with("/api/ciphers/"))
        .count();
    assert_eq!(targeted, 1, "warm get must be exactly one targeted fetch");
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn no_cache_path_means_sync_every_time() {
    let e = env(false).await;
    let r = Ref::parse("vw://shared/smtp#password").unwrap();
    e.provider.get_secret(&e.session, &r).await.unwrap();
    e.provider.get_secret(&e.session, &r).await.unwrap();
    let reqs = e.server.received_requests().await.unwrap();
    let syncs = reqs.iter().filter(|q| q.url.path() == "/api/sync").count();
    assert_eq!(syncs, 2, "without a cache path every get full-syncs");
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn tampered_cache_self_heals() {
    let e = env(true).await;
    let item = "smtp";
    let r = Ref::parse(&format!("vw://shared/{item}#password")).unwrap();
    e.provider.get_secret(&e.session, &r).await.unwrap(); // cold, writes cache

    // Corrupt the cache file on disk -> load must fail MAC -> cold path
    // -> full sync again -> still the right answer.
    let cache_path = e.dir.join("cache").join("cipher-index");
    std::fs::write(&cache_path, "crc1.AAAA.AAAA.AAAA.AAAA").unwrap();
    let s2 = e.provider.get_secret(&e.session, &r).await.unwrap();
    assert_eq!(
        s2.field("password").unwrap().expose_secret(),
        e.fx["expect"]["org_item_password"].as_str().unwrap()
    );
    let reqs = e.server.received_requests().await.unwrap();
    let syncs = reqs.iter().filter(|q| q.url.path() == "/api/sync").count();
    assert_eq!(syncs, 2, "corrupt cache must fall back to full sync");
    let _ = std::fs::remove_dir_all(&e.dir);
}
