// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! CLI-level sync-cache persistence e2e: the real `cryptile` binary with a
//! temp `--state-dir` must leave the sealed cache at
//! `<state-dir>/cache/cipher-index` after any full sync (the contract
//! docs/onboarding.md states). Regression lock for the bare `list` path,
//! which full-synced but dropped the cache write; the namespace-list
//! control pins that the `--state-dir` wiring itself was never broken.

use assert_cmd::Command;
use cryptile_core::provider::{LoginParams, Provider};
use cryptile_core::SecretString;
use predicates::str::contains;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../vaultwarden/tests/wiremock_fixture.json"
    ))
    .unwrap()
}

/// Mock VW: prelogin + token + full sync (personal + org cipher) +
/// collections. Wire shape mirrors crates/vaultwarden/tests/cache_e2e.rs.
async fn mock_vw() -> MockServer {
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

    server
}

/// Seed a logged-in state dir: config.json + keyring sealed around a REAL
/// session handle (library login against the mock, so the sealed
/// `user_key_b64` genuinely decrypts the vault the CLI then syncs).
async fn seed_login(dir: &std::path::Path, server: &MockServer) {
    let fx = fixture();
    let provider = cryptile_vaultwarden::VaultwardenProvider::new(&server.uri()).unwrap();
    let session = provider
        .login(LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: SecretString::new(fx["password"].as_str().unwrap().into()),
            second_factor: None,
            pin_source: None,
        })
        .await
        .unwrap();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        json!({"server": server.uri(), "account": fx["email"]}).to_string(),
    )
    .unwrap();
    let line =
        cryptile_core::keyring::seal(&session.handle, &SecretString::from("test-passphrase"))
            .unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();
}

fn cryptile() -> Command {
    let mut c = Command::cargo_bin("cryptile").unwrap();
    c.env_remove("XDG_CONFIG_HOME");
    c
}

/// THE REPRO (red before the fix): bare `cryptile list` full-syncs (the
/// mock serves /sync) but must ALSO leave the sealed cache at
/// `<state-dir>/cache/cipher-index` — "written after any full sync" per
/// docs/onboarding.md. Before the fix the run exited 0 and the file was
/// absent, so a later get always rode a cold cache.
#[tokio::test]
async fn list_persists_cipher_cache_under_state_dir() {
    let server = mock_vw().await;
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join("state");
    seed_login(&state_dir, &server).await;

    cryptile()
        .env("CRYPTILE_PASSPHRASE", "test-passphrase")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("list")
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .assert()
        .success()
        .stdout(contains("shared"))
        .stdout(contains("personal"));

    // The full sync really happened (so the cache, if written, is fresh).
    let reqs = server.received_requests().await.unwrap();
    assert!(
        reqs.iter().any(|q| q.url.path() == "/api/sync"),
        "bare list must full-sync first"
    );

    let cache = state_dir.join("cache").join("cipher-index");
    assert!(
        cache.is_file(),
        "bare list must persist the sealed cache under the configured state dir"
    );
    let line = std::fs::read_to_string(&cache).unwrap();
    assert!(
        line.starts_with("crc1."),
        "cache must be the sealed crc1 format"
    );
}

/// Control (green before AND after the fix): `list <namespace>` through the
/// exact same `--state-dir` → `with_cache_path` wiring DOES persist the
/// cache — pinning that the divergence lived inside the library's
/// `list_namespaces`, not the CLI plumbing.
#[tokio::test]
async fn list_namespace_persists_cipher_cache_under_state_dir() {
    let fx = fixture();
    let server = mock_vw().await;
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join("state");
    seed_login(&state_dir, &server).await;

    cryptile()
        .env("CRYPTILE_PASSPHRASE", "test-passphrase")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("list")
        .arg(fx["expect"]["coll_name"].as_str().unwrap())
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .assert()
        .success();

    let cache = state_dir.join("cache").join("cipher-index");
    assert!(
        cache.is_file(),
        "list <namespace> persists the cache through the same CLI wiring"
    );
}
