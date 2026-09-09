// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Token refresh round-trip against a wiremock identity server.
//! Proves: refresh grant rotates the access token, preserves the user key,
//! and a session without a refresh token fails with AuthExpired (caller
//! must fall back to password re-login).

use cryptile_core::model::Session;
use cryptile_core::provider::Provider;
use cryptile_vaultwarden::VaultwardenProvider;
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn session(handle_json: &str) -> Session {
    Session {
        provider: "vw".into(),
        handle: handle_json.into(),
    }
}

#[tokio::test]
async fn refresh_rotates_token_and_keeps_user_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-at",
            "refresh_token": "new-rt",
            "expires_in": 7200,
        })))
        .mount(&server)
        .await;

    let provider = VaultwardenProvider::new(&server.uri()).unwrap();
    let old =
        session(r#"{"access_token":"old-at","refresh_token":"old-rt","user_key_b64":"QQ=="}"#);
    let refreshed = provider.refresh_session(&old).await.unwrap();

    let sess: serde_json::Value = serde_json::from_str(&refreshed.handle).unwrap();
    assert_eq!(sess["access_token"], "new-at");
    assert_eq!(sess["refresh_token"], "new-rt");
    assert_eq!(sess["user_key_b64"], "QQ==");
}

#[tokio::test]
async fn refresh_records_expiry_and_reports_it() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-at",
            "refresh_token": "new-rt",
            "expires_in": 7200,
        })))
        .mount(&server)
        .await;

    let provider = VaultwardenProvider::new(&server.uri()).unwrap();
    let before = now() + 7100;
    let after = now() + 7300;
    let old =
        session(r#"{"access_token":"old-at","refresh_token":"old-rt","user_key_b64":"QQ=="}"#);
    let refreshed = provider.refresh_session(&old).await.unwrap();

    let exp = provider.session_expiry(&refreshed).expect("expiry set");
    assert!(
        (before..=after).contains(&exp),
        "expires_at {exp} outside [{before},{after}]"
    );
}

#[test]
fn legacy_handle_without_expiry_reports_none() {
    let provider = VaultwardenProvider::new("https://vault.example.com").unwrap();
    let old =
        session(r#"{"access_token":"old-at","refresh_token":"old-rt","user_key_b64":"QQ=="}"#);
    assert!(provider.session_expiry(&old).is_none());
}

#[test]
fn near_expiry_handle_reports_expiry() {
    let provider = VaultwardenProvider::new("https://vault.example.com").unwrap();
    let soon = session(
        r#"{"access_token":"a","refresh_token":"r","user_key_b64":"QQ==","expires_at":100}"#,
    );
    assert_eq!(provider.session_expiry(&soon), Some(100));
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn refresh_without_refresh_token_is_auth_expired() {
    let server = MockServer::start().await;
    let provider = VaultwardenProvider::new(&server.uri()).unwrap();
    let old = session(r#"{"access_token":"old-at","refresh_token":null,"user_key_b64":"QQ=="}"#);
    match provider.refresh_session(&old).await {
        Err(cryptile_core::ProviderError::AuthExpired) => {}
        other => panic!("expected AuthExpired, got {other:?}"),
    }
    // no requests hit the server
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}
