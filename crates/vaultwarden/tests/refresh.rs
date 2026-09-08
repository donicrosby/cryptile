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
