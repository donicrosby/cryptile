//! End-to-end provider test against a wiremock VW: real crypto chain from
//! fixture (Python oracle), mock transport. Proves KDF → auth hash → token →
//! user-key unwrap → private-key unwrap → org-key unwrap → cipher decrypt
//! → field mapping, plus ref resolution by collection NAME.

use cryptile_core::provider::{LoginParams, Provider};
use cryptile_core::{ExposeSecret, Ref, SecretString};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use cryptile_vaultwarden::VaultwardenProvider;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("wiremock_fixture.json")).unwrap()
}

#[tokio::test]
async fn full_login_sync_get_roundtrip() {
    let fx = fixture();
    let server = MockServer::start().await;

    // prelogin
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kdf": 0,
            "kdfIterations": fx["iterations"],
        })))
        .mount(&server)
        .await;

    // token
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

    // sync
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
                    "organizationId": fx["org"]["org_id"],
                    "collectionIds": [fx["org"]["collection"]],
                    "login": {"password": fx["org"]["password"]},
                },
            ],
        })))
        .mount(&server)
        .await;

    // collections
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

    let provider = VaultwardenProvider::new(&server.uri()).unwrap();
    let session = provider
        .login(LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: SecretString::new(fx["password"].as_str().unwrap().into()),
        })
        .await
        .unwrap();

    // get by collection NAME
    let r = Ref::parse("vw://shared/smtp#password").unwrap();
    let secret = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        secret.field("password").unwrap().expose_secret(),
        fx["expect"]["org_item_password"].as_str().unwrap()
    );

    // personal item
    let r = Ref::parse("vw://personal/personal-item#password").unwrap();
    let secret = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        secret.field("password").unwrap().expose_secret(),
        fx["expect"]["personal_item_password"].as_str().unwrap()
    );

    // list namespaces: shared collection + personal
    let nss = provider.list_namespaces(&session).await.unwrap();
    assert!(nss.iter().any(|n| n.name == "shared"));
    assert!(nss.iter().any(|n| n.name == "personal"));

    // list secrets in shared
    let shared = nss.iter().find(|n| n.name == "shared").unwrap();
    let metas = provider.list_secrets(&session, shared).await.unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].name, "smtp");
}
