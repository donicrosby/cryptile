// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
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
    let uris_json: Vec<serde_json::Value> = fx["multiuri"]["uris"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| serde_json::json!({ "uri": u }))
        .collect();

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
                {
                    "id": fx["note"]["id"],
                    "name": fx["note"]["name"],
                    "organizationId": fx["org"]["org_id"],
                    "collectionIds": [fx["org"]["collection"]],
                    "notes": fx["note"]["notes"],
                    "type": 2,
                },
                {
                    "id": fx["card"]["id"],
                    "name": fx["card"]["name"],
                    "organizationId": fx["org"]["org_id"],
                    "collectionIds": [fx["org"]["collection"]],
                    "card": {
                        "cardholderName": fx["card"]["cardholder_name"],
                        "brand": fx["card"]["brand"],
                        "number": fx["card"]["number"],
                        "expMonth": fx["card"]["exp_month"],
                        "expYear": fx["card"]["exp_year"],
                        "code": fx["card"]["code"],
                    },
                    "type": 3,
                },
                {
                    "id": fx["identity"]["id"],
                    "name": fx["identity"]["name"],
                    "organizationId": fx["org"]["org_id"],
                    "collectionIds": [fx["org"]["collection"]],
                    "identity": {
                        "title": fx["identity"]["title"],
                        "firstName": fx["identity"]["first_name"],
                        "lastName": fx["identity"]["last_name"],
                        "passportNumber": fx["identity"]["passport_number"],
                        "ssn": fx["identity"]["ssn"],
                    },
                    "type": 4,
                },
                {
                    "id": fx["sshkey"]["id"],
                    "name": fx["sshkey"]["name"],
                    "organizationId": fx["org"]["org_id"],
                    "collectionIds": [fx["org"]["collection"]],
                    "sshKey": {
                        "privateKey": fx["sshkey"]["private_key"],
                        "publicKey": fx["sshkey"]["public_key"],
                        "keyFingerprint": fx["sshkey"]["key_fingerprint"],
                    },
                    "type": 5,
                },
                {
                    "id": fx["multiuri"]["id"],
                    "name": fx["multiuri"]["name"],
                    "organizationId": fx["org"]["org_id"],
                    "collectionIds": [fx["org"]["collection"]],
                    "login": {
                        "password": fx["multiuri"]["password"],
                        "uris": uris_json,
                    },
                    "type": 1,
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
    assert_eq!(metas.len(), 6);
    let names: Vec<&str> = metas.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"smtp"));
    assert!(names.contains(&"lease-key"));
    assert!(names.contains(&"corp-card"));
    assert!(names.contains(&"passport"));
    assert!(names.contains(&"bootstrap-node"));
    assert!(names.contains(&"multi-uri"));

    // secure note: notes field
    let r = Ref::parse("vw://shared/lease-key#notes").unwrap();
    let secret = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        secret.field("notes").unwrap().expose_secret(),
        fx["expect"]["note_notes"].as_str().unwrap()
    );

    // card: number + code
    let r = Ref::parse("vw://shared/corp-card#number").unwrap();
    let secret = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        secret.field("number").unwrap().expose_secret(),
        fx["expect"]["card_number"].as_str().unwrap()
    );
    assert_eq!(
        secret.field("code").unwrap().expose_secret(),
        fx["expect"]["card_code"].as_str().unwrap()
    );

    // identity: passport number
    let r = Ref::parse("vw://shared/passport#passport_number").unwrap();
    let secret = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        secret.field("passport_number").unwrap().expose_secret(),
        fx["expect"]["identity_passport_number"].as_str().unwrap()
    );

    // ssh key: private key + public key + fingerprint
    let r = Ref::parse("vw://shared/bootstrap-node#private_key").unwrap();
    let secret = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        secret.field("private_key").unwrap().expose_secret(),
        fx["expect"]["sshkey_private_key"].as_str().unwrap()
    );
    assert_eq!(
        secret.field("public_key").unwrap().expose_secret(),
        fx["expect"]["sshkey_public_key"].as_str().unwrap()
    );
    assert_eq!(
        secret.field("key_fingerprint").unwrap().expose_secret(),
        fx["expect"]["sshkey_key_fingerprint"].as_str().unwrap()
    );

    // login uris: first + joined
    let r = Ref::parse("vw://shared/multi-uri#uri").unwrap();
    let secret = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        secret.field("uri").unwrap().expose_secret(),
        fx["expect"]["multiuri_uri"].as_str().unwrap()
    );
    assert_eq!(
        secret.field("uris").unwrap().expose_secret(),
        fx["expect"]["multiuri_uris"].as_str().unwrap()
    );
}
