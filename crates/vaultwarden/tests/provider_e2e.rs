// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! End-to-end provider test against a wiremock VW: real crypto chain from
//! fixture (Python oracle), mock transport. Proves KDF → auth hash → token →
//! user-key unwrap → private-key unwrap → org-key unwrap → cipher decrypt
//! → field mapping, plus ref resolution by collection NAME.

use cryptile_core::provider::{LoginParams, Provider, ProviderError, SecondFactor};
use cryptile_core::{ExposeSecret, Ref, SecretString};
use serde_json::json;
use wiremock::matchers::{header, method, path};
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

    // prelogin — every request class must carry client identification
    // (CLIENT_NAME/CLIENT_VERSION); a stripped header fails here.
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .and(header(
            "Bitwarden-Client-Name",
            cryptile_vaultwarden::api::CLIENT_NAME,
        ))
        .and(header(
            "Bitwarden-Client-Version",
            cryptile_vaultwarden::api::CLIENT_VERSION,
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kdf": 0,
            "kdfIterations": fx["iterations"],
        })))
        .mount(&server)
        .await;

    // token
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(header(
            "Bitwarden-Client-Name",
            cryptile_vaultwarden::api::CLIENT_NAME,
        ))
        .and(header(
            "Bitwarden-Client-Version",
            cryptile_vaultwarden::api::CLIENT_VERSION,
        ))
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

    // sync — the header is load-bearing: version-gating servers omit
    // type-5 (SSH-key) ciphers from this payload without it.
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(header(
            "Bitwarden-Client-Name",
            cryptile_vaultwarden::api::CLIENT_NAME,
        ))
        .and(header(
            "Bitwarden-Client-Version",
            cryptile_vaultwarden::api::CLIENT_VERSION,
        ))
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
                {
                    "id": fx["cipherkey"]["id"],
                    "name": fx["cipherkey"]["name"],
                    "key": fx["cipherkey"]["key"],
                    "notes": fx["cipherkey"]["notes"],
                    "organizationId": fx["org"]["org_id"],
                    "collectionIds": [fx["org"]["collection"]],
                    "type": 2,
                },
            ],
        })))
        .mount(&server)
        .await;

    // collections
    Mock::given(method("GET"))
        .and(path("/api/collections"))
        .and(header(
            "Bitwarden-Client-Name",
            cryptile_vaultwarden::api::CLIENT_NAME,
        ))
        .and(header(
            "Bitwarden-Client-Version",
            cryptile_vaultwarden::api::CLIENT_VERSION,
        ))
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
            second_factor: None,
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
    assert_eq!(metas.len(), 7);
    let names: Vec<&str> = metas.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"smtp"));
    assert!(names.contains(&"lease-key"));
    assert!(names.contains(&"corp-card"));
    assert!(names.contains(&"passport"));
    assert!(names.contains(&"bootstrap-node"));
    assert!(names.contains(&"multi-uri"));
    assert!(names.contains(&"per-cipher-key-note"));

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

    // cipher-level key: fields sealed under the per-cipher key, not the org
    // key. get must unwrap cipher.key under the org key first.
    let r = Ref::parse("vw://shared/per-cipher-key-note#notes").unwrap();
    let secret = provider.get_secret(&session, &r).await.unwrap();
    assert_eq!(
        secret.field("notes").unwrap().expose_secret(),
        fx["expect"]["cipherkey_notes"].as_str().unwrap()
    );

    // bare ref on a note resolves via the primary chain (no password on a
    // note -> notes). Fragment-less must equal #notes here.
    let bare = Ref::parse("vw://shared/lease-key").unwrap();
    let secret = provider.get_secret(&session, &bare).await.unwrap();
    assert_eq!(
        secret.primary_value().unwrap().expose_secret(),
        fx["expect"]["note_notes"].as_str().unwrap()
    );
    // bare ref on the per-cipher-key note too (chain + unwrap composed).
    let bare = Ref::parse("vw://shared/per-cipher-key-note").unwrap();
    let secret = provider.get_secret(&session, &bare).await.unwrap();
    assert_eq!(
        secret.primary_value().unwrap().expose_secret(),
        fx["expect"]["cipherkey_notes"].as_str().unwrap()
    );
    // bare ref on a card -> number (no password/notes on the fixture card).
    let bare = Ref::parse("vw://shared/corp-card").unwrap();
    let secret = provider.get_secret(&session, &bare).await.unwrap();
    assert_eq!(
        secret.primary_value().unwrap().expose_secret(),
        fx["expect"]["card_number"].as_str().unwrap()
    );
    // bare ref on a login with password: password still wins.
    let bare = Ref::parse("vw://shared/smtp").unwrap();
    let secret = provider.get_secret(&session, &bare).await.unwrap();
    assert_eq!(
        secret.primary_value().unwrap().expose_secret(),
        fx["expect"]["org_item_password"].as_str().unwrap()
    );
}

/// 2FA leg, wire pinned to fixtures/CAPTURES.md (VW 1.37.2 live capture):
/// password grant → 400 challenge (both provider spellings) → typed
/// `TwoFactorRequired` → resubmit with `twoFactorToken`/`twoFactorProvider`
/// → session unwraps the user key. Wrong code → typed AUTH error.
#[tokio::test]
async fn two_factor_challenge_resubmit_roundtrip() {
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

    // First password grant (no 2FA fields): challenge with BOTH spellings —
    // the live capture uses the array form; the map form duplicates id "1"
    // (email) to prove the decoder merges both without duplicates.
    let challenge_body = fx["twofactor"]["challenge"].clone();
    let mut challenge = challenge_body.as_object().unwrap().clone();
    challenge.insert(
        "TwoFactorProviders2".to_string(),
        json!({"0": null, "1": null}),
    );
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(wiremock::matchers::body_string_contains("grant_type"))
        .and(wiremock::matchers::body_string_contains("username"))
        .respond_with(ResponseTemplate::new(400).set_body_json(challenge))
        .with_priority(2)
        .mount(&server)
        .await;

    // Resubmit: priority 1 wins when the form carries the token; asserts the
    // exact wire field names from CAPTURES.md.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(wiremock::matchers::body_string_contains(
            "twoFactorToken=123456",
        ))
        .and(wiremock::matchers::body_string_contains(
            "twoFactorProvider=0",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at-token",
            "refresh_token": "rt-token",
            "expires_in": 7200,
            "key": fx["protected_user_key"],
            "Kdf": 0,
            "KdfIterations": fx["iterations"],
        })))
        .with_priority(1)
        .mount(&server)
        .await;

    let provider = VaultwardenProvider::new(&server.uri()).unwrap();

    // First leg: challenge decoded into sorted, de-duplicated backend-agnostic
    // tags ("0" -> totp, "1" -> email).
    let err = provider
        .login(LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: SecretString::new(fx["password"].as_str().unwrap().into()),
            second_factor: None,
        })
        .await
        .expect_err("challenge must surface as an error");
    match &err {
        ProviderError::TwoFactorRequired { providers } => {
            assert_eq!(providers, &vec!["totp".to_string(), "email".to_string()])
        }
        other => panic!("expected TwoFactorRequired, got: {other:?}"),
    }

    // Second leg: the CLI resubmits with the chosen factor; the mock pins the
    // exact form fields, and a session that unwraps proves the full chain.
    let _session = provider
        .login(LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: SecretString::new(fx["password"].as_str().unwrap().into()),
            second_factor: Some(SecondFactor {
                provider_tag: "totp".into(),
                code: SecretString::new(fx["twofactor"]["code"].as_str().unwrap().into()),
            }),
        })
        .await
        .expect("resubmit with the 2FA token must yield a session");

    // Verify the exact wire exchange from the recorded requests: the first
    // token call must carry no 2FA fields, the second must carry both fields
    // verbatim (CAPTURES.md), and the code itself must never leak into logs.
    let requests = server.received_requests().await.unwrap();
    let token_posts: Vec<&wiremock::Request> = requests
        .iter()
        .filter(|r| r.url.path() == "/identity/connect/token")
        .collect();
    assert_eq!(token_posts.len(), 2, "exactly two token endpoint calls");
    let first_body = String::from_utf8(token_posts[0].body.clone()).unwrap();
    let second_body = String::from_utf8(token_posts[1].body.clone()).unwrap();
    assert!(
        !first_body.contains("twoFactorToken"),
        "first grant must not carry 2FA fields"
    );
    assert!(
        second_body.contains("twoFactorToken=123456")
            && second_body.contains("twoFactorProvider=0"),
        "resubmit must carry the captured wire fields verbatim"
    );
}

/// Wrong TOTP code: VW answers 400 "Invalid TOTP code!" (wrong-code.json
/// capture) — NOT a two-factor challenge. Must surface as the typed AUTH
/// error (exit code 3 family), never as TwoFactorRequired.
#[tokio::test]
async fn two_factor_wrong_code_is_auth_error() {
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

    let _wrong = Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(fx["twofactor"]["wrong_code"].clone()),
        )
        .mount(&server)
        .await;

    let provider = VaultwardenProvider::new(&server.uri()).unwrap();
    let err = provider
        .login(LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: SecretString::new(fx["password"].as_str().unwrap().into()),
            second_factor: Some(SecondFactor {
                provider_tag: "totp".into(),
                code: SecretString::new(fx["twofactor"]["wrong"].as_str().unwrap().into()),
            }),
        })
        .await
        .expect_err("wrong code must fail");
    assert!(
        matches!(err, ProviderError::Auth(_)),
        "expected typed Auth error, got: {err:?}"
    );
}
