// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Export e2e + boundary tests. The e2e spins a wiremock VW with the real
//! crypto fixture and drives export through --passphrase-env (no TTY),
//! exactly the Hermes bootstrap path.

use assert_cmd::Command;
use cryptile_core::provider::Provider;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../vaultwarden/tests/wiremock_fixture.json"
    ))
    .unwrap()
}

fn base_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

async fn mount_vw(server: &MockServer, fx: &serde_json::Value) {
    let email = fx["email"].as_str().unwrap();
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "kdf": 0,
            "kdfIterations": fx["iterations"],
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-token",
            "refresh_token": "rt-token",
            "expires_in": 7200,
            "key": fx["protected_user_key"],
            "Kdf": 0,
            "KdfIterations": fx["iterations"],
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "profile": {
                "id": "u1",
                "email": email,
                "key": fx["protected_user_key"],
                "privateKey": fx["protected_private_key"],
                "organizations": [{
                    "id": fx["org"]["org_id"],
                    "key": fx["org_key"],
                }],
            },
            "ciphers": [
                {
                    "id": fx["org"]["id"],
                    "name": fx["org"]["name"],
                    "organizationId": fx["org"]["org_id"],
                    "collectionIds": [fx["org"]["collection"]],
                    "login": {"password": fx["org"]["password"]},
                    "notes": fx["org"]["notes"],
                },
            ],
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "id": fx["org"]["collection"],
                "organizationId": fx["org"]["org_id"],
                "name": fx["org"]["coll_name"],
            }],
            "object": "list",
        })))
        .mount(server)
        .await;
}

/// Drive a full login + export without any TTY: state is seeded via the
/// same library calls the CLI uses (keyring::seal + config.json), provider
/// login runs in-process (no TTY needed at the API layer).
#[tokio::test]
async fn export_env_passphrase_end_to_end() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_vw(&server, &fx).await;

    // Real provider login (no TTY needed at the API layer).
    let provider = cryptile_vaultwarden::VaultwardenProvider::new(&server.uri()).unwrap();
    let session = provider
        .login(cryptile_core::LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: secrecy::SecretString::from(fx["password"].as_str().unwrap()),
        })
        .await
        .unwrap();

    // Seed CLI state exactly as `cryptile login` would.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("state");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        serde_json::json!({"server": server.uri(), "account": fx["email"]}).to_string(),
    )
    .unwrap();
    let pw = secrecy::SecretString::from("keyring-pass");
    let line = cryptile_core::keyring::seal(&session.handle, &pw).unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();

    // Export via env passphrase — the Hermes bootstrap path.
    let mut cmd = Command::cargo_bin("cryptile").unwrap();
    let assert = cmd
        .env("CRYPTILE_PASSPHRASE", "keyring-pass")
        .arg("--state-dir")
        .arg(&dir)
        .arg("export")
        .arg("--namespace")
        .arg("shared")
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .assert();
    let assert = assert.success();
    let out = assert.get_output().stdout.clone();
    let text = String::from_utf8(out).unwrap();
    let expected = fx["expect"]["org_item_password"].as_str().unwrap();
    assert!(
        text.contains(&format!("PASSWORD={expected}")),
        "expected PASSWORD={expected} in:\n{text}"
    );
    // newline + backslash escaping stays one line (task 1.4)
    assert!(
        text.contains("NOTES=line1\\nline2\\\\tail\n"),
        "expected escaped NOTES line in:\n{text}"
    );
    // exactly one line per field: no raw newline inside a value
    for line in text.lines() {
        assert!(
            line.starts_with(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
            "non-KEY line on stdout:\n{line}"
        );
    }
    // metadata lines never on stdout
    assert!(
        !text.contains("smtp"),
        "item name leaked to stdout:\n{text}"
    );
    assert!(
        !text.contains("shared"),
        "namespace name on stdout:\n{text}"
    );
}

#[test]
fn export_without_any_passphrase_path_fails_clean() {
    let tmp = base_dir();
    let dir = tmp.path().join("state");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        r#"{"server":"https://vault.example.com","account":"a@b.c"}"#,
    )
    .unwrap();
    let line = cryptile_core::keyring::seal("{}", &secrecy::SecretString::from("x")).unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();

    Command::cargo_bin("cryptile")
        .unwrap()
        .arg("--state-dir")
        .arg(&dir)
        .arg("export")
        .arg("--namespace")
        .arg("whatever")
        .assert()
        .failure()
        .code(3)
        .stderr(predicates::str::contains("no passphrase path"));
}

#[test]
fn export_missing_env_var_fails_clean() {
    let tmp = base_dir();
    let dir = tmp.path().join("state");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        r#"{"server":"https://vault.example.com","account":"a@b.c"}"#,
    )
    .unwrap();
    let line = cryptile_core::keyring::seal("{}", &secrecy::SecretString::from("x")).unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();

    Command::cargo_bin("cryptile")
        .unwrap()
        .env_remove("CRYPTILE_PASSPHRASE")
        .arg("--state-dir")
        .arg(&dir)
        .arg("export")
        .arg("--namespace")
        .arg("whatever")
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .assert()
        .failure()
        .code(3)
        .stderr(predicates::str::contains("is not set"));
}

#[test]
fn mangle_and_escape_rules() {
    // Same logic the CLI uses; pinned here as unit-level expectations.
    // Uppercase, non-alnum -> _, collision suffix.
    let mut seen = std::collections::BTreeMap::new();
    assert_eq!(mangle("totp-secret", &mut seen), "TOTP_SECRET");
    assert_eq!(mangle("TOTP_SECRET", &mut seen), "TOTP_SECRET__1");
    assert_eq!(mangle("user name", &mut seen), "USER_NAME");
    let esc = |v: &str| v.replace('\\', "\\\\").replace('\n', "\\n");
    assert_eq!(esc("a\nb"), "a\\nb");
    assert_eq!(esc("a\\b"), "a\\\\b");
}

fn mangle(name: &str, seen: &mut std::collections::BTreeMap<String, String>) -> String {
    let base: String = name
        .to_ascii_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let mut candidate = base.clone();
    let mut n = 0;
    while seen.contains_key(&candidate) {
        n += 1;
        candidate = format!("{base}__{n}");
    }
    seen.insert(candidate.clone(), name.to_string());
    candidate
}

/// Proactive refresh (add-token-lifecycle): a sealed session whose token
/// expires inside the 300s margin must be refreshed BEFORE backend calls.
/// The sync/collections mocks only answer `Authorization: Bearer fresh-at`;
/// the stale token gets no mock, so success proves the rotation happened.
#[tokio::test]
async fn export_proactively_refreshes_near_expiry_session() {
    use wiremock::matchers::header;

    let fx = fixture();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "kdf": 0,
            "kdfIterations": fx["iterations"],
        })))
        .mount(&server)
        .await;
    // One token mock serves both the password grant (login) and the
    // refresh grant (proactive rotation); both yield "fresh-at".
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh-at",
            "refresh_token": "rt2",
            "expires_in": 7200,
            "key": fx["protected_user_key"],
            "Kdf": 0,
            "KdfIterations": fx["iterations"],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(header("Authorization", "Bearer fresh-at"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
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
            "ciphers": [{
                "id": fx["org"]["id"],
                "name": fx["org"]["name"],
                "organizationId": fx["org"]["org_id"],
                "collectionIds": [fx["org"]["collection"]],
                "login": {"password": fx["org"]["password"]},
                "notes": fx["org"]["notes"],
            }],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/collections"))
        .and(header("Authorization", "Bearer fresh-at"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "id": fx["org"]["collection"],
                "organizationId": fx["org"]["org_id"],
                "name": fx["org"]["coll_name"],
            }],
            "object": "list",
        })))
        .mount(&server)
        .await;

    // Real login, then age the session: stale token, expiry inside margin.
    let provider = cryptile_vaultwarden::VaultwardenProvider::new(&server.uri()).unwrap();
    let session = provider
        .login(cryptile_core::LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: secrecy::SecretString::from(fx["password"].as_str().unwrap()),
        })
        .await
        .unwrap();
    let mut handle: serde_json::Value = serde_json::from_str(&session.handle).unwrap();
    handle["access_token"] = serde_json::json!("stale-at");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    handle["expires_at"] = serde_json::json!(now + 60);

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("state");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        serde_json::json!({"server": server.uri(), "account": fx["email"]}).to_string(),
    )
    .unwrap();
    let line = cryptile_core::keyring::seal(
        &handle.to_string(),
        &secrecy::SecretString::from("keyring-pass"),
    )
    .unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();

    let mut cmd = Command::cargo_bin("cryptile").unwrap();
    let assert = cmd
        .env("CRYPTILE_PASSPHRASE", "keyring-pass")
        .arg("--state-dir")
        .arg(&dir)
        .arg("export")
        .arg("--namespace")
        .arg("shared")
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .assert();
    let assert = assert.success();
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let expected = fx["expect"]["org_item_password"].as_str().unwrap();
    assert!(
        text.contains(&format!("PASSWORD={expected}")),
        "expected PASSWORD={expected} after proactive refresh, got:\n{text}"
    );
}
