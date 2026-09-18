// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! CLI-level 2FA tests: exit-code + stderr contracts for the login retry
//! leg, wire pinned to vaultwarden/tests/fixtures/CAPTURES.md. All tests
//! force a non-TTY stdin (write_stdin) so the resolver never prompts.

use assert_cmd::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../vaultwarden/tests/wiremock_fixture.json"
    ))
    .unwrap()
}

fn challenge_body(fx: &serde_json::Value) -> serde_json::Value {
    fx["twofactor"]["challenge"].clone()
}

fn wrong_code_body(fx: &serde_json::Value) -> serde_json::Value {
    fx["twofactor"]["wrong_code"].clone()
}

fn success_body(fx: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "access_token": "at-token",
        "refresh_token": "rt-token",
        "expires_in": 7200,
        "key": fx["protected_user_key"],
        "Kdf": 0,
        "KdfIterations": fx["iterations"],
    })
}

async fn mount_prelogin(server: &MockServer, fx: &serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "kdf": 0,
            "kdfIterations": fx["iterations"],
        })))
        .mount(server)
        .await;
}

fn login_cmd(server: &MockServer, fx: &serde_json::Value, dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("cryptile").unwrap();
    cmd.env("CRYPTILE_PASSPHRASE", "keyring-pass")
        .env("CRYPTILE_MASTER_PASSWORD", fx["password"].as_str().unwrap())
        .arg("--state-dir")
        .arg(dir)
        .arg("login")
        .arg("--server")
        .arg(server.uri())
        .arg("--account")
        .arg(fx["email"].as_str().unwrap())
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .arg("--master-password-env")
        .arg("CRYPTILE_MASTER_PASSWORD");
    cmd
}

/// Challenge + no code source + non-TTY: exit 3 with a stderr hint naming
/// both resolution flags (spec: remediation hint, no interactive stall).
#[tokio::test]
async fn login_challenge_without_code_source_exits_3_with_hint() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_prelogin(&server, &fx).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(challenge_body(&fx)))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let assert = login_cmd(&server, &fx, tmp.path())
        .write_stdin("")
        .assert();
    let output = assert.failure().get_output().to_owned();
    assert_eq!(output.status.code(), Some(3), "stderr: {:?}", output.stderr);
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(err.contains("--2fa-code"), "hint must name --2fa-code: {err}");
    assert!(err.contains("--2fa-env"), "hint must name --2fa-env: {err}");
}

/// Challenge + --2fa-env: exactly one resubmit carrying the captured wire
/// fields, then a sealed session on disk.
#[tokio::test]
async fn login_with_2fa_env_resubmits_once_and_seals_session() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_prelogin(&server, &fx).await;
    // Priority 2: bare grants get the challenge; priority 1: the resubmit
    // (form carries the token) gets success.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(challenge_body(&fx)))
        .with_priority(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(wiremock::matchers::body_string_contains(
            "twoFactorToken=654321",
        ))
        .and(wiremock::matchers::body_string_contains(
            "twoFactorProvider=0",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_body(&fx)))
        .with_priority(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let assert = login_cmd(&server, &fx, tmp.path())
        .env("MY_2FA_CODE", "654321")
        .arg("--2fa-env")
        .arg("MY_2FA_CODE")
        .write_stdin("")
        .assert();
    assert.success();

    let requests = server.received_requests().await.unwrap();
    let token_posts: Vec<&wiremock::Request> = requests
        .iter()
        .filter(|r| r.url.path() == "/identity/connect/token")
        .collect();
    assert_eq!(token_posts.len(), 2, "exactly two token endpoint calls");
    let first = String::from_utf8(token_posts[0].body.clone()).unwrap();
    let second = String::from_utf8(token_posts[1].body.clone()).unwrap();
    assert!(!first.contains("twoFactorToken"));
    assert!(
        second.contains("twoFactorToken=654321")
            && second.contains("twoFactorProvider=0")
    );
    // Session actually sealed: both state files exist.
    assert!(tmp.path().join("config.json").exists());
    assert!(tmp.path().join("keyring").exists());
}

/// --2fa-env naming an unset variable: exit 3 naming the variable.
#[tokio::test]
async fn login_2fa_env_unset_var_exits_3() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_prelogin(&server, &fx).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(challenge_body(&fx)))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let assert = login_cmd(&server, &fx, tmp.path())
        .arg("--2fa-env")
        .arg("CRYPTILE_MISSING_2FA")
        .write_stdin("")
        .assert();
    let output = assert.failure().get_output().to_owned();
    assert_eq!(output.status.code(), Some(3));
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(err.contains("CRYPTILE_MISSING_2FA"), "stderr: {err}");
}

/// --2fa-provider naming a factor the server did not offer: exit 3,
/// no resubmit attempted.
#[tokio::test]
async fn login_2fa_provider_not_offered_exits_3() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_prelogin(&server, &fx).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(challenge_body(&fx)))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let assert = login_cmd(&server, &fx, tmp.path())
        .env("MY_2FA_CODE", "654321")
        .arg("--2fa-provider")
        .arg("email")
        .arg("--2fa-env")
        .arg("MY_2FA_CODE")
        .write_stdin("")
        .assert();
    let output = assert.failure().get_output().to_owned();
    assert_eq!(output.status.code(), Some(3));
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(err.contains("did not offer"), "stderr: {err}");
}

/// --2fa-code together with --2fa-env: usage error (exit 2), no network.
#[test]
fn login_conflicting_code_flags_exit_2() {
    let fx = fixture();
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("cryptile").unwrap();
    cmd.arg("--state-dir")
        .arg(tmp.path())
        .arg("login")
        .arg("--server")
        .arg("https://vault.example.com")
        .arg("--account")
        .arg(fx["email"].as_str().unwrap())
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .arg("--master-password-env")
        .arg("CRYPTILE_MASTER_PASSWORD")
        .arg("--2fa-code")
        .arg("123456")
        .arg("--2fa-env")
        .arg("MY_2FA_CODE")
        .write_stdin("")
        .assert()
        .failure()
        .code(2);
}

/// Wrong TOTP code: the "Invalid TOTP code!" 400 is a typed AUTH failure
/// (exit 3), NOT another challenge — one attempt, no retry loop.
#[tokio::test]
async fn login_wrong_2fa_code_exits_3_without_loop() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_prelogin(&server, &fx).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(wrong_code_body(&fx)))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let assert = login_cmd(&server, &fx, tmp.path())
        .env("MY_2FA_CODE", "000000")
        .arg("--2fa-env")
        .arg("MY_2FA_CODE")
        .write_stdin("")
        .assert();
    let output = assert.failure().get_output().to_owned();
    assert_eq!(output.status.code(), Some(3));

    let requests = server.received_requests().await.unwrap();
    let token_posts = requests
        .iter()
        .filter(|r| r.url.path() == "/identity/connect/token")
        .count();
    assert_eq!(token_posts, 1, "wrong code must not loop");
}
