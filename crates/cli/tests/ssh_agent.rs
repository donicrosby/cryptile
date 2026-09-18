// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! `get --agent` boundary e2e. A fake `ssh-add` shim on PATH captures the
//! piped key, proving the full CLI boundary without a real agent. Companion
//! cases: missing agent degrades silently (value still prints), and
//! non-key values never reach the shim at all.

use assert_cmd::Command;
use cryptile_core::provider::Provider as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../vaultwarden/tests/wiremock_fixture.json"
    ))
    .unwrap()
}

/// Same four-endpoint VW mock the export e2e uses (prelogin, token, sync
/// with the full cipher set, collections).
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

/// Install a fake `ssh-add` that dumps stdin into the baked capture path and
/// exits 0. Lives under `CARGO_TARGET_TMPDIR`: the sandbox (and some CI
/// images) mount /tmp noexec, and the shim must be executable. `variant`
/// isolates the shim file per test — tests run in parallel and must not
/// rewrite each other's capture path mid-flight.
fn install_shim(capture: &std::path::Path, variant: &str) -> std::path::PathBuf {
    let shim_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("shims")
        .join(variant);
    std::fs::create_dir_all(&shim_dir).unwrap();
    let shim = shim_dir.join("ssh-add");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\n[ \"$1\" = \"-\" ] && cat > '{}'\nexit 0\n",
            capture.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    shim_dir
}

/// Seed CLI state exactly as `cryptile login` would (provider login against
/// the mock, config.json + sealed keyring in a temp state dir).
async fn seed_state(
    server: &MockServer,
    fx: &serde_json::Value,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let provider = cryptile_vaultwarden::VaultwardenProvider::new(&server.uri()).unwrap();
    let session = provider
        .login(cryptile_core::LoginParams {
            account: fx["email"].as_str().unwrap().into(),
            secret: secrecy::SecretString::from(fx["password"].as_str().unwrap()),
            second_factor: None,
        })
        .await
        .unwrap();

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
    (tmp, dir)
}

/// Prepend `shim_dir` to the current PATH (plain string splice; the shim is
/// a unix script so this is unix-only by construction).
fn path_with_shim(shim_dir: &std::path::Path) -> String {
    format!(
        "{}:{}",
        shim_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

#[tokio::test]
async fn get_agent_flag_pipes_ssh_key_to_ssh_add() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_vw(&server, &fx).await;
    let (_state_tmp, dir) = seed_state(&server, &fx).await;

    let capture = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("ssh-agent-capture-pipes");
    let _ = std::fs::remove_file(&capture);
    let shim_dir = install_shim(&capture, "pipes");

    let ssh_name = "bootstrap-node"; // fixture's plaintext sshkey item name
    let expected = fx["expect"]["sshkey_private_key"].as_str().unwrap();

    let assert = Command::cargo_bin("cryptile")
        .unwrap()
        // The shim needs the gate var set; it never touches the socket.
        .env("SSH_AUTH_SOCK", "/tmp/cryptile-test-agent.sock")
        .env("CRYPTILE_PASSPHRASE", "keyring-pass")
        .env("PATH", path_with_shim(&shim_dir))
        .arg("--state-dir")
        .arg(&dir)
        .arg("get")
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .arg("--agent")
        .arg("--")
        .arg(format!("vw://shared/{ssh_name}#private_key"))
        .assert()
        .success();

    // The key reached the agent shim byte-for-byte.
    let captured = std::fs::read_to_string(&capture).unwrap();
    assert_eq!(
        captured.trim(),
        expected.trim(),
        "shim must capture the key"
    );

    // …and the value still prints on stdout (agent failure would not have
    // changed this, but prove the happy path prints too).
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains(expected.trim_end()),
        "value must still print on stdout:\n{stdout}"
    );
    // The courtesy note goes to stderr, never stdout.
    assert!(
        !stdout.contains("ssh-agent"),
        "agent chatter leaked to stdout:\n{stdout}"
    );
}

#[tokio::test]
async fn get_agent_flag_without_agent_degrades_silently() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_vw(&server, &fx).await;
    let (_state_tmp, dir) = seed_state(&server, &fx).await;

    let ssh_name = "bootstrap-node"; // fixture's plaintext sshkey item name
    let expected = fx["expect"]["sshkey_private_key"].as_str().unwrap();

    let assert = Command::cargo_bin("cryptile")
        .unwrap()
        .env_remove("SSH_AUTH_SOCK")
        .env("CRYPTILE_PASSPHRASE", "keyring-pass")
        .arg("--state-dir")
        .arg(&dir)
        .arg("get")
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .arg("--agent")
        .arg("--")
        .arg(format!("vw://shared/{ssh_name}#private_key"))
        .assert()
        .success();

    // Fetch succeeded, value intact, no agent noise anywhere.
    let out = assert.get_output();
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(stdout.contains(expected.trim_end()));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("ssh-agent"),
        "no-agent skip must be silent"
    );
}

#[tokio::test]
async fn get_agent_flag_never_pipes_non_key_values() {
    let fx = fixture();
    let server = MockServer::start().await;
    mount_vw(&server, &fx).await;
    let (_state_tmp, dir) = seed_state(&server, &fx).await;

    let capture =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("ssh-agent-capture-nonkey");
    let _ = std::fs::remove_file(&capture);
    let shim_dir = install_shim(&capture, "nonkey");

    let item_name = "smtp"; // fixture's plaintext login item name
    let expected = fx["expect"]["org_item_password"].as_str().unwrap();

    let assert = Command::cargo_bin("cryptile")
        .unwrap()
        .env("SSH_AUTH_SOCK", "/tmp/cryptile-test-agent.sock")
        .env("CRYPTILE_PASSPHRASE", "keyring-pass")
        .env("PATH", path_with_shim(&shim_dir))
        .arg("--state-dir")
        .arg(&dir)
        .arg("get")
        .arg("--passphrase-env")
        .arg("CRYPTILE_PASSPHRASE")
        .arg("--agent")
        .arg("--")
        .arg(format!("vw://shared/{item_name}#password"))
        .assert()
        .success();

    // Password printed fine; the shim was never handed anything.
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains(expected));
    assert!(!capture.exists(), "non-key value must never reach ssh-add");
}
