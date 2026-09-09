// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Tracing-gate tests: spans exist when RUST_LOG is set, output is silent
//! without it, and no fixture secret material ever appears in span output.
//!
//! Strategy: run the real binary against a dead server with a sealed
//! keyring (wrong passphrase is fine — we need the phases to *run*, not
//! succeed; unlock fails after Argon2) with RUST_LOG=cryptile=trace and
//! capture stderr. Spans fire for parse/unlock/total and the vaultwarden
//! request phase errors get recorded; then assert:
//!   1. span markers are present (proves tracing actually wired)
//!   2. neither the passphrase nor derived material appears anywhere

use std::process::Output;

use assert_cmd::Command;

const PASSPHRASE: &str = "tracing-test-passphrase";
const MASTER: &str = "never-the-master-password";

fn sealed_state(tmp: &std::path::Path) -> std::path::PathBuf {
    let dir = tmp.join("state");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        r#"{"server":"http://127.0.0.1:1","account":"a@b.c"}"#,
    )
    .unwrap();
    // Well-formed VW session (64 zero bytes, base64) sealed under the
    // fixture passphrase: unseal + deserialize succeed so the op proceeds
    // through provider spans to the refused transport call.
    let session_json = r#"{"access_token":"t","user_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}"#;
    let line = cryptile_core::keyring::seal(session_json, &secrecy::SecretString::from(PASSPHRASE))
        .unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();
    dir
}

fn run_get(state_dir: &std::path::Path, rust_log: Option<&str>) -> Output {
    let mut cmd = Command::cargo_bin("cryptile").unwrap();
    cmd.args([
        "--state-dir",
        state_dir.to_str().unwrap(),
        "get",
        "--passphrase-env",
        "CRYPTILE_TR_PASS",
        "--",
        "vw://shared/smtp#password",
    ])
    .env("CRYPTILE_TR_PASS", PASSPHRASE)
    .env_remove("RUST_LOG");
    if let Some(v) = rust_log {
        cmd.env("RUST_LOG", v);
    }
    cmd.output().unwrap()
}

#[test]
fn spans_fire_when_rust_log_set_and_no_secrets_leak() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = sealed_state(tmp.path());

    let out = run_get(&dir, Some("cryptile=trace"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Tracing must actually be wired: span markers present. Against the
    // dead server the op fails at transport; the unlock + total spans
    // must still have been entered and closed.
    assert!(
        stderr.contains("cli_total") || stderr.contains("keyring_unlock"),
        "no span markers in stderr with RUST_LOG=cryptile=trace:\n{stderr}"
    );

    // No secret material anywhere in either stream.
    for stream in [&stdout, &stderr] {
        assert!(!stream.contains(PASSPHRASE), "passphrase leaked: {stream}");
        assert!(!stream.contains(MASTER), "master leaked: {stream}");
    }

    // And the test is not vacuous: the same invocation without RUST_LOG
    // must NOT emit span markers (default-off gate holds).
    let quiet = run_get(&dir, None);
    let quiet_err = String::from_utf8_lossy(&quiet.stderr);
    let quiet_out = String::from_utf8_lossy(&quiet.stdout);
    assert!(
        !quiet_err.contains("cli_total") && !quiet_err.contains("keyring_unlock"),
        "spans emitted without RUST_LOG: {quiet_err}"
    );
    assert!(!quiet_out.contains(PASSPHRASE));
}

#[test]
fn dead_server_get_still_exits_4_with_tracing_on() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = sealed_state(tmp.path());
    Command::cargo_bin("cryptile")
        .unwrap()
        .args([
            "--state-dir",
            dir.to_str().unwrap(),
            "get",
            "--passphrase-env",
            "CRYPTILE_TR_PASS",
            "--",
            "vw://shared/smtp#password",
        ])
        .env("CRYPTILE_TR_PASS", PASSPHRASE)
        .env("RUST_LOG", "cryptile=debug")
        .assert()
        .failure()
        .code(4);
}
