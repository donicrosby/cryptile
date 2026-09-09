//! CLI boundary tests: refs, login state gating, non-TTY refusals.
//! Full get/list e2e needs a TTY for the keyring passphrase (by design);
//! the boundary itself is what these tests pin down.

use assert_cmd::Command;
use predicates::str::contains;

fn cryptile() -> Command {
    let mut c = Command::cargo_bin("cryptile").unwrap();
    c.env_remove("XDG_CONFIG_HOME");
    c
}

#[test]
fn parse_prints_components() {
    cryptile()
        .arg("parse")
        .arg("vw://shared/smtp#username")
        .assert()
        .success()
        .stdout("scheme=vw\nlocus=shared/smtp\nfield=username\n");
}

#[test]
fn parse_rejects_garbage_with_exit_2() {
    cryptile()
        .arg("parse")
        .arg("no-scheme-here")
        .assert()
        .failure()
        .code(2)
        .stderr(contains("error"));
}

#[test]
fn get_without_login_is_exit_3_not_logged_in() {
    let tmp = tempfile::tempdir().unwrap();
    cryptile()
        .arg("--state-dir")
        .arg(tmp.path())
        .arg("get")
        .arg("vw://shared/smtp")
        .assert()
        .failure()
        .code(3)
        .stderr(contains("not logged in"));
}

#[test]
fn get_with_state_but_no_tty_refuses_passphrase_prompt() {
    // state exists (config + sealed keyring written via the library), but
    // tests run without a TTY: the passphrase prompt must refuse, not hang.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("state");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        r#"{"server":"http://127.0.0.1:1","account":"a@b.c"}"#,
    )
    .unwrap();
    // sealed with a throwaway passphrase; content irrelevant here
    let line = cryptile_core::keyring::seal("{}", &secrecy::SecretString::from("x")).unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();

    cryptile()
        .env("XDG_CONFIG_HOME", "") // ensure default path not consulted
        .arg("--state-dir")
        .arg(&dir)
        .arg("get")
        .arg("vw://shared/smtp")
        .assert()
        .failure()
        .code(3)
        .stderr(contains("no passphrase path"));
}

#[test]
fn login_without_tty_refuses_master_password_prompt() {
    let tmp = tempfile::tempdir().unwrap();
    cryptile()
        .arg("--state-dir")
        .arg(tmp.path())
        .arg("login")
        .arg("--server")
        .arg("http://127.0.0.1:1")
        .arg("--account")
        .arg("a@b.c")
        .assert()
        .failure()
        .code(2)
        .stderr(contains("refusing"));
}

#[test]
fn list_without_login_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    cryptile()
        .arg("--state-dir")
        .arg(tmp.path())
        .arg("list")
        .assert()
        .failure()
        .code(3)
        .stderr(contains("not logged in"));
}

#[test]
fn backends_lists_linked_backends() {
    cryptile().arg("backends").assert().success().stdout("vw\n");
}

// --- --passphrase-env on get/list (machine path for the Hermes plugin) ---

fn state_with_sealed_keyring() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("state");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        r#"{"server":"http://127.0.0.1:1","account":"a@b.c"}"#,
    )
    .unwrap();
    let line = cryptile_core::keyring::seal("{}", &secrecy::SecretString::from("x")).unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();
    (tmp, dir)
}

#[test]
fn get_passphrase_env_unset_var_is_exit_3() {
    let (tmp, dir) = state_with_sealed_keyring();
    cryptile()
        .env_remove("CRYPTILE_TEST_PASS")
        .arg("--state-dir")
        .arg(&dir)
        .arg("get")
        .arg("vw://shared/smtp#password")
        .arg("--passphrase-env")
        .arg("CRYPTILE_TEST_PASS")
        .assert()
        .failure()
        .code(3)
        .stderr(contains("is not set"));
    drop(tmp);
}

#[test]
fn get_passphrase_env_wrong_value_is_exit_3() {
    let (tmp, dir) = state_with_sealed_keyring();
    cryptile()
        .env("CRYPTILE_TEST_PASS", "definitely-wrong")
        .arg("--state-dir")
        .arg(&dir)
        .arg("get")
        .arg("vw://shared/smtp#password")
        .arg("--passphrase-env")
        .arg("CRYPTILE_TEST_PASS")
        .assert()
        .failure()
        .code(3);
    drop(tmp);
}

#[test]
fn get_passphrase_env_valid_session_reaches_transport_exit_4() {
    // A well-formed VW session handle sealed under passphrase "x": unseal
    // AND deserialize succeed, then http://127.0.0.1:1 refuses the
    // connection — exit 4. Proves the whole env-var path end to end.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("state");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        r#"{"server":"http://127.0.0.1:1","account":"a@b.c"}"#,
    )
    .unwrap();
    // 64 zero bytes, base64: valid key shape, so deserialization succeeds and
    // the op proceeds to the (refused) transport call.
    let session_json = r#"{"access_token":"t","user_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}"#;
    let line =
        cryptile_core::keyring::seal(session_json, &secrecy::SecretString::from("x")).unwrap();
    std::fs::write(dir.join("keyring"), line).unwrap();

    cryptile()
        .env("CRYPTILE_TEST_PASS", "x")
        .arg("--state-dir")
        .arg(&dir)
        .arg("get")
        .arg("vw://shared/smtp#password")
        .arg("--passphrase-env")
        .arg("CRYPTILE_TEST_PASS")
        .assert()
        .failure()
        .code(4);
    drop(tmp);
}
