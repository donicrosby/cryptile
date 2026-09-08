//! Keyring roundtrip + adversarial tests. Argon2id at 64 MiB per derivation,
//! so each test does as few seal/open cycles as possible.

use cryptile_core::keyring::{open, seal, Keyring, KeyringError};
use secrecy::SecretString;

fn pw(s: &str) -> SecretString {
    SecretString::from(s)
}

#[test]
fn seal_open_roundtrip() {
    let line = seal("{\"session\":\"abc\"}", &pw("correct horse")).unwrap();
    assert!(line.starts_with("crk1."));
    let back = open(&line, &pw("correct horse")).unwrap();
    assert_eq!(back.as_str(), "{\"session\":\"abc\"}");
}

#[test]
fn wrong_passphrase_is_tamper_not_format() {
    let line = seal("secret-json", &pw("right")).unwrap();
    match open(&line, &pw("wrong")) {
        Err(KeyringError::Tamper) => {}
        other => panic!("expected Tamper, got {other:?}"),
    }
}

#[test]
fn bit_flip_in_ciphertext_is_rejected() {
    let line = seal("secret-json", &pw("right")).unwrap();
    let parts: Vec<&str> = line.split('.').collect();
    // flip a char inside the ciphertext segment
    let ct = parts[3].to_string();
    let mut flipped = ct.clone();
    let idx = ct.len() / 2;
    flipped.replace_range(
        idx..idx + 1,
        if ct.as_bytes()[idx] == b'A' { "B" } else { "A" },
    );
    let tampered = format!(
        "{}.{}.{}.{}.{}",
        parts[0], parts[1], parts[2], flipped, parts[4]
    );
    match open(&tampered, &pw("right")) {
        Err(KeyringError::Tamper) => {}
        other => panic!("expected Tamper, got {other:?}"),
    }
}

#[test]
fn bad_magic_is_format_error() {
    match open("junk.no.pe.ms.here", &pw("x")) {
        Err(KeyringError::Format) => {}
        other => panic!("expected Format, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn saved_file_is_0600_and_loads_back() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("cryptile-keyring-test-{}", std::process::id()));
    let path = dir.join("keyring");
    let kr = Keyring::with_path(&path);
    kr.save("{\"at\":\"tok\"}", &pw("pass")).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "keyring must be 0600, got {:o}", mode);
    let back = kr.load(&pw("pass")).unwrap();
    assert_eq!(back.as_str(), "{\"at\":\"tok\"}");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(unix)]
#[test]
fn save_is_atomic_no_tmp_left_behind() {
    let dir = std::env::temp_dir().join(format!("cryptile-keyring-atomic-{}", std::process::id()));
    let path = dir.join("keyring");
    let kr = Keyring::with_path(&path);
    kr.save("one", &pw("p")).unwrap();
    kr.save("two", &pw("p")).unwrap();
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(entries.len(), 1, "temp file leaked: {entries:?}");
    let back = kr.load(&pw("p")).unwrap();
    assert_eq!(back.as_str(), "two");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}
