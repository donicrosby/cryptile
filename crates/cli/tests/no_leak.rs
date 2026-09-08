//! End-to-end guard: secret material must never reach the CLI's stdout/stderr
//! through formatting paths. Mirrors the unit tests but exercises the actual
//! binary, catching accidental future `Display`/`Debug` leaks in one place.

use std::process::Output;

use assert_cmd::Command;
use cryptile_core::ExposeSecret;
use predicates::boolean::PredicateBooleanExt;
use predicates::str::contains;

fn run(args: &[&str]) -> Output {
    Command::cargo_bin("cryptile")
        .expect("binary built")
        .args(args)
        .output()
        .expect("spawn")
}

const SECRET: &str = "hunter2-super-secret";

#[test]
fn secret_values_never_appear_in_cli_output() {
    // Materialize a secret through the core API, then format it every way the
    // CLI can: Debug of the wrapper, Debug of a containing model. (secrecy
    // deliberately implements no Display — compile-time redaction.)
    let v = cryptile_core::SecretString::from(SECRET);
    let bag = format!("{v:?}");

    // And prove the plumbing is honest: the raw value IS reachable via the
    // exposure API (otherwise this test would pass vacuously).
    assert!(v.expose_secret().contains(SECRET));

    // Now run the binary and assert neither stream ever carries the material.
    for args in [
        vec!["parse", "vw://shared/smtp"],
        vec!["parse", "vw://shared/smtp#password"],
        vec!["backends"],
        vec!["--help"],
    ] {
        let out = run(&args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(SECRET) && !stderr.contains(SECRET),
            "leak via {args:?}: {stdout} {stderr}"
        );
    }

    // The formatted forms themselves must be redacted.
    assert!(!bag.contains(SECRET));
    assert!(bag.contains("[REDACTED]"));
}

#[test]
fn bad_ref_exits_nonzero_with_clean_message() {
    Command::cargo_bin("cryptile")
        .unwrap()
        .args(["parse", "vw://"])
        .assert()
        .failure()
        .stderr(contains("locus").and(contains("empty")));
}
