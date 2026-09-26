// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Lock test for default-fidoh-backend: the CLI binary's default feature
//! set must carry the fidoh CTAP2 backend, so plain `cargo build` /
//! `cargo install` produces the fidoh binary. Parses Cargo.toml as text —
//! deliberately dependency-free (no toml crate added).

use std::path::Path;

#[test]
fn default_features_carry_fidoh_backend() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest).expect("read crates/cli/Cargo.toml");

    let section = text
        .split("[features]")
        .nth(1)
        .expect("[features] section in crates/cli/Cargo.toml");
    let line = section
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("default ="))
        .expect("default = line in [features]");

    assert_eq!(
        line.replace(' ', ""),
        r#"default=["fidoh"]"#,
        "crates/cli default feature set drifted: plain `cargo install` must keep \
         building the fidoh CTAP2 backend; the legacy stack is the explicit \
         escape hatch `--no-default-features --features webauthn`"
    );
}
