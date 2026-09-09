// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Crypto micro-benches. NOT in CI (`cargo bench` is a local tool; see
//! BENCHMARKS.md). Argon2 dominates runtime (~76 ms/op at t=3/m=64MiB/p=4),
//! so sample counts are cut to keep the whole suite inside ~2 minutes.

use criterion::{criterion_group, criterion_main, Criterion};
use secrecy::SecretString;

fn bench_seal_open(c: &mut Criterion) {
    let payload = r#"{"access_token":"t","user_key_b64":"AAAA"}"#;
    let pass = SecretString::from("bench-passphrase-not-a-secret");
    let mut group = c.benchmark_group("keyring");
    // seal: fresh salt+iv each call + Argon2 derive (the expensive part)
    group.sample_size(10);
    group.bench_function("seal", |b| {
        b.iter(|| {
            let line = cryptile_core::keyring::seal(payload, &pass).unwrap();
            std::hint::black_box(&line);
        })
    });
    // open: one Argon2 derive + AES decrypt + MAC verify
    let line = cryptile_core::keyring::seal(payload, &pass).unwrap();
    group.bench_function("open", |b| {
        b.iter(|| {
            let pt = cryptile_core::keyring::open(&line, &pass).unwrap();
            std::hint::black_box(pt.as_str());
        })
    });
    group.finish();
}

criterion_group!(benches, bench_seal_open);
criterion_main!(benches);
