// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! EncString type-2 decrypt bench. The vector is built in-place with the
//! same encrypt-then-MAC construction VW uses (AES-CBC + HMAC-SHA256),
//! fixed key/IV, so no fixture file is needed. NOT in CI.

use criterion::{criterion_group, criterion_main, Criterion};
use cryptile_vaultwarden::crypto::{EncString, EncStringType, SymmetricKey};

fn bench_type2_decrypt(c: &mut Criterion) {
    let key = SymmetricKey::from_parts([0x11u8; 32], [0x22u8; 32]);
    // 64-byte plaintext: representative of a cipher name/field payload.
    let pt = [0x5au8; 64];
    let iv = [0x33u8; 16];
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
    let enc = cbc::Encryptor::<aes::Aes256>::new_from_slices(key.enc_bytes(), &iv).unwrap();
    let ct = enc.encrypt_padded_vec::<Pkcs7>(&pt);

    // encrypt-then-MAC: HMAC(iv || ct) with the mac half
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.mac_bytes()).unwrap();
    mac.update(&iv);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes().to_vec();

    let es = EncString {
        kind: EncStringType::AesCbc256_HmacSha256_B64,
        iv: iv.to_vec(),
        ct,
        mac: Some(tag),
    };

    // sanity: decryption round-trips (bench must measure a working path)
    let check = es.decrypt_symmetric(&key).unwrap();
    assert_eq!(check.as_slice(), &pt);

    let mut group = c.benchmark_group("encstring");
    group.bench_function("decrypt_type2_64b", |b| {
        b.iter(|| {
            let out = es.decrypt_symmetric(&key).unwrap();
            std::hint::black_box(&out);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_type2_decrypt);
criterion_main!(benches);
