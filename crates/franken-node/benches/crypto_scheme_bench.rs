use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use frankenengine_node::crypto::{Ed25519Scheme, SignatureScheme};
use std::time::Duration;

fn bench_keypair() -> ([u8; 32], [u8; 32], SigningKey) {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let secret_key = signing_key.to_bytes();
    (public_key, secret_key, signing_key)
}

fn bench_payload(size: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size);
    for index in 0..size {
        payload.push((index % 251) as u8);
    }
    payload
}

fn benchmark_raw_signing(c: &mut Criterion) {
    let (_public_key, secret_key, direct_key) = bench_keypair();
    let mut group = c.benchmark_group("crypto_scheme_raw_sign");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    for size in [64_usize, 512, 4096] {
        let payload = bench_payload(size);
        group.bench_with_input(
            BenchmarkId::new("ed25519_dalek_direct", size),
            &payload,
            |b, msg| {
                b.iter(|| black_box(direct_key.sign(black_box(msg)).to_bytes()));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("ed25519_scheme_sign_raw", size),
            &payload,
            |b, msg| {
                b.iter(|| {
                    black_box(
                        Ed25519Scheme::sign_raw(black_box(&secret_key), black_box(msg)).unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

fn benchmark_raw_verification(c: &mut Criterion) {
    let (public_key, secret_key, direct_key) = bench_keypair();
    let verifying_key = direct_key.verifying_key();
    let mut group = c.benchmark_group("crypto_scheme_raw_verify");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    for size in [64_usize, 512, 4096] {
        let payload = bench_payload(size);
        let trait_signature = Ed25519Scheme::sign_raw(&secret_key, &payload).unwrap();
        let direct_signature = Signature::from_bytes(&trait_signature);

        group.bench_with_input(
            BenchmarkId::new("ed25519_dalek_direct", size),
            &payload,
            |b, msg| {
                b.iter(|| {
                    black_box(
                        verifying_key
                            .verify_strict(black_box(msg), black_box(&direct_signature))
                            .is_ok(),
                    )
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("ed25519_scheme_verify_raw", size),
            &payload,
            |b, msg| {
                b.iter(|| {
                    black_box(Ed25519Scheme::verify_raw(
                        black_box(&public_key),
                        black_box(msg),
                        black_box(&trait_signature),
                    ))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_raw_signing, benchmark_raw_verification);
criterion_main!(benches);
