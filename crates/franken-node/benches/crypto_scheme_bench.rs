use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use frankenengine_node::crypto::{
    Ed25519PreparsedSigner, Ed25519PreparsedVerifier, Ed25519Scheme, SignatureScheme,
};
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
    // Preparsed signer is built ONCE outside the per-iter loop — this is the
    // whole point of the bd-98xo5.2 optimisation: amortise the
    // SHA-512 + basepoint scalar mult done by `SigningKey::from_bytes`
    // across many signatures rather than paying it per call.
    let preparsed_signer = Ed25519PreparsedSigner::from_secret_bytes(&secret_key);
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
        // bd-98xo5.2.5: documents the preparsed-handle path. Round-1
        // baseline at tests/artifacts/perf/20260520T214003Z_franken_node_perf/
        // criterion_raw/crypto_scheme.txt showed ed25519_scheme_sign_raw/64
        // at 45.69 µs against a 23.86 µs dalek_direct floor (+21.83 µs of
        // pure key-parsing overhead). With the preparsed handle the parse
        // happens once at construction (outside the iter loop), so this
        // case should approach the dalek_direct floor — the bead's T2
        // target is ≤ 26 µs at the 64 B size, i.e. ≥ 43 % of the wrapper
        // overhead removed.
        group.bench_with_input(
            BenchmarkId::new("ed25519_preparsed_sign", size),
            &payload,
            |b, msg| {
                b.iter(|| black_box(preparsed_signer.sign_raw(black_box(msg))));
            },
        );
    }

    group.finish();
}

fn benchmark_raw_verification(c: &mut Criterion) {
    let (public_key, secret_key, direct_key) = bench_keypair();
    let verifying_key = direct_key.verifying_key();
    // Preparsed verifier is built ONCE outside the per-iter loop — the
    // Edwards-point decompression cost is paid at construction, not per
    // call. Round-1 baseline showed the wrapper added +6 µs / call over
    // dalek_direct (53.30 µs vs 47.25 µs at 64 B); the bead's T2 target
    // is ≤ 48.50 µs for the preparsed path, i.e. nearly all wrapper
    // overhead removed.
    let preparsed_verifier =
        Ed25519PreparsedVerifier::from_public_bytes(&public_key).expect("valid public key");
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
        // bd-98xo5.2.5: preparsed verifier path. The verifying_key handle
        // is constructed once at the top of this function and reused
        // across every iter, matching how production call sites that hold
        // a long-lived `Ed25519PreparsedVerifier` (e.g. supply-chain key
        // ring, fleet trust anchors, capability replay window) re-use it
        // for every verify decision.
        group.bench_with_input(
            BenchmarkId::new("ed25519_preparsed_verify", size),
            &payload,
            |b, msg| {
                b.iter(|| {
                    black_box(preparsed_verifier.verify_raw(black_box(msg), &trait_signature))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_raw_signing, benchmark_raw_verification);
criterion_main!(benches);
