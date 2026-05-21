use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use frankenengine_node::security::threshold_sig::{
    PartialSignature, PreparsedThresholdConfig, PublicationArtifact, SignerKey, ThresholdConfig,
    sign, verify_threshold, verify_threshold_preparsed,
};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn extend_len_prefixed_field(msg: &mut Vec<u8>, value: &str) {
    let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    msg.extend_from_slice(&value_len.to_le_bytes());
    msg.extend_from_slice(value.as_bytes());
}

fn build_signing_message(artifact_id: &str, connector_id: &str, content_hash: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"threshold_sig_verify_v2:");
    extend_len_prefixed_field(&mut msg, artifact_id);
    extend_len_prefixed_field(&mut msg, connector_id);
    extend_len_prefixed_field(&mut msg, content_hash);
    msg
}

fn test_signing_key(i: u32) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"threshold_sig_bench_seed_v1:");
    hasher.update(i.to_le_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn build_case(
    count: usize,
) -> (
    ThresholdConfig,
    PublicationArtifact,
    PreparsedThresholdConfig,
) {
    let mut signer_keys = Vec::with_capacity(count);
    let mut signing_keys = Vec::with_capacity(count);

    for index in 0..count {
        let signing_key = test_signing_key(u32::try_from(index).unwrap_or(u32::MAX));
        let key_id = format!("signer-{index:02}");
        signer_keys.push(SignerKey {
            key_id: key_id.clone(),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        });
        signing_keys.push((key_id, signing_key));
    }

    let config = ThresholdConfig {
        threshold: u32::try_from(count).unwrap_or(u32::MAX),
        total_signers: u32::try_from(count).unwrap_or(u32::MAX),
        signer_keys: signer_keys.clone(),
    };

    let artifact_id = format!("artifact-{count}");
    let connector_id = "connector-bench";
    let content_hash = "content-hash-bench";

    let signatures: Vec<PartialSignature> = signing_keys
        .iter()
        .map(|(key_id, signing_key)| {
            sign(
                signing_key,
                key_id,
                &artifact_id,
                connector_id,
                content_hash,
            )
        })
        .collect();

    let artifact = PublicationArtifact {
        artifact_id,
        connector_id: connector_id.to_string(),
        content_hash: content_hash.to_string(),
        signatures,
    };

    let parsed = PreparsedThresholdConfig::from_config(config.clone())
        .expect("PreparsedThresholdConfig should construct from a valid ThresholdConfig");
    (config, artifact, parsed)
}

// The bench previously carried a bench-local `PreparsedThresholdConfig` +
// `verify_threshold_preparsed` clone authored before the production public
// API existed (see bd-98xo5.1.1 → 718af0e4 for the public-API promotion).
// Per bd-98xo5.1.3 the bench now drives the production
// `frankenengine_node::security::threshold_sig::{PreparsedThresholdConfig,
// verify_threshold_preparsed}` so the criterion regression target measures
// what production actually runs, not a divergent local reimplementation.
// Round-1 envelope from
// `tests/artifacts/perf/20260520T214003Z_franken_node_perf/criterion_raw/threshold_sig_verify.txt`:
// preparsed_keys/8 ≤ 436 µs (was 396.4 µs), preparsed_keys/32 ≤ 1772 µs
// (was 1611 µs) — both within the ±10 % envelope.

fn bench_verify_threshold(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold_sig_verify");
    group.sample_size(40);
    group.measurement_time(Duration::from_secs(5));

    for count in [8usize, 32usize] {
        let (config, artifact, parsed) = build_case(count);

        group.bench_with_input(
            BenchmarkId::new("current", count),
            &(&config, &artifact),
            |b, case| {
                b.iter(|| {
                    black_box(verify_threshold(
                        black_box(case.0),
                        black_box(case.1),
                        "bench-trace",
                        "2026-04-27T00:00:00Z",
                    ))
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("preparsed_keys", count),
            &(&parsed, &artifact),
            |b, case| {
                b.iter(|| {
                    black_box(verify_threshold_preparsed(
                        black_box(case.0),
                        black_box(case.1),
                        "bench-trace",
                        "2026-04-27T00:00:00Z",
                    ))
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_verify_threshold);
criterion_main!(benches);
