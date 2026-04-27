use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use frankenengine_node::security::threshold_sig::{
    PartialSignature, PublicationArtifact, SignerKey, ThresholdConfig, sign, verify_threshold,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

fn build_signing_message(content_hash: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"threshold_sig_verify_v1:");
    let content_hash_len = u64::try_from(content_hash.len()).unwrap_or(u64::MAX);
    msg.extend_from_slice(&content_hash_len.to_le_bytes());
    msg.extend_from_slice(content_hash.as_bytes());
    msg
}

fn test_signing_key(i: u32) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"threshold_sig_bench_seed_v1:");
    hasher.update(i.to_le_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn build_case(count: usize) -> (ThresholdConfig, PublicationArtifact, PreparsedThresholdConfig) {
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

    let signatures: Vec<PartialSignature> = signing_keys
        .iter()
        .map(|(key_id, signing_key)| sign(signing_key, key_id, "content-hash-bench"))
        .collect();

    let artifact = PublicationArtifact {
        artifact_id: format!("artifact-{count}"),
        connector_id: "connector-bench".to_string(),
        content_hash: "content-hash-bench".to_string(),
        signatures,
    };

    let parsed = PreparsedThresholdConfig::new(&config);
    (config, artifact, parsed)
}

struct PreparsedThresholdConfig {
    threshold: u32,
    verifying_keys: BTreeMap<String, VerifyingKey>,
}

impl PreparsedThresholdConfig {
    fn new(config: &ThresholdConfig) -> Self {
        let mut verifying_keys = BTreeMap::new();
        for signer in &config.signer_keys {
            let bytes = hex::decode(&signer.public_key_hex).expect("public key hex should decode");
            let array: [u8; 32] = bytes.try_into().expect("ed25519 public key length");
            let verifying_key =
                VerifyingKey::from_bytes(&array).expect("public key bytes should parse");
            verifying_keys.insert(signer.key_id.clone(), verifying_key);
        }

        Self {
            threshold: config.threshold,
            verifying_keys,
        }
    }
}

fn verify_threshold_preparsed(
    config: &PreparsedThresholdConfig,
    artifact: &PublicationArtifact,
) -> bool {
    let message = build_signing_message(&artifact.content_hash);
    let mut valid_count = 0u32;
    let mut seen_signers: BTreeSet<&str> = BTreeSet::new();
    let mut seen_key_ids: BTreeSet<&str> = BTreeSet::new();

    for sig in &artifact.signatures {
        if sig.signer_id != sig.key_id {
            continue;
        }

        let Some(verifying_key) = config.verifying_keys.get(sig.key_id.as_str()) else {
            continue;
        };

        if sig.signature_hex.len() != 128 {
            continue;
        }

        let Ok(sig_bytes) = hex::decode(&sig.signature_hex) else {
            continue;
        };
        let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes) else {
            continue;
        };
        let signature = Signature::from_bytes(&sig_array);
        if verifying_key.verify_strict(&message, &signature).is_err() {
            continue;
        }

        if !seen_key_ids.insert(sig.key_id.as_str()) {
            continue;
        }

        if !seen_signers.insert(sig.signer_id.as_str()) {
            continue;
        }

        valid_count = valid_count.saturating_add(1);
    }

    valid_count >= config.threshold
}

fn bench_verify_threshold(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold_sig_verify");
    group.sample_size(40);
    group.measurement_time(Duration::from_secs(5));

    for count in [8usize, 32usize] {
        let (config, artifact, parsed) = build_case(count);

        group.bench_with_input(BenchmarkId::new("current", count), &(&config, &artifact), |b, case| {
            b.iter(|| {
                black_box(verify_threshold(
                    black_box(case.0),
                    black_box(case.1),
                    "bench-trace",
                    "2026-04-27T00:00:00Z",
                ))
            })
        });

        group.bench_with_input(
            BenchmarkId::new("preparsed_keys", count),
            &(&parsed, &artifact),
            |b, case| {
                b.iter(|| {
                    black_box(verify_threshold_preparsed(
                        black_box(case.0),
                        black_box(case.1),
                    ))
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_verify_threshold);
criterion_main!(benches);
