//! Conformance tests for bd-12n3 idempotency key derivation vectors.

use frankenengine_node::remote::computation_registry::{ComputationEntry, ComputationRegistry};
use frankenengine_node::remote::idempotency::{IdempotencyKeyDeriver, key_fingerprint};
use frankenengine_node::remote::idempotency_store::hash_payload;
use frankenengine_node::security::remote_cap::RemoteOperation;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const VECTOR_REL: &str = "artifacts/10.14/idempotency_vectors.json";

fn vector_path() -> std::path::PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut root = manifest.to_path_buf();
    loop {
        let candidate = root.join(VECTOR_REL);
        if candidate.exists() {
            return candidate;
        }
        if !root.pop() {
            break;
        }
    }
    std::path::PathBuf::from(VECTOR_REL)
}

#[derive(Debug, Deserialize)]
struct VectorBundle {
    vectors: Vec<IdempotencyVector>,
}

#[derive(Debug, Deserialize)]
struct IdempotencyVector {
    computation_name: String,
    epoch: u64,
    request_bytes_hex: String,
    expected_key_hex: String,
}

fn demo_registry() -> ComputationRegistry {
    let mut registry = ComputationRegistry::new(1, "trace-conformance");
    for name in [
        "core.remote_compute.v1",
        "core.audit.v1",
        "core.telemetry_export.v1",
    ] {
        registry
            .register_computation(
                ComputationEntry {
                    name: name.to_string(),
                    description: "registered for conformance vectors".to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: "{}".to_string(),
                    output_schema: "{}".to_string(),
                },
                "trace-conformance",
            )
            .expect("valid registration");
    }
    registry
}

#[test]
fn published_idempotency_vectors_match_derivation() {
    let raw = fs::read_to_string(vector_path()).expect("idempotency vectors artifact must exist");
    let bundle: VectorBundle = serde_json::from_str(&raw).expect("vector json must parse");
    assert!(
        bundle.vectors.len() >= 20,
        "expected at least 20 vectors, got {}",
        bundle.vectors.len()
    );

    let deriver = IdempotencyKeyDeriver::default();
    let mut registry = demo_registry();

    for vector in bundle.vectors {
        let payload = hex::decode(&vector.request_bytes_hex).expect("payload hex");
        let key = deriver
            .derive_registered_key(
                &mut registry,
                &vector.computation_name,
                vector.epoch,
                &payload,
                "trace-vector",
            )
            .expect("vector derivation should pass");
        assert_eq!(
            key.to_hex(),
            vector.expected_key_hex,
            "vector mismatch for computation={} epoch={}",
            vector.computation_name,
            vector.epoch
        );
    }
}

#[test]
fn derivation_enforces_domain_and_epoch_separation() {
    let deriver = IdempotencyKeyDeriver::default();
    let payload = br#"{"resource":"alpha","nonce":7}"#;
    let key_a = deriver
        .derive_key("core.remote_compute.v1", 42, payload)
        .expect("derive key a");
    let key_b = deriver
        .derive_key("core.audit.v1", 42, payload)
        .expect("derive key b");
    let key_c = deriver
        .derive_key("core.remote_compute.v1", 43, payload)
        .expect("derive key c");

    assert_ne!(key_a, key_b, "domain separation failed");
    assert_ne!(key_a, key_c, "epoch binding failed");
}

#[test]
fn payload_hash_and_fingerprint_use_length_prefixed_hash_inputs() {
    let payload = b"payload-with:idempotency-prefix";
    let mut expected_payload = Sha256::new();
    expected_payload.update(b"idempotency_payload_v1:");
    expected_payload.update(
        u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    expected_payload.update(payload);
    let legacy_payload = hex::encode(
        Sha256::digest([b"idempotency_payload_v1:" as &[u8], payload].concat())
    );

    assert_eq!(
        hash_payload(payload),
        hex::encode(expected_payload.finalize())
    );
    assert_ne!(hash_payload(payload), legacy_payload);

    let key = IdempotencyKeyDeriver::default()
        .derive_key("core.remote_compute.v1", 42, payload)
        .expect("derive key");
    let mut expected_fingerprint = Sha256::new();
    expected_fingerprint.update(b"idempotency_fingerprint_v1:");
    expected_fingerprint.update(
        u64::try_from(key.as_bytes().len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    expected_fingerprint.update(key.as_bytes());
    let legacy_fingerprint =
        Sha256::digest([b"idempotency_fingerprint_v1:" as &[u8], key.as_bytes()].concat());

    assert_eq!(
        key_fingerprint(&key),
        format!("fp:{}", &hex::encode(expected_fingerprint.finalize())[..16])
    );
    assert_ne!(
        key_fingerprint(&key),
        format!("fp:{}", &hex::encode(legacy_fingerprint)[..16])
    );
}

#[test]
fn collision_check_10k_is_clean() {
    let deriver = IdempotencyKeyDeriver::default();
    let payloads = (0_u64..10_000)
        .map(|i| {
            let mut v = vec![0_u8; 16];
            v[..8].copy_from_slice(&i.to_be_bytes());
            v[8..].copy_from_slice(&(i.wrapping_mul(977)).to_be_bytes());
            v
        })
        .collect::<Vec<_>>();
    let collisions = deriver
        .collision_count("core.remote_compute.v1", 9, &payloads)
        .expect("collision check should execute");
    assert_eq!(collisions, 0, "expected zero collisions for 10k samples");
}

fn legacy_separator_framing(
    prefix: &[u8],
    computation_name: &str,
    epoch: u64,
    request_bytes: &[u8],
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(prefix);
    input.push(0x1f);
    input.extend_from_slice(computation_name.as_bytes());
    input.push(0x1f);
    input.extend_from_slice(&epoch.to_be_bytes());
    input.push(0x1f);
    input.extend_from_slice(request_bytes);
    input
}

#[test]
fn separator_collision_inputs_do_not_alias_after_derivation_fix() {
    let deriver = IdempotencyKeyDeriver::default();
    let computation_a = "core.remote_compute.v1";
    let computation_b = "core.remote_compute.v1\u{1f}\0\0\0\0\0\0\0\0\u{1f}suffix";
    let request_a = b"suffix\x1f\0\0\0\0\0\0\0\x01\x1frest";
    let request_b = b"rest";

    let legacy_a = legacy_separator_framing(
        frankenengine_node::remote::idempotency::IDEMPOTENCY_DOMAIN_PREFIX,
        computation_a,
        0,
        request_a,
    );
    let legacy_b = legacy_separator_framing(
        frankenengine_node::remote::idempotency::IDEMPOTENCY_DOMAIN_PREFIX,
        computation_b,
        1,
        request_b,
    );
    assert_eq!(legacy_a, legacy_b, "legacy framing should collide here");

    let key_a = deriver
        .derive_key(computation_a, 0, request_a)
        .expect("derive key a");
    let key_b = deriver
        .derive_key(computation_b, 1, request_b)
        .expect("derive key b");
    assert_ne!(key_a, key_b, "fixed derivation must not alias");
}

#[test]
fn registry_rejection_happens_before_derivation() {
    let deriver = IdempotencyKeyDeriver::default();
    let mut registry = demo_registry();
    let err = deriver
        .derive_registered_key(
            &mut registry,
            "unknown.operation.v1",
            1,
            b"payload",
            "trace-registry-reject",
        )
        .expect_err("unknown computation should fail");
    let rendered = err.to_string();
    assert!(
        rendered.contains("IK_ERR_REGISTRY_REJECTED"),
        "expected registry rejection code in error: {rendered}"
    );
}
