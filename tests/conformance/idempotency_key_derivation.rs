//! Conformance tests for bd-12n3 idempotency key derivation vectors.

#[path = "../../crates/franken-node/src/remote/computation_registry.rs"]
pub mod computation_registry_impl;

pub mod remote {
    pub use super::computation_registry_impl as computation_registry;
}

#[path = "../../crates/franken-node/src/remote/idempotency.rs"]
mod idempotency;

use idempotency::IdempotencyKeyDeriver;
use remote::computation_registry::{ComputationEntry, ComputationRegistry, RequiredCapability};
use serde::Deserialize;
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
    let mut registry = ComputationRegistry::init("trace-conformance");
    for name in [
        "core.remote_compute.v1",
        "core.audit.v1",
        "core.telemetry_export.v1",
    ] {
        registry
            .register(
                ComputationEntry {
                    name: name.to_string(),
                    description: "registered for conformance vectors".to_string(),
                    required_capabilities: vec![RequiredCapability::RemoteComputation],
                    input_schema: "{}".to_string(),
                    output_schema: "{}".to_string(),
                    registered_at_version: 1,
                },
                "trace-conformance",
            )
            .expect("valid registration");
    }
    registry
}

#[test]
fn published_idempotency_vectors_match_derivation() {
    let raw = fs::read_to_string(vector_path())
        .expect("idempotency vectors artifact must exist");
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
