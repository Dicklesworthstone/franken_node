use std::collections::BTreeMap;

use frankenengine_verifier_sdk::SDK_VERSION;
use frankenengine_verifier_sdk::bundle::{
    BundleArtifact, BundleChunk, BundleError, BundleHeader, BundleSignature,
    REPLAY_BUNDLE_HASH_ALGORITHM, REPLAY_BUNDLE_SCHEMA_VERSION, ReplayBundle, TimelineEvent, hash,
    seal, serialize, verify,
};
use serde_json::json;

#[test]
fn verify_returns_typed_error_for_tampered_signature_bytes() {
    let bundle = canonical_replay_bundle();
    let mut bytes = serialize(&bundle).expect("fixture should serialize");
    let offset = find_subsequence(&bytes, bundle.signature.signature_hex.as_bytes())
        .expect("serialized fixture should contain signature bytes");
    bytes[offset] = if bytes[offset] == b'a' { b'b' } else { b'a' };

    let err = verify(&bytes).expect_err("tampered signature must be rejected");
    assert!(matches!(err, BundleError::SignatureMismatch { .. }));
}

#[test]
fn verify_returns_typed_error_for_header_payload_length_mismatch() {
    let mut bundle = canonical_replay_bundle();
    bundle.header.payload_length_bytes = bundle
        .header
        .payload_length_bytes
        .checked_add(1)
        .expect("fixture length should allow one-byte mismatch");

    let err = verify_serialized(&bundle);
    assert!(matches!(err, BundleError::PayloadLengthMismatch { .. }));
}

#[test]
fn verify_returns_typed_error_for_wrong_hash_algorithm_tag() {
    let mut bundle = canonical_replay_bundle();
    bundle.header.hash_algorithm = "blake3".to_string();

    let err = verify_serialized(&bundle);
    assert!(matches!(
        err,
        BundleError::UnsupportedHashAlgorithm {
            expected,
            actual
        } if expected == REPLAY_BUNDLE_HASH_ALGORITHM && actual == "blake3"
    ));
}

#[test]
fn verify_returns_typed_error_for_corrupted_chunk_index() {
    let mut bundle = canonical_replay_bundle();
    bundle.chunks[1].chunk_index = 7;

    let err = verify_serialized(&bundle);
    assert!(matches!(
        err,
        BundleError::ChunkIndexMismatch {
            expected: 1,
            actual: 7
        }
    ));
}

#[test]
fn verify_returns_typed_error_for_non_monotonic_timestamps() {
    let mut bundle = canonical_replay_bundle();
    bundle.timeline[1].timestamp = "2026-04-20T14:09:59.000000Z".to_string();

    let err = verify_serialized(&bundle);
    assert!(matches!(
        err,
        BundleError::NonMonotonicTimestamp {
            previous,
            current,
            event_id
        } if previous == "2026-04-20T14:10:00.000001Z"
            && current == "2026-04-20T14:09:59.000000Z"
            && event_id == "evt-0002"
    ));
}

fn verify_serialized(bundle: &ReplayBundle) -> BundleError {
    let bytes = serialize(bundle).expect("mutated fixture should remain serializable");
    verify(&bytes).expect_err("mutated fixture must be rejected")
}

fn canonical_replay_bundle() -> ReplayBundle {
    let evidence_json = br#"{"schema_version":"incident-evidence-v1","incident_id":"inc-2026-04-20-negative","trace_id":"trace-negative-0042","detector":"lockstep-divergence","policy_version":"strict@2026-04-20","events":[{"event_id":"evt-0001","event_type":"external_signal","decision":"quarantine"},{"event_id":"evt-0002","event_type":"policy_eval","decision":"quarantine"}]}"#;
    let transcript =
        br#"{"sequence":1,"substrate":"node","event":"external_signal","decision":"quarantine"}
{"sequence":2,"substrate":"extension-host","event":"policy_eval","decision":"quarantine"}
"#;

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "evidence/inc-2026-04-20-negative.json".to_string(),
        artifact("application/json", evidence_json),
    );
    artifacts.insert(
        "transcripts/replay-negative.ndjson".to_string(),
        artifact("application/x-ndjson", transcript),
    );
    let chunks = chunks_from_artifacts(&artifacts);

    let mut metadata = BTreeMap::new();
    metadata.insert("domain".to_string(), "sdk/verifier".to_string());
    metadata.insert("posture".to_string(), "adversarial-negative".to_string());

    let mut bundle = ReplayBundle {
        header: BundleHeader {
            hash_algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            payload_length_bytes: payload_length_bytes(&artifacts),
            chunk_count: chunks
                .len()
                .try_into()
                .expect("fixture chunk count should fit u32"),
        },
        schema_version: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "018f4c6e-69d5-7a52-9d4d-0f7ffab7c099".to_string(),
        incident_id: "inc-2026-04-20-negative".to_string(),
        created_at: "2026-04-20T14:10:00.000000Z".to_string(),
        policy_version: "strict@2026-04-20".to_string(),
        verifier_identity: "verifier://sdk-negative-contract".to_string(),
        timeline: vec![
            TimelineEvent {
                sequence_number: 1,
                event_id: "evt-0001".to_string(),
                timestamp: "2026-04-20T14:10:00.000001Z".to_string(),
                event_type: "external_signal".to_string(),
                payload: json!({
                    "incident_id": "inc-2026-04-20-negative",
                    "signal": "cross_substrate_divergence",
                    "severity": "high"
                }),
                state_snapshot: json!({
                    "active_substrates": ["node", "extension-host"],
                    "epoch": 44_u64,
                    "risk_gate": "strict"
                }),
                causal_parent: None,
                policy_version: "strict@2026-04-20".to_string(),
            },
            TimelineEvent {
                sequence_number: 2,
                event_id: "evt-0002".to_string(),
                timestamp: "2026-04-20T14:10:00.000450Z".to_string(),
                event_type: "policy_eval".to_string(),
                payload: json!({
                    "decision": "quarantine",
                    "rule_id": "policy.cross-substrate.lockstep",
                    "matched_receipts": 2_u64
                }),
                state_snapshot: json!({
                    "quarantine": true,
                    "release_window": "blocked"
                }),
                causal_parent: Some(1),
                policy_version: "strict@2026-04-20".to_string(),
            },
        ],
        initial_state_snapshot: json!({
            "baseline_epoch": 43_u64,
            "policy": "strict",
            "substrates": {
                "node": "frankenengine-node-0.1.0",
                "extension-host": "frankenengine-extension-host-0.1.0"
            }
        }),
        evidence_refs: vec![
            "evidence/inc-2026-04-20-negative.json".to_string(),
            "transcripts/replay-negative.ndjson".to_string(),
        ],
        artifacts,
        chunks,
        metadata,
        integrity_hash: String::new(),
        signature: BundleSignature {
            algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            signature_hex: String::new(),
        },
    };
    seal(&mut bundle).expect("fixture should seal");
    bundle
}

fn artifact(media_type: &str, bytes: &[u8]) -> BundleArtifact {
    BundleArtifact {
        media_type: media_type.to_string(),
        digest: hash(bytes),
        bytes_hex: hex_encode(bytes),
    }
}

fn chunks_from_artifacts(artifacts: &BTreeMap<String, BundleArtifact>) -> Vec<BundleChunk> {
    let total_chunks = artifacts
        .len()
        .try_into()
        .expect("fixture chunk count should fit u32");
    artifacts
        .iter()
        .enumerate()
        .map(|(index, (path, artifact))| BundleChunk {
            chunk_index: index
                .try_into()
                .expect("fixture chunk index should fit u32"),
            total_chunks,
            artifact_path: path.clone(),
            payload_length_bytes: u64::try_from(artifact.bytes_hex.len() / 2)
                .expect("fixture artifact length should fit u64"),
            payload_digest: artifact.digest.clone(),
        })
        .collect()
}

fn payload_length_bytes(artifacts: &BTreeMap<String, BundleArtifact>) -> u64 {
    artifacts
        .values()
        .map(|artifact| {
            u64::try_from(artifact.bytes_hex.len() / 2)
                .expect("fixture artifact length should fit u64")
        })
        .sum()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
