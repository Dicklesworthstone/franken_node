use std::collections::BTreeMap;

use frankenengine_verifier_sdk::SDK_VERSION;
use frankenengine_verifier_sdk::bundle::{
    BundleArtifact, REPLAY_BUNDLE_SCHEMA_VERSION, ReplayBundle, TimelineEvent, hash, seal,
    serialize, verify,
};
use serde_json::json;

#[test]
fn replay_bundle_serialization_and_hash_are_byte_stable() {
    let bundle = canonical_replay_bundle();

    let first_bytes = serialize(&bundle).expect("fixture should serialize");
    let second_bytes = serialize(&bundle).expect("fixture should serialize repeatedly");
    assert_eq!(first_bytes, second_bytes);

    let first_hash = hash(&first_bytes);
    let second_hash = hash(&second_bytes);
    assert_eq!(first_hash, second_hash);

    let verified = verify(&first_bytes).expect("fixture should verify");
    let verified_bytes = serialize(&verified).expect("verified bundle should reserialize");
    assert_eq!(first_bytes, verified_bytes);
    assert_eq!(bundle, verified);
}

#[test]
fn replay_bundle_verify_rejects_single_byte_mutation() {
    let bundle = canonical_replay_bundle();
    let original_bytes = serialize(&bundle).expect("fixture should serialize");
    let original_hash = hash(&original_bytes);

    let mut tampered_bytes = original_bytes.clone();
    let mutation_offset = find_subsequence(&tampered_bytes, b"quarantine")
        .expect("canonical fixture should contain the decision string");
    tampered_bytes[mutation_offset] = b'Q';

    assert_ne!(original_hash, hash(&tampered_bytes));
    assert!(verify(&tampered_bytes).is_err());
    assert_eq!(
        verify(&original_bytes).expect("original fixture should remain valid"),
        bundle
    );
}

fn canonical_replay_bundle() -> ReplayBundle {
    let evidence_json = br#"{"schema_version":"incident-evidence-v1","incident_id":"inc-2026-04-20-cross-substrate","trace_id":"trace-cross-substrate-0042","detector":"lockstep-divergence","policy_version":"strict@2026-04-20","events":[{"event_id":"evt-0001","event_type":"external_signal","decision":"quarantine"},{"event_id":"evt-0002","event_type":"policy_eval","decision":"quarantine"},{"event_id":"evt-0003","event_type":"extension_result","decision":"release_denied"}]}"#;
    let substrate_matrix = br#"substrate,engine_version,decision,receipt
node,frankenengine-node-0.1.0,quarantine,sha256:36b7
extension-host,frankenengine-extension-host-0.1.0,quarantine,sha256:36b7
federated-peer,frankenengine-node-0.1.0,quarantine,sha256:36b7
"#;
    let transcript =
        br#"{"sequence":1,"substrate":"node","event":"external_signal","decision":"quarantine"}
{"sequence":2,"substrate":"extension-host","event":"policy_eval","decision":"quarantine"}
{"sequence":3,"substrate":"federated-peer","event":"extension_result","decision":"release_denied"}
"#;

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "evidence/inc-2026-04-20-cross-substrate.json".to_string(),
        artifact("application/json", evidence_json),
    );
    artifacts.insert(
        "matrices/cross-substrate.csv".to_string(),
        artifact("text/csv", substrate_matrix),
    );
    artifacts.insert(
        "transcripts/replay.ndjson".to_string(),
        artifact("application/x-ndjson", transcript),
    );

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "domain".to_string(),
        "conformance/sdk/extensions/federation".to_string(),
    );
    metadata.insert("matrix".to_string(), "cross-substrate".to_string());
    metadata.insert("runtime_profile".to_string(), "strict".to_string());

    let mut bundle = ReplayBundle {
        schema_version: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "018f4c6e-69d5-7a52-9d4d-0f7ffab7c042".to_string(),
        incident_id: "inc-2026-04-20-cross-substrate".to_string(),
        created_at: "2026-04-20T14:05:00.000000Z".to_string(),
        policy_version: "strict@2026-04-20".to_string(),
        verifier_identity: "sdk-verifier-public-contract".to_string(),
        timeline: vec![
            TimelineEvent {
                sequence_number: 1,
                event_id: "evt-0001".to_string(),
                timestamp: "2026-04-20T14:05:00.000001Z".to_string(),
                event_type: "external_signal".to_string(),
                payload: json!({
                    "incident_id": "inc-2026-04-20-cross-substrate",
                    "signal": "cross_substrate_divergence",
                    "severity": "high"
                }),
                state_snapshot: json!({
                    "active_substrates": ["node", "extension-host", "federated-peer"],
                    "epoch": 42_u64,
                    "risk_gate": "strict"
                }),
                causal_parent: None,
                policy_version: "strict@2026-04-20".to_string(),
            },
            TimelineEvent {
                sequence_number: 2,
                event_id: "evt-0002".to_string(),
                timestamp: "2026-04-20T14:05:00.000450Z".to_string(),
                event_type: "policy_eval".to_string(),
                payload: json!({
                    "decision": "quarantine",
                    "rule_id": "policy.cross-substrate.lockstep",
                    "matched_receipts": 3_u64
                }),
                state_snapshot: json!({
                    "quarantine": true,
                    "release_window": "blocked"
                }),
                causal_parent: Some(1),
                policy_version: "strict@2026-04-20".to_string(),
            },
            TimelineEvent {
                sequence_number: 3,
                event_id: "evt-0003".to_string(),
                timestamp: "2026-04-20T14:05:00.000900Z".to_string(),
                event_type: "extension_result".to_string(),
                payload: json!({
                    "extension": "cross-substrate-verifier",
                    "decision": "release_denied",
                    "reason": "federated peer receipt requires quarantine"
                }),
                state_snapshot: json!({
                    "quarantine": true,
                    "federation_votes": {
                        "agree": 3_u64,
                        "disagree": 0_u64
                    }
                }),
                causal_parent: Some(2),
                policy_version: "strict@2026-04-20".to_string(),
            },
        ],
        initial_state_snapshot: json!({
            "baseline_epoch": 41_u64,
            "policy": "strict",
            "substrates": {
                "node": "frankenengine-node-0.1.0",
                "extension-host": "frankenengine-extension-host-0.1.0",
                "federated-peer": "frankenengine-node-0.1.0"
            }
        }),
        evidence_refs: vec![
            "evidence/inc-2026-04-20-cross-substrate.json".to_string(),
            "matrices/cross-substrate.csv".to_string(),
            "transcripts/replay.ndjson".to_string(),
        ],
        artifacts,
        metadata,
        integrity_hash: String::new(),
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
