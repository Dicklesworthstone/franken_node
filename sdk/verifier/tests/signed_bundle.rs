use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use frankenengine_verifier_sdk::SDK_VERSION;
use frankenengine_verifier_sdk::bundle::{
    BundleArtifact, BundleChunk, BundleError, BundleHeader, BundleSignature,
    REPLAY_BUNDLE_HASH_ALGORITHM, REPLAY_BUNDLE_SCHEMA_VERSION, ReplayBundle, TimelineEvent, hash,
    seal, sign_bundle, verify_signed_bundle,
};
use serde_json::json;

#[test]
fn signed_bundle_roundtrip_verifies_with_public_key() {
    let bundle = canonical_replay_bundle();
    let signing_key = signing_key(42);
    let signature = sign_bundle(&signing_key, &bundle);
    let signature_bytes = signature.to_bytes();

    verify_signed_bundle(&signing_key.verifying_key(), &bundle, &signature_bytes)
        .expect("signed canonical bundle should verify");
}

#[test]
fn signed_bundle_rejects_tampered_bundle() {
    let bundle = canonical_replay_bundle();
    let signing_key = signing_key(42);
    let signature = sign_bundle(&signing_key, &bundle);
    let signature_bytes = signature.to_bytes();

    let mut tampered = bundle.clone();
    tampered.metadata.insert(
        "operator_override".to_string(),
        "attempted-after-signature".to_string(),
    );
    seal(&mut tampered).expect("tampered bundle should remain structurally sealable");

    let err = verify_signed_bundle(&signing_key.verifying_key(), &tampered, &signature_bytes)
        .expect_err("tampered bundle must fail detached Ed25519 verification");
    assert_eq!(err, BundleError::Ed25519SignatureInvalid);
}

#[test]
fn signed_bundle_rejects_wrong_public_key() {
    let bundle = canonical_replay_bundle();
    let primary_key = signing_key(42);
    let wrong_key = signing_key(7).verifying_key();
    let signature = sign_bundle(&primary_key, &bundle);
    let signature_bytes = signature.to_bytes();

    let err = verify_signed_bundle(&wrong_key, &bundle, &signature_bytes)
        .expect_err("wrong public key must fail detached Ed25519 verification");
    assert_eq!(err, BundleError::Ed25519SignatureInvalid);
}

#[test]
fn signed_bundle_rejects_truncated_signature() {
    let bundle = canonical_replay_bundle();
    let signing_key = signing_key(42);
    let signature = sign_bundle(&signing_key, &bundle);
    let signature_bytes = signature.to_bytes();

    let err = verify_signed_bundle(
        &signing_key.verifying_key(),
        &bundle,
        &signature_bytes[..63],
    )
    .expect_err("truncated signature must fail before verification");
    assert_eq!(err, BundleError::Ed25519SignatureMalformed { length: 63 });
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn canonical_replay_bundle() -> ReplayBundle {
    let evidence_json = br#"{"schema_version":"incident-evidence-v1","incident_id":"inc-2026-04-20-signed","trace_id":"trace-signed-0042","detector":"sdk-ed25519-verifier","policy_version":"strict@2026-04-20","events":[{"event_id":"evt-0001","event_type":"external_signal","decision":"quarantine"},{"event_id":"evt-0002","event_type":"policy_eval","decision":"quarantine"}]}"#;
    let transcript =
        br#"{"sequence":1,"substrate":"node","event":"external_signal","decision":"quarantine"}
{"sequence":2,"substrate":"extension-host","event":"policy_eval","decision":"quarantine"}
"#;

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "evidence/inc-2026-04-20-signed.json".to_string(),
        artifact("application/json", evidence_json),
    );
    artifacts.insert(
        "transcripts/replay-signed.ndjson".to_string(),
        artifact("application/x-ndjson", transcript),
    );
    let chunks = chunks_from_artifacts(&artifacts);

    let mut metadata = BTreeMap::new();
    metadata.insert("domain".to_string(), "sdk/verifier".to_string());
    metadata.insert("posture".to_string(), "ed25519-signed".to_string());

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
        bundle_id: "018f4c6e-69d5-7a52-9d4d-0f7ffab7c123".to_string(),
        incident_id: "inc-2026-04-20-signed".to_string(),
        created_at: "2026-04-20T14:20:00.000000Z".to_string(),
        policy_version: "strict@2026-04-20".to_string(),
        verifier_identity: "sdk-verifier-ed25519-contract".to_string(),
        timeline: vec![
            TimelineEvent {
                sequence_number: 1,
                event_id: "evt-0001".to_string(),
                timestamp: "2026-04-20T14:20:00.000001Z".to_string(),
                event_type: "external_signal".to_string(),
                payload: json!({
                    "incident_id": "inc-2026-04-20-signed",
                    "signal": "detached_signature_required",
                    "severity": "high"
                }),
                state_snapshot: json!({
                    "active_substrates": ["node", "extension-host"],
                    "epoch": 45_u64,
                    "risk_gate": "strict"
                }),
                causal_parent: None,
                policy_version: "strict@2026-04-20".to_string(),
            },
            TimelineEvent {
                sequence_number: 2,
                event_id: "evt-0002".to_string(),
                timestamp: "2026-04-20T14:20:00.000450Z".to_string(),
                event_type: "policy_eval".to_string(),
                payload: json!({
                    "decision": "quarantine",
                    "rule_id": "policy.sdk.detached-signature",
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
            "baseline_epoch": 44_u64,
            "policy": "strict",
            "substrates": {
                "node": "frankenengine-node-0.1.0",
                "extension-host": "frankenengine-extension-host-0.1.0"
            }
        }),
        evidence_refs: vec![
            "evidence/inc-2026-04-20-signed.json".to_string(),
            "transcripts/replay-signed.ndjson".to_string(),
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
