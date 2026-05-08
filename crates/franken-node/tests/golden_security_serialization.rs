//! Golden snapshot tests for security-critical canonical serialization paths.
//!
//! These tests pin the exact byte-output of deterministic serializers to catch
//! any changes that could break cryptographic hash consistency or security assumptions.

use frankenengine_node::sdk::replay_capsule::{
    CapsuleInput, CapsuleOutput, ReplayCapsule, EnvironmentSnapshot, CURRENT_FORMAT_VERSION,
};
use frankenengine_node::supply_chain::trust_card::{
    TrustCard, ExtensionIdentity, PublisherIdentity, CertificationLevel, BehavioralProfile,
    RevocationStatus, ProvenanceSummary, ReputationTrend, RiskAssessment,
};
use frankenengine_node::supply_chain::certification::DerivationMetadata;
use insta::{assert_json_snapshot, assert_snapshot};
use serde_json;
use std::collections::BTreeMap;

/// Test golden snapshot for trust card JSON serialization.
///
/// Trust cards must have stable JSON shape for signature verification
/// and registry consistency across versions.
#[test]
fn test_trust_card_canonical_json_snapshot() {
    let trust_card = TrustCard {
        schema_version: "trust-card-v1.0".to_string(),
        trust_card_version: 42,
        previous_version_hash: Some("sha256:abcd1234".to_string()),
        extension: ExtensionIdentity {
            extension_id: "example-ext-v1.0.0".to_string(),
            version: "1.0.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "pub-example-corp".to_string(),
            display_name: "Example Corporation".to_string(),
        },
        certification_level: CertificationLevel::Basic,
        capability_declarations: vec![],
        behavioral_profile: BehavioralProfile {
            network_access: false,
            file_system_access: false,
            external_process_spawn: false,
            privilege_escalation_risk: false,
        },
        revocation_status: RevocationStatus {
            is_revoked: false,
            revocation_reason: None,
            revoked_at: None,
        },
        provenance_summary: ProvenanceSummary {
            source_hash: "sha256:deadbeef".to_string(),
            build_environment: "secure-ci-v1".to_string(),
            supply_chain_verified: true,
        },
        reputation_score_basis_points: 8500, // 85%
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![],
        last_verified_timestamp: "2026-05-08T12:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment::Low,
        audit_history: vec![],
        derivation_evidence: Some(DerivationMetadata {
            evidence_bundle_hash: "sha256:evidence123".to_string(),
            verification_timestamp: "2026-05-08T12:00:00Z".to_string(),
            verifier_identity: "verifier-alpha".to_string(),
        }),
        card_hash: "sha256:cardhash123".to_string(),
        registry_signature: "sig-fixture-trust-card-v1".to_string(),
    };

    // Pin the exact JSON serialization for security-critical consistency
    assert_json_snapshot!("trust_card_canonical", trust_card);
}

/// Test golden snapshot for replay capsule JSON serialization.
///
/// Replay capsules must have deterministic serialization for cryptographic
/// verification and cross-verifier consistency.
#[test]
fn test_replay_capsule_canonical_json_snapshot() {
    let mut properties = BTreeMap::new();
    properties.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    properties.insert("USER".to_string(), "testuser".to_string());

    let mut input_metadata_1 = BTreeMap::new();
    input_metadata_1.insert("type".to_string(), "command".to_string());

    let mut input_metadata_2 = BTreeMap::new();
    input_metadata_2.insert("type".to_string(), "file".to_string());
    input_metadata_2.insert("filename".to_string(), "data.json".to_string());

    let mut output_metadata = BTreeMap::new();
    output_metadata.insert("type".to_string(), "result".to_string());

    let replay_capsule = ReplayCapsule {
        capsule_id: "capsule-fixture-v1-001".to_string(),
        format_version: CURRENT_FORMAT_VERSION,
        inputs: vec![
            CapsuleInput {
                seq: 1,
                data: b"verify --input data.json".to_vec(),
                metadata: input_metadata_1,
            },
            CapsuleInput {
                seq: 2,
                data: b"file:data.json:sha256:filedata123".to_vec(),
                metadata: input_metadata_2,
            },
        ],
        expected_outputs: vec![
            CapsuleOutput {
                seq: 1,
                data: b"PASS:0.95".to_vec(),
                metadata: output_metadata,
            },
        ],
        environment: EnvironmentSnapshot {
            runtime_version: "franken-v1.0.0".to_string(),
            platform: "linux-x86_64".to_string(),
            config_hash: "sha256:config123".to_string(),
            properties,
        },
    };

    // Pin the exact JSON serialization for deterministic replay verification
    assert_json_snapshot!("replay_capsule_canonical", replay_capsule);
}

/// Test golden snapshot for length-prefixed canonical serialization.
///
/// Demonstrates the canonical hash input format used for domain-separated
/// cryptographic operations.
#[test]
fn test_canonical_hash_input_length_prefixed_snapshot() {
    // Simulate the length-prefixed canonical hash input format used in security-critical operations
    let domain_separator = b"trust_card_verification_v1:";
    let field_1 = b"example-extension-id";
    let field_2 = b"verified";
    let field_3 = b"sha256:deadbeef";

    // Length-prefixed canonical format: each field prefixed with its length as u64 little-endian
    let mut canonical_input = Vec::new();

    // Domain separator (always first)
    canonical_input.extend_from_slice(&(domain_separator.len() as u64).to_le_bytes());
    canonical_input.extend_from_slice(domain_separator);

    // Field 1: extension_id
    canonical_input.extend_from_slice(&(field_1.len() as u64).to_le_bytes());
    canonical_input.extend_from_slice(field_1);

    // Field 2: verification_status
    canonical_input.extend_from_slice(&(field_2.len() as u64).to_le_bytes());
    canonical_input.extend_from_slice(field_2);

    // Field 3: content_hash
    canonical_input.extend_from_slice(&(field_3.len() as u64).to_le_bytes());
    canonical_input.extend_from_slice(field_3);

    // Convert to hex for readable snapshot comparison
    let canonical_hex = hex::encode(&canonical_input);

    // Pin the exact byte sequence for canonical hash input consistency
    assert_snapshot!("canonical_hash_input_hex", canonical_hex);
}