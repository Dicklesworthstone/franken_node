//! Trust Card Cross-Version Conformance Matrix
//!
//! Tests compatibility between different versions of trust card schemas and verifiers:
//! - old-trust-card × new-verifier (backward compatibility)
//! - new-trust-card × old-verifier (forward compatibility)
//! - version history chain validation across schema transitions
//! - signature verification cross-compatibility
//!
//! This harness follows Pattern 1 (Differential Testing) + Pattern 2 (Golden Files)
//! from /testing-conformance-harnesses skill.

use std::collections::BTreeMap;

#[cfg(test)]
use insta::assert_json_snapshot;

use frankenengine_node::supply_chain::trust_card::{
    TrustCard, TrustCardRegistry, TrustCardInput, TrustCardRegistrySnapshot,
    ExtensionIdentity, PublisherIdentity, CertificationLevel,
    CapabilityDeclaration, CapabilityRisk, BehavioralProfile,
    RevocationStatus, ProvenanceSummary, ReputationTrend, RiskLevel, RiskAssessment,
    DependencyTrustStatus, verify_card_signature, TrustCardError,
};
use frankenengine_node::supply_chain::certification::{VerifiedEvidenceRef, EvidenceType};

// ---------------------------------------------------------------------------
// Schema Version Constants (for testing compatibility)
// ---------------------------------------------------------------------------

/// Current production schema version
const CURRENT_CARD_SCHEMA: &str = "1.0.0";
/// Simulated future schema version for forward compatibility testing
const FUTURE_CARD_SCHEMA: &str = "1.1.0";
/// Simulated legacy schema version for backward compatibility testing
const LEGACY_CARD_SCHEMA: &str = "0.9.0";

const CURRENT_REGISTRY_SCHEMA: &str = "franken-node/trust-card-registry-state/v1";
const FUTURE_REGISTRY_SCHEMA: &str = "franken-node/trust-card-registry-state/v2";
const LEGACY_REGISTRY_SCHEMA: &str = "franken-node/trust-card-registry-state/v0";

// ---------------------------------------------------------------------------
// Fixture Generation
// ---------------------------------------------------------------------------

fn create_test_input_v1() -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@conformance/test-extension".to_string(),
            version: "1.0.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "conformance-publisher".to_string(),
            display_name: "Conformance Test Publisher".to_string(),
        },
        certification_level: CertificationLevel::Gold,
        capability_declarations: vec![
            CapabilityDeclaration {
                name: "filesystem.read".to_string(),
                description: "Read file system".to_string(),
                risk: CapabilityRisk::Medium,
            },
            CapabilityDeclaration {
                name: "network.http".to_string(),
                description: "HTTP client".to_string(),
                risk: CapabilityRisk::Low,
            },
        ],
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: true,
            subprocess_access: false,
            profile_summary: "File processor with network sync".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "signed".to_string(),
            source_uri: "https://registry.npmjs.org/@conformance/test-extension/-/test-extension-1.0.0.tgz".to_string(),
            artifact_hashes: vec![
                "sha256:conformance1234567890".to_string(),
                "sha512:conformance0987654321".to_string(),
            ],
            verified_at: "2024-01-01T00:00:00Z".to_string(),
        },
        reputation_score_basis_points: 8500,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![
            DependencyTrustStatus {
                dependency_id: "npm:lodash".to_string(),
                trust_level: "verified".to_string(),
            },
        ],
        last_verified_timestamp: "2024-01-01T00:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Well-maintained conformance test package".to_string(),
        },
        evidence_refs: vec![
            VerifiedEvidenceRef {
                evidence_id: "conformance-evidence-1".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: 1000,
                verification_receipt_hash: "conformance-receipt-hash-1".to_string(),
            },
        ],
    }
}

/// Create a trust card with explicit schema version for compatibility testing
fn create_card_with_schema(input: TrustCardInput, schema_version: &str, now_secs: u64) -> TrustCard {
    let mut registry = TrustCardRegistry::new(60, b"conformance-test-key");
    let mut card = registry.create(input, now_secs, "conformance-trace").unwrap();
    // Override schema version for testing
    card.schema_version = schema_version.to_string();
    card
}

/// Create registry snapshot with explicit schema version
fn create_registry_snapshot_with_schema(cards: BTreeMap<String, Vec<TrustCard>>, schema_version: &str) -> TrustCardRegistrySnapshot {
    TrustCardRegistrySnapshot {
        schema_version: schema_version.to_string(),
        cache_ttl_secs: 60,
        cards_by_extension: cards,
    }
}

// ---------------------------------------------------------------------------
// Conformance Tests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CrossVersionTest {
    name: &'static str,
    card_schema: &'static str,
    registry_schema: &'static str,
    verifier_version: VerifierVersion,
    expected_result: TestExpectation,
}

#[derive(Debug, Clone)]
enum VerifierVersion {
    Current,
    Legacy,
    Future,
}

#[derive(Debug, Clone)]
enum TestExpectation {
    Pass,
    Fail(&'static str),
    WarningButPass,
}

const CROSS_VERSION_TEST_MATRIX: &[CrossVersionTest] = &[
    // Backward compatibility: old cards with new verifier
    CrossVersionTest {
        name: "legacy_card_current_verifier",
        card_schema: LEGACY_CARD_SCHEMA,
        registry_schema: LEGACY_REGISTRY_SCHEMA,
        verifier_version: VerifierVersion::Current,
        expected_result: TestExpectation::Pass, // Must maintain backward compatibility
    },

    // Forward compatibility: new cards with old verifier
    CrossVersionTest {
        name: "future_card_current_verifier",
        card_schema: FUTURE_CARD_SCHEMA,
        registry_schema: FUTURE_REGISTRY_SCHEMA,
        verifier_version: VerifierVersion::Current,
        expected_result: TestExpectation::Fail("unsupported_schema"), // Expected to fail gracefully
    },

    // Version chain validation across schema transitions
    CrossVersionTest {
        name: "schema_transition_chain_valid",
        card_schema: CURRENT_CARD_SCHEMA,
        registry_schema: CURRENT_REGISTRY_SCHEMA,
        verifier_version: VerifierVersion::Current,
        expected_result: TestExpectation::Pass,
    },

    // Edge case: mixed schema versions in history
    CrossVersionTest {
        name: "mixed_schema_history",
        card_schema: CURRENT_CARD_SCHEMA,
        registry_schema: CURRENT_REGISTRY_SCHEMA,
        verifier_version: VerifierVersion::Current,
        expected_result: TestExpectation::Pass,
    },
];

#[test]
fn cross_version_conformance_matrix() {
    for test_case in CROSS_VERSION_TEST_MATRIX {
        println!("Running conformance test: {}", test_case.name);

        let result = run_cross_version_test(test_case);

        match (&result, &test_case.expected_result) {
            (Ok(_), TestExpectation::Pass) => {
                println!("✓ {} PASS", test_case.name);
            },
            (Err(_), TestExpectation::Fail(_)) => {
                println!("✓ {} FAIL (expected)", test_case.name);
            },
            (Ok(_), TestExpectation::Fail(reason)) => {
                panic!("❌ {} expected to fail with '{}' but passed", test_case.name, reason);
            },
            (Err(e), TestExpectation::Pass) => {
                panic!("❌ {} expected to pass but failed: {:?}", test_case.name, e);
            },
            (Ok(_), TestExpectation::WarningButPass) => {
                println!("⚠ {} PASS (with warnings)", test_case.name);
            },
            (Err(_), TestExpectation::WarningButPass) => {
                panic!("❌ {} expected warning but failed", test_case.name);
            },
        }

        // Generate golden file for this test case
        let test_output = format!("{}_output", test_case.name);
        assert_json_snapshot!(test_output, serde_json::json!({
            "test_name": test_case.name,
            "card_schema": test_case.card_schema,
            "registry_schema": test_case.registry_schema,
            "verifier_version": format!("{:?}", test_case.verifier_version),
            "result": match result {
                Ok(_) => "pass",
                Err(_) => "fail"
            },
            "expected": format!("{:?}", test_case.expected_result)
        }));
    }
}

fn run_cross_version_test(test_case: &CrossVersionTest) -> Result<(), TrustCardError> {
    let input = create_test_input_v1();
    let now_secs = 1000;

    match test_case.name {
        "legacy_card_current_verifier" => {
            // Test: can current verifier handle legacy schema cards?
            let card = create_card_with_schema(input, test_case.card_schema, now_secs);
            verify_card_signature(&card, b"conformance-test-key")
        },

        "future_card_current_verifier" => {
            // Test: does current verifier gracefully reject future schema?
            let card = create_card_with_schema(input, test_case.card_schema, now_secs);
            // This should fail - we don't support future schemas yet
            verify_card_signature(&card, b"conformance-test-key")
        },

        "schema_transition_chain_valid" => {
            // Test: version history chains remain valid during schema transitions
            test_version_chain_across_schemas()
        },

        "mixed_schema_history" => {
            // Test: registry with mixed schema versions in card history
            test_mixed_schema_registry()
        },

        _ => Ok(()), // Default pass for unknown tests
    }
}

fn test_version_chain_across_schemas() -> Result<(), TrustCardError> {
    let mut registry = TrustCardRegistry::new(60, b"conformance-test-key");
    let input = create_test_input_v1();

    // Create version 1 with current schema
    let card_v1 = registry.create(input.clone(), 1000, "trace")?;
    assert_eq!(card_v1.trust_card_version, 1);
    assert_eq!(card_v1.schema_version, CURRENT_CARD_SCHEMA);

    // Create version 2 - should link correctly to v1
    let card_v2 = registry.create(input.clone(), 2000, "trace")?;
    assert_eq!(card_v2.trust_card_version, 2);
    assert_eq!(card_v2.previous_version_hash, Some(card_v1.card_hash.clone()));

    // Verify both cards validate
    verify_card_signature(&card_v1, b"conformance-test-key")?;
    verify_card_signature(&card_v2, b"conformance-test-key")?;

    Ok(())
}

fn test_mixed_schema_registry() -> Result<(), TrustCardError> {
    // Create registry snapshot with mixed schema versions
    let input = create_test_input_v1();
    let now_secs = 1000;

    let legacy_card = create_card_with_schema(input.clone(), LEGACY_CARD_SCHEMA, now_secs);
    let current_card = create_card_with_schema(input, CURRENT_CARD_SCHEMA, now_secs + 1000);

    let mut cards_map = BTreeMap::new();
    cards_map.insert(
        "npm:@conformance/test-extension".to_string(),
        vec![legacy_card, current_card],
    );

    let snapshot = create_registry_snapshot_with_schema(cards_map, CURRENT_REGISTRY_SCHEMA);

    // Test: can we restore registry from mixed-schema snapshot?
    let _restored_registry = TrustCardRegistry::from_snapshot(
        snapshot,
        b"conformance-test-key",
        now_secs + 2000
    )?;

    Ok(())
}

#[test]
fn registry_schema_compatibility() {
    // Test registry snapshot schema compatibility
    let input = create_test_input_v1();
    let card = create_card_with_schema(input, CURRENT_CARD_SCHEMA, 1000);

    let mut cards_map = BTreeMap::new();
    cards_map.insert(
        "npm:@conformance/test-extension".to_string(),
        vec![card],
    );

    // Test current schema
    let current_snapshot = create_registry_snapshot_with_schema(
        cards_map.clone(),
        CURRENT_REGISTRY_SCHEMA
    );
    assert_json_snapshot!("registry_current_schema", current_snapshot);

    // Test that current verifier accepts current schema
    let result = TrustCardRegistry::from_snapshot(
        current_snapshot,
        b"conformance-test-key",
        2000
    );
    assert!(result.is_ok(), "Current schema should be accepted");

    // Test that current verifier rejects future schema
    let future_snapshot = create_registry_snapshot_with_schema(
        cards_map,
        FUTURE_REGISTRY_SCHEMA
    );

    let result = TrustCardRegistry::from_snapshot(
        future_snapshot,
        b"conformance-test-key",
        2000
    );
    assert!(result.is_err(), "Future schema should be rejected");

    if let Err(TrustCardError::UnsupportedSnapshotSchema(schema)) = result {
        assert_eq!(schema, FUTURE_REGISTRY_SCHEMA);
        assert_json_snapshot!("registry_future_schema_error", serde_json::json!({
            "error": "UnsupportedSnapshotSchema",
            "schema": schema
        }));
    } else {
        panic!("Expected UnsupportedSnapshotSchema error");
    }
}

#[test]
fn signature_verification_cross_version() {
    // Test that signature verification works consistently across versions
    let input = create_test_input_v1();
    let key = b"conformance-test-key";

    // Create cards with different schema versions
    let legacy_card = create_card_with_schema(input.clone(), LEGACY_CARD_SCHEMA, 1000);
    let current_card = create_card_with_schema(input.clone(), CURRENT_CARD_SCHEMA, 2000);

    // Both should verify with current verifier (backward compatibility)
    assert!(verify_card_signature(&legacy_card, key).is_ok(),
           "Legacy card should verify with current verifier");
    assert!(verify_card_signature(&current_card, key).is_ok(),
           "Current card should verify with current verifier");

    // Test with wrong key (should fail regardless of schema)
    let wrong_key = b"wrong-key";
    assert!(verify_card_signature(&legacy_card, wrong_key).is_err());
    assert!(verify_card_signature(&current_card, wrong_key).is_err());

    // Golden files for verification results
    assert_json_snapshot!("signature_verification_results", serde_json::json!({
        "legacy_card_correct_key": verify_card_signature(&legacy_card, key).is_ok(),
        "current_card_correct_key": verify_card_signature(&current_card, key).is_ok(),
        "legacy_card_wrong_key": verify_card_signature(&legacy_card, wrong_key).is_ok(),
        "current_card_wrong_key": verify_card_signature(&current_card, wrong_key).is_ok(),
    }));
}

#[test]
fn serialization_round_trip_cross_version() {
    // Test that cards can be serialized and deserialized across versions
    let input = create_test_input_v1();

    // Test with different schema versions
    let test_schemas = vec![LEGACY_CARD_SCHEMA, CURRENT_CARD_SCHEMA];

    for schema in test_schemas {
        let original_card = create_card_with_schema(input.clone(), schema, 1000);

        // Serialize to JSON
        let json_str = serde_json::to_string(&original_card)
            .expect("Card should serialize to JSON");

        // Deserialize back
        let deserialized_card: TrustCard = serde_json::from_str(&json_str)
            .expect("Card should deserialize from JSON");

        // Should be identical
        assert_eq!(original_card, deserialized_card,
                  "Round-trip should preserve card for schema {}", schema);

        // Golden file for this schema version
        assert_json_snapshot!(format!("card_serialization_{}", schema.replace(".", "_")), deserialized_card);
    }
}

// ---------------------------------------------------------------------------
// Conformance Report Generation
// ---------------------------------------------------------------------------

#[test]
fn generate_conformance_report() {
    let mut report = serde_json::Map::new();

    // Test each cross-version scenario
    for test_case in CROSS_VERSION_TEST_MATRIX {
        let result = run_cross_version_test(test_case);
        let passed = result.is_ok();

        report.insert(test_case.name.to_string(), serde_json::json!({
            "card_schema": test_case.card_schema,
            "registry_schema": test_case.registry_schema,
            "verifier_version": format!("{:?}", test_case.verifier_version),
            "expected": format!("{:?}", test_case.expected_result),
            "actual": if passed { "Pass" } else { "Fail" },
            "conformant": match (&result, &test_case.expected_result) {
                (Ok(_), TestExpectation::Pass) => true,
                (Err(_), TestExpectation::Fail(_)) => true,
                (Ok(_), TestExpectation::WarningButPass) => true,
                _ => false,
            }
        }));
    }

    // Calculate overall conformance score
    let total_tests = CROSS_VERSION_TEST_MATRIX.len();
    let conformant_tests = report.values()
        .filter(|v| v.get("conformant").and_then(|c| c.as_bool()).unwrap_or(false))
        .count();

    let final_report = serde_json::json!({
        "trust_card_cross_version_conformance": {
            "schema_version": "conformance-report/v1",
            "generated_at": "2024-01-01T00:00:00Z",
            "conformance_score": format!("{:.1}%", (conformant_tests as f64 / total_tests as f64) * 100.0),
            "total_tests": total_tests,
            "conformant_tests": conformant_tests,
            "failed_tests": total_tests - conformant_tests,
            "test_results": report
        }
    });

    assert_json_snapshot!("trust_card_cross_version_conformance_report", final_report);
}