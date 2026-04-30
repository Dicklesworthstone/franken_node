//! Trust Card Extension ID Length Boundary Conformance Test (bd-173ds)
//!
//! Validates trust-card admission boundary for extension ID length per bd-2yh
//! specification. This conformance test ensures that the MAX_EXTENSION_ID_LEN
//! security boundary is enforced correctly during trust card admission.
//!
//! ## Specification Reference
//! - bd-2yh contract: docs/specs/section_10_4/bd-2yh_contract.md
//! - Security requirement: Extension ID length must be bounded to prevent DoS
//! - Boundary: MAX_EXTENSION_ID_LEN = 256 characters

use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    ExtensionIdentity, ProvenanceSummary, PublisherIdentity, ReputationTrend,
    RevocationStatus, RiskAssessment, RiskLevel, TrustCardInput, TrustCardRegistry,
};

const MAX_EXTENSION_ID_LEN: usize = 256;
const REGISTRY_KEY: &str = "extension-id-boundary-test-key";
const BASE_TIMESTAMP: u64 = 1745000000;

fn create_valid_baseline_input() -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@test/package".to_string(),
            version: "1.0.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "publisher:test".to_string(),
            display_name: "Test Publisher".to_string(),
        },
        certification_level: CertificationLevel::Bronze,
        capability_declarations: vec![
            CapabilityDeclaration {
                name: "fs.read".to_string(),
                description: "Reads configuration".to_string(),
                risk: CapabilityRisk::Low,
            },
        ],
        behavioral_profile: BehavioralProfile {
            network_access: false,
            filesystem_access: true,
            subprocess_access: false,
            profile_summary: "File reading only".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            verified_sources: vec!["test-source".to_string()],
            verification_timestamp: "2026-04-23T06:30:00Z".to_string(),
            chain_integrity_score: 95,
        },
        reputation_score_basis_points: 8500,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![],
        last_verified_timestamp: "2026-04-23T06:30:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            overall_risk: RiskLevel::Low,
            risk_factors: vec!["filesystem access".to_string()],
            mitigation_suggestions: vec!["Review file patterns".to_string()],
        },
        evidence_refs: vec![
            VerifiedEvidenceRef {
                evidence_id: "test-evidence-001".to_string(),
                evidence_type: EvidenceType::StaticAnalysis,
                verified_at_epoch: BASE_TIMESTAMP,
                verification_receipt_hash: "sha256:".to_string() + &"a".repeat(64),
            }
        ],
    }
}

#[test]
fn trust_card_extension_id_at_max_length_boundary_is_accepted() {
    // Test case: Extension ID exactly at MAX_EXTENSION_ID_LEN should be accepted
    let mut registry = TrustCardRegistry::new(300, REGISTRY_KEY.as_bytes());
    let mut input = create_valid_baseline_input();

    // Create extension ID exactly at the boundary (256 characters)
    input.extension.extension_id = "npm:@".to_string() + &"a".repeat(MAX_EXTENSION_ID_LEN - 5);
    assert_eq!(input.extension.extension_id.len(), MAX_EXTENSION_ID_LEN);

    let result = registry.create(input, BASE_TIMESTAMP, "trace-boundary-max");

    assert!(
        result.is_ok(),
        "Trust card with extension ID exactly at MAX_EXTENSION_ID_LEN ({}) should be accepted. \
         Error: {:?}",
        MAX_EXTENSION_ID_LEN,
        result.err()
    );
}

#[test]
fn trust_card_extension_id_just_under_max_length_is_accepted() {
    // Test case: Extension ID just under MAX_EXTENSION_ID_LEN should be accepted
    let mut registry = TrustCardRegistry::new(300, REGISTRY_KEY.as_bytes());
    let mut input = create_valid_baseline_input();

    // Create extension ID one character under the boundary (255 characters)
    input.extension.extension_id = "npm:@".to_string() + &"b".repeat(MAX_EXTENSION_ID_LEN - 6);
    assert_eq!(input.extension.extension_id.len(), MAX_EXTENSION_ID_LEN - 1);

    let result = registry.create(input, BASE_TIMESTAMP + 1, "trace-boundary-under");

    assert!(
        result.is_ok(),
        "Trust card with extension ID under MAX_EXTENSION_ID_LEN ({}) should be accepted. \
         Error: {:?}",
        MAX_EXTENSION_ID_LEN - 1,
        result.err()
    );
}

#[test]
fn trust_card_extension_id_exceeding_max_length_is_rejected() {
    // Test case: Extension ID exceeding MAX_EXTENSION_ID_LEN should be rejected
    let mut registry = TrustCardRegistry::new(300, REGISTRY_KEY.as_bytes());
    let mut input = create_valid_baseline_input();

    // Create extension ID exceeding the boundary (257 characters)
    input.extension.extension_id = "npm:@".to_string() + &"c".repeat(MAX_EXTENSION_ID_LEN - 4);
    assert_eq!(input.extension.extension_id.len(), MAX_EXTENSION_ID_LEN + 1);

    let result = registry.create(input, BASE_TIMESTAMP + 2, "trace-boundary-exceed");

    assert!(
        result.is_err(),
        "Trust card with extension ID exceeding MAX_EXTENSION_ID_LEN ({}) must be rejected",
        MAX_EXTENSION_ID_LEN + 1
    );

    let error_message = result.err().unwrap().to_string().to_lowercase();
    assert!(
        error_message.contains("extension") &&
        (error_message.contains("length") || error_message.contains("long") || error_message.contains("size")),
        "Error message should indicate extension ID length violation. Got: {}",
        error_message
    );
}

#[test]
fn trust_card_extension_id_significantly_exceeding_max_length_is_rejected() {
    // Test case: Extension ID significantly exceeding MAX_EXTENSION_ID_LEN should be rejected
    let mut registry = TrustCardRegistry::new(300, REGISTRY_KEY.as_bytes());
    let mut input = create_valid_baseline_input();

    // Create extension ID significantly exceeding the boundary (300 characters)
    input.extension.extension_id = "npm:@malicious-package/".to_string() + &"x".repeat(275);
    assert!(input.extension.extension_id.len() > MAX_EXTENSION_ID_LEN + 40);

    let result = registry.create(input, BASE_TIMESTAMP + 3, "trace-boundary-large");

    assert!(
        result.is_err(),
        "Trust card with significantly large extension ID ({} chars) must be rejected",
        input.extension.extension_id.len()
    );
}

#[test]
fn trust_card_extension_id_empty_string_is_rejected() {
    // Test case: Empty extension ID should be rejected (different boundary case)
    let mut registry = TrustCardRegistry::new(300, REGISTRY_KEY.as_bytes());
    let mut input = create_valid_baseline_input();

    input.extension.extension_id = "".to_string();

    let result = registry.create(input, BASE_TIMESTAMP + 4, "trace-boundary-empty");

    assert!(
        result.is_err(),
        "Trust card with empty extension ID must be rejected"
    );
}

#[test]
fn extension_id_length_boundary_conformance_report() {
    // Generate conformance report for extension ID length boundary testing
    let test_cases = vec![
        ("at-max-boundary", MAX_EXTENSION_ID_LEN, true),
        ("under-boundary", MAX_EXTENSION_ID_LEN - 1, true),
        ("exceed-boundary", MAX_EXTENSION_ID_LEN + 1, false),
        ("significantly-exceed", MAX_EXTENSION_ID_LEN + 50, false),
        ("empty-string", 0, false),
    ];

    let mut registry = TrustCardRegistry::new(300, REGISTRY_KEY.as_bytes());
    let mut results = Vec::new();

    for (i, (case_name, length, should_accept)) in test_cases.iter().enumerate() {
        let mut input = create_valid_baseline_input();

        // Generate extension ID of specified length
        input.extension.extension_id = if *length == 0 {
            "".to_string()
        } else {
            let prefix = "npm:@test/";
            let remaining = length.saturating_sub(prefix.len());
            prefix.to_string() + &"a".repeat(remaining)
        };

        let actual_length = input.extension.extension_id.len();
        let trace_id = format!("trace-report-{}", case_name);
        let result = registry.create(input, BASE_TIMESTAMP + i as u64 + 10, &trace_id);

        let test_passed = match (should_accept, result.is_ok()) {
            (true, true) => true,   // Should accept and did accept
            (false, false) => true, // Should reject and did reject
            _ => false,             // Mismatch
        };

        results.push((case_name, actual_length, should_accept, result.is_ok(), test_passed));

        if test_passed {
            eprintln!("✅ {}: {} chars - {}", case_name, actual_length,
                     if *should_accept { "accepted as expected" } else { "rejected as expected" });
        } else {
            eprintln!("❌ {}: {} chars - expected {}, got {}",
                     case_name, actual_length,
                     if *should_accept { "accept" } else { "reject" },
                     if result.is_ok() { "accept" } else { "reject" });
        }
    }

    let total_tests = results.len();
    let passed_tests = results.iter().filter(|(_, _, _, _, passed)| *passed).count();

    eprintln!("\n📋 Extension ID Length Boundary Conformance Report");
    eprintln!("Spec: docs/specs/section_10_4/bd-2yh_contract.md");
    eprintln!("Boundary: MAX_EXTENSION_ID_LEN = {}", MAX_EXTENSION_ID_LEN);
    eprintln!("Results: {}/{} tests passed", passed_tests, total_tests);

    if passed_tests == total_tests {
        eprintln!("🎉 All extension ID length boundary tests passed!");
    } else {
        panic!("Extension ID length boundary conformance failed: {}/{} tests passed",
               passed_tests, total_tests);
    }
}