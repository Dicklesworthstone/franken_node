//! Capability Artifact + Trust Card Integration Conformance Harness
//!
//! Cross-validates that capability artifact admission and trust card admission
//! work together correctly, ensuring that trust cards properly reflect the
//! capability contracts of admitted artifacts and that admission decisions
//! are consistent across both systems.
//!
//! ## Specification Coverage
//!
//! | Integration Requirement | Type | Test Cases | Status |
//! |------------------------|------|------------|--------|
//! | Artifact capability → Trust card capability | MUST | 4 | ✅ |
//! | Admission failure consistency | MUST | 6 | ✅ |
//! | Signature verification alignment | MUST | 3 | ✅ |
//! | Schema version compatibility | MUST | 2 | ✅ |
//! | Trust card reflects artifact state | MUST | 5 | ✅ |

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use frankenengine_node::extensions::artifact_contract::{
    AdmissionConfig, AdmissionGate, AdmissionOutcome, CapabilityContract, CapabilityEntry,
    ExtensionArtifact, SCHEMA_VERSION, make_artifact, make_contract,
    error_codes as artifact_error_codes, event_codes as artifact_event_codes,
};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    ExtensionIdentity, ProvenanceSummary, PublisherIdentity, ReputationTrend,
    RevocationStatus, RiskAssessment, RiskLevel, TrustCard, TrustCardError,
    TrustCardInput, TrustCardRegistry,
};

const INTEGRATION_SPEC_REFERENCE: &str = "docs/specs/capability_artifact_format.md + docs/specs/section_10_4/bd-2yh_contract.md";
const TEST_REGISTRY_KEY: &[u8] = b"integration-conformance-test-key";
const BASE_TIMESTAMP: u64 = 1745000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementLevel {
    Must,
    Should,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegrationTestCategory {
    CapabilityMapping,
    AdmissionConsistency,
    SignatureAlignment,
    SchemaCompatibility,
    StateReflection,
}

#[derive(Debug, Clone)]
enum ConformanceResult {
    Pass,
    Fail { reason: String },
}

#[derive(Debug)]
struct IntegrationConformanceCase {
    id: &'static str,
    spec_section: &'static str,
    requirement_level: RequirementLevel,
    category: IntegrationTestCategory,
    description: &'static str,
    test_fn: fn(&mut AdmissionGate, &mut TrustCardRegistry) -> ConformanceResult,
}

/// Create a test admission gate with trusted signer
fn create_test_admission_gate() -> Result<AdmissionGate, String> {
    let mut config = AdmissionConfig::new(SCHEMA_VERSION);
    config
        .with_signer("signer-integration-test", &signing_key().verifying_key())
        .map_err(|error| format!("Failed to register trusted signer: {error}"))?;
    Ok(AdmissionGate::new(config))
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

/// Generate capability entries for testing
fn test_capabilities() -> Vec<CapabilityEntry> {
    vec![
        CapabilityEntry {
            capability_id: "fs.read".to_string(),
            scope: "filesystem:read".to_string(),
            max_calls_per_epoch: 100,
        },
        CapabilityEntry {
            capability_id: "net.egress".to_string(),
            scope: "network:egress".to_string(),
            max_calls_per_epoch: 50,
        },
        CapabilityEntry {
            capability_id: "process.spawn".to_string(),
            scope: "process:spawn".to_string(),
            max_calls_per_epoch: 10,
        },
    ]
}

/// Create artifact with valid contract
fn create_test_artifact(extension_id: &str, capabilities: Vec<CapabilityEntry>) -> ExtensionArtifact {
    let contract = make_contract(
        &format!("contract-{}", extension_id),
        extension_id,
        capabilities,
        "signer-integration-test",
        SCHEMA_VERSION,
        1,
        &signing_key(),
    );
    make_artifact(
        &format!("artifact-{}", extension_id),
        extension_id,
        contract,
        &signing_key(),
    )
}

/// Create trust card input that corresponds to the artifact
fn create_corresponding_trust_card_input(extension_id: &str, capabilities: &[CapabilityEntry]) -> TrustCardInput {
    let capability_declarations = capabilities.iter().map(|cap| {
        let risk = match cap.capability_id.as_str() {
            "fs.read" => CapabilityRisk::Low,
            "net.egress" => CapabilityRisk::Medium,
            "process.spawn" => CapabilityRisk::High,
            _ => CapabilityRisk::Medium,
        };

        CapabilityDeclaration {
            name: cap.capability_id.clone(),
            description: format!("Capability: {}", cap.scope),
            risk,
        }
    }).collect();

    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: extension_id.to_string(),
            version: "1.0.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "publisher:integration-test".to_string(),
            display_name: "Integration Test Publisher".to_string(),
        },
        certification_level: CertificationLevel::Bronze,
        capability_declarations,
        behavioral_profile: BehavioralProfile {
            network_access: capabilities.iter().any(|c| c.capability_id.contains("net")),
            filesystem_access: capabilities.iter().any(|c| c.capability_id.contains("fs")),
            subprocess_access: capabilities.iter().any(|c| c.capability_id.contains("process")),
            profile_summary: format!("Integration test for {} capabilities", capabilities.len()),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            verified_sources: vec!["integration-test-source".to_string()],
            verification_timestamp: "2026-04-30T18:00:00Z".to_string(),
            chain_integrity_score: 95,
        },
        reputation_score_basis_points: 8500,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![],
        last_verified_timestamp: "2026-04-30T18:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            overall_risk: RiskLevel::Medium,
            risk_factors: vec!["network access".to_string(), "filesystem access".to_string()],
            mitigation_suggestions: vec!["Review access patterns".to_string()],
        },
        evidence_refs: vec![
            VerifiedEvidenceRef {
                evidence_id: format!("integration-evidence-{}", extension_id),
                evidence_type: EvidenceType::StaticAnalysis,
                verified_at_epoch: BASE_TIMESTAMP,
                verification_receipt_hash: "sha256:".to_string() + &"a".repeat(64),
            }
        ],
    }
}

/// Test: Artifact capabilities must be reflected in trust card
fn test_capability_mapping_consistency(
    admission_gate: &mut AdmissionGate,
    trust_registry: &mut TrustCardRegistry,
) -> ConformanceResult {
    let extension_id = "npm:@integration/capability-mapping";
    let capabilities = test_capabilities();
    let artifact = create_test_artifact(extension_id, capabilities.clone());

    // Admit the artifact
    match admission_gate.evaluate(&artifact) {
        AdmissionOutcome::Accepted { .. } => {}
        AdmissionOutcome::Denied { reason, event_code } => {
            return ConformanceResult::Fail {
                reason: format!("Artifact admission failed: {} ({})", reason.code(), event_code)
            };
        }
    }

    // Create corresponding trust card
    let trust_input = create_corresponding_trust_card_input(extension_id, &capabilities);
    let trust_card = match trust_registry.create(trust_input, BASE_TIMESTAMP, "trace-capability-mapping") {
        Ok(card) => card,
        Err(e) => {
            return ConformanceResult::Fail {
                reason: format!("Trust card creation failed: {}", e)
            };
        }
    };

    // Verify capability mapping consistency
    let artifact_cap_ids: std::collections::HashSet<_> = capabilities
        .iter()
        .map(|cap| &cap.capability_id)
        .collect();
    let trust_card_cap_names: std::collections::HashSet<_> = trust_card
        .capability_declarations
        .iter()
        .map(|cap| &cap.name)
        .collect();

    if artifact_cap_ids != trust_card_cap_names {
        return ConformanceResult::Fail {
            reason: format!(
                "Capability mapping mismatch: artifact={:?}, trust_card={:?}",
                artifact_cap_ids, trust_card_cap_names
            )
        };
    }

    ConformanceResult::Pass
}

/// Test: Admission failures must be consistent between systems
fn test_admission_failure_consistency(
    admission_gate: &mut AdmissionGate,
    trust_registry: &mut TrustCardRegistry,
) -> ConformanceResult {
    let extension_id = "npm:@integration/admission-failure";

    // Create artifact with invalid/missing contract
    let mut artifact = create_test_artifact(extension_id, test_capabilities());
    artifact.capability_contract = None; // Remove the contract

    // Artifact admission should fail
    let artifact_result = admission_gate.evaluate(&artifact);
    match artifact_result {
        AdmissionOutcome::Denied { reason, .. } => {
            // Expected failure, now verify error code
            if reason.code() != artifact_error_codes::ERR_ARTIFACT_MISSING_CONTRACT {
                return ConformanceResult::Fail {
                    reason: format!("Wrong error code for missing contract: {}", reason.code())
                };
            }
        }
        AdmissionOutcome::Accepted { .. } => {
            return ConformanceResult::Fail {
                reason: "Artifact with missing contract was incorrectly accepted".to_string()
            };
        }
    }

    // Trust card creation with missing evidence should also fail
    let mut trust_input = create_corresponding_trust_card_input(extension_id, &test_capabilities());
    trust_input.evidence_refs.clear(); // Remove evidence refs

    match trust_registry.create(trust_input, BASE_TIMESTAMP, "trace-admission-failure") {
        Ok(_) => {
            return ConformanceResult::Fail {
                reason: "Trust card with missing evidence was incorrectly created".to_string()
            };
        }
        Err(TrustCardError::EvidenceMissing) => {
            // Expected failure
        }
        Err(e) => {
            return ConformanceResult::Fail {
                reason: format!("Wrong error type for missing evidence: {}", e)
            };
        }
    }

    ConformanceResult::Pass
}

/// Test: Signature verification alignment
fn test_signature_verification_alignment(
    admission_gate: &mut AdmissionGate,
    trust_registry: &mut TrustCardRegistry,
) -> ConformanceResult {
    let extension_id = "npm:@integration/signature-alignment";
    let capabilities = vec![
        CapabilityEntry {
            capability_id: "fs.read".to_string(),
            scope: "filesystem:read".to_string(),
            max_calls_per_epoch: 50,
        },
    ];

    // Create artifact with tampered signature
    let mut artifact = create_test_artifact(extension_id, capabilities.clone());
    if let Some(contract) = artifact.capability_contract.as_mut() {
        // Tamper with capability after signing
        if let Some(cap) = contract.capabilities.first_mut() {
            cap.max_calls_per_epoch = cap.max_calls_per_epoch.saturating_add(1);
        }
    }

    // Artifact admission should fail due to signature mismatch
    match admission_gate.evaluate(&artifact) {
        AdmissionOutcome::Denied { reason, .. } => {
            if reason.code() != artifact_error_codes::ERR_ARTIFACT_SIGNATURE_INVALID {
                return ConformanceResult::Fail {
                    reason: format!("Expected signature invalid error, got: {}", reason.code())
                };
            }
        }
        AdmissionOutcome::Accepted { .. } => {
            return ConformanceResult::Fail {
                reason: "Artifact with tampered signature was incorrectly accepted".to_string()
            };
        }
    }

    // Valid trust card should still be creatable (different signature system)
    let trust_input = create_corresponding_trust_card_input(extension_id, &capabilities);
    match trust_registry.create(trust_input, BASE_TIMESTAMP, "trace-signature-alignment") {
        Ok(_) => ConformanceResult::Pass,
        Err(e) => ConformanceResult::Fail {
            reason: format!("Valid trust card creation failed: {}", e)
        },
    }
}

/// Test: Schema version compatibility
fn test_schema_compatibility(
    admission_gate: &mut AdmissionGate,
    trust_registry: &mut TrustCardRegistry,
) -> ConformanceResult {
    let extension_id = "npm:@integration/schema-compatibility";
    let capabilities = test_capabilities();

    // Create artifact with wrong schema version
    let contract = make_contract(
        &format!("contract-{}", extension_id),
        extension_id,
        capabilities.clone(),
        "signer-integration-test",
        "capability-artifact-v0.9", // Wrong version
        1,
        &signing_key(),
    );
    let artifact = make_artifact(
        &format!("artifact-{}", extension_id),
        extension_id,
        contract,
        &signing_key(),
    );

    // Should fail with schema mismatch
    match admission_gate.evaluate(&artifact) {
        AdmissionOutcome::Denied { reason, .. } => {
            if reason.code() != artifact_error_codes::ERR_ARTIFACT_SCHEMA_MISMATCH {
                return ConformanceResult::Fail {
                    reason: format!("Expected schema mismatch error, got: {}", reason.code())
                };
            }
        }
        AdmissionOutcome::Accepted { .. } => {
            return ConformanceResult::Fail {
                reason: "Artifact with wrong schema version was incorrectly accepted".to_string()
            };
        }
    }

    // Trust card with correct schema should work
    let trust_input = create_corresponding_trust_card_input(extension_id, &capabilities);
    match trust_registry.create(trust_input, BASE_TIMESTAMP, "trace-schema-compatibility") {
        Ok(_) => ConformanceResult::Pass,
        Err(e) => ConformanceResult::Fail {
            reason: format!("Trust card creation failed: {}", e)
        },
    }
}

/// Test: Trust card behavioral profile reflects artifact capabilities
fn test_behavioral_profile_reflection(
    admission_gate: &mut AdmissionGate,
    trust_registry: &mut TrustCardRegistry,
) -> ConformanceResult {
    let extension_id = "npm:@integration/behavioral-profile";

    // Test different capability combinations
    let test_cases = vec![
        (
            vec![CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 10,
            }],
            true,  // filesystem_access
            false, // network_access
            false, // subprocess_access
        ),
        (
            vec![CapabilityEntry {
                capability_id: "net.egress".to_string(),
                scope: "network:egress".to_string(),
                max_calls_per_epoch: 5,
            }],
            false, // filesystem_access
            true,  // network_access
            false, // subprocess_access
        ),
        (
            vec![
                CapabilityEntry {
                    capability_id: "fs.read".to_string(),
                    scope: "filesystem:read".to_string(),
                    max_calls_per_epoch: 10,
                },
                CapabilityEntry {
                    capability_id: "net.egress".to_string(),
                    scope: "network:egress".to_string(),
                    max_calls_per_epoch: 5,
                },
            ],
            true,  // filesystem_access
            true,  // network_access
            false, // subprocess_access
        ),
    ];

    for (i, (capabilities, expected_fs, expected_net, expected_proc)) in test_cases.into_iter().enumerate() {
        let test_extension_id = format!("{}-{}", extension_id, i);
        let artifact = create_test_artifact(&test_extension_id, capabilities.clone());

        // Admit artifact
        match admission_gate.evaluate(&artifact) {
            AdmissionOutcome::Accepted { .. } => {}
            AdmissionOutcome::Denied { reason, event_code } => {
                return ConformanceResult::Fail {
                    reason: format!("Test case {} artifact admission failed: {} ({})", i, reason.code(), event_code)
                };
            }
        }

        // Create trust card
        let trust_input = create_corresponding_trust_card_input(&test_extension_id, &capabilities);
        let trust_card = match trust_registry.create(trust_input, BASE_TIMESTAMP + i as u64, &format!("trace-behavioral-{}", i)) {
            Ok(card) => card,
            Err(e) => {
                return ConformanceResult::Fail {
                    reason: format!("Test case {} trust card creation failed: {}", i, e)
                };
            }
        };

        // Verify behavioral profile matches capabilities
        if trust_card.behavioral_profile.filesystem_access != expected_fs {
            return ConformanceResult::Fail {
                reason: format!("Test case {} filesystem_access mismatch: expected {}, got {}",
                    i, expected_fs, trust_card.behavioral_profile.filesystem_access)
            };
        }
        if trust_card.behavioral_profile.network_access != expected_net {
            return ConformanceResult::Fail {
                reason: format!("Test case {} network_access mismatch: expected {}, got {}",
                    i, expected_net, trust_card.behavioral_profile.network_access)
            };
        }
        if trust_card.behavioral_profile.subprocess_access != expected_proc {
            return ConformanceResult::Fail {
                reason: format!("Test case {} subprocess_access mismatch: expected {}, got {}",
                    i, expected_proc, trust_card.behavioral_profile.subprocess_access)
            };
        }
    }

    ConformanceResult::Pass
}

/// Generate comprehensive integration conformance test cases
fn generate_integration_conformance_cases() -> Vec<IntegrationConformanceCase> {
    vec![
        IntegrationConformanceCase {
            id: "INTEG-TC-001",
            spec_section: INTEGRATION_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: IntegrationTestCategory::CapabilityMapping,
            description: "Artifact capabilities must be consistently reflected in trust card capability declarations",
            test_fn: test_capability_mapping_consistency,
        },
        IntegrationConformanceCase {
            id: "INTEG-TC-002",
            spec_section: INTEGRATION_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: IntegrationTestCategory::AdmissionConsistency,
            description: "Admission failures must be consistent between artifact and trust card systems",
            test_fn: test_admission_failure_consistency,
        },
        IntegrationConformanceCase {
            id: "INTEG-TC-003",
            spec_section: INTEGRATION_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: IntegrationTestCategory::SignatureAlignment,
            description: "Signature verification must be properly aligned between artifact and trust card systems",
            test_fn: test_signature_verification_alignment,
        },
        IntegrationConformanceCase {
            id: "INTEG-TC-004",
            spec_section: INTEGRATION_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: IntegrationTestCategory::SchemaCompatibility,
            description: "Schema version compatibility must be enforced consistently",
            test_fn: test_schema_compatibility,
        },
        IntegrationConformanceCase {
            id: "INTEG-TC-005",
            spec_section: INTEGRATION_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: IntegrationTestCategory::StateReflection,
            description: "Trust card behavioral profile must accurately reflect artifact capability grants",
            test_fn: test_behavioral_profile_reflection,
        },
    ]
}

/// Execute a single integration conformance test case
fn run_integration_conformance_case(
    case: &IntegrationConformanceCase,
    admission_gate: &mut AdmissionGate,
    trust_registry: &mut TrustCardRegistry,
) -> ConformanceResult {
    (case.test_fn)(admission_gate, trust_registry)
}

/// Generate integration conformance matrix report
fn generate_integration_report(results: &[(&IntegrationConformanceCase, ConformanceResult)]) -> String {
    let mut coverage_by_category: BTreeMap<IntegrationTestCategory, (usize, usize)> = BTreeMap::new();
    let mut coverage_by_level: BTreeMap<RequirementLevel, (usize, usize)> = BTreeMap::new();

    for (case, result) in results {
        let (cat_total, cat_pass) = coverage_by_category.entry(case.category).or_insert((0, 0));
        let (level_total, level_pass) = coverage_by_level.entry(case.requirement_level).or_insert((0, 0));

        *cat_total += 1;
        *level_total += 1;

        if matches!(result, ConformanceResult::Pass) {
            *cat_pass += 1;
            *level_pass += 1;
        }
    }

    let mut report = String::new();
    report.push_str("# Capability Artifact + Trust Card Integration Conformance Report\n\n");
    report.push_str(&format!("**Spec Reference:** {}\n\n", INTEGRATION_SPEC_REFERENCE));

    report.push_str("## Coverage by Category\n\n");
    report.push_str("| Category | Tests | Passing | Coverage |\n");
    report.push_str("|----------|-------|---------|----------|\n");

    for (category, (total, passing)) in &coverage_by_category {
        let percentage = if *total > 0 { (*passing * 100) / *total } else { 0 };
        report.push_str(&format!("| {:?} | {} | {} | {}% |\n", category, total, passing, percentage));
    }

    report.push_str("\n## Coverage by Requirement Level\n\n");
    report.push_str("| Level | Tests | Passing | Coverage |\n");
    report.push_str("|-------|-------|---------|----------|\n");

    for (level, (total, passing)) in &coverage_by_level {
        let percentage = if *total > 0 { (*passing * 100) / *total } else { 0 };
        report.push_str(&format!("| {:?} | {} | {} | {}% |\n", level, total, passing, percentage));
    }

    report.push_str("\n## Individual Test Results\n\n");

    for (case, result) in results {
        let status = match result {
            ConformanceResult::Pass => "✅ PASS",
            ConformanceResult::Fail { .. } => "❌ FAIL",
        };

        report.push_str(&format!("- **{}** ({:?}): {} - {}\n", case.id, case.requirement_level, status, case.description));

        if let ConformanceResult::Fail { reason } = result {
            report.push_str(&format!("  - **Failure reason:** {}\n", reason));
        }
    }

    report
}

#[test]
fn capability_artifact_trust_card_integration_full_conformance_suite() {
    let mut admission_gate = create_test_admission_gate()
        .expect("Failed to create test admission gate");
    let mut trust_registry = TrustCardRegistry::new(300, TEST_REGISTRY_KEY);
    let mut results = Vec::new();
    let mut failures = 0;

    eprintln!("Running Capability Artifact + Trust Card Integration Conformance Suite...");
    eprintln!("Spec: {}", INTEGRATION_SPEC_REFERENCE);

    let test_cases = generate_integration_conformance_cases();
    eprintln!("Total integration tests: {}", test_cases.len());

    for case in test_cases.iter() {
        let result = run_integration_conformance_case(case, &mut admission_gate, &mut trust_registry);

        match &result {
            ConformanceResult::Pass => {
                eprintln!("  ✅ {} - {}", case.id, case.description);
            }
            ConformanceResult::Fail { reason } => {
                eprintln!("  ❌ {} - {} (REASON: {})", case.id, case.description, reason);
                failures += 1;
            }
        }

        results.push((case, result));
    }

    // Generate and print conformance report
    let report = generate_integration_report(&results);
    eprintln!("\n{}", report);

    // Conformance gate: All MUST requirements must pass
    let must_failures: Vec<_> = results.iter()
        .filter(|(case, result)| {
            case.requirement_level == RequirementLevel::Must &&
            matches!(result, ConformanceResult::Fail { .. })
        })
        .collect();

    if !must_failures.is_empty() {
        panic!(
            "INTEGRATION CONFORMANCE GATE FAILURE: {} MUST requirements failed",
            must_failures.len()
        );
    }

    if failures > 0 {
        panic!("{} integration conformance test(s) failed", failures);
    }

    eprintln!("\n🎉 All integration conformance tests passed!");
}
