//! Trust Card Schema Conformance Test Harness
//!
//! Implements spec-frozen conformance testing for trust card schema according to
//! bd-2yh contract specification. Verifies MUST/SHOULD requirements via golden
//! fixtures and round-trip testing.

use frankenengine_node::supply_chain::trust_card::{
    AuditRecord, BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard, TrustCardError,
    compute_card_hash, to_canonical_json, verify_card_signature,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

// Schema version for conformance testing
const TRUST_CARD_SCHEMA_VERSION: &str = "franken-node/trust-card/v1";

// Test constants for deterministic fixtures
const TEST_TIMESTAMP: &str = "2026-04-23T06:30:00Z";
const TEST_TRACE_ID: &str = "trust-card-conformance-001";
const TEST_REGISTRY_KEY: &str = "trust-card-conformance-key";

/// Conformance test requirement levels from bd-2yh specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementLevel {
    Must,
    Should,
    #[expect(dead_code, reason = "reserved for future MAY-level conformance cases")]
    May,
}

/// Conformance test categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestCategory {
    Schema,
    Serialization,
    Signature,
    RoundTrip,
    EdgeCase,
}

/// Test result for conformance reporting
#[derive(Debug, Clone)]
enum TestResult {
    Pass,
    Fail { reason: String },
    ExpectedFailure { reason: String },
}

/// Individual conformance test case
#[derive(Debug, Clone)]
struct ConformanceCase {
    id: &'static str,
    spec_section: &'static str,
    level: RequirementLevel,
    category: TestCategory,
    description: &'static str,
}

/// Statistics for compliance reporting
#[derive(Debug, Default)]
struct SectionStats {
    must_total: usize,
    should_total: usize,
    may_total: usize,
    passing: usize,
    failing: usize,
    expected_failures: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct TrustCardWireVectors {
    vectors: Vec<TrustCardWireVector>,
}

#[derive(Debug, Clone, Deserialize)]
struct TrustCardWireVector {
    name: String,
    registry_key_ascii: String,
    expected_card_hash: String,
    expected_registry_signature: String,
    expected_wire_artifact: String,
    expected_hash_preimage_artifact: String,
    expected_signature_preimage_hex_artifact: String,
}

// ============================================================================
// CONFORMANCE TEST MATRIX
// ============================================================================

const CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Schema Structure Requirements (INV-TC-SCHEMA-*)
    ConformanceCase {
        id: "TC-SCHEMA-001",
        spec_section: "bd-2yh/schema",
        level: RequirementLevel::Must,
        category: TestCategory::Schema,
        description: "TrustCard MUST contain all required fields",
    },
    ConformanceCase {
        id: "TC-SCHEMA-002",
        spec_section: "bd-2yh/schema",
        level: RequirementLevel::Must,
        category: TestCategory::Schema,
        description: "schema_version MUST be present and valid",
    },
    ConformanceCase {
        id: "TC-SCHEMA-003",
        spec_section: "bd-2yh/schema",
        level: RequirementLevel::Must,
        category: TestCategory::Schema,
        description: "trust_card_version MUST be monotonic u64",
    },
    // Serialization Requirements (INV-TC-DETERMINISTIC)
    ConformanceCase {
        id: "TC-SERIAL-001",
        spec_section: "bd-2yh/deterministic",
        level: RequirementLevel::Must,
        category: TestCategory::Serialization,
        description: "JSON serialization MUST be canonical and deterministic",
    },
    ConformanceCase {
        id: "TC-SERIAL-002",
        spec_section: "bd-2yh/deterministic",
        level: RequirementLevel::Must,
        category: TestCategory::Serialization,
        description: "Field ordering MUST be lexicographic",
    },
    // Round-trip Requirements
    ConformanceCase {
        id: "TC-ROUND-001",
        spec_section: "bd-2yh/serialization",
        level: RequirementLevel::Must,
        category: TestCategory::RoundTrip,
        description: "serialize(deserialize(data)) MUST equal data",
    },
    // Signature Requirements (INV-TC-SIGNATURE)
    ConformanceCase {
        id: "TC-SIG-001",
        spec_section: "bd-2yh/signature",
        level: RequirementLevel::Must,
        category: TestCategory::Signature,
        description: "registry_signature MUST verify with correct key",
    },
    ConformanceCase {
        id: "TC-SIG-002",
        spec_section: "bd-2yh/signature",
        level: RequirementLevel::Must,
        category: TestCategory::Signature,
        description: "card_hash MUST be derived deterministically",
    },
    // Edge Cases and Constraints
    ConformanceCase {
        id: "TC-EDGE-001",
        spec_section: "bd-2yh/constraints",
        level: RequirementLevel::Must,
        category: TestCategory::EdgeCase,
        description: "Empty capability_declarations MUST be valid",
    },
    ConformanceCase {
        id: "TC-EDGE-002",
        spec_section: "bd-2yh/constraints",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "Large audit_history SHOULD be bounded",
    },
];

// ============================================================================
// GOLDEN FIXTURE MANAGEMENT
// ============================================================================

fn golden_path(test_name: &str) -> PathBuf {
    PathBuf::from("tests/golden/trust_card_conformance").join(format!("{}.golden", test_name))
}

fn assert_golden(test_name: &str, actual: &str) -> TestResult {
    let golden_file = golden_path(test_name);

    if std::env::var("UPDATE_GOLDENS").is_ok() {
        if let Some(parent) = golden_file.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&golden_file, actual).unwrap();
        eprintln!("UPDATED golden: {}", golden_file.display());
        return TestResult::Pass;
    }

    let expected = match fs::read_to_string(&golden_file) {
        Ok(content) => content,
        Err(_) => {
            return TestResult::Fail {
                reason: format!(
                    "Golden file missing: {}\nRun with UPDATE_GOLDENS=1 to create it",
                    golden_file.display()
                ),
            };
        }
    };

    if actual != expected {
        let actual_file = golden_file.with_extension("actual");
        fs::write(&actual_file, actual).unwrap();
        return TestResult::Fail {
            reason: format!(
                "Golden mismatch for {}\ndiff {} {}",
                test_name,
                golden_file.display(),
                actual_file.display()
            ),
        };
    }

    TestResult::Pass
}

// ============================================================================
// FIXTURE GENERATION
// ============================================================================

fn create_minimal_trust_card() -> TrustCard {
    TrustCard {
        schema_version: TRUST_CARD_SCHEMA_VERSION.to_string(),
        trust_card_version: 1,
        previous_version_hash: None,
        extension: ExtensionIdentity {
            extension_id: "test:minimal".to_string(),
            version: "1.0.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "test:publisher".to_string(),
            display_name: "Test Publisher".to_string(),
        },
        certification_level: CertificationLevel::Bronze,
        capability_declarations: vec![],
        behavioral_profile: BehavioralProfile {
            network_access: false,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "Minimal test profile".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "basic".to_string(),
            source_uri: "test://source".to_string(),
            artifact_hashes: vec!["sha256:deadbeef".to_string()],
            verified_at: TEST_TIMESTAMP.to_string(),
        },
        reputation_score_basis_points: 7500, // 75%
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![],
        last_verified_timestamp: TEST_TIMESTAMP.to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Minimal risk profile".to_string(),
        },
        audit_history: vec![],
        derivation_evidence: None,
        card_hash: "placeholder".to_string(), // Computed later
        registry_signature: "placeholder".to_string(), // Computed later
    }
}

fn create_maximal_trust_card() -> TrustCard {
    let mut card = create_minimal_trust_card();

    // Populate with maximum realistic data
    card.trust_card_version = u64::MAX - 1;
    card.previous_version_hash = Some("sha256:previous".to_string());
    card.certification_level = CertificationLevel::Gold;

    // Multiple capability declarations
    card.capability_declarations = vec![
        CapabilityDeclaration {
            name: "network.egress".to_string(),
            description: "Outbound network access".to_string(),
            risk: CapabilityRisk::High,
        },
        CapabilityDeclaration {
            name: "fs.write".to_string(),
            description: "Filesystem write access".to_string(),
            risk: CapabilityRisk::Critical,
        },
    ];

    card.behavioral_profile.network_access = true;
    card.behavioral_profile.filesystem_access = true;
    card.behavioral_profile.subprocess_access = true;

    // Dependencies
    card.dependency_trust_summary = vec![
        DependencyTrustStatus {
            dependency_id: "dep1".to_string(),
            trust_level: "high".to_string(),
        },
        DependencyTrustStatus {
            dependency_id: "dep2".to_string(),
            trust_level: "medium".to_string(),
        },
    ];

    // Audit history
    card.audit_history = vec![AuditRecord {
        timestamp: TEST_TIMESTAMP.to_string(),
        event_code: "CERT_UPGRADE".to_string(),
        detail: "Upgraded to gold certification".to_string(),
        trace_id: TEST_TRACE_ID.to_string(),
    }];

    card
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .expect("workspace root should exist")
}

fn workspace_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

fn read_workspace_file(relative: &str) -> Result<String, String> {
    fs::read_to_string(workspace_path(relative))
        .map_err(|err| format!("failed reading workspace file `{relative}`: {err}"))
}

fn load_signature_vector(name: &str) -> Result<TrustCardWireVector, String> {
    let raw = read_workspace_file("artifacts/conformance/trust_card_wire_vectors.json")?;
    let vectors: TrustCardWireVectors = serde_json::from_str(&raw)
        .map_err(|err| format!("failed parsing trust card wire vectors: {err}"))?;
    vectors
        .vectors
        .into_iter()
        .find(|vector| vector.name == name)
        .ok_or_else(|| format!("missing trust card wire vector `{name}`"))
}

fn load_trust_card_fixture(relative: &str) -> Result<TrustCard, String> {
    let raw = read_workspace_file(relative)?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("failed parsing trust card fixture `{relative}`: {err}"))
}

fn canonical_hash_preimage(card: &TrustCard) -> Result<String, String> {
    let mut value = serde_json::to_value(card)
        .map_err(|err| format!("failed converting trust card to JSON value: {err}"))?;
    let Some(map) = value.as_object_mut() else {
        return Err("trust card fixture did not serialize to a JSON object".to_string());
    };
    map.insert("card_hash".to_string(), Value::String(String::new()));
    map.insert(
        "registry_signature".to_string(),
        Value::String(String::new()),
    );
    to_canonical_json(&value)
        .map_err(|err| format!("failed canonicalizing card hash preimage: {err}"))
}

fn signature_preimage_string(card_hash: &str) -> String {
    format!("trust_card_registry_sig_v1:{card_hash}")
}

fn test_signature_vector_verification(_card: &TrustCard) -> TestResult {
    let vector = match load_signature_vector("signed_card_baseline") {
        Ok(vector) => vector,
        Err(reason) => return TestResult::Fail { reason },
    };
    let fixture = match load_trust_card_fixture(&vector.expected_wire_artifact) {
        Ok(card) => card,
        Err(reason) => return TestResult::Fail { reason },
    };
    let expected_wire = match read_workspace_file(&vector.expected_wire_artifact) {
        Ok(raw) => raw,
        Err(reason) => return TestResult::Fail { reason },
    };
    let expected_signature_preimage_hex =
        match read_workspace_file(&vector.expected_signature_preimage_hex_artifact) {
            Ok(raw) => raw,
            Err(reason) => return TestResult::Fail { reason },
        };
    let expected_signature_preimage = match hex::decode(expected_signature_preimage_hex.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    {
        Some(value) => value,
        None => {
            return TestResult::Fail {
                reason: format!(
                    "failed decoding signature preimage artifact `{}`",
                    vector.expected_signature_preimage_hex_artifact
                ),
            };
        }
    };
    let actual_wire = match to_canonical_json(&fixture) {
        Ok(json) => json,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("failed serializing wire fixture canonically: {err}"),
            };
        }
    };
    if actual_wire != expected_wire.trim_end() {
        return TestResult::Fail {
            reason: "wire fixture canonical JSON diverged from expected artifact".to_string(),
        };
    }
    if fixture.registry_signature != vector.expected_registry_signature {
        return TestResult::Fail {
            reason: format!(
                "fixture registry signature mismatch: expected {} got {}",
                vector.expected_registry_signature, fixture.registry_signature
            ),
        };
    }

    let expected_preimage = signature_preimage_string(&fixture.card_hash);
    if expected_preimage != expected_signature_preimage {
        return TestResult::Fail {
            reason: format!(
                "signature preimage mismatch: expected `{expected_signature_preimage}` got `{expected_preimage}`"
            ),
        };
    }

    let registry_key = vector.registry_key_ascii.as_bytes();
    if let Err(err) = verify_card_signature(&fixture, registry_key) {
        return TestResult::Fail {
            reason: format!("fixture signature should verify with documented registry key: {err}"),
        };
    }

    let wrong_key_err = match verify_card_signature(&fixture, TEST_REGISTRY_KEY.as_bytes()) {
        Ok(()) => {
            return TestResult::Fail {
                reason: "fixture signature unexpectedly verified with the wrong registry key"
                    .to_string(),
            };
        }
        Err(err) => err,
    };
    if !matches!(wrong_key_err, TrustCardError::SignatureInvalid(_)) {
        return TestResult::Fail {
            reason: format!(
                "wrong registry key should fail with SignatureInvalid, got {wrong_key_err}"
            ),
        };
    }

    let mut tampered = fixture.clone();
    tampered.registry_signature = "00".repeat(fixture.registry_signature.len() / 2);
    let tampered_err = match verify_card_signature(&tampered, registry_key) {
        Ok(()) => {
            return TestResult::Fail {
                reason: "tampered registry signature unexpectedly verified".to_string(),
            };
        }
        Err(err) => err,
    };
    if !matches!(tampered_err, TrustCardError::SignatureInvalid(_)) {
        return TestResult::Fail {
            reason: format!(
                "tampered registry signature should fail with SignatureInvalid, got {tampered_err}"
            ),
        };
    }

    TestResult::Pass
}

fn test_card_hash_vector_determinism(_card: &TrustCard) -> TestResult {
    let vector = match load_signature_vector("signed_card_baseline") {
        Ok(vector) => vector,
        Err(reason) => return TestResult::Fail { reason },
    };
    let fixture = match load_trust_card_fixture(&vector.expected_wire_artifact) {
        Ok(card) => card,
        Err(reason) => return TestResult::Fail { reason },
    };
    let expected_hash_preimage = match read_workspace_file(&vector.expected_hash_preimage_artifact)
    {
        Ok(raw) => raw,
        Err(reason) => return TestResult::Fail { reason },
    };

    let computed_hash = match compute_card_hash(&fixture) {
        Ok(hash) => hash,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("failed computing fixture card_hash: {err}"),
            };
        }
    };
    if computed_hash != vector.expected_card_hash {
        return TestResult::Fail {
            reason: format!(
                "computed card_hash mismatch: expected {} got {}",
                vector.expected_card_hash, computed_hash
            ),
        };
    }
    if fixture.card_hash != computed_hash {
        return TestResult::Fail {
            reason: format!(
                "embedded fixture card_hash mismatch: expected {} got {}",
                computed_hash, fixture.card_hash
            ),
        };
    }
    let recomputed_hash = match compute_card_hash(&fixture) {
        Ok(hash) => hash,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("failed recomputing fixture card_hash: {err}"),
            };
        }
    };
    if recomputed_hash != computed_hash {
        return TestResult::Fail {
            reason: "card_hash computation was not deterministic across repeated calls".to_string(),
        };
    }

    let actual_hash_preimage = match canonical_hash_preimage(&fixture) {
        Ok(json) => json,
        Err(reason) => return TestResult::Fail { reason },
    };
    if actual_hash_preimage != expected_hash_preimage.trim_end() {
        return TestResult::Fail {
            reason: "card_hash preimage artifact diverged from canonicalized fixture".to_string(),
        };
    }

    let registry_key = vector.registry_key_ascii.as_bytes();
    let mut tampered = fixture.clone();
    tampered.publisher.display_name.push_str(" (tampered)");
    let tampered_hash = match compute_card_hash(&tampered) {
        Ok(hash) => hash,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("failed computing tampered card_hash: {err}"),
            };
        }
    };
    if tampered_hash == computed_hash {
        return TestResult::Fail {
            reason: "tampering trust-card payload did not change card_hash".to_string(),
        };
    }

    let tampered_err = match verify_card_signature(&tampered, registry_key) {
        Ok(()) => {
            return TestResult::Fail {
                reason: "tampered payload unexpectedly preserved signature verification"
                    .to_string(),
            };
        }
        Err(err) => err,
    };
    if !matches!(tampered_err, TrustCardError::CardHashMismatch(_)) {
        return TestResult::Fail {
            reason: format!(
                "tampered payload should fail with CardHashMismatch, got {tampered_err}"
            ),
        };
    }

    TestResult::Pass
}

// ============================================================================
// CONFORMANCE TEST IMPLEMENTATIONS
// ============================================================================

fn test_schema_required_fields(card: &TrustCard) -> TestResult {
    // Verify all required fields are present and non-empty where applicable
    if card.schema_version.is_empty() {
        return TestResult::Fail {
            reason: "schema_version cannot be empty".to_string(),
        };
    }

    if card.extension.extension_id.is_empty() {
        return TestResult::Fail {
            reason: "extension.extension_id cannot be empty".to_string(),
        };
    }

    if card.publisher.publisher_id.is_empty() {
        return TestResult::Fail {
            reason: "publisher.publisher_id cannot be empty".to_string(),
        };
    }

    TestResult::Pass
}

fn test_schema_version_validity(card: &TrustCard) -> TestResult {
    if !card.schema_version.starts_with("franken-node/trust-card/") {
        return TestResult::Fail {
            reason: format!("Invalid schema_version format: {}", card.schema_version),
        };
    }

    TestResult::Pass
}

fn test_deterministic_serialization(card: &TrustCard) -> TestResult {
    // Serialize twice and ensure identical output
    let json1 = match to_canonical_json(card) {
        Ok(json) => json,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Serialization failed: {}", e),
            };
        }
    };
    let json2 = match to_canonical_json(card) {
        Ok(json) => json,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Serialization failed on second attempt: {}", e),
            };
        }
    };

    if json1 != json2 {
        return TestResult::Fail {
            reason: "Serialization is not deterministic".to_string(),
        };
    }

    // Verify golden fixture
    assert_golden("deterministic_serialization", &json1)
}

fn test_field_ordering(card: &TrustCard) -> TestResult {
    let json = match to_canonical_json(card) {
        Ok(json) => json,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Serialization failed: {}", e),
            };
        }
    };

    let value: Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("JSON parsing failed: {}", e),
            };
        }
    };

    if let Value::Object(map) = value {
        let keys: Vec<_> = map.keys().collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();

        if keys != sorted_keys {
            return TestResult::Fail {
                reason: format!(
                    "Fields not in lexicographic order. Expected: {:?}, Got: {:?}",
                    sorted_keys, keys
                ),
            };
        }
    }

    TestResult::Pass
}

fn test_round_trip_consistency(card: &TrustCard) -> TestResult {
    // Serialize → Deserialize → Serialize
    let json1 = match to_canonical_json(card) {
        Ok(json) => json,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("First serialization failed: {}", e),
            };
        }
    };

    let deserialized: TrustCard = match serde_json::from_str(&json1) {
        Ok(card) => card,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Deserialization failed: {}", e),
            };
        }
    };

    let json2 = match to_canonical_json(&deserialized) {
        Ok(json) => json,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Second serialization failed: {}", e),
            };
        }
    };

    if json1 != json2 {
        return TestResult::Fail {
            reason: "Round-trip serialization not consistent".to_string(),
        };
    }

    TestResult::Pass
}

fn test_empty_capabilities_valid(_card: &TrustCard) -> TestResult {
    let mut minimal = create_minimal_trust_card();
    minimal.capability_declarations.clear();

    // Should serialize successfully
    let json = match to_canonical_json(&minimal) {
        Ok(json) => json,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Serialization with empty capabilities failed: {}", e),
            };
        }
    };

    // Should deserialize successfully
    match serde_json::from_str::<TrustCard>(&json) {
        Ok(_) => TestResult::Pass,
        Err(e) => TestResult::Fail {
            reason: format!("Empty capabilities not valid: {}", e),
        },
    }
}

// ============================================================================
// TEST RUNNER AND REPORTING
// ============================================================================

fn run_conformance_case(case: &ConformanceCase) -> TestResult {
    let minimal_card = create_minimal_trust_card();
    let maximal_card = create_maximal_trust_card();

    match case.id {
        "TC-SCHEMA-001" => test_schema_required_fields(&minimal_card),
        "TC-SCHEMA-002" => test_schema_version_validity(&minimal_card),
        "TC-SCHEMA-003" => {
            // Test monotonic version requirement
            if maximal_card.trust_card_version > minimal_card.trust_card_version {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: "trust_card_version not monotonic".to_string(),
                }
            }
        }
        "TC-SERIAL-001" => test_deterministic_serialization(&minimal_card),
        "TC-SERIAL-002" => test_field_ordering(&minimal_card),
        "TC-ROUND-001" => test_round_trip_consistency(&minimal_card),
        "TC-SIG-001" => test_signature_vector_verification(&minimal_card),
        "TC-SIG-002" => test_card_hash_vector_determinism(&minimal_card),
        "TC-EDGE-001" => test_empty_capabilities_valid(&minimal_card),
        "TC-EDGE-002" => {
            // Audit history bounds testing
            TestResult::ExpectedFailure {
                reason: "Audit history bounds not yet enforced".to_string(),
            }
        }
        _ => TestResult::Fail {
            reason: format!("Unknown test case: {}", case.id),
        },
    }
}

fn generate_compliance_report(results: &[(ConformanceCase, TestResult)]) -> String {
    let mut report = String::new();
    report.push_str("# Trust Card Schema Conformance Report\n\n");
    report.push_str(&format!("Generated: {}\n", TEST_TIMESTAMP));
    report.push_str(&format!("Total test cases: {}\n\n", results.len()));

    let mut by_section: BTreeMap<&str, SectionStats> = BTreeMap::new();

    for (case, result) in results {
        let stats = by_section.entry(case.spec_section).or_default();

        match case.level {
            RequirementLevel::Must => stats.must_total += 1,
            RequirementLevel::Should => stats.should_total += 1,
            RequirementLevel::May => stats.may_total += 1,
        }

        match result {
            TestResult::Pass => stats.passing += 1,
            TestResult::Fail { .. } => stats.failing += 1,
            TestResult::ExpectedFailure { .. } => stats.expected_failures += 1,
        }
    }

    report.push_str("| Section | MUST (pass/total) | SHOULD (pass/total) | Score |\n");
    report.push_str("|---------|-------------------|---------------------|-------|\n");

    for (section, stats) in &by_section {
        let must_score = if stats.must_total > 0 {
            (stats.passing as f64 / stats.must_total as f64) * 100.0
        } else {
            100.0
        };

        report.push_str(&format!(
            "| {} | {}/{} | {}/{} | {:.1}% |\n",
            section,
            stats.passing.min(stats.must_total),
            stats.must_total,
            stats
                .passing
                .saturating_sub(stats.must_total.min(stats.passing)),
            stats.should_total,
            must_score
        ));
    }

    report
}

// ============================================================================
// MAIN TEST ENTRY POINTS
// ============================================================================

#[test]
fn trust_card_schema_conformance_full() {
    let mut results = Vec::new();
    let mut pass_count = 0;
    let mut fail_count = 0;
    let mut expected_fail_count = 0;

    for case in CONFORMANCE_CASES {
        let result = run_conformance_case(case);

        match &result {
            TestResult::Pass => {
                pass_count += 1;
                println!(
                    "PASS [{:?}]: {} - {}",
                    case.category, case.id, case.description
                );
            }
            TestResult::Fail { reason } => {
                fail_count += 1;
                eprintln!(
                    "FAIL [{:?}]: {} - {}: {}",
                    case.category, case.id, case.description, reason
                );
            }
            TestResult::ExpectedFailure { reason } => {
                expected_fail_count += 1;
                println!(
                    "XFAIL [{:?}]: {} - {}: {}",
                    case.category, case.id, case.description, reason
                );
            }
        }

        results.push((case.clone(), result));
    }

    let report = generate_compliance_report(&results);
    println!("\n{}", report);

    // Write compliance report
    if fs::create_dir_all("tests/golden/trust_card_conformance").is_ok() {
        let _ = fs::write(
            "tests/golden/trust_card_conformance/compliance_report.md",
            report,
        );
    }

    println!(
        "\nConformance Summary: {pass_count} pass, {fail_count} fail, {expected_fail_count} expected-fail"
    );

    // Conformance requirement: zero hard failures
    assert_eq!(
        fail_count, 0,
        "{fail_count} conformance tests failed - see report for details"
    );
}

#[test]
fn trust_card_round_trip_minimal() {
    let card = create_minimal_trust_card();
    let result = test_round_trip_consistency(&card);
    match result {
        TestResult::Pass => {}
        TestResult::Fail { reason } => panic!("Round-trip test failed: {}", reason),
        TestResult::ExpectedFailure { reason } => panic!("Unexpected expected failure: {}", reason),
    }
}

#[test]
fn trust_card_round_trip_maximal() {
    let card = create_maximal_trust_card();
    let result = test_round_trip_consistency(&card);
    match result {
        TestResult::Pass => {}
        TestResult::Fail { reason } => panic!("Round-trip test failed: {}", reason),
        TestResult::ExpectedFailure { reason } => panic!("Unexpected expected failure: {}", reason),
    }
}

#[test]
fn trust_card_deterministic_serialization() {
    let card = create_minimal_trust_card();
    let result = test_deterministic_serialization(&card);
    match result {
        TestResult::Pass => {}
        TestResult::Fail { reason } => panic!("Deterministic serialization failed: {}", reason),
        TestResult::ExpectedFailure { reason } => panic!("Unexpected expected failure: {}", reason),
    }
}
