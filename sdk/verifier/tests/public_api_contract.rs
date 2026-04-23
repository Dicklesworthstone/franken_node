//! Public API Conformance Harness for Verifier SDK
//!
//! Tests the stability of the public API contract to prevent downstream breakage.
//! This harness verifies:
//! - Exported constants (SDK_VERSION, event codes, error codes, invariants)
//! - Enum serde serialization/deserialization (VerificationVerdict, VerificationOperation, etc.)
//! - Result JSON shape (VerificationResult, SessionStep, TransparencyLogEntry)
//! - Error variants and display formats
//! - Public function signatures and behavior
//!
//! Pattern: Spec-Derived Testing (Pattern 4) - one test per API contract requirement

use std::collections::BTreeMap;

use frankenengine_verifier_sdk::*;
use serde_json::json;

/// API contract requirement levels for test prioritization
#[derive(Debug, Clone, Copy)]
enum RequirementLevel {
    Must,    // Breaking changes are NOT allowed
    Should,  // Breaking changes require major version bump
    May,     // Breaking changes allowed with documentation
}

/// Test categories for organization
#[derive(Debug, Clone, Copy)]
enum TestCategory {
    Constants,
    Enums,
    Structures,
    ErrorHandling,
    Functions,
}

/// Public API contract test case
struct ApiContractTest {
    id: &'static str,
    category: TestCategory,
    level: RequirementLevel,
    description: &'static str,
    test_fn: fn() -> Result<(), String>,
}

// =============================================================================
// Constants Contract Tests
// =============================================================================

fn test_sdk_version_constant() -> Result<(), String> {
    assert_eq!(SDK_VERSION, "vsdk-v1.0",
        "SDK_VERSION constant changed - BREAKING for downstream consumers");
    Ok(())
}

fn test_sdk_version_min_constant() -> Result<(), String> {
    assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0",
        "SDK_VERSION_MIN constant changed - BREAKING for version checks");
    Ok(())
}

fn test_event_codes_constants() -> Result<(), String> {
    // Event codes must remain stable - downstream monitoring depends on them
    assert_eq!(CAPSULE_CREATED, "CAPSULE_CREATED");
    assert_eq!(CAPSULE_SIGNED, "CAPSULE_SIGNED");
    assert_eq!(CAPSULE_REPLAY_START, "CAPSULE_REPLAY_START");
    assert_eq!(CAPSULE_VERDICT_REPRODUCED, "CAPSULE_VERDICT_REPRODUCED");
    assert_eq!(SDK_VERSION_CHECK, "SDK_VERSION_CHECK");
    Ok(())
}

fn test_error_codes_constants() -> Result<(), String> {
    // Error codes must remain stable - downstream error handling depends on them
    assert_eq!(ERR_CAPSULE_SIGNATURE_INVALID, "ERR_CAPSULE_SIGNATURE_INVALID");
    assert_eq!(ERR_CAPSULE_SCHEMA_MISMATCH, "ERR_CAPSULE_SCHEMA_MISMATCH");
    assert_eq!(ERR_CAPSULE_REPLAY_DIVERGED, "ERR_CAPSULE_REPLAY_DIVERGED");
    assert_eq!(ERR_CAPSULE_VERDICT_MISMATCH, "ERR_CAPSULE_VERDICT_MISMATCH");
    assert_eq!(ERR_SDK_VERSION_UNSUPPORTED, "ERR_SDK_VERSION_UNSUPPORTED");
    assert_eq!(ERR_CAPSULE_ACCESS_DENIED, "ERR_CAPSULE_ACCESS_DENIED");
    Ok(())
}

fn test_invariant_constants() -> Result<(), String> {
    // Invariant identifiers must remain stable - used in compliance checking
    assert_eq!(INV_CAPSULE_STABLE_SCHEMA, "INV-CAPSULE-STABLE-SCHEMA");
    assert_eq!(INV_CAPSULE_VERSIONED_API, "INV-CAPSULE-VERSIONED-API");
    assert_eq!(INV_CAPSULE_NO_PRIVILEGED_ACCESS, "INV-CAPSULE-NO-PRIVILEGED-ACCESS");
    assert_eq!(INV_CAPSULE_VERDICT_REPRODUCIBLE, "INV-CAPSULE-VERDICT-REPRODUCIBLE");
    Ok(())
}

// =============================================================================
// Enum Serialization Contract Tests
// =============================================================================

fn test_verification_verdict_serde() -> Result<(), String> {
    // VerificationVerdict enum must serialize consistently
    let pass = VerificationVerdict::Pass;
    let fail = VerificationVerdict::Fail;
    let inconclusive = VerificationVerdict::Inconclusive;

    // Test serialization
    assert_eq!(serde_json::to_string(&pass).unwrap(), "\"pass\"");
    assert_eq!(serde_json::to_string(&fail).unwrap(), "\"fail\"");
    assert_eq!(serde_json::to_string(&inconclusive).unwrap(), "\"inconclusive\"");

    // Test deserialization (round-trip)
    assert_eq!(serde_json::from_str::<VerificationVerdict>("\"pass\"").unwrap(), pass);
    assert_eq!(serde_json::from_str::<VerificationVerdict>("\"fail\"").unwrap(), fail);
    assert_eq!(serde_json::from_str::<VerificationVerdict>("\"inconclusive\"").unwrap(), inconclusive);

    Ok(())
}

fn test_verification_operation_serde() -> Result<(), String> {
    // VerificationOperation enum must serialize consistently
    let claim = VerificationOperation::Claim;
    let migration = VerificationOperation::MigrationArtifact;
    let trust = VerificationOperation::TrustState;
    let workflow = VerificationOperation::Workflow;

    // Test serialization
    assert_eq!(serde_json::to_string(&claim).unwrap(), "\"claim\"");
    assert_eq!(serde_json::to_string(&migration).unwrap(), "\"migration_artifact\"");
    assert_eq!(serde_json::to_string(&trust).unwrap(), "\"trust_state\"");
    assert_eq!(serde_json::to_string(&workflow).unwrap(), "\"workflow\"");

    // Test round-trip deserialization
    assert_eq!(serde_json::from_str::<VerificationOperation>("\"claim\"").unwrap(), claim);
    assert_eq!(serde_json::from_str::<VerificationOperation>("\"migration_artifact\"").unwrap(), migration);
    assert_eq!(serde_json::from_str::<VerificationOperation>("\"trust_state\"").unwrap(), trust);
    assert_eq!(serde_json::from_str::<VerificationOperation>("\"workflow\"").unwrap(), workflow);

    Ok(())
}

fn test_validation_workflow_serde() -> Result<(), String> {
    // ValidationWorkflow enum must serialize consistently
    let release = ValidationWorkflow::ReleaseValidation;
    let incident = ValidationWorkflow::IncidentValidation;
    let audit = ValidationWorkflow::ComplianceAudit;

    // Test serialization
    assert_eq!(serde_json::to_string(&release).unwrap(), "\"release_validation\"");
    assert_eq!(serde_json::to_string(&incident).unwrap(), "\"incident_validation\"");
    assert_eq!(serde_json::to_string(&audit).unwrap(), "\"compliance_audit\"");

    // Test round-trip
    assert_eq!(serde_json::from_str::<ValidationWorkflow>("\"release_validation\"").unwrap(), release);
    assert_eq!(serde_json::from_str::<ValidationWorkflow>("\"incident_validation\"").unwrap(), incident);
    assert_eq!(serde_json::from_str::<ValidationWorkflow>("\"compliance_audit\"").unwrap(), audit);

    Ok(())
}

// =============================================================================
// Structure JSON Shape Tests
// =============================================================================

fn test_verification_result_json_shape() -> Result<(), String> {
    // VerificationResult must have stable JSON schema for API consumers
    let result: VerificationResult = serde_json::from_value(serde_json::json!({
        "operation": "claim",
        "verdict": "pass",
        "confidence_score": 0.95,
        "checked_assertions": [
            {
                "assertion": "test_assertion",
                "passed": true,
                "detail": "test detail"
            }
        ],
        "execution_timestamp": "2026-04-21T12:00:00Z",
        "verifier_identity": "test-verifier",
        "artifact_binding_hash": "abc123",
        "verifier_signature": "def456",
        "sdk_version": "vsdk-v1.0"
    }))
    .unwrap();

    let json_str = serde_json::to_string_pretty(&result).unwrap();
    let parsed_value: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // Verify required fields exist and have correct types
    assert!(parsed_value.get("operation").unwrap().is_string());
    assert!(parsed_value.get("verdict").unwrap().is_string());
    assert!(parsed_value.get("confidence_score").unwrap().is_number());
    assert!(parsed_value.get("checked_assertions").unwrap().is_array());
    assert!(parsed_value.get("execution_timestamp").unwrap().is_string());
    assert!(parsed_value.get("verifier_identity").unwrap().is_string());
    assert!(parsed_value.get("artifact_binding_hash").unwrap().is_string());
    assert!(parsed_value.get("verifier_signature").unwrap().is_string());
    assert!(parsed_value.get("sdk_version").unwrap().is_string());

    // Test round-trip deserialization
    let roundtrip: VerificationResult = serde_json::from_str(&json_str).unwrap();
    assert_eq!(result, roundtrip);

    Ok(())
}

fn test_session_step_json_shape() -> Result<(), String> {
    // SessionStep must have stable JSON schema
    let step = SessionStep {
        step_index: 1,
        operation: VerificationOperation::Claim,
        verdict: VerificationVerdict::Pass,
        artifact_binding_hash: "abc123".to_string(),
        timestamp: "2026-04-21T12:00:00Z".to_string(),
        step_signature: "sig123".to_string(),
    };

    let json_str = serde_json::to_string_pretty(&step).unwrap();
    let parsed_value: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // Verify required fields
    assert!(parsed_value.get("step_index").unwrap().is_number());
    assert!(parsed_value.get("operation").unwrap().is_string());
    assert!(parsed_value.get("verdict").unwrap().is_string());
    assert!(parsed_value.get("artifact_binding_hash").unwrap().is_string());
    assert!(parsed_value.get("timestamp").unwrap().is_string());
    assert!(parsed_value.get("step_signature").unwrap().is_string());

    // Test round-trip
    let roundtrip: SessionStep = serde_json::from_str(&json_str).unwrap();
    assert_eq!(step, roundtrip);

    Ok(())
}

fn test_transparency_log_entry_json_shape() -> Result<(), String> {
    // TransparencyLogEntry must have stable JSON schema
    let entry = TransparencyLogEntry {
        result_hash: "hash123".to_string(),
        timestamp: "2026-04-21T12:00:00Z".to_string(),
        verifier_id: "test-verifier".to_string(),
        merkle_proof: vec!["proof1".to_string(), "proof2".to_string()],
    };

    let json_str = serde_json::to_string_pretty(&entry).unwrap();
    let parsed_value: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // Verify required fields
    assert!(parsed_value.get("result_hash").unwrap().is_string());
    assert!(parsed_value.get("timestamp").unwrap().is_string());
    assert!(parsed_value.get("verifier_id").unwrap().is_string());
    assert!(parsed_value.get("merkle_proof").unwrap().is_array());

    // Test round-trip
    let roundtrip: TransparencyLogEntry = serde_json::from_str(&json_str).unwrap();
    assert_eq!(entry, roundtrip);

    Ok(())
}

// =============================================================================
// Error Display Format Tests
// =============================================================================

fn test_verifier_sdk_error_display() -> Result<(), String> {
    // Error display formats must be stable for downstream error parsing
    let unsupported = VerifierSdkError::UnsupportedSdk("test message".to_string());
    let empty_anchor = VerifierSdkError::EmptyTrustAnchor;
    let session_sealed = VerifierSdkError::SessionSealed("session-123".to_string());
    let signature_mismatch = VerifierSdkError::ResultSignatureMismatch {
        expected: "expected_sig".to_string(),
        actual: "actual_sig".to_string(),
    };
    let json_error = VerifierSdkError::Json("json parse error".to_string());

    // Test display formats
    assert_eq!(format!("{}", unsupported), "test message");
    assert_eq!(format!("{}", empty_anchor), "trust anchor is empty");
    assert_eq!(format!("{}", session_sealed), "verification session session-123 is sealed");
    assert!(format!("{}", signature_mismatch).contains("verifier SDK result signature mismatch"));
    assert_eq!(format!("{}", json_error), "verifier SDK JSON error: json parse error");

    Ok(())
}

// =============================================================================
// Function Behavior Tests
// =============================================================================

fn test_check_sdk_version_function() -> Result<(), String> {
    // check_sdk_version function behavior must be stable
    assert!(check_sdk_version("vsdk-v1.0").is_ok());

    let err = check_sdk_version("invalid-version").unwrap_err();
    assert!(err.contains("ERR_SDK_VERSION_UNSUPPORTED"));
    assert!(err.contains("requested=invalid-version"));
    assert!(err.contains("supported=vsdk-v1.0"));

    Ok(())
}

fn test_verifier_sdk_new_function() -> Result<(), String> {
    // VerifierSdk::new function behavior must be stable
    let sdk = VerifierSdk::new("test-verifier");

    assert_eq!(sdk.verifier_identity, "test-verifier");
    assert_eq!(sdk.sdk_version, "vsdk-v1.0");

    // Config must contain required keys
    assert!(sdk.config.contains_key("schema_version"));
    assert!(sdk.config.contains_key("security_posture"));
    assert_eq!(sdk.config.get("schema_version").unwrap(), "vsdk-v1.0");

    Ok(())
}

// =============================================================================
// Test Matrix Definition
// =============================================================================

const API_CONTRACT_TESTS: &[ApiContractTest] = &[
    // Constants - MUST level (breaking changes not allowed)
    ApiContractTest {
        id: "API-CONST-001",
        category: TestCategory::Constants,
        level: RequirementLevel::Must,
        description: "SDK_VERSION constant must remain 'vsdk-v1.0'",
        test_fn: test_sdk_version_constant,
    },
    ApiContractTest {
        id: "API-CONST-002",
        category: TestCategory::Constants,
        level: RequirementLevel::Must,
        description: "SDK_VERSION_MIN constant must remain 'vsdk-v1.0'",
        test_fn: test_sdk_version_min_constant,
    },
    ApiContractTest {
        id: "API-CONST-003",
        category: TestCategory::Constants,
        level: RequirementLevel::Must,
        description: "Event code constants must remain stable",
        test_fn: test_event_codes_constants,
    },
    ApiContractTest {
        id: "API-CONST-004",
        category: TestCategory::Constants,
        level: RequirementLevel::Must,
        description: "Error code constants must remain stable",
        test_fn: test_error_codes_constants,
    },
    ApiContractTest {
        id: "API-CONST-005",
        category: TestCategory::Constants,
        level: RequirementLevel::Must,
        description: "Invariant constants must remain stable",
        test_fn: test_invariant_constants,
    },

    // Enums - MUST level (serde names cannot change)
    ApiContractTest {
        id: "API-ENUM-001",
        category: TestCategory::Enums,
        level: RequirementLevel::Must,
        description: "VerificationVerdict enum serde must remain stable",
        test_fn: test_verification_verdict_serde,
    },
    ApiContractTest {
        id: "API-ENUM-002",
        category: TestCategory::Enums,
        level: RequirementLevel::Must,
        description: "VerificationOperation enum serde must remain stable",
        test_fn: test_verification_operation_serde,
    },
    ApiContractTest {
        id: "API-ENUM-003",
        category: TestCategory::Enums,
        level: RequirementLevel::Must,
        description: "ValidationWorkflow enum serde must remain stable",
        test_fn: test_validation_workflow_serde,
    },

    // Structures - MUST level (JSON shape cannot change)
    ApiContractTest {
        id: "API-STRUCT-001",
        category: TestCategory::Structures,
        level: RequirementLevel::Must,
        description: "VerificationResult JSON shape must remain stable",
        test_fn: test_verification_result_json_shape,
    },
    ApiContractTest {
        id: "API-STRUCT-002",
        category: TestCategory::Structures,
        level: RequirementLevel::Must,
        description: "SessionStep JSON shape must remain stable",
        test_fn: test_session_step_json_shape,
    },
    ApiContractTest {
        id: "API-STRUCT-003",
        category: TestCategory::Structures,
        level: RequirementLevel::Must,
        description: "TransparencyLogEntry JSON shape must remain stable",
        test_fn: test_transparency_log_entry_json_shape,
    },

    // Error handling - SHOULD level (display can improve, semantics cannot)
    ApiContractTest {
        id: "API-ERROR-001",
        category: TestCategory::ErrorHandling,
        level: RequirementLevel::Should,
        description: "VerifierSdkError display formats should remain stable",
        test_fn: test_verifier_sdk_error_display,
    },

    // Functions - MUST level (signature and behavior cannot change)
    ApiContractTest {
        id: "API-FUNC-001",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "check_sdk_version function behavior must remain stable",
        test_fn: test_check_sdk_version_function,
    },
    ApiContractTest {
        id: "API-FUNC-002",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::new function behavior must remain stable",
        test_fn: test_verifier_sdk_new_function,
    },
];

// =============================================================================
// Main Conformance Test Runner
// =============================================================================

#[test]
fn public_api_conformance_suite() {
    let mut results = Vec::new();
    let mut must_pass = 0;
    let mut must_fail = 0;
    let mut should_pass = 0;
    let mut should_fail = 0;

    println!("Running Public API Conformance Suite...");
    println!("======================================");

    for test_case in API_CONTRACT_TESTS {
        print!("Running {} ... ", test_case.id);

        let result = (test_case.test_fn)();
        let verdict = match result {
            Ok(_) => {
                match test_case.level {
                    RequirementLevel::Must => must_pass += 1,
                    RequirementLevel::Should => should_pass += 1,
                    RequirementLevel::May => {},
                }
                println!("PASS");
                "PASS"
            }
            Err(error) => {
                match test_case.level {
                    RequirementLevel::Must => {
                        must_fail += 1;
                        eprintln!("FAIL (MUST): {}: {}", test_case.description, error);
                    }
                    RequirementLevel::Should => {
                        should_fail += 1;
                        eprintln!("FAIL (SHOULD): {}: {}", test_case.description, error);
                    }
                    RequirementLevel::May => {
                        eprintln!("FAIL (MAY): {}: {}", test_case.description, error);
                    }
                }
                println!("FAIL");
                "FAIL"
            }
        };

        // Structured JSON-line output for CI parsing
        let json_result = json!({
            "test_id": test_case.id,
            "category": format!("{:?}", test_case.category),
            "level": format!("{:?}", test_case.level),
            "description": test_case.description,
            "verdict": verdict
        });
        eprintln!("{}", json_result);
        results.push(json_result);
    }

    let must_total = must_pass + must_fail;
    let should_total = should_pass + should_fail;
    let total_tests = API_CONTRACT_TESTS.len();

    println!("\n=== Public API Conformance Summary ===");
    println!("MUST requirements:   {}/{} pass ({:.1}%)", must_pass, must_total,
        if must_total > 0 { must_pass as f64 / must_total as f64 * 100.0 } else { 100.0 });
    println!("SHOULD requirements: {}/{} pass ({:.1}%)", should_pass, should_total,
        if should_total > 0 { should_pass as f64 / should_total as f64 * 100.0 } else { 100.0 });
    println!("Total tests: {}", total_tests);

    // Fail if any MUST requirements failed
    if must_fail > 0 {
        panic!("{} MUST requirements failed - API contract broken!", must_fail);
    }

    // Warn if SHOULD requirements failed
    if should_fail > 0 {
        eprintln!("WARNING: {} SHOULD requirements failed - consider major version bump", should_fail);
    }

    println!("✅ Public API contract verified!");
}
