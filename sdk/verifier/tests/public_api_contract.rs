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
use serde::Deserialize;
use serde_json::{json, Value};

/// API contract requirement levels for test prioritization
#[derive(Debug, Clone, Copy)]
enum RequirementLevel {
    Must,   // Breaking changes are NOT allowed
    Should, // Breaking changes require major version bump
    May,    // Breaking changes allowed with documentation
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

#[derive(Debug, Deserialize)]
struct ErrorMatrixFixture {
    bundle_errors: Vec<ErrorMatrixEntry>,
    sdk_errors: Vec<ErrorMatrixEntry>,
}

#[derive(Debug, Deserialize)]
struct ErrorMatrixEntry {
    error_type: String,
    error_data: Value,
    expected_display: String,
}

fn make_structural_bundle_bytes(verifier_identity: &str) -> Result<Vec<u8>, String> {
    let artifact_bytes = br#"{"event":"replay"}"#;
    let artifact_path = "artifacts/replay.json".to_string();
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        artifact_path.clone(),
        bundle::BundleArtifact {
            media_type: "application/json".to_string(),
            digest: bundle::hash(artifact_bytes),
            bytes_hex: hex::encode(artifact_bytes),
        },
    );

    let mut replay_bundle = bundle::ReplayBundle {
        header: bundle::BundleHeader {
            hash_algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            payload_length_bytes: u64::try_from(artifact_bytes.len())
                .map_err(|err| format!("artifact length conversion failed: {err}"))?,
            chunk_count: 1,
        },
        schema_version: bundle::REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "bundle-contract-001".to_string(),
        incident_id: "incident-contract-001".to_string(),
        created_at: "2026-04-23T12:00:00Z".to_string(),
        policy_version: "policy.v1".to_string(),
        verifier_identity: verifier_identity.to_string(),
        timeline: vec![bundle::TimelineEvent {
            sequence_number: 1,
            event_id: "evt-contract-001".to_string(),
            timestamp: "2026-04-23T12:00:01Z".to_string(),
            event_type: "verification.started".to_string(),
            payload: json!({"phase": "replay"}),
            state_snapshot: json!({"step": 1}),
            causal_parent: None,
            policy_version: "policy.v1".to_string(),
        }],
        initial_state_snapshot: json!({"baseline": true}),
        evidence_refs: vec!["evidence://capsule/contract".to_string()],
        artifacts,
        chunks: vec![bundle::BundleChunk {
            chunk_index: 0,
            total_chunks: 1,
            artifact_path,
            payload_length_bytes: u64::try_from(artifact_bytes.len())
                .map_err(|err| format!("chunk length conversion failed: {err}"))?,
            payload_digest: bundle::hash(artifact_bytes),
        }],
        metadata: BTreeMap::new(),
        integrity_hash: String::new(),
        signature: bundle::BundleSignature {
            algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            signature_hex: String::new(),
        },
    };

    bundle::seal(&mut replay_bundle).map_err(|err| err.to_string())?;
    bundle::serialize(&replay_bundle).map_err(|err| err.to_string())
}

fn load_error_matrix_fixture() -> Result<ErrorMatrixFixture, String> {
    serde_json::from_str(include_str!("fixtures/public_api/error_matrix.json"))
        .map_err(|err| format!("failed to parse error_matrix fixture: {err}"))
}

fn load_api_manifest_fixture() -> Result<Value, String> {
    serde_json::from_str(include_str!("fixtures/public_api/api_manifest.json"))
        .map_err(|err| format!("failed to parse api_manifest fixture: {err}"))
}

fn parse_public_api_fixture(raw: &str, fixture_name: &str) -> Result<Value, String> {
    serde_json::from_str(raw)
        .map_err(|err| format!("failed to parse {fixture_name} fixture: {err}"))
}

fn load_facade_result_fixture() -> Result<Value, String> {
    parse_public_api_fixture(
        include_str!("fixtures/public_api/facade_result.json"),
        "facade_result",
    )
}

fn load_session_step_fixture() -> Result<Value, String> {
    parse_public_api_fixture(
        include_str!("fixtures/public_api/session_step.json"),
        "session_step",
    )
}

fn load_transparency_entry_fixture() -> Result<Value, String> {
    parse_public_api_fixture(
        include_str!("fixtures/public_api/transparency_entry.json"),
        "transparency_entry",
    )
}

fn fixture_string<'a>(value: &'a Value, context: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{context} must be a string"))
}

fn fixture_object<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))
}

fn fixture_object_string<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> Result<&'a str, String> {
    fixture_object(value, context)?
        .get(key)
        .ok_or_else(|| format!("{context}.{key} is missing"))?
        .as_str()
        .ok_or_else(|| format!("{context}.{key} must be a string"))
}

fn bundle_error_display_from_fixture(entry: &ErrorMatrixEntry) -> Result<String, String> {
    let display = match entry.error_type.as_str() {
        "Json" => format!(
            "{}",
            bundle::BundleError::Json(fixture_string(&entry.error_data, "bundle Json.error_data")?.to_string())
        ),
        "UnsupportedSchema" => format!(
            "{}",
            bundle::BundleError::UnsupportedSchema {
                expected: fixture_object_string(
                    &entry.error_data,
                    "expected",
                    "bundle UnsupportedSchema.error_data",
                )?
                .to_string(),
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "bundle UnsupportedSchema.error_data",
                )?
                .to_string(),
            }
        ),
        "UnsupportedSdk" => format!(
            "{}",
            bundle::BundleError::UnsupportedSdk {
                expected: fixture_object_string(
                    &entry.error_data,
                    "expected",
                    "bundle UnsupportedSdk.error_data",
                )?
                .to_string(),
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "bundle UnsupportedSdk.error_data",
                )?
                .to_string(),
            }
        ),
        "UnsupportedHashAlgorithm" => format!(
            "{}",
            bundle::BundleError::UnsupportedHashAlgorithm {
                expected: fixture_object_string(
                    &entry.error_data,
                    "expected",
                    "bundle UnsupportedHashAlgorithm.error_data",
                )?
                .to_string(),
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "bundle UnsupportedHashAlgorithm.error_data",
                )?
                .to_string(),
            }
        ),
        "MissingField" => {
            let field = fixture_object_string(
                &entry.error_data,
                "field",
                "bundle MissingField.error_data",
            )?;
            let field = match field {
                "bundle_id" => "bundle_id",
                other => return Err(format!("unsupported bundle MissingField fixture field {other}")),
            };
            format!("{}", bundle::BundleError::MissingField { field })
        }
        "EmptyTimeline" => format!("{}", bundle::BundleError::EmptyTimeline),
        "EmptyArtifacts" => format!("{}", bundle::BundleError::EmptyArtifacts),
        other => return Err(format!("unsupported bundle error fixture type {other}")),
    };
    Ok(display)
}

fn sdk_error_display_from_fixture(entry: &ErrorMatrixEntry) -> Result<String, String> {
    let display = match entry.error_type.as_str() {
        "UnsupportedSdk" => format!(
            "{}",
            VerifierSdkError::UnsupportedSdk(
                fixture_string(&entry.error_data, "sdk UnsupportedSdk.error_data")?.to_string(),
            )
        ),
        "EmptyTrustAnchor" => format!("{}", VerifierSdkError::EmptyTrustAnchor),
        "MalformedTrustAnchor" => format!(
            "{}",
            VerifierSdkError::MalformedTrustAnchor {
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "sdk MalformedTrustAnchor.error_data",
                )?
                .to_string(),
            }
        ),
        "SessionSealed" => format!(
            "{}",
            VerifierSdkError::SessionSealed(
                fixture_string(&entry.error_data, "sdk SessionSealed.error_data")?.to_string(),
            )
        ),
        "InvalidVerifierIdentity" => format!(
            "{}",
            VerifierSdkError::InvalidVerifierIdentity {
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "sdk InvalidVerifierIdentity.error_data",
                )?
                .to_string(),
                reason: fixture_object_string(
                    &entry.error_data,
                    "reason",
                    "sdk InvalidVerifierIdentity.error_data",
                )?
                .to_string(),
            }
        ),
        "InvalidSessionId" => format!(
            "{}",
            VerifierSdkError::InvalidSessionId {
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "sdk InvalidSessionId.error_data",
                )?
                .to_string(),
                reason: fixture_object_string(
                    &entry.error_data,
                    "reason",
                    "sdk InvalidSessionId.error_data",
                )?
                .to_string(),
            }
        ),
        "SessionVerifierMismatch" => format!(
            "{}",
            VerifierSdkError::SessionVerifierMismatch {
                expected: fixture_object_string(
                    &entry.error_data,
                    "expected",
                    "sdk SessionVerifierMismatch.error_data",
                )?
                .to_string(),
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "sdk SessionVerifierMismatch.error_data",
                )?
                .to_string(),
            }
        ),
        "ResultSignatureMismatch" => format!(
            "{}",
            VerifierSdkError::ResultSignatureMismatch {
                expected: fixture_object_string(
                    &entry.error_data,
                    "expected",
                    "sdk ResultSignatureMismatch.error_data",
                )?
                .to_string(),
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "sdk ResultSignatureMismatch.error_data",
                )?
                .to_string(),
            }
        ),
        "ResultOriginMismatch" => format!(
            "{}",
            VerifierSdkError::ResultOriginMismatch {
                expected: fixture_object_string(
                    &entry.error_data,
                    "expected",
                    "sdk ResultOriginMismatch.error_data",
                )?
                .to_string(),
                actual: fixture_object_string(
                    &entry.error_data,
                    "actual",
                    "sdk ResultOriginMismatch.error_data",
                )?
                .to_string(),
            }
        ),
        "Json" => format!(
            "{}",
            VerifierSdkError::Json(fixture_string(&entry.error_data, "sdk Json.error_data")?.to_string())
        ),
        other => return Err(format!("unsupported sdk error fixture type {other}")),
    };
    Ok(display)
}

// =============================================================================
// Constants Contract Tests
// =============================================================================

fn test_sdk_version_constant() -> Result<(), String> {
    assert_eq!(
        SDK_VERSION, "vsdk-v1.0",
        "SDK_VERSION constant changed - BREAKING for downstream consumers"
    );
    Ok(())
}

fn test_sdk_version_min_constant() -> Result<(), String> {
    assert_eq!(
        SDK_VERSION_MIN, "vsdk-v1.0",
        "SDK_VERSION_MIN constant changed - BREAKING for version checks"
    );
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
    assert_eq!(
        ERR_CAPSULE_SIGNATURE_INVALID,
        "ERR_CAPSULE_SIGNATURE_INVALID"
    );
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
    assert_eq!(
        INV_CAPSULE_NO_PRIVILEGED_ACCESS,
        "INV-CAPSULE-NO-PRIVILEGED-ACCESS"
    );
    assert_eq!(
        INV_CAPSULE_VERDICT_REPRODUCIBLE,
        "INV-CAPSULE-VERDICT-REPRODUCIBLE"
    );
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
    assert_eq!(
        serde_json::to_string(&inconclusive).unwrap(),
        "\"inconclusive\""
    );

    // Test deserialization (round-trip)
    assert_eq!(
        serde_json::from_str::<VerificationVerdict>("\"pass\"").unwrap(),
        pass
    );
    assert_eq!(
        serde_json::from_str::<VerificationVerdict>("\"fail\"").unwrap(),
        fail
    );
    assert_eq!(
        serde_json::from_str::<VerificationVerdict>("\"inconclusive\"").unwrap(),
        inconclusive
    );

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
    assert_eq!(
        serde_json::to_string(&migration).unwrap(),
        "\"migration_artifact\""
    );
    assert_eq!(serde_json::to_string(&trust).unwrap(), "\"trust_state\"");
    assert_eq!(serde_json::to_string(&workflow).unwrap(), "\"workflow\"");

    // Test round-trip deserialization
    assert_eq!(
        serde_json::from_str::<VerificationOperation>("\"claim\"").unwrap(),
        claim
    );
    assert_eq!(
        serde_json::from_str::<VerificationOperation>("\"migration_artifact\"").unwrap(),
        migration
    );
    assert_eq!(
        serde_json::from_str::<VerificationOperation>("\"trust_state\"").unwrap(),
        trust
    );
    assert_eq!(
        serde_json::from_str::<VerificationOperation>("\"workflow\"").unwrap(),
        workflow
    );

    Ok(())
}

fn test_validation_workflow_serde() -> Result<(), String> {
    // ValidationWorkflow enum must serialize consistently
    let release = ValidationWorkflow::ReleaseValidation;
    let incident = ValidationWorkflow::IncidentValidation;
    let audit = ValidationWorkflow::ComplianceAudit;

    // Test serialization
    assert_eq!(
        serde_json::to_string(&release).unwrap(),
        "\"release_validation\""
    );
    assert_eq!(
        serde_json::to_string(&incident).unwrap(),
        "\"incident_validation\""
    );
    assert_eq!(
        serde_json::to_string(&audit).unwrap(),
        "\"compliance_audit\""
    );

    // Test round-trip
    assert_eq!(
        serde_json::from_str::<ValidationWorkflow>("\"release_validation\"").unwrap(),
        release
    );
    assert_eq!(
        serde_json::from_str::<ValidationWorkflow>("\"incident_validation\"").unwrap(),
        incident
    );
    assert_eq!(
        serde_json::from_str::<ValidationWorkflow>("\"compliance_audit\"").unwrap(),
        audit
    );

    Ok(())
}

// =============================================================================
// Structure JSON Shape Tests
// =============================================================================

fn test_verification_result_json_shape() -> Result<(), String> {
    // VerificationResult must have stable JSON schema for API consumers
    let sdk = create_verifier_sdk("verifier://shape-test");
    let capsule = capsule::build_reference_capsule();
    let result = sdk
        .verify_claim(&capsule)
        .map_err(|err| format!("expected reference claim verification, got {err:?}"))?;

    let json_str = serde_json::to_string_pretty(&result).unwrap();
    let parsed_value: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // Verify required fields exist and have correct types
    assert!(parsed_value.get("operation").unwrap().is_string());
    assert!(parsed_value.get("verdict").unwrap().is_string());
    assert!(parsed_value.get("confidence_score").unwrap().is_number());
    assert!(parsed_value.get("checked_assertions").unwrap().is_array());
    assert!(parsed_value.get("execution_timestamp").unwrap().is_string());
    assert!(parsed_value.get("verifier_identity").unwrap().is_string());
    assert!(
        parsed_value
            .get("artifact_binding_hash")
            .unwrap()
            .is_string()
    );
    assert!(parsed_value.get("verifier_signature").unwrap().is_string());
    assert!(parsed_value.get("sdk_version").unwrap().is_string());
    assert!(parsed_value.get("result_origin_nonce").is_none());

    Ok(())
}

fn test_verification_result_fixture_matches_live_json_contract() -> Result<(), String> {
    let fixture_value = load_facade_result_fixture()?;
    let fixture: VerificationResult = serde_json::from_value(fixture_value.clone())
        .map_err(|err| format!("failed to deserialize facade_result fixture: {err}"))?;

    let roundtrip_value = serde_json::to_value(&fixture)
        .map_err(|err| format!("failed to serialize facade_result fixture: {err}"))?;
    assert_eq!(
        roundtrip_value, fixture_value,
        "facade_result fixture drifted from the live VerificationResult serde contract"
    );

    assert_eq!(fixture.operation, VerificationOperation::Claim);
    assert_eq!(fixture.verdict, VerificationVerdict::Pass);
    assert!(fixture.confidence_score.is_finite());
    assert!((0.0..=1.0).contains(&fixture.confidence_score));
    assert!(!fixture.checked_assertions.is_empty());
    assert_eq!(fixture.verifier_identity, "verifier://facade-test");
    assert_eq!(fixture.sdk_version, SDK_VERSION);

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
    assert!(
        parsed_value
            .get("artifact_binding_hash")
            .unwrap()
            .is_string()
    );
    assert!(parsed_value.get("timestamp").unwrap().is_string());
    assert!(parsed_value.get("step_signature").unwrap().is_string());

    // Test round-trip
    let roundtrip: SessionStep = serde_json::from_str(&json_str).unwrap();
    assert_eq!(step, roundtrip);

    Ok(())
}

fn test_session_step_fixture_matches_live_json_contract() -> Result<(), String> {
    let fixture_value = load_session_step_fixture()?;
    let fixture: SessionStep = serde_json::from_value(fixture_value.clone())
        .map_err(|err| format!("failed to deserialize session_step fixture: {err}"))?;

    let roundtrip_value = serde_json::to_value(&fixture)
        .map_err(|err| format!("failed to serialize session_step fixture: {err}"))?;
    assert_eq!(
        roundtrip_value, fixture_value,
        "session_step fixture drifted from the live SessionStep serde contract"
    );

    assert_eq!(fixture.step_index, 1);
    assert_eq!(fixture.operation, VerificationOperation::Claim);
    assert_eq!(fixture.verdict, VerificationVerdict::Pass);
    assert!(!fixture.artifact_binding_hash.is_empty());
    assert!(!fixture.step_signature.is_empty());

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

fn test_transparency_entry_fixture_matches_live_json_contract() -> Result<(), String> {
    let fixture_value = load_transparency_entry_fixture()?;
    let fixture: TransparencyLogEntry = serde_json::from_value(fixture_value.clone())
        .map_err(|err| format!("failed to deserialize transparency_entry fixture: {err}"))?;

    let roundtrip_value = serde_json::to_value(&fixture)
        .map_err(|err| format!("failed to serialize transparency_entry fixture: {err}"))?;
    assert_eq!(
        roundtrip_value, fixture_value,
        "transparency_entry fixture drifted from the live TransparencyLogEntry serde contract"
    );

    assert_eq!(fixture.verifier_id, "verifier://facade-test");
    assert!(fixture.merkle_proof.len() >= 3);
    assert!(fixture.merkle_proof[0].starts_with("root:"));
    assert!(fixture.merkle_proof[1].starts_with("leaf_index:"));
    assert!(fixture.merkle_proof[2].starts_with("tree_size:"));

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
    let structural_bundle = VerifierSdkError::UnauthenticatedStructuralBundle {
        bundle_id: "bundle-contract-001".to_string(),
        verifier_identity: "verifier://alpha".to_string(),
    };
    let signature_mismatch = VerifierSdkError::ResultSignatureMismatch {
        expected: "expected_sig".to_string(),
        actual: "actual_sig".to_string(),
    };
    let result_origin_mismatch = VerifierSdkError::ResultOriginMismatch {
        expected: "origin-a".to_string(),
        actual: "origin-b".to_string(),
    };
    let json_error = VerifierSdkError::Json("json parse error".to_string());

    // Test display formats
    assert_eq!(format!("{}", unsupported), "test message");
    assert_eq!(format!("{}", empty_anchor), "trust anchor is empty");
    assert_eq!(
        format!("{}", session_sealed),
        "verification session session-123 is sealed"
    );
    assert!(format!("{}", structural_bundle).contains("structural-only"));
    assert!(format!("{}", signature_mismatch).contains("verifier SDK result signature mismatch"));
    assert!(format!("{}", result_origin_mismatch).contains("result origin mismatch"));
    assert_eq!(
        format!("{}", json_error),
        "verifier SDK JSON error: json parse error"
    );

    Ok(())
}

fn test_error_matrix_fixture_matches_live_error_displays() -> Result<(), String> {
    let fixture = load_error_matrix_fixture()?;

    for entry in &fixture.bundle_errors {
        let actual_display = bundle_error_display_from_fixture(entry)?;
        assert_eq!(
            actual_display, entry.expected_display,
            "bundle fixture drift for {}",
            entry.error_type
        );
    }

    for entry in &fixture.sdk_errors {
        let actual_display = sdk_error_display_from_fixture(entry)?;
        assert_eq!(
            actual_display, entry.expected_display,
            "sdk fixture drift for {}",
            entry.error_type
        );
    }

    Ok(())
}

fn test_api_manifest_fixture_matches_live_public_surface() -> Result<(), String> {
    let fixture = load_api_manifest_fixture()?;
    let expected = json!({
        "api_contract_version": "1.0.0",
        "sdk_version": SDK_VERSION,
        "frozen_at": "2026-04-23T12:00:00Z",
        "public_constants": [
            {
                "name": "SDK_VERSION",
                "value": SDK_VERSION,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "SDK_VERSION_MIN",
                "value": SDK_VERSION_MIN,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "CAPSULE_CREATED",
                "value": CAPSULE_CREATED,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "CAPSULE_SIGNED",
                "value": CAPSULE_SIGNED,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "CAPSULE_REPLAY_START",
                "value": CAPSULE_REPLAY_START,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "CAPSULE_VERDICT_REPRODUCED",
                "value": CAPSULE_VERDICT_REPRODUCED,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "SDK_VERSION_CHECK",
                "value": SDK_VERSION_CHECK,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "ERR_CAPSULE_SIGNATURE_INVALID",
                "value": ERR_CAPSULE_SIGNATURE_INVALID,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "ERR_CAPSULE_SCHEMA_MISMATCH",
                "value": ERR_CAPSULE_SCHEMA_MISMATCH,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "ERR_CAPSULE_REPLAY_DIVERGED",
                "value": ERR_CAPSULE_REPLAY_DIVERGED,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "ERR_CAPSULE_VERDICT_MISMATCH",
                "value": ERR_CAPSULE_VERDICT_MISMATCH,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "ERR_SDK_VERSION_UNSUPPORTED",
                "value": ERR_SDK_VERSION_UNSUPPORTED,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "ERR_CAPSULE_ACCESS_DENIED",
                "value": ERR_CAPSULE_ACCESS_DENIED,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "INV_CAPSULE_STABLE_SCHEMA",
                "value": INV_CAPSULE_STABLE_SCHEMA,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "INV_CAPSULE_VERSIONED_API",
                "value": INV_CAPSULE_VERSIONED_API,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "INV_CAPSULE_NO_PRIVILEGED_ACCESS",
                "value": INV_CAPSULE_NO_PRIVILEGED_ACCESS,
                "type": "string",
                "requirement_level": "must"
            },
            {
                "name": "INV_CAPSULE_VERDICT_REPRODUCIBLE",
                "value": INV_CAPSULE_VERDICT_REPRODUCIBLE,
                "type": "string",
                "requirement_level": "must"
            }
        ],
        "public_enums": [
            {
                "name": "VerificationVerdict",
                "variants": ["pass", "fail", "inconclusive"],
                "serde_representation": "snake_case",
                "requirement_level": "must"
            },
            {
                "name": "VerificationOperation",
                "variants": ["claim", "migration_artifact", "trust_state", "workflow"],
                "serde_representation": "snake_case",
                "requirement_level": "must"
            },
            {
                "name": "ValidationWorkflow",
                "variants": ["release_validation", "incident_validation", "compliance_audit"],
                "serde_representation": "snake_case",
                "requirement_level": "must"
            }
        ],
        "public_structures": [
            {
                "name": "AssertionResult",
                "required_fields": ["assertion", "passed", "detail"],
                "field_types": {
                    "assertion": "String",
                    "passed": "bool",
                    "detail": "String"
                },
                "requirement_level": "must"
            },
            {
                "name": "VerificationResult",
                "required_fields": ["operation", "verdict", "confidence_score", "checked_assertions", "execution_timestamp", "verifier_identity", "artifact_binding_hash", "verifier_signature", "sdk_version"],
                "field_types": {
                    "operation": "VerificationOperation",
                    "verdict": "VerificationVerdict",
                    "confidence_score": "f64",
                    "checked_assertions": "Vec<AssertionResult>",
                    "execution_timestamp": "String",
                    "verifier_identity": "String",
                    "artifact_binding_hash": "String",
                    "verifier_signature": "String",
                    "sdk_version": "String"
                },
                "requirement_level": "must"
            },
            {
                "name": "SessionStep",
                "required_fields": ["step_index", "operation", "verdict", "artifact_binding_hash", "timestamp", "step_signature"],
                "field_types": {
                    "step_index": "usize",
                    "operation": "VerificationOperation",
                    "verdict": "VerificationVerdict",
                    "artifact_binding_hash": "String",
                    "timestamp": "String",
                    "step_signature": "String"
                },
                "requirement_level": "must"
            },
            {
                "name": "TransparencyLogEntry",
                "required_fields": ["result_hash", "timestamp", "verifier_id", "merkle_proof"],
                "field_types": {
                    "result_hash": "String",
                    "timestamp": "String",
                    "verifier_id": "String",
                    "merkle_proof": "Vec<String>"
                },
                "requirement_level": "must"
            }
        ],
        "public_functions": [
            {
                "name": "check_sdk_version",
                "signature": "fn check_sdk_version(version: &str) -> Result<(), String>",
                "behavior": "Returns Ok(()) for supported versions and ERR_SDK_VERSION_UNSUPPORTED details for unsupported versions",
                "requirement_level": "must"
            },
            {
                "name": "VerifierSdk::new",
                "signature": "fn new(verifier_identity: impl Into<String>) -> Self",
                "behavior": "Creates new SDK instance, seeds stable config keys, and defers verifier-identity validation to operational methods",
                "requirement_level": "must"
            }
        ],
        "breaking_change_policy": {
            "constants": "never",
            "enum_variants": "major_version_only",
            "struct_required_fields": "never",
            "struct_optional_fields": "minor_version_ok",
            "function_signatures": "major_version_only",
            "error_display_format": "minor_version_ok"
        }
    });

    assert_eq!(fixture, expected);
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

fn test_verify_migration_artifact_rejects_structural_bundle() -> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let artifact = make_structural_bundle_bytes("verifier://alpha")?;

    match sdk.verify_migration_artifact(&artifact) {
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id,
            verifier_identity,
        }) => {
            assert_eq!(bundle_id, "bundle-contract-001");
            assert_eq!(verifier_identity, "verifier://alpha");
            Ok(())
        }
        Ok(result) => Err(format!(
            "expected structural bundle rejection, got success verdict {:?}",
            result.verdict
        )),
        Err(other) => Err(format!(
            "expected UnauthenticatedStructuralBundle, got {other:?}"
        )),
    }
}

fn test_verify_trust_state_rejects_structural_bundle() -> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let state = make_structural_bundle_bytes("verifier://alpha")?;
    let verified = bundle::verify(&state).map_err(|err| err.to_string())?;

    match sdk.verify_trust_state(&state, &verified.integrity_hash) {
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id,
            verifier_identity,
        }) => {
            assert_eq!(bundle_id, "bundle-contract-001");
            assert_eq!(verifier_identity, "verifier://alpha");
            Ok(())
        }
        Ok(result) => Err(format!(
            "expected structural bundle rejection, got success verdict {:?}",
            result.verdict
        )),
        Err(other) => Err(format!(
            "expected UnauthenticatedStructuralBundle, got {other:?}"
        )),
    }
}

fn test_verify_trust_state_rejects_malformed_trust_anchor() -> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let state = make_structural_bundle_bytes("verifier://alpha")?;

    match sdk.verify_trust_state(&state, "not-a-sha256-digest") {
        Err(VerifierSdkError::MalformedTrustAnchor { actual }) => {
            assert_eq!(actual, "not-a-sha256-digest");
            Ok(())
        }
        Ok(result) => Err(format!(
            "expected malformed trust-anchor rejection, got success verdict {:?}",
            result.verdict
        )),
        Err(other) => Err(format!("expected MalformedTrustAnchor, got {other:?}")),
    }
}

fn test_create_session_rejects_malformed_session_ids() -> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let invalid_cases = [
        ("", "session id must be non-empty"),
        (
            " session-alpha ",
            "session id must not contain leading or trailing whitespace",
        ),
        (
            "session-\u{0000}-alpha",
            "session id must include only ASCII letters, digits, '.', '-', and '_'",
        ),
    ];

    for (session_id, expected_reason) in invalid_cases {
        match sdk.create_session(session_id) {
            Err(VerifierSdkError::InvalidSessionId { actual, reason }) => {
                assert_eq!(actual, session_id);
                assert_eq!(reason, expected_reason);
            }
            Ok(session) => {
                return Err(format!(
                    "expected InvalidSessionId for {session_id:?}, got session {:?}",
                    session.session_id
                ));
            }
            Err(other) => {
                return Err(format!(
                    "expected InvalidSessionId for {session_id:?}, got {other:?}"
                ));
            }
        }
    }

    Ok(())
}

fn test_record_session_step_rejects_same_verifier_result_from_different_sdk_instance()
-> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let sibling_sdk = create_verifier_sdk("verifier://alpha");
    let mut session = sdk
        .create_session("session-contract-alpha")
        .map_err(|err| format!("primary session creation failed: {err}"))?;
    let capsule = capsule::build_reference_capsule();
    let sibling_result = sibling_sdk
        .verify_claim(&capsule)
        .map_err(|err| format!("sibling claim verification failed: {err}"))?;

    match sdk.record_session_step(&mut session, &sibling_result) {
        Err(VerifierSdkError::ResultOriginMismatch { .. }) => Ok(()),
        Ok(step) => Err(format!(
            "expected ResultOriginMismatch, but record_session_step accepted step {step:?}"
        )),
        Err(other) => Err(format!("expected ResultOriginMismatch, got {other:?}")),
    }
}

fn test_append_transparency_log_rejects_same_verifier_result_from_different_sdk_instance()
-> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let sibling_sdk = create_verifier_sdk("verifier://alpha");
    let capsule = capsule::build_reference_capsule();
    let sibling_result = sibling_sdk
        .verify_claim(&capsule)
        .map_err(|err| format!("sibling claim verification failed: {err}"))?;
    let mut log = Vec::new();

    match sdk.append_transparency_log(&mut log, &sibling_result) {
        Err(VerifierSdkError::ResultOriginMismatch { .. }) => Ok(()),
        Ok(entry) => Err(format!(
            "expected ResultOriginMismatch, but append_transparency_log accepted entry {entry:?}"
        )),
        Err(other) => Err(format!("expected ResultOriginMismatch, got {other:?}")),
    }
}

fn test_validate_bundle_accepts_same_verifier_bundle() -> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let bundle = make_structural_bundle_bytes("verifier://alpha")?;

    sdk.validate_bundle(&bundle)
        .map_err(|err| format!("expected same-verifier bundle acceptance, got {err:?}"))
}

fn test_validate_bundle_rejects_foreign_verifier_bundle() -> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let foreign_bundle = make_structural_bundle_bytes("verifier://beta")?;

    match sdk.validate_bundle(&foreign_bundle) {
        Err(VerifierSdkError::SessionVerifierMismatch { expected, actual }) => {
            assert_eq!(expected, "verifier://alpha");
            assert_eq!(actual, "verifier://beta");
            Ok(())
        }
        Ok(()) => Err("expected foreign bundle rejection, got success".to_string()),
        Err(other) => Err(format!(
            "expected SessionVerifierMismatch for foreign bundle, got {other:?}"
        )),
    }
}

fn test_execute_workflow_rejects_structural_bundle() -> Result<(), String> {
    let sdk = create_verifier_sdk("verifier://alpha");
    let bundle = make_structural_bundle_bytes("verifier://alpha")?;

    match sdk.execute_workflow(ValidationWorkflow::ReleaseValidation, &bundle) {
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id,
            verifier_identity,
        }) => {
            assert_eq!(bundle_id, "bundle-contract-001");
            assert_eq!(verifier_identity, "verifier://alpha");
            Ok(())
        }
        Ok(result) => Err(format!(
            "expected structural bundle rejection, got workflow verdict {:?}",
            result.verdict
        )),
        Err(other) => Err(format!(
            "expected UnauthenticatedStructuralBundle, got {other:?}"
        )),
    }
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
    ApiContractTest {
        id: "API-CONST-006",
        category: TestCategory::Constants,
        level: RequirementLevel::Must,
        description: "Frozen API manifest fixture must match the live verifier public surface",
        test_fn: test_api_manifest_fixture_matches_live_public_surface,
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
    ApiContractTest {
        id: "API-STRUCT-004",
        category: TestCategory::Structures,
        level: RequirementLevel::Must,
        description: "facade_result golden JSON fixture must round-trip under the live VerificationResult contract",
        test_fn: test_verification_result_fixture_matches_live_json_contract,
    },
    ApiContractTest {
        id: "API-STRUCT-005",
        category: TestCategory::Structures,
        level: RequirementLevel::Must,
        description: "session_step golden JSON fixture must round-trip under the live SessionStep contract",
        test_fn: test_session_step_fixture_matches_live_json_contract,
    },
    ApiContractTest {
        id: "API-STRUCT-006",
        category: TestCategory::Structures,
        level: RequirementLevel::Must,
        description: "transparency_entry golden JSON fixture must round-trip under the live TransparencyLogEntry contract",
        test_fn: test_transparency_entry_fixture_matches_live_json_contract,
    },
    // Error handling - SHOULD level (display can improve, semantics cannot)
    ApiContractTest {
        id: "API-ERROR-001",
        category: TestCategory::ErrorHandling,
        level: RequirementLevel::Should,
        description: "VerifierSdkError display formats should remain stable",
        test_fn: test_verifier_sdk_error_display,
    },
    ApiContractTest {
        id: "API-ERROR-002",
        category: TestCategory::ErrorHandling,
        level: RequirementLevel::Should,
        description: "Frozen error-matrix fixture must match live bundle and SDK error displays",
        test_fn: test_error_matrix_fixture_matches_live_error_displays,
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
    ApiContractTest {
        id: "API-FUNC-003",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::verify_migration_artifact must reject structural-only same-verifier bundles",
        test_fn: test_verify_migration_artifact_rejects_structural_bundle,
    },
    ApiContractTest {
        id: "API-FUNC-004",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::verify_trust_state must reject structural-only same-verifier bundles",
        test_fn: test_verify_trust_state_rejects_structural_bundle,
    },
    ApiContractTest {
        id: "API-FUNC-005",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::verify_trust_state must reject malformed trust anchors before structural bundle handling",
        test_fn: test_verify_trust_state_rejects_malformed_trust_anchor,
    },
    ApiContractTest {
        id: "API-FUNC-006",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::create_session must reject malformed session ids with stable details",
        test_fn: test_create_session_rejects_malformed_session_ids,
    },
    ApiContractTest {
        id: "API-FUNC-007",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::record_session_step must reject same-verifier results from a different SDK instance",
        test_fn: test_record_session_step_rejects_same_verifier_result_from_different_sdk_instance,
    },
    ApiContractTest {
        id: "API-FUNC-008",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::append_transparency_log must reject same-verifier results from a different SDK instance",
        test_fn:
            test_append_transparency_log_rejects_same_verifier_result_from_different_sdk_instance,
    },
    ApiContractTest {
        id: "API-FUNC-009",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::validate_bundle must accept same-verifier bundles",
        test_fn: test_validate_bundle_accepts_same_verifier_bundle,
    },
    ApiContractTest {
        id: "API-FUNC-010",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::validate_bundle must reject foreign-verifier bundles",
        test_fn: test_validate_bundle_rejects_foreign_verifier_bundle,
    },
    ApiContractTest {
        id: "API-FUNC-011",
        category: TestCategory::Functions,
        level: RequirementLevel::Must,
        description: "VerifierSdk::execute_workflow must reject structural-only same-verifier bundles",
        test_fn: test_execute_workflow_rejects_structural_bundle,
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
                    RequirementLevel::May => {}
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
    println!(
        "MUST requirements:   {}/{} pass ({:.1}%)",
        must_pass,
        must_total,
        if must_total > 0 {
            must_pass as f64 / must_total as f64 * 100.0
        } else {
            100.0
        }
    );
    println!(
        "SHOULD requirements: {}/{} pass ({:.1}%)",
        should_pass,
        should_total,
        if should_total > 0 {
            should_pass as f64 / should_total as f64 * 100.0
        } else {
            100.0
        }
    );
    println!("Total tests: {}", total_tests);

    // Fail if any MUST requirements failed
    if must_fail > 0 {
        panic!(
            "{} MUST requirements failed - API contract broken!",
            must_fail
        );
    }

    // Warn if SHOULD requirements failed
    if should_fail > 0 {
        eprintln!(
            "WARNING: {} SHOULD requirements failed - consider major version bump",
            should_fail
        );
    }

    println!("✅ Public API contract verified!");
}
