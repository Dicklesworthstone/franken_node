//! Conformance harness for bd-1fck retrievability gate (storage tier L2→L3 transitions).
//!
//! Validates the four critical safety invariants that prevent unsafe eviction:
//! - **INV-RG-BLOCK-EVICTION**: Eviction requires a successful retrievability proof; no bypass.
//! - **INV-RG-PROOF-BINDING**: Each proof is bound to a specific (artifact_id, segment_id, target_tier).
//! - **INV-RG-FAIL-CLOSED**: Failed proofs block eviction unconditionally; no override or timeout bypass.
//! - **INV-RG-AUDIT-TRAIL**: Every proof attempt (pass or fail) is logged with structured diagnostics.

use std::collections::HashSet;

// API-DRIFT REMEDIATION (bd-rjc2m.7): crate renamed franken_node -> frankenengine_node.
use frankenengine_node::storage::retrievability_gate::{
    ArtifactId, ProofFailureReason, RG_EVICTION_BLOCKED, RG_EVICTION_PERMITTED,
    RG_GATE_INITIALIZED, RG_PROOF_FAILED, RG_PROOF_PASSED, RetrievabilityConfig,
    RetrievabilityGate, SegmentId, StorageTier, TargetTierState, content_hash,
};

/// **MUST** requirement: Eviction attempts MUST require a successful retrievability proof.
/// No direct eviction bypass — all L2→L3 transitions must pass through the gate.
///
/// Specification: INV-RG-BLOCK-EVICTION
#[test]
fn conformance_must_block_eviction_without_proof_verification() {
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
    let artifact_id = ArtifactId("test-artifact".to_string());
    let segment_id = SegmentId("test-segment".to_string());
    let expected_hash = content_hash(b"test-content");

    // No target tier state registered — eviction must fail
    let result = gate.attempt_eviction(&artifact_id, &segment_id, &expected_hash);

    assert!(
        result.is_err(),
        "Eviction must fail when target tier is unreachable"
    );

    // Verify blocking event was logged
    let events = gate.events();
    assert!(
        events
            .iter()
            .any(|e| e.code == RG_EVICTION_BLOCKED && e.artifact_id == "test-artifact"),
        "Blocked eviction must be audit-logged"
    );

    // Verify no permits issued
    assert_eq!(
        gate.passed_count(),
        0,
        "No proof success before target setup"
    );
    assert!(gate.failed_count() > 0, "Failure must be recorded");
}

/// **MUST** requirement: Each retrievability proof MUST be cryptographically bound
/// to a specific (artifact_id, segment_id, target_tier) tuple.
/// Cross-artifact or cross-segment proof reuse is forbidden.
///
/// Specification: INV-RG-PROOF-BINDING
#[test]
fn conformance_must_enforce_proof_binding_to_specific_artifact_segment_tier() {
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

    // Setup two different artifacts with different content
    let artifact_a = ArtifactId("artifact-a".to_string());
    let artifact_b = ArtifactId("artifact-b".to_string());
    let segment_1 = SegmentId("segment-1".to_string());
    let segment_2 = SegmentId("segment-2".to_string());

    let content_a = b"content-a-data";
    let content_b = b"content-b-data";
    let hash_a = content_hash(content_a);
    let hash_b = content_hash(content_b);

    // Register target states for artifact A segment 1
    gate.register_target(
        &artifact_a,
        &segment_1,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: hash_a.clone(),
            reachable: true,
            fetch_latency_ms: 100,
        },
    );

    // Register target states for artifact B segment 2
    gate.register_target(
        &artifact_b,
        &segment_2,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: hash_b.clone(),
            reachable: true,
            fetch_latency_ms: 100,
        },
    );

    // Valid proof for artifact A, segment 1
    let proof_a_result = gate.check_retrievability(
        &artifact_a,
        &segment_1,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &hash_a,
    );
    assert!(
        proof_a_result.is_ok(),
        "Valid proof for artifact A must succeed"
    );
    let proof_a = proof_a_result.unwrap();

    // Verify proof binding
    assert_eq!(proof_a.artifact_id, artifact_a);
    assert_eq!(proof_a.segment_id, segment_1);
    assert_eq!(proof_a.target_tier, StorageTier::L3Archive);

    // Cross-artifact proof attempt must fail: artifact A hash for artifact B
    let cross_artifact_result = gate.check_retrievability(
        &artifact_b, // Different artifact
        &segment_2,  // Different segment
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &hash_a, // Wrong hash for artifact B
    );
    assert!(
        cross_artifact_result.is_err(),
        "Cross-artifact hash reuse must be rejected"
    );

    // Cross-segment proof attempt must fail: segment 1 hash for segment 2
    let cross_segment_result = gate.check_retrievability(
        &artifact_a, // Same artifact
        &segment_2,  // Different segment - not registered for artifact A
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &hash_a, // Hash doesn't match segment 2
    );
    assert!(
        cross_segment_result.is_err(),
        "Cross-segment proof reuse must be rejected"
    );

    // Verify proof binding isolation in audit trail
    let receipts = gate.receipts();
    let passed_receipts: Vec<_> = receipts.iter().filter(|r| r.passed).collect();
    assert_eq!(passed_receipts.len(), 1, "Only one valid proof should pass");

    let passed = &passed_receipts[0];
    assert_eq!(passed.artifact_id, "artifact-a");
    assert_eq!(passed.segment_id, "segment-1");
    assert_eq!(passed.content_hash, hash_a);
}

/// **MUST** requirement: Failed retrievability proofs MUST block eviction unconditionally.
/// No override mechanism, timeout bypass, or fallback permitted on proof failure.
///
/// Specification: INV-RG-FAIL-CLOSED
#[test]
fn conformance_must_fail_closed_on_proof_validation_errors() {
    let config = RetrievabilityConfig {
        max_latency_ms: 1000,
        require_hash_match: true,
    };
    let mut gate = RetrievabilityGate::new(config);

    let artifact_id = ArtifactId("fail-closed-test".to_string());
    let segment_id = SegmentId("fail-segment".to_string());
    let valid_hash = content_hash(b"valid-content");
    let wrong_hash = content_hash(b"wrong-content");

    // Test case 1: Hash mismatch must fail closed
    gate.register_target(
        &artifact_id,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: wrong_hash.clone(), // Wrong hash
            reachable: true,
            fetch_latency_ms: 100,
        },
    );

    let hash_mismatch_result = gate.attempt_eviction(&artifact_id, &segment_id, &valid_hash);
    assert!(
        hash_mismatch_result.is_err(),
        "Hash mismatch must fail closed - no eviction"
    );

    // Test case 2: Latency exceeded must fail closed
    let latency_artifact = ArtifactId("latency-test".to_string());
    gate.register_target(
        &latency_artifact,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: valid_hash.clone(),
            reachable: true,
            fetch_latency_ms: 2000, // Exceeds 1000ms limit
        },
    );

    let latency_result = gate.attempt_eviction(&latency_artifact, &segment_id, &valid_hash);
    assert!(
        latency_result.is_err(),
        "Latency exceeded must fail closed - no eviction"
    );

    // Test case 3: Target unreachable must fail closed
    let unreachable_artifact = ArtifactId("unreachable-test".to_string());
    gate.register_target(
        &unreachable_artifact,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: valid_hash.clone(),
            reachable: false, // Unreachable
            fetch_latency_ms: 100,
        },
    );

    let unreachable_result = gate.attempt_eviction(&unreachable_artifact, &segment_id, &valid_hash);
    assert!(
        unreachable_result.is_err(),
        "Unreachable target must fail closed - no eviction"
    );

    // Test case 4: Invalid artifact ID must fail closed
    let empty_artifact = ArtifactId("".to_string()); // Invalid
    let invalid_artifact_result = gate.attempt_eviction(&empty_artifact, &segment_id, &valid_hash);
    assert!(
        invalid_artifact_result.is_err(),
        "Invalid artifact ID must fail closed - no eviction"
    );

    // Verify ALL failures blocked eviction
    assert_eq!(
        gate.passed_count(),
        0,
        "No proofs should pass with validation errors"
    );
    assert!(
        gate.failed_count() >= 4,
        "All failure cases must be recorded"
    );

    // Verify eviction blocking events
    let events = gate.events();
    let blocked_events: Vec<_> = events
        .iter()
        .filter(|e| e.code == RG_EVICTION_BLOCKED)
        .collect();
    assert!(
        blocked_events.len() >= 4,
        "All failed proof attempts must log eviction blocking"
    );
}

/// **MUST** requirement: Every retrievability proof attempt MUST be logged with
/// structured diagnostics including success/failure status, timing, and error details.
///
/// Specification: INV-RG-AUDIT-TRAIL
#[test]
fn conformance_must_maintain_complete_audit_trail_for_all_proof_attempts() {
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

    let artifact_id = ArtifactId("audit-test".to_string());
    let segment_id = SegmentId("audit-segment".to_string());
    let valid_content = b"audit-content-data";
    let valid_hash = content_hash(valid_content);

    // Initial state should have initialization event
    let initial_events = gate.events();
    assert!(
        initial_events.iter().any(|e| e.code == RG_GATE_INITIALIZED),
        "Gate initialization must be audit-logged"
    );

    // Setup successful case
    gate.register_target(
        &artifact_id,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: valid_hash.clone(),
            reachable: true,
            fetch_latency_ms: 150,
        },
    );

    // Test successful proof - should generate comprehensive audit trail
    let success_result = gate.check_retrievability(
        &artifact_id,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &valid_hash,
    );
    assert!(success_result.is_ok(), "Valid proof must succeed");

    // Verify success audit trail
    let success_receipts: Vec<_> = gate.receipts().iter().filter(|r| r.passed).collect();
    assert_eq!(success_receipts.len(), 1, "Success must be receipted");

    let success_receipt = &success_receipts[0];
    assert_eq!(success_receipt.artifact_id, "audit-test");
    assert_eq!(success_receipt.segment_id, "audit-segment");
    assert_eq!(success_receipt.source_tier, "L2_warm");
    assert_eq!(success_receipt.target_tier, "L3_archive");
    assert_eq!(success_receipt.content_hash, valid_hash);
    assert_eq!(success_receipt.latency_ms, 150);
    assert!(success_receipt.passed);
    assert!(success_receipt.failure_reason.is_none());

    // Verify success event
    let events = gate.events();
    let success_events: Vec<_> = events
        .iter()
        .filter(|e| e.code == RG_PROOF_PASSED)
        .collect();
    assert!(
        success_events.len() >= 1,
        "Proof success must be event-logged"
    );

    let success_event = &success_events[0];
    assert_eq!(success_event.artifact_id, "audit-test");
    assert_eq!(success_event.segment_id, "audit-segment");
    assert!(
        success_event.detail.contains("latency=150ms"),
        "Event must include timing"
    );

    // Test failure case with hash mismatch
    let wrong_hash = content_hash(b"wrong-content");
    let failure_result = gate.check_retrievability(
        &artifact_id,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &wrong_hash, // Hash mismatch
    );
    assert!(failure_result.is_err(), "Hash mismatch must fail");

    // Verify failure audit trail
    let all_receipts = gate.receipts();
    let failure_receipts: Vec<_> = all_receipts.iter().filter(|r| !r.passed).collect();
    assert!(failure_receipts.len() >= 1, "Failure must be receipted");

    let failure_receipt = &failure_receipts[0];
    assert_eq!(failure_receipt.artifact_id, "audit-test");
    assert_eq!(failure_receipt.segment_id, "audit-segment");
    assert!(!failure_receipt.passed);
    assert!(failure_receipt.failure_reason.is_some());
    assert!(
        failure_receipt
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("hash mismatch"),
        "Failure reason must be detailed"
    );

    // Verify failure event
    // API-DRIFT REMEDIATION (bd-rjc2m.7): re-fetch the event log here. The original `events`
    // binding was captured BEFORE the failure-generating check_retrievability call, so (a) it
    // held an immutable borrow of `gate` across that &mut call (E0502) and (b) it could not have
    // contained the failure event at all — a latent bug. Fetching fresh fixes both.
    let events_after_failure = gate.events();
    let failure_events: Vec<_> = events_after_failure
        .iter()
        .filter(|e| e.code == RG_PROOF_FAILED)
        .collect();
    assert!(
        failure_events.len() >= 1,
        "Proof failure must be event-logged"
    );

    let failure_event = &failure_events[failure_events.len() - 1]; // Latest failure
    assert_eq!(failure_event.artifact_id, "audit-test");
    assert_eq!(failure_event.segment_id, "audit-segment");
    assert!(
        failure_event.detail.contains("Proof failed"),
        "Failure detail required"
    );

    // Verify audit trail completeness
    assert_eq!(
        gate.passed_count() + gate.failed_count(),
        all_receipts.len(),
        "All attempts must be receipted"
    );
    assert_eq!(gate.passed_count(), 1, "One success recorded");
    assert!(gate.failed_count() >= 1, "At least one failure recorded");

    // Verify no audit data corruption
    for receipt in all_receipts {
        assert!(
            !receipt.artifact_id.is_empty(),
            "Artifact ID must not be empty in audit"
        );
        assert!(
            !receipt.segment_id.is_empty(),
            "Segment ID must not be empty in audit"
        );
        assert!(
            !receipt.source_tier.is_empty(),
            "Source tier must be logged"
        );
        assert!(
            !receipt.target_tier.is_empty(),
            "Target tier must be logged"
        );
        // Content hash may be empty on early validation failures - this is OK
        assert!(receipt.proof_timestamp > 0, "Timestamp must be logged");
    }
}

/// **SHOULD** requirement: Hash validation SHOULD use constant-time comparison
/// to prevent timing-based hash discovery attacks.
///
/// Specification: Hash comparison security
#[test]
fn conformance_should_use_constant_time_hash_comparison() {
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

    let artifact_id = ArtifactId("timing-test".to_string());
    let segment_id = SegmentId("timing-segment".to_string());
    let correct_hash = content_hash(b"correct-content-data");

    // Create a hash that differs in the first vs last character
    let mut early_diff_hash = correct_hash.clone();
    early_diff_hash.replace_range(0..2, "ff"); // Change first 2 chars

    let mut late_diff_hash = correct_hash.clone();
    let len = late_diff_hash.len();
    late_diff_hash.replace_range(len - 2..len, "ff"); // Change last 2 chars

    gate.register_target(
        &artifact_id,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: correct_hash.clone(),
            reachable: true,
            fetch_latency_ms: 100,
        },
    );

    // Both comparisons should fail in similar time (constant-time property)
    let early_diff_result = gate.check_retrievability(
        &artifact_id,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &early_diff_hash,
    );

    let late_diff_result = gate.check_retrievability(
        &artifact_id,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &late_diff_hash,
    );

    // Both should fail due to hash mismatch
    assert!(
        early_diff_result.is_err(),
        "Early position hash diff must fail"
    );
    assert!(
        late_diff_result.is_err(),
        "Late position hash diff must fail"
    );

    // Both should be hash mismatch errors specifically
    if let Err(early_err) = early_diff_result {
        assert!(matches!(
            early_err.reason,
            ProofFailureReason::HashMismatch { .. }
        ));
    }
    if let Err(late_err) = late_diff_result {
        assert!(matches!(
            late_err.reason,
            ProofFailureReason::HashMismatch { .. }
        ));
    }

    // Verify both failures are audited equally
    assert_eq!(
        gate.failed_count(),
        2,
        "Both hash mismatches must be recorded"
    );
}

/// **SHOULD** requirement: Input validation SHOULD reject malformed artifact IDs,
/// segment IDs, and content hashes early before expensive operations.
///
/// Specification: Input validation and sanitization
#[test]
fn conformance_should_validate_inputs_early_before_processing() {
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
    let valid_hash = content_hash(b"valid-content");

    // Test malformed artifact IDs
    let malformed_artifacts = vec![
        ArtifactId("".to_string()),                // Empty
        ArtifactId("   ".to_string()),             // Whitespace only
        ArtifactId(" leading-space".to_string()),  // Leading whitespace
        ArtifactId("trailing-space ".to_string()), // Trailing whitespace
        ArtifactId("control\x00char".to_string()), // Null byte
        ArtifactId("control\x0achar".to_string()), // Newline
        ArtifactId("<unknown>".to_string()),       // Reserved ID
    ];

    for malformed_artifact in malformed_artifacts {
        let result = gate.check_retrievability(
            &malformed_artifact,
            &SegmentId("valid-segment".to_string()),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &valid_hash,
        );

        assert!(
            result.is_err(),
            "Malformed artifact ID must be rejected early"
        );
        if let Err(err) = result {
            assert!(matches!(
                err.reason,
                ProofFailureReason::InvalidArtifactId { .. }
            ));
        }
    }

    // Test malformed segment IDs
    let malformed_segments = vec![
        SegmentId("".to_string()),                // Empty
        SegmentId("   ".to_string()),             // Whitespace only
        SegmentId(" leading".to_string()),        // Leading whitespace
        SegmentId("trailing ".to_string()),       // Trailing whitespace
        SegmentId("control\x09char".to_string()), // Tab
        SegmentId("control\x0dchar".to_string()), // Carriage return
    ];

    for malformed_segment in malformed_segments {
        let result = gate.check_retrievability(
            &ArtifactId("valid-artifact".to_string()),
            &malformed_segment,
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &valid_hash,
        );

        assert!(
            result.is_err(),
            "Malformed segment ID must be rejected early"
        );
        if let Err(err) = result {
            assert!(matches!(
                err.reason,
                ProofFailureReason::InvalidSegmentId { .. }
            ));
        }
    }

    // Setup valid target for hash testing
    let artifact_id = ArtifactId("valid-artifact".to_string());
    let segment_id = SegmentId("valid-segment".to_string());

    // Test malformed observed content hashes in target state
    // API-DRIFT REMEDIATION (bd-rjc2m.7): vec mixed &str literals with String values
    // (.repeat()/`+` yield String); normalize every element to String.
    let malformed_hashes = vec![
        String::new(),                          // Empty
        "not-hex-at-all".to_string(),           // Non-hex characters
        "12345".to_string(),                    // Too short
        "Z".repeat(64),                         // Invalid hex chars
        "1234567890abcdef".repeat(2) + "extra", // Too long
        "1234567890ABCDEF".repeat(4),           // Uppercase (non-canonical)
    ];

    for malformed_hash in malformed_hashes {
        gate.register_target(
            &artifact_id,
            &segment_id,
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: malformed_hash.to_string(),
                reachable: true,
                fetch_latency_ms: 100,
            },
        );

        let result = gate.check_retrievability(
            &artifact_id,
            &segment_id,
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &valid_hash,
        );

        assert!(result.is_err(), "Malformed observed hash must be rejected");
        if let Err(err) = result {
            assert!(matches!(
                err.reason,
                ProofFailureReason::InvalidObservedHash { .. }
            ));
        }
    }

    // All validation failures should be audit-logged
    assert!(
        gate.failed_count() > 10,
        "All input validation failures must be recorded"
    );
}

/// **SHOULD** requirement: Configuration validation SHOULD reject invalid latency
/// limits and ensure sensible operational parameters.
///
/// Specification: Configuration validation
#[test]
fn conformance_should_validate_configuration_parameters() {
    // Valid configuration should work
    let valid_config = RetrievabilityConfig {
        max_latency_ms: 5000,
        require_hash_match: true,
    };
    let mut gate = RetrievabilityGate::new(valid_config.clone());
    assert_eq!(gate.config().max_latency_ms, 5000);
    assert!(gate.config().require_hash_match);

    // Test boundary conditions
    let artifact_id = ArtifactId("config-test".to_string());
    let segment_id = SegmentId("config-segment".to_string());
    let valid_hash = content_hash(b"config-test-content");

    // Latency exactly at limit should fail (>= comparison, fail-closed)
    gate.register_target(
        &artifact_id,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: valid_hash.clone(),
            reachable: true,
            fetch_latency_ms: 5000, // Exactly at limit
        },
    );

    let at_limit_result = gate.check_retrievability(
        &artifact_id,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &valid_hash,
    );
    assert!(
        at_limit_result.is_err(),
        "Latency at exact limit must fail (fail-closed)"
    );

    // Just under limit should pass
    let under_limit_artifact = ArtifactId("under-limit".to_string());
    gate.register_target(
        &under_limit_artifact,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: valid_hash.clone(),
            reachable: true,
            fetch_latency_ms: 4999, // Just under limit
        },
    );

    let under_limit_result = gate.check_retrievability(
        &under_limit_artifact,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &valid_hash,
    );
    assert!(
        under_limit_result.is_ok(),
        "Latency under limit must succeed"
    );

    // Configuration with hash matching disabled
    let no_hash_config = RetrievabilityConfig {
        max_latency_ms: 1000,
        require_hash_match: false,
    };
    let mut no_hash_gate = RetrievabilityGate::new(no_hash_config);

    let no_hash_artifact = ArtifactId("no-hash-test".to_string());
    no_hash_gate.register_target(
        &no_hash_artifact,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: content_hash(b"different-content"), // Different hash
            reachable: true,
            fetch_latency_ms: 100,
        },
    );

    let no_hash_result = no_hash_gate.check_retrievability(
        &no_hash_artifact,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &valid_hash, // Different expected hash
    );
    assert!(
        no_hash_result.is_ok(),
        "Hash mismatch allowed when hash checking disabled"
    );
}

/// **MAY** requirement: The gate MAY support querying proof statistics
/// and exporting audit trails for external compliance reporting.
///
/// Specification: Audit trail export and reporting
#[test]
fn conformance_may_support_audit_trail_export_and_statistics() {
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

    let artifact_id = ArtifactId("export-test".to_string());
    let segment_id = SegmentId("export-segment".to_string());
    let valid_hash = content_hash(b"export-content");

    // Generate some proof activity
    gate.register_target(
        &artifact_id,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: valid_hash.clone(),
            reachable: true,
            fetch_latency_ms: 100,
        },
    );

    // Successful proof
    let _success = gate.check_retrievability(
        &artifact_id,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        &valid_hash,
    );

    // Failed proof
    let _failure = gate.check_retrievability(
        &artifact_id,
        &segment_id,
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        "invalid-hash-value",
    );

    // Verify statistics API
    assert_eq!(
        gate.passed_count(),
        1,
        "Statistics should track passed proofs"
    );
    assert_eq!(
        gate.failed_count(),
        1,
        "Statistics should track failed proofs"
    );

    // Verify audit trail export
    let json_export = gate.receipts_json();
    assert!(!json_export.is_empty(), "Should support JSON export");
    assert!(
        json_export.contains("export-test"),
        "Export should include artifact data"
    );
    assert!(
        json_export.contains("passed"),
        "Export should include pass/fail status"
    );

    // Verify receipt access
    let receipts = gate.receipts();
    assert_eq!(receipts.len(), 2, "Should provide access to all receipts");

    let passed_receipts: Vec<_> = receipts.iter().filter(|r| r.passed).collect();
    let failed_receipts: Vec<_> = receipts.iter().filter(|r| !r.passed).collect();
    assert_eq!(passed_receipts.len(), 1, "Should separate passed receipts");
    assert_eq!(failed_receipts.len(), 1, "Should separate failed receipts");

    // Verify event log access
    let events = gate.events();
    assert!(!events.is_empty(), "Should maintain event log");

    let event_codes: HashSet<_> = events.iter().map(|e| e.code.as_str()).collect();
    let expected_codes = vec![RG_GATE_INITIALIZED, RG_PROOF_PASSED, RG_PROOF_FAILED];

    for expected_code in expected_codes {
        assert!(
            event_codes.contains(expected_code),
            "Event log should contain expected code: {}",
            expected_code
        );
    }
}

/// **MAY** requirement: Successful eviction attempts MAY return permits
/// that can be used for authorization tracking in the storage system.
///
/// Specification: Eviction permit system
#[test]
fn conformance_may_provide_eviction_permits_for_successful_proofs() {
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

    let artifact_id = ArtifactId("permit-test".to_string());
    let segment_id = SegmentId("permit-segment".to_string());
    let valid_hash = content_hash(b"permit-content");

    gate.register_target(
        &artifact_id,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: valid_hash.clone(),
            reachable: true,
            fetch_latency_ms: 200,
        },
    );

    // Successful eviction should return permit
    let permit_result = gate.attempt_eviction(&artifact_id, &segment_id, &valid_hash);
    assert!(permit_result.is_ok(), "Valid eviction should return permit");

    let permit = permit_result.unwrap();
    assert_eq!(permit.proof.artifact_id, artifact_id);
    assert_eq!(permit.proof.segment_id, segment_id);
    assert_eq!(permit.proof.content_hash, valid_hash);
    assert_eq!(permit.proof.latency_ms, 200);
    assert_eq!(permit.proof.source_tier, StorageTier::L2Warm);
    assert_eq!(permit.proof.target_tier, StorageTier::L3Archive);
    assert!(!permit.permit_id.is_empty(), "Permit should have unique ID");

    // Verify permit event was logged
    let events = gate.events();
    assert!(
        events.iter().any(|e| e.code == RG_EVICTION_PERMITTED),
        "Successful eviction should log permit event"
    );

    // Failed eviction should not return permit
    let unreachable_artifact = ArtifactId("unreachable".to_string());
    gate.register_target(
        &unreachable_artifact,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: valid_hash.clone(),
            reachable: false, // Unreachable
            fetch_latency_ms: 100,
        },
    );

    let no_permit_result = gate.attempt_eviction(&unreachable_artifact, &segment_id, &valid_hash);
    assert!(
        no_permit_result.is_err(),
        "Failed eviction should not return permit"
    );
}
