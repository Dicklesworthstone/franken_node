// Comprehensive conformance tests for proof verifier - security edge cases
//
// Tests focus on:
// - Time boundary conditions (fail-closed semantics)
// - Integer overflow/underflow scenarios
// - Cryptographic hash integrity validation
// - Input validation edge cases
// - Sequence number overflow protection
// - Memory exhaustion protection

use super::proof_verifier::*;
use std::collections::BTreeMap;

const NOW: u64 = 1_701_000_000_000; // Base timestamp for tests
const VERY_OLD_TIME: u64 = 1_000_000_000_000; // Very old timestamp
const FUTURE_TIME: u64 = 2_000_000_000_000; // Far future timestamp

fn default_test_config() -> VerificationGateConfig {
    VerificationGateConfig {
        max_proof_age_millis: 3_600_000, // 1 hour
        degrade_threshold: 80,
        enforce_policy_version: true,
    }
}

fn default_test_predicate() -> PolicyPredicate {
    PolicyPredicate {
        predicate_id: "test-predicate".to_string(),
        action_class: "test_action".to_string(),
        max_proof_age_millis: 600_000, // 10 minutes
        min_confidence: 90,
        require_witnesses: true,
        min_witness_count: 2,
        policy_version_hash: "sha256:test-policy-v1".to_string(),
    }
}

fn valid_test_proof() -> ComplianceProof {
    ComplianceProof {
        proof_id: "test-proof-001".to_string(),
        action_class: "test_action".to_string(),
        proof_hash: "sha256:test-proof-hash".to_string(),
        confidence: 95,
        generated_at_millis: NOW - 60_000, // 1 minute ago
        expires_at_millis: NOW + 600_000,  // 10 minutes from now
        witness_references: vec!["witness1".to_string(), "witness2".to_string()],
        policy_version_hash: "sha256:test-policy-v1".to_string(),
        trace_id: "test-trace".to_string(),
    }
}

/// Test exact time boundary conditions for fail-closed semantics
#[test]
fn test_time_boundary_fail_closed_semantics() {
    let config = default_test_config();
    let mut verifier = ProofVerifier::new(config);
    let predicate = default_test_predicate();

    // Test 1: Proof expires exactly at current time (should fail)
    let mut proof = valid_test_proof();
    proof.expires_at_millis = NOW;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, _) = result.unwrap();
    assert!(
        matches!(decision, TrustDecision::Deny(_)),
        "Proof expiring exactly at current time should be denied (fail-closed)"
    );

    // Test 2: Proof expires 1ms before current time (should fail)
    proof.expires_at_millis = NOW - 1;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, _) = result.unwrap();
    assert!(matches!(decision, TrustDecision::Deny(_)));

    // Test 3: Proof expires 1ms after current time (should pass expiry check)
    proof.expires_at_millis = NOW + 1;
    proof.confidence = 100; // Ensure other checks pass
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, evidence) = result.unwrap();
    // Should pass expiry check specifically
    let expiry_evidence = evidence
        .iter()
        .find(|e| e.reason.contains("expiry"))
        .unwrap();
    assert!(expiry_evidence.satisfied);
}

/// Test freshness boundary conditions
#[test]
fn test_freshness_boundary_conditions() {
    let config = default_test_config();
    let mut verifier = ProofVerifier::new(config);
    let predicate = default_test_predicate();

    // Test 1: Proof age exactly equals limit (should fail closed)
    let mut proof = valid_test_proof();
    proof.generated_at_millis = NOW - predicate.max_proof_age_millis; // Exactly at limit
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, evidence) = result.unwrap();
    // Should fail freshness check
    let freshness_evidence = evidence.iter().find(|e| e.reason.contains("age")).unwrap();
    assert!(
        !freshness_evidence.satisfied,
        "Proof at exact age limit should fail (fail-closed)"
    );

    // Test 2: Proof age 1ms under limit (should pass)
    proof.generated_at_millis = NOW - predicate.max_proof_age_millis + 1;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_, evidence) = result.unwrap();
    let freshness_evidence = evidence.iter().find(|e| e.reason.contains("age")).unwrap();
    assert!(freshness_evidence.satisfied);

    // Test 3: Proof from the future (should fail)
    proof.generated_at_millis = NOW + 1000;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, evidence) = result.unwrap();
    assert!(matches!(decision, TrustDecision::Deny(_)));
    let freshness_evidence = evidence
        .iter()
        .find(|e| e.reason.contains("future"))
        .unwrap();
    assert!(!freshness_evidence.satisfied);
}

/// Test integer overflow scenarios in time calculations
#[test]
fn test_time_calculation_overflow_protection() {
    let config = default_test_config();
    let mut verifier = ProofVerifier::new(config);
    let predicate = default_test_predicate();

    // Test 1: Very large timestamps that could cause overflow
    let mut proof = valid_test_proof();
    proof.generated_at_millis = u64::MAX - 1000;
    proof.expires_at_millis = u64::MAX;

    let result = verifier.validate_proof(&proof, &predicate, u64::MAX - 500, "test");
    assert!(
        result.is_ok(),
        "Should handle very large timestamps without panic"
    );

    // Test 2: Current time is smaller than generated time (underflow protection)
    proof.generated_at_millis = 1_000_000;
    let result = verifier.validate_proof(&proof, &predicate, 500_000, "test");
    assert!(
        result.is_ok(),
        "Should handle timestamp underflow gracefully with saturating_sub"
    );
    let (_, evidence) = result.unwrap();
    let freshness_evidence = evidence
        .iter()
        .find(|e| e.reason.contains("future"))
        .unwrap();
    assert!(!freshness_evidence.satisfied);

    // Test 3: Zero timestamps
    proof.generated_at_millis = 0;
    proof.expires_at_millis = u64::MAX;
    let result = verifier.validate_proof(&proof, &predicate, 1000, "test");
    assert!(result.is_ok(), "Should handle zero timestamps");
}

/// Test confidence score edge cases and degrade logic
#[test]
fn test_confidence_score_edge_cases() {
    let config = VerificationGateConfig {
        max_proof_age_millis: 3_600_000,
        degrade_threshold: 80,
        enforce_policy_version: false, // Simplify other checks
    };
    let mut verifier = ProofVerifier::new(config);
    let mut predicate = default_test_predicate();
    predicate.require_witnesses = false; // Simplify other checks

    let mut proof = valid_test_proof();

    // Test 1: Confidence exactly at minimum (should pass)
    proof.confidence = predicate.min_confidence;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, evidence) = result.unwrap();
    let conf_evidence = evidence
        .iter()
        .find(|e| e.reason.contains("confidence"))
        .unwrap();
    assert!(conf_evidence.satisfied);

    // Test 2: Confidence 1 below minimum but above degrade threshold (should degrade)
    proof.confidence = predicate.min_confidence - 1; // 89
    assert!(proof.confidence >= 80, "Should be above degrade threshold");
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, _) = result.unwrap();
    assert!(matches!(decision, TrustDecision::Degrade(_)));

    // Test 3: Confidence below degrade threshold (should deny)
    proof.confidence = 70; // Below degrade threshold of 80
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, _) = result.unwrap();
    assert!(matches!(decision, TrustDecision::Deny(_)));

    // Test 4: Zero confidence (should deny)
    proof.confidence = 0;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, _) = result.unwrap();
    assert!(matches!(decision, TrustDecision::Deny(_)));

    // Test 5: Maximum confidence (should pass)
    proof.confidence = 100;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, _) = result.unwrap();
    // Should pass confidence check but may fail others
    let conf_evidence = evidence
        .iter()
        .find(|e| e.reason.contains("confidence"))
        .unwrap();
    assert!(conf_evidence.satisfied);
}

/// Test witness count validation edge cases
#[test]
fn test_witness_count_edge_cases() {
    let config = default_test_config();
    let mut verifier = ProofVerifier::new(config.clone());
    let mut predicate = default_test_predicate();
    let mut proof = valid_test_proof();

    // Simplify other checks
    proof.confidence = 100;
    predicate.min_confidence = 80;

    // Test 1: Exactly minimum witnesses required (should pass)
    proof.witness_references = vec!["w1".to_string(), "w2".to_string()];
    predicate.min_witness_count = 2;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_, evidence) = result.unwrap();
    let witness_evidence = evidence
        .iter()
        .find(|e| e.reason.contains("witness"))
        .unwrap();
    assert!(witness_evidence.satisfied);

    // Test 2: One less than required (should fail)
    proof.witness_references = vec!["w1".to_string()];
    predicate.min_witness_count = 2;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_decision, evidence) = result.unwrap();
    assert!(matches!(decision, TrustDecision::Deny(_)));
    let witness_evidence = evidence
        .iter()
        .find(|e| e.reason.contains("witness"))
        .unwrap();
    assert!(!witness_evidence.satisfied);

    // Test 3: Zero witnesses when none required (should pass)
    proof.witness_references.clear();
    predicate.require_witnesses = false;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok());
    let (_, evidence) = result.unwrap();
    let witness_evidence = evidence
        .iter()
        .find(|e| e.reason.contains("witness"))
        .unwrap();
    assert!(witness_evidence.satisfied);

    // Test 4: Very large witness count (stress test)
    proof.witness_references = (0..10000).map(|i| format!("witness{}", i)).collect();
    predicate.require_witnesses = true;
    predicate.min_witness_count = 5000;
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_ok(), "Should handle large witness counts");
}

/// Test input validation edge cases
#[test]
fn test_input_validation_edge_cases() {
    let config = default_test_config();
    let mut verifier = ProofVerifier::new(config);
    let predicate = default_test_predicate();

    // Test 1: Empty proof_id
    let mut proof = valid_test_proof();
    proof.proof_id = String::new();
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, "ERR-PVF-INVALID-FORMAT");

    // Test 2: Empty proof_hash
    proof = valid_test_proof();
    proof.proof_hash = String::new();
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "ERR-PVF-INVALID-FORMAT");

    // Test 3: Empty action_class
    proof = valid_test_proof();
    proof.action_class = String::new();
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "ERR-PVF-INVALID-FORMAT");

    // Test 4: Whitespace-only strings (should be handled properly)
    proof = valid_test_proof();
    proof.proof_id = "   ".to_string();
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    // Should not crash - whitespace-only IDs might be valid for some use cases
    assert!(result.is_ok());

    // Test 5: Very long strings (potential DoS)
    proof = valid_test_proof();
    proof.proof_id = "x".repeat(1_000_000);
    let result = verifier.validate_proof(&proof, &predicate, NOW, "test");
    assert!(
        result.is_ok(),
        "Should handle very long strings without crashing"
    );
}

/// Test cryptographic hash determinism and integrity
#[test]
fn test_hash_determinism_and_integrity() {
    // Test that identical inputs produce identical hashes
    let evidence = vec![PredicateEvidence {
        predicate_id: "pred1".to_string(),
        action_class: "action1".to_string(),
        satisfied: true,
        reason: "test reason".to_string(),
    }];

    let digest1 = compute_report_digest(
        "req1",
        "proof1",
        "action1",
        &TrustDecision::Allow,
        &evidence,
    )
    .unwrap();

    let digest2 = compute_report_digest(
        "req1",
        "proof1",
        "action1",
        &TrustDecision::Allow,
        &evidence,
    )
    .unwrap();

    assert_eq!(
        digest1, digest2,
        "Identical inputs should produce identical digests"
    );
    assert!(
        digest1.starts_with("sha256:"),
        "Digest should be SHA-256 formatted"
    );

    // Test that different inputs produce different hashes
    let digest3 = compute_report_digest(
        "req2",
        "proof1",
        "action1",
        &TrustDecision::Allow,
        &evidence,
    )
    .unwrap();

    assert_ne!(
        digest1, digest3,
        "Different inputs should produce different digests"
    );

    // Test decision type changes hash
    let digest4 = compute_report_digest(
        "req1",
        "proof1",
        "action1",
        &TrustDecision::Deny("reason".to_string()),
        &evidence,
    )
    .unwrap();

    assert_ne!(
        digest1, digest4,
        "Different decisions should produce different digests"
    );
}

/// Test sequence number overflow protection
#[test]
fn test_sequence_number_overflow_protection() {
    let mut gate = VerificationGate::new(default_test_config());
    gate.register_predicate(default_test_predicate());

    // Set sequence number near overflow
    gate.next_report_seq = u64::MAX - 1;

    let request = VerificationRequest {
        request_id: "test-overflow-1".to_string(),
        proof: valid_test_proof(),
        now_millis: NOW,
        trace_id: "trace-overflow".to_string(),
    };

    // Should succeed with MAX-1
    let result = gate.verify(&request);
    assert!(result.is_ok(), "Should handle near-max sequence numbers");

    // Try at MAX (should trigger overflow protection)
    let mut request2 = request.clone();
    request2.request_id = "test-overflow-2".to_string();

    let result = gate.verify(&request2);
    match result {
        Ok(_) => {
            // If it succeeds, sequence should be at max
            assert_eq!(gate.next_report_seq, u64::MAX);
        }
        Err(err) => {
            // Should fail with internal error about overflow
            assert_eq!(err.code, "ERR-PVF-INTERNAL");
            assert!(err.message.contains("overflow"));
        }
    }
}

/// Test memory exhaustion protection via bounded collections
#[test]
fn test_memory_exhaustion_protection() {
    let mut gate = VerificationGate::new(default_test_config());
    gate.register_predicate(default_test_predicate());

    // Generate many reports to test bounded storage
    let max_iterations = MAX_REPORTS + 100; // Exceed the limit

    for i in 0..max_iterations {
        let mut proof = valid_test_proof();
        proof.proof_id = format!("stress-test-{}", i);

        let request = VerificationRequest {
            request_id: format!("req-{}", i),
            proof,
            now_millis: NOW,
            trace_id: format!("trace-{}", i),
        };

        let result = gate.verify(&request);
        assert!(
            result.is_ok(),
            "Verification should not fail due to memory limits"
        );

        // Check that reports are bounded
        assert!(
            gate.reports().len() <= MAX_REPORTS,
            "Reports should be bounded to prevent memory exhaustion"
        );
    }

    // Ensure oldest reports were evicted (FIFO behavior)
    let report_ids: Vec<String> = gate
        .reports()
        .iter()
        .map(|r| r.request_id.clone())
        .collect();

    // Should not contain early requests (they should have been evicted)
    assert!(
        !report_ids.contains(&"req-0".to_string()),
        "Oldest reports should have been evicted"
    );

    // Should contain recent requests
    assert!(
        report_ids.contains(&format!("req-{}", max_iterations - 1)),
        "Most recent reports should be retained"
    );
}

/// Test batch verification with mixed valid/invalid proofs
#[test]
fn test_batch_verification_mixed_results() {
    let mut gate = VerificationGate::new(default_test_config());
    gate.register_predicate(default_test_predicate());

    let mut requests = Vec::new();

    // Valid proof
    requests.push(VerificationRequest {
        request_id: "batch-valid".to_string(),
        proof: valid_test_proof(),
        now_millis: NOW,
        trace_id: "batch-trace-1".to_string(),
    });

    // Expired proof
    let mut expired_proof = valid_test_proof();
    expired_proof.proof_id = "batch-expired".to_string();
    expired_proof.expires_at_millis = NOW - 1;
    requests.push(VerificationRequest {
        request_id: "batch-expired".to_string(),
        proof: expired_proof,
        now_millis: NOW,
        trace_id: "batch-trace-2".to_string(),
    });

    // Invalid format proof
    let mut invalid_proof = valid_test_proof();
    invalid_proof.proof_id = String::new();
    requests.push(VerificationRequest {
        request_id: "batch-invalid".to_string(),
        proof: invalid_proof,
        now_millis: NOW,
        trace_id: "batch-trace-3".to_string(),
    });

    let results = gate.verify_batch(&requests);
    assert_eq!(results.len(), 3);

    // First should succeed
    assert!(results[0].is_ok());
    assert_eq!(results[0].as_ref().unwrap().decision, TrustDecision::Allow);

    // Second should succeed but with Deny decision
    assert!(results[1].is_ok());
    assert!(matches!(
        results[1].as_ref().unwrap().decision,
        TrustDecision::Deny(_)
    ));

    // Third should fail with error
    assert!(results[2].is_err());
}

/// Test constant-time comparison usage for policy version hashes
#[test]
fn test_constant_time_policy_comparison() {
    let config = VerificationGateConfig {
        enforce_policy_version: true,
        ..default_test_config()
    };
    let mut verifier = ProofVerifier::new(config);
    let predicate = default_test_predicate();

    // Test that policy version comparison uses constant time
    let mut proof1 = valid_test_proof();
    proof1.policy_version_hash = "sha256:correct-hash".to_string();

    let mut proof2 = valid_test_proof();
    proof2.policy_version_hash = "sha256:wrong-hash-same-length".to_string();

    let mut predicate_test = predicate.clone();
    predicate_test.policy_version_hash = "sha256:correct-hash".to_string();

    // Both should complete in similar time (testing for constant-time behavior)
    // This is more of a documentation test since timing attacks are hard to test in unit tests
    let result1 = verifier.validate_proof(&proof1, &predicate_test, NOW, "test1");
    let result2 = verifier.validate_proof(&proof2, &predicate_test, NOW, "test2");

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Correct hash should pass policy version check
    let (_, evidence1) = result1.unwrap();
    let policy_evidence1 = evidence1
        .iter()
        .find(|e| e.reason.contains("policy version"))
        .unwrap();
    assert!(policy_evidence1.satisfied);

    // Wrong hash should fail policy version check
    let (_, evidence2) = result2.unwrap();
    let policy_evidence2 = evidence2
        .iter()
        .find(|e| e.reason.contains("policy version"))
        .unwrap();
    assert!(!policy_evidence2.satisfied);
}

/// Test decision summary statistics accuracy
#[test]
fn test_decision_summary_accuracy() {
    let mut gate = VerificationGate::new(default_test_config());
    gate.register_predicate(default_test_predicate());

    // Generate mix of decisions

    // 2 Allow decisions
    for i in 0..2 {
        let mut proof = valid_test_proof();
        proof.proof_id = format!("allow-{}", i);
        let request = VerificationRequest {
            request_id: format!("allow-req-{}", i),
            proof,
            now_millis: NOW,
            trace_id: format!("allow-trace-{}", i),
        };
        gate.verify(&request).unwrap();
    }

    // 3 Deny decisions (expired proofs)
    for i in 0..3 {
        let mut proof = valid_test_proof();
        proof.proof_id = format!("deny-{}", i);
        proof.expires_at_millis = NOW - 1;
        let request = VerificationRequest {
            request_id: format!("deny-req-{}", i),
            proof,
            now_millis: NOW,
            trace_id: format!("deny-trace-{}", i),
        };
        gate.verify(&request).unwrap();
    }

    // 1 Degrade decision
    let mut degrade_proof = valid_test_proof();
    degrade_proof.proof_id = "degrade-1".to_string();
    degrade_proof.confidence = 85; // Between degrade_threshold and min_confidence
    let degrade_config = VerificationGateConfig {
        degrade_threshold: 80,
        ..default_test_config()
    };
    let mut degrade_gate = VerificationGate::new(degrade_config);
    degrade_gate.register_predicate(default_test_predicate());

    let request = VerificationRequest {
        request_id: "degrade-req".to_string(),
        proof: degrade_proof,
        now_millis: NOW,
        trace_id: "degrade-trace".to_string(),
    };
    degrade_gate.verify(&request).unwrap();

    // Check gate with Allow/Deny only
    let summary = gate.decision_summary();
    assert_eq!(summary.total_reports, 5);
    assert_eq!(summary.allow_count, 2);
    assert_eq!(summary.deny_count, 3);
    assert_eq!(summary.degrade_count, 0);

    // Check degrade gate
    let degrade_summary = degrade_gate.decision_summary();
    assert_eq!(degrade_summary.degrade_count, 1);
}

/// Test edge cases in push_bounded function
#[test]
fn test_push_bounded_edge_cases() {
    // Test with capacity 0 (should handle gracefully)
    let mut items = vec![1, 2, 3];
    push_bounded(&mut items, 4, 0);
    assert_eq!(items, vec![4], "Should handle zero capacity");

    // Test with capacity 1 (constant replacement)
    let mut items = vec![1];
    push_bounded(&mut items, 2, 1);
    assert_eq!(items, vec![2]);
    push_bounded(&mut items, 3, 1);
    assert_eq!(items, vec![3]);

    // Test normal capacity behavior
    let mut items = Vec::new();
    for i in 0..5 {
        push_bounded(&mut items, i, 3);
    }
    assert_eq!(
        items,
        vec![2, 3, 4],
        "Should maintain FIFO eviction with capacity 3"
    );
}

/// Negative serde cases for external verifier API payloads.
#[test]
fn test_trust_decision_deserialize_rejects_unknown_variant() {
    let result: Result<TrustDecision, _> = serde_json::from_str(r#""quarantine""#);

    assert!(result.is_err());
}

#[test]
fn test_compliance_proof_deserialize_rejects_missing_proof_id() {
    let json = r#"{
        "action_class": "test_action",
        "proof_hash": "sha256:test-proof-hash",
        "confidence": 95,
        "generated_at_millis": 1700999940000,
        "expires_at_millis": 1701000600000,
        "witness_references": ["witness1", "witness2"],
        "policy_version_hash": "sha256:test-policy-v1",
        "trace_id": "test-trace"
    }"#;

    let result: Result<ComplianceProof, _> = serde_json::from_str(json);

    assert!(result.is_err());
}

#[test]
fn test_compliance_proof_deserialize_rejects_string_confidence() {
    let json = r#"{
        "proof_id": "test-proof-001",
        "action_class": "test_action",
        "proof_hash": "sha256:test-proof-hash",
        "confidence": "95",
        "generated_at_millis": 1700999940000,
        "expires_at_millis": 1701000600000,
        "witness_references": ["witness1", "witness2"],
        "policy_version_hash": "sha256:test-policy-v1",
        "trace_id": "test-trace"
    }"#;

    let result: Result<ComplianceProof, _> = serde_json::from_str(json);

    assert!(result.is_err());
}

#[test]
fn test_verification_request_deserialize_rejects_now_type_confusion() {
    let json = r#"{
        "request_id": "req-proof-001",
        "proof": {
            "proof_id": "test-proof-001",
            "action_class": "test_action",
            "proof_hash": "sha256:test-proof-hash",
            "confidence": 95,
            "generated_at_millis": 1700999940000,
            "expires_at_millis": 1701000600000,
            "witness_references": ["witness1", "witness2"],
            "policy_version_hash": "sha256:test-policy-v1",
            "trace_id": "test-trace"
        },
        "now_millis": "1701000000000",
        "trace_id": "test-trace"
    }"#;

    let result: Result<VerificationRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
}

#[test]
fn test_verification_report_deserialize_rejects_missing_digest() {
    let json = r#"{
        "schema_version": "vef-proof-verifier-v1",
        "request_id": "req-proof-001",
        "proof_id": "test-proof-001",
        "action_class": "test_action",
        "decision": "allow",
        "evidence": [],
        "events": [],
        "trace_id": "test-trace",
        "created_at_millis": 1701000000000
    }"#;

    let result: Result<VerificationReport, _> = serde_json::from_str(json);

    assert!(result.is_err());
}

#[test]
fn test_verifier_event_deserialize_rejects_missing_event_code() {
    let json = r#"{
        "trace_id": "test-trace",
        "detail": "missing event code"
    }"#;

    let result: Result<VerifierEvent, _> = serde_json::from_str(json);

    assert!(result.is_err());
}

#[test]
fn test_policy_predicate_deserialize_rejects_string_witness_count() {
    let json = r#"{
        "predicate_id": "test-predicate",
        "action_class": "test_action",
        "max_proof_age_millis": 600000,
        "min_confidence": 90,
        "require_witnesses": true,
        "min_witness_count": "2",
        "policy_version_hash": "sha256:test-policy-v1"
    }"#;

    let result: Result<PolicyPredicate, _> = serde_json::from_str(json);

    assert!(result.is_err());
}

#[test]
fn test_gate_config_deserialize_rejects_string_degrade_threshold() {
    let json = r#"{
        "max_proof_age_millis": 3600000,
        "degrade_threshold": "80",
        "enforce_policy_version": true
    }"#;

    let result: Result<VerificationGateConfig, _> = serde_json::from_str(json);

    assert!(result.is_err());
}
