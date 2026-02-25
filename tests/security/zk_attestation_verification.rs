//! Security conformance tests for bd-kcg9: Zero-knowledge attestation
//! support for selective compliance verification.
//!
//! Validates that verifiers can validate compliance predicates without
//! privileged disclosure of full private metadata and that invalid/forged
//! proofs fail admission deterministically.

use frankenengine_node::security::zk_attestation::*;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn test_policy() -> ZkPolicy {
    ZkPolicy {
        policy_id: "pol-compliance-01".to_string(),
        predicate_description: "GDPR data residency check".to_string(),
        issuer: "issuer-key-abc123".to_string(),
        validity_ms: DEFAULT_VALIDITY_MS,
        schema_version: SCHEMA_VERSION.to_string(),
        active: true,
        registered_at_ms: 1_000_000,
    }
}

fn alt_policy() -> ZkPolicy {
    ZkPolicy {
        policy_id: "pol-other-02".to_string(),
        predicate_description: "SOC2 audit check".to_string(),
        issuer: "issuer-key-xyz789".to_string(),
        validity_ms: DEFAULT_VALIDITY_MS,
        schema_version: SCHEMA_VERSION.to_string(),
        active: true,
        registered_at_ms: 1_000_000,
    }
}

fn make_attestation(
    ledger: &mut AttestationLedger,
    id: &str,
    policy: &ZkPolicy,
    outcome: PredicateOutcome,
    now_ms: u64,
) -> ZkAttestation {
    ledger
        .generate_proof(
            id.to_string(),
            policy,
            format!("commit-{}", id),
            "deadbeef".to_string(),
            outcome,
            now_ms,
            format!("trace-{}", id),
        )
        .unwrap()
}

// ── INV-ZK-NO-DISCLOSURE / INV-ZKA-SELECTIVE ─────────────────────────────────

#[test]
fn valid_proof_does_not_disclose_private_metadata() {
    // ZK_ATTESTATION_REQUEST / ZK_PROOF_GENERATED
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-sel-1", &policy, PredicateOutcome::Pass, 1_000_000);
    // Proof payload must contain only hex commitment, not plaintext.
    assert!(invariants::check_selective(&att), "INV-ZKA-SELECTIVE");
    assert!(
        att.payload.proof_bytes_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "proof bytes must be pure hex"
    );
    assert!(
        !att.payload.metadata_commitment.is_empty(),
        "commitment must be non-empty"
    );
}

#[test]
fn empty_commitment_fails_selective_invariant() {
    let att = ZkAttestation {
        attestation_id: "att-leak".to_string(),
        policy_id: "pol-1".to_string(),
        payload: ZkProofPayload {
            schema_version: SCHEMA_VERSION.to_string(),
            proof_bytes_hex: "aabb".to_string(),
            metadata_commitment: "".to_string(),
        },
        outcome: PredicateOutcome::Pass,
        status: AttestationStatus::Active,
        generated_at_ms: 1_000_000,
        expires_at_ms: 2_000_000,
        trace_id: "trace-leak".to_string(),
    };
    assert!(
        !invariants::check_selective(&att),
        "Empty commitment must fail INV-ZKA-SELECTIVE"
    );
}

#[test]
fn non_hex_proof_bytes_rejected_at_generation() {
    // ERR_ZK_PROOF_INVALID / ERR_ZKA_METADATA_LEAK
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let result = ledger.generate_proof(
        "att-nonhex".to_string(),
        &policy,
        "commit-nonhex".to_string(),
        "ZZZZ-not-hex!!".to_string(),
        PredicateOutcome::Pass,
        1_000_000,
        "trace-nonhex".to_string(),
    );
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains(error_codes::ERR_ZKA_METADATA_LEAK),
        "Non-hex proof bytes must fail with ERR_ZKA_METADATA_LEAK"
    );
}

// ── INV-ZK-PROOF-SOUNDNESS / INV-ZKA-SOUNDNESS ──────────────────────────────

#[test]
fn forged_proof_policy_mismatch_rejected() {
    // ERR_ZK_CIRCUIT_MISMATCH / ERR_ZKA_POLICY_MISMATCH
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let wrong_policy = alt_policy();
    let att = make_attestation(&mut ledger, "att-forge-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let result = ledger.verify_proof(&att, &wrong_policy, 1_000_001, "trace-forge".to_string());
    assert!(!result.is_verified());
    match &result {
        ZkVerificationResult::Rejected { error_code, .. } => {
            assert_eq!(error_code, error_codes::ERR_ZKA_POLICY_MISMATCH);
        }
        _ => panic!("Expected Rejected for policy mismatch"),
    }
}

#[test]
fn revoked_proof_rejected_deterministically() {
    // ERR_ZK_PROOF_FORGED analogue: revoked proofs are rejected
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let mut att = make_attestation(&mut ledger, "att-rev-1", &policy, PredicateOutcome::Pass, 1_000_000);
    att.status = AttestationStatus::Revoked;
    let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-rev".to_string());
    assert!(!result.is_verified());
    match &result {
        ZkVerificationResult::Rejected { error_code, .. } => {
            assert_eq!(error_code, error_codes::ERR_ZKA_REVOKED);
        }
        _ => panic!("Expected Rejected for revoked attestation"),
    }
}

#[test]
fn soundness_invariant_holds_for_verified_result() {
    let result = ZkVerificationResult::Verified {
        attestation_id: "a1".to_string(),
        policy_id: "p1".to_string(),
        trace_id: "t1".to_string(),
        verified_at_ms: 1_000_000,
    };
    assert!(invariants::check_soundness(&result), "INV-ZKA-SOUNDNESS for Verified");
}

#[test]
fn soundness_invariant_holds_for_rejected_result() {
    let result = ZkVerificationResult::Rejected {
        attestation_id: "a1".to_string(),
        policy_id: "p1".to_string(),
        trace_id: "t1".to_string(),
        reason: "bad proof".to_string(),
        error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
    };
    assert!(invariants::check_soundness(&result), "INV-ZKA-SOUNDNESS for Rejected");
}

// ── INV-ZK-FAIL-CLOSED ──────────────────────────────────────────────────────

#[test]
fn expired_proof_is_fail_closed() {
    // ERR_ZK_ATTESTATION_EXPIRED / ERR_ZKA_EXPIRED
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-exp-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let result = ledger.verify_proof(&att, &policy, att.expires_at_ms + 1, "trace-exp".to_string());
    assert!(
        !result.is_verified(),
        "Expired proof must be rejected (fail-closed)"
    );
    match &result {
        ZkVerificationResult::Rejected { error_code, .. } => {
            assert_eq!(error_code, error_codes::ERR_ZKA_EXPIRED);
        }
        _ => panic!("Expected Rejected for expired attestation"),
    }
}

#[test]
fn failing_predicate_is_fail_closed() {
    // ERR_ZK_PREDICATE_UNSATISFIED / ERR_ZKA_PREDICATE_UNSATISFIED
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-pred-1", &policy, PredicateOutcome::Fail, 1_000_000);
    let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-pred".to_string());
    assert!(
        !result.is_verified(),
        "Failing predicate must be rejected (fail-closed)"
    );
    match &result {
        ZkVerificationResult::Rejected { error_code, .. } => {
            assert_eq!(error_code, error_codes::ERR_ZKA_PREDICATE_UNSATISFIED);
        }
        _ => panic!("Expected Rejected for failing predicate"),
    }
}

#[test]
fn error_predicate_is_fail_closed() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-err-1", &policy, PredicateOutcome::Error, 1_000_000);
    let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-err".to_string());
    assert!(
        !result.is_verified(),
        "Error outcome must be rejected (fail-closed)"
    );
}

// ── INV-ZK-PREDICATE-COMPLETENESS / INV-ZKA-COMPLETENESS ────────────────────

#[test]
fn valid_proof_within_window_passes_verification() {
    // ZK_PROOF_VERIFIED / ZK_PREDICATE_SATISFIED
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-comp-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-comp".to_string());
    assert!(
        result.is_verified(),
        "Valid proof within window must pass (INV-ZKA-COMPLETENESS)"
    );
}

#[test]
fn completeness_invariant_holds_for_active_pass() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-cinv-1", &policy, PredicateOutcome::Pass, 1_000_000);
    assert!(
        invariants::check_completeness(&att, 1_000_001),
        "INV-ZKA-COMPLETENESS: active pass within window"
    );
}

// ── Policy binding ───────────────────────────────────────────────────────────

#[test]
fn policy_bound_invariant() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-pb-1", &policy, PredicateOutcome::Pass, 1_000_000);
    assert!(invariants::check_policy_bound(&att, &policy));
    assert!(!invariants::check_policy_bound(&att, &alt_policy()));
}

// ── Batch verification ──────────────────────────────────────────────────────

#[test]
fn batch_all_pass() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let a1 = make_attestation(&mut ledger, "att-ba-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let a2 = make_attestation(&mut ledger, "att-ba-2", &policy, PredicateOutcome::Pass, 1_000_000);
    let batch = ledger.verify_batch(&[a1, a2], &policy, 1_000_001, "trace-ba".to_string());
    assert_eq!(batch.total, 2);
    assert_eq!(batch.passed, 2);
    assert_eq!(batch.failed, 0);
}

#[test]
fn batch_partial_failure() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let a1 = make_attestation(&mut ledger, "att-bp-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let a2 = make_attestation(&mut ledger, "att-bp-2", &policy, PredicateOutcome::Fail, 1_000_000);
    let batch = ledger.verify_batch(&[a1, a2], &policy, 1_000_001, "trace-bp".to_string());
    assert_eq!(batch.total, 2);
    assert_eq!(batch.passed, 1);
    assert_eq!(batch.failed, 1);
}

// ── Revocation lifecycle ─────────────────────────────────────────────────────

#[test]
fn revoke_attestation_success() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(&mut ledger, "att-rk-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let result = ledger.revoke_attestation("att-rk-1", 1_000_100, "trace-rk".to_string());
    assert!(result.is_ok());
    assert!(result.unwrap().contains(event_codes::FN_ZK_007));
    assert_eq!(
        ledger.attestations["att-rk-1"].status,
        AttestationStatus::Revoked
    );
}

#[test]
fn double_revoke_fails() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(&mut ledger, "att-rk-2", &policy, PredicateOutcome::Pass, 1_000_000);
    ledger.revoke_attestation("att-rk-2", 1_000_100, "trace-rk2a".to_string()).unwrap();
    let result = ledger.revoke_attestation("att-rk-2", 1_000_200, "trace-rk2b".to_string());
    assert!(result.is_err());
}

// ── Audit trail ──────────────────────────────────────────────────────────────

#[test]
fn audit_trail_populated_after_generation() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(&mut ledger, "att-aud-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_001);
    assert_eq!(records.len(), 1);
}

#[test]
fn audit_trail_records_verification_events() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-aud-2", &policy, PredicateOutcome::Pass, 1_000_000);
    ledger.verify_proof(&att, &policy, 1_000_001, "trace-aud".to_string());
    let submit = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_002);
    let pass = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_003);
    assert_eq!(submit.len(), 1);
    assert_eq!(pass.len(), 1);
}

#[test]
fn audit_record_has_required_fields() {
    let record = ZkAuditRecord {
        record_id: "r1".to_string(),
        event_code: event_codes::FN_ZK_001.to_string(),
        attestation_id: Some("a1".to_string()),
        policy_id: Some("p1".to_string()),
        trace_id: "t1".to_string(),
        timestamp_ms: 1_000_000,
        detail: "test".to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
    };
    assert!(invariants::check_audit_trail(&record), "INV-ZKA-AUDIT-TRAIL");
}

// ── Sweep / validity ─────────────────────────────────────────────────────────

#[test]
fn sweep_expired_marks_correctly() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-sw-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let expired = ledger.sweep_expired(att.expires_at_ms + 1);
    assert!(expired.contains(&"att-sw-1".to_string()));
    assert_eq!(
        ledger.attestations["att-sw-1"].status,
        AttestationStatus::Expired
    );
}

#[test]
fn is_valid_within_window() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(&mut ledger, "att-val-1", &policy, PredicateOutcome::Pass, 1_000_000);
    assert!(ledger.is_valid("att-val-1", 1_000_001));
}

#[test]
fn is_valid_after_expiry() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-val-2", &policy, PredicateOutcome::Pass, 1_000_000);
    assert!(!ledger.is_valid("att-val-2", att.expires_at_ms + 1));
}

// ── Schema version ──────────────────────────────────────────────────────────

#[test]
fn schema_version_constant() {
    assert_eq!(SCHEMA_VERSION, "zka-v1.0");
}

#[test]
fn attestation_carries_schema_version() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(&mut ledger, "att-sv-1", &policy, PredicateOutcome::Pass, 1_000_000);
    assert!(invariants::check_schema_versioned(&att), "INV-ZKA-SCHEMA-VERSIONED");
}

// ── Duplicate detection ─────────────────────────────────────────────────────

#[test]
fn duplicate_commitment_rejected() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(&mut ledger, "att-dup-1", &policy, PredicateOutcome::Pass, 1_000_000);
    let result = ledger.generate_proof(
        "att-dup-2".to_string(),
        &policy,
        "commit-att-dup-1".to_string(),
        "aabbccdd".to_string(),
        PredicateOutcome::Pass,
        1_000_001,
        "trace-dup".to_string(),
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains(error_codes::ERR_ZKA_DUPLICATE));
}

// ── Policy registry ─────────────────────────────────────────────────────────

#[test]
fn register_and_lookup_policy() {
    let mut registry = PolicyRegistry::new();
    let policy = test_policy();
    let msg = registry.register_policy(policy.clone()).unwrap();
    assert!(msg.contains(event_codes::FN_ZK_008));
    assert!(registry.get_policy(&policy.policy_id).is_some());
}

#[test]
fn deregister_policy() {
    let mut registry = PolicyRegistry::new();
    let policy = test_policy();
    registry.register_policy(policy.clone()).unwrap();
    let msg = registry.deregister_policy(&policy.policy_id).unwrap();
    assert!(msg.contains(event_codes::FN_ZK_009));
    assert!(registry.get_policy(&policy.policy_id).is_none());
}

// ── Compliance report ───────────────────────────────────────────────────────

#[test]
fn compliance_report_counts() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(&mut ledger, "att-cr-1", &policy, PredicateOutcome::Pass, 1_000_000);
    make_attestation(&mut ledger, "att-cr-2", &policy, PredicateOutcome::Fail, 1_000_000);
    let report = ledger.generate_compliance_report(&policy.policy_id);
    assert_eq!(report["total"], 2);
    assert_eq!(report["outcome_pass"], 1);
    assert_eq!(report["outcome_fail"], 1);
}
