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
    let att = make_attestation(
        &mut ledger,
        "att-sel-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    // Proof payload must contain only hex commitment, not plaintext.
    assert!(invariants::check_selective(&att), "INV-ZKA-SELECTIVE");
    assert!(
        att.payload
            .proof_bytes_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
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
        result
            .unwrap_err()
            .contains(error_codes::ERR_ZKA_METADATA_LEAK),
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
    let att = make_attestation(
        &mut ledger,
        "att-forge-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
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
    let att = make_attestation(
        &mut ledger,
        "att-rev-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    ledger
        .revoke_attestation(&att.attestation_id, 1_000_000, "trace-revoke".to_string())
        .unwrap();
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
    assert!(
        invariants::check_soundness(&result),
        "INV-ZKA-SOUNDNESS for Verified"
    );
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
    assert!(
        invariants::check_soundness(&result),
        "INV-ZKA-SOUNDNESS for Rejected"
    );
}

// ── INV-ZK-FAIL-CLOSED ──────────────────────────────────────────────────────

#[test]
fn expired_proof_is_fail_closed() {
    // ERR_ZK_ATTESTATION_EXPIRED / ERR_ZKA_EXPIRED
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(
        &mut ledger,
        "att-exp-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    let result = ledger.verify_proof(
        &att,
        &policy,
        att.expires_at_ms + 1,
        "trace-exp".to_string(),
    );
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
    let att = make_attestation(
        &mut ledger,
        "att-pred-1",
        &policy,
        PredicateOutcome::Fail,
        1_000_000,
    );
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
    let att = make_attestation(
        &mut ledger,
        "att-err-1",
        &policy,
        PredicateOutcome::Error,
        1_000_000,
    );
    let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-err".to_string());
    assert!(
        !result.is_verified(),
        "Error outcome must be rejected (fail-closed)"
    );
}

// ── INV-ZK-PREDICATE-COMPLETENESS / INV-ZKA-COMPLETENESS ────────────────────

#[test]
fn active_registration_within_window_still_requires_a_verifier() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(
        &mut ledger,
        "att-comp-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-comp".to_string());
    assert!(
        matches!(result, ZkVerificationResult::Rejected { error_code, .. }
            if error_code == error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE),
        "A validity window cannot establish cryptographic completeness"
    );
}

#[test]
fn completeness_invariant_holds_for_active_pass() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(
        &mut ledger,
        "att-cinv-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
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
    let att = make_attestation(
        &mut ledger,
        "att-pb-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    assert!(invariants::check_policy_bound(&att, &policy));
    assert!(!invariants::check_policy_bound(&att, &alt_policy()));
}

// ── Batch verification ──────────────────────────────────────────────────────

#[test]
fn batch_claimed_passes_require_cryptographic_verification() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let a1 = make_attestation(
        &mut ledger,
        "att-ba-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    let a2 = make_attestation(
        &mut ledger,
        "att-ba-2",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    let batch = ledger.verify_batch(&[a1, a2], &policy, 1_000_001, "trace-ba".to_string());
    assert_eq!(batch.total, 2);
    assert_eq!(batch.passed, 0);
    assert_eq!(batch.failed, 2);
}

#[test]
fn batch_partial_failure() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let a1 = make_attestation(
        &mut ledger,
        "att-bp-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    let a2 = make_attestation(
        &mut ledger,
        "att-bp-2",
        &policy,
        PredicateOutcome::Fail,
        1_000_000,
    );
    let batch = ledger.verify_batch(&[a1, a2], &policy, 1_000_001, "trace-bp".to_string());
    assert_eq!(batch.total, 2);
    assert_eq!(batch.passed, 0);
    assert_eq!(batch.failed, 2);
}

// ── Revocation lifecycle ─────────────────────────────────────────────────────

#[test]
fn revoke_attestation_success() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(
        &mut ledger,
        "att-rk-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
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
    make_attestation(
        &mut ledger,
        "att-rk-2",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    ledger
        .revoke_attestation("att-rk-2", 1_000_100, "trace-rk2a".to_string())
        .unwrap();
    let result = ledger.revoke_attestation("att-rk-2", 1_000_200, "trace-rk2b".to_string());
    assert!(result.is_err());
}

// ── Audit trail ──────────────────────────────────────────────────────────────

#[test]
fn audit_trail_populated_after_generation() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(
        &mut ledger,
        "att-aud-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    let records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_001);
    assert_eq!(records.len(), 1);
}

#[test]
fn audit_trail_records_verification_events() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(
        &mut ledger,
        "att-aud-2",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    ledger.verify_proof(&att, &policy, 1_000_001, "trace-aud".to_string());
    let submit = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_002);
    let pass = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_003);
    assert_eq!(submit.len(), 1);
    assert!(pass.is_empty());
    let rejected = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_004);
    assert_eq!(rejected.len(), 1);
}

#[test]
fn registered_arbitrary_bytes_and_pass_never_establish_compliance() {
    for bytes in ["", "0", "00", "deadbeef"] {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = ledger
            .generate_proof(
                "arbitrary".to_string(),
                &policy,
                "commitment".to_string(),
                bytes.to_string(),
                PredicateOutcome::Pass,
                1_000_000,
                "register".to_string(),
            )
            .unwrap();
        let restored = serde_json::to_string(&ledger).unwrap();
        let mut restored: AttestationLedger = serde_json::from_str(&restored).unwrap();
        for ledger in [&mut ledger, &mut restored] {
            let result = ledger.verify_proof(&att, &policy, 1_000_001, "verify".to_string());
            assert!(
                matches!(result, ZkVerificationResult::Rejected { error_code, .. }
                if error_code == error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE)
            );
            assert!(
                ledger
                    .query_audit(|r| r.event_code == event_codes::FN_ZK_003)
                    .is_empty()
            );
        }
    }
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
    assert!(
        invariants::check_audit_trail(&record),
        "INV-ZKA-AUDIT-TRAIL"
    );
}

// ── Sweep / validity ─────────────────────────────────────────────────────────

#[test]
fn sweep_expired_marks_correctly() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(
        &mut ledger,
        "att-sw-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
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
    make_attestation(
        &mut ledger,
        "att-val-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    assert!(ledger.is_valid("att-val-1", 1_000_001));
}

#[test]
fn is_valid_after_expiry() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let att = make_attestation(
        &mut ledger,
        "att-val-2",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
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
    let att = make_attestation(
        &mut ledger,
        "att-sv-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    assert!(
        invariants::check_schema_versioned(&att),
        "INV-ZKA-SCHEMA-VERSIONED"
    );
}

// ── Duplicate detection ─────────────────────────────────────────────────────

#[test]
fn duplicate_commitment_rejected() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    make_attestation(
        &mut ledger,
        "att-dup-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
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
    make_attestation(
        &mut ledger,
        "att-cr-1",
        &policy,
        PredicateOutcome::Pass,
        1_000_000,
    );
    make_attestation(
        &mut ledger,
        "att-cr-2",
        &policy,
        PredicateOutcome::Fail,
        1_000_000,
    );
    let report = ledger.generate_compliance_report(&policy.policy_id);
    assert_eq!(report["total"], 2);
    assert_eq!(report["outcome_pass"], 1);
    assert_eq!(report["outcome_fail"], 1);
}

// ── Ristretto255 Cryptographic Compliance Verification (bd-reality-20260923-26n9r.18) ──

#[test]
fn ristretto_stateless_validity_interval_is_authenticated_for_both_relations() {
    let policy = test_policy();
    let relations = [
        (
            "threshold",
            ZkComplianceRelation::threshold_at_least(100, 8).unwrap(),
        ),
        (
            "allowlist",
            ZkComplianceRelation::allowlist(vec![100, 142, 200]).unwrap(),
        ),
    ];
    let mut accepted_mutations = Vec::new();

    for (name, relation) in relations {
        let params = ZkVerifierParams::for_policy(
            &policy,
            "vk-independent-validity",
            7,
            "nonce-independent-validity",
            relation,
        )
        .unwrap();
        let witness = ZkPrivateWitness::new(142, [0x43; 32]).unwrap();
        let mut ledger = AttestationLedger::new();
        let generated = ledger
            .prove_compliance(
                format!("att-independent-validity-{name}"),
                &policy,
                &params,
                &witness,
                1_000_000,
                "trace-independent-validity".to_string(),
            )
            .unwrap();
        let att: ZkAttestation =
            serde_json::from_str(&serde_json::to_string(&generated).unwrap()).unwrap();
        drop(ledger);

        // An independent consumer has no authoritative ledger to repair an
        // attacker's timestamps. Honest serialized proofs still work.
        for now_ms in [att.generated_at_ms, att.expires_at_ms - 1] {
            let result = verify_compliance_proof_stateless(
                &att,
                &policy,
                &params,
                now_ms,
                "trace-honest".to_string(),
            );
            assert!(result.is_verified(), "{name} honest proof: {result:?}");
        }
        for now_ms in [att.generated_at_ms - 1, att.expires_at_ms] {
            assert!(
                !verify_compliance_proof_stateless(
                    &att,
                    &policy,
                    &params,
                    now_ms,
                    "trace-outside-interval".to_string(),
                )
                .is_verified()
            );
        }

        for (mutation, generated_at_ms, expires_at_ms, now_ms) in [
            (
                "extend_expiry",
                att.generated_at_ms,
                att.expires_at_ms + 1,
                att.expires_at_ms,
            ),
            (
                "postpone_interval",
                att.generated_at_ms + policy.validity_ms,
                att.expires_at_ms + policy.validity_ms,
                att.expires_at_ms,
            ),
            (
                "backdate_interval",
                att.generated_at_ms - 1,
                att.expires_at_ms - 1,
                att.generated_at_ms - 1,
            ),
            (
                "shorten_interval",
                att.generated_at_ms,
                att.expires_at_ms - 1,
                att.generated_at_ms + 1,
            ),
            (
                "move_generation",
                att.generated_at_ms + 1,
                att.expires_at_ms,
                att.generated_at_ms + 1,
            ),
        ] {
            let mut forged = att.clone();
            forged.generated_at_ms = generated_at_ms;
            forged.expires_at_ms = expires_at_ms;
            assert_eq!(forged.payload, att.payload);
            if verify_compliance_proof_stateless(
                &forged,
                &policy,
                &params,
                now_ms,
                format!("trace-forged-{mutation}"),
            )
            .is_verified()
            {
                accepted_mutations.push(format!("{name}/{mutation}"));
            }
        }
    }

    assert!(
        accepted_mutations.is_empty(),
        "stateless verifier accepted unauthenticated validity edits: {accepted_mutations:?}"
    );
}

#[test]
fn ristretto_v2_proof_cannot_be_upgraded_by_relabeling_its_envelope() {
    // Generated and successfully verified with the unchanged v2 implementation
    // at dcd2e62f88526106c9605c45ce42821fbeb336fa. This authentic historical
    // proof has no lifetime in its transcript; changing labels cannot repair it.
    let mut att = ZkAttestation {
        attestation_id: "att-legacy-v2".to_string(),
        policy_id: "pol-compliance-01".to_string(),
        payload: ZkProofPayload {
            schema_version: "zka-ristretto255-v2.0".to_string(),
            proof_bytes_hex: concat!(
                "5a4b52503202a8254a69c4a6c094a1aa9235ba73c17a3db26ce93bcaa942ff86aed794146753",
                "4683189fe925243aeb34e040ca6dc6cfdd49fae2ea9185dbf7d2309f40f214040300",
                "34e80d18e0ced72b87738e627c5dce0a8e67ed98ed19fe098661129f6665d504",
                "1b1fa0df4595698c91de354f6e55af6513fd0800a583eacc4824e3353e29ed05",
                "4d42795a4144d470a24514b8a663c94fab3ebc9289fa4e8aa26f1142ce13af06",
                "cfdc7681979a1a5046922d3a35e4d0596c806ba3e4e4a791f550c96b43f09b03",
                "2d45158b45f69375a3bd2c4c72a2853c16fbac141128aa296c5add69853bdc04",
                "c001579c5ca3d2f58c35eea355461d13a38b29fb51ddbd05b33bdc9e5a10e104",
            )
            .to_string(),
            metadata_commitment: "4683189fe925243aeb34e040ca6dc6cfdd49fae2ea9185dbf7d2309f40f21404"
                .to_string(),
        },
        outcome: PredicateOutcome::Pass,
        status: AttestationStatus::Active,
        generated_at_ms: 1_000_000,
        expires_at_ms: 1_600_000,
        trace_id: "trace-legacy-v2".to_string(),
    };
    let policy = test_policy();
    let params = ZkVerifierParams::for_policy(
        &policy,
        "vk-independent-validity",
        7,
        "nonce-independent-validity",
        ZkComplianceRelation::allowlist(vec![100, 142, 200]).unwrap(),
    )
    .unwrap();
    let verify = |candidate: &ZkAttestation| {
        verify_compliance_proof_stateless(
            candidate,
            &policy,
            &params,
            1_000_001,
            "trace-reject-v2".to_string(),
        )
    };

    assert!(matches!(
        verify(&att),
        ZkVerificationResult::Rejected { error_code, .. }
            if error_code == error_codes::ERR_ZKA_INVALID_PROOF
    ));
    att.payload.schema_version = CRYPTO_SCHEMA_VERSION.to_string();
    assert!(matches!(
        verify(&att),
        ZkVerificationResult::Rejected { error_code, .. }
            if error_code == error_codes::ERR_ZKA_INVALID_PROOF
    ));
    let mut wire = hex::decode(&att.payload.proof_bytes_hex).unwrap();
    wire[..5].copy_from_slice(b"ZKRP3");
    att.payload.proof_bytes_hex = hex::encode(&wire);
    assert!(matches!(
        verify(&att),
        ZkVerificationResult::Rejected { error_code, .. }
            if error_code == error_codes::ERR_ZKA_POLICY_MISMATCH
    ));
    wire[6..38].copy_from_slice(&hex::decode(params.params_sha256()).unwrap());
    att.payload.proof_bytes_hex = hex::encode(wire);
    assert!(matches!(
        verify(&att),
        ZkVerificationResult::Rejected { error_code, .. }
            if error_code == error_codes::ERR_ZKA_WITNESS_INVALID
    ));
}

#[test]
fn ristretto_rejects_empty_and_overflowing_lifetimes_without_registering_a_proof() {
    for (validity_ms, now_ms) in [(0, 1_000_000), (2, u64::MAX - 1), (1, u64::MAX)] {
        let mut policy = test_policy();
        policy.validity_ms = validity_ms;
        let params = ZkVerifierParams::for_policy(
            &policy,
            "vk-lifetime-bounds",
            7,
            "nonce-lifetime-bounds",
            ZkComplianceRelation::allowlist(vec![142]).unwrap(),
        )
        .unwrap();
        let witness = ZkPrivateWitness::new(142, [0x44; 32]).unwrap();
        let mut ledger = AttestationLedger::new();
        let before = serde_json::to_value(&ledger).unwrap();
        let error = ledger
            .prove_compliance(
                "att-invalid-lifetime".to_string(),
                &policy,
                &params,
                &witness,
                now_ms,
                "trace-invalid-lifetime".to_string(),
            )
            .unwrap_err();
        assert!(error.starts_with(error_codes::ERR_ZKA_INVALID_PROOF));
        assert_eq!(serde_json::to_value(&ledger).unwrap(), before);
    }

    let mut policy = test_policy();
    policy.validity_ms = 1;
    let params = ZkVerifierParams::for_policy(
        &policy,
        "vk-lifetime-boundary",
        7,
        "nonce-lifetime-boundary",
        ZkComplianceRelation::allowlist(vec![142]).unwrap(),
    )
    .unwrap();
    let witness = ZkPrivateWitness::new(142, [0x45; 32]).unwrap();
    let mut ledger = AttestationLedger::new();
    let att = ledger
        .prove_compliance(
            "att-lifetime-boundary".to_string(),
            &policy,
            &params,
            &witness,
            u64::MAX - 1,
            "trace-lifetime-boundary".to_string(),
        )
        .unwrap();
    assert_eq!(att.expires_at_ms, u64::MAX);
    assert!(
        verify_compliance_proof_stateless(
            &att,
            &policy,
            &params,
            u64::MAX - 1,
            "trace-boundary-live".to_string(),
        )
        .is_verified()
    );
    assert!(matches!(
        verify_compliance_proof_stateless(
            &att,
            &policy,
            &params,
            u64::MAX,
            "trace-boundary-expired".to_string(),
        ),
        ZkVerificationResult::Rejected { error_code, .. }
            if error_code == error_codes::ERR_ZKA_EXPIRED
    ));
}

#[test]
fn ristretto_retained_expired_status_cannot_be_reactivated_with_an_earlier_clock() {
    let policy = test_policy();
    let params = ZkVerifierParams::for_policy(
        &policy,
        "vk-terminal-expiry",
        7,
        "nonce-terminal-expiry",
        ZkComplianceRelation::allowlist(vec![142]).unwrap(),
    )
    .unwrap();
    let witness = ZkPrivateWitness::new(142, [0x46; 32]).unwrap();
    let mut ledger = AttestationLedger::new();
    let att = ledger
        .prove_compliance(
            "att-terminal-expiry".to_string(),
            &policy,
            &params,
            &witness,
            1_000_000,
            "trace-terminal-expiry".to_string(),
        )
        .unwrap();
    ledger.sweep_expired(att.expires_at_ms);
    let retained = ledger.attestations[&att.attestation_id].clone();
    assert_eq!(retained.status, AttestationStatus::Expired);
    for result in [
        ledger.verify_authenticated_proof(
            &att,
            &policy,
            &params,
            att.generated_at_ms,
            "trace-stale-active".to_string(),
        ),
        verify_compliance_proof_stateless(
            &retained,
            &policy,
            &params,
            att.generated_at_ms,
            "trace-retained-expired".to_string(),
        ),
    ] {
        assert!(matches!(
            result,
            ZkVerificationResult::Rejected { error_code, .. }
                if error_code == error_codes::ERR_ZKA_EXPIRED
        ));
    }
    assert_eq!(
        ledger.attestations[&att.attestation_id].status,
        AttestationStatus::Expired
    );
}

#[test]
fn ristretto_threshold_above_and_exact_boundary_verify_and_64bit_range_works() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let params_16 = ZkVerifierParams::for_policy(
        &policy,
        "vk-threshold-16",
        7,
        "nonce-701",
        ZkComplianceRelation::threshold_at_least(1_000, 16).unwrap(),
    )
    .unwrap();

    // Strictly above threshold: v = 1_512 > 1_000
    let w_above = ZkPrivateWitness::new(1_512, [0x31u8; 32]).unwrap();
    let att_above = ledger
        .prove_compliance(
            "att-crypto-above".to_string(),
            &policy,
            &params_16,
            &w_above,
            1_000_000,
            "trace-above".to_string(),
        )
        .unwrap();
    assert!(
        ledger
            .verify_authenticated_proof(
                &att_above,
                &policy,
                &params_16,
                1_000_001,
                "trace-above-v".to_string(),
            )
            .is_verified()
    );
    assert!(
        verify_compliance_proof_stateless(
            &att_above,
            &policy,
            &params_16,
            1_000_001,
            "trace-stateless".to_string(),
        )
        .is_verified()
    );

    // Exact boundary: v == 1_000
    let w_exact = ZkPrivateWitness::new(1_000, [0x32u8; 32]).unwrap();
    let att_exact = ledger
        .prove_compliance(
            "att-crypto-exact".to_string(),
            &policy,
            &params_16,
            &w_exact,
            1_000_000,
            "trace-exact".to_string(),
        )
        .unwrap();
    assert!(
        ledger
            .verify_authenticated_proof(
                &att_exact,
                &policy,
                &params_16,
                1_000_001,
                "trace-exact-v".to_string(),
            )
            .is_verified()
    );

    // Full 64-bit threshold boundary near u64::MAX
    let params_64 = ZkVerifierParams::for_policy(
        &policy,
        "vk-threshold-64",
        7,
        "nonce-702",
        ZkComplianceRelation::threshold_at_least(u64::MAX - 10, 64).unwrap(),
    )
    .unwrap();
    let w_max = ZkPrivateWitness::new(u64::MAX, [0x33u8; 32]).unwrap();
    let att_max = ledger
        .prove_compliance(
            "att-crypto-u64max".to_string(),
            &policy,
            &params_64,
            &w_max,
            1_000_000,
            "trace-max".to_string(),
        )
        .unwrap();
    assert!(
        ledger
            .verify_authenticated_proof(
                &att_max,
                &policy,
                &params_64,
                1_000_001,
                "trace-max-v".to_string(),
            )
            .is_verified()
    );
    assert_eq!(
        ledger
            .query_audit(|r| r.event_code == event_codes::FN_ZK_003)
            .len(),
        3
    );
}

#[test]
fn ristretto_threshold_underflow_witness_and_forged_commitment_rejected() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let params = ZkVerifierParams::for_policy(
        &policy,
        "vk-threshold-underflow",
        3,
        "nonce-underflow",
        ZkComplianceRelation::threshold_at_least(500, 16).unwrap(),
    )
    .unwrap();

    // 1. Prover refuses v = tau - 1 = 499
    let w_under = ZkPrivateWitness::new(499, [0x41u8; 32]).unwrap();
    let err = ledger
        .prove_compliance(
            "att-underflow".to_string(),
            &policy,
            &params,
            &w_under,
            1_000_000,
            "trace-under".to_string(),
        )
        .unwrap_err();
    assert!(err.contains(error_codes::ERR_ZKA_PREDICATE_UNSATISFIED));

    // 2. Attacker substitutes commitment C(499, r) into an otherwise valid proof transcript
    let w_valid = ZkPrivateWitness::new(500, [0x42u8; 32]).unwrap();
    let mut att = ledger
        .prove_compliance(
            "att-forged-underflow".to_string(),
            &policy,
            &params,
            &w_valid,
            1_000_000,
            "trace-forge".to_string(),
        )
        .unwrap();
    let underflow_comm_hex = w_under.pedersen_commitment_hex();
    let underflow_comm_bytes = hex::decode(&underflow_comm_hex).unwrap();
    let mut wire = hex::decode(&att.payload.proof_bytes_hex).unwrap();
    wire[38..70].copy_from_slice(&underflow_comm_bytes);
    att.payload.metadata_commitment = underflow_comm_hex;
    att.payload.proof_bytes_hex = hex::encode(wire);

    let res = ledger.verify_authenticated_proof(
        &att,
        &policy,
        &params,
        1_000_005,
        "trace-forge-v".to_string(),
    );
    assert!(
        matches!(
            res,
            ZkVerificationResult::Rejected { ref error_code, .. }
            if error_code == error_codes::ERR_ZKA_WITNESS_INVALID
        ),
        "expected ERR_ZKA_WITNESS_INVALID, got {res:?}"
    );
}

#[test]
fn ristretto_allowlist_membership_verifies_members_and_rejects_nonmembers_and_tampered_merkle() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    // ISO-3166 EU numeric codes subset
    let eu_subset = vec![250, 276, 372, 528, 724];
    let params = ZkVerifierParams::for_policy(
        &policy,
        "vk-eu-residency",
        2,
        "nonce-eu-01",
        ZkComplianceRelation::allowlist(eu_subset).unwrap(),
    )
    .unwrap();

    // Member 372 (Ireland) verifies without revealing 372
    let w_member = ZkPrivateWitness::random(372);
    let att = ledger
        .prove_compliance(
            "att-eu-372".to_string(),
            &policy,
            &params,
            &w_member,
            1_000_000,
            "trace-eu".to_string(),
        )
        .unwrap();
    assert!(
        ledger
            .verify_authenticated_proof(&att, &policy, &params, 1_000_002, "trace-eu-v".to_string())
            .is_verified()
    );

    // Non-member 840 rejected
    let w_nonmember = ZkPrivateWitness::new(840, [0x55u8; 32]).unwrap();
    let err = ledger
        .prove_compliance(
            "att-eu-840".to_string(),
            &policy,
            &params,
            &w_nonmember,
            1_000_000,
            "trace-nonmember".to_string(),
        )
        .unwrap_err();
    assert!(err.contains(error_codes::ERR_ZKA_PREDICATE_UNSATISFIED));

    // Tampered Merkle root on verifier_params rejected fail-closed
    let mut tampered_params = params.clone();
    if let ZkComplianceRelation::AllowlistMembership {
        ref mut merkle_root_hex,
        ..
    } = tampered_params.relation
    {
        *merkle_root_hex = "00".repeat(32);
    }
    let res_merkle = ledger.verify_authenticated_proof(
        &att,
        &policy,
        &tampered_params,
        1_000_003,
        "trace-tampered-merkle".to_string(),
    );
    assert!(
        matches!(
            res_merkle,
            ZkVerificationResult::Rejected { ref error_code, .. }
            if error_code == error_codes::ERR_ZKA_POLICY_MISMATCH
        ),
        "expected ERR_ZKA_POLICY_MISMATCH on tampered Merkle root, got {res_merkle:?}"
    );
}

#[test]
fn ristretto_same_policy_id_with_different_policy_content_or_params_is_rejected() {
    let mut ledger = AttestationLedger::new();
    let policy_a = test_policy();
    // Identical policy_id ("pol-compliance-01") but different issuer / predicate!
    let mut policy_b_same_id = policy_a.clone();
    policy_b_same_id.issuer = "rogue-issuer-key-999".to_string();

    let params_a = ZkVerifierParams::for_policy(
        &policy_a,
        "vk-bind-1",
        1,
        "nonce-bind-a",
        ZkComplianceRelation::threshold_at_least(50, 8).unwrap(),
    )
    .unwrap();
    let params_b_higher_threshold = ZkVerifierParams::for_policy(
        &policy_a,
        "vk-bind-1",
        1,
        "nonce-bind-a",
        ZkComplianceRelation::threshold_at_least(200, 8).unwrap(),
    )
    .unwrap();

    let witness = ZkPrivateWitness::new(75, [0x61u8; 32]).unwrap();
    let att = ledger
        .prove_compliance(
            "att-bind-1".to_string(),
            &policy_a,
            &params_a,
            &witness,
            1_000_000,
            "trace-bind".to_string(),
        )
        .unwrap();

    // 1. Same policy_id, mutated policy issuer -> ERR_ZKA_POLICY_MISMATCH
    let res_policy_swap = ledger.verify_authenticated_proof(
        &att,
        &policy_b_same_id,
        &params_a,
        1_000_001,
        "trace-bind-swap-pol".to_string(),
    );
    assert!(matches!(
        res_policy_swap,
        ZkVerificationResult::Rejected { ref error_code, .. }
        if error_code == error_codes::ERR_ZKA_POLICY_MISMATCH
    ));

    // 2. Same policy, swapped verifier_params threshold (200 vs 50) -> ERR_ZKA_POLICY_MISMATCH
    let res_param_swap = ledger.verify_authenticated_proof(
        &att,
        &policy_a,
        &params_b_higher_threshold,
        1_000_001,
        "trace-bind-swap-params".to_string(),
    );
    assert!(matches!(
        res_param_swap,
        ZkVerificationResult::Rejected { ref error_code, .. }
        if error_code == error_codes::ERR_ZKA_POLICY_MISMATCH
    ));

    // 3. Attacker patches wire params_sha256 to match params_b_higher_threshold -> Fiat-Shamir / homomorphic check rejects with ERR_ZKA_WITNESS_INVALID
    let mut patched_att = att.clone();
    let mut wire = hex::decode(&patched_att.payload.proof_bytes_hex).unwrap();
    let target_digest = hex::decode(params_b_higher_threshold.params_sha256()).unwrap();
    wire[6..38].copy_from_slice(&target_digest);
    patched_att.payload.proof_bytes_hex = hex::encode(wire);

    let res_patched = ledger.verify_authenticated_proof(
        &patched_att,
        &policy_a,
        &params_b_higher_threshold,
        1_000_001,
        "trace-bind-patched".to_string(),
    );
    assert!(
        matches!(
            res_patched,
            ZkVerificationResult::Rejected { ref error_code, .. }
            if error_code == error_codes::ERR_ZKA_WITNESS_INVALID
        ),
        "expected ERR_ZKA_WITNESS_INVALID on patched params digest, got {res_patched:?}"
    );
}

#[test]
fn ristretto_caller_forced_pass_garbage_hex_revocation_and_zero_witness_disclosure() {
    let mut ledger = AttestationLedger::new();
    let policy = test_policy();
    let params = ZkVerifierParams::for_policy(
        &policy,
        "vk-disclosure-1",
        5,
        "nonce-disc-01",
        ZkComplianceRelation::threshold_at_least(100_000, 32).unwrap(),
    )
    .unwrap();

    // Caller-registered legacy Pass with garbage hex still fails closed under authenticated verifier
    let legacy_att = ledger
        .generate_proof(
            "att-legacy-pass".to_string(),
            &policy,
            "ab".repeat(32),
            "deadbeef".to_string(),
            PredicateOutcome::Pass,
            1_000_000,
            "trace-legacy".to_string(),
        )
        .unwrap();
    let legacy_res = ledger.verify_authenticated_proof(
        &legacy_att,
        &policy,
        &params,
        1_000_001,
        "trace-legacy-v".to_string(),
    );
    assert!(matches!(
        legacy_res,
        ZkVerificationResult::Rejected { ref error_code, .. }
        if error_code == error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE
    ));

    // Caller mutates schema_version to CRYPTO_SCHEMA_VERSION with empty/garbage hex
    let mut forged_v2 = legacy_att.clone();
    forged_v2.payload.schema_version = CRYPTO_SCHEMA_VERSION.to_string();
    for bad_hex in ["", "deadbeef"] {
        forged_v2.payload.proof_bytes_hex = bad_hex.to_string();
        let bad_res = ledger.verify_authenticated_proof(
            &forged_v2,
            &policy,
            &params,
            1_000_001,
            "trace-bad-hex".to_string(),
        );
        assert!(matches!(
            bad_res,
            ZkVerificationResult::Rejected { ref error_code, .. }
            if error_code == error_codes::ERR_ZKA_INVALID_PROOF
        ));
    }

    // Secret witness value 987_654_321 and secret blinding never appear in Debug, JSON, or audit logs
    let secret_value = 987_654_321u64;
    let secret_blinding = [0x7au8; 32];
    let secret_blinding_hex = hex::encode(secret_blinding);
    let witness = ZkPrivateWitness::new(secret_value, secret_blinding).unwrap();
    let real_att = ledger
        .prove_compliance(
            "att-nodisclose".to_string(),
            &policy,
            &params,
            &witness,
            1_000_000,
            "trace-nodisclose".to_string(),
        )
        .unwrap();

    let batch = ledger.verify_batch_authenticated(
        &[real_att.clone(), forged_v2],
        &policy,
        &params,
        1_000_002,
        "trace-batch-auth".to_string(),
    );
    assert_eq!(batch.total, 2);
    assert_eq!(batch.passed, 1);
    assert_eq!(batch.failed, 1);

    let ledger_json = serde_json::to_string(&ledger).unwrap();
    let witness_dbg = format!("{witness:?}");
    assert!(!witness_dbg.contains("987654321"));
    assert!(!witness_dbg.contains(&secret_blinding_hex));
    assert!(!ledger_json.contains("987654321"));
    assert!(!ledger_json.contains(&secret_blinding_hex));

    // Revoking the cryptographic attestation immediately blocks subsequent verification even with stale struct
    ledger
        .revoke_attestation("att-nodisclose", 1_000_003, "trace-rev".to_string())
        .unwrap();
    let after_revoke = ledger.verify_authenticated_proof(
        &real_att,
        &policy,
        &params,
        1_000_004,
        "trace-after-rev".to_string(),
    );
    assert!(matches!(
        after_revoke,
        ZkVerificationResult::Rejected { ref error_code, .. }
        if error_code == error_codes::ERR_ZKA_REVOKED
    ));
}
