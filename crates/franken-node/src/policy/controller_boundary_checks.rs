//! bd-bq4p: Controller boundary checks rejecting correctness-semantic mutations.
//!
//! Pre-apply enforcement layer that intercepts every policy proposal and rejects
//! any attempt to mutate a correctness-semantic invariant defined in the
//! CorrectnessEnvelope (bd-sddz). Every rejected mutation is recorded in an
//! audit trail with stable error classification.
//!
//! Log codes:
//! - `EVD-BOUNDARY-001`: check passed — proposal is within envelope
//! - `EVD-BOUNDARY-002`: rejection — proposal violates an invariant
//! - `EVD-BOUNDARY-003`: audit trail write — rejected mutation recorded
//! - `EVD-BOUNDARY-004`: checker initialization

use serde::{Deserialize, Serialize};
use std::fmt;

use super::correctness_envelope::{CorrectnessEnvelope, InvariantId, PolicyProposal};

// ── Error classification ────────────────────────────────────────────

/// Stable error classification for boundary violations.
///
/// INV-BOUNDARY-STABLE-ERRORS: These variants are stable across versions.
/// Adding new variants is allowed; renaming or removing is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Proposal targets an immutable invariant field.
    CorrectnessSemanticMutation,
    /// Proposal attempts to bypass the checker entirely.
    EnvelopeBypass,
    /// Proposal targets an unrecognized invariant.
    UnknownInvariantTarget,
}

impl ErrorClass {
    /// Stable label for serialization/logging.
    pub fn label(&self) -> &'static str {
        match self {
            Self::CorrectnessSemanticMutation => "correctness_semantic_mutation",
            Self::EnvelopeBypass => "envelope_bypass",
            Self::UnknownInvariantTarget => "unknown_invariant_target",
        }
    }

    /// Parse from label string.
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "correctness_semantic_mutation" => Some(Self::CorrectnessSemanticMutation),
            "envelope_bypass" => Some(Self::EnvelopeBypass),
            "unknown_invariant_target" => Some(Self::UnknownInvariantTarget),
            _ => None,
        }
    }

    /// All known variants (for stability checks).
    pub fn all_variants() -> &'static [ErrorClass] {
        &[
            Self::CorrectnessSemanticMutation,
            Self::EnvelopeBypass,
            Self::UnknownInvariantTarget,
        ]
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Boundary violation ──────────────────────────────────────────────

/// Detailed rejection produced when a proposal violates the correctness envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryViolation {
    pub violated_invariant: InvariantId,
    pub proposal_summary: String,
    pub rejection_reason: String,
    pub stable_error_class: ErrorClass,
}

impl fmt::Display for BoundaryViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EVD-BOUNDARY-002: boundary violation: invariant={}, class={}, reason={}",
            self.violated_invariant, self.stable_error_class, self.rejection_reason
        )
    }
}

impl std::error::Error for BoundaryViolation {}

// ── Rejected mutation record ────────────────────────────────────────

/// Audit record for a rejected mutation attempt.
///
/// INV-BOUNDARY-AUDITABLE: Every rejection produces exactly one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedMutationRecord {
    pub timestamp: u64,
    pub proposal_summary: String,
    pub violated_invariant: InvariantId,
    pub controller_id: String,
    pub error_class: ErrorClass,
    pub epoch_id: u64,
}

// ── Controller boundary checker ─────────────────────────────────────

/// Pre-apply boundary checker that validates all policy proposals against
/// the correctness envelope.
///
/// INV-BOUNDARY-MANDATORY: Every PolicyProposal must pass through
/// `check_proposal` before `apply()` is called.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerBoundaryChecker {
    /// Audit trail of all rejected mutation attempts.
    rejected_mutations: Vec<RejectedMutationRecord>,
    /// Running count of checks passed.
    checks_passed: u64,
    /// Running count of checks rejected.
    checks_rejected: u64,
}

impl ControllerBoundaryChecker {
    /// Create a new boundary checker.
    ///
    /// EVD-BOUNDARY-004: Checker initialization.
    pub fn new() -> Self {
        eprintln!("EVD-BOUNDARY-004: controller boundary checker initialized");
        Self {
            rejected_mutations: Vec::new(),
            checks_passed: 0,
            checks_rejected: 0,
        }
    }

    /// Check a policy proposal against the correctness envelope.
    ///
    /// INV-BOUNDARY-MANDATORY: This is the single enforcement point.
    /// INV-BOUNDARY-FAIL-CLOSED: Unknown/malformed proposals are rejected.
    ///
    /// Returns `Ok(())` if the proposal is within the envelope.
    /// Returns `Err(BoundaryViolation)` if any change targets an immutable field.
    pub fn check_proposal(
        &mut self,
        proposal: &PolicyProposal,
        envelope: &CorrectnessEnvelope,
        timestamp: u64,
    ) -> Result<(), BoundaryViolation> {
        // INV-BOUNDARY-FAIL-CLOSED: reject empty proposals
        if proposal.changes.is_empty() {
            let violation = BoundaryViolation {
                violated_invariant: InvariantId::new("UNKNOWN"),
                proposal_summary: format!(
                    "proposal={} controller={} epoch={}",
                    proposal.proposal_id, proposal.controller_id, proposal.epoch_id
                ),
                rejection_reason: "empty proposal: no changes specified".to_string(),
                stable_error_class: ErrorClass::UnknownInvariantTarget,
            };
            self.record_rejection(proposal, &violation, timestamp);
            return Err(violation);
        }

        // INV-BOUNDARY-FAIL-CLOSED: reject proposals with empty proposal_id
        if proposal.proposal_id.is_empty() {
            let violation = BoundaryViolation {
                violated_invariant: InvariantId::new("UNKNOWN"),
                proposal_summary: format!(
                    "proposal=(empty) controller={} epoch={}",
                    proposal.controller_id, proposal.epoch_id
                ),
                rejection_reason: "malformed proposal: empty proposal_id".to_string(),
                stable_error_class: ErrorClass::EnvelopeBypass,
            };
            self.record_rejection(proposal, &violation, timestamp);
            return Err(violation);
        }

        // Check each change against the envelope
        match envelope.is_within_envelope(proposal) {
            Ok(()) => {
                // EVD-BOUNDARY-001: check passed
                self.checks_passed += 1;
                eprintln!(
                    "EVD-BOUNDARY-001: boundary check passed: proposal={}, controller={}, epoch={}",
                    proposal.proposal_id, proposal.controller_id, proposal.epoch_id
                );
                Ok(())
            }
            Err(env_violation) => {
                let violation = BoundaryViolation {
                    violated_invariant: env_violation.invariant_id.clone(),
                    proposal_summary: format!(
                        "proposal={} controller={} epoch={} field={}",
                        proposal.proposal_id,
                        proposal.controller_id,
                        proposal.epoch_id,
                        env_violation.proposal_field
                    ),
                    rejection_reason: env_violation.reason.clone(),
                    stable_error_class: ErrorClass::CorrectnessSemanticMutation,
                };
                // EVD-BOUNDARY-002: rejection
                eprintln!(
                    "EVD-BOUNDARY-002: boundary violation: invariant={}, error_class={}, controller={}, epoch={}",
                    env_violation.invariant_id,
                    violation.stable_error_class,
                    proposal.controller_id,
                    proposal.epoch_id
                );
                self.record_rejection(proposal, &violation, timestamp);
                Err(violation)
            }
        }
    }

    /// Record a rejection in the audit trail.
    ///
    /// INV-BOUNDARY-AUDITABLE: Every rejection is recorded.
    /// EVD-BOUNDARY-003: Audit trail write.
    fn record_rejection(
        &mut self,
        proposal: &PolicyProposal,
        violation: &BoundaryViolation,
        timestamp: u64,
    ) {
        let record = RejectedMutationRecord {
            timestamp,
            proposal_summary: violation.proposal_summary.clone(),
            violated_invariant: violation.violated_invariant.clone(),
            controller_id: proposal.controller_id.clone(),
            error_class: violation.stable_error_class,
            epoch_id: proposal.epoch_id,
        };
        self.rejected_mutations.push(record);
        self.checks_rejected += 1;
        eprintln!(
            "EVD-BOUNDARY-003: audit trail write: invariant={}, controller={}, epoch={}",
            violation.violated_invariant, proposal.controller_id, proposal.epoch_id
        );
    }

    /// Return the audit trail of all rejected mutation attempts.
    pub fn rejected_mutations(&self) -> &[RejectedMutationRecord] {
        &self.rejected_mutations
    }

    /// Return count of rejected mutations.
    pub fn rejection_count(&self) -> usize {
        self.rejected_mutations.len()
    }

    /// Return count of checks passed.
    pub fn checks_passed(&self) -> u64 {
        self.checks_passed
    }

    /// Return count of checks rejected.
    pub fn checks_rejected(&self) -> u64 {
        self.checks_rejected
    }

    /// Generate a JSON rejection report with per-invariant counts and error
    /// class distribution.
    pub fn rejection_report(&self) -> serde_json::Value {
        let mut per_invariant: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        let mut per_class: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();

        for record in &self.rejected_mutations {
            *per_invariant
                .entry(record.violated_invariant.as_str().to_string())
                .or_insert(0) += 1;
            *per_class
                .entry(record.error_class.label().to_string())
                .or_insert(0) += 1;
        }

        serde_json::json!({
            "schema_version": "1.0",
            "total_rejections": self.rejected_mutations.len(),
            "total_passed": self.checks_passed,
            "per_invariant": per_invariant,
            "per_error_class": per_class,
            "records": self.rejected_mutations,
        })
    }

    /// Serialize the audit trail to JSON bytes (for persistence).
    pub fn serialize_audit_trail(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.rejected_mutations)
    }

    /// Restore audit trail from persisted JSON bytes.
    pub fn restore_audit_trail(&mut self, data: &[u8]) -> Result<(), serde_json::Error> {
        let records: Vec<RejectedMutationRecord> = serde_json::from_slice(data)?;
        self.rejected_mutations = records;
        self.checks_rejected = self.rejected_mutations.len() as u64;
        Ok(())
    }
}

impl Default for ControllerBoundaryChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::correctness_envelope::PolicyChange;

    fn envelope() -> CorrectnessEnvelope {
        CorrectnessEnvelope::canonical()
    }

    fn checker() -> ControllerBoundaryChecker {
        ControllerBoundaryChecker::new()
    }

    fn violating_proposal(field: &str) -> PolicyProposal {
        PolicyProposal {
            proposal_id: "test-violating-001".to_string(),
            controller_id: "controller-alpha".to_string(),
            epoch_id: 42,
            changes: vec![PolicyChange {
                field: field.to_string(),
                old_value: serde_json::json!(true),
                new_value: serde_json::json!(false),
            }],
        }
    }

    fn valid_proposal(field: &str) -> PolicyProposal {
        PolicyProposal {
            proposal_id: "test-valid-001".to_string(),
            controller_id: "controller-beta".to_string(),
            epoch_id: 43,
            changes: vec![PolicyChange {
                field: field.to_string(),
                old_value: serde_json::json!(100),
                new_value: serde_json::json!(200),
            }],
        }
    }

    fn empty_proposal() -> PolicyProposal {
        PolicyProposal {
            proposal_id: "test-empty-001".to_string(),
            controller_id: "controller-gamma".to_string(),
            epoch_id: 44,
            changes: vec![],
        }
    }

    fn malformed_proposal() -> PolicyProposal {
        PolicyProposal {
            proposal_id: String::new(),
            controller_id: "controller-delta".to_string(),
            epoch_id: 45,
            changes: vec![PolicyChange {
                field: "something".to_string(),
                old_value: serde_json::json!(1),
                new_value: serde_json::json!(2),
            }],
        }
    }

    // ── Initialization ──

    #[test]
    fn checker_starts_empty() {
        let c = checker();
        assert_eq!(c.rejection_count(), 0);
        assert_eq!(c.checks_passed(), 0);
        assert_eq!(c.checks_rejected(), 0);
        assert!(c.rejected_mutations().is_empty());
    }

    // ── Valid proposals pass ──

    #[test]
    fn valid_proposal_passes_check() {
        let env = envelope();
        let mut c = checker();
        let result = c.check_proposal(&valid_proposal("admission.budget_limit"), &env, 1000);
        assert!(result.is_ok());
        assert_eq!(c.checks_passed(), 1);
        assert_eq!(c.rejection_count(), 0);
    }

    #[test]
    fn valid_proposal_passes_scoring_threshold() {
        let env = envelope();
        let mut c = checker();
        let result = c.check_proposal(&valid_proposal("scoring.risk_threshold"), &env, 1001);
        assert!(result.is_ok());
    }

    #[test]
    fn valid_proposal_passes_telemetry_interval() {
        let env = envelope();
        let mut c = checker();
        let result = c.check_proposal(&valid_proposal("telemetry.flush_interval_ms"), &env, 1002);
        assert!(result.is_ok());
    }

    #[test]
    fn valid_proposal_passes_scheduling_parameter() {
        let env = envelope();
        let mut c = checker();
        let result = c.check_proposal(
            &valid_proposal("scheduling.max_concurrent_activations"),
            &env,
            1003,
        );
        assert!(result.is_ok());
    }

    // ── Correctness-semantic mutations rejected: all 12 invariants ──

    #[test]
    fn rejects_hardening_direction_mutation() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("hardening.direction"), &env, 2000)
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-001-MONOTONIC-HARDENING"
        );
        assert_eq!(
            err.stable_error_class,
            ErrorClass::CorrectnessSemanticMutation
        );
    }

    #[test]
    fn rejects_evidence_suppression() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("evidence.suppress"), &env, 2001)
            .unwrap_err();
        assert_eq!(err.violated_invariant.as_str(), "INV-002-EVIDENCE-EMISSION");
        assert_eq!(
            err.stable_error_class,
            ErrorClass::CorrectnessSemanticMutation
        );
    }

    #[test]
    fn rejects_seed_algorithm_change() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("seed.algorithm"), &env, 2002)
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-003-DETERMINISTIC-SEED"
        );
    }

    #[test]
    fn rejects_integrity_bypass() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(
                &violating_proposal("integrity.bypass_hash_check"),
                &env,
                2003,
            )
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-004-INTEGRITY-PROOF-VERIFICATION"
        );
    }

    #[test]
    fn rejects_ring_buffer_overflow_change() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(
                &violating_proposal("ring_buffer.overflow_policy"),
                &env,
                2004,
            )
            .unwrap_err();
        assert_eq!(err.violated_invariant.as_str(), "INV-005-RING-BUFFER-FIFO");
    }

    #[test]
    fn rejects_epoch_decrement() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("epoch.decrement"), &env, 2005)
            .unwrap_err();
        assert_eq!(err.violated_invariant.as_str(), "INV-006-EPOCH-MONOTONIC");
    }

    #[test]
    fn rejects_witness_hash_change() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("witness.hash_algorithm"), &env, 2006)
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-007-WITNESS-HASH-SHA256"
        );
    }

    #[test]
    fn rejects_guardrail_precedence_override() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("guardrail.precedence"), &env, 2007)
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-008-GUARDRAIL-PRECEDENCE"
        );
    }

    #[test]
    fn rejects_object_class_mutation() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(
                &violating_proposal("object_class.mutate_existing"),
                &env,
                2008,
            )
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-009-OBJECT-CLASS-APPEND-ONLY"
        );
    }

    #[test]
    fn rejects_network_bypass() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("network.bypass_remote_cap"), &env, 2009)
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-010-REMOTE-CAP-REQUIRED"
        );
    }

    #[test]
    fn rejects_marker_stream_rewrite() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("marker_stream.rewrite"), &env, 2010)
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-011-MARKER-CHAIN-APPEND-ONLY"
        );
    }

    #[test]
    fn rejects_receipt_chain_truncation() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&violating_proposal("receipt_chain.truncate"), &env, 2011)
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-012-RECEIPT-CHAIN-IMMUTABLE"
        );
    }

    // ── Fail-closed behavior ──

    #[test]
    fn rejects_empty_proposal() {
        let env = envelope();
        let mut c = checker();
        let err = c.check_proposal(&empty_proposal(), &env, 3000).unwrap_err();
        assert_eq!(err.stable_error_class, ErrorClass::UnknownInvariantTarget);
        assert!(err.rejection_reason.contains("empty proposal"));
    }

    #[test]
    fn rejects_malformed_proposal_empty_id() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(&malformed_proposal(), &env, 3001)
            .unwrap_err();
        assert_eq!(err.stable_error_class, ErrorClass::EnvelopeBypass);
        assert!(err.rejection_reason.contains("empty proposal_id"));
    }

    // ── Audit trail ──

    #[test]
    fn rejection_creates_audit_record() {
        let env = envelope();
        let mut c = checker();
        let _ = c.check_proposal(&violating_proposal("hardening.direction"), &env, 4000);
        assert_eq!(c.rejection_count(), 1);
        let records = c.rejected_mutations();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].violated_invariant.as_str(),
            "INV-001-MONOTONIC-HARDENING"
        );
        assert_eq!(records[0].controller_id, "controller-alpha");
        assert_eq!(records[0].epoch_id, 42);
        assert_eq!(records[0].timestamp, 4000);
        assert_eq!(
            records[0].error_class,
            ErrorClass::CorrectnessSemanticMutation
        );
    }

    #[test]
    fn multiple_rejections_accumulate_in_audit_trail() {
        let env = envelope();
        let mut c = checker();
        let _ = c.check_proposal(&violating_proposal("hardening.direction"), &env, 4001);
        let _ = c.check_proposal(&violating_proposal("evidence.suppress"), &env, 4002);
        let _ = c.check_proposal(&violating_proposal("seed.algorithm"), &env, 4003);
        assert_eq!(c.rejection_count(), 3);
        assert_eq!(c.checks_rejected(), 3);
    }

    #[test]
    fn valid_proposals_do_not_add_to_audit_trail() {
        let env = envelope();
        let mut c = checker();
        let _ = c.check_proposal(&valid_proposal("admission.budget_limit"), &env, 4010);
        assert_eq!(c.rejection_count(), 0);
        assert_eq!(c.checks_passed(), 1);
    }

    #[test]
    fn mixed_proposals_track_both_counts() {
        let env = envelope();
        let mut c = checker();
        let _ = c.check_proposal(&valid_proposal("admission.budget_limit"), &env, 5000);
        let _ = c.check_proposal(&violating_proposal("hardening.direction"), &env, 5001);
        let _ = c.check_proposal(&valid_proposal("scoring.risk_threshold"), &env, 5002);
        assert_eq!(c.checks_passed(), 2);
        assert_eq!(c.checks_rejected(), 1);
        assert_eq!(c.rejection_count(), 1);
    }

    // ── Rejection report ──

    #[test]
    fn rejection_report_contains_per_invariant_counts() {
        let env = envelope();
        let mut c = checker();
        let _ = c.check_proposal(&violating_proposal("hardening.direction"), &env, 6000);
        let _ = c.check_proposal(&violating_proposal("hardening.level_decrease"), &env, 6001);
        let _ = c.check_proposal(&violating_proposal("evidence.suppress"), &env, 6002);
        let report = c.rejection_report();
        assert_eq!(report["total_rejections"], 3);
        let per_inv = &report["per_invariant"];
        assert_eq!(per_inv["INV-001-MONOTONIC-HARDENING"], 2);
        assert_eq!(per_inv["INV-002-EVIDENCE-EMISSION"], 1);
    }

    #[test]
    fn rejection_report_contains_error_class_distribution() {
        let env = envelope();
        let mut c = checker();
        let _ = c.check_proposal(&violating_proposal("hardening.direction"), &env, 6010);
        let _ = c.check_proposal(&empty_proposal(), &env, 6011);
        let report = c.rejection_report();
        let per_class = &report["per_error_class"];
        assert_eq!(per_class["correctness_semantic_mutation"], 1);
        assert_eq!(per_class["unknown_invariant_target"], 1);
    }

    // ── ErrorClass stability ──

    #[test]
    fn error_class_label_round_trip() {
        for class in ErrorClass::all_variants() {
            let label = class.label();
            let parsed = ErrorClass::from_label(label).unwrap();
            assert_eq!(*class, parsed);
        }
    }

    #[test]
    fn error_class_all_variants_has_three() {
        assert_eq!(ErrorClass::all_variants().len(), 3);
    }

    #[test]
    fn error_class_display_matches_label() {
        for class in ErrorClass::all_variants() {
            assert_eq!(format!("{class}"), class.label());
        }
    }

    #[test]
    fn error_class_from_label_unknown_returns_none() {
        assert!(ErrorClass::from_label("nonexistent").is_none());
    }

    // ── BoundaryViolation serialization ──

    #[test]
    fn boundary_violation_serialization_round_trip() {
        let violation = BoundaryViolation {
            violated_invariant: InvariantId::new("INV-001-MONOTONIC-HARDENING"),
            proposal_summary: "test proposal".to_string(),
            rejection_reason: "test reason".to_string(),
            stable_error_class: ErrorClass::CorrectnessSemanticMutation,
        };
        let json = serde_json::to_string(&violation).unwrap();
        let parsed: BoundaryViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(violation, parsed);
    }

    #[test]
    fn boundary_violation_display_includes_event_code() {
        let violation = BoundaryViolation {
            violated_invariant: InvariantId::new("INV-001"),
            proposal_summary: "test".to_string(),
            rejection_reason: "test reason".to_string(),
            stable_error_class: ErrorClass::CorrectnessSemanticMutation,
        };
        let display = format!("{violation}");
        assert!(display.contains("EVD-BOUNDARY-002"));
        assert!(display.contains("INV-001"));
        assert!(display.contains("correctness_semantic_mutation"));
    }

    // ── RejectedMutationRecord serialization ──

    #[test]
    fn rejected_mutation_record_serialization_round_trip() {
        let record = RejectedMutationRecord {
            timestamp: 1234,
            proposal_summary: "test summary".to_string(),
            violated_invariant: InvariantId::new("INV-002"),
            controller_id: "controller-test".to_string(),
            error_class: ErrorClass::EnvelopeBypass,
            epoch_id: 99,
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: RejectedMutationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, parsed);
    }

    // ── Audit trail persistence ──

    #[test]
    fn audit_trail_serialize_and_restore() {
        let env = envelope();
        let mut c = checker();
        let _ = c.check_proposal(&violating_proposal("hardening.direction"), &env, 7000);
        let _ = c.check_proposal(&violating_proposal("evidence.suppress"), &env, 7001);

        let data = c.serialize_audit_trail().unwrap();

        let mut c2 = checker();
        c2.restore_audit_trail(&data).unwrap();
        assert_eq!(c2.rejection_count(), 2);
        assert_eq!(
            c2.rejected_mutations()[0].violated_invariant.as_str(),
            "INV-001-MONOTONIC-HARDENING"
        );
        assert_eq!(
            c2.rejected_mutations()[1].violated_invariant.as_str(),
            "INV-002-EVIDENCE-EMISSION"
        );
    }

    // ── Rapid sequential submissions ──

    #[test]
    fn rapid_sequential_submissions_all_tracked() {
        let env = envelope();
        let mut c = checker();
        let fields = [
            "hardening.direction",
            "evidence.suppress",
            "seed.algorithm",
            "integrity.bypass_hash_check",
            "ring_buffer.overflow_policy",
            "epoch.decrement",
            "witness.hash_algorithm",
            "guardrail.precedence",
            "object_class.mutate_existing",
            "network.bypass_remote_cap",
            "marker_stream.rewrite",
            "receipt_chain.truncate",
        ];
        for (i, field) in fields.iter().enumerate() {
            let _ = c.check_proposal(&violating_proposal(field), &env, 8000 + i as u64);
        }
        assert_eq!(c.rejection_count(), 12);
        assert_eq!(c.checks_rejected(), 12);
        let report = c.rejection_report();
        assert_eq!(report["total_rejections"], 12);
    }

    // ── Mixed proposal (valid + invalid changes) ──

    #[test]
    fn mixed_changes_proposal_rejected_on_first_violation() {
        let env = envelope();
        let mut c = checker();
        let proposal = PolicyProposal {
            proposal_id: "mixed-001".to_string(),
            controller_id: "controller-mixed".to_string(),
            epoch_id: 50,
            changes: vec![
                PolicyChange {
                    field: "telemetry.flush_interval_ms".to_string(),
                    old_value: serde_json::json!(1000),
                    new_value: serde_json::json!(2000),
                },
                PolicyChange {
                    field: "evidence.suppress".to_string(),
                    old_value: serde_json::json!(false),
                    new_value: serde_json::json!(true),
                },
            ],
        };
        let err = c.check_proposal(&proposal, &env, 9000).unwrap_err();
        assert_eq!(
            err.stable_error_class,
            ErrorClass::CorrectnessSemanticMutation
        );
        assert_eq!(c.rejection_count(), 1);
    }

    // ── Sub-field targeting ──

    #[test]
    fn rejects_sub_field_of_immutable_prefix() {
        let env = envelope();
        let mut c = checker();
        let err = c
            .check_proposal(
                &violating_proposal("hardening.direction.override"),
                &env,
                9100,
            )
            .unwrap_err();
        assert_eq!(
            err.violated_invariant.as_str(),
            "INV-001-MONOTONIC-HARDENING"
        );
    }

    // ── Full lifecycle test ──

    #[test]
    fn full_lifecycle_check_reject_check_report() {
        let env = envelope();
        let mut c = checker();

        // Pass
        assert!(
            c.check_proposal(&valid_proposal("admission.budget_limit"), &env, 10000)
                .is_ok()
        );

        // Reject
        assert!(
            c.check_proposal(&violating_proposal("hardening.direction"), &env, 10001)
                .is_err()
        );

        // Pass again
        assert!(
            c.check_proposal(&valid_proposal("scoring.risk_threshold"), &env, 10002)
                .is_ok()
        );

        // Reject again
        assert!(
            c.check_proposal(&violating_proposal("evidence.suppress"), &env, 10003)
                .is_err()
        );

        assert_eq!(c.checks_passed(), 2);
        assert_eq!(c.checks_rejected(), 2);
        assert_eq!(c.rejection_count(), 2);

        let report = c.rejection_report();
        assert_eq!(report["total_rejections"], 2);
        assert_eq!(report["total_passed"], 2);
    }

    // ── Default trait ──

    #[test]
    fn default_creates_empty_checker() {
        let c = ControllerBoundaryChecker::default();
        assert_eq!(c.rejection_count(), 0);
    }
}
