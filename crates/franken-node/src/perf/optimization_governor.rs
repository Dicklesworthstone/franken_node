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

const MAX_AUDIT_TRAIL_ENTRIES: usize = 4096;

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
        push_bounded(&mut self.audit_trail, GateAuditEntry {
            event_code: event_codes::GOVERNOR_CANDIDATE_PROPOSED.to_string(),
            proposal_id: pid.clone(),
            detail: format!(
                "knob={} old={} new={}",
                proposal.knob, proposal.old_value, proposal.new_value
            ),
        }, MAX_AUDIT_TRAIL_ENTRIES);

        // GOVERNOR_SHADOW_EVAL_START
        push_bounded(&mut self.audit_trail, GateAuditEntry {
            event_code: event_codes::GOVERNOR_SHADOW_EVAL_START.to_string(),
            proposal_id: pid.clone(),
            detail: "shadow evaluation starting".to_string(),
        }, MAX_AUDIT_TRAIL_ENTRIES);

        let decision = self.inner.submit(proposal);

        match &decision {
            GovernorDecision::Approved => {
                // GOVERNOR_SAFETY_CHECK_PASS
                push_bounded(&mut self.audit_trail, GateAuditEntry {
                    event_code: event_codes::GOVERNOR_SAFETY_CHECK_PASS.to_string(),
                    proposal_id: pid.clone(),
                    detail: "all safety checks passed".to_string(),
                }, MAX_AUDIT_TRAIL_ENTRIES);
                // GOVERNOR_POLICY_APPLIED
                push_bounded(&mut self.audit_trail, GateAuditEntry {
                    event_code: event_codes::GOVERNOR_POLICY_APPLIED.to_string(),
                    proposal_id: pid,
                    detail: "policy applied to runtime knob".to_string(),
                }, MAX_AUDIT_TRAIL_ENTRIES);
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
                push_bounded(&mut self.audit_trail, GateAuditEntry {
                    event_code: err.to_string(),
                    proposal_id: pid,
                    detail: format!("{reason:?}"),
                }, MAX_AUDIT_TRAIL_ENTRIES);
            }
            GovernorDecision::Reverted(msg) => {
                push_bounded(&mut self.audit_trail, GateAuditEntry {
                    event_code: event_codes::GOVERNOR_POLICY_REVERTED.to_string(),
                    proposal_id: pid,
                    detail: msg.clone(),
                }, MAX_AUDIT_TRAIL_ENTRIES);
            }
            GovernorDecision::ShadowOnly => {}
        }

        decision
    }

    /// Perform a live safety-envelope check and auto-revert breaching policies.
    ///
    /// INV-GOVERNOR-AUTO-REVERT: any applied policy whose live metrics
    /// breach the envelope is reverted with evidence.
    pub fn live_check(&mut self, live_metrics: &PredictedMetrics) -> Vec<String> {
        let reverted = self.inner.live_check(live_metrics);
        for pid in &reverted {
            // GOVERNOR_POLICY_REVERTED
            push_bounded(&mut self.audit_trail, GateAuditEntry {
                event_code: event_codes::GOVERNOR_POLICY_REVERTED.to_string(),
                proposal_id: pid.clone(),
                detail: "auto-reverted: live metrics breached safety envelope".to_string(),
            }, MAX_AUDIT_TRAIL_ENTRIES);
        }
        reverted
    }

    /// Attempt to set an engine-core internal knob, which must fail.
    ///
    /// INV-GOVERNOR-ENGINE-BOUNDARY: the governor cannot adjust
    /// engine-core internals.  This method always returns an error.
    pub fn reject_engine_internal_adjustment(&mut self, internal_name: &str) -> Result<(), String> {
        push_bounded(&mut self.audit_trail, GateAuditEntry {
            event_code: error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION.to_string(),
            proposal_id: String::new(),
            detail: format!("rejected engine-core internal: {internal_name}"),
        }, MAX_AUDIT_TRAIL_ENTRIES);
        Err(format!(
            "{}: cannot adjust engine-core internal '{}'",
            error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION,
            internal_name,
        ))
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
    }

    /// Look up a knob by its variant.
    pub fn get(&self, knob: &RuntimeKnob) -> Option<&KnobDescriptor> {
        self.knobs.iter().find(|d| &d.knob == knob)
    }

    /// All unlocked knobs (available for optimization).
    pub fn unlocked(&self) -> Vec<&KnobDescriptor> {
        self.knobs.iter().filter(|d| !d.locked).collect()
    }

    /// All locked knobs.
    pub fn locked(&self) -> Vec<&KnobDescriptor> {
        self.knobs.iter().filter(|d| d.locked).collect()
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

        push_bounded(self.audit_trail_mut(), GateAuditEntry {
            event_code: GOV_008_KNOB_ENUMERATION.to_string(),
            proposal_id: String::new(),
            detail: format!("{} knobs enumerated", knobs.len()),
        }, MAX_AUDIT_TRAIL_ENTRIES);

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

        push_bounded(self.audit_trail_mut(), GateAuditEntry {
            event_code: GOV_009_DISPATCH_HOOK.to_string(),
            proposal_id: String::new(),
            detail: format!(
                "dispatch payload: {} env vars, {} applied",
                env_vars.len(),
                applied_count
            ),
        }, MAX_AUDIT_TRAIL_ENTRIES);

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
            push_bounded(self.audit_trail_mut(), GateAuditEntry {
                event_code: GOV_010_KNOB_DISPATCHED.to_string(),
                proposal_id: String::new(),
                detail: format!("knob {} dispatched to engine", knob),
            }, MAX_AUDIT_TRAIL_ENTRIES);
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
    if items.len() >= cap {
        items.drain(..items.len() - cap + 1);
    }
    items.push(item);
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
        let err_msg = result.unwrap_err();
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
        let desc = enumeration.get(&RuntimeKnob::ConcurrencyLimit).unwrap();
        assert_eq!(desc.current_value, 64);
        assert!(!desc.locked);
        assert_eq!(desc.label, "concurrency_limit");
    }

    #[test]
    fn test_enumerate_knobs_has_batch_size() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        let desc = enumeration.get(&RuntimeKnob::BatchSize).unwrap();
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
        let retry = enumeration.get(&RuntimeKnob::RetryBudget).unwrap();
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
        let desc = enumeration.get(&RuntimeKnob::ConcurrencyLimit).unwrap();
        assert_eq!(desc.current_value, 128);
    }

    #[test]
    fn test_knob_enumeration_serde_roundtrip() {
        let mut gate = GovernorGate::with_defaults();
        let enumeration = gate.enumerate_knobs();
        let json = serde_json::to_string(&enumeration).unwrap();
        let parsed: KnobEnumeration = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: DispatchHookPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.env_vars.len(), payload.env_vars.len());
    }

    // -- submit_and_dispatch --

    #[test]
    fn test_submit_and_dispatch_approved() {
        let mut gate = GovernorGate::with_defaults();
        let (decision, payload) = gate.submit_and_dispatch(good_proposal("p1"));
        assert!(matches!(decision, GovernorDecision::Approved));
        assert!(payload.is_some());
        let payload = payload.unwrap();
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

    // -- Full pipeline --

    #[test]
    fn test_full_pipeline_enumerate_submit_dispatch() {
        let mut gate = GovernorGate::with_defaults();

        // 1. Enumerate knobs
        let enum_before = gate.enumerate_knobs();
        assert_eq!(
            enum_before
                .get(&RuntimeKnob::ConcurrencyLimit)
                .unwrap()
                .current_value,
            64
        );

        // 2. Submit and dispatch
        let (decision, payload) = gate.submit_and_dispatch(good_proposal("p1"));
        assert!(matches!(decision, GovernorDecision::Approved));
        let payload = payload.unwrap();
        assert_eq!(payload.env_vars["FRANKEN_GOV_CONCURRENCY_LIMIT"], "128");

        // 3. Enumerate again — reflects new value
        let enum_after = gate.enumerate_knobs();
        assert_eq!(
            enum_after
                .get(&RuntimeKnob::ConcurrencyLimit)
                .unwrap()
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
        let json = serde_json::to_string(&desc).unwrap();
        let parsed: KnobDescriptor = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&record).unwrap();
        let parsed: DispatchHookRecord = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&snap).unwrap();
        let parsed: GovernorDispatchSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enumeration.count(), 5);
    }
}
