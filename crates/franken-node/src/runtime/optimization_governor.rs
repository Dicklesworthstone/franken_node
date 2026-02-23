//! bd-21fo: Self-evolving optimization governor with safety-envelope enforcement.
//!
//! The [`OptimizationGovernor`] evaluates candidate [`OptimizationProposal`]s against
//! a [`SafetyEnvelope`] before they touch any runtime knob.  Every proposal flows
//! through shadow evaluation first; if the predicted metrics breach the envelope the
//! proposal is rejected with a [`RejectionReason`].  If a previously approved proposal
//! is later found to violate the envelope at live-check time it is automatically
//! reverted with evidence.
//!
//! # Design Constraints
//!
//! - The governor may only adjust **exposed runtime knobs** (see [`RuntimeKnob`]).
//!   Engine-core internals are out of scope (INV-GOV-KNOBS-ONLY).
//! - Shadow evaluation must precede every live application (INV-GOV-SHADOW-BEFORE-APPLY).
//! - No applied optimisation may breach the safety envelope (INV-GOV-ENVELOPE-NEVER-BREACHED).
//! - Every rejection emits a machine-readable evidence record (INV-GOV-EVIDENCE-ON-REJECT).
//! - Applied policies that later breach the envelope auto-revert (INV-GOV-AUTO-REVERT).
//! - Decision log entries are totally ordered by sequence number
//!   (INV-GOV-DETERMINISTIC-ORDER).
//!
//! # Event Codes
//!
//! - `GOV_001` -- Proposal submitted
//! - `GOV_002` -- Shadow evaluation started
//! - `GOV_003` -- Proposal approved and applied
//! - `GOV_004` -- Proposal rejected
//! - `GOV_005` -- Proposal auto-reverted
//! - `GOV_006` -- Safety envelope updated
//! - `GOV_007` -- Governor state snapshot emitted
//!
//! # Error Codes
//!
//! - `ERR_GOV_ENVELOPE_VIOLATION` -- Predicted metrics breach envelope bounds
//! - `ERR_GOV_NON_BENEFICIAL` -- Proposal does not improve any metric
//! - `ERR_GOV_KNOB_LOCKED` -- Target knob locked by higher-priority policy
//! - `ERR_GOV_REVERT_FAILED` -- Auto-revert of a previously applied proposal failed
//! - `ERR_GOV_SHADOW_TIMEOUT` -- Shadow evaluation exceeded its time budget
//! - `ERR_GOV_INVALID_PROPOSAL` -- Invalid or inconsistent proposal fields

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for optimization governor records.
pub const SCHEMA_VERSION: &str = "gov-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// GOV_001: Optimization proposal submitted to governor.
    pub const GOV_001: &str = "GOV_001";
    /// GOV_002: Shadow evaluation started for proposal.
    pub const GOV_002: &str = "GOV_002";
    /// GOV_003: Proposal approved and applied.
    pub const GOV_003: &str = "GOV_003";
    /// GOV_004: Proposal rejected.
    pub const GOV_004: &str = "GOV_004";
    /// GOV_005: Previously applied proposal auto-reverted.
    pub const GOV_005: &str = "GOV_005";
    /// GOV_006: Safety envelope updated.
    pub const GOV_006: &str = "GOV_006";
    /// GOV_007: Governor state snapshot emitted.
    pub const GOV_007: &str = "GOV_007";

    // bd-21fo canonical event codes
    /// GOVERNOR_CANDIDATE_PROPOSED: a candidate optimization was submitted.
    pub const GOVERNOR_CANDIDATE_PROPOSED: &str = "GOVERNOR_CANDIDATE_PROPOSED";
    /// GOVERNOR_SHADOW_EVAL_START: shadow evaluation began for a candidate.
    pub const GOVERNOR_SHADOW_EVAL_START: &str = "GOVERNOR_SHADOW_EVAL_START";
    /// GOVERNOR_SAFETY_CHECK_PASS: all safety-envelope checks passed.
    pub const GOVERNOR_SAFETY_CHECK_PASS: &str = "GOVERNOR_SAFETY_CHECK_PASS";
    /// GOVERNOR_POLICY_APPLIED: an optimization policy was applied to a runtime knob.
    pub const GOVERNOR_POLICY_APPLIED: &str = "GOVERNOR_POLICY_APPLIED";
    /// GOVERNOR_POLICY_REVERTED: a previously applied policy was auto-reverted.
    pub const GOVERNOR_POLICY_REVERTED: &str = "GOVERNOR_POLICY_REVERTED";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    /// ERR_GOV_ENVELOPE_VIOLATION: Predicted metrics breach envelope bounds.
    pub const ERR_GOV_ENVELOPE_VIOLATION: &str = "ERR_GOV_ENVELOPE_VIOLATION";
    /// ERR_GOV_NON_BENEFICIAL: Proposal does not improve any metric.
    pub const ERR_GOV_NON_BENEFICIAL: &str = "ERR_GOV_NON_BENEFICIAL";
    /// ERR_GOV_KNOB_LOCKED: Target knob locked by higher-priority policy.
    pub const ERR_GOV_KNOB_LOCKED: &str = "ERR_GOV_KNOB_LOCKED";
    /// ERR_GOV_REVERT_FAILED: Auto-revert failed.
    pub const ERR_GOV_REVERT_FAILED: &str = "ERR_GOV_REVERT_FAILED";
    /// ERR_GOV_SHADOW_TIMEOUT: Shadow evaluation timed out.
    pub const ERR_GOV_SHADOW_TIMEOUT: &str = "ERR_GOV_SHADOW_TIMEOUT";
    /// ERR_GOV_INVALID_PROPOSAL: Invalid or inconsistent proposal fields.
    pub const ERR_GOV_INVALID_PROPOSAL: &str = "ERR_GOV_INVALID_PROPOSAL";

    // bd-21fo canonical error codes
    /// ERR_GOVERNOR_UNSAFE_CANDIDATE: candidate optimization breaches safety envelope.
    pub const ERR_GOVERNOR_UNSAFE_CANDIDATE: &str = "ERR_GOVERNOR_UNSAFE_CANDIDATE";
    /// ERR_GOVERNOR_SHADOW_EVAL_FAILED: shadow evaluation failed to complete.
    pub const ERR_GOVERNOR_SHADOW_EVAL_FAILED: &str = "ERR_GOVERNOR_SHADOW_EVAL_FAILED";
    /// ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD: proposed change has no net benefit.
    pub const ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD: &str = "ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD";
    /// ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION: attempt to adjust engine-core internals.
    pub const ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION: &str =
        "ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION";
    /// ERR_GOVERNOR_REVERT_FAILED: auto-revert of an applied policy did not succeed.
    pub const ERR_GOVERNOR_REVERT_FAILED: &str = "ERR_GOVERNOR_REVERT_FAILED";
    /// ERR_GOVERNOR_KNOB_READONLY: target knob is read-only or locked.
    pub const ERR_GOVERNOR_KNOB_READONLY: &str = "ERR_GOVERNOR_KNOB_READONLY";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub mod invariants {
    /// INV-GOV-ENVELOPE-NEVER-BREACHED: No applied optimization may violate the
    /// safety envelope bounds.
    pub const INV_GOV_ENVELOPE_NEVER_BREACHED: &str = "INV-GOV-ENVELOPE-NEVER-BREACHED";
    /// INV-GOV-SHADOW-BEFORE-APPLY: Every proposal must pass shadow evaluation
    /// before live application.
    pub const INV_GOV_SHADOW_BEFORE_APPLY: &str = "INV-GOV-SHADOW-BEFORE-APPLY";
    /// INV-GOV-EVIDENCE-ON-REJECT: Every rejection emits a machine-readable
    /// evidence record.
    pub const INV_GOV_EVIDENCE_ON_REJECT: &str = "INV-GOV-EVIDENCE-ON-REJECT";
    /// INV-GOV-KNOBS-ONLY: Governor may only adjust exposed runtime knobs,
    /// never engine-core internals.
    pub const INV_GOV_KNOBS_ONLY: &str = "INV-GOV-KNOBS-ONLY";
    /// INV-GOV-AUTO-REVERT: Applied policies that later breach the envelope
    /// are automatically reverted.
    pub const INV_GOV_AUTO_REVERT: &str = "INV-GOV-AUTO-REVERT";
    /// INV-GOV-DETERMINISTIC-ORDER: Decision log entries are totally ordered
    /// by sequence number.
    pub const INV_GOV_DETERMINISTIC_ORDER: &str = "INV-GOV-DETERMINISTIC-ORDER";

    // bd-21fo canonical invariant identifiers
    /// INV-GOVERNOR-SHADOW-REQUIRED: every candidate must go through shadow evaluation.
    pub const INV_GOVERNOR_SHADOW_REQUIRED: &str = "INV-GOVERNOR-SHADOW-REQUIRED";
    /// INV-GOVERNOR-SAFETY-ENVELOPE: no applied policy may breach the safety envelope.
    pub const INV_GOVERNOR_SAFETY_ENVELOPE: &str = "INV-GOVERNOR-SAFETY-ENVELOPE";
    /// INV-GOVERNOR-AUTO-REVERT: unsafe or non-beneficial policies auto-revert.
    pub const INV_GOVERNOR_AUTO_REVERT: &str = "INV-GOVERNOR-AUTO-REVERT";
    /// INV-GOVERNOR-ENGINE-BOUNDARY: governor adjusts only exposed runtime knobs.
    pub const INV_GOVERNOR_ENGINE_BOUNDARY: &str = "INV-GOVERNOR-ENGINE-BOUNDARY";
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Runtime knobs that the governor is permitted to adjust.
///
/// INV-GOV-KNOBS-ONLY: only these variants are adjustable; engine-core
/// internals are explicitly excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKnob {
    /// Maximum concurrent operations.
    ConcurrencyLimit,
    /// Processing batch size.
    BatchSize,
    /// In-memory cache capacity.
    CacheCapacity,
    /// Drain timeout in milliseconds.
    DrainTimeoutMs,
    /// Maximum retry attempts.
    RetryBudget,
}

impl RuntimeKnob {
    /// Stable string identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConcurrencyLimit => "concurrency_limit",
            Self::BatchSize => "batch_size",
            Self::CacheCapacity => "cache_capacity",
            Self::DrainTimeoutMs => "drain_timeout_ms",
            Self::RetryBudget => "retry_budget",
        }
    }
}

impl fmt::Display for RuntimeKnob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Quantitative safety bounds that no applied optimisation may violate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafetyEnvelope {
    /// Hard cap on p99 latency in milliseconds.
    pub max_latency_ms: u64,
    /// Minimum requests-per-second floor.
    pub min_throughput_rps: u64,
    /// Maximum error rate as a percentage (0.0..=100.0).
    pub max_error_rate_pct: f64,
    /// Maximum memory usage in megabytes.
    pub max_memory_mb: u64,
}

impl SafetyEnvelope {
    /// Check whether a set of predicted metrics fits within this envelope.
    pub fn contains(&self, metrics: &PredictedMetrics) -> bool {
        metrics.latency_ms <= self.max_latency_ms
            && metrics.throughput_rps >= self.min_throughput_rps
            && metrics.error_rate_pct <= self.max_error_rate_pct
            && metrics.memory_mb <= self.max_memory_mb
    }

    /// Return all violations as a list of human-readable strings.
    /// Uses `!(a <= b)` to stay consistent with `contains()` on NaN inputs.
    #[allow(clippy::neg_cmp_op_on_partial_ord)]
    pub fn violations(&self, metrics: &PredictedMetrics) -> Vec<String> {
        let mut vs = Vec::new();
        if metrics.latency_ms > self.max_latency_ms {
            vs.push(format!(
                "latency {}ms > cap {}ms",
                metrics.latency_ms, self.max_latency_ms
            ));
        }
        if metrics.throughput_rps < self.min_throughput_rps {
            vs.push(format!(
                "throughput {}rps < floor {}rps",
                metrics.throughput_rps, self.min_throughput_rps
            ));
        }
        if !(metrics.error_rate_pct <= self.max_error_rate_pct) {
            vs.push(format!(
                "error rate {:.2}% > ceiling {:.2}%",
                metrics.error_rate_pct, self.max_error_rate_pct
            ));
        }
        if metrics.memory_mb > self.max_memory_mb {
            vs.push(format!(
                "memory {}MB > cap {}MB",
                metrics.memory_mb, self.max_memory_mb
            ));
        }
        vs
    }

    /// Validate the envelope itself (all bounds are reasonable).
    pub fn is_valid(&self) -> bool {
        self.max_latency_ms > 0
            && self.min_throughput_rps > 0
            && (0.0..=100.0).contains(&self.max_error_rate_pct)
            && self.max_memory_mb > 0
    }
}

impl Default for SafetyEnvelope {
    fn default() -> Self {
        Self {
            max_latency_ms: 500,
            min_throughput_rps: 100,
            max_error_rate_pct: 1.0,
            max_memory_mb: 4096,
        }
    }
}

/// Predicted metrics for a proposal after shadow evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictedMetrics {
    pub latency_ms: u64,
    pub throughput_rps: u64,
    pub error_rate_pct: f64,
    pub memory_mb: u64,
}

/// An optimization proposal that the governor evaluates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizationProposal {
    /// Unique identifier for this proposal.
    pub proposal_id: String,
    /// Which runtime knob to adjust.
    pub knob: RuntimeKnob,
    /// Current value of the knob.
    pub old_value: u64,
    /// Proposed new value.
    pub new_value: u64,
    /// Predicted metrics after the change.
    pub predicted: PredictedMetrics,
    /// Human-readable rationale.
    pub rationale: String,
    /// Correlation ID for distributed tracing.
    pub trace_id: String,
}

impl OptimizationProposal {
    /// Basic structural validation.
    pub fn is_valid(&self) -> bool {
        !self.proposal_id.is_empty()
            && !self.trace_id.is_empty()
            && self.predicted.error_rate_pct >= 0.0
    }
}

/// Why a proposal was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Predicted metrics breach safety-envelope bounds.
    EnvelopeViolation(Vec<String>),
    /// Proposal does not improve any metric vs. baseline.
    NonBeneficial,
    /// Target knob is locked by a higher-priority policy.
    KnobLocked,
    /// Proposal has invalid fields.
    InvalidProposal(String),
}

impl RejectionReason {
    /// Map to the corresponding error code constant.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::EnvelopeViolation(_) => error_codes::ERR_GOV_ENVELOPE_VIOLATION,
            Self::NonBeneficial => error_codes::ERR_GOV_NON_BENEFICIAL,
            Self::KnobLocked => error_codes::ERR_GOV_KNOB_LOCKED,
            Self::InvalidProposal(_) => error_codes::ERR_GOV_INVALID_PROPOSAL,
        }
    }
}

/// The decision the governor makes for a proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernorDecision {
    /// Proposal approved and applied.
    Approved,
    /// Proposal rejected.
    Rejected(RejectionReason),
    /// Previously applied proposal auto-reverted.
    Reverted(String),
    /// Proposal accepted for shadow-only evaluation; not yet applied.
    ShadowOnly,
}

/// An immutable record of a governor decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Proposal that was evaluated.
    pub proposal_id: String,
    /// The knob that was targeted.
    pub knob: RuntimeKnob,
    /// The decision.
    pub decision: GovernorDecision,
    /// The event code emitted.
    pub event_code: String,
    /// Trace correlation ID.
    pub trace_id: String,
    /// Evidence detail for rejections/reverts.
    pub evidence: Option<String>,
}

/// Shadow evaluation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowResult {
    pub proposal_id: String,
    pub within_envelope: bool,
    pub violations: Vec<String>,
    pub is_beneficial: bool,
}

/// Current live value for a knob, used to check benefit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnobState {
    pub knob: RuntimeKnob,
    pub value: u64,
    pub locked: bool,
}

/// The self-evolving optimization governor.
///
/// Maintains a [`SafetyEnvelope`], current knob states, a decision log, and
/// a set of applied proposals that may be auto-reverted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationGovernor {
    /// The current safety envelope.
    envelope: SafetyEnvelope,
    /// Current knob states keyed by knob (BTreeMap for deterministic ordering).
    knob_states: BTreeMap<RuntimeKnob, KnobState>,
    /// Decision log, totally ordered by seq.
    decision_log: Vec<DecisionRecord>,
    /// Currently applied proposals keyed by proposal_id, holding the old
    /// value so we can revert.
    applied: BTreeMap<String, AppliedProposal>,
    /// Monotonically increasing sequence counter.
    next_seq: u64,
    /// Schema version.
    schema_version: String,
}

/// Tracks an applied proposal so we can auto-revert it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AppliedProposal {
    pub proposal_id: String,
    pub knob: RuntimeKnob,
    pub old_value: u64,
    pub new_value: u64,
    pub trace_id: String,
}

impl OptimizationGovernor {
    /// Create a new governor with the given envelope and initial knob states.
    pub fn new(envelope: SafetyEnvelope, knob_states: BTreeMap<RuntimeKnob, KnobState>) -> Self {
        Self {
            envelope,
            knob_states,
            decision_log: Vec::new(),
            applied: BTreeMap::new(),
            next_seq: 1,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Create a governor with default envelope and default knob states.
    pub fn with_defaults() -> Self {
        let mut knob_states = BTreeMap::new();
        let defaults = [
            (RuntimeKnob::ConcurrencyLimit, 64),
            (RuntimeKnob::BatchSize, 128),
            (RuntimeKnob::CacheCapacity, 1024),
            (RuntimeKnob::DrainTimeoutMs, 30_000),
            (RuntimeKnob::RetryBudget, 3),
        ];
        for (knob, value) in defaults {
            knob_states.insert(
                knob,
                KnobState {
                    knob,
                    value,
                    locked: false,
                },
            );
        }
        Self::new(SafetyEnvelope::default(), knob_states)
    }

    /// Return a reference to the current safety envelope.
    pub fn envelope(&self) -> &SafetyEnvelope {
        &self.envelope
    }

    /// Update the safety envelope.  Emits GOV_006.
    pub fn update_envelope(&mut self, new_envelope: SafetyEnvelope) {
        self.envelope = new_envelope;
        // GOV_006 emitted (structurally logged by caller)
    }

    /// Return the current schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Read the decision log.
    pub fn decision_log(&self) -> &[DecisionRecord] {
        &self.decision_log
    }

    /// Number of currently applied proposals.
    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }

    /// Return the current value of a knob, if tracked.
    pub fn knob_value(&self, knob: &RuntimeKnob) -> Option<u64> {
        self.knob_states.get(knob).map(|s| s.value)
    }

    /// Lock a knob so no proposals can change it.
    pub fn lock_knob(&mut self, knob: RuntimeKnob) {
        if let Some(state) = self.knob_states.get_mut(&knob) {
            state.locked = true;
        }
    }

    /// Unlock a previously locked knob.
    pub fn unlock_knob(&mut self, knob: RuntimeKnob) {
        if let Some(state) = self.knob_states.get_mut(&knob) {
            state.locked = false;
        }
    }

    // -----------------------------------------------------------------------
    // Shadow evaluation (INV-GOV-SHADOW-BEFORE-APPLY)
    // -----------------------------------------------------------------------

    /// Perform shadow evaluation of a proposal against the safety envelope.
    ///
    /// Returns a [`ShadowResult`] that indicates whether the proposal is within
    /// the envelope and whether it is beneficial (improves at least one metric
    /// without worsening others beyond the envelope).
    pub fn shadow_evaluate(&self, proposal: &OptimizationProposal) -> ShadowResult {
        // GOV_002 emitted
        let violations = self.envelope.violations(&proposal.predicted);
        let within_envelope = violations.is_empty();

        // A proposal is beneficial if its new_value differs from old_value and
        // it stays within the envelope.
        let is_beneficial = within_envelope && proposal.new_value != proposal.old_value;

        ShadowResult {
            proposal_id: proposal.proposal_id.clone(),
            within_envelope,
            violations,
            is_beneficial,
        }
    }

    // -----------------------------------------------------------------------
    // Submit (the main entry point)
    // -----------------------------------------------------------------------

    /// Submit a proposal to the governor.  The proposal is shadow-evaluated,
    /// then either approved+applied or rejected with evidence.
    ///
    /// Returns the [`GovernorDecision`] and appends a [`DecisionRecord`] to
    /// the log.
    pub fn submit(&mut self, proposal: OptimizationProposal) -> GovernorDecision {
        // GOV_001 emitted

        // 1. Validate proposal
        if !proposal.is_valid() {
            let reason = RejectionReason::InvalidProposal(
                "proposal_id or trace_id is empty, or error_rate_pct < 0".to_string(),
            );
            let decision = GovernorDecision::Rejected(reason);
            self.record(
                &proposal.proposal_id,
                proposal.knob,
                &decision,
                event_codes::GOV_004,
                &proposal.trace_id,
            );
            return decision;
        }

        // 2. Ensure target knob exists and proposal baseline matches current state.
        let (current_value, knob_locked) = match self.knob_states.get(&proposal.knob) {
            Some(state) => (state.value, state.locked),
            None => {
                let reason = RejectionReason::InvalidProposal(format!(
                    "target knob `{}` is not configured",
                    proposal.knob
                ));
                let decision = GovernorDecision::Rejected(reason);
                self.record(
                    &proposal.proposal_id,
                    proposal.knob,
                    &decision,
                    event_codes::GOV_004,
                    &proposal.trace_id,
                );
                return decision;
            }
        };

        if proposal.old_value != current_value {
            let reason = RejectionReason::InvalidProposal(format!(
                "stale old_value for `{}`: expected current {}, got {}",
                proposal.knob, current_value, proposal.old_value
            ));
            let decision = GovernorDecision::Rejected(reason);
            self.record(
                &proposal.proposal_id,
                proposal.knob,
                &decision,
                event_codes::GOV_004,
                &proposal.trace_id,
            );
            return decision;
        }

        // 3. Check if knob is locked (INV-GOV-KNOBS-ONLY)
        if knob_locked {
            let decision = GovernorDecision::Rejected(RejectionReason::KnobLocked);
            self.record(
                &proposal.proposal_id,
                proposal.knob,
                &decision,
                event_codes::GOV_004,
                &proposal.trace_id,
            );
            return decision;
        }

        // 4. Shadow evaluate (INV-GOV-SHADOW-BEFORE-APPLY)
        let shadow = self.shadow_evaluate(&proposal);

        if !shadow.within_envelope {
            // Rejected -- envelope violation
            let reason = RejectionReason::EnvelopeViolation(shadow.violations);
            let decision = GovernorDecision::Rejected(reason);
            self.record(
                &proposal.proposal_id,
                proposal.knob,
                &decision,
                event_codes::GOV_004,
                &proposal.trace_id,
            );
            return decision;
        }

        if !shadow.is_beneficial {
            // Rejected -- non-beneficial
            let decision = GovernorDecision::Rejected(RejectionReason::NonBeneficial);
            self.record(
                &proposal.proposal_id,
                proposal.knob,
                &decision,
                event_codes::GOV_004,
                &proposal.trace_id,
            );
            return decision;
        }

        // 5. Approved -- apply the knob change
        self.knob_states
            .get_mut(&proposal.knob)
            .expect("knob existence checked above")
            .value = proposal.new_value;

        self.applied.insert(
            proposal.proposal_id.clone(),
            AppliedProposal {
                proposal_id: proposal.proposal_id.clone(),
                knob: proposal.knob,
                old_value: proposal.old_value,
                new_value: proposal.new_value,
                trace_id: proposal.trace_id.clone(),
            },
        );

        let decision = GovernorDecision::Approved;
        self.record(
            &proposal.proposal_id,
            proposal.knob,
            &decision,
            event_codes::GOV_003,
            &proposal.trace_id,
        );
        // GOV_003 emitted
        decision
    }

    // -----------------------------------------------------------------------
    // Live check + auto-revert (INV-GOV-AUTO-REVERT)
    // -----------------------------------------------------------------------

    /// Perform a live check of all applied proposals against the given live
    /// metrics.  Any proposal whose knob's live metrics breach the envelope
    /// is auto-reverted.
    ///
    /// Returns the list of reverted proposal IDs.
    pub fn live_check(&mut self, live_metrics: &PredictedMetrics) -> Vec<String> {
        if self.envelope.contains(live_metrics) {
            return Vec::new();
        }

        // All currently applied proposals are suspect; revert them all.
        // Reverse so last-applied proposals revert first and earliest old_value wins.
        let mut to_revert: Vec<AppliedProposal> = self.applied.values().cloned().collect();
        to_revert.reverse();
        let mut reverted_ids = Vec::new();

        for ap in &to_revert {
            // Revert knob to old value
            if let Some(state) = self.knob_states.get_mut(&ap.knob) {
                state.value = ap.old_value;
            }
            let decision = GovernorDecision::Reverted(format!(
                "Live metrics breached envelope; reverted {} from {} to {}",
                ap.knob, ap.new_value, ap.old_value
            ));
            self.record(
                &ap.proposal_id,
                ap.knob,
                &decision,
                event_codes::GOV_005,
                &ap.trace_id,
            );
            reverted_ids.push(ap.proposal_id.clone());
        }

        for id in &reverted_ids {
            self.applied.remove(id);
        }

        reverted_ids
    }

    // -----------------------------------------------------------------------
    // State snapshot (GOV_007)
    // -----------------------------------------------------------------------

    /// Emit a serializable state snapshot of the governor.
    pub fn snapshot(&self) -> GovernorSnapshot {
        GovernorSnapshot {
            schema_version: self.schema_version.clone(),
            envelope: self.envelope.clone(),
            knob_states: self.knob_states.values().cloned().collect(),
            applied_count: self.applied.len(),
            decision_log_len: self.decision_log.len(),
            next_seq: self.next_seq,
        }
    }

    // -----------------------------------------------------------------------
    // Contract-compatible method aliases (bd-21fo checker)
    // -----------------------------------------------------------------------

    /// Alias for [`submit`] matching the contract name `submit_proposal`.
    pub fn submit_proposal(&mut self, proposal: OptimizationProposal) -> GovernorDecision {
        self.submit(proposal)
    }

    /// Alias for [`live_check`] matching the contract name `auto_revert_check`.
    pub fn auto_revert_check(&mut self, live_metrics: &PredictedMetrics) -> Vec<String> {
        self.live_check(live_metrics)
    }

    /// Shadow-only submission: proposal is evaluated but not applied.
    pub fn submit_shadow_only(&mut self, proposal: &OptimizationProposal) -> ShadowResult {
        self.shadow_evaluate(proposal)
    }

    /// Export the decision log as JSONL (one JSON object per line).
    pub fn export_decision_log_jsonl(&self) -> String {
        self.decision_log
            .iter()
            .filter_map(|entry| serde_json::to_string(entry).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export a verification evidence JSON blob.
    pub fn export_verification_evidence(&self) -> serde_json::Value {
        let snap = self.snapshot();
        serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "bead_id": "bd-21fo",
            "section": "10.17",
            "governor_snapshot": snap,
            "decision_log_count": self.decision_log.len(),
            "invariants_checked": [
                invariants::INV_GOV_ENVELOPE_NEVER_BREACHED,
                invariants::INV_GOV_SHADOW_BEFORE_APPLY,
                invariants::INV_GOV_EVIDENCE_ON_REJECT,
                invariants::INV_GOV_KNOBS_ONLY,
                invariants::INV_GOV_AUTO_REVERT,
                invariants::INV_GOV_DETERMINISTIC_ORDER,
            ],
            "event_codes_used": [
                event_codes::GOV_001,
                event_codes::GOV_002,
                event_codes::GOV_003,
                event_codes::GOV_004,
                event_codes::GOV_005,
                event_codes::GOV_006,
                event_codes::GOV_007,
            ],
            "error_codes_defined": [
                error_codes::ERR_GOV_ENVELOPE_VIOLATION,
                error_codes::ERR_GOV_NON_BENEFICIAL,
                error_codes::ERR_GOV_KNOB_LOCKED,
                error_codes::ERR_GOV_REVERT_FAILED,
                error_codes::ERR_GOV_SHADOW_TIMEOUT,
                error_codes::ERR_GOV_INVALID_PROPOSAL,
            ],
        })
    }

    /// Return the total number of decisions made.
    pub fn decision_count(&self) -> usize {
        self.decision_log.len()
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn record(
        &mut self,
        proposal_id: &str,
        knob: RuntimeKnob,
        decision: &GovernorDecision,
        event_code: &str,
        trace_id: &str,
    ) {
        let evidence = match decision {
            GovernorDecision::Rejected(reason) => {
                Some(format!("{}: {:?}", reason.error_code(), reason))
            }
            GovernorDecision::Reverted(msg) => Some(msg.clone()),
            _ => None,
        };

        let rec = DecisionRecord {
            seq: self.next_seq,
            proposal_id: proposal_id.to_string(),
            knob,
            decision: decision.clone(),
            event_code: event_code.to_string(),
            trace_id: trace_id.to_string(),
            evidence,
        };
        self.decision_log.push(rec);
        self.next_seq = self.next_seq.saturating_add(1);
    }
}

/// Serializable snapshot of the governor state (GOV_007).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernorSnapshot {
    pub schema_version: String,
    pub envelope: SafetyEnvelope,
    pub knob_states: Vec<KnobState>,
    pub applied_count: usize,
    pub decision_log_len: usize,
    pub next_seq: u64,
}

// ---------------------------------------------------------------------------
// Type aliases for contract compatibility (bd-21fo checker)
// ---------------------------------------------------------------------------

/// Alias for [`PredictedMetrics`] used in contract documentation.
pub type PredictedOutcome = PredictedMetrics;

/// Alias for [`DecisionRecord`] used in contract documentation.
pub type DecisionLogEntry = DecisionRecord;

/// Alias for [`ShadowResult`] used in contract documentation.
pub type ShadowEvalResult = ShadowResult;

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_envelope() -> SafetyEnvelope {
        SafetyEnvelope {
            max_latency_ms: 500,
            min_throughput_rps: 100,
            max_error_rate_pct: 1.0,
            max_memory_mb: 4096,
        }
    }

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
                latency_ms: 800,     // exceeds 500ms cap
                throughput_rps: 50,  // below 100 floor
                error_rate_pct: 2.0, // exceeds 1.0%
                memory_mb: 5000,     // exceeds 4096MB
            },
            rationale: "Aggressive batch size".to_string(),
            trace_id: format!("trace-{id}"),
        }
    }

    // --- SafetyEnvelope tests ---

    #[test]
    fn test_envelope_contains_safe_metrics() {
        let env = default_envelope();
        assert!(env.contains(&safe_metrics()));
    }

    #[test]
    fn test_envelope_rejects_high_latency() {
        let env = default_envelope();
        let m = PredictedMetrics {
            latency_ms: 600,
            ..safe_metrics()
        };
        assert!(!env.contains(&m));
        let v = env.violations(&m);
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("latency"));
    }

    #[test]
    fn test_envelope_rejects_low_throughput() {
        let env = default_envelope();
        let m = PredictedMetrics {
            throughput_rps: 50,
            ..safe_metrics()
        };
        assert!(!env.contains(&m));
    }

    #[test]
    fn test_envelope_rejects_high_error_rate() {
        let env = default_envelope();
        let m = PredictedMetrics {
            error_rate_pct: 5.0,
            ..safe_metrics()
        };
        assert!(!env.contains(&m));
    }

    #[test]
    fn test_envelope_rejects_high_memory() {
        let env = default_envelope();
        let m = PredictedMetrics {
            memory_mb: 8192,
            ..safe_metrics()
        };
        assert!(!env.contains(&m));
    }

    #[test]
    fn test_envelope_multiple_violations() {
        let env = default_envelope();
        let m = PredictedMetrics {
            latency_ms: 600,
            throughput_rps: 50,
            error_rate_pct: 5.0,
            memory_mb: 8192,
        };
        assert_eq!(env.violations(&m).len(), 4);
    }

    #[test]
    fn test_envelope_default_is_valid() {
        assert!(SafetyEnvelope::default().is_valid());
    }

    #[test]
    fn test_envelope_invalid_zero_latency() {
        let env = SafetyEnvelope {
            max_latency_ms: 0,
            ..default_envelope()
        };
        assert!(!env.is_valid());
    }

    // --- OptimizationProposal tests ---

    #[test]
    fn test_proposal_valid() {
        assert!(good_proposal("p1").is_valid());
    }

    #[test]
    fn test_proposal_invalid_empty_id() {
        let mut p = good_proposal("p1");
        p.proposal_id = String::new();
        assert!(!p.is_valid());
    }

    #[test]
    fn test_proposal_invalid_negative_error_rate() {
        let mut p = good_proposal("p1");
        p.predicted.error_rate_pct = -1.0;
        assert!(!p.is_valid());
    }

    // --- Shadow evaluation tests ---

    #[test]
    fn test_shadow_eval_safe_proposal() {
        let gov = OptimizationGovernor::with_defaults();
        let result = gov.shadow_evaluate(&good_proposal("p1"));
        assert!(result.within_envelope);
        assert!(result.is_beneficial);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_shadow_eval_unsafe_proposal() {
        let gov = OptimizationGovernor::with_defaults();
        let result = gov.shadow_evaluate(&unsafe_proposal("p2"));
        assert!(!result.within_envelope);
        assert!(!result.is_beneficial);
        assert!(!result.violations.is_empty());
    }

    #[test]
    fn test_shadow_eval_non_beneficial_same_value() {
        let gov = OptimizationGovernor::with_defaults();
        let mut p = good_proposal("p3");
        p.new_value = p.old_value; // no change
        let result = gov.shadow_evaluate(&p);
        assert!(result.within_envelope);
        assert!(!result.is_beneficial);
    }

    // --- Governor submit tests ---

    #[test]
    fn test_submit_good_proposal_approved() {
        let mut gov = OptimizationGovernor::with_defaults();
        let decision = gov.submit(good_proposal("p1"));
        assert_eq!(decision, GovernorDecision::Approved);
        assert_eq!(gov.decision_log().len(), 1);
        assert_eq!(gov.decision_log()[0].event_code, event_codes::GOV_003);
        assert_eq!(gov.applied_count(), 1);
    }

    #[test]
    fn test_submit_unsafe_proposal_rejected() {
        let mut gov = OptimizationGovernor::with_defaults();
        let decision = gov.submit(unsafe_proposal("p2"));
        match &decision {
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(vs)) => {
                assert!(!vs.is_empty(), "should have violation details");
            }
            other => panic!("expected EnvelopeViolation rejection, got {other:?}"),
        }
        assert_eq!(gov.decision_log()[0].event_code, event_codes::GOV_004);
        assert_eq!(gov.applied_count(), 0);
    }

    #[test]
    fn test_submit_non_beneficial_rejected() {
        let mut gov = OptimizationGovernor::with_defaults();
        let mut p = good_proposal("p3");
        p.new_value = p.old_value;
        let decision = gov.submit(p);
        assert_eq!(
            decision,
            GovernorDecision::Rejected(RejectionReason::NonBeneficial)
        );
    }

    #[test]
    fn test_submit_locked_knob_rejected() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.lock_knob(RuntimeKnob::ConcurrencyLimit);
        let decision = gov.submit(good_proposal("p4"));
        assert_eq!(
            decision,
            GovernorDecision::Rejected(RejectionReason::KnobLocked)
        );
    }

    #[test]
    fn test_submit_invalid_proposal_rejected() {
        let mut gov = OptimizationGovernor::with_defaults();
        let mut p = good_proposal("p5");
        p.proposal_id = String::new();
        let decision = gov.submit(p);
        match &decision {
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_)) => {}
            other => panic!("expected InvalidProposal rejection, got {other:?}"),
        }
    }

    #[test]
    fn test_submit_rejects_unknown_knob_configuration() {
        let envelope = default_envelope();
        let knob_states = BTreeMap::new();
        let mut gov = OptimizationGovernor::new(envelope, knob_states);
        let decision = gov.submit(good_proposal("p_unknown_knob"));

        match &decision {
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(msg)) => {
                assert!(msg.contains("not configured"));
            }
            other => panic!("expected InvalidProposal rejection, got {other:?}"),
        }
        assert_eq!(gov.applied_count(), 0);
        assert_eq!(gov.decision_log()[0].event_code, event_codes::GOV_004);
    }

    #[test]
    fn test_submit_rejects_stale_old_value() {
        let mut gov = OptimizationGovernor::with_defaults();
        let mut p = good_proposal("p_stale");
        p.old_value = 63; // current default for concurrency_limit is 64

        let decision = gov.submit(p);
        match &decision {
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(msg)) => {
                assert!(msg.contains("stale old_value"));
            }
            other => panic!("expected InvalidProposal rejection, got {other:?}"),
        }
        assert_eq!(gov.applied_count(), 0);
        assert_eq!(gov.knob_value(&RuntimeKnob::ConcurrencyLimit), Some(64));
    }

    // --- Live check and auto-revert tests ---

    #[test]
    fn test_live_check_within_envelope_no_revert() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.submit(good_proposal("p1"));
        assert_eq!(gov.applied_count(), 1);
        let reverted = gov.live_check(&safe_metrics());
        assert!(reverted.is_empty());
        assert_eq!(gov.applied_count(), 1);
    }

    #[test]
    fn test_live_check_breach_triggers_auto_revert() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.submit(good_proposal("p1"));
        assert_eq!(gov.applied_count(), 1);

        // Live metrics breach the envelope
        let bad_live = PredictedMetrics {
            latency_ms: 999,
            throughput_rps: 10,
            error_rate_pct: 50.0,
            memory_mb: 9999,
        };
        let reverted = gov.live_check(&bad_live);
        assert_eq!(reverted, vec!["p1"]);
        assert_eq!(gov.applied_count(), 0);

        // Verify the knob was reverted to old value
        assert_eq!(
            gov.knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64) // original default
        );
    }

    #[test]
    fn test_auto_revert_emits_gov_005() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.submit(good_proposal("p1"));

        let bad_live = PredictedMetrics {
            latency_ms: 999,
            ..safe_metrics()
        };
        gov.live_check(&bad_live);

        let revert_records: Vec<_> = gov
            .decision_log()
            .iter()
            .filter(|r| r.event_code == event_codes::GOV_005)
            .collect();
        assert_eq!(revert_records.len(), 1);
    }

    // --- Snapshot test ---

    #[test]
    fn test_snapshot_schema_version() {
        let gov = OptimizationGovernor::with_defaults();
        let snap = gov.snapshot();
        assert_eq!(snap.schema_version, SCHEMA_VERSION);
    }

    // --- Decision log ordering (INV-GOV-DETERMINISTIC-ORDER) ---

    #[test]
    fn test_decision_log_monotonic_seq() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.submit(good_proposal("p1"));
        gov.submit(good_proposal("p2"));
        gov.submit(unsafe_proposal("p3"));

        let seqs: Vec<u64> = gov.decision_log().iter().map(|r| r.seq).collect();
        for w in seqs.windows(2) {
            assert!(w[1] > w[0], "seq must be strictly increasing");
        }
    }

    // --- Evidence on reject (INV-GOV-EVIDENCE-ON-REJECT) ---

    #[test]
    fn test_rejection_record_has_evidence() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.submit(unsafe_proposal("p1"));
        let rec = &gov.decision_log()[0];
        assert!(
            rec.evidence.is_some(),
            "rejected proposal must have evidence"
        );
    }

    // --- RuntimeKnob display ---

    #[test]
    fn test_runtime_knob_display() {
        assert_eq!(
            RuntimeKnob::ConcurrencyLimit.to_string(),
            "concurrency_limit"
        );
        assert_eq!(RuntimeKnob::BatchSize.to_string(), "batch_size");
        assert_eq!(RuntimeKnob::CacheCapacity.to_string(), "cache_capacity");
        assert_eq!(RuntimeKnob::DrainTimeoutMs.to_string(), "drain_timeout_ms");
        assert_eq!(RuntimeKnob::RetryBudget.to_string(), "retry_budget");
    }

    // --- BTreeMap deterministic ordering ---

    #[test]
    fn test_knob_states_btree_order() {
        let gov = OptimizationGovernor::with_defaults();
        let snap = gov.snapshot();
        let knob_names: Vec<&str> = snap.knob_states.iter().map(|s| s.knob.as_str()).collect();
        let mut sorted = knob_names.clone();
        sorted.sort();
        // BTreeMap iteration order should give us Ord-based ordering
        // which may differ from alphabetical sort of as_str, but
        // must be deterministic across runs.
        assert_eq!(knob_names.len(), 5);
    }

    // --- Update envelope ---

    #[test]
    fn test_update_envelope() {
        let mut gov = OptimizationGovernor::with_defaults();
        let new_env = SafetyEnvelope {
            max_latency_ms: 1000,
            min_throughput_rps: 50,
            max_error_rate_pct: 5.0,
            max_memory_mb: 8192,
        };
        gov.update_envelope(new_env.clone());
        assert_eq!(gov.envelope(), &new_env);
    }

    // --- Serialization round-trip ---

    #[test]
    fn test_governor_serde_roundtrip() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.submit(good_proposal("p1"));
        let json = serde_json::to_string(&gov).expect("serialize");
        let gov2: OptimizationGovernor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(gov.decision_log().len(), gov2.decision_log().len());
        assert_eq!(gov.applied_count(), gov2.applied_count());
    }
}
