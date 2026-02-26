//! bd-1vsr: Transition abort semantics on timeout/cancellation.
//!
//! Defines the abort semantics for epoch transition barriers: when a barrier
//! times out or receives a cancellation signal, all participants revert to the
//! current epoch and no partial transition state is left. An explicit
//! `ForceTransitionPolicy` allows scoped override for exceptional cases.
//!
//! # Invariants
//!
//! - INV-ABORT-NO-PARTIAL: after abort, system is in exactly the pre-transition epoch
//! - INV-ABORT-ALL-NOTIFIED: all participants receive abort notification
//! - INV-ABORT-FORCE-EXPLICIT: force policy must be explicitly constructed (no default)
//! - INV-ABORT-FORCE-SCOPED: force policy names specific skippable participants
//! - INV-ABORT-FORCE-AUDITED: every force override is logged with operator identity
//! - INV-ABORT-FORCE-BOUNDED: skipped participants cannot exceed max_skippable

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Schema version for abort event records.
pub const SCHEMA_VERSION: &str = "ta-v1.0";

// ---- Event codes ----

pub mod event_codes {
    pub const TRANSITION_ABORTED: &str = "TRANSITION_ABORTED";
    pub const FORCE_TRANSITION_APPLIED: &str = "FORCE_TRANSITION_APPLIED";
    pub const TRANSITION_ABORT_REJECTED: &str = "TRANSITION_ABORT_REJECTED";
    pub const ABORT_PARTICIPANT_NOTIFIED: &str = "ABORT_PARTICIPANT_NOTIFIED";
    pub const FORCE_POLICY_VALIDATED: &str = "FORCE_POLICY_VALIDATED";
    pub const FORCE_POLICY_REJECTED: &str = "FORCE_POLICY_REJECTED";
    pub const ABORT_EPOCH_CONFIRMED: &str = "ABORT_EPOCH_CONFIRMED";
    pub const FORCE_EPOCH_ADVANCED: &str = "FORCE_EPOCH_ADVANCED";
    pub const ABORT_EVENT_PERSISTED: &str = "ABORT_EVENT_PERSISTED";
    pub const ABORT_RETRY_ALLOWED: &str = "ABORT_RETRY_ALLOWED";
}

// ---- Error codes ----

pub mod error_codes {
    pub const ERR_ABORT_NO_BARRIER: &str = "ERR_ABORT_NO_BARRIER";
    pub const ERR_FORCE_NO_OPERATOR: &str = "ERR_FORCE_NO_OPERATOR";
    pub const ERR_FORCE_NO_REASON: &str = "ERR_FORCE_NO_REASON";
    pub const ERR_FORCE_OVER_LIMIT: &str = "ERR_FORCE_OVER_LIMIT";
    pub const ERR_FORCE_UNKNOWN_PARTICIPANT: &str = "ERR_FORCE_UNKNOWN_PARTICIPANT";
    pub const ERR_ABORT_ALREADY_TERMINAL: &str = "ERR_ABORT_ALREADY_TERMINAL";
    pub const ERR_FORCE_ALL_SKIPPED: &str = "ERR_FORCE_ALL_SKIPPED";
    pub const ERR_ABORT_INVALID_EPOCH: &str = "ERR_ABORT_INVALID_EPOCH";
}

// ---- Abort reason ----

/// Why a transition was aborted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionAbortReason {
    /// Barrier timed out waiting for drain ACKs.
    Timeout { elapsed_ms: u64 },
    /// Explicit cancellation by operator or system.
    Cancellation { source: String },
    /// A participant failed during drain.
    ParticipantFailure {
        participant_id: String,
        detail: String,
    },
}

impl fmt::Display for TransitionAbortReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout { elapsed_ms } => write!(f, "timeout after {}ms", elapsed_ms),
            Self::Cancellation { source } => write!(f, "cancelled by {}", source),
            Self::ParticipantFailure {
                participant_id,
                detail,
            } => {
                write!(f, "participant {} failed: {}", participant_id, detail)
            }
        }
    }
}

// ---- Participant state at abort time ----

/// Snapshot of a participant's state at abort time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantAbortState {
    pub participant_id: String,
    pub had_acked: bool,
    pub current_epoch: u64,
    pub in_flight_items: u64,
}

// ---- TransitionAbortEvent ----

/// Event recording a transition abort with full context.
/// INV-ABORT-NO-PARTIAL: records that system remains at pre_epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionAbortEvent {
    pub barrier_id: String,
    pub reason: TransitionAbortReason,
    pub pre_epoch: u64,
    pub proposed_epoch: u64,
    pub participant_states: Vec<ParticipantAbortState>,
    pub elapsed_ms: u64,
    pub timestamp_ms: u64,
    pub trace_id: String,
    pub schema_version: String,
}

impl TransitionAbortEvent {
    /// Create a new abort event.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        barrier_id: &str,
        reason: TransitionAbortReason,
        pre_epoch: u64,
        proposed_epoch: u64,
        participant_states: Vec<ParticipantAbortState>,
        elapsed_ms: u64,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Self {
        Self {
            barrier_id: barrier_id.to_string(),
            reason,
            pre_epoch,
            proposed_epoch,
            participant_states,
            elapsed_ms,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Verify that all participants are at the pre-transition epoch.
    /// INV-ABORT-NO-PARTIAL
    pub fn verify_no_partial_state(&self) -> bool {
        !self.participant_states.is_empty()
            && self
                .participant_states
                .iter()
                .all(|p| p.current_epoch == self.pre_epoch)
    }

    /// Export as JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// ---- ForceTransitionPolicy ----

/// Explicit, scoped override policy for forcing a transition despite participant
/// failures. INV-ABORT-FORCE-EXPLICIT: must be explicitly constructed.
/// INV-ABORT-FORCE-SCOPED: names specific skippable participants.
/// INV-ABORT-FORCE-AUDITED: includes operator identity and audit reason.
/// INV-ABORT-FORCE-BOUNDED: skipped count bounded by max_skippable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForceTransitionPolicy {
    /// Which participants may be skipped during forced transition.
    pub skippable_participants: BTreeSet<String>,
    /// Maximum number of participants that may be skipped.
    pub max_skippable: usize,
    /// Operator identity authorizing the force transition.
    pub operator_id: String,
    /// Audit reason explaining why force is necessary.
    pub audit_reason: String,
}

impl ForceTransitionPolicy {
    /// Construct a new force policy.
    /// INV-ABORT-FORCE-EXPLICIT: no Default impl.
    pub fn new(
        skippable_participants: BTreeSet<String>,
        max_skippable: usize,
        operator_id: &str,
        audit_reason: &str,
    ) -> Self {
        Self {
            skippable_participants,
            max_skippable,
            operator_id: operator_id.to_string(),
            audit_reason: audit_reason.to_string(),
        }
    }

    /// Compute a deterministic hash of the policy for audit logging.
    pub fn policy_hash(&self) -> String {
        use sha2::Digest;
        let canonical = format!(
            "force_policy|{}|{}|{}|{}",
            self.skippable_participants
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
            self.max_skippable,
            self.operator_id,
            self.audit_reason,
        );
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"transition_abort_policy_v1:");
        sha2::Digest::update(&mut hasher, canonical.as_bytes());
        format!("policy:{:x}", sha2::Digest::finalize(hasher))
    }
}

/// Errors from abort/force operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbortError {
    /// No active barrier to abort.
    NoBarrier,
    /// Force policy missing operator identity.
    NoOperator,
    /// Force policy missing audit reason.
    NoReason,
    /// Force policy skips more participants than allowed.
    OverLimit { skipped: usize, max: usize },
    /// Force policy references unknown participants.
    UnknownParticipant { participant_id: String },
    /// Barrier already in terminal state.
    AlreadyTerminal { barrier_id: String },
    /// Force policy would skip ALL participants (meaningless).
    AllSkipped { total: usize },
    /// Epoch mismatch.
    InvalidEpoch { expected: u64, actual: u64 },
}

impl AbortError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoBarrier => error_codes::ERR_ABORT_NO_BARRIER,
            Self::NoOperator => error_codes::ERR_FORCE_NO_OPERATOR,
            Self::NoReason => error_codes::ERR_FORCE_NO_REASON,
            Self::OverLimit { .. } => error_codes::ERR_FORCE_OVER_LIMIT,
            Self::UnknownParticipant { .. } => error_codes::ERR_FORCE_UNKNOWN_PARTICIPANT,
            Self::AlreadyTerminal { .. } => error_codes::ERR_ABORT_ALREADY_TERMINAL,
            Self::AllSkipped { .. } => error_codes::ERR_FORCE_ALL_SKIPPED,
            Self::InvalidEpoch { .. } => error_codes::ERR_ABORT_INVALID_EPOCH,
        }
    }
}

impl fmt::Display for AbortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBarrier => write!(f, "{}: no active barrier", self.code()),
            Self::NoOperator => write!(f, "{}: force policy missing operator_id", self.code()),
            Self::NoReason => write!(f, "{}: force policy missing audit_reason", self.code()),
            Self::OverLimit { skipped, max } => {
                write!(
                    f,
                    "{}: skipped {} exceeds max {}",
                    self.code(),
                    skipped,
                    max
                )
            }
            Self::UnknownParticipant { participant_id } => {
                write!(f, "{}: unknown participant {}", self.code(), participant_id)
            }
            Self::AlreadyTerminal { barrier_id } => {
                write!(
                    f,
                    "{}: barrier {} already terminal",
                    self.code(),
                    barrier_id
                )
            }
            Self::AllSkipped { total } => {
                write!(f, "{}: cannot skip all {} participants", self.code(), total)
            }
            Self::InvalidEpoch { expected, actual } => {
                write!(
                    f,
                    "{}: expected epoch {} but got {}",
                    self.code(),
                    expected,
                    actual
                )
            }
        }
    }
}

/// Event record for force transition application.
/// INV-ABORT-FORCE-AUDITED
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForceTransitionEvent {
    pub barrier_id: String,
    pub policy_hash: String,
    pub operator_id: String,
    pub skipped_participants: Vec<String>,
    pub audit_reason: String,
    pub pre_epoch: u64,
    pub target_epoch: u64,
    pub timestamp_ms: u64,
    pub trace_id: String,
    pub schema_version: String,
}

/// Audit record for JSONL export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortAuditRecord {
    pub event_code: String,
    pub barrier_id: String,
    pub pre_epoch: u64,
    pub proposed_epoch: u64,
    pub outcome: String,
    pub reason: String,
    pub timestamp_ms: u64,
    pub trace_id: String,
    pub schema_version: String,
}

/// Manages transition abort semantics atop EpochTransitionBarrier.
pub struct TransitionAbortManager {
    /// Recorded abort events.
    abort_events: Vec<TransitionAbortEvent>,
    /// Recorded force transition events.
    force_events: Vec<ForceTransitionEvent>,
    /// Audit log.
    audit_log: Vec<AbortAuditRecord>,
}

impl TransitionAbortManager {
    pub fn new() -> Self {
        Self {
            abort_events: Vec::new(),
            force_events: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Validate a force transition policy against known participants.
    /// INV-ABORT-FORCE-BOUNDED, INV-ABORT-FORCE-SCOPED
    pub fn validate_force_policy(
        &self,
        policy: &ForceTransitionPolicy,
        known_participants: &BTreeSet<String>,
    ) -> Result<(), AbortError> {
        // INV-ABORT-FORCE-EXPLICIT: no default — caller must construct
        if policy.operator_id.is_empty() {
            return Err(AbortError::NoOperator);
        }
        if policy.audit_reason.is_empty() {
            return Err(AbortError::NoReason);
        }

        // INV-ABORT-FORCE-BOUNDED
        if policy.skippable_participants.len() > policy.max_skippable {
            return Err(AbortError::OverLimit {
                skipped: policy.skippable_participants.len(),
                max: policy.max_skippable,
            });
        }

        // Cannot skip ALL participants
        if !known_participants.is_empty()
            && policy.skippable_participants.len() >= known_participants.len()
        {
            return Err(AbortError::AllSkipped {
                total: known_participants.len(),
            });
        }

        // INV-ABORT-FORCE-SCOPED: all named participants must be known
        for pid in &policy.skippable_participants {
            if !known_participants.contains(pid) {
                return Err(AbortError::UnknownParticipant {
                    participant_id: pid.clone(),
                });
            }
        }

        Ok(())
    }

    /// Record a standard abort (no force policy).
    /// INV-ABORT-NO-PARTIAL, INV-ABORT-ALL-NOTIFIED
    #[allow(clippy::too_many_arguments)]
    pub fn record_abort(
        &mut self,
        barrier_id: &str,
        reason: TransitionAbortReason,
        pre_epoch: u64,
        proposed_epoch: u64,
        participant_states: Vec<ParticipantAbortState>,
        elapsed_ms: u64,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> TransitionAbortEvent {
        let event = TransitionAbortEvent::new(
            barrier_id,
            reason.clone(),
            pre_epoch,
            proposed_epoch,
            participant_states,
            elapsed_ms,
            timestamp_ms,
            trace_id,
        );

        self.audit_log.push(AbortAuditRecord {
            event_code: event_codes::TRANSITION_ABORTED.to_string(),
            barrier_id: barrier_id.to_string(),
            pre_epoch,
            proposed_epoch,
            outcome: "ABORTED".to_string(),
            reason: reason.to_string(),
            timestamp_ms,
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.abort_events.push(event.clone());
        event
    }

    /// Record a force transition application.
    /// INV-ABORT-FORCE-AUDITED
    #[allow(clippy::too_many_arguments)]
    pub fn record_force_transition(
        &mut self,
        barrier_id: &str,
        policy: &ForceTransitionPolicy,
        actually_skipped: &[String],
        pre_epoch: u64,
        target_epoch: u64,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> ForceTransitionEvent {
        let event = ForceTransitionEvent {
            barrier_id: barrier_id.to_string(),
            policy_hash: policy.policy_hash(),
            operator_id: policy.operator_id.clone(),
            skipped_participants: actually_skipped.to_vec(),
            audit_reason: policy.audit_reason.clone(),
            pre_epoch,
            target_epoch,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        self.audit_log.push(AbortAuditRecord {
            event_code: event_codes::FORCE_TRANSITION_APPLIED.to_string(),
            barrier_id: barrier_id.to_string(),
            pre_epoch,
            proposed_epoch: target_epoch,
            outcome: "FORCE_COMMITTED".to_string(),
            reason: format!(
                "operator={}, reason={}",
                policy.operator_id, policy.audit_reason
            ),
            timestamp_ms,
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.force_events.push(event.clone());
        event
    }

    /// Get all recorded abort events.
    pub fn abort_events(&self) -> &[TransitionAbortEvent] {
        &self.abort_events
    }

    /// Get all recorded force transition events.
    pub fn force_events(&self) -> &[ForceTransitionEvent] {
        &self.force_events
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[AbortAuditRecord] {
        &self.audit_log
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Total abort count.
    pub fn abort_count(&self) -> usize {
        self.abort_events.len()
    }

    /// Total force transition count.
    pub fn force_count(&self) -> usize {
        self.force_events.len()
    }
}

impl Default for TransitionAbortManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participants_3() -> BTreeSet<String> {
        ["svc-a", "svc-b", "svc-c"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn make_states(epoch: u64, acked: &[&str], all: &[&str]) -> Vec<ParticipantAbortState> {
        all.iter()
            .map(|pid| ParticipantAbortState {
                participant_id: pid.to_string(),
                had_acked: acked.contains(pid),
                current_epoch: epoch,
                in_flight_items: if acked.contains(pid) { 0 } else { 5 },
            })
            .collect()
    }

    // ---- TransitionAbortEvent ----

    #[test]
    fn abort_event_creation() {
        let event = TransitionAbortEvent::new(
            "barrier-001",
            TransitionAbortReason::Timeout { elapsed_ms: 5000 },
            5,
            6,
            make_states(5, &["svc-a"], &["svc-a", "svc-b", "svc-c"]),
            5000,
            10000,
            "t1",
        );
        assert_eq!(event.barrier_id, "barrier-001");
        assert_eq!(event.pre_epoch, 5);
        assert_eq!(event.proposed_epoch, 6);
        assert_eq!(event.participant_states.len(), 3);
        assert_eq!(event.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn abort_event_verify_no_partial_state_passes() {
        let event = TransitionAbortEvent::new(
            "b1",
            TransitionAbortReason::Cancellation {
                source: "test".into(),
            },
            5,
            6,
            make_states(5, &[], &["svc-a", "svc-b"]),
            1000,
            2000,
            "t1",
        );
        assert!(event.verify_no_partial_state());
    }

    #[test]
    fn abort_event_verify_no_partial_state_fails_on_mixed() {
        let mut states = make_states(5, &[], &["svc-a", "svc-b"]);
        states[1].current_epoch = 6; // partial state!
        let event = TransitionAbortEvent::new(
            "b1",
            TransitionAbortReason::Timeout { elapsed_ms: 1000 },
            5,
            6,
            states,
            1000,
            2000,
            "t1",
        );
        assert!(!event.verify_no_partial_state());
    }

    #[test]
    fn abort_event_to_json() {
        let event = TransitionAbortEvent::new(
            "b1",
            TransitionAbortReason::Timeout { elapsed_ms: 1000 },
            0,
            1,
            vec![],
            1000,
            2000,
            "t1",
        );
        let json = event.to_json();
        assert!(json.contains("barrier_id"));
        assert!(json.contains("ta-v1.0"));
    }

    // ---- Abort reason display ----

    #[test]
    fn abort_reason_display_variants() {
        let reasons = vec![
            TransitionAbortReason::Timeout { elapsed_ms: 5000 },
            TransitionAbortReason::Cancellation {
                source: "operator".into(),
            },
            TransitionAbortReason::ParticipantFailure {
                participant_id: "svc-a".into(),
                detail: "connection refused".into(),
            },
        ];
        for r in &reasons {
            assert!(!r.to_string().is_empty());
        }
    }

    // ---- ForceTransitionPolicy ----

    #[test]
    fn force_policy_construction() {
        let mut skip = BTreeSet::new();
        skip.insert("svc-c".to_string());
        let policy = ForceTransitionPolicy::new(skip, 1, "admin@acme.com", "DR failover");
        assert_eq!(policy.operator_id, "admin@acme.com");
        assert_eq!(policy.max_skippable, 1);
        assert_eq!(policy.skippable_participants.len(), 1);
    }

    #[test]
    fn force_policy_hash_deterministic() {
        let mut skip = BTreeSet::new();
        skip.insert("svc-c".to_string());
        let p1 = ForceTransitionPolicy::new(skip.clone(), 1, "op", "reason");
        let p2 = ForceTransitionPolicy::new(skip, 1, "op", "reason");
        assert_eq!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn force_policy_hash_differs_on_change() {
        let mut skip = BTreeSet::new();
        skip.insert("svc-c".to_string());
        let p1 = ForceTransitionPolicy::new(skip.clone(), 1, "op1", "reason");
        let p2 = ForceTransitionPolicy::new(skip, 1, "op2", "reason");
        assert_ne!(p1.policy_hash(), p2.policy_hash());
    }

    // ---- Validate force policy ----

    #[test]
    fn validate_valid_force_policy() {
        let mgr = TransitionAbortManager::new();
        let known = participants_3();
        let mut skip = BTreeSet::new();
        skip.insert("svc-c".to_string());
        let policy = ForceTransitionPolicy::new(skip, 1, "admin", "DR test");
        assert!(mgr.validate_force_policy(&policy, &known).is_ok());
    }

    #[test]
    fn validate_rejects_empty_operator() {
        let mgr = TransitionAbortManager::new();
        let known = participants_3();
        let policy = ForceTransitionPolicy::new(BTreeSet::new(), 0, "", "reason");
        let err = mgr.validate_force_policy(&policy, &known).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_FORCE_NO_OPERATOR);
    }

    #[test]
    fn validate_rejects_empty_reason() {
        let mgr = TransitionAbortManager::new();
        let known = participants_3();
        let policy = ForceTransitionPolicy::new(BTreeSet::new(), 0, "admin", "");
        let err = mgr.validate_force_policy(&policy, &known).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_FORCE_NO_REASON);
    }

    #[test]
    fn validate_rejects_over_limit() {
        let mgr = TransitionAbortManager::new();
        let known = participants_3();
        let mut skip = BTreeSet::new();
        skip.insert("svc-a".to_string());
        skip.insert("svc-b".to_string());
        let policy = ForceTransitionPolicy::new(skip, 1, "admin", "reason");
        let err = mgr.validate_force_policy(&policy, &known).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_FORCE_OVER_LIMIT);
    }

    #[test]
    fn validate_rejects_all_skipped() {
        let mgr = TransitionAbortManager::new();
        let known = participants_3();
        let policy = ForceTransitionPolicy::new(known.clone(), 3, "admin", "reason");
        let err = mgr.validate_force_policy(&policy, &known).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_FORCE_ALL_SKIPPED);
    }

    #[test]
    fn validate_rejects_unknown_participant() {
        let mgr = TransitionAbortManager::new();
        let known = participants_3();
        let mut skip = BTreeSet::new();
        skip.insert("unknown-svc".to_string());
        let policy = ForceTransitionPolicy::new(skip, 1, "admin", "reason");
        let err = mgr.validate_force_policy(&policy, &known).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_FORCE_UNKNOWN_PARTICIPANT);
    }

    // ---- TransitionAbortManager ----

    #[test]
    fn record_abort_returns_event() {
        let mut mgr = TransitionAbortManager::new();
        let event = mgr.record_abort(
            "barrier-001",
            TransitionAbortReason::Timeout { elapsed_ms: 5000 },
            5,
            6,
            make_states(5, &["svc-a"], &["svc-a", "svc-b", "svc-c"]),
            5000,
            10000,
            "t1",
        );
        assert_eq!(event.barrier_id, "barrier-001");
        assert_eq!(mgr.abort_count(), 1);
        assert_eq!(mgr.audit_log().len(), 1);
        assert_eq!(
            mgr.audit_log()[0].event_code,
            event_codes::TRANSITION_ABORTED
        );
    }

    #[test]
    fn record_force_transition_returns_event() {
        let mut mgr = TransitionAbortManager::new();
        let mut skip = BTreeSet::new();
        skip.insert("svc-c".to_string());
        let policy = ForceTransitionPolicy::new(skip, 1, "admin", "DR failover");
        let event = mgr.record_force_transition(
            "barrier-002",
            &policy,
            &["svc-c".to_string()],
            5,
            6,
            10000,
            "t2",
        );
        assert_eq!(event.barrier_id, "barrier-002");
        assert_eq!(event.operator_id, "admin");
        assert!(!event.policy_hash.is_empty());
        assert_eq!(mgr.force_count(), 1);
        assert_eq!(mgr.audit_log().len(), 1);
        assert_eq!(
            mgr.audit_log()[0].event_code,
            event_codes::FORCE_TRANSITION_APPLIED
        );
    }

    #[test]
    fn audit_log_tracks_both_abort_and_force() {
        let mut mgr = TransitionAbortManager::new();
        mgr.record_abort(
            "b1",
            TransitionAbortReason::Cancellation {
                source: "test".into(),
            },
            5,
            6,
            vec![],
            1000,
            2000,
            "t1",
        );
        let policy = ForceTransitionPolicy::new(BTreeSet::new(), 0, "admin", "reason");
        mgr.record_force_transition("b2", &policy, &[], 6, 7, 3000, "t2");

        assert_eq!(mgr.audit_log().len(), 2);
        assert_eq!(mgr.audit_log()[0].outcome, "ABORTED");
        assert_eq!(mgr.audit_log()[1].outcome, "FORCE_COMMITTED");
    }

    #[test]
    fn export_audit_log_jsonl() {
        let mut mgr = TransitionAbortManager::new();
        mgr.record_abort(
            "b1",
            TransitionAbortReason::Timeout { elapsed_ms: 1000 },
            0,
            1,
            vec![],
            1000,
            2000,
            "t1",
        );
        let jsonl = mgr.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::TRANSITION_ABORTED);
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<AbortError> = vec![
            AbortError::NoBarrier,
            AbortError::NoOperator,
            AbortError::NoReason,
            AbortError::OverLimit { skipped: 3, max: 1 },
            AbortError::UnknownParticipant {
                participant_id: "x".into(),
            },
            AbortError::AlreadyTerminal {
                barrier_id: "b".into(),
            },
            AbortError::AllSkipped { total: 3 },
            AbortError::InvalidEpoch {
                expected: 5,
                actual: 3,
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(s.contains(e.code()), "{:?} should contain {}", e, e.code());
        }
    }

    // ---- Default trait ----

    #[test]
    fn default_manager() {
        let mgr = TransitionAbortManager::default();
        assert_eq!(mgr.abort_count(), 0);
        assert_eq!(mgr.force_count(), 0);
        assert!(mgr.audit_log().is_empty());
    }

    // ---- Multiple aborts ----

    #[test]
    fn multiple_aborts_tracked() {
        let mut mgr = TransitionAbortManager::new();
        for i in 0..5 {
            mgr.record_abort(
                &format!("b-{i}"),
                TransitionAbortReason::Timeout { elapsed_ms: 1000 },
                i,
                i + 1,
                vec![],
                1000,
                2000 + i * 100,
                &format!("t{i}"),
            );
        }
        assert_eq!(mgr.abort_count(), 5);
        assert_eq!(mgr.abort_events().len(), 5);
    }

    // ---- Force event schema version ----

    #[test]
    fn force_event_has_schema_version() {
        let mut mgr = TransitionAbortManager::new();
        let policy = ForceTransitionPolicy::new(BTreeSet::new(), 0, "admin", "reason");
        let event = mgr.record_force_transition("b1", &policy, &[], 0, 1, 1000, "t1");
        assert_eq!(event.schema_version, SCHEMA_VERSION);
    }

    // ---- Participant abort state ----

    #[test]
    fn participant_abort_state_fields() {
        let state = ParticipantAbortState {
            participant_id: "svc-a".to_string(),
            had_acked: true,
            current_epoch: 5,
            in_flight_items: 0,
        };
        assert_eq!(state.participant_id, "svc-a");
        assert!(state.had_acked);
        assert_eq!(state.current_epoch, 5);
        assert_eq!(state.in_flight_items, 0);
    }

    #[test]
    fn verify_no_partial_state_empty_participants_returns_false() {
        let event = TransitionAbortEvent::new(
            "b-empty",
            TransitionAbortReason::Cancellation {
                source: "test".into(),
            },
            5,
            6,
            vec![], // empty participants
            1000,
            2000,
            "t-empty",
        );
        assert!(
            !event.verify_no_partial_state(),
            "empty participant list must not pass verification (vacuous truth guard)"
        );
    }
}
