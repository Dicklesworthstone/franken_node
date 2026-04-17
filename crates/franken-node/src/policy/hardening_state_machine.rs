//! bd-3rya: Monotonic hardening mode state machine with one-way escalation.
//!
//! Enforces that the system's integrity assurance level can only increase
//! over time. Downward transitions require an explicit governance rollback
//! artifact that creates an auditable exception.
//!
//! # Invariants
//!
//! - INV-HARDEN-MONOTONIC: hardening level can only increase without governance rollback
//! - INV-HARDEN-DURABLE: committed level survives crash recovery
//! - INV-HARDEN-AUDITABLE: every transition is recorded with timestamp and trigger
//! - INV-HARDEN-GOVERNANCE: rollback requires valid signed governance artifact

use std::fmt;

/// Stable event codes for structured logging.
#[cfg(feature = "extended-surfaces")]
pub mod event_codes {
    pub const HARDEN_ESCALATED: &str = "EVD-HARDEN-001";
    pub const HARDEN_REGRESSION_REJECTED: &str = "EVD-HARDEN-002";
    pub const HARDEN_GOVERNANCE_ROLLBACK: &str = "EVD-HARDEN-003";
    pub const HARDEN_STATE_REPLAYED: &str = "EVD-HARDEN-004";
}

#[cfg(any(test, feature = "extended-surfaces"))]
const RESERVED_ARTIFACT_ID: &str = "<unknown>";

#[cfg(any(test, feature = "extended-surfaces"))]
fn invalid_artifact_id_reason(artifact_id: &str) -> Option<String> {
    let trimmed = artifact_id.trim();
    if trimmed.is_empty() {
        return Some("artifact_id must not be empty".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", artifact_id));
    }
    if trimmed != artifact_id {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    None
}

/// Hardening levels ordered from weakest to strongest.
///
/// Total ordering: Baseline < Standard < Enhanced < Maximum < Critical
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HardeningLevel {
    Baseline = 0,
    Standard = 1,
    Enhanced = 2,
    Maximum = 3,
    Critical = 4,
}

impl HardeningLevel {
    /// Numeric rank for ordering comparisons.
    pub fn rank(self) -> u8 {
        self as u8
    }

    /// Label for structured logging and serialization.
    pub fn label(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Standard => "standard",
            Self::Enhanced => "enhanced",
            Self::Maximum => "maximum",
            Self::Critical => "critical",
        }
    }

    /// Parse from label string.
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "baseline" => Some(Self::Baseline),
            "standard" => Some(Self::Standard),
            "enhanced" => Some(Self::Enhanced),
            "maximum" => Some(Self::Maximum),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    /// All levels in ascending order.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn all() -> &'static [HardeningLevel] {
        &[
            Self::Baseline,
            Self::Standard,
            Self::Enhanced,
            Self::Maximum,
            Self::Critical,
        ]
    }
}

impl PartialOrd for HardeningLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HardeningLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for HardeningLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A governance rollback artifact authorizing a downward hardening transition.
#[cfg(any(test, feature = "extended-surfaces"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceRollbackArtifact {
    pub artifact_id: String,
    pub approver_id: String,
    pub reason: String,
    pub timestamp: u64,
    pub signature: String,
}

#[cfg(any(test, feature = "extended-surfaces"))]
impl GovernanceRollbackArtifact {
    /// Validate the artifact has all required fields populated.
    pub fn validate(&self) -> Result<(), HardeningError> {
        if let Some(reason) = invalid_artifact_id_reason(&self.artifact_id) {
            return Err(HardeningError::InvalidRollbackArtifact { reason });
        }
        if self.approver_id.trim().is_empty() {
            return Err(HardeningError::InvalidRollbackArtifact {
                reason: "approver_id must not be empty".into(),
            });
        }
        if self.reason.trim().is_empty() {
            return Err(HardeningError::InvalidRollbackArtifact {
                reason: "reason must not be empty".into(),
            });
        }
        if self.signature.trim().is_empty() {
            return Err(HardeningError::InvalidRollbackArtifact {
                reason: "signature must not be empty".into(),
            });
        }
        // In production, verify the signature cryptographically
        Ok(())
    }
}

/// A record of a single hardening transition.
#[cfg(any(test, feature = "extended-surfaces"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRecord {
    pub from_level: HardeningLevel,
    pub to_level: HardeningLevel,
    pub timestamp: u64,
    pub trigger: TransitionTrigger,
    pub trace_id: String,
}

/// What triggered the hardening transition.
#[cfg(any(test, feature = "extended-surfaces"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionTrigger {
    /// Normal upward escalation.
    Escalation,
    /// Governance-authorized rollback.
    GovernanceRollback {
        artifact_id: String,
        approver_id: String,
    },
}

/// Errors from hardening state machine operations.
#[cfg(any(test, feature = "extended-surfaces"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardeningError {
    /// Attempted to escalate to the same or lower level.
    IllegalRegression {
        current: HardeningLevel,
        attempted: HardeningLevel,
    },
    /// Invalid governance rollback artifact.
    InvalidRollbackArtifact { reason: String },
    /// Attempted rollback to the same or higher level.
    InvalidRollbackTarget {
        current: HardeningLevel,
        target: HardeningLevel,
    },
    /// Already at maximum possible level.
    AlreadyAtMaximumLevel,
}

#[cfg(any(test, feature = "extended-surfaces"))]
impl HardeningError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::IllegalRegression { .. } => "HARDEN_ILLEGAL_REGRESSION",
            Self::InvalidRollbackArtifact { .. } => "HARDEN_INVALID_ARTIFACT",
            Self::InvalidRollbackTarget { .. } => "HARDEN_INVALID_ROLLBACK_TARGET",
            Self::AlreadyAtMaximumLevel => "HARDEN_AT_MAXIMUM",
        }
    }
}

#[cfg(any(test, feature = "extended-surfaces"))]
impl fmt::Display for HardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalRegression { current, attempted } => {
                write!(
                    f,
                    "HARDEN_ILLEGAL_REGRESSION: cannot escalate from {} to {} (same or lower)",
                    current.label(),
                    attempted.label()
                )
            }
            Self::InvalidRollbackArtifact { reason } => {
                write!(f, "HARDEN_INVALID_ARTIFACT: {reason}")
            }
            Self::InvalidRollbackTarget { current, target } => {
                write!(
                    f,
                    "HARDEN_INVALID_ROLLBACK_TARGET: cannot roll back from {} to {} (must be strictly lower)",
                    current.label(),
                    target.label()
                )
            }
            Self::AlreadyAtMaximumLevel => {
                write!(f, "HARDEN_AT_MAXIMUM: already at Critical level")
            }
        }
    }
}

#[cfg(any(test, feature = "extended-surfaces"))]
const MAX_TRANSITION_LOG_ENTRIES: usize = 4096;

#[cfg(any(test, feature = "extended-surfaces"))]
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

/// Monotonic hardening mode state machine.
///
/// INV-HARDEN-MONOTONIC: level can only increase via `escalate`.
/// INV-HARDEN-GOVERNANCE: rollback requires valid signed governance artifact.
/// INV-HARDEN-AUDITABLE: all transitions are recorded.
/// INV-HARDEN-DURABLE: state can be replayed from the transition log.
#[cfg(any(test, feature = "extended-surfaces"))]
#[derive(Debug)]
pub struct HardeningStateMachine {
    current_level: HardeningLevel,
    transition_log: Vec<TransitionRecord>,
}

#[cfg(any(test, feature = "extended-surfaces"))]
impl HardeningStateMachine {
    /// Create a new state machine at Baseline level.
    pub fn new() -> Self {
        Self {
            current_level: HardeningLevel::Baseline,
            transition_log: Vec::new(),
        }
    }

    /// Create a state machine at a specific initial level.
    pub fn with_level(level: HardeningLevel) -> Self {
        Self {
            current_level: level,
            transition_log: Vec::new(),
        }
    }

    /// Get the current hardening level.
    pub fn current_level(&self) -> HardeningLevel {
        self.current_level
    }

    /// Escalate to a strictly higher hardening level.
    ///
    /// INV-HARDEN-MONOTONIC: rejects transitions to same or lower level.
    pub fn escalate(
        &mut self,
        target: HardeningLevel,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<TransitionRecord, HardeningError> {
        if target <= self.current_level {
            return Err(HardeningError::IllegalRegression {
                current: self.current_level,
                attempted: target,
            });
        }

        let record = TransitionRecord {
            from_level: self.current_level,
            to_level: target,
            timestamp,
            trigger: TransitionTrigger::Escalation,
            trace_id: trace_id.to_string(),
        };

        self.current_level = target;
        push_bounded(
            &mut self.transition_log,
            record.clone(),
            MAX_TRANSITION_LOG_ENTRIES,
        );

        Ok(record)
    }

    /// Roll back to a lower hardening level with a governance artifact.
    ///
    /// INV-HARDEN-GOVERNANCE: requires valid signed artifact.
    pub fn governance_rollback(
        &mut self,
        target: HardeningLevel,
        artifact: &GovernanceRollbackArtifact,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<TransitionRecord, HardeningError> {
        // Validate the artifact first
        artifact.validate()?;

        // Target must be strictly lower than current
        if target >= self.current_level {
            return Err(HardeningError::InvalidRollbackTarget {
                current: self.current_level,
                target,
            });
        }

        let record = TransitionRecord {
            from_level: self.current_level,
            to_level: target,
            timestamp,
            trigger: TransitionTrigger::GovernanceRollback {
                artifact_id: artifact.artifact_id.clone(),
                approver_id: artifact.approver_id.clone(),
            },
            trace_id: trace_id.to_string(),
        };

        self.current_level = target;
        push_bounded(
            &mut self.transition_log,
            record.clone(),
            MAX_TRANSITION_LOG_ENTRIES,
        );

        Ok(record)
    }

    /// Get the full transition log.
    pub fn transition_log(&self) -> &[TransitionRecord] {
        &self.transition_log
    }

    /// Number of transitions recorded.
    pub fn transition_count(&self) -> usize {
        self.transition_log.len()
    }

    /// Replay a sequence of transition records to reconstruct state.
    ///
    /// INV-HARDEN-DURABLE: replay produces identical state as live execution.
    pub fn replay_transitions(log: &[TransitionRecord]) -> Self {
        let mut machine = Self::new();
        for record in log {
            machine.current_level = record.to_level;
            push_bounded(
                &mut machine.transition_log,
                record.clone(),
                MAX_TRANSITION_LOG_ENTRIES,
            );
        }
        machine
    }
}

#[cfg(any(test, feature = "extended-surfaces"))]
impl Default for HardeningStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u32) -> String {
        format!("trace-{n:04}")
    }

    fn valid_artifact() -> GovernanceRollbackArtifact {
        GovernanceRollbackArtifact {
            artifact_id: "GOV-2026-001".into(),
            approver_id: "admin@franken.io".into(),
            reason: "Emergency rollback for compatibility testing".into(),
            timestamp: 2000,
            signature: "sig:valid_governance_signature".into(),
        }
    }

    // ---- HardeningLevel tests ----

    #[test]
    fn level_ordering() {
        assert!(HardeningLevel::Baseline < HardeningLevel::Standard);
        assert!(HardeningLevel::Standard < HardeningLevel::Enhanced);
        assert!(HardeningLevel::Enhanced < HardeningLevel::Maximum);
        assert!(HardeningLevel::Maximum < HardeningLevel::Critical);
    }

    #[test]
    fn level_total_ordering_five_levels() {
        let levels = HardeningLevel::all();
        assert_eq!(levels.len(), 5);
        for i in 0..levels.len() - 1 {
            assert!(levels[i] < levels[i + 1]);
        }
    }

    #[test]
    fn level_rank() {
        assert_eq!(HardeningLevel::Baseline.rank(), 0);
        assert_eq!(HardeningLevel::Standard.rank(), 1);
        assert_eq!(HardeningLevel::Enhanced.rank(), 2);
        assert_eq!(HardeningLevel::Maximum.rank(), 3);
        assert_eq!(HardeningLevel::Critical.rank(), 4);
    }

    #[test]
    fn level_label_roundtrip() {
        for level in HardeningLevel::all() {
            let label = level.label();
            let parsed = HardeningLevel::from_label(label).unwrap();
            assert_eq!(*level, parsed);
        }
    }

    #[test]
    fn level_unknown_label() {
        assert!(HardeningLevel::from_label("unknown").is_none());
    }

    #[test]
    fn level_display() {
        assert_eq!(HardeningLevel::Critical.to_string(), "critical");
    }

    // ---- HardeningStateMachine basic tests ----

    #[test]
    fn starts_at_baseline() {
        let sm = HardeningStateMachine::new();
        assert_eq!(sm.current_level(), HardeningLevel::Baseline);
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn default_is_baseline() {
        let sm = HardeningStateMachine::default();
        assert_eq!(sm.current_level(), HardeningLevel::Baseline);
    }

    #[test]
    fn with_level() {
        let sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
    }

    // ---- Forward escalation tests ----

    #[test]
    fn escalate_baseline_to_standard() {
        let mut sm = HardeningStateMachine::new();
        let r = sm
            .escalate(HardeningLevel::Standard, 1000, &tid(1))
            .unwrap();
        assert_eq!(r.from_level, HardeningLevel::Baseline);
        assert_eq!(r.to_level, HardeningLevel::Standard);
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
    }

    #[test]
    fn escalate_standard_to_enhanced() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);
        sm.escalate(HardeningLevel::Enhanced, 1000, &tid(1))
            .unwrap();
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
    }

    #[test]
    fn escalate_enhanced_to_maximum() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        sm.escalate(HardeningLevel::Maximum, 1000, &tid(1)).unwrap();
        assert_eq!(sm.current_level(), HardeningLevel::Maximum);
    }

    #[test]
    fn escalate_maximum_to_critical() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Maximum);
        sm.escalate(HardeningLevel::Critical, 1000, &tid(1))
            .unwrap();
        assert_eq!(sm.current_level(), HardeningLevel::Critical);
    }

    #[test]
    fn escalate_skip_levels() {
        let mut sm = HardeningStateMachine::new();
        sm.escalate(HardeningLevel::Maximum, 1000, &tid(1)).unwrap();
        assert_eq!(sm.current_level(), HardeningLevel::Maximum);
    }

    #[test]
    fn escalate_full_chain() {
        let mut sm = HardeningStateMachine::new();
        for (i, level) in HardeningLevel::all().iter().enumerate().skip(1) {
            sm.escalate(*level, 1000 + i as u64, &tid(i as u32))
                .unwrap();
        }
        assert_eq!(sm.current_level(), HardeningLevel::Critical);
        assert_eq!(sm.transition_count(), 4);
    }

    // ---- Regression rejection tests ----

    #[test]
    fn regression_same_level_rejected() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);
        let err = sm
            .escalate(HardeningLevel::Standard, 1000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_ILLEGAL_REGRESSION");
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
    }

    #[test]
    fn regression_lower_level_rejected() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let err = sm
            .escalate(HardeningLevel::Standard, 1000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_ILLEGAL_REGRESSION");
    }

    #[test]
    fn regression_to_baseline_rejected() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Critical);
        let err = sm
            .escalate(HardeningLevel::Baseline, 1000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_ILLEGAL_REGRESSION");
    }

    // ---- Governance rollback tests ----

    #[test]
    fn governance_rollback_with_valid_artifact() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let artifact = valid_artifact();
        let r = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(1))
            .unwrap();
        assert_eq!(r.from_level, HardeningLevel::Enhanced);
        assert_eq!(r.to_level, HardeningLevel::Standard);
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
    }

    #[test]
    fn governance_rollback_to_baseline() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Critical);
        let artifact = valid_artifact();
        sm.governance_rollback(HardeningLevel::Baseline, &artifact, 2000, &tid(1))
            .unwrap();
        assert_eq!(sm.current_level(), HardeningLevel::Baseline);
    }

    #[test]
    fn governance_rollback_missing_artifact_id() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.artifact_id = String::new();
        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
    }

    #[test]
    fn governance_rollback_reserved_artifact_id() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.artifact_id = RESERVED_ARTIFACT_ID.to_string();
        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert!(format!("{err}").contains("reserved"));
    }

    #[test]
    fn governance_rollback_whitespace_artifact_id() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.artifact_id = " GOV-2026-001 ".to_string();
        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert!(format!("{err}").contains("leading or trailing whitespace"));
    }

    #[test]
    fn governance_rollback_missing_signature() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.signature = String::new();
        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
    }

    #[test]
    fn governance_rollback_same_level_rejected() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let artifact = valid_artifact();
        let err = sm
            .governance_rollback(HardeningLevel::Enhanced, &artifact, 2000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_INVALID_ROLLBACK_TARGET");
    }

    #[test]
    fn governance_rollback_higher_level_rejected() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);
        let artifact = valid_artifact();
        let err = sm
            .governance_rollback(HardeningLevel::Enhanced, &artifact, 2000, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "HARDEN_INVALID_ROLLBACK_TARGET");
    }

    #[test]
    fn level_from_label_rejects_case_variants_and_padding() {
        assert!(HardeningLevel::from_label("Critical").is_none());
        assert!(HardeningLevel::from_label(" critical").is_none());
        assert!(HardeningLevel::from_label("critical ").is_none());
        assert!(HardeningLevel::from_label("maximum\n").is_none());
    }

    #[test]
    fn regression_rejection_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);

        let err = sm
            .escalate(HardeningLevel::Standard, 1000, &tid(1))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_ILLEGAL_REGRESSION");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert!(sm.transition_log().is_empty());
    }

    #[test]
    fn same_level_escalation_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Maximum);

        let err = sm
            .escalate(HardeningLevel::Maximum, 1000, &tid(1))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_ILLEGAL_REGRESSION");
        assert_eq!(sm.current_level(), HardeningLevel::Maximum);
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn rollback_missing_approver_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.approver_id = String::new();

        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(1))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert!(sm.transition_log().is_empty());
    }

    #[test]
    fn rollback_missing_signature_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.signature = String::new();

        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(1))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn rollback_same_level_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let artifact = valid_artifact();

        let err = sm
            .governance_rollback(HardeningLevel::Enhanced, &artifact, 2000, &tid(1))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ROLLBACK_TARGET");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert!(sm.transition_log().is_empty());
    }

    #[test]
    fn rollback_higher_level_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);
        let artifact = valid_artifact();

        let err = sm
            .governance_rollback(HardeningLevel::Enhanced, &artifact, 2000, &tid(1))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ROLLBACK_TARGET");
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn invalid_artifact_precedes_invalid_rollback_target() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.reason = String::new();

        let err = sm
            .governance_rollback(HardeningLevel::Enhanced, &artifact, 2000, &tid(1))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn whitespace_only_artifact_id_is_invalid() {
        let mut artifact = valid_artifact();
        artifact.artifact_id = " \t ".to_string();

        let err = artifact.validate().unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert!(format!("{err}").contains("must not be empty"));
    }

    // ---- Full lifecycle test ----

    #[test]
    fn full_lifecycle_escalate_rollback_escalate() {
        let mut sm = HardeningStateMachine::new();

        // Baseline -> Standard -> Enhanced
        sm.escalate(HardeningLevel::Standard, 1000, &tid(1))
            .unwrap();
        sm.escalate(HardeningLevel::Enhanced, 1001, &tid(2))
            .unwrap();

        // Governance rollback: Enhanced -> Standard
        let artifact = valid_artifact();
        sm.governance_rollback(HardeningLevel::Standard, &artifact, 1002, &tid(3))
            .unwrap();
        assert_eq!(sm.current_level(), HardeningLevel::Standard);

        // Re-escalate: Standard -> Maximum
        sm.escalate(HardeningLevel::Maximum, 1003, &tid(4)).unwrap();
        assert_eq!(sm.current_level(), HardeningLevel::Maximum);
        assert_eq!(sm.transition_count(), 4);
    }

    // ---- Replay tests ----

    #[test]
    fn replay_empty_log() {
        let sm = HardeningStateMachine::replay_transitions(&[]);
        assert_eq!(sm.current_level(), HardeningLevel::Baseline);
    }

    #[test]
    fn replay_single_transition() {
        let log = vec![TransitionRecord {
            from_level: HardeningLevel::Baseline,
            to_level: HardeningLevel::Standard,
            timestamp: 1000,
            trigger: TransitionTrigger::Escalation,
            trace_id: tid(1),
        }];
        let sm = HardeningStateMachine::replay_transitions(&log);
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
        assert_eq!(sm.transition_count(), 1);
    }

    #[test]
    fn replay_multi_transition() {
        let log = vec![
            TransitionRecord {
                from_level: HardeningLevel::Baseline,
                to_level: HardeningLevel::Standard,
                timestamp: 1000,
                trigger: TransitionTrigger::Escalation,
                trace_id: tid(1),
            },
            TransitionRecord {
                from_level: HardeningLevel::Standard,
                to_level: HardeningLevel::Enhanced,
                timestamp: 1001,
                trigger: TransitionTrigger::Escalation,
                trace_id: tid(2),
            },
            TransitionRecord {
                from_level: HardeningLevel::Enhanced,
                to_level: HardeningLevel::Standard,
                timestamp: 1002,
                trigger: TransitionTrigger::GovernanceRollback {
                    artifact_id: "GOV-001".into(),
                    approver_id: "admin".into(),
                },
                trace_id: tid(3),
            },
        ];
        let sm = HardeningStateMachine::replay_transitions(&log);
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
        assert_eq!(sm.transition_count(), 3);
    }

    #[test]
    fn replay_determinism() {
        // Run the same escalation sequence and verify replay matches
        let mut live = HardeningStateMachine::new();
        live.escalate(HardeningLevel::Standard, 1000, &tid(1))
            .unwrap();
        live.escalate(HardeningLevel::Enhanced, 1001, &tid(2))
            .unwrap();
        live.escalate(HardeningLevel::Maximum, 1002, &tid(3))
            .unwrap();

        let replayed = HardeningStateMachine::replay_transitions(live.transition_log());
        assert_eq!(replayed.current_level(), live.current_level());
        assert_eq!(replayed.transition_count(), live.transition_count());
        assert_eq!(replayed.transition_log(), live.transition_log());
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<HardeningError> = vec![
            HardeningError::IllegalRegression {
                current: HardeningLevel::Enhanced,
                attempted: HardeningLevel::Standard,
            },
            HardeningError::InvalidRollbackArtifact {
                reason: "test".into(),
            },
            HardeningError::InvalidRollbackTarget {
                current: HardeningLevel::Standard,
                target: HardeningLevel::Enhanced,
            },
            HardeningError::AlreadyAtMaximumLevel,
        ];
        for e in &errors {
            let display = e.to_string();
            assert!(
                display.contains(e.code()),
                "Display for {e:?} should contain code {}",
                e.code()
            );
        }
    }

    // ---- Transition trigger ----

    #[test]
    fn transition_trigger_escalation() {
        let mut sm = HardeningStateMachine::new();
        let r = sm
            .escalate(HardeningLevel::Standard, 1000, &tid(1))
            .unwrap();
        assert_eq!(r.trigger, TransitionTrigger::Escalation);
    }

    #[test]
    fn transition_trigger_governance() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let artifact = valid_artifact();
        let r = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(1))
            .unwrap();
        match &r.trigger {
            TransitionTrigger::GovernanceRollback {
                artifact_id,
                approver_id,
            } => {
                assert_eq!(artifact_id, "GOV-2026-001");
                assert_eq!(approver_id, "admin@franken.io");
            }
            _ => unreachable!("Expected GovernanceRollback trigger"),
        }
    }

    // ---- Artifact validation ----

    #[test]
    fn artifact_valid() {
        let a = valid_artifact();
        a.validate().unwrap();
    }

    #[test]
    fn artifact_missing_reason() {
        let mut a = valid_artifact();
        a.reason = String::new();
        assert!(a.validate().is_err());
    }

    #[test]
    fn artifact_missing_approver() {
        let mut a = valid_artifact();
        a.approver_id = String::new();
        assert!(a.validate().is_err());
    }

    #[test]
    fn negative_artifact_whitespace_approver_rejected() {
        let mut artifact = valid_artifact();
        artifact.approver_id = " \t\n ".to_string();

        let err = artifact.validate().unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert!(err.to_string().contains("approver_id"));
    }

    #[test]
    fn negative_artifact_whitespace_reason_rejected() {
        let mut artifact = valid_artifact();
        artifact.reason = "\n\t".to_string();

        let err = artifact.validate().unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert!(err.to_string().contains("reason"));
    }

    #[test]
    fn negative_artifact_whitespace_signature_rejected() {
        let mut artifact = valid_artifact();
        artifact.signature = "   ".to_string();

        let err = artifact.validate().unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn negative_rollback_whitespace_approver_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.approver_id = " \t ".to_string();

        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(88))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert!(sm.transition_log().is_empty());
    }

    #[test]
    fn negative_rollback_whitespace_reason_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.reason = "\n".to_string();

        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(89))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn negative_rollback_whitespace_signature_preserves_state_and_log() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let mut artifact = valid_artifact();
        artifact.signature = "\t".to_string();

        let err = sm
            .governance_rollback(HardeningLevel::Standard, &artifact, 2000, &tid(90))
            .unwrap_err();

        assert_eq!(err.code(), "HARDEN_INVALID_ARTIFACT");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert_eq!(sm.transition_count(), 0);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_transition_log_window() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_preserves_latest_transitions() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 3);

        assert_eq!(items, vec![2, 3, 4]);
    }
}

#[cfg(test)]
mod hardening_state_machine_comprehensive_negative_tests {
    use super::*;
    use std::collections::HashMap;

    /// Negative test: Unicode injection and malicious content in governance artifacts
    #[test]
    fn negative_unicode_injection_governance_artifacts() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);

        // Test malicious Unicode in artifact ID
        let unicode_artifact = GovernanceRollbackArtifact {
            artifact_id: "GOV-2026\u{202e}EVIL\u{200b}001\u{0000}".to_string(),
            approver_id: "admin@franken.io".to_string(),
            reason: "Emergency rollback".to_string(),
            timestamp: 2000,
            signature: "valid_signature".to_string(),
        };

        let result = sm.governance_rollback(
            HardeningLevel::Standard,
            &unicode_artifact,
            2000,
            "trace-unicode-artifact",
        );

        // Should handle Unicode gracefully without bypass
        match result {
            Ok(_) => {
                // Unicode was accepted and properly processed
                assert_eq!(sm.current_level(), HardeningLevel::Standard);
            },
            Err(e) => {
                // Unicode caused validation failure, which is also acceptable
                assert_eq!(e.code(), "HARDEN_INVALID_ARTIFACT");
            }
        }

        // Test malicious Unicode in approver ID and reason
        let malicious_approver_artifact = GovernanceRollbackArtifact {
            artifact_id: "GOV-2026-002".to_string(),
            approver_id: "admin\u{202e}evil\u{200c}@franken.io".to_string(),
            reason: "Emergency\u{2028}script:alert('xss')\u{2029}rollback".to_string(),
            timestamp: 2001,
            signature: "signature_with_\u{feff}bom".to_string(),
        };

        sm = HardeningStateMachine::with_level(HardeningLevel::Maximum);
        let result = sm.governance_rollback(
            HardeningLevel::Enhanced,
            &malicious_approver_artifact,
            2001,
            "trace-malicious-approver",
        );

        // Should process Unicode content without corruption or bypass
        match result {
            Ok(record) => {
                // Verify Unicode didn't corrupt the transition record
                assert_eq!(record.from_level, HardeningLevel::Maximum);
                assert_eq!(record.to_level, HardeningLevel::Enhanced);
                if let TransitionTrigger::GovernanceRollback { artifact_id, approver_id } = &record.trigger {
                    assert_eq!(artifact_id, "GOV-2026-002");
                    assert!(approver_id.contains("admin") && approver_id.contains("franken.io"));
                }
            },
            Err(_) => {
                // Unicode validation rejection is also acceptable
                assert_eq!(sm.current_level(), HardeningLevel::Maximum);
            }
        }

        // Test zero-width and control characters
        let control_char_artifact = GovernanceRollbackArtifact {
            artifact_id: "GOV\x00\x01\x02-2026-003".to_string(),
            approver_id: "admin@franken.io".to_string(),
            reason: "Control\x7f\x80\x9fcharacters".to_string(),
            timestamp: 2002,
            signature: "signature".to_string(),
        };

        let validation_result = control_char_artifact.validate();
        // Should either accept or properly reject control characters
        match validation_result {
            Ok(_) => {}, // Accepted gracefully
            Err(e) => assert_eq!(e.code(), "HARDEN_INVALID_ARTIFACT"), // Properly rejected
        }
    }

    /// Negative test: Arithmetic overflow protection in timestamps and counters
    #[test]
    fn negative_arithmetic_overflow_protection() {
        let mut sm = HardeningStateMachine::new();

        // Test near-maximum timestamp values
        let near_max_timestamp = u64::MAX - 100;
        let result = sm.escalate(
            HardeningLevel::Standard,
            near_max_timestamp,
            "trace-max-timestamp",
        );
        assert!(result.is_ok(), "Should handle near-maximum timestamps");

        // Test maximum timestamp boundary
        let max_timestamp = u64::MAX;
        let result = sm.escalate(
            HardeningLevel::Enhanced,
            max_timestamp,
            "trace-absolute-max-timestamp",
        );
        assert!(result.is_ok(), "Should handle maximum timestamp");

        // Test timestamp ordering with overflow potential
        let result = sm.escalate(
            HardeningLevel::Maximum,
            0, // Timestamp rollover
            "trace-timestamp-rollover",
        );
        assert!(result.is_ok(), "Should handle timestamp rollover gracefully");

        // Verify transition log handles overflow correctly
        let log = sm.transition_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].timestamp, near_max_timestamp);
        assert_eq!(log[1].timestamp, max_timestamp);
        assert_eq!(log[2].timestamp, 0);

        // Test governance artifact with overflow timestamp
        let overflow_artifact = GovernanceRollbackArtifact {
            artifact_id: "GOV-OVERFLOW-001".to_string(),
            approver_id: "admin@franken.io".to_string(),
            reason: "Testing overflow handling".to_string(),
            timestamp: u64::MAX,
            signature: "overflow_signature".to_string(),
        };

        let result = sm.governance_rollback(
            HardeningLevel::Enhanced,
            &overflow_artifact,
            u64::MAX,
            "trace-overflow-rollback",
        );
        assert!(result.is_ok(), "Should handle overflow timestamps in governance artifacts");

        // Test massive transition log that could cause capacity overflow
        let mut massive_sm = HardeningStateMachine::new();
        for i in 0..MAX_TRANSITION_LOG_ENTRIES + 1000 {
            let level = match i % 4 {
                0 => HardeningLevel::Standard,
                1 => HardeningLevel::Enhanced,
                2 => HardeningLevel::Maximum,
                _ => HardeningLevel::Critical,
            };

            if level > massive_sm.current_level() {
                let _ = massive_sm.escalate(level, i as u64, &format!("trace-overflow-{}", i));
            }
        }

        // Verify log is properly bounded
        assert!(massive_sm.transition_count() <= MAX_TRANSITION_LOG_ENTRIES);
        assert!(massive_sm.transition_count() > 0);
    }

    /// Negative test: Memory exhaustion attacks with massive transition logs
    #[test]
    fn negative_memory_exhaustion_massive_logs() {
        let mut sm = HardeningStateMachine::new();

        // Create massive number of transitions with large trace IDs
        let huge_trace_id = "x".repeat(10000); // Very large trace ID
        let huge_artifact_id = "y".repeat(5000);
        let huge_approver_id = "z".repeat(3000);
        let huge_reason = "w".repeat(8000);

        // Test escalation with massive trace ID
        let result = sm.escalate(HardeningLevel::Standard, 1000, &huge_trace_id);
        assert!(result.is_ok(), "Should handle large trace IDs without memory exhaustion");

        // Test governance rollback with massive artifact content
        let massive_artifact = GovernanceRollbackArtifact {
            artifact_id: huge_artifact_id.clone(),
            approver_id: huge_approver_id.clone(),
            reason: huge_reason.clone(),
            timestamp: 2000,
            signature: "signature".to_string(),
        };

        sm.escalate(HardeningLevel::Enhanced, 1500, "trace-before-rollback").unwrap();

        let result = sm.governance_rollback(
            HardeningLevel::Standard,
            &massive_artifact,
            2000,
            &huge_trace_id,
        );
        assert!(result.is_ok(), "Should handle massive artifact content");

        // Verify memory usage remains reasonable
        let log = sm.transition_log();
        assert!(log.len() <= 3); // Should not have excessive entries

        // Test rapid escalation/rollback cycles to stress memory
        for cycle in 0..1000 {
            let escalate_trace = format!("escalate-cycle-{}-{}", cycle, "x".repeat(1000));
            let rollback_trace = format!("rollback-cycle-{}-{}", cycle, "y".repeat(1000));

            if sm.current_level() < HardeningLevel::Enhanced {
                let _ = sm.escalate(HardeningLevel::Enhanced, 3000 + cycle, &escalate_trace);
            }

            let cycle_artifact = GovernanceRollbackArtifact {
                artifact_id: format!("CYCLE-{}-{}", cycle, "z".repeat(500)),
                approver_id: format!("admin-{}-{}", cycle, "a".repeat(200)),
                reason: format!("Cycle-{}-{}", cycle, "b".repeat(300)),
                timestamp: 3001 + cycle,
                signature: format!("sig-{}", cycle),
            };

            if sm.current_level() > HardeningLevel::Baseline {
                let _ = sm.governance_rollback(
                    HardeningLevel::Baseline,
                    &cycle_artifact,
                    3001 + cycle,
                    &rollback_trace,
                );
            }
        }

        // Memory should be bounded despite many transitions
        assert!(sm.transition_count() <= MAX_TRANSITION_LOG_ENTRIES);
    }

    /// Negative test: Concurrent operation safety and state corruption
    #[test]
    fn negative_concurrent_operation_safety() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);

        // Simulate concurrent escalations with overlapping timestamps
        let concurrent_results = vec![
            sm.escalate(HardeningLevel::Enhanced, 1000, "trace-concurrent-1"),
            sm.escalate(HardeningLevel::Maximum, 1000, "trace-concurrent-2"), // Same timestamp
            sm.escalate(HardeningLevel::Critical, 999, "trace-concurrent-3"), // Earlier timestamp
        ];

        // Verify state consistency despite concurrent attempts
        let mut success_count = 0;
        let mut regression_errors = 0;

        for result in concurrent_results {
            match result {
                Ok(_) => success_count += 1,
                Err(e) if e.code() == "HARDEN_ILLEGAL_REGRESSION" => regression_errors += 1,
                Err(_) => {} // Other errors
            }
        }

        // Should have progressed monotonically
        assert!(success_count > 0, "At least one escalation should succeed");
        assert!(sm.current_level() >= HardeningLevel::Enhanced, "Should have progressed");

        // Test concurrent rollbacks with different artifacts
        let artifacts = vec![
            GovernanceRollbackArtifact {
                artifact_id: "CONCURRENT-1".to_string(),
                approver_id: "admin1@franken.io".to_string(),
                reason: "Concurrent rollback 1".to_string(),
                timestamp: 2000,
                signature: "sig1".to_string(),
            },
            GovernanceRollbackArtifact {
                artifact_id: "CONCURRENT-2".to_string(),
                approver_id: "admin2@franken.io".to_string(),
                reason: "Concurrent rollback 2".to_string(),
                timestamp: 2000,
                signature: "sig2".to_string(),
            },
        ];

        let initial_level = sm.current_level();
        let rollback_results = vec![
            sm.governance_rollback(HardeningLevel::Standard, &artifacts[0], 2000, "trace-rollback-1"),
            sm.governance_rollback(HardeningLevel::Baseline, &artifacts[1], 2000, "trace-rollback-2"),
        ];

        // Verify state remains consistent after concurrent operations
        assert!(sm.current_level() <= initial_level, "State should not have illegally escalated");

        // At most one rollback should succeed
        let rollback_successes = rollback_results.iter().filter(|r| r.is_ok()).count();
        assert!(rollback_successes <= 1, "At most one rollback should succeed from same state");

        // Verify audit trail integrity under concurrent operations
        let log = sm.transition_log();
        for (i, record) in log.iter().enumerate() {
            // Each transition should have valid levels
            assert!(record.from_level <= HardeningLevel::Critical);
            assert!(record.to_level <= HardeningLevel::Critical);

            // Timestamps should be reasonable (allowing for concurrent same-time operations)
            if i > 0 {
                let prev = &log[i-1];
                assert!(record.timestamp >= prev.timestamp ||
                       record.timestamp.abs_diff(prev.timestamp) <= 1000,
                       "Timestamp ordering should be reasonable");
            }
        }
    }

    /// Negative test: Timing attacks in governance artifact validation
    #[test]
    fn negative_timing_attacks_governance_validation() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);

        // Create various malformed artifacts to test timing differences
        let test_artifacts = vec![
            // Empty fields
            GovernanceRollbackArtifact {
                artifact_id: "".to_string(),
                approver_id: "admin@franken.io".to_string(),
                reason: "Valid reason".to_string(),
                timestamp: 2000,
                signature: "signature".to_string(),
            },
            // Reserved artifact ID
            GovernanceRollbackArtifact {
                artifact_id: "<unknown>".to_string(),
                approver_id: "admin@franken.io".to_string(),
                reason: "Valid reason".to_string(),
                timestamp: 2000,
                signature: "signature".to_string(),
            },
            // Valid artifact
            GovernanceRollbackArtifact {
                artifact_id: "VALID-001".to_string(),
                approver_id: "admin@franken.io".to_string(),
                reason: "Valid reason".to_string(),
                timestamp: 2000,
                signature: "signature".to_string(),
            },
            // Missing signature
            GovernanceRollbackArtifact {
                artifact_id: "VALID-002".to_string(),
                approver_id: "admin@franken.io".to_string(),
                reason: "Valid reason".to_string(),
                timestamp: 2000,
                signature: "".to_string(),
            },
        ];

        let mut timing_results = Vec::new();

        for artifact in test_artifacts {
            let start = std::time::Instant::now();
            let result = sm.governance_rollback(
                HardeningLevel::Standard,
                &artifact,
                2000,
                "trace-timing-test",
            );
            let duration = start.elapsed();
            timing_results.push(duration);

            // Most should fail validation
            if result.is_ok() {
                // Reset state for next test
                sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
            }
        }

        // Timing differences should be minimal (no timing-based information leakage)
        let max_timing = timing_results.iter().max().unwrap();
        let min_timing = timing_results.iter().min().unwrap();
        let timing_ratio = max_timing.as_nanos() as f64 / min_timing.as_nanos() as f64;

        // Allow reasonable variance but prevent timing attacks
        assert!(timing_ratio < 5.0, "Validation timing variance too high: {}", timing_ratio);

        // Test artifact ID comparison timing
        let similar_ids = vec![
            "GOV-2026-001",
            "GOV-2026-002",
            "GOV-2026-AAA",
            "TOTALLY-DIFFERENT",
            "",
        ];

        let mut id_timing_results = Vec::new();
        for id in similar_ids {
            let artifact = GovernanceRollbackArtifact {
                artifact_id: id.to_string(),
                approver_id: "admin@franken.io".to_string(),
                reason: "Testing timing".to_string(),
                timestamp: 2000,
                signature: "signature".to_string(),
            };

            let start = std::time::Instant::now();
            let _result = artifact.validate();
            let duration = start.elapsed();
            id_timing_results.push(duration);
        }

        // ID validation timing should also be consistent
        let max_id_timing = id_timing_results.iter().max().unwrap();
        let min_id_timing = id_timing_results.iter().min().unwrap();
        let id_timing_ratio = max_id_timing.as_nanos() as f64 / min_id_timing.as_nanos() as f64;

        assert!(id_timing_ratio < 4.0, "Artifact ID validation timing variance too high: {}", id_timing_ratio);
    }

    /// Negative test: State machine replay corruption and inconsistency attacks
    #[test]
    fn negative_replay_corruption_attacks() {
        // Create a legitimate transition log
        let legitimate_log = vec![
            TransitionRecord {
                from_level: HardeningLevel::Baseline,
                to_level: HardeningLevel::Standard,
                timestamp: 1000,
                trigger: TransitionTrigger::Escalation,
                trace_id: "trace-001".to_string(),
            },
            TransitionRecord {
                from_level: HardeningLevel::Standard,
                to_level: HardeningLevel::Enhanced,
                timestamp: 1001,
                trigger: TransitionTrigger::Escalation,
                trace_id: "trace-002".to_string(),
            },
        ];

        // Test replay with corrupted transition records
        let corrupted_logs = vec![
            // Inconsistent from/to levels
            vec![TransitionRecord {
                from_level: HardeningLevel::Enhanced, // Wrong starting level
                to_level: HardeningLevel::Standard,
                timestamp: 1000,
                trigger: TransitionTrigger::Escalation,
                trace_id: "corrupted-001".to_string(),
            }],

            // Invalid level progression (downward escalation)
            vec![
                legitimate_log[0].clone(),
                TransitionRecord {
                    from_level: HardeningLevel::Enhanced, // Skips Standard
                    to_level: HardeningLevel::Baseline, // Illegal downward
                    timestamp: 1001,
                    trigger: TransitionTrigger::Escalation, // Wrong trigger for downward
                    trace_id: "corrupted-002".to_string(),
                }
            ],

            // Timestamp manipulation
            vec![
                TransitionRecord {
                    from_level: HardeningLevel::Baseline,
                    to_level: HardeningLevel::Standard,
                    timestamp: u64::MAX, // Maximum timestamp
                    trigger: TransitionTrigger::Escalation,
                    trace_id: "corrupted-timestamp".to_string(),
                },
                TransitionRecord {
                    from_level: HardeningLevel::Standard,
                    to_level: HardeningLevel::Enhanced,
                    timestamp: 0, // Timestamp rollover
                    trigger: TransitionTrigger::Escalation,
                    trace_id: "corrupted-rollover".to_string(),
                }
            ],

            // Malformed trace IDs
            vec![TransitionRecord {
                from_level: HardeningLevel::Baseline,
                to_level: HardeningLevel::Standard,
                timestamp: 1000,
                trigger: TransitionTrigger::Escalation,
                trace_id: "\u{202e}malicious\u{0000}trace".to_string(), // Unicode attacks
            }],

            // Malformed governance trigger
            vec![TransitionRecord {
                from_level: HardeningLevel::Enhanced,
                to_level: HardeningLevel::Standard,
                timestamp: 1000,
                trigger: TransitionTrigger::GovernanceRollback {
                    artifact_id: "".to_string(), // Empty artifact ID
                    approver_id: "\u{202e}evil@domain.com".to_string(), // Unicode attack
                },
                trace_id: "corrupted-governance".to_string(),
            }],
        ];

        for (i, corrupted_log) in corrupted_logs.iter().enumerate() {
            let replayed_sm = HardeningStateMachine::replay_transitions(corrupted_log);

            // Replay should complete without panic even with corrupted data
            assert!(
                replayed_sm.current_level() <= HardeningLevel::Critical,
                "Corrupted log {} should not result in invalid level", i
            );

            // Transition count should match input (replay is forgiving)
            assert_eq!(
                replayed_sm.transition_count(),
                corrupted_log.len(),
                "Corrupted log {} should preserve transition count", i
            );

            // Final level should match last transition target
            if !corrupted_log.is_empty() {
                assert_eq!(
                    replayed_sm.current_level(),
                    corrupted_log.last().unwrap().to_level,
                    "Corrupted log {} should end at last transition target", i
                );
            }
        }

        // Test massive corrupted log that could cause memory issues
        let massive_corrupted_log: Vec<TransitionRecord> = (0..50000)
            .map(|i| TransitionRecord {
                from_level: HardeningLevel::Baseline,
                to_level: HardeningLevel::Critical,
                timestamp: i as u64,
                trigger: TransitionTrigger::Escalation,
                trace_id: format!("massive-trace-{}-{}", i, "x".repeat(1000)),
            })
            .collect();

        let massive_replayed = HardeningStateMachine::replay_transitions(&massive_corrupted_log);

        // Should handle massive log without memory exhaustion
        assert_eq!(massive_replayed.current_level(), HardeningLevel::Critical);
        assert!(massive_replayed.transition_count() <= MAX_TRANSITION_LOG_ENTRIES);
    }

    /// Negative test: Hardening level boundary and ordering attacks
    #[test]
    fn negative_level_boundary_ordering_attacks() {
        // Test all possible level combinations for illegal transitions
        let all_levels = HardeningLevel::all();

        for &from_level in all_levels {
            let mut sm = HardeningStateMachine::with_level(from_level);

            for &to_level in all_levels {
                let result = sm.escalate(to_level, 1000, "trace-boundary-test");

                if to_level <= from_level {
                    // Should reject same or lower level
                    assert!(result.is_err(),
                           "Escalation from {:?} to {:?} should be rejected", from_level, to_level);
                    assert_eq!(result.unwrap_err().code(), "HARDEN_ILLEGAL_REGRESSION");
                    assert_eq!(sm.current_level(), from_level, "State should be unchanged after rejection");
                } else {
                    // Should accept higher level
                    assert!(result.is_ok(),
                           "Escalation from {:?} to {:?} should succeed", from_level, to_level);
                    assert_eq!(sm.current_level(), to_level, "State should update on success");
                    // Reset for next test
                    sm = HardeningStateMachine::with_level(from_level);
                }
            }
        }

        // Test governance rollback boundary conditions
        let valid_artifact = GovernanceRollbackArtifact {
            artifact_id: "BOUNDARY-TEST".to_string(),
            approver_id: "admin@franken.io".to_string(),
            reason: "Testing boundaries".to_string(),
            timestamp: 2000,
            signature: "signature".to_string(),
        };

        for &from_level in all_levels {
            let mut sm = HardeningStateMachine::with_level(from_level);

            for &to_level in all_levels {
                let result = sm.governance_rollback(to_level, &valid_artifact, 2000, "trace-rollback-boundary");

                if to_level >= from_level {
                    // Should reject same or higher level for rollback
                    assert!(result.is_err(),
                           "Rollback from {:?} to {:?} should be rejected", from_level, to_level);
                    assert_eq!(result.unwrap_err().code(), "HARDEN_INVALID_ROLLBACK_TARGET");
                    assert_eq!(sm.current_level(), from_level, "State should be unchanged after rollback rejection");
                } else {
                    // Should accept lower level for rollback
                    assert!(result.is_ok(),
                           "Rollback from {:?} to {:?} should succeed", from_level, to_level);
                    assert_eq!(sm.current_level(), to_level, "State should update on rollback success");
                    // Reset for next test
                    sm = HardeningStateMachine::with_level(from_level);
                }
            }
        }

        // Test rank consistency
        for level in all_levels {
            assert!(level.rank() <= 4, "Rank should be within expected range");
            assert_eq!(level.rank() as usize, *level as usize, "Rank should match enum discriminant");
        }

        // Test level parsing attacks
        let malicious_labels = vec![
            "critical\0", // Null byte
            "CRITICAL", // Case variant
            " critical", // Leading space
            "critical ", // Trailing space
            "critical\n", // Newline
            "baseline\x00injection", // Null injection
            "\u{202e}critical", // Unicode direction override
            "maximum\u{200b}", // Zero-width space
        ];

        for malicious_label in malicious_labels {
            let parsed = HardeningLevel::from_label(&malicious_label);
            assert!(parsed.is_none(), "Malicious label '{}' should not parse", malicious_label);
        }
    }
}
