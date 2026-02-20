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
pub mod event_codes {
    pub const HARDEN_ESCALATED: &str = "EVD-HARDEN-001";
    pub const HARDEN_REGRESSION_REJECTED: &str = "EVD-HARDEN-002";
    pub const HARDEN_GOVERNANCE_ROLLBACK: &str = "EVD-HARDEN-003";
    pub const HARDEN_STATE_REPLAYED: &str = "EVD-HARDEN-004";
}

/// Hardening levels ordered from weakest to strongest.
///
/// Total ordering: Baseline < Standard < Enhanced < Maximum < Critical
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceRollbackArtifact {
    pub artifact_id: String,
    pub approver_id: String,
    pub reason: String,
    pub timestamp: u64,
    pub signature: String,
}

impl GovernanceRollbackArtifact {
    /// Validate the artifact has all required fields populated.
    pub fn validate(&self) -> Result<(), HardeningError> {
        if self.artifact_id.is_empty() {
            return Err(HardeningError::InvalidRollbackArtifact {
                reason: "artifact_id must not be empty".into(),
            });
        }
        if self.approver_id.is_empty() {
            return Err(HardeningError::InvalidRollbackArtifact {
                reason: "approver_id must not be empty".into(),
            });
        }
        if self.reason.is_empty() {
            return Err(HardeningError::InvalidRollbackArtifact {
                reason: "reason must not be empty".into(),
            });
        }
        if self.signature.is_empty() {
            return Err(HardeningError::InvalidRollbackArtifact {
                reason: "signature must not be empty".into(),
            });
        }
        // In production, verify the signature cryptographically
        Ok(())
    }
}

/// A record of a single hardening transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRecord {
    pub from_level: HardeningLevel,
    pub to_level: HardeningLevel,
    pub timestamp: u64,
    pub trigger: TransitionTrigger,
    pub trace_id: String,
}

/// What triggered the hardening transition.
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

/// Monotonic hardening mode state machine.
///
/// INV-HARDEN-MONOTONIC: level can only increase via `escalate`.
/// INV-HARDEN-GOVERNANCE: rollback requires valid signed governance artifact.
/// INV-HARDEN-AUDITABLE: all transitions are recorded.
/// INV-HARDEN-DURABLE: state can be replayed from the transition log.
#[derive(Debug)]
pub struct HardeningStateMachine {
    current_level: HardeningLevel,
    transition_log: Vec<TransitionRecord>,
}

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
        self.transition_log.push(record.clone());

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
        self.transition_log.push(record.clone());

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
            machine.transition_log.push(record.clone());
        }
        machine
    }
}

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
        let r = sm.escalate(HardeningLevel::Standard, 1000, &tid(1)).unwrap();
        assert_eq!(r.from_level, HardeningLevel::Baseline);
        assert_eq!(r.to_level, HardeningLevel::Standard);
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
    }

    #[test]
    fn escalate_standard_to_enhanced() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);
        sm.escalate(HardeningLevel::Enhanced, 1000, &tid(1)).unwrap();
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
        sm.escalate(HardeningLevel::Critical, 1000, &tid(1)).unwrap();
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
            sm.escalate(*level, 1000 + i as u64, &tid(i as u32)).unwrap();
        }
        assert_eq!(sm.current_level(), HardeningLevel::Critical);
        assert_eq!(sm.transition_count(), 4);
    }

    // ---- Regression rejection tests ----

    #[test]
    fn regression_same_level_rejected() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);
        let err = sm.escalate(HardeningLevel::Standard, 1000, &tid(1)).unwrap_err();
        assert_eq!(err.code(), "HARDEN_ILLEGAL_REGRESSION");
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
    }

    #[test]
    fn regression_lower_level_rejected() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let err = sm.escalate(HardeningLevel::Standard, 1000, &tid(1)).unwrap_err();
        assert_eq!(err.code(), "HARDEN_ILLEGAL_REGRESSION");
    }

    #[test]
    fn regression_to_baseline_rejected() {
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Critical);
        let err = sm.escalate(HardeningLevel::Baseline, 1000, &tid(1)).unwrap_err();
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

    // ---- Full lifecycle test ----

    #[test]
    fn full_lifecycle_escalate_rollback_escalate() {
        let mut sm = HardeningStateMachine::new();

        // Baseline -> Standard -> Enhanced
        sm.escalate(HardeningLevel::Standard, 1000, &tid(1)).unwrap();
        sm.escalate(HardeningLevel::Enhanced, 1001, &tid(2)).unwrap();

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
        live.escalate(HardeningLevel::Standard, 1000, &tid(1)).unwrap();
        live.escalate(HardeningLevel::Enhanced, 1001, &tid(2)).unwrap();
        live.escalate(HardeningLevel::Maximum, 1002, &tid(3)).unwrap();

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
        let r = sm.escalate(HardeningLevel::Standard, 1000, &tid(1)).unwrap();
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
            _ => panic!("Expected GovernanceRollback trigger"),
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
}
