//! bd-oolt: Mandatory evidence emission for policy-driven control actions.
//!
//! Every policy-driven control decision (commit, abort, quarantine, release)
//! must emit an `EvidenceEntry` into the ledger before execution proceeds.
//! Missing evidence constitutes a conformance violation that blocks the operation.
//!
//! # Invariants
//!
//! - INV-EVIDENCE-MANDATORY: every policy action requires an evidence entry
//! - INV-EVIDENCE-LINKAGE: evidence entry links to action via action_id
//! - INV-EVIDENCE-COMPLETE: all DecisionKind variants are covered

use std::fmt;

use crate::observability::evidence_ledger::{DecisionKind, EvidenceEntry, EvidenceLedger};

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const POLICY_ACTION_SUCCESS: &str = "EVD-POLICY-001";
    pub const POLICY_MISSING_EVIDENCE: &str = "EVD-POLICY-002";
    pub const POLICY_LINKAGE_MISMATCH: &str = "EVD-POLICY-003";
}

// ── ActionId ────────────────────────────────────────────────────────

/// Stable action identifier for cross-referencing evidence entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionId(pub String);

impl ActionId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── PolicyAction ────────────────────────────────────────────────────

/// Policy-driven control action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyAction {
    /// Data durability commitment.
    Commit,
    /// Operation cancellation / rollback.
    Abort,
    /// Suspicious artifact isolation.
    Quarantine,
    /// Quarantine release / trust promotion.
    Release,
}

impl PolicyAction {
    /// Map to the corresponding `DecisionKind` for evidence validation.
    pub fn expected_decision_kind(&self) -> DecisionKind {
        match self {
            Self::Commit => DecisionKind::Admit,
            Self::Abort => DecisionKind::Deny,
            Self::Quarantine => DecisionKind::Quarantine,
            Self::Release => DecisionKind::Release,
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Abort => "abort",
            Self::Quarantine => "quarantine",
            Self::Release => "release",
        }
    }

    /// All policy action variants.
    pub fn all() -> &'static [PolicyAction] {
        &[Self::Commit, Self::Abort, Self::Quarantine, Self::Release]
    }
}

impl fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── EvidenceRequirement ─────────────────────────────────────────────

/// Describes the evidence required for a given policy action.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceRequirement {
    pub action: PolicyAction,
    pub required_decision_kind: DecisionKind,
    pub action_id_must_match: bool,
}

impl EvidenceRequirement {
    /// Build a requirement for the given action.
    pub fn for_action(action: PolicyAction) -> Self {
        Self {
            required_decision_kind: action.expected_decision_kind(),
            action,
            action_id_must_match: true,
        }
    }

    /// Build requirements for all action types.
    pub fn all_requirements() -> Vec<Self> {
        PolicyAction::all()
            .iter()
            .map(|a| Self::for_action(*a))
            .collect()
    }
}

// ── ConformanceError ─────────────────────────────────────────────────

/// Errors from evidence conformance checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceError {
    /// No evidence entry was provided.
    MissingEvidence {
        action: PolicyAction,
        action_id: ActionId,
    },
    /// Evidence decision_kind doesn't match the action type.
    DecisionKindMismatch {
        action: PolicyAction,
        expected: String,
        actual: String,
    },
    /// Evidence action_id doesn't match the action's ID.
    ActionIdMismatch { expected: ActionId, actual: String },
    /// Evidence entry is malformed (empty required fields).
    MalformedEvidence { reason: String },
    /// Ledger append failed.
    LedgerAppendFailed { reason: String },
}

impl ConformanceError {
    /// Stable error code for each variant.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingEvidence { .. } => "ERR_MISSING_EVIDENCE",
            Self::DecisionKindMismatch { .. } => "ERR_DECISION_KIND_MISMATCH",
            Self::ActionIdMismatch { .. } => "ERR_ACTION_ID_MISMATCH",
            Self::MalformedEvidence { .. } => "ERR_MALFORMED_EVIDENCE",
            Self::LedgerAppendFailed { .. } => "ERR_LEDGER_APPEND_FAILED",
        }
    }
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEvidence { action, action_id } => {
                write!(
                    f,
                    "{}: action={}, action_id={}",
                    event_codes::POLICY_MISSING_EVIDENCE,
                    action,
                    action_id
                )
            }
            Self::DecisionKindMismatch {
                action,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{}: action={}, expected={}, actual={}",
                    event_codes::POLICY_LINKAGE_MISMATCH,
                    action,
                    expected,
                    actual
                )
            }
            Self::ActionIdMismatch { expected, actual } => {
                write!(
                    f,
                    "{}: expected_action_id={}, actual={}",
                    event_codes::POLICY_LINKAGE_MISMATCH,
                    expected,
                    actual
                )
            }
            Self::MalformedEvidence { reason } => {
                write!(
                    f,
                    "{}: malformed evidence: {}",
                    event_codes::POLICY_MISSING_EVIDENCE,
                    reason
                )
            }
            Self::LedgerAppendFailed { reason } => {
                write!(f, "ledger append failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for ConformanceError {}

// ── PolicyActionOutcome ──────────────────────────────────────────────

/// Outcome of a policy action attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyActionOutcome {
    /// Action executed successfully with evidence recorded.
    Executed {
        action: PolicyAction,
        action_id: ActionId,
        evidence_decision_id: String,
    },
    /// Action was rejected due to missing/invalid evidence.
    Rejected {
        action: PolicyAction,
        error: ConformanceError,
    },
}

impl PolicyActionOutcome {
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Executed { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    /// Event code for structured logging.
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Executed { .. } => event_codes::POLICY_ACTION_SUCCESS,
            Self::Rejected { .. } => event_codes::POLICY_MISSING_EVIDENCE,
        }
    }
}

// ── EvidenceConformanceChecker ───────────────────────────────────────

/// Middleware that verifies evidence emission before allowing policy actions.
///
/// INV-EVIDENCE-MANDATORY: all actions require evidence.
/// INV-EVIDENCE-LINKAGE: evidence links to action via action_id.
/// INV-EVIDENCE-COMPLETE: all DecisionKind variants are covered.
#[derive(Debug)]
pub struct EvidenceConformanceChecker {
    /// Count of successful actions.
    executed_count: u64,
    /// Count of rejected actions.
    rejected_count: u64,
    /// Action log for audit.
    action_log: Vec<PolicyActionOutcome>,
}

impl EvidenceConformanceChecker {
    pub fn new() -> Self {
        Self {
            executed_count: 0,
            rejected_count: 0,
            action_log: Vec::new(),
        }
    }

    /// Get count of successfully executed actions.
    pub fn executed_count(&self) -> u64 {
        self.executed_count
    }

    /// Get count of rejected actions.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_count
    }

    /// Get the full action log.
    pub fn action_log(&self) -> &[PolicyActionOutcome] {
        &self.action_log
    }

    /// Validate evidence for an action and append to the ledger if valid.
    ///
    /// Returns `Executed` if evidence is valid and ledger append succeeds.
    /// Returns `Rejected` if evidence is missing, mismatched, or malformed.
    pub fn verify_and_execute(
        &mut self,
        action: PolicyAction,
        action_id: &ActionId,
        evidence: Option<&EvidenceEntry>,
        ledger: &mut EvidenceLedger,
    ) -> PolicyActionOutcome {
        // Step 1: Check evidence exists
        let entry = match evidence {
            Some(e) => e,
            None => {
                let outcome = PolicyActionOutcome::Rejected {
                    action,
                    error: ConformanceError::MissingEvidence {
                        action,
                        action_id: action_id.clone(),
                    },
                };
                eprintln!(
                    "{}: action={}, action_id={}",
                    event_codes::POLICY_MISSING_EVIDENCE,
                    action,
                    action_id
                );
                self.rejected_count = self.rejected_count.saturating_add(1);
                self.action_log.push(outcome.clone());
                return outcome;
            }
        };

        // Step 2: Validate evidence is well-formed
        if entry.decision_id.is_empty() {
            let outcome = PolicyActionOutcome::Rejected {
                action,
                error: ConformanceError::MalformedEvidence {
                    reason: "decision_id is empty".into(),
                },
            };
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.action_log.push(outcome.clone());
            return outcome;
        }

        if entry.trace_id.is_empty() {
            let outcome = PolicyActionOutcome::Rejected {
                action,
                error: ConformanceError::MalformedEvidence {
                    reason: "trace_id is empty".into(),
                },
            };
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.action_log.push(outcome.clone());
            return outcome;
        }

        // Step 3: Validate decision_kind matches action type
        let expected_kind = action.expected_decision_kind();
        if entry.decision_kind != expected_kind {
            let outcome = PolicyActionOutcome::Rejected {
                action,
                error: ConformanceError::DecisionKindMismatch {
                    action,
                    expected: expected_kind.label().to_string(),
                    actual: entry.decision_kind.label().to_string(),
                },
            };
            eprintln!(
                "{}: action={}, expected_kind={}, actual_kind={}",
                event_codes::POLICY_LINKAGE_MISMATCH,
                action,
                expected_kind.label(),
                entry.decision_kind.label()
            );
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.action_log.push(outcome.clone());
            return outcome;
        }

        // Step 4: Validate action_id linkage via decision_id
        if entry.decision_id != action_id.as_str() {
            let outcome = PolicyActionOutcome::Rejected {
                action,
                error: ConformanceError::ActionIdMismatch {
                    expected: action_id.clone(),
                    actual: entry.decision_id.clone(),
                },
            };
            eprintln!(
                "{}: expected_action_id={}, actual={}",
                event_codes::POLICY_LINKAGE_MISMATCH,
                action_id,
                entry.decision_id
            );
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.action_log.push(outcome.clone());
            return outcome;
        }

        // Step 5: Append to ledger
        match ledger.append(entry.clone()) {
            Ok(_entry_id) => {
                eprintln!(
                    "{}: action={}, action_id={}, decision_id={}",
                    event_codes::POLICY_ACTION_SUCCESS,
                    action,
                    action_id,
                    entry.decision_id
                );
                let outcome = PolicyActionOutcome::Executed {
                    action,
                    action_id: action_id.clone(),
                    evidence_decision_id: entry.decision_id.clone(),
                };
                self.executed_count = self.executed_count.saturating_add(1);
                self.action_log.push(outcome.clone());
                outcome
            }
            Err(e) => {
                let outcome = PolicyActionOutcome::Rejected {
                    action,
                    error: ConformanceError::LedgerAppendFailed {
                        reason: e.to_string(),
                    },
                };
                self.rejected_count = self.rejected_count.saturating_add(1);
                self.action_log.push(outcome.clone());
                outcome
            }
        }
    }

    /// Check that all DecisionKind variants used by policy actions are covered.
    pub fn coverage_check() -> Vec<(PolicyAction, DecisionKind)> {
        PolicyAction::all()
            .iter()
            .map(|a| (*a, a.expected_decision_kind()))
            .collect()
    }

    /// Generate a coverage matrix as a serializable structure.
    pub fn coverage_matrix() -> Vec<CoverageEntry> {
        PolicyAction::all()
            .iter()
            .map(|action| CoverageEntry {
                action: action.label().to_string(),
                decision_kind: action.expected_decision_kind().label().to_string(),
                evidence_required: true,
                rejection_on_missing: true,
            })
            .collect()
    }
}

impl Default for EvidenceConformanceChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Coverage matrix entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CoverageEntry {
    pub action: String,
    pub decision_kind: String,
    pub evidence_required: bool,
    pub rejection_on_missing: bool,
}

// ── Helper: build evidence entry for a policy action ─────────────────

/// Build an evidence entry for a policy action with the correct decision_kind.
pub fn build_evidence_entry(
    action: PolicyAction,
    action_id: &ActionId,
    trace_id: &str,
    epoch_id: u64,
    payload: serde_json::Value,
) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: action_id.as_str().to_string(),
        decision_kind: action.expected_decision_kind(),
        decision_time: String::new(),
        timestamp_ms: 0,
        trace_id: trace_id.to_string(),
        epoch_id,
        payload,
        size_bytes: 0,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::evidence_ledger::LedgerCapacity;

    fn make_ledger() -> EvidenceLedger {
        EvidenceLedger::new(LedgerCapacity::new(100, 100_000))
    }

    fn make_evidence(action: PolicyAction, action_id: &str) -> EvidenceEntry {
        build_evidence_entry(
            action,
            &ActionId::new(action_id),
            "trace-test",
            1,
            serde_json::json!({"test": true}),
        )
    }

    // ── ActionId tests ──

    #[test]
    fn action_id_display() {
        let id = ActionId::new("ACT-001");
        assert_eq!(id.to_string(), "ACT-001");
        assert_eq!(id.as_str(), "ACT-001");
    }

    #[test]
    fn action_id_equality() {
        let a = ActionId::new("ACT-001");
        let b = ActionId::new("ACT-001");
        assert_eq!(a, b);
    }

    // ── PolicyAction tests ──

    #[test]
    fn policy_action_all_four_variants() {
        let all = PolicyAction::all();
        assert_eq!(all.len(), 4);
        assert!(all.contains(&PolicyAction::Commit));
        assert!(all.contains(&PolicyAction::Abort));
        assert!(all.contains(&PolicyAction::Quarantine));
        assert!(all.contains(&PolicyAction::Release));
    }

    #[test]
    fn policy_action_labels() {
        assert_eq!(PolicyAction::Commit.label(), "commit");
        assert_eq!(PolicyAction::Abort.label(), "abort");
        assert_eq!(PolicyAction::Quarantine.label(), "quarantine");
        assert_eq!(PolicyAction::Release.label(), "release");
    }

    #[test]
    fn policy_action_decision_kind_mapping() {
        assert_eq!(
            PolicyAction::Commit.expected_decision_kind(),
            DecisionKind::Admit
        );
        assert_eq!(
            PolicyAction::Abort.expected_decision_kind(),
            DecisionKind::Deny
        );
        assert_eq!(
            PolicyAction::Quarantine.expected_decision_kind(),
            DecisionKind::Quarantine
        );
        assert_eq!(
            PolicyAction::Release.expected_decision_kind(),
            DecisionKind::Release
        );
    }

    #[test]
    fn policy_action_display() {
        assert_eq!(PolicyAction::Commit.to_string(), "commit");
    }

    // ── EvidenceRequirement tests ──

    #[test]
    fn evidence_requirement_for_each_action() {
        for action in PolicyAction::all() {
            let req = EvidenceRequirement::for_action(*action);
            assert_eq!(req.action, *action);
            assert_eq!(req.required_decision_kind, action.expected_decision_kind());
            assert!(req.action_id_must_match);
        }
    }

    #[test]
    fn all_requirements_covers_all_actions() {
        let reqs = EvidenceRequirement::all_requirements();
        assert_eq!(reqs.len(), 4);
    }

    // ── ConformanceError tests ──

    #[test]
    fn conformance_error_codes() {
        let errors = [
            ConformanceError::MissingEvidence {
                action: PolicyAction::Commit,
                action_id: ActionId::new("ACT-001"),
            },
            ConformanceError::DecisionKindMismatch {
                action: PolicyAction::Commit,
                expected: "admit".into(),
                actual: "deny".into(),
            },
            ConformanceError::ActionIdMismatch {
                expected: ActionId::new("ACT-001"),
                actual: "ACT-002".into(),
            },
            ConformanceError::MalformedEvidence {
                reason: "test".into(),
            },
            ConformanceError::LedgerAppendFailed {
                reason: "test".into(),
            },
        ];
        let expected_codes = [
            "ERR_MISSING_EVIDENCE",
            "ERR_DECISION_KIND_MISMATCH",
            "ERR_ACTION_ID_MISMATCH",
            "ERR_MALFORMED_EVIDENCE",
            "ERR_LEDGER_APPEND_FAILED",
        ];
        for (err, code) in errors.iter().zip(expected_codes.iter()) {
            assert_eq!(err.code(), *code);
        }
    }

    #[test]
    fn conformance_error_display() {
        let err = ConformanceError::MissingEvidence {
            action: PolicyAction::Commit,
            action_id: ActionId::new("ACT-001"),
        };
        let display = err.to_string();
        assert!(display.contains("EVD-POLICY-002"));
        assert!(display.contains("commit"));
    }

    // ── PolicyActionOutcome tests ──

    #[test]
    fn outcome_executed() {
        let outcome = PolicyActionOutcome::Executed {
            action: PolicyAction::Commit,
            action_id: ActionId::new("ACT-001"),
            evidence_decision_id: "ACT-001".into(),
        };
        assert!(outcome.is_executed());
        assert!(!outcome.is_rejected());
        assert_eq!(outcome.event_code(), "EVD-POLICY-001");
    }

    #[test]
    fn outcome_rejected() {
        let outcome = PolicyActionOutcome::Rejected {
            action: PolicyAction::Commit,
            error: ConformanceError::MissingEvidence {
                action: PolicyAction::Commit,
                action_id: ActionId::new("ACT-001"),
            },
        };
        assert!(!outcome.is_executed());
        assert!(outcome.is_rejected());
        assert_eq!(outcome.event_code(), "EVD-POLICY-002");
    }

    // ── EvidenceConformanceChecker: successful execution ──

    #[test]
    fn commit_with_evidence_executes() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-COMMIT-001");
        let evidence = make_evidence(PolicyAction::Commit, "ACT-COMMIT-001");

        let outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );
        assert!(outcome.is_executed());
        assert_eq!(checker.executed_count(), 1);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn abort_with_evidence_executes() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-ABORT-001");
        let evidence = make_evidence(PolicyAction::Abort, "ACT-ABORT-001");

        let outcome = checker.verify_and_execute(
            PolicyAction::Abort,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );
        assert!(outcome.is_executed());
    }

    #[test]
    fn quarantine_with_evidence_executes() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-QUAR-001");
        let evidence = make_evidence(PolicyAction::Quarantine, "ACT-QUAR-001");

        let outcome = checker.verify_and_execute(
            PolicyAction::Quarantine,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );
        assert!(outcome.is_executed());
    }

    #[test]
    fn release_with_evidence_executes() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-REL-001");
        let evidence = make_evidence(PolicyAction::Release, "ACT-REL-001");

        let outcome = checker.verify_and_execute(
            PolicyAction::Release,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );
        assert!(outcome.is_executed());
    }

    // ── Missing evidence rejection ──

    #[test]
    fn commit_without_evidence_rejected() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");

        let outcome =
            checker.verify_and_execute(PolicyAction::Commit, &action_id, None, &mut ledger);
        assert!(outcome.is_rejected());
        assert_eq!(checker.rejected_count(), 1);
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn abort_without_evidence_rejected() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");

        let outcome =
            checker.verify_and_execute(PolicyAction::Abort, &action_id, None, &mut ledger);
        assert!(outcome.is_rejected());
    }

    #[test]
    fn quarantine_without_evidence_rejected() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");

        let outcome =
            checker.verify_and_execute(PolicyAction::Quarantine, &action_id, None, &mut ledger);
        assert!(outcome.is_rejected());
    }

    #[test]
    fn release_without_evidence_rejected() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");

        let outcome =
            checker.verify_and_execute(PolicyAction::Release, &action_id, None, &mut ledger);
        assert!(outcome.is_rejected());
    }

    // ── Decision kind mismatch ──

    #[test]
    fn wrong_decision_kind_rejected() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");
        // Commit expects Admit, but we provide Deny evidence
        let evidence = make_evidence(PolicyAction::Abort, "ACT-001");

        let outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );
        assert!(outcome.is_rejected());
        if let PolicyActionOutcome::Rejected { error, .. } = &outcome {
            assert_eq!(error.code(), "ERR_DECISION_KIND_MISMATCH");
        }
    }

    // ── Action ID mismatch ──

    #[test]
    fn wrong_action_id_rejected() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");
        let evidence = make_evidence(PolicyAction::Commit, "ACT-999"); // different ID

        let outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );
        assert!(outcome.is_rejected());
        if let PolicyActionOutcome::Rejected { error, .. } = &outcome {
            assert_eq!(error.code(), "ERR_ACTION_ID_MISMATCH");
        }
    }

    // ── Malformed evidence ──

    #[test]
    fn empty_decision_id_rejected() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");
        let mut evidence = make_evidence(PolicyAction::Commit, "ACT-001");
        evidence.decision_id = String::new();

        let outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );
        assert!(outcome.is_rejected());
        if let PolicyActionOutcome::Rejected { error, .. } = &outcome {
            assert_eq!(error.code(), "ERR_MALFORMED_EVIDENCE");
        }
    }

    #[test]
    fn empty_trace_id_rejected() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");
        let mut evidence = make_evidence(PolicyAction::Commit, "ACT-001");
        evidence.trace_id = String::new();

        let outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );
        assert!(outcome.is_rejected());
    }

    // ── Coverage ──

    #[test]
    fn coverage_check_all_four_actions() {
        let coverage = EvidenceConformanceChecker::coverage_check();
        assert_eq!(coverage.len(), 4);
    }

    #[test]
    fn coverage_matrix_all_actions() {
        let matrix = EvidenceConformanceChecker::coverage_matrix();
        assert_eq!(matrix.len(), 4);
        for entry in &matrix {
            assert!(entry.evidence_required);
            assert!(entry.rejection_on_missing);
        }
    }

    // ── Action log ──

    #[test]
    fn action_log_accumulates() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-001");

        // One success
        let evidence = make_evidence(PolicyAction::Commit, "ACT-001");
        checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );

        // One rejection
        checker.verify_and_execute(PolicyAction::Abort, &action_id, None, &mut ledger);

        assert_eq!(checker.action_log().len(), 2);
        assert_eq!(checker.executed_count(), 1);
        assert_eq!(checker.rejected_count(), 1);
    }

    // ── Full lifecycle: all four actions ──

    #[test]
    fn full_lifecycle_all_four_actions_with_evidence() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();

        for action in PolicyAction::all() {
            let action_id = ActionId::new(format!("ACT-{}", action.label().to_uppercase()));
            let evidence = build_evidence_entry(
                *action,
                &action_id,
                "trace-lifecycle",
                1,
                serde_json::json!({"action": action.label()}),
            );
            let outcome =
                checker.verify_and_execute(*action, &action_id, Some(&evidence), &mut ledger);
            assert!(
                outcome.is_executed(),
                "action {} should have executed, got {:?}",
                action,
                outcome
            );
        }
        assert_eq!(checker.executed_count(), 4);
        assert_eq!(ledger.len(), 4);
    }

    #[test]
    fn full_lifecycle_all_four_without_evidence() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();

        for action in PolicyAction::all() {
            let action_id = ActionId::new(format!("ACT-{}", action.label().to_uppercase()));
            let outcome = checker.verify_and_execute(*action, &action_id, None, &mut ledger);
            assert!(
                outcome.is_rejected(),
                "action {} should have been rejected, got {:?}",
                action,
                outcome
            );
        }
        assert_eq!(checker.rejected_count(), 4);
        assert_eq!(ledger.len(), 0);
    }

    // ── build_evidence_entry helper ──

    #[test]
    fn build_evidence_entry_sets_correct_fields() {
        let action_id = ActionId::new("ACT-001");
        let entry = build_evidence_entry(
            PolicyAction::Quarantine,
            &action_id,
            "trace-123",
            42,
            serde_json::json!({"key": "value"}),
        );
        assert_eq!(entry.decision_id, "ACT-001");
        assert_eq!(entry.decision_kind, DecisionKind::Quarantine);
        assert_eq!(entry.trace_id, "trace-123");
        assert_eq!(entry.epoch_id, 42);
        assert_eq!(entry.schema_version, "1.0");
    }

    // ── Default trait ──

    #[test]
    fn checker_default() {
        let checker = EvidenceConformanceChecker::default();
        assert_eq!(checker.executed_count(), 0);
        assert_eq!(checker.rejected_count(), 0);
    }
}
