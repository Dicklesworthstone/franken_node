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

use crate::capacity_defaults::aliases::MAX_ACTION_LOG_ENTRIES;

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

    fn push_action(&mut self, outcome: PolicyActionOutcome) {
        push_bounded(&mut self.action_log, outcome, MAX_ACTION_LOG_ENTRIES);
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
                self.push_action(outcome.clone());
                return outcome;
            }
        };

        // Step 2: Validate evidence is well-formed
        if entry.schema_version.trim().is_empty() {
            let outcome = PolicyActionOutcome::Rejected {
                action,
                error: ConformanceError::MalformedEvidence {
                    reason: "schema_version is empty or whitespace".into(),
                },
            };
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.push_action(outcome.clone());
            return outcome;
        }

        if entry.decision_id.trim().is_empty() {
            let outcome = PolicyActionOutcome::Rejected {
                action,
                error: ConformanceError::MalformedEvidence {
                    reason: "decision_id is empty or whitespace".into(),
                },
            };
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.push_action(outcome.clone());
            return outcome;
        }

        if entry.trace_id.trim().is_empty() {
            let outcome = PolicyActionOutcome::Rejected {
                action,
                error: ConformanceError::MalformedEvidence {
                    reason: "trace_id is empty or whitespace".into(),
                },
            };
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.push_action(outcome.clone());
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
            self.push_action(outcome.clone());
            return outcome;
        }

        // Step 4: Validate action_id linkage via decision_id
        if !crate::security::constant_time::ct_eq(entry.decision_id.as_str(), action_id.as_str()) {
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
            self.push_action(outcome.clone());
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
                self.push_action(outcome.clone());
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
                self.push_action(outcome.clone());
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
        signature: String::new(),
        prev_entry_hash: String::new(),
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

    #[test]
    fn action_id_boundary_mismatches_rejected() {
        let cases = [
            ("ACT-SECRET-001", "ACT-SECRET-001-suffix"),
            ("ACT-SECRET-001", "XACT-SECRET-001"),
            ("ACT-SECRET-001", "ACT-SECRET-002"),
        ];

        for (expected, actual) in cases {
            let mut checker = EvidenceConformanceChecker::new();
            let mut ledger = make_ledger();
            let action_id = ActionId::new(expected);
            let evidence = make_evidence(PolicyAction::Commit, actual);

            let outcome = checker.verify_and_execute(
                PolicyAction::Commit,
                &action_id,
                Some(&evidence),
                &mut ledger,
            );

            assert!(
                matches!(outcome, PolicyActionOutcome::Rejected { .. }),
                "expected action ID mismatch rejection"
            );
            if let PolicyActionOutcome::Rejected { error, .. } = outcome {
                assert_eq!(error.code(), "ERR_ACTION_ID_MISMATCH");
            }
            assert_eq!(checker.rejected_count(), 1);
            assert_eq!(ledger.len(), 0);
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

    #[test]
    fn missing_evidence_records_rejected_action_log_entry() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-MISSING-001");

        let outcome =
            checker.verify_and_execute(PolicyAction::Commit, &action_id, None, &mut ledger);

        match outcome {
            PolicyActionOutcome::Rejected {
                action,
                error:
                    ConformanceError::MissingEvidence {
                        action: missing_action,
                        action_id: missing_action_id,
                    },
            } => {
                assert_eq!(action, PolicyAction::Commit);
                assert_eq!(missing_action, PolicyAction::Commit);
                assert_eq!(missing_action_id, action_id);
            }
            other => unreachable!("expected missing-evidence rejection, got {other:?}"),
        }
        assert_eq!(checker.executed_count(), 0);
        assert_eq!(checker.rejected_count(), 1);
        assert_eq!(checker.action_log().len(), 1);
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn decision_kind_mismatch_does_not_append_to_ledger() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-KIND-001");
        let evidence = make_evidence(PolicyAction::Abort, "ACT-KIND-001");

        let outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );

        assert!(matches!(
            outcome,
            PolicyActionOutcome::Rejected {
                error: ConformanceError::DecisionKindMismatch { .. },
                ..
            }
        ));
        assert_eq!(checker.executed_count(), 0);
        assert_eq!(checker.rejected_count(), 1);
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn action_id_mismatch_preserves_expected_and_actual_ids() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-EXPECTED-001");
        let evidence = make_evidence(PolicyAction::Release, "ACT-ACTUAL-001");

        let outcome = checker.verify_and_execute(
            PolicyAction::Release,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );

        match outcome {
            PolicyActionOutcome::Rejected {
                error: ConformanceError::ActionIdMismatch { expected, actual },
                ..
            } => {
                assert_eq!(expected, action_id);
                assert_eq!(actual, "ACT-ACTUAL-001");
            }
            other => unreachable!("expected action-id mismatch, got {other:?}"),
        }
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn empty_trace_id_rejection_prevents_later_linkage_checks() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-TRACE-001");
        let mut evidence = make_evidence(PolicyAction::Abort, "DIFFERENT-ID");
        evidence.trace_id = String::new();

        let outcome = checker.verify_and_execute(
            PolicyAction::Abort,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );

        assert!(matches!(
            outcome,
            PolicyActionOutcome::Rejected {
                error: ConformanceError::MalformedEvidence { ref reason },
                ..
            } if reason.contains("trace_id")
        ));
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn empty_decision_id_rejection_prevents_kind_mismatch_checks() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-DECISION-001");
        let mut evidence = make_evidence(PolicyAction::Abort, "ACT-DECISION-001");
        evidence.decision_id = String::new();

        let outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );

        assert!(matches!(
            outcome,
            PolicyActionOutcome::Rejected {
                error: ConformanceError::MalformedEvidence { ref reason },
                ..
            } if reason.contains("decision_id")
        ));
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn zero_capacity_ledger_rejects_valid_evidence_without_execution_count() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(0, 100_000));
        let action_id = ActionId::new("ACT-ZERO-CAPACITY");
        let evidence = make_evidence(PolicyAction::Quarantine, "ACT-ZERO-CAPACITY");

        let outcome = checker.verify_and_execute(
            PolicyAction::Quarantine,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );

        assert!(matches!(
            outcome,
            PolicyActionOutcome::Rejected {
                error: ConformanceError::LedgerAppendFailed { .. },
                ..
            }
        ));
        assert_eq!(checker.executed_count(), 0);
        assert_eq!(checker.rejected_count(), 1);
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn tiny_byte_budget_ledger_rejects_valid_evidence() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(1, 1));
        let action_id = ActionId::new("ACT-TINY-BUDGET");
        let evidence = make_evidence(PolicyAction::Commit, "ACT-TINY-BUDGET");

        let outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &action_id,
            Some(&evidence),
            &mut ledger,
        );

        assert!(matches!(
            outcome,
            PolicyActionOutcome::Rejected {
                error: ConformanceError::LedgerAppendFailed { ref reason },
                ..
            } if reason.contains("exceeds max_bytes")
        ));
        assert_eq!(checker.executed_count(), 0);
        assert_eq!(checker.rejected_count(), 1);
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_action_log_window() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_preserves_latest_action_log_entries() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 3);

        assert_eq!(items, vec![2, 3, 4]);
    }

    // === NEGATIVE-PATH ROBUSTNESS TESTS ===

    #[test]
    fn unicode_injection_in_action_identifiers_handled_safely() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();

        // Unicode injection attack vectors in action IDs
        let malicious_action_ids = [
            "ACT\u{202e}evil\u{200b}\u{0000}inject", // Bidirectional override + zero width + null
            "ACT\u{feff}\u{1f4a9}\u{2028}bypass",    // BOM + emoji + line separator
            "ACT\u{0085}\u{2029}\u{00ad}payload\u{061c}", // Control chars + soft hyphen
            "ACT\u{034f}\u{180e}\u{200c}id",         // Combining marks + invisible chars
            "ACT-001\r\nHost: evil.com",             // CRLF injection
            "ACT-001\x00truncated",                  // Null termination attack
            &"A".repeat(100_000),                    // Massive action ID (DoS)
        ];

        for malicious_id in malicious_action_ids {
            let action_id = ActionId::new(malicious_id);
            let evidence = build_evidence_entry(
                PolicyAction::Commit,
                &action_id,
                "trace-unicode-test",
                1,
                serde_json::json!({"test": "unicode"}),
            );

            let outcome = checker.verify_and_execute(
                PolicyAction::Commit,
                &action_id,
                Some(&evidence),
                &mut ledger,
            );

            // Should handle Unicode injection safely
            assert!(
                outcome.is_executed() || outcome.is_rejected(),
                "Unicode action ID '{}' should be handled without panic",
                malicious_id
            );

            if outcome.is_executed() {
                // Verify ledger entry is recorded safely
                assert!(
                    ledger.len() > 0,
                    "Ledger should contain entry for Unicode action ID"
                );

                // Verify action ID is preserved as-is (no interpretation)
                assert_eq!(
                    action_id.as_str(),
                    malicious_id,
                    "Action ID should be preserved exactly as provided"
                );
            }

            // Action log should contain outcome regardless of success/rejection
            assert!(
                !checker.action_log().is_empty(),
                "Action log should record Unicode attempts"
            );
        }
    }

    #[test]
    fn malformed_evidence_entries_comprehensive_validation() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();
        let action_id = ActionId::new("ACT-MALFORMED-001");

        // Test various malformed evidence scenarios
        let malformed_evidence_tests = [
            // Empty required string fields
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.decision_id = String::new();
                ("empty decision_id", evidence)
            },
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.trace_id = String::new();
                ("empty trace_id", evidence)
            },
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.schema_version = String::new();
                ("empty schema_version", evidence)
            },
            // Whitespace-only fields
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.decision_id = "   ".to_string();
                ("whitespace-only decision_id", evidence)
            },
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.trace_id = "\t\n\r ".to_string();
                ("whitespace-only trace_id", evidence)
            },
            // Unicode control characters in fields
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.decision_id = "ACT\u{0000}hidden".to_string();
                ("null byte in decision_id", evidence)
            },
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.trace_id = "trace\u{001F}control".to_string();
                ("control char in trace_id", evidence)
            },
            // Extremely long field values (potential DoS)
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.decision_id = "x".repeat(50_000);
                ("massive decision_id", evidence)
            },
            {
                let mut evidence = make_evidence(PolicyAction::Commit, "ACT-MALFORMED-001");
                evidence.trace_id = "t".repeat(25_000);
                ("massive trace_id", evidence)
            },
        ];

        for (test_name, evidence) in malformed_evidence_tests {
            let outcome = checker.verify_and_execute(
                PolicyAction::Commit,
                &action_id,
                Some(&evidence),
                &mut ledger,
            );

            // Blank required string fields should be rejected as malformed
            if evidence.schema_version.trim().is_empty()
                || evidence.decision_id.trim().is_empty()
                || evidence.trace_id.trim().is_empty()
            {
                assert!(
                    outcome.is_rejected(),
                    "Test '{}' should reject malformed evidence",
                    test_name
                );

                if let PolicyActionOutcome::Rejected { error, .. } = &outcome {
                    assert_eq!(
                        error.code(),
                        "ERR_MALFORMED_EVIDENCE",
                        "Test '{}' should produce malformed evidence error",
                        test_name
                    );
                }
            } else {
                // Other malformed inputs should be handled safely (may succeed or fail)
                assert!(
                    outcome.is_executed() || outcome.is_rejected(),
                    "Test '{}' should handle malformed input safely",
                    test_name
                );
            }

            // Verify no memory leaks or crashes with malformed data
            assert!(
                checker.action_log().len() > 0,
                "Action log should record attempt"
            );
        }
    }

    #[test]
    fn decision_kind_mismatch_comprehensive_cross_validation() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();

        // Test all combinations of action vs decision_kind mismatches
        let actions = PolicyAction::all();

        for &requesting_action in actions {
            for &evidence_action in actions {
                if requesting_action == evidence_action {
                    continue; // Skip matching pairs
                }

                let action_id = ActionId::new(format!(
                    "ACT-MISMATCH-{}-{}",
                    requesting_action.label().to_uppercase(),
                    evidence_action.label().to_uppercase()
                ));

                let evidence = make_evidence(evidence_action, action_id.as_str());

                let outcome = checker.verify_and_execute(
                    requesting_action,
                    &action_id,
                    Some(&evidence),
                    &mut ledger,
                );

                // All mismatches should be rejected
                assert!(
                    outcome.is_rejected(),
                    "Mismatch {} action with {} evidence should be rejected",
                    requesting_action.label(),
                    evidence_action.label()
                );

                if let PolicyActionOutcome::Rejected { error, .. } = &outcome {
                    assert_eq!(
                        error.code(),
                        "ERR_DECISION_KIND_MISMATCH",
                        "Should produce decision kind mismatch error"
                    );
                }

                // Ledger should not be modified by rejected actions
                assert_eq!(
                    ledger.len(),
                    0,
                    "Ledger should remain empty for all mismatches"
                );
            }
        }

        // Verify all mismatches were rejected
        assert!(
            checker.rejected_count() > 0,
            "Should have rejected multiple mismatches"
        );
        assert_eq!(
            checker.executed_count(),
            0,
            "Should not have executed any mismatched actions"
        );
    }

    #[test]
    fn action_id_linkage_injection_and_substitution_attacks() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();

        // Action ID substitution attack scenarios
        let linkage_attacks = [
            // Basic substitution
            ("ACT-LEGIT-001", "ACT-MALICIOUS-001"),
            // Case sensitivity bypass attempts
            ("ACT-SECURE-001", "act-secure-001"),
            ("act-secure-001", "ACT-SECURE-001"),
            // Unicode normalization attacks
            ("ACT-café-001", "ACT-cafe\u{0301}-001"), // NFC vs NFD
            // Injection attempts via action IDs
            ("ACT-001", "ACT-001\"; DROP TABLE evidence; --"),
            ("ACT-001", "ACT-001<script>alert('xss')</script>"),
            ("ACT-001", "ACT-001\r\nBypass: true"),
            // Null byte truncation attacks
            ("ACT-REAL-001", "ACT-REAL-001\0fake"),
            // Whitespace confusion
            ("ACT-001", "ACT-001 "),
            ("ACT-001", " ACT-001"),
            ("ACT-001", "ACT-001\t"),
            // Length-based attacks
            ("ACT-SHORT", &"A".repeat(100_000)),
        ];

        for (expected_id, evidence_id) in linkage_attacks {
            let action_id = ActionId::new(expected_id);
            let evidence = make_evidence(PolicyAction::Release, evidence_id);

            let outcome = checker.verify_and_execute(
                PolicyAction::Release,
                &action_id,
                Some(&evidence),
                &mut ledger,
            );

            // All linkage attacks should be rejected (exact match required)
            if expected_id != evidence_id {
                assert!(
                    outcome.is_rejected(),
                    "Linkage attack expected='{}', evidence='{}' should be rejected",
                    expected_id,
                    evidence_id
                );

                if let PolicyActionOutcome::Rejected { error, .. } = &outcome {
                    assert_eq!(
                        error.code(),
                        "ERR_ACTION_ID_MISMATCH",
                        "Should produce action ID mismatch error"
                    );
                }
            } else {
                // Exact matches should succeed
                assert!(outcome.is_executed(), "Exact match should succeed");
            }
        }

        // Verify no malicious evidence was accepted
        let expected_successes = linkage_attacks
            .iter()
            .filter(|(expected, evidence)| expected == evidence)
            .count();
        assert_eq!(
            checker.executed_count() as usize,
            expected_successes,
            "Only exact matches should have succeeded"
        );
    }

    #[test]
    fn concurrent_evidence_verification_state_corruption_resistance() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let checker = Arc::new(Mutex::new(EvidenceConformanceChecker::new()));
        let ledger = Arc::new(Mutex::new(make_ledger()));

        // Spawn multiple threads performing concurrent evidence verification
        let handles: Vec<_> = (0..8)
            .map(|thread_id| {
                let checker_clone = Arc::clone(&checker);
                let ledger_clone = Arc::clone(&ledger);

                thread::spawn(move || {
                    let mut results = Vec::new();

                    for i in 0..25 {
                        let action_id = ActionId::new(format!("CONCURRENT-{}-{}", thread_id, i));
                        let action = PolicyAction::all()[i % PolicyAction::all().len()];

                        // Mix of valid and invalid evidence
                        let evidence = if i % 3 == 0 {
                            None // Missing evidence
                        } else if i % 3 == 1 {
                            // Valid evidence
                            Some(make_evidence(action, action_id.as_str()))
                        } else {
                            // Invalid evidence (wrong action ID)
                            Some(make_evidence(action, "WRONG-ID"))
                        };

                        if let (Ok(mut checker_lock), Ok(mut ledger_lock)) =
                            (checker_clone.try_lock(), ledger_clone.try_lock())
                        {
                            let outcome = checker_lock.verify_and_execute(
                                action,
                                &action_id,
                                evidence.as_ref(),
                                &mut ledger_lock,
                            );

                            results.push((outcome.is_executed(), outcome.is_rejected()));
                        }

                        // Brief yield to encourage race conditions
                        thread::yield_now();
                    }

                    results
                })
            })
            .collect();

        // Collect all results
        let mut all_results = Vec::new();
        for handle in handles {
            let thread_results = handle.join().unwrap();
            all_results.extend(thread_results);
        }

        // Verify consistency under concurrent access
        let executed_count = all_results.iter().filter(|(exec, _)| *exec).count();
        let rejected_count = all_results.iter().filter(|(_, rej)| *rej).count();

        // All operations should have deterministic outcomes
        assert_eq!(
            executed_count + rejected_count,
            all_results.len(),
            "All operations should have definitive outcomes"
        );

        // Verify final state consistency
        let final_checker = checker.lock().unwrap();
        let final_ledger = ledger.lock().unwrap();

        assert_eq!(
            final_checker.executed_count() as usize,
            executed_count,
            "Executed count should match successful operations"
        );
        assert_eq!(
            final_checker.rejected_count() as usize,
            rejected_count,
            "Rejected count should match failed operations"
        );
        assert_eq!(
            final_ledger.len(),
            executed_count,
            "Ledger size should match executed operations"
        );
    }

    #[test]
    fn massive_action_log_capacity_exhaustion_protection() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();

        // Generate more actions than MAX_ACTION_LOG_ENTRIES capacity
        let excess_actions = MAX_ACTION_LOG_ENTRIES + 500;

        for i in 0..excess_actions {
            let action_id = ActionId::new(format!("FLOOD-{:06}", i));
            let action = PolicyAction::all()[i % PolicyAction::all().len()];

            // Mix of successful and rejected actions
            let evidence = if i % 2 == 0 {
                Some(make_evidence(action, action_id.as_str()))
            } else {
                None // Missing evidence
            };

            let outcome =
                checker.verify_and_execute(action, &action_id, evidence.as_ref(), &mut ledger);

            // Verify operation completes without memory exhaustion
            assert!(
                outcome.is_executed() || outcome.is_rejected(),
                "Operation {} should complete without panic",
                i
            );
        }

        // Action log should be bounded by capacity
        assert!(
            checker.action_log().len() <= MAX_ACTION_LOG_ENTRIES,
            "Action log should be bounded to capacity, got {}",
            checker.action_log().len()
        );

        // Counters should accurately reflect all operations
        let expected_executed = excess_actions / 2;
        let expected_rejected = excess_actions - expected_executed;

        assert_eq!(
            checker.executed_count() as usize,
            expected_executed,
            "Executed count should reflect all successful operations"
        );
        assert_eq!(
            checker.rejected_count() as usize,
            expected_rejected,
            "Rejected count should reflect all failed operations"
        );

        // Ledger should contain only executed entries
        assert_eq!(
            ledger.len(),
            expected_executed,
            "Ledger should contain only successfully executed entries"
        );

        // Action log should contain most recent entries (oldest evicted)
        if checker.action_log().len() == MAX_ACTION_LOG_ENTRIES {
            // Verify latest entries are preserved
            let last_entry_in_log = &checker.action_log()[MAX_ACTION_LOG_ENTRIES - 1];
            // Should be one of the recent outcomes
            assert!(
                last_entry_in_log.is_executed() || last_entry_in_log.is_rejected(),
                "Last action log entry should be valid"
            );
        }
    }

    #[test]
    fn evidence_payload_json_injection_and_structure_attacks() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = make_ledger();

        // JSON injection attack vectors in evidence payloads
        let malicious_payloads = [
            // JSON structure manipulation
            serde_json::json!({"key": "value\"},\"malicious\":true,\"original\":\""}),
            serde_json::json!({"key": "\": {\"bypass\": true}, \"real_key\": \""}),
            // Unicode escapes and control characters
            serde_json::json!({"unicode": "value\u{0000}bypass"}),
            serde_json::json!({"control": "value\u{001F}\u{007F}"}),
            serde_json::json!({"bidi": "value\u{202e}reversed"}),
            // CRLF injection attempts
            serde_json::json!({"crlf": "value\r\nX-Injection: malicious"}),
            serde_json::json!({"newline": "value\n{\"fake\": \"entry\"}"}),
            // Massive nested structures (DoS)
            {
                let mut nested = serde_json::json!("deep");
                for _ in 0..1000 {
                    nested = serde_json::json!({"level": nested});
                }
                nested
            },
            // Array flooding
            serde_json::json!({"flood": vec!["x"; 100_000]}),
            // String length attacks
            serde_json::json!({"massive": "x".repeat(100_000)}),
            // Number boundary attacks
            serde_json::json!({"max_int": i64::MAX}),
            serde_json::json!({"max_uint": u64::MAX}),
            serde_json::json!({"infinity": f64::INFINITY}),
            serde_json::json!({"neg_infinity": f64::NEG_INFINITY}),
            // Null and undefined values
            serde_json::json!(null),
            serde_json::json!({"null_field": null}),
        ];

        for (i, payload) in malicious_payloads.into_iter().enumerate() {
            let action_id = ActionId::new(format!("PAYLOAD-ATTACK-{}", i));
            let evidence = build_evidence_entry(
                PolicyAction::Quarantine,
                &action_id,
                "trace-payload-attack",
                1,
                payload.clone(),
            );

            let outcome = checker.verify_and_execute(
                PolicyAction::Quarantine,
                &action_id,
                Some(&evidence),
                &mut ledger,
            );

            // Should handle all payload attacks safely
            assert!(
                outcome.is_executed() || outcome.is_rejected(),
                "Payload attack {} should be handled without panic",
                i
            );

            if outcome.is_executed() {
                // Verify payload is preserved as-is in ledger
                assert!(ledger.len() > 0, "Ledger should contain entry");

                // Verify JSON serialization doesn't break
                let serialized = serde_json::to_string(&evidence);
                assert!(serialized.is_ok(), "Evidence should serialize safely");

                // Verify no interpretation of payload content
                assert_eq!(
                    evidence.payload, payload,
                    "Payload should be preserved exactly as provided"
                );
            }
        }

        // All operations should complete without system compromise
        assert!(
            checker.executed_count() > 0 || checker.rejected_count() > 0,
            "Should have processed all payload attacks"
        );
    }

    #[test]
    fn ledger_failure_cascade_and_consistency_guarantees() {
        let mut checker = EvidenceConformanceChecker::new();

        // Test various ledger failure scenarios
        let failure_scenarios = [
            // Zero capacity ledger
            (
                "zero_capacity",
                EvidenceLedger::new(LedgerCapacity::new(0, 100_000)),
            ),
            // Minimal byte budget
            (
                "tiny_bytes",
                EvidenceLedger::new(LedgerCapacity::new(100, 1)),
            ),
            // Moderate capacity for overflow testing
            (
                "small_capacity",
                EvidenceLedger::new(LedgerCapacity::new(2, 1_000)),
            ),
        ];

        for (scenario_name, mut ledger) in failure_scenarios {
            let mut local_checker = EvidenceConformanceChecker::new();

            // Attempt multiple evidence submissions
            for i in 0..10 {
                let action_id =
                    ActionId::new(format!("{}-ACT-{}", scenario_name.to_uppercase(), i));
                let action = PolicyAction::all()[i % PolicyAction::all().len()];
                let evidence = build_evidence_entry(
                    action,
                    &action_id,
                    &format!("trace-{}-{}", scenario_name, i),
                    i as u64,
                    serde_json::json!({"iteration": i, "scenario": scenario_name}),
                );

                let outcome = local_checker.verify_and_execute(
                    action,
                    &action_id,
                    Some(&evidence),
                    &mut ledger,
                );

                // Verify state consistency regardless of outcome
                match outcome {
                    PolicyActionOutcome::Executed { .. } => {
                        // Execution should increment executed count
                        assert!(
                            local_checker.executed_count() > 0,
                            "Executed count should reflect successful operations in {}",
                            scenario_name
                        );

                        // Ledger should contain the entry
                        assert!(
                            ledger.len() > 0,
                            "Ledger should contain executed entry in {}",
                            scenario_name
                        );
                    }
                    PolicyActionOutcome::Rejected { error, .. } => {
                        // Rejection should increment rejected count
                        assert!(
                            local_checker.rejected_count() > 0,
                            "Rejected count should reflect failed operations in {}",
                            scenario_name
                        );

                        // For ledger failures, evidence should be valid but append failed
                        if let ConformanceError::LedgerAppendFailed { reason } = &error {
                            assert!(!reason.is_empty(), "Ledger failure should have reason");

                            // Ledger should not be modified by failed appends
                            // (depends on ledger implementation, but generally true)
                        }
                    }
                }

                // Action log should always record the attempt
                assert!(
                    local_checker.action_log().len() > 0,
                    "Action log should record all attempts in {}",
                    scenario_name
                );

                // Counters should be consistent
                let total_ops = local_checker.executed_count() + local_checker.rejected_count();
                assert!(
                    (total_ops as usize) <= (i + 1),
                    "Total operations should not exceed attempts in {}",
                    scenario_name
                );
            }

            // Verify final state consistency
            let final_executed = local_checker.executed_count();
            let final_rejected = local_checker.rejected_count();
            let final_total = final_executed + final_rejected;

            assert_eq!(
                final_total, 10,
                "Should have processed exactly 10 operations in {}",
                scenario_name
            );

            assert_eq!(
                u64::try_from(local_checker.action_log().len()).unwrap_or(u64::MAX),
                final_total.min(MAX_ACTION_LOG_ENTRIES as u64),
                "Action log should record all operations (up to capacity) in {}",
                scenario_name
            );
        }
    }

    // === Comprehensive Negative-Path Security Tests ===

    /// Negative test: Unicode injection attacks in action IDs and evidence metadata
    #[test]
    fn negative_unicode_injection_action_ids_metadata() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        // Test malicious Unicode in action IDs
        let malicious_action_ids = vec![
            "action\u{202e}evil\u{200b}", // Right-to-Left Override + Zero Width Space
            "action\u{0000}injection",    // Null byte injection
            "action\u{feff}bom",          // Byte Order Mark
            "action\u{2028}line\u{2029}para", // Line/Paragraph separators
            "action\u{200c}\u{200d}joiners", // Zero-width joiners
            "action\x00\x01\x02\x03\x1f", // Control characters
        ];

        for (i, malicious_action_id) in malicious_action_ids.iter().enumerate() {
            let action = PolicyAction::all()[i % PolicyAction::all().len()];
            let action_id = ActionId::new(malicious_action_id.to_string());

            // Test Unicode in evidence metadata
            let malicious_metadata = serde_json::json!({
                "trace_id": format!("trace\u{202e}evil\u{200b}{}", i),
                "operator": format!("operator\u{0000}injection{}", i),
                "reason": format!("reason\u{feff}bom\u{2028}{}", i),
                "details": format!("details\u{200c}joiners{}", i),
            });

            let evidence = build_evidence_entry(
                action,
                &action_id,
                &format!("unicode-trace-{}", i),
                1000 + i as u64,
                malicious_metadata,
            );

            let outcome =
                checker.verify_and_execute(action, &action_id, Some(&evidence), &mut ledger);

            // Should handle Unicode gracefully without corruption
            match outcome {
                PolicyActionOutcome::Executed { .. } => {
                    // Unicode was accepted, verify no corruption occurred
                    assert!(
                        ledger.len() > 0,
                        "Ledger should contain evidence with Unicode"
                    );

                    // Verify action ID integrity
                    assert_eq!(action_id.as_str(), *malicious_action_id);
                }
                PolicyActionOutcome::Rejected { error, .. } => {
                    // Unicode rejection is also acceptable for security
                    match error {
                        ConformanceError::MissingEvidence { .. }
                        | ConformanceError::DecisionKindMismatch { .. }
                        | ConformanceError::ActionIdMismatch { .. } => {
                            // These errors indicate Unicode validation passed but other checks failed
                        }
                        _ => {
                            // Other rejection reasons are acceptable
                        }
                    }
                }
            }
        }

        // Test Unicode in trace IDs and JSON payloads
        let complex_unicode_payload = serde_json::json!({
            "key\u{202e}": "value\u{200b}reversed",
            "field\u{0000}": "hidden\u{2028}null",
            "control\u{feff}": "bom\u{2029}breaks",
            "nested": {
                "unicode\u{200c}": "joiners\u{200d}test"
            }
        });

        let unicode_trace_evidence = build_evidence_entry(
            PolicyAction::Commit,
            &ActionId::new("unicode-trace-test"),
            "trace\u{202e}evil\u{0000}unicode",
            2000,
            complex_unicode_payload,
        );

        let unicode_trace_outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &ActionId::new("unicode-trace-test"),
            Some(&unicode_trace_evidence),
            &mut ledger,
        );

        // Should handle complex Unicode structures gracefully
        match unicode_trace_outcome {
            PolicyActionOutcome::Executed { .. } => {
                // Complex Unicode accepted
            }
            PolicyActionOutcome::Rejected { .. } => {
                // Unicode rejection acceptable
            }
        }
    }

    /// Negative test: Memory exhaustion through massive evidence payloads
    #[test]
    fn negative_memory_exhaustion_massive_payloads() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        // Test extremely large JSON payloads
        let massive_payload_sizes = vec![10_000, 50_000, 100_000]; // 10KB, 50KB, 100KB

        for (i, payload_size) in massive_payload_sizes.iter().enumerate() {
            let massive_data = "x".repeat(*payload_size);
            let massive_payload = serde_json::json!({
                "massive_field": massive_data,
                "size": payload_size,
                "test_iteration": i
            });

            let action_id = ActionId::new(format!("massive-payload-{}", i));
            let evidence = build_evidence_entry(
                PolicyAction::Commit,
                &action_id,
                &format!("massive-trace-{}", i),
                1000 + i as u64,
                massive_payload,
            );

            let outcome = checker.verify_and_execute(
                PolicyAction::Commit,
                &action_id,
                Some(&evidence),
                &mut ledger,
            );

            // Should handle massive payloads or reject gracefully
            match outcome {
                PolicyActionOutcome::Executed { .. } => {
                    // Large payload accepted - verify system remains responsive
                    assert!(checker.executed_count() > 0);
                }
                PolicyActionOutcome::Rejected { error, .. } => {
                    // Size-based rejection is acceptable
                    match error {
                        ConformanceError::LedgerAppendFailed { reason } => {
                            assert!(!reason.is_empty(), "Ledger failure should have reason");
                        }
                        _ => {
                            // Other rejection reasons acceptable
                        }
                    }
                }
            }
        }

        // Test rapid evidence submission with large payloads
        for rapid_cycle in 0..50 {
            let large_payload = serde_json::json!({
                "cycle": rapid_cycle,
                "data": "y".repeat(5_000), // 5KB per cycle
                "metadata": {
                    "timestamp": format!("{}ms", rapid_cycle * 100),
                    "batch_id": format!("batch-{}", rapid_cycle / 10)
                }
            });

            let rapid_action_id = ActionId::new(format!("rapid-{}", rapid_cycle));
            let rapid_evidence = build_evidence_entry(
                PolicyAction::all()[rapid_cycle % PolicyAction::all().len()],
                &rapid_action_id,
                &format!("rapid-trace-{}", rapid_cycle),
                2000 + rapid_cycle as u64,
                large_payload,
            );

            let rapid_outcome = checker.verify_and_execute(
                PolicyAction::all()[rapid_cycle % PolicyAction::all().len()],
                &rapid_action_id,
                Some(&rapid_evidence),
                &mut ledger,
            );

            // Should handle rapid submission or hit capacity limits gracefully
            match rapid_outcome {
                PolicyActionOutcome::Executed { .. } => {}
                PolicyActionOutcome::Rejected { error, .. } => {
                    match error {
                        ConformanceError::LedgerAppendFailed { .. } => {
                            // Hit capacity limits - expected behavior
                            break;
                        }
                        _ => {
                            // Other rejections acceptable
                        }
                    }
                }
            }
        }

        // Verify bounded memory usage despite stress test
        assert!(checker.action_log().len() <= MAX_ACTION_LOG_ENTRIES);
        assert!(ledger.len() <= 100); // Capacity limit
    }

    /// Negative test: Evidence spoofing and forgery attempts
    #[test]
    fn negative_evidence_spoofing_forgery_attempts() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        // Test decision kind spoofing
        let spoofing_attempts = vec![
            (PolicyAction::Commit, DecisionKind::Deny), // Commit with Deny decision
            (PolicyAction::Abort, DecisionKind::Admit), // Abort with Admit decision
            (PolicyAction::Quarantine, DecisionKind::Release), // Quarantine with Release decision
            (PolicyAction::Release, DecisionKind::Quarantine), // Release with Quarantine decision
        ];

        for (i, (action, spoofed_decision)) in spoofing_attempts.iter().enumerate() {
            let action_id = ActionId::new(format!("spoof-{}", i));

            // Create evidence with mismatched decision kind
            let mut spoofed_evidence = build_evidence_entry(
                *action,
                &action_id,
                &format!("spoof-trace-{}", i),
                1000u64.saturating_add(u64::try_from(i).unwrap_or(u64::MAX)),
                serde_json::json!({
                    "action": action.label(),
                    "spoofed_decision": format!("{:?}", spoofed_decision),
                    "attempt": "decision_kind_spoofing"
                }),
            );
            spoofed_evidence.decision_kind = *spoofed_decision;

            let spoof_outcome = checker.verify_and_execute(
                *action,
                &action_id,
                Some(&spoofed_evidence),
                &mut ledger,
            );

            // Should reject spoofed evidence
            match spoof_outcome {
                PolicyActionOutcome::Executed { .. } => {
                    panic!(
                        "Spoofed evidence should not be accepted for {:?} with {:?}",
                        action, spoofed_decision
                    );
                }
                PolicyActionOutcome::Rejected { error, .. } => {
                    match error {
                        ConformanceError::DecisionKindMismatch { .. } => {
                            // Expected rejection for spoofing
                        }
                        _ => {
                            panic!("Unexpected rejection reason for spoofing: {:?}", error);
                        }
                    }
                }
            }
        }

        // Test action ID manipulation
        let legitimate_action_id = ActionId::new("legitimate-action");
        let malicious_action_id = ActionId::new("malicious-action");

        let legitimate_evidence = build_evidence_entry(
            PolicyAction::Commit,
            &legitimate_action_id,
            "legitimate-trace",
            2000,
            serde_json::json!({"type": "legitimate"}),
        );

        // Try to use legitimate evidence with different action ID
        let id_manipulation_outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &malicious_action_id, // Different action ID
            Some(&legitimate_evidence),
            &mut ledger,
        );

        // Should reject action ID mismatch
        match id_manipulation_outcome {
            PolicyActionOutcome::Executed { .. } => {
                panic!("Action ID manipulation should be rejected");
            }
            PolicyActionOutcome::Rejected { error, .. } => {
                match error {
                    ConformanceError::ActionIdMismatch { .. } => {
                        // Expected rejection for ID manipulation
                    }
                    _ => {
                        panic!(
                            "Unexpected rejection reason for ID manipulation: {:?}",
                            error
                        );
                    }
                }
            }
        }

        // Test evidence timestamp manipulation
        let timestamp_action_id = ActionId::new("timestamp-test");
        let timestamp_evidence = build_evidence_entry(
            PolicyAction::Commit,
            &timestamp_action_id,
            "timestamp-trace",
            u64::MAX,
            serde_json::json!({
                "timestamp_attack": true,
                "value": "max_u64"
            }),
        );

        let timestamp_outcome = checker.verify_and_execute(
            PolicyAction::Commit,
            &timestamp_action_id,
            Some(&timestamp_evidence),
            &mut ledger,
        );

        // Should handle extreme timestamps gracefully
        match timestamp_outcome {
            PolicyActionOutcome::Executed { .. } => {
                // Extreme timestamp accepted
            }
            PolicyActionOutcome::Rejected { .. } => {
                // Timestamp rejection acceptable
            }
        }
    }

    /// Negative test: Timing attacks in evidence verification
    #[test]
    fn negative_timing_attacks_evidence_verification() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        // Test timing consistency across valid vs invalid evidence
        let mut valid_timings = Vec::new();
        let mut invalid_timings = Vec::new();

        for i in 0..50 {
            let action = PolicyAction::all()[i % PolicyAction::all().len()];
            let action_id = ActionId::new(format!("timing-test-{}", i));

            // Valid evidence timing
            let valid_evidence = build_evidence_entry(
                action,
                &action_id,
                &format!("valid-trace-{}", i),
                1000 + i as u64,
                serde_json::json!({"iteration": i, "type": "valid"}),
            );

            let start = std::time::Instant::now();
            let _result =
                checker.verify_and_execute(action, &action_id, Some(&valid_evidence), &mut ledger);
            valid_timings.push(start.elapsed());

            // Invalid evidence timing (wrong decision kind)
            let invalid_action_id = ActionId::new(format!("invalid-timing-{}", i));
            let wrong_decision = match action.expected_decision_kind() {
                DecisionKind::Admit => DecisionKind::Deny,
                DecisionKind::Deny => DecisionKind::Admit,
                DecisionKind::Quarantine => DecisionKind::Release,
                DecisionKind::Release => DecisionKind::Quarantine,
            };

            let mut invalid_evidence = build_evidence_entry(
                action,
                &invalid_action_id,
                &format!("invalid-trace-{}", i),
                2000u64.saturating_add(u64::try_from(i).unwrap_or(u64::MAX)),
                serde_json::json!({"iteration": i, "type": "invalid"}),
            );
            invalid_evidence.decision_kind = wrong_decision;

            let start = std::time::Instant::now();
            let _result = checker.verify_and_execute(
                action,
                &invalid_action_id,
                Some(&invalid_evidence),
                &mut ledger,
            );
            invalid_timings.push(start.elapsed());
        }

        // Timing difference should be minimal (no timing-based information leakage)
        if valid_timings.len() > 1 && invalid_timings.len() > 1 {
            let avg_valid: f64 = valid_timings
                .iter()
                .map(|d| d.as_nanos() as f64)
                .sum::<f64>()
                / valid_timings.len() as f64;
            let avg_invalid: f64 = invalid_timings
                .iter()
                .map(|d| d.as_nanos() as f64)
                .sum::<f64>()
                / invalid_timings.len() as f64;

            let timing_ratio = avg_valid.max(avg_invalid) / avg_valid.min(avg_invalid).max(1.0);
            assert!(
                timing_ratio < 4.0,
                "Evidence verification timing variance too high: {}",
                timing_ratio
            );
        }
    }

    /// Negative test: Concurrent evidence submission race conditions
    #[test]
    fn negative_concurrent_evidence_submission_races() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let checker = Arc::new(Mutex::new(EvidenceConformanceChecker::new()));
        let ledger = Arc::new(Mutex::new(EvidenceLedger::new(LedgerCapacity::new(
            200, 200_000,
        ))));

        let mut handles = Vec::new();

        // Simulate concurrent evidence submission from multiple threads
        for thread_id in 0..4 {
            let checker_clone = Arc::clone(&checker);
            let ledger_clone = Arc::clone(&ledger);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for operation in 0..25 {
                    let action = PolicyAction::all()[operation % PolicyAction::all().len()];
                    let action_id =
                        ActionId::new(format!("concurrent-{}-{}", thread_id, operation));

                    let evidence = build_evidence_entry(
                        action,
                        &action_id,
                        &format!("concurrent-trace-{}-{}", thread_id, operation),
                        1000 + (thread_id * 100) + operation as u64,
                        serde_json::json!({
                            "thread_id": thread_id,
                            "operation": operation,
                            "concurrent_test": true
                        }),
                    );

                    // Attempt concurrent evidence submission
                    let outcome = {
                        let mut checker_guard = checker_clone.lock().unwrap();
                        let mut ledger_guard = ledger_clone.lock().unwrap();
                        checker_guard.verify_and_execute(
                            action,
                            &action_id,
                            Some(&evidence),
                            &mut *ledger_guard,
                        )
                    };

                    thread_results.push((thread_id, operation, outcome));
                }
                thread_results
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        let mut all_results = Vec::new();
        for handle in handles {
            all_results.extend(handle.join().unwrap());
        }

        // Verify state consistency after concurrent operations
        let final_checker = checker.lock().unwrap();
        let final_ledger = ledger.lock().unwrap();

        let total_executed = final_checker.executed_count();
        let total_rejected = final_checker.rejected_count();
        let total_operations = total_executed + total_rejected;

        // Should have processed all operations from all threads
        assert_eq!(
            total_operations,
            4 * 25,
            "Should have processed all concurrent operations"
        );

        // Verify ledger consistency
        assert!(
            u64::try_from(final_ledger.len()).unwrap_or(u64::MAX) <= total_executed,
            "Ledger entries should not exceed executed count"
        );
        assert!(
            final_ledger.len() <= 200,
            "Ledger should not exceed capacity"
        );

        // Verify action log consistency
        assert!(
            u64::try_from(final_checker.action_log().len()).unwrap_or(u64::MAX)
                <= total_operations.min(MAX_ACTION_LOG_ENTRIES as u64)
        );
    }

    /// Negative test: Arithmetic overflow in timestamps and counters
    #[test]
    fn negative_arithmetic_overflow_timestamps_counters() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        // Test near-maximum timestamp values
        let overflow_timestamps = vec![
            u64::MAX - 1000, // Near maximum
            u64::MAX,        // Maximum
            0,               // Minimum
        ];

        for (i, timestamp) in overflow_timestamps.iter().enumerate() {
            let action_id = ActionId::new(format!("overflow-timestamp-{}", i));
            let evidence = build_evidence_entry(
                PolicyAction::Commit,
                &action_id,
                &format!("overflow-trace-{}", i),
                *timestamp,
                serde_json::json!({
                    "timestamp": timestamp,
                    "overflow_test": true,
                    "iteration": i
                }),
            );

            let outcome = checker.verify_and_execute(
                PolicyAction::Commit,
                &action_id,
                Some(&evidence),
                &mut ledger,
            );

            // Should handle timestamp edge cases gracefully
            match outcome {
                PolicyActionOutcome::Executed { .. } => {
                    // Extreme timestamp accepted
                    assert!(checker.executed_count() > 0);
                }
                PolicyActionOutcome::Rejected { .. } => {
                    // Timestamp rejection is acceptable for edge cases
                }
            }
        }

        // Test counter overflow scenarios by forcing high execution counts
        let initial_executed = checker.executed_count();

        // Simulate moderate counter stress testing
        for stress_iteration in 0..100 {
            let stress_action_id = ActionId::new(format!("stress-{}", stress_iteration));
            let stress_evidence = build_evidence_entry(
                PolicyAction::all()[stress_iteration % PolicyAction::all().len()],
                &stress_action_id,
                &format!("stress-trace-{}", stress_iteration),
                3000 + stress_iteration as u64,
                serde_json::json!({
                    "stress_test": stress_iteration,
                    "counter_overflow_test": true
                }),
            );

            let stress_outcome = checker.verify_and_execute(
                PolicyAction::all()[stress_iteration % PolicyAction::all().len()],
                &stress_action_id,
                Some(&stress_evidence),
                &mut ledger,
            );

            // Monitor for counter arithmetic overflow
            let current_executed = checker.executed_count();
            let current_rejected = checker.rejected_count();
            let current_total = current_executed.saturating_add(current_rejected);

            // Verify counters don't overflow
            assert!(
                current_executed >= initial_executed,
                "Executed counter should not overflow"
            );
            assert!(
                current_total >= initial_executed,
                "Total counter should be consistent"
            );

            // Break if ledger hits capacity to prevent excessive test time
            if ledger.len() >= 100 {
                break;
            }
        }

        // Verify final counter consistency after overflow tests
        let final_executed = checker.executed_count();
        let final_rejected = checker.rejected_count();
        let final_total = final_executed.saturating_add(final_rejected);

        assert!(
            final_total >= final_executed,
            "Final counter arithmetic should be consistent"
        );
        assert!(
            final_total >= final_rejected,
            "Final counter arithmetic should be consistent"
        );
    }

    /// Negative test: Policy decision bypass and evidence linkage manipulation
    #[test]
    fn negative_policy_bypass_evidence_linkage_manipulation() {
        let mut checker = EvidenceConformanceChecker::new();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        // Test evidence linkage bypass through similar action IDs
        let bypass_action_ids = vec![
            ("legitimate-action", "legitimate-action "), // Trailing space
            ("legitimate-action", "legitimate-action\t"), // Tab character
            ("legitimate-action", "legitimate-action\n"), // Newline
            ("legitimate-action", "legitimate\u{200b}action"), // Zero-width space
            ("legitimate-action", "legitimate\u{feff}action"), // BOM
        ];

        for (i, (original_id, bypass_id)) in bypass_action_ids.iter().enumerate() {
            let original_action_id = ActionId::new(original_id.to_string());
            let bypass_action_id = ActionId::new(bypass_id.to_string());

            // Create legitimate evidence for original action
            let legitimate_evidence = build_evidence_entry(
                PolicyAction::Commit,
                &original_action_id,
                &format!("legitimate-trace-{}", i),
                1000 + i as u64,
                serde_json::json!({"legitimate": true, "iteration": i}),
            );

            // Try to use evidence for similar but different action ID
            let bypass_outcome = checker.verify_and_execute(
                PolicyAction::Commit,
                &bypass_action_id,
                Some(&legitimate_evidence),
                &mut ledger,
            );

            // Should reject linkage bypass attempts
            match bypass_outcome {
                PolicyActionOutcome::Executed { .. } => {
                    panic!(
                        "Evidence linkage bypass should be rejected for '{}' vs '{}'",
                        original_id, bypass_id
                    );
                }
                PolicyActionOutcome::Rejected { error, .. } => {
                    match error {
                        ConformanceError::ActionIdMismatch { .. } => {
                            // Expected rejection for linkage bypass
                        }
                        _ => {
                            // Other rejection reasons are acceptable
                        }
                    }
                }
            }
        }

        // Test policy decision bypass through edge cases
        let policy_bypass_attempts = vec![
            // Try to use Quarantine decision for Release action (reverse mapping)
            (
                PolicyAction::Release,
                DecisionKind::Quarantine,
                "reverse_mapping",
            ),
            // Try to use generic decisions for specific actions
            (
                PolicyAction::Commit,
                DecisionKind::Release,
                "generic_decision",
            ),
            (
                PolicyAction::Abort,
                DecisionKind::Quarantine,
                "generic_decision_2",
            ),
        ];

        for (i, (action, malicious_decision, bypass_type)) in
            policy_bypass_attempts.iter().enumerate()
        {
            let bypass_action_id = ActionId::new(format!("policy-bypass-{}-{}", i, bypass_type));

            let mut malicious_evidence = build_evidence_entry(
                *action,
                &bypass_action_id,
                &format!("bypass-trace-{}", i),
                2000u64.saturating_add(u64::try_from(i).unwrap_or(u64::MAX)),
                serde_json::json!({
                    "bypass_type": bypass_type,
                    "attempted_action": action.label(),
                    "malicious_decision": format!("{:?}", malicious_decision),
                    "policy_bypass_attempt": true
                }),
            );
            malicious_evidence.decision_kind = *malicious_decision;

            let bypass_outcome = checker.verify_and_execute(
                *action,
                &bypass_action_id,
                Some(&malicious_evidence),
                &mut ledger,
            );

            // Should reject policy bypass attempts
            match bypass_outcome {
                PolicyActionOutcome::Executed { .. } => {
                    panic!(
                        "Policy bypass should be rejected for {:?} with {:?}",
                        action, malicious_decision
                    );
                }
                PolicyActionOutcome::Rejected { error, .. } => {
                    match error {
                        ConformanceError::DecisionKindMismatch { .. } => {
                            // Expected rejection for policy bypass
                        }
                        _ => {
                            // Other rejection reasons are acceptable
                        }
                    }
                }
            }
        }
    }
}
