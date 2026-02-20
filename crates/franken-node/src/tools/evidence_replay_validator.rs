//! bd-2ona: Evidence-ledger replay validator that reproduces chosen actions
//! from captured inputs.
//!
//! Offline tool that takes a captured `EvidenceEntry` (with decision context)
//! and re-executes the decision logic to confirm the outcome matches. Closes
//! the loop from "we recorded decisions" to "we can prove decisions were
//! deterministic."
//!
//! # Invariants
//!
//! - INV-REPLAY-DETERMINISTIC: identical inputs always produce identical results
//! - INV-REPLAY-COMPLETE: all DecisionKind variants have replay coverage
//! - INV-REPLAY-INDEPENDENT: replay has no wall-clock or random state dependency

use std::fmt;

use crate::observability::evidence_ledger::{DecisionKind, EvidenceEntry};

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const REPLAY_START: &str = "EVD-REPLAY-001";
    pub const REPLAY_MATCH: &str = "EVD-REPLAY-002";
    pub const REPLAY_MISMATCH: &str = "EVD-REPLAY-003";
    pub const REPLAY_UNRESOLVABLE: &str = "EVD-REPLAY-004";
}

// ── ActionRef ────────────────────────────────────────────────────────

/// Reference to a specific action for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRef {
    pub decision_kind: String,
    pub decision_id: String,
    pub epoch_id: u64,
}

impl ActionRef {
    pub fn from_entry(entry: &EvidenceEntry) -> Self {
        Self {
            decision_kind: entry.decision_kind.label().to_string(),
            decision_id: entry.decision_id.clone(),
            epoch_id: entry.epoch_id,
        }
    }
}

impl fmt::Display for ActionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "ActionRef(kind={}, id={}, epoch={})",
            self.decision_kind, self.decision_id, self.epoch_id
        )
    }
}

// ── Candidate / Constraint ───────────────────────────────────────────

/// A candidate action that was considered during the decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub id: String,
    pub decision_kind: DecisionKind,
    pub score: f64,
    pub metadata: serde_json::Value,
}

/// A constraint that was active during the decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Constraint {
    pub id: String,
    pub description: String,
    /// Whether this constraint was satisfied by the chosen action.
    pub satisfied: bool,
}

// ── ReplayContext ─────────────────────────────────────────────────────

/// Context needed to replay a decision. Contains the frozen state at
/// the entry's epoch: candidates, constraints, and policy snapshot.
#[derive(Debug, Clone)]
pub struct ReplayContext {
    /// The candidates that were considered.
    pub candidates: Vec<Candidate>,
    /// The constraints that were active.
    pub constraints: Vec<Constraint>,
    /// The epoch at which the decision was made.
    pub epoch_id: u64,
    /// Policy snapshot identifier (opaque to the validator).
    pub policy_snapshot_id: String,
}

impl ReplayContext {
    pub fn new(
        candidates: Vec<Candidate>,
        constraints: Vec<Constraint>,
        epoch_id: u64,
        policy_snapshot_id: impl Into<String>,
    ) -> Self {
        Self {
            candidates,
            constraints,
            epoch_id,
            policy_snapshot_id: policy_snapshot_id.into(),
        }
    }

    /// Check if context is minimally valid for replay.
    pub fn is_valid(&self) -> bool {
        !self.candidates.is_empty() && !self.policy_snapshot_id.is_empty()
    }
}

// ── ReplayDiff ───────────────────────────────────────────────────────

/// Minimal, human-readable diff between expected and actual outcomes.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayDiff {
    pub fields: Vec<DiffField>,
}

/// A single field that diverged.
#[derive(Debug, Clone, PartialEq)]
pub struct DiffField {
    pub field_name: String,
    pub expected: String,
    pub actual: String,
}

impl ReplayDiff {
    pub fn new() -> Self {
        Self { fields: Vec::new() }
    }

    pub fn add(&mut self, field_name: impl Into<String>, expected: impl Into<String>, actual: impl Into<String>) {
        self.fields.push(DiffField {
            field_name: field_name.into(),
            expected: expected.into(),
            actual: actual.into(),
        });
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

impl Default for ReplayDiff {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ReplayDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for field in &self.fields {
            writeln!(
                f, "  {} expected={} actual={}",
                field.field_name, field.expected, field.actual
            )?;
        }
        Ok(())
    }
}

// ── ReplayResult ─────────────────────────────────────────────────────

/// Result of replaying an evidence entry.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplayResult {
    /// The replay matched the recorded decision.
    Match,
    /// The replay produced a different outcome.
    Mismatch {
        expected: ActionRef,
        got: ActionRef,
        diff: ReplayDiff,
    },
    /// The replay could not be completed (missing context).
    Unresolvable { reason: String },
}

impl ReplayResult {
    /// Event code for structured logging.
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Match => event_codes::REPLAY_MATCH,
            Self::Mismatch { .. } => event_codes::REPLAY_MISMATCH,
            Self::Unresolvable { .. } => event_codes::REPLAY_UNRESOLVABLE,
        }
    }

    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }

    pub fn is_mismatch(&self) -> bool {
        matches!(self, Self::Mismatch { .. })
    }

    pub fn is_unresolvable(&self) -> bool {
        matches!(self, Self::Unresolvable { .. })
    }
}

impl fmt::Display for ReplayResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Match => write!(f, "MATCH"),
            Self::Mismatch { expected, got, diff } => {
                write!(f, "MISMATCH: expected={}, got={}\n{}", expected, got, diff)
            }
            Self::Unresolvable { reason } => write!(f, "UNRESOLVABLE: {reason}"),
        }
    }
}

// ── Decision replay logic ────────────────────────────────────────────

/// Re-execute the decision logic: pick the highest-scoring candidate
/// that satisfies all constraints and matches the epoch.
///
/// This is a deterministic, stateless function with no wall-clock or
/// random state dependency.
fn replay_decision(context: &ReplayContext) -> Option<(DecisionKind, String)> {
    let mut best: Option<(&Candidate, f64)> = None;

    // If any constraint is unsatisfied, no candidate can be selected
    let all_satisfied = context.constraints.iter().all(|c| c.satisfied);
    if !all_satisfied {
        return None;
    }

    for candidate in &context.candidates {
        match &best {
            None => best = Some((candidate, candidate.score)),
            Some((_, best_score)) => {
                if candidate.score > *best_score {
                    best = Some((candidate, candidate.score));
                }
            }
        }
    }

    best.map(|(c, _)| (c.decision_kind, c.id.clone()))
}

// ── EvidenceReplayValidator ──────────────────────────────────────────

/// Offline replay validator for evidence entries.
///
/// INV-REPLAY-DETERMINISTIC: identical inputs produce identical results.
/// INV-REPLAY-COMPLETE: covers all DecisionKind variants.
/// INV-REPLAY-INDEPENDENT: no wall-clock or random dependency.
#[derive(Debug)]
pub struct EvidenceReplayValidator {
    total_validations: u64,
    match_count: u64,
    mismatch_count: u64,
    unresolvable_count: u64,
    results: Vec<(String, ReplayResult)>,
}

impl EvidenceReplayValidator {
    pub fn new() -> Self {
        Self {
            total_validations: 0,
            match_count: 0,
            mismatch_count: 0,
            unresolvable_count: 0,
            results: Vec::new(),
        }
    }

    pub fn total_validations(&self) -> u64 { self.total_validations }
    pub fn match_count(&self) -> u64 { self.match_count }
    pub fn mismatch_count(&self) -> u64 { self.mismatch_count }
    pub fn unresolvable_count(&self) -> u64 { self.unresolvable_count }
    pub fn results(&self) -> &[(String, ReplayResult)] { &self.results }

    /// Validate a single evidence entry against its replay context.
    pub fn validate(&mut self, entry: &EvidenceEntry, context: &ReplayContext) -> ReplayResult {
        eprintln!(
            "{}: entry_id={}, epoch_id={}, decision_kind={}",
            event_codes::REPLAY_START, entry.decision_id, entry.epoch_id, entry.decision_kind.label()
        );

        self.total_validations += 1;

        // Check context validity
        if !context.is_valid() {
            let result = ReplayResult::Unresolvable {
                reason: "context is invalid: empty candidates or missing policy snapshot".into(),
            };
            eprintln!("{}: entry_id={}, reason=invalid context", event_codes::REPLAY_UNRESOLVABLE, entry.decision_id);
            self.unresolvable_count += 1;
            self.results.push((entry.decision_id.clone(), result.clone()));
            return result;
        }

        // Check epoch consistency
        if entry.epoch_id != context.epoch_id {
            let result = ReplayResult::Unresolvable {
                reason: format!("epoch mismatch: entry epoch {} != context epoch {}", entry.epoch_id, context.epoch_id),
            };
            eprintln!("{}: entry_id={}, reason=epoch mismatch", event_codes::REPLAY_UNRESOLVABLE, entry.decision_id);
            self.unresolvable_count += 1;
            self.results.push((entry.decision_id.clone(), result.clone()));
            return result;
        }

        // Replay the decision
        let replayed = replay_decision(context);

        let result = match replayed {
            Some((kind, candidate_id)) => {
                let expected_ref = ActionRef::from_entry(entry);
                let got_ref = ActionRef {
                    decision_kind: kind.label().to_string(),
                    decision_id: candidate_id.clone(),
                    epoch_id: context.epoch_id,
                };

                if expected_ref.decision_kind == got_ref.decision_kind
                    && expected_ref.decision_id == got_ref.decision_id
                {
                    eprintln!("{}: entry_id={}, decision_kind={}", event_codes::REPLAY_MATCH, entry.decision_id, entry.decision_kind.label());
                    ReplayResult::Match
                } else {
                    let mut diff = ReplayDiff::new();
                    if expected_ref.decision_kind != got_ref.decision_kind {
                        diff.add("decision_kind", &expected_ref.decision_kind, &got_ref.decision_kind);
                    }
                    if expected_ref.decision_id != got_ref.decision_id {
                        diff.add("decision_id", &expected_ref.decision_id, &got_ref.decision_id);
                    }
                    eprintln!("{}: entry_id={}, diff_fields={}", event_codes::REPLAY_MISMATCH, entry.decision_id, diff.field_count());
                    ReplayResult::Mismatch { expected: expected_ref, got: got_ref, diff }
                }
            }
            None => {
                // No candidate selected — Deny/Rollback may be expected to have no winner
                if entry.decision_kind == DecisionKind::Deny || entry.decision_kind == DecisionKind::Rollback {
                    eprintln!("{}: entry_id={}, decision_kind={} (no candidate expected)", event_codes::REPLAY_MATCH, entry.decision_id, entry.decision_kind.label());
                    ReplayResult::Match
                } else {
                    let mut diff = ReplayDiff::new();
                    diff.add("selected_candidate", &entry.decision_id, "none (no candidate selected)");
                    let expected_ref = ActionRef::from_entry(entry);
                    let got_ref = ActionRef { decision_kind: "none".into(), decision_id: "none".into(), epoch_id: context.epoch_id };
                    eprintln!("{}: entry_id={}, no candidate selected", event_codes::REPLAY_MISMATCH, entry.decision_id);
                    ReplayResult::Mismatch { expected: expected_ref, got: got_ref, diff }
                }
            }
        };

        match &result {
            ReplayResult::Match => self.match_count += 1,
            ReplayResult::Mismatch { .. } => self.mismatch_count += 1,
            ReplayResult::Unresolvable { .. } => self.unresolvable_count += 1,
        }
        self.results.push((entry.decision_id.clone(), result.clone()));
        result
    }

    /// Validate a batch of entries.
    pub fn validate_batch(&mut self, entries: &[(EvidenceEntry, ReplayContext)]) -> Vec<ReplayResult> {
        entries.iter().map(|(entry, ctx)| self.validate(entry, ctx)).collect()
    }

    /// Generate a summary report.
    pub fn summary_report(&self) -> ReplaySummary {
        ReplaySummary {
            total: self.total_validations,
            matches: self.match_count,
            mismatches: self.mismatch_count,
            unresolvable: self.unresolvable_count,
        }
    }
}

impl Default for EvidenceReplayValidator {
    fn default() -> Self { Self::new() }
}

/// Summary of replay validation results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaySummary {
    pub total: u64,
    pub matches: u64,
    pub mismatches: u64,
    pub unresolvable: u64,
}

impl ReplaySummary {
    pub fn all_match(&self) -> bool {
        self.mismatches == 0 && self.unresolvable == 0 && self.total > 0
    }
}

impl fmt::Display for ReplaySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Replay: total={}, match={}, mismatch={}, unresolvable={}", self.total, self.matches, self.mismatches, self.unresolvable)
    }
}

// ── Test helpers ─────────────────────────────────────────────────────

/// Create a test entry with the given parameters.
pub fn test_replay_entry(decision_id: &str, kind: DecisionKind, epoch_id: u64) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: decision_id.to_string(),
        decision_kind: kind,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: epoch_id * 1000,
        trace_id: format!("trace-{decision_id}"),
        epoch_id,
        payload: serde_json::json!({}),
        size_bytes: 0,
    }
}

/// Create a matching context for an entry (will produce Match).
pub fn matching_context(entry: &EvidenceEntry) -> ReplayContext {
    ReplayContext::new(
        vec![Candidate {
            id: entry.decision_id.clone(),
            decision_kind: entry.decision_kind,
            score: 1.0,
            metadata: serde_json::json!({}),
        }],
        vec![Constraint { id: "default".into(), description: "default constraint".into(), satisfied: true }],
        entry.epoch_id,
        "policy-snapshot-001",
    )
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ActionRef tests ──

    #[test]
    fn action_ref_from_entry() {
        let entry = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let aref = ActionRef::from_entry(&entry);
        assert_eq!(aref.decision_kind, "admit");
        assert_eq!(aref.decision_id, "DEC-001");
        assert_eq!(aref.epoch_id, 1);
    }

    #[test]
    fn action_ref_display() {
        let aref = ActionRef { decision_kind: "admit".into(), decision_id: "DEC-001".into(), epoch_id: 1 };
        assert!(aref.to_string().contains("DEC-001"));
    }

    // ── ReplayDiff tests ──

    #[test]
    fn replay_diff_empty() {
        let diff = ReplayDiff::new();
        assert!(diff.is_empty());
        assert_eq!(diff.field_count(), 0);
    }

    #[test]
    fn replay_diff_single_field() {
        let mut diff = ReplayDiff::new();
        diff.add("decision_kind", "admit", "deny");
        assert!(!diff.is_empty());
        assert_eq!(diff.field_count(), 1);
        assert!(diff.to_string().contains("decision_kind"));
    }

    #[test]
    fn replay_diff_multiple_fields() {
        let mut diff = ReplayDiff::new();
        diff.add("decision_kind", "admit", "deny");
        diff.add("decision_id", "DEC-001", "DEC-002");
        assert_eq!(diff.field_count(), 2);
    }

    // ── ReplayResult tests ──

    #[test]
    fn replay_result_match() {
        let r = ReplayResult::Match;
        assert!(r.is_match());
        assert!(!r.is_mismatch());
        assert_eq!(r.event_code(), "EVD-REPLAY-002");
    }

    #[test]
    fn replay_result_mismatch() {
        let r = ReplayResult::Mismatch {
            expected: ActionRef { decision_kind: "admit".into(), decision_id: "DEC-001".into(), epoch_id: 1 },
            got: ActionRef { decision_kind: "deny".into(), decision_id: "DEC-001".into(), epoch_id: 1 },
            diff: ReplayDiff::new(),
        };
        assert!(r.is_mismatch());
        assert_eq!(r.event_code(), "EVD-REPLAY-003");
    }

    #[test]
    fn replay_result_unresolvable() {
        let r = ReplayResult::Unresolvable { reason: "missing context".into() };
        assert!(r.is_unresolvable());
        assert_eq!(r.event_code(), "EVD-REPLAY-004");
    }

    #[test]
    fn replay_result_display() {
        assert_eq!(ReplayResult::Match.to_string(), "MATCH");
        let r = ReplayResult::Unresolvable { reason: "test".into() };
        assert!(r.to_string().contains("UNRESOLVABLE"));
    }

    // ── ReplayContext tests ──

    #[test]
    fn replay_context_valid() {
        let ctx = ReplayContext::new(
            vec![Candidate { id: "c1".into(), decision_kind: DecisionKind::Admit, score: 1.0, metadata: serde_json::json!({}) }],
            vec![], 1, "snap-001",
        );
        assert!(ctx.is_valid());
    }

    #[test]
    fn replay_context_invalid_empty_candidates() {
        let ctx = ReplayContext::new(vec![], vec![], 1, "snap-001");
        assert!(!ctx.is_valid());
    }

    #[test]
    fn replay_context_invalid_empty_snapshot() {
        let ctx = ReplayContext::new(
            vec![Candidate { id: "c1".into(), decision_kind: DecisionKind::Admit, score: 1.0, metadata: serde_json::json!({}) }],
            vec![], 1, "",
        );
        assert!(!ctx.is_valid());
    }

    // ── EvidenceReplayValidator: Match cases ──

    #[test]
    fn validate_admit_match() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = matching_context(&e);
        assert!(v.validate(&e, &c).is_match());
        assert_eq!(v.match_count(), 1);
    }

    #[test]
    fn validate_deny_match() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-002", DecisionKind::Deny, 1);
        let c = ReplayContext::new(
            vec![Candidate { id: "other".into(), decision_kind: DecisionKind::Admit, score: 0.5, metadata: serde_json::json!({}) }],
            vec![Constraint { id: "c1".into(), description: "blocked".into(), satisfied: false }],
            1, "snap-001",
        );
        assert!(v.validate(&e, &c).is_match());
    }

    #[test]
    fn validate_quarantine_match() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-003", DecisionKind::Quarantine, 1);
        let c = matching_context(&e);
        assert!(v.validate(&e, &c).is_match());
    }

    #[test]
    fn validate_release_match() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-004", DecisionKind::Release, 1);
        let c = matching_context(&e);
        assert!(v.validate(&e, &c).is_match());
    }

    #[test]
    fn validate_rollback_match() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-005", DecisionKind::Rollback, 1);
        let c = ReplayContext::new(
            vec![Candidate { id: "x".into(), decision_kind: DecisionKind::Admit, score: 0.5, metadata: serde_json::json!({}) }],
            vec![Constraint { id: "c1".into(), description: "blocked".into(), satisfied: false }],
            1, "snap-001",
        );
        assert!(v.validate(&e, &c).is_match());
    }

    #[test]
    fn validate_throttle_match() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-006", DecisionKind::Throttle, 1);
        let c = matching_context(&e);
        assert!(v.validate(&e, &c).is_match());
    }

    #[test]
    fn validate_escalate_match() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-007", DecisionKind::Escalate, 1);
        let c = matching_context(&e);
        assert!(v.validate(&e, &c).is_match());
    }

    // ── Mismatch cases ──

    #[test]
    fn validate_decision_kind_mismatch() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = ReplayContext::new(
            vec![Candidate { id: "DEC-001".into(), decision_kind: DecisionKind::Deny, score: 1.0, metadata: serde_json::json!({}) }],
            vec![Constraint { id: "c1".into(), description: "ok".into(), satisfied: true }],
            1, "snap-001",
        );
        let result = v.validate(&e, &c);
        assert!(result.is_mismatch());
        if let ReplayResult::Mismatch { diff, .. } = &result {
            assert!(!diff.is_empty());
        }
    }

    #[test]
    fn validate_decision_id_mismatch() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = ReplayContext::new(
            vec![
                Candidate { id: "DEC-001".into(), decision_kind: DecisionKind::Admit, score: 0.5, metadata: serde_json::json!({}) },
                Candidate { id: "DEC-999".into(), decision_kind: DecisionKind::Admit, score: 1.0, metadata: serde_json::json!({}) },
            ],
            vec![Constraint { id: "c1".into(), description: "ok".into(), satisfied: true }],
            1, "snap-001",
        );
        let result = v.validate(&e, &c);
        assert!(result.is_mismatch());
        assert_eq!(v.mismatch_count(), 1);
    }

    // ── Unresolvable cases ──

    #[test]
    fn validate_invalid_context_unresolvable() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = ReplayContext::new(vec![], vec![], 1, "snap-001");
        assert!(v.validate(&e, &c).is_unresolvable());
        assert_eq!(v.unresolvable_count(), 1);
    }

    #[test]
    fn validate_epoch_mismatch_unresolvable() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = ReplayContext::new(
            vec![Candidate { id: "DEC-001".into(), decision_kind: DecisionKind::Admit, score: 1.0, metadata: serde_json::json!({}) }],
            vec![], 999, "snap-001",
        );
        assert!(v.validate(&e, &c).is_unresolvable());
    }

    // ── Determinism ──

    #[test]
    fn determinism_identical_runs() {
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = matching_context(&e);
        let mut v1 = EvidenceReplayValidator::new();
        let mut v2 = EvidenceReplayValidator::new();
        assert_eq!(v1.validate(&e, &c), v2.validate(&e, &c));
    }

    #[test]
    fn determinism_100_runs() {
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = matching_context(&e);
        let mut first: Option<ReplayResult> = None;
        for _ in 0..100 {
            let mut v = EvidenceReplayValidator::new();
            let r = v.validate(&e, &c);
            match &first {
                None => first = Some(r),
                Some(expected) => assert_eq!(&r, expected, "non-deterministic replay"),
            }
        }
    }

    // ── Batch validation ──

    #[test]
    fn validate_batch() {
        let mut v = EvidenceReplayValidator::new();
        let entries: Vec<(EvidenceEntry, ReplayContext)> = vec![
            { let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1); let c = matching_context(&e); (e, c) },
            { let e = test_replay_entry("DEC-002", DecisionKind::Quarantine, 1); let c = matching_context(&e); (e, c) },
        ];
        let results = v.validate_batch(&entries);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_match()));
        assert_eq!(v.total_validations(), 2);
    }

    // ── Summary ──

    #[test]
    fn summary_report() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = matching_context(&e);
        v.validate(&e, &c);
        let summary = v.summary_report();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.matches, 1);
        assert!(summary.all_match());
    }

    #[test]
    fn summary_not_all_match() {
        let mut v = EvidenceReplayValidator::new();
        let e = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let c = ReplayContext::new(vec![], vec![], 1, "snap-001");
        v.validate(&e, &c);
        assert!(!v.summary_report().all_match());
    }

    #[test]
    fn summary_display() {
        let s = ReplaySummary { total: 10, matches: 8, mismatches: 1, unresolvable: 1 };
        assert!(s.to_string().contains("10"));
        assert!(s.to_string().contains("mismatch=1"));
    }

    // ── Results log ──

    #[test]
    fn results_log_accumulates() {
        let mut v = EvidenceReplayValidator::new();
        let e1 = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        v.validate(&e1, &matching_context(&e1));
        let e2 = test_replay_entry("DEC-002", DecisionKind::Release, 1);
        v.validate(&e2, &matching_context(&e2));
        assert_eq!(v.results().len(), 2);
        assert_eq!(v.results()[0].0, "DEC-001");
        assert_eq!(v.results()[1].0, "DEC-002");
    }

    // ── Default ──

    #[test]
    fn validator_default() {
        let v = EvidenceReplayValidator::default();
        assert_eq!(v.total_validations(), 0);
    }

    // ── Candidate / Constraint ──

    #[test]
    fn candidate_fields() {
        let c = Candidate { id: "c1".into(), decision_kind: DecisionKind::Admit, score: 0.95, metadata: serde_json::json!({"key": "value"}) };
        assert_eq!(c.id, "c1");
        assert_eq!(c.decision_kind, DecisionKind::Admit);
    }

    #[test]
    fn constraint_satisfied() {
        let c = Constraint { id: "constraint-1".into(), description: "memory budget".into(), satisfied: true };
        assert!(c.satisfied);
    }

    // ── All DecisionKind coverage ──

    #[test]
    fn all_decision_kinds_covered() {
        let kinds = [DecisionKind::Admit, DecisionKind::Deny, DecisionKind::Quarantine,
                     DecisionKind::Release, DecisionKind::Rollback, DecisionKind::Throttle, DecisionKind::Escalate];
        let mut v = EvidenceReplayValidator::new();
        for (i, kind) in kinds.iter().enumerate() {
            let e = test_replay_entry(&format!("DEC-{i:03}"), *kind, 1);
            let c = matching_context(&e);
            let result = v.validate(&e, &c);
            assert!(result.is_match(), "kind {:?} did not match: {:?}", kind, result);
        }
        assert_eq!(v.match_count(), 7);
    }
}
