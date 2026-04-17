//! bd-tyr2: Integrate canonical evidence replay validator (from 10.14)
//! into control-plane decision gates.
//!
//! Wires the canonical `EvidenceReplayValidator` into franken_node's
//! control-plane so that every policy-influenced decision can be verified
//! post-hoc. The control-plane gate consumes the validator's verdict and
//! blocks releases where decisions cannot be replayed.
//!
//! # Invariants
//!
//! - **INV-CRG-CANONICAL**: Uses the 10.14 canonical replay validator (no custom logic).
//! - **INV-CRG-BLOCK-DIVERGED**: DIVERGED/ERROR verdicts block the gate.
//! - **INV-CRG-DETERMINISTIC**: Same inputs produce same verdict.
//! - **INV-CRG-COMPLETE**: All 5 control decision types have replay coverage.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::capacity_defaults::aliases::MAX_EVENTS;
const MAX_VERDICTS: usize = 4096;
const MAX_CANDIDATES: usize = 4096;

use crate::connector::control_evidence::{ControlEvidenceEntry, DecisionKind, DecisionType};
use crate::observability::evidence_ledger::{DecisionKind as LedgerDecisionKind, EvidenceEntry};
use crate::tools::evidence_replay_validator::{
    Candidate, Constraint, EvidenceReplayValidator, ReplayContext, ReplayResult,
};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Replay initiated for a control decision.
    pub const RPL_001_REPLAY_INITIATED: &str = "RPL-001";
    /// Replay produced REPRODUCED verdict.
    pub const RPL_002_REPRODUCED: &str = "RPL-002";
    /// Replay produced DIVERGED verdict (with diff hash).
    pub const RPL_003_DIVERGED: &str = "RPL-003";
    /// Replay produced ERROR verdict.
    pub const RPL_004_ERROR: &str = "RPL-004";
    /// Gate decision based on replay verdict.
    pub const RPL_005_GATE_DECISION: &str = "RPL-005";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_CRG_CANONICAL: &str = "INV-CRG-CANONICAL";
pub const INV_CRG_BLOCK_DIVERGED: &str = "INV-CRG-BLOCK-DIVERGED";
pub const INV_CRG_DETERMINISTIC: &str = "INV-CRG-DETERMINISTIC";
pub const INV_CRG_COMPLETE: &str = "INV-CRG-COMPLETE";

// ---------------------------------------------------------------------------
// Kind mapping
// ---------------------------------------------------------------------------

/// Map `control_evidence::DecisionKind` to `evidence_ledger::DecisionKind`.
pub fn map_to_ledger_kind(kind: DecisionKind) -> LedgerDecisionKind {
    match kind {
        DecisionKind::Admit => LedgerDecisionKind::Admit,
        DecisionKind::Deny => LedgerDecisionKind::Deny,
        DecisionKind::Quarantine => LedgerDecisionKind::Quarantine,
        DecisionKind::Release => LedgerDecisionKind::Release,
        DecisionKind::Rollback => LedgerDecisionKind::Rollback,
        DecisionKind::Throttle => LedgerDecisionKind::Throttle,
        DecisionKind::Escalate => LedgerDecisionKind::Escalate,
    }
}

// ---------------------------------------------------------------------------
// Bridge: ControlEvidenceEntry → EvidenceEntry
// ---------------------------------------------------------------------------

/// Convert a `ControlEvidenceEntry` to the canonical `EvidenceEntry`
/// consumed by the 10.14 replay validator.
pub fn to_ledger_entry(entry: &ControlEvidenceEntry) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: entry.schema_version.clone(),
        entry_id: None,
        decision_id: entry.decision_id.clone(),
        decision_kind: map_to_ledger_kind(entry.decision_kind),
        decision_time: format!("{}ms", entry.timestamp_ms),
        timestamp_ms: entry.timestamp_ms,
        trace_id: entry.trace_id.clone(),
        epoch_id: entry.epoch,
        payload: serde_json::json!({
            "decision_type": entry.decision_type.label(),
            "policy_inputs": entry.policy_inputs,
            "chosen_action": entry.chosen_action,
        }),
        size_bytes: 0,
    }
}

// ---------------------------------------------------------------------------
// Bridge: ControlEvidenceEntry → ReplayContext
// ---------------------------------------------------------------------------

/// Build a `ReplayContext` from a `ControlEvidenceEntry`.
///
/// The chosen candidate (matching `entry.decision_id`) gets score 1.0;
/// other candidates from `entry.candidates_considered` get lower scores.
/// A single satisfied constraint represents the policy gate.
pub fn build_replay_context(
    entry: &ControlEvidenceEntry,
    policy_snapshot_id: &str,
) -> ReplayContext {
    let ledger_kind = map_to_ledger_kind(entry.decision_kind);

    let mut candidates = Vec::new();

    // Primary candidate (the chosen action)
    push_bounded(
        &mut candidates,
        Candidate {
            id: entry.decision_id.clone(),
            decision_kind: ledger_kind,
            score: 1.0,
            metadata: serde_json::json!({
                "chosen_action": entry.chosen_action,
            }),
        },
        MAX_CANDIDATES,
    );

    // Other candidates (lower score, same kind for simplicity)
    for (i, candidate_name) in entry.candidates_considered.iter().enumerate() {
        if *candidate_name != entry.decision_id {
            if candidates.len() >= MAX_CANDIDATES {
                break;
            }
            let raw_score = (0.5 - (i as f64 * 0.01)).max(0.0);
            let score = if raw_score.is_finite() {
                raw_score
            } else {
                0.0
            };
            push_bounded(
                &mut candidates,
                Candidate {
                    id: candidate_name.clone(),
                    decision_kind: ledger_kind,
                    score,
                    metadata: serde_json::json!({}),
                },
                MAX_CANDIDATES,
            );
        }
    }

    let constraints = vec![Constraint {
        id: "policy-gate".into(),
        description: "control-plane policy gate".into(),
        satisfied: true,
    }];

    let policy_snapshot_id =
        if policy_snapshot_id.trim() != policy_snapshot_id || policy_snapshot_id.contains('\0') {
            ""
        } else {
            policy_snapshot_id
        };

    ReplayContext::new(candidates, constraints, entry.epoch, policy_snapshot_id)
}

// ---------------------------------------------------------------------------
// ReplayVerdict
// ---------------------------------------------------------------------------

/// Verdict from replaying a control-plane decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReplayVerdict {
    /// Replay reproduced the same action.
    Reproduced,
    /// Replay produced a different outcome.
    Diverged {
        diff_summary: String,
        diff_field_count: usize,
    },
    /// Replay could not be completed.
    Error { reason: String },
}

impl ReplayVerdict {
    pub fn is_reproduced(&self) -> bool {
        matches!(self, Self::Reproduced)
    }

    pub fn is_diverged(&self) -> bool {
        matches!(self, Self::Diverged { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Reproduced => "REPRODUCED",
            Self::Diverged { .. } => "DIVERGED",
            Self::Error { .. } => "ERROR",
        }
    }
}

impl fmt::Display for ReplayVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reproduced => write!(f, "REPRODUCED"),
            Self::Diverged {
                diff_summary,
                diff_field_count,
            } => {
                write!(
                    f,
                    "DIVERGED ({} fields): {}",
                    diff_field_count, diff_summary
                )
            }
            Self::Error { reason } => write!(f, "ERROR: {}", reason),
        }
    }
}

// ---------------------------------------------------------------------------
// ReplayGateEvent
// ---------------------------------------------------------------------------

/// Structured log event from the replay gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayGateEvent {
    pub code: String,
    pub decision_id: String,
    pub decision_type: String,
    pub verdict: String,
    pub detail: String,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// ReplayGateSummary
// ---------------------------------------------------------------------------

/// Summary of replay gate results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayGateSummary {
    pub total: usize,
    pub reproduced: usize,
    pub diverged: usize,
    pub errors: usize,
}

impl ReplayGateSummary {
    /// Gate passes only when all verdicts are REPRODUCED.
    pub fn gate_pass(&self) -> bool {
        self.diverged == 0 && self.errors == 0 && self.total > 0
    }
}

impl fmt::Display for ReplayGateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReplayGate: total={}, reproduced={}, diverged={}, errors={}",
            self.total, self.reproduced, self.diverged, self.errors
        )
    }
}

// ---------------------------------------------------------------------------
// ControlReplayGate
// ---------------------------------------------------------------------------

/// Control-plane replay gate that wraps the canonical 10.14
/// `EvidenceReplayValidator` and produces verdicts for each
/// policy-influenced decision.
///
/// INV-CRG-CANONICAL: delegates ALL replay logic to the canonical
/// validator — no custom replay logic here.
pub struct ControlReplayGate {
    validator: EvidenceReplayValidator,
    events: Vec<ReplayGateEvent>,
    verdicts: Vec<(String, DecisionType, ReplayVerdict)>,
}

impl ControlReplayGate {
    pub fn new() -> Self {
        Self {
            validator: EvidenceReplayValidator::new(),
            events: Vec::new(),
            verdicts: Vec::new(),
        }
    }

    /// Verify a single control evidence entry using an explicit
    /// replay context.
    pub fn verify(
        &mut self,
        entry: &ControlEvidenceEntry,
        context: &ReplayContext,
    ) -> ReplayVerdict {
        // RPL-001: replay initiated
        self.emit_event(
            event_codes::RPL_001_REPLAY_INITIATED,
            &entry.decision_id,
            entry.decision_type,
            "pending",
            format!("Replay initiated for {}", entry.decision_type.label()),
            &entry.trace_id,
        );

        // Delegate to canonical validator (INV-CRG-CANONICAL)
        let ledger_entry = to_ledger_entry(entry);
        let result = self.validator.validate(&ledger_entry, context);

        // Map canonical ReplayResult → ReplayVerdict
        let verdict = match &result {
            ReplayResult::Match => {
                self.emit_event(
                    event_codes::RPL_002_REPRODUCED,
                    &entry.decision_id,
                    entry.decision_type,
                    "REPRODUCED",
                    format!("Decision {} reproduced successfully", entry.decision_id),
                    &entry.trace_id,
                );
                ReplayVerdict::Reproduced
            }
            ReplayResult::Mismatch { diff, .. } => {
                let diff_summary = diff.to_string();
                let diff_field_count = diff.field_count();
                self.emit_event(
                    event_codes::RPL_003_DIVERGED,
                    &entry.decision_id,
                    entry.decision_type,
                    "DIVERGED",
                    format!(
                        "Decision {} diverged: {} field(s) differ",
                        entry.decision_id, diff_field_count
                    ),
                    &entry.trace_id,
                );
                ReplayVerdict::Diverged {
                    diff_summary,
                    diff_field_count,
                }
            }
            ReplayResult::Unresolvable { reason } => {
                self.emit_event(
                    event_codes::RPL_004_ERROR,
                    &entry.decision_id,
                    entry.decision_type,
                    "ERROR",
                    format!("Replay error for {}: {}", entry.decision_id, reason),
                    &entry.trace_id,
                );
                ReplayVerdict::Error {
                    reason: reason.clone(),
                }
            }
        };

        // RPL-005: gate decision
        let gate_status = if verdict.is_reproduced() {
            "PASS"
        } else {
            "BLOCK"
        };
        self.emit_event(
            event_codes::RPL_005_GATE_DECISION,
            &entry.decision_id,
            entry.decision_type,
            gate_status,
            format!(
                "Gate decision for {}: {} -> {}",
                entry.decision_id,
                verdict.label(),
                gate_status
            ),
            &entry.trace_id,
        );

        let decision_id = entry.decision_id.clone();
        let decision_type = entry.decision_type;
        push_bounded(
            &mut self.verdicts,
            (decision_id, decision_type, verdict.clone()),
            MAX_VERDICTS,
        );
        verdict
    }

    /// Verify using automatically-built context from the entry.
    pub fn verify_from_entry(
        &mut self,
        entry: &ControlEvidenceEntry,
        policy_snapshot_id: &str,
    ) -> ReplayVerdict {
        let context = build_replay_context(entry, policy_snapshot_id);
        self.verify(entry, &context)
    }

    /// Verify a batch of entries with contexts.
    pub fn verify_batch(
        &mut self,
        entries: &[(ControlEvidenceEntry, ReplayContext)],
    ) -> Vec<ReplayVerdict> {
        entries
            .iter()
            .map(|(entry, ctx)| self.verify(entry, ctx))
            .collect()
    }

    /// Check if the gate passes (all verdicts are REPRODUCED).
    pub fn gate_pass(&self) -> bool {
        !self.verdicts.is_empty() && self.verdicts.iter().all(|(_, _, v)| v.is_reproduced())
    }

    /// Summary of replay results.
    pub fn summary(&self) -> ReplayGateSummary {
        ReplayGateSummary {
            total: self.verdicts.len(),
            reproduced: self
                .verdicts
                .iter()
                .filter(|(_, _, v)| v.is_reproduced())
                .count(),
            diverged: self
                .verdicts
                .iter()
                .filter(|(_, _, v)| v.is_diverged())
                .count(),
            errors: self
                .verdicts
                .iter()
                .filter(|(_, _, v)| v.is_error())
                .count(),
        }
    }

    /// All events.
    pub fn events(&self) -> &[ReplayGateEvent] {
        &self.events
    }

    /// Drain and return all events.
    pub fn take_events(&mut self) -> Vec<ReplayGateEvent> {
        std::mem::take(&mut self.events)
    }

    /// All verdicts.
    pub fn verdicts(&self) -> &[(String, DecisionType, ReplayVerdict)] {
        &self.verdicts
    }

    /// Generate a JSON report of per-decision-type replay results.
    pub fn to_report(&self) -> serde_json::Value {
        let mut per_type = serde_json::Map::new();
        for dt in DecisionType::all() {
            let type_verdicts: Vec<_> = self
                .verdicts
                .iter()
                .filter(|(_, t, _)| *t == *dt)
                .map(|(id, _, v)| {
                    serde_json::json!({
                        "decision_id": id,
                        "verdict": v.label(),
                        "detail": v.to_string(),
                    })
                })
                .collect();
            if !type_verdicts.is_empty() {
                per_type.insert(
                    dt.label().to_string(),
                    serde_json::Value::Array(type_verdicts),
                );
            }
        }

        let summary = self.summary();
        serde_json::json!({
            "bead_id": "bd-tyr2",
            "section": "10.15",
            "gate_pass": summary.gate_pass(),
            "summary": {
                "total": summary.total,
                "reproduced": summary.reproduced,
                "diverged": summary.diverged,
                "errors": summary.errors,
            },
            "per_decision_type": per_type,
        })
    }

    fn emit_event(
        &mut self,
        code: &str,
        decision_id: &str,
        decision_type: DecisionType,
        verdict: &str,
        detail: String,
        trace_id: &str,
    ) {
        push_bounded(
            &mut self.events,
            ReplayGateEvent {
                code: code.to_string(),
                decision_id: decision_id.to_string(),
                decision_type: decision_type.label().to_string(),
                verdict: verdict.to_string(),
                detail,
                trace_id: trace_id.to_string(),
            },
            MAX_EVENTS,
        );
    }
}

impl Default for ControlReplayGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Push an item to a bounded Vec, evicting oldest entries if at capacity.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max: usize) {
    if max == 0 {
        vec.clear();
        return;
    }
    if vec.len() >= max {
        let overflow = vec.len() - max + 1;
        vec.drain(0..overflow);
    }
    vec.push(item);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::control_evidence::{DecisionOutcome, map_decision_kind};

    fn make_entry(
        decision_type: DecisionType,
        outcome: DecisionOutcome,
        decision_id: &str,
        ts: u64,
    ) -> ControlEvidenceEntry {
        ControlEvidenceEntry {
            schema_version: "1.0".to_string(),
            decision_id: decision_id.to_string(),
            decision_type,
            decision_kind: map_decision_kind(decision_type, outcome),
            policy_inputs: vec!["input-1".to_string()],
            candidates_considered: vec!["candidate-a".to_string(), "candidate-b".to_string()],
            chosen_action: format!("{:?}", outcome),
            rejection_reasons: vec![],
            epoch: 42,
            trace_id: "trace-001".to_string(),
            timestamp_ms: ts,
        }
    }

    // ── Kind mapping ──────────────────────────────────────────────

    #[test]
    fn test_map_to_ledger_kind_admit() {
        assert_eq!(
            map_to_ledger_kind(DecisionKind::Admit),
            LedgerDecisionKind::Admit
        );
    }

    #[test]
    fn test_map_to_ledger_kind_deny() {
        assert_eq!(
            map_to_ledger_kind(DecisionKind::Deny),
            LedgerDecisionKind::Deny
        );
    }

    #[test]
    fn test_map_to_ledger_kind_quarantine() {
        assert_eq!(
            map_to_ledger_kind(DecisionKind::Quarantine),
            LedgerDecisionKind::Quarantine
        );
    }

    #[test]
    fn test_map_to_ledger_kind_release() {
        assert_eq!(
            map_to_ledger_kind(DecisionKind::Release),
            LedgerDecisionKind::Release
        );
    }

    #[test]
    fn test_map_to_ledger_kind_rollback() {
        assert_eq!(
            map_to_ledger_kind(DecisionKind::Rollback),
            LedgerDecisionKind::Rollback
        );
    }

    #[test]
    fn test_map_to_ledger_kind_throttle() {
        assert_eq!(
            map_to_ledger_kind(DecisionKind::Throttle),
            LedgerDecisionKind::Throttle
        );
    }

    #[test]
    fn test_map_to_ledger_kind_escalate() {
        assert_eq!(
            map_to_ledger_kind(DecisionKind::Escalate),
            LedgerDecisionKind::Escalate
        );
    }

    // ── Bridge: to_ledger_entry ───────────────────────────────────

    #[test]
    fn test_to_ledger_entry_fields() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ledger = to_ledger_entry(&entry);
        assert_eq!(ledger.decision_id, "DEC-001");
        assert_eq!(ledger.decision_kind, LedgerDecisionKind::Admit);
        assert_eq!(ledger.epoch_id, 42);
        assert_eq!(ledger.timestamp_ms, 1000);
        assert_eq!(ledger.trace_id, "trace-001");
        assert_eq!(ledger.schema_version, "1.0");
    }

    #[test]
    fn test_to_ledger_entry_payload() {
        let entry = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-002",
            2000,
        );
        let ledger = to_ledger_entry(&entry);
        assert_eq!(ledger.payload["decision_type"], "fencing_decision");
    }

    // ── Bridge: build_replay_context ──────────────────────────────

    #[test]
    fn test_build_replay_context_has_primary_candidate() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = build_replay_context(&entry, "snap-001");
        assert!(!ctx.candidates.is_empty());
        assert_eq!(ctx.candidates[0].id, "DEC-001");
        assert_eq!(ctx.candidates[0].score, 1.0);
    }

    #[test]
    fn test_build_replay_context_epoch() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = build_replay_context(&entry, "snap-001");
        assert_eq!(ctx.epoch_id, 42);
    }

    #[test]
    fn test_build_replay_context_policy_snapshot() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = build_replay_context(&entry, "snap-xyz");
        assert_eq!(ctx.policy_snapshot_id, "snap-xyz");
    }

    #[test]
    fn test_build_replay_context_is_valid() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = build_replay_context(&entry, "snap-001");
        assert!(ctx.is_valid());
    }

    #[test]
    fn test_build_replay_context_constraint_satisfied() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = build_replay_context(&entry, "snap-001");
        assert!(ctx.constraints.iter().all(|c| c.satisfied));
    }

    // ── ReplayVerdict ─────────────────────────────────────────────

    #[test]
    fn test_verdict_reproduced_label() {
        assert_eq!(ReplayVerdict::Reproduced.label(), "REPRODUCED");
    }

    #[test]
    fn test_verdict_diverged_label() {
        let v = ReplayVerdict::Diverged {
            diff_summary: "x".into(),
            diff_field_count: 1,
        };
        assert_eq!(v.label(), "DIVERGED");
    }

    #[test]
    fn test_verdict_error_label() {
        let v = ReplayVerdict::Error {
            reason: "bad".into(),
        };
        assert_eq!(v.label(), "ERROR");
    }

    #[test]
    fn test_verdict_is_reproduced() {
        assert!(ReplayVerdict::Reproduced.is_reproduced());
        assert!(!ReplayVerdict::Reproduced.is_diverged());
        assert!(!ReplayVerdict::Reproduced.is_error());
    }

    #[test]
    fn test_verdict_is_diverged() {
        let v = ReplayVerdict::Diverged {
            diff_summary: String::new(),
            diff_field_count: 0,
        };
        assert!(v.is_diverged());
        assert!(!v.is_reproduced());
    }

    #[test]
    fn test_verdict_is_error() {
        let v = ReplayVerdict::Error {
            reason: String::new(),
        };
        assert!(v.is_error());
        assert!(!v.is_reproduced());
    }

    #[test]
    fn test_verdict_display_reproduced() {
        assert_eq!(ReplayVerdict::Reproduced.to_string(), "REPRODUCED");
    }

    #[test]
    fn test_verdict_display_diverged() {
        let v = ReplayVerdict::Diverged {
            diff_summary: "kind mismatch".into(),
            diff_field_count: 1,
        };
        assert!(v.to_string().contains("DIVERGED"));
        assert!(v.to_string().contains("1 fields"));
    }

    #[test]
    fn test_verdict_display_error() {
        let v = ReplayVerdict::Error {
            reason: "epoch mismatch".into(),
        };
        assert!(v.to_string().contains("ERROR"));
        assert!(v.to_string().contains("epoch mismatch"));
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        let v = ReplayVerdict::Reproduced;
        let json = serde_json::to_string(&v).unwrap();
        let parsed: ReplayVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn test_verdict_diverged_serde_roundtrip() {
        let v = ReplayVerdict::Diverged {
            diff_summary: "mismatch".into(),
            diff_field_count: 2,
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: ReplayVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, v);
    }

    // ── ReplayGateSummary ─────────────────────────────────────────

    #[test]
    fn test_summary_gate_pass_all_reproduced() {
        let s = ReplayGateSummary {
            total: 5,
            reproduced: 5,
            diverged: 0,
            errors: 0,
        };
        assert!(s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_on_diverged() {
        let s = ReplayGateSummary {
            total: 5,
            reproduced: 4,
            diverged: 1,
            errors: 0,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_on_error() {
        let s = ReplayGateSummary {
            total: 5,
            reproduced: 4,
            diverged: 0,
            errors: 1,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_empty() {
        let s = ReplayGateSummary {
            total: 0,
            reproduced: 0,
            diverged: 0,
            errors: 0,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_display() {
        let s = ReplayGateSummary {
            total: 10,
            reproduced: 8,
            diverged: 1,
            errors: 1,
        };
        let text = s.to_string();
        assert!(text.contains("10"));
        assert!(text.contains("diverged=1"));
    }

    #[test]
    fn test_summary_serde_roundtrip() {
        let s = ReplayGateSummary {
            total: 3,
            reproduced: 2,
            diverged: 1,
            errors: 0,
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: ReplayGateSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, s);
    }

    // ── ControlReplayGate: REPRODUCED per decision type ───────────

    #[test]
    fn test_verify_health_gate_reproduced() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let v = gate.verify_from_entry(&entry, "snap-001");
        assert!(v.is_reproduced());
    }

    #[test]
    fn test_verify_rollout_reproduced() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::RolloutTransition,
            DecisionOutcome::Proceed,
            "DEC-002",
            1000,
        );
        let v = gate.verify_from_entry(&entry, "snap-001");
        assert!(v.is_reproduced());
    }

    #[test]
    fn test_verify_quarantine_reproduced() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::QuarantineAction,
            DecisionOutcome::Promote,
            "DEC-003",
            1000,
        );
        let v = gate.verify_from_entry(&entry, "snap-001");
        assert!(v.is_reproduced());
    }

    #[test]
    fn test_verify_fencing_reproduced() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-004",
            1000,
        );
        let v = gate.verify_from_entry(&entry, "snap-001");
        assert!(v.is_reproduced());
    }

    #[test]
    fn test_verify_migration_reproduced() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::MigrationDecision,
            DecisionOutcome::Proceed,
            "DEC-005",
            1000,
        );
        let v = gate.verify_from_entry(&entry, "snap-001");
        assert!(v.is_reproduced());
    }

    // ── DIVERGED cases ────────────────────────────────────────────

    #[test]
    fn test_verify_mismatch_diverged() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        // Context with a different winning candidate
        let ctx = ReplayContext::new(
            vec![
                Candidate {
                    id: "DEC-001".into(),
                    decision_kind: LedgerDecisionKind::Admit,
                    score: 0.3,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "DEC-999".into(),
                    decision_kind: LedgerDecisionKind::Admit,
                    score: 1.0,
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "c1".into(),
                description: "ok".into(),
                satisfied: true,
            }],
            42,
            "snap-001",
        );
        let v = gate.verify(&entry, &ctx);
        assert!(v.is_diverged());
    }

    #[test]
    fn test_verify_kind_mismatch_diverged() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        // Context produces Deny instead of Admit
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-001".into(),
                decision_kind: LedgerDecisionKind::Deny,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "c1".into(),
                description: "ok".into(),
                satisfied: true,
            }],
            42,
            "snap-001",
        );
        let v = gate.verify(&entry, &ctx);
        assert!(v.is_diverged());
    }

    // ── ERROR cases ───────────────────────────────────────────────

    #[test]
    fn test_verify_invalid_context_error() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = ReplayContext::new(vec![], vec![], 42, "snap-001");
        let v = gate.verify(&entry, &ctx);
        assert!(v.is_error());
    }

    #[test]
    fn test_verify_epoch_mismatch_error() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        // Context has different epoch
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-001".into(),
                decision_kind: LedgerDecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![],
            999,
            "snap-001",
        );
        let v = gate.verify(&entry, &ctx);
        assert!(v.is_error());
    }

    // ── Event emission ────────────────────────────────────────────

    #[test]
    fn test_verify_emits_rpl001() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        gate.verify_from_entry(&entry, "snap-001");
        let rpl001: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::RPL_001_REPLAY_INITIATED)
            .collect();
        assert_eq!(rpl001.len(), 1);
    }

    #[test]
    fn test_verify_reproduced_emits_rpl002() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        gate.verify_from_entry(&entry, "snap-001");
        let rpl002: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::RPL_002_REPRODUCED)
            .collect();
        assert_eq!(rpl002.len(), 1);
    }

    #[test]
    fn test_verify_diverged_emits_rpl003() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-001".into(),
                decision_kind: LedgerDecisionKind::Deny,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "c1".into(),
                description: "ok".into(),
                satisfied: true,
            }],
            42,
            "snap-001",
        );
        gate.verify(&entry, &ctx);
        let rpl003: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::RPL_003_DIVERGED)
            .collect();
        assert_eq!(rpl003.len(), 1);
    }

    #[test]
    fn test_verify_error_emits_rpl004() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = ReplayContext::new(vec![], vec![], 42, "snap-001");
        gate.verify(&entry, &ctx);
        let rpl004: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::RPL_004_ERROR)
            .collect();
        assert_eq!(rpl004.len(), 1);
    }

    #[test]
    fn test_verify_emits_rpl005() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        gate.verify_from_entry(&entry, "snap-001");
        let rpl005: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::RPL_005_GATE_DECISION)
            .collect();
        assert_eq!(rpl005.len(), 1);
        assert_eq!(rpl005[0].verdict, "PASS");
    }

    #[test]
    fn test_verify_block_emits_rpl005_block() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = ReplayContext::new(vec![], vec![], 42, "snap-001");
        gate.verify(&entry, &ctx);
        let rpl005: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::RPL_005_GATE_DECISION)
            .collect();
        assert_eq!(rpl005[0].verdict, "BLOCK");
    }

    // ── Gate pass/fail ────────────────────────────────────────────

    #[test]
    fn test_gate_pass_all_reproduced() {
        let mut gate = ControlReplayGate::new();
        for (i, dt) in DecisionType::all().iter().enumerate() {
            let outcome = match dt {
                DecisionType::QuarantineAction => DecisionOutcome::Promote,
                DecisionType::FencingDecision => DecisionOutcome::Grant,
                _ => DecisionOutcome::Pass,
            };
            let entry = make_entry(*dt, outcome, &format!("DEC-{i:03}"), (i as u64 + 1) * 100);
            gate.verify_from_entry(&entry, "snap-001");
        }
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_gate_fail_on_diverged() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        gate.verify_from_entry(&entry, "snap-001");
        // Now inject a diverged entry
        let entry2 = make_entry(
            DecisionType::RolloutTransition,
            DecisionOutcome::Proceed,
            "DEC-002",
            2000,
        );
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-002".into(),
                decision_kind: LedgerDecisionKind::Deny,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "c1".into(),
                description: "ok".into(),
                satisfied: true,
            }],
            42,
            "snap-001",
        );
        gate.verify(&entry2, &ctx);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_fail_on_error() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = ReplayContext::new(vec![], vec![], 42, "snap-001");
        gate.verify(&entry, &ctx);
        assert!(!gate.gate_pass());
    }

    // ── Batch ─────────────────────────────────────────────────────

    #[test]
    fn test_verify_batch_all_reproduced() {
        let mut gate = ControlReplayGate::new();
        let entries: Vec<(ControlEvidenceEntry, ReplayContext)> = vec![
            {
                let e = make_entry(
                    DecisionType::HealthGateEval,
                    DecisionOutcome::Pass,
                    "DEC-001",
                    1000,
                );
                let c = build_replay_context(&e, "snap-001");
                (e, c)
            },
            {
                let e = make_entry(
                    DecisionType::FencingDecision,
                    DecisionOutcome::Grant,
                    "DEC-002",
                    2000,
                );
                let c = build_replay_context(&e, "snap-001");
                (e, c)
            },
        ];
        let results = gate.verify_batch(&entries);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_reproduced()));
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_verify_batch_mixed() {
        let mut gate = ControlReplayGate::new();
        let e1 = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let c1 = build_replay_context(&e1, "snap-001");
        let e2 = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-002",
            2000,
        );
        // Bad context for e2
        let c2 = ReplayContext::new(vec![], vec![], 42, "snap-001");
        let results = gate.verify_batch(&[(e1, c1), (e2, c2)]);
        assert!(results[0].is_reproduced());
        assert!(results[1].is_error());
        assert!(!gate.gate_pass());
    }

    // ── Determinism ───────────────────────────────────────────────

    #[test]
    fn test_determinism_identical_runs() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let mut g1 = ControlReplayGate::new();
        let mut g2 = ControlReplayGate::new();
        let v1 = g1.verify_from_entry(&entry, "snap-001");
        let v2 = g2.verify_from_entry(&entry, "snap-001");
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_determinism_100_runs() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let mut first: Option<ReplayVerdict> = None;
        for _ in 0..100 {
            let mut gate = ControlReplayGate::new();
            let v = gate.verify_from_entry(&entry, "snap-001");
            match &first {
                None => first = Some(v),
                Some(expected) => assert_eq!(&v, expected, "non-deterministic verdict"),
            }
        }
    }

    // ── Summary ───────────────────────────────────────────────────

    #[test]
    fn test_summary_all_reproduced() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        gate.verify_from_entry(&entry, "snap-001");
        let s = gate.summary();
        assert_eq!(s.total, 1);
        assert_eq!(s.reproduced, 1);
        assert!(s.gate_pass());
    }

    #[test]
    fn test_summary_with_diverged() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-001".into(),
                decision_kind: LedgerDecisionKind::Deny,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "c1".into(),
                description: "ok".into(),
                satisfied: true,
            }],
            42,
            "snap-001",
        );
        gate.verify(&entry, &ctx);
        let s = gate.summary();
        assert_eq!(s.diverged, 1);
        assert!(!s.gate_pass());
    }

    // ── Report ────────────────────────────────────────────────────

    #[test]
    fn test_report_json_structure() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        gate.verify_from_entry(&entry, "snap-001");
        let report = gate.to_report();
        assert_eq!(report["bead_id"], "bd-tyr2");
        assert_eq!(report["section"], "10.15");
        assert!(report["gate_pass"].as_bool().unwrap());
    }

    #[test]
    fn test_report_per_type_results() {
        let mut gate = ControlReplayGate::new();
        for (i, dt) in DecisionType::all().iter().enumerate() {
            let outcome = match dt {
                DecisionType::QuarantineAction => DecisionOutcome::Promote,
                DecisionType::FencingDecision => DecisionOutcome::Grant,
                _ => DecisionOutcome::Pass,
            };
            let entry = make_entry(*dt, outcome, &format!("DEC-{i:03}"), (i as u64 + 1) * 100);
            gate.verify_from_entry(&entry, "snap-001");
        }
        let report = gate.to_report();
        let per_type = report["per_decision_type"].as_object().unwrap();
        assert_eq!(per_type.len(), 5);
    }

    // ── Events ────────────────────────────────────────────────────

    #[test]
    fn test_take_events_drains() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        gate.verify_from_entry(&entry, "snap-001");
        assert!(!gate.events().is_empty());
        let events = gate.take_events();
        assert!(!events.is_empty());
        assert!(gate.events().is_empty());
    }

    #[test]
    fn test_event_trace_id() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        gate.verify_from_entry(&entry, "snap-001");
        assert!(gate.events().iter().all(|e| e.trace_id == "trace-001"));
    }

    // ── Default / Verdicts ────────────────────────────────────────

    #[test]
    fn test_default_gate() {
        let gate = ControlReplayGate::default();
        assert!(gate.verdicts().is_empty());
        assert!(gate.events().is_empty());
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_verdicts_accumulate() {
        let mut gate = ControlReplayGate::new();
        let e1 = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let e2 = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-002",
            2000,
        );
        gate.verify_from_entry(&e1, "snap-001");
        gate.verify_from_entry(&e2, "snap-001");
        assert_eq!(gate.verdicts().len(), 2);
    }

    // ── Adversarial ───────────────────────────────────────────────

    #[test]
    fn test_adversarial_wrong_epoch() {
        let mut gate = ControlReplayGate::new();
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        entry.epoch = 42;
        // Context from different epoch
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-001".into(),
                decision_kind: LedgerDecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![],
            999,
            "snap-001",
        );
        let v = gate.verify(&entry, &ctx);
        assert!(v.is_error());
    }

    #[test]
    fn test_adversarial_tampered_kind() {
        let mut gate = ControlReplayGate::new();
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        // Tamper: claim Deny but should have been Admit
        entry.decision_kind = DecisionKind::Deny;
        let ctx = build_replay_context(&entry, "snap-001");
        // With deny, the replay will produce deny (matches the entry) but
        // the decision_id also matters. Since we set score=1.0 for entry.decision_id
        // and kind=Deny, the canonical validator will find a match for Deny.
        // This tests that tampered entries still pass through the canonical validator.
        let v = gate.verify(&entry, &ctx);
        // The build_replay_context uses the tampered kind, so replay matches
        assert!(v.is_reproduced());
    }

    #[test]
    fn test_adversarial_empty_candidates() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-001",
            1000,
        );
        let ctx = ReplayContext::new(
            vec![],
            vec![Constraint {
                id: "c1".into(),
                description: "ok".into(),
                satisfied: true,
            }],
            42,
            "snap-001",
        );
        let v = gate.verify(&entry, &ctx);
        assert!(v.is_error());
    }

    // ── All decision types full cycle ─────────────────────────────

    #[test]
    fn test_all_decision_types_replay() {
        let mut gate = ControlReplayGate::new();
        let outcomes = [
            (DecisionType::HealthGateEval, DecisionOutcome::Pass),
            (DecisionType::RolloutTransition, DecisionOutcome::Proceed),
            (DecisionType::QuarantineAction, DecisionOutcome::Promote),
            (DecisionType::FencingDecision, DecisionOutcome::Grant),
            (DecisionType::MigrationDecision, DecisionOutcome::Proceed),
        ];
        for (i, (dt, outcome)) in outcomes.iter().enumerate() {
            let entry = make_entry(*dt, *outcome, &format!("DEC-{i:03}"), (i as u64 + 1) * 100);
            let v = gate.verify_from_entry(&entry, "snap-001");
            assert!(
                v.is_reproduced(),
                "Decision type {} failed replay: {:?}",
                dt.label(),
                v
            );
        }
        assert!(gate.gate_pass());
        assert_eq!(gate.summary().total, 5);
        assert_eq!(gate.summary().reproduced, 5);
    }

    // ── Event codes defined ───────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert!(!event_codes::RPL_001_REPLAY_INITIATED.is_empty());
        assert!(!event_codes::RPL_002_REPRODUCED.is_empty());
        assert!(!event_codes::RPL_003_DIVERGED.is_empty());
        assert!(!event_codes::RPL_004_ERROR.is_empty());
        assert!(!event_codes::RPL_005_GATE_DECISION.is_empty());
    }

    // ── Invariant constants defined ───────────────────────────────

    #[test]
    fn test_invariant_constants_defined() {
        assert!(!INV_CRG_CANONICAL.is_empty());
        assert!(!INV_CRG_BLOCK_DIVERGED.is_empty());
        assert!(!INV_CRG_DETERMINISTIC.is_empty());
        assert!(!INV_CRG_COMPLETE.is_empty());
    }

    // ── Event serde ───────────────────────────────────────────────

    #[test]
    fn test_replay_gate_event_serde() {
        let event = ReplayGateEvent {
            code: "RPL-001".into(),
            decision_id: "DEC-001".into(),
            decision_type: "health_gate_eval".into(),
            verdict: "pending".into(),
            detail: "test".into(),
            trace_id: "trace-001".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: ReplayGateEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "RPL-001");
    }

    #[test]
    fn test_verify_missing_policy_snapshot_errors_and_blocks_gate() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-NO-SNAPSHOT",
            1000,
        );
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-NO-SNAPSHOT".into(),
                decision_kind: LedgerDecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "policy-gate".into(),
                description: "control-plane policy gate".into(),
                satisfied: true,
            }],
            42,
            "",
        );

        let verdict = gate.verify(&entry, &ctx);

        assert!(verdict.is_error());
        assert!(!gate.gate_pass());
        assert_eq!(gate.summary().errors, 1);
        assert!(gate.events().iter().any(|event| {
            event.code == event_codes::RPL_004_ERROR && event.decision_id == "DEC-NO-SNAPSHOT"
        }));
    }

    #[test]
    fn test_unsatisfied_constraint_diverges_and_records_block() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-CONSTRAINT-BLOCK",
            1000,
        );
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-CONSTRAINT-BLOCK".into(),
                decision_kind: LedgerDecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "policy-gate".into(),
                description: "unsatisfied policy gate".into(),
                satisfied: false,
            }],
            42,
            "snap-001",
        );

        let verdict = gate.verify(&entry, &ctx);

        assert!(matches!(
            verdict,
            ReplayVerdict::Diverged {
                diff_field_count: 1,
                ..
            }
        ));
        assert!(!gate.gate_pass());
        assert!(gate.events().iter().any(|event| {
            event.code == event_codes::RPL_005_GATE_DECISION
                && event.decision_id == "DEC-CONSTRAINT-BLOCK"
                && event.verdict == "BLOCK"
        }));
    }

    #[test]
    fn test_non_finite_candidate_scores_select_no_winner_and_block() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::MigrationDecision,
            DecisionOutcome::Proceed,
            "DEC-NON-FINITE",
            1000,
        );
        let ctx = ReplayContext::new(
            vec![
                Candidate {
                    id: "DEC-NON-FINITE".into(),
                    decision_kind: LedgerDecisionKind::Admit,
                    score: f64::NAN,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "DEC-OTHER".into(),
                    decision_kind: LedgerDecisionKind::Admit,
                    score: f64::INFINITY,
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "policy-gate".into(),
                description: "control-plane policy gate".into(),
                satisfied: true,
            }],
            42,
            "snap-001",
        );

        let verdict = gate.verify(&entry, &ctx);

        assert!(verdict.is_diverged());
        assert_eq!(gate.summary().diverged, 1);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_wrong_kind_and_wrong_id_reports_two_diff_fields() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-EXPECTED",
            1000,
        );
        let ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-ACTUAL".into(),
                decision_kind: LedgerDecisionKind::Deny,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "policy-gate".into(),
                description: "control-plane policy gate".into(),
                satisfied: true,
            }],
            42,
            "snap-001",
        );

        let verdict = gate.verify(&entry, &ctx);

        assert!(matches!(
            verdict,
            ReplayVerdict::Diverged {
                diff_field_count: 2,
                ..
            }
        ));
        assert_eq!(gate.summary().diverged, 1);
    }

    #[test]
    fn test_empty_batch_returns_no_verdicts_and_gate_remains_closed() {
        let mut gate = ControlReplayGate::new();

        let results = gate.verify_batch(&[]);

        assert!(results.is_empty());
        assert!(gate.verdicts().is_empty());
        assert!(gate.events().is_empty());
        assert!(!gate.gate_pass());
        assert_eq!(
            gate.summary(),
            ReplayGateSummary {
                total: 0,
                reproduced: 0,
                diverged: 0,
                errors: 0,
            }
        );
    }

    #[test]
    fn test_report_for_only_errors_keeps_gate_closed() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-ERR-REPORT",
            1000,
        );
        let ctx = ReplayContext::new(vec![], vec![], 42, "snap-001");

        let verdict = gate.verify(&entry, &ctx);
        let report = gate.to_report();

        assert!(verdict.is_error());
        assert_eq!(report["gate_pass"], false);
        assert_eq!(report["summary"]["total"], 1);
        assert_eq!(report["summary"]["errors"], 1);
        assert_eq!(report["summary"]["reproduced"], 0);
    }

    #[test]
    fn test_take_events_after_error_does_not_clear_blocking_verdict() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-DRAIN-ERROR",
            1000,
        );
        let ctx = ReplayContext::new(vec![], vec![], 42, "snap-001");
        gate.verify(&entry, &ctx);

        let events = gate.take_events();

        assert!(!events.is_empty());
        assert!(gate.events().is_empty());
        assert_eq!(gate.verdicts().len(), 1);
        assert!(!gate.gate_pass());
        assert_eq!(gate.summary().errors, 1);
    }

    #[test]
    fn negative_build_replay_context_preserves_primary_when_alternates_exceed_cap() {
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-HUGE-CANDIDATES",
            1000,
        );
        entry.candidates_considered = (0..MAX_CANDIDATES.saturating_add(64))
            .map(|idx| format!("alt-{idx}"))
            .collect();

        let ctx = build_replay_context(&entry, "snap-oversized");

        assert_eq!(ctx.candidates.len(), MAX_CANDIDATES);
        assert_eq!(ctx.candidates[0].id, "DEC-HUGE-CANDIDATES");
        assert!(ctx.candidates.iter().any(|candidate| {
            candidate.id == "DEC-HUGE-CANDIDATES" && candidate.score.to_bits() == 1.0f64.to_bits()
        }));
    }

    #[test]
    fn negative_verify_from_entry_with_oversized_alternates_still_reproduces_primary() {
        let mut gate = ControlReplayGate::new();
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-HUGE-REPLAY",
            1000,
        );
        entry.candidates_considered = (0..MAX_CANDIDATES.saturating_add(64))
            .map(|idx| format!("candidate-{idx}"))
            .collect();

        let verdict = gate.verify_from_entry(&entry, "snap-huge-replay");

        assert!(verdict.is_reproduced());
        assert!(gate.gate_pass());
        assert_eq!(gate.summary().reproduced, 1);
    }

    #[test]
    fn negative_build_replay_context_skips_duplicate_chosen_candidate_names() {
        let mut entry = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-DUP",
            2000,
        );
        entry.candidates_considered = vec![
            "DEC-DUP".to_string(),
            "fallback".to_string(),
            "DEC-DUP".to_string(),
        ];

        let ctx = build_replay_context(&entry, "snap-duplicates");
        let chosen_count = ctx
            .candidates
            .iter()
            .filter(|candidate| candidate.id == "DEC-DUP")
            .count();

        assert_eq!(chosen_count, 1);
        assert_eq!(ctx.candidates.len(), 2);
        assert_eq!(ctx.candidates[0].score.to_bits(), 1.0f64.to_bits());
    }

    #[test]
    fn negative_verify_from_entry_with_blank_policy_snapshot_errors() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::MigrationDecision,
            DecisionOutcome::Proceed,
            "DEC-BLANK-SNAPSHOT",
            3000,
        );

        let verdict = gate.verify_from_entry(&entry, "");

        assert!(verdict.is_error());
        assert!(!gate.gate_pass());
        assert_eq!(gate.summary().errors, 1);
        assert!(gate.events().iter().any(|event| {
            event.code == event_codes::RPL_004_ERROR && event.decision_id == "DEC-BLANK-SNAPSHOT"
        }));
    }

    #[test]
    fn negative_batch_error_before_success_keeps_gate_closed() {
        let mut gate = ControlReplayGate::new();
        let bad_entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-BAD-FIRST",
            1000,
        );
        let good_entry = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-GOOD-SECOND",
            2000,
        );
        let bad_ctx = ReplayContext::new(Vec::new(), Vec::new(), 42, "snap-batch");
        let good_ctx = build_replay_context(&good_entry, "snap-batch");

        let results = gate.verify_batch(&[(bad_entry, bad_ctx), (good_entry, good_ctx)]);

        assert_eq!(results.len(), 2);
        assert!(results[0].is_error());
        assert!(results[1].is_reproduced());
        assert!(!gate.gate_pass());
        assert_eq!(gate.summary().errors, 1);
        assert_eq!(gate.summary().reproduced, 1);
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_existing_items() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn negative_push_bounded_zero_capacity_drops_new_item_from_empty_vec() {
        let mut values: Vec<u8> = Vec::new();

        push_bounded(&mut values, 7, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn negative_build_replay_context_with_padded_snapshot_is_invalid() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-PADDED-SNAPSHOT",
            1000,
        );

        let ctx = build_replay_context(&entry, " snap-padded ");

        assert!(!ctx.is_valid());
        assert_eq!(ctx.policy_snapshot_id, "");
        assert!(!ctx.candidates.is_empty());
    }

    #[test]
    fn negative_build_replay_context_with_null_snapshot_is_invalid() {
        let entry = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-NULL-SNAPSHOT",
            1000,
        );

        let ctx = build_replay_context(&entry, "snap\0shadow");

        assert!(!ctx.is_valid());
        assert_eq!(ctx.policy_snapshot_id, "");
        assert_eq!(ctx.candidates[0].id, "DEC-NULL-SNAPSHOT");
    }

    #[test]
    fn negative_verify_from_entry_with_padded_policy_snapshot_errors() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::MigrationDecision,
            DecisionOutcome::Proceed,
            "DEC-PADDED-VERIFY",
            1000,
        );

        let verdict = gate.verify_from_entry(&entry, "\tsnap-padded");

        assert!(verdict.is_error());
        assert!(!gate.gate_pass());
        assert_eq!(gate.summary().errors, 1);
        assert!(gate.events().iter().any(|event| {
            event.code == event_codes::RPL_005_GATE_DECISION
                && event.decision_id == "DEC-PADDED-VERIFY"
                && event.verdict == "BLOCK"
        }));
    }

    #[test]
    fn negative_verify_from_entry_with_null_policy_snapshot_errors() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::RolloutTransition,
            DecisionOutcome::Proceed,
            "DEC-NULL-VERIFY",
            1000,
        );

        let verdict = gate.verify_from_entry(&entry, "snap\0shadow");

        assert!(verdict.is_error());
        assert_eq!(gate.verdicts().len(), 1);
        assert_eq!(gate.summary().errors, 1);
        assert!(gate.events().iter().any(|event| {
            event.code == event_codes::RPL_004_ERROR && event.decision_id == "DEC-NULL-VERIFY"
        }));
    }

    #[test]
    fn negative_batch_with_padded_snapshot_error_keeps_gate_closed_after_success() {
        let mut gate = ControlReplayGate::new();
        let bad_entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-PADDED-BATCH",
            1000,
        );
        let good_entry = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "DEC-GOOD-BATCH",
            2000,
        );
        let bad_ctx = build_replay_context(&bad_entry, " snap-bad ");
        let good_ctx = build_replay_context(&good_entry, "snap-good");

        let results = gate.verify_batch(&[(bad_entry, bad_ctx), (good_entry, good_ctx)]);

        assert_eq!(results.len(), 2);
        assert!(results[0].is_error());
        assert!(results[1].is_reproduced());
        assert!(!gate.gate_pass());
        assert_eq!(gate.summary().errors, 1);
        assert_eq!(gate.summary().reproduced, 1);
    }

    #[test]
    fn negative_report_after_mixed_diverged_and_error_has_blocking_counts() {
        let mut gate = ControlReplayGate::new();
        let diverged_entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "DEC-DIVERGED-REPORT",
            1000,
        );
        let diverged_ctx = ReplayContext::new(
            vec![Candidate {
                id: "DEC-DIVERGED-ACTUAL".into(),
                decision_kind: LedgerDecisionKind::Deny,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "policy-gate".into(),
                description: "control-plane policy gate".into(),
                satisfied: true,
            }],
            42,
            "snap-report",
        );
        gate.verify(&diverged_entry, &diverged_ctx);

        let error_entry = make_entry(
            DecisionType::MigrationDecision,
            DecisionOutcome::Proceed,
            "DEC-ERROR-REPORT",
            2000,
        );
        gate.verify_from_entry(&error_entry, "snap\0bad");

        let report = gate.to_report();

        assert_eq!(report["gate_pass"], false);
        assert_eq!(report["summary"]["total"], 2);
        assert_eq!(report["summary"]["diverged"], 1);
        assert_eq!(report["summary"]["errors"], 1);
        assert_eq!(report["summary"]["reproduced"], 0);
    }

    #[test]
    fn negative_take_events_after_padded_snapshot_error_preserves_verdict() {
        let mut gate = ControlReplayGate::new();
        let entry = make_entry(
            DecisionType::QuarantineAction,
            DecisionOutcome::Promote,
            "DEC-DRAIN-PADDED",
            1000,
        );
        gate.verify_from_entry(&entry, " snap-drain ");

        let events = gate.take_events();

        assert!(!events.is_empty());
        assert!(gate.events().is_empty());
        assert_eq!(gate.verdicts().len(), 1);
        assert_eq!(gate.summary().errors, 1);
        assert!(!gate.gate_pass());
    }
}
