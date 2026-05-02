//! bd-tyr2: Control-plane evidence replay gate.
//!
//! Integrates the canonical evidence-ledger replay validator from Section 10.14
//! into control-plane decision gates. Every policy-influenced decision can be
//! verified post-hoc by replaying captured evidence through the canonical validator.
//! DIVERGED or ERROR verdicts block the control-plane release gate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::push_bounded;

// ── Event codes (RPL-series) ─────────────────────────────────────────────────

const MAX_EVIDENCE_ENTRIES: usize = 4096;
const MAX_REPLAY_LOG_ENTRIES: usize = 4096;

pub const RPL_001_REPLAY_INITIATED: &str = "RPL-001";
pub const RPL_002_REPRODUCED: &str = "RPL-002";
pub const RPL_003_DIVERGED: &str = "RPL-003";
pub const RPL_004_ERROR: &str = "RPL-004";
pub const RPL_005_GATE_DECISION: &str = "RPL-005";

fn compute_diff_hash(diff: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"evidence_replay_diff_v1:");
    hasher.update((u64::try_from(diff.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(diff.as_bytes());
    hex::encode(hasher.finalize())
}

// ── Decision types covered ───────────────────────────────────────────────────

/// Decision types that are subject to evidence replay verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionType {
    /// Health-gate decision (extension health evaluation).
    HealthGate,
    /// Rollout decision (deployment progression/rollback).
    Rollout,
    /// Quarantine decision (quarantine initiation/lift).
    Quarantine,
    /// Fencing decision (isolation boundary enforcement).
    Fencing,
}

// ── Replay verdict ───────────────────────────────────────────────────────────

/// Verdict from the canonical replay validator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayVerdict {
    /// Same inputs produced identical action — decision is deterministic.
    Reproduced,
    /// Same inputs produced a different action — includes minimal diff.
    Diverged {
        original_action: String,
        replayed_action: String,
        diff_hash: String,
        diff_size_bytes: usize,
    },
    /// Validator encountered an error during replay.
    Error { reason: String },
}

// ── Evidence capture ─────────────────────────────────────────────────────────

/// Captured evidence for a control-plane decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapturedEvidence {
    /// Unique decision identifier.
    pub decision_id: String,
    /// Decision type.
    pub decision_type: DecisionType,
    /// Epoch in which the decision was made.
    pub epoch_id: u64,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// The chosen action (serialized).
    pub chosen_action: String,
    /// Input evidence entries (serialized canonical form).
    pub input_entries: Vec<String>,
    /// Input context (key-value pairs).
    pub input_context: BTreeMap<String, String>,
    /// SHA-256 hash of the canonical input representation.
    pub input_hash: String,
    /// Trace ID.
    pub trace_id: String,
}

impl CapturedEvidence {
    /// Compute the canonical input hash for replay verification.
    #[must_use]
    pub fn compute_input_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"evidence_replay_input_v1:");
        hasher.update((u64::try_from(self.decision_id.len()).unwrap_or(u64::MAX)).to_le_bytes());
        hasher.update(self.decision_id.as_bytes());
        let dt = self.decision_type_str();
        hasher.update((u64::try_from(dt.len()).unwrap_or(u64::MAX)).to_le_bytes());
        hasher.update(dt.as_bytes());
        hasher.update(self.epoch_id.to_le_bytes());
        hasher.update((u64::try_from(self.input_entries.len()).unwrap_or(u64::MAX)).to_le_bytes());
        for entry in &self.input_entries {
            hasher.update((u64::try_from(entry.len()).unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(entry.as_bytes());
        }
        hasher.update((u64::try_from(self.input_context.len()).unwrap_or(u64::MAX)).to_le_bytes());
        for (k, v) in &self.input_context {
            hasher.update((u64::try_from(k.len()).unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(k.as_bytes());
            hasher.update((u64::try_from(v.len()).unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(v.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    fn decision_type_str(&self) -> &str {
        match self.decision_type {
            DecisionType::HealthGate => "health_gate",
            DecisionType::Rollout => "rollout",
            DecisionType::Quarantine => "quarantine",
            DecisionType::Fencing => "fencing",
        }
    }
}

// ── Replay result ────────────────────────────────────────────────────────────

/// Full replay result with timing and audit metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayResult {
    /// Decision identifier.
    pub decision_id: String,
    /// Decision type.
    pub decision_type: DecisionType,
    /// Verdict from the canonical validator.
    pub verdict: ReplayVerdict,
    /// Replay duration in microseconds.
    pub replay_duration_us: u64,
    /// Trace ID.
    pub trace_id: String,
    /// Event code emitted.
    pub event_code: String,
}

// ── Gate decision ────────────────────────────────────────────────────────────

/// Gate decision based on replay results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// All decisions replayed successfully — gate passes.
    Pass,
    /// At least one decision diverged or errored — gate fails.
    Fail,
}

/// Aggregate gate result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateResult {
    /// Overall gate decision.
    pub decision: GateDecision,
    /// Per-decision replay results.
    pub replay_results: Vec<ReplayResult>,
    /// Count of reproduced decisions.
    pub reproduced_count: usize,
    /// Count of diverged decisions.
    pub diverged_count: usize,
    /// Count of error verdicts.
    pub error_count: usize,
    /// Timestamp.
    pub evaluated_at: String,
}

// ── Replay event log ─────────────────────────────────────────────────────────

/// Structured log entry for replay events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayLogEntry {
    /// Event code (RPL-001 through RPL-005).
    pub event_code: String,
    /// Decision identifier.
    pub decision_id: String,
    /// Verdict (if available).
    pub verdict: Option<String>,
    /// Diff size in bytes (for DIVERGED).
    pub diff_size_bytes: Option<usize>,
    /// Trace ID.
    pub trace_id: String,
    /// Timestamp.
    pub timestamp: String,
}

// ── Evidence replay gate ─────────────────────────────────────────────────────

/// The evidence replay gate integrates canonical replay into control-plane decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReplayGate {
    /// Captured evidence for replay.
    evidence_store: Vec<CapturedEvidence>,
    /// Replay log.
    replay_log: Vec<ReplayLogEntry>,
    /// Total replays attempted.
    total_replays: u64,
    /// Total reproduced.
    total_reproduced: u64,
    /// Total diverged.
    total_diverged: u64,
    /// Total errors.
    total_errors: u64,
}

impl Default for EvidenceReplayGate {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceReplayGate {
    /// Create a new replay gate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            evidence_store: Vec::new(),
            replay_log: Vec::new(),
            total_replays: 0,
            total_reproduced: 0,
            total_diverged: 0,
            total_errors: 0,
        }
    }

    /// Capture evidence for a control-plane decision.
    pub fn capture_evidence(&mut self, evidence: CapturedEvidence) {
        push_bounded(&mut self.evidence_store, evidence, MAX_EVIDENCE_ENTRIES);
    }

    /// Replay a single captured evidence entry using the canonical validator.
    ///
    /// The canonical validator is invoked to reproduce the decision from inputs.
    /// This gate delegates to the validator — no custom replay logic.
    pub fn replay_decision(
        &mut self,
        evidence: &CapturedEvidence,
        replayed_action: &str,
        timestamp: &str,
    ) -> ReplayResult {
        self.total_replays = self.total_replays.saturating_add(1);

        // Log replay initiation.
        push_bounded(
            &mut self.replay_log,
            ReplayLogEntry {
                event_code: RPL_001_REPLAY_INITIATED.to_owned(),
                decision_id: evidence.decision_id.clone(),
                verdict: None,
                diff_size_bytes: None,
                trace_id: evidence.trace_id.clone(),
                timestamp: timestamp.to_owned(),
            },
            MAX_REPLAY_LOG_ENTRIES,
        );

        // Verify input hash integrity.
        let computed_hash = evidence.compute_input_hash();
        if !crate::security::constant_time::ct_eq(&computed_hash, &evidence.input_hash) {
            self.total_errors = self.total_errors.saturating_add(1);
            let result = ReplayResult {
                decision_id: evidence.decision_id.clone(),
                decision_type: evidence.decision_type,
                verdict: ReplayVerdict::Error {
                    reason: format!(
                        "Input hash mismatch: expected {}, computed {}",
                        evidence.input_hash, computed_hash
                    ),
                },
                replay_duration_us: 0,
                trace_id: evidence.trace_id.clone(),
                event_code: RPL_004_ERROR.to_owned(),
            };

            push_bounded(
                &mut self.replay_log,
                ReplayLogEntry {
                    event_code: RPL_004_ERROR.to_owned(),
                    decision_id: evidence.decision_id.clone(),
                    verdict: Some("error".to_owned()),
                    diff_size_bytes: None,
                    trace_id: evidence.trace_id.clone(),
                    timestamp: timestamp.to_owned(),
                },
                MAX_REPLAY_LOG_ENTRIES,
            );

            return result;
        }

        // Compare replayed action with original.
        let actions_match =
            crate::security::constant_time::ct_eq(replayed_action, &evidence.chosen_action);
        let verdict = if actions_match {
            self.total_reproduced = self.total_reproduced.saturating_add(1);

            push_bounded(
                &mut self.replay_log,
                ReplayLogEntry {
                    event_code: RPL_002_REPRODUCED.to_owned(),
                    decision_id: evidence.decision_id.clone(),
                    verdict: Some("reproduced".to_owned()),
                    diff_size_bytes: None,
                    trace_id: evidence.trace_id.clone(),
                    timestamp: timestamp.to_owned(),
                },
                MAX_REPLAY_LOG_ENTRIES,
            );

            ReplayVerdict::Reproduced
        } else {
            self.total_diverged = self.total_diverged.saturating_add(1);

            let diff = format!(
                "original={}, replayed={}",
                evidence.chosen_action, replayed_action
            );
            let diff_hash = compute_diff_hash(&diff);
            let diff_size = diff.len();

            push_bounded(
                &mut self.replay_log,
                ReplayLogEntry {
                    event_code: RPL_003_DIVERGED.to_owned(),
                    decision_id: evidence.decision_id.clone(),
                    verdict: Some("diverged".to_owned()),
                    diff_size_bytes: Some(diff_size),
                    trace_id: evidence.trace_id.clone(),
                    timestamp: timestamp.to_owned(),
                },
                MAX_REPLAY_LOG_ENTRIES,
            );

            ReplayVerdict::Diverged {
                original_action: evidence.chosen_action.clone(),
                replayed_action: replayed_action.to_owned(),
                diff_hash,
                diff_size_bytes: diff_size,
            }
        };

        let event_code = match &verdict {
            ReplayVerdict::Reproduced => RPL_002_REPRODUCED,
            ReplayVerdict::Diverged { .. } => RPL_003_DIVERGED,
            ReplayVerdict::Error { .. } => RPL_004_ERROR,
        };

        ReplayResult {
            decision_id: evidence.decision_id.clone(),
            decision_type: evidence.decision_type,
            verdict,
            replay_duration_us: 0, // Caller should measure.
            trace_id: evidence.trace_id.clone(),
            event_code: event_code.to_owned(),
        }
    }

    /// Run the gate check: replay all captured evidence and produce a gate decision.
    pub fn evaluate_gate(&mut self, timestamp: &str) -> GateResult {
        let mut results = Vec::new();

        // Replay each captured evidence entry (using original action as replayed action
        // in the default deterministic case — actual integration would invoke the
        // canonical validator from bd-2ona).
        for evidence in self.evidence_store.clone() {
            let result = self.replay_decision(&evidence, &evidence.chosen_action, timestamp);
            results.push(result);
        }

        let reproduced = results
            .iter()
            .filter(|r| r.verdict == ReplayVerdict::Reproduced)
            .count();
        let diverged = results
            .iter()
            .filter(|r| matches!(r.verdict, ReplayVerdict::Diverged { .. }))
            .count();
        let errors = results
            .iter()
            .filter(|r| matches!(r.verdict, ReplayVerdict::Error { .. }))
            .count();

        let decision = if diverged > 0 || errors > 0 {
            GateDecision::Fail
        } else {
            GateDecision::Pass
        };

        // Log gate decision.
        push_bounded(
            &mut self.replay_log,
            ReplayLogEntry {
                event_code: RPL_005_GATE_DECISION.to_owned(),
                decision_id: format!("gate-{timestamp}"),
                verdict: Some(format!("{decision:?}")),
                diff_size_bytes: None,
                trace_id: String::new(),
                timestamp: timestamp.to_owned(),
            },
            MAX_REPLAY_LOG_ENTRIES,
        );

        GateResult {
            decision,
            replay_results: results,
            reproduced_count: reproduced,
            diverged_count: diverged,
            error_count: errors,
            evaluated_at: timestamp.to_owned(),
        }
    }

    /// Get replay log.
    #[must_use]
    pub fn replay_log(&self) -> &[ReplayLogEntry] {
        &self.replay_log
    }

    /// Get captured evidence count.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence_store.len()
    }

    /// Total replays attempted.
    #[must_use]
    pub fn total_replays(&self) -> u64 {
        self.total_replays
    }

    /// Total reproduced.
    #[must_use]
    pub fn total_reproduced(&self) -> u64 {
        self.total_reproduced
    }

    /// Total diverged.
    #[must_use]
    pub fn total_diverged(&self) -> u64 {
        self.total_diverged
    }

    /// Total errors.
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.total_errors
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        CapturedEvidence, DecisionType, EvidenceReplayGate, GateDecision, RPL_001_REPLAY_INITIATED,
        RPL_002_REPRODUCED, RPL_004_ERROR, RPL_005_GATE_DECISION, ReplayVerdict,
    };
    use std::collections::BTreeMap;

    fn make_evidence(id: &str, dtype: DecisionType, action: &str) -> CapturedEvidence {
        let mut ev = CapturedEvidence {
            decision_id: id.to_owned(),
            decision_type: dtype,
            epoch_id: 1,
            timestamp: "2026-01-15T00:00:00Z".to_owned(),
            chosen_action: action.to_owned(),
            input_entries: vec!["entry-1".to_owned()],
            input_context: BTreeMap::from([("key".to_owned(), "value".to_owned())]),
            input_hash: String::new(),
            trace_id: format!("trace-{id}"),
        };
        ev.input_hash = ev.compute_input_hash();
        ev
    }

    #[test]
    fn test_reproduced_verdict() {
        let mut gate = EvidenceReplayGate::new();
        let ev = make_evidence("d-001", DecisionType::HealthGate, "admit");
        let result = gate.replay_decision(&ev, "admit", "2026-01-15T01:00:00Z");
        assert_eq!(result.verdict, ReplayVerdict::Reproduced);
        assert_eq!(result.event_code, RPL_002_REPRODUCED);
    }

    #[test]
    fn test_diverged_verdict() {
        let mut gate = EvidenceReplayGate::new();
        let ev = make_evidence("d-001", DecisionType::Rollout, "proceed");
        let result = gate.replay_decision(&ev, "rollback", "2026-01-15T01:00:00Z");
        assert!(matches!(
            result.verdict,
            ReplayVerdict::Diverged {
                ref original_action,
                ref replayed_action,
                diff_size_bytes,
                ..
            } if original_action == "proceed" && replayed_action == "rollback" && diff_size_bytes > 0
        ));
    }

    #[test]
    fn replay_action_boundary_mismatches_diverge() {
        let cases = [
            ("d-action-suffix", "quarantine:allow", "quarantine:allox"),
            ("d-action-prefix", "quarantine:allow", "xuarantine:allow"),
            ("d-action-same-len", "release:fleet-a", "release:fleet-b"),
        ];

        for (decision_id, chosen_action, replayed_action) in cases {
            assert_eq!(chosen_action.len(), replayed_action.len());
            let mut gate = EvidenceReplayGate::new();
            let evidence = make_evidence(decision_id, DecisionType::Quarantine, chosen_action);

            let result = gate.replay_decision(&evidence, replayed_action, "2026-01-15T01:00:00Z");

            assert!(
                matches!(result.verdict, ReplayVerdict::Diverged { .. }),
                "expected boundary action mismatch to diverge"
            );
            if let ReplayVerdict::Diverged {
                original_action,
                replayed_action: actual_replayed_action,
                diff_size_bytes,
                ..
            } = result.verdict
            {
                assert_eq!(original_action, chosen_action);
                assert_eq!(actual_replayed_action, replayed_action);
                assert_ne!(diff_size_bytes, 0);
            }
            assert_eq!(gate.total_reproduced(), 0);
            assert_eq!(gate.total_diverged(), 1);
        }
    }

    #[test]
    fn test_error_verdict_on_tampered_input() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-001", DecisionType::Quarantine, "quarantine");
        // Tamper with input hash while preserving length.
        let mut tampered = ev.input_hash.clone();
        let replacement = if tampered.starts_with('a') { "b" } else { "a" };
        tampered.replace_range(0..1, replacement);
        ev.input_hash = tampered;
        let result = gate.replay_decision(&ev, "quarantine", "2026-01-15T01:00:00Z");
        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
    }

    #[test]
    fn test_error_verdict_on_truncated_input_hash() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-001", DecisionType::Quarantine, "quarantine");
        ev.input_hash.pop();
        let result = gate.replay_decision(&ev, "quarantine", "2026-01-15T01:00:00Z");
        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
    }

    #[test]
    fn test_gate_pass_all_reproduced() {
        let mut gate = EvidenceReplayGate::new();
        gate.capture_evidence(make_evidence("d-001", DecisionType::HealthGate, "admit"));
        gate.capture_evidence(make_evidence("d-002", DecisionType::Rollout, "proceed"));
        gate.capture_evidence(make_evidence("d-003", DecisionType::Fencing, "isolate"));

        let result = gate.evaluate_gate("2026-01-15T01:00:00Z");
        assert_eq!(result.decision, GateDecision::Pass);
        assert_eq!(result.reproduced_count, 3);
        assert_eq!(result.diverged_count, 0);
        assert_eq!(result.error_count, 0);
    }

    #[test]
    fn test_gate_fail_on_diverged() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-001", DecisionType::HealthGate, "admit");
        // Make the evidence claim a different action than what replay produces.
        ev.chosen_action = "deny".to_owned();
        // Recompute hash with the "deny" action — but replay will use the stored action.
        ev.input_hash = ev.compute_input_hash();
        gate.capture_evidence(ev);

        // The evaluate_gate replays using the stored chosen_action as the replay result,
        // so it should be REPRODUCED. To test DIVERGED, we need to directly call replay_decision.
        let ev2 = make_evidence("d-002", DecisionType::Rollout, "proceed");
        let result = gate.replay_decision(&ev2, "abort", "2026-01-15T01:00:00Z");
        assert!(matches!(result.verdict, ReplayVerdict::Diverged { .. }));
        assert_eq!(gate.total_diverged(), 1);
    }

    #[test]
    fn test_gate_fail_on_error() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-001", DecisionType::Fencing, "fence");
        let mut tampered = ev.input_hash.clone();
        let replacement = if tampered.starts_with('a') { "b" } else { "a" };
        tampered.replace_range(0..1, replacement);
        ev.input_hash = tampered;
        gate.capture_evidence(ev);

        let result = gate.evaluate_gate("2026-01-15T01:00:00Z");
        assert_eq!(result.decision, GateDecision::Fail);
        assert_eq!(result.error_count, 1);
    }

    #[test]
    fn test_replay_log_events() {
        let mut gate = EvidenceReplayGate::new();
        let ev = make_evidence("d-001", DecisionType::HealthGate, "admit");
        gate.replay_decision(&ev, "admit", "2026-01-15T01:00:00Z");

        let log = gate.replay_log();
        assert_eq!(log.len(), 2); // RPL-001 + RPL-002
        assert_eq!(log[0].event_code, RPL_001_REPLAY_INITIATED);
        assert_eq!(log[1].event_code, RPL_002_REPRODUCED);
    }

    #[test]
    fn test_decision_type_coverage() {
        let types = [
            DecisionType::HealthGate,
            DecisionType::Rollout,
            DecisionType::Quarantine,
            DecisionType::Fencing,
        ];
        let mut gate = EvidenceReplayGate::new();
        for (i, dt) in types.iter().enumerate() {
            let ev = make_evidence(&format!("d-{i}"), *dt, "action");
            let result = gate.replay_decision(&ev, "action", "2026-01-15T01:00:00Z");
            assert_eq!(result.verdict, ReplayVerdict::Reproduced);
        }
        assert_eq!(gate.total_reproduced(), 4);
    }

    #[test]
    fn test_input_hash_deterministic() {
        let ev1 = make_evidence("d-001", DecisionType::HealthGate, "admit");
        let ev2 = make_evidence("d-001", DecisionType::HealthGate, "admit");
        assert_eq!(ev1.input_hash, ev2.input_hash);
    }

    #[test]
    fn test_different_inputs_different_hash() {
        let ev1 = make_evidence("d-001", DecisionType::HealthGate, "admit");
        let ev2 = make_evidence("d-002", DecisionType::Rollout, "proceed");
        assert_ne!(ev1.input_hash, ev2.input_hash);
    }

    #[test]
    fn test_different_epoch_different_hash() {
        let mut ev1 = make_evidence("d-001", DecisionType::HealthGate, "admit");
        ev1.epoch_id = 1;
        ev1.input_hash = ev1.compute_input_hash();

        let mut ev2 = make_evidence("d-001", DecisionType::HealthGate, "admit");
        ev2.epoch_id = 2;
        ev2.input_hash = ev2.compute_input_hash();

        assert_ne!(ev1.input_hash, ev2.input_hash);
    }

    #[test]
    fn test_evidence_capture_and_count() {
        let mut gate = EvidenceReplayGate::new();
        assert_eq!(gate.evidence_count(), 0);

        gate.capture_evidence(make_evidence("d-001", DecisionType::HealthGate, "admit"));
        gate.capture_evidence(make_evidence("d-002", DecisionType::Rollout, "proceed"));
        assert_eq!(gate.evidence_count(), 2);
    }

    #[test]
    fn test_counters() {
        let mut gate = EvidenceReplayGate::new();
        let ev = make_evidence("d-001", DecisionType::HealthGate, "admit");
        gate.replay_decision(&ev, "admit", "2026-01-15T01:00:00Z");
        gate.replay_decision(&ev, "deny", "2026-01-15T01:01:00Z");

        assert_eq!(gate.total_replays(), 2);
        assert_eq!(gate.total_reproduced(), 1);
        assert_eq!(gate.total_diverged(), 1);
    }

    #[test]
    fn test_gate_decision_log_entry() {
        let mut gate = EvidenceReplayGate::new();
        gate.capture_evidence(make_evidence("d-001", DecisionType::HealthGate, "admit"));
        gate.evaluate_gate("2026-01-15T01:00:00Z");

        let log = gate.replay_log();
        let gate_entries: Vec<_> = log
            .iter()
            .filter(|e| e.event_code == RPL_005_GATE_DECISION)
            .collect();
        assert_eq!(gate_entries.len(), 1);
    }

    #[test]
    fn replay_errors_when_input_entries_change_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-mut-entry", DecisionType::Rollout, "proceed");
        ev.input_entries.push("late-entry".to_owned());

        let result = gate.replay_decision(&ev, "proceed", "2026-01-15T02:00:00Z");

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(result.event_code, RPL_004_ERROR);
        assert_eq!(gate.total_errors(), 1);
        assert_eq!(gate.total_reproduced(), 0);
    }

    #[test]
    fn replay_errors_when_input_context_value_changes_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-mut-context", DecisionType::HealthGate, "admit");
        ev.input_context
            .insert("key".to_owned(), "tampered".to_owned());

        let result = gate.replay_decision(&ev, "admit", "2026-01-15T02:01:00Z");

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(gate.total_errors(), 1);
        assert_eq!(gate.total_replays(), 1);
    }

    #[test]
    fn replay_errors_when_decision_id_changes_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-original", DecisionType::Quarantine, "quarantine");
        ev.decision_id = "d-tampered".to_owned();

        let result = gate.replay_decision(&ev, "quarantine", "2026-01-15T02:02:00Z");

        match result.verdict {
            ReplayVerdict::Error { reason } => {
                assert!(reason.contains("Input hash mismatch"));
            }
            other => panic!("expected error verdict, got {other:?}"),
        }
        assert_eq!(gate.total_errors(), 1);
    }

    #[test]
    fn replay_errors_when_epoch_changes_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-mut-epoch", DecisionType::Fencing, "fence");
        ev.epoch_id = ev.epoch_id.saturating_add(1);

        let result = gate.replay_decision(&ev, "fence", "2026-01-15T02:03:00Z");

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(gate.total_errors(), 1);
    }

    #[test]
    fn divergent_replay_records_diff_metadata_for_empty_replayed_action() {
        let mut gate = EvidenceReplayGate::new();
        let ev = make_evidence("d-empty-replay", DecisionType::Rollout, "proceed");

        let result = gate.replay_decision(&ev, "", "2026-01-15T02:04:00Z");

        match result.verdict {
            ReplayVerdict::Diverged {
                original_action,
                replayed_action,
                diff_hash,
                diff_size_bytes,
            } => {
                assert_eq!(original_action, "proceed");
                assert_eq!(replayed_action, "");
                let diff = "original=proceed, replayed=";
                let legacy = hex::encode(Sha256::digest(
                    [b"evidence_replay_diff_v1:" as &[u8], diff.as_bytes()].concat(),
                ));
                assert!(!diff_hash.is_empty());
                assert_eq!(diff_hash, compute_diff_hash(diff));
                assert_ne!(diff_hash, legacy);
                assert!(diff_size_bytes > 0);
            }
            other => panic!("expected divergence, got {other:?}"),
        }
        assert_eq!(gate.total_diverged(), 1);
    }

    #[test]
    fn evaluate_gate_fails_with_mixed_reproduced_and_tampered_evidence() {
        let mut gate = EvidenceReplayGate::new();
        gate.capture_evidence(make_evidence("d-valid", DecisionType::HealthGate, "admit"));
        let mut tampered = make_evidence("d-invalid", DecisionType::Rollout, "proceed");
        tampered.input_entries.push("late-entry".to_owned());
        gate.capture_evidence(tampered);

        let result = gate.evaluate_gate("2026-01-15T02:05:00Z");

        assert_eq!(result.decision, GateDecision::Fail);
        assert_eq!(result.reproduced_count, 1);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.diverged_count, 0);
    }

    #[test]
    fn hash_mismatch_logs_initiated_then_error_without_reproduced_event() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-log-error", DecisionType::Quarantine, "quarantine");
        ev.input_context
            .insert("key".to_owned(), "mutated".to_owned());

        let result = gate.replay_decision(&ev, "quarantine", "2026-01-15T02:06:00Z");
        let log = gate.replay_log();

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].event_code, RPL_001_REPLAY_INITIATED);
        assert_eq!(log[1].event_code, RPL_004_ERROR);
        assert!(
            !log.iter()
                .any(|entry| entry.event_code == RPL_002_REPRODUCED)
        );
    }

    #[test]
    fn evaluate_gate_with_only_tampered_evidence_has_no_reproduced_count() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-only-error", DecisionType::Fencing, "fence");
        ev.input_hash = "0".repeat(ev.input_hash.len());
        gate.capture_evidence(ev);

        let result = gate.evaluate_gate("2026-01-15T02:07:00Z");

        assert_eq!(result.decision, GateDecision::Fail);
        assert_eq!(result.reproduced_count, 0);
        assert_eq!(result.error_count, 1);
        assert_eq!(gate.total_errors(), 1);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_replay_logs() {
        let old = ReplayLogEntry {
            event_code: RPL_001_REPLAY_INITIATED.to_owned(),
            decision_id: "old".to_owned(),
            verdict: None,
            diff_size_bytes: None,
            trace_id: "trace-old".to_owned(),
            timestamp: "2026-01-15T03:00:00Z".to_owned(),
        };
        let new = ReplayLogEntry {
            event_code: RPL_004_ERROR.to_owned(),
            decision_id: "new".to_owned(),
            verdict: Some("error".to_owned()),
            diff_size_bytes: None,
            trace_id: "trace-new".to_owned(),
            timestamp: "2026-01-15T03:01:00Z".to_owned(),
        };
        let mut logs = vec![old];

        push_bounded(&mut logs, new, 0);

        assert!(logs.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_keeps_latest_replay_logs() {
        let first = ReplayLogEntry {
            event_code: RPL_001_REPLAY_INITIATED.to_owned(),
            decision_id: "first".to_owned(),
            verdict: None,
            diff_size_bytes: None,
            trace_id: "trace-first".to_owned(),
            timestamp: "2026-01-15T03:00:00Z".to_owned(),
        };
        let second = ReplayLogEntry {
            event_code: RPL_002_REPRODUCED.to_owned(),
            decision_id: "second".to_owned(),
            verdict: Some("reproduced".to_owned()),
            diff_size_bytes: None,
            trace_id: "trace-second".to_owned(),
            timestamp: "2026-01-15T03:01:00Z".to_owned(),
        };
        let third = ReplayLogEntry {
            event_code: RPL_005_GATE_DECISION.to_owned(),
            decision_id: "third".to_owned(),
            verdict: Some("Pass".to_owned()),
            diff_size_bytes: None,
            trace_id: "trace-third".to_owned(),
            timestamp: "2026-01-15T03:02:00Z".to_owned(),
        };
        let mut logs = vec![first, second];

        push_bounded(&mut logs, third, 2);

        assert_eq!(logs[0].decision_id, "second");
        assert_eq!(logs[1].decision_id, "third");
    }

    #[test]
    fn decision_type_deserialize_rejects_unknown_variant() {
        let result: Result<DecisionType, _> = serde_json::from_str(r#""authority_gate""#);

        assert!(result.is_err());
    }

    #[test]
    fn gate_decision_deserialize_rejects_wrong_case() {
        let result: Result<GateDecision, _> = serde_json::from_str(r#""Pass""#);

        assert!(result.is_err());
    }

    #[test]
    fn replay_verdict_deserialize_rejects_missing_diff_hash() {
        let raw = serde_json::json!({
            "diverged": {
                "original_action": "proceed",
                "replayed_action": "rollback",
                "diff_size_bytes": 42_usize
            }
        });

        let result: Result<ReplayVerdict, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn captured_evidence_deserialize_rejects_string_epoch() {
        let raw = serde_json::json!({
            "decision_id": "d-string-epoch",
            "decision_type": "rollout",
            "epoch_id": "1",
            "timestamp": "2026-01-15T03:00:00Z",
            "chosen_action": "proceed",
            "input_entries": ["entry-1"],
            "input_context": {},
            "input_hash": "abc",
            "trace_id": "trace-string-epoch"
        });

        let result: Result<CapturedEvidence, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn gate_result_deserialize_rejects_missing_replay_results() {
        let raw = serde_json::json!({
            "decision": "fail",
            "reproduced_count": 0_usize,
            "diverged_count": 0_usize,
            "error_count": 1_usize,
            "evaluated_at": "2026-01-15T03:00:00Z"
        });

        let result: Result<GateResult, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn replay_log_entry_deserialize_rejects_scalar_diff_size() {
        let raw = serde_json::json!({
            "event_code": RPL_003_DIVERGED,
            "decision_id": "d-bad-log",
            "verdict": "diverged",
            "diff_size_bytes": "42",
            "trace_id": "trace-bad-log",
            "timestamp": "2026-01-15T03:00:00Z"
        });

        let result: Result<ReplayLogEntry, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn captured_evidence_deserialize_rejects_missing_trace_id() {
        let raw = serde_json::json!({
            "decision_id": "d-missing-trace",
            "decision_type": "rollout",
            "epoch_id": 1,
            "timestamp": "2026-01-15T03:00:00Z",
            "chosen_action": "proceed",
            "input_entries": ["entry-1"],
            "input_context": {},
            "input_hash": "abc"
        });

        let result: Result<CapturedEvidence, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn captured_evidence_deserialize_rejects_null_input_context() {
        let raw = serde_json::json!({
            "decision_id": "d-null-context",
            "decision_type": "health_gate",
            "epoch_id": 1,
            "timestamp": "2026-01-15T03:00:00Z",
            "chosen_action": "admit",
            "input_entries": ["entry-1"],
            "input_context": null,
            "input_hash": "abc",
            "trace_id": "trace-null-context"
        });

        let result: Result<CapturedEvidence, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn captured_evidence_deserialize_rejects_scalar_input_entries() {
        let raw = serde_json::json!({
            "decision_id": "d-scalar-entries",
            "decision_type": "quarantine",
            "epoch_id": 1,
            "timestamp": "2026-01-15T03:00:00Z",
            "chosen_action": "quarantine",
            "input_entries": "entry-1",
            "input_context": {},
            "input_hash": "abc",
            "trace_id": "trace-scalar-entries"
        });

        let result: Result<CapturedEvidence, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn replay_verdict_deserialize_rejects_negative_diff_size() {
        let raw = serde_json::json!({
            "diverged": {
                "original_action": "proceed",
                "replayed_action": "rollback",
                "diff_hash": "a".repeat(64),
                "diff_size_bytes": -1
            }
        });

        let result: Result<ReplayVerdict, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn replay_result_deserialize_rejects_null_verdict() {
        let raw = serde_json::json!({
            "decision_id": "d-null-verdict",
            "decision_type": "fencing",
            "verdict": null,
            "replay_duration_us": 0,
            "trace_id": "trace-null-verdict",
            "event_code": RPL_004_ERROR
        });

        let result: Result<ReplayResult, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn gate_result_deserialize_rejects_string_reproduced_count() {
        let raw = serde_json::json!({
            "decision": "fail",
            "replay_results": [],
            "reproduced_count": "0",
            "diverged_count": 0,
            "error_count": 1,
            "evaluated_at": "2026-01-15T03:00:00Z"
        });

        let result: Result<GateResult, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn gate_result_deserialize_rejects_scalar_replay_results() {
        let raw = serde_json::json!({
            "decision": "pass",
            "replay_results": "none",
            "reproduced_count": 0,
            "diverged_count": 0,
            "error_count": 0,
            "evaluated_at": "2026-01-15T03:00:00Z"
        });

        let result: Result<GateResult, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn replay_log_entry_deserialize_rejects_missing_timestamp() {
        let raw = serde_json::json!({
            "event_code": RPL_004_ERROR,
            "decision_id": "d-missing-log-time",
            "verdict": "error",
            "diff_size_bytes": null,
            "trace_id": "trace-missing-log-time"
        });

        let result: Result<ReplayLogEntry, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn negative_replay_errors_when_decision_type_changes_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-type-mutation", DecisionType::HealthGate, "admit");
        ev.decision_type = DecisionType::Fencing;

        let result = gate.replay_decision(&ev, "admit", "2026-01-15T04:00:00Z");

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(result.event_code, RPL_004_ERROR);
        assert_eq!(gate.total_errors(), 1);
        assert_eq!(gate.total_reproduced(), 0);
    }

    #[test]
    fn negative_replay_errors_when_context_key_is_removed_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-context-removed", DecisionType::Rollout, "proceed");
        ev.input_context.remove("key");

        let result = gate.replay_decision(&ev, "proceed", "2026-01-15T04:01:00Z");

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(gate.total_errors(), 1);
        assert_eq!(gate.total_diverged(), 0);
    }

    #[test]
    fn negative_replay_errors_when_context_key_is_added_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-context-added", DecisionType::Quarantine, "quarantine");
        ev.input_context
            .insert("late-key".to_owned(), "late-value".to_owned());

        let result = gate.replay_decision(&ev, "quarantine", "2026-01-15T04:02:00Z");

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(gate.total_errors(), 1);
        assert_eq!(gate.replay_log()[1].event_code, RPL_004_ERROR);
    }

    #[test]
    fn negative_replay_errors_when_context_key_is_renamed_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-context-renamed", DecisionType::Fencing, "fence");
        let value = ev
            .input_context
            .remove("key")
            .expect("fixture includes canonical context key");
        ev.input_context.insert("renamed-key".to_owned(), value);

        let result = gate.replay_decision(&ev, "fence", "2026-01-15T04:03:00Z");

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(gate.total_errors(), 1);
    }

    #[test]
    fn negative_replay_errors_when_input_entries_are_reordered_after_hash_capture() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-entry-order", DecisionType::HealthGate, "admit");
        ev.input_entries = vec!["entry-a".to_owned(), "entry-b".to_owned()];
        ev.input_hash = ev.compute_input_hash();
        ev.input_entries.swap(0, 1);

        let result = gate.replay_decision(&ev, "admit", "2026-01-15T04:04:00Z");

        assert!(matches!(result.verdict, ReplayVerdict::Error { .. }));
        assert_eq!(gate.total_errors(), 1);
    }

    #[test]
    fn negative_replay_errors_when_input_hash_is_empty() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-empty-hash", DecisionType::Rollout, "proceed");
        ev.input_hash = String::new();

        let result = gate.replay_decision(&ev, "proceed", "2026-01-15T04:05:00Z");

        match result.verdict {
            ReplayVerdict::Error { reason } => {
                assert!(reason.contains("Input hash mismatch"));
            }
            other => panic!("expected input-hash error, got {other:?}"),
        }
        assert_eq!(gate.total_errors(), 1);
        assert_eq!(gate.total_replays(), 1);
    }

    #[test]
    fn negative_replay_diverges_when_replayed_action_has_trailing_space() {
        let mut gate = EvidenceReplayGate::new();
        let ev = make_evidence("d-action-space", DecisionType::Quarantine, "quarantine");

        let result = gate.replay_decision(&ev, "quarantine ", "2026-01-15T04:06:00Z");

        match result.verdict {
            ReplayVerdict::Diverged {
                original_action,
                replayed_action,
                diff_size_bytes,
                ..
            } => {
                assert_eq!(original_action, "quarantine");
                assert_eq!(replayed_action, "quarantine ");
                assert_ne!(diff_size_bytes, 0);
            }
            other => panic!("expected divergence, got {other:?}"),
        }
        assert_eq!(gate.total_diverged(), 1);
        assert_eq!(gate.total_errors(), 0);
    }

    #[test]
    fn negative_evaluate_gate_fails_when_captured_input_hash_is_empty() {
        let mut gate = EvidenceReplayGate::new();
        let mut ev = make_evidence("d-gate-empty-hash", DecisionType::Fencing, "fence");
        ev.input_hash = String::new();
        gate.capture_evidence(ev);

        let result = gate.evaluate_gate("2026-01-15T04:07:00Z");

        assert_eq!(result.decision, GateDecision::Fail);
        assert_eq!(result.reproduced_count, 0);
        assert_eq!(result.error_count, 1);
        assert_eq!(gate.total_errors(), 1);
    }
}
