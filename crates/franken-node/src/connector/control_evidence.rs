//! bd-15j6: Mandatory evidence-ledger emission for policy-influenced
//! control decisions.
//!
//! Every policy-influenced control decision (health-gate, rollout,
//! quarantine, fencing, migration) MUST emit an evidence entry.
//! A missing entry is a conformance failure, not a warning.
//!
//! # Invariants
//!
//! - **INV-CE-MANDATORY**: Every policy decision emits evidence.
//! - **INV-CE-SCHEMA**: Entries match canonical EvidenceEntry schema from 10.14.
//! - **INV-CE-DETERMINISTIC**: Same inputs produce same entry sequence.
//! - **INV-CE-FAIL-CLOSED**: Missing evidence blocks decision execution.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const EVD_001_ENTRY_EMITTED: &str = "EVD-001";
pub const EVD_002_ENTRY_MISSING: &str = "EVD-002";
pub const EVD_003_SCHEMA_VALID: &str = "EVD-003";
pub const EVD_004_SCHEMA_INVALID: &str = "EVD-004";
pub const EVD_005_ORDERING_VIOLATION: &str = "EVD-005";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_CE_MANDATORY: &str = "INV-CE-MANDATORY";
pub const INV_CE_SCHEMA: &str = "INV-CE-SCHEMA";
pub const INV_CE_DETERMINISTIC: &str = "INV-CE-DETERMINISTIC";
pub const INV_CE_FAIL_CLOSED: &str = "INV-CE-FAIL-CLOSED";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Policy-influenced control decision types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionType {
    HealthGateEval,
    RolloutTransition,
    QuarantineAction,
    FencingDecision,
    MigrationDecision,
}

impl DecisionType {
    pub fn all() -> &'static [DecisionType] {
        &[
            DecisionType::HealthGateEval,
            DecisionType::RolloutTransition,
            DecisionType::QuarantineAction,
            DecisionType::FencingDecision,
            DecisionType::MigrationDecision,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            DecisionType::HealthGateEval => "health_gate_eval",
            DecisionType::RolloutTransition => "rollout_transition",
            DecisionType::QuarantineAction => "quarantine_action",
            DecisionType::FencingDecision => "fencing_decision",
            DecisionType::MigrationDecision => "migration_decision",
        }
    }
}

impl fmt::Display for DecisionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Canonical decision kind from bd-nupr schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionKind {
    Admit,
    Deny,
    Quarantine,
    Release,
    Rollback,
    Throttle,
    Escalate,
}

impl DecisionKind {
    pub fn label(&self) -> &'static str {
        match self {
            DecisionKind::Admit => "admit",
            DecisionKind::Deny => "deny",
            DecisionKind::Quarantine => "quarantine",
            DecisionKind::Release => "release",
            DecisionKind::Rollback => "rollback",
            DecisionKind::Throttle => "throttle",
            DecisionKind::Escalate => "escalate",
        }
    }
}

impl fmt::Display for DecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Decision outcome for mapping to DecisionKind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionOutcome {
    Pass,
    Fail,
    Promote,
    Demote,
    Grant,
    Deny,
    Proceed,
    Abort,
}

/// Map a decision type and outcome to the canonical DecisionKind.
pub fn map_decision_kind(dt: DecisionType, outcome: DecisionOutcome) -> DecisionKind {
    match (dt, outcome) {
        (DecisionType::HealthGateEval, DecisionOutcome::Pass) => DecisionKind::Admit,
        (DecisionType::HealthGateEval, DecisionOutcome::Fail) => DecisionKind::Deny,
        (DecisionType::RolloutTransition, DecisionOutcome::Pass)
        | (DecisionType::RolloutTransition, DecisionOutcome::Proceed) => DecisionKind::Admit,
        (DecisionType::RolloutTransition, DecisionOutcome::Fail)
        | (DecisionType::RolloutTransition, DecisionOutcome::Abort) => DecisionKind::Deny,
        (DecisionType::QuarantineAction, DecisionOutcome::Promote) => DecisionKind::Release,
        (DecisionType::QuarantineAction, DecisionOutcome::Demote) => DecisionKind::Quarantine,
        (DecisionType::FencingDecision, DecisionOutcome::Grant) => DecisionKind::Admit,
        (DecisionType::FencingDecision, DecisionOutcome::Deny) => DecisionKind::Deny,
        (DecisionType::MigrationDecision, DecisionOutcome::Proceed) => DecisionKind::Admit,
        (DecisionType::MigrationDecision, DecisionOutcome::Abort) => DecisionKind::Deny,
        // Default: deny for unmatched combinations
        _ => DecisionKind::Deny,
    }
}

/// Evidence entry for a control decision (aligned with bd-nupr schema).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEvidenceEntry {
    pub schema_version: String,
    pub decision_id: String,
    pub decision_type: DecisionType,
    pub decision_kind: DecisionKind,
    pub policy_inputs: Vec<String>,
    pub candidates_considered: Vec<String>,
    pub chosen_action: String,
    pub rejection_reasons: Vec<String>,
    pub epoch: u64,
    pub trace_id: String,
    pub timestamp_ms: u64,
}

impl ControlEvidenceEntry {
    /// Validate this entry against the canonical schema.
    pub fn validate(&self) -> Result<(), ConformanceError> {
        if self.schema_version != "1.0" {
            return Err(ConformanceError::SchemaInvalid(format!(
                "Expected schema_version '1.0', got '{}'",
                self.schema_version
            )));
        }
        if self.decision_id.is_empty() {
            return Err(ConformanceError::SchemaInvalid(
                "decision_id must not be empty".to_string(),
            ));
        }
        if self.trace_id.is_empty() {
            return Err(ConformanceError::SchemaInvalid(
                "trace_id must not be empty".to_string(),
            ));
        }
        if self.chosen_action.is_empty() {
            return Err(ConformanceError::SchemaInvalid(
                "chosen_action must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Canonical ordering key for deterministic sequencing.
    pub fn ordering_key(&self) -> (u64, &str, &str) {
        (self.timestamp_ms, &self.decision_id, &self.chosen_action)
    }
}

/// Conformance error types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceError {
    /// Evidence entry missing for a policy decision.
    MissingEvidence(String),
    /// Schema validation failed.
    SchemaInvalid(String),
    /// Ordering violation detected.
    OrderingViolation(String),
    /// Decision type mismatch.
    DecisionMismatch(String),
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConformanceError::MissingEvidence(msg) => write!(f, "missing evidence: {}", msg),
            ConformanceError::SchemaInvalid(msg) => write!(f, "schema invalid: {}", msg),
            ConformanceError::OrderingViolation(msg) => write!(f, "ordering violation: {}", msg),
            ConformanceError::DecisionMismatch(msg) => write!(f, "decision mismatch: {}", msg),
        }
    }
}

/// Audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvidenceEvent {
    pub code: String,
    pub decision_id: String,
    pub decision_type: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// ControlEvidenceEmitter
// ---------------------------------------------------------------------------

/// Enforces mandatory evidence emission for all policy-influenced
/// control decisions. A missing entry is a conformance failure.
pub struct ControlEvidenceEmitter {
    entries: Vec<ControlEvidenceEntry>,
    events: Vec<ControlEvidenceEvent>,
    /// Track which decision types have been exercised.
    coverage: Vec<(DecisionType, bool)>,
}

impl ControlEvidenceEmitter {
    pub fn new() -> Self {
        let coverage = DecisionType::all().iter().map(|dt| (*dt, false)).collect();
        ControlEvidenceEmitter {
            entries: Vec::new(),
            events: Vec::new(),
            coverage,
        }
    }

    /// Emit evidence for a control decision.
    ///
    /// Validates the entry schema, appends it to the ledger,
    /// and emits appropriate events.
    pub fn emit_evidence(&mut self, entry: ControlEvidenceEntry) -> Result<(), ConformanceError> {
        // Validate schema
        entry.validate().map_err(|e| {
            self.emit_event(
                EVD_004_SCHEMA_INVALID,
                &entry.decision_id,
                entry.decision_type,
                format!("Schema validation failed: {}", e),
            );
            e
        })?;

        self.emit_event(
            EVD_003_SCHEMA_VALID,
            &entry.decision_id,
            entry.decision_type,
            "Schema validation passed".to_string(),
        );

        // Update coverage
        for (dt, covered) in &mut self.coverage {
            if *dt == entry.decision_type {
                *covered = true;
            }
        }

        self.emit_event(
            EVD_001_ENTRY_EMITTED,
            &entry.decision_id,
            entry.decision_type,
            format!(
                "Evidence emitted: {} -> {}",
                entry.decision_type.label(),
                entry.decision_kind.label()
            ),
        );

        self.entries.push(entry);
        Ok(())
    }

    /// Execute a decision with mandatory evidence.
    ///
    /// If evidence is None, the decision is blocked (fail-closed).
    pub fn execute_with_evidence(
        &mut self,
        decision_type: DecisionType,
        evidence: Option<ControlEvidenceEntry>,
    ) -> Result<ControlEvidenceEntry, ConformanceError> {
        match evidence {
            None => {
                self.emit_event(
                    EVD_002_ENTRY_MISSING,
                    "unknown",
                    decision_type,
                    format!(
                        "Missing evidence for {} — conformance failure",
                        decision_type.label()
                    ),
                );
                Err(ConformanceError::MissingEvidence(format!(
                    "No evidence provided for {}",
                    decision_type.label()
                )))
            }
            Some(entry) => {
                if entry.decision_type != decision_type {
                    return Err(ConformanceError::DecisionMismatch(format!(
                        "Expected {}, got {}",
                        decision_type.label(),
                        entry.decision_type.label()
                    )));
                }
                self.emit_evidence(entry.clone())?;
                Ok(entry)
            }
        }
    }

    /// Verify ordering: entries for the same decision_id must be
    /// in deterministic order (by timestamp then action).
    pub fn verify_ordering(&mut self) -> Result<(), ConformanceError> {
        let mut last_key: Option<(u64, String, String)> = None;
        let mut violation: Option<(String, DecisionType)> = None;
        for entry in &self.entries {
            let key = (
                entry.timestamp_ms,
                entry.decision_id.clone(),
                entry.chosen_action.clone(),
            );
            if let Some(ref prev) = last_key
                && key < *prev
            {
                violation = Some((entry.decision_id.clone(), entry.decision_type));
                break;
            }
            last_key = Some(key);
        }
        if let Some((decision_id, decision_type)) = violation {
            self.emit_event(
                EVD_005_ORDERING_VIOLATION,
                &decision_id,
                decision_type,
                "Ordering violation detected".to_string(),
            );
            return Err(ConformanceError::OrderingViolation(format!(
                "Entry {} is out of order",
                decision_id
            )));
        }
        Ok(())
    }

    /// Check coverage: all decision types should have been exercised.
    pub fn uncovered_types(&self) -> Vec<DecisionType> {
        self.coverage
            .iter()
            .filter(|(_, covered)| !*covered)
            .map(|(dt, _)| *dt)
            .collect()
    }

    /// All emitted entries.
    pub fn entries(&self) -> &[ControlEvidenceEntry] {
        &self.entries
    }

    /// All events.
    pub fn events(&self) -> &[ControlEvidenceEvent] {
        &self.events
    }

    /// Drain and return all events.
    pub fn take_events(&mut self) -> Vec<ControlEvidenceEvent> {
        std::mem::take(&mut self.events)
    }

    /// Export entries as JSONL string.
    pub fn to_jsonl(&self) -> String {
        self.entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn emit_event(
        &mut self,
        code: &str,
        decision_id: &str,
        decision_type: DecisionType,
        detail: String,
    ) {
        self.events.push(ControlEvidenceEvent {
            code: code.to_string(),
            decision_id: decision_id.to_string(),
            decision_type: decision_type.label().to_string(),
            detail,
        });
    }
}

impl Default for ControlEvidenceEmitter {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

    // -- DecisionType ---------------------------------------------------

    #[test]
    fn test_decision_type_all() {
        assert_eq!(DecisionType::all().len(), 5);
    }

    #[test]
    fn test_decision_type_labels() {
        assert_eq!(DecisionType::HealthGateEval.label(), "health_gate_eval");
        assert_eq!(
            DecisionType::RolloutTransition.label(),
            "rollout_transition"
        );
        assert_eq!(DecisionType::QuarantineAction.label(), "quarantine_action");
        assert_eq!(DecisionType::FencingDecision.label(), "fencing_decision");
        assert_eq!(
            DecisionType::MigrationDecision.label(),
            "migration_decision"
        );
    }

    #[test]
    fn test_decision_type_display() {
        assert_eq!(
            format!("{}", DecisionType::HealthGateEval),
            "health_gate_eval"
        );
    }

    // -- DecisionKind ---------------------------------------------------

    #[test]
    fn test_decision_kind_labels() {
        assert_eq!(DecisionKind::Admit.label(), "admit");
        assert_eq!(DecisionKind::Deny.label(), "deny");
        assert_eq!(DecisionKind::Quarantine.label(), "quarantine");
        assert_eq!(DecisionKind::Release.label(), "release");
        assert_eq!(DecisionKind::Rollback.label(), "rollback");
        assert_eq!(DecisionKind::Throttle.label(), "throttle");
        assert_eq!(DecisionKind::Escalate.label(), "escalate");
    }

    #[test]
    fn test_decision_kind_display() {
        assert_eq!(format!("{}", DecisionKind::Admit), "admit");
    }

    // -- Decision mapping -----------------------------------------------

    #[test]
    fn test_map_health_gate_pass() {
        assert_eq!(
            map_decision_kind(DecisionType::HealthGateEval, DecisionOutcome::Pass),
            DecisionKind::Admit
        );
    }

    #[test]
    fn test_map_health_gate_fail() {
        assert_eq!(
            map_decision_kind(DecisionType::HealthGateEval, DecisionOutcome::Fail),
            DecisionKind::Deny
        );
    }

    #[test]
    fn test_map_rollout_go() {
        assert_eq!(
            map_decision_kind(DecisionType::RolloutTransition, DecisionOutcome::Proceed),
            DecisionKind::Admit
        );
    }

    #[test]
    fn test_map_rollout_nogo() {
        assert_eq!(
            map_decision_kind(DecisionType::RolloutTransition, DecisionOutcome::Abort),
            DecisionKind::Deny
        );
    }

    #[test]
    fn test_map_quarantine_promote() {
        assert_eq!(
            map_decision_kind(DecisionType::QuarantineAction, DecisionOutcome::Promote),
            DecisionKind::Release
        );
    }

    #[test]
    fn test_map_quarantine_demote() {
        assert_eq!(
            map_decision_kind(DecisionType::QuarantineAction, DecisionOutcome::Demote),
            DecisionKind::Quarantine
        );
    }

    #[test]
    fn test_map_fencing_grant() {
        assert_eq!(
            map_decision_kind(DecisionType::FencingDecision, DecisionOutcome::Grant),
            DecisionKind::Admit
        );
    }

    #[test]
    fn test_map_fencing_deny() {
        assert_eq!(
            map_decision_kind(DecisionType::FencingDecision, DecisionOutcome::Deny),
            DecisionKind::Deny
        );
    }

    #[test]
    fn test_map_migration_proceed() {
        assert_eq!(
            map_decision_kind(DecisionType::MigrationDecision, DecisionOutcome::Proceed),
            DecisionKind::Admit
        );
    }

    #[test]
    fn test_map_migration_abort() {
        assert_eq!(
            map_decision_kind(DecisionType::MigrationDecision, DecisionOutcome::Abort),
            DecisionKind::Deny
        );
    }

    // -- ControlEvidenceEntry validation --------------------------------

    #[test]
    fn test_entry_validate_valid() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_entry_validate_bad_schema_version() {
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        entry.schema_version = "2.0".to_string();
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, ConformanceError::SchemaInvalid(_)));
    }

    #[test]
    fn test_entry_validate_empty_decision_id() {
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        entry.decision_id = String::new();
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, ConformanceError::SchemaInvalid(_)));
    }

    #[test]
    fn test_entry_validate_empty_trace_id() {
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        entry.trace_id = String::new();
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, ConformanceError::SchemaInvalid(_)));
    }

    #[test]
    fn test_entry_validate_empty_action() {
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        entry.chosen_action = String::new();
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, ConformanceError::SchemaInvalid(_)));
    }

    // -- ControlEvidenceEmitter: emit evidence --------------------------

    #[test]
    fn test_emit_valid_evidence() {
        let mut emitter = ControlEvidenceEmitter::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        assert!(emitter.emit_evidence(entry).is_ok());
        assert_eq!(emitter.entries().len(), 1);
    }

    #[test]
    fn test_emit_invalid_evidence_rejected() {
        let mut emitter = ControlEvidenceEmitter::new();
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        entry.schema_version = "bad".to_string();
        assert!(emitter.emit_evidence(entry).is_err());
        assert_eq!(emitter.entries().len(), 0);
    }

    #[test]
    fn test_emit_emits_evd001_event() {
        let mut emitter = ControlEvidenceEmitter::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        emitter.emit_evidence(entry).unwrap();
        let emitted: Vec<_> = emitter
            .events()
            .iter()
            .filter(|e| e.code == EVD_001_ENTRY_EMITTED)
            .collect();
        assert_eq!(emitted.len(), 1);
    }

    #[test]
    fn test_emit_emits_evd003_event() {
        let mut emitter = ControlEvidenceEmitter::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        emitter.emit_evidence(entry).unwrap();
        let validated: Vec<_> = emitter
            .events()
            .iter()
            .filter(|e| e.code == EVD_003_SCHEMA_VALID)
            .collect();
        assert_eq!(validated.len(), 1);
    }

    #[test]
    fn test_emit_invalid_emits_evd004_event() {
        let mut emitter = ControlEvidenceEmitter::new();
        let mut entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        entry.schema_version = "bad".to_string();
        let _ = emitter.emit_evidence(entry);
        let invalid: Vec<_> = emitter
            .events()
            .iter()
            .filter(|e| e.code == EVD_004_SCHEMA_INVALID)
            .collect();
        assert_eq!(invalid.len(), 1);
    }

    // -- ControlEvidenceEmitter: execute_with_evidence ------------------

    #[test]
    fn test_execute_with_evidence_success() {
        let mut emitter = ControlEvidenceEmitter::new();
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        let result = emitter.execute_with_evidence(DecisionType::HealthGateEval, Some(entry));
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_without_evidence_fails() {
        let mut emitter = ControlEvidenceEmitter::new();
        let result = emitter.execute_with_evidence(DecisionType::HealthGateEval, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConformanceError::MissingEvidence(_)
        ));
    }

    #[test]
    fn test_execute_without_evidence_emits_evd002() {
        let mut emitter = ControlEvidenceEmitter::new();
        let _ = emitter.execute_with_evidence(DecisionType::HealthGateEval, None);
        let missing: Vec<_> = emitter
            .events()
            .iter()
            .filter(|e| e.code == EVD_002_ENTRY_MISSING)
            .collect();
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn test_execute_with_wrong_type_fails() {
        let mut emitter = ControlEvidenceEmitter::new();
        let entry = make_entry(
            DecisionType::FencingDecision,
            DecisionOutcome::Grant,
            "d1",
            100,
        );
        let result = emitter.execute_with_evidence(DecisionType::HealthGateEval, Some(entry));
        assert!(matches!(
            result.unwrap_err(),
            ConformanceError::DecisionMismatch(_)
        ));
    }

    // -- Ordering verification ------------------------------------------

    #[test]
    fn test_ordering_valid() {
        let mut emitter = ControlEvidenceEmitter::new();
        emitter
            .emit_evidence(make_entry(
                DecisionType::HealthGateEval,
                DecisionOutcome::Pass,
                "d1",
                100,
            ))
            .unwrap();
        emitter
            .emit_evidence(make_entry(
                DecisionType::RolloutTransition,
                DecisionOutcome::Proceed,
                "d2",
                200,
            ))
            .unwrap();
        assert!(emitter.verify_ordering().is_ok());
    }

    #[test]
    fn test_ordering_violation_detected() {
        let mut emitter = ControlEvidenceEmitter::new();
        emitter
            .emit_evidence(make_entry(
                DecisionType::HealthGateEval,
                DecisionOutcome::Pass,
                "d2",
                200,
            ))
            .unwrap();
        // Insert entry with earlier timestamp
        emitter
            .emit_evidence(make_entry(
                DecisionType::RolloutTransition,
                DecisionOutcome::Proceed,
                "d1",
                100,
            ))
            .unwrap();
        let result = emitter.verify_ordering();
        assert!(matches!(
            result,
            Err(ConformanceError::OrderingViolation(_))
        ));
    }

    #[test]
    fn test_ordering_violation_emits_evd005() {
        let mut emitter = ControlEvidenceEmitter::new();
        emitter
            .emit_evidence(make_entry(
                DecisionType::HealthGateEval,
                DecisionOutcome::Pass,
                "d2",
                200,
            ))
            .unwrap();
        emitter
            .emit_evidence(make_entry(
                DecisionType::RolloutTransition,
                DecisionOutcome::Proceed,
                "d1",
                100,
            ))
            .unwrap();
        let _ = emitter.verify_ordering();
        let violations: Vec<_> = emitter
            .events()
            .iter()
            .filter(|e| e.code == EVD_005_ORDERING_VIOLATION)
            .collect();
        assert_eq!(violations.len(), 1);
    }

    // -- Coverage tracking ----------------------------------------------

    #[test]
    fn test_coverage_starts_empty() {
        let emitter = ControlEvidenceEmitter::new();
        assert_eq!(emitter.uncovered_types().len(), 5);
    }

    #[test]
    fn test_coverage_tracks_emitted_types() {
        let mut emitter = ControlEvidenceEmitter::new();
        emitter
            .emit_evidence(make_entry(
                DecisionType::HealthGateEval,
                DecisionOutcome::Pass,
                "d1",
                100,
            ))
            .unwrap();
        assert_eq!(emitter.uncovered_types().len(), 4);
    }

    #[test]
    fn test_full_coverage() {
        let mut emitter = ControlEvidenceEmitter::new();
        for (i, dt) in DecisionType::all().iter().enumerate() {
            let outcome = match dt {
                DecisionType::QuarantineAction => DecisionOutcome::Promote,
                DecisionType::FencingDecision => DecisionOutcome::Grant,
                _ => DecisionOutcome::Pass,
            };
            emitter
                .emit_evidence(make_entry(
                    *dt,
                    outcome,
                    &format!("d{}", i),
                    (i as u64 + 1) * 100,
                ))
                .unwrap();
        }
        assert!(emitter.uncovered_types().is_empty());
    }

    // -- Determinism ----------------------------------------------------

    #[test]
    fn test_deterministic_entries() {
        let mut e1 = ControlEvidenceEmitter::new();
        let mut e2 = ControlEvidenceEmitter::new();

        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        e1.emit_evidence(entry.clone()).unwrap();
        e2.emit_evidence(entry).unwrap();

        assert_eq!(e1.entries(), e2.entries());
    }

    #[test]
    fn test_deterministic_jsonl() {
        let mut e1 = ControlEvidenceEmitter::new();
        let mut e2 = ControlEvidenceEmitter::new();

        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        e1.emit_evidence(entry.clone()).unwrap();
        e2.emit_evidence(entry).unwrap();

        assert_eq!(e1.to_jsonl(), e2.to_jsonl());
    }

    // -- JSONL export ---------------------------------------------------

    #[test]
    fn test_jsonl_export() {
        let mut emitter = ControlEvidenceEmitter::new();
        emitter
            .emit_evidence(make_entry(
                DecisionType::HealthGateEval,
                DecisionOutcome::Pass,
                "d1",
                100,
            ))
            .unwrap();
        let jsonl = emitter.to_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&jsonl).unwrap();
        assert_eq!(parsed["decision_id"], "d1");
    }

    #[test]
    fn test_jsonl_multiple_entries() {
        let mut emitter = ControlEvidenceEmitter::new();
        emitter
            .emit_evidence(make_entry(
                DecisionType::HealthGateEval,
                DecisionOutcome::Pass,
                "d1",
                100,
            ))
            .unwrap();
        emitter
            .emit_evidence(make_entry(
                DecisionType::FencingDecision,
                DecisionOutcome::Grant,
                "d2",
                200,
            ))
            .unwrap();
        let jsonl = emitter.to_jsonl();
        let lines: Vec<_> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    // -- Events ---------------------------------------------------------

    #[test]
    fn test_take_events_drains() {
        let mut emitter = ControlEvidenceEmitter::new();
        emitter
            .emit_evidence(make_entry(
                DecisionType::HealthGateEval,
                DecisionOutcome::Pass,
                "d1",
                100,
            ))
            .unwrap();
        assert!(!emitter.events().is_empty());
        let events = emitter.take_events();
        assert!(!events.is_empty());
        assert!(emitter.events().is_empty());
    }

    // -- ConformanceError display ---------------------------------------

    #[test]
    fn test_conformance_error_display_missing() {
        let err = ConformanceError::MissingEvidence("test".into());
        assert!(format!("{}", err).contains("missing evidence"));
    }

    #[test]
    fn test_conformance_error_display_schema() {
        let err = ConformanceError::SchemaInvalid("bad field".into());
        assert!(format!("{}", err).contains("schema invalid"));
    }

    #[test]
    fn test_conformance_error_display_ordering() {
        let err = ConformanceError::OrderingViolation("out of order".into());
        assert!(format!("{}", err).contains("ordering violation"));
    }

    #[test]
    fn test_conformance_error_display_mismatch() {
        let err = ConformanceError::DecisionMismatch("wrong type".into());
        assert!(format!("{}", err).contains("decision mismatch"));
    }

    // -- Serde roundtrips -----------------------------------------------

    #[test]
    fn test_entry_serde_roundtrip() {
        let entry = make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "d1",
            100,
        );
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ControlEvidenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn test_decision_type_serde_roundtrip() {
        for dt in DecisionType::all() {
            let json = serde_json::to_string(dt).unwrap();
            let parsed: DecisionType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *dt);
        }
    }

    #[test]
    fn test_conformance_error_serde_roundtrip() {
        let err = ConformanceError::MissingEvidence("test".into());
        let json = serde_json::to_string(&err).unwrap();
        let parsed: ConformanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    // -- Event code constants -------------------------------------------

    #[test]
    fn test_event_codes_defined() {
        assert!(!EVD_001_ENTRY_EMITTED.is_empty());
        assert!(!EVD_002_ENTRY_MISSING.is_empty());
        assert!(!EVD_003_SCHEMA_VALID.is_empty());
        assert!(!EVD_004_SCHEMA_INVALID.is_empty());
        assert!(!EVD_005_ORDERING_VIOLATION.is_empty());
    }

    // -- Invariant constants --------------------------------------------

    #[test]
    fn test_invariant_constants_defined() {
        assert!(!INV_CE_MANDATORY.is_empty());
        assert!(!INV_CE_SCHEMA.is_empty());
        assert!(!INV_CE_DETERMINISTIC.is_empty());
        assert!(!INV_CE_FAIL_CLOSED.is_empty());
    }

    // -- Default trait --------------------------------------------------

    #[test]
    fn test_default_emitter() {
        let emitter = ControlEvidenceEmitter::default();
        assert!(emitter.entries().is_empty());
        assert!(emitter.events().is_empty());
    }

    // -- All decision types emit evidence successfully ------------------

    #[test]
    fn test_all_types_can_emit() {
        let mut emitter = ControlEvidenceEmitter::new();
        let outcomes = [
            (DecisionType::HealthGateEval, DecisionOutcome::Pass),
            (DecisionType::RolloutTransition, DecisionOutcome::Proceed),
            (DecisionType::QuarantineAction, DecisionOutcome::Promote),
            (DecisionType::FencingDecision, DecisionOutcome::Grant),
            (DecisionType::MigrationDecision, DecisionOutcome::Proceed),
        ];
        for (i, (dt, outcome)) in outcomes.iter().enumerate() {
            let entry = make_entry(*dt, *outcome, &format!("d{}", i), (i as u64 + 1) * 100);
            assert!(emitter.emit_evidence(entry).is_ok());
        }
        assert_eq!(emitter.entries().len(), 5);
    }
}
