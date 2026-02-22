//! bd-3h63: Generic saga wrappers with deterministic compensations.
//!
//! Provides a `SagaExecutor` that runs multi-step workflows with
//! forward actions and compensating actions. On failure/cancel,
//! compensations execute in reverse order.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Constants ────────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "saga-v1.0";

// ── Event codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Saga instance created and registered.
    pub const SAG_SAGA_STARTED: &str = "SAG-001";
    /// A forward step executed successfully.
    pub const SAG_STEP_FORWARD: &str = "SAG-002";
    /// A compensating action executed for a completed step.
    pub const SAG_STEP_COMPENSATED: &str = "SAG-003";
    /// All forward steps completed; saga committed.
    pub const SAG_SAGA_COMMITTED: &str = "SAG-004";
    /// All necessary compensations completed; saga fully rolled back.
    pub const SAG_SAGA_COMPENSATED: &str = "SAG-005";
    /// A compensation action itself failed (requires operator attention).
    pub const SAG_COMPENSATION_FAILURE: &str = "SAG-006";
    /// A forward step was skipped (pre-condition not met).
    pub const SAG_STEP_SKIPPED: &str = "SAG-007";
    /// Compensation trace exported for audit/replay.
    pub const SAG_TRACE_EXPORTED: &str = "SAG-008";
}

// ── Invariants ───────────────────────────────────────────────────────────────

pub mod invariants {
    /// Every saga reaches a terminal state (Committed, Compensated, or Failed).
    pub const INV_SAGA_TERMINAL: &str = "INV-SAGA-TERMINAL";
    /// Compensations execute in strict reverse order of forward steps.
    pub const INV_SAGA_REVERSE_COMP: &str = "INV-SAGA-REVERSE-COMP";
    /// Compensations are idempotent; re-compensating a Compensated saga is a no-op.
    pub const INV_SAGA_IDEMPOTENT_COMP: &str = "INV-SAGA-IDEMPOTENT-COMP";
    /// Same inputs produce the same trace output (deterministic).
    pub const INV_SAGA_DETERMINISTIC: &str = "INV-SAGA-DETERMINISTIC";
    /// Every state transition is recorded in the audit log.
    pub const INV_SAGA_AUDITABLE: &str = "INV-SAGA-AUDITABLE";
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Step outcome after executing a forward or compensating action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepOutcome {
    /// Forward step succeeded with optional result data.
    Success { result_data: Vec<u8> },
    /// Forward step failed with a reason string.
    Failed { reason: String },
    /// Step was skipped (pre-condition not met).
    Skipped { reason: String },
    /// Step was compensated (rolled back).
    Compensated,
}

impl fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StepOutcome::Success { .. } => write!(f, "Success"),
            StepOutcome::Failed { reason } => write!(f, "Failed({reason})"),
            StepOutcome::Skipped { reason } => write!(f, "Skipped({reason})"),
            StepOutcome::Compensated => write!(f, "Compensated"),
        }
    }
}

/// A single step definition within a saga.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaStepDef {
    /// Human-readable step name.
    pub name: String,
    /// If the step invokes a remote computation, the registry name.
    pub computation_name: Option<String>,
    /// Whether this step involves a remote call.
    pub is_remote: bool,
    /// Optional idempotency key for safe retries.
    pub idempotency_key: Option<String>,
}

/// A record of a step execution (forward or compensate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    /// Index of the step in the saga definition.
    pub step_index: usize,
    /// Name of the step.
    pub step_name: String,
    /// Action performed: "forward" or "compensate".
    pub action: String,
    /// Outcome of the action.
    pub outcome: StepOutcome,
    /// Wall-clock time in milliseconds.
    pub elapsed_ms: u64,
}

/// Saga lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaState {
    /// Saga created but no steps executed yet.
    Pending,
    /// At least one forward step has executed; saga is in progress.
    Running,
    /// All forward steps completed successfully.
    Committed,
    /// Compensations are being applied.
    Compensating,
    /// All necessary compensations completed.
    Compensated,
    /// A compensation failed; requires operator intervention.
    Failed,
}

impl fmt::Display for SagaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SagaState::Pending => write!(f, "Pending"),
            SagaState::Running => write!(f, "Running"),
            SagaState::Committed => write!(f, "Committed"),
            SagaState::Compensating => write!(f, "Compensating"),
            SagaState::Compensated => write!(f, "Compensated"),
            SagaState::Failed => write!(f, "Failed"),
        }
    }
}

/// A saga instance tracking step definitions, execution state, and records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaInstance {
    /// Unique saga identifier.
    pub saga_id: String,
    /// Current lifecycle state.
    pub state: SagaState,
    /// Ordered list of step definitions.
    pub steps: Vec<SagaStepDef>,
    /// Number of forward steps that have completed (Success or Skipped).
    pub completed_steps: usize,
    /// Chronological execution records (forward + compensate).
    pub records: Vec<StepRecord>,
}

/// Compensation trace for replay and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompensationTrace {
    /// Saga ID this trace belongs to.
    pub saga_id: String,
    /// Records of compensation actions, in the order they were executed
    /// (which is reverse of the forward order).
    pub compensated_steps: Vec<StepRecord>,
    /// Final state after compensation.
    pub final_state: SagaState,
}

/// Audit record emitted for every significant saga event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaAuditRecord {
    /// Event code (SAG-001 through SAG-008).
    pub event_code: String,
    /// Distributed trace ID for correlation.
    pub trace_id: String,
    /// Saga ID this event relates to.
    pub saga_id: String,
    /// Structured detail payload.
    pub detail: serde_json::Value,
}

/// The generic saga executor managing multiple saga instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaExecutor {
    sagas: BTreeMap<String, SagaInstance>,
    audit_log: Vec<SagaAuditRecord>,
    next_saga_id: u64,
}

impl SagaExecutor {
    /// Create a new, empty saga executor.
    pub fn new() -> Self {
        Self {
            sagas: BTreeMap::new(),
            audit_log: Vec::new(),
            next_saga_id: 1,
        }
    }

    /// Internal: append an audit record.
    fn log(&mut self, event_code: &str, trace_id: &str, saga_id: &str, detail: serde_json::Value) {
        self.audit_log.push(SagaAuditRecord {
            event_code: event_code.to_string(),
            trace_id: trace_id.to_string(),
            saga_id: saga_id.to_string(),
            detail,
        });
    }

    /// Create a new saga with a list of step definitions.
    ///
    /// Returns the saga ID. The saga starts in `Pending` state.
    pub fn create_saga(&mut self, steps: Vec<SagaStepDef>, trace_id: &str) -> String {
        let saga_id = format!("saga-{}", self.next_saga_id);
        self.next_saga_id += 1;

        let step_names: Vec<_> = steps.iter().map(|s| s.name.clone()).collect();

        let saga = SagaInstance {
            saga_id: saga_id.clone(),
            state: SagaState::Pending,
            steps,
            completed_steps: 0,
            records: Vec::new(),
        };

        self.sagas.insert(saga_id.clone(), saga);

        self.log(
            event_codes::SAG_SAGA_STARTED,
            trace_id,
            &saga_id,
            serde_json::json!({
                "step_count": step_names.len(),
                "steps": step_names,
            }),
        );

        saga_id
    }

    /// Execute the next forward step of a saga.
    ///
    /// The caller provides the outcome of the step execution and timing.
    /// Returns the step index that was executed.
    ///
    /// # Errors
    /// - Saga not found
    /// - Saga not in a state that allows forward execution (must be Pending or Running)
    /// - All steps already completed
    pub fn execute_step(
        &mut self,
        saga_id: &str,
        outcome: StepOutcome,
        elapsed_ms: u64,
        trace_id: &str,
    ) -> Result<usize, String> {
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.state != SagaState::Pending && saga.state != SagaState::Running {
            return Err(format!(
                "saga {saga_id} in state {} cannot execute forward steps",
                saga.state
            ));
        }

        let step_index = saga.completed_steps;
        if step_index >= saga.steps.len() {
            return Err(format!(
                "saga {saga_id} has no more steps to execute ({} of {})",
                step_index,
                saga.steps.len()
            ));
        }

        let step_name = saga.steps[step_index].name.clone();

        // Determine the event code based on outcome
        let event_code = match &outcome {
            StepOutcome::Success { .. } => event_codes::SAG_STEP_FORWARD,
            StepOutcome::Failed { .. } => event_codes::SAG_STEP_FORWARD,
            StepOutcome::Skipped { .. } => event_codes::SAG_STEP_SKIPPED,
            StepOutcome::Compensated => event_codes::SAG_STEP_FORWARD,
        };

        let record = StepRecord {
            step_index,
            step_name: step_name.clone(),
            action: "forward".to_string(),
            outcome: outcome.clone(),
            elapsed_ms,
        };

        saga.records.push(record);
        saga.completed_steps += 1;
        saga.state = SagaState::Running;

        self.log(
            event_code,
            trace_id,
            saga_id,
            serde_json::json!({
                "step_index": step_index,
                "step_name": step_name,
                "outcome": format!("{outcome}"),
                "elapsed_ms": elapsed_ms,
            }),
        );

        Ok(step_index)
    }

    /// Commit the saga after all forward steps have succeeded.
    ///
    /// # Errors
    /// - Saga not found
    /// - Not all steps completed
    /// - Any step failed (must compensate instead)
    pub fn commit(&mut self, saga_id: &str, trace_id: &str) -> Result<(), String> {
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.state != SagaState::Running {
            return Err(format!(
                "saga {saga_id} in state {} cannot commit (must be Running)",
                saga.state
            ));
        }

        if saga.completed_steps < saga.steps.len() {
            return Err(format!(
                "saga {saga_id} has only completed {} of {} steps",
                saga.completed_steps,
                saga.steps.len()
            ));
        }

        // Check that no step failed
        let has_failure = saga
            .records
            .iter()
            .any(|r| r.action == "forward" && matches!(r.outcome, StepOutcome::Failed { .. }));
        if has_failure {
            return Err(format!(
                "saga {saga_id} has failed steps; must compensate, not commit"
            ));
        }

        saga.state = SagaState::Committed;
        let completed_steps = saga.completed_steps;

        self.log(
            event_codes::SAG_SAGA_COMMITTED,
            trace_id,
            saga_id,
            serde_json::json!({
                "completed_steps": completed_steps,
            }),
        );

        Ok(())
    }

    /// Compensate (roll back) a saga by executing compensations in reverse order.
    ///
    /// Only forward steps that succeeded (not skipped, not failed) are compensated.
    /// Compensations execute in strict reverse order per INV-SAGA-REVERSE-COMP.
    ///
    /// If the saga is already Compensated, this is a no-op per INV-SAGA-IDEMPOTENT-COMP.
    ///
    /// # Errors
    /// - Saga not found
    /// - Saga in Committed state (cannot compensate after commit)
    pub fn compensate(
        &mut self,
        saga_id: &str,
        trace_id: &str,
    ) -> Result<CompensationTrace, String> {
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        // Idempotent: already compensated is a no-op
        if saga.state == SagaState::Compensated {
            return Ok(CompensationTrace {
                saga_id: saga_id.to_string(),
                compensated_steps: Vec::new(),
                final_state: SagaState::Compensated,
            });
        }

        if saga.state == SagaState::Committed {
            return Err(format!(
                "saga {saga_id} is Committed and cannot be compensated"
            ));
        }

        saga.state = SagaState::Compensating;

        // Collect indices of steps that succeeded (need compensation), in forward order
        let succeeded_indices: Vec<usize> = saga
            .records
            .iter()
            .filter(|r| r.action == "forward" && matches!(r.outcome, StepOutcome::Success { .. }))
            .map(|r| r.step_index)
            .collect();

        // Compensate in reverse order (INV-SAGA-REVERSE-COMP)
        let mut comp_records = Vec::new();
        for &idx in succeeded_indices.iter().rev() {
            let step_name = saga.steps[idx].name.clone();
            let record = StepRecord {
                step_index: idx,
                step_name: step_name.clone(),
                action: "compensate".to_string(),
                outcome: StepOutcome::Compensated,
                elapsed_ms: 0,
            };
            comp_records.push(record.clone());
            saga.records.push(record);
        }

        saga.state = SagaState::Compensated;
        let final_state = saga.state;

        // Log each compensation
        for rec in &comp_records {
            self.log(
                event_codes::SAG_STEP_COMPENSATED,
                trace_id,
                saga_id,
                serde_json::json!({
                    "step_index": rec.step_index,
                    "step_name": rec.step_name,
                }),
            );
        }

        self.log(
            event_codes::SAG_SAGA_COMPENSATED,
            trace_id,
            saga_id,
            serde_json::json!({
                "compensated_count": comp_records.len(),
            }),
        );

        Ok(CompensationTrace {
            saga_id: saga_id.to_string(),
            compensated_steps: comp_records,
            final_state,
        })
    }

    /// Get a saga by ID.
    pub fn get_saga(&self, saga_id: &str) -> Option<&SagaInstance> {
        self.sagas.get(saga_id)
    }

    /// Export compensation trace for a saga.
    ///
    /// Returns `None` if the saga does not exist or has not been compensated.
    pub fn export_trace(&self, saga_id: &str) -> Option<CompensationTrace> {
        let saga = self.sagas.get(saga_id)?;

        let comp_records: Vec<StepRecord> = saga
            .records
            .iter()
            .filter(|r| r.action == "compensate")
            .cloned()
            .collect();

        if comp_records.is_empty() && saga.state != SagaState::Compensated {
            return None;
        }

        Some(CompensationTrace {
            saga_id: saga_id.to_string(),
            compensated_steps: comp_records,
            final_state: saga.state,
        })
    }

    /// Export the full audit log as JSONL (one JSON object per line).
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Compute a deterministic content hash over all saga state.
    pub fn content_hash(&self) -> String {
        let content = serde_json::to_string(&self.sagas).unwrap_or_default();
        format!("{:x}", Sha256::digest(content.as_bytes()))
    }

    /// Return the number of sagas tracked by this executor.
    pub fn saga_count(&self) -> usize {
        self.sagas.len()
    }
}

impl Default for SagaExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_steps(names: &[&str]) -> Vec<SagaStepDef> {
        names
            .iter()
            .map(|n| SagaStepDef {
                name: n.to_string(),
                computation_name: None,
                is_remote: false,
                idempotency_key: None,
            })
            .collect()
    }

    fn success_outcome() -> StepOutcome {
        StepOutcome::Success {
            result_data: vec![],
        }
    }

    // 1. test_create_saga
    #[test]
    fn test_create_saga() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["step_a", "step_b", "step_c"]);
        let id = exec.create_saga(steps, "trace-1");
        assert_eq!(id, "saga-1");
        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.state, SagaState::Pending);
        assert_eq!(saga.steps.len(), 3);
        assert_eq!(saga.completed_steps, 0);
    }

    // 2. test_execute_steps_in_order
    #[test]
    fn test_execute_steps_in_order() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["s1", "s2", "s3"]);
        let id = exec.create_saga(steps, "t");

        let idx0 = exec.execute_step(&id, success_outcome(), 10, "t").unwrap();
        assert_eq!(idx0, 0);
        let idx1 = exec.execute_step(&id, success_outcome(), 20, "t").unwrap();
        assert_eq!(idx1, 1);
        let idx2 = exec.execute_step(&id, success_outcome(), 30, "t").unwrap();
        assert_eq!(idx2, 2);

        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.completed_steps, 3);
        assert_eq!(saga.state, SagaState::Running);
    }

    // 3. test_commit_all_steps
    #[test]
    fn test_commit_all_steps() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b"]);
        let id = exec.create_saga(steps, "t");
        exec.execute_step(&id, success_outcome(), 5, "t").unwrap();
        exec.execute_step(&id, success_outcome(), 5, "t").unwrap();
        exec.commit(&id, "t").unwrap();

        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.state, SagaState::Committed);
    }

    // 4. test_compensate_reverses
    #[test]
    fn test_compensate_reverses() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["s0", "s1", "s2"]);
        let id = exec.create_saga(steps, "t");

        exec.execute_step(&id, success_outcome(), 5, "t").unwrap();
        exec.execute_step(&id, success_outcome(), 5, "t").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "boom".to_string(),
            },
            5,
            "t",
        )
        .unwrap();

        let trace = exec.compensate(&id, "t").unwrap();

        // Only s0 and s1 succeeded (s2 failed), so compensated in reverse: s1, s0
        assert_eq!(trace.compensated_steps.len(), 2);
        assert_eq!(trace.compensated_steps[0].step_index, 1); // s1 first (reverse)
        assert_eq!(trace.compensated_steps[1].step_index, 0); // s0 second
        assert_eq!(trace.final_state, SagaState::Compensated);
    }

    // 5. test_compensate_partial
    #[test]
    fn test_compensate_partial() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b", "c", "d"]);
        let id = exec.create_saga(steps, "t");

        // Execute a, b successfully, then c fails
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "err".to_string(),
            },
            1,
            "t",
        )
        .unwrap();
        // d never executed

        let trace = exec.compensate(&id, "t").unwrap();
        // Compensate b (index 1) then a (index 0) -- reverse of success order
        assert_eq!(trace.compensated_steps.len(), 2);
        assert_eq!(trace.compensated_steps[0].step_index, 1);
        assert_eq!(trace.compensated_steps[1].step_index, 0);
    }

    // 6. test_no_intermediate_state (INV-SAGA-TERMINAL)
    #[test]
    fn test_no_intermediate_state() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["x"]);
        let id = exec.create_saga(steps, "t");
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.commit(&id, "t").unwrap();

        let saga = exec.get_saga(&id).unwrap();
        // Terminal state: Committed
        assert!(
            saga.state == SagaState::Committed
                || saga.state == SagaState::Compensated
                || saga.state == SagaState::Failed
        );
    }

    // 7. test_idempotent_compensation (INV-SAGA-IDEMPOTENT-COMP)
    #[test]
    fn test_idempotent_compensation() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b"]);
        let id = exec.create_saga(steps, "t");
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "x".to_string(),
            },
            1,
            "t",
        )
        .unwrap();

        let trace1 = exec.compensate(&id, "t").unwrap();
        assert_eq!(trace1.compensated_steps.len(), 1); // Only 'a' succeeded

        // Second compensate is a no-op
        let trace2 = exec.compensate(&id, "t").unwrap();
        assert_eq!(trace2.compensated_steps.len(), 0);
        assert_eq!(trace2.final_state, SagaState::Compensated);
    }

    // 8. test_compensation_trace_deterministic (INV-SAGA-DETERMINISTIC)
    #[test]
    fn test_compensation_trace_deterministic() {
        // Run the same saga twice and compare traces
        let run = || {
            let mut exec = SagaExecutor::new();
            let steps = make_steps(&["s1", "s2", "s3"]);
            let id = exec.create_saga(steps, "t");
            exec.execute_step(&id, success_outcome(), 5, "t").unwrap();
            exec.execute_step(&id, success_outcome(), 10, "t").unwrap();
            exec.execute_step(
                &id,
                StepOutcome::Failed {
                    reason: "err".to_string(),
                },
                1,
                "t",
            )
            .unwrap();
            exec.compensate(&id, "t").unwrap()
        };

        let t1 = run();
        let t2 = run();

        assert_eq!(t1.compensated_steps.len(), t2.compensated_steps.len());
        for (a, b) in t1.compensated_steps.iter().zip(t2.compensated_steps.iter()) {
            assert_eq!(a.step_index, b.step_index);
            assert_eq!(a.step_name, b.step_name);
            assert_eq!(a.action, b.action);
        }
        assert_eq!(t1.final_state, t2.final_state);
    }

    // 9. test_compensation_trace_records_all
    #[test]
    fn test_compensation_trace_records_all() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b", "c"]);
        let id = exec.create_saga(steps, "t");
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();

        // Don't commit, compensate instead
        let trace = exec.compensate(&id, "t").unwrap();

        // All 3 steps succeeded, so all 3 should be compensated
        assert_eq!(trace.compensated_steps.len(), 3);
        // Verify all recorded in the trace
        let indices: Vec<usize> = trace
            .compensated_steps
            .iter()
            .map(|r| r.step_index)
            .collect();
        assert_eq!(indices, vec![2, 1, 0]); // reverse order
    }

    // 10. test_saga_not_found
    #[test]
    fn test_saga_not_found() {
        let mut exec = SagaExecutor::new();

        assert!(
            exec.execute_step("nonexistent", success_outcome(), 1, "t")
                .is_err()
        );
        assert!(exec.commit("nonexistent", "t").is_err());
        assert!(exec.compensate("nonexistent", "t").is_err());
        assert!(exec.get_saga("nonexistent").is_none());
        assert!(exec.export_trace("nonexistent").is_none());
    }

    // 11. test_content_hash_deterministic
    #[test]
    fn test_content_hash_deterministic() {
        let mut e1 = SagaExecutor::new();
        let mut e2 = SagaExecutor::new();

        let steps1 = make_steps(&["a", "b"]);
        let steps2 = make_steps(&["a", "b"]);

        e1.create_saga(steps1, "t");
        e2.create_saga(steps2, "t");

        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    // 12. test_audit_log
    #[test]
    fn test_audit_log() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a"]);
        let id = exec.create_saga(steps, "t1");
        exec.execute_step(&id, success_outcome(), 1, "t2").unwrap();
        exec.commit(&id, "t3").unwrap();

        let jsonl = exec.export_audit_log_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        // At minimum: SAG_SAGA_STARTED, SAG_STEP_FORWARD, SAG_SAGA_COMMITTED
        assert!(
            lines.len() >= 3,
            "Expected >= 3 audit lines, got {}",
            lines.len()
        );

        // Each line should be valid JSON
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("event_code").is_some());
            assert!(parsed.get("trace_id").is_some());
            assert!(parsed.get("saga_id").is_some());
        }
    }

    // 13. test_saga_state_transitions
    #[test]
    fn test_saga_state_transitions() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b"]);
        let id = exec.create_saga(steps, "t");

        // Pending -> Running (first step)
        assert_eq!(exec.get_saga(&id).unwrap().state, SagaState::Pending);
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        assert_eq!(exec.get_saga(&id).unwrap().state, SagaState::Running);

        // Cannot commit until all steps done
        assert!(exec.commit(&id, "t").is_err());

        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        // Running -> Committed
        exec.commit(&id, "t").unwrap();
        assert_eq!(exec.get_saga(&id).unwrap().state, SagaState::Committed);

        // Cannot compensate a committed saga
        assert!(exec.compensate(&id, "t").is_err());

        // Cannot execute more steps on a committed saga
        assert!(exec.execute_step(&id, success_outcome(), 1, "t").is_err());
    }

    // 14. test_step_with_remote_computation
    #[test]
    fn test_step_with_remote_computation() {
        let mut exec = SagaExecutor::new();
        let steps = vec![
            SagaStepDef {
                name: "local_prep".to_string(),
                computation_name: None,
                is_remote: false,
                idempotency_key: None,
            },
            SagaStepDef {
                name: "remote_call".to_string(),
                computation_name: Some("matrix_multiply".to_string()),
                is_remote: true,
                idempotency_key: Some("idem-123".to_string()),
            },
            SagaStepDef {
                name: "local_finalize".to_string(),
                computation_name: None,
                is_remote: false,
                idempotency_key: None,
            },
        ];
        let id = exec.create_saga(steps, "t");

        let saga = exec.get_saga(&id).unwrap();
        assert!(saga.steps[1].is_remote);
        assert_eq!(
            saga.steps[1].computation_name.as_deref(),
            Some("matrix_multiply")
        );
        assert_eq!(saga.steps[1].idempotency_key.as_deref(), Some("idem-123"));

        // Execute all steps
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Success {
                result_data: vec![42, 43],
            },
            100,
            "t",
        )
        .unwrap();
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.commit(&id, "t").unwrap();

        assert_eq!(exec.get_saga(&id).unwrap().state, SagaState::Committed);
    }

    // 15. test_multiple_sagas
    #[test]
    fn test_multiple_sagas() {
        let mut exec = SagaExecutor::new();
        let id1 = exec.create_saga(make_steps(&["a"]), "t");
        let id2 = exec.create_saga(make_steps(&["b"]), "t");
        let id3 = exec.create_saga(make_steps(&["c"]), "t");

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_eq!(exec.saga_count(), 3);

        // Commit saga 1
        exec.execute_step(&id1, success_outcome(), 1, "t").unwrap();
        exec.commit(&id1, "t").unwrap();

        // Compensate saga 2
        exec.execute_step(
            &id2,
            StepOutcome::Failed {
                reason: "err".to_string(),
            },
            1,
            "t",
        )
        .unwrap();
        exec.compensate(&id2, "t").unwrap();

        // Saga 3 still pending
        assert_eq!(exec.get_saga(&id1).unwrap().state, SagaState::Committed);
        assert_eq!(exec.get_saga(&id2).unwrap().state, SagaState::Compensated);
        assert_eq!(exec.get_saga(&id3).unwrap().state, SagaState::Pending);
    }

    // 16. test_export_trace
    #[test]
    fn test_export_trace() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b"]);
        let id = exec.create_saga(steps, "t");
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "x".to_string(),
            },
            1,
            "t",
        )
        .unwrap();
        exec.compensate(&id, "t").unwrap();

        let trace = exec.export_trace(&id).unwrap();
        assert_eq!(trace.saga_id, id);
        assert_eq!(trace.final_state, SagaState::Compensated);
        assert!(!trace.compensated_steps.is_empty());
    }

    // 17. test_export_trace_not_compensated
    #[test]
    fn test_export_trace_not_compensated() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a"]);
        let id = exec.create_saga(steps, "t");
        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.commit(&id, "t").unwrap();

        // No compensation trace for committed sagas
        assert!(exec.export_trace(&id).is_none());
    }

    // 18. test_skipped_step_not_compensated
    #[test]
    fn test_skipped_step_not_compensated() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b", "c"]);
        let id = exec.create_saga(steps, "t");

        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Skipped {
                reason: "not needed".to_string(),
            },
            0,
            "t",
        )
        .unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "boom".to_string(),
            },
            1,
            "t",
        )
        .unwrap();

        let trace = exec.compensate(&id, "t").unwrap();
        // Only step 'a' (index 0) succeeded; 'b' was skipped, 'c' failed
        assert_eq!(trace.compensated_steps.len(), 1);
        assert_eq!(trace.compensated_steps[0].step_index, 0);
    }

    // 19. test_default_executor
    #[test]
    fn test_default_executor() {
        let exec = SagaExecutor::default();
        assert_eq!(exec.saga_count(), 0);
        assert!(exec.export_audit_log_jsonl().is_empty());
    }

    // 20. test_step_outcome_display
    #[test]
    fn test_step_outcome_display() {
        assert_eq!(format!("{}", success_outcome()), "Success");
        assert_eq!(
            format!("{}", StepOutcome::Failed { reason: "x".into() }),
            "Failed(x)"
        );
        assert_eq!(
            format!("{}", StepOutcome::Skipped { reason: "y".into() }),
            "Skipped(y)"
        );
        assert_eq!(format!("{}", StepOutcome::Compensated), "Compensated");
    }

    // 21. test_saga_state_display
    #[test]
    fn test_saga_state_display() {
        assert_eq!(format!("{}", SagaState::Pending), "Pending");
        assert_eq!(format!("{}", SagaState::Running), "Running");
        assert_eq!(format!("{}", SagaState::Committed), "Committed");
        assert_eq!(format!("{}", SagaState::Compensating), "Compensating");
        assert_eq!(format!("{}", SagaState::Compensated), "Compensated");
        assert_eq!(format!("{}", SagaState::Failed), "Failed");
    }

    // 22. test_schema_version
    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "saga-v1.0");
    }
}
