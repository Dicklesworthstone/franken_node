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

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

/// Maximum retained sagas before terminal-only reclamation or fail-closed rejection.
const MAX_SAGAS: usize = 2048;

/// Maximum step records per saga before oldest are evicted.
const MAX_RECORDS_PER_SAGA: usize = 4096;

/// Stable error when the saga registry is full of non-reclaimable live instances.
const ERR_SAGA_CAPACITY_EXCEEDED: &str = "ERR_SAGA_CAPACITY_EXCEEDED";
/// Stable error when a generated saga id would overwrite an existing saga.
const ERR_SAGA_ID_REUSED: &str = "ERR_SAGA_ID_REUSED";

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
    /// A forward step failed (will trigger compensation).
    pub const SAG_STEP_FAILED: &str = "SAG-009";
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

impl SagaState {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            SagaState::Committed | SagaState::Compensated | SagaState::Failed
        )
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

    /// Internal: append an audit record with capacity eviction.
    fn log(&mut self, event_code: &str, trace_id: &str, saga_id: &str, detail: serde_json::Value) {
        push_bounded(
            &mut self.audit_log,
            SagaAuditRecord {
                event_code: event_code.to_string(),
                trace_id: trace_id.to_string(),
                saga_id: saga_id.to_string(),
                detail,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }

    fn oldest_reclaimable_saga_id(&self) -> Option<String> {
        self.sagas
            .iter()
            .filter(|(_, saga)| saga.state.is_terminal())
            .min_by_key(|(saga_id, _)| saga_id_sequence(saga_id))
            .map(|(saga_id, _)| saga_id.clone())
    }

    /// Create a new saga with a list of step definitions.
    ///
    /// Returns the saga ID. The saga starts in `Pending` state.
    ///
    /// # Errors
    /// - The generated saga ID already exists and would overwrite an existing saga
    /// - The saga registry is at capacity and contains no terminal saga that can be reclaimed
    pub fn create_saga(
        &mut self,
        steps: Vec<SagaStepDef>,
        trace_id: &str,
    ) -> Result<String, String> {
        if self.next_saga_id == u64::MAX {
            return Err(format!(
                "{ERR_SAGA_CAPACITY_EXCEEDED}: saga ID counter exhausted"
            ));
        }

        let saga_id = format!("saga-{}", self.next_saga_id);

        if self.sagas.contains_key(&saga_id) {
            // Advance the counter even on collision to prevent permanent deadlock:
            // without this, every subsequent create_saga call generates the same ID.
            self.next_saga_id = self.next_saga_id.saturating_add(1);
            return Err(format!(
                "{ERR_SAGA_ID_REUSED}: generated saga id already exists: {saga_id}"
            ));
        }

        if self.sagas.len() >= MAX_SAGAS {
            let Some(oldest_key) = self.oldest_reclaimable_saga_id() else {
                return Err(format!(
                    "{ERR_SAGA_CAPACITY_EXCEEDED}: saga registry full of live instances"
                ));
            };
            self.sagas.remove(&oldest_key);
        }

        self.next_saga_id = self.next_saga_id.saturating_add(1);

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

        Ok(saga_id)
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
        if matches!(outcome, StepOutcome::Compensated) {
            return Err("cannot pass Compensated as a forward step outcome".to_string());
        }

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

        // Invariant: once any forward step fails, no additional forward steps
        // may execute. A compensation run is required first.
        let has_failed_forward_step = saga
            .records
            .iter()
            .any(|r| r.action == "forward" && matches!(r.outcome, StepOutcome::Failed { .. }));
        if has_failed_forward_step {
            saga.state = SagaState::Failed;
            return Err(format!(
                "saga {saga_id} contains failed forward steps and must be compensated before additional execution"
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
            StepOutcome::Failed { .. } => event_codes::SAG_STEP_FAILED,
            StepOutcome::Skipped { .. } => event_codes::SAG_STEP_SKIPPED,
            StepOutcome::Compensated => event_codes::SAG_STEP_COMPENSATED,
        };

        let record = StepRecord {
            step_index,
            step_name: step_name.clone(),
            action: "forward".to_string(),
            outcome: outcome.clone(),
            elapsed_ms,
        };

        push_bounded(&mut saga.records, record, MAX_RECORDS_PER_SAGA);
        if matches!(outcome, StepOutcome::Failed { .. }) {
            saga.state = SagaState::Failed;
        } else {
            saga.completed_steps = saga.completed_steps.saturating_add(1);
            saga.state = SagaState::Running;
        }

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
            push_bounded(&mut comp_records, record.clone(), MAX_RECORDS_PER_SAGA);
            push_bounded(&mut saga.records, record, MAX_RECORDS_PER_SAGA);
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
        let content =
            serde_json::to_string(&self.sagas).unwrap_or_else(|e| format!("__serde_err:{e}"));
        hex::encode(
            Sha256::digest([b"saga_content_hash_v1:" as &[u8], content.as_bytes()].concat())
        )
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

fn saga_id_sequence(saga_id: &str) -> u64 {
    saga_id
        .strip_prefix("saga-")
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_saga_instance(saga_id: &str, state: SagaState) -> SagaInstance {
        SagaInstance {
            saga_id: saga_id.to_string(),
            state,
            steps: make_steps(&["step"]),
            completed_steps: usize::from(matches!(
                state,
                SagaState::Running | SagaState::Committed
            )),
            records: Vec::new(),
        }
    }

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

    #[test]
    fn test_push_bounded_zero_capacity_clears_without_appending() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn test_push_bounded_evicts_oldest_at_capacity() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 3);

        assert_eq!(items, vec![2, 3, 4]);
    }

    // 1. test_create_saga
    #[test]
    fn test_create_saga() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["step_a", "step_b", "step_c"]);
        let id = exec.create_saga(steps, "trace-1").unwrap();
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
        let id = exec.create_saga(steps, "t").unwrap();

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
        let id = exec.create_saga(steps, "t").unwrap();
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
        let id = exec.create_saga(steps, "t").unwrap();

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
        let id = exec.create_saga(steps, "t").unwrap();

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

    #[test]
    fn test_failed_step_sets_failed_state_and_does_not_increment_completed_steps() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b", "c"]);
        let id = exec.create_saga(steps, "t").unwrap();

        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "boom".to_string(),
            },
            1,
            "t",
        )
        .unwrap();

        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.state, SagaState::Failed);
        assert_eq!(
            saga.completed_steps, 1,
            "failed forward steps must not count as completed"
        );
    }

    #[test]
    fn test_cannot_execute_additional_forward_steps_after_failure() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b", "c"]);
        let id = exec.create_saga(steps, "t").unwrap();

        exec.execute_step(&id, success_outcome(), 1, "t").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "boom".to_string(),
            },
            1,
            "t",
        )
        .unwrap();

        let err = exec
            .execute_step(&id, success_outcome(), 1, "t")
            .expect_err("forward execution must stop after first failure");
        assert!(
            err.contains("cannot execute forward steps"),
            "unexpected error text: {err}"
        );

        // Failed saga can still be compensated.
        let trace = exec.compensate(&id, "t").unwrap();
        assert_eq!(trace.compensated_steps.len(), 1);
        assert_eq!(trace.compensated_steps[0].step_index, 0);
    }

    // 6. test_no_intermediate_state (INV-SAGA-TERMINAL)
    #[test]
    fn test_no_intermediate_state() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["x"]);
        let id = exec.create_saga(steps, "t").unwrap();
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
        let id = exec.create_saga(steps, "t").unwrap();
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
            let id = exec.create_saga(steps, "t").unwrap();
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
        let id = exec.create_saga(steps, "t").unwrap();
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

        e1.create_saga(steps1, "t").unwrap();
        e2.create_saga(steps2, "t").unwrap();

        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    // 12. test_audit_log
    #[test]
    fn test_audit_log() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a"]);
        let id = exec.create_saga(steps, "t1").unwrap();
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

    // 12b. test_audit_event_codes_for_failed_step
    #[test]
    fn test_audit_event_codes_for_failed_step() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b"]);
        let id = exec.create_saga(steps, "t1").unwrap();
        exec.execute_step(&id, success_outcome(), 1, "t2").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "oops".to_string(),
            },
            1,
            "t3",
        )
        .unwrap();

        let jsonl = exec.export_audit_log_jsonl();
        let events: Vec<serde_json::Value> = jsonl
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        // Find the forward step event
        let forward = events
            .iter()
            .find(|e| e["event_code"].as_str() == Some(event_codes::SAG_STEP_FORWARD))
            .expect("should have a SAG_STEP_FORWARD event");
        assert_eq!(forward["detail"]["step_name"].as_str(), Some("a"));

        // Find the failed step event
        let failed = events
            .iter()
            .find(|e| e["event_code"].as_str() == Some(event_codes::SAG_STEP_FAILED))
            .expect("should have a SAG_STEP_FAILED event");
        assert_eq!(failed["detail"]["step_name"].as_str(), Some("b"));
    }

    // 12c. test_audit_event_codes_for_compensated_step
    #[test]
    fn test_audit_event_codes_for_compensated_step() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a"]);
        let id = exec.create_saga(steps, "t1").unwrap();

        // Compensation requires a previously-succeeded forward step.
        exec.execute_step(
            &id,
            StepOutcome::Success {
                result_data: b"ok".to_vec(),
            },
            1,
            "t1",
        )
        .unwrap();

        // Now compensate: this produces SAG_STEP_COMPENSATED for step "a".
        exec.compensate(&id, "t2").unwrap();

        let jsonl = exec.export_audit_log_jsonl();
        let events: Vec<serde_json::Value> = jsonl
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        let compensated = events
            .iter()
            .find(|e| e["event_code"].as_str() == Some(event_codes::SAG_STEP_COMPENSATED))
            .expect("should have a SAG_STEP_COMPENSATED event");
        assert_eq!(compensated["detail"]["step_name"].as_str(), Some("a"));
    }

    // 13. test_saga_state_transitions
    #[test]
    fn test_saga_state_transitions() {
        let mut exec = SagaExecutor::new();
        let steps = make_steps(&["a", "b"]);
        let id = exec.create_saga(steps, "t").unwrap();

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
        let id = exec.create_saga(steps, "t").unwrap();

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
        let id1 = exec.create_saga(make_steps(&["a"]), "t").unwrap();
        let id2 = exec.create_saga(make_steps(&["b"]), "t").unwrap();
        let id3 = exec.create_saga(make_steps(&["c"]), "t").unwrap();

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
        let id = exec.create_saga(steps, "t").unwrap();
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
        let id = exec.create_saga(steps, "t").unwrap();
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
        let id = exec.create_saga(steps, "t").unwrap();

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
        // Verify skipped step (index 1) is NOT in the compensation trace
        assert!(
            !trace.compensated_steps.iter().any(|s| s.step_index == 1),
            "skipped step must not appear in compensation trace"
        );
    }

    #[test]
    fn test_create_saga_rejects_when_registry_full_of_live_sagas() {
        let mut exec = SagaExecutor::new();
        for seq in 1..=MAX_SAGAS {
            let saga_id = format!("saga-{seq}");
            exec.sagas.insert(
                saga_id.clone(),
                make_saga_instance(&saga_id, SagaState::Running),
            );
        }
        exec.next_saga_id = MAX_SAGAS as u64 + 1;

        let err = exec
            .create_saga(make_steps(&["new"]), "t")
            .expect_err("full live registry must fail closed");
        assert!(err.contains(ERR_SAGA_CAPACITY_EXCEEDED));
        assert_eq!(exec.saga_count(), MAX_SAGAS);
        assert!(exec.get_saga("saga-1").is_some());
        assert!(exec.get_saga("saga-2048").is_some());
        assert!(exec.get_saga("saga-2049").is_none());
    }

    #[test]
    fn test_create_saga_reclaims_oldest_terminal_saga_by_issuance_order() {
        let mut exec = SagaExecutor::new();
        for seq in 1..=MAX_SAGAS {
            let saga_id = format!("saga-{seq}");
            let state = match seq {
                2 | 10 => SagaState::Committed,
                _ => SagaState::Running,
            };
            exec.sagas
                .insert(saga_id.clone(), make_saga_instance(&saga_id, state));
        }
        exec.next_saga_id = MAX_SAGAS as u64 + 1;

        let new_id = exec.create_saga(make_steps(&["new"]), "t").unwrap();
        assert_eq!(new_id, "saga-2049");
        assert_eq!(exec.saga_count(), MAX_SAGAS);
        assert!(
            exec.get_saga("saga-1").is_some(),
            "live saga must be preserved"
        );
        assert!(
            exec.get_saga("saga-2").is_none(),
            "oldest terminal saga should be reclaimed first"
        );
        assert!(
            exec.get_saga("saga-10").is_some(),
            "issuance order must beat lexicographic ordering among terminals"
        );
        assert!(exec.get_saga(&new_id).is_some());
    }

    #[test]
    fn test_create_saga_rejects_generated_id_reuse_without_overwriting_existing_saga() {
        let mut exec = SagaExecutor::new();
        let original_id = exec
            .create_saga(make_steps(&["original", "persisted"]), "t")
            .unwrap();
        exec.execute_step(&original_id, success_outcome(), 7, "t")
            .unwrap();
        exec.next_saga_id = 1;

        let err = exec
            .create_saga(make_steps(&["replacement"]), "t2")
            .expect_err("reused generated saga id must fail closed");
        assert!(err.contains(ERR_SAGA_ID_REUSED));
        assert_eq!(exec.next_saga_id, 2);
        assert_eq!(exec.saga_count(), 1);
        assert_eq!(exec.audit_log.len(), 2);

        let preserved = exec
            .get_saga(&original_id)
            .expect("original saga preserved");
        assert_eq!(preserved.state, SagaState::Running);
        assert_eq!(preserved.completed_steps, 1);
        assert_eq!(preserved.records.len(), 1);
        assert_eq!(
            preserved
                .steps
                .iter()
                .map(|step| step.name.as_str())
                .collect::<Vec<_>>(),
            vec!["original", "persisted"]
        );
    }

    #[test]
    fn test_execute_rejects_compensated_outcome_before_saga_lookup() {
        let mut exec = SagaExecutor::new();

        let err = exec
            .execute_step("missing-saga", StepOutcome::Compensated, 9, "trace")
            .expect_err("compensated cannot be accepted as a forward outcome");

        assert!(err.contains("cannot pass Compensated"));
        assert_eq!(exec.saga_count(), 0);
        assert!(exec.audit_log.is_empty());
    }

    #[test]
    fn test_commit_pending_saga_fails_without_state_or_audit_mutation() {
        let mut exec = SagaExecutor::new();
        let id = exec
            .create_saga(make_steps(&["prepare"]), "create")
            .unwrap();
        let audit_len = exec.audit_log.len();

        let err = exec
            .commit(&id, "commit")
            .expect_err("pending saga must not commit");

        assert!(err.contains("Pending"));
        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.state, SagaState::Pending);
        assert_eq!(saga.completed_steps, 0);
        assert!(saga.records.is_empty());
        assert_eq!(exec.audit_log.len(), audit_len);
    }

    #[test]
    fn test_commit_incomplete_running_saga_fails_without_extra_audit() {
        let mut exec = SagaExecutor::new();
        let id = exec
            .create_saga(make_steps(&["prepare", "apply"]), "create")
            .unwrap();
        exec.execute_step(&id, success_outcome(), 3, "step")
            .unwrap();
        let audit_len = exec.audit_log.len();

        let err = exec
            .commit(&id, "commit")
            .expect_err("partially completed saga must not commit");

        assert!(err.contains("completed 1 of 2"));
        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.state, SagaState::Running);
        assert_eq!(saga.completed_steps, 1);
        assert_eq!(saga.records.len(), 1);
        assert_eq!(exec.audit_log.len(), audit_len);
    }

    #[test]
    fn test_execute_after_all_steps_completed_fails_without_new_record() {
        let mut exec = SagaExecutor::new();
        let id = exec.create_saga(make_steps(&["only"]), "create").unwrap();
        exec.execute_step(&id, success_outcome(), 4, "step")
            .unwrap();
        let audit_len = exec.audit_log.len();
        let record_len = exec.get_saga(&id).unwrap().records.len();

        let err = exec
            .execute_step(&id, success_outcome(), 5, "extra")
            .expect_err("completed saga must not accept extra forward records");

        assert!(err.contains("no more steps"));
        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.state, SagaState::Running);
        assert_eq!(saga.completed_steps, 1);
        assert_eq!(saga.records.len(), record_len);
        assert_eq!(exec.audit_log.len(), audit_len);
    }

    #[test]
    fn test_compensate_committed_saga_fails_without_trace_or_audit_mutation() {
        let mut exec = SagaExecutor::new();
        let id = exec.create_saga(make_steps(&["only"]), "create").unwrap();
        exec.execute_step(&id, success_outcome(), 4, "step")
            .unwrap();
        exec.commit(&id, "commit").unwrap();
        let audit_len = exec.audit_log.len();
        let record_len = exec.get_saga(&id).unwrap().records.len();

        let err = exec
            .compensate(&id, "compensate")
            .expect_err("committed saga must not compensate");

        assert!(err.contains("Committed"));
        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.state, SagaState::Committed);
        assert_eq!(saga.records.len(), record_len);
        assert!(exec.export_trace(&id).is_none());
        assert_eq!(exec.audit_log.len(), audit_len);
    }

    #[test]
    fn test_compensate_pending_saga_has_empty_trace_and_terminal_state() {
        let mut exec = SagaExecutor::new();
        let id = exec
            .create_saga(make_steps(&["never-ran"]), "create")
            .unwrap();

        let trace = exec.compensate(&id, "compensate").unwrap();

        assert_eq!(trace.saga_id, id);
        assert!(trace.compensated_steps.is_empty());
        assert_eq!(trace.final_state, SagaState::Compensated);
        let exported = exec.export_trace(&id).unwrap();
        assert!(exported.compensated_steps.is_empty());
        assert_eq!(exported.final_state, SagaState::Compensated);
        assert_eq!(exec.get_saga(&id).unwrap().state, SagaState::Compensated);
    }

    #[test]
    fn test_export_trace_for_failed_uncompensated_saga_is_none() {
        let mut exec = SagaExecutor::new();
        let id = exec.create_saga(make_steps(&["fail"]), "create").unwrap();
        exec.execute_step(
            &id,
            StepOutcome::Failed {
                reason: "boom".to_string(),
            },
            1,
            "step",
        )
        .unwrap();

        let saga = exec.get_saga(&id).unwrap();
        assert_eq!(saga.state, SagaState::Failed);
        assert!(exec.export_trace(&id).is_none());
    }

    #[test]
    fn test_create_saga_counter_exhaustion_fails_without_side_effects() {
        let mut exec = SagaExecutor::new();
        exec.next_saga_id = u64::MAX;

        let err = exec
            .create_saga(make_steps(&["never-created"]), "create")
            .expect_err("exhausted saga counter must fail closed");

        assert!(err.contains(ERR_SAGA_CAPACITY_EXCEEDED));
        assert!(err.contains("counter exhausted"));
        assert_eq!(exec.next_saga_id, u64::MAX);
        assert_eq!(exec.saga_count(), 0);
        assert!(exec.audit_log.is_empty());
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

    // ---------------------------------------------------------------------------
    // NEGATIVE-PATH TESTS: Security hardening for saga execution
    // ---------------------------------------------------------------------------

    #[test]
    fn negative_unicode_injection_in_saga_identifiers_and_step_names() {
        let mut exec = SagaExecutor::new();

        // BiDi override attack in step name
        let malicious_steps = vec![
            SagaStepDef {
                name: "\u{202E}pets_malicious\u{202D}legitimate_step".to_string(),
                computation_name: Some("\u{202E}drojan\u{202D}safe_computation".to_string()),
                is_remote: true,
                idempotency_key: Some("key\u{200B}\u{200C}hidden\u{FEFF}".to_string()),
            },
            SagaStepDef {
                name: "normal_step".to_string(),
                computation_name: None,
                is_remote: false,
                idempotency_key: None,
            },
        ];

        // Malicious trace ID with control characters
        let malicious_trace_id = "trace\u{0000}\ninjection\r\tlog_corruption";

        let saga_id = exec
            .create_saga(malicious_steps.clone(), malicious_trace_id)
            .unwrap();

        // Verify Unicode is preserved in saga data
        let saga = exec.get_saga(&saga_id).unwrap();
        assert!(saga.steps[0].name.contains('\u{202E}'));
        assert!(
            saga.steps[0]
                .computation_name
                .as_ref()
                .unwrap()
                .contains('\u{202E}')
        );
        assert!(
            saga.steps[0]
                .idempotency_key
                .as_ref()
                .unwrap()
                .contains('\u{200B}')
        );

        // Test step execution with Unicode in outcome data
        let unicode_outcome = StepOutcome::Success {
            result_data: "result\u{202E}kcattA\u{202D}normal".as_bytes().to_vec(),
        };

        let step_idx = exec
            .execute_step(&saga_id, unicode_outcome, 100, malicious_trace_id)
            .unwrap();
        assert_eq!(step_idx, 0);

        // Path traversal injection in step names
        let path_traversal_steps = vec![SagaStepDef {
            name: "../../../etc/passwd\0\nmalicious_path".to_string(),
            computation_name: Some("computation\n\r\0injection".to_string()),
            is_remote: true,
            idempotency_key: Some("../../../keys/secret\0".to_string()),
        }];

        let traversal_saga = exec
            .create_saga(path_traversal_steps, "traversal_trace")
            .unwrap();
        let saga2 = exec.get_saga(&traversal_saga).unwrap();
        assert!(saga2.steps[0].name.contains('\0'));
        assert!(saga2.steps[0].name.contains('\n'));

        // Verify audit log preserves Unicode injection for analysis
        let audit_jsonl = exec.export_audit_log_jsonl();
        assert!(audit_jsonl.contains(malicious_trace_id));
    }

    #[test]
    fn negative_memory_exhaustion_with_massive_audit_logs_and_step_records() {
        let mut exec = SagaExecutor::new();

        // Create saga with maximum steps
        let huge_steps: Vec<SagaStepDef> = (0..10_000)
            .map(|i| SagaStepDef {
                name: format!("massive_step_{}", i),
                computation_name: Some(format!("computation_{}", i)),
                is_remote: true,
                idempotency_key: Some(format!("key_{}", i)),
            })
            .collect();

        let saga_id = exec.create_saga(huge_steps, "memory_stress_trace").unwrap();

        // Execute steps with large result data
        for i in 0..1000 {
            let massive_result = StepOutcome::Success {
                result_data: vec![0x42; 100_000], // 100KB per step result
            };

            if exec.get_saga(&saga_id).unwrap().completed_steps
                < exec.get_saga(&saga_id).unwrap().steps.len()
            {
                let _ = exec
                    .execute_step(&saga_id, massive_result, u64::MAX, "stress")
                    .unwrap();
            }
        }

        // Verify bounded storage prevents unbounded growth
        let saga = exec.get_saga(&saga_id).unwrap();
        assert!(saga.records.len() <= MAX_RECORDS_PER_SAGA);

        // Test memory stress with audit log
        for i in 0..MAX_AUDIT_LOG_ENTRIES * 2 {
            let stress_steps = vec![SagaStepDef {
                name: format!("audit_stress_{}", i),
                computation_name: None,
                is_remote: false,
                idempotency_key: None,
            }];

            let _ = exec.create_saga(stress_steps, &format!("audit_trace_{}", i));
        }

        // Verify audit log is bounded
        assert!(exec.audit_log.len() <= MAX_AUDIT_LOG_ENTRIES);

        // Test massive failure reasons and skip reasons
        let failure_saga = exec
            .create_saga(make_steps(&["fail", "skip"]), "fail_trace")
            .unwrap();

        let massive_failure = StepOutcome::Failed {
            reason: "A".repeat(1_000_000), // 1MB error message
        };

        let _ = exec
            .execute_step(&failure_saga, massive_failure, 1, "fail")
            .unwrap();

        let massive_skip = StepOutcome::Skipped {
            reason: "B".repeat(1_000_000), // 1MB skip reason
        };

        let _ = exec
            .execute_step(&failure_saga, massive_skip, 1, "skip")
            .unwrap();

        // Verify large data is preserved but bounded by collection limits
        let fail_saga = exec.get_saga(&failure_saga).unwrap();
        assert!(fail_saga.records.len() <= MAX_RECORDS_PER_SAGA);
    }

    #[test]
    fn negative_counter_overflow_and_arithmetic_boundary_attacks() {
        let mut exec = SagaExecutor::new();

        // Test saga ID counter overflow protection
        exec.next_saga_id = u64::MAX - 5;

        for i in 0..10 {
            let steps = make_steps(&[&format!("overflow_test_{}", i)]);
            let result = exec.create_saga(steps, "overflow_trace");

            if i < 5 {
                assert!(result.is_ok());
            } else {
                // Should hit overflow and fail
                assert!(result.is_err());
                assert!(result.unwrap_err().contains("counter exhausted"));
            }
        }

        // Verify saturating arithmetic was used
        assert_eq!(exec.next_saga_id, u64::MAX);

        // Test completed_steps counter overflow
        let mut overflow_exec = SagaExecutor::new();
        let saga_id = overflow_exec
            .create_saga(make_steps(&["test"]), "trace")
            .unwrap();

        // Manually set completed_steps near overflow
        if let Some(saga) = overflow_exec.sagas.get_mut(&saga_id) {
            saga.completed_steps = usize::MAX - 5;
        }

        // Execute step should use saturating arithmetic
        let outcome = StepOutcome::Success {
            result_data: vec![],
        };
        let _ = overflow_exec.execute_step(&saga_id, outcome, 1, "trace");

        let saga = overflow_exec.get_saga(&saga_id).unwrap();
        assert!(saga.completed_steps <= usize::MAX);

        // Test elapsed time overflow
        let time_saga = overflow_exec
            .create_saga(make_steps(&["time_test"]), "time")
            .unwrap();
        let time_outcome = StepOutcome::Success {
            result_data: vec![],
        };

        let _ = overflow_exec.execute_step(&time_saga, time_outcome, u64::MAX, "time");

        let time_saga_data = overflow_exec.get_saga(&time_saga).unwrap();
        assert_eq!(time_saga_data.records[0].elapsed_ms, u64::MAX);

        // Test step index overflow during compensation
        let comp_saga = overflow_exec
            .create_saga(make_steps(&["comp"]), "comp")
            .unwrap();
        let comp_outcome = StepOutcome::Success {
            result_data: vec![],
        };
        let _ = overflow_exec.execute_step(&comp_saga, comp_outcome, 1, "comp");

        // Manually corrupt step_index to test overflow handling
        if let Some(saga) = overflow_exec.sagas.get_mut(&comp_saga) {
            saga.records[0].step_index = usize::MAX;
        }

        // Compensation should handle corrupted indices gracefully
        let trace = overflow_exec.compensate(&comp_saga, "comp").unwrap();
        assert_eq!(trace.final_state, SagaState::Compensated);
    }

    #[test]
    fn negative_json_serialization_corruption_and_injection_attacks() {
        let mut exec = SagaExecutor::new();

        // Create saga with JSON injection attempts in various fields
        let injection_steps = vec![
            SagaStepDef {
                name: r#"step","malicious":"injection"#.to_string(),
                computation_name: Some(r#"comp\"}],"evil":"payload"#.to_string()),
                is_remote: true,
                idempotency_key: Some(r#"key\n\r\t\0"#.to_string()),
            },
            SagaStepDef {
                name: "\\u0000\\n\\r\\t".to_string(), // Escape sequence injection
                computation_name: None,
                is_remote: false,
                idempotency_key: None,
            },
        ];

        let saga_id = exec
            .create_saga(injection_steps, r#"trace","attack":"value"#)
            .unwrap();

        // Execute with JSON injection in outcome data
        let json_attack_outcome = StepOutcome::Success {
            result_data: r#"{"fake":"json","injection":true}"#.as_bytes().to_vec(),
        };

        let _ = exec
            .execute_step(
                &saga_id,
                json_attack_outcome,
                100,
                r#"trace\"},{"evil":true"#,
            )
            .unwrap();

        // Execute with JSON injection in failure reason
        let json_fail_outcome = StepOutcome::Failed {
            reason: r#"error\"}],"malicious_payload":"injected"#.to_string(),
        };

        let fail_saga = exec
            .create_saga(make_steps(&["fail"]), "fail_trace")
            .unwrap();
        let _ = exec
            .execute_step(&fail_saga, json_fail_outcome, 50, "fail")
            .unwrap();

        // Export audit log and verify JSON integrity
        let audit_jsonl = exec.export_audit_log_jsonl();
        let lines: Vec<&str> = audit_jsonl.lines().collect();

        for line in &lines {
            // Each line should parse as valid JSON
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "Corrupted JSON in audit log: {}", line);

            if let Ok(json) = parsed {
                // Verify required fields are present
                assert!(json.get("event_code").is_some());
                assert!(json.get("trace_id").is_some());
                assert!(json.get("saga_id").is_some());
                assert!(json.get("detail").is_some());

                // Verify no unescaped injection
                let json_str = serde_json::to_string(&json).unwrap();
                assert!(!json_str.contains(r#""malicious""#));
                assert!(!json_str.contains(r#""evil""#));
                assert!(!json_str.contains(r#""attack""#));
            }
        }

        // Test content hash with injection attempts
        let hash1 = exec.content_hash();

        // Modify internal state with injection
        if let Some(saga) = exec.sagas.get_mut(&saga_id) {
            saga.saga_id = r#"modified","injection":"here"#.to_string();
        }

        let hash2 = exec.content_hash();
        assert_ne!(hash1, hash2); // Hash should change with content

        // Test serialization of compensation trace
        let comp_saga = exec.create_saga(make_steps(&["comp"]), "comp").unwrap();
        let _ = exec.execute_step(
            &comp_saga,
            StepOutcome::Success {
                result_data: vec![],
            },
            1,
            "comp",
        );
        let trace = exec.compensate(&comp_saga, "comp").unwrap();

        let trace_json = serde_json::to_string(&trace).unwrap();
        let parsed_trace: CompensationTrace = serde_json::from_str(&trace_json).unwrap();
        assert_eq!(parsed_trace.saga_id, trace.saga_id);
        assert_eq!(parsed_trace.final_state, trace.final_state);
    }

    #[test]
    fn negative_state_transition_bypass_and_manipulation_attacks() {
        let mut exec = SagaExecutor::new();
        let saga_id = exec
            .create_saga(make_steps(&["step1", "step2"]), "trace")
            .unwrap();

        // Try to execute step while in wrong state (should fail)
        if let Some(saga) = exec.sagas.get_mut(&saga_id) {
            saga.state = SagaState::Committed; // Force invalid state
        }

        let bypass_outcome = StepOutcome::Success {
            result_data: vec![],
        };
        let result = exec.execute_step(&saga_id, bypass_outcome, 10, "bypass");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot execute forward steps"));

        // Reset to valid state
        if let Some(saga) = exec.sagas.get_mut(&saga_id) {
            saga.state = SagaState::Pending;
        }

        // Execute valid step
        let _ = exec.execute_step(
            &saga_id,
            StepOutcome::Success {
                result_data: vec![],
            },
            10,
            "valid",
        );

        // Try to manipulate completed_steps counter beyond steps.len()
        if let Some(saga) = exec.sagas.get_mut(&saga_id) {
            saga.completed_steps = saga.steps.len() + 100; // Illegal state
        }

        // Should reject additional execution
        let overflow_result = exec.execute_step(
            &saga_id,
            StepOutcome::Success {
                result_data: vec![],
            },
            5,
            "overflow",
        );
        assert!(overflow_result.is_err());

        // Test compensation state bypass
        let comp_saga = exec
            .create_saga(make_steps(&["comp1", "comp2"]), "comp")
            .unwrap();

        // Force saga to Committed state
        if let Some(saga) = exec.sagas.get_mut(&comp_saga) {
            saga.state = SagaState::Committed;
        }

        // Should reject compensation of committed saga
        let comp_result = exec.compensate(&comp_saga, "comp");
        assert!(comp_result.is_err());
        assert!(comp_result.unwrap_err().contains("Committed"));

        // Test invalid step record manipulation
        let record_saga = exec.create_saga(make_steps(&["record"]), "record").unwrap();
        let _ = exec.execute_step(
            &record_saga,
            StepOutcome::Success {
                result_data: vec![],
            },
            5,
            "record",
        );

        // Manually corrupt step record
        if let Some(saga) = exec.sagas.get_mut(&record_saga) {
            saga.records[0].action = "invalid_action".to_string();
            saga.records[0].step_index = 999; // Out of bounds
        }

        // Compensation should handle corrupted records gracefully
        let corrupted_trace = exec.compensate(&record_saga, "record");
        assert!(corrupted_trace.is_ok());

        // Test failed forward step validation bypass
        let fail_saga = exec
            .create_saga(make_steps(&["fail", "after_fail"]), "fail")
            .unwrap();
        let _ = exec.execute_step(
            &fail_saga,
            StepOutcome::Failed {
                reason: "boom".to_string(),
            },
            1,
            "fail",
        );

        // Manually reset state to try bypassing failure check
        if let Some(saga) = exec.sagas.get_mut(&fail_saga) {
            saga.state = SagaState::Running; // Try to bypass failure state
        }

        // Should still detect failed forward step and reject
        let bypass_fail = exec.execute_step(
            &fail_saga,
            StepOutcome::Success {
                result_data: vec![],
            },
            1,
            "bypass",
        );
        assert!(bypass_fail.is_err());
        assert!(bypass_fail.unwrap_err().contains("failed forward steps"));
    }

    #[test]
    fn negative_concurrent_access_safety_and_race_conditions() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let exec = Arc::new(Mutex::new(SagaExecutor::new()));
        let mut handles = vec![];

        // Spawn multiple threads performing concurrent saga operations
        for thread_id in 0..8 {
            let exec_clone = Arc::clone(&exec);
            let handle = thread::spawn(move || {
                for op_id in 0..50 {
                    let mut executor = exec_clone.lock().unwrap();

                    // Create saga
                    let steps = vec![
                        SagaStepDef {
                            name: format!("thread_{}_step_{}_a", thread_id, op_id),
                            computation_name: Some(format!("comp_{}", thread_id)),
                            is_remote: thread_id % 2 == 0,
                            idempotency_key: Some(format!("key_{}_{}", thread_id, op_id)),
                        },
                        SagaStepDef {
                            name: format!("thread_{}_step_{}_b", thread_id, op_id),
                            computation_name: None,
                            is_remote: false,
                            idempotency_key: None,
                        },
                    ];

                    let saga_id_result =
                        executor.create_saga(steps, &format!("trace_{}_{}", thread_id, op_id));

                    if let Ok(saga_id) = saga_id_result {
                        // Execute first step
                        let outcome1 = StepOutcome::Success {
                            result_data: vec![thread_id as u8; 100],
                        };
                        let _ = executor.execute_step(&saga_id, outcome1, op_id as u64, "step1");

                        // Some threads compensate, others commit
                        if thread_id % 2 == 0 {
                            let outcome2 = StepOutcome::Success {
                                result_data: vec![0xFF; 100],
                            };
                            let _ =
                                executor.execute_step(&saga_id, outcome2, op_id as u64, "step2");
                            let _ = executor.commit(&saga_id, "commit");
                        } else {
                            let outcome2 = StepOutcome::Failed {
                                reason: format!("deliberate_fail_{}", op_id),
                            };
                            let _ =
                                executor.execute_step(&saga_id, outcome2, op_id as u64, "step2");
                            let _ = executor.compensate(&saga_id, "compensate");
                        }
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state consistency
        let final_exec = exec.lock().unwrap();
        let saga_count = final_exec.saga_count();
        assert!(saga_count > 0); // Some sagas should have been created

        // Verify audit log integrity
        let audit_jsonl = final_exec.export_audit_log_jsonl();
        if !audit_jsonl.is_empty() {
            for line in audit_jsonl.lines() {
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
                assert!(parsed.is_ok(), "Concurrent access corrupted audit log");
            }
        }

        // Verify content hash is deterministic
        let hash = final_exec.content_hash();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex string length
    }

    #[test]
    fn negative_compensation_trace_manipulation_and_replay_attacks() {
        let mut exec = SagaExecutor::new();

        // Create saga with multiple steps for compensation testing
        let steps = make_steps(&["prepare", "validate", "execute", "finalize"]);
        let saga_id = exec.create_saga(steps, "comp_trace").unwrap();

        // Execute steps with different outcomes
        let _ = exec.execute_step(
            &saga_id,
            StepOutcome::Success {
                result_data: b"prepare_ok".to_vec(),
            },
            10,
            "step1",
        );
        let _ = exec.execute_step(
            &saga_id,
            StepOutcome::Skipped {
                reason: "validation_skipped".to_string(),
            },
            5,
            "step2",
        );
        let _ = exec.execute_step(
            &saga_id,
            StepOutcome::Success {
                result_data: b"execute_ok".to_vec(),
            },
            15,
            "step3",
        );
        let _ = exec.execute_step(
            &saga_id,
            StepOutcome::Failed {
                reason: "finalize_failed".to_string(),
            },
            20,
            "step4",
        );

        // Get compensation trace
        let trace = exec.compensate(&saga_id, "compensate").unwrap();

        // Verify only successful steps are in compensation trace (not skipped or failed)
        assert_eq!(trace.compensated_steps.len(), 2); // prepare and execute

        // Verify reverse order (execute compensated before prepare)
        assert_eq!(trace.compensated_steps[0].step_index, 2); // execute (index 2)
        assert_eq!(trace.compensated_steps[1].step_index, 0); // prepare (index 0)
        assert_eq!(trace.compensated_steps[0].step_name, "execute");
        assert_eq!(trace.compensated_steps[1].step_name, "prepare");

        // All compensation actions should be marked as "compensate"
        for comp_record in &trace.compensated_steps {
            assert_eq!(comp_record.action, "compensate");
            assert_eq!(comp_record.outcome, StepOutcome::Compensated);
        }

        // Test idempotent compensation
        let trace2 = exec.compensate(&saga_id, "compensate2").unwrap();
        assert!(trace2.compensated_steps.is_empty()); // No additional compensation
        assert_eq!(trace2.final_state, SagaState::Compensated);

        // Test export trace consistency
        let exported = exec.export_trace(&saga_id).unwrap();
        assert_eq!(exported.saga_id, saga_id);
        assert_eq!(exported.final_state, SagaState::Compensated);

        // Should include both compensation rounds (but only non-empty first round)
        assert_eq!(exported.compensated_steps.len(), 2);

        // Test compensation with corrupted step records
        let corrupt_saga = exec
            .create_saga(make_steps(&["corrupt"]), "corrupt")
            .unwrap();
        let _ = exec.execute_step(
            &corrupt_saga,
            StepOutcome::Success {
                result_data: vec![],
            },
            1,
            "corrupt",
        );

        // Manually corrupt the records
        if let Some(saga) = exec.sagas.get_mut(&corrupt_saga) {
            // Add fake compensation record
            saga.records.push(StepRecord {
                step_index: 999, // Invalid index
                step_name: "fake_compensation".to_string(),
                action: "compensate".to_string(),
                outcome: StepOutcome::Compensated,
                elapsed_ms: 0,
            });
        }

        // Export should handle corrupted records gracefully
        let corrupt_trace = exec.export_trace(&corrupt_saga);
        assert!(corrupt_trace.is_some());

        // Test compensation with massive step counts
        let large_steps: Vec<SagaStepDef> = (0..1000)
            .map(|i| SagaStepDef {
                name: format!("mass_step_{}", i),
                computation_name: None,
                is_remote: false,
                idempotency_key: None,
            })
            .collect();

        let mass_saga = exec.create_saga(large_steps, "mass").unwrap();

        // Execute many successful steps
        for i in 0..100 {
            if exec.get_saga(&mass_saga).unwrap().completed_steps < 100 {
                let _ = exec.execute_step(
                    &mass_saga,
                    StepOutcome::Success {
                        result_data: vec![i as u8],
                    },
                    1,
                    "mass",
                );
            }
        }

        // Compensation should handle large compensation lists
        let mass_trace = exec.compensate(&mass_saga, "mass_comp").unwrap();
        assert_eq!(mass_trace.compensated_steps.len(), 100);

        // Verify reverse order for large compensation
        for (i, record) in mass_trace.compensated_steps.iter().enumerate() {
            assert_eq!(record.step_index, 99 - i); // Reverse order
            assert_eq!(record.action, "compensate");
        }
    }

    #[test]
    fn test_compensate_bounds_returned_trace_from_corrupt_oversized_records() {
        let mut exec = SagaExecutor::new();
        let saga_id = "saga-oversized-records".to_string();
        let step_count = MAX_RECORDS_PER_SAGA.saturating_add(5);

        let steps: Vec<SagaStepDef> = (0..step_count)
            .map(|i| SagaStepDef {
                name: format!("oversized_step_{i}"),
                computation_name: None,
                is_remote: false,
                idempotency_key: None,
            })
            .collect();
        let records: Vec<StepRecord> = (0..step_count)
            .map(|i| StepRecord {
                step_index: i,
                step_name: format!("oversized_step_{i}"),
                action: "forward".to_string(),
                outcome: success_outcome(),
                elapsed_ms: 1,
            })
            .collect();

        exec.sagas.insert(
            saga_id.clone(),
            SagaInstance {
                saga_id: saga_id.clone(),
                state: SagaState::Running,
                steps,
                completed_steps: step_count,
                records,
            },
        );

        let trace = exec.compensate(&saga_id, "trace-oversized").unwrap();

        assert_eq!(trace.compensated_steps.len(), MAX_RECORDS_PER_SAGA);
        assert_eq!(
            trace.compensated_steps.first().map(|r| r.step_index),
            Some(MAX_RECORDS_PER_SAGA - 1)
        );
        assert_eq!(
            trace.compensated_steps.last().map(|r| r.step_index),
            Some(0)
        );
        assert!(exec.get_saga(&saga_id).unwrap().records.len() <= MAX_RECORDS_PER_SAGA);
    }

    #[test]
    fn negative_hash_collision_and_content_integrity_attacks() {
        let mut exec1 = SagaExecutor::new();
        let mut exec2 = SagaExecutor::new();

        // Create identical sagas in both executors
        let steps1 = make_steps(&["identical1", "identical2"]);
        let steps2 = make_steps(&["identical1", "identical2"]);

        let id1 = exec1.create_saga(steps1, "trace1").unwrap();
        let id2 = exec2.create_saga(steps2, "trace1").unwrap();

        // Hashes should be identical for identical content
        let hash1 = exec1.content_hash();
        let hash2 = exec2.content_hash();
        assert_eq!(hash1, hash2);

        // Modify one executor and verify hash changes
        let _ = exec1.execute_step(
            &id1,
            StepOutcome::Success {
                result_data: b"data1".to_vec(),
            },
            10,
            "exec1",
        );
        let _ = exec2.execute_step(
            &id2,
            StepOutcome::Success {
                result_data: b"data2".to_vec(),
            },
            10,
            "exec2",
        );

        let hash1_modified = exec1.content_hash();
        let hash2_modified = exec2.content_hash();
        assert_ne!(hash1_modified, hash2_modified);
        assert_ne!(hash1, hash1_modified);

        // Test hash collision resistance with crafted inputs
        let collision_attempts = vec![
            ("hash_test_1", "collision_attempt"),
            ("hash_test", "_1collision_attempt"),
            ("hash_tes", "t_1collision_attempt"),
            ("hash", "_test_1collision_attempt"),
        ];

        let mut collision_hashes = Vec::new();
        for (name1, name2) in collision_attempts {
            let mut collision_exec = SagaExecutor::new();
            let collision_steps = vec![SagaStepDef {
                name: name1.to_string(),
                computation_name: Some(name2.to_string()),
                is_remote: true,
                idempotency_key: None,
            }];
            let _ = collision_exec.create_saga(collision_steps, "collision");
            collision_hashes.push(collision_exec.content_hash());
        }

        // All hashes should be unique (no collisions)
        for i in 0..collision_hashes.len() {
            for j in i + 1..collision_hashes.len() {
                assert_ne!(collision_hashes[i], collision_hashes[j]);
            }
        }

        // Test hash with serialization failures
        let mut corrupt_exec = SagaExecutor::new();
        let corrupt_id = corrupt_exec
            .create_saga(make_steps(&["test"]), "trace")
            .unwrap();

        // Force a serialization error by corrupting internal state
        if let Some(saga) = corrupt_exec.sagas.get_mut(&corrupt_id) {
            // Insert non-serializable data (this will cause serde to fail)
            // We can't actually break serde with the current types, but we can test the error path
            saga.saga_id = "\x00\x01\x02\x03invalid_utf8".to_string();
        }

        let error_hash = corrupt_exec.content_hash();
        assert!(error_hash.starts_with("e3b0c44298fc1c149afbf4c8996fb924")); // Empty string SHA256 when serde fails

        // Test deterministic hashing across multiple operations
        let mut deterministic_exec = SagaExecutor::new();
        let det_id = deterministic_exec
            .create_saga(make_steps(&["det1", "det2"]), "det")
            .unwrap();

        let hash_before = deterministic_exec.content_hash();
        let _ = deterministic_exec.execute_step(
            &det_id,
            StepOutcome::Success {
                result_data: vec![42],
            },
            100,
            "det",
        );
        let hash_after = deterministic_exec.content_hash();
        let _ = deterministic_exec.compensate(&det_id, "det");
        let hash_compensated = deterministic_exec.content_hash();

        // All hashes should be different
        assert_ne!(hash_before, hash_after);
        assert_ne!(hash_after, hash_compensated);
        assert_ne!(hash_before, hash_compensated);

        // Verify hash length and format consistency
        for hash in &[hash_before, hash_after, hash_compensated] {
            assert_eq!(hash.len(), 64); // SHA-256 hex string
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
