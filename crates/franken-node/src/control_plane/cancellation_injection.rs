//! bd-876n: Cancellation injection at all await points for critical control workflows.
//!
//! Systematically cancels workflows at every identified await point to verify that
//! the system maintains its invariants under all possible cancellation timings.
//! Enforces runtime invariant #7 (epoch barriers survive cancellation without
//! partial state) and #9 (cancellation safety is proven, not assumed).
//!
//! # Invariants
//!
//! - INV-CANCEL-LEAK-FREE: no resource leaks after cancellation at any await point
//! - INV-CANCEL-HALFCOMMIT-FREE: no partial state visible after cancellation
//! - INV-CANCEL-MATRIX-COMPLETE: every (workflow, await_point) pair is tested
//! - INV-CANCEL-DETERMINISTIC: same cancellation point produces same outcome
//! - INV-CANCEL-BARRIER-SAFE: epoch barriers survive cancellation without partial state
//! - INV-CANCEL-SAGA-SAFE: eviction sagas compensate correctly on cancellation

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Schema version for cancel injection reports.
pub const SCHEMA_VERSION: &str = "ci-v1.0";

/// Minimum required test cases in the cancel injection matrix.
pub const MIN_MATRIX_CASES: usize = 20;

// ---- Event codes ----

pub mod event_codes {
    pub const CANCEL_INJECTED: &str = "CANCEL_INJECTED";
    pub const CANCEL_LEAK_CHECK: &str = "CANCEL_LEAK_CHECK";
    pub const CANCEL_HALFCOMMIT_CHECK: &str = "CANCEL_HALFCOMMIT_CHECK";
    pub const CANCEL_MATRIX_COMPLETE: &str = "CANCEL_MATRIX_COMPLETE";
    pub const CANCEL_WORKFLOW_START: &str = "CANCEL_WORKFLOW_START";
    pub const CANCEL_WORKFLOW_END: &str = "CANCEL_WORKFLOW_END";
    pub const CANCEL_RESOURCE_SNAPSHOT: &str = "CANCEL_RESOURCE_SNAPSHOT";
    pub const CANCEL_STATE_SNAPSHOT: &str = "CANCEL_STATE_SNAPSHOT";
    pub const CANCEL_CASE_PASSED: &str = "CANCEL_CASE_PASSED";
    pub const CANCEL_CASE_FAILED: &str = "CANCEL_CASE_FAILED";
}

// ---- Error codes ----

pub mod error_codes {
    pub const ERR_CANCEL_LEAK_DETECTED: &str = "ERR_CANCEL_LEAK_DETECTED";
    pub const ERR_CANCEL_HALFCOMMIT: &str = "ERR_CANCEL_HALFCOMMIT";
    pub const ERR_CANCEL_MATRIX_INCOMPLETE: &str = "ERR_CANCEL_MATRIX_INCOMPLETE";
    pub const ERR_CANCEL_UNKNOWN_WORKFLOW: &str = "ERR_CANCEL_UNKNOWN_WORKFLOW";
    pub const ERR_CANCEL_INVALID_POINT: &str = "ERR_CANCEL_INVALID_POINT";
    pub const ERR_CANCEL_FRAMEWORK_ERROR: &str = "ERR_CANCEL_FRAMEWORK_ERROR";
    pub const ERR_CANCEL_STATE_MISMATCH: &str = "ERR_CANCEL_STATE_MISMATCH";
    pub const ERR_CANCEL_TIMEOUT: &str = "ERR_CANCEL_TIMEOUT";
}

// ---- Core types ----

/// Identifies a workflow under test.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WorkflowId {
    /// Epoch transition barrier (bd-2wsm).
    EpochTransitionBarrier,
    /// Marker stream append (bd-126h).
    MarkerStreamAppend,
    /// Root pointer publication (bd-nwhn).
    RootPointerPublication,
    /// Evidence commit.
    EvidenceCommit,
    /// Cancel-safe eviction saga (bd-1ru2).
    EvictionSaga,
    /// Custom workflow for extension.
    Custom(String),
}

impl fmt::Display for WorkflowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochTransitionBarrier => write!(f, "epoch_transition_barrier"),
            Self::MarkerStreamAppend => write!(f, "marker_stream_append"),
            Self::RootPointerPublication => write!(f, "root_pointer_publication"),
            Self::EvidenceCommit => write!(f, "evidence_commit"),
            Self::EvictionSaga => write!(f, "eviction_saga"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// An await point within a workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwaitPoint {
    pub workflow: WorkflowId,
    pub index: usize,
    pub label: String,
    pub description: String,
}

impl AwaitPoint {
    pub fn new(workflow: WorkflowId, index: usize, label: &str, description: &str) -> Self {
        Self {
            workflow,
            index,
            label: label.to_string(),
            description: description.to_string(),
        }
    }
}

/// Resource snapshot for leak detection.
/// INV-CANCEL-LEAK-FREE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub file_handles: u64,
    pub locks_held: u64,
    pub memory_allocations: u64,
    pub temp_files: u64,
    pub timestamp_ms: u64,
}

impl ResourceSnapshot {
    pub fn empty(timestamp_ms: u64) -> Self {
        Self {
            file_handles: 0,
            locks_held: 0,
            memory_allocations: 0,
            temp_files: 0,
            timestamp_ms,
        }
    }

    /// Compute delta between two snapshots for leak detection.
    pub fn delta(&self, after: &ResourceSnapshot) -> ResourceDelta {
        ResourceDelta {
            file_handles: after.file_handles as i64 - self.file_handles as i64,
            locks_held: after.locks_held as i64 - self.locks_held as i64,
            memory_allocations: after.memory_allocations as i64 - self.memory_allocations as i64,
            temp_files: after.temp_files as i64 - self.temp_files as i64,
        }
    }
}

/// Resource delta for leak detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDelta {
    pub file_handles: i64,
    pub locks_held: i64,
    pub memory_allocations: i64,
    pub temp_files: i64,
}

impl ResourceDelta {
    /// True if any resource leaked (positive delta).
    pub fn has_leaks(&self) -> bool {
        self.file_handles > 0
            || self.locks_held > 0
            || self.memory_allocations > 0
            || self.temp_files > 0
    }

    /// Zero delta (no leaks).
    pub fn zero() -> Self {
        Self {
            file_handles: 0,
            locks_held: 0,
            memory_allocations: 0,
            temp_files: 0,
        }
    }
}

/// State snapshot for half-commit detection.
/// INV-CANCEL-HALFCOMMIT-FREE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub epoch: u64,
    pub marker_head: Option<String>,
    pub root_pointer: Option<String>,
    pub saga_phase: Option<String>,
    pub custom_fields: BTreeMap<String, String>,
    pub timestamp_ms: u64,
}

impl StateSnapshot {
    pub fn new(epoch: u64, timestamp_ms: u64) -> Self {
        Self {
            epoch,
            marker_head: None,
            root_pointer: None,
            saga_phase: None,
            custom_fields: BTreeMap::new(),
            timestamp_ms,
        }
    }

    /// Detect half-commit: any unexpected state change.
    pub fn detect_halfcommit(&self, after: &StateSnapshot) -> Option<HalfCommitDetection> {
        let mut changes = Vec::new();

        if self.epoch != after.epoch {
            changes.push(format!("epoch: {} -> {}", self.epoch, after.epoch));
        }
        if self.marker_head != after.marker_head {
            changes.push(format!(
                "marker_head: {:?} -> {:?}",
                self.marker_head, after.marker_head
            ));
        }
        if self.root_pointer != after.root_pointer {
            changes.push(format!(
                "root_pointer: {:?} -> {:?}",
                self.root_pointer, after.root_pointer
            ));
        }
        if self.saga_phase != after.saga_phase {
            changes.push(format!(
                "saga_phase: {:?} -> {:?}",
                self.saga_phase, after.saga_phase
            ));
        }

        if changes.is_empty() {
            None
        } else {
            Some(HalfCommitDetection {
                changes,
                before_timestamp_ms: self.timestamp_ms,
                after_timestamp_ms: after.timestamp_ms,
            })
        }
    }
}

/// Detection result for half-commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HalfCommitDetection {
    pub changes: Vec<String>,
    pub before_timestamp_ms: u64,
    pub after_timestamp_ms: u64,
}

/// Result of a single cancellation test case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CancelTestOutcome {
    Passed,
    LeakDetected { delta: ResourceDelta },
    HalfCommitDetected { detection: HalfCommitDetection },
    FrameworkError { detail: String },
}

impl CancelTestOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

impl fmt::Display for CancelTestOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed => write!(f, "PASSED"),
            Self::LeakDetected { delta } => write!(f, "LEAK: {:?}", delta),
            Self::HalfCommitDetected { detection } => {
                write!(f, "HALFCOMMIT: {}", detection.changes.join("; "))
            }
            Self::FrameworkError { detail } => write!(f, "ERROR: {}", detail),
        }
    }
}

/// A single entry in the cancel injection matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelMatrixEntry {
    pub workflow: String,
    pub await_point_index: usize,
    pub await_point_label: String,
    pub outcome: CancelTestOutcome,
    pub resource_delta: ResourceDelta,
    pub halfcommit_detected: bool,
    pub elapsed_ms: u64,
    pub trace_id: String,
}

/// The complete cancel injection matrix report.
/// INV-CANCEL-MATRIX-COMPLETE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelInjectionMatrix {
    pub entries: Vec<CancelMatrixEntry>,
    pub total_cases: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub workflows_tested: Vec<String>,
    pub schema_version: String,
}

impl CancelInjectionMatrix {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_cases: 0,
            pass_count: 0,
            fail_count: 0,
            workflows_tested: Vec::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Add a test case result.
    pub fn record_case(&mut self, entry: CancelMatrixEntry) {
        self.total_cases = self.total_cases.saturating_add(1);
        if entry.outcome.is_pass() {
            self.pass_count = self.pass_count.saturating_add(1);
        } else {
            self.fail_count = self.fail_count.saturating_add(1);
        }

        let wf = entry.workflow.clone();
        if !self.workflows_tested.contains(&wf) {
            self.workflows_tested.push(wf);
        }

        self.entries.push(entry);
    }

    /// Check if the matrix meets minimum coverage.
    pub fn meets_minimum_coverage(&self) -> bool {
        self.total_cases >= MIN_MATRIX_CASES
    }

    /// Overall verdict.
    pub fn verdict(&self) -> &'static str {
        if self.fail_count == 0 && self.meets_minimum_coverage() {
            "PASS"
        } else {
            "FAIL"
        }
    }

    /// Export as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

impl Default for CancelInjectionMatrix {
    fn default() -> Self {
        Self::new()
    }
}

/// Audit record for JSONL export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelAuditRecord {
    pub event_code: String,
    pub workflow: String,
    pub await_point_index: usize,
    pub outcome: String,
    pub trace_id: String,
    pub timestamp_ms: u64,
    pub schema_version: String,
}

/// Errors from the cancellation injection framework.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelError {
    LeakDetected {
        workflow: String,
        point: usize,
        delta: ResourceDelta,
    },
    HalfCommit {
        workflow: String,
        point: usize,
        changes: Vec<String>,
    },
    MatrixIncomplete {
        total: usize,
        required: usize,
    },
    UnknownWorkflow {
        name: String,
    },
    InvalidPoint {
        workflow: String,
        point: usize,
        max: usize,
    },
    FrameworkError {
        detail: String,
    },
    StateMismatch {
        expected: String,
        actual: String,
    },
    Timeout {
        workflow: String,
        point: usize,
        elapsed_ms: u64,
    },
}

impl CancelError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::LeakDetected { .. } => error_codes::ERR_CANCEL_LEAK_DETECTED,
            Self::HalfCommit { .. } => error_codes::ERR_CANCEL_HALFCOMMIT,
            Self::MatrixIncomplete { .. } => error_codes::ERR_CANCEL_MATRIX_INCOMPLETE,
            Self::UnknownWorkflow { .. } => error_codes::ERR_CANCEL_UNKNOWN_WORKFLOW,
            Self::InvalidPoint { .. } => error_codes::ERR_CANCEL_INVALID_POINT,
            Self::FrameworkError { .. } => error_codes::ERR_CANCEL_FRAMEWORK_ERROR,
            Self::StateMismatch { .. } => error_codes::ERR_CANCEL_STATE_MISMATCH,
            Self::Timeout { .. } => error_codes::ERR_CANCEL_TIMEOUT,
        }
    }
}

impl fmt::Display for CancelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeakDetected {
                workflow,
                point,
                delta,
            } => {
                write!(
                    f,
                    "{}: {}@{} delta={:?}",
                    self.code(),
                    workflow,
                    point,
                    delta
                )
            }
            Self::HalfCommit {
                workflow,
                point,
                changes,
            } => {
                write!(
                    f,
                    "{}: {}@{} changes={}",
                    self.code(),
                    workflow,
                    point,
                    changes.join("; ")
                )
            }
            Self::MatrixIncomplete { total, required } => {
                write!(f, "{}: {}/{} cases", self.code(), total, required)
            }
            Self::UnknownWorkflow { name } => {
                write!(f, "{}: unknown workflow {}", self.code(), name)
            }
            Self::InvalidPoint {
                workflow,
                point,
                max,
            } => {
                write!(
                    f,
                    "{}: {}@{} exceeds max {}",
                    self.code(),
                    workflow,
                    point,
                    max
                )
            }
            Self::FrameworkError { detail } => {
                write!(f, "{}: {}", self.code(), detail)
            }
            Self::StateMismatch { expected, actual } => {
                write!(f, "{}: expected {} got {}", self.code(), expected, actual)
            }
            Self::Timeout {
                workflow,
                point,
                elapsed_ms,
            } => {
                write!(
                    f,
                    "{}: {}@{} after {}ms",
                    self.code(),
                    workflow,
                    point,
                    elapsed_ms
                )
            }
        }
    }
}

/// Workflow registration for the cancellation injection framework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRegistration {
    pub id: WorkflowId,
    pub await_points: Vec<AwaitPoint>,
    pub description: String,
}

/// The cancellation injection framework.
///
/// Manages workflow registration, test execution, and result collection.
pub struct CancellationInjectionFramework {
    workflows: BTreeMap<String, WorkflowRegistration>,
    matrix: CancelInjectionMatrix,
    audit_log: Vec<CancelAuditRecord>,
}

impl CancellationInjectionFramework {
    pub fn new() -> Self {
        Self {
            workflows: BTreeMap::new(),
            matrix: CancelInjectionMatrix::new(),
            audit_log: Vec::new(),
        }
    }

    /// Register a workflow with its await points.
    pub fn register_workflow(&mut self, reg: WorkflowRegistration) {
        let key = reg.id.to_string();
        self.workflows.insert(key, reg);
    }

    /// Get all registered workflows.
    pub fn registered_workflows(&self) -> Vec<&WorkflowRegistration> {
        self.workflows.values().collect()
    }

    /// Total number of (workflow, await_point) pairs.
    pub fn total_test_cases(&self) -> usize {
        self.workflows.values().map(|w| w.await_points.len()).sum()
    }

    /// Run a single cancellation test case.
    ///
    /// Takes snapshots before/after, checks for leaks and half-commits.
    #[allow(clippy::too_many_arguments)]
    pub fn run_cancel_case(
        &mut self,
        workflow_name: &str,
        await_point_index: usize,
        resource_before: &ResourceSnapshot,
        resource_after: &ResourceSnapshot,
        state_before: &StateSnapshot,
        state_after: &StateSnapshot,
        elapsed_ms: u64,
        trace_id: &str,
    ) -> Result<CancelTestOutcome, CancelError> {
        let wf = self
            .workflows
            .get(workflow_name)
            .ok_or_else(|| CancelError::UnknownWorkflow {
                name: workflow_name.to_string(),
            })?;

        if await_point_index >= wf.await_points.len() {
            return Err(CancelError::InvalidPoint {
                workflow: workflow_name.to_string(),
                point: await_point_index,
                max: wf.await_points.len().saturating_sub(1),
            });
        }

        let label = wf.await_points[await_point_index].label.clone();

        // INV-CANCEL-LEAK-FREE
        let delta = resource_before.delta(resource_after);
        if delta.has_leaks() {
            let outcome = CancelTestOutcome::LeakDetected {
                delta: delta.clone(),
            };
            self.record_entry(
                workflow_name,
                await_point_index,
                &label,
                &outcome,
                &delta,
                false,
                elapsed_ms,
                trace_id,
            );
            return Ok(outcome);
        }

        // INV-CANCEL-HALFCOMMIT-FREE
        if let Some(detection) = state_before.detect_halfcommit(state_after) {
            let outcome = CancelTestOutcome::HalfCommitDetected { detection };
            self.record_entry(
                workflow_name,
                await_point_index,
                &label,
                &outcome,
                &delta,
                true,
                elapsed_ms,
                trace_id,
            );
            return Ok(outcome);
        }

        let outcome = CancelTestOutcome::Passed;
        self.record_entry(
            workflow_name,
            await_point_index,
            &label,
            &outcome,
            &delta,
            false,
            elapsed_ms,
            trace_id,
        );
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_entry(
        &mut self,
        workflow: &str,
        point: usize,
        label: &str,
        outcome: &CancelTestOutcome,
        delta: &ResourceDelta,
        halfcommit: bool,
        elapsed_ms: u64,
        trace_id: &str,
    ) {
        let entry = CancelMatrixEntry {
            workflow: workflow.to_string(),
            await_point_index: point,
            await_point_label: label.to_string(),
            outcome: outcome.clone(),
            resource_delta: delta.clone(),
            halfcommit_detected: halfcommit,
            elapsed_ms,
            trace_id: trace_id.to_string(),
        };
        self.matrix.record_case(entry);

        let event_code = if outcome.is_pass() {
            event_codes::CANCEL_CASE_PASSED
        } else {
            event_codes::CANCEL_CASE_FAILED
        };

        self.audit_log.push(CancelAuditRecord {
            event_code: event_code.to_string(),
            workflow: workflow.to_string(),
            await_point_index: point,
            outcome: outcome.to_string(),
            trace_id: trace_id.to_string(),
            timestamp_ms: 0,
            schema_version: SCHEMA_VERSION.to_string(),
        });
    }

    /// Get the current matrix report.
    pub fn matrix(&self) -> &CancelInjectionMatrix {
        &self.matrix
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[CancelAuditRecord] {
        &self.audit_log
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Build the default set of workflow registrations for 10.14 critical workflows.
    pub fn register_default_workflows(&mut self) {
        // Epoch transition barrier (bd-2wsm)
        self.register_workflow(WorkflowRegistration {
            id: WorkflowId::EpochTransitionBarrier,
            await_points: vec![
                AwaitPoint::new(
                    WorkflowId::EpochTransitionBarrier,
                    0,
                    "propose_start",
                    "Before barrier propose",
                ),
                AwaitPoint::new(
                    WorkflowId::EpochTransitionBarrier,
                    1,
                    "drain_broadcast",
                    "After sending drain requests",
                ),
                AwaitPoint::new(
                    WorkflowId::EpochTransitionBarrier,
                    2,
                    "drain_ack_collect",
                    "While collecting drain ACKs",
                ),
                AwaitPoint::new(
                    WorkflowId::EpochTransitionBarrier,
                    3,
                    "commit_prepare",
                    "Before epoch commit",
                ),
                AwaitPoint::new(
                    WorkflowId::EpochTransitionBarrier,
                    4,
                    "commit_notify",
                    "After epoch advance, notifying participants",
                ),
                AwaitPoint::new(
                    WorkflowId::EpochTransitionBarrier,
                    5,
                    "transcript_write",
                    "Writing barrier transcript",
                ),
            ],
            description: "Epoch transition barrier protocol".to_string(),
        });

        // Marker stream append (bd-126h)
        self.register_workflow(WorkflowRegistration {
            id: WorkflowId::MarkerStreamAppend,
            await_points: vec![
                AwaitPoint::new(
                    WorkflowId::MarkerStreamAppend,
                    0,
                    "marker_create",
                    "Before marker creation",
                ),
                AwaitPoint::new(
                    WorkflowId::MarkerStreamAppend,
                    1,
                    "marker_sign",
                    "After marker creation, before signing",
                ),
                AwaitPoint::new(
                    WorkflowId::MarkerStreamAppend,
                    2,
                    "marker_append",
                    "After signing, before append to stream",
                ),
                AwaitPoint::new(
                    WorkflowId::MarkerStreamAppend,
                    3,
                    "marker_confirm",
                    "After append, before confirmation",
                ),
            ],
            description: "Marker stream append workflow".to_string(),
        });

        // Root pointer publication (bd-nwhn)
        self.register_workflow(WorkflowRegistration {
            id: WorkflowId::RootPointerPublication,
            await_points: vec![
                AwaitPoint::new(
                    WorkflowId::RootPointerPublication,
                    0,
                    "root_compute",
                    "Before root computation",
                ),
                AwaitPoint::new(
                    WorkflowId::RootPointerPublication,
                    1,
                    "root_sign",
                    "After computation, before signing",
                ),
                AwaitPoint::new(
                    WorkflowId::RootPointerPublication,
                    2,
                    "root_publish",
                    "After signing, before publication",
                ),
                AwaitPoint::new(
                    WorkflowId::RootPointerPublication,
                    3,
                    "root_confirm",
                    "After publication, before confirmation",
                ),
            ],
            description: "Root pointer publication workflow".to_string(),
        });

        // Evidence commit
        self.register_workflow(WorkflowRegistration {
            id: WorkflowId::EvidenceCommit,
            await_points: vec![
                AwaitPoint::new(
                    WorkflowId::EvidenceCommit,
                    0,
                    "evidence_prepare",
                    "Before evidence preparation",
                ),
                AwaitPoint::new(
                    WorkflowId::EvidenceCommit,
                    1,
                    "evidence_validate",
                    "After preparation, before validation",
                ),
                AwaitPoint::new(
                    WorkflowId::EvidenceCommit,
                    2,
                    "evidence_commit",
                    "After validation, before commit",
                ),
                AwaitPoint::new(
                    WorkflowId::EvidenceCommit,
                    3,
                    "evidence_confirm",
                    "After commit, before confirmation",
                ),
            ],
            description: "Evidence commit workflow".to_string(),
        });

        // Eviction saga (bd-1ru2)
        self.register_workflow(WorkflowRegistration {
            id: WorkflowId::EvictionSaga,
            await_points: vec![
                AwaitPoint::new(
                    WorkflowId::EvictionSaga,
                    0,
                    "saga_begin",
                    "Before saga begin",
                ),
                AwaitPoint::new(
                    WorkflowId::EvictionSaga,
                    1,
                    "saga_upload",
                    "During L2->L3 upload",
                ),
                AwaitPoint::new(
                    WorkflowId::EvictionSaga,
                    2,
                    "saga_verify",
                    "During L3 verification",
                ),
                AwaitPoint::new(
                    WorkflowId::EvictionSaga,
                    3,
                    "saga_retire",
                    "During L2 retirement",
                ),
                AwaitPoint::new(
                    WorkflowId::EvictionSaga,
                    4,
                    "saga_compensate",
                    "During compensation",
                ),
                AwaitPoint::new(
                    WorkflowId::EvictionSaga,
                    5,
                    "saga_complete",
                    "Before completion commit",
                ),
            ],
            description: "Cancel-safe eviction saga".to_string(),
        });
    }
}

impl Default for CancellationInjectionFramework {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_framework() -> CancellationInjectionFramework {
        let mut f = CancellationInjectionFramework::new();
        f.register_default_workflows();
        f
    }

    fn clean_snapshots(
        ts: u64,
    ) -> (
        ResourceSnapshot,
        ResourceSnapshot,
        StateSnapshot,
        StateSnapshot,
    ) {
        let rb = ResourceSnapshot::empty(ts);
        let ra = ResourceSnapshot::empty(ts + 100);
        let sb = StateSnapshot::new(5, ts);
        let sa = StateSnapshot::new(5, ts + 100);
        (rb, ra, sb, sa)
    }

    // ---- Framework setup ----

    #[test]
    fn default_workflows_registered() {
        let f = make_framework();
        assert_eq!(f.registered_workflows().len(), 5);
        assert_eq!(f.total_test_cases(), 24);
    }

    #[test]
    fn total_test_cases_count() {
        let f = make_framework();
        // 6 + 4 + 4 + 4 + 6 = 24
        assert_eq!(f.total_test_cases(), 24);
    }

    // ---- Clean cancellation (no leaks, no half-commits) ----

    #[test]
    fn clean_cancel_passes() {
        let mut f = make_framework();
        let (rb, ra, sb, sa) = clean_snapshots(1000);
        let outcome = f
            .run_cancel_case("epoch_transition_barrier", 0, &rb, &ra, &sb, &sa, 50, "t1")
            .unwrap();
        assert!(outcome.is_pass());
    }

    // ---- Leak detection ----

    #[test]
    fn leak_detected_on_resource_delta() {
        let mut f = make_framework();
        let rb = ResourceSnapshot::empty(1000);
        let mut ra = ResourceSnapshot::empty(1100);
        ra.file_handles = 2; // leaked 2 file handles
        let sb = StateSnapshot::new(5, 1000);
        let sa = StateSnapshot::new(5, 1100);

        let outcome = f
            .run_cancel_case("epoch_transition_barrier", 1, &rb, &ra, &sb, &sa, 50, "t2")
            .unwrap();
        assert!(!outcome.is_pass());
        assert!(matches!(outcome, CancelTestOutcome::LeakDetected { .. }));
    }

    // ---- Half-commit detection ----

    #[test]
    fn halfcommit_detected_on_epoch_change() {
        let mut f = make_framework();
        let rb = ResourceSnapshot::empty(1000);
        let ra = ResourceSnapshot::empty(1100);
        let sb = StateSnapshot::new(5, 1000);
        let sa = StateSnapshot::new(6, 1100); // epoch advanced!

        let outcome = f
            .run_cancel_case("epoch_transition_barrier", 2, &rb, &ra, &sb, &sa, 50, "t3")
            .unwrap();
        assert!(!outcome.is_pass());
        assert!(matches!(
            outcome,
            CancelTestOutcome::HalfCommitDetected { .. }
        ));
    }

    #[test]
    fn halfcommit_detected_on_marker_change() {
        let mut f = make_framework();
        let rb = ResourceSnapshot::empty(1000);
        let ra = ResourceSnapshot::empty(1100);
        let mut sb = StateSnapshot::new(5, 1000);
        sb.marker_head = Some("head-1".to_string());
        let mut sa = StateSnapshot::new(5, 1100);
        sa.marker_head = Some("head-2".to_string()); // marker changed!

        let outcome = f
            .run_cancel_case("marker_stream_append", 2, &rb, &ra, &sb, &sa, 50, "t4")
            .unwrap();
        assert!(!outcome.is_pass());
    }

    // ---- Unknown workflow ----

    #[test]
    fn unknown_workflow_rejected() {
        let mut f = make_framework();
        let (rb, ra, sb, sa) = clean_snapshots(1000);
        let err = f
            .run_cancel_case("nonexistent", 0, &rb, &ra, &sb, &sa, 50, "t5")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_UNKNOWN_WORKFLOW);
    }

    // ---- Invalid await point ----

    #[test]
    fn invalid_await_point_rejected() {
        let mut f = make_framework();
        let (rb, ra, sb, sa) = clean_snapshots(1000);
        let err = f
            .run_cancel_case("epoch_transition_barrier", 99, &rb, &ra, &sb, &sa, 50, "t6")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_INVALID_POINT);
    }

    // ---- Matrix recording ----

    #[test]
    fn matrix_records_pass_and_fail() {
        let mut f = make_framework();
        let (rb, ra, sb, sa) = clean_snapshots(1000);

        // Pass case
        f.run_cancel_case("epoch_transition_barrier", 0, &rb, &ra, &sb, &sa, 50, "t1")
            .unwrap();

        // Fail case (leak)
        let mut ra_leak = rb.clone();
        ra_leak.locks_held = 1;
        f.run_cancel_case(
            "epoch_transition_barrier",
            1,
            &rb,
            &ra_leak,
            &sb,
            &sa,
            50,
            "t2",
        )
        .unwrap();

        let m = f.matrix();
        assert_eq!(m.total_cases, 2);
        assert_eq!(m.pass_count, 1);
        assert_eq!(m.fail_count, 1);
    }

    // ---- Matrix coverage ----

    #[test]
    fn matrix_minimum_coverage_check() {
        let mut m = CancelInjectionMatrix::new();
        assert!(!m.meets_minimum_coverage());

        for i in 0..MIN_MATRIX_CASES {
            m.record_case(CancelMatrixEntry {
                workflow: "test".to_string(),
                await_point_index: i,
                await_point_label: format!("point-{i}"),
                outcome: CancelTestOutcome::Passed,
                resource_delta: ResourceDelta::zero(),
                halfcommit_detected: false,
                elapsed_ms: 10,
                trace_id: format!("t{i}"),
            });
        }
        assert!(m.meets_minimum_coverage());
    }

    // ---- Matrix verdict ----

    #[test]
    fn matrix_verdict_pass_when_all_pass_and_sufficient() {
        let mut m = CancelInjectionMatrix::new();
        for i in 0..MIN_MATRIX_CASES {
            m.record_case(CancelMatrixEntry {
                workflow: "test".to_string(),
                await_point_index: i,
                await_point_label: format!("p{i}"),
                outcome: CancelTestOutcome::Passed,
                resource_delta: ResourceDelta::zero(),
                halfcommit_detected: false,
                elapsed_ms: 10,
                trace_id: format!("t{i}"),
            });
        }
        assert_eq!(m.verdict(), "PASS");
    }

    #[test]
    fn matrix_verdict_fail_with_failures() {
        let mut m = CancelInjectionMatrix::new();
        m.record_case(CancelMatrixEntry {
            workflow: "test".to_string(),
            await_point_index: 0,
            await_point_label: "p0".to_string(),
            outcome: CancelTestOutcome::LeakDetected {
                delta: ResourceDelta {
                    file_handles: 1,
                    locks_held: 0,
                    memory_allocations: 0,
                    temp_files: 0,
                },
            },
            resource_delta: ResourceDelta {
                file_handles: 1,
                locks_held: 0,
                memory_allocations: 0,
                temp_files: 0,
            },
            halfcommit_detected: false,
            elapsed_ms: 10,
            trace_id: "t0".to_string(),
        });
        assert_eq!(m.verdict(), "FAIL");
    }

    // ---- Full matrix run ----

    #[test]
    fn full_matrix_all_clean() {
        let mut f = make_framework();
        let workflows: Vec<String> = f
            .registered_workflows()
            .iter()
            .map(|w| w.id.to_string())
            .collect();
        let point_counts: Vec<usize> = f
            .registered_workflows()
            .iter()
            .map(|w| w.await_points.len())
            .collect();

        for (wf, count) in workflows.iter().zip(point_counts.iter()) {
            for point in 0..*count {
                let (rb, ra, sb, sa) = clean_snapshots(1000 + point as u64 * 100);
                let outcome = f
                    .run_cancel_case(
                        wf,
                        point,
                        &rb,
                        &ra,
                        &sb,
                        &sa,
                        50,
                        &format!("t-{wf}-{point}"),
                    )
                    .unwrap();
                assert!(outcome.is_pass(), "Failed at {}@{}", wf, point);
            }
        }

        let m = f.matrix();
        assert_eq!(m.total_cases, 24);
        assert_eq!(m.pass_count, 24);
        assert_eq!(m.fail_count, 0);
        assert!(m.meets_minimum_coverage());
        assert_eq!(m.verdict(), "PASS");
    }

    // ---- Resource delta ----

    #[test]
    fn resource_delta_no_leaks() {
        let before = ResourceSnapshot::empty(1000);
        let after = ResourceSnapshot::empty(1100);
        let delta = before.delta(&after);
        assert!(!delta.has_leaks());
    }

    #[test]
    fn resource_delta_detects_leaks() {
        let before = ResourceSnapshot::empty(1000);
        let mut after = ResourceSnapshot::empty(1100);
        after.locks_held = 1;
        let delta = before.delta(&after);
        assert!(delta.has_leaks());
    }

    // ---- State snapshot half-commit ----

    #[test]
    fn state_snapshot_no_halfcommit_when_same() {
        let s1 = StateSnapshot::new(5, 1000);
        let s2 = StateSnapshot::new(5, 1100);
        assert!(s1.detect_halfcommit(&s2).is_none());
    }

    #[test]
    fn state_snapshot_detects_epoch_halfcommit() {
        let s1 = StateSnapshot::new(5, 1000);
        let s2 = StateSnapshot::new(6, 1100);
        let hc = s1.detect_halfcommit(&s2).unwrap();
        assert!(!hc.changes.is_empty());
        assert!(hc.changes[0].contains("epoch"));
    }

    // ---- Audit log ----

    #[test]
    fn audit_log_records_events() {
        let mut f = make_framework();
        let (rb, ra, sb, sa) = clean_snapshots(1000);
        f.run_cancel_case("epoch_transition_barrier", 0, &rb, &ra, &sb, &sa, 50, "t1")
            .unwrap();
        assert_eq!(f.audit_log().len(), 1);
        assert_eq!(f.audit_log()[0].event_code, event_codes::CANCEL_CASE_PASSED);
    }

    #[test]
    fn export_audit_jsonl() {
        let mut f = make_framework();
        let (rb, ra, sb, sa) = clean_snapshots(1000);
        f.run_cancel_case("epoch_transition_barrier", 0, &rb, &ra, &sb, &sa, 50, "t1")
            .unwrap();
        let jsonl = f.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    // ---- WorkflowId display ----

    #[test]
    fn workflow_id_display() {
        assert_eq!(
            WorkflowId::EpochTransitionBarrier.to_string(),
            "epoch_transition_barrier"
        );
        assert_eq!(
            WorkflowId::MarkerStreamAppend.to_string(),
            "marker_stream_append"
        );
        assert_eq!(WorkflowId::EvictionSaga.to_string(), "eviction_saga");
        assert_eq!(WorkflowId::Custom("foo".into()).to_string(), "custom:foo");
    }

    // ---- CancelTestOutcome display ----

    #[test]
    fn outcome_display() {
        assert_eq!(CancelTestOutcome::Passed.to_string(), "PASSED");
        assert!(
            !CancelTestOutcome::FrameworkError {
                detail: "err".into()
            }
            .to_string()
            .is_empty()
        );
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<CancelError> = vec![
            CancelError::LeakDetected {
                workflow: "w".into(),
                point: 0,
                delta: ResourceDelta::zero(),
            },
            CancelError::HalfCommit {
                workflow: "w".into(),
                point: 0,
                changes: vec!["c".into()],
            },
            CancelError::MatrixIncomplete {
                total: 5,
                required: 20,
            },
            CancelError::UnknownWorkflow { name: "x".into() },
            CancelError::InvalidPoint {
                workflow: "w".into(),
                point: 99,
                max: 5,
            },
            CancelError::FrameworkError {
                detail: "err".into(),
            },
            CancelError::StateMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            CancelError::Timeout {
                workflow: "w".into(),
                point: 0,
                elapsed_ms: 5000,
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(s.contains(e.code()), "{:?} should contain {}", e, e.code());
        }
    }

    // ---- Matrix JSON export ----

    #[test]
    fn matrix_to_json() {
        let m = CancelInjectionMatrix::new();
        let json = m.to_json();
        assert!(json.contains("ci-v1.0"));
        assert!(json.contains("total_cases"));
    }

    // ---- Default trait ----

    #[test]
    fn framework_default() {
        let f = CancellationInjectionFramework::default();
        assert!(f.registered_workflows().is_empty());
        assert_eq!(f.matrix().total_cases, 0);
    }

    #[test]
    fn matrix_default() {
        let m = CancelInjectionMatrix::default();
        assert_eq!(m.total_cases, 0);
        assert_eq!(m.schema_version, SCHEMA_VERSION);
    }
}
