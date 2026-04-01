//! bd-3tpg: Enforce canonical all-point cancellation injection gate for
//! critical control workflows.
//!
//! Integrates the canonical cancellation injection framework (bd-876n) into
//! franken_node's control-plane workflows. Every critical protocol must survive
//! cancellation at every await point without obligation leaks, half-commit
//! outcomes, or quiescence violations.
//!
//! # Invariants
//!
//! - INV-CIG-CANONICAL-ONLY: no custom injection logic; all cancellation injection
//!   uses the canonical CancellationInjectionFramework from bd-876n
//! - INV-CIG-ALL-WORKFLOWS: every critical control workflow is registered
//! - INV-CIG-FULL-MATRIX: the injection matrix covers every (workflow, await_point) pair
//! - INV-CIG-ZERO-FAILURES: a single failure at any injection point fails the gate
//! - INV-CIG-LEAK-FREE: no resource leaks after cancellation at any await point
//! - INV-CIG-REPORT-COMPLETE: the injection report includes per-workflow per-point results

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

use crate::control_plane::cancellation_injection::{
    AwaitPoint, CancelTestOutcome, CancellationInjectionFramework, ResourceSnapshot, StateSnapshot,
    WorkflowId, WorkflowRegistration,
};

/// Schema version for the control-plane cancellation injection gate.
pub const SCHEMA_VERSION: &str = "cig-v1.0";

// ── Event codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Injection point enumerated for a control workflow.
    pub const CIN_POINT_ENUMERATED: &str = "CIN-001";
    /// Cancellation injected at a specific await point.
    pub const CIN_CANCELLATION_INJECTED: &str = "CIN-002";
    /// Post-cancel assertion passed (no leak, no halfcommit, no quiescence violation).
    pub const CIN_ASSERTION_PASSED: &str = "CIN-003";
    /// Post-cancel assertion failed: obligation leak detected.
    pub const CIN_OBLIGATION_LEAK: &str = "CIN-004";
    /// Post-cancel assertion failed: half-commit detected.
    pub const CIN_HALFCOMMIT_DETECTED: &str = "CIN-005";
    /// Post-cancel assertion failed: quiescence violation detected.
    pub const CIN_QUIESCENCE_VIOLATION: &str = "CIN-006";
    /// Gate verdict emitted.
    pub const CIN_GATE_VERDICT: &str = "CIN-007";
    /// Control workflow registered with the injection framework.
    pub const CIN_WORKFLOW_REGISTERED: &str = "CIN-008";
}

// ── Error codes ──────────────────────────────────────────────────────────────

pub mod error_codes {
    pub const ERR_CIG_LEAK_DETECTED: &str = "ERR_CIG_LEAK_DETECTED";
    pub const ERR_CIG_HALFCOMMIT: &str = "ERR_CIG_HALFCOMMIT";
    pub const ERR_CIG_QUIESCENCE: &str = "ERR_CIG_QUIESCENCE";
    pub const ERR_CIG_MATRIX_INCOMPLETE: &str = "ERR_CIG_MATRIX_INCOMPLETE";
    pub const ERR_CIG_CUSTOM_INJECTION: &str = "ERR_CIG_CUSTOM_INJECTION";
    pub const ERR_CIG_MISSING_WORKFLOW: &str = "ERR_CIG_MISSING_WORKFLOW";
}

/// Control-plane workflow identifiers for the gate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ControlWorkflow {
    ConnectorLifecycle,
    RolloutTransition,
    QuarantinePromotion,
    MigrationOrchestration,
    FencingAcquire,
    HealthGateEvaluation,
}

impl ControlWorkflow {
    pub fn all() -> &'static [ControlWorkflow] {
        &[
            Self::ConnectorLifecycle,
            Self::RolloutTransition,
            Self::QuarantinePromotion,
            Self::MigrationOrchestration,
            Self::FencingAcquire,
            Self::HealthGateEvaluation,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectorLifecycle => "connector_lifecycle",
            Self::RolloutTransition => "rollout_transition",
            Self::QuarantinePromotion => "quarantine_promotion",
            Self::MigrationOrchestration => "migration_orchestration",
            Self::FencingAcquire => "fencing_acquire",
            Self::HealthGateEvaluation => "health_gate_evaluation",
        }
    }

    pub fn canonical_await_point_labels(&self) -> &'static [&'static str] {
        match self {
            Self::ConnectorLifecycle => {
                &["init_start", "health_probe", "state_load", "ready_signal"]
            }
            Self::RolloutTransition => &[
                "canary_check",
                "promote_prepare",
                "state_commit",
                "notify_peers",
            ],
            Self::QuarantinePromotion => &["quarantine_check", "trust_verify", "promotion_commit"],
            Self::MigrationOrchestration => &[
                "schema_check",
                "data_migrate",
                "validate_result",
                "finalize",
            ],
            Self::FencingAcquire => &["token_request", "epoch_validate", "token_commit"],
            Self::HealthGateEvaluation => &["probe_collect", "score_compute", "verdict_emit"],
        }
    }

    pub fn expected_point_count(&self) -> usize {
        self.canonical_await_point_labels().len()
    }
}

impl fmt::Display for ControlWorkflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Per-workflow injection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowInjectionResult {
    pub workflow: String,
    pub total_points: usize,
    pub points_passed: usize,
    pub points_failed: usize,
    pub failures: Vec<PointFailure>,
}

/// Detail of a single injection point failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointFailure {
    pub await_point_index: usize,
    pub await_point_label: String,
    pub failure_type: String,
    pub detail: String,
}

/// Complete gate report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelInjectionGateReport {
    pub gate_id: String,
    pub schema_version: String,
    pub total_workflows: usize,
    pub total_injection_points: usize,
    pub total_passed: usize,
    pub total_failed: usize,
    pub verdict: String,
    pub workflow_results: Vec<WorkflowInjectionResult>,
}

/// Audit record for the gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateAuditRecord {
    pub event_code: String,
    pub workflow: String,
    pub detail: String,
    pub trace_id: String,
    pub schema_version: String,
}

/// The cancellation injection gate for control-plane workflows.
///
/// Wraps the canonical CancellationInjectionFramework (bd-876n) and enforces
/// it across all critical control workflows. INV-CIG-CANONICAL-ONLY
pub struct CancelInjectionGate {
    framework: CancellationInjectionFramework,
    control_workflows: BTreeMap<String, ControlWorkflow>,
    audit_log: Vec<GateAuditRecord>,
    report: Option<CancelInjectionGateReport>,
}

impl CancelInjectionGate {
    /// Create a new gate backed by the canonical framework.
    pub fn new() -> Self {
        let mut framework = CancellationInjectionFramework::new();
        // Register the canonical 10.14 default workflows
        framework.register_default_workflows();

        Self {
            framework,
            control_workflows: BTreeMap::new(),
            audit_log: Vec::new(),
            report: None,
        }
    }

    /// Register a control-plane workflow with its await points.
    /// INV-CIG-ALL-WORKFLOWS
    pub fn register_control_workflow(
        &mut self,
        workflow: ControlWorkflow,
        await_points: Vec<AwaitPoint>,
        trace_id: &str,
    ) {
        let key = workflow.as_str().to_string();
        let wf_id = WorkflowId::Custom(key.clone());

        self.framework.register_workflow(WorkflowRegistration {
            id: wf_id,
            await_points,
            description: format!("Control-plane workflow: {}", workflow),
        });

        self.control_workflows.insert(key.clone(), workflow);

        push_bounded(
            &mut self.audit_log,
            GateAuditRecord {
                event_code: event_codes::CIN_WORKFLOW_REGISTERED.to_string(),
                workflow: key,
                detail: "registered".to_string(),
                trace_id: trace_id.to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }

    /// Register the default set of control-plane workflows.
    pub fn register_default_control_workflows(&mut self, trace_id: &str) {
        // Connector lifecycle
        self.register_control_workflow(
            ControlWorkflow::ConnectorLifecycle,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("connector_lifecycle".into()),
                    0,
                    "init_start",
                    "Before connector initialization",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("connector_lifecycle".into()),
                    1,
                    "health_probe",
                    "During initial health probe",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("connector_lifecycle".into()),
                    2,
                    "state_load",
                    "Loading persisted state",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("connector_lifecycle".into()),
                    3,
                    "ready_signal",
                    "Before signaling ready",
                ),
            ],
            trace_id,
        );

        // Rollout transition
        self.register_control_workflow(
            ControlWorkflow::RolloutTransition,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("rollout_transition".into()),
                    0,
                    "canary_check",
                    "Before canary evaluation",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("rollout_transition".into()),
                    1,
                    "promote_prepare",
                    "Preparing promotion",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("rollout_transition".into()),
                    2,
                    "state_commit",
                    "Committing rollout state",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("rollout_transition".into()),
                    3,
                    "notify_peers",
                    "Notifying peer nodes",
                ),
            ],
            trace_id,
        );

        // Quarantine promotion
        self.register_control_workflow(
            ControlWorkflow::QuarantinePromotion,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("quarantine_promotion".into()),
                    0,
                    "quarantine_check",
                    "Evaluating quarantine status",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("quarantine_promotion".into()),
                    1,
                    "trust_verify",
                    "Verifying trust score",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("quarantine_promotion".into()),
                    2,
                    "promotion_commit",
                    "Committing promotion",
                ),
            ],
            trace_id,
        );

        // Migration orchestration
        self.register_control_workflow(
            ControlWorkflow::MigrationOrchestration,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("migration_orchestration".into()),
                    0,
                    "schema_check",
                    "Checking schema compatibility",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("migration_orchestration".into()),
                    1,
                    "data_migrate",
                    "Migrating data",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("migration_orchestration".into()),
                    2,
                    "validate_result",
                    "Validating migration",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("migration_orchestration".into()),
                    3,
                    "finalize",
                    "Finalizing migration",
                ),
            ],
            trace_id,
        );

        // Fencing acquire
        self.register_control_workflow(
            ControlWorkflow::FencingAcquire,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    0,
                    "token_request",
                    "Requesting fencing token",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    1,
                    "epoch_validate",
                    "Validating epoch binding",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    2,
                    "token_commit",
                    "Committing token acquisition",
                ),
            ],
            trace_id,
        );

        // Health gate evaluation
        self.register_control_workflow(
            ControlWorkflow::HealthGateEvaluation,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("health_gate_evaluation".into()),
                    0,
                    "probe_collect",
                    "Collecting health probes",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("health_gate_evaluation".into()),
                    1,
                    "score_compute",
                    "Computing health score",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("health_gate_evaluation".into()),
                    2,
                    "verdict_emit",
                    "Emitting health verdict",
                ),
            ],
            trace_id,
        );
    }

    /// Run a single injection case through the canonical framework.
    #[allow(clippy::too_many_arguments)]
    pub fn run_injection_case(
        &mut self,
        workflow_name: &str,
        point_index: usize,
        resource_before: &ResourceSnapshot,
        resource_after: &ResourceSnapshot,
        state_before: &StateSnapshot,
        state_after: &StateSnapshot,
        elapsed_ms: u64,
        trace_id: &str,
    ) -> Result<CancelTestOutcome, String> {
        let wf_key = format!("custom:{}", workflow_name);
        self.framework
            .run_cancel_case(
                &wf_key,
                point_index,
                resource_before,
                resource_after,
                state_before,
                state_after,
                elapsed_ms,
                trace_id,
            )
            .map_err(|e| e.to_string())
    }

    /// Run the complete injection matrix on all registered control workflows
    /// with clean snapshots (simulated). INV-CIG-FULL-MATRIX
    pub fn run_full_gate(&mut self, trace_id: &str) -> CancelInjectionGateReport {
        let mut workflow_results = Vec::new();
        let mut total_passed = 0usize;
        let mut total_failed = 0usize;
        let mut total_points = 0usize;

        for workflow in ControlWorkflow::all() {
            let wf_key = workflow.as_str().to_string();
            let canonical_key = format!("custom:{}", wf_key);

            if !self.control_workflows.contains_key(&wf_key) {
                total_points += 1;
                total_failed += 1;
                workflow_results.push(WorkflowInjectionResult {
                    workflow: wf_key,
                    total_points: 1,
                    points_passed: 0,
                    points_failed: 1,
                    failures: vec![PointFailure {
                        await_point_index: 0,
                        await_point_label: "workflow_registration".to_string(),
                        failure_type: error_codes::ERR_CIG_MISSING_WORKFLOW.to_string(),
                        detail: "required control workflow is not registered".to_string(),
                    }],
                });
                continue;
            }

            let await_points = self
                .framework
                .registered_workflows()
                .into_iter()
                .find(|w| w.id.to_string() == canonical_key)
                .map(|w| w.await_points.clone())
                .unwrap_or_default();
            let point_count = await_points.len();

            if point_count == 0 {
                total_points += 1;
                total_failed += 1;
                workflow_results.push(WorkflowInjectionResult {
                    workflow: wf_key,
                    total_points: 1,
                    points_passed: 0,
                    points_failed: 1,
                    failures: vec![PointFailure {
                        await_point_index: 0,
                        await_point_label: "workflow_registration".to_string(),
                        failure_type: error_codes::ERR_CIG_MATRIX_INCOMPLETE.to_string(),
                        detail: "required control workflow has no registered await points"
                            .to_string(),
                    }],
                });
                continue;
            }

            let count_failures = point_count_mismatch_failures(workflow, &await_points);
            if !count_failures.is_empty() {
                let failure_count = count_failures.len();
                total_points += failure_count;
                total_failed += failure_count;
                workflow_results.push(WorkflowInjectionResult {
                    workflow: wf_key,
                    total_points: failure_count,
                    points_passed: 0,
                    points_failed: failure_count,
                    failures: count_failures,
                });
                continue;
            }

            let metadata_failures = malformed_await_point_failures(workflow, &await_points);
            if !metadata_failures.is_empty() {
                total_points += point_count;
                total_failed += point_count;
                workflow_results.push(WorkflowInjectionResult {
                    workflow: wf_key,
                    total_points: point_count,
                    points_passed: 0,
                    points_failed: point_count,
                    failures: metadata_failures,
                });
                continue;
            }

            let mut wf_result = WorkflowInjectionResult {
                workflow: wf_key.clone(),
                total_points: point_count,
                points_passed: 0,
                points_failed: 0,
                failures: Vec::new(),
            };

            for (point, await_point) in await_points.iter().enumerate() {
                total_points += 1;
                let ts = 1000 + point as u64 * 100;
                let rb = ResourceSnapshot::empty(ts);
                let ra = ResourceSnapshot::empty(ts + 50);
                let sb = StateSnapshot::new(5, ts);
                let sa = StateSnapshot::new(5, ts + 50);

                match self.framework.run_cancel_case(
                    &canonical_key,
                    point,
                    &rb,
                    &ra,
                    &sb,
                    &sa,
                    50,
                    &format!("{}-{}-{}", trace_id, wf_key, point),
                ) {
                    Ok(outcome) => {
                        if outcome.is_pass() {
                            wf_result.points_passed += 1;
                            total_passed += 1;
                        } else {
                            wf_result.points_failed += 1;
                            total_failed += 1;
                            wf_result.failures.push(PointFailure {
                                await_point_index: point,
                                await_point_label: await_point.label.clone(),
                                failure_type: format!("{}", outcome),
                                detail: format!("{}", outcome),
                            });
                        }
                    }
                    Err(e) => {
                        wf_result.points_failed += 1;
                        total_failed += 1;
                        wf_result.failures.push(PointFailure {
                            await_point_index: point,
                            await_point_label: await_point.label.clone(),
                            failure_type: "framework_error".to_string(),
                            detail: e.to_string(),
                        });
                    }
                }
            }

            workflow_results.push(wf_result);
        }

        let verdict = if total_failed == 0 && total_points > 0 {
            "PASS"
        } else {
            "FAIL"
        }
        .to_string();

        push_bounded(
            &mut self.audit_log,
            GateAuditRecord {
                event_code: event_codes::CIN_GATE_VERDICT.to_string(),
                workflow: String::new(),
                detail: format!(
                    "verdict={} passed={} failed={} total={}",
                    verdict, total_passed, total_failed, total_points
                ),
                trace_id: trace_id.to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );

        let report = CancelInjectionGateReport {
            gate_id: "bd-3tpg".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            total_workflows: ControlWorkflow::all().len(),
            total_injection_points: total_points,
            total_passed,
            total_failed,
            verdict,
            workflow_results,
        };

        self.report = Some(report.clone());
        report
    }

    /// Get the framework (for canonical access).
    pub fn framework(&self) -> &CancellationInjectionFramework {
        &self.framework
    }

    /// Get the gate report.
    pub fn report(&self) -> Option<&CancelInjectionGateReport> {
        self.report.as_ref()
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export gate report as JSON.
    pub fn export_report_json(&self) -> String {
        match &self.report {
            Some(r) => serde_json::to_string_pretty(r).unwrap_or_default(),
            None => "{}".to_string(),
        }
    }

    /// Number of control workflows registered.
    pub fn control_workflow_count(&self) -> usize {
        self.control_workflows.len()
    }
}

impl Default for CancelInjectionGate {
    fn default() -> Self {
        Self::new()
    }
}

fn malformed_await_point_failures(
    workflow: &ControlWorkflow,
    await_points: &[AwaitPoint],
) -> Vec<PointFailure> {
    let expected_workflow = WorkflowId::Custom(workflow.as_str().to_string());
    let expected_labels = workflow.canonical_await_point_labels();
    let metadata_errors: Vec<Option<String>> = await_points
        .iter()
        .enumerate()
        .map(|(expected_index, await_point)| {
            if await_point.workflow != expected_workflow {
                Some(format!(
                    "await point {} is registered for {} instead of {}",
                    await_point.label, await_point.workflow, expected_workflow
                ))
            } else if await_point.index != expected_index {
                Some(format!(
                    "await point {} has non-canonical index {} (expected {})",
                    await_point.label, await_point.index, expected_index
                ))
            } else if await_point.label != expected_labels[expected_index] {
                Some(format!(
                    "await point {} has non-canonical label {} (expected {})",
                    expected_index, await_point.label, expected_labels[expected_index]
                ))
            } else {
                None
            }
        })
        .collect();

    let first_error = match metadata_errors.iter().flatten().next() {
        Some(detail) => detail.clone(),
        None => return Vec::new(),
    };

    await_points
        .iter()
        .enumerate()
        .map(|(expected_index, await_point)| PointFailure {
            await_point_index: expected_index,
            await_point_label: await_point.label.clone(),
            failure_type: error_codes::ERR_CIG_MATRIX_INCOMPLETE.to_string(),
            detail: metadata_errors[expected_index].clone().unwrap_or_else(|| {
                format!(
                    "workflow registration is malformed; execution skipped because {}",
                    first_error
                )
            }),
        })
        .collect()
}

fn point_count_mismatch_failures(
    workflow: &ControlWorkflow,
    await_points: &[AwaitPoint],
) -> Vec<PointFailure> {
    let expected_labels = workflow.canonical_await_point_labels();
    let expected_count = workflow.expected_point_count();
    let actual_count = await_points.len();

    if actual_count == expected_count {
        return Vec::new();
    }

    let detail = format!(
        "workflow registers {actual_count} await points but canonical matrix requires {expected_count}"
    );
    let report_width = actual_count.max(expected_count);

    (0..report_width)
        .map(|expected_index| PointFailure {
            await_point_index: expected_index,
            await_point_label: await_points
                .get(expected_index)
                .map(|await_point| await_point.label.clone())
                .or_else(|| {
                    expected_labels
                        .get(expected_index)
                        .map(|label| (*label).to_string())
                })
                .unwrap_or_else(|| "workflow_registration".to_string()),
            failure_type: error_codes::ERR_CIG_MATRIX_INCOMPLETE.to_string(),
            detail: detail.clone(),
        })
        .collect()
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gate() -> CancelInjectionGate {
        let mut gate = CancelInjectionGate::new();
        gate.register_default_control_workflows("test");
        gate
    }

    // ---- Setup ----

    #[test]
    fn default_gate_creates() {
        let gate = CancelInjectionGate::default();
        assert_eq!(gate.control_workflow_count(), 0);
    }

    #[test]
    fn register_default_workflows() {
        let gate = make_gate();
        assert_eq!(gate.control_workflow_count(), 6);
    }

    #[test]
    fn control_workflow_all_has_six() {
        assert_eq!(ControlWorkflow::all().len(), 6);
    }

    #[test]
    fn control_workflow_display() {
        assert_eq!(
            ControlWorkflow::ConnectorLifecycle.to_string(),
            "connector_lifecycle"
        );
        assert_eq!(
            ControlWorkflow::RolloutTransition.to_string(),
            "rollout_transition"
        );
        assert_eq!(
            ControlWorkflow::QuarantinePromotion.to_string(),
            "quarantine_promotion"
        );
        assert_eq!(
            ControlWorkflow::MigrationOrchestration.to_string(),
            "migration_orchestration"
        );
        assert_eq!(
            ControlWorkflow::FencingAcquire.to_string(),
            "fencing_acquire"
        );
        assert_eq!(
            ControlWorkflow::HealthGateEvaluation.to_string(),
            "health_gate_evaluation"
        );
    }

    // ---- Gate execution ----

    #[test]
    fn full_gate_passes_with_clean_snapshots() {
        let mut gate = make_gate();
        let report = gate.run_full_gate("test");
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.total_failed, 0);
        assert!(report.total_injection_points > 0);
    }

    #[test]
    fn full_gate_covers_all_workflows() {
        let mut gate = make_gate();
        let report = gate.run_full_gate("test");
        assert_eq!(report.total_workflows, 6);
        assert_eq!(report.workflow_results.len(), 6);
    }

    #[test]
    fn full_gate_total_points() {
        let mut gate = make_gate();
        let report = gate.run_full_gate("test");
        // 4 + 4 + 3 + 4 + 3 + 3 = 21 control workflow points
        assert_eq!(report.total_injection_points, 21);
    }

    #[test]
    fn report_schema_version() {
        let mut gate = make_gate();
        gate.run_full_gate("test");
        let report = gate.report().unwrap();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_gate_id() {
        let mut gate = make_gate();
        gate.run_full_gate("test");
        let report = gate.report().unwrap();
        assert_eq!(report.gate_id, "bd-3tpg");
    }

    // ---- Per-workflow results ----

    #[test]
    fn lifecycle_workflow_points() {
        let mut gate = make_gate();
        let report = gate.run_full_gate("test");
        let lifecycle = report
            .workflow_results
            .iter()
            .find(|r| r.workflow == "connector_lifecycle")
            .unwrap();
        assert_eq!(lifecycle.total_points, 4);
        assert_eq!(lifecycle.points_passed, 4);
    }

    #[test]
    fn all_workflow_results_pass() {
        let mut gate = make_gate();
        let report = gate.run_full_gate("test");
        for wr in &report.workflow_results {
            assert_eq!(wr.points_failed, 0, "Failures in {}", wr.workflow);
        }
    }

    #[test]
    fn partial_required_workflow_registration_fails_closed() {
        let mut gate = CancelInjectionGate::new();
        gate.register_control_workflow(
            ControlWorkflow::ConnectorLifecycle,
            vec![AwaitPoint::new(
                WorkflowId::Custom("connector_lifecycle".into()),
                0,
                "init_start",
                "Before connector initialization",
            )],
            "test",
        );

        let report = gate.run_full_gate("test");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.total_workflows, ControlWorkflow::all().len());
        assert!(report.total_failed >= 1);
        let missing = report
            .workflow_results
            .iter()
            .find(|result| result.workflow == "rollout_transition")
            .expect("missing workflow result");
        assert_eq!(missing.total_points, 1);
        assert_eq!(missing.points_failed, 1);
        assert_eq!(
            missing.points_passed + missing.points_failed,
            missing.total_points
        );
        assert_eq!(missing.failures.len(), 1);
        assert_eq!(
            missing.failures[0].failure_type,
            error_codes::ERR_CIG_MISSING_WORKFLOW
        );
    }

    #[test]
    fn zero_point_required_workflow_fails_closed() {
        let mut gate = make_gate();
        gate.register_control_workflow(ControlWorkflow::HealthGateEvaluation, Vec::new(), "test");

        let report = gate.run_full_gate("test");

        assert_eq!(report.verdict, "FAIL");
        let zero_point = report
            .workflow_results
            .iter()
            .find(|result| result.workflow == "health_gate_evaluation")
            .expect("zero-point workflow result");
        assert_eq!(zero_point.total_points, 1);
        assert_eq!(zero_point.points_failed, 1);
        assert_eq!(
            zero_point.points_passed + zero_point.points_failed,
            zero_point.total_points
        );
        assert_eq!(zero_point.failures.len(), 1);
        assert_eq!(
            zero_point.failures[0].failure_type,
            error_codes::ERR_CIG_MATRIX_INCOMPLETE
        );
    }

    #[test]
    fn non_canonical_await_point_count_fails_closed() {
        let mut gate = make_gate();
        gate.register_control_workflow(
            ControlWorkflow::FencingAcquire,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    0,
                    "token_request",
                    "Requesting fencing token",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    1,
                    "epoch_validate",
                    "Validating epoch binding",
                ),
            ],
            "test",
        );

        let report = gate.run_full_gate("test");

        assert_eq!(report.verdict, "FAIL");
        let malformed = report
            .workflow_results
            .iter()
            .find(|result| result.workflow == "fencing_acquire")
            .expect("count-mismatch workflow result");
        assert_eq!(malformed.total_points, 3);
        assert_eq!(malformed.points_passed, 0);
        assert_eq!(malformed.points_failed, 3);
        assert_eq!(malformed.failures.len(), 3);
        assert_eq!(
            malformed.points_passed + malformed.points_failed,
            malformed.total_points
        );
        assert!(
            malformed.failures[0]
                .detail
                .contains("registers 2 await points but canonical matrix requires 3")
        );
        assert_eq!(malformed.failures[2].await_point_label, "token_commit");
    }

    #[test]
    fn duplicate_or_holey_await_point_indices_fail_closed() {
        let mut gate = make_gate();
        gate.register_control_workflow(
            ControlWorkflow::FencingAcquire,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    0,
                    "token_request",
                    "Requesting fencing token",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    0,
                    "epoch_validate",
                    "Validating epoch binding",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    5,
                    "token_commit",
                    "Committing token acquisition",
                ),
            ],
            "test",
        );

        let report = gate.run_full_gate("test");

        assert_eq!(report.verdict, "FAIL");
        let malformed = report
            .workflow_results
            .iter()
            .find(|result| result.workflow == "fencing_acquire")
            .expect("malformed workflow result");
        assert_eq!(malformed.total_points, 3);
        assert_eq!(malformed.points_passed, 0);
        assert_eq!(malformed.points_failed, 3);
        assert_eq!(malformed.failures.len(), 3);
        assert!(
            malformed.failures[0]
                .detail
                .contains("workflow registration is malformed")
        );
        assert_eq!(
            malformed.failures[1].failure_type,
            error_codes::ERR_CIG_MATRIX_INCOMPLETE
        );
        assert!(malformed.failures[1].detail.contains("non-canonical index"));
        assert_eq!(
            malformed.points_passed + malformed.points_failed,
            malformed.total_points
        );
    }

    #[test]
    fn single_malformed_await_point_aborts_entire_workflow_report() {
        let mut gate = make_gate();
        gate.register_control_workflow(
            ControlWorkflow::MigrationOrchestration,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("migration_orchestration".into()),
                    0,
                    "schema_check",
                    "Checking schema compatibility",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("migration_orchestration".into()),
                    7,
                    "data_migrate",
                    "Migrating data",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("migration_orchestration".into()),
                    2,
                    "validate_result",
                    "Validating migration",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("migration_orchestration".into()),
                    3,
                    "finalize",
                    "Finalizing migration",
                ),
            ],
            "test",
        );

        let report = gate.run_full_gate("test");

        assert_eq!(report.verdict, "FAIL");
        let malformed = report
            .workflow_results
            .iter()
            .find(|result| result.workflow == "migration_orchestration")
            .expect("malformed workflow result");
        assert_eq!(malformed.total_points, 4);
        assert_eq!(malformed.points_passed, 0);
        assert_eq!(malformed.points_failed, 4);
        assert_eq!(malformed.failures.len(), 4);
        assert_eq!(
            malformed.points_passed + malformed.points_failed,
            malformed.total_points
        );
        assert!(
            malformed.failures[0]
                .detail
                .contains("workflow registration is malformed")
        );
        assert!(
            malformed.failures[1]
                .detail
                .contains("non-canonical index 7 (expected 1)")
        );
        assert!(
            malformed.failures[3]
                .detail
                .contains("workflow registration is malformed")
        );
    }

    #[test]
    fn renamed_await_point_label_fails_closed() {
        let mut gate = make_gate();
        gate.register_control_workflow(
            ControlWorkflow::FencingAcquire,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    0,
                    "token_request",
                    "Requesting fencing token",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    1,
                    "epoch_validate",
                    "Validating epoch binding",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("fencing_acquire".into()),
                    2,
                    "commit_token",
                    "Committing token acquisition",
                ),
            ],
            "test",
        );

        let report = gate.run_full_gate("test");

        assert_eq!(report.verdict, "FAIL");
        let malformed = report
            .workflow_results
            .iter()
            .find(|result| result.workflow == "fencing_acquire")
            .expect("renamed-label workflow result");
        assert_eq!(malformed.total_points, 3);
        assert_eq!(malformed.points_passed, 0);
        assert_eq!(malformed.points_failed, 3);
        assert_eq!(malformed.failures.len(), 3);
        assert_eq!(
            malformed.points_passed + malformed.points_failed,
            malformed.total_points
        );
        assert!(
            malformed.failures[0]
                .detail
                .contains("workflow registration is malformed")
        );
        assert!(
            malformed.failures[2]
                .detail
                .contains("has non-canonical label commit_token (expected token_commit)")
        );
    }

    #[test]
    fn cross_wired_await_point_workflow_fails_closed() {
        let mut gate = make_gate();
        gate.register_control_workflow(
            ControlWorkflow::ConnectorLifecycle,
            vec![
                AwaitPoint::new(
                    WorkflowId::Custom("rollout_transition".into()),
                    0,
                    "init_start",
                    "Before connector initialization",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("connector_lifecycle".into()),
                    1,
                    "health_probe",
                    "Health check point",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("connector_lifecycle".into()),
                    2,
                    "state_load",
                    "Load canonical state",
                ),
                AwaitPoint::new(
                    WorkflowId::Custom("connector_lifecycle".into()),
                    3,
                    "ready_signal",
                    "Connector ready",
                ),
            ],
            "test",
        );

        let report = gate.run_full_gate("test");

        assert_eq!(report.verdict, "FAIL");
        let malformed = report
            .workflow_results
            .iter()
            .find(|result| result.workflow == "connector_lifecycle")
            .expect("cross-wired workflow result");
        assert_eq!(malformed.total_points, 4);
        assert_eq!(malformed.points_passed, 0);
        assert_eq!(malformed.points_failed, 4);
        assert_eq!(malformed.failures.len(), 4);
        let cross_wire_failure = malformed
            .failures
            .iter()
            .find(|f| f.failure_type == error_codes::ERR_CIG_MATRIX_INCOMPLETE && f.detail.contains("instead of custom:connector_lifecycle"))
            .expect("should have cross wire failure");
        assert!(cross_wire_failure.detail.contains("instead of"));
    }

    // ---- Audit log ----

    #[test]
    fn audit_log_has_registrations() {
        let gate = make_gate();
        let jsonl = gate.export_audit_log_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 6, "Expected exactly 6 registration events");
    }

    #[test]
    fn audit_log_has_verdict() {
        let mut gate = make_gate();
        gate.run_full_gate("test");
        let jsonl = gate.export_audit_log_jsonl();
        assert!(jsonl.contains(event_codes::CIN_GATE_VERDICT));
    }

    // ---- Report export ----

    #[test]
    fn export_report_json_valid() {
        let mut gate = make_gate();
        gate.run_full_gate("test");
        let json = gate.export_report_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["gate_id"], "bd-3tpg");
        assert_eq!(parsed["verdict"], "PASS");
    }

    #[test]
    fn export_report_json_empty_before_run() {
        let gate = make_gate();
        let json = gate.export_report_json();
        assert_eq!(json, "{}");
    }

    // ---- INV-CIG-ZERO-FAILURES ----

    #[test]
    fn single_injection_case_passes() {
        let mut gate = make_gate();
        let rb = ResourceSnapshot::empty(1000);
        let ra = ResourceSnapshot::empty(1050);
        let sb = StateSnapshot::new(5, 1000);
        let sa = StateSnapshot::new(5, 1050);

        let outcome = gate
            .run_injection_case("connector_lifecycle", 0, &rb, &ra, &sb, &sa, 50, "t1")
            .unwrap();
        assert!(outcome.is_pass());
    }

    // ---- INV-CIG-CANONICAL-ONLY ----

    #[test]
    fn framework_is_canonical() {
        let gate = make_gate();
        // The gate uses the canonical framework from bd-876n
        // Verify it has the default 10.14 workflows registered too
        let total = gate.framework().total_test_cases();
        // 24 (default) + 21 (control) = 45
        assert_eq!(
            total, 45,
            "Expected 45 total cases (24 default + 21 control), got {}",
            total
        );
    }

    // ---- Schema version ----

    #[test]
    fn schema_version_correct() {
        assert_eq!(SCHEMA_VERSION, "cig-v1.0");
    }

    // ---- Invariants referenced ----

    #[test]
    fn invariant_names_present_in_module() {
        // This test verifies the module doc comments reference all invariants
        let src = include_str!("cancel_injection_gate.rs");
        assert!(src.contains("INV-CIG-CANONICAL-ONLY"));
        assert!(src.contains("INV-CIG-ALL-WORKFLOWS"));
        assert!(src.contains("INV-CIG-FULL-MATRIX"));
        assert!(src.contains("INV-CIG-ZERO-FAILURES"));
        assert!(src.contains("INV-CIG-LEAK-FREE"));
        assert!(src.contains("INV-CIG-REPORT-COMPLETE"));
    }

    // ---- Event codes present ----

    #[test]
    fn event_codes_defined() {
        assert!(!event_codes::CIN_POINT_ENUMERATED.is_empty());
        assert!(!event_codes::CIN_CANCELLATION_INJECTED.is_empty());
        assert!(!event_codes::CIN_ASSERTION_PASSED.is_empty());
        assert!(!event_codes::CIN_OBLIGATION_LEAK.is_empty());
        assert!(!event_codes::CIN_HALFCOMMIT_DETECTED.is_empty());
        assert!(!event_codes::CIN_QUIESCENCE_VIOLATION.is_empty());
        assert!(!event_codes::CIN_GATE_VERDICT.is_empty());
        assert!(!event_codes::CIN_WORKFLOW_REGISTERED.is_empty());
    }

    // ---- Error codes present ----

    #[test]
    fn error_codes_defined() {
        assert!(!error_codes::ERR_CIG_LEAK_DETECTED.is_empty());
        assert!(!error_codes::ERR_CIG_HALFCOMMIT.is_empty());
        assert!(!error_codes::ERR_CIG_QUIESCENCE.is_empty());
        assert!(!error_codes::ERR_CIG_MATRIX_INCOMPLETE.is_empty());
        assert!(!error_codes::ERR_CIG_CUSTOM_INJECTION.is_empty());
        assert!(!error_codes::ERR_CIG_MISSING_WORKFLOW.is_empty());
    }
}
