//! bd-3j4: End-to-end migration singularity pipeline for pilot cohorts (Section 10.12).
//!
//! Orchestrates the full migration lifecycle as a deterministic, restartable
//! state machine with stages:
//!
//! INTAKE -> ANALYSIS -> PLAN_GENERATION -> PLAN_REVIEW -> EXECUTION ->
//! VERIFICATION -> RECEIPT_ISSUANCE -> COMPLETE
//!
//! ROLLBACK is reachable from any post-INTAKE stage.
//!
//! # Capabilities
//!
//! - Deterministic, restartable state machine for migration cohorts
//! - Per-extension compatibility analysis with blocker detection
//! - Plan generation with deterministic plan IDs derived from content
//! - 95% verification gate enforcement before receipt issuance
//! - Signed migration receipts with rollback proofs
//! - Cohort-level summary reporting (throughput, success rate, rollback rate)
//! - Idempotent state transitions
//!
//! # Invariants
//!
//! - **INV-PIPE-DETERMINISTIC**: Same cohort input produces identical pipeline traces.
//! - **INV-PIPE-IDEMPOTENT**: Re-advancing from a given state yields the same result.
//! - **INV-PIPE-THRESHOLD-ENFORCED**: Verification must reach 95% pass rate to proceed.
//! - **INV-PIPE-ROLLBACK-ANY-STAGE**: Rollback is reachable from any post-INTAKE stage.
//! - **INV-PIPE-RECEIPT-SIGNED**: Every migration receipt carries a non-empty signature.
//! - **INV-PIPE-STAGE-MONOTONIC**: Stage transitions are strictly forward (except rollback).

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use super::rollout_state::RolloutPhase;
use crate::runtime::nversion_oracle::{BoundaryScope, RiskTier};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Pipeline stage entered.
    pub const PIPELINE_STAGE_ENTER: &str = "PIPE-001";
    /// Pipeline stage exited.
    pub const PIPELINE_STAGE_EXIT: &str = "PIPE-002";
    /// Analysis blocker found.
    pub const ANALYSIS_BLOCKER_FOUND: &str = "PIPE-003";
    /// Plan generated.
    pub const PLAN_GENERATED: &str = "PIPE-004";
    /// Execution step completed.
    pub const EXECUTION_STEP: &str = "PIPE-005";
    /// Execution idempotency check.
    pub const EXECUTION_IDEMPOTENT_CHECK: &str = "PIPE-006";
    /// Verification passed.
    pub const VERIFICATION_PASS: &str = "PIPE-007";
    /// Verification failed.
    pub const VERIFICATION_FAIL: &str = "PIPE-008";
    /// Receipt issued.
    pub const RECEIPT_ISSUED: &str = "PIPE-009";
    /// Receipt verified.
    pub const RECEIPT_VERIFIED: &str = "PIPE-010";
    /// Rollback initiated.
    pub const ROLLBACK_INITIATED: &str = "PIPE-011";
    /// Rollback complete.
    pub const ROLLBACK_COMPLETE: &str = "PIPE-012";
    /// Cohort summary generated.
    pub const COHORT_SUMMARY: &str = "PIPE-013";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_PIPE_INVALID_TRANSITION: &str = "ERR_PIPE_INVALID_TRANSITION";
    pub const ERR_PIPE_VERIFICATION_FAILED: &str = "ERR_PIPE_VERIFICATION_FAILED";
    pub const ERR_PIPE_IDEMPOTENCY_VIOLATED: &str = "ERR_PIPE_IDEMPOTENCY_VIOLATED";
    pub const ERR_PIPE_ROLLBACK_FAILED: &str = "ERR_PIPE_ROLLBACK_FAILED";
    pub const ERR_PIPE_THRESHOLD_NOT_MET: &str = "ERR_PIPE_THRESHOLD_NOT_MET";
    pub const ERR_PIPE_DUPLICATE_EXTENSION: &str = "ERR_PIPE_DUPLICATE_EXTENSION";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_PIPE_DETERMINISTIC: &str = "INV-PIPE-DETERMINISTIC";
    pub const INV_PIPE_IDEMPOTENT: &str = "INV-PIPE-IDEMPOTENT";
    pub const INV_PIPE_THRESHOLD_ENFORCED: &str = "INV-PIPE-THRESHOLD-ENFORCED";
    pub const INV_PIPE_ROLLBACK_ANY_STAGE: &str = "INV-PIPE-ROLLBACK-ANY-STAGE";
    pub const INV_PIPE_RECEIPT_SIGNED: &str = "INV-PIPE-RECEIPT-SIGNED";
    pub const INV_PIPE_STAGE_MONOTONIC: &str = "INV-PIPE-STAGE-MONOTONIC";
}

/// Schema version for the migration pipeline format.
pub const SCHEMA_VERSION: &str = "pipe-v1.0";

/// Verification pass-rate threshold (95%).
pub const VERIFICATION_THRESHOLD: f64 = 0.95;
const VERIFICATION_CONFIDENCE_LEVEL: f64 = 0.95;
const DEFAULT_PHASE_CONFIDENCE_BPS: u16 = 7_000;
const GUARDED_PHASE_CONFIDENCE_BPS: u16 = 5_500;
const RECEIPT_SIGNING_KEY: &[u8] = b"franken_node.connector.migration_pipeline.receipt_sign_v1";

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// PipelineStage
// ---------------------------------------------------------------------------

/// Stages of the migration singularity pipeline.
///
/// Transitions are strictly forward (monotonic) except for ROLLBACK which
/// can be entered from any post-INTAKE stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    Intake,
    Analysis,
    PlanGeneration,
    PlanReview,
    Execution,
    Verification,
    ReceiptIssuance,
    Complete,
    Rollback,
}

impl PipelineStage {
    /// The canonical string representation.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Intake => "INTAKE",
            Self::Analysis => "ANALYSIS",
            Self::PlanGeneration => "PLAN_GENERATION",
            Self::PlanReview => "PLAN_REVIEW",
            Self::Execution => "EXECUTION",
            Self::Verification => "VERIFICATION",
            Self::ReceiptIssuance => "RECEIPT_ISSUANCE",
            Self::Complete => "COMPLETE",
            Self::Rollback => "ROLLBACK",
        }
    }

    /// The next stage in the happy path, if any.
    pub fn next(&self) -> Option<PipelineStage> {
        match self {
            Self::Intake => Some(Self::Analysis),
            Self::Analysis => Some(Self::PlanGeneration),
            Self::PlanGeneration => Some(Self::PlanReview),
            Self::PlanReview => Some(Self::Execution),
            Self::Execution => Some(Self::Verification),
            Self::Verification => Some(Self::ReceiptIssuance),
            Self::ReceiptIssuance => Some(Self::Complete),
            Self::Complete => None,
            Self::Rollback => None,
        }
    }

    /// All defined stages.
    pub fn all() -> &'static [PipelineStage] {
        &[
            Self::Intake,
            Self::Analysis,
            Self::PlanGeneration,
            Self::PlanReview,
            Self::Execution,
            Self::Verification,
            Self::ReceiptIssuance,
            Self::Complete,
            Self::Rollback,
        ]
    }

    /// Whether rollback can be initiated from this stage.
    pub fn can_rollback(&self) -> bool {
        !matches!(self, Self::Intake | Self::Complete | Self::Rollback)
    }
}

// ---------------------------------------------------------------------------
// StageTransition
// ---------------------------------------------------------------------------

/// Record of a stage transition within the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageTransition {
    pub from: PipelineStage,
    pub to: PipelineStage,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// PipelineState
// ---------------------------------------------------------------------------

/// The current state of a migration pipeline instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipelineState {
    /// Current pipeline stage.
    pub current_stage: PipelineStage,
    /// Cohort identifier.
    pub cohort_id: String,
    /// Extension-level state (BTreeMap for determinism).
    pub extensions: BTreeMap<String, String>,
    /// Evidence-rich extension specifications preserved across the pipeline.
    pub extension_specs: BTreeMap<String, ExtensionSpec>,
    /// History of stage transitions.
    pub stage_history: Vec<StageTransition>,
    /// Pipeline start time (RFC 3339).
    pub started_at: String,
    /// Idempotency key for this pipeline run.
    pub idempotency_key: String,
    /// Schema version.
    pub schema_version: String,
    /// Compatibility report (populated after ANALYSIS).
    pub compatibility_report: Option<CompatibilityReport>,
    /// Migration plan (populated after PLAN_GENERATION).
    pub migration_plan: Option<MigrationPlan>,
    /// Execution traces (populated during EXECUTION).
    pub execution_traces: Vec<ExecutionTrace>,
    /// Verification report (populated after VERIFICATION).
    pub verification_report: Option<VerificationReport>,
    /// Migration receipt (populated after RECEIPT_ISSUANCE).
    pub migration_receipt: Option<MigrationReceipt>,
}

// ---------------------------------------------------------------------------
// CohortDefinition
// ---------------------------------------------------------------------------

/// Definition of a pilot cohort for migration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortDefinition {
    /// Unique cohort identifier.
    pub cohort_id: String,
    /// Extensions in the cohort.
    pub extensions: Vec<ExtensionSpec>,
    /// Selection criteria describing how the cohort was formed.
    pub selection_criteria: String,
}

// ---------------------------------------------------------------------------
// ExtensionSpec
// ---------------------------------------------------------------------------

/// Specification of an extension to be migrated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionSpec {
    /// Extension name.
    pub name: String,
    /// Source version (pre-migration).
    pub source_version: String,
    /// Target version (post-migration).
    pub target_version: String,
    /// Dependency complexity score.
    pub dependency_complexity: u32,
    /// Risk tier (1 = low, 2 = medium, 3 = high).
    pub risk_tier: u32,
    /// Evidence captured for deterministic migration analysis.
    #[serde(default)]
    pub evidence: ExtensionEvidence,
}

/// Evidence inventory for a migration extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExtensionEvidence {
    /// Observed API/runtime surface from scanner inventory.
    pub api_inventory: Vec<String>,
    /// Direct dependencies discovered for this extension.
    pub dependency_edges: Vec<String>,
    /// Runtime targets expected to run this extension.
    pub runtime_targets: Vec<String>,
    /// Compatibility bands already observed across runtimes.
    pub compatibility_bands: BTreeMap<String, String>,
    /// Known runtime divergences from lockstep verification or audits.
    pub known_divergences: Vec<KnownDivergence>,
    /// Corpus coverage in basis points [0, 10_000].
    pub corpus_coverage_bps: u16,
    /// Capability requirements needed during migration/execution.
    pub required_capabilities: Vec<String>,
    /// Lockstep observations collected for this extension.
    pub lockstep_samples: u32,
    /// Lockstep observations that diverged.
    pub lockstep_failures: u32,
    /// Project validation observations for this extension.
    pub validation_samples: u32,
    /// Project validation failures for this extension.
    pub validation_failures: u32,
    /// Explicit evidence source availability flags.
    pub evidence_sources: BTreeMap<String, bool>,
}

/// Known divergence recorded for an extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownDivergence {
    pub scope: BoundaryScope,
    pub risk_tier: RiskTier,
    pub detail: String,
}

/// Compatibility bucket derived from measured evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityBand {
    Compatible,
    Guarded,
    Blocked,
}

/// Structured degraded-mode summary when evidence is incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeReport {
    pub missing_sources: Vec<String>,
    pub confidence_penalty_bps: u16,
    pub fail_closed: bool,
    pub explanation: String,
}

/// Analysis result for a single extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityFinding {
    pub compatibility_band: CompatibilityBand,
    pub risk_score: f64,
    pub confidence_bps: u16,
    pub rollback_cost_score: u32,
    pub blockers: Vec<String>,
    pub explanation_trace: Vec<String>,
    pub degraded_mode: Option<DegradedModeReport>,
}

/// Machine-readable evidence emitted by the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineEvidenceArtifact {
    pub artifact_id: String,
    pub artifact_kind: String,
    pub digest: String,
    pub detail: String,
}

/// Rollback certificate attached to a rollout phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackCertificate {
    pub certificate_id: String,
    pub rollback_procedure_hash: String,
    pub rollback_cost_score: u32,
    pub admitted_extensions: usize,
    pub explanation: String,
}

/// Deterministic rollout phase with justification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPhasePlan {
    pub phase: RolloutPhase,
    pub extension_names: Vec<String>,
    pub rollback_certificate: RollbackCertificate,
    pub explanation_trace: Vec<String>,
}

/// Deterministic uncertainty interval for verification results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationInterval {
    pub lower_bound: f64,
    pub upper_bound: f64,
    pub confidence_level: f64,
}

/// Minimal incompatibility witness emitted on failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterexampleWitness {
    pub extension_name: String,
    pub reason_code: String,
    pub witness_kind: String,
    pub minimal_slice: Vec<String>,
    pub digest: String,
}

/// Verification details for a single extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionVerification {
    pub observed_pass_rate: f64,
    pub success_interval: CalibrationInterval,
    pub degraded_mode: Option<DegradedModeReport>,
    pub explanation_trace: Vec<String>,
    pub counterexample_witness: Option<CounterexampleWitness>,
}

// ---------------------------------------------------------------------------
// CompatibilityReport
// ---------------------------------------------------------------------------

/// Report from the ANALYSIS stage with per-extension compatibility results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityReport {
    /// Per-extension compatibility results (BTreeMap for determinism).
    pub per_extension_results: BTreeMap<String, bool>,
    /// List of blocking issues found.
    pub blockers: Vec<String>,
    /// Overall pass rate in [0.0, 1.0].
    pub overall_pass_rate: f64,
    /// Evidence-backed findings for each extension.
    pub findings: BTreeMap<String, CompatibilityFinding>,
    /// Aggregate degraded-mode report when evidence is incomplete.
    pub degraded_mode: Option<DegradedModeReport>,
    /// Machine-readable evidence artifacts from analysis.
    pub evidence_artifacts: Vec<PipelineEvidenceArtifact>,
}

// ---------------------------------------------------------------------------
// MigrationPlan
// ---------------------------------------------------------------------------

/// A migration plan generated from compatibility analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Plan ID derived deterministically from content.
    pub plan_id: String,
    /// Ordered transformation steps.
    pub steps: Vec<TransformationStep>,
    /// Aggregate risk score.
    pub risk_score: f64,
    /// Rollback specification.
    pub rollback_spec: String,
    /// Deterministic rollout phases.
    pub phases: Vec<RolloutPhasePlan>,
    /// Human/machine-readable explanation trace.
    pub explanation_trace: Vec<String>,
    /// Machine-readable evidence artifacts from planning.
    pub evidence_artifacts: Vec<PipelineEvidenceArtifact>,
}

// ---------------------------------------------------------------------------
// TransformationStep
// ---------------------------------------------------------------------------

/// A single transformation step in a migration plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransformationStep {
    /// Action type.
    pub action: TransformAction,
    /// Target resource or extension.
    pub target: String,
    /// Hash of pre-transformation state.
    pub pre_state_hash: String,
    /// Hash of post-transformation state.
    pub post_state_hash: String,
}

/// Types of transformation actions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformAction {
    ApiShim,
    PolyfillInjection,
    DependencyRewire,
}

// ---------------------------------------------------------------------------
// ExecutionTrace
// ---------------------------------------------------------------------------

/// Trace of a single extension's execution during migration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Extension being migrated.
    pub extension_name: String,
    /// State transition records.
    pub state_transitions: Vec<String>,
    /// Mutations applied.
    pub mutations: Vec<String>,
    /// Duration of execution in milliseconds.
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// VerificationReport
// ---------------------------------------------------------------------------

/// Report from the VERIFICATION stage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Overall pass rate in [0.0, 1.0].
    pub pass_rate: f64,
    /// Per-extension verification results (BTreeMap for determinism).
    pub per_extension_results: BTreeMap<String, bool>,
    /// Whether the 95% threshold was met.
    pub meets_threshold: bool,
    /// Per-extension uncertainty and witness data.
    pub extension_details: BTreeMap<String, ExtensionVerification>,
    /// Aggregate degraded-mode report when evidence is incomplete.
    pub degraded_mode: Option<DegradedModeReport>,
    /// Minimal failure witnesses.
    pub counterexample_witnesses: Vec<CounterexampleWitness>,
    /// Machine-readable evidence artifacts from verification.
    pub evidence_artifacts: Vec<PipelineEvidenceArtifact>,
}

// ---------------------------------------------------------------------------
// MigrationReceipt
// ---------------------------------------------------------------------------

/// Signed receipt issued upon successful migration.
///
/// # INV-PIPE-RECEIPT-SIGNED
/// The `signature` field must be non-empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationReceipt {
    /// SHA-256 hash of pre-migration state.
    pub pre_migration_hash: String,
    /// Fingerprint of the migration plan used.
    pub plan_fingerprint: String,
    /// SHA-256 hash of post-migration state.
    pub post_migration_hash: String,
    /// Summary of verification results.
    pub verification_summary: String,
    /// Proof that rollback is available.
    pub rollback_proof: String,
    /// Cryptographic signature.
    pub signature: String,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// Evidence artifacts bound into the receipt.
    pub evidence_artifact_ids: Vec<String>,
    /// Degraded-mode summary when receipt issuance followed incomplete evidence.
    pub degraded_mode_summary: Option<String>,
}

#[derive(Debug, Serialize)]
struct UnsignedMigrationReceipt<'a> {
    pre_migration_hash: &'a str,
    plan_fingerprint: &'a str,
    post_migration_hash: &'a str,
    verification_summary: &'a str,
    rollback_proof: &'a str,
    timestamp: &'a str,
    evidence_artifact_ids: &'a [String],
    degraded_mode_summary: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// CohortSummary
// ---------------------------------------------------------------------------

/// Summary of a cohort migration run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortSummary {
    /// Extensions processed per second.
    pub throughput: f64,
    /// Fraction of extensions that succeeded.
    pub success_rate: f64,
    /// Mean time to migrate a single extension in milliseconds.
    pub mean_time_to_migrate_ms: u64,
    /// Fraction of extensions that required rollback.
    pub rollback_rate: f64,
}

// ---------------------------------------------------------------------------
// PipelineError
// ---------------------------------------------------------------------------

/// Errors that can occur during pipeline operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipelineError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PipelineError {}

// ---------------------------------------------------------------------------
// PipelineEvent
// ---------------------------------------------------------------------------

/// Structured audit event for pipeline operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineEvent {
    pub event_code: String,
    pub cohort_id: String,
    pub stage: String,
    pub detail: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Pipeline operations
// ---------------------------------------------------------------------------

/// Create a new pipeline state from a cohort definition.
///
/// The pipeline starts in the INTAKE stage. The idempotency key is derived
/// deterministically from the cohort definition for INV-PIPE-IDEMPOTENT.
pub fn new(cohort: &CohortDefinition) -> Result<PipelineState, PipelineError> {
    // Check for duplicate extensions (ERR_PIPE_DUPLICATE_EXTENSION)
    let mut seen = std::collections::BTreeSet::new();
    let mut extension_specs = BTreeMap::new();
    for ext in &cohort.extensions {
        if !seen.insert(&ext.name) {
            return Err(PipelineError {
                code: error_codes::ERR_PIPE_DUPLICATE_EXTENSION.to_string(),
                message: format!("Duplicate extension: {}", ext.name),
            });
        }
        extension_specs.insert(ext.name.clone(), ext.clone());
    }

    let mut extensions = BTreeMap::new();
    for ext in &cohort.extensions {
        extensions.insert(ext.name.clone(), ext.source_version.clone());
    }

    let idempotency_key = calculate_idempotency_key(cohort);

    Ok(PipelineState {
        current_stage: PipelineStage::Intake,
        cohort_id: cohort.cohort_id.clone(),
        extensions,
        extension_specs,
        stage_history: Vec::new(),
        started_at: "2026-02-21T00:00:00Z".to_string(),
        idempotency_key,
        schema_version: SCHEMA_VERSION.to_string(),
        compatibility_report: None,
        migration_plan: None,
        execution_traces: Vec::new(),
        verification_report: None,
        migration_receipt: None,
    })
}

/// Advance the pipeline to the next stage.
///
/// # INV-PIPE-STAGE-MONOTONIC
/// Stage transitions are strictly forward.
///
/// # INV-PIPE-THRESHOLD-ENFORCED
/// Advancement past VERIFICATION requires 95% pass rate.
pub fn advance(mut state: PipelineState) -> Result<PipelineState, PipelineError> {
    let current = state.current_stage;
    let next = current.next().ok_or_else(|| PipelineError {
        code: error_codes::ERR_PIPE_INVALID_TRANSITION.to_string(),
        message: format!("Cannot advance from terminal stage {}", current.label()),
    })?;

    // Stage-specific processing
    match current {
        PipelineStage::Intake => {
            // Transition to Analysis -- no preconditions beyond having extensions
        }
        PipelineStage::Analysis => {
            // Generate compatibility report
            let report = run_analysis(&state);
            state.compatibility_report = Some(report);
        }
        PipelineStage::PlanGeneration => {
            // Generate migration plan from compatibility report
            let report = state
                .compatibility_report
                .as_ref()
                .ok_or_else(|| PipelineError {
                    code: error_codes::ERR_PIPE_INVALID_TRANSITION.to_string(),
                    message: "Cannot generate plan without compatibility report".to_string(),
                })?;
            let plan = generate_plan(&state, report);
            state.migration_plan = Some(plan);
        }
        PipelineStage::PlanReview => {
            // Plan review is a gate -- plan must exist
            if state.migration_plan.is_none() {
                return Err(PipelineError {
                    code: error_codes::ERR_PIPE_INVALID_TRANSITION.to_string(),
                    message: "Cannot review without a migration plan".to_string(),
                });
            }
        }
        PipelineStage::Execution => {
            // Execute the migration plan
            let traces = run_execution(&state);
            state.execution_traces = traces;
        }
        PipelineStage::Verification => {
            // Run verification and enforce 95% threshold
            let report = run_verification(&state);
            if !report.meets_threshold {
                state.verification_report = Some(report.clone());
                return Err(PipelineError {
                    code: error_codes::ERR_PIPE_THRESHOLD_NOT_MET.to_string(),
                    message: format!(
                        "Verification pass rate {:.2}% below threshold {:.0}%",
                        report.pass_rate * 100.0,
                        VERIFICATION_THRESHOLD * 100.0,
                    ),
                });
            }
            state.verification_report = Some(report);
        }
        PipelineStage::ReceiptIssuance => {
            // Issue signed receipt
            let receipt = issue_receipt(&state);
            state.migration_receipt = Some(receipt);
        }
        PipelineStage::Complete | PipelineStage::Rollback => {
            // Terminal stages handled above via next() returning None
        }
    }

    // Record transition
    state.stage_history.push(StageTransition {
        from: current,
        to: next,
        timestamp: "2026-02-21T00:00:00Z".to_string(),
    });
    state.current_stage = next;

    Ok(state)
}

/// Initiate rollback from any post-INTAKE stage.
///
/// # INV-PIPE-ROLLBACK-ANY-STAGE
/// Rollback is reachable from any stage after INTAKE (but not from
/// COMPLETE or ROLLBACK itself).
pub fn rollback(mut state: PipelineState) -> Result<PipelineState, PipelineError> {
    if !state.current_stage.can_rollback() {
        return Err(PipelineError {
            code: error_codes::ERR_PIPE_ROLLBACK_FAILED.to_string(),
            message: format!("Cannot rollback from stage {}", state.current_stage.label()),
        });
    }

    let from = state.current_stage;
    state.stage_history.push(StageTransition {
        from,
        to: PipelineStage::Rollback,
        timestamp: "2026-02-21T00:00:00Z".to_string(),
    });
    state.current_stage = PipelineStage::Rollback;

    Ok(state)
}

/// Check that two pipeline states are idempotent (same stage, same cohort,
/// same idempotency key).
///
/// # INV-PIPE-IDEMPOTENT
pub fn is_idempotent(a: &PipelineState, b: &PipelineState) -> bool {
    a.current_stage == b.current_stage
        && a.cohort_id == b.cohort_id
        && crate::security::constant_time::ct_eq(&a.idempotency_key, &b.idempotency_key)
        && a.extensions == b.extensions
        && a.extension_specs == b.extension_specs
        && a.schema_version == b.schema_version
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic idempotency key from a cohort definition.
fn calculate_idempotency_key(cohort: &CohortDefinition) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"migration_idempotency_v1:");
    hasher.update((cohort.cohort_id.len() as u64).to_le_bytes());
    hasher.update(cohort.cohort_id.as_bytes());
    hasher.update((cohort.extensions.len() as u64).to_le_bytes());
    for ext in &cohort.extensions {
        hasher.update((ext.name.len() as u64).to_le_bytes());
        hasher.update(ext.name.as_bytes());
        hasher.update((ext.source_version.len() as u64).to_le_bytes());
        hasher.update(ext.source_version.as_bytes());
        hasher.update((ext.target_version.len() as u64).to_le_bytes());
        hasher.update(ext.target_version.as_bytes());
    }
    hex::encode(hasher.finalize())
}

impl CompatibilityBand {
    fn label(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Guarded => "guarded",
            Self::Blocked => "blocked",
        }
    }
}

fn stable_digest(prefix: &str, parts: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn unit_ratio(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        f64::from(numerator) / f64::from(denominator)
    }
}

fn ratio_bps(numerator: usize, denominator: usize) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let scaled = numerator.saturating_mul(10_000) / denominator;
    u16::try_from(scaled).unwrap_or(10_000)
}

fn clamp_bps(value: i32) -> u16 {
    let clamped = value.clamp(0, 10_000);
    u16::try_from(clamped).unwrap_or(0)
}

fn clamp_unit(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

fn weighted_confidence_bps(components: &[(u16, u16)]) -> u16 {
    let total_weight: u32 = components
        .iter()
        .map(|(_, weight)| u32::from(*weight))
        .sum();
    if total_weight == 0 {
        return 0;
    }

    let weighted_sum: u32 = components
        .iter()
        .map(|(value, weight)| u32::from(*value) * u32::from(*weight))
        .sum();

    u16::try_from(weighted_sum / total_weight).unwrap_or(10_000)
}

fn sample_confidence_bps(total_samples: u32) -> u16 {
    let scaled = total_samples.saturating_mul(250).min(10_000);
    u16::try_from(scaled).unwrap_or(10_000)
}

fn collect_missing_sources(spec: &ExtensionSpec) -> Vec<String> {
    let mut missing = BTreeSet::new();
    if spec.evidence.api_inventory.is_empty() {
        missing.insert("scanner_api_inventory".to_string());
    }
    if spec.evidence.runtime_targets.is_empty() {
        missing.insert("runtime_targets".to_string());
    }
    if spec.evidence.corpus_coverage_bps == 0 {
        missing.insert("corpus_coverage".to_string());
    }
    if spec.evidence.lockstep_samples == 0 {
        missing.insert("lockstep_observations".to_string());
    }
    if spec.evidence.validation_samples == 0 {
        missing.insert("project_validation".to_string());
    }
    for (source, available) in &spec.evidence.evidence_sources {
        if !available {
            missing.insert(source.clone());
        }
    }
    missing.into_iter().collect()
}

fn degraded_report(
    context: &str,
    missing_sources: &[String],
    penalty_bps: u16,
    fail_closed: bool,
) -> Option<DegradedModeReport> {
    if missing_sources.is_empty() {
        return None;
    }

    Some(DegradedModeReport {
        missing_sources: missing_sources.to_vec(),
        confidence_penalty_bps: penalty_bps,
        fail_closed,
        explanation: format!(
            "{context}: missing evidence sources [{}]",
            missing_sources.join(", ")
        ),
    })
}

fn merge_degraded_reports<'a>(
    reports: impl Iterator<Item = &'a DegradedModeReport>,
    context: &str,
) -> Option<DegradedModeReport> {
    let mut missing = BTreeSet::new();
    let mut penalty_bps = 0_u16;
    let mut fail_closed = false;

    for report in reports {
        penalty_bps = penalty_bps.max(report.confidence_penalty_bps);
        fail_closed |= report.fail_closed;
        for source in &report.missing_sources {
            missing.insert(source.clone());
        }
    }

    if missing.is_empty() {
        return None;
    }

    let missing_sources: Vec<String> = missing.into_iter().collect();
    Some(DegradedModeReport {
        missing_sources: missing_sources.clone(),
        confidence_penalty_bps: penalty_bps,
        fail_closed,
        explanation: format!("{context}: {}", missing_sources.join(", ")),
    })
}

fn impactful_api_weight(api: &str) -> f64 {
    match api {
        "child_process" | "fs" | "worker_threads" => 0.08,
        "crypto" | "net" | "tls" => 0.06,
        _ => 0.02,
    }
}

fn capability_weight(capability: &str) -> f64 {
    match capability {
        "native-ffi" | "raw-net" | "kernel-fs" => 0.18,
        "dynamic-loader" | "subprocess" => 0.08,
        _ => 0.03,
    }
}

fn divergence_weight(divergence: &KnownDivergence) -> f64 {
    let base = match divergence.risk_tier {
        RiskTier::Critical => 0.30,
        RiskTier::High => 0.22,
        RiskTier::Medium => 0.12,
        RiskTier::Low => 0.06,
        RiskTier::Info => 0.02,
    };
    base + match divergence.scope {
        BoundaryScope::Security | BoundaryScope::Concurrency => 0.02,
        BoundaryScope::IO => 0.01,
        BoundaryScope::TypeSystem | BoundaryScope::Memory => 0.0,
    }
}

fn choose_action(spec: &ExtensionSpec, finding: &CompatibilityFinding) -> TransformAction {
    let has_dependency_or_security_pressure = spec.evidence.known_divergences.iter().any(|div| {
        matches!(
            div.scope,
            BoundaryScope::Security | BoundaryScope::Concurrency | BoundaryScope::IO
        )
    });

    if has_dependency_or_security_pressure {
        TransformAction::DependencyRewire
    } else if !spec.evidence.required_capabilities.is_empty()
        || finding.compatibility_band == CompatibilityBand::Guarded
    {
        TransformAction::PolyfillInjection
    } else {
        TransformAction::ApiShim
    }
}

fn internal_dependency_blocker(
    spec: &ExtensionSpec,
    findings: &BTreeMap<String, CompatibilityFinding>,
) -> Option<String> {
    spec.evidence
        .dependency_edges
        .iter()
        .find_map(|dependency| {
            findings.get(dependency).and_then(|finding| {
                if finding.compatibility_band == CompatibilityBand::Blocked {
                    Some(dependency.clone())
                } else {
                    None
                }
            })
        })
}

fn build_rollback_certificate(
    phase: RolloutPhase,
    extension_names: &[String],
    rollback_cost_score: u32,
) -> RollbackCertificate {
    let mut digest_inputs = vec![phase.as_str().to_string(), rollback_cost_score.to_string()];
    digest_inputs.extend(extension_names.iter().cloned());
    let digest = stable_digest("rollback_certificate_v1", &digest_inputs);

    RollbackCertificate {
        certificate_id: format!("rollback-{}-{}", phase.as_str(), &digest[..12]),
        rollback_procedure_hash: digest,
        rollback_cost_score,
        admitted_extensions: extension_names.len(),
        explanation: format!(
            "{} phase rollback cost={} extensions={}",
            phase.as_str(),
            rollback_cost_score,
            extension_names.len()
        ),
    }
}

fn build_counterexample(
    extension_name: &str,
    reason_code: &str,
    witness_kind: &str,
    minimal_slice: Vec<String>,
) -> CounterexampleWitness {
    let mut digest_inputs = vec![
        extension_name.to_string(),
        reason_code.to_string(),
        witness_kind.to_string(),
    ];
    digest_inputs.extend(minimal_slice.iter().cloned());
    let digest = stable_digest("counterexample_witness_v1", &digest_inputs);

    CounterexampleWitness {
        extension_name: extension_name.to_string(),
        reason_code: reason_code.to_string(),
        witness_kind: witness_kind.to_string(),
        minimal_slice,
        digest,
    }
}

fn wilson_interval(successes: u32, total: u32, confidence_level: f64) -> CalibrationInterval {
    if total == 0 || successes > total {
        return CalibrationInterval {
            lower_bound: 0.0,
            upper_bound: if total == 0 { 1.0 } else { 0.0 },
            confidence_level,
        };
    }

    let n = f64::from(total);
    let p_hat = f64::from(successes) / n;
    let z = 1.96_f64;
    let z2_over_n = (z * z) / n;
    let denominator = 1.0 + z2_over_n;
    let center = (p_hat + (z * z) / (2.0 * n)) / denominator;
    let radius =
        (z / denominator) * ((p_hat * (1.0 - p_hat) / n) + ((z * z) / (4.0 * n * n))).sqrt();

    // Defense in depth: clamp NaN/Inf to safe defaults.
    if !center.is_finite() || !radius.is_finite() {
        return CalibrationInterval {
            lower_bound: 0.0,
            upper_bound: 1.0,
            confidence_level,
        };
    }

    CalibrationInterval {
        lower_bound: clamp_unit(center - radius),
        upper_bound: clamp_unit(center + radius),
        confidence_level,
    }
}

/// Run compatibility analysis on the extensions.
fn run_analysis(state: &PipelineState) -> CompatibilityReport {
    let mut per_extension_results = BTreeMap::new();
    let mut blockers = Vec::new();
    let mut findings = BTreeMap::new();
    let mut evidence_artifacts = Vec::new();

    for (name, spec) in &state.extension_specs {
        let missing_sources = collect_missing_sources(spec);
        let penalty_bps = clamp_bps(i32::try_from(missing_sources.len()).unwrap_or(i32::MAX) * 900);
        let fail_closed =
            spec.evidence.lockstep_samples == 0 || spec.evidence.validation_samples == 0;
        let degraded_mode = degraded_report(
            &format!("analysis:{name}"),
            &missing_sources,
            penalty_bps,
            fail_closed,
        );

        let explicit_sources_total = spec.evidence.evidence_sources.len();
        let explicit_sources_available = spec
            .evidence
            .evidence_sources
            .values()
            .filter(|value| **value)
            .count();
        let source_availability_bps = if explicit_sources_total == 0 {
            ratio_bps(5_usize.saturating_sub(missing_sources.len()), 5)
        } else {
            ratio_bps(explicit_sources_available, explicit_sources_total)
        };

        let dependency_pressure = f64::from(spec.dependency_complexity.min(12)) * 0.035;
        let api_pressure = spec
            .evidence
            .api_inventory
            .iter()
            .map(|api| impactful_api_weight(api))
            .sum::<f64>()
            .min(0.25);
        let capability_pressure = spec
            .evidence
            .required_capabilities
            .iter()
            .map(|capability| capability_weight(capability))
            .sum::<f64>()
            .min(0.30);
        let divergence_pressure = spec
            .evidence
            .known_divergences
            .iter()
            .map(divergence_weight)
            .sum::<f64>()
            .min(0.40);
        let coverage_penalty = if spec.evidence.corpus_coverage_bps >= 8_000 {
            0.0
        } else {
            f64::from(8_000_u16.saturating_sub(spec.evidence.corpus_coverage_bps)) / 10_000.0 * 0.25
        };
        let validation_failure_rate = unit_ratio(
            spec.evidence.validation_failures,
            spec.evidence.validation_samples.max(1),
        );
        let lockstep_failure_rate = unit_ratio(
            spec.evidence.lockstep_failures,
            spec.evidence.lockstep_samples.max(1),
        );
        let sample_penalty = validation_failure_rate * 0.35 + lockstep_failure_rate * 0.45;
        let degraded_penalty = f64::from(penalty_bps) / 10_000.0;
        let base_risk = f64::from(spec.risk_tier.min(4)) * 0.12;
        let risk_score = clamp_unit(
            base_risk
                + dependency_pressure
                + api_pressure
                + capability_pressure
                + divergence_pressure
                + coverage_penalty
                + sample_penalty
                + degraded_penalty,
        );

        let confidence_components = [
            (source_availability_bps, 35),
            (spec.evidence.corpus_coverage_bps, 30),
            (
                sample_confidence_bps(
                    spec.evidence
                        .validation_samples
                        .saturating_add(spec.evidence.lockstep_samples),
                ),
                20,
            ),
            (
                clamp_bps(((1.0 - risk_score) * 10_000.0).round() as i32),
                15,
            ),
        ];
        let confidence_bps = clamp_bps(
            i32::from(weighted_confidence_bps(&confidence_components)) - i32::from(penalty_bps),
        );

        let has_blocking_divergence =
            spec.evidence.known_divergences.iter().any(|divergence| {
                matches!(divergence.risk_tier, RiskTier::High | RiskTier::Critical)
            });

        let compatibility_band =
            if has_blocking_divergence
                || risk_score >= 0.78
                || confidence_bps < 4_500
                || spec.evidence.corpus_coverage_bps < 4_500
                || source_availability_bps < 5_000
            {
                CompatibilityBand::Blocked
            } else if risk_score >= 0.45
                || confidence_bps < DEFAULT_PHASE_CONFIDENCE_BPS
                || !missing_sources.is_empty()
                || spec.evidence.known_divergences.iter().any(|divergence| {
                    matches!(divergence.risk_tier, RiskTier::Medium | RiskTier::Low)
                })
            {
                CompatibilityBand::Guarded
            } else {
                CompatibilityBand::Compatible
            };

        let rollback_cost_score = spec
            .dependency_complexity
            .saturating_mul(10)
            .saturating_add(
                u32::try_from(spec.evidence.required_capabilities.len())
                    .unwrap_or(u32::MAX)
                    .saturating_mul(15),
            )
            .saturating_add(
                u32::try_from(spec.evidence.known_divergences.len())
                    .unwrap_or(u32::MAX)
                    .saturating_mul(20),
            )
            .saturating_add(
                u32::try_from(spec.evidence.api_inventory.len())
                    .unwrap_or(u32::MAX)
                    .saturating_mul(4),
            );

        let mut explanation_trace = vec![
            format!(
                "risk_score={risk_score:.3} confidence_bps={} coverage_bps={}",
                confidence_bps, spec.evidence.corpus_coverage_bps
            ),
            format!(
                "lockstep_samples={} lockstep_failures={} validation_samples={} validation_failures={}",
                spec.evidence.lockstep_samples,
                spec.evidence.lockstep_failures,
                spec.evidence.validation_samples,
                spec.evidence.validation_failures
            ),
        ];
        if !spec.evidence.api_inventory.is_empty() {
            explanation_trace.push(format!(
                "api_inventory={}",
                spec.evidence.api_inventory.join(", ")
            ));
        }
        if !spec.evidence.required_capabilities.is_empty() {
            explanation_trace.push(format!(
                "required_capabilities={}",
                spec.evidence.required_capabilities.join(", ")
            ));
        }
        for (i, divergence) in spec.evidence.known_divergences.iter().enumerate() {
            explanation_trace.push(format!(
                "known_divergence[{}]:scope={},risk_tier={},detail_len={},detail={}",
                i,
                divergence.scope,
                divergence.risk_tier,
                divergence.detail.len(),
                divergence.detail,
            ));
        }

        let mut extension_blockers = Vec::new();
        if has_blocking_divergence {
            extension_blockers.push(format!("{name} has high-risk lockstep divergence evidence"));
        }
        if spec.evidence.corpus_coverage_bps < 4_500 {
            extension_blockers.push(format!(
                "{name} coverage below rollout floor ({})",
                spec.evidence.corpus_coverage_bps
            ));
        }
        if fail_closed {
            extension_blockers.push(format!(
                "{name} missing critical evidence for fail-closed analysis"
            ));
        }
        if compatibility_band == CompatibilityBand::Guarded && extension_blockers.is_empty() {
            extension_blockers.push(format!(
                "{name} requires guarded rollout due to confidence {}bps",
                confidence_bps
            ));
        }

        let pass = compatibility_band != CompatibilityBand::Blocked;
        per_extension_results.insert(name.clone(), pass);
        if !pass {
            blockers.extend(extension_blockers.iter().cloned());
        }

        let artifact_detail = format!(
            "{}:{}:{}:{}:{}",
            name,
            compatibility_band.label(),
            confidence_bps,
            spec.evidence.corpus_coverage_bps,
            rollback_cost_score
        );
        let mut artifact_inputs = vec![artifact_detail.clone()];
        artifact_inputs.extend(explanation_trace.iter().cloned());
        evidence_artifacts.push(PipelineEvidenceArtifact {
            artifact_id: format!("analysis-{name}"),
            artifact_kind: "analysis".to_string(),
            digest: stable_digest("analysis_artifact_v1", &artifact_inputs),
            detail: artifact_detail,
        });

        findings.insert(
            name.clone(),
            CompatibilityFinding {
                compatibility_band,
                risk_score,
                confidence_bps,
                rollback_cost_score,
                blockers: extension_blockers,
                explanation_trace,
                degraded_mode,
            },
        );
    }

    let total = per_extension_results.len() as f64;
    let passing = per_extension_results.values().filter(|v| **v).count() as f64;
    let overall_pass_rate = if total > 0.0 { passing / total } else { 0.0 };
    let degraded_mode = merge_degraded_reports(
        findings
            .values()
            .filter_map(|finding| finding.degraded_mode.as_ref()),
        "analysis aggregate degraded-mode",
    );

    CompatibilityReport {
        per_extension_results,
        blockers,
        overall_pass_rate,
        findings,
        degraded_mode,
        evidence_artifacts,
    }
}

/// Generate a migration plan from compatibility results.
fn generate_plan(state: &PipelineState, report: &CompatibilityReport) -> MigrationPlan {
    let mut steps = Vec::new();
    for (name, spec) in &state.extension_specs {
        let Some(finding) = report.findings.get(name) else {
            continue;
        };

        let pre_hash = stable_digest(
            "migration_pre_hash_v2",
            &[
                name.clone(),
                spec.source_version.clone(),
                spec.target_version.clone(),
                spec.risk_tier.to_string(),
                spec.dependency_complexity.to_string(),
            ],
        );
        let post_hash = stable_digest(
            "migration_post_hash_v2",
            &[
                pre_hash.clone(),
                finding.compatibility_band.label().to_string(),
                finding.confidence_bps.to_string(),
            ],
        );
        steps.push(TransformationStep {
            action: choose_action(spec, finding),
            target: name.clone(),
            pre_state_hash: pre_hash,
            post_state_hash: post_hash,
        });
    }

    let risk_score = if report.findings.is_empty() {
        0.0
    } else {
        report
            .findings
            .values()
            .map(|finding| finding.risk_score)
            .sum::<f64>()
            / report.findings.len() as f64
    };

    let mut phases = Vec::new();
    for phase in [
        RolloutPhase::Shadow,
        RolloutPhase::Canary,
        RolloutPhase::Ramp,
        RolloutPhase::Default,
    ] {
        let mut extension_names = Vec::new();
        let mut explanation_trace = vec![format!(
            "{} phase evaluates measured risk, dependency constraints, and rollback cost",
            phase.as_str()
        )];

        for (name, spec) in &state.extension_specs {
            let Some(finding) = report.findings.get(name) else {
                continue;
            };
            let dependency_blocker = internal_dependency_blocker(spec, &report.findings);
            let admit = match phase {
                RolloutPhase::Shadow => true,
                RolloutPhase::Canary => {
                    finding.compatibility_band != CompatibilityBand::Blocked
                        && dependency_blocker.is_none()
                        && finding.confidence_bps >= GUARDED_PHASE_CONFIDENCE_BPS
                }
                RolloutPhase::Ramp => {
                    finding.compatibility_band != CompatibilityBand::Blocked
                        && dependency_blocker.is_none()
                        && finding.rollback_cost_score <= 120
                }
                RolloutPhase::Default => {
                    finding.compatibility_band == CompatibilityBand::Compatible
                        && dependency_blocker.is_none()
                        && finding.confidence_bps >= DEFAULT_PHASE_CONFIDENCE_BPS
                }
            };

            if admit {
                extension_names.push(name.clone());
            } else if let Some(blocker) = dependency_blocker {
                explanation_trace.push(format!(
                    "{name} withheld from {} due to blocked dependency {blocker}",
                    phase.as_str()
                ));
            }
        }

        extension_names.sort();
        let rollback_cost_score = extension_names
            .iter()
            .filter_map(|name| report.findings.get(name))
            .fold(0_u32, |acc, finding| {
                acc.saturating_add(finding.rollback_cost_score)
            });

        explanation_trace.push(format!(
            "{} admits {} extension(s) with rollback_cost={}",
            phase.as_str(),
            extension_names.len(),
            rollback_cost_score
        ));

        let rollback_certificate =
            build_rollback_certificate(phase, &extension_names, rollback_cost_score);

        phases.push(RolloutPhasePlan {
            phase,
            extension_names,
            rollback_certificate,
            explanation_trace,
        });
    }

    let mut explanation_trace = vec![
        "rollout order is shadow -> canary -> ramp -> default".to_string(),
        format!(
            "plan risk_score={risk_score:.3} blocker_count={}",
            report.blockers.len()
        ),
    ];
    explanation_trace.extend(phases.iter().map(|phase| {
        format!(
            "{} certificate={} admitted={}",
            phase.phase.as_str(),
            phase.rollback_certificate.certificate_id,
            phase.extension_names.len()
        )
    }));

    let mut evidence_artifacts = Vec::new();
    for phase in &phases {
        let artifact_inputs = vec![
            phase.phase.as_str().to_string(),
            phase.rollback_certificate.certificate_id.clone(),
            phase.extension_names.join(","),
        ];
        evidence_artifacts.push(PipelineEvidenceArtifact {
            artifact_id: format!("plan-{}", phase.phase.as_str()),
            artifact_kind: "rollout_plan".to_string(),
            digest: stable_digest("migration_plan_phase_v1", &artifact_inputs),
            detail: format!(
                "{} phase extensions={}",
                phase.phase.as_str(),
                phase.extension_names.join(",")
            ),
        });
    }

    let mut plan_id_inputs = steps
        .iter()
        .map(|step| {
            format!(
                "{}:{}:{}:{}",
                step.target,
                step.pre_state_hash,
                step.post_state_hash,
                match step.action {
                    TransformAction::ApiShim => "api_shim",
                    TransformAction::PolyfillInjection => "polyfill_injection",
                    TransformAction::DependencyRewire => "dependency_rewire",
                }
            )
        })
        .collect::<Vec<_>>();
    plan_id_inputs.extend(
        phases
            .iter()
            .map(|phase| phase.rollback_certificate.certificate_id.clone()),
    );
    let plan_digest = stable_digest("migration_plan_id_v2", &plan_id_inputs);
    let plan_id = format!("plan-{}", &plan_digest[..16]);

    MigrationPlan {
        plan_id,
        steps,
        risk_score,
        rollback_spec: "rollback_all_steps_in_reverse_with_phase_certificates".to_string(),
        phases,
        explanation_trace,
        evidence_artifacts,
    }
}

/// Execute migration steps and produce traces.
fn run_execution(state: &PipelineState) -> Vec<ExecutionTrace> {
    let mut traces = Vec::new();
    for (name, spec) in &state.extension_specs {
        let planned_action = state
            .migration_plan
            .as_ref()
            .and_then(|plan| plan.steps.iter().find(|step| step.target == *name))
            .map(|step| match step.action {
                TransformAction::ApiShim => "api_shim".to_string(),
                TransformAction::PolyfillInjection => "polyfill_injection".to_string(),
                TransformAction::DependencyRewire => "dependency_rewire".to_string(),
            })
            .unwrap_or_else(|| "api_shim".to_string());

        let enrolled_phases = state
            .migration_plan
            .as_ref()
            .map(|plan| {
                plan.phases
                    .iter()
                    .filter(|phase| phase.extension_names.contains(name))
                    .map(|phase| phase.phase.as_str().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["shadow".to_string()]);

        let mut state_transitions = vec![format!("{name}:pre_migration")];
        state_transitions.extend(
            enrolled_phases
                .iter()
                .map(|phase| format!("{name}:phase:{phase}")),
        );
        state_transitions.push(format!("{name}:post_migration"));

        traces.push(ExecutionTrace {
            extension_name: name.clone(),
            state_transitions,
            mutations: vec![format!("{name}:{planned_action}_applied")],
            duration_ms: 50_u64
                .saturating_add(u64::from(spec.dependency_complexity).saturating_mul(15))
                .saturating_add(
                    u64::try_from(enrolled_phases.len())
                        .unwrap_or(u64::MAX)
                        .saturating_mul(20),
                ),
        });
    }
    traces
}

/// Run verification and produce a report.
fn run_verification(state: &PipelineState) -> VerificationReport {
    let mut per_extension_results = BTreeMap::new();
    let mut extension_details = BTreeMap::new();
    let mut counterexample_witnesses = Vec::new();
    let mut evidence_artifacts = Vec::new();

    let findings = state
        .compatibility_report
        .as_ref()
        .map(|report| &report.findings)
        .cloned()
        .unwrap_or_default();

    for (name, spec) in &state.extension_specs {
        let finding = findings.get(name).cloned().unwrap_or(CompatibilityFinding {
            compatibility_band: CompatibilityBand::Blocked,
            risk_score: 1.0,
            confidence_bps: 0,
            rollback_cost_score: 0,
            blockers: vec![format!("{name} missing analysis finding")],
            explanation_trace: vec!["verification entered without analysis finding".to_string()],
            degraded_mode: degraded_report(
                &format!("verification:{name}"),
                &["analysis_finding".to_string()],
                4_000,
                true,
            ),
        });

        let total_samples = spec
            .evidence
            .validation_samples
            .saturating_add(spec.evidence.lockstep_samples);
        let total_failures = spec
            .evidence
            .validation_failures
            .saturating_add(spec.evidence.lockstep_failures);
        let successes = total_samples.saturating_sub(total_failures);
        let observed_pass_rate = if total_samples == 0 {
            0.0
        } else {
            f64::from(successes) / f64::from(total_samples)
        };
        let success_interval =
            wilson_interval(successes, total_samples, VERIFICATION_CONFIDENCE_LEVEL);

        let missing_sources = collect_missing_sources(spec);
        let degraded_penalty_bps =
            clamp_bps(i32::try_from(missing_sources.len()).unwrap_or(i32::MAX) * 900);
        let degraded_mode = degraded_report(
            &format!("verification:{name}"),
            &missing_sources,
            degraded_penalty_bps,
            spec.evidence.lockstep_samples == 0 || spec.evidence.validation_samples == 0,
        );

        let fail_closed_due_to_degraded = degraded_mode.as_ref().is_some_and(|report| {
            report.fail_closed && finding.confidence_bps < DEFAULT_PHASE_CONFIDENCE_BPS
        });
        let pass = finding.compatibility_band != CompatibilityBand::Blocked
            && total_failures == 0
            && observed_pass_rate >= VERIFICATION_THRESHOLD
            && !fail_closed_due_to_degraded
            && finding.confidence_bps >= GUARDED_PHASE_CONFIDENCE_BPS;
        per_extension_results.insert(name.clone(), pass);

        let counterexample_witness = if pass {
            None
        } else {
            let (reason_code, witness_kind, minimal_slice) =
                if finding.compatibility_band == CompatibilityBand::Blocked {
                    (
                        "ERR_PIPE_ANALYSIS_BLOCKED",
                        "analysis_failure",
                        if !finding.blockers.is_empty() {
                            vec![finding.blockers[0].clone()]
                        } else {
                            vec!["analysis classified extension as blocked".to_string()]
                        },
                    )
                } else if fail_closed_due_to_degraded {
                    (
                        "ERR_PIPE_DEGRADED_MODE",
                        "missing_evidence",
                        missing_sources.iter().take(1).cloned().collect(),
                    )
                } else if total_failures > 0 {
                    (
                        "ERR_PIPE_VALIDATION_FAILURE",
                        "validation_counterexample",
                        spec.evidence
                            .known_divergences
                            .iter()
                            .map(|divergence| divergence.detail.clone())
                            .take(1)
                            .collect::<Vec<_>>(),
                    )
                } else {
                    (
                        "ERR_PIPE_THRESHOLD_NOT_MET",
                        "insufficient_confidence",
                        vec![format!(
                            "observed_pass_rate={observed_pass_rate:.3}, confidence_bps={}",
                            finding.confidence_bps
                        )],
                    )
                };

            Some(build_counterexample(
                name,
                reason_code,
                witness_kind,
                if minimal_slice.is_empty() {
                    vec!["no-minimal-slice-available".to_string()]
                } else {
                    minimal_slice
                },
            ))
        };

        if let Some(witness) = counterexample_witness.clone() {
            counterexample_witnesses.push(witness);
        }

        let mut explanation_trace = finding.explanation_trace.clone();
        explanation_trace.push(format!(
            "observed_pass_rate={observed_pass_rate:.3} interval=[{:.3}, {:.3}] samples={} failures={}",
            success_interval.lower_bound,
            success_interval.upper_bound,
            total_samples,
            total_failures
        ));
        if let Some(report) = &degraded_mode {
            explanation_trace.push(report.explanation.clone());
        }

        evidence_artifacts.push(PipelineEvidenceArtifact {
            artifact_id: format!("verification-{name}"),
            artifact_kind: "verification".to_string(),
            digest: stable_digest(
                "verification_artifact_v1",
                &[
                    name.clone(),
                    format!("{observed_pass_rate:.5}"),
                    format!("{:.5}", success_interval.lower_bound),
                    format!("{:.5}", success_interval.upper_bound),
                ],
            ),
            detail: format!(
                "{} pass={} samples={} failures={}",
                name, pass, total_samples, total_failures
            ),
        });

        extension_details.insert(
            name.clone(),
            ExtensionVerification {
                observed_pass_rate,
                success_interval,
                degraded_mode,
                explanation_trace,
                counterexample_witness,
            },
        );
    }

    let total = per_extension_results.len() as f64;
    let passing = per_extension_results.values().filter(|v| **v).count() as f64;
    let pass_rate = if total > 0.0 { passing / total } else { 0.0 };
    let meets_threshold = pass_rate >= VERIFICATION_THRESHOLD;
    let degraded_mode = merge_degraded_reports(
        extension_details
            .values()
            .filter_map(|detail| detail.degraded_mode.as_ref()),
        "verification aggregate degraded-mode",
    );

    VerificationReport {
        pass_rate,
        per_extension_results,
        meets_threshold,
        extension_details,
        degraded_mode,
        counterexample_witnesses,
        evidence_artifacts,
    }
}

/// Issue a signed migration receipt.
fn issue_receipt(state: &PipelineState) -> MigrationReceipt {
    let pre_hash = {
        let mut h = Sha256::new();
        h.update(b"migration_receipt_pre_v1:");
        h.update((state.extensions.len() as u64).to_le_bytes());
        for (name, ver) in &state.extensions {
            h.update((name.len() as u64).to_le_bytes());
            h.update(name.as_bytes());
            h.update((ver.len() as u64).to_le_bytes());
            h.update(ver.as_bytes());
        }
        hex::encode(h.finalize())
    };

    let plan_fingerprint = state
        .migration_plan
        .as_ref()
        .map(|p| p.plan_id.clone())
        .unwrap_or_default();

    let post_hash = {
        let mut h = Sha256::new();
        h.update(b"migration_receipt_post_v1:");
        h.update((pre_hash.len() as u64).to_le_bytes());
        h.update(pre_hash.as_bytes());
        h.update(b"migrated");
        hex::encode(h.finalize())
    };

    let verification_summary = state
        .verification_report
        .as_ref()
        .map(|report| {
            format!(
                "pass_rate={:.2}% witnesses={} degraded={}",
                report.pass_rate * 100.0,
                report.counterexample_witnesses.len(),
                report.degraded_mode.is_some()
            )
        })
        .unwrap_or_default();

    let evidence_artifact_ids = state
        .migration_plan
        .as_ref()
        .map(|plan| {
            plan.evidence_artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let degraded_mode_summary = state
        .verification_report
        .as_ref()
        .and_then(|report| report.degraded_mode.as_ref())
        .map(|report| report.explanation.clone());

    let rollback_proof = state
        .migration_plan
        .as_ref()
        .and_then(|plan| plan.phases.last())
        .map(|phase| phase.rollback_certificate.certificate_id.clone())
        .unwrap_or_else(|| "rollback_validated".to_string());

    let mut receipt = MigrationReceipt {
        pre_migration_hash: pre_hash,
        plan_fingerprint,
        post_migration_hash: post_hash,
        verification_summary,
        rollback_proof,
        signature: String::new(),
        timestamp: "2026-02-21T00:00:00Z".to_string(),
        evidence_artifact_ids,
        degraded_mode_summary,
    };
    receipt.signature = sign_receipt(&receipt);
    receipt
}

fn canonical_receipt_payload(receipt: &MigrationReceipt) -> Vec<u8> {
    serde_json::to_vec(&UnsignedMigrationReceipt {
        pre_migration_hash: &receipt.pre_migration_hash,
        plan_fingerprint: &receipt.plan_fingerprint,
        post_migration_hash: &receipt.post_migration_hash,
        verification_summary: &receipt.verification_summary,
        rollback_proof: &receipt.rollback_proof,
        timestamp: &receipt.timestamp,
        evidence_artifact_ids: &receipt.evidence_artifact_ids,
        degraded_mode_summary: receipt.degraded_mode_summary.as_deref(),
    })
    .unwrap_or_else(|error| format!("__receipt_serde_error:{error}").into_bytes())
}

fn sign_receipt(receipt: &MigrationReceipt) -> String {
    let mut mac =
        HmacSha256::new_from_slice(RECEIPT_SIGNING_KEY).expect("receipt signing key is valid");
    mac.update(b"migration_receipt_sign_v1:");
    mac.update(&canonical_receipt_payload(receipt));
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_receipt_signature(receipt: &MigrationReceipt) -> bool {
    crate::security::constant_time::ct_eq(&receipt.signature, &sign_receipt(receipt))
}

/// Compute a cohort summary from a completed pipeline state.
pub fn compute_cohort_summary(state: &PipelineState) -> CohortSummary {
    let total = state.extensions.len() as f64;
    let success_count = state
        .verification_report
        .as_ref()
        .map(|r| r.per_extension_results.values().filter(|v| **v).count())
        .unwrap_or(0) as f64;

    let total_duration: u64 = state
        .execution_traces
        .iter()
        .fold(0u64, |acc, t| acc.saturating_add(t.duration_ms));
    let mean_time = if !state.execution_traces.is_empty() {
        total_duration / state.execution_traces.len() as u64
    } else {
        0
    };

    let rollback_count = state
        .verification_report
        .as_ref()
        .map(|r| r.per_extension_results.values().filter(|v| !**v).count())
        .unwrap_or(0) as f64;

    CohortSummary {
        throughput: if total > 0.0 && total_duration > 0 {
            total / (total_duration as f64 / 1000.0)
        } else {
            0.0
        },
        success_rate: if total > 0.0 {
            success_count / total
        } else {
            0.0
        },
        mean_time_to_migrate_ms: mean_time,
        rollback_rate: if total > 0.0 {
            rollback_count / total
        } else {
            0.0
        },
    }
}

/// Run the full pipeline from INTAKE to COMPLETE.
///
/// # INV-PIPE-DETERMINISTIC
/// Same cohort input produces identical pipeline traces.
pub fn run_full_pipeline(cohort: &CohortDefinition) -> Result<PipelineState, PipelineError> {
    let mut state = new(cohort)?;
    // Advance through all stages until Complete
    while state.current_stage != PipelineStage::Complete {
        state = advance(state)?;
    }
    Ok(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn healthy_evidence() -> ExtensionEvidence {
        let mut compatibility_bands = BTreeMap::new();
        compatibility_bands.insert("bun".to_string(), "compatible".to_string());
        compatibility_bands.insert("franken-node".to_string(), "compatible".to_string());
        compatibility_bands.insert("node".to_string(), "compatible".to_string());

        let mut evidence_sources = BTreeMap::new();
        evidence_sources.insert("scanner".to_string(), true);
        evidence_sources.insert("lockstep".to_string(), true);
        evidence_sources.insert("validation".to_string(), true);
        evidence_sources.insert("corpus".to_string(), true);

        ExtensionEvidence {
            api_inventory: vec!["console".to_string()],
            dependency_edges: Vec::new(),
            runtime_targets: vec![
                "node".to_string(),
                "bun".to_string(),
                "franken-node".to_string(),
            ],
            compatibility_bands,
            known_divergences: Vec::new(),
            corpus_coverage_bps: 9_400,
            required_capabilities: Vec::new(),
            lockstep_samples: 24,
            lockstep_failures: 0,
            validation_samples: 24,
            validation_failures: 0,
            evidence_sources,
        }
    }

    fn high_risk_evidence() -> ExtensionEvidence {
        let mut evidence = healthy_evidence();
        evidence.api_inventory = vec!["child_process".to_string(), "fs".to_string()];
        evidence.corpus_coverage_bps = 3_200;
        evidence.required_capabilities = vec!["native-ffi".to_string()];
        evidence.lockstep_samples = 14;
        evidence.lockstep_failures = 4;
        evidence.validation_samples = 12;
        evidence.validation_failures = 2;
        evidence.known_divergences = vec![KnownDivergence {
            scope: BoundaryScope::Security,
            risk_tier: RiskTier::High,
            detail: "receipt canonicalization mismatch under strict mode".to_string(),
        }];
        evidence
    }

    fn degraded_evidence() -> ExtensionEvidence {
        let mut evidence = healthy_evidence();
        evidence.runtime_targets.clear();
        evidence.corpus_coverage_bps = 6_200;
        evidence.lockstep_samples = 0;
        evidence.validation_samples = 0;
        evidence
            .evidence_sources
            .insert("lockstep".to_string(), false);
        evidence
            .evidence_sources
            .insert("validation".to_string(), false);
        evidence
    }

    fn verification_failure_evidence() -> ExtensionEvidence {
        let mut evidence = healthy_evidence();
        evidence.validation_samples = 20;
        evidence.validation_failures = 2;
        evidence.lockstep_samples = 20;
        evidence.lockstep_failures = 1;
        evidence.known_divergences = vec![KnownDivergence {
            scope: BoundaryScope::IO,
            risk_tier: RiskTier::Medium,
            detail: "shadow-mode lockstep mismatch for file-handle ordering".to_string(),
        }];
        evidence
    }

    fn ext(
        name: &str,
        source_version: &str,
        target_version: &str,
        dependency_complexity: u32,
        risk_tier: u32,
        evidence: ExtensionEvidence,
    ) -> ExtensionSpec {
        ExtensionSpec {
            name: name.to_string(),
            source_version: source_version.to_string(),
            target_version: target_version.to_string(),
            dependency_complexity,
            risk_tier,
            evidence,
        }
    }

    fn sample_cohort() -> CohortDefinition {
        CohortDefinition {
            cohort_id: "cohort-001".to_string(),
            extensions: vec![
                ext("ext_alpha", "1.0.0", "2.0.0", 3, 1, healthy_evidence()),
                ext("ext_beta", "0.9.0", "1.0.0", 5, 2, healthy_evidence()),
            ],
            selection_criteria: "pilot_v1".to_string(),
        }
    }

    fn single_ext_cohort(name: &str) -> CohortDefinition {
        single_ext_cohort_with_evidence(name, healthy_evidence())
    }

    fn single_ext_cohort_with_evidence(
        name: &str,
        evidence: ExtensionEvidence,
    ) -> CohortDefinition {
        CohortDefinition {
            cohort_id: "cohort-single".to_string(),
            extensions: vec![ext(name, "1.0.0", "2.0.0", 1, 1, evidence)],
            selection_criteria: "single".to_string(),
        }
    }

    // ── Pipeline creation ───────────────────────────────────────────────

    #[test]
    fn test_new_pipeline_starts_at_intake() {
        let state = new(&sample_cohort()).unwrap();
        assert_eq!(state.current_stage, PipelineStage::Intake);
    }

    #[test]
    fn test_new_pipeline_has_cohort_id() {
        let state = new(&sample_cohort()).unwrap();
        assert_eq!(state.cohort_id, "cohort-001");
    }

    #[test]
    fn test_new_pipeline_has_extensions() {
        let state = new(&sample_cohort()).unwrap();
        assert_eq!(state.extensions.len(), 2);
        assert!(state.extensions.contains_key("ext_alpha"));
        assert!(state.extensions.contains_key("ext_beta"));
    }

    #[test]
    fn test_new_pipeline_has_idempotency_key() {
        let state = new(&sample_cohort()).unwrap();
        assert!(!state.idempotency_key.is_empty());
        assert_eq!(state.idempotency_key.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_new_pipeline_has_schema_version() {
        let state = new(&sample_cohort()).unwrap();
        assert_eq!(state.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_new_pipeline_empty_history() {
        let state = new(&sample_cohort()).unwrap();
        assert!(state.stage_history.is_empty());
    }

    // ── Duplicate extension rejection ───────────────────────────────────

    #[test]
    fn test_duplicate_extension_rejected() {
        let cohort = CohortDefinition {
            cohort_id: "dup".to_string(),
            extensions: vec![
                ext("ext_a", "1.0.0", "2.0.0", 1, 1, healthy_evidence()),
                ext("ext_a", "1.0.0", "2.0.0", 1, 1, healthy_evidence()),
            ],
            selection_criteria: "dup".to_string(),
        };
        let err = new(&cohort).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PIPE_DUPLICATE_EXTENSION);
    }

    // ── Stage advancement ───────────────────────────────────────────────

    #[test]
    fn test_advance_intake_to_analysis() {
        let state = new(&sample_cohort()).unwrap();
        let state = advance(state).unwrap();
        assert_eq!(state.current_stage, PipelineStage::Analysis);
    }

    #[test]
    fn test_advance_through_all_stages() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        assert_eq!(state.current_stage, PipelineStage::Complete);
    }

    #[test]
    fn test_stage_history_recorded() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        // 7 transitions: Intake->Analysis->PlanGen->PlanReview->Exec->Verif->Receipt->Complete
        assert_eq!(state.stage_history.len(), 7);
    }

    #[test]
    fn test_cannot_advance_from_complete() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let err = advance(state).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PIPE_INVALID_TRANSITION);
    }

    #[test]
    fn test_cannot_advance_from_rollback() {
        let mut state = new(&sample_cohort()).unwrap();
        state = advance(state).unwrap(); // -> Analysis
        state = rollback(state).unwrap(); // -> Rollback
        let err = advance(state).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PIPE_INVALID_TRANSITION);
    }

    // ── Analysis ────────────────────────────────────────────────────────

    #[test]
    fn test_analysis_produces_report() {
        let mut state = new(&sample_cohort()).unwrap();
        state = advance(state).unwrap(); // Intake -> Analysis
        state = advance(state).unwrap(); // Analysis -> PlanGeneration (report generated)
        let report = state.compatibility_report.as_ref().unwrap();
        assert_eq!(report.per_extension_results.len(), 2);
        assert!(report.blockers.is_empty());
        assert!((report.overall_pass_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_analysis_detects_blockers() {
        let cohort = single_ext_cohort_with_evidence("needs_real_evidence", high_risk_evidence());
        let mut state = new(&cohort).unwrap();
        state = advance(state).unwrap(); // -> Analysis
        state = advance(state).unwrap(); // Analysis runs, produces report
        let report = state.compatibility_report.as_ref().unwrap();
        assert!(!report.blockers.is_empty());
        assert_eq!(report.overall_pass_rate, 0.0);
        assert_eq!(
            report.findings["needs_real_evidence"].compatibility_band,
            CompatibilityBand::Blocked
        );
    }

    // ── Plan generation ─────────────────────────────────────────────────

    #[test]
    fn test_plan_generated() {
        let mut state = new(&sample_cohort()).unwrap();
        state = advance(state).unwrap(); // -> Analysis
        state = advance(state).unwrap(); // -> PlanGeneration
        state = advance(state).unwrap(); // -> PlanReview (plan generated)
        let plan = state.migration_plan.as_ref().unwrap();
        assert!(!plan.plan_id.is_empty());
        assert!(!plan.steps.is_empty());
        assert_eq!(plan.phases.len(), 4);
    }

    #[test]
    fn test_plan_has_deterministic_rollout_phases_and_certificates() {
        let mut state = new(&sample_cohort()).unwrap();
        state = advance(state).unwrap();
        state = advance(state).unwrap();
        state = advance(state).unwrap();
        let plan = state.migration_plan.as_ref().unwrap();
        let phases: Vec<_> = plan.phases.iter().map(|phase| phase.phase).collect();
        assert_eq!(
            phases,
            vec![
                RolloutPhase::Shadow,
                RolloutPhase::Canary,
                RolloutPhase::Ramp,
                RolloutPhase::Default
            ]
        );
        assert!(
            plan.phases
                .iter()
                .all(|phase| !phase.rollback_certificate.certificate_id.is_empty())
        );
    }

    #[test]
    fn test_plan_id_deterministic() {
        let cohort = sample_cohort();
        let s1 = run_full_pipeline(&cohort).unwrap();
        let s2 = run_full_pipeline(&cohort).unwrap();
        assert_eq!(
            s1.migration_plan.as_ref().unwrap().plan_id,
            s2.migration_plan.as_ref().unwrap().plan_id
        );
    }

    // ── Execution ───────────────────────────────────────────────────────

    #[test]
    fn test_execution_traces_produced() {
        let mut state = new(&sample_cohort()).unwrap();
        // Advance to Execution, then past it
        for _ in 0..5 {
            state = advance(state).unwrap();
        }
        // Now at Verification, execution traces should exist
        assert_eq!(state.execution_traces.len(), 2);
    }

    #[test]
    fn test_execution_trace_has_transitions() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        for trace in &state.execution_traces {
            assert!(!trace.state_transitions.is_empty());
            assert!(!trace.mutations.is_empty());
            assert!(trace.duration_ms > 0);
        }
    }

    // ── Verification (95% threshold) ────────────────────────────────────

    #[test]
    fn test_verification_passes_for_good_cohort() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let report = state.verification_report.as_ref().unwrap();
        assert!(report.meets_threshold);
        assert!((report.pass_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_verification_threshold_enforced() {
        let cohort = single_ext_cohort_with_evidence(
            "verification_regression",
            verification_failure_evidence(),
        );
        let mut state = new(&cohort).unwrap();
        // Advance to Verification
        for _ in 0..5 {
            state = advance(state).unwrap();
        }
        assert_eq!(state.current_stage, PipelineStage::Verification);
        // Try to advance past Verification -- should fail
        let err = advance(state).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PIPE_THRESHOLD_NOT_MET);
    }

    #[test]
    fn test_verification_emits_counterexample_witness_for_failure() {
        let cohort = single_ext_cohort_with_evidence(
            "verification_regression",
            verification_failure_evidence(),
        );
        let mut state = new(&cohort).unwrap();
        for _ in 0..5 {
            state = advance(state).unwrap();
        }
        let report = run_verification(&state);
        assert_eq!(report.counterexample_witnesses.len(), 1);
        assert_eq!(
            report.counterexample_witnesses[0].extension_name,
            "verification_regression"
        );
    }

    #[test]
    fn test_degraded_mode_is_reported_and_not_green() {
        let cohort = single_ext_cohort_with_evidence("degraded_case", degraded_evidence());
        let mut state = new(&cohort).unwrap();
        state = advance(state).unwrap();
        state = advance(state).unwrap();
        let report = state.compatibility_report.as_ref().unwrap();
        assert!(report.degraded_mode.is_some());
        assert_eq!(
            report.findings["degraded_case"].compatibility_band,
            CompatibilityBand::Blocked
        );
    }

    #[test]
    fn test_verification_report_has_per_extension() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let report = state.verification_report.as_ref().unwrap();
        assert_eq!(report.per_extension_results.len(), 2);
    }

    // ── Receipt issuance ────────────────────────────────────────────────

    #[test]
    fn test_receipt_issued() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let receipt = state.migration_receipt.as_ref().unwrap();
        assert!(!receipt.pre_migration_hash.is_empty());
        assert!(!receipt.post_migration_hash.is_empty());
        assert!(!receipt.plan_fingerprint.is_empty());
    }

    #[test]
    fn test_receipt_signed() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let receipt = state.migration_receipt.as_ref().unwrap();
        assert!(!receipt.signature.is_empty());
        assert_eq!(receipt.signature.len(), 64);
        assert!(verify_receipt_signature(receipt));
    }

    #[test]
    fn test_receipt_has_verification_summary() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let receipt = state.migration_receipt.as_ref().unwrap();
        assert!(!receipt.verification_summary.is_empty());
    }

    #[test]
    fn test_receipt_signature_detects_tampering() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let mut receipt = state.migration_receipt.as_ref().unwrap().clone();
        assert!(verify_receipt_signature(&receipt));
        receipt.verification_summary.push_str(" tampered");
        assert!(!verify_receipt_signature(&receipt));
    }

    // ── Rollback ────────────────────────────────────────────────────────

    #[test]
    fn test_rollback_from_analysis() {
        let mut state = new(&sample_cohort()).unwrap();
        state = advance(state).unwrap(); // -> Analysis
        state = rollback(state).unwrap();
        assert_eq!(state.current_stage, PipelineStage::Rollback);
    }

    #[test]
    fn test_rollback_from_execution() {
        let mut state = new(&sample_cohort()).unwrap();
        for _ in 0..4 {
            state = advance(state).unwrap(); // -> Execution
        }
        assert_eq!(state.current_stage, PipelineStage::Execution);
        state = rollback(state).unwrap();
        assert_eq!(state.current_stage, PipelineStage::Rollback);
    }

    #[test]
    fn test_rollback_from_verification() {
        let mut state = new(&sample_cohort()).unwrap();
        for _ in 0..5 {
            state = advance(state).unwrap(); // -> Verification
        }
        assert_eq!(state.current_stage, PipelineStage::Verification);
        state = rollback(state).unwrap();
        assert_eq!(state.current_stage, PipelineStage::Rollback);
    }

    #[test]
    fn test_cannot_rollback_from_intake() {
        let state = new(&sample_cohort()).unwrap();
        let err = rollback(state).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PIPE_ROLLBACK_FAILED);
    }

    #[test]
    fn test_cannot_rollback_from_complete() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let err = rollback(state).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PIPE_ROLLBACK_FAILED);
    }

    #[test]
    fn test_cannot_rollback_from_rollback() {
        let mut state = new(&sample_cohort()).unwrap();
        state = advance(state).unwrap();
        state = rollback(state).unwrap();
        let err = rollback(state).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PIPE_ROLLBACK_FAILED);
    }

    #[test]
    fn test_rollback_records_transition() {
        let mut state = new(&sample_cohort()).unwrap();
        state = advance(state).unwrap(); // -> Analysis
        state = rollback(state).unwrap();
        let last = state.stage_history.last().unwrap();
        assert_eq!(last.from, PipelineStage::Analysis);
        assert_eq!(last.to, PipelineStage::Rollback);
    }

    // ── Idempotency ─────────────────────────────────────────────────────

    #[test]
    fn test_idempotency_same_cohort() {
        let cohort = sample_cohort();
        let s1 = new(&cohort).unwrap();
        let s2 = new(&cohort).unwrap();
        assert!(is_idempotent(&s1, &s2));
    }

    #[test]
    fn test_idempotency_different_cohort() {
        let s1 = new(&sample_cohort()).unwrap();
        let s2 = new(&single_ext_cohort("other")).unwrap();
        assert!(!is_idempotent(&s1, &s2));
    }

    #[test]
    fn test_idempotency_key_deterministic() {
        let cohort = sample_cohort();
        let s1 = new(&cohort).unwrap();
        let s2 = new(&cohort).unwrap();
        assert_eq!(s1.idempotency_key, s2.idempotency_key);
    }

    // ── Deterministic pipeline ──────────────────────────────────────────

    #[test]
    fn test_deterministic_full_pipeline() {
        let cohort = sample_cohort();
        let s1 = run_full_pipeline(&cohort).unwrap();
        let s2 = run_full_pipeline(&cohort).unwrap();
        // Same receipt
        assert_eq!(
            s1.migration_receipt.as_ref().unwrap().signature,
            s2.migration_receipt.as_ref().unwrap().signature
        );
        // Same plan ID
        assert_eq!(
            s1.migration_plan.as_ref().unwrap().plan_id,
            s2.migration_plan.as_ref().unwrap().plan_id
        );
        // Same idempotency key
        assert_eq!(s1.idempotency_key, s2.idempotency_key);
    }

    // ── Cohort summary ──────────────────────────────────────────────────

    #[test]
    fn test_cohort_summary_success_rate() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let summary = compute_cohort_summary(&state);
        assert!((summary.success_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cohort_summary_rollback_rate() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let summary = compute_cohort_summary(&state);
        assert!((summary.rollback_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cohort_summary_throughput() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let summary = compute_cohort_summary(&state);
        assert!(summary.throughput > 0.0);
    }

    #[test]
    fn test_cohort_summary_mean_time() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let summary = compute_cohort_summary(&state);
        assert!(summary.mean_time_to_migrate_ms > 0);
    }

    // ── PipelineStage ───────────────────────────────────────────────────

    #[test]
    fn test_pipeline_stage_all() {
        assert_eq!(PipelineStage::all().len(), 9);
    }

    #[test]
    fn test_pipeline_stage_labels() {
        assert_eq!(PipelineStage::Intake.label(), "INTAKE");
        assert_eq!(PipelineStage::Analysis.label(), "ANALYSIS");
        assert_eq!(PipelineStage::PlanGeneration.label(), "PLAN_GENERATION");
        assert_eq!(PipelineStage::PlanReview.label(), "PLAN_REVIEW");
        assert_eq!(PipelineStage::Execution.label(), "EXECUTION");
        assert_eq!(PipelineStage::Verification.label(), "VERIFICATION");
        assert_eq!(PipelineStage::ReceiptIssuance.label(), "RECEIPT_ISSUANCE");
        assert_eq!(PipelineStage::Complete.label(), "COMPLETE");
        assert_eq!(PipelineStage::Rollback.label(), "ROLLBACK");
    }

    #[test]
    fn test_pipeline_stage_next() {
        assert_eq!(PipelineStage::Intake.next(), Some(PipelineStage::Analysis));
        assert_eq!(PipelineStage::Complete.next(), None);
        assert_eq!(PipelineStage::Rollback.next(), None);
    }

    #[test]
    fn test_pipeline_stage_can_rollback() {
        assert!(!PipelineStage::Intake.can_rollback());
        assert!(PipelineStage::Analysis.can_rollback());
        assert!(PipelineStage::PlanGeneration.can_rollback());
        assert!(PipelineStage::PlanReview.can_rollback());
        assert!(PipelineStage::Execution.can_rollback());
        assert!(PipelineStage::Verification.can_rollback());
        assert!(PipelineStage::ReceiptIssuance.can_rollback());
        assert!(!PipelineStage::Complete.can_rollback());
        assert!(!PipelineStage::Rollback.can_rollback());
    }

    // ── Serde round-trips ───────────────────────────────────────────────

    #[test]
    fn test_pipeline_state_serde_roundtrip() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        let parsed: PipelineState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.current_stage, parsed.current_stage);
        assert_eq!(state.cohort_id, parsed.cohort_id);
        assert_eq!(state.idempotency_key, parsed.idempotency_key);
    }

    #[test]
    fn test_cohort_definition_serde_roundtrip() {
        let cohort = sample_cohort();
        let json = serde_json::to_string(&cohort).unwrap();
        let parsed: CohortDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(cohort, parsed);
    }

    #[test]
    fn test_migration_receipt_serde_roundtrip() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let receipt = state.migration_receipt.as_ref().unwrap();
        let json = serde_json::to_string(receipt).unwrap();
        let parsed: MigrationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, &parsed);
    }

    #[test]
    fn test_verification_report_serde_roundtrip() {
        let state = run_full_pipeline(&sample_cohort()).unwrap();
        let report = state.verification_report.as_ref().unwrap();
        let json = serde_json::to_string(report).unwrap();
        let parsed: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.pass_rate, parsed.pass_rate);
        assert_eq!(report.per_extension_results, parsed.per_extension_results);
        assert_eq!(report.meets_threshold, parsed.meets_threshold);
        assert_eq!(report.degraded_mode, parsed.degraded_mode);
        assert_eq!(
            report.counterexample_witnesses,
            parsed.counterexample_witnesses
        );
        assert_eq!(report.evidence_artifacts, parsed.evidence_artifacts);

        for (name, detail) in &report.extension_details {
            let parsed_detail = parsed.extension_details.get(name).unwrap();
            assert_eq!(detail.observed_pass_rate, parsed_detail.observed_pass_rate);
            assert!(
                (detail.success_interval.lower_bound - parsed_detail.success_interval.lower_bound)
                    .abs()
                    < 1e-12
            );
            assert!(
                (detail.success_interval.upper_bound - parsed_detail.success_interval.upper_bound)
                    .abs()
                    < 1e-12
            );
            assert_eq!(
                detail.success_interval.confidence_level,
                parsed_detail.success_interval.confidence_level
            );
            assert_eq!(detail.degraded_mode, parsed_detail.degraded_mode);
            assert_eq!(detail.explanation_trace, parsed_detail.explanation_trace);
            assert_eq!(
                detail.counterexample_witness,
                parsed_detail.counterexample_witness
            );
        }
    }

    #[test]
    fn test_transform_action_serde_roundtrip() {
        let action = TransformAction::ApiShim;
        let json = serde_json::to_string(&action).unwrap();
        let parsed: TransformAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, parsed);
    }

    // ── Event codes ─────────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::PIPELINE_STAGE_ENTER, "PIPE-001");
        assert_eq!(event_codes::PIPELINE_STAGE_EXIT, "PIPE-002");
        assert_eq!(event_codes::ANALYSIS_BLOCKER_FOUND, "PIPE-003");
        assert_eq!(event_codes::PLAN_GENERATED, "PIPE-004");
        assert_eq!(event_codes::EXECUTION_STEP, "PIPE-005");
        assert_eq!(event_codes::EXECUTION_IDEMPOTENT_CHECK, "PIPE-006");
        assert_eq!(event_codes::VERIFICATION_PASS, "PIPE-007");
        assert_eq!(event_codes::VERIFICATION_FAIL, "PIPE-008");
        assert_eq!(event_codes::RECEIPT_ISSUED, "PIPE-009");
        assert_eq!(event_codes::RECEIPT_VERIFIED, "PIPE-010");
        assert_eq!(event_codes::ROLLBACK_INITIATED, "PIPE-011");
        assert_eq!(event_codes::ROLLBACK_COMPLETE, "PIPE-012");
        assert_eq!(event_codes::COHORT_SUMMARY, "PIPE-013");
    }

    // ── Error codes ─────────────────────────────────────────────────────

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(
            error_codes::ERR_PIPE_INVALID_TRANSITION,
            "ERR_PIPE_INVALID_TRANSITION"
        );
        assert_eq!(
            error_codes::ERR_PIPE_VERIFICATION_FAILED,
            "ERR_PIPE_VERIFICATION_FAILED"
        );
        assert_eq!(
            error_codes::ERR_PIPE_IDEMPOTENCY_VIOLATED,
            "ERR_PIPE_IDEMPOTENCY_VIOLATED"
        );
        assert_eq!(
            error_codes::ERR_PIPE_ROLLBACK_FAILED,
            "ERR_PIPE_ROLLBACK_FAILED"
        );
        assert_eq!(
            error_codes::ERR_PIPE_THRESHOLD_NOT_MET,
            "ERR_PIPE_THRESHOLD_NOT_MET"
        );
        assert_eq!(
            error_codes::ERR_PIPE_DUPLICATE_EXTENSION,
            "ERR_PIPE_DUPLICATE_EXTENSION"
        );
    }

    // ── Invariants ──────────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(invariants::INV_PIPE_DETERMINISTIC, "INV-PIPE-DETERMINISTIC");
        assert_eq!(invariants::INV_PIPE_IDEMPOTENT, "INV-PIPE-IDEMPOTENT");
        assert_eq!(
            invariants::INV_PIPE_THRESHOLD_ENFORCED,
            "INV-PIPE-THRESHOLD-ENFORCED"
        );
        assert_eq!(
            invariants::INV_PIPE_ROLLBACK_ANY_STAGE,
            "INV-PIPE-ROLLBACK-ANY-STAGE"
        );
        assert_eq!(
            invariants::INV_PIPE_RECEIPT_SIGNED,
            "INV-PIPE-RECEIPT-SIGNED"
        );
        assert_eq!(
            invariants::INV_PIPE_STAGE_MONOTONIC,
            "INV-PIPE-STAGE-MONOTONIC"
        );
    }

    // ── Schema version ──────────────────────────────────────────────────

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "pipe-v1.0");
    }

    // ── Send + Sync ─────────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<PipelineState>();
        assert_sync::<PipelineState>();
        assert_send::<PipelineStage>();
        assert_sync::<PipelineStage>();
        assert_send::<CohortDefinition>();
        assert_sync::<CohortDefinition>();
        assert_send::<ExtensionSpec>();
        assert_sync::<ExtensionSpec>();
        assert_send::<CompatibilityReport>();
        assert_sync::<CompatibilityReport>();
        assert_send::<MigrationPlan>();
        assert_sync::<MigrationPlan>();
        assert_send::<TransformationStep>();
        assert_sync::<TransformationStep>();
        assert_send::<TransformAction>();
        assert_sync::<TransformAction>();
        assert_send::<ExecutionTrace>();
        assert_sync::<ExecutionTrace>();
        assert_send::<VerificationReport>();
        assert_sync::<VerificationReport>();
        assert_send::<MigrationReceipt>();
        assert_sync::<MigrationReceipt>();
        assert_send::<CohortSummary>();
        assert_sync::<CohortSummary>();
        assert_send::<PipelineError>();
        assert_sync::<PipelineError>();
        assert_send::<PipelineEvent>();
        assert_sync::<PipelineEvent>();
    }

    // ── PipelineError ───────────────────────────────────────────────────

    #[test]
    fn test_pipeline_error_display() {
        let err = PipelineError {
            code: "ERR_TEST".to_string(),
            message: "test error".to_string(),
        };
        assert_eq!(format!("{}", err), "ERR_TEST: test error");
    }

    // ── PipelineEvent ───────────────────────────────────────────────────

    #[test]
    fn test_pipeline_event_serde() {
        let evt = PipelineEvent {
            event_code: event_codes::PIPELINE_STAGE_ENTER.to_string(),
            cohort_id: "cohort-001".to_string(),
            stage: "INTAKE".to_string(),
            detail: "entering intake".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let parsed: PipelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "PIPE-001");
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn test_empty_cohort() {
        let cohort = CohortDefinition {
            cohort_id: "empty".to_string(),
            extensions: vec![],
            selection_criteria: "none".to_string(),
        };
        let state = new(&cohort).unwrap();
        assert_eq!(state.extensions.len(), 0);
    }

    #[test]
    fn test_single_extension_full_pipeline() {
        let cohort = single_ext_cohort("solo_ext");
        let state = run_full_pipeline(&cohort).unwrap();
        assert_eq!(state.current_stage, PipelineStage::Complete);
    }

    #[test]
    fn test_btreemap_ordering() {
        let cohort = sample_cohort();
        let state = new(&cohort).unwrap();
        let keys: Vec<_> = state.extensions.keys().collect();
        // BTreeMap ensures sorted order
        assert_eq!(keys, vec!["ext_alpha", "ext_beta"]);
    }

    #[test]
    fn test_placeholder_prefix_shortcuts_absent_from_source() {
        let source = include_str!("migration_pipeline.rs");
        let legacy_analysis_marker = ["blocked", "_"].concat();
        let legacy_verify_marker = ["fail", "_", "verify", "_"].concat();
        assert!(!source.contains(&legacy_analysis_marker));
        assert!(!source.contains(&legacy_verify_marker));
    }

    #[test]
    fn wilson_interval_zero_total_returns_full_range() {
        let ci = wilson_interval(0, 0, 0.95);
        assert_eq!(ci.lower_bound, 0.0);
        assert_eq!(ci.upper_bound, 1.0);
    }

    #[test]
    fn wilson_interval_successes_exceed_total_returns_zero() {
        let ci = wilson_interval(10, 5, 0.95);
        assert_eq!(ci.lower_bound, 0.0);
        assert_eq!(ci.upper_bound, 0.0);
    }

    #[test]
    fn wilson_interval_normal_produces_finite_bounds() {
        let ci = wilson_interval(80, 100, 0.95);
        assert!(ci.lower_bound.is_finite());
        assert!(ci.upper_bound.is_finite());
        assert!(ci.lower_bound >= 0.0);
        assert!(ci.upper_bound <= 1.0);
        assert!(ci.lower_bound <= ci.upper_bound);
    }

    #[test]
    fn wilson_interval_all_pass_produces_finite_bounds() {
        let ci = wilson_interval(100, 100, 0.95);
        assert!(ci.lower_bound.is_finite());
        assert!(ci.upper_bound.is_finite());
        assert!(ci.upper_bound <= 1.0);
    }

    #[test]
    fn wilson_interval_all_fail_produces_finite_bounds() {
        let ci = wilson_interval(0, 100, 0.95);
        assert!(ci.lower_bound.is_finite());
        assert!(ci.upper_bound.is_finite());
        assert!(ci.lower_bound >= 0.0);
    }
}
