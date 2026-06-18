//! bd-p9mpd.4: Workspace build admission and cleanup decision policy.
//!
//! Provides deterministic admission decisions for expensive work and cleanup
//! candidates based on workspace pressure, RCH availability, and resource constraints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

// External dependencies for disk space detection
extern crate fs2;

use crate::runtime::hardware_planner::{
    HardwarePlanner, HardwareProfile, PlacementDecision, PlacementPolicy, WorkloadRequest,
};
use crate::{bounded_read_to_string, push_bounded};

/// Maximum diagnostic reasons to track per decision.
const MAX_DIAGNOSTIC_REASONS: usize = 32;

/// Schema version for agent command/resource budget ledgers.
pub const AGENT_COMMAND_LEDGER_SCHEMA_VERSION: &str = "franken-node/agent-command-ledger/v1";

/// Maximum command records to keep in one agent session ledger.
pub const MAX_AGENT_COMMAND_LEDGER_ENTRIES: usize = 512;

/// Maximum paths or references attached to one command record.
const MAX_AGENT_COMMAND_LEDGER_ITEMS: usize = 128;

/// Maximum byte length for command summaries and ledger fields.
const MAX_AGENT_COMMAND_FIELD_BYTES: usize = 1024;

/// Maximum Agent Mail reservation lease JSON size accepted by live probes.
const MAX_AGENT_MAIL_RESERVATION_FILE_BYTES: u64 = 64 * 1024;

/// Schema version for operator what-if simulation reports.
pub const OPERATOR_WHAT_IF_SCHEMA_VERSION: &str = "franken-node/operator-what-if/v1";

/// Schema version for deterministic no-ready Beads autopilot receipts.
pub const NO_READY_AUTOPILOT_SCHEMA_VERSION: &str = "franken-node/no-ready-autopilot/v1";

/// Schema version for cross-repo blocker handoff envelopes.
pub const CROSS_REPO_BLOCKER_ENVELOPE_SCHEMA_VERSION: &str =
    "franken-node/cross-repo-blocker-envelope/v1";

/// Schema version for workspace-pressure to hardware-planner bridge decisions.
pub const WORKSPACE_HARDWARE_ADMISSION_SCHEMA_VERSION: &str =
    "franken-node/workspace-hardware-admission/v1";

/// Schema version for deterministic target-dir lease plans.
pub const TARGET_DIR_LEASE_PLAN_SCHEMA_VERSION: &str = "franken-node/target-dir-lease-plan/v1";

/// Maximum structured log entries emitted by one what-if simulation.
const MAX_OPERATOR_WHAT_IF_LOGS: usize = 32;

/// Maximum RCH build states carried in one operator what-if report.
const MAX_OPERATOR_RCH_BUILD_STATES: usize = 16;

/// Maximum stale/blocked Beads evidence rows carried in one no-ready receipt.
const MAX_NO_READY_AUTOPILOT_ITEMS: usize = 32;

/// Age threshold after which an in-progress bead needs explicit refresh.
const STALE_IN_PROGRESS_AFTER_SECS: u64 = 60 * 60;

/// Maximum cleanup actions returned by one what-if simulation.
const MAX_OPERATOR_WHAT_IF_CLEANUP_ACTIONS: usize = 64;

/// Maximum target-dir roots or reservation hints accepted by one lease plan.
pub const MAX_TARGET_DIR_LEASE_CANDIDATES: usize = 64;

/// Default lease expiry hint for validation target directories.
pub const DEFAULT_TARGET_DIR_LEASE_TTL_MS: u64 = 3_600_000;

pub mod target_dir_lease_reason_codes {
    pub const SELECT_OFF_REPO_RCH: &str = "TDL_SELECT_OFF_REPO_RCH";
    pub const SELECT_LOCAL_SOURCE: &str = "TDL_SELECT_LOCAL_SOURCE";
    pub const SELECT_TEMP_ISOLATED: &str = "TDL_SELECT_TEMP_ISOLATED";
    pub const REJECT_REPO_LOCAL_HEAVY: &str = "TDL_REJECT_REPO_LOCAL_HEAVY";
    pub const REJECT_FULL_ROOT: &str = "TDL_REJECT_FULL_ROOT";
    pub const REJECT_STALE_ROOT: &str = "TDL_REJECT_STALE_ROOT";
    pub const REJECT_UNSTABLE_OWNER: &str = "TDL_REJECT_UNSTABLE_OWNER";
    pub const FAIL_STALE_TOPOLOGY: &str = "TDL_FAIL_STALE_TOPOLOGY";
    pub const FAIL_INVALID_MEMORY: &str = "TDL_FAIL_INVALID_MEMORY";
    pub const FAIL_UNSAFE_PATH: &str = "TDL_FAIL_UNSAFE_PATH";
    pub const FAIL_NO_ROOTS: &str = "TDL_FAIL_NO_ROOTS";
    pub const FAIL_NO_ELIGIBLE_ROOT: &str = "TDL_FAIL_NO_ELIGIBLE_ROOT";
    pub const FAIL_TOO_MANY_ITEMS: &str = "TDL_FAIL_TOO_MANY_ITEMS";
}

/// Workspace cost classification for different types of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkCostClass {
    /// Validation/proof jobs - moderate cost, RCH beneficial
    Validation,
    /// Fuzzing - high CPU, long duration, good RCH candidate
    Fuzzing,
    /// Benchmark runs - high cost, timing sensitive
    Benchmark,
    /// Documentation gates - low cost, usually local-only
    DocsGate,
    /// One-off source checks - very low cost, local preferred
    SourceOnly,
    /// Full workspace cleanup - I/O intensive
    Cleanup,
}

impl WorkCostClass {
    /// Returns the relative cost weight (higher = more expensive).
    pub const fn cost_weight(self) -> u32 {
        match self {
            Self::SourceOnly => 1,
            Self::DocsGate => 2,
            Self::Validation => 5,
            Self::Benchmark => 8,
            Self::Fuzzing => 10,
            Self::Cleanup => 6,
        }
    }

    /// Returns whether this work type benefits from RCH offloading.
    pub const fn prefers_rch(self) -> bool {
        matches!(
            self,
            Self::Validation | Self::Fuzzing | Self::Benchmark | Self::Cleanup
        )
    }
}

/// Build admission decision from workspace pressure analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionDecision {
    /// Proceed with local execution immediately.
    AllowLocal,
    /// Require RCH offloading for resource management.
    RequireRch,
    /// Queue the work for later execution.
    Queue { retry_after_ms: u32 },
    /// Wait briefly and retry admission decision.
    Wait { retry_after_ms: u32 },
    /// Refuse to use local fallback when RCH unavailable.
    RefuseLocalFallback,
}

/// Cleanup candidate with audit evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupCandidate {
    /// Canonical path to the cleanup target.
    pub path: PathBuf,
    /// Estimated bytes that would be freed.
    pub size_bytes: u64,
    /// Why this is eligible for cleanup.
    pub reason: String,
    /// Whether this requires explicit approval.
    pub requires_approval: bool,
    /// Last modified time (for staleness analysis).
    pub mtime: Option<String>,
}

/// Complete workspace pressure policy decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// The admission decision for the requested work.
    pub admission: AdmissionDecision,
    /// Cleanup candidates identified during analysis.
    pub cleanup_candidates: Vec<CleanupCandidate>,
    /// Machine-readable reason code.
    pub reason_code: String,
    /// Human-readable summary of the decision.
    pub summary: String,
    /// Detailed diagnostic reasons.
    pub diagnostic_reasons: Vec<String>,
    /// Confidence level in the decision (0.0-1.0).
    pub confidence: f32,
}

/// Workspace pressure inputs for policy decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePressureInputs {
    /// Free disk space in bytes.
    pub free_disk_bytes: u64,
    /// Total size of target directories in bytes.
    pub target_dir_bytes: u64,
    /// Number of active cargo/rustc processes.
    pub active_build_count: u32,
    /// RCH queue state (workers available).
    pub rch_available_slots: Option<u32>,
    /// Memory pressure (0.0-1.0, where 1.0 is full).
    pub memory_pressure: f32,
    /// Number of active file reservations.
    pub active_reservations: u32,
    /// Whether Agent Mail coordination is healthy.
    pub coordination_healthy: bool,
}

/// Optional deterministic topology snapshot used by hardware placement bridging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceHardwareTopologySnapshot {
    pub snapshot_id: String,
    pub cpu_cores: u32,
    pub memory_bytes: u64,
    pub numa_nodes: Option<u32>,
    pub stale: bool,
}

/// Input for projecting workspace pressure into hardware-planner placement evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceHardwarePlacementInput {
    pub bridge_id: String,
    pub workload_id: String,
    pub work_class: WorkCostClass,
    pub bead_priority: u32,
    pub requested_command: Option<String>,
    pub workspace: WorkspacePressureInputs,
    pub topology: Option<WorkspaceHardwareTopologySnapshot>,
    pub timestamp_ms: u64,
}

/// Read-only placement bridge output. The bridge never launches work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceHardwarePlacementDecision {
    pub schema_version: String,
    pub bridge_id: String,
    pub workload_id: String,
    pub action: OperatorWhatIfAction,
    pub reason_code: String,
    pub policy_decision: PolicyDecision,
    pub placement_decision: Option<PlacementDecision>,
    pub target_profile_id: Option<String>,
    pub approved_dispatch_notes: Vec<String>,
    pub diagnostics: Vec<String>,
    pub fail_closed: bool,
}

/// Command family requesting an isolated validation target directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetDirLeaseCommandFamily {
    Cargo,
    RchCargo,
    Rustfmt,
    Ubs,
    PythonGate,
    SourceOnly,
    Other,
}

impl TargetDirLeaseCommandFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::RchCargo => "rch_cargo",
            Self::Rustfmt => "rustfmt",
            Self::Ubs => "ubs",
            Self::PythonGate => "python_gate",
            Self::SourceOnly => "source_only",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub const fn is_heavy(self) -> bool {
        matches!(self, Self::Cargo | Self::RchCargo)
    }
}

/// Expected artifact class for the target-dir lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetDirLeaseArtifactClass {
    BuildOutput,
    TestArtifacts,
    Evidence,
    TempOutput,
    Cache,
}

/// Candidate root class for lease planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetDirLeaseRootKind {
    OffRepo,
    RchWorker,
    Temp,
    RepoLocal,
    Unknown,
}

/// Safety class attached to a lease candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetDirLeaseSafetyClass {
    PreferredIsolated,
    AcceptableShared,
    RequiresExplicitApproval,
    Rejected,
}

/// Expected cleanup owner. This is advisory only and never deletes files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetDirLeaseCleanupOwner {
    Agent,
    RchWorker,
    Operator,
    None,
}

/// Observed or configured target-dir root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDirLeaseRoot {
    pub path: String,
    pub kind: TargetDirLeaseRootKind,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub numa_node: Option<u32>,
    pub stable_owner: bool,
    pub existing_lease_count: u32,
    pub stale: bool,
}

/// Active reservation/lease hint used to avoid piling work onto one root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDirLeaseReservationHint {
    pub path: String,
    pub holder: String,
    pub expires_at_ms: Option<u64>,
}

/// Input for deterministic target-dir lease planning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetDirLeasePlanInput {
    pub plan_id: String,
    pub workspace_root: String,
    pub bead_id: String,
    pub command_family: TargetDirLeaseCommandFamily,
    pub expected_artifact_class: TargetDirLeaseArtifactClass,
    pub roots: Vec<TargetDirLeaseRoot>,
    pub topology: Option<WorkspaceHardwareTopologySnapshot>,
    pub memory_pressure: f32,
    pub active_reservation_hints: Vec<TargetDirLeaseReservationHint>,
    pub rch_required: bool,
    pub lease_ttl_ms: u64,
}

/// One ranked target-dir lease candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDirLeaseCandidate {
    pub path: String,
    pub root_path: String,
    pub root_kind: TargetDirLeaseRootKind,
    pub safety_class: TargetDirLeaseSafetyClass,
    pub expected_cleanup_owner: TargetDirLeaseCleanupOwner,
    pub expires_after_ms: u64,
    pub reason_code: String,
    pub fail_closed: bool,
    pub score: i64,
    pub free_bytes: u64,
    pub numa_node: Option<u32>,
    pub requires_approval: bool,
    pub diagnostics: Vec<String>,
}

/// Cleanup advice emitted by the planner. It is never an executable delete command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDirLeaseCleanupRecommendation {
    pub path: String,
    pub reason: String,
    pub requires_approval: bool,
}

/// Deterministic target-dir lease plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDirLeasePlan {
    pub schema_version: String,
    pub plan_id: String,
    pub bead_id: String,
    pub selected_path: Option<String>,
    pub selected_reason_code: String,
    pub candidates: Vec<TargetDirLeaseCandidate>,
    pub cleanup_recommendations: Vec<TargetDirLeaseCleanupRecommendation>,
    pub diagnostics: Vec<String>,
    pub fail_closed: bool,
    pub human_summary: String,
}

/// RCH build state visible to an operator simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorWhatIfRchBuildState {
    pub build_id: String,
    pub worker_id: String,
    pub command: String,
    pub heartbeat_fresh: bool,
    pub progress_stale: bool,
    pub progress_age_secs: Option<u64>,
}

/// RCH queue state visible to an operator simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorWhatIfRchQueueState {
    pub available_slots: Option<u32>,
    pub queued_jobs: u32,
    pub degraded_workers: u32,
    pub local_fallback_allowed: bool,
    #[serde(default)]
    pub active_builds: Vec<OperatorWhatIfRchBuildState>,
}

/// Cleanup safety class attached to an observed artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorWhatIfArtifactSafetyClass {
    CleanupEligible,
    Pinned,
    Protected,
}

/// Bounded artifact observation for operator simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorWhatIfArtifact {
    pub path: String,
    pub size_bytes: u64,
    pub safety_class: OperatorWhatIfArtifactSafetyClass,
    pub reason: String,
    pub pinned_by: Option<String>,
}

/// Operator-facing input for simulating a validation or cleanup decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorWhatIfInput {
    pub scenario_id: String,
    pub bead_id: Option<String>,
    pub work_class: WorkCostClass,
    pub bead_priority: u32,
    pub requested_command: Option<String>,
    pub workspace: WorkspacePressureInputs,
    pub rch_queue: OperatorWhatIfRchQueueState,
    pub artifacts: Vec<OperatorWhatIfArtifact>,
    pub command_ledger: Option<AgentCommandBudgetLedger>,
    pub stale_sibling_blocker: Option<String>,
}

/// Stable simulation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorWhatIfAction {
    Allow,
    Wait,
    Queue,
    RequireRch,
    RefuseLocalFallback,
}

impl OperatorWhatIfAction {
    const fn from_admission(admission: &AdmissionDecision) -> Self {
        match admission {
            AdmissionDecision::AllowLocal => Self::Allow,
            AdmissionDecision::RequireRch => Self::RequireRch,
            AdmissionDecision::Queue { .. } => Self::Queue,
            AdmissionDecision::Wait { .. } => Self::Wait,
            AdmissionDecision::RefuseLocalFallback => Self::RefuseLocalFallback,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Wait => "wait",
            Self::Queue => "queue",
            Self::RequireRch => "require_rch",
            Self::RefuseLocalFallback => "refuse_local_fallback",
        }
    }
}

/// Dry-run cleanup action that is safe to present to an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorWhatIfCleanupAction {
    pub path: String,
    pub size_bytes: u64,
    pub reason: String,
    pub dry_run_command: String,
}

/// Structured event emitted while simulating a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorWhatIfLog {
    pub event_code: String,
    pub message: String,
}

/// RCH stale-progress evidence surfaced in operator what-if output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorWhatIfRchStaleProgress {
    pub active_builds: Vec<OperatorWhatIfRchBuildState>,
    pub safe_next_action: String,
}

/// Deterministic what-if report. This never mutates bead state or deletes files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorWhatIfReport {
    pub schema_version: String,
    pub scenario_id: String,
    pub bead_id: Option<String>,
    pub action: OperatorWhatIfAction,
    pub reason_code: String,
    pub retry_after_ms: Option<u32>,
    pub simulated_command: Option<String>,
    pub cleanup_actions: Vec<OperatorWhatIfCleanupAction>,
    pub pinned_artifact_count: usize,
    pub protected_artifact_count: usize,
    pub command_ledger_summary: Option<AgentCommandLedgerSummary>,
    pub rch_stale_progress: Option<OperatorWhatIfRchStaleProgress>,
    pub policy_decision: PolicyDecision,
    pub logs: Vec<OperatorWhatIfLog>,
    pub human_summary: String,
}

/// Origin class for a blocked bead when ready work is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoReadyBlockerOrigin {
    Local,
    SiblingRepository,
    BuildInfrastructure,
}

/// In-progress bead evidence used by no-ready autopilot receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoReadyInProgressBead {
    pub bead_id: String,
    pub assignee: String,
    pub updated_age_secs: u64,
    pub status_summary: String,
    pub reserved_paths: Vec<String>,
}

/// Blocked bead evidence used by no-ready autopilot receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoReadyBlockedBeadEvidence {
    pub bead_id: String,
    pub origin: NoReadyBlockerOrigin,
    pub owner: Option<String>,
    pub sibling_project: Option<String>,
    pub blocker_command: String,
    pub first_blocker_line: String,
    pub notes: String,
}

/// Input for a deterministic cross-repo blocker handoff envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRepoBlockerEnvelopeInput {
    pub envelope_id: String,
    pub franken_node_bead_id: String,
    pub blocker_origin: NoReadyBlockerOrigin,
    pub next_owner: String,
    pub sibling_project: Option<String>,
    pub sibling_bead_id: Option<String>,
    pub agent_mail_thread_id: Option<String>,
    pub agent_mail_message_id: Option<String>,
    pub rch_build_id: Option<String>,
    pub required_committed_revision: String,
    pub observed_revision: Option<String>,
    pub observed_revision_committed: bool,
    pub validation_command: String,
    pub first_blocker_line: String,
}

/// Stable envelope that can be pasted into Beads and Agent Mail without mutating status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRepoBlockerEnvelope {
    pub schema_version: String,
    pub envelope_id: String,
    pub franken_node_bead_id: String,
    pub blocker_origin: NoReadyBlockerOrigin,
    pub next_owner: String,
    pub sibling_project: Option<String>,
    pub sibling_bead_id: Option<String>,
    pub agent_mail_thread_id: Option<String>,
    pub agent_mail_message_id: Option<String>,
    pub rch_build_id: Option<String>,
    pub required_committed_revision: String,
    pub observed_revision: Option<String>,
    pub observed_revision_committed: bool,
    pub validation_command: String,
    pub first_blocker_line: String,
    pub retry_validation_allowed: bool,
    pub sufficient_to_unblock: bool,
    pub beads_status_change_allowed: bool,
    pub reason_code: String,
    pub safe_next_action: String,
    pub pasteable_beads_note: String,
    pub agent_mail_handoff_body: String,
    pub human_summary: String,
}

/// Operator-facing input for a ready-empty Beads decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoReadyAutopilotInput {
    pub receipt_id: String,
    pub workspace_root: String,
    pub ready_issue_count: u32,
    pub open_issue_count: u32,
    pub blocked_issue_count: u32,
    pub in_progress_beads: Vec<NoReadyInProgressBead>,
    pub blocked_beads: Vec<NoReadyBlockedBeadEvidence>,
    pub rch_queue: OperatorWhatIfRchQueueState,
    pub last_ready_command: Option<String>,
    pub idea_wizard_allowed: bool,
}

/// Stable decision selected by the no-ready autopilot planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoReadyAutopilotAction {
    UseReadyWork,
    DeferForRchPressure,
    RefreshStaleInProgress,
    HandoffCrossRepoBlocker,
    RefreshBlockedEvidence,
    CreatePlanningBead,
    ReportNoAction,
}

impl NoReadyAutopilotAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UseReadyWork => "use_ready_work",
            Self::DeferForRchPressure => "defer_for_rch_pressure",
            Self::RefreshStaleInProgress => "refresh_stale_in_progress",
            Self::HandoffCrossRepoBlocker => "handoff_cross_repo_blocker",
            Self::RefreshBlockedEvidence => "refresh_blocked_evidence",
            Self::CreatePlanningBead => "create_planning_bead",
            Self::ReportNoAction => "report_no_action",
        }
    }
}

/// Alternative considered and rejected by the no-ready autopilot planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoReadyAutopilotRejectedAlternative {
    pub action: NoReadyAutopilotAction,
    pub reason_code: String,
    pub rationale: String,
}

/// Deterministic receipt for the state where ready work is empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoReadyAutopilotReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub workspace_root: String,
    pub selected_action: NoReadyAutopilotAction,
    pub reason_code: String,
    pub safe_next_action: String,
    pub ready_issue_count: u32,
    pub open_issue_count: u32,
    pub blocked_issue_count: u32,
    pub stale_in_progress_beads: Vec<NoReadyInProgressBead>,
    pub blocked_evidence: Vec<NoReadyBlockedBeadEvidence>,
    pub rch_stale_progress: Option<OperatorWhatIfRchStaleProgress>,
    pub rejected_alternatives: Vec<NoReadyAutopilotRejectedAlternative>,
    pub pasteable_beads_note: String,
    pub human_summary: String,
}

/// High-level command family for an agent operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCommandFamily {
    Cargo,
    Rch,
    Rustfmt,
    Ubs,
    Git,
    Beads,
    AgentMail,
    Filesystem,
    SourceOnly,
    Other,
}

/// Resource cost class for an agent command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCommandCostClass {
    SourceOnly,
    LocalFast,
    LocalCpuSensitive,
    RchRemote,
    DiskImpacting,
    Coordination,
}

/// Expected execution policy for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCommandExecutionPolicy {
    SourceOnly,
    LocalAllowed,
    RchRequired,
    RchUsed,
    CoordinationOnly,
}

/// Validation outcome attached to a command record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCommandValidationOutcome {
    NotRun,
    Passed,
    Failed,
    Blocked,
}

/// Machine-readable policy violations detected from a command ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCommandPolicyViolation {
    BareCargo,
    MissingRchForCargo,
    UnsafeDeleteAttempt,
    UnreservedCodeEdit,
    StaleInProgressClaim,
}

/// One bounded command/resource budget record for an agent session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCommandBudgetEntry {
    pub command_id: String,
    pub family: AgentCommandFamily,
    pub cost_class: AgentCommandCostClass,
    pub execution_policy: AgentCommandExecutionPolicy,
    pub command_summary: String,
    pub elapsed_ms: Option<u64>,
    pub target_dir: Option<String>,
    pub touched_paths: Vec<String>,
    pub reservation_refs: Vec<String>,
    pub evidence_links: Vec<String>,
    pub uses_rch: bool,
    pub local_cpu_sensitive: bool,
    pub disk_impacting: bool,
    pub validation_outcome: AgentCommandValidationOutcome,
    pub stale_in_progress_claim: bool,
    pub violations: Vec<AgentCommandPolicyViolation>,
}

impl AgentCommandBudgetEntry {
    #[must_use]
    pub fn new(
        command_id: impl Into<String>,
        family: AgentCommandFamily,
        cost_class: AgentCommandCostClass,
        execution_policy: AgentCommandExecutionPolicy,
        command_summary: impl Into<String>,
    ) -> Self {
        Self {
            command_id: command_id.into(),
            family,
            cost_class,
            execution_policy,
            command_summary: command_summary.into(),
            elapsed_ms: None,
            target_dir: None,
            touched_paths: Vec::new(),
            reservation_refs: Vec::new(),
            evidence_links: Vec::new(),
            uses_rch: matches!(
                execution_policy,
                AgentCommandExecutionPolicy::RchRequired | AgentCommandExecutionPolicy::RchUsed
            ),
            local_cpu_sensitive: matches!(
                cost_class,
                AgentCommandCostClass::LocalCpuSensitive | AgentCommandCostClass::RchRemote
            ),
            disk_impacting: matches!(cost_class, AgentCommandCostClass::DiskImpacting),
            validation_outcome: AgentCommandValidationOutcome::NotRun,
            stale_in_progress_claim: false,
            violations: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_elapsed_ms(mut self, elapsed_ms: u64) -> Self {
        self.elapsed_ms = Some(elapsed_ms);
        self
    }

    #[must_use]
    pub fn with_target_dir(mut self, target_dir: impl Into<String>) -> Self {
        self.target_dir = Some(target_dir.into());
        self
    }

    #[must_use]
    pub fn with_touched_paths<I, T>(mut self, touched_paths: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.touched_paths = touched_paths.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_reservation_refs<I, T>(mut self, reservation_refs: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.reservation_refs = reservation_refs.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_evidence_links<I, T>(mut self, evidence_links: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.evidence_links = evidence_links.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub const fn with_uses_rch(mut self, uses_rch: bool) -> Self {
        self.uses_rch = uses_rch;
        self
    }

    #[must_use]
    pub const fn with_local_cpu_sensitive(mut self, local_cpu_sensitive: bool) -> Self {
        self.local_cpu_sensitive = local_cpu_sensitive;
        self
    }

    #[must_use]
    pub const fn with_disk_impacting(mut self, disk_impacting: bool) -> Self {
        self.disk_impacting = disk_impacting;
        self
    }

    #[must_use]
    pub const fn with_validation_outcome(
        mut self,
        validation_outcome: AgentCommandValidationOutcome,
    ) -> Self {
        self.validation_outcome = validation_outcome;
        self
    }

    #[must_use]
    pub const fn with_stale_in_progress_claim(mut self, stale_in_progress_claim: bool) -> Self {
        self.stale_in_progress_claim = stale_in_progress_claim;
        self
    }

    fn validated(mut self) -> Result<Self, AgentCommandLedgerError> {
        validate_required_ledger_text("command_id", &self.command_id)?;
        validate_required_ledger_text("command_summary", &self.command_summary)?;
        self.command_summary = redact_protected_command_text(&self.command_summary);
        validate_optional_ledger_path("target_dir", self.target_dir.as_deref())?;
        validate_ledger_items("touched_paths", &self.touched_paths, true)?;
        validate_ledger_items("reservation_refs", &self.reservation_refs, false)?;
        validate_ledger_items("evidence_links", &self.evidence_links, false)?;
        self.violations = self.derive_policy_violations();
        Ok(self)
    }

    fn derive_policy_violations(&self) -> Vec<AgentCommandPolicyViolation> {
        let mut violations = Vec::new();

        if self.family == AgentCommandFamily::Cargo && !self.uses_rch {
            violations.push(AgentCommandPolicyViolation::BareCargo);
        }

        if self.family == AgentCommandFamily::Cargo && self.local_cpu_sensitive && !self.uses_rch {
            violations.push(AgentCommandPolicyViolation::MissingRchForCargo);
        }

        if command_summary_has_unsafe_delete(&self.command_summary) {
            violations.push(AgentCommandPolicyViolation::UnsafeDeleteAttempt);
        }

        if self
            .touched_paths
            .iter()
            .any(|path| path_requires_reservation(path))
            && self.reservation_refs.is_empty()
        {
            violations.push(AgentCommandPolicyViolation::UnreservedCodeEdit);
        }

        if self.stale_in_progress_claim {
            violations.push(AgentCommandPolicyViolation::StaleInProgressClaim);
        }

        violations.sort();
        violations.dedup();
        violations
    }
}

/// Bounded summary computed from agent command budget entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCommandLedgerSummary {
    pub command_count: usize,
    pub rch_submissions: usize,
    pub local_cpu_sensitive_operations: usize,
    pub disk_impacting_operations: usize,
    pub validation_passed: usize,
    pub validation_failed: usize,
    pub validation_blocked: usize,
    pub commands_with_violations: usize,
    pub policy_violation_count: usize,
}

impl AgentCommandLedgerSummary {
    fn from_entries(entries: &[AgentCommandBudgetEntry]) -> Self {
        Self {
            command_count: entries.len(),
            rch_submissions: entries.iter().filter(|entry| entry.uses_rch).count(),
            local_cpu_sensitive_operations: entries
                .iter()
                .filter(|entry| entry.local_cpu_sensitive)
                .count(),
            disk_impacting_operations: entries.iter().filter(|entry| entry.disk_impacting).count(),
            validation_passed: entries
                .iter()
                .filter(|entry| entry.validation_outcome == AgentCommandValidationOutcome::Passed)
                .count(),
            validation_failed: entries
                .iter()
                .filter(|entry| entry.validation_outcome == AgentCommandValidationOutcome::Failed)
                .count(),
            validation_blocked: entries
                .iter()
                .filter(|entry| entry.validation_outcome == AgentCommandValidationOutcome::Blocked)
                .count(),
            commands_with_violations: entries
                .iter()
                .filter(|entry| !entry.violations.is_empty())
                .count(),
            policy_violation_count: entries.iter().map(|entry| entry.violations.len()).sum(),
        }
    }
}

/// Agent session command/resource budget ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCommandBudgetLedger {
    pub schema_version: String,
    pub session_id: String,
    pub agent_name: String,
    pub bead_id: Option<String>,
    pub entries: Vec<AgentCommandBudgetEntry>,
    pub summary: AgentCommandLedgerSummary,
}

impl AgentCommandBudgetLedger {
    pub fn try_new(
        session_id: impl Into<String>,
        agent_name: impl Into<String>,
        bead_id: Option<String>,
        entries: Vec<AgentCommandBudgetEntry>,
    ) -> Result<Self, AgentCommandLedgerError> {
        if entries.len() > MAX_AGENT_COMMAND_LEDGER_ENTRIES {
            return Err(AgentCommandLedgerError::TooManyEntries {
                count: entries.len(),
                max: MAX_AGENT_COMMAND_LEDGER_ENTRIES,
            });
        }

        let session_id = session_id.into();
        let agent_name = agent_name.into();
        validate_required_ledger_text("session_id", &session_id)?;
        validate_required_ledger_text("agent_name", &agent_name)?;
        validate_optional_ledger_text("bead_id", bead_id.as_deref())?;

        let mut validated_entries = Vec::with_capacity(entries.len());
        for entry in entries {
            validated_entries.push(entry.validated()?);
        }
        let summary = AgentCommandLedgerSummary::from_entries(&validated_entries);

        Ok(Self {
            schema_version: AGENT_COMMAND_LEDGER_SCHEMA_VERSION.to_string(),
            session_id,
            agent_name,
            bead_id,
            entries: validated_entries,
            summary,
        })
    }
}

pub fn render_agent_command_ledger_human(ledger: &AgentCommandBudgetLedger) -> String {
    format!(
        "agent command ledger: session={} agent={} bead={} commands={} rch_submissions={} local_cpu_sensitive={} disk_impacting={} validation_passed={} validation_failed={} validation_blocked={} commands_with_violations={} policy_violations={}",
        ledger.session_id,
        ledger.agent_name,
        ledger.bead_id.as_deref().unwrap_or("none"),
        ledger.summary.command_count,
        ledger.summary.rch_submissions,
        ledger.summary.local_cpu_sensitive_operations,
        ledger.summary.disk_impacting_operations,
        ledger.summary.validation_passed,
        ledger.summary.validation_failed,
        ledger.summary.validation_blocked,
        ledger.summary.commands_with_violations,
        ledger.summary.policy_violation_count
    )
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentCommandLedgerError {
    #[error("AGENT_COMMAND_LEDGER_TOO_MANY_ENTRIES: ledger has {count} entries, max {max}")]
    TooManyEntries { count: usize, max: usize },
    #[error("AGENT_COMMAND_LEDGER_TOO_MANY_ITEMS: {field} has {count} items, max {max}")]
    TooManyItems {
        field: &'static str,
        count: usize,
        max: usize,
    },
    #[error("AGENT_COMMAND_LEDGER_EMPTY_FIELD: {field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("AGENT_COMMAND_LEDGER_STRING_TOO_LONG: {field} has {len} bytes, max {max}")]
    StringTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    #[error("AGENT_COMMAND_LEDGER_NUL_PATH: {field} contains a nul byte")]
    PathContainsNul { field: &'static str },
    #[error("AGENT_COMMAND_LEDGER_PATH_TRAVERSAL: {field} contains parent traversal")]
    PathTraversal { field: &'static str },
}

/// Workspace build admission policy engine.
#[derive(Debug, Clone)]
pub struct WorkspacePressurePolicy {
    /// Configuration thresholds for admission decisions.
    pub thresholds: PolicyThresholds,
}

/// Policy thresholds for workspace pressure decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyThresholds {
    /// Minimum free disk bytes before blocking new work.
    pub min_free_disk_bytes: u64,
    /// Maximum target directory size before cleanup suggestions.
    pub max_target_dir_bytes: u64,
    /// Maximum concurrent builds before RCH requirement.
    pub max_concurrent_builds: u32,
    /// Memory pressure threshold for build restrictions (0.0-1.0).
    pub max_memory_pressure: f32,
    /// Maximum active reservations before coordination warnings.
    pub max_active_reservations: u32,
}

impl PolicyThresholds {
    /// Create conservative default thresholds suitable for shared environments.
    pub fn conservative() -> Self {
        Self {
            min_free_disk_bytes: 1_000_000_000,  // 1GB
            max_target_dir_bytes: 5_000_000_000, // 5GB
            max_concurrent_builds: 3,
            max_memory_pressure: 0.8,
            max_active_reservations: 20,
        }
    }

    /// Create balanced default thresholds for typical development.
    pub fn balanced() -> Self {
        Self {
            min_free_disk_bytes: 500_000_000,     // 500MB
            max_target_dir_bytes: 10_000_000_000, // 10GB
            max_concurrent_builds: 5,
            max_memory_pressure: 0.9,
            max_active_reservations: 50,
        }
    }

    /// Create permissive thresholds for high-capacity environments.
    pub fn permissive() -> Self {
        Self {
            min_free_disk_bytes: 100_000_000,     // 100MB
            max_target_dir_bytes: 50_000_000_000, // 50GB
            max_concurrent_builds: 10,
            max_memory_pressure: 0.95,
            max_active_reservations: 100,
        }
    }
}

impl WorkspacePressurePolicy {
    /// Create a new policy with the given thresholds.
    pub fn new(thresholds: PolicyThresholds) -> Self {
        Self { thresholds }
    }

    /// Create a policy with balanced default thresholds.
    pub fn with_balanced_defaults() -> Self {
        Self::new(PolicyThresholds::balanced())
    }

    /// Make an admission decision for the given work and pressure inputs.
    pub fn decide_admission(
        &self,
        work_class: WorkCostClass,
        priority: u32,
        inputs: &WorkspacePressureInputs,
    ) -> PolicyDecision {
        let mut diagnostic_reasons = Vec::new();
        let mut cleanup_candidates = Vec::new();

        // Analyze disk pressure
        let disk_pressure =
            self.analyze_disk_pressure(inputs, &mut diagnostic_reasons, &mut cleanup_candidates);

        // Analyze build pressure
        let build_pressure = self.analyze_build_pressure(inputs, &mut diagnostic_reasons);

        // Analyze memory pressure
        let memory_pressure = self.analyze_memory_pressure(inputs, &mut diagnostic_reasons);

        // Analyze coordination health
        let coordination_issues = self.analyze_coordination_health(inputs, &mut diagnostic_reasons);

        // Make admission decision based on analysis
        let admission = self.compute_admission_decision(
            work_class,
            priority,
            inputs,
            disk_pressure,
            build_pressure,
            memory_pressure,
            coordination_issues,
            &mut diagnostic_reasons,
        );

        // Compute overall confidence
        let confidence = self.compute_confidence(
            &admission,
            inputs,
            disk_pressure,
            build_pressure,
            memory_pressure,
        );

        // Generate reason code and summary
        let (reason_code, summary) =
            self.generate_reason_and_summary(&admission, work_class, &diagnostic_reasons);

        PolicyDecision {
            admission,
            cleanup_candidates,
            reason_code,
            summary,
            diagnostic_reasons: limit_diagnostics(diagnostic_reasons),
            confidence,
        }
    }

    /// Build read-only hardware placement evidence from workspace pressure.
    pub fn plan_hardware_placement(
        &self,
        input: WorkspaceHardwarePlacementInput,
    ) -> WorkspaceHardwarePlacementDecision {
        let policy_decision =
            self.decide_admission(input.work_class, input.bead_priority, &input.workspace);
        let mut diagnostics = policy_decision.diagnostic_reasons.clone();
        if input
            .topology
            .as_ref()
            .and_then(|topology| topology.numa_nodes)
            .unwrap_or(0)
            == 0
        {
            push_bounded(
                &mut diagnostics,
                "NUMA topology unavailable; placement evidence downgraded".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
        }

        let (action, reason_code, fail_closed) =
            hardware_bridge_action(&input, &policy_decision.admission);
        let mut approved_dispatch_notes = Vec::new();
        let mut placement_decision = None;
        let mut target_profile_id = None;

        if matches!(
            action,
            OperatorWhatIfAction::Allow | OperatorWhatIfAction::RequireRch
        ) {
            match build_hardware_bridge_placement(&input, action) {
                Ok(decision) => {
                    target_profile_id = decision.target_profile_id.clone();
                    push_bounded(
                        &mut approved_dispatch_notes,
                        hardware_bridge_dispatch_note(&input, action),
                        MAX_DIAGNOSTIC_REASONS,
                    );
                    placement_decision = Some(decision);
                }
                Err(message) => {
                    push_bounded(&mut diagnostics, message, MAX_DIAGNOSTIC_REASONS);
                    return WorkspaceHardwarePlacementDecision {
                        schema_version: WORKSPACE_HARDWARE_ADMISSION_SCHEMA_VERSION.to_string(),
                        bridge_id: input.bridge_id,
                        workload_id: input.workload_id,
                        action: OperatorWhatIfAction::RefuseLocalFallback,
                        reason_code: "HWP_BRIDGE_PLACEMENT_FAILED".to_string(),
                        policy_decision,
                        placement_decision: None,
                        target_profile_id: None,
                        approved_dispatch_notes,
                        diagnostics: limit_diagnostics(diagnostics),
                        fail_closed: true,
                    };
                }
            }
        }

        WorkspaceHardwarePlacementDecision {
            schema_version: WORKSPACE_HARDWARE_ADMISSION_SCHEMA_VERSION.to_string(),
            bridge_id: input.bridge_id,
            workload_id: input.workload_id,
            action,
            reason_code,
            policy_decision,
            placement_decision,
            target_profile_id,
            approved_dispatch_notes,
            diagnostics: limit_diagnostics(diagnostics),
            fail_closed,
        }
    }

    /// Plan an isolated target directory for validation work without mutating the filesystem.
    pub fn plan_target_dir_lease(&self, input: TargetDirLeasePlanInput) -> TargetDirLeasePlan {
        let mut diagnostics = Vec::new();
        let mut cleanup_recommendations = Vec::new();
        let minimum_free_bytes = self.thresholds.min_free_disk_bytes;

        if input.roots.len() > MAX_TARGET_DIR_LEASE_CANDIDATES
            || input.active_reservation_hints.len() > MAX_TARGET_DIR_LEASE_CANDIDATES
        {
            return fail_closed_target_dir_lease_plan(
                input.plan_id,
                input.bead_id,
                target_dir_lease_reason_codes::FAIL_TOO_MANY_ITEMS,
                "target-dir lease input exceeded bounded candidate limits".to_string(),
            );
        }

        if !input.memory_pressure.is_finite() {
            return fail_closed_target_dir_lease_plan(
                input.plan_id,
                input.bead_id,
                target_dir_lease_reason_codes::FAIL_INVALID_MEMORY,
                "target-dir lease memory pressure was not finite".to_string(),
            );
        }

        if input
            .topology
            .as_ref()
            .is_some_and(|topology| topology.stale)
        {
            return fail_closed_target_dir_lease_plan(
                input.plan_id,
                input.bead_id,
                target_dir_lease_reason_codes::FAIL_STALE_TOPOLOGY,
                "target-dir lease topology snapshot was stale".to_string(),
            );
        }

        if target_dir_lease_path_is_unsafe(&input.workspace_root) {
            return fail_closed_target_dir_lease_plan(
                input.plan_id,
                input.bead_id,
                target_dir_lease_reason_codes::FAIL_UNSAFE_PATH,
                "target-dir lease workspace root was unsafe".to_string(),
            );
        }

        if input.roots.is_empty() {
            return fail_closed_target_dir_lease_plan(
                input.plan_id,
                input.bead_id,
                target_dir_lease_reason_codes::FAIL_NO_ROOTS,
                "target-dir lease plan had no candidate roots".to_string(),
            );
        }

        for hint in &input.active_reservation_hints {
            if target_dir_lease_path_is_unsafe(&hint.path) || hint.holder.trim().is_empty() {
                return fail_closed_target_dir_lease_plan(
                    input.plan_id,
                    input.bead_id,
                    target_dir_lease_reason_codes::FAIL_UNSAFE_PATH,
                    "target-dir lease reservation hint was unsafe".to_string(),
                );
            }
        }

        if input
            .topology
            .as_ref()
            .and_then(|topology| topology.numa_nodes)
            .unwrap_or(0)
            == 0
        {
            push_bounded(
                &mut diagnostics,
                "NUMA topology unavailable; target-dir ranking uses disk and lease signals only"
                    .to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
        }

        let mut candidates = Vec::with_capacity(input.roots.len());
        for root in &input.roots {
            if target_dir_lease_path_is_unsafe(&root.path) {
                return fail_closed_target_dir_lease_plan(
                    input.plan_id,
                    input.bead_id,
                    target_dir_lease_reason_codes::FAIL_UNSAFE_PATH,
                    format!("target-dir lease root was unsafe: {}", root.path),
                );
            }

            candidates.push(build_target_dir_lease_candidate(
                &input,
                root,
                minimum_free_bytes,
                target_dir_reservation_count_for_root(root, &input.active_reservation_hints),
                &mut cleanup_recommendations,
            ));
        }

        candidates.sort_by(|left, right| {
            left.fail_closed
                .cmp(&right.fail_closed)
                .then_with(|| right.score.cmp(&left.score))
                .then_with(|| left.path.cmp(&right.path))
        });

        let selected_path = candidates
            .iter()
            .find(|candidate| !candidate.fail_closed)
            .map(|candidate| candidate.path.clone());
        let selected_reason_code = candidates
            .iter()
            .find(|candidate| !candidate.fail_closed)
            .map(|candidate| candidate.reason_code.clone())
            .unwrap_or_else(|| target_dir_lease_reason_codes::FAIL_NO_ELIGIBLE_ROOT.to_string());
        let fail_closed = selected_path.is_none();

        if fail_closed {
            push_bounded(
                &mut diagnostics,
                "no eligible target-dir lease root remained after policy filtering".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
        }

        let human_summary = render_target_dir_lease_plan_human_parts(
            &input.bead_id,
            selected_path.as_deref(),
            &selected_reason_code,
            candidates.len(),
            cleanup_recommendations.len(),
            fail_closed,
        );

        TargetDirLeasePlan {
            schema_version: TARGET_DIR_LEASE_PLAN_SCHEMA_VERSION.to_string(),
            plan_id: input.plan_id,
            bead_id: input.bead_id,
            selected_path,
            selected_reason_code,
            candidates,
            cleanup_recommendations,
            diagnostics: limit_diagnostics(diagnostics),
            fail_closed,
            human_summary,
        }
    }

    /// Propose cleanup candidates without requiring work admission.
    pub fn propose_cleanup(&self, inputs: &WorkspacePressureInputs) -> Vec<CleanupCandidate> {
        let mut candidates = Vec::new();

        // Add target directory cleanup candidates if over threshold
        if inputs.target_dir_bytes > self.thresholds.max_target_dir_bytes {
            candidates.push(CleanupCandidate {
                path: "target".into(),
                size_bytes: inputs
                    .target_dir_bytes
                    .saturating_sub(self.thresholds.max_target_dir_bytes / 2),
                reason: "Large target directory detected".to_string(),
                requires_approval: true,
                mtime: None,
            });
        }

        // Add temp file cleanup candidates if disk pressure high
        if inputs.free_disk_bytes < self.thresholds.min_free_disk_bytes.saturating_mul(2)
            && let Ok(temp_size) = estimate_temp_artifacts_size()
            && temp_size > 100_000_000
        {
            candidates.push(CleanupCandidate {
                path: "/tmp/cargo-*".into(),
                size_bytes: temp_size,
                reason: "Temporary cargo artifacts consuming space".to_string(),
                requires_approval: false,
                mtime: None,
            });
        }

        candidates
    }

    /// Simulate an operator decision without executing validation or cleanup.
    pub fn simulate_operator_what_if(&self, input: OperatorWhatIfInput) -> OperatorWhatIfReport {
        let mut logs = Vec::new();
        push_operator_log(
            &mut logs,
            "OP-WHATIF-001",
            format!(
                "simulating scenario={} work_class={:?} priority={}",
                input.scenario_id, input.work_class, input.bead_priority
            ),
        );

        let policy_decision =
            self.decide_admission(input.work_class, input.bead_priority, &input.workspace);
        let mut action = OperatorWhatIfAction::from_admission(&policy_decision.admission);
        let mut retry_after_ms = admission_retry_after_ms(&policy_decision.admission);
        let mut reason_code = operator_reason_code_for_action(action).to_string();
        let rch_stale_progress = build_rch_stale_progress(&input.rch_queue);

        if command_summary_has_unsafe_delete(input.requested_command.as_deref().unwrap_or_default())
        {
            action = OperatorWhatIfAction::RefuseLocalFallback;
            retry_after_ms = None;
            reason_code = "OP_WHATIF_REFUSE_UNSAFE_COMMAND".to_string();
            push_operator_log(
                &mut logs,
                "OP-WHATIF-007",
                "unsafe filesystem command refused during simulation".to_string(),
            );
        } else if input
            .stale_sibling_blocker
            .as_deref()
            .is_some_and(|blocker| !blocker.trim().is_empty())
        {
            action = OperatorWhatIfAction::Wait;
            retry_after_ms = Some(30_000);
            reason_code = "OP_WHATIF_WAIT_SIBLING_BLOCKER".to_string();
            push_operator_log(
                &mut logs,
                "OP-WHATIF-006",
                "stale sibling blocker requires a fresh proof before launch".to_string(),
            );
        } else if input.work_class.prefers_rch() && rch_stale_progress.is_some() {
            action = OperatorWhatIfAction::Wait;
            retry_after_ms = Some(60_000);
            reason_code = "VAL_DEFER_RCH_STALE".to_string();
            if let Some(progress) = &rch_stale_progress {
                push_operator_log(
                    &mut logs,
                    "OP-WHATIF-010",
                    format!(
                        "RCH stale-progress active builds observed: {}; safe_next_action={}",
                        render_rch_stale_build_refs(progress),
                        progress.safe_next_action
                    ),
                );
            }
        } else if input.rch_queue.available_slots == Some(0) && input.work_class.prefers_rch() {
            action = OperatorWhatIfAction::Queue;
            retry_after_ms = Some(60_000);
            reason_code = "OP_WHATIF_QUEUE_RCH_SATURATED".to_string();
            push_operator_log(
                &mut logs,
                "OP-WHATIF-003",
                format!(
                    "RCH queue saturated with {} queued jobs",
                    input.rch_queue.queued_jobs
                ),
            );
        }

        let command_ledger_summary = input.command_ledger.as_ref().map(|ledger| {
            push_operator_log(
                &mut logs,
                "OP-WHATIF-004",
                format!(
                    "command ledger commands={} violations={}",
                    ledger.summary.command_count, ledger.summary.policy_violation_count
                ),
            );
            ledger.summary.clone()
        });

        if action == OperatorWhatIfAction::Allow
            && command_ledger_summary
                .as_ref()
                .is_some_and(|summary| summary.commands_with_violations > 0)
        {
            action = OperatorWhatIfAction::Wait;
            retry_after_ms = Some(10_000);
            reason_code = "OP_WHATIF_WAIT_COMMAND_LEDGER_VIOLATION".to_string();
            push_operator_log(
                &mut logs,
                "OP-WHATIF-008",
                "command ledger contains policy violations; operator should inspect first"
                    .to_string(),
            );
        }

        if input.rch_queue.degraded_workers > 0 {
            push_operator_log(
                &mut logs,
                "OP-WHATIF-009",
                format!(
                    "{} degraded RCH workers observed",
                    input.rch_queue.degraded_workers
                ),
            );
        }

        let cleanup_actions = build_operator_cleanup_actions(&input.artifacts, &mut logs);
        let pinned_artifact_count = input
            .artifacts
            .iter()
            .filter(|artifact| artifact.safety_class == OperatorWhatIfArtifactSafetyClass::Pinned)
            .count();
        let protected_artifact_count = input
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.safety_class == OperatorWhatIfArtifactSafetyClass::Protected
            })
            .count();
        let simulated_command = input
            .requested_command
            .as_deref()
            .map(|command| render_simulated_command(input.work_class, action, command));

        if matches!(
            action,
            OperatorWhatIfAction::RequireRch | OperatorWhatIfAction::Queue
        ) && simulated_command
            .as_deref()
            .is_some_and(|command| command.starts_with("rch exec --"))
        {
            push_operator_log(
                &mut logs,
                "OP-WHATIF-002",
                "cargo-heavy simulated command rendered through rch exec".to_string(),
            );
        }

        let human_summary = render_operator_what_if_human_summary(
            &input,
            action,
            &reason_code,
            retry_after_ms,
            simulated_command.as_deref(),
            cleanup_actions.len(),
            pinned_artifact_count,
            protected_artifact_count,
            rch_stale_progress.as_ref(),
        );

        OperatorWhatIfReport {
            schema_version: OPERATOR_WHAT_IF_SCHEMA_VERSION.to_string(),
            scenario_id: input.scenario_id,
            bead_id: input.bead_id,
            action,
            reason_code,
            retry_after_ms,
            simulated_command,
            cleanup_actions,
            pinned_artifact_count,
            protected_artifact_count,
            command_ledger_summary,
            rch_stale_progress,
            policy_decision,
            logs: limit_operator_logs(logs),
            human_summary,
        }
    }

    /// Build a deterministic decision receipt when Beads reports no ready work.
    pub fn plan_no_ready_autopilot(&self, input: NoReadyAutopilotInput) -> NoReadyAutopilotReceipt {
        let rch_stale_progress = build_rch_stale_progress(&input.rch_queue);
        let stale_in_progress_beads = collect_stale_in_progress_beads(&input.in_progress_beads);
        let blocked_evidence = limit_no_ready_blocked_evidence(&input.blocked_beads);

        let selected_action = select_no_ready_autopilot_action(
            &input,
            &stale_in_progress_beads,
            &blocked_evidence,
            rch_stale_progress.as_ref(),
        );
        let reason_code = no_ready_reason_code(selected_action).to_string();
        let safe_next_action = no_ready_safe_next_action(
            selected_action,
            &stale_in_progress_beads,
            &blocked_evidence,
            rch_stale_progress.as_ref(),
        );
        let rejected_alternatives = build_no_ready_rejected_alternatives(
            selected_action,
            &input,
            &stale_in_progress_beads,
            &blocked_evidence,
            rch_stale_progress.as_ref(),
        );
        let pasteable_beads_note = render_no_ready_pasteable_note(
            &input,
            selected_action,
            &reason_code,
            &safe_next_action,
            &stale_in_progress_beads,
            &blocked_evidence,
            rch_stale_progress.as_ref(),
        );
        let human_summary = render_no_ready_human_summary(
            &input,
            selected_action,
            &reason_code,
            &safe_next_action,
            stale_in_progress_beads.len(),
            blocked_evidence.len(),
            rch_stale_progress.as_ref(),
        );

        NoReadyAutopilotReceipt {
            schema_version: NO_READY_AUTOPILOT_SCHEMA_VERSION.to_string(),
            receipt_id: input.receipt_id,
            workspace_root: input.workspace_root,
            selected_action,
            reason_code,
            safe_next_action,
            ready_issue_count: input.ready_issue_count,
            open_issue_count: input.open_issue_count,
            blocked_issue_count: input.blocked_issue_count,
            stale_in_progress_beads,
            blocked_evidence,
            rch_stale_progress,
            rejected_alternatives,
            pasteable_beads_note,
            human_summary,
        }
    }

    /// Build a deterministic handoff envelope for sibling-repo or build-infrastructure blockers.
    pub fn build_cross_repo_blocker_envelope(
        &self,
        input: CrossRepoBlockerEnvelopeInput,
    ) -> CrossRepoBlockerEnvelope {
        let observed_matches_required =
            input.observed_revision.as_deref() == Some(input.required_committed_revision.as_str());
        let retry_validation_allowed =
            input.observed_revision_committed && observed_matches_required;
        let sufficient_to_unblock = retry_validation_allowed;
        let beads_status_change_allowed = false;
        let reason_code = cross_repo_blocker_reason_code(
            input.blocker_origin,
            input.observed_revision_committed,
            observed_matches_required,
        )
        .to_string();
        let safe_next_action = cross_repo_blocker_safe_next_action(
            &input,
            retry_validation_allowed,
            observed_matches_required,
        );
        let pasteable_beads_note = render_cross_repo_blocker_beads_note(
            &input,
            &reason_code,
            retry_validation_allowed,
            sufficient_to_unblock,
            beads_status_change_allowed,
            &safe_next_action,
        );
        let agent_mail_handoff_body = render_cross_repo_blocker_agent_mail_body(
            &input,
            &reason_code,
            retry_validation_allowed,
            &safe_next_action,
        );
        let human_summary = render_cross_repo_blocker_human_summary(
            &input,
            &reason_code,
            retry_validation_allowed,
            sufficient_to_unblock,
            &safe_next_action,
        );

        CrossRepoBlockerEnvelope {
            schema_version: CROSS_REPO_BLOCKER_ENVELOPE_SCHEMA_VERSION.to_string(),
            envelope_id: input.envelope_id,
            franken_node_bead_id: input.franken_node_bead_id,
            blocker_origin: input.blocker_origin,
            next_owner: input.next_owner,
            sibling_project: input.sibling_project,
            sibling_bead_id: input.sibling_bead_id,
            agent_mail_thread_id: input.agent_mail_thread_id,
            agent_mail_message_id: input.agent_mail_message_id,
            rch_build_id: input.rch_build_id,
            required_committed_revision: input.required_committed_revision,
            observed_revision: input.observed_revision,
            observed_revision_committed: input.observed_revision_committed,
            validation_command: input.validation_command,
            first_blocker_line: input.first_blocker_line,
            retry_validation_allowed,
            sufficient_to_unblock,
            beads_status_change_allowed,
            reason_code,
            safe_next_action,
            pasteable_beads_note,
            agent_mail_handoff_body,
            human_summary,
        }
    }

    fn analyze_disk_pressure(
        &self,
        inputs: &WorkspacePressureInputs,
        diagnostics: &mut Vec<String>,
        cleanup_candidates: &mut Vec<CleanupCandidate>,
    ) -> f32 {
        let disk_pressure = if inputs.free_disk_bytes < self.thresholds.min_free_disk_bytes {
            push_bounded(
                diagnostics,
                "Critical disk space shortage".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );

            // Suggest cleanup candidates
            cleanup_candidates.extend(self.propose_cleanup(inputs));

            1.0
        } else if inputs.free_disk_bytes < self.thresholds.min_free_disk_bytes.saturating_mul(2) {
            push_bounded(
                diagnostics,
                "Low disk space warning".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            0.7
        } else {
            0.0
        };

        if inputs.target_dir_bytes > self.thresholds.max_target_dir_bytes {
            push_bounded(
                diagnostics,
                "Target directories consuming excessive space".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
        }

        disk_pressure
    }

    fn analyze_build_pressure(
        &self,
        inputs: &WorkspacePressureInputs,
        diagnostics: &mut Vec<String>,
    ) -> f32 {
        if inputs.active_build_count > self.thresholds.max_concurrent_builds {
            push_bounded(
                diagnostics,
                "High concurrent build activity".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            0.8
        } else if inputs.active_build_count > self.thresholds.max_concurrent_builds / 2 {
            push_bounded(
                diagnostics,
                "Moderate build activity".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            0.4
        } else {
            0.0
        }
    }

    fn analyze_memory_pressure(
        &self,
        inputs: &WorkspacePressureInputs,
        diagnostics: &mut Vec<String>,
    ) -> f32 {
        if inputs.memory_pressure > self.thresholds.max_memory_pressure {
            push_bounded(
                diagnostics,
                "High memory pressure detected".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            inputs.memory_pressure
        } else {
            0.0
        }
    }

    fn analyze_coordination_health(
        &self,
        inputs: &WorkspacePressureInputs,
        diagnostics: &mut Vec<String>,
    ) -> bool {
        if !inputs.coordination_healthy {
            push_bounded(
                diagnostics,
                "Agent coordination degraded".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            return true;
        }

        if inputs.active_reservations > self.thresholds.max_active_reservations {
            push_bounded(
                diagnostics,
                "High file reservation contention".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            return true;
        }

        false
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "admission scoring intentionally keeps the normalized pressure inputs visible"
    )]
    fn compute_admission_decision(
        &self,
        work_class: WorkCostClass,
        priority: u32,
        inputs: &WorkspacePressureInputs,
        disk_pressure: f32,
        build_pressure: f32,
        memory_pressure: f32,
        coordination_issues: bool,
        diagnostics: &mut Vec<String>,
    ) -> AdmissionDecision {
        // Critical disk pressure blocks most work
        if disk_pressure >= 1.0 && work_class != WorkCostClass::SourceOnly {
            return AdmissionDecision::RefuseLocalFallback;
        }

        // High memory pressure limits work
        if memory_pressure > 0.9 && work_class.cost_weight() > 2 {
            return AdmissionDecision::Queue {
                retry_after_ms: 30000,
            };
        }

        // RCH availability check
        match inputs.rch_available_slots {
            Some(slots) if slots > 0 => {
                // RCH available - use it for expensive work or high pressure
                if work_class.prefers_rch() || build_pressure > 0.5 || disk_pressure > 0.5 {
                    push_bounded(
                        diagnostics,
                        "Offloading to RCH for resource management".to_string(),
                        MAX_DIAGNOSTIC_REASONS,
                    );
                    return AdmissionDecision::RequireRch;
                }
            }
            Some(_) => {
                // RCH saturated
                if work_class.prefers_rch() && (build_pressure > 0.7 || memory_pressure > 0.8) {
                    push_bounded(
                        diagnostics,
                        "RCH saturated, queueing expensive work".to_string(),
                        MAX_DIAGNOSTIC_REASONS,
                    );
                    return AdmissionDecision::Queue {
                        retry_after_ms: 60000,
                    };
                }
            }
            None => {
                // RCH unavailable
                if work_class.prefers_rch() && work_class.cost_weight() > 7 {
                    return AdmissionDecision::RefuseLocalFallback;
                }
            }
        }

        // Coordination issues affect cleanup and high-contention work
        if coordination_issues && matches!(work_class, WorkCostClass::Cleanup) {
            push_bounded(
                diagnostics,
                "Deferring cleanup due to coordination issues".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            return AdmissionDecision::Wait {
                retry_after_ms: 10000,
            };
        }

        // High priority work gets preference
        if priority >= 1 && work_class.cost_weight() <= 5 {
            push_bounded(
                diagnostics,
                "High priority work approved for local execution".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            return AdmissionDecision::AllowLocal;
        }

        // Default: allow local for low-cost work, moderate throttling for others
        if work_class.cost_weight() <= 3 || (build_pressure < 0.5 && memory_pressure < 0.7) {
            AdmissionDecision::AllowLocal
        } else {
            AdmissionDecision::Wait {
                retry_after_ms: 15000,
            }
        }
    }

    fn compute_confidence(
        &self,
        admission: &AdmissionDecision,
        inputs: &WorkspacePressureInputs,
        disk_pressure: f32,
        build_pressure: f32,
        memory_pressure: f32,
    ) -> f32 {
        // Higher confidence for clear decisions
        match admission {
            AdmissionDecision::RefuseLocalFallback => {
                if disk_pressure >= 1.0 || memory_pressure > 0.95 {
                    0.95 // Very confident in blocking critical pressure
                } else {
                    0.8
                }
            }
            AdmissionDecision::AllowLocal => {
                if disk_pressure < 0.3 && build_pressure < 0.3 && memory_pressure < 0.5 {
                    0.9 // Very confident in allowing when pressure is low
                } else {
                    0.7
                }
            }
            AdmissionDecision::RequireRch => {
                if inputs.rch_available_slots.is_some() {
                    0.85 // Confident when RCH is actually available
                } else {
                    0.6
                }
            }
            AdmissionDecision::Queue { .. } | AdmissionDecision::Wait { .. } => {
                0.75 // Moderate confidence in throttling decisions
            }
        }
    }

    fn generate_reason_and_summary(
        &self,
        admission: &AdmissionDecision,
        work_class: WorkCostClass,
        _diagnostics: &[String],
    ) -> (String, String) {
        let reason_code = match admission {
            AdmissionDecision::AllowLocal => "ADMIT_LOCAL",
            AdmissionDecision::RequireRch => "REQUIRE_RCH",
            AdmissionDecision::Queue { .. } => "QUEUE_PRESSURE",
            AdmissionDecision::Wait { .. } => "WAIT_THROTTLE",
            AdmissionDecision::RefuseLocalFallback => "REFUSE_CRITICAL",
        };

        let summary = match admission {
            AdmissionDecision::AllowLocal => {
                format!("{:?} work approved for local execution", work_class)
            }
            AdmissionDecision::RequireRch => {
                format!("{:?} work requires RCH offloading", work_class)
            }
            AdmissionDecision::Queue { retry_after_ms } => {
                format!(
                    "{:?} work queued, retry after {}ms",
                    work_class, retry_after_ms
                )
            }
            AdmissionDecision::Wait { retry_after_ms } => {
                format!("{:?} work throttled, wait {}ms", work_class, retry_after_ms)
            }
            AdmissionDecision::RefuseLocalFallback => {
                format!("{:?} work refused due to critical pressure", work_class)
            }
        };

        (reason_code.to_string(), summary)
    }
}

fn admission_retry_after_ms(admission: &AdmissionDecision) -> Option<u32> {
    match admission {
        AdmissionDecision::Queue { retry_after_ms }
        | AdmissionDecision::Wait { retry_after_ms } => Some(*retry_after_ms),
        AdmissionDecision::AllowLocal
        | AdmissionDecision::RequireRch
        | AdmissionDecision::RefuseLocalFallback => None,
    }
}

fn operator_reason_code_for_action(action: OperatorWhatIfAction) -> &'static str {
    match action {
        OperatorWhatIfAction::Allow => "OP_WHATIF_ALLOW",
        OperatorWhatIfAction::Wait => "OP_WHATIF_WAIT",
        OperatorWhatIfAction::Queue => "OP_WHATIF_QUEUE",
        OperatorWhatIfAction::RequireRch => "OP_WHATIF_REQUIRE_RCH",
        OperatorWhatIfAction::RefuseLocalFallback => "OP_WHATIF_REFUSE_LOCAL_FALLBACK",
    }
}

fn push_operator_log(logs: &mut Vec<OperatorWhatIfLog>, event_code: &'static str, message: String) {
    push_bounded(
        logs,
        OperatorWhatIfLog {
            event_code: event_code.to_string(),
            message,
        },
        MAX_OPERATOR_WHAT_IF_LOGS,
    );
}

fn limit_operator_logs(mut logs: Vec<OperatorWhatIfLog>) -> Vec<OperatorWhatIfLog> {
    if logs.len() > MAX_OPERATOR_WHAT_IF_LOGS {
        logs.truncate(MAX_OPERATOR_WHAT_IF_LOGS);
        logs.push(OperatorWhatIfLog {
            event_code: "OP-WHATIF-TRUNCATED".to_string(),
            message: "additional what-if logs truncated".to_string(),
        });
    }
    logs
}

fn build_rch_stale_progress(
    rch_queue: &OperatorWhatIfRchQueueState,
) -> Option<OperatorWhatIfRchStaleProgress> {
    let mut active_builds = Vec::new();
    for build in &rch_queue.active_builds {
        if build.heartbeat_fresh && build.progress_stale {
            push_bounded(
                &mut active_builds,
                build.clone(),
                MAX_OPERATOR_RCH_BUILD_STATES,
            );
        }
    }

    if active_builds.is_empty() {
        return None;
    }

    Some(OperatorWhatIfRchStaleProgress {
        active_builds,
        safe_next_action: "Do not enqueue additional heavy cargo work; preserve the exact blocker command/output and wait for RCH progress or cancel only a build you own after confirming stale progress.".to_string(),
    })
}

fn render_rch_stale_build_refs(progress: &OperatorWhatIfRchStaleProgress) -> String {
    progress
        .active_builds
        .iter()
        .map(|build| {
            format!(
                "{}@{}:fresh_heartbeat={}:stale_progress={}:progress_age_secs={}",
                build.build_id,
                build.worker_id,
                build.heartbeat_fresh,
                build.progress_stale,
                build
                    .progress_age_secs
                    .map(|age| age.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn build_operator_cleanup_actions(
    artifacts: &[OperatorWhatIfArtifact],
    logs: &mut Vec<OperatorWhatIfLog>,
) -> Vec<OperatorWhatIfCleanupAction> {
    let mut actions = Vec::new();

    for artifact in artifacts {
        match artifact.safety_class {
            OperatorWhatIfArtifactSafetyClass::CleanupEligible => {
                if actions.len() < MAX_OPERATOR_WHAT_IF_CLEANUP_ACTIONS {
                    actions.push(OperatorWhatIfCleanupAction {
                        path: artifact.path.clone(),
                        size_bytes: artifact.size_bytes,
                        reason: artifact.reason.clone(),
                        dry_run_command: format!(
                            "franken-node ops resource-governor --cleanup-mode --dry-run --candidate {}",
                            artifact.path
                        ),
                    });
                }
            }
            OperatorWhatIfArtifactSafetyClass::Pinned => {
                push_operator_log(
                    logs,
                    "OP-WHATIF-005",
                    format!("pinned artifact excluded from cleanup: {}", artifact.path),
                );
            }
            OperatorWhatIfArtifactSafetyClass::Protected => {
                push_operator_log(
                    logs,
                    "OP-WHATIF-005",
                    format!(
                        "protected artifact excluded from cleanup: {}",
                        artifact.path
                    ),
                );
            }
        }
    }

    actions.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.size_bytes.cmp(&right.size_bytes))
            .then(left.reason.cmp(&right.reason))
    });
    actions
}

fn render_simulated_command(
    _work_class: WorkCostClass,
    _action: OperatorWhatIfAction,
    command: &str,
) -> String {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("rch exec --") {
        return redact_protected_command_text(trimmed);
    }

    let cargo_heavy = command_is_cargo_heavy(trimmed);
    if cargo_heavy {
        return redact_protected_command_text(&format!("rch exec -- {trimmed}"));
    }

    redact_protected_command_text(trimmed)
}

fn command_is_cargo_heavy(command: &str) -> bool {
    command == "cargo"
        || command.starts_with("cargo ")
        || command.starts_with("cargo\t")
        || command.contains(" cargo ")
}

#[expect(
    clippy::too_many_arguments,
    reason = "operator what-if summaries render independent contract fields explicitly"
)]
fn render_operator_what_if_human_summary(
    input: &OperatorWhatIfInput,
    action: OperatorWhatIfAction,
    reason_code: &str,
    retry_after_ms: Option<u32>,
    simulated_command: Option<&str>,
    cleanup_action_count: usize,
    pinned_artifact_count: usize,
    protected_artifact_count: usize,
    rch_stale_progress: Option<&OperatorWhatIfRchStaleProgress>,
) -> String {
    let rch_stale_builds = rch_stale_progress
        .map(render_rch_stale_build_refs)
        .unwrap_or_else(|| "none".to_string());
    let rch_safe_next_action = rch_stale_progress
        .map(|progress| progress.safe_next_action.as_str())
        .unwrap_or("none");

    format!(
        "operator what-if: scenario={} bead={} action={} reason={} retry_after_ms={} command={} cleanup_actions={} pinned_artifacts={} protected_artifacts={} rch_slots={:?} queued_jobs={} rch_stale_builds={} rch_safe_next_action={}",
        input.scenario_id,
        input.bead_id.as_deref().unwrap_or("none"),
        action.as_str(),
        reason_code,
        retry_after_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string()),
        simulated_command.unwrap_or("none"),
        cleanup_action_count,
        pinned_artifact_count,
        protected_artifact_count,
        input.rch_queue.available_slots,
        input.rch_queue.queued_jobs,
        rch_stale_builds,
        rch_safe_next_action,
    )
}

fn collect_stale_in_progress_beads(
    in_progress_beads: &[NoReadyInProgressBead],
) -> Vec<NoReadyInProgressBead> {
    let mut stale = Vec::new();
    for bead in in_progress_beads {
        if bead.updated_age_secs >= STALE_IN_PROGRESS_AFTER_SECS {
            push_bounded(&mut stale, bead.clone(), MAX_NO_READY_AUTOPILOT_ITEMS);
        }
    }
    stale.sort_by(|left, right| {
        right
            .updated_age_secs
            .cmp(&left.updated_age_secs)
            .then_with(|| left.bead_id.cmp(&right.bead_id))
    });
    stale
}

fn limit_no_ready_blocked_evidence(
    blocked_beads: &[NoReadyBlockedBeadEvidence],
) -> Vec<NoReadyBlockedBeadEvidence> {
    let mut evidence = Vec::new();
    for bead in blocked_beads {
        push_bounded(&mut evidence, bead.clone(), MAX_NO_READY_AUTOPILOT_ITEMS);
    }
    evidence.sort_by(|left, right| {
        left.origin
            .cmp(&right.origin)
            .then_with(|| left.bead_id.cmp(&right.bead_id))
    });
    evidence
}

fn select_no_ready_autopilot_action(
    input: &NoReadyAutopilotInput,
    stale_in_progress_beads: &[NoReadyInProgressBead],
    blocked_evidence: &[NoReadyBlockedBeadEvidence],
    rch_stale_progress: Option<&OperatorWhatIfRchStaleProgress>,
) -> NoReadyAutopilotAction {
    if input.ready_issue_count > 0 {
        return NoReadyAutopilotAction::UseReadyWork;
    }
    if rch_stale_progress.is_some() {
        return NoReadyAutopilotAction::DeferForRchPressure;
    }
    if !stale_in_progress_beads.is_empty() {
        return NoReadyAutopilotAction::RefreshStaleInProgress;
    }
    if blocked_evidence
        .iter()
        .any(|evidence| evidence.origin == NoReadyBlockerOrigin::SiblingRepository)
    {
        return NoReadyAutopilotAction::HandoffCrossRepoBlocker;
    }
    if !blocked_evidence.is_empty() || input.blocked_issue_count > 0 {
        return NoReadyAutopilotAction::RefreshBlockedEvidence;
    }
    if input.idea_wizard_allowed {
        return NoReadyAutopilotAction::CreatePlanningBead;
    }
    NoReadyAutopilotAction::ReportNoAction
}

fn no_ready_reason_code(action: NoReadyAutopilotAction) -> &'static str {
    match action {
        NoReadyAutopilotAction::UseReadyWork => "NO_READY_READY_WORK_AVAILABLE",
        NoReadyAutopilotAction::DeferForRchPressure => "NO_READY_DEFER_RCH_STALE",
        NoReadyAutopilotAction::RefreshStaleInProgress => "NO_READY_REFRESH_STALE_IN_PROGRESS",
        NoReadyAutopilotAction::HandoffCrossRepoBlocker => "NO_READY_HANDOFF_CROSS_REPO",
        NoReadyAutopilotAction::RefreshBlockedEvidence => "NO_READY_REFRESH_BLOCKED_EVIDENCE",
        NoReadyAutopilotAction::CreatePlanningBead => "NO_READY_CREATE_PLANNING_BEAD",
        NoReadyAutopilotAction::ReportNoAction => "NO_READY_REPORT_NO_ACTION",
    }
}

fn cross_repo_blocker_reason_code(
    origin: NoReadyBlockerOrigin,
    observed_revision_committed: bool,
    observed_matches_required: bool,
) -> &'static str {
    if !observed_revision_committed {
        return "XREPO_BLOCKER_UNCOMMITTED_EVIDENCE";
    }
    if !observed_matches_required {
        return "XREPO_BLOCKER_REVISION_MISMATCH";
    }
    match origin {
        NoReadyBlockerOrigin::SiblingRepository => "XREPO_BLOCKER_COMMITTED_READY",
        NoReadyBlockerOrigin::BuildInfrastructure => "XREPO_BLOCKER_BUILD_READY",
        NoReadyBlockerOrigin::Local => "XREPO_BLOCKER_LOCAL_READY",
    }
}

fn cross_repo_blocker_safe_next_action(
    input: &CrossRepoBlockerEnvelopeInput,
    retry_validation_allowed: bool,
    observed_matches_required: bool,
) -> String {
    if retry_validation_allowed {
        return format!(
            "Record the committed revision `{}` in Beads/Agent Mail, then retry `{}` through `rch exec` for `{}`; do not close or unblock until validation passes.",
            input.required_committed_revision, input.validation_command, input.franken_node_bead_id
        );
    }

    if !input.observed_revision_committed {
        return format!(
            "Ask `{}` to commit the required evidence revision `{}` for `{}` before retrying `{}`.",
            input.next_owner,
            input.required_committed_revision,
            input
                .sibling_project
                .as_deref()
                .unwrap_or("the external blocker"),
            input.validation_command
        );
    }

    if !observed_matches_required {
        return format!(
            "Ask `{}` to align the observed revision `{}` with required committed revision `{}` before retrying `{}`.",
            input.next_owner,
            input.observed_revision.as_deref().unwrap_or("none"),
            input.required_committed_revision,
            input.validation_command
        );
    }

    format!(
        "Preserve blocker evidence for `{}` and contact `{}` before changing Beads status.",
        input.franken_node_bead_id, input.next_owner
    )
}

fn render_cross_repo_blocker_beads_note(
    input: &CrossRepoBlockerEnvelopeInput,
    reason_code: &str,
    retry_validation_allowed: bool,
    sufficient_to_unblock: bool,
    beads_status_change_allowed: bool,
    safe_next_action: &str,
) -> String {
    let mut lines = vec![
        format!("Cross-repo blocker envelope `{}`", input.envelope_id),
        format!("franken_node_bead={}", input.franken_node_bead_id),
        format!("origin={:?}", input.blocker_origin),
        format!("reason_code={reason_code}"),
        format!("next_owner={}", input.next_owner),
        format!(
            "required_committed_revision={}",
            input.required_committed_revision
        ),
        format!(
            "observed_revision={}",
            input.observed_revision.as_deref().unwrap_or("none")
        ),
        format!(
            "observed_revision_committed={}",
            input.observed_revision_committed
        ),
        format!("validation_command={}", input.validation_command),
        format!("first_blocker_line={}", input.first_blocker_line),
        format!("retry_validation_allowed={retry_validation_allowed}"),
        format!("sufficient_to_unblock={sufficient_to_unblock}"),
        format!("beads_status_change_allowed={beads_status_change_allowed}"),
        format!("safe_next_action={safe_next_action}"),
    ];

    if let Some(project) = &input.sibling_project {
        lines.push(format!("sibling_project={project}"));
    }
    if let Some(bead_id) = &input.sibling_bead_id {
        lines.push(format!("sibling_bead_id={bead_id}"));
    }
    if let Some(thread_id) = &input.agent_mail_thread_id {
        lines.push(format!("agent_mail_thread_id={thread_id}"));
    }
    if let Some(message_id) = &input.agent_mail_message_id {
        lines.push(format!("agent_mail_message_id={message_id}"));
    }
    if let Some(build_id) = &input.rch_build_id {
        lines.push(format!("rch_build_id={build_id}"));
    }

    lines.join("\n")
}

fn render_cross_repo_blocker_agent_mail_body(
    input: &CrossRepoBlockerEnvelopeInput,
    reason_code: &str,
    retry_validation_allowed: bool,
    safe_next_action: &str,
) -> String {
    format!(
        "Blocked franken_node bead `{}` needs `{}` action.\n\norigin={:?}\nsibling_project={}\nsibling_bead_id={}\nagent_mail_thread_id={}\nagent_mail_message_id={}\nrch_build_id={}\nrequired_committed_revision={}\nobserved_revision={}\nobserved_revision_committed={}\nvalidation_command={}\nfirst_blocker_line={}\nreason_code={}\nretry_validation_allowed={}\nsafe_next_action={}",
        input.franken_node_bead_id,
        input.next_owner,
        input.blocker_origin,
        input.sibling_project.as_deref().unwrap_or("none"),
        input.sibling_bead_id.as_deref().unwrap_or("none"),
        input.agent_mail_thread_id.as_deref().unwrap_or("none"),
        input.agent_mail_message_id.as_deref().unwrap_or("none"),
        input.rch_build_id.as_deref().unwrap_or("none"),
        input.required_committed_revision,
        input.observed_revision.as_deref().unwrap_or("none"),
        input.observed_revision_committed,
        input.validation_command,
        input.first_blocker_line,
        reason_code,
        retry_validation_allowed,
        safe_next_action
    )
}

fn render_cross_repo_blocker_human_summary(
    input: &CrossRepoBlockerEnvelopeInput,
    reason_code: &str,
    retry_validation_allowed: bool,
    sufficient_to_unblock: bool,
    safe_next_action: &str,
) -> String {
    format!(
        "cross-repo blocker: bead={} origin={:?} owner={} sibling_project={} sibling_bead={} required_revision={} observed_revision={} committed={} retry_validation_allowed={} sufficient_to_unblock={} beads_status_change_allowed=false reason={} first_blocker_line={} safe_next_action={}",
        input.franken_node_bead_id,
        input.blocker_origin,
        input.next_owner,
        input.sibling_project.as_deref().unwrap_or("none"),
        input.sibling_bead_id.as_deref().unwrap_or("none"),
        input.required_committed_revision,
        input.observed_revision.as_deref().unwrap_or("none"),
        input.observed_revision_committed,
        retry_validation_allowed,
        sufficient_to_unblock,
        reason_code,
        input.first_blocker_line,
        safe_next_action
    )
}

fn no_ready_safe_next_action(
    action: NoReadyAutopilotAction,
    stale_in_progress_beads: &[NoReadyInProgressBead],
    blocked_evidence: &[NoReadyBlockedBeadEvidence],
    rch_stale_progress: Option<&OperatorWhatIfRchStaleProgress>,
) -> String {
    match action {
        NoReadyAutopilotAction::UseReadyWork => {
            "Run `br ready --json`, claim the ready bead, reserve files, and announce start in Agent Mail.".to_string()
        }
        NoReadyAutopilotAction::DeferForRchPressure => rch_stale_progress
            .map(|progress| progress.safe_next_action.clone())
            .unwrap_or_else(|| "Wait for RCH pressure to clear before enqueueing validation work.".to_string()),
        NoReadyAutopilotAction::RefreshStaleInProgress => {
            let bead = stale_in_progress_beads
                .first()
                .map(|bead| bead.bead_id.as_str())
                .unwrap_or("the stale in-progress bead");
            format!(
                "Inspect `{bead}` with `br show`, contact the assignee, and update or unblock the bead before creating new work."
            )
        }
        NoReadyAutopilotAction::HandoffCrossRepoBlocker => {
            let evidence = blocked_evidence
                .iter()
                .find(|evidence| evidence.origin == NoReadyBlockerOrigin::SiblingRepository);
            match evidence {
                Some(evidence) => format!(
                    "Send a handoff for `{}` to `{}` with the exact command and first blocker line.",
                    evidence.bead_id,
                    evidence.sibling_project.as_deref().unwrap_or("the sibling repository")
                ),
                None => "Send a cross-repo blocker handoff with the exact command and first blocker line.".to_string(),
            }
        }
        NoReadyAutopilotAction::RefreshBlockedEvidence => {
            "Refresh blocked-bead evidence; preserve the exact command and first failure line in Beads and Agent Mail.".to_string()
        }
        NoReadyAutopilotAction::CreatePlanningBead => {
            "Create an idea-wizard or planning bead only after recording that `br ready --json` returned no actionable work.".to_string()
        }
        NoReadyAutopilotAction::ReportNoAction => {
            "Report that no ready, refreshable, or safely creatable work was found.".to_string()
        }
    }
}

fn build_no_ready_rejected_alternatives(
    selected_action: NoReadyAutopilotAction,
    input: &NoReadyAutopilotInput,
    stale_in_progress_beads: &[NoReadyInProgressBead],
    blocked_evidence: &[NoReadyBlockedBeadEvidence],
    rch_stale_progress: Option<&OperatorWhatIfRchStaleProgress>,
) -> Vec<NoReadyAutopilotRejectedAlternative> {
    let candidates = [
        (
            NoReadyAutopilotAction::UseReadyWork,
            if input.ready_issue_count == 0 {
                "rejected because `br ready --json` returned zero ready beads"
            } else {
                "rejected because a higher-priority safety action was selected"
            },
        ),
        (
            NoReadyAutopilotAction::DeferForRchPressure,
            if rch_stale_progress.is_none() {
                "rejected because no heartbeat-fresh/progress-stale RCH build was observed"
            } else {
                "rejected because a higher-priority no-ready action was selected"
            },
        ),
        (
            NoReadyAutopilotAction::RefreshStaleInProgress,
            if stale_in_progress_beads.is_empty() {
                "rejected because no stale in-progress bead exceeded the refresh threshold"
            } else {
                "rejected because validation infrastructure pressure takes precedence"
            },
        ),
        (
            NoReadyAutopilotAction::HandoffCrossRepoBlocker,
            if blocked_evidence
                .iter()
                .any(|evidence| evidence.origin == NoReadyBlockerOrigin::SiblingRepository)
            {
                "rejected because a higher-priority no-ready action was selected"
            } else {
                "rejected because no sibling-repository blocker evidence was present"
            },
        ),
        (
            NoReadyAutopilotAction::RefreshBlockedEvidence,
            if blocked_evidence.is_empty() && input.blocked_issue_count == 0 {
                "rejected because no blocked-bead evidence was present"
            } else {
                "rejected because a more specific blocked-work action was selected"
            },
        ),
        (
            NoReadyAutopilotAction::CreatePlanningBead,
            if input.idea_wizard_allowed {
                "rejected because existing work needs refresh before creating a new bead"
            } else {
                "rejected because idea-wizard or new-bead creation is disabled"
            },
        ),
    ];

    let mut rejected = Vec::new();
    for (action, rationale) in candidates {
        if action != selected_action {
            push_bounded(
                &mut rejected,
                NoReadyAutopilotRejectedAlternative {
                    action,
                    reason_code: format!("{}_REJECTED", no_ready_reason_code(action)),
                    rationale: rationale.to_string(),
                },
                MAX_NO_READY_AUTOPILOT_ITEMS,
            );
        }
    }
    rejected
}

fn render_no_ready_pasteable_note(
    input: &NoReadyAutopilotInput,
    selected_action: NoReadyAutopilotAction,
    reason_code: &str,
    safe_next_action: &str,
    stale_in_progress_beads: &[NoReadyInProgressBead],
    blocked_evidence: &[NoReadyBlockedBeadEvidence],
    rch_stale_progress: Option<&OperatorWhatIfRchStaleProgress>,
) -> String {
    let mut lines = vec![
        format!("No-ready autopilot receipt `{}`", input.receipt_id),
        format!(
            "selected_action={} reason_code={}",
            selected_action.as_str(),
            reason_code
        ),
        format!(
            "counts: ready={} open={} blocked={}",
            input.ready_issue_count, input.open_issue_count, input.blocked_issue_count
        ),
        format!(
            "last_ready_command={}",
            input
                .last_ready_command
                .as_deref()
                .unwrap_or("br ready --json")
        ),
        format!("safe_next_action={safe_next_action}"),
    ];

    if let Some(progress) = rch_stale_progress {
        lines.push(format!(
            "rch_stale_builds={}",
            render_rch_stale_build_refs(progress)
        ));
    }
    if let Some(bead) = stale_in_progress_beads.first() {
        lines.push(format!(
            "stale_in_progress={} assignee={} age_secs={} status={}",
            bead.bead_id, bead.assignee, bead.updated_age_secs, bead.status_summary
        ));
    }
    if let Some(evidence) = blocked_evidence.first() {
        lines.push(format!("blocked_bead={}", evidence.bead_id));
        if let Some(project) = &evidence.sibling_project {
            lines.push(format!("sibling_project={project}"));
        }
        lines.push(format!("blocker_command={}", evidence.blocker_command));
        lines.push(format!(
            "first_blocker_line={}",
            evidence.first_blocker_line
        ));
    }

    lines.join("\n")
}

fn render_no_ready_human_summary(
    input: &NoReadyAutopilotInput,
    selected_action: NoReadyAutopilotAction,
    reason_code: &str,
    safe_next_action: &str,
    stale_in_progress_count: usize,
    blocked_evidence_count: usize,
    rch_stale_progress: Option<&OperatorWhatIfRchStaleProgress>,
) -> String {
    let rch_stale_builds = rch_stale_progress
        .map(render_rch_stale_build_refs)
        .unwrap_or_else(|| "none".to_string());

    format!(
        "no-ready autopilot: receipt={} workspace={} ready={} open={} blocked={} action={} reason={} stale_in_progress={} blocked_evidence={} rch_stale_builds={} safe_next_action={}",
        input.receipt_id,
        input.workspace_root,
        input.ready_issue_count,
        input.open_issue_count,
        input.blocked_issue_count,
        selected_action.as_str(),
        reason_code,
        stale_in_progress_count,
        blocked_evidence_count,
        rch_stale_builds,
        safe_next_action,
    )
}

fn hardware_bridge_action(
    input: &WorkspaceHardwarePlacementInput,
    admission: &AdmissionDecision,
) -> (OperatorWhatIfAction, String, bool) {
    if !input.workspace.memory_pressure.is_finite() {
        return (
            OperatorWhatIfAction::RefuseLocalFallback,
            "HWP_BRIDGE_INVALID_PRESSURE_INPUT".to_string(),
            true,
        );
    }

    if input
        .topology
        .as_ref()
        .is_some_and(|topology| topology.stale)
    {
        return (
            OperatorWhatIfAction::RefuseLocalFallback,
            "HWP_BRIDGE_STALE_TOPOLOGY".to_string(),
            true,
        );
    }

    match admission {
        AdmissionDecision::RefuseLocalFallback => (
            OperatorWhatIfAction::RefuseLocalFallback,
            "HWP_BRIDGE_REFUSE_POLICY".to_string(),
            true,
        ),
        AdmissionDecision::Queue { .. } => (
            OperatorWhatIfAction::Queue,
            "HWP_BRIDGE_QUEUE_POLICY".to_string(),
            false,
        ),
        AdmissionDecision::Wait { .. } => (
            OperatorWhatIfAction::Wait,
            "HWP_BRIDGE_WAIT_POLICY".to_string(),
            false,
        ),
        AdmissionDecision::RequireRch => (
            OperatorWhatIfAction::RequireRch,
            "HWP_BRIDGE_REQUIRE_RCH_POLICY".to_string(),
            false,
        ),
        AdmissionDecision::AllowLocal => hardware_bridge_local_action(input),
    }
}

fn hardware_bridge_local_action(
    input: &WorkspaceHardwarePlacementInput,
) -> (OperatorWhatIfAction, String, bool) {
    if !input.work_class.prefers_rch() {
        return (
            OperatorWhatIfAction::Allow,
            "HWP_BRIDGE_ALLOW_LOCAL_SOURCE".to_string(),
            false,
        );
    }

    match input.workspace.rch_available_slots {
        Some(slots) if slots > 0 => (
            OperatorWhatIfAction::RequireRch,
            "HWP_BRIDGE_REQUIRE_RCH_FOR_COSTLY_WORK".to_string(),
            false,
        ),
        Some(_) => (
            OperatorWhatIfAction::Queue,
            "HWP_BRIDGE_QUEUE_RCH_SATURATED".to_string(),
            false,
        ),
        None => (
            OperatorWhatIfAction::RefuseLocalFallback,
            "HWP_BRIDGE_REFUSE_MISSING_RCH".to_string(),
            true,
        ),
    }
}

fn build_hardware_bridge_placement(
    input: &WorkspaceHardwarePlacementInput,
    action: OperatorWhatIfAction,
) -> Result<PlacementDecision, String> {
    let mut planner = HardwarePlanner::default();
    let profile = match action {
        OperatorWhatIfAction::RequireRch => hardware_bridge_rch_profile(input)?,
        OperatorWhatIfAction::Allow => hardware_bridge_local_profile(input)?,
        OperatorWhatIfAction::Wait
        | OperatorWhatIfAction::Queue
        | OperatorWhatIfAction::RefuseLocalFallback => {
            return Err("hardware bridge action does not permit placement".to_string());
        }
    };
    let policy = PlacementPolicy::new(
        hardware_bridge_policy_id(action),
        "workspace pressure hardware admission bridge",
        hardware_bridge_max_risk(input),
    );
    let policy_id = policy.policy_id.clone();
    planner
        .register_profile(profile, input.timestamp_ms, &input.bridge_id)
        .map_err(|err| err.to_string())?;
    planner
        .register_policy(policy, input.timestamp_ms, &input.bridge_id)
        .map_err(|err| err.to_string())?;

    let request = WorkloadRequest {
        workload_id: input.workload_id.clone(),
        required_capabilities: hardware_bridge_required_capabilities(input.work_class, action),
        max_risk: hardware_bridge_max_risk(input),
        policy_id,
        trace_id: input.bridge_id.clone(),
    };
    planner
        .request_placement(&request, input.timestamp_ms)
        .map_err(|err| err.to_string())
}

fn hardware_bridge_rch_profile(
    input: &WorkspaceHardwarePlacementInput,
) -> Result<HardwareProfile, String> {
    let available_slots = input
        .workspace
        .rch_available_slots
        .ok_or_else(|| "RCH slot count unavailable".to_string())?;
    if available_slots == 0 {
        return Err("RCH slots saturated".to_string());
    }
    let total_slots = available_slots.max(1);
    let mut profile = HardwareProfile::new(
        "rch-high-capacity",
        "RCH high-capacity worker pool",
        hardware_bridge_profile_capabilities(input.work_class, OperatorWhatIfAction::RequireRch),
        hardware_bridge_profile_risk(input),
        total_slots,
    )
    .map_err(|err| err.to_string())?;
    profile.metadata.insert(
        "rch_available_slots".to_string(),
        available_slots.to_string(),
    );
    if let Some(topology) = &input.topology {
        profile.metadata.insert(
            "topology_snapshot".to_string(),
            topology.snapshot_id.clone(),
        );
    }
    Ok(profile)
}

fn hardware_bridge_local_profile(
    input: &WorkspaceHardwarePlacementInput,
) -> Result<HardwareProfile, String> {
    let topology = input
        .topology
        .as_ref()
        .ok_or_else(|| "local topology snapshot unavailable".to_string())?;
    if topology.cpu_cores == 0 || topology.memory_bytes == 0 {
        return Err("local topology snapshot is incomplete".to_string());
    }
    let total_slots = topology.cpu_cores.saturating_div(16).clamp(1, 64);
    let mut profile = HardwareProfile::new(
        "local-high-capacity",
        "Local high-capacity workspace host",
        hardware_bridge_profile_capabilities(input.work_class, OperatorWhatIfAction::Allow),
        hardware_bridge_profile_risk(input),
        total_slots,
    )
    .map_err(|err| err.to_string())?;
    profile.used_slots = input.workspace.active_build_count.min(total_slots);
    profile
        .metadata
        .insert("cpu_cores".to_string(), topology.cpu_cores.to_string());
    profile.metadata.insert(
        "memory_bytes".to_string(),
        topology.memory_bytes.to_string(),
    );
    profile.metadata.insert(
        "numa_nodes".to_string(),
        topology.numa_nodes.unwrap_or_default().to_string(),
    );
    Ok(profile)
}

fn hardware_bridge_profile_capabilities(
    work_class: WorkCostClass,
    action: OperatorWhatIfAction,
) -> BTreeSet<String> {
    let mut capabilities = BTreeSet::new();
    capabilities.insert(hardware_bridge_work_capability(work_class).to_string());
    match action {
        OperatorWhatIfAction::RequireRch => {
            capabilities.insert("rch".to_string());
            capabilities.insert("remote_worker".to_string());
        }
        OperatorWhatIfAction::Allow => {
            capabilities.insert("local".to_string());
            capabilities.insert("high_capacity".to_string());
        }
        OperatorWhatIfAction::Wait
        | OperatorWhatIfAction::Queue
        | OperatorWhatIfAction::RefuseLocalFallback => {}
    }
    capabilities
}

fn hardware_bridge_required_capabilities(
    work_class: WorkCostClass,
    action: OperatorWhatIfAction,
) -> BTreeSet<String> {
    hardware_bridge_profile_capabilities(work_class, action)
}

fn hardware_bridge_work_capability(work_class: WorkCostClass) -> &'static str {
    match work_class {
        WorkCostClass::Validation => "validation",
        WorkCostClass::Fuzzing => "fuzzing",
        WorkCostClass::Benchmark => "benchmark",
        WorkCostClass::DocsGate => "docs_gate",
        WorkCostClass::SourceOnly => "source_only",
        WorkCostClass::Cleanup => "cleanup",
    }
}

fn hardware_bridge_policy_id(action: OperatorWhatIfAction) -> &'static str {
    match action {
        OperatorWhatIfAction::Allow => "workspace-hardware-admission/local/v1",
        OperatorWhatIfAction::RequireRch => "workspace-hardware-admission/rch/v1",
        OperatorWhatIfAction::Wait
        | OperatorWhatIfAction::Queue
        | OperatorWhatIfAction::RefuseLocalFallback => "workspace-hardware-admission/none/v1",
    }
}

fn hardware_bridge_max_risk(input: &WorkspaceHardwarePlacementInput) -> u32 {
    if input.work_class.prefers_rch() {
        50
    } else {
        80
    }
}

fn hardware_bridge_profile_risk(input: &WorkspaceHardwarePlacementInput) -> u32 {
    let memory_pressure = if input.workspace.memory_pressure.is_finite() {
        input.workspace.memory_pressure.clamp(0.0, 1.0)
    } else {
        1.0
    };
    let memory_risk: u32 = if memory_pressure >= 0.95 {
        95
    } else if memory_pressure >= 0.9 {
        90
    } else if memory_pressure >= 0.8 {
        80
    } else if memory_pressure >= 0.7 {
        70
    } else if memory_pressure >= 0.5 {
        50
    } else if memory_pressure >= 0.3 {
        30
    } else if memory_pressure >= 0.1 {
        10
    } else {
        0
    };
    let build_risk = input
        .workspace
        .active_build_count
        .saturating_mul(10)
        .min(40);
    memory_risk.saturating_add(build_risk).min(100)
}

fn hardware_bridge_dispatch_note(
    input: &WorkspaceHardwarePlacementInput,
    action: OperatorWhatIfAction,
) -> String {
    let command = input
        .requested_command
        .as_deref()
        .unwrap_or("source-only proof");
    match action {
        OperatorWhatIfAction::RequireRch => {
            format!(
                "dispatch via {}",
                render_simulated_command(input.work_class, action, command)
            )
        }
        OperatorWhatIfAction::Allow => {
            format!(
                "local dispatch approved for {}",
                hardware_bridge_work_capability(input.work_class)
            )
        }
        OperatorWhatIfAction::Wait
        | OperatorWhatIfAction::Queue
        | OperatorWhatIfAction::RefuseLocalFallback => "no dispatch approved".to_string(),
    }
}

fn fail_closed_target_dir_lease_plan(
    plan_id: String,
    bead_id: String,
    reason_code: &'static str,
    diagnostic: String,
) -> TargetDirLeasePlan {
    TargetDirLeasePlan {
        schema_version: TARGET_DIR_LEASE_PLAN_SCHEMA_VERSION.to_string(),
        plan_id,
        bead_id: bead_id.clone(),
        selected_path: None,
        selected_reason_code: reason_code.to_string(),
        candidates: Vec::new(),
        cleanup_recommendations: Vec::new(),
        diagnostics: vec![diagnostic],
        fail_closed: true,
        human_summary: render_target_dir_lease_plan_human_parts(
            &bead_id,
            None,
            reason_code,
            0,
            0,
            true,
        ),
    }
}

fn build_target_dir_lease_candidate(
    input: &TargetDirLeasePlanInput,
    root: &TargetDirLeaseRoot,
    minimum_free_bytes: u64,
    reservation_count: u32,
    cleanup_recommendations: &mut Vec<TargetDirLeaseCleanupRecommendation>,
) -> TargetDirLeaseCandidate {
    let mut diagnostics = Vec::new();
    let required_free_bytes = target_dir_lease_required_free_bytes(input, minimum_free_bytes);
    let heavy = input.command_family.is_heavy() || input.rch_required;
    let path = target_dir_lease_candidate_path(
        &root.path,
        &input.bead_id,
        input.command_family,
        input.expected_artifact_class,
    );
    let expected_cleanup_owner = target_dir_lease_cleanup_owner(root.kind);
    let expires_after_ms = input.lease_ttl_ms.max(DEFAULT_TARGET_DIR_LEASE_TTL_MS);

    let mut safety_class = match root.kind {
        TargetDirLeaseRootKind::OffRepo | TargetDirLeaseRootKind::RchWorker => {
            TargetDirLeaseSafetyClass::PreferredIsolated
        }
        TargetDirLeaseRootKind::Temp => TargetDirLeaseSafetyClass::AcceptableShared,
        TargetDirLeaseRootKind::RepoLocal | TargetDirLeaseRootKind::Unknown => {
            TargetDirLeaseSafetyClass::RequiresExplicitApproval
        }
    };
    let mut reason_code = match root.kind {
        TargetDirLeaseRootKind::OffRepo | TargetDirLeaseRootKind::RchWorker => {
            target_dir_lease_reason_codes::SELECT_OFF_REPO_RCH
        }
        TargetDirLeaseRootKind::Temp => target_dir_lease_reason_codes::SELECT_TEMP_ISOLATED,
        TargetDirLeaseRootKind::RepoLocal | TargetDirLeaseRootKind::Unknown => {
            target_dir_lease_reason_codes::SELECT_LOCAL_SOURCE
        }
    };
    let mut fail_closed = false;
    let mut requires_approval = false;

    if root.stale {
        safety_class = TargetDirLeaseSafetyClass::Rejected;
        reason_code = target_dir_lease_reason_codes::REJECT_STALE_ROOT;
        fail_closed = true;
        requires_approval = true;
        push_bounded(
            &mut diagnostics,
            "root observation is stale".to_string(),
            MAX_DIAGNOSTIC_REASONS,
        );
    } else if root.free_bytes < required_free_bytes {
        safety_class = TargetDirLeaseSafetyClass::Rejected;
        reason_code = target_dir_lease_reason_codes::REJECT_FULL_ROOT;
        fail_closed = true;
        requires_approval = true;
        push_bounded(
            &mut diagnostics,
            format!(
                "root free bytes {} below required {}",
                root.free_bytes, required_free_bytes
            ),
            MAX_DIAGNOSTIC_REASONS,
        );
    } else if heavy && root.kind == TargetDirLeaseRootKind::RepoLocal {
        safety_class = TargetDirLeaseSafetyClass::Rejected;
        reason_code = target_dir_lease_reason_codes::REJECT_REPO_LOCAL_HEAVY;
        fail_closed = true;
        requires_approval = true;
        push_bounded(
            &mut diagnostics,
            "repo-local target dir rejected for heavy cargo/RCH-required work".to_string(),
            MAX_DIAGNOSTIC_REASONS,
        );
    } else if !root.stable_owner {
        safety_class = TargetDirLeaseSafetyClass::RequiresExplicitApproval;
        reason_code = target_dir_lease_reason_codes::REJECT_UNSTABLE_OWNER;
        fail_closed = true;
        requires_approval = true;
        push_bounded(
            &mut diagnostics,
            "root ownership is unstable".to_string(),
            MAX_DIAGNOSTIC_REASONS,
        );
    }

    if fail_closed {
        cleanup_recommendations.push(TargetDirLeaseCleanupRecommendation {
            path: root.path.clone(),
            reason: format!(
                "candidate rejected with {reason_code}; cleanup or lease recovery requires operator approval"
            ),
            requires_approval: true,
        });
    }

    let score = target_dir_lease_score(input, root, reservation_count, fail_closed);

    TargetDirLeaseCandidate {
        path,
        root_path: root.path.clone(),
        root_kind: root.kind,
        safety_class,
        expected_cleanup_owner,
        expires_after_ms,
        reason_code: reason_code.to_string(),
        fail_closed,
        score,
        free_bytes: root.free_bytes,
        numa_node: root.numa_node,
        requires_approval,
        diagnostics: limit_diagnostics(diagnostics),
    }
}

fn target_dir_lease_required_free_bytes(
    input: &TargetDirLeasePlanInput,
    minimum_free_bytes: u64,
) -> u64 {
    let artifact_floor = match (input.command_family, input.expected_artifact_class) {
        (TargetDirLeaseCommandFamily::Cargo | TargetDirLeaseCommandFamily::RchCargo, _) => {
            8 * 1024 * 1024 * 1024
        }
        (_, TargetDirLeaseArtifactClass::BuildOutput | TargetDirLeaseArtifactClass::Cache) => {
            2 * 1024 * 1024 * 1024
        }
        (_, TargetDirLeaseArtifactClass::TestArtifacts) => 1024 * 1024 * 1024,
        _ => 512 * 1024 * 1024,
    };
    artifact_floor.max(minimum_free_bytes)
}

fn target_dir_lease_score(
    input: &TargetDirLeasePlanInput,
    root: &TargetDirLeaseRoot,
    reservation_count: u32,
    fail_closed: bool,
) -> i64 {
    if fail_closed {
        return -1_000_000;
    }

    let root_score = match root.kind {
        TargetDirLeaseRootKind::OffRepo => 50_000,
        TargetDirLeaseRootKind::RchWorker => 48_000,
        TargetDirLeaseRootKind::Temp => 30_000,
        TargetDirLeaseRootKind::RepoLocal => 10_000,
        TargetDirLeaseRootKind::Unknown => 1_000,
    };
    let free_gib = i64::try_from(root.free_bytes / (1024 * 1024 * 1024)).unwrap_or(i64::MAX);
    let free_score = free_gib.min(512).saturating_mul(25);
    let lease_penalty =
        i64::from(root.existing_lease_count.saturating_add(reservation_count)).saturating_mul(250);
    let memory_penalty = target_dir_lease_memory_penalty(input.memory_pressure);
    let numa_bonus = target_dir_lease_numa_bonus(input, root);
    let owner_bonus = if root.stable_owner { 2_000 } else { 0 };

    i64::from(root_score)
        .saturating_add(free_score)
        .saturating_add(numa_bonus)
        .saturating_add(owner_bonus)
        .saturating_sub(lease_penalty)
        .saturating_sub(memory_penalty)
}

fn target_dir_lease_memory_penalty(memory_pressure: f32) -> i64 {
    if memory_pressure >= 0.95 {
        10_000
    } else if memory_pressure >= 0.9 {
        5_000
    } else if memory_pressure >= 0.8 {
        2_000
    } else {
        0
    }
}

fn target_dir_lease_numa_bonus(input: &TargetDirLeasePlanInput, root: &TargetDirLeaseRoot) -> i64 {
    let Some(node) = root.numa_node else {
        return 0;
    };
    let Some(node_count) = input
        .topology
        .as_ref()
        .and_then(|topology| topology.numa_nodes)
    else {
        return 0;
    };
    if node < node_count { 1_500 } else { -1_500 }
}

fn target_dir_reservation_count_for_root(
    root: &TargetDirLeaseRoot,
    hints: &[TargetDirLeaseReservationHint],
) -> u32 {
    let root_prefix = root.path.trim_end_matches('/');
    let count = hints
        .iter()
        .filter(|hint| {
            hint.path == root.path
                || hint
                    .path
                    .strip_prefix(root_prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn target_dir_lease_candidate_path(
    root_path: &str,
    bead_id: &str,
    command_family: TargetDirLeaseCommandFamily,
    artifact_class: TargetDirLeaseArtifactClass,
) -> String {
    let root = root_path.trim_end_matches('/');
    let root = if root.is_empty() { "/" } else { root };
    let leaf = format!(
        "franken-node-{}-{}-{}",
        sanitize_lease_component(bead_id),
        command_family.as_str(),
        target_dir_lease_artifact_class_slug(artifact_class)
    );
    if root == "/" {
        format!("/{leaf}")
    } else {
        format!("{root}/{leaf}")
    }
}

fn target_dir_lease_artifact_class_slug(
    artifact_class: TargetDirLeaseArtifactClass,
) -> &'static str {
    match artifact_class {
        TargetDirLeaseArtifactClass::BuildOutput => "build-output",
        TargetDirLeaseArtifactClass::TestArtifacts => "test-artifacts",
        TargetDirLeaseArtifactClass::Evidence => "evidence",
        TargetDirLeaseArtifactClass::TempOutput => "temp-output",
        TargetDirLeaseArtifactClass::Cache => "cache",
    }
}

fn target_dir_lease_cleanup_owner(root_kind: TargetDirLeaseRootKind) -> TargetDirLeaseCleanupOwner {
    match root_kind {
        TargetDirLeaseRootKind::OffRepo | TargetDirLeaseRootKind::Temp => {
            TargetDirLeaseCleanupOwner::Agent
        }
        TargetDirLeaseRootKind::RchWorker => TargetDirLeaseCleanupOwner::RchWorker,
        TargetDirLeaseRootKind::RepoLocal | TargetDirLeaseRootKind::Unknown => {
            TargetDirLeaseCleanupOwner::Operator
        }
    }
}

fn target_dir_lease_path_is_unsafe(path: &str) -> bool {
    path.trim().is_empty()
        || path.contains('\0')
        || Path::new(path)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn sanitize_lease_component(value: &str) -> String {
    let mut out = String::new();
    let mut last_was_separator = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            out.push('-');
            last_was_separator = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn render_target_dir_lease_plan_human_parts(
    bead_id: &str,
    selected_path: Option<&str>,
    reason_code: &str,
    candidate_count: usize,
    cleanup_count: usize,
    fail_closed: bool,
) -> String {
    format!(
        "target_dir_lease bead={} selected={} reason_code={} candidates={} cleanup_recommendations={} fail_closed={}",
        bead_id,
        selected_path.unwrap_or("none"),
        reason_code,
        candidate_count,
        cleanup_count,
        fail_closed
    )
}

#[must_use]
pub fn render_target_dir_lease_plan_human(plan: &TargetDirLeasePlan) -> String {
    render_target_dir_lease_plan_human_parts(
        &plan.bead_id,
        plan.selected_path.as_deref(),
        &plan.selected_reason_code,
        plan.candidates.len(),
        plan.cleanup_recommendations.len(),
        plan.fail_closed,
    )
}

/// Estimate size of temporary artifacts for cleanup analysis.
fn estimate_temp_artifacts_size() -> std::io::Result<u64> {
    let mut total: u64 = 0;

    // Check common temp locations
    let temp_patterns = ["/tmp/cargo-*", "/tmp/rust-*", "/tmp/rch-*"];

    for pattern in temp_patterns {
        if let Some(prefix) = pattern.strip_suffix('*') {
            let Some(name_prefix) = prefix.strip_prefix("/tmp/") else {
                continue;
            };
            if let Ok(entries) = std::fs::read_dir("/tmp") {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str()
                        && name.starts_with(name_prefix)
                    {
                        // Remove "/tmp/" prefix
                        if let Ok(size) = calculate_directory_size_safe(entry.path()) {
                            total = total.saturating_add(size);
                        }
                    }
                }
            }
        }
    }

    Ok(total)
}

/// Safe directory size calculation with bounds checking.
fn calculate_directory_size_safe<P: AsRef<Path>>(path: P) -> std::io::Result<u64> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(0);
    }

    let mut total: u64 = 0;
    const MAX_DEPTH: usize = 10; // Prevent infinite recursion

    fn calculate_recursive(path: &Path, depth: usize, total: &mut u64) -> std::io::Result<()> {
        if depth > MAX_DEPTH {
            return Ok(()); // Truncate very deep trees
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;

            if metadata.is_dir() {
                calculate_recursive(&entry.path(), depth + 1, total)?;
            } else {
                *total = total.saturating_add(metadata.len());
            }

            // Safety check: don't let single operations take too long
            if *total > 100_000_000_000 {
                // 100GB limit
                break;
            }
        }
        Ok(())
    }

    calculate_recursive(path, 0, &mut total)?;
    Ok(total)
}

/// Limit diagnostic messages to prevent memory exhaustion.
fn limit_diagnostics(mut diagnostics: Vec<String>) -> Vec<String> {
    if diagnostics.len() > MAX_DIAGNOSTIC_REASONS {
        diagnostics.truncate(MAX_DIAGNOSTIC_REASONS);
        diagnostics.push("... additional diagnostics truncated".to_string());
    }
    diagnostics
}

fn validate_required_ledger_text(
    field: &'static str,
    value: &str,
) -> Result<(), AgentCommandLedgerError> {
    if value.trim().is_empty() {
        return Err(AgentCommandLedgerError::EmptyField { field });
    }
    validate_optional_ledger_text(field, Some(value))
}

fn validate_optional_ledger_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), AgentCommandLedgerError> {
    if let Some(value) = value
        && value.len() > MAX_AGENT_COMMAND_FIELD_BYTES
    {
        return Err(AgentCommandLedgerError::StringTooLong {
            field,
            len: value.len(),
            max: MAX_AGENT_COMMAND_FIELD_BYTES,
        });
    }
    Ok(())
}

fn validate_optional_ledger_path(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), AgentCommandLedgerError> {
    if let Some(value) = value {
        validate_required_ledger_text(field, value)?;
        if value.contains('\0') {
            return Err(AgentCommandLedgerError::PathContainsNul { field });
        }
        if Path::new(value)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(AgentCommandLedgerError::PathTraversal { field });
        }
    }
    Ok(())
}

fn validate_ledger_items(
    field: &'static str,
    items: &[String],
    paths: bool,
) -> Result<(), AgentCommandLedgerError> {
    if items.len() > MAX_AGENT_COMMAND_LEDGER_ITEMS {
        return Err(AgentCommandLedgerError::TooManyItems {
            field,
            count: items.len(),
            max: MAX_AGENT_COMMAND_LEDGER_ITEMS,
        });
    }

    for item in items {
        if paths {
            validate_optional_ledger_path(field, Some(item))?;
        } else {
            validate_required_ledger_text(field, item)?;
        }
    }

    Ok(())
}

fn path_requires_reservation(path: &str) -> bool {
    path.ends_with(".rs")
        || path.ends_with("Cargo.toml")
        || path.ends_with("Cargo.lock")
        || path.starts_with("crates/")
        || path.starts_with("src/")
        || path.starts_with("tests/")
        || path.starts_with("scripts/")
}

fn command_summary_has_unsafe_delete(command_summary: &str) -> bool {
    let normalized = command_summary.to_ascii_lowercase();
    normalized.contains("rm -rf")
        || normalized.contains("git reset --hard")
        || normalized.contains("git clean -fd")
        || normalized.contains("git clean -df")
}

fn redact_protected_command_text(command_summary: &str) -> String {
    let mut redacted = Vec::new();
    let mut redact_next = false;

    for token in command_summary.split_whitespace() {
        if redact_next {
            redacted.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }

        if token_flag_requires_redaction(token) {
            if let Some((flag, _value)) = token.split_once('=') {
                redacted.push(format!("{flag}=<redacted>"));
            } else {
                redacted.push(token.to_string());
                redact_next = true;
            }
            continue;
        }

        if let Some((key, _value)) = token.split_once('=')
            && contains_secret_marker(key)
        {
            redacted.push(format!("{key}=<redacted>"));
            continue;
        }

        redacted.push(token.to_string());
    }

    redacted.join(" ")
}

fn token_flag_requires_redaction(token: &str) -> bool {
    let upper = token.to_ascii_uppercase();
    upper.starts_with("--TOKEN")
        || upper.starts_with("--SECRET")
        || upper.starts_with("--PASSWORD")
        || upper.starts_with("--API-KEY")
        || upper.starts_with("--API_KEY")
}

fn contains_secret_marker(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("API_KEY")
        || upper.contains("API-KEY")
}

/// Get available disk space for the current working directory.
///
/// Uses fs2::available_space to query the filesystem for actual available space.
/// This replaces the hardcoded placeholder value in main.rs with real disk monitoring.
pub fn get_available_disk_space(path: impl AsRef<std::path::Path>) -> std::io::Result<u64> {
    fs2::available_space(path)
}

/// Get available disk space for the current working directory with fallback.
///
/// Returns actual disk space or a conservative fallback if detection fails.
pub fn get_workspace_disk_space() -> Result<u64, Box<dyn std::error::Error>> {
    match get_available_disk_space(".") {
        Ok(bytes) => Ok(bytes),
        Err(e) => {
            // Log error but don't fail - return conservative estimate
            eprintln!("Warning: disk space detection failed: {e}. Using conservative estimate.");
            Ok(1_000_000_000) // 1GB conservative fallback
        }
    }
}

/// Get active file reservation count from Agent Mail system.
///
/// Queries the Agent Mail system for the current count of active file reservations.
/// This replaces the hardcoded placeholder value in main.rs with real coordination data.
pub fn get_active_file_reservations() -> Result<u32, Box<dyn std::error::Error>> {
    if let Some(count) = try_get_workspace_file_reservations() {
        return Ok(count);
    }

    eprintln!("Warning: Agent Mail reservation count unavailable. Using conservative estimate.");
    Ok(5)
}

/// Return the live Agent Mail reservation count without inventing a fallback.
pub fn try_get_workspace_file_reservations() -> Option<u32> {
    active_reservation_count_from_agent_mail_http()
        .or_else(active_reservation_count_from_agent_mail_archive)
}

fn active_reservation_count_from_agent_mail_http() -> Option<u32> {
    let url = std::env::var("FRANKEN_NODE_AGENT_MAIL_RESERVATIONS_URL")
        .or_else(|_| std::env::var("AGENT_MAIL_RESERVATIONS_URL"))
        .unwrap_or_else(|_| {
            "http://127.0.0.1:8765/mail/api/file-reservations/active/count".to_string()
        });

    let output = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "2",
            &url,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .ok()
}

fn active_reservation_count_from_agent_mail_archive() -> Option<u32> {
    for dir in agent_mail_archive_dirs("file_reservations") {
        if let Some(count) = count_active_reservations_in_dir(&dir) {
            return Some(count);
        }
    }
    None
}

/// Count active Agent Mail file reservation leases in a reservation archive directory.
pub fn count_active_reservations_in_dir(dir: &Path) -> Option<u32> {
    let entries = std::fs::read_dir(dir).ok()?;
    let now = Utc::now();
    let mut count = 0_u32;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }

        let Ok(contents) = bounded_read_to_string(&path, MAX_AGENT_MAIL_RESERVATION_FILE_BYTES)
        else {
            continue;
        };
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&contents) else {
            continue;
        };

        if payload
            .get("released_ts")
            .is_some_and(|value| !value.is_null())
        {
            continue;
        }

        let Some(expires_ts) = payload
            .get("expires_ts")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };

        let Ok(expires_at) = DateTime::parse_from_rfc3339(expires_ts) else {
            continue;
        };

        if expires_at.with_timezone(&Utc) > now {
            count = count.saturating_add(1);
        }
    }

    Some(count)
}

fn agent_mail_archive_dirs(child: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(root) = std::env::var("FRANKEN_NODE_AGENT_MAIL_PROJECT_ARCHIVE") {
        dirs.push(PathBuf::from(root).join(child));
    }

    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join(child));

        if let Some(home) = std::env::var_os("HOME") {
            dirs.push(
                PathBuf::from(home)
                    .join(".mcp_agent_mail_git_mailbox_repo")
                    .join("projects")
                    .join(agent_mail_project_slug(&cwd))
                    .join(child),
            );
        }
    }

    dirs
}

fn agent_mail_project_slug(path: &Path) -> String {
    let mut parts = Vec::new();

    for component in path.components() {
        let Component::Normal(value) = component else {
            continue;
        };
        let Some(value) = value.to_str() else {
            continue;
        };

        let mut part = String::new();
        let mut last_was_separator = false;
        for ch in value.chars() {
            if ch.is_ascii_alphanumeric() {
                part.push(ch.to_ascii_lowercase());
                last_was_separator = false;
            } else if !last_was_separator {
                part.push('-');
                last_was_separator = true;
            }
        }

        let part = part.trim_matches('-');
        if !part.is_empty() {
            parts.push(part.to_string());
        }
    }

    parts.join("-")
}

/// Get workspace file reservation count with fallback.
///
/// Returns actual reservation count from Agent Mail or a conservative fallback.
pub fn get_workspace_file_reservations() -> Result<u32, Box<dyn std::error::Error>> {
    get_active_file_reservations()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cargo_entry(command_id: &str) -> AgentCommandBudgetEntry {
        AgentCommandBudgetEntry::new(
            command_id,
            AgentCommandFamily::Cargo,
            AgentCommandCostClass::LocalCpuSensitive,
            AgentCommandExecutionPolicy::LocalAllowed,
            "cargo test -p frankenengine-node",
        )
        .with_touched_paths(["crates/franken-node/src/lib.rs"])
    }

    fn write_reservation_fixture(
        dir: &Path,
        name: &str,
        expires_ts: &str,
        released_ts: Option<&str>,
    ) {
        let payload = serde_json::json!({
            "id": name,
            "project": "/data/projects/franken_node",
            "agent": "TestAgent",
            "path_pattern": "crates/franken-node/src/main.rs",
            "exclusive": true,
            "reason": "test",
            "created_ts": Utc::now().to_rfc3339(),
            "expires_ts": expires_ts,
            "released_ts": released_ts,
        });

        std::fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&payload).expect("serialize reservation fixture"),
        )
        .expect("write reservation fixture");
    }

    #[test]
    fn active_reservation_archive_counter_ignores_expired_released_and_invalid_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let reservations_dir = dir.path().join("file_reservations");
        std::fs::create_dir_all(&reservations_dir).expect("create reservations dir");

        let future = (Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
        let past = (Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
        let released = Utc::now().to_rfc3339();

        write_reservation_fixture(&reservations_dir, "active", &future, None);
        write_reservation_fixture(&reservations_dir, "expired", &past, None);
        write_reservation_fixture(&reservations_dir, "released", &future, Some(&released));
        std::fs::write(
            reservations_dir.join("missing_expiry.json"),
            br#"{"released_ts":null}"#,
        )
        .expect("write missing expiry");
        std::fs::write(reservations_dir.join("malformed.json"), b"{").expect("write malformed");
        std::fs::write(reservations_dir.join("ignored.txt"), b"{}").expect("write ignored");

        assert_eq!(count_active_reservations_in_dir(&reservations_dir), Some(1));
    }

    #[test]
    fn active_reservation_archive_counter_returns_none_for_missing_directory() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert_eq!(
            count_active_reservations_in_dir(&dir.path().join("missing")),
            None
        );
    }

    #[test]
    fn empty_agent_command_ledger_has_stable_schema() {
        let ledger = AgentCommandBudgetLedger::try_new(
            "session-empty",
            "CalmSnow",
            Some("bd-38hez.4".to_string()),
            Vec::new(),
        )
        .expect("empty ledger should be valid");

        assert_eq!(ledger.schema_version, AGENT_COMMAND_LEDGER_SCHEMA_VERSION);
        assert_eq!(ledger.summary.command_count, 0);
        assert_eq!(ledger.summary.policy_violation_count, 0);

        let encoded = serde_json::to_string_pretty(&ledger).expect("ledger serializes");
        assert!(encoded.contains("franken-node/agent-command-ledger/v1"));
        assert!(encoded.contains("\"command_count\": 0"));
    }

    #[test]
    fn agent_command_ledger_caps_entries() {
        let entries = (0..=MAX_AGENT_COMMAND_LEDGER_ENTRIES)
            .map(|idx| {
                AgentCommandBudgetEntry::new(
                    format!("cmd-{idx}"),
                    AgentCommandFamily::SourceOnly,
                    AgentCommandCostClass::SourceOnly,
                    AgentCommandExecutionPolicy::SourceOnly,
                    "ubs crates/franken-node/src/ops/workspace_pressure_policy.rs",
                )
            })
            .collect();

        let err = AgentCommandBudgetLedger::try_new("session-cap", "CalmSnow", None, entries)
            .expect_err("entry cap should fail closed");

        assert_eq!(
            err,
            AgentCommandLedgerError::TooManyEntries {
                count: MAX_AGENT_COMMAND_LEDGER_ENTRIES + 1,
                max: MAX_AGENT_COMMAND_LEDGER_ENTRIES
            }
        );
    }

    #[test]
    fn bare_cargo_command_records_policy_violations() {
        let ledger = AgentCommandBudgetLedger::try_new(
            "session-bare-cargo",
            "CalmSnow",
            Some("bd-38hez.4".to_string()),
            vec![cargo_entry("cmd-bare-cargo")],
        )
        .expect("ledger should derive violations");

        assert!(ledger.entries.first().is_some_and(|entry| {
            entry
                .violations
                .contains(&AgentCommandPolicyViolation::BareCargo)
                && entry
                    .violations
                    .contains(&AgentCommandPolicyViolation::MissingRchForCargo)
                && entry
                    .violations
                    .contains(&AgentCommandPolicyViolation::UnreservedCodeEdit)
        }));
        assert_eq!(ledger.summary.commands_with_violations, 1);
        assert_eq!(ledger.summary.policy_violation_count, 3);
    }

    #[test]
    fn valid_rch_cargo_proof_has_no_policy_violations() {
        let entry = AgentCommandBudgetEntry::new(
            "cmd-rch-cargo",
            AgentCommandFamily::Cargo,
            AgentCommandCostClass::RchRemote,
            AgentCommandExecutionPolicy::RchRequired,
            "rch exec -- cargo test -p frankenengine-node validation_planner",
        )
        .with_elapsed_ms(42_000)
        .with_target_dir(".rch-target-vmi1167313-job")
        .with_touched_paths(["crates/franken-node/src/ops/workspace_pressure_policy.rs"])
        .with_reservation_refs(["agent-mail-reservation-17248"])
        .with_evidence_links(["rch://29833915539653001"])
        .with_validation_outcome(AgentCommandValidationOutcome::Passed);

        let ledger = AgentCommandBudgetLedger::try_new(
            "session-rch",
            "CalmSnow",
            Some("bd-38hez.4".to_string()),
            vec![entry],
        )
        .expect("rch proof ledger should validate");

        assert!(
            ledger
                .entries
                .first()
                .is_some_and(|entry| entry.violations.is_empty())
        );
        assert_eq!(ledger.summary.rch_submissions, 1);
        assert_eq!(ledger.summary.validation_passed, 1);
        assert_eq!(ledger.summary.policy_violation_count, 0);
    }

    #[test]
    fn non_cargo_source_only_proof_has_no_policy_violations() {
        let entry = AgentCommandBudgetEntry::new(
            "cmd-ubs",
            AgentCommandFamily::Ubs,
            AgentCommandCostClass::SourceOnly,
            AgentCommandExecutionPolicy::SourceOnly,
            "UBS_SKIP_RUST_BUILD=1 ubs crates/franken-node/src/ops/workspace_pressure_policy.rs",
        )
        .with_touched_paths(["docs/specs/validation_closeout.md"])
        .with_validation_outcome(AgentCommandValidationOutcome::Passed);

        let ledger =
            AgentCommandBudgetLedger::try_new("session-source", "CalmSnow", None, vec![entry])
                .expect("source-only ledger should validate");

        assert!(
            ledger
                .entries
                .first()
                .is_some_and(|entry| entry.violations.is_empty())
        );
        assert_eq!(ledger.summary.command_count, 1);
        assert_eq!(ledger.summary.validation_passed, 1);
    }

    #[test]
    fn protected_command_values_are_redacted_in_ledger() {
        let entry = AgentCommandBudgetEntry::new(
            "cmd-redact",
            AgentCommandFamily::AgentMail,
            AgentCommandCostClass::Coordination,
            AgentCommandExecutionPolicy::CoordinationOnly,
            "send_message SECRET_TOKEN=raw --password hunter2 --api-key=abcdef",
        );

        let ledger =
            AgentCommandBudgetLedger::try_new("session-redact", "CalmSnow", None, vec![entry])
                .expect("redacted ledger should validate");

        let summary = ledger
            .entries
            .first()
            .map(|entry| entry.command_summary.as_str())
            .unwrap_or("");
        assert!(!summary.contains("raw"));
        assert!(!summary.contains("hunter2"));
        assert!(!summary.contains("abcdef"));
        assert!(summary.contains("SECRET_TOKEN=<redacted>"));
        assert!(summary.contains("--password <redacted>"));
        assert!(summary.contains("--api-key=<redacted>"));
    }

    #[test]
    fn human_agent_command_ledger_summary_is_stable() {
        let ledger = AgentCommandBudgetLedger::try_new(
            "session-human",
            "CalmSnow",
            Some("bd-38hez.4".to_string()),
            vec![cargo_entry("cmd-human")],
        )
        .expect("ledger should validate");

        let rendered = render_agent_command_ledger_human(&ledger);
        assert!(rendered.contains("session=session-human"));
        assert!(rendered.contains("agent=CalmSnow"));
        assert!(rendered.contains("bead=bd-38hez.4"));
        assert!(rendered.contains("commands=1"));
        assert!(rendered.contains("policy_violations=3"));
    }

    #[test]
    fn test_work_cost_classes() {
        assert!(WorkCostClass::SourceOnly.cost_weight() < WorkCostClass::Fuzzing.cost_weight());
        assert!(WorkCostClass::Validation.prefers_rch());
        assert!(!WorkCostClass::SourceOnly.prefers_rch());
    }

    #[test]
    fn test_policy_thresholds() {
        let conservative = PolicyThresholds::conservative();
        let permissive = PolicyThresholds::permissive();

        assert!(conservative.min_free_disk_bytes > permissive.min_free_disk_bytes);
        assert!(conservative.max_concurrent_builds < permissive.max_concurrent_builds);
    }

    #[test]
    fn test_admission_decision_local_low_pressure() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 2_000_000_000,
            target_dir_bytes: 1_000_000_000,
            active_build_count: 1,
            rch_available_slots: Some(5),
            memory_pressure: 0.3,
            active_reservations: 5,
            coordination_healthy: true,
        };

        let decision = policy.decide_admission(WorkCostClass::SourceOnly, 2, &inputs);
        assert!(matches!(decision.admission, AdmissionDecision::AllowLocal));
        assert!(decision.confidence > 0.8);
    }

    #[test]
    fn test_admission_decision_critical_pressure() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 100_000_000,     // Below threshold
            target_dir_bytes: 15_000_000_000, // Above threshold
            active_build_count: 8,
            rch_available_slots: None,
            memory_pressure: 0.95,
            active_reservations: 75,
            coordination_healthy: false,
        };

        let decision = policy.decide_admission(WorkCostClass::Fuzzing, 1, &inputs);
        assert!(matches!(
            decision.admission,
            AdmissionDecision::RefuseLocalFallback
        ));
        assert!(!decision.cleanup_candidates.is_empty());
    }

    #[test]
    fn test_require_rch_for_expensive_work() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 1_000_000_000,
            target_dir_bytes: 3_000_000_000,
            active_build_count: 4,
            rch_available_slots: Some(3),
            memory_pressure: 0.6,
            active_reservations: 15,
            coordination_healthy: true,
        };

        let decision = policy.decide_admission(WorkCostClass::Benchmark, 1, &inputs);
        assert!(matches!(decision.admission, AdmissionDecision::RequireRch));
    }

    fn bridge_pressure_inputs(
        active_build_count: u32,
        rch_available_slots: Option<u32>,
        memory_pressure: f32,
    ) -> WorkspacePressureInputs {
        WorkspacePressureInputs {
            free_disk_bytes: 2_000_000_000,
            target_dir_bytes: 1_000_000_000,
            active_build_count,
            rch_available_slots,
            memory_pressure,
            active_reservations: 3,
            coordination_healthy: true,
        }
    }

    fn bridge_topology(
        cpu_cores: u32,
        memory_bytes: u64,
        numa_nodes: Option<u32>,
    ) -> WorkspaceHardwareTopologySnapshot {
        WorkspaceHardwareTopologySnapshot {
            snapshot_id: format!("topology-{cpu_cores}-{memory_bytes}"),
            cpu_cores,
            memory_bytes,
            numa_nodes,
            stale: false,
        }
    }

    fn bridge_input(
        work_class: WorkCostClass,
        workspace: WorkspacePressureInputs,
        topology: Option<WorkspaceHardwareTopologySnapshot>,
    ) -> WorkspaceHardwarePlacementInput {
        WorkspaceHardwarePlacementInput {
            bridge_id: format!("bridge-{work_class:?}"),
            workload_id: format!("workload-{work_class:?}"),
            work_class,
            bead_priority: 1,
            requested_command: Some("cargo test -p frankenengine-node validation".to_string()),
            workspace,
            topology,
            timestamp_ms: 1_776_000_000_000,
        }
    }

    #[test]
    fn hardware_bridge_places_source_only_on_high_capacity_host() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let decision = policy.plan_hardware_placement(bridge_input(
            WorkCostClass::SourceOnly,
            bridge_pressure_inputs(0, Some(8), 0.2),
            Some(bridge_topology(96, 256 * 1024 * 1024 * 1024, Some(4))),
        ));

        assert_eq!(decision.action, OperatorWhatIfAction::Allow);
        assert_eq!(decision.reason_code, "HWP_BRIDGE_ALLOW_LOCAL_SOURCE");
        assert_eq!(
            decision.target_profile_id.as_deref(),
            Some("local-high-capacity")
        );
        assert!(!decision.fail_closed);
        assert!(
            decision
                .placement_decision
                .as_ref()
                .is_some_and(|placement| placement
                    .evidence
                    .reasoning_chain
                    .iter()
                    .any(|step| step.contains("selected local-high-capacity")))
        );
    }

    #[test]
    fn hardware_bridge_requires_rch_for_validation_when_slots_exist() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let decision = policy.plan_hardware_placement(bridge_input(
            WorkCostClass::Validation,
            bridge_pressure_inputs(1, Some(6), 0.35),
            Some(bridge_topology(96, 256 * 1024 * 1024 * 1024, Some(4))),
        ));

        assert_eq!(decision.action, OperatorWhatIfAction::RequireRch);
        assert_eq!(
            decision.target_profile_id.as_deref(),
            Some("rch-high-capacity")
        );
        assert!(
            decision
                .approved_dispatch_notes
                .iter()
                .any(|note| note.contains("rch exec -- cargo test"))
        );
        assert!(!decision.fail_closed);
    }

    #[test]
    fn hardware_bridge_queues_when_rch_saturated_and_cpu_busy() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let decision = policy.plan_hardware_placement(bridge_input(
            WorkCostClass::Validation,
            bridge_pressure_inputs(12, Some(0), 0.65),
            Some(bridge_topology(96, 256 * 1024 * 1024 * 1024, Some(4))),
        ));

        assert_eq!(decision.action, OperatorWhatIfAction::Queue);
        assert_eq!(decision.reason_code, "HWP_BRIDGE_QUEUE_POLICY");
        assert!(decision.placement_decision.is_none());
    }

    #[test]
    fn hardware_bridge_refuses_missing_rch_for_benchmark_work() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let decision = policy.plan_hardware_placement(bridge_input(
            WorkCostClass::Benchmark,
            bridge_pressure_inputs(0, None, 0.3),
            Some(bridge_topology(96, 256 * 1024 * 1024 * 1024, Some(4))),
        ));

        assert_eq!(decision.action, OperatorWhatIfAction::RefuseLocalFallback);
        assert!(decision.fail_closed);
        assert!(decision.placement_decision.is_none());
    }

    #[test]
    fn hardware_bridge_reports_missing_numa_without_blocking_source_only() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let decision = policy.plan_hardware_placement(bridge_input(
            WorkCostClass::SourceOnly,
            bridge_pressure_inputs(0, Some(8), 0.2),
            Some(bridge_topology(96, 256 * 1024 * 1024 * 1024, None)),
        ));

        assert_eq!(decision.action, OperatorWhatIfAction::Allow);
        assert!(
            decision
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("NUMA topology unavailable"))
        );
    }

    #[test]
    fn hardware_bridge_fail_closes_stale_topology() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let mut topology = bridge_topology(96, 256 * 1024 * 1024 * 1024, Some(4));
        topology.stale = true;

        let decision = policy.plan_hardware_placement(bridge_input(
            WorkCostClass::SourceOnly,
            bridge_pressure_inputs(0, Some(8), 0.2),
            Some(topology),
        ));

        assert_eq!(decision.action, OperatorWhatIfAction::RefuseLocalFallback);
        assert_eq!(decision.reason_code, "HWP_BRIDGE_STALE_TOPOLOGY");
        assert!(decision.fail_closed);
        assert!(decision.placement_decision.is_none());
    }

    #[test]
    fn hardware_bridge_fail_closes_invalid_pressure_input() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let decision = policy.plan_hardware_placement(bridge_input(
            WorkCostClass::SourceOnly,
            bridge_pressure_inputs(0, Some(8), f32::NAN),
            Some(bridge_topology(96, 256 * 1024 * 1024 * 1024, Some(4))),
        ));

        assert_eq!(decision.action, OperatorWhatIfAction::RefuseLocalFallback);
        assert_eq!(decision.reason_code, "HWP_BRIDGE_INVALID_PRESSURE_INPUT");
        assert!(decision.fail_closed);
    }

    fn lease_root(
        path: &str,
        kind: TargetDirLeaseRootKind,
        free_bytes: u64,
        numa_node: Option<u32>,
    ) -> TargetDirLeaseRoot {
        TargetDirLeaseRoot {
            path: path.to_string(),
            kind,
            total_bytes: 512 * 1024 * 1024 * 1024,
            free_bytes,
            numa_node,
            stable_owner: true,
            existing_lease_count: 0,
            stale: false,
        }
    }

    fn lease_input(roots: Vec<TargetDirLeaseRoot>) -> TargetDirLeasePlanInput {
        TargetDirLeasePlanInput {
            plan_id: "target-dir-plan-bd-c9hho-2".to_string(),
            workspace_root: "/data/projects/franken_node".to_string(),
            bead_id: "bd-c9hho.2".to_string(),
            command_family: TargetDirLeaseCommandFamily::RchCargo,
            expected_artifact_class: TargetDirLeaseArtifactClass::BuildOutput,
            roots,
            topology: Some(bridge_topology(96, 256 * 1024 * 1024 * 1024, Some(4))),
            memory_pressure: 0.35,
            active_reservation_hints: Vec::new(),
            rch_required: true,
            lease_ttl_ms: DEFAULT_TARGET_DIR_LEASE_TTL_MS,
        }
    }

    #[test]
    fn target_dir_lease_prefers_off_repo_root_for_rch_work() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let plan = policy.plan_target_dir_lease(lease_input(vec![
            lease_root(
                "/data/projects/franken_node/target",
                TargetDirLeaseRootKind::RepoLocal,
                200 * 1024 * 1024 * 1024,
                Some(0),
            ),
            lease_root(
                "/data/tmp/franken-node-targets",
                TargetDirLeaseRootKind::OffRepo,
                64 * 1024 * 1024 * 1024,
                Some(1),
            ),
        ]));

        assert_eq!(plan.schema_version, TARGET_DIR_LEASE_PLAN_SCHEMA_VERSION);
        assert_eq!(
            plan.selected_reason_code,
            target_dir_lease_reason_codes::SELECT_OFF_REPO_RCH
        );
        assert!(
            plan.selected_path
                .as_deref()
                .is_some_and(|path| path.starts_with("/data/tmp/franken-node-targets/"))
        );
        assert!(!plan.fail_closed);
        assert!(plan.candidates.iter().any(|candidate| candidate.reason_code
            == target_dir_lease_reason_codes::REJECT_REPO_LOCAL_HEAVY
            && candidate.requires_approval));
    }

    #[test]
    fn target_dir_lease_rejects_unsafe_paths() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let traversal = policy.plan_target_dir_lease(lease_input(vec![lease_root(
            "/data/tmp/../target",
            TargetDirLeaseRootKind::OffRepo,
            64 * 1024 * 1024 * 1024,
            Some(0),
        )]));
        assert!(traversal.fail_closed);
        assert_eq!(
            traversal.selected_reason_code,
            target_dir_lease_reason_codes::FAIL_UNSAFE_PATH
        );

        let nul = policy.plan_target_dir_lease(lease_input(vec![lease_root(
            "/data/tmp/franken\0target",
            TargetDirLeaseRootKind::OffRepo,
            64 * 1024 * 1024 * 1024,
            Some(0),
        )]));
        assert!(nul.fail_closed);
        assert_eq!(
            nul.selected_reason_code,
            target_dir_lease_reason_codes::FAIL_UNSAFE_PATH
        );
    }

    #[test]
    fn target_dir_lease_fail_closes_stale_topology_and_full_roots() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let mut stale_topology = bridge_topology(96, 256 * 1024 * 1024 * 1024, Some(4));
        stale_topology.stale = true;
        let mut input = lease_input(vec![lease_root(
            "/data/tmp/franken-node-targets",
            TargetDirLeaseRootKind::OffRepo,
            64 * 1024 * 1024 * 1024,
            Some(0),
        )]);
        input.topology = Some(stale_topology);

        let stale = policy.plan_target_dir_lease(input);
        assert!(stale.fail_closed);
        assert_eq!(
            stale.selected_reason_code,
            target_dir_lease_reason_codes::FAIL_STALE_TOPOLOGY
        );

        let full = policy.plan_target_dir_lease(lease_input(vec![lease_root(
            "/data/tmp/full",
            TargetDirLeaseRootKind::OffRepo,
            1024 * 1024,
            Some(0),
        )]));
        assert!(full.fail_closed);
        assert_eq!(
            full.selected_reason_code,
            target_dir_lease_reason_codes::FAIL_NO_ELIGIBLE_ROOT
        );
        assert!(
            full.cleanup_recommendations
                .iter()
                .all(|recommendation| recommendation.requires_approval)
        );

        let mut invalid_memory = lease_input(vec![lease_root(
            "/data/tmp/franken-node-targets",
            TargetDirLeaseRootKind::OffRepo,
            64 * 1024 * 1024 * 1024,
            Some(0),
        )]);
        invalid_memory.memory_pressure = f32::NAN;
        let invalid = policy.plan_target_dir_lease(invalid_memory);
        assert!(invalid.fail_closed);
        assert_eq!(
            invalid.selected_reason_code,
            target_dir_lease_reason_codes::FAIL_INVALID_MEMORY
        );
    }

    #[test]
    fn target_dir_lease_missing_numa_degrades_without_blocking_source_only() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let mut input = lease_input(vec![lease_root(
            "/data/tmp/source-targets",
            TargetDirLeaseRootKind::Temp,
            16 * 1024 * 1024 * 1024,
            None,
        )]);
        input.command_family = TargetDirLeaseCommandFamily::SourceOnly;
        input.expected_artifact_class = TargetDirLeaseArtifactClass::Evidence;
        input.rch_required = false;
        input.topology = Some(bridge_topology(96, 256 * 1024 * 1024 * 1024, None));

        let plan = policy.plan_target_dir_lease(input);
        assert!(!plan.fail_closed);
        assert_eq!(
            plan.selected_reason_code,
            target_dir_lease_reason_codes::SELECT_TEMP_ISOLATED
        );
        assert!(
            plan.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("NUMA topology unavailable"))
        );
    }

    #[test]
    fn test_cleanup_candidates_generation() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 200_000_000,     // Low
            target_dir_bytes: 20_000_000_000, // High
            active_build_count: 2,
            rch_available_slots: Some(2),
            memory_pressure: 0.4,
            active_reservations: 10,
            coordination_healthy: true,
        };

        let candidates = policy.propose_cleanup(&inputs);
        assert!(!candidates.is_empty());
        assert!(
            candidates
                .iter()
                .any(|c| c.path.to_string_lossy().contains("target"))
        );
    }

    #[test]
    fn test_coordination_issues_affect_cleanup() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 1_000_000_000,
            target_dir_bytes: 2_000_000_000,
            active_build_count: 1,
            rch_available_slots: Some(5),
            memory_pressure: 0.3,
            active_reservations: 60, // High
            coordination_healthy: false,
        };

        let decision = policy.decide_admission(WorkCostClass::Cleanup, 1, &inputs);
        assert!(matches!(decision.admission, AdmissionDecision::Wait { .. }));
    }

    #[test]
    fn test_get_available_disk_space() {
        // Test happy path - should return a reasonable value
        let disk_space = get_available_disk_space(".");
        assert!(disk_space.is_ok());
        let bytes = disk_space.unwrap();

        // Sanity check: should be more than 1MB and less than 100TB
        assert!(bytes >= 1_000_000); // At least 1MB
        assert!(bytes <= 100_000_000_000_000); // Less than 100TB
    }

    #[test]
    fn test_get_workspace_disk_space_success() {
        // Test that workspace function returns actual disk space when it works
        let workspace_result = get_workspace_disk_space();
        assert!(workspace_result.is_ok());
        let bytes = workspace_result.unwrap();

        // Should be a reasonable amount (more than 1MB, since we're in a valid workspace)
        assert!(bytes >= 1_000_000);
    }

    #[test]
    fn test_get_active_file_reservations() {
        // Test that reservation count function returns a reasonable value
        let reservations_result = get_active_file_reservations();
        assert!(reservations_result.is_ok());
        let count = reservations_result.unwrap();

        // Should be a reasonable count (0-1000 reservations)
        assert!(count <= 1000);
    }

    #[test]
    fn test_get_workspace_file_reservations_fallback() {
        // Test that workspace reservation function always succeeds
        let workspace_result = get_workspace_file_reservations();
        assert!(workspace_result.is_ok());
        let count = workspace_result.unwrap();

        // Should always return a reasonable value (even if Agent Mail is down)
        assert!(count <= 1000);
    }

    #[test]
    fn test_get_active_file_reservations_timeout_protection() {
        // Test that reservation function fails gracefully on unreachable endpoint
        // This tests the timeout protection by trying to connect to a non-existent port
        use std::process::Command;

        // Try connecting to a port that should be closed/timeout quickly
        let result = Command::new("curl")
            .args([
                "-s",
                "-f",
                "--connect-timeout",
                "1",
                "--max-time",
                "2",
                "http://localhost:99999/nonexistent",
            ])
            .output();

        // Should either timeout quickly or fail to connect, not hang indefinitely
        assert!(result.is_ok());
        let output = result.unwrap();
        // Should fail (non-zero exit) due to connection refused or timeout
        assert!(!output.status.success());
    }
}
