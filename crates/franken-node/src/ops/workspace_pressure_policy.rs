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

/// Schema version for workspace-pressure to hardware-planner bridge decisions.
pub const WORKSPACE_HARDWARE_ADMISSION_SCHEMA_VERSION: &str =
    "franken-node/workspace-hardware-admission/v1";

/// Maximum structured log entries emitted by one what-if simulation.
const MAX_OPERATOR_WHAT_IF_LOGS: usize = 32;

/// Maximum cleanup actions returned by one what-if simulation.
const MAX_OPERATOR_WHAT_IF_CLEANUP_ACTIONS: usize = 64;

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

/// RCH queue state visible to an operator simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorWhatIfRchQueueState {
    pub available_slots: Option<u32>,
    pub queued_jobs: u32,
    pub degraded_workers: u32,
    pub local_fallback_allowed: bool,
}

/// Cleanup safety class attached to an observed artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub policy_decision: PolicyDecision,
    pub logs: Vec<OperatorWhatIfLog>,
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
            policy_decision,
            logs: limit_operator_logs(logs),
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
) -> String {
    format!(
        "operator what-if: scenario={} bead={} action={} reason={} retry_after_ms={} command={} cleanup_actions={} pinned_artifacts={} protected_artifacts={} rch_slots={:?} queued_jobs={}",
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
    let memory_risk = if memory_pressure >= 0.95 {
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
