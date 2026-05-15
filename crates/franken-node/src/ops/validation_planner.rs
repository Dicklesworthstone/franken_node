//! Adaptive validation planner for changed files and Beads acceptance.
//!
//! The planner turns a patch surface into a small, auditable validation plan. It
//! favors exact registered integration tests and explicit source-only checks,
//! while recording why broad gates were skipped or when they must be escalated.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use crate::ops::rch_adapter::DEFAULT_MAX_ACTIVE_CARGO_PROCESSES;
use crate::push_bounded;

pub const VALIDATION_PLANNER_SCHEMA_VERSION: &str = "franken-node/validation-planner/plan/v1";
pub const SIBLING_DRIFT_PREFLIGHT_SCHEMA_VERSION: &str =
    "franken-node/validation-planner/sibling-drift-preflight/v1";
pub const BUILD_GRAPH_WATCHER_SCHEMA_VERSION: &str =
    "franken-node/validation-planner/build-graph-watcher/v1";
pub const VALIDATION_SHARD_PLANNER_SCHEMA_VERSION: &str =
    "franken-node/validation-planner/shards/v1";
pub const DEFAULT_CARGO_TOOLCHAIN: &str = "nightly-2026-02-19";
pub const DEFAULT_PACKAGE: &str = "frankenengine-node";
pub const DEFAULT_WORKSPACE_ROOT: &str = "/data/projects/franken_node";
pub const DEFAULT_RCH_PRIORITY: &str = "low";

/// Maximum skipped gates per validation plan to prevent DoS attacks.
const MAX_SKIPPED_GATES: usize = 1_000;
pub const MAX_VALIDATION_SHARDS: usize = 128;
pub const MAX_SIBLING_PREFLIGHT_REPOS: usize = 32;
pub const MAX_SIBLING_PREFLIGHT_BLOCKERS: usize = 128;
pub const MAX_SIBLING_PREFLIGHT_DIAGNOSTICS: usize = 256;
pub const MAX_SIBLING_PREFLIGHT_PATHS: usize = 512;
pub const MAX_SIBLING_PREFLIGHT_FEATURES: usize = 128;
pub const MAX_SIBLING_PREFLIGHT_PATH_BYTES: usize = 4_096;
pub const MAX_SIBLING_PREFLIGHT_FIELD_BYTES: usize = 1_024;
pub const MAX_BUILD_GRAPH_PATH_DEPS: usize = 256;
pub const MAX_BUILD_GRAPH_INVALIDATIONS: usize = 512;

pub mod sibling_drift_reason_codes {
    pub const HEALTHY: &str = "SDP_HEALTHY";
    pub const MISSING_CHECKOUT: &str = "SDP_MISSING_CHECKOUT";
    pub const DIRTY_SOURCE: &str = "SDP_DIRTY_SOURCE";
    pub const MANIFEST_PATH_MISMATCH: &str = "SDP_MANIFEST_PATH_MISMATCH";
    pub const FEATURE_MISMATCH: &str = "SDP_FEATURE_MISMATCH";
    pub const ACTIVE_BLOCKER: &str = "SDP_ACTIVE_BLOCKER";
    pub const CLOSED_BLOCKER: &str = "SDP_CLOSED_BLOCKER";
    pub const STALE_BLOCKER: &str = "SDP_STALE_BLOCKER";
}

pub mod build_graph_reason_codes {
    pub const SIBLING_API_DRIFT: &str = "BGW_SIBLING_API_DRIFT";
    pub const MISSING_PATH_DEPENDENCY: &str = "BGW_MISSING_PATH_DEPENDENCY";
    pub const FEATURE_FLAG_DRIFT: &str = "BGW_FEATURE_FLAG_DRIFT";
    pub const CLOSED_BLOCKER_CARRYOVER: &str = "BGW_CLOSED_BLOCKER_CARRYOVER";
}

pub mod validation_shard_reason_codes {
    pub const SOURCE_ONLY_READY: &str = "VSP_SOURCE_ONLY_READY";
    pub const SOURCE_LANE_SATURATED: &str = "VSP_SOURCE_LANE_SATURATED";
    pub const PROOF_CACHE_HIT: &str = "VSP_PROOF_CACHE_HIT";
    pub const PROOF_COALESCER_IN_FLIGHT: &str = "VSP_PROOF_COALESCER_IN_FLIGHT";
    pub const RCH_FOCUSED_READY: &str = "VSP_RCH_FOCUSED_READY";
    pub const RCH_QUEUE_SATURATED: &str = "VSP_RCH_QUEUE_SATURATED";
    pub const RCH_UNAVAILABLE: &str = "VSP_RCH_UNAVAILABLE";
    pub const SHARED_TARGET_DIR_SERIALIZED: &str = "VSP_SHARED_TARGET_DIR_SERIALIZED";
}

pub mod impact_mapper_reason_codes {
    pub const DIFF_CHECK: &str = "VIM_DIFF_CHECK";
    pub const RUSTFMT_SCOPE: &str = "VIM_RUSTFMT_SCOPE";
    pub const UBS_SCOPE: &str = "VIM_UBS_SCOPE";
    pub const JSON_PARSE: &str = "VIM_JSON_PARSE";
    pub const PYTHON_GATE: &str = "VIM_PYTHON_GATE";
    pub const VALIDATION_CONTRACT: &str = "VIM_VALIDATION_CONTRACT";
    pub const PROOF_CACHE_LOOKUP: &str = "VIM_PROOF_CACHE_LOOKUP";
    pub const PROOF_COALESCER_LOOKUP: &str = "VIM_PROOF_COALESCER_LOOKUP";
    pub const REGISTERED_TEST: &str = "VIM_REGISTERED_TEST";
    pub const PACKAGE_CHECK: &str = "VIM_PACKAGE_CHECK";
    pub const DOCS_ONLY: &str = "VIM_DOCS_ONLY";
    pub const SIBLING_PREFLIGHT: &str = "VIM_SIBLING_PREFLIGHT";
    pub const SIBLING_BLOCKED: &str = "VIM_SIBLING_BLOCKED";
    pub const NO_KNOWN_PROOF: &str = "VIM_NO_KNOWN_PROOF";
    pub const BROAD_GATE_SKIPPED: &str = "VIM_BROAD_GATE_SKIPPED";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredTest {
    pub name: String,
    pub path: String,
    pub required_features: Vec<String>,
}

impl RegisteredTest {
    #[must_use]
    pub fn new(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: normalize_path(path.into()),
            required_features: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_required_features(
        mut self,
        features: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.required_features = sorted_unique(features);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerInput {
    pub bead_id: String,
    pub thread_id: String,
    pub changed_paths: Vec<String>,
    pub labels: Vec<String>,
    pub priority: u8,
    pub acceptance: String,
    pub dependency_context: Vec<PlannerDependencyContext>,
    pub registered_tests: Vec<RegisteredTest>,
    pub workspace_root: String,
    pub package: String,
    pub cargo_toolchain: String,
    pub target_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sibling_preflight: Option<SiblingDriftPreflightReport>,
}

impl PlannerInput {
    #[must_use]
    pub fn new(
        bead_id: impl Into<String>,
        changed_paths: impl IntoIterator<Item = impl Into<String>>,
        registered_tests: Vec<RegisteredTest>,
    ) -> Self {
        let bead_id = bead_id.into();
        Self {
            thread_id: bead_id.clone(),
            target_dir: default_target_dir(&bead_id),
            bead_id,
            changed_paths: sorted_unique(changed_paths),
            labels: Vec::new(),
            priority: 2,
            acceptance: String::new(),
            dependency_context: Vec::new(),
            registered_tests,
            workspace_root: DEFAULT_WORKSPACE_ROOT.to_string(),
            package: DEFAULT_PACKAGE.to_string(),
            cargo_toolchain: DEFAULT_CARGO_TOOLCHAIN.to_string(),
            sibling_preflight: None,
        }
    }

    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.labels = sorted_unique(labels);
        self
    }

    #[must_use]
    pub const fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    #[must_use]
    pub fn with_acceptance(mut self, acceptance: impl Into<String>) -> Self {
        self.acceptance = acceptance.into();
        self
    }

    #[must_use]
    pub fn with_dependency_context(
        mut self,
        dependency_context: impl IntoIterator<Item = PlannerDependencyContext>,
    ) -> Self {
        self.dependency_context = dependency_context.into_iter().collect();
        self.dependency_context
            .sort_by(|left, right| left.bead_id.cmp(&right.bead_id));
        self
    }

    #[must_use]
    pub fn with_sibling_preflight(mut self, preflight: SiblingDriftPreflightReport) -> Self {
        self.sibling_preflight = Some(preflight);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerDependencyContext {
    pub bead_id: String,
    pub status: String,
    pub summary: String,
}

impl PlannerDependencyContext {
    #[must_use]
    pub fn new(
        bead_id: impl Into<String>,
        status: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            bead_id: bead_id.into(),
            status: status.into(),
            summary: summary.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedCommandKind {
    SourceOnly,
    ProofCacheLookup,
    ProofCoalescerLookup,
    RchCargo,
    PythonGate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStrength {
    Required,
    Recommended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCostClass {
    SourceOnly,
    LocalFast,
    ExternalGate,
    CacheLookup,
    RemoteFocused,
    RemoteBroad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationExecutionPolicy {
    SourceOnly,
    SafeLocal,
    PythonGate,
    ProofLookup,
    RchRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationPlanUrgency {
    Routine,
    High,
    Urgent,
}

impl ValidationPlanUrgency {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::High => "high",
            Self::Urgent => "urgent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedCommand {
    pub command_id: String,
    pub kind: PlannedCommandKind,
    pub strength: GateStrength,
    pub reason_code: String,
    pub cost_class: ValidationCostClass,
    pub execution_policy: ValidationExecutionPolicy,
    pub shell: String,
    pub env: BTreeMap<String, String>,
    pub argv: Vec<String>,
    pub rationale: String,
    pub covers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedGate {
    pub gate: String,
    pub reason_code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiblingDriftDecision {
    AllowBroadValidation,
    TargetedSiblingValidation,
    SourceOnly,
    BlockBroadValidation,
}

impl SiblingDriftDecision {
    #[must_use]
    pub const fn blocks_broad_validation(self) -> bool {
        matches!(
            self,
            Self::SourceOnly | Self::BlockBroadValidation | Self::TargetedSiblingValidation
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiblingDriftDiagnosticSeverity {
    Info,
    Warning,
    Blocker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiblingBlockerStatus {
    Active,
    Closed,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingBlockerRef {
    pub repo_id: String,
    pub bead_id: String,
    pub status: SiblingBlockerStatus,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at_utc: Option<String>,
}

impl SiblingBlockerRef {
    #[must_use]
    pub fn new(
        repo_id: impl Into<String>,
        bead_id: impl Into<String>,
        status: SiblingBlockerStatus,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            repo_id: repo_id.into(),
            bead_id: bead_id.into(),
            status,
            summary: summary.into(),
            updated_at_utc: None,
        }
    }

    #[must_use]
    pub fn with_updated_at_utc(mut self, updated_at_utc: impl Into<String>) -> Self {
        self.updated_at_utc = Some(updated_at_utc.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingRepoDriftInput {
    pub repo_id: String,
    pub path: String,
    pub expected_path: String,
    pub manifest_path: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    pub dirty_paths: Vec<String>,
    pub dependency_paths: Vec<String>,
    pub required_features: Vec<String>,
    pub available_features: Vec<String>,
}

impl SiblingRepoDriftInput {
    #[must_use]
    pub fn new(
        repo_id: impl Into<String>,
        path: impl Into<String>,
        expected_path: impl Into<String>,
        manifest_path: impl Into<String>,
    ) -> Self {
        Self {
            repo_id: repo_id.into(),
            path: path.into(),
            expected_path: expected_path.into(),
            manifest_path: manifest_path.into(),
            exists: true,
            head_sha: None,
            dirty_paths: Vec::new(),
            dependency_paths: Vec::new(),
            required_features: Vec::new(),
            available_features: Vec::new(),
        }
    }

    #[must_use]
    pub fn missing(mut self) -> Self {
        self.exists = false;
        self
    }

    #[must_use]
    pub fn with_head_sha(mut self, head_sha: impl Into<String>) -> Self {
        self.head_sha = Some(head_sha.into());
        self
    }

    #[must_use]
    pub fn with_dirty_paths(mut self, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.dirty_paths = sorted_unique(paths);
        self
    }

    #[must_use]
    pub fn with_dependency_paths(
        mut self,
        paths: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.dependency_paths = sorted_unique(paths);
        self
    }

    #[must_use]
    pub fn with_required_features(
        mut self,
        features: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.required_features = sorted_unique(features);
        self
    }

    #[must_use]
    pub fn with_available_features(
        mut self,
        features: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.available_features = sorted_unique(features);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingRepoDrift {
    pub repo_id: String,
    pub path: String,
    pub expected_path: String,
    pub manifest_path: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    pub dirty_paths: Vec<String>,
    pub dependency_paths: Vec<String>,
    pub required_features: Vec<String>,
    pub available_features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingDriftDiagnostic {
    pub repo_id: String,
    pub reason_code: String,
    pub severity: SiblingDriftDiagnosticSeverity,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingDriftPreflightInput {
    pub workspace_root: String,
    pub siblings: Vec<SiblingRepoDriftInput>,
    pub known_blockers: Vec<SiblingBlockerRef>,
}

impl SiblingDriftPreflightInput {
    #[must_use]
    pub fn new(
        workspace_root: impl Into<String>,
        siblings: impl IntoIterator<Item = SiblingRepoDriftInput>,
    ) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            siblings: siblings.into_iter().collect(),
            known_blockers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_known_blockers(
        mut self,
        blockers: impl IntoIterator<Item = SiblingBlockerRef>,
    ) -> Self {
        self.known_blockers = blockers.into_iter().collect();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingDriftPreflightReport {
    pub schema_version: String,
    pub workspace_root: String,
    pub decision: SiblingDriftDecision,
    pub decision_reason_code: String,
    pub siblings: Vec<SiblingRepoDrift>,
    pub known_blockers: Vec<SiblingBlockerRef>,
    pub diagnostics: Vec<SiblingDriftDiagnostic>,
    pub br_comment_markdown: String,
    pub agent_mail_markdown: String,
}

impl SiblingDriftPreflightReport {
    #[must_use]
    pub fn blocks_broad_validation(&self) -> bool {
        self.decision.blocks_broad_validation()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingBuildGraphInput {
    pub repo_id: String,
    pub checkout_path: String,
    pub expected_path: String,
    pub manifest_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_toml: Option<String>,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    pub dirty_paths: Vec<String>,
    pub changed_paths: Vec<String>,
}

impl SiblingBuildGraphInput {
    #[must_use]
    pub fn new(
        repo_id: impl Into<String>,
        checkout_path: impl Into<String>,
        expected_path: impl Into<String>,
        manifest_path: impl Into<String>,
        manifest_toml: impl Into<String>,
    ) -> Self {
        Self {
            repo_id: repo_id.into(),
            checkout_path: checkout_path.into(),
            expected_path: expected_path.into(),
            manifest_path: manifest_path.into(),
            manifest_toml: Some(manifest_toml.into()),
            exists: true,
            head_sha: None,
            dirty_paths: Vec::new(),
            changed_paths: Vec::new(),
        }
    }

    #[must_use]
    pub fn missing(
        repo_id: impl Into<String>,
        checkout_path: impl Into<String>,
        expected_path: impl Into<String>,
        manifest_path: impl Into<String>,
    ) -> Self {
        Self {
            repo_id: repo_id.into(),
            checkout_path: checkout_path.into(),
            expected_path: expected_path.into(),
            manifest_path: manifest_path.into(),
            manifest_toml: None,
            exists: false,
            head_sha: None,
            dirty_paths: Vec::new(),
            changed_paths: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_head_sha(mut self, head_sha: impl Into<String>) -> Self {
        self.head_sha = Some(head_sha.into());
        self
    }

    #[must_use]
    pub fn with_dirty_paths(mut self, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.dirty_paths = sorted_unique(paths);
        self
    }

    #[must_use]
    pub fn with_changed_paths(
        mut self,
        paths: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.changed_paths = sorted_unique(paths);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiRepoBuildGraphWatchInput {
    pub workspace_root: String,
    pub package_manifest_path: String,
    pub package_manifest_toml: String,
    pub siblings: Vec<SiblingBuildGraphInput>,
    pub known_blockers: Vec<SiblingBlockerRef>,
}

impl MultiRepoBuildGraphWatchInput {
    #[must_use]
    pub fn new(
        workspace_root: impl Into<String>,
        package_manifest_path: impl Into<String>,
        package_manifest_toml: impl Into<String>,
        siblings: impl IntoIterator<Item = SiblingBuildGraphInput>,
    ) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            package_manifest_path: package_manifest_path.into(),
            package_manifest_toml: package_manifest_toml.into(),
            siblings: siblings.into_iter().collect(),
            known_blockers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_known_blockers(
        mut self,
        blockers: impl IntoIterator<Item = SiblingBlockerRef>,
    ) -> Self {
        self.known_blockers = blockers.into_iter().collect();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildGraphDependency {
    pub repo_id: String,
    pub dependency_name: String,
    pub manifest_path: String,
    pub dependency_path: String,
    pub expected_path: String,
    pub local_feature_gates: Vec<String>,
    pub requested_features: Vec<String>,
    pub available_features: Vec<String>,
    pub affected_tests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildGraphInvalidation {
    pub repo_id: String,
    pub reason_code: String,
    pub severity: SiblingDriftDiagnosticSeverity,
    pub summary: String,
    pub affected_features: Vec<String>,
    pub affected_tests: Vec<String>,
    pub proof_cache_reusable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiRepoBuildGraphWatchReport {
    pub schema_version: String,
    pub workspace_root: String,
    pub package_manifest_path: String,
    pub dependencies: Vec<BuildGraphDependency>,
    pub sibling_preflight: SiblingDriftPreflightReport,
    pub invalidations: Vec<BuildGraphInvalidation>,
    pub proof_cache_invalidation_reasons: Vec<String>,
    pub validation_plan_invalidation_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationPlan {
    pub schema_version: String,
    pub bead_id: String,
    pub thread_id: String,
    pub labels: Vec<String>,
    pub bead_priority: u8,
    pub urgency: ValidationPlanUrgency,
    pub human_summary: String,
    pub dependency_context: Vec<PlannerDependencyContext>,
    pub changed_paths: Vec<String>,
    pub commands: Vec<PlannedCommand>,
    pub skipped_gates: Vec<SkippedGate>,
    pub escalation_conditions: Vec<String>,
    pub source_only_allowed: bool,
}

impl ValidationPlan {
    #[must_use]
    pub fn command(&self, command_id: &str) -> Option<&PlannedCommand> {
        self.commands
            .iter()
            .find(|command| command.command_id == command_id)
    }

    pub fn rch_commands(&self) -> impl Iterator<Item = &PlannedCommand> {
        self.commands
            .iter()
            .filter(|command| command.kind == PlannedCommandKind::RchCargo)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationShardKind {
    SourceOnly,
    ProofReuse,
    RchCargo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationShardStatus {
    Ready,
    Waiting,
    Blocked,
    Reused,
}

impl ValidationShardStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Waiting => "waiting",
            Self::Blocked => "blocked",
            Self::Reused => "reused",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationShardProofState {
    CacheHit,
    CoalescerInFlight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationShardProofEvidence {
    pub command_id: String,
    pub state: ValidationShardProofState,
    pub evidence_ref: String,
}

impl ValidationShardProofEvidence {
    #[must_use]
    pub fn cache_hit(command_id: impl Into<String>, evidence_ref: impl Into<String>) -> Self {
        Self {
            command_id: command_id.into(),
            state: ValidationShardProofState::CacheHit,
            evidence_ref: evidence_ref.into(),
        }
    }

    #[must_use]
    pub fn coalescer_in_flight(
        command_id: impl Into<String>,
        evidence_ref: impl Into<String>,
    ) -> Self {
        Self {
            command_id: command_id.into(),
            state: ValidationShardProofState::CoalescerInFlight,
            evidence_ref: evidence_ref.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationShardRchQueueState {
    pub rch_available: bool,
    pub workers_available: u16,
    pub queued_builds: u16,
    pub active_builds: u16,
    pub oldest_queued_age_secs: u64,
}

impl Default for ValidationShardRchQueueState {
    fn default() -> Self {
        Self {
            rch_available: true,
            workers_available: 1,
            queued_builds: 0,
            active_builds: 0,
            oldest_queued_age_secs: 0,
        }
    }
}

impl ValidationShardRchQueueState {
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            rch_available: false,
            workers_available: 0,
            queued_builds: 0,
            active_builds: 0,
            oldest_queued_age_secs: 0,
        }
    }

    #[must_use]
    pub const fn saturated(queued_builds: u16, active_builds: u16) -> Self {
        Self {
            rch_available: true,
            workers_available: 0,
            queued_builds,
            active_builds,
            oldest_queued_age_secs: 0,
        }
    }

    fn is_saturated(&self) -> bool {
        self.rch_available
            && (self.workers_available == 0
                || self.queued_builds > self.workers_available
                || usize::from(self.active_builds) > DEFAULT_MAX_ACTIVE_CARGO_PROCESSES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationShardCommandBudget {
    pub max_parallel_rch: usize,
    pub local_source_slots_available: usize,
}

impl Default for ValidationShardCommandBudget {
    fn default() -> Self {
        Self {
            max_parallel_rch: 2,
            local_source_slots_available: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationShardPlannerInput {
    pub plan: ValidationPlan,
    pub rch_queue: ValidationShardRchQueueState,
    pub command_budget: ValidationShardCommandBudget,
    #[serde(default)]
    pub proof_evidence: Vec<ValidationShardProofEvidence>,
    #[serde(default)]
    pub target_dir_overrides: BTreeMap<String, String>,
}

impl ValidationShardPlannerInput {
    #[must_use]
    pub fn new(plan: ValidationPlan) -> Self {
        Self {
            plan,
            rch_queue: ValidationShardRchQueueState::default(),
            command_budget: ValidationShardCommandBudget::default(),
            proof_evidence: Vec::new(),
            target_dir_overrides: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_rch_queue(mut self, rch_queue: ValidationShardRchQueueState) -> Self {
        self.rch_queue = rch_queue;
        self
    }

    #[must_use]
    pub fn with_command_budget(mut self, command_budget: ValidationShardCommandBudget) -> Self {
        self.command_budget = command_budget;
        self
    }

    #[must_use]
    pub fn with_proof_evidence(
        mut self,
        proof_evidence: impl IntoIterator<Item = ValidationShardProofEvidence>,
    ) -> Self {
        self.proof_evidence = proof_evidence.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_target_dir_override(
        mut self,
        command_id: impl Into<String>,
        target_dir: impl Into<String>,
    ) -> Self {
        self.target_dir_overrides
            .insert(command_id.into(), normalize_path(target_dir.into()));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationShard {
    pub shard_id: String,
    pub kind: ValidationShardKind,
    pub status: ValidationShardStatus,
    pub reason_code: String,
    pub command_ids: Vec<String>,
    pub target_dir: Option<String>,
    pub parallel_slot: usize,
    pub blocked_by: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationShardDecisionLog {
    pub command_id: String,
    pub shard_id: String,
    pub reason_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationShardPlan {
    pub schema_version: String,
    pub bead_id: String,
    pub thread_id: String,
    pub source_only_allowed: bool,
    pub max_parallel_rch: usize,
    pub shards: Vec<ValidationShard>,
    pub decision_log: Vec<ValidationShardDecisionLog>,
    pub human_summary: String,
}

impl ValidationShardPlan {
    #[must_use]
    pub fn shard(&self, shard_id: &str) -> Option<&ValidationShard> {
        self.shards
            .iter()
            .find(|shard| shard.shard_id.as_str().eq(shard_id))
    }
}

#[must_use]
pub fn plan_validation_shards(input: &ValidationShardPlannerInput) -> ValidationShardPlan {
    let proof_evidence = input
        .proof_evidence
        .iter()
        .map(|evidence| (evidence.command_id.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let mut source_commands = Vec::new();
    let mut rch_groups: BTreeMap<String, Vec<&PlannedCommand>> = BTreeMap::new();
    let mut shards = Vec::new();
    let mut decision_log = Vec::new();

    for command in &input.plan.commands {
        if let Some(evidence) = proof_evidence.get(command.command_id.as_str()) {
            let (status, reason_code, summary) = match evidence.state {
                ValidationShardProofState::CacheHit => (
                    ValidationShardStatus::Reused,
                    validation_shard_reason_codes::PROOF_CACHE_HIT,
                    format!(
                        "proof cache hit for {} via {}",
                        command.command_id, evidence.evidence_ref
                    ),
                ),
                ValidationShardProofState::CoalescerInFlight => (
                    ValidationShardStatus::Waiting,
                    validation_shard_reason_codes::PROOF_COALESCER_IN_FLIGHT,
                    format!(
                        "join in-flight proof for {} via {}",
                        command.command_id, evidence.evidence_ref
                    ),
                ),
            };
            let shard_id = format!("proof-{}", stable_token(&command.command_id));
            push_shard(
                &mut shards,
                ValidationShard {
                    shard_id: shard_id.clone(),
                    kind: ValidationShardKind::ProofReuse,
                    status,
                    reason_code: reason_code.to_string(),
                    command_ids: vec![command.command_id.clone()],
                    target_dir: None,
                    parallel_slot: 0,
                    blocked_by: Vec::new(),
                    summary: summary.clone(),
                },
            );
            decision_log.push(ValidationShardDecisionLog {
                command_id: command.command_id.clone(),
                shard_id,
                reason_code: reason_code.to_string(),
                detail: summary,
            });
            continue;
        }

        match command.kind {
            PlannedCommandKind::RchCargo => {
                let target_dir = input
                    .target_dir_overrides
                    .get(&command.command_id)
                    .cloned()
                    .or_else(|| command_target_dir(command))
                    .unwrap_or_else(|| "unknown-target-dir".to_string());
                rch_groups.entry(target_dir).or_default().push(command);
            }
            PlannedCommandKind::SourceOnly
            | PlannedCommandKind::ProofCacheLookup
            | PlannedCommandKind::ProofCoalescerLookup
            | PlannedCommandKind::PythonGate => {
                source_commands.push(command);
            }
        }
    }

    if !source_commands.is_empty() {
        let waiting = input.command_budget.local_source_slots_available == 0;
        let reason_code = if waiting {
            validation_shard_reason_codes::SOURCE_LANE_SATURATED
        } else {
            validation_shard_reason_codes::SOURCE_ONLY_READY
        };
        let status = if waiting {
            ValidationShardStatus::Waiting
        } else {
            ValidationShardStatus::Ready
        };
        let command_ids = source_commands
            .iter()
            .map(|command| command.command_id.clone())
            .collect::<Vec<_>>();
        let summary = if waiting {
            format!(
                "source-only lane is saturated; wait before running {} local commands",
                command_ids.len()
            )
        } else {
            format!(
                "run {} source-only, Python, and proof-lookup commands locally",
                command_ids.len()
            )
        };
        push_shard(
            &mut shards,
            ValidationShard {
                shard_id: "source-only".to_string(),
                kind: ValidationShardKind::SourceOnly,
                status,
                reason_code: reason_code.to_string(),
                command_ids: command_ids.clone(),
                target_dir: None,
                parallel_slot: 0,
                blocked_by: Vec::new(),
                summary: summary.clone(),
            },
        );
        for command_id in command_ids {
            decision_log.push(ValidationShardDecisionLog {
                command_id,
                shard_id: "source-only".to_string(),
                reason_code: reason_code.to_string(),
                detail: summary.clone(),
            });
        }
    }

    let mut rch_slot = 0usize;
    for (target_dir, commands) in rch_groups {
        let command_ids = commands
            .iter()
            .map(|command| command.command_id.clone())
            .collect::<Vec<_>>();
        let shared_target = command_ids.len() > 1;
        let (status, reason_code, blocked_by, summary) = if !input.rch_queue.rch_available {
            (
                ValidationShardStatus::Blocked,
                validation_shard_reason_codes::RCH_UNAVAILABLE,
                vec!["rch unavailable".to_string()],
                format!(
                    "RCH is unavailable; cannot run {} cargo commands for {}",
                    command_ids.len(),
                    target_dir
                ),
            )
        } else if input.rch_queue.is_saturated() {
            (
                ValidationShardStatus::Waiting,
                validation_shard_reason_codes::RCH_QUEUE_SATURATED,
                vec![format!(
                    "workers_available={} queued_builds={} active_builds={}",
                    input.rch_queue.workers_available,
                    input.rch_queue.queued_builds,
                    input.rch_queue.active_builds
                )],
                format!(
                    "RCH queue is saturated; wait before running {} cargo commands for {}",
                    command_ids.len(),
                    target_dir
                ),
            )
        } else if shared_target {
            (
                ValidationShardStatus::Ready,
                validation_shard_reason_codes::SHARED_TARGET_DIR_SERIALIZED,
                Vec::new(),
                format!(
                    "serialize {} cargo commands through shared target dir {}",
                    command_ids.len(),
                    target_dir
                ),
            )
        } else {
            (
                ValidationShardStatus::Ready,
                validation_shard_reason_codes::RCH_FOCUSED_READY,
                Vec::new(),
                format!(
                    "run focused RCH cargo command {} in isolated target dir {}",
                    command_ids[0], target_dir
                ),
            )
        };
        let shard_id = format!("rch-{}", stable_token(&target_dir));
        let parallel_slot = if status == ValidationShardStatus::Ready {
            let slot = rch_slot % input.command_budget.max_parallel_rch.max(1);
            rch_slot = rch_slot.saturating_add(1);
            slot
        } else {
            0
        };
        push_shard(
            &mut shards,
            ValidationShard {
                shard_id: shard_id.clone(),
                kind: ValidationShardKind::RchCargo,
                status,
                reason_code: reason_code.to_string(),
                command_ids: command_ids.clone(),
                target_dir: Some(target_dir.clone()),
                parallel_slot,
                blocked_by,
                summary: summary.clone(),
            },
        );
        for command_id in command_ids {
            decision_log.push(ValidationShardDecisionLog {
                command_id,
                shard_id: shard_id.clone(),
                reason_code: reason_code.to_string(),
                detail: summary.clone(),
            });
        }
    }

    shards.sort_by(|left, right| {
        left.status
            .cmp(&right.status)
            .then(left.kind_label().cmp(right.kind_label()))
            .then(left.shard_id.cmp(&right.shard_id))
    });
    decision_log.sort_by(|left, right| left.command_id.cmp(&right.command_id));
    let ready = shards
        .iter()
        .filter(|shard| shard.status == ValidationShardStatus::Ready)
        .count();
    let waiting = shards
        .iter()
        .filter(|shard| shard.status == ValidationShardStatus::Waiting)
        .count();
    let blocked = shards
        .iter()
        .filter(|shard| shard.status == ValidationShardStatus::Blocked)
        .count();
    let reused = shards
        .iter()
        .filter(|shard| shard.status == ValidationShardStatus::Reused)
        .count();

    ValidationShardPlan {
        schema_version: VALIDATION_SHARD_PLANNER_SCHEMA_VERSION.to_string(),
        bead_id: input.plan.bead_id.clone(),
        thread_id: input.plan.thread_id.clone(),
        source_only_allowed: input.plan.source_only_allowed,
        max_parallel_rch: input.command_budget.max_parallel_rch,
        human_summary: format!(
            "{} validation shards: shards={} ready={} waiting={} blocked={} reused={} max_parallel_rch={}",
            input.plan.bead_id,
            shards.len(),
            ready,
            waiting,
            blocked,
            reused,
            input.command_budget.max_parallel_rch
        ),
        shards,
        decision_log,
    }
}

impl ValidationShard {
    fn kind_label(&self) -> &'static str {
        match self.kind {
            ValidationShardKind::SourceOnly => "source_only",
            ValidationShardKind::ProofReuse => "proof_reuse",
            ValidationShardKind::RchCargo => "rch_cargo",
        }
    }
}

fn push_shard(shards: &mut Vec<ValidationShard>, shard: ValidationShard) {
    push_bounded(shards, shard, MAX_VALIDATION_SHARDS);
}

fn command_target_dir(command: &PlannedCommand) -> Option<String> {
    command.argv.iter().find_map(|arg| {
        arg.strip_prefix("CARGO_TARGET_DIR=")
            .map(|target_dir| normalize_path(target_dir.to_string()))
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationPlannerError {
    #[error("Cargo manifest TOML did not parse: {0}")]
    ManifestToml(#[from] toml::de::Error),
    #[error("Cargo manifest [[test]] entry is missing string name or path at index {index}")]
    InvalidTestEntry { index: usize },
    #[error("sibling drift preflight field {field} exceeded a bounded limit")]
    SiblingPreflightLimit { field: &'static str },
    #[error("sibling drift preflight field {field} contains invalid text")]
    SiblingPreflightText { field: &'static str },
    #[error("build graph watcher field {field} exceeded a bounded limit")]
    BuildGraphLimit { field: &'static str },
}

pub fn parse_registered_tests_from_manifest(
    manifest_toml: &str,
) -> Result<Vec<RegisteredTest>, ValidationPlannerError> {
    let manifest: toml::Value = toml::from_str(manifest_toml)?;
    let Some(tests) = manifest.get("test").and_then(toml::Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut parsed = Vec::with_capacity(tests.len());
    for (index, test) in tests.iter().enumerate() {
        let Some(name) = test.get("name").and_then(toml::Value::as_str) else {
            return Err(ValidationPlannerError::InvalidTestEntry { index });
        };
        let Some(path) = test.get("path").and_then(toml::Value::as_str) else {
            return Err(ValidationPlannerError::InvalidTestEntry { index });
        };
        let required_features = test
            .get("required-features")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        parsed.push(RegisteredTest::new(name, path).with_required_features(required_features));
    }
    parsed.sort_by(|left, right| left.name.cmp(&right.name).then(left.path.cmp(&right.path)));
    Ok(parsed)
}

pub fn build_sibling_drift_preflight(
    input: SiblingDriftPreflightInput,
) -> Result<SiblingDriftPreflightReport, ValidationPlannerError> {
    validate_sibling_preflight_string(
        "workspace_root",
        &input.workspace_root,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_sibling_preflight_len(
        "siblings",
        input.siblings.len(),
        MAX_SIBLING_PREFLIGHT_REPOS,
    )?;
    validate_sibling_preflight_len(
        "known_blockers",
        input.known_blockers.len(),
        MAX_SIBLING_PREFLIGHT_BLOCKERS,
    )?;

    let mut diagnostics = Vec::new();
    let mut siblings = Vec::with_capacity(input.siblings.len());
    for sibling in input.siblings {
        let sibling = normalize_sibling_input(sibling)?;
        append_sibling_drift_diagnostics(&sibling, &mut diagnostics)?;
        siblings.push(sibling);
    }
    siblings.sort_by(|left, right| {
        left.repo_id
            .cmp(&right.repo_id)
            .then(left.path.cmp(&right.path))
    });

    let mut known_blockers = input
        .known_blockers
        .into_iter()
        .map(normalize_blocker_ref)
        .collect::<Result<Vec<_>, _>>()?;
    known_blockers.sort_by(|left, right| {
        left.repo_id
            .cmp(&right.repo_id)
            .then(left.bead_id.cmp(&right.bead_id))
    });
    for blocker in &known_blockers {
        append_blocker_diagnostic(blocker, &mut diagnostics)?;
    }

    diagnostics.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then(left.repo_id.cmp(&right.repo_id))
            .then(left.reason_code.cmp(&right.reason_code))
            .then(left.summary.cmp(&right.summary))
            .then(left.bead_id.cmp(&right.bead_id))
    });
    diagnostics.dedup_by(|left, right| {
        left.repo_id == right.repo_id
            && left.reason_code == right.reason_code
            && left.summary == right.summary
            && left.bead_id == right.bead_id
    });

    let decision = sibling_preflight_decision(&diagnostics);
    let decision_reason_code = sibling_preflight_decision_reason(decision, &diagnostics);
    let br_comment_markdown =
        render_sibling_preflight_markdown(decision, &decision_reason_code, &diagnostics);

    Ok(SiblingDriftPreflightReport {
        schema_version: SIBLING_DRIFT_PREFLIGHT_SCHEMA_VERSION.to_string(),
        workspace_root: normalize_path(input.workspace_root),
        decision,
        decision_reason_code: decision_reason_code.clone(),
        siblings,
        known_blockers,
        diagnostics,
        agent_mail_markdown: br_comment_markdown.clone(),
        br_comment_markdown,
    })
}

pub fn build_multi_repo_build_graph_watch(
    input: MultiRepoBuildGraphWatchInput,
) -> Result<MultiRepoBuildGraphWatchReport, ValidationPlannerError> {
    validate_sibling_preflight_string(
        "build_graph.workspace_root",
        &input.workspace_root,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_sibling_preflight_string(
        "build_graph.package_manifest_path",
        &input.package_manifest_path,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_sibling_preflight_len(
        "build_graph.siblings",
        input.siblings.len(),
        MAX_SIBLING_PREFLIGHT_REPOS,
    )?;
    validate_sibling_preflight_len(
        "build_graph.known_blockers",
        input.known_blockers.len(),
        MAX_SIBLING_PREFLIGHT_BLOCKERS,
    )?;

    let package_manifest: toml::Value = toml::from_str(&input.package_manifest_toml)?;
    let registered_tests = parse_registered_tests_from_manifest(&input.package_manifest_toml)?;
    let package_manifest_path = normalize_resolved_path(Path::new(&input.package_manifest_path));
    let path_deps = extract_manifest_path_dependencies(&package_manifest, &package_manifest_path)?;
    validate_sibling_preflight_len(
        "build_graph.path_dependencies",
        path_deps.len(),
        MAX_BUILD_GRAPH_PATH_DEPS,
    )?;
    let feature_map = manifest_feature_map(&package_manifest);

    let mut preflight_siblings = Vec::with_capacity(input.siblings.len());
    let mut dependencies = Vec::new();
    let mut invalidations = Vec::new();

    for sibling in input.siblings {
        let sibling = normalize_build_graph_sibling(sibling)?;
        let available_features = sibling
            .manifest_toml
            .as_deref()
            .map(parse_manifest_feature_names)
            .transpose()?
            .unwrap_or_default();
        let related_deps = path_deps
            .iter()
            .filter(|dependency| dependency_matches_sibling(dependency, &sibling))
            .cloned()
            .collect::<Vec<_>>();
        let matching_deps = related_deps
            .iter()
            .filter(|dependency| {
                path_is_at_or_under(&dependency.resolved_path, &sibling.expected_path)
            })
            .cloned()
            .collect::<Vec<_>>();

        if matching_deps.is_empty() {
            push_build_graph_invalidation(
                &mut invalidations,
                BuildGraphInvalidation {
                    repo_id: sibling.repo_id.clone(),
                    reason_code: build_graph_reason_codes::MISSING_PATH_DEPENDENCY.to_string(),
                    severity: SiblingDriftDiagnosticSeverity::Blocker,
                    summary: format!(
                        "package manifest has no path dependency under {} for {}",
                        sibling.expected_path, sibling.repo_id
                    ),
                    affected_features: Vec::new(),
                    affected_tests: Vec::new(),
                    proof_cache_reusable: false,
                },
            )?;
        }

        let mut sibling_requested_features = BTreeSet::new();
        for dependency in related_deps {
            let local_feature_gates = feature_gates_for_dependency(&dependency.name, &feature_map);
            let affected_tests = affected_tests_for_dependency(
                &dependency.name,
                &sibling.repo_id,
                &local_feature_gates,
                &registered_tests,
            );
            sibling_requested_features.extend(dependency.requested_features.iter().cloned());
            dependencies.push(BuildGraphDependency {
                repo_id: sibling.repo_id.clone(),
                dependency_name: dependency.name,
                manifest_path: package_manifest_path.clone(),
                dependency_path: dependency.resolved_path,
                expected_path: sibling.expected_path.clone(),
                local_feature_gates,
                requested_features: dependency.requested_features,
                available_features: available_features.clone(),
                affected_tests,
            });
        }

        if !sibling.changed_paths.is_empty() || !sibling.dirty_paths.is_empty() {
            let affected_features = dependencies
                .iter()
                .filter(|dependency| dependency.repo_id == sibling.repo_id)
                .flat_map(|dependency| dependency.local_feature_gates.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let affected_tests = dependencies
                .iter()
                .filter(|dependency| dependency.repo_id == sibling.repo_id)
                .flat_map(|dependency| dependency.affected_tests.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let changed = sorted_unique(
                sibling
                    .changed_paths
                    .iter()
                    .chain(sibling.dirty_paths.iter())
                    .cloned(),
            );
            push_build_graph_invalidation(
                &mut invalidations,
                BuildGraphInvalidation {
                    repo_id: sibling.repo_id.clone(),
                    reason_code: build_graph_reason_codes::SIBLING_API_DRIFT.to_string(),
                    severity: SiblingDriftDiagnosticSeverity::Blocker,
                    summary: format!(
                        "sibling {} changed build/API inputs: {}",
                        sibling.repo_id,
                        changed.join(",")
                    ),
                    affected_features,
                    affected_tests,
                    proof_cache_reusable: false,
                },
            )?;
        }

        let missing_features = sibling_requested_features
            .iter()
            .filter(|feature| !available_features.contains(*feature))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_features.is_empty() {
            let affected_features = dependencies
                .iter()
                .filter(|dependency| dependency.repo_id == sibling.repo_id)
                .flat_map(|dependency| dependency.local_feature_gates.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let affected_tests = dependencies
                .iter()
                .filter(|dependency| dependency.repo_id == sibling.repo_id)
                .flat_map(|dependency| dependency.affected_tests.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            push_build_graph_invalidation(
                &mut invalidations,
                BuildGraphInvalidation {
                    repo_id: sibling.repo_id.clone(),
                    reason_code: build_graph_reason_codes::FEATURE_FLAG_DRIFT.to_string(),
                    severity: SiblingDriftDiagnosticSeverity::Blocker,
                    summary: format!(
                        "sibling {} is missing requested dependency features: {}",
                        sibling.repo_id,
                        missing_features.join(",")
                    ),
                    affected_features,
                    affected_tests,
                    proof_cache_reusable: false,
                },
            )?;
        }

        let dependency_paths = dependencies
            .iter()
            .filter(|dependency| dependency.repo_id == sibling.repo_id)
            .map(|dependency| dependency.dependency_path.clone())
            .collect::<Vec<_>>();
        let drift = SiblingRepoDriftInput::new(
            sibling.repo_id,
            sibling.checkout_path,
            sibling.expected_path,
            sibling.manifest_path,
        )
        .with_dirty_paths(sibling.dirty_paths)
        .with_dependency_paths(dependency_paths)
        .with_required_features(sibling_requested_features)
        .with_available_features(available_features);
        let drift = if sibling.exists {
            drift
        } else {
            drift.missing()
        };
        let drift = if let Some(head_sha) = sibling.head_sha {
            drift.with_head_sha(head_sha)
        } else {
            drift
        };
        preflight_siblings.push(drift);
    }

    for blocker in &input.known_blockers {
        if blocker.status == SiblingBlockerStatus::Closed {
            push_build_graph_invalidation(
                &mut invalidations,
                BuildGraphInvalidation {
                    repo_id: blocker.repo_id.clone(),
                    reason_code: build_graph_reason_codes::CLOSED_BLOCKER_CARRYOVER.to_string(),
                    severity: SiblingDriftDiagnosticSeverity::Info,
                    summary: blocker.summary.clone(),
                    affected_features: Vec::new(),
                    affected_tests: Vec::new(),
                    proof_cache_reusable: true,
                },
            )?;
        }
    }

    dependencies.sort_by(|left, right| {
        left.repo_id
            .cmp(&right.repo_id)
            .then(left.dependency_name.cmp(&right.dependency_name))
            .then(left.dependency_path.cmp(&right.dependency_path))
    });
    invalidations.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then(left.repo_id.cmp(&right.repo_id))
            .then(left.reason_code.cmp(&right.reason_code))
            .then(left.summary.cmp(&right.summary))
    });
    invalidations.dedup_by(|left, right| {
        left.repo_id == right.repo_id
            && left.reason_code == right.reason_code
            && left.summary == right.summary
    });

    let proof_cache_invalidation_reasons = invalidations
        .iter()
        .filter(|invalidation| !invalidation.proof_cache_reusable)
        .map(|invalidation| invalidation.reason_code.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let validation_plan_invalidation_reasons = invalidations
        .iter()
        .map(|invalidation| invalidation.reason_code.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let sibling_preflight = build_sibling_drift_preflight(
        SiblingDriftPreflightInput::new(&input.workspace_root, preflight_siblings)
            .with_known_blockers(input.known_blockers),
    )?;

    Ok(MultiRepoBuildGraphWatchReport {
        schema_version: BUILD_GRAPH_WATCHER_SCHEMA_VERSION.to_string(),
        workspace_root: normalize_resolved_path(Path::new(&input.workspace_root)),
        package_manifest_path,
        dependencies,
        sibling_preflight,
        invalidations,
        proof_cache_invalidation_reasons,
        validation_plan_invalidation_reasons,
    })
}

#[must_use]
pub fn plan_validation(input: &PlannerInput) -> ValidationPlan {
    let changed_paths = sorted_unique(input.changed_paths.clone());
    let mut builder = PlanBuilder::new(input, changed_paths.clone());

    if changed_paths.is_empty() {
        builder.add_skipped_gate(
            "cargo validation",
            impact_mapper_reason_codes::NO_KNOWN_PROOF,
            "no changed paths were supplied; require a concrete Beads diff before cargo proof",
        );
        builder.add_escalation("rerun planner with changed paths before closing the bead");
        return builder.finish(true);
    }

    let rust_paths = changed_paths
        .iter()
        .filter(|path| path.ends_with(".rs"))
        .cloned()
        .collect::<Vec<_>>();
    let has_rust = !rust_paths.is_empty();
    let has_manifest = changed_paths
        .iter()
        .any(|path| path.ends_with("Cargo.toml"));
    let has_script = changed_paths
        .iter()
        .any(|path| path.starts_with("scripts/"));
    let has_validation_artifact = changed_paths.iter().any(|path| {
        path.starts_with("artifacts/validation_broker/")
            || path == "docs/specs/validation_broker.md"
    });
    let has_sibling_drift = changed_paths
        .iter()
        .any(|path| is_sibling_dependency_path(path));
    let has_docs_only = changed_paths.iter().all(|path| {
        path.starts_with("docs/")
            || path.starts_with("artifacts/")
            || path.ends_with(".md")
            || path.ends_with(".json")
    });

    builder.add_git_diff_check();
    builder.add_ubs_scope();
    if has_rust {
        builder.add_rustfmt_check(rust_paths.clone());
    }

    if let Some(preflight) = &input.sibling_preflight {
        builder.add_sibling_preflight(preflight);
        if preflight.blocks_broad_validation() {
            builder.add_skipped_gate(
                "rch cargo validation",
                impact_mapper_reason_codes::SIBLING_BLOCKED,
                format!(
                    "sibling drift preflight {} blocks broad validation",
                    preflight.decision_reason_code
                ),
            );
            for diagnostic in preflight
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.severity == SiblingDriftDiagnosticSeverity::Blocker)
            {
                builder.add_escalation(format!(
                    "resolve sibling drift {} for {} before broad validation",
                    diagnostic.reason_code, diagnostic.repo_id
                ));
            }
            return builder.finish(true);
        }
    }

    for path in &changed_paths {
        if path.ends_with(".json") {
            builder.add_json_tool_check(path);
        }
        if path.starts_with("scripts/") && path.ends_with(".py") {
            builder.add_python_script_gate(path);
        }
    }

    if has_validation_artifact {
        builder.add_validation_broker_contract_gate();
    }

    if has_docs_only && !has_rust && !has_manifest && !has_script {
        builder.add_skipped_gate(
            "rch cargo test",
            impact_mapper_reason_codes::DOCS_ONLY,
            "changed paths are docs or contract artifacts only; source-only and contract gates are sufficient",
        );
        builder.add_escalation(
            "run focused RCH cargo tests if the artifact changes a Rust-consumed schema or fixture",
        );
        return builder.finish(true);
    }

    if has_rust || has_manifest || has_sibling_drift {
        builder.add_proof_cache_lookup();
        builder.add_proof_coalescer_lookup();
    }

    if has_manifest {
        builder.add_cargo_check_tests(
            "cargo-check-tests",
            "Cargo manifest changed; validate registered targets and feature metadata",
            changed_paths.clone(),
        );
    }

    if has_sibling_drift {
        builder.add_cargo_check_tests(
            "cargo-check-sibling-drift",
            "sibling dependency drift can break default frankenengine-node validation before local tests run",
            changed_paths.clone(),
        );
        builder.add_escalation(
            "if default-feature check fails in franken_engine, file or cite a sibling blocker bead",
        );
    }

    let mut matched_tests = BTreeSet::new();
    for path in &changed_paths {
        for test in matching_registered_tests(path, &input.registered_tests) {
            matched_tests.insert(test.name.clone());
        }
        if is_cli_surface(path) {
            for test in cli_registered_tests(&input.registered_tests) {
                matched_tests.insert(test.name.clone());
            }
        }
        if path.contains("validation_broker") {
            matched_tests.insert("validation_broker".to_string());
        }
        if path.contains("validation_planner") {
            matched_tests.insert("validation_planner".to_string());
        }
    }

    for test_name in matched_tests {
        if let Some(test) = input
            .registered_tests
            .iter()
            .find(|registered| registered.name == test_name)
        {
            builder.add_cargo_test(test, &changed_paths);
        } else {
            builder.add_escalation(format!(
                "register Cargo test `{test_name}` before relying on it for closeout"
            ));
        }
    }

    if has_rust && builder.rch_command_count == 0 {
        builder.add_cargo_check_tests(
            "cargo-check-rust-surface",
            "Rust source changed but no exact registered integration test matched",
            changed_paths.clone(),
        );
    }

    if builder.rch_command_count == 0 {
        builder.add_skipped_gate(
            "cargo check --all-targets",
            impact_mapper_reason_codes::NO_KNOWN_PROOF,
            "no Rust, Cargo manifest, or sibling dependency path changed",
        );
    } else {
        builder.add_skipped_gate(
            "cargo check --all-targets",
            impact_mapper_reason_codes::BROAD_GATE_SKIPPED,
            "focused registered tests or package checks cover this patch; broaden only after focused failure or changed shared API",
        );
        builder.add_skipped_gate(
            "cargo clippy --all-targets -- -D warnings",
            impact_mapper_reason_codes::BROAD_GATE_SKIPPED,
            "defer broad clippy until focused plan is green or the patch touches shared lint-sensitive APIs",
        );
    }

    builder.finish(false)
}

struct PlanBuilder<'a> {
    input: &'a PlannerInput,
    changed_paths: Vec<String>,
    commands: BTreeMap<String, PlannedCommand>,
    skipped_gates: Vec<SkippedGate>,
    escalation_conditions: BTreeSet<String>,
    rch_command_count: usize,
}

impl<'a> PlanBuilder<'a> {
    fn new(input: &'a PlannerInput, changed_paths: Vec<String>) -> Self {
        Self {
            input,
            changed_paths,
            commands: BTreeMap::new(),
            skipped_gates: Vec::new(),
            escalation_conditions: BTreeSet::new(),
            rch_command_count: 0,
        }
    }

    fn add_git_diff_check(&mut self) {
        let mut argv = vec![
            "git".to_string(),
            "diff".to_string(),
            "--check".to_string(),
            "--".to_string(),
        ];
        argv.extend(self.changed_paths.clone());
        self.add_command(PlannedCommand {
            command_id: "source-diff-check".to_string(),
            kind: PlannedCommandKind::SourceOnly,
            strength: GateStrength::Required,
            reason_code: impact_mapper_reason_codes::DIFF_CHECK.to_string(),
            cost_class: ValidationCostClass::SourceOnly,
            execution_policy: ValidationExecutionPolicy::SourceOnly,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale: "detect whitespace and conflict-marker errors on the exact changed paths"
                .to_string(),
            covers: self.changed_paths.clone(),
        });
    }

    fn add_ubs_scope(&mut self) {
        let mut env = BTreeMap::new();
        env.insert("UBS_SKIP_RUST_BUILD".to_string(), "1".to_string());
        let mut argv = vec!["ubs".to_string()];
        argv.extend(self.changed_paths.clone());
        argv.extend(["--format=jsonl".to_string()]);
        self.add_command(PlannedCommand {
            command_id: "source-ubs-scope".to_string(),
            kind: PlannedCommandKind::SourceOnly,
            strength: GateStrength::Required,
            reason_code: impact_mapper_reason_codes::UBS_SCOPE.to_string(),
            cost_class: ValidationCostClass::LocalFast,
            execution_policy: ValidationExecutionPolicy::SafeLocal,
            shell: shell_command(&env, &argv),
            env,
            argv,
            rationale: "run UBS on the exact changed file set without invoking cargo build hooks"
                .to_string(),
            covers: self.changed_paths.clone(),
        });
    }

    fn add_rustfmt_check(&mut self, rust_paths: Vec<String>) {
        let mut argv = vec![
            "rustfmt".to_string(),
            "--edition".to_string(),
            "2024".to_string(),
            "--check".to_string(),
        ];
        argv.extend(rust_paths.clone());
        self.add_command(PlannedCommand {
            command_id: "source-rustfmt-check".to_string(),
            kind: PlannedCommandKind::SourceOnly,
            strength: GateStrength::Required,
            reason_code: impact_mapper_reason_codes::RUSTFMT_SCOPE.to_string(),
            cost_class: ValidationCostClass::LocalFast,
            execution_policy: ValidationExecutionPolicy::SafeLocal,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale: "format-check only the changed Rust files before scheduling cargo proof"
                .to_string(),
            covers: rust_paths,
        });
    }

    fn add_json_tool_check(&mut self, path: &str) {
        let argv = vec![
            "python3".to_string(),
            "-m".to_string(),
            "json.tool".to_string(),
            path.to_string(),
        ];
        self.add_command(PlannedCommand {
            command_id: format!("json-tool-{}", stable_token(path)),
            kind: PlannedCommandKind::SourceOnly,
            strength: GateStrength::Required,
            reason_code: impact_mapper_reason_codes::JSON_PARSE.to_string(),
            cost_class: ValidationCostClass::LocalFast,
            execution_policy: ValidationExecutionPolicy::SafeLocal,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale: "JSON artifact changed; validate parseability before using it as evidence"
                .to_string(),
            covers: vec![path.to_string()],
        });
    }

    fn add_python_script_gate(&mut self, path: &str) {
        let argv = vec![
            "python3".to_string(),
            path.to_string(),
            "--json".to_string(),
        ];
        self.add_command(PlannedCommand {
            command_id: format!("python-gate-{}", stable_token(path)),
            kind: PlannedCommandKind::PythonGate,
            strength: GateStrength::Recommended,
            reason_code: impact_mapper_reason_codes::PYTHON_GATE.to_string(),
            cost_class: ValidationCostClass::ExternalGate,
            execution_policy: ValidationExecutionPolicy::PythonGate,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale:
                "Python gate script changed; run the script directly in machine-readable mode"
                    .to_string(),
            covers: vec![path.to_string()],
        });
    }

    fn add_validation_broker_contract_gate(&mut self) {
        let argv = vec![
            "python3".to_string(),
            "scripts/check_validation_broker_contract.py".to_string(),
            "--json".to_string(),
        ];
        self.add_command(PlannedCommand {
            command_id: "python-validation-broker-contract".to_string(),
            kind: PlannedCommandKind::PythonGate,
            strength: GateStrength::Required,
            reason_code: impact_mapper_reason_codes::VALIDATION_CONTRACT.to_string(),
            cost_class: ValidationCostClass::ExternalGate,
            execution_policy: ValidationExecutionPolicy::PythonGate,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale: "validation broker contract artifacts changed; run the contract gate"
                .to_string(),
            covers: self.changed_paths.clone(),
        });
    }

    fn add_sibling_preflight(&mut self, preflight: &SiblingDriftPreflightReport) {
        self.add_skipped_gate(
            "sibling drift preflight",
            impact_mapper_reason_codes::SIBLING_PREFLIGHT,
            format!(
                "{} produced {} diagnostics",
                preflight.decision_reason_code,
                preflight.diagnostics.len()
            ),
        );
        if preflight.decision == SiblingDriftDecision::TargetedSiblingValidation {
            self.add_escalation("run targeted sibling validation before broad local proof");
        }
    }

    fn add_proof_cache_lookup(&mut self) {
        let changed_paths = self.changed_paths.join(",");
        let argv = vec![
            "franken-node".to_string(),
            "ops".to_string(),
            "validation-proof-cache".to_string(),
            "lookup".to_string(),
            "--bead-id".to_string(),
            self.input.bead_id.clone(),
            "--thread-id".to_string(),
            self.input.thread_id.clone(),
            "--package".to_string(),
            self.input.package.clone(),
            "--cargo-toolchain".to_string(),
            self.input.cargo_toolchain.clone(),
            "--changed-paths".to_string(),
            changed_paths,
        ];
        self.add_command(PlannedCommand {
            command_id: "cache-lookup".to_string(),
            kind: PlannedCommandKind::ProofCacheLookup,
            strength: GateStrength::Recommended,
            reason_code: impact_mapper_reason_codes::PROOF_CACHE_LOOKUP.to_string(),
            cost_class: ValidationCostClass::CacheLookup,
            execution_policy: ValidationExecutionPolicy::ProofLookup,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale:
                "look up a fresh validation proof-cache receipt before scheduling RCH cargo work"
                    .to_string(),
            covers: self.changed_paths.clone(),
        });
    }

    fn add_proof_coalescer_lookup(&mut self) {
        let changed_paths = self.changed_paths.join(",");
        let argv = vec![
            "franken-node".to_string(),
            "ops".to_string(),
            "validation-proof-coalescer".to_string(),
            "lookup".to_string(),
            "--bead-id".to_string(),
            self.input.bead_id.clone(),
            "--thread-id".to_string(),
            self.input.thread_id.clone(),
            "--package".to_string(),
            self.input.package.clone(),
            "--cargo-toolchain".to_string(),
            self.input.cargo_toolchain.clone(),
            "--target-dir".to_string(),
            self.input.target_dir.clone(),
            "--changed-paths".to_string(),
            changed_paths,
        ];
        self.add_command(PlannedCommand {
            command_id: "cache-proof-coalescer-lookup".to_string(),
            kind: PlannedCommandKind::ProofCoalescerLookup,
            strength: GateStrength::Recommended,
            reason_code: impact_mapper_reason_codes::PROOF_COALESCER_LOOKUP.to_string(),
            cost_class: ValidationCostClass::CacheLookup,
            execution_policy: ValidationExecutionPolicy::ProofLookup,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale: "join an existing in-flight validation proof before scheduling duplicate RCH cargo work"
                .to_string(),
            covers: self.changed_paths.clone(),
        });
    }

    fn add_cargo_test(&mut self, test: &RegisteredTest, covers: &[String]) {
        let mut cargo_args = vec![
            "test".to_string(),
            "-p".to_string(),
            self.input.package.clone(),
        ];
        if !test.required_features.is_empty() {
            cargo_args.push("--no-default-features".to_string());
            cargo_args.push("--features".to_string());
            cargo_args.push(test.required_features.join(","));
        }
        cargo_args.extend([
            "--test".to_string(),
            test.name.clone(),
            "--".to_string(),
            "--nocapture".to_string(),
        ]);

        let command = self.rch_cargo_command(
            format!("cargo-test-{}", test.name),
            impact_mapper_reason_codes::REGISTERED_TEST,
            ValidationCostClass::RemoteFocused,
            cargo_args,
            format!(
                "registered Cargo test `{}` directly covers the changed surface",
                test.name
            ),
            covers.to_vec(),
        );
        self.add_command(command);
        self.rch_command_count = self.rch_command_count.saturating_add(1);
    }

    fn add_cargo_check_tests(
        &mut self,
        command_id: impl Into<String>,
        rationale: impl Into<String>,
        covers: Vec<String>,
    ) {
        let cargo_args = vec![
            "check".to_string(),
            "-p".to_string(),
            self.input.package.clone(),
            "--tests".to_string(),
        ];
        let command = self.rch_cargo_command(
            command_id,
            impact_mapper_reason_codes::PACKAGE_CHECK,
            ValidationCostClass::RemoteBroad,
            cargo_args,
            rationale,
            covers,
        );
        self.add_command(command);
        self.rch_command_count = self.rch_command_count.saturating_add(1);
    }

    fn rch_cargo_command(
        &self,
        command_id: impl Into<String>,
        reason_code: impl Into<String>,
        cost_class: ValidationCostClass,
        cargo_args: Vec<String>,
        rationale: impl Into<String>,
        covers: Vec<String>,
    ) -> PlannedCommand {
        let mut env = BTreeMap::new();
        env.insert("RCH_REQUIRE_REMOTE".to_string(), "1".to_string());
        env.insert("RCH_VISIBILITY".to_string(), "summary".to_string());
        env.insert("RCH_PRIORITY".to_string(), DEFAULT_RCH_PRIORITY.to_string());

        let mut argv = vec![
            "rch".to_string(),
            "exec".to_string(),
            "--".to_string(),
            "env".to_string(),
            format!("CARGO_TARGET_DIR={}", self.input.target_dir),
            "CARGO_INCREMENTAL=0".to_string(),
            "CARGO_BUILD_JOBS=1".to_string(),
            "cargo".to_string(),
            format!("+{}", self.input.cargo_toolchain),
        ];
        argv.extend(cargo_args);

        PlannedCommand {
            command_id: command_id.into(),
            kind: PlannedCommandKind::RchCargo,
            strength: GateStrength::Required,
            reason_code: reason_code.into(),
            cost_class,
            execution_policy: ValidationExecutionPolicy::RchRequired,
            shell: shell_command(&env, &argv),
            env,
            argv,
            rationale: rationale.into(),
            covers: sorted_unique(covers),
        }
    }

    fn add_command(&mut self, command: PlannedCommand) {
        self.commands.insert(command.command_id.clone(), command);
    }

    fn add_skipped_gate(
        &mut self,
        gate: impl Into<String>,
        reason_code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        push_bounded(
            &mut self.skipped_gates,
            SkippedGate {
                gate: gate.into(),
                reason_code: reason_code.into(),
                reason: reason.into(),
            },
            MAX_SKIPPED_GATES,
        );
    }

    fn add_escalation(&mut self, condition: impl Into<String>) {
        self.escalation_conditions.insert(condition.into());
    }

    fn finish(mut self, source_only_allowed: bool) -> ValidationPlan {
        self.skipped_gates.sort_by(|left, right| {
            left.gate
                .cmp(&right.gate)
                .then(left.reason_code.cmp(&right.reason_code))
                .then(left.reason.cmp(&right.reason))
        });
        self.skipped_gates.dedup_by(|left, right| {
            left.gate == right.gate
                && left.reason_code == right.reason_code
                && left.reason == right.reason
        });

        let urgency = validation_plan_urgency(self.input.priority, &self.input.labels);
        let command_count = self.commands.len();
        let rch_command_count = self.rch_command_count;

        ValidationPlan {
            schema_version: VALIDATION_PLANNER_SCHEMA_VERSION.to_string(),
            bead_id: self.input.bead_id.clone(),
            thread_id: self.input.thread_id.clone(),
            labels: self.input.labels.clone(),
            bead_priority: self.input.priority,
            urgency,
            human_summary: render_validation_plan_summary(
                self.input,
                urgency,
                command_count,
                rch_command_count,
                source_only_allowed,
            ),
            dependency_context: self.input.dependency_context.clone(),
            changed_paths: self.changed_paths,
            commands: self.commands.into_values().collect(),
            skipped_gates: self.skipped_gates,
            escalation_conditions: self.escalation_conditions.into_iter().collect(),
            source_only_allowed,
        }
    }
}

fn validation_plan_urgency(priority: u8, labels: &[String]) -> ValidationPlanUrgency {
    if priority == 0
        || labels.iter().any(|label| {
            matches!(
                label.as_str(),
                "urgent" | "security" | "prod" | "production" | "incident"
            )
        })
    {
        return ValidationPlanUrgency::Urgent;
    }

    if priority <= 1
        || labels.iter().any(|label| {
            matches!(
                label.as_str(),
                "validation" | "rch" | "testing" | "operator-safety"
            )
        })
    {
        return ValidationPlanUrgency::High;
    }

    ValidationPlanUrgency::Routine
}

fn render_validation_plan_summary(
    input: &PlannerInput,
    urgency: ValidationPlanUrgency,
    command_count: usize,
    rch_command_count: usize,
    source_only_allowed: bool,
) -> String {
    format!(
        "{} validation plan: priority={} urgency={} changed_paths={} commands={} rch_commands={} source_only_allowed={} dependencies={}",
        input.bead_id,
        input.priority,
        urgency.as_str(),
        input.changed_paths.len(),
        command_count,
        rch_command_count,
        source_only_allowed,
        input.dependency_context.len()
    )
}

fn matching_registered_tests<'a>(
    changed_path: &str,
    registered_tests: &'a [RegisteredTest],
) -> Vec<&'a RegisteredTest> {
    let normalized = normalize_path(changed_path);
    let crate_relative = normalized
        .strip_prefix("crates/franken-node/")
        .unwrap_or(&normalized);
    let stem = file_stem(&normalized);

    registered_tests
        .iter()
        .filter(|test| {
            test.path == crate_relative
                || format!("crates/franken-node/{}", test.path) == normalized
                || stem.is_some_and(|stem| stem == test.name)
        })
        .collect()
}

fn cli_registered_tests(registered_tests: &[RegisteredTest]) -> Vec<&RegisteredTest> {
    registered_tests
        .iter()
        .filter(|test| test.name == "cli_arg_validation")
        .collect()
}

fn is_cli_surface(path: &str) -> bool {
    matches!(
        path,
        "crates/franken-node/src/cli.rs" | "crates/franken-node/src/main.rs"
    )
}

fn is_sibling_dependency_path(path: &str) -> bool {
    path.starts_with("../franken_engine/")
        || path.starts_with("/data/projects/franken_engine/")
        || path.starts_with("franken_engine/")
}

#[derive(Debug, Clone)]
struct ManifestPathDependency {
    name: String,
    resolved_path: String,
    requested_features: Vec<String>,
}

#[derive(Debug, Clone)]
struct NormalizedSiblingBuildGraphInput {
    repo_id: String,
    checkout_path: String,
    expected_path: String,
    manifest_path: String,
    manifest_toml: Option<String>,
    exists: bool,
    head_sha: Option<String>,
    dirty_paths: Vec<String>,
    changed_paths: Vec<String>,
}

fn normalize_build_graph_sibling(
    input: SiblingBuildGraphInput,
) -> Result<NormalizedSiblingBuildGraphInput, ValidationPlannerError> {
    validate_sibling_preflight_string(
        "build_graph.sibling.repo_id",
        &input.repo_id,
        MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
    )?;
    validate_sibling_preflight_string(
        "build_graph.sibling.checkout_path",
        &input.checkout_path,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_sibling_preflight_string(
        "build_graph.sibling.expected_path",
        &input.expected_path,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_sibling_preflight_string(
        "build_graph.sibling.manifest_path",
        &input.manifest_path,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_optional_sibling_preflight_string(
        "build_graph.sibling.head_sha",
        input.head_sha.as_deref(),
        MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
    )?;
    validate_sibling_preflight_len(
        "build_graph.sibling.dirty_paths",
        input.dirty_paths.len(),
        MAX_SIBLING_PREFLIGHT_PATHS,
    )?;
    validate_sibling_preflight_len(
        "build_graph.sibling.changed_paths",
        input.changed_paths.len(),
        MAX_SIBLING_PREFLIGHT_PATHS,
    )?;

    Ok(NormalizedSiblingBuildGraphInput {
        repo_id: input.repo_id,
        checkout_path: normalize_resolved_path(Path::new(&input.checkout_path)),
        expected_path: normalize_resolved_path(Path::new(&input.expected_path)),
        manifest_path: normalize_resolved_path(Path::new(&input.manifest_path)),
        manifest_toml: input.manifest_toml,
        exists: input.exists,
        head_sha: input.head_sha,
        dirty_paths: normalize_sibling_paths(input.dirty_paths)?,
        changed_paths: normalize_sibling_paths(input.changed_paths)?,
    })
}

fn extract_manifest_path_dependencies(
    manifest: &toml::Value,
    manifest_path: &str,
) -> Result<Vec<ManifestPathDependency>, ValidationPlannerError> {
    let manifest_dir = Path::new(manifest_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let mut dependencies = Vec::new();
    collect_manifest_path_dependencies(manifest, manifest_dir, &mut dependencies)?;
    dependencies.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.resolved_path.cmp(&right.resolved_path))
    });
    dependencies.dedup_by(|left, right| {
        left.name == right.name && left.resolved_path == right.resolved_path
    });
    Ok(dependencies)
}

fn collect_manifest_path_dependencies(
    value: &toml::Value,
    manifest_dir: &Path,
    dependencies: &mut Vec<ManifestPathDependency>,
) -> Result<(), ValidationPlannerError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };

    for (key, value) in table {
        if is_dependency_table_name(key) {
            if let Some(dependency_table) = value.as_table() {
                collect_dependency_entries(dependency_table, manifest_dir, dependencies)?;
            }
        } else if key != "features" {
            collect_manifest_path_dependencies(value, manifest_dir, dependencies)?;
        }
    }

    Ok(())
}

fn collect_dependency_entries(
    dependency_table: &toml::map::Map<String, toml::Value>,
    manifest_dir: &Path,
    dependencies: &mut Vec<ManifestPathDependency>,
) -> Result<(), ValidationPlannerError> {
    for (name, value) in dependency_table {
        let Some(path) = value.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        validate_sibling_preflight_string(
            "build_graph.dependency.name",
            name,
            MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
        )?;
        validate_sibling_preflight_string(
            "build_graph.dependency.path",
            path,
            MAX_SIBLING_PREFLIGHT_PATH_BYTES,
        )?;
        dependencies.push(ManifestPathDependency {
            name: name.clone(),
            resolved_path: resolve_dependency_path(manifest_dir, path),
            requested_features: dependency_requested_features(value)?,
        });
    }
    Ok(())
}

fn is_dependency_table_name(name: &str) -> bool {
    matches!(
        name,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    )
}

fn dependency_requested_features(
    value: &toml::Value,
) -> Result<Vec<String>, ValidationPlannerError> {
    let features = value
        .get("features")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    normalize_sibling_features(features)
}

fn parse_manifest_feature_names(
    manifest_toml: &str,
) -> Result<Vec<String>, ValidationPlannerError> {
    let manifest: toml::Value = toml::from_str(manifest_toml)?;
    Ok(manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .map(|features| features.keys().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default()
        .into_iter()
        .collect())
}

fn manifest_feature_map(manifest: &toml::Value) -> BTreeMap<String, Vec<String>> {
    manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .map(|features| {
            features
                .iter()
                .map(|(feature, members)| {
                    let members = members
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(toml::Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>();
                    (feature.clone(), members)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn feature_gates_for_dependency(
    dependency_name: &str,
    feature_map: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut gates = feature_map
        .iter()
        .filter_map(|(feature, members)| {
            let direct_dep = format!("dep:{dependency_name}");
            members
                .iter()
                .any(|member| member == &direct_dep || member == dependency_name)
                .then(|| feature.clone())
        })
        .collect::<BTreeSet<_>>();

    let mut changed = true;
    while changed {
        changed = false;
        for (feature, members) in feature_map {
            if gates.contains(feature) {
                continue;
            }
            if members.iter().any(|member| gates.contains(member)) {
                gates.insert(feature.clone());
                changed = true;
            }
        }
    }

    gates.into_iter().collect()
}

fn affected_tests_for_dependency(
    dependency_name: &str,
    repo_id: &str,
    local_feature_gates: &[String],
    registered_tests: &[RegisteredTest],
) -> Vec<String> {
    let feature_gates = local_feature_gates
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let dependency_token = tokenish(dependency_name);
    let repo_token = tokenish(repo_id);

    registered_tests
        .iter()
        .filter(|test| {
            test.required_features
                .iter()
                .any(|feature| feature_gates.contains(feature.as_str()))
                || test_matches_token(test, &dependency_token)
                || test_matches_token(test, &repo_token)
                || local_feature_gates
                    .iter()
                    .any(|feature| test_matches_token(test, &tokenish(feature)))
        })
        .map(|test| test.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn test_matches_token(test: &RegisteredTest, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    tokenish(&test.name).contains(token) || tokenish(&test.path).contains(token)
}

fn tokenish(value: &str) -> String {
    stable_token(value).replace('-', "_")
}

fn dependency_matches_sibling(
    dependency: &ManifestPathDependency,
    sibling: &NormalizedSiblingBuildGraphInput,
) -> bool {
    path_is_at_or_under(&dependency.resolved_path, &sibling.expected_path)
        || path_is_at_or_under(&dependency.resolved_path, &sibling.checkout_path)
        || tokenish(&dependency.name).contains(&tokenish(&sibling.repo_id))
}

fn push_build_graph_invalidation(
    invalidations: &mut Vec<BuildGraphInvalidation>,
    invalidation: BuildGraphInvalidation,
) -> Result<(), ValidationPlannerError> {
    if invalidations.len() >= MAX_BUILD_GRAPH_INVALIDATIONS {
        return Err(ValidationPlannerError::BuildGraphLimit {
            field: "invalidations",
        });
    }
    invalidations.push(invalidation);
    Ok(())
}

fn normalize_sibling_input(
    input: SiblingRepoDriftInput,
) -> Result<SiblingRepoDrift, ValidationPlannerError> {
    validate_sibling_preflight_string(
        "sibling.repo_id",
        &input.repo_id,
        MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
    )?;
    validate_sibling_preflight_string(
        "sibling.path",
        &input.path,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_sibling_preflight_string(
        "sibling.expected_path",
        &input.expected_path,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_sibling_preflight_string(
        "sibling.manifest_path",
        &input.manifest_path,
        MAX_SIBLING_PREFLIGHT_PATH_BYTES,
    )?;
    validate_optional_sibling_preflight_string(
        "sibling.head_sha",
        input.head_sha.as_deref(),
        MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
    )?;
    validate_sibling_preflight_len(
        "sibling.dirty_paths",
        input.dirty_paths.len(),
        MAX_SIBLING_PREFLIGHT_PATHS,
    )?;
    validate_sibling_preflight_len(
        "sibling.dependency_paths",
        input.dependency_paths.len(),
        MAX_SIBLING_PREFLIGHT_PATHS,
    )?;
    validate_sibling_preflight_len(
        "sibling.required_features",
        input.required_features.len(),
        MAX_SIBLING_PREFLIGHT_FEATURES,
    )?;
    validate_sibling_preflight_len(
        "sibling.available_features",
        input.available_features.len(),
        MAX_SIBLING_PREFLIGHT_FEATURES,
    )?;

    Ok(SiblingRepoDrift {
        repo_id: input.repo_id,
        path: normalize_path(input.path),
        expected_path: normalize_path(input.expected_path),
        manifest_path: normalize_path(input.manifest_path),
        exists: input.exists,
        head_sha: input.head_sha,
        dirty_paths: normalize_sibling_paths(input.dirty_paths)?,
        dependency_paths: normalize_sibling_paths(input.dependency_paths)?,
        required_features: normalize_sibling_features(input.required_features)?,
        available_features: normalize_sibling_features(input.available_features)?,
    })
}

fn normalize_blocker_ref(
    blocker: SiblingBlockerRef,
) -> Result<SiblingBlockerRef, ValidationPlannerError> {
    validate_sibling_preflight_string(
        "blocker.repo_id",
        &blocker.repo_id,
        MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
    )?;
    validate_sibling_preflight_string(
        "blocker.bead_id",
        &blocker.bead_id,
        MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
    )?;
    validate_sibling_preflight_string(
        "blocker.summary",
        &blocker.summary,
        MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
    )?;
    validate_optional_sibling_preflight_string(
        "blocker.updated_at_utc",
        blocker.updated_at_utc.as_deref(),
        MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
    )?;
    Ok(SiblingBlockerRef {
        repo_id: blocker.repo_id,
        bead_id: blocker.bead_id,
        status: blocker.status,
        summary: blocker.summary,
        updated_at_utc: blocker.updated_at_utc,
    })
}

fn normalize_sibling_paths(paths: Vec<String>) -> Result<Vec<String>, ValidationPlannerError> {
    paths
        .into_iter()
        .map(|path| {
            validate_sibling_preflight_string(
                "sibling.path_list",
                &path,
                MAX_SIBLING_PREFLIGHT_PATH_BYTES,
            )?;
            Ok(normalize_path(path))
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map(|set| set.into_iter().collect())
}

fn normalize_sibling_features(
    features: Vec<String>,
) -> Result<Vec<String>, ValidationPlannerError> {
    features
        .into_iter()
        .map(|feature| {
            validate_sibling_preflight_string(
                "sibling.feature",
                &feature,
                MAX_SIBLING_PREFLIGHT_FIELD_BYTES,
            )?;
            Ok(feature)
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map(|set| set.into_iter().collect())
}

fn append_sibling_drift_diagnostics(
    sibling: &SiblingRepoDrift,
    diagnostics: &mut Vec<SiblingDriftDiagnostic>,
) -> Result<(), ValidationPlannerError> {
    if !sibling.exists {
        push_sibling_diagnostic(
            diagnostics,
            SiblingDriftDiagnostic {
                repo_id: sibling.repo_id.clone(),
                reason_code: sibling_drift_reason_codes::MISSING_CHECKOUT.to_string(),
                severity: SiblingDriftDiagnosticSeverity::Blocker,
                summary: format!("sibling checkout {} is missing", sibling.path),
                bead_id: None,
            },
        )?;
    }

    if !sibling.dirty_paths.is_empty() {
        push_sibling_diagnostic(
            diagnostics,
            SiblingDriftDiagnostic {
                repo_id: sibling.repo_id.clone(),
                reason_code: sibling_drift_reason_codes::DIRTY_SOURCE.to_string(),
                severity: SiblingDriftDiagnosticSeverity::Blocker,
                summary: format!(
                    "sibling checkout has dirty source: {}",
                    sibling.dirty_paths.join(",")
                ),
                bead_id: None,
            },
        )?;
    }

    if sibling.dependency_paths.is_empty() {
        push_sibling_diagnostic(
            diagnostics,
            SiblingDriftDiagnostic {
                repo_id: sibling.repo_id.clone(),
                reason_code: sibling_drift_reason_codes::MANIFEST_PATH_MISMATCH.to_string(),
                severity: SiblingDriftDiagnosticSeverity::Blocker,
                summary: format!(
                    "manifest has no dependency path for expected sibling {}",
                    sibling.expected_path
                ),
                bead_id: None,
            },
        )?;
    }

    for dependency_path in &sibling.dependency_paths {
        if !path_is_at_or_under(dependency_path, &sibling.expected_path) {
            push_sibling_diagnostic(
                diagnostics,
                SiblingDriftDiagnostic {
                    repo_id: sibling.repo_id.clone(),
                    reason_code: sibling_drift_reason_codes::MANIFEST_PATH_MISMATCH.to_string(),
                    severity: SiblingDriftDiagnosticSeverity::Blocker,
                    summary: format!(
                        "manifest dependency path {dependency_path} does not match expected {}",
                        sibling.expected_path
                    ),
                    bead_id: None,
                },
            )?;
        }
    }

    let available = sibling
        .available_features
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let missing_features = sibling
        .required_features
        .iter()
        .filter(|feature| !available.contains(*feature))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_features.is_empty() {
        push_sibling_diagnostic(
            diagnostics,
            SiblingDriftDiagnostic {
                repo_id: sibling.repo_id.clone(),
                reason_code: sibling_drift_reason_codes::FEATURE_MISMATCH.to_string(),
                severity: SiblingDriftDiagnosticSeverity::Blocker,
                summary: format!("missing sibling features: {}", missing_features.join(",")),
                bead_id: None,
            },
        )?;
    }

    Ok(())
}

fn append_blocker_diagnostic(
    blocker: &SiblingBlockerRef,
    diagnostics: &mut Vec<SiblingDriftDiagnostic>,
) -> Result<(), ValidationPlannerError> {
    let (reason_code, severity) = match blocker.status {
        SiblingBlockerStatus::Active => (
            sibling_drift_reason_codes::ACTIVE_BLOCKER,
            SiblingDriftDiagnosticSeverity::Blocker,
        ),
        SiblingBlockerStatus::Closed => (
            sibling_drift_reason_codes::CLOSED_BLOCKER,
            SiblingDriftDiagnosticSeverity::Info,
        ),
        SiblingBlockerStatus::Stale => (
            sibling_drift_reason_codes::STALE_BLOCKER,
            SiblingDriftDiagnosticSeverity::Blocker,
        ),
    };

    push_sibling_diagnostic(
        diagnostics,
        SiblingDriftDiagnostic {
            repo_id: blocker.repo_id.clone(),
            reason_code: reason_code.to_string(),
            severity,
            summary: blocker.summary.clone(),
            bead_id: Some(blocker.bead_id.clone()),
        },
    )
}

fn push_sibling_diagnostic(
    diagnostics: &mut Vec<SiblingDriftDiagnostic>,
    diagnostic: SiblingDriftDiagnostic,
) -> Result<(), ValidationPlannerError> {
    if diagnostics.len() >= MAX_SIBLING_PREFLIGHT_DIAGNOSTICS {
        return Err(ValidationPlannerError::SiblingPreflightLimit {
            field: "diagnostics",
        });
    }
    diagnostics.push(diagnostic);
    Ok(())
}

fn sibling_preflight_decision(diagnostics: &[SiblingDriftDiagnostic]) -> SiblingDriftDecision {
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == SiblingDriftDiagnosticSeverity::Blocker)
    {
        return SiblingDriftDecision::BlockBroadValidation;
    }
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == SiblingDriftDiagnosticSeverity::Warning)
    {
        return SiblingDriftDecision::TargetedSiblingValidation;
    }
    SiblingDriftDecision::AllowBroadValidation
}

fn sibling_preflight_decision_reason(
    decision: SiblingDriftDecision,
    diagnostics: &[SiblingDriftDiagnostic],
) -> String {
    match decision {
        SiblingDriftDecision::AllowBroadValidation => {
            sibling_drift_reason_codes::HEALTHY.to_string()
        }
        SiblingDriftDecision::TargetedSiblingValidation => {
            sibling_drift_reason_codes::DIRTY_SOURCE.to_string()
        }
        SiblingDriftDecision::SourceOnly => sibling_drift_reason_codes::DIRTY_SOURCE.to_string(),
        SiblingDriftDecision::BlockBroadValidation => diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == SiblingDriftDiagnosticSeverity::Blocker)
            .map(|diagnostic| diagnostic.reason_code.clone())
            .unwrap_or_else(|| sibling_drift_reason_codes::ACTIVE_BLOCKER.to_string()),
    }
}

fn render_sibling_preflight_markdown(
    decision: SiblingDriftDecision,
    decision_reason_code: &str,
    diagnostics: &[SiblingDriftDiagnostic],
) -> String {
    let mut lines = vec![format!(
        "Sibling drift preflight: {:?} ({decision_reason_code})",
        decision
    )];
    for diagnostic in diagnostics {
        let bead = diagnostic
            .bead_id
            .as_ref()
            .map(|bead_id| format!(" {bead_id}"))
            .unwrap_or_default();
        lines.push(format!(
            "- {} {}{}: {}",
            diagnostic.repo_id, diagnostic.reason_code, bead, diagnostic.summary
        ));
    }
    lines.join("\n")
}

fn validate_sibling_preflight_len(
    field: &'static str,
    len: usize,
    max: usize,
) -> Result<(), ValidationPlannerError> {
    if len > max {
        return Err(ValidationPlannerError::SiblingPreflightLimit { field });
    }
    Ok(())
}

fn validate_optional_sibling_preflight_string(
    field: &'static str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), ValidationPlannerError> {
    if let Some(value) = value {
        validate_sibling_preflight_string(field, value, max_bytes)?;
    }
    Ok(())
}

fn validate_sibling_preflight_string(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ValidationPlannerError> {
    if value.len() > max_bytes {
        return Err(ValidationPlannerError::SiblingPreflightLimit { field });
    }
    if value.contains('\0') {
        return Err(ValidationPlannerError::SiblingPreflightText { field });
    }
    Ok(())
}

fn default_target_dir(bead_id: &str) -> String {
    let suffix = stable_token(if bead_id.trim().is_empty() {
        "untracked"
    } else {
        bead_id
    });
    format!("/data/tmp/franken_node-{suffix}-validation-planner-target")
}

fn normalize_path(path: impl Into<String>) -> String {
    let mut normalized = path.into().replace('\\', "/");
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped.to_string();
    }
    if let Some(stripped) = normalized.strip_prefix("/data/projects/franken_node/") {
        normalized = stripped.to_string();
    }
    normalized
}

fn resolve_dependency_path(manifest_dir: &Path, dependency_path: &str) -> String {
    let dependency_path = Path::new(dependency_path);
    if dependency_path.is_absolute() {
        return normalize_resolved_path(dependency_path);
    }

    let mut resolved = manifest_dir.to_path_buf();
    for component in dependency_path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(part) => resolved.push(part),
        }
    }
    normalize_resolved_path(&resolved)
}

fn normalize_resolved_path(path: &Path) -> String {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    let rendered = normalized.to_string_lossy().replace('\\', "/");
    if rendered.is_empty() {
        ".".to_string()
    } else if rendered.len() > 1 {
        rendered.trim_end_matches('/').to_string()
    } else {
        rendered
    }
}

fn path_is_at_or_under(path: &str, root: &str) -> bool {
    let path = path.trim_end_matches('/');
    let root = root.trim_end_matches('/');
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn file_stem(path: &str) -> Option<&str> {
    let file = path.rsplit('/').next()?;
    file.rsplit_once('.')
        .map_or(Some(file), |(stem, _)| Some(stem))
}

fn stable_token(input: &str) -> String {
    let mut token = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            token.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            token.push(ch);
        } else if !token.ends_with('-') {
            token.push('-');
        }
    }
    token.trim_matches('-').to_string()
}

fn sorted_unique(values: impl IntoIterator<Item = impl Into<String>>) -> Vec<String> {
    values
        .into_iter()
        .map(Into::into)
        .map(normalize_path)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn shell_command(env: &BTreeMap<String, String>, argv: &[String]) -> String {
    env.iter()
        .map(|(key, value)| format!("{key}={}", shell_quote(value)))
        .chain(argv.iter().map(|arg| shell_quote(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&byte))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::validation_input::ValidationInput;
    use std::path::PathBuf;

    #[test]
    fn test_rch_command_count_saturating_arithmetic() {
        let input = ValidationInput {
            package: "test-package".to_string(),
            changed_files: vec![],
            workspace_root: PathBuf::from("/tmp"),
            workdir: PathBuf::from("/tmp"),
        };

        let mut planner = ValidationPlanner::new(input);

        // Set counter near usize::MAX to test saturation
        planner.rch_command_count = usize::MAX - 1;

        // These should saturate instead of wrapping
        planner.add_cargo_test_named(
            "overflow-test",
            "test-module",
            "Testing saturating arithmetic",
            vec!["test-file.rs".to_string()],
        );

        // Should be at usize::MAX, not wrapped around
        assert_eq!(planner.rch_command_count, usize::MAX);

        // Another addition should still be MAX
        planner.add_cargo_check_tests(
            "overflow-test-2",
            "Testing saturating arithmetic again",
            vec!["test-file2.rs".to_string()],
        );

        assert_eq!(planner.rch_command_count, usize::MAX);
    }
}
