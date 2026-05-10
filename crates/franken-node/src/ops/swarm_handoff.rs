//! Read-only evidence model for stale-work and handoff decisions.
//!
//! Scanners feed this module with already-collected Beads, Agent Mail, RCH, git,
//! and sibling-repo signals. The policy layer stays deterministic and read-only:
//! it emits recommended Beads commands, but never mutates issue state itself.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, error::Error, fmt};

pub const SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION: &str = "franken-node/swarm-handoff/evidence/v1";
pub const SWARM_HANDOFF_SUMMARY_SCHEMA_VERSION: &str = "franken-node/swarm-handoff/summary/v1";
pub const SWARM_HANDOFF_POLICY_SCHEMA_VERSION: &str = "franken-node/swarm-handoff/policy/v1";
pub const SWARM_HANDOFF_READINESS_SCHEMA_VERSION: &str = "franken-node/swarm-handoff/readiness/v1";
pub const SWARM_OVERLAP_RISK_SCHEMA_VERSION: &str = "franken-node/swarm-overlap-risk/v1";

pub const MAX_HANDOFF_ISSUES: usize = 256;
pub const MAX_HANDOFF_AGENTS: usize = 256;
pub const MAX_HANDOFF_RESERVATIONS: usize = 512;
pub const MAX_HANDOFF_RCH_BUILDS: usize = 128;
pub const MAX_HANDOFF_GIT_EVENTS: usize = 512;
pub const MAX_HANDOFF_CROSS_REPO_BLOCKERS: usize = 128;
pub const MAX_HANDOFF_LIST_ITEMS: usize = 64;
pub const MAX_HANDOFF_STRING_BYTES: usize = 512;
pub const MAX_HANDOFF_SUMMARY_BYTES: usize = 2048;
pub const MAX_OVERLAP_CANDIDATE_PATHS: usize = 128;
pub const MAX_OVERLAP_CONFLICTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHandoffIssueStatus {
    Open,
    InProgress,
    Blocked,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHandoffRchBuildState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Unknown,
}

impl SwarmHandoffRchBuildState {
    const fn is_active(self) -> bool {
        matches!(self, Self::Queued | Self::Running)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHandoffBlockerKind {
    CompileError,
    TestFailure,
    ReservationConflict,
    RchInProgress,
    ToolingUnavailable,
    Unknown,
}

impl SwarmHandoffBlockerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompileError => "compile_error",
            Self::TestFailure => "test_failure",
            Self::ReservationConflict => "reservation_conflict",
            Self::RchInProgress => "rch_in_progress",
            Self::ToolingUnavailable => "tooling_unavailable",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHandoffVerificationCommandFamily {
    CargoCheck,
    CargoTest,
    CargoClippy,
    Rustfmt,
    PythonGate,
    Rch,
    Other,
    Unknown,
}

impl SwarmHandoffVerificationCommandFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CargoCheck => "cargo_check",
            Self::CargoTest => "cargo_test",
            Self::CargoClippy => "cargo_clippy",
            Self::Rustfmt => "rustfmt",
            Self::PythonGate => "python_gate",
            Self::Rch => "rch",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

pub mod handoff_reason_codes {
    pub const HANDOFF_ACTIVE_RECENT_AGENT: &str = "HANDOFF_ACTIVE_RECENT_AGENT";
    pub const HANDOFF_ACTIVE_OWNER_OTHER_PROJECT: &str = "HANDOFF_ACTIVE_OWNER_OTHER_PROJECT";
    pub const HANDOFF_ACTIVE_RECENT_ISSUE_ACTIVITY: &str = "HANDOFF_ACTIVE_RECENT_ISSUE_ACTIVITY";
    pub const HANDOFF_ACTIVE_RECENT_GIT_ACTIVITY: &str = "HANDOFF_ACTIVE_RECENT_GIT_ACTIVITY";
    pub const HANDOFF_BLOCKED_DEPENDENCY_OPEN: &str = "HANDOFF_BLOCKED_DEPENDENCY_OPEN";
    pub const HANDOFF_BLOCKED_DEPENDENCY_UNKNOWN: &str = "HANDOFF_BLOCKED_DEPENDENCY_UNKNOWN";
    pub const HANDOFF_BLOCKED_RESERVATION_ACTIVE: &str = "HANDOFF_BLOCKED_RESERVATION_ACTIVE";
    pub const HANDOFF_BLOCKED_CROSS_REPO_RESERVATION: &str =
        "HANDOFF_BLOCKED_CROSS_REPO_RESERVATION";
    pub const HANDOFF_BLOCKED_CROSS_REPO_BLOCKER: &str = "HANDOFF_BLOCKED_CROSS_REPO_BLOCKER";
    pub const HANDOFF_WAITING_RCH_ACTIVE: &str = "HANDOFF_WAITING_RCH_ACTIVE";
    pub const HANDOFF_STALE_CONTESTED_RESERVATION: &str = "HANDOFF_STALE_CONTESTED_RESERVATION";
    pub const HANDOFF_STALE_CONTESTED_RCH_STALE: &str = "HANDOFF_STALE_CONTESTED_RCH_STALE";
    pub const HANDOFF_STALE_ACK_REQUIRED: &str = "HANDOFF_STALE_ACK_REQUIRED";
    pub const HANDOFF_ABANDONED_NO_RECENT_SIGNALS: &str = "HANDOFF_ABANDONED_NO_RECENT_SIGNALS";
    pub const HANDOFF_READY_EXPIRED_RESERVATION: &str = "HANDOFF_READY_EXPIRED_RESERVATION";
    pub const HANDOFF_READY_UNASSIGNED: &str = "HANDOFF_READY_UNASSIGNED";
    pub const HANDOFF_MANUAL_REVIEW_MALFORMED_EVIDENCE: &str =
        "HANDOFF_MANUAL_REVIEW_MALFORMED_EVIDENCE";
    pub const HANDOFF_MANUAL_REVIEW_ISSUE_NOT_FOUND: &str = "HANDOFF_MANUAL_REVIEW_ISSUE_NOT_FOUND";
    pub const HANDOFF_MANUAL_REVIEW_UNKNOWN_ISSUE_STATUS: &str =
        "HANDOFF_MANUAL_REVIEW_UNKNOWN_ISSUE_STATUS";
    pub const HANDOFF_MANUAL_REVIEW_CLOSED_ISSUE: &str = "HANDOFF_MANUAL_REVIEW_CLOSED_ISSUE";
}

pub mod overlap_reason_codes {
    pub const OVERLAP_CLEAR_NO_SIGNALS: &str = "OVERLAP_CLEAR_NO_SIGNALS";
    pub const OVERLAP_ACTIVE_OWNER: &str = "OVERLAP_ACTIVE_OWNER";
    pub const OVERLAP_STALE_OWNER: &str = "OVERLAP_STALE_OWNER";
    pub const OVERLAP_ACTIVE_RESERVATION: &str = "OVERLAP_ACTIVE_RESERVATION";
    pub const OVERLAP_STALE_RESERVATION: &str = "OVERLAP_STALE_RESERVATION";
    pub const OVERLAP_BR_MAIL_DISAGREE: &str = "OVERLAP_BR_MAIL_DISAGREE";
    pub const OVERLAP_RECENT_GIT_TOUCH: &str = "OVERLAP_RECENT_GIT_TOUCH";
    pub const OVERLAP_DEPENDENCY_DISTANCE: &str = "OVERLAP_DEPENDENCY_DISTANCE";
    pub const OVERLAP_DISJOINT_TEST_SURFACE: &str = "OVERLAP_DISJOINT_TEST_SURFACE";
    pub const OVERLAP_MALFORMED_INPUT: &str = "OVERLAP_MALFORMED_INPUT";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHandoffPolicyDecision {
    Active,
    BlockedOnKnownDependency,
    BlockedOnReservation,
    WaitingOnRch,
    StaleButContested,
    Abandoned,
    ReadyToReopen,
    ManualReviewRequired,
}

impl SwarmHandoffPolicyDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::BlockedOnKnownDependency => "blocked_on_known_dependency",
            Self::BlockedOnReservation => "blocked_on_reservation",
            Self::WaitingOnRch => "waiting_on_rch",
            Self::StaleButContested => "stale_but_contested",
            Self::Abandoned => "abandoned",
            Self::ReadyToReopen => "ready_to_reopen",
            Self::ManualReviewRequired => "manual_review_required",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmOverlapRiskLevel {
    Clear,
    Advisory,
    StaleConflict,
    HardConflict,
}

impl SwarmOverlapRiskLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Advisory => "advisory",
            Self::StaleConflict => "stale_conflict",
            Self::HardConflict => "hard_conflict",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmOverlapSuggestedAction {
    Claim,
    AskForHandoff,
    PickTestOnlySurface,
    Wait,
    RefreshEvidence,
}

impl SwarmOverlapSuggestedAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::AskForHandoff => "ask_for_handoff",
            Self::PickTestOnlySurface => "pick_test_only_surface",
            Self::Wait => "wait",
            Self::RefreshEvidence => "refresh_evidence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmOverlapConflictKind {
    NoOverlap,
    ActiveOwner,
    StaleOwner,
    ReservationOverlap,
    BrMailDisagreement,
    RecentGitTouch,
    DependencyDistance,
    DisjointTestSurface,
    MalformedInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmHandoffPolicyConfig {
    pub local_project_key: Option<String>,
    pub agent_activity_grace_secs: u64,
    pub issue_activity_grace_secs: u64,
    pub git_activity_grace_secs: u64,
    pub rch_activity_grace_secs: u64,
}

impl Default for SwarmHandoffPolicyConfig {
    fn default() -> Self {
        Self {
            local_project_key: None,
            agent_activity_grace_secs: 30 * 60,
            issue_activity_grace_secs: 30 * 60,
            git_activity_grace_secs: 60 * 60,
            rch_activity_grace_secs: 15 * 60,
        }
    }
}

impl SwarmHandoffPolicyConfig {
    #[must_use]
    pub fn with_local_project_key(mut self, project_key: impl Into<String>) -> Self {
        self.local_project_key = Some(project_key.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffIssueEvidence {
    pub bead_id: String,
    pub title: String,
    pub status: SwarmHandoffIssueStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_comment_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub dependency_ids: Vec<String>,
    #[serde(default)]
    pub dependent_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffAgentEvidence {
    pub agent_name: String,
    pub project_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_policy: Option<String>,
    #[serde(default)]
    pub ack_required_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffReservationEvidence {
    pub holder_agent: String,
    pub project_key: String,
    pub path_pattern: String,
    pub exclusive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffRchBuildEvidence {
    pub build_id: String,
    pub project_id: String,
    pub state: SwarmHandoffRchBuildState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub detector_progress_stale: bool,
    #[serde(default)]
    pub detector_heartbeat_stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker_bead_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffGitActivityEvidence {
    pub project_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
    pub summary: String,
    pub authored_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffCrossRepoBlockerEvidence {
    pub local_bead_id: String,
    pub sibling_project_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sibling_bead_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    pub blocker_kind: SwarmHandoffBlockerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_command_family: Option<SwarmHandoffVerificationCommandFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_error: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub cleared: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clearing_commit_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOverlapCandidateWork {
    pub bead_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub candidate_paths: Vec<String>,
    #[serde(default)]
    pub dependency_ids: Vec<String>,
    #[serde(default)]
    pub dependent_ids: Vec<String>,
}

impl SwarmOverlapCandidateWork {
    #[must_use]
    pub fn new(
        bead_id: impl Into<String>,
        candidate_paths: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            bead_id: bead_id.into(),
            agent_name: None,
            candidate_paths: candidate_paths.into_iter().map(Into::into).collect(),
            dependency_ids: Vec::new(),
            dependent_ids: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_agent_name(mut self, agent_name: impl Into<String>) -> Self {
        self.agent_name = Some(agent_name.into());
        self
    }

    #[must_use]
    pub fn with_dependency_ids(
        mut self,
        dependency_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.dependency_ids = dependency_ids.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_dependent_ids(
        mut self,
        dependent_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.dependent_ids = dependent_ids.into_iter().map(Into::into).collect();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOverlapGitActivityEvidence {
    pub project_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub touched_paths: Vec<String>,
    pub authored_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOverlapRiskConflict {
    pub kind: SwarmOverlapConflictKind,
    pub risk_level: SwarmOverlapRiskLevel,
    pub score: u8,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub reason_code: String,
    pub evidence_pointer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOverlapRiskReport {
    pub schema_version: String,
    pub bead_id: String,
    pub observed_at: DateTime<Utc>,
    pub candidate_paths: Vec<String>,
    pub risk_level: SwarmOverlapRiskLevel,
    pub risk_score: u8,
    pub suggested_action: SwarmOverlapSuggestedAction,
    pub reason_codes: Vec<String>,
    pub conflicts: Vec<SwarmOverlapRiskConflict>,
    pub operator_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffEvidenceInput {
    #[serde(default = "default_evidence_schema_version")]
    pub schema_version: String,
    pub observed_at: DateTime<Utc>,
    #[serde(default)]
    pub issues: Vec<SwarmHandoffIssueEvidence>,
    #[serde(default)]
    pub agents: Vec<SwarmHandoffAgentEvidence>,
    #[serde(default)]
    pub reservations: Vec<SwarmHandoffReservationEvidence>,
    #[serde(default)]
    pub rch_builds: Vec<SwarmHandoffRchBuildEvidence>,
    #[serde(default)]
    pub git_activity: Vec<SwarmHandoffGitActivityEvidence>,
    #[serde(default)]
    pub cross_repo_blockers: Vec<SwarmHandoffCrossRepoBlockerEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffEvidenceSummary {
    pub schema_version: String,
    pub observed_at: DateTime<Utc>,
    pub issue_count: usize,
    pub in_progress_issue_count: usize,
    pub agent_count: usize,
    pub reservation_count: usize,
    pub exclusive_reservation_count: usize,
    pub active_rch_build_count: usize,
    pub stale_rch_build_count: usize,
    pub git_activity_count: usize,
    pub cross_repo_blocker_count: usize,
    pub uncleared_cross_repo_blocker_count: usize,
    pub unknown_signal_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffPolicyOutcome {
    pub schema_version: String,
    pub bead_id: String,
    pub observed_at: DateTime<Utc>,
    pub decision: SwarmHandoffPolicyDecision,
    pub reason_codes: Vec<String>,
    pub evidence_pointers: Vec<String>,
    pub required_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_br_command: Option<String>,
    pub reopen_allowed: bool,
    pub operator_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffReadinessReport {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_summary: Option<SwarmHandoffEvidenceSummary>,
    pub decision_counts: Vec<SwarmHandoffDecisionCount>,
    pub decisions: Vec<SwarmHandoffDecisionView>,
    pub decision_logs: Vec<SwarmHandoffDecisionLogEntry>,
    pub runbook_goldens: Vec<SwarmHandoffRunbookGoldenEntry>,
    pub audit_ledger: Vec<SwarmHandoffAuditLedgerEntry>,
    pub active_agents: Vec<SwarmHandoffAgentView>,
    pub claimed_beads: Vec<SwarmHandoffClaimedBeadView>,
    pub active_reservations: Vec<SwarmHandoffReservationView>,
    pub active_rch_builds: Vec<SwarmHandoffRchBuildView>,
    pub cross_repo_blockers: Vec<SwarmHandoffCrossRepoBlockerView>,
    pub cleared_cross_repo_blockers: Vec<SwarmHandoffCrossRepoBlockerView>,
    pub stale_candidates: Vec<SwarmHandoffDecisionView>,
    pub safe_reopen_commands: Vec<SwarmHandoffCommandView>,
    pub warnings: Vec<String>,
    pub agent_mail_markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffDecisionCount {
    pub decision: SwarmHandoffPolicyDecision,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffDecisionView {
    pub bead_id: String,
    pub decision: SwarmHandoffPolicyDecision,
    pub decision_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_holder: Option<String>,
    pub blocker_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_age_secs: Option<i64>,
    pub next_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_br_command: Option<String>,
    pub reopen_allowed: bool,
    pub reason_codes: Vec<String>,
    pub evidence_pointers: Vec<String>,
    pub operator_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffDecisionLogEntry {
    pub trace_id: String,
    pub bead_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_holder: Option<String>,
    pub blocker_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_freshness_age_secs: Option<i64>,
    pub required_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffRunbookGoldenEntry {
    pub bead_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_holder: Option<String>,
    pub reservation_or_blocker_evidence: Vec<String>,
    pub decision_code: String,
    pub required_action: String,
    pub must_not_do: String,
    pub evidence_pointers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffAuditLedgerEntry {
    pub sequence: usize,
    pub trace_id: String,
    pub bead_id: String,
    pub decision_code: String,
    pub evidence_pointers: Vec<String>,
    pub required_action: String,
    pub must_not_do: String,
    pub no_files_deleted: bool,
    pub reservations_overridden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffAgentView {
    pub agent_name: String,
    pub project_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_age_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_policy: Option<String>,
    pub ack_required_count: u32,
    pub claimed_issue_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffClaimedBeadView {
    pub bead_id: String,
    pub title: String,
    pub status: SwarmHandoffIssueStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_age_secs: Option<i64>,
    pub dependency_count: usize,
    pub dependent_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffReservationView {
    pub holder_agent: String,
    pub project_key: String,
    pub path_pattern: String,
    pub exclusive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub expires_in_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffRchBuildView {
    pub build_id: String,
    pub project_id: String,
    pub state: SwarmHandoffRchBuildState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker_bead_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_age_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_age_secs: Option<i64>,
    pub detector_progress_stale: bool,
    pub detector_heartbeat_stale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffCrossRepoBlockerView {
    pub local_bead_id: String,
    pub sibling_project_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sibling_bead_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    pub blocker_kind: SwarmHandoffBlockerKind,
    pub blocker_kind_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_command_family: Option<SwarmHandoffVerificationCommandFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_command_family_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_error: Option<String>,
    pub observed_age_secs: i64,
    pub cleared: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clearing_commit_hash: Option<String>,
    pub action_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffCommandView {
    pub bead_id: String,
    pub command: String,
    pub reopen_allowed: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmHandoffEvidenceError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    EmptyField {
        field: &'static str,
    },
    TooManyItems {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    StringTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    InvalidString {
        field: &'static str,
        reason: &'static str,
    },
    InvalidTimestampOrder {
        field: &'static str,
    },
}

impl fmt::Display for SwarmHandoffEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchemaVersion { expected, actual } => {
                write!(
                    f,
                    "invalid swarm handoff evidence schema `{actual}`, expected `{expected}`"
                )
            }
            Self::EmptyField { field } => write!(f, "`{field}` must not be empty"),
            Self::TooManyItems { field, max, actual } => {
                write!(f, "`{field}` has {actual} items, max {max}")
            }
            Self::StringTooLong { field, max, actual } => {
                write!(f, "`{field}` is {actual} bytes, max {max}")
            }
            Self::InvalidString { field, reason } => write!(f, "`{field}` is invalid: {reason}"),
            Self::InvalidTimestampOrder { field } => {
                write!(f, "`{field}` timestamp order is invalid")
            }
        }
    }
}

impl Error for SwarmHandoffEvidenceError {}

pub type SwarmHandoffEvidenceResult<T> = Result<T, SwarmHandoffEvidenceError>;

const SWARM_HANDOFF_READINESS_COMMAND: &str = "ops swarm-handoff-readiness";
const POLICY_DECISION_ORDER: [SwarmHandoffPolicyDecision; 8] = [
    SwarmHandoffPolicyDecision::Active,
    SwarmHandoffPolicyDecision::BlockedOnKnownDependency,
    SwarmHandoffPolicyDecision::BlockedOnReservation,
    SwarmHandoffPolicyDecision::WaitingOnRch,
    SwarmHandoffPolicyDecision::StaleButContested,
    SwarmHandoffPolicyDecision::Abandoned,
    SwarmHandoffPolicyDecision::ReadyToReopen,
    SwarmHandoffPolicyDecision::ManualReviewRequired,
];

impl SwarmHandoffEvidenceInput {
    /// Validate scanner evidence and return deterministic aggregate counts.
    pub fn validate_and_summarize(
        &self,
    ) -> SwarmHandoffEvidenceResult<SwarmHandoffEvidenceSummary> {
        validate_schema(&self.schema_version)?;
        require_len("issues", self.issues.len(), MAX_HANDOFF_ISSUES)?;
        require_len("agents", self.agents.len(), MAX_HANDOFF_AGENTS)?;
        require_len(
            "reservations",
            self.reservations.len(),
            MAX_HANDOFF_RESERVATIONS,
        )?;
        require_len("rch_builds", self.rch_builds.len(), MAX_HANDOFF_RCH_BUILDS)?;
        require_len(
            "git_activity",
            self.git_activity.len(),
            MAX_HANDOFF_GIT_EVENTS,
        )?;
        require_len(
            "cross_repo_blockers",
            self.cross_repo_blockers.len(),
            MAX_HANDOFF_CROSS_REPO_BLOCKERS,
        )?;

        for issue in &self.issues {
            validate_issue(issue)?;
        }
        for agent in &self.agents {
            validate_agent(agent)?;
        }
        for reservation in &self.reservations {
            validate_reservation(reservation)?;
        }
        for build in &self.rch_builds {
            validate_rch_build(build)?;
        }
        for activity in &self.git_activity {
            validate_git_activity(activity)?;
        }
        for blocker in &self.cross_repo_blockers {
            validate_cross_repo_blocker(blocker)?;
        }

        Ok(SwarmHandoffEvidenceSummary {
            schema_version: SWARM_HANDOFF_SUMMARY_SCHEMA_VERSION.to_string(),
            observed_at: self.observed_at,
            issue_count: self.issues.len(),
            in_progress_issue_count: self
                .issues
                .iter()
                .filter(|issue| issue.status == SwarmHandoffIssueStatus::InProgress)
                .count(),
            agent_count: self.agents.len(),
            reservation_count: self.reservations.len(),
            exclusive_reservation_count: self
                .reservations
                .iter()
                .filter(|reservation| reservation.exclusive && reservation.released_at.is_none())
                .count(),
            active_rch_build_count: self
                .rch_builds
                .iter()
                .filter(|build| build.state.is_active())
                .count(),
            stale_rch_build_count: self
                .rch_builds
                .iter()
                .filter(|build| build.detector_progress_stale || build.detector_heartbeat_stale)
                .count(),
            git_activity_count: self.git_activity.len(),
            cross_repo_blocker_count: self.cross_repo_blockers.len(),
            uncleared_cross_repo_blocker_count: self
                .cross_repo_blockers
                .iter()
                .filter(|blocker| !blocker.cleared)
                .count(),
            unknown_signal_count: self.unknown_signal_count(),
        })
    }

    fn unknown_signal_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| issue.status == SwarmHandoffIssueStatus::Unknown)
            .count()
            + self
                .rch_builds
                .iter()
                .filter(|build| build.state == SwarmHandoffRchBuildState::Unknown)
                .count()
            + self
                .cross_repo_blockers
                .iter()
                .filter(|blocker| {
                    blocker.blocker_kind == SwarmHandoffBlockerKind::Unknown // ubs:ignore - enum policy label, not secret material
                })
                .count()
    }

    #[must_use]
    pub fn classify_handoff_policy(
        &self,
        bead_id: &str,
        config: &SwarmHandoffPolicyConfig,
    ) -> SwarmHandoffPolicyOutcome {
        use handoff_reason_codes::{
            HANDOFF_ABANDONED_NO_RECENT_SIGNALS, HANDOFF_ACTIVE_OWNER_OTHER_PROJECT,
            HANDOFF_BLOCKED_RESERVATION_ACTIVE, HANDOFF_MANUAL_REVIEW_CLOSED_ISSUE,
            HANDOFF_MANUAL_REVIEW_ISSUE_NOT_FOUND, HANDOFF_MANUAL_REVIEW_MALFORMED_EVIDENCE,
            HANDOFF_MANUAL_REVIEW_UNKNOWN_ISSUE_STATUS, HANDOFF_READY_EXPIRED_RESERVATION,
            HANDOFF_READY_UNASSIGNED, HANDOFF_STALE_ACK_REQUIRED,
            HANDOFF_STALE_CONTESTED_RCH_STALE, HANDOFF_STALE_CONTESTED_RESERVATION,
            HANDOFF_WAITING_RCH_ACTIVE,
        };

        if let Err(error) = self.validate_and_summarize() {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::ManualReviewRequired,
                vec![HANDOFF_MANUAL_REVIEW_MALFORMED_EVIDENCE],
                vec![format!("evidence.validation_error:{error}")],
                "Fix scanner evidence and rerun handoff classification; do not reopen this bead from malformed evidence.",
                None,
            );
        }

        let Some(issue) = self.issues.iter().find(|issue| issue.bead_id == bead_id) else {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::ManualReviewRequired,
                vec![HANDOFF_MANUAL_REVIEW_ISSUE_NOT_FOUND],
                vec![format!("issue:{bead_id}:missing")],
                "Refresh Beads evidence before making a handoff decision.",
                None,
            );
        };

        match issue.status {
            SwarmHandoffIssueStatus::Closed => {
                return policy_outcome(
                    bead_id,
                    self.observed_at,
                    SwarmHandoffPolicyDecision::ManualReviewRequired,
                    vec![HANDOFF_MANUAL_REVIEW_CLOSED_ISSUE],
                    vec![issue_pointer(issue)],
                    "Closed beads must not be reopened by stale-work policy without a separate explicit reopen review.",
                    None,
                );
            }
            SwarmHandoffIssueStatus::Unknown => {
                return policy_outcome(
                    bead_id,
                    self.observed_at,
                    SwarmHandoffPolicyDecision::ManualReviewRequired,
                    vec![HANDOFF_MANUAL_REVIEW_UNKNOWN_ISSUE_STATUS],
                    vec![issue_pointer(issue)],
                    "Refresh Beads status evidence; unknown issue status is fail-closed.",
                    None,
                );
            }
            SwarmHandoffIssueStatus::Open
            | SwarmHandoffIssueStatus::InProgress
            | SwarmHandoffIssueStatus::Blocked => {}
        }

        if let Some(outcome) = self.classify_dependency_blockers(issue) {
            return outcome;
        }

        if let Some(outcome) = self.classify_cross_repo_blockers(bead_id) {
            return outcome;
        }

        let assignee = issue.assignee.as_deref();
        let active_reservations = self.matching_reservations(bead_id, issue, true);
        if let Some(reservation) = active_reservations
            .iter()
            .find(|reservation| Some(reservation.holder_agent.as_str()) != assignee)
        {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::BlockedOnReservation,
                vec![HANDOFF_BLOCKED_RESERVATION_ACTIVE],
                vec![reservation_pointer(reservation)],
                "Do not override an active file reservation; contact the holder or wait for expiry.",
                None,
            );
        }

        if let Some((reason_code, pointer)) = self.recent_owner_signal(issue, config) {
            let required_action = if reason_code == HANDOFF_ACTIVE_OWNER_OTHER_PROJECT {
                "Do not reopen; the assignee is recently active in another project, so request a handoff acknowledgement first."
            } else {
                "Do not reopen; owner activity is still inside the configured freshness grace window."
            };
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::Active,
                vec![reason_code],
                vec![pointer],
                required_action,
                None,
            );
        }

        if let Some(build) = self
            .matching_rch_builds(bead_id)
            .into_iter()
            .find(|build| rch_build_is_recently_active(build, self.observed_at, config))
        {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::WaitingOnRch,
                vec![HANDOFF_WAITING_RCH_ACTIVE],
                vec![rch_pointer(build)],
                "Do not mark validation green or reopen while a live RCH proof is still running.",
                None,
            );
        }

        if let Some(reservation) = active_reservations.first() {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::StaleButContested,
                vec![HANDOFF_STALE_CONTESTED_RESERVATION],
                vec![reservation_pointer(reservation)],
                "The owner looks stale but still holds an active reservation; request acknowledgement or wait for expiry before reopening.",
                None,
            );
        }

        if let Some(build) = self
            .matching_rch_builds(bead_id)
            .into_iter()
            .find(|build| build.state.is_active())
        {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::StaleButContested,
                vec![HANDOFF_STALE_CONTESTED_RCH_STALE],
                vec![rch_pointer(build)],
                "RCH evidence is stale or incomplete; record the worker-infra blocker instead of treating validation as green.",
                None,
            );
        }

        if let Some(agent) =
            assignee.and_then(|name| self.agents.iter().find(|agent| agent.agent_name == name))
            && agent.ack_required_count > 0
        {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::StaleButContested,
                vec![HANDOFF_STALE_ACK_REQUIRED],
                vec![agent_pointer(agent)],
                "The assignee has pending acknowledgement requests; ask for explicit handoff before reopening.",
                None,
            );
        }

        if self
            .matching_reservations(bead_id, issue, false)
            .into_iter()
            .any(|reservation| reservation_is_expired(reservation, self.observed_at))
        {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::ReadyToReopen,
                vec![HANDOFF_READY_EXPIRED_RESERVATION],
                vec![issue_pointer(issue)],
                "Evidence supports an explicit reopen; clear the stale assignee before a new agent claims the bead.",
                Some(reopen_command(bead_id)),
            );
        }

        if assignee.is_none() {
            return policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::ReadyToReopen,
                vec![HANDOFF_READY_UNASSIGNED],
                vec![issue_pointer(issue)],
                "The bead has no assignee and no active blockers; a new agent may claim it normally.",
                Some(format!("br update {bead_id} --claim --actor <agent>")),
            );
        }

        policy_outcome(
            bead_id,
            self.observed_at,
            SwarmHandoffPolicyDecision::Abandoned,
            vec![HANDOFF_ABANDONED_NO_RECENT_SIGNALS],
            vec![issue_pointer(issue)],
            "No recent Agent Mail, Beads, RCH, reservation, or git activity supports the stale claim; reopen only via explicit br update.",
            Some(reopen_command(bead_id)),
        )
    }

    fn classify_dependency_blockers(
        &self,
        issue: &SwarmHandoffIssueEvidence,
    ) -> Option<SwarmHandoffPolicyOutcome> {
        use handoff_reason_codes::{
            HANDOFF_BLOCKED_DEPENDENCY_OPEN, HANDOFF_BLOCKED_DEPENDENCY_UNKNOWN,
        };

        for dependency_id in &issue.dependency_ids {
            let Some(dependency) = self
                .issues
                .iter()
                .find(|candidate| candidate.bead_id == *dependency_id)
            else {
                return Some(policy_outcome(
                    &issue.bead_id,
                    self.observed_at,
                    SwarmHandoffPolicyDecision::ManualReviewRequired,
                    vec![HANDOFF_BLOCKED_DEPENDENCY_UNKNOWN],
                    vec![format!("dependency:{dependency_id}:missing")],
                    "Refresh dependency evidence before reopening stale work.",
                    None,
                ));
            };

            match dependency.status {
                SwarmHandoffIssueStatus::Closed => {}
                SwarmHandoffIssueStatus::Unknown => {
                    return Some(policy_outcome(
                        &issue.bead_id,
                        self.observed_at,
                        SwarmHandoffPolicyDecision::ManualReviewRequired,
                        vec![HANDOFF_BLOCKED_DEPENDENCY_UNKNOWN],
                        vec![issue_pointer(dependency)],
                        "Dependency status is unknown; handoff policy fails closed.",
                        None,
                    ));
                }
                SwarmHandoffIssueStatus::Open
                | SwarmHandoffIssueStatus::InProgress
                | SwarmHandoffIssueStatus::Blocked => {
                    return Some(policy_outcome(
                        &issue.bead_id,
                        self.observed_at,
                        SwarmHandoffPolicyDecision::BlockedOnKnownDependency,
                        vec![HANDOFF_BLOCKED_DEPENDENCY_OPEN],
                        vec![issue_pointer(dependency)],
                        "Keep the bead blocked until the dependency closes or a human changes the dependency graph.",
                        None,
                    ));
                }
            }
        }

        None
    }

    fn classify_cross_repo_blockers(&self, bead_id: &str) -> Option<SwarmHandoffPolicyOutcome> {
        use handoff_reason_codes::{
            HANDOFF_BLOCKED_CROSS_REPO_BLOCKER, HANDOFF_BLOCKED_CROSS_REPO_RESERVATION,
        };

        let blocker = self
            .cross_repo_blockers
            .iter()
            .find(|blocker| blocker.local_bead_id == bead_id && !blocker.cleared)?;

        let is_reservation_conflict =
            blocker.blocker_kind == SwarmHandoffBlockerKind::ReservationConflict; // ubs:ignore - enum policy label, not secret material
        let reservation_like = is_reservation_conflict || blocker.holder_agent.is_some();
        if reservation_like {
            return Some(policy_outcome(
                bead_id,
                self.observed_at,
                SwarmHandoffPolicyDecision::BlockedOnReservation,
                vec![HANDOFF_BLOCKED_CROSS_REPO_RESERVATION],
                vec![cross_repo_pointer(blocker)],
                "Do not override the sibling repository holder; coordinate with that agent or wait for the blocker mirror to clear.",
                None,
            ));
        }

        Some(policy_outcome(
            bead_id,
            self.observed_at,
            SwarmHandoffPolicyDecision::BlockedOnKnownDependency,
            vec![HANDOFF_BLOCKED_CROSS_REPO_BLOCKER],
            vec![cross_repo_pointer(blocker)],
            "Keep the bead blocked on the sibling validation failure; do not treat worker or compile failures as product success.",
            None,
        ))
    }

    fn matching_reservations(
        &self,
        bead_id: &str,
        issue: &SwarmHandoffIssueEvidence,
        active_only: bool,
    ) -> Vec<&SwarmHandoffReservationEvidence> {
        self.reservations
            .iter()
            .filter(|reservation| {
                reservation_matches_bead(reservation, bead_id, issue)
                    && (!active_only || reservation_is_active(reservation, self.observed_at))
            })
            .collect()
    }

    fn matching_rch_builds(&self, bead_id: &str) -> Vec<&SwarmHandoffRchBuildEvidence> {
        self.rch_builds
            .iter()
            .filter(|build| build.blocker_bead_id.as_deref() == Some(bead_id))
            .collect()
    }

    fn recent_owner_signal(
        &self,
        issue: &SwarmHandoffIssueEvidence,
        config: &SwarmHandoffPolicyConfig,
    ) -> Option<(&'static str, String)> {
        use handoff_reason_codes::{
            HANDOFF_ACTIVE_OWNER_OTHER_PROJECT, HANDOFF_ACTIVE_RECENT_AGENT,
            HANDOFF_ACTIVE_RECENT_GIT_ACTIVITY, HANDOFF_ACTIVE_RECENT_ISSUE_ACTIVITY,
        };

        if issue_timestamp_is_recent(issue.updated_at, self.observed_at, config)
            || issue_timestamp_is_recent(issue.last_comment_at, self.observed_at, config)
        {
            return Some((HANDOFF_ACTIVE_RECENT_ISSUE_ACTIVITY, issue_pointer(issue)));
        }

        let assignee = issue.assignee.as_deref()?;
        if let Some(agent) = self.agents.iter().find(|agent| {
            agent.agent_name == assignee
                && agent_timestamp_is_recent(agent.last_active_at, self.observed_at, config)
        }) {
            let reason = if config
                .local_project_key
                .as_deref()
                .is_some_and(|local| local != agent.project_key.as_str())
            {
                HANDOFF_ACTIVE_OWNER_OTHER_PROJECT
            } else {
                HANDOFF_ACTIVE_RECENT_AGENT
            };
            return Some((reason, agent_pointer(agent)));
        }

        self.git_activity
            .iter()
            .find(|activity| {
                git_activity_matches_issue(activity, issue)
                    && git_timestamp_is_recent(activity.authored_at, self.observed_at, config)
            })
            .map(|activity| (HANDOFF_ACTIVE_RECENT_GIT_ACTIVITY, git_pointer(activity)))
    }
}

#[must_use]
pub fn score_cross_agent_overlap_risk(
    input: &SwarmHandoffEvidenceInput,
    candidate: &SwarmOverlapCandidateWork,
    git_activity: &[SwarmOverlapGitActivityEvidence],
    config: &SwarmHandoffPolicyConfig,
) -> SwarmOverlapRiskReport {
    use overlap_reason_codes::{
        OVERLAP_ACTIVE_OWNER, OVERLAP_ACTIVE_RESERVATION, OVERLAP_BR_MAIL_DISAGREE,
        OVERLAP_CLEAR_NO_SIGNALS, OVERLAP_DEPENDENCY_DISTANCE, OVERLAP_DISJOINT_TEST_SURFACE,
        OVERLAP_MALFORMED_INPUT, OVERLAP_RECENT_GIT_TOUCH, OVERLAP_STALE_OWNER,
        OVERLAP_STALE_RESERVATION,
    };

    let mut conflicts = Vec::new();
    let candidate_paths = normalize_overlap_paths(&candidate.candidate_paths);
    if validate_overlap_candidate(candidate, &candidate_paths).is_err()
        || input.validate_and_summarize().is_err()
    {
        conflicts.push(overlap_conflict(
            SwarmOverlapConflictKind::MalformedInput,
            SwarmOverlapRiskLevel::HardConflict,
            100,
            &candidate.bead_id,
            candidate.agent_name.as_deref(),
            None,
            OVERLAP_MALFORMED_INPUT,
            "overlap_input:malformed".to_string(),
            None,
        ));
        return overlap_report(input.observed_at, candidate, candidate_paths, conflicts);
    }

    let issue = input
        .issues
        .iter()
        .find(|issue| issue.bead_id == candidate.bead_id);
    if let Some(issue) = issue {
        let same_agent = issue.assignee.as_deref() == candidate.agent_name.as_deref();
        if issue.assignee.is_some() && !same_agent {
            if owner_has_recent_signal(input, issue, config) {
                conflicts.push(overlap_conflict(
                    SwarmOverlapConflictKind::ActiveOwner,
                    SwarmOverlapRiskLevel::HardConflict,
                    95,
                    &issue.bead_id,
                    issue.assignee.as_deref(),
                    None,
                    OVERLAP_ACTIVE_OWNER,
                    issue_pointer(issue),
                    freshness_age_secs(input, issue),
                ));
            } else {
                conflicts.push(overlap_conflict(
                    SwarmOverlapConflictKind::StaleOwner,
                    SwarmOverlapRiskLevel::StaleConflict,
                    55,
                    &issue.bead_id,
                    issue.assignee.as_deref(),
                    None,
                    OVERLAP_STALE_OWNER,
                    issue_pointer(issue),
                    freshness_age_secs(input, issue),
                ));
            }
        }
    }

    for reservation in input
        .reservations
        .iter()
        .filter(|reservation| reservation.released_at.is_none())
    {
        let holder_is_candidate =
            candidate.agent_name.as_deref() == Some(reservation.holder_agent.as_str());
        let matched_path = candidate_paths
            .iter()
            .find(|path| path_patterns_overlap(&reservation.path_pattern, path));
        let reason_matches_candidate = reservation.reason.as_deref().is_some_and(|reason| {
            reason.contains(&candidate.bead_id)
                || issue
                    .and_then(|issue| issue.assignee.as_deref())
                    .is_some_and(|assignee| reason.contains(assignee))
        });
        let br_mail_disagrees = reason_matches_candidate
            && !holder_is_candidate
            && issue
                .and_then(|issue| issue.assignee.as_deref())
                .is_none_or(|assignee| assignee != reservation.holder_agent);

        if br_mail_disagrees {
            conflicts.push(overlap_conflict(
                SwarmOverlapConflictKind::BrMailDisagreement,
                if reservation_is_active(reservation, input.observed_at) {
                    SwarmOverlapRiskLevel::HardConflict
                } else {
                    SwarmOverlapRiskLevel::StaleConflict
                },
                if reservation_is_active(reservation, input.observed_at) {
                    90
                } else {
                    50
                },
                &candidate.bead_id,
                Some(&reservation.holder_agent),
                Some(&reservation.path_pattern),
                OVERLAP_BR_MAIL_DISAGREE,
                reservation_pointer(reservation),
                Some(
                    input
                        .observed_at
                        .signed_duration_since(reservation.expires_at)
                        .num_seconds(),
                ),
            ));
        }

        if let Some(path) = matched_path {
            if holder_is_candidate {
                continue;
            }
            let active = reservation_is_active(reservation, input.observed_at);
            conflicts.push(overlap_conflict(
                SwarmOverlapConflictKind::ReservationOverlap,
                if active {
                    SwarmOverlapRiskLevel::HardConflict
                } else {
                    SwarmOverlapRiskLevel::StaleConflict
                },
                if active { 100 } else { 60 },
                &candidate.bead_id,
                Some(&reservation.holder_agent),
                Some(path),
                if active {
                    OVERLAP_ACTIVE_RESERVATION
                } else {
                    OVERLAP_STALE_RESERVATION
                },
                reservation_pointer(reservation),
                Some(
                    input
                        .observed_at
                        .signed_duration_since(reservation.expires_at)
                        .num_seconds(),
                ),
            ));
        } else if reservation_is_active(reservation, input.observed_at)
            && !holder_is_candidate
            && candidate_paths
                .iter()
                .all(|path| overlap_path_is_test_surface(path))
        {
            conflicts.push(overlap_conflict(
                SwarmOverlapConflictKind::DisjointTestSurface,
                SwarmOverlapRiskLevel::Advisory,
                20,
                &candidate.bead_id,
                Some(&reservation.holder_agent),
                Some(&reservation.path_pattern),
                OVERLAP_DISJOINT_TEST_SURFACE,
                reservation_pointer(reservation),
                None,
            ));
        }
    }

    for activity in git_activity {
        let owner_is_candidate = candidate.agent_name.as_deref() == activity.agent_name.as_deref();
        if owner_is_candidate
            || !git_timestamp_is_recent(activity.authored_at, input.observed_at, config)
        {
            continue;
        }
        let touched_paths = normalize_overlap_paths(&activity.touched_paths);
        let matched_path = candidate_paths
            .iter()
            .find(|candidate_path| {
                touched_paths
                    .iter()
                    .any(|touched_path| path_patterns_overlap(touched_path, candidate_path))
            })
            .cloned();
        if let Some(path) = matched_path {
            conflicts.push(overlap_conflict(
                SwarmOverlapConflictKind::RecentGitTouch,
                SwarmOverlapRiskLevel::Advisory,
                30,
                &candidate.bead_id,
                activity.agent_name.as_deref(),
                Some(path.as_str()),
                OVERLAP_RECENT_GIT_TOUCH,
                overlap_git_pointer(activity),
                age_secs(input.observed_at, Some(activity.authored_at)),
            ));
        }
    }

    for issue in input
        .issues
        .iter()
        .filter(|issue| issue.bead_id != candidate.bead_id)
        .filter(|issue| {
            matches!(
                issue.status,
                SwarmHandoffIssueStatus::InProgress | SwarmHandoffIssueStatus::Blocked
            )
        })
    {
        if dependency_context_overlaps(candidate, issue) {
            conflicts.push(overlap_conflict(
                SwarmOverlapConflictKind::DependencyDistance,
                SwarmOverlapRiskLevel::Advisory,
                25,
                &issue.bead_id,
                issue.assignee.as_deref(),
                None,
                OVERLAP_DEPENDENCY_DISTANCE,
                issue_pointer(issue),
                freshness_age_secs(input, issue),
            ));
        }
    }

    if conflicts.is_empty() {
        conflicts.push(overlap_conflict(
            SwarmOverlapConflictKind::NoOverlap,
            SwarmOverlapRiskLevel::Clear,
            0,
            &candidate.bead_id,
            None,
            None,
            OVERLAP_CLEAR_NO_SIGNALS,
            format!("issue:{}:clear", candidate.bead_id),
            None,
        ));
    }

    overlap_report(input.observed_at, candidate, candidate_paths, conflicts)
}

#[must_use]
pub fn render_cross_agent_overlap_risk_human(report: &SwarmOverlapRiskReport) -> String {
    let mut lines = vec![
        format!(
            "{} overlap_risk={} score={} action={}",
            report.bead_id,
            report.risk_level.as_str(),
            report.risk_score,
            report.suggested_action.as_str()
        ),
        format!("reason_codes={}", report.reason_codes.join(",")),
    ];
    for conflict in report.conflicts.iter().take(5) {
        lines.push(format!(
            "- kind={:?} level={} owner={} path={} reason={} evidence={}",
            conflict.kind,
            conflict.risk_level.as_str(),
            conflict.owner.as_deref().unwrap_or(""),
            conflict.path.as_deref().unwrap_or(""),
            conflict.reason_code,
            conflict.evidence_pointer
        ));
    }
    truncate_policy_string(&lines.join("\n"))
}

#[must_use]
pub fn build_swarm_handoff_readiness_report(
    input: &SwarmHandoffEvidenceInput,
    config: &SwarmHandoffPolicyConfig,
    trace_id: impl Into<String>,
    generated_at_utc: DateTime<Utc>,
) -> SwarmHandoffReadinessReport {
    let evidence_summary = input.validate_and_summarize();
    let mut warnings = evidence_summary
        .as_ref()
        .err()
        .map(|error| vec![format!("evidence validation failed: {error}")])
        .unwrap_or_default();
    let evidence_summary = evidence_summary.ok();

    let decisions = input
        .issues
        .iter()
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(|issue| {
            let outcome = input.classify_handoff_policy(&issue.bead_id, config);
            decision_view(input, issue, &outcome)
        })
        .collect::<Vec<_>>();

    for decision in &decisions {
        match decision.decision {
            SwarmHandoffPolicyDecision::ManualReviewRequired => warnings.push(format!(
                "{} requires manual review before any handoff action",
                decision.bead_id
            )),
            SwarmHandoffPolicyDecision::StaleButContested => warnings.push(format!(
                "{} is stale but contested; do not override without acknowledgement",
                decision.bead_id
            )),
            _ => {}
        }
    }

    let decision_counts = POLICY_DECISION_ORDER
        .iter()
        .map(|decision| SwarmHandoffDecisionCount {
            decision: *decision,
            count: decisions
                .iter()
                .filter(|view| view.decision == *decision)
                .count(),
        })
        .collect::<Vec<_>>();
    let active_agents = input
        .agents
        .iter()
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(|agent| agent_view(input, agent))
        .collect::<Vec<_>>();
    let claimed_beads = input
        .issues
        .iter()
        .filter(|issue| {
            issue.assignee.is_some() || issue.status == SwarmHandoffIssueStatus::InProgress
        })
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(|issue| claimed_bead_view(input, issue))
        .collect::<Vec<_>>();
    let active_reservations = input
        .reservations
        .iter()
        .filter(|reservation| reservation_is_active(reservation, input.observed_at))
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(|reservation| reservation_view(input, reservation))
        .collect::<Vec<_>>();
    let active_rch_builds = input
        .rch_builds
        .iter()
        .filter(|build| build.state.is_active())
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(|build| rch_build_view(input, build))
        .collect::<Vec<_>>();
    let cross_repo_blockers = input
        .cross_repo_blockers
        .iter()
        .filter(|blocker| !blocker.cleared)
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(|blocker| cross_repo_blocker_view(input, blocker))
        .collect::<Vec<_>>();
    let cleared_cross_repo_blockers = input
        .cross_repo_blockers
        .iter()
        .filter(|blocker| blocker.cleared)
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(|blocker| cross_repo_blocker_view(input, blocker))
        .collect::<Vec<_>>();
    let stale_candidates = decisions
        .iter()
        .filter(|view| {
            matches!(
                view.decision,
                SwarmHandoffPolicyDecision::StaleButContested
                    | SwarmHandoffPolicyDecision::Abandoned
                    | SwarmHandoffPolicyDecision::ReadyToReopen
                    | SwarmHandoffPolicyDecision::ManualReviewRequired
            )
        })
        .take(MAX_HANDOFF_LIST_ITEMS)
        .cloned()
        .collect::<Vec<_>>();
    let safe_reopen_commands = decisions
        .iter()
        .filter(|view| view.reopen_allowed)
        .filter_map(|view| {
            view.required_br_command
                .as_ref()
                .map(|command| SwarmHandoffCommandView {
                    bead_id: view.bead_id.clone(),
                    command: command.clone(),
                    reopen_allowed: view.reopen_allowed,
                    reason_codes: view.reason_codes.clone(),
                })
        })
        .take(MAX_HANDOFF_LIST_ITEMS)
        .collect::<Vec<_>>();

    let trace_id = truncate_policy_string(&trace_id.into());
    let decision_logs = decisions
        .iter()
        .map(|decision| decision_log_entry(&trace_id, decision))
        .collect::<Vec<_>>();
    let runbook_goldens = decisions
        .iter()
        .map(runbook_golden_entry)
        .collect::<Vec<_>>();
    let audit_ledger = runbook_goldens
        .iter()
        .enumerate()
        .map(|(idx, entry)| audit_ledger_entry(idx + 1, &trace_id, entry))
        .collect::<Vec<_>>();
    let mut report = SwarmHandoffReadinessReport {
        schema_version: SWARM_HANDOFF_READINESS_SCHEMA_VERSION.to_string(),
        command: SWARM_HANDOFF_READINESS_COMMAND.to_string(),
        trace_id,
        generated_at_utc,
        observed_at: input.observed_at,
        evidence_summary,
        decision_counts,
        decisions,
        decision_logs,
        runbook_goldens,
        audit_ledger,
        active_agents,
        claimed_beads,
        active_reservations,
        active_rch_builds,
        cross_repo_blockers,
        cleared_cross_repo_blockers,
        stale_candidates,
        safe_reopen_commands,
        warnings,
        agent_mail_markdown: String::new(),
    };
    report.agent_mail_markdown = render_swarm_handoff_readiness_human(&report);
    report
}

pub fn render_swarm_handoff_readiness_json(
    report: &SwarmHandoffReadinessReport,
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

#[must_use]
pub fn render_swarm_handoff_readiness_human(report: &SwarmHandoffReadinessReport) -> String {
    let mut lines = vec![
        format!(
            "`{}` swarm handoff readiness: trace=`{}`",
            report.command, report.trace_id
        ),
        String::new(),
        format!("- schema: `{}`", report.schema_version),
        format!("- observed_at: `{}`", report.observed_at.to_rfc3339()),
        format!("- generated_at: `{}`", report.generated_at_utc.to_rfc3339()),
        format!("- decisions: {}", render_decision_count_summary(report)),
        format!("- active_agents: {}", report.active_agents.len()),
        format!("- claimed_beads: {}", report.claimed_beads.len()),
        format!(
            "- active_reservations: {}",
            report.active_reservations.len()
        ),
        format!("- active_rch_builds: {}", report.active_rch_builds.len()),
        format!(
            "- cross_repo_blockers: {}",
            report.cross_repo_blockers.len()
        ),
        format!(
            "- cleared_cross_repo_blockers: {}",
            report.cleared_cross_repo_blockers.len()
        ),
        format!("- decision_logs: {}", report.decision_logs.len()),
        format!("- runbook_goldens: {}", report.runbook_goldens.len()),
        format!("- audit_ledger: {}", report.audit_ledger.len()),
        format!("- stale_candidates: {}", report.stale_candidates.len()),
        format!(
            "- safe_reopen_commands: {}",
            report.safe_reopen_commands.len()
        ),
    ];

    if let Some(summary) = &report.evidence_summary {
        lines.push(format!(
            "- evidence_summary: issues={} agents={} reservations={} active_rch={} cross_repo_uncleared={} unknown_signals={}",
            summary.issue_count,
            summary.agent_count,
            summary.reservation_count,
            summary.active_rch_build_count,
            summary.uncleared_cross_repo_blocker_count,
            summary.unknown_signal_count
        ));
    }

    if report.warnings.is_empty() {
        lines.push("- warnings: none".to_string());
    } else {
        lines.push("- warnings:".to_string());
        for warning in &report.warnings {
            lines.push(format!("  - {warning}"));
        }
    }

    if !report.decisions.is_empty() {
        lines.push(String::new());
        lines.push("Decisions:".to_string());
        for decision in &report.decisions {
            lines.push(format!(
                "- bead=`{}` decision=`{}` agent=`{}` reservation_holder=`{}` blocker_class=`{}` freshness_age_secs={} next_action=`{}`",
                decision.bead_id,
                decision.decision_label,
                decision.assignee.as_deref().unwrap_or(""),
                decision.reservation_holder.as_deref().unwrap_or(""),
                decision.blocker_class,
                render_optional_i64(decision.freshness_age_secs),
                decision.next_action
            ));
            if let Some(command) = &decision.required_br_command {
                lines.push(format!("  - br_command: `{command}`"));
            }
            lines.push(format!(
                "  - reason_codes: `{}`",
                decision.reason_codes.join(",")
            ));
            lines.push(format!(
                "  - evidence_pointers: `{}`",
                decision.evidence_pointers.join(",")
            ));
        }
    } else {
        lines.push(String::new());
        lines.push("No handoff actions required.".to_string());
    }

    if !report.decision_logs.is_empty() {
        lines.push(String::new());
        lines.push("Decision logs:".to_string());
        for log in &report.decision_logs {
            lines.push(format!(
                "- trace=`{}` bead=`{}` current_owner=`{}` reservation_holder=`{}` blocker_class=`{}` evidence_freshness_age_secs={} required_action=`{}`",
                log.trace_id,
                log.bead_id,
                log.current_owner.as_deref().unwrap_or(""),
                log.reservation_holder.as_deref().unwrap_or(""),
                log.blocker_class,
                render_optional_i64(log.evidence_freshness_age_secs),
                log.required_action
            ));
        }
    }

    if !report.runbook_goldens.is_empty() {
        lines.push(String::new());
        lines.push("Runbook goldens:".to_string());
        for entry in &report.runbook_goldens {
            lines.push(format!(
                "- bead=`{}` agent=`{}` reservation_holder=`{}` decision_code=`{}` evidence=`{}` required_action=`{}` must_not_do=`{}` evidence_pointers=`{}`",
                entry.bead_id,
                entry.agent.as_deref().unwrap_or(""),
                entry.reservation_holder.as_deref().unwrap_or(""),
                entry.decision_code,
                entry.reservation_or_blocker_evidence.join(","),
                entry.required_action,
                entry.must_not_do,
                entry.evidence_pointers.join(",")
            ));
        }
    }

    if !report.audit_ledger.is_empty() {
        lines.push(String::new());
        lines.push("Audit ledger:".to_string());
        for entry in &report.audit_ledger {
            lines.push(format!(
                "- sequence={} trace=`{}` bead=`{}` decision_code=`{}` no_files_deleted={} reservations_overridden={} evidence_pointers=`{}` required_action=`{}` must_not_do=`{}`",
                entry.sequence,
                entry.trace_id,
                entry.bead_id,
                entry.decision_code,
                entry.no_files_deleted,
                entry.reservations_overridden,
                entry.evidence_pointers.join(","),
                entry.required_action,
                entry.must_not_do
            ));
        }
    }

    if !report.active_agents.is_empty() {
        lines.push(String::new());
        lines.push("Active agents:".to_string());
        for agent in &report.active_agents {
            lines.push(format!(
                "- agent=`{}` project=`{}` last_active_age_secs={} ack_required={} claimed_issues={} task=`{}`",
                agent.agent_name,
                agent.project_key,
                render_optional_i64(agent.last_active_age_secs),
                agent.ack_required_count,
                agent.claimed_issue_count,
                agent.task_description.as_deref().unwrap_or("")
            ));
        }
    }

    if !report.active_reservations.is_empty() {
        lines.push(String::new());
        lines.push("Active reservations:".to_string());
        for reservation in &report.active_reservations {
            lines.push(format!(
                "- holder=`{}` path=`{}` reason=`{}` expires_in_secs={} exclusive={}",
                reservation.holder_agent,
                reservation.path_pattern,
                reservation.reason.as_deref().unwrap_or(""),
                reservation.expires_in_secs,
                reservation.exclusive
            ));
        }
    }

    if !report.active_rch_builds.is_empty() {
        lines.push(String::new());
        lines.push("Active RCH builds:".to_string());
        for build in &report.active_rch_builds {
            lines.push(format!(
                "- build=`{}` bead=`{}` worker=`{}` state=`{:?}` heartbeat_age_secs={} progress_age_secs={} stale_progress={} stale_heartbeat={}",
                build.build_id,
                build.blocker_bead_id.as_deref().unwrap_or(""),
                build.worker_id.as_deref().unwrap_or(""),
                build.state,
                render_optional_i64(build.heartbeat_age_secs),
                render_optional_i64(build.progress_age_secs),
                build.detector_progress_stale,
                build.detector_heartbeat_stale
            ));
        }
    }

    if !report.cross_repo_blockers.is_empty() {
        lines.push(String::new());
        lines.push("Cross-repo blockers:".to_string());
        for blocker in &report.cross_repo_blockers {
            lines.push(format!(
                "- bead=`{}` sibling=`{}` sibling_bead=`{}` subsystem=`{}` blocker_kind=`{}` command_family=`{}` holder=`{}` file=`{}` observed_age_secs={} error=`{}` action=`{}`",
                blocker.local_bead_id,
                blocker.sibling_project_key,
                blocker.sibling_bead_id.as_deref().unwrap_or(""),
                blocker.subsystem.as_deref().unwrap_or(""),
                blocker.blocker_kind_label,
                blocker
                    .verification_command_family_label
                    .as_deref()
                    .unwrap_or(""),
                blocker.holder_agent.as_deref().unwrap_or(""),
                blocker.file_path.as_deref().unwrap_or(""),
                blocker.observed_age_secs,
                blocker.observed_error.as_deref().unwrap_or(""),
                blocker.action_summary
            ));
        }
    }

    if !report.cleared_cross_repo_blockers.is_empty() {
        lines.push(String::new());
        lines.push("Cleared cross-repo blockers:".to_string());
        for blocker in &report.cleared_cross_repo_blockers {
            lines.push(format!(
                "- bead=`{}` sibling=`{}` sibling_bead=`{}` blocker_kind=`{}` command_family=`{}` cleared_at=`{}` clearing_commit=`{}` action=`{}`",
                blocker.local_bead_id,
                blocker.sibling_project_key,
                blocker.sibling_bead_id.as_deref().unwrap_or(""),
                blocker.blocker_kind_label,
                blocker
                    .verification_command_family_label
                    .as_deref()
                    .unwrap_or(""),
                blocker
                    .cleared_at
                    .map(|timestamp| timestamp.to_rfc3339())
                    .unwrap_or_default(),
                blocker.clearing_commit_hash.as_deref().unwrap_or(""),
                blocker.action_summary
            ));
        }
    }

    if !report.safe_reopen_commands.is_empty() {
        lines.push(String::new());
        lines.push("Safe reopen commands:".to_string());
        for command in &report.safe_reopen_commands {
            lines.push(format!(
                "- bead=`{}` command=`{}` reason_codes=`{}`",
                command.bead_id,
                command.command,
                command.reason_codes.join(",")
            ));
        }
    }

    lines.join("\n")
}

fn decision_view(
    input: &SwarmHandoffEvidenceInput,
    issue: &SwarmHandoffIssueEvidence,
    outcome: &SwarmHandoffPolicyOutcome,
) -> SwarmHandoffDecisionView {
    SwarmHandoffDecisionView {
        bead_id: outcome.bead_id.clone(),
        decision: outcome.decision,
        decision_label: outcome.decision.as_str().to_string(),
        assignee: issue.assignee.clone(),
        reservation_holder: decision_reservation_holder(input, issue),
        blocker_class: decision_blocker_class(outcome).to_string(),
        freshness_age_secs: freshness_age_secs(input, issue),
        next_action: outcome.required_action.clone(),
        required_br_command: outcome.required_br_command.clone(),
        reopen_allowed: outcome.reopen_allowed,
        reason_codes: outcome.reason_codes.clone(),
        evidence_pointers: outcome.evidence_pointers.clone(),
        operator_message: outcome.operator_message.clone(),
    }
}

fn decision_log_entry(
    trace_id: &str,
    decision: &SwarmHandoffDecisionView,
) -> SwarmHandoffDecisionLogEntry {
    SwarmHandoffDecisionLogEntry {
        trace_id: trace_id.to_string(),
        bead_id: decision.bead_id.clone(),
        current_owner: decision.assignee.clone(),
        reservation_holder: decision.reservation_holder.clone(),
        blocker_class: decision.blocker_class.clone(),
        evidence_freshness_age_secs: decision.freshness_age_secs,
        required_action: decision.next_action.clone(),
    }
}

fn runbook_golden_entry(decision: &SwarmHandoffDecisionView) -> SwarmHandoffRunbookGoldenEntry {
    SwarmHandoffRunbookGoldenEntry {
        bead_id: decision.bead_id.clone(),
        agent: decision.assignee.clone(),
        reservation_holder: decision.reservation_holder.clone(),
        reservation_or_blocker_evidence: decision_evidence_summary(decision),
        decision_code: decision.decision_label.clone(),
        required_action: decision.next_action.clone(),
        must_not_do: decision_prohibited_action(decision.decision),
        evidence_pointers: decision.evidence_pointers.clone(),
    }
}

fn audit_ledger_entry(
    sequence: usize,
    trace_id: &str,
    entry: &SwarmHandoffRunbookGoldenEntry,
) -> SwarmHandoffAuditLedgerEntry {
    SwarmHandoffAuditLedgerEntry {
        sequence,
        trace_id: trace_id.to_string(),
        bead_id: entry.bead_id.clone(),
        decision_code: entry.decision_code.clone(),
        evidence_pointers: entry.evidence_pointers.clone(),
        required_action: entry.required_action.clone(),
        must_not_do: entry.must_not_do.clone(),
        no_files_deleted: true,
        reservations_overridden: false,
    }
}

fn agent_view(
    input: &SwarmHandoffEvidenceInput,
    agent: &SwarmHandoffAgentEvidence,
) -> SwarmHandoffAgentView {
    SwarmHandoffAgentView {
        agent_name: agent.agent_name.clone(),
        project_key: agent.project_key.clone(),
        task_description: agent.task_description.clone(),
        last_active_at: agent.last_active_at,
        last_active_age_secs: age_secs(input.observed_at, agent.last_active_at),
        contact_policy: agent.contact_policy.clone(),
        ack_required_count: agent.ack_required_count,
        claimed_issue_count: input
            .issues
            .iter()
            .filter(|issue| issue.assignee.as_deref() == Some(agent.agent_name.as_str()))
            .count(),
    }
}

fn claimed_bead_view(
    input: &SwarmHandoffEvidenceInput,
    issue: &SwarmHandoffIssueEvidence,
) -> SwarmHandoffClaimedBeadView {
    SwarmHandoffClaimedBeadView {
        bead_id: issue.bead_id.clone(),
        title: issue.title.clone(),
        status: issue.status,
        assignee: issue.assignee.clone(),
        updated_age_secs: age_secs(input.observed_at, issue.updated_at),
        dependency_count: issue.dependency_ids.len(),
        dependent_count: issue.dependent_ids.len(),
    }
}

fn reservation_view(
    input: &SwarmHandoffEvidenceInput,
    reservation: &SwarmHandoffReservationEvidence,
) -> SwarmHandoffReservationView {
    SwarmHandoffReservationView {
        holder_agent: reservation.holder_agent.clone(),
        project_key: reservation.project_key.clone(),
        path_pattern: reservation.path_pattern.clone(),
        exclusive: reservation.exclusive,
        reason: reservation.reason.clone(),
        expires_at: reservation.expires_at,
        expires_in_secs: reservation
            .expires_at
            .signed_duration_since(input.observed_at)
            .num_seconds()
            .max(0),
    }
}

fn rch_build_view(
    input: &SwarmHandoffEvidenceInput,
    build: &SwarmHandoffRchBuildEvidence,
) -> SwarmHandoffRchBuildView {
    SwarmHandoffRchBuildView {
        build_id: build.build_id.clone(),
        project_id: build.project_id.clone(),
        state: build.state,
        worker_id: build.worker_id.clone(),
        blocker_bead_id: build.blocker_bead_id.clone(),
        heartbeat_age_secs: age_secs(input.observed_at, build.heartbeat_at),
        progress_age_secs: age_secs(input.observed_at, build.progress_at),
        detector_progress_stale: build.detector_progress_stale,
        detector_heartbeat_stale: build.detector_heartbeat_stale,
    }
}

fn cross_repo_blocker_view(
    input: &SwarmHandoffEvidenceInput,
    blocker: &SwarmHandoffCrossRepoBlockerEvidence,
) -> SwarmHandoffCrossRepoBlockerView {
    SwarmHandoffCrossRepoBlockerView {
        local_bead_id: blocker.local_bead_id.clone(),
        sibling_project_key: blocker.sibling_project_key.clone(),
        sibling_bead_id: blocker.sibling_bead_id.clone(),
        subsystem: blocker.subsystem.clone(),
        blocker_kind: blocker.blocker_kind,
        blocker_kind_label: blocker.blocker_kind.as_str().to_string(),
        verification_command_family: blocker.verification_command_family,
        verification_command_family_label: blocker
            .verification_command_family
            .map(|family| family.as_str().to_string()),
        file_path: blocker.file_path.clone(),
        holder_agent: blocker.holder_agent.clone(),
        observed_error: blocker.observed_error.clone(),
        observed_age_secs: input
            .observed_at
            .signed_duration_since(blocker.observed_at)
            .num_seconds()
            .max(0),
        cleared: blocker.cleared,
        cleared_at: blocker.cleared_at,
        clearing_commit_hash: blocker.clearing_commit_hash.clone(),
        action_summary: cross_repo_blocker_action_summary(blocker).to_string(),
    }
}

fn cross_repo_blocker_action_summary(
    blocker: &SwarmHandoffCrossRepoBlockerEvidence,
) -> &'static str {
    if blocker.cleared {
        return "Sibling blocker is cleared; keep the mirror for audit context and rerun local validation before closing dependent work.";
    }

    match blocker.blocker_kind {
        SwarmHandoffBlockerKind::ReservationConflict => {
            "Coordinate with the sibling reservation holder; do not override the remote holder from this repository."
        }
        SwarmHandoffBlockerKind::RchInProgress => {
            "Wait for the sibling RCH proof or record a worker-infra blocker; do not treat the pending proof as green."
        }
        SwarmHandoffBlockerKind::CompileError | SwarmHandoffBlockerKind::TestFailure => {
            "Keep the local bead blocked on the sibling validation failure until the mirror is cleared with verification evidence."
        }
        SwarmHandoffBlockerKind::ToolingUnavailable => {
            "Record the sibling tooling failure as infrastructure evidence and avoid broadening the local product task."
        }
        SwarmHandoffBlockerKind::Unknown => {
            "Refresh sibling evidence before taking ownership or reopening related local work."
        }
    }
}

fn decision_reservation_holder(
    input: &SwarmHandoffEvidenceInput,
    issue: &SwarmHandoffIssueEvidence,
) -> Option<String> {
    input
        .cross_repo_blockers
        .iter()
        .find(|blocker| blocker.local_bead_id == issue.bead_id && !blocker.cleared)
        .and_then(|blocker| blocker.holder_agent.clone())
        .or_else(|| {
            input
                .matching_reservations(&issue.bead_id, issue, false)
                .first()
                .map(|reservation| reservation.holder_agent.clone())
        })
}

fn decision_evidence_summary(decision: &SwarmHandoffDecisionView) -> Vec<String> {
    let mut evidence = Vec::new();
    if let Some(holder) = &decision.reservation_holder {
        evidence.push(format!("reservation_holder:{holder}"));
    }
    evidence.push(format!("blocker_class:{}", decision.blocker_class));
    evidence.extend(decision.evidence_pointers.iter().cloned());
    evidence.into_iter().take(MAX_HANDOFF_LIST_ITEMS).collect()
}

fn decision_prohibited_action(decision: SwarmHandoffPolicyDecision) -> String {
    match decision {
        SwarmHandoffPolicyDecision::Active => {
            "Do not reopen; request an explicit handoff acknowledgement from the current owner first."
        }
        SwarmHandoffPolicyDecision::BlockedOnKnownDependency => {
            "Do not reopen or close the local bead until blocker evidence is cleared and reproduced."
        }
        SwarmHandoffPolicyDecision::BlockedOnReservation => {
            "Do not override or release another agent's reservation."
        }
        SwarmHandoffPolicyDecision::WaitingOnRch => {
            "Do not treat a pending RCH proof as green or close dependent work."
        }
        SwarmHandoffPolicyDecision::StaleButContested => {
            "Do not override the active reservation without an acknowledgement from the holder."
        }
        SwarmHandoffPolicyDecision::Abandoned => {
            "Do not delete files or assume ownership without an explicit Beads transition."
        }
        SwarmHandoffPolicyDecision::ReadyToReopen => {
            "Do not delete files, override reservations, or skip the explicit reopen command."
        }
        SwarmHandoffPolicyDecision::ManualReviewRequired => {
            "Do not reopen from malformed, unknown, or incomplete evidence."
        }
    }
    .to_string()
}

fn decision_blocker_class(outcome: &SwarmHandoffPolicyOutcome) -> &'static str {
    if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_BLOCKED_CROSS_REPO_RESERVATION)
    {
        "cross_repo_reservation"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_BLOCKED_CROSS_REPO_BLOCKER)
    {
        "cross_repo_blocker"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_BLOCKED_RESERVATION_ACTIVE)
    {
        "reservation"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_BLOCKED_DEPENDENCY_OPEN)
    {
        "dependency"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_WAITING_RCH_ACTIVE)
    {
        "rch"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_STALE_CONTESTED_RCH_STALE)
    {
        "rch_stale"
    } else if outcome.reason_codes.iter().any(|code| {
        code == handoff_reason_codes::HANDOFF_STALE_CONTESTED_RESERVATION
            || code == handoff_reason_codes::HANDOFF_READY_EXPIRED_RESERVATION
    }) {
        "reservation"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_STALE_ACK_REQUIRED)
    {
        "agent_mail_ack"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_ABANDONED_NO_RECENT_SIGNALS)
    {
        "stale_claim"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code == handoff_reason_codes::HANDOFF_READY_UNASSIGNED)
    {
        "unassigned"
    } else if outcome
        .reason_codes
        .iter()
        .any(|code| code.starts_with("HANDOFF_MANUAL_REVIEW_"))
    {
        "manual_review"
    } else if outcome.decision == SwarmHandoffPolicyDecision::Active {
        "owner_activity"
    } else {
        "unknown"
    }
}

fn freshness_age_secs(
    input: &SwarmHandoffEvidenceInput,
    issue: &SwarmHandoffIssueEvidence,
) -> Option<i64> {
    let mut latest = issue
        .updated_at
        .into_iter()
        .chain(issue.last_comment_at)
        .max();
    if let Some(assignee) = issue.assignee.as_deref() {
        latest = latest.max(
            input
                .agents
                .iter()
                .filter(|agent| agent.agent_name == assignee)
                .filter_map(|agent| agent.last_active_at)
                .max(),
        );
    }
    latest = latest.max(
        input
            .git_activity
            .iter()
            .filter(|activity| git_activity_matches_issue(activity, issue))
            .map(|activity| activity.authored_at)
            .max(),
    );
    latest = latest.max(
        input
            .matching_rch_builds(&issue.bead_id)
            .into_iter()
            .flat_map(|build| [build.heartbeat_at, build.progress_at])
            .flatten()
            .max(),
    );
    latest = latest.max(
        input
            .cross_repo_blockers
            .iter()
            .filter(|blocker| blocker.local_bead_id == issue.bead_id && !blocker.cleared)
            .map(|blocker| blocker.observed_at)
            .max(),
    );
    age_secs(input.observed_at, latest)
}

fn age_secs(observed_at: DateTime<Utc>, timestamp: Option<DateTime<Utc>>) -> Option<i64> {
    timestamp.map(|timestamp| {
        observed_at
            .signed_duration_since(timestamp)
            .num_seconds()
            .max(0)
    })
}

fn render_decision_count_summary(report: &SwarmHandoffReadinessReport) -> String {
    report
        .decision_counts
        .iter()
        .filter(|count| count.count > 0)
        .map(|count| format!("{}={}", count.decision.as_str(), count.count))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

fn default_evidence_schema_version() -> String {
    SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION.to_string()
}

fn policy_outcome(
    bead_id: &str,
    observed_at: DateTime<Utc>,
    decision: SwarmHandoffPolicyDecision,
    reason_codes: Vec<&'static str>,
    evidence_pointers: Vec<String>,
    required_action: &str,
    required_br_command: Option<String>,
) -> SwarmHandoffPolicyOutcome {
    let reason_codes = reason_codes
        .into_iter()
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let evidence_pointers = evidence_pointers
        .into_iter()
        .take(MAX_HANDOFF_LIST_ITEMS)
        .map(|pointer| truncate_policy_string(&pointer))
        .collect::<Vec<_>>();
    let required_action = truncate_policy_string(required_action);
    let operator_message = truncate_policy_string(&format!(
        "{bead_id}: handoff_decision={} reason_codes={} required_action={}",
        decision.as_str(),
        reason_codes.join(","),
        required_action
    ));
    SwarmHandoffPolicyOutcome {
        schema_version: SWARM_HANDOFF_POLICY_SCHEMA_VERSION.to_string(),
        bead_id: bead_id.to_string(),
        observed_at,
        decision,
        reason_codes,
        evidence_pointers,
        required_action,
        required_br_command,
        reopen_allowed: decision == SwarmHandoffPolicyDecision::ReadyToReopen,
        operator_message,
    }
}

fn truncate_policy_string(value: &str) -> String {
    if value.len() <= MAX_HANDOFF_SUMMARY_BYTES {
        value.to_string()
    } else {
        value
            .chars()
            .scan(0usize, |bytes, ch| {
                let next = bytes.saturating_add(ch.len_utf8());
                if next > MAX_HANDOFF_SUMMARY_BYTES {
                    None
                } else {
                    *bytes = next;
                    Some(ch)
                }
            })
            .collect()
    }
}

fn reopen_command(bead_id: &str) -> String {
    format!("br update {bead_id} --status open --assignee \"\" --actor <agent>")
}

fn issue_pointer(issue: &SwarmHandoffIssueEvidence) -> String {
    format!("issue:{}", issue.bead_id)
}

fn agent_pointer(agent: &SwarmHandoffAgentEvidence) -> String {
    format!("agent:{}@{}", agent.agent_name, agent.project_key)
}

fn reservation_pointer(reservation: &SwarmHandoffReservationEvidence) -> String {
    format!(
        "reservation:{}:{}:expires={}",
        reservation.holder_agent,
        reservation.path_pattern,
        reservation.expires_at.to_rfc3339()
    )
}

fn rch_pointer(build: &SwarmHandoffRchBuildEvidence) -> String {
    format!("rch:{}:{:?}", build.build_id, build.state)
}

fn git_pointer(activity: &SwarmHandoffGitActivityEvidence) -> String {
    match activity.commit_hash.as_deref() {
        Some(commit) => format!("git:{commit}:{}", activity.authored_at.to_rfc3339()),
        None => format!("git:{}", activity.authored_at.to_rfc3339()),
    }
}

fn cross_repo_pointer(blocker: &SwarmHandoffCrossRepoBlockerEvidence) -> String {
    let command_family = blocker
        .verification_command_family
        .map(SwarmHandoffVerificationCommandFamily::as_str)
        .unwrap_or("unknown");
    format!(
        "cross_repo:{}:{}:{}:{}",
        blocker.local_bead_id,
        blocker.blocker_kind.as_str(),
        command_family,
        blocker.sibling_project_key
    )
}

fn reservation_matches_bead(
    reservation: &SwarmHandoffReservationEvidence,
    bead_id: &str,
    issue: &SwarmHandoffIssueEvidence,
) -> bool {
    reservation.reason.as_deref().is_some_and(|reason| {
        reason.contains(bead_id)
            || issue
                .assignee
                .as_deref()
                .is_some_and(|assignee| reason.contains(assignee))
    })
}

fn reservation_is_active(
    reservation: &SwarmHandoffReservationEvidence,
    observed_at: DateTime<Utc>,
) -> bool {
    reservation.released_at.is_none() && reservation.expires_at > observed_at
}

fn reservation_is_expired(
    reservation: &SwarmHandoffReservationEvidence,
    observed_at: DateTime<Utc>,
) -> bool {
    reservation.released_at.is_none() && reservation.expires_at <= observed_at
}

fn rch_build_is_recently_active(
    build: &SwarmHandoffRchBuildEvidence,
    observed_at: DateTime<Utc>,
    config: &SwarmHandoffPolicyConfig,
) -> bool {
    build.state.is_active()
        && !build.detector_progress_stale
        && !build.detector_heartbeat_stale
        && (timestamp_is_recent(
            build.heartbeat_at,
            observed_at,
            config.rch_activity_grace_secs,
        ) || timestamp_is_recent(
            build.progress_at,
            observed_at,
            config.rch_activity_grace_secs,
        ))
}

fn issue_timestamp_is_recent(
    timestamp: Option<DateTime<Utc>>,
    observed_at: DateTime<Utc>,
    config: &SwarmHandoffPolicyConfig,
) -> bool {
    timestamp_is_recent(timestamp, observed_at, config.issue_activity_grace_secs)
}

fn agent_timestamp_is_recent(
    timestamp: Option<DateTime<Utc>>,
    observed_at: DateTime<Utc>,
    config: &SwarmHandoffPolicyConfig,
) -> bool {
    timestamp_is_recent(timestamp, observed_at, config.agent_activity_grace_secs)
}

fn git_timestamp_is_recent(
    timestamp: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    config: &SwarmHandoffPolicyConfig,
) -> bool {
    timestamp_is_recent(Some(timestamp), observed_at, config.git_activity_grace_secs)
}

fn timestamp_is_recent(
    timestamp: Option<DateTime<Utc>>,
    observed_at: DateTime<Utc>,
    grace_secs: u64,
) -> bool {
    let Some(timestamp) = timestamp else {
        return false;
    };
    let age_secs = observed_at.signed_duration_since(timestamp).num_seconds();
    age_secs >= 0 && u64::try_from(age_secs).is_ok_and(|age| age <= grace_secs)
}

fn git_activity_matches_issue(
    activity: &SwarmHandoffGitActivityEvidence,
    issue: &SwarmHandoffIssueEvidence,
) -> bool {
    activity.agent_name.as_deref() == issue.assignee.as_deref()
        || activity.summary.contains(&issue.bead_id)
}

fn validate_overlap_candidate(
    candidate: &SwarmOverlapCandidateWork,
    candidate_paths: &[String],
) -> SwarmHandoffEvidenceResult<()> {
    require_non_empty_string("overlap_candidate.bead_id", &candidate.bead_id)?;
    require_optional_string(
        "overlap_candidate.agent_name",
        candidate.agent_name.as_deref(),
    )?;
    require_len(
        "overlap_candidate.candidate_paths",
        candidate_paths.len(),
        MAX_OVERLAP_CANDIDATE_PATHS,
    )?;
    if candidate_paths.is_empty() {
        return Err(SwarmHandoffEvidenceError::EmptyField {
            field: "overlap_candidate.candidate_paths",
        });
    }
    for path in candidate_paths {
        require_path_pattern("overlap_candidate.candidate_paths", path)?;
    }
    require_string_list(
        "overlap_candidate.dependency_ids",
        &candidate.dependency_ids,
    )?;
    require_string_list("overlap_candidate.dependent_ids", &candidate.dependent_ids)?;
    Ok(())
}

fn overlap_report(
    observed_at: DateTime<Utc>,
    candidate: &SwarmOverlapCandidateWork,
    candidate_paths: Vec<String>,
    mut conflicts: Vec<SwarmOverlapRiskConflict>,
) -> SwarmOverlapRiskReport {
    conflicts.sort_by(|left, right| {
        right
            .risk_level
            .cmp(&left.risk_level)
            .then_with(|| right.score.cmp(&left.score))
            .then_with(|| left.reason_code.cmp(&right.reason_code))
            .then_with(|| left.subject.cmp(&right.subject))
    });
    conflicts.truncate(MAX_OVERLAP_CONFLICTS);
    let risk_level = conflicts
        .iter()
        .map(|conflict| conflict.risk_level)
        .max()
        .unwrap_or(SwarmOverlapRiskLevel::Clear);
    let risk_score = conflicts
        .iter()
        .map(|conflict| conflict.score)
        .max()
        .unwrap_or(0);
    let suggested_action = overlap_suggested_action(risk_level, &conflicts);
    let mut reason_codes = conflicts
        .iter()
        .map(|conflict| conflict.reason_code.clone())
        .collect::<Vec<_>>();
    reason_codes.sort();
    reason_codes.dedup();
    let operator_message = truncate_policy_string(&format!(
        "{}: overlap_risk={} score={} suggested_action={} reason_codes={}",
        candidate.bead_id,
        risk_level.as_str(),
        risk_score,
        suggested_action.as_str(),
        reason_codes.join(",")
    ));
    SwarmOverlapRiskReport {
        schema_version: SWARM_OVERLAP_RISK_SCHEMA_VERSION.to_string(),
        bead_id: candidate.bead_id.clone(),
        observed_at,
        candidate_paths,
        risk_level,
        risk_score,
        suggested_action,
        reason_codes,
        conflicts,
        operator_message,
    }
}

fn overlap_suggested_action(
    risk_level: SwarmOverlapRiskLevel,
    conflicts: &[SwarmOverlapRiskConflict],
) -> SwarmOverlapSuggestedAction {
    if conflicts
        .iter()
        .any(|conflict| conflict.kind == SwarmOverlapConflictKind::MalformedInput)
    {
        return SwarmOverlapSuggestedAction::RefreshEvidence;
    }
    if conflicts
        .iter()
        .any(|conflict| conflict.kind == SwarmOverlapConflictKind::BrMailDisagreement)
    {
        return SwarmOverlapSuggestedAction::AskForHandoff;
    }
    if conflicts.iter().any(|conflict| {
        conflict.kind == SwarmOverlapConflictKind::ReservationOverlap
            && conflict.risk_level == SwarmOverlapRiskLevel::HardConflict
    }) {
        return SwarmOverlapSuggestedAction::Wait;
    }
    if conflicts.iter().any(|conflict| {
        conflict.kind == SwarmOverlapConflictKind::ActiveOwner
            && conflict.risk_level == SwarmOverlapRiskLevel::HardConflict
    }) {
        return SwarmOverlapSuggestedAction::AskForHandoff;
    }
    if conflicts
        .iter()
        .any(|conflict| conflict.kind == SwarmOverlapConflictKind::DisjointTestSurface)
    {
        return SwarmOverlapSuggestedAction::PickTestOnlySurface;
    }
    match risk_level {
        SwarmOverlapRiskLevel::Clear
        | SwarmOverlapRiskLevel::Advisory
        | SwarmOverlapRiskLevel::StaleConflict => SwarmOverlapSuggestedAction::Claim,
        SwarmOverlapRiskLevel::HardConflict => SwarmOverlapSuggestedAction::AskForHandoff,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "small conflict constructor keeps call sites readable at the scoring point"
)]
fn overlap_conflict(
    kind: SwarmOverlapConflictKind,
    risk_level: SwarmOverlapRiskLevel,
    score: u8,
    subject: &str,
    owner: Option<&str>,
    path: Option<&str>,
    reason_code: &'static str,
    evidence_pointer: String,
    age_secs: Option<i64>,
) -> SwarmOverlapRiskConflict {
    SwarmOverlapRiskConflict {
        kind,
        risk_level,
        score,
        subject: truncate_policy_string(subject),
        owner: owner.map(truncate_policy_string),
        path: path.map(truncate_policy_string),
        reason_code: reason_code.to_string(),
        evidence_pointer: truncate_policy_string(&evidence_pointer),
        age_secs,
    }
}

fn owner_has_recent_signal(
    input: &SwarmHandoffEvidenceInput,
    issue: &SwarmHandoffIssueEvidence,
    config: &SwarmHandoffPolicyConfig,
) -> bool {
    issue_timestamp_is_recent(issue.updated_at, input.observed_at, config)
        || issue_timestamp_is_recent(issue.last_comment_at, input.observed_at, config)
        || issue.assignee.as_deref().is_some_and(|assignee| {
            input.agents.iter().any(|agent| {
                agent.agent_name == assignee
                    && agent_timestamp_is_recent(agent.last_active_at, input.observed_at, config)
            }) || input.git_activity.iter().any(|activity| {
                git_activity_matches_issue(activity, issue)
                    && git_timestamp_is_recent(activity.authored_at, input.observed_at, config)
            })
        })
}

fn dependency_context_overlaps(
    candidate: &SwarmOverlapCandidateWork,
    issue: &SwarmHandoffIssueEvidence,
) -> bool {
    if candidate
        .dependency_ids
        .iter()
        .any(|id| id == &issue.bead_id)
        || candidate
            .dependent_ids
            .iter()
            .any(|id| id == &issue.bead_id)
        || issue
            .dependency_ids
            .iter()
            .any(|id| id == &candidate.bead_id)
        || issue
            .dependent_ids
            .iter()
            .any(|id| id == &candidate.bead_id)
    {
        return true;
    }
    let candidate_context = candidate
        .dependency_ids
        .iter()
        .chain(candidate.dependent_ids.iter())
        .collect::<BTreeSet<_>>();
    issue
        .dependency_ids
        .iter()
        .chain(issue.dependent_ids.iter())
        .any(|id| candidate_context.contains(id))
}

fn normalize_overlap_paths(paths: &[String]) -> Vec<String> {
    let mut normalized = paths
        .iter()
        .take(MAX_OVERLAP_CANDIDATE_PATHS)
        .map(|path| {
            path.trim()
                .trim_start_matches("./")
                .trim_end_matches('/')
                .replace('\\', "/")
        })
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn path_patterns_overlap(left: &str, right: &str) -> bool {
    let left = normalize_overlap_pattern(left);
    let right = normalize_overlap_pattern(right);
    if left == right || path_pattern_matches(&left, &right) || path_pattern_matches(&right, &left) {
        return true;
    }
    let left_prefix = glob_literal_prefix(&left);
    let right_prefix = glob_literal_prefix(&right);
    !left_prefix.is_empty()
        && !right_prefix.is_empty()
        && overlap_prefix_contains(&left_prefix, &right_prefix)
}

fn overlap_prefix_contains(left: &str, right: &str) -> bool {
    left == right
        || left.starts_with(&format!("{right}/"))
        || right.starts_with(&format!("{left}/"))
}

fn path_pattern_matches(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    if pattern.ends_with("/**") {
        let prefix = pattern.trim_end_matches("/**");
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if pattern.ends_with("/*") {
        let prefix = pattern.trim_end_matches("/*");
        return path
            .strip_prefix(&format!("{prefix}/"))
            .is_some_and(|suffix| !suffix.contains('/'));
    }
    if pattern.contains('*') {
        let prefix = pattern.split('*').next().unwrap_or_default();
        let suffix = pattern.rsplit('*').next().unwrap_or_default();
        return path.starts_with(prefix) && (suffix.is_empty() || path.ends_with(suffix));
    }
    path.starts_with(&format!("{pattern}/"))
}

fn normalize_overlap_pattern(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("./")
        .trim_end_matches('/')
        .replace('\\', "/")
}

fn glob_literal_prefix(pattern: &str) -> String {
    let prefix = pattern.split(['*', '?', '[']).next().unwrap_or_default();
    prefix.trim_end_matches('/').to_string()
}

fn overlap_path_is_test_surface(path: &str) -> bool {
    path == "tests"
        || path.starts_with("tests/")
        || path.contains("/tests/")
        || path.ends_with("_test.rs")
        || path.ends_with("_tests.rs")
}

fn overlap_git_pointer(activity: &SwarmOverlapGitActivityEvidence) -> String {
    match activity.commit_hash.as_deref() {
        Some(commit) => format!("git:{commit}:{}", activity.authored_at.to_rfc3339()),
        None => format!("git:{}", activity.authored_at.to_rfc3339()),
    }
}

fn validate_schema(schema_version: &str) -> SwarmHandoffEvidenceResult<()> {
    if schema_version == SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(SwarmHandoffEvidenceError::InvalidSchemaVersion {
            expected: SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION,
            actual: schema_version.to_string(),
        })
    }
}

fn validate_issue(issue: &SwarmHandoffIssueEvidence) -> SwarmHandoffEvidenceResult<()> {
    require_non_empty_string("issue.bead_id", &issue.bead_id)?;
    require_non_empty_string("issue.title", &issue.title)?;
    require_optional_string("issue.assignee", issue.assignee.as_deref())?;
    require_optional_string("issue.blocker_summary", issue.blocker_summary.as_deref())?;
    require_string_list("issue.dependency_ids", &issue.dependency_ids)?;
    require_string_list("issue.dependent_ids", &issue.dependent_ids)?;
    Ok(())
}

fn validate_agent(agent: &SwarmHandoffAgentEvidence) -> SwarmHandoffEvidenceResult<()> {
    require_non_empty_string("agent.agent_name", &agent.agent_name)?;
    require_non_empty_string("agent.project_key", &agent.project_key)?;
    require_optional_string("agent.task_description", agent.task_description.as_deref())?;
    require_optional_string("agent.contact_policy", agent.contact_policy.as_deref())?;
    Ok(())
}

fn validate_reservation(
    reservation: &SwarmHandoffReservationEvidence,
) -> SwarmHandoffEvidenceResult<()> {
    require_non_empty_string("reservation.holder_agent", &reservation.holder_agent)?;
    require_non_empty_string("reservation.project_key", &reservation.project_key)?;
    require_path_pattern("reservation.path_pattern", &reservation.path_pattern)?;
    require_optional_string("reservation.reason", reservation.reason.as_deref())?;
    Ok(())
}

fn validate_rch_build(build: &SwarmHandoffRchBuildEvidence) -> SwarmHandoffEvidenceResult<()> {
    require_non_empty_string("rch_build.build_id", &build.build_id)?;
    require_non_empty_string("rch_build.project_id", &build.project_id)?;
    require_optional_string("rch_build.command_digest", build.command_digest.as_deref())?;
    require_optional_string("rch_build.worker_id", build.worker_id.as_deref())?;
    require_optional_string(
        "rch_build.blocker_bead_id",
        build.blocker_bead_id.as_deref(),
    )?;
    Ok(())
}

fn validate_git_activity(
    activity: &SwarmHandoffGitActivityEvidence,
) -> SwarmHandoffEvidenceResult<()> {
    require_non_empty_string("git_activity.project_key", &activity.project_key)?;
    require_non_empty_string("git_activity.summary", &activity.summary)?;
    require_optional_string("git_activity.agent_name", activity.agent_name.as_deref())?;
    require_optional_string("git_activity.commit_hash", activity.commit_hash.as_deref())?;
    Ok(())
}

fn validate_cross_repo_blocker(
    blocker: &SwarmHandoffCrossRepoBlockerEvidence,
) -> SwarmHandoffEvidenceResult<()> {
    require_non_empty_string("cross_repo_blocker.local_bead_id", &blocker.local_bead_id)?;
    require_non_empty_string(
        "cross_repo_blocker.sibling_project_key",
        &blocker.sibling_project_key,
    )?;
    require_optional_string(
        "cross_repo_blocker.sibling_bead_id",
        blocker.sibling_bead_id.as_deref(),
    )?;
    require_optional_string("cross_repo_blocker.subsystem", blocker.subsystem.as_deref())?;
    if let Some(file_path) = &blocker.file_path {
        require_path_pattern("cross_repo_blocker.file_path", file_path)?;
    }
    require_optional_string(
        "cross_repo_blocker.holder_agent",
        blocker.holder_agent.as_deref(),
    )?;
    require_optional_string(
        "cross_repo_blocker.observed_error",
        blocker.observed_error.as_deref(),
    )?;
    require_optional_string(
        "cross_repo_blocker.clearing_commit_hash",
        blocker.clearing_commit_hash.as_deref(),
    )?;
    Ok(())
}

fn require_len(field: &'static str, actual: usize, max: usize) -> SwarmHandoffEvidenceResult<()> {
    if actual <= max {
        Ok(())
    } else {
        Err(SwarmHandoffEvidenceError::TooManyItems { field, max, actual })
    }
}

fn require_string_list(field: &'static str, values: &[String]) -> SwarmHandoffEvidenceResult<()> {
    require_len(field, values.len(), MAX_HANDOFF_LIST_ITEMS)?;
    for value in values {
        require_non_empty_string(field, value)?;
    }
    Ok(())
}

fn require_optional_string(
    field: &'static str,
    value: Option<&str>,
) -> SwarmHandoffEvidenceResult<()> {
    if let Some(value) = value {
        require_non_empty_string(field, value)?;
    }
    Ok(())
}

fn require_non_empty_string(field: &'static str, value: &str) -> SwarmHandoffEvidenceResult<()> {
    if value.trim().is_empty() {
        return Err(SwarmHandoffEvidenceError::EmptyField { field });
    }
    require_string(field, value, MAX_HANDOFF_STRING_BYTES)
}

fn require_path_pattern(field: &'static str, value: &str) -> SwarmHandoffEvidenceResult<()> {
    require_non_empty_string(field, value)?;
    if value.contains("..") {
        return Err(SwarmHandoffEvidenceError::InvalidString {
            field,
            reason: "path patterns must not contain parent traversal",
        });
    }
    Ok(())
}

fn require_string(field: &'static str, value: &str, max: usize) -> SwarmHandoffEvidenceResult<()> {
    if value.len() > max {
        return Err(SwarmHandoffEvidenceError::StringTooLong {
            field,
            max,
            actual: value.len(),
        });
    }
    if value.contains('\0') {
        return Err(SwarmHandoffEvidenceError::InvalidString {
            field,
            reason: "NUL bytes are not allowed",
        });
    }
    Ok(())
}
