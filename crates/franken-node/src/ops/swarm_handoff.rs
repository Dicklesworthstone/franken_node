//! Read-only evidence model for stale-work and handoff decisions.
//!
//! This module intentionally stops at evidence capture and validation. Policy
//! decisions live in a later layer so scanners can stay side-effect free.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub const SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION: &str = "franken-node/swarm-handoff/evidence/v1";
pub const SWARM_HANDOFF_SUMMARY_SCHEMA_VERSION: &str = "franken-node/swarm-handoff/summary/v1";

pub const MAX_HANDOFF_ISSUES: usize = 256;
pub const MAX_HANDOFF_AGENTS: usize = 256;
pub const MAX_HANDOFF_RESERVATIONS: usize = 512;
pub const MAX_HANDOFF_RCH_BUILDS: usize = 128;
pub const MAX_HANDOFF_GIT_EVENTS: usize = 512;
pub const MAX_HANDOFF_CROSS_REPO_BLOCKERS: usize = 128;
pub const MAX_HANDOFF_LIST_ITEMS: usize = 64;
pub const MAX_HANDOFF_STRING_BYTES: usize = 512;
pub const MAX_HANDOFF_SUMMARY_BYTES: usize = 2048;

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
    pub blocker_kind: SwarmHandoffBlockerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_error: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub cleared: bool,
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
                .filter(|blocker| blocker.blocker_kind == SwarmHandoffBlockerKind::Unknown)
                .count()
    }
}

fn default_evidence_schema_version() -> String {
    SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION.to_string()
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
