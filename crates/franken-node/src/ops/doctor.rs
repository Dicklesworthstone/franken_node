//! bd-p9mpd.5: Doctor output for workspace pressure decisions.
//!
//! Surfaces workspace pressure governance decisions, resource status,
//! and recommended actions in both JSON and human-readable formats for operators.

use crate::ops::workspace_pressure_policy::{
    AdmissionDecision, PolicyDecision, PolicyThresholds, WorkCostClass, WorkspacePressureInputs,
    WorkspacePressurePolicy,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::push_bounded;

/// Maximum diagnostic messages to include in doctor output.
const MAX_DOCTOR_DIAGNOSTICS: usize = 20;

/// Maximum recommended actions to include in doctor output.
const MAX_RECOMMENDED_ACTIONS: usize = 10;

/// Schema version for doctor output format.
pub const DOCTOR_OUTPUT_SCHEMA_VERSION: &str = "franken-node/doctor/workspace-pressure/v1";

/// Doctor output status levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    /// All systems healthy, no pressure detected.
    Healthy,
    /// Minor issues detected, monitor but continue operating.
    Warning,
    /// Significant pressure detected, action recommended.
    Degraded,
    /// Critical pressure, immediate action required.
    Critical,
}

impl DoctorStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Warning => "WARNING",
            Self::Degraded => "DEGRADED",
            Self::Critical => "CRITICAL",
        }
    }

    #[must_use]
    pub const fn emoji(self) -> &'static str {
        match self {
            Self::Healthy => "✅",
            Self::Warning => "⚠️",
            Self::Degraded => "🔶",
            Self::Critical => "🚨",
        }
    }
}

/// Workspace resource summary for doctor output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSummary {
    /// Free disk space in bytes.
    pub free_disk_bytes: u64,
    /// Free disk space as human-readable string.
    pub free_disk_human: String,
    /// Target directory size in bytes.
    pub target_dir_bytes: u64,
    /// Target directory size as human-readable string.
    pub target_dir_human: String,
    /// Active cargo/rustc build processes.
    pub active_builds: u32,
    /// Memory pressure ratio (0.0-1.0).
    pub memory_pressure: f32,
    /// RCH worker availability.
    pub rch_status: RchStatus,
    /// File reservation activity.
    pub active_reservations: u32,
    /// Agent Mail coordination health.
    pub coordination_healthy: bool,
    /// Structured Agent Mail coordination diagnostics.
    pub agent_mail_coordination: AgentMailCoordinationSummary,
}

/// Agent Mail coordination health state surfaced by workspace-pressure doctor output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMailHealthState {
    /// Agent Mail health probes and coordination archives are consistent.
    Healthy,
    /// Agent Mail is in read-only/degraded mode.
    DegradedReadOnly,
    /// The archive contains durable state that is ahead of the SQLite index.
    ArchiveAheadIndex,
    /// A repair or mailbox lock owner is active.
    LockOwnerActive,
    /// Agent Mail reports an explicit repair recommendation.
    RepairRecommended,
    /// Agent Mail could not be probed.
    Unavailable,
    /// Agent Mail was reachable but did not expose enough structured state.
    Unknown,
}

impl AgentMailHealthState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::DegradedReadOnly => "degraded_read_only",
            Self::ArchiveAheadIndex => "archive_ahead_index",
            Self::LockOwnerActive => "lock_owner_active",
            Self::RepairRecommended => "repair_recommended",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }
}

/// File-reservation hygiene state surfaced by Agent Mail coordination diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationHygieneState {
    /// Agent Mail reported no stale or expired active reservations.
    Healthy,
    /// Agent Mail reported unreleased reservations that are expired or stale.
    StaleReservations,
    /// Agent Mail is degraded, so normal release/contact flows may fail.
    DegradedMail,
    /// Reservation state was incomplete or not reported.
    Unknown,
}

impl ReservationHygieneState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::StaleReservations => "stale_reservations",
            Self::DegradedMail => "degraded_mail",
            Self::Unknown => "unknown",
        }
    }
}

/// A single Agent Mail file reservation lease included in hygiene diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMailReservationLease {
    /// Stable reservation identifier, when Agent Mail reports one.
    pub reservation_id: String,
    /// Agent or holder that owns the lease.
    pub owner: String,
    /// Affected file path or glob.
    pub path_pattern: String,
    /// Lease expiry timestamp as reported by Agent Mail.
    pub expires_ts: Option<String>,
    /// Whether the lease is expired at diagnostic-generation time.
    pub expired: bool,
    /// Whether Agent Mail explicitly marked the lease stale.
    pub stale: bool,
}

/// Structured diagnostic for Agent Mail reservation leaks and degraded release paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationHygieneSummary {
    /// Overall reservation hygiene state.
    pub state: ReservationHygieneState,
    /// Whether Agent Mail coordination is degraded while reservation action is needed.
    pub backend_degraded: bool,
    /// Count of active unreleased reservations known to the diagnostic.
    pub active_count: u32,
    /// Count of active reservations marked stale.
    pub stale_count: u32,
    /// Count of active reservations whose expiry timestamp is in the past.
    pub expired_count: u32,
    /// Active unreleased reservation details, capped for operator output.
    pub reservations: Vec<AgentMailReservationLease>,
    /// Whether force-release escalation requires explicit human approval.
    pub force_release_requires_human: bool,
    /// Safe next action for operators and agents.
    pub safe_next_action: String,
    /// Compact text suitable for a Beads comment.
    pub beads_comment: String,
    /// Markdown text suitable for an Agent Mail status message.
    pub agent_mail_status_body: String,
}

impl ReservationHygieneSummary {
    #[must_use]
    pub fn not_reported(backend_degraded: bool) -> Self {
        Self::from_parts(backend_degraded, None, Vec::new(), false)
    }

    #[must_use]
    pub fn from_health_payload(payload: &serde_json::Value, backend_degraded: bool) -> Self {
        let reservations = reservation_entries_from_payload(payload);
        let reported = !reservations.is_empty()
            || nested_u64(
                payload,
                &[
                    &["file_reservations", "active_count"],
                    &["file_reservations", "count"],
                    &["active_reservation_count"],
                    &["active_reservations_count"],
                    &["active_reservations"],
                ],
            )
            .is_some();
        let active_count = nested_u64(
            payload,
            &[
                &["file_reservations", "active_count"],
                &["file_reservations", "count"],
                &["active_reservation_count"],
                &["active_reservations_count"],
                &["active_reservations"],
            ],
        )
        .map(saturating_u32_from_u64);

        Self::from_parts(backend_degraded, active_count, reservations, reported)
    }

    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self.state, ReservationHygieneState::Healthy)
    }

    #[must_use]
    pub fn has_reportable_details(&self) -> bool {
        self.backend_degraded
            || self.active_count > 0
            || self.stale_count > 0
            || self.expired_count > 0
            || !self.reservations.is_empty()
            || matches!(self.state, ReservationHygieneState::Unknown)
    }

    #[must_use]
    pub fn diagnostic_reason(&self) -> String {
        format!(
            "reservation_hygiene={}; active_reservations={}; stale_reservations={}; expired_reservations={}; backend_degraded={}; force_release_requires_human={}",
            self.state.as_str(),
            self.active_count,
            self.stale_count,
            self.expired_count,
            self.backend_degraded,
            self.force_release_requires_human
        )
    }

    fn from_parts(
        backend_degraded: bool,
        active_count: Option<u32>,
        reservations: Vec<AgentMailReservationLease>,
        reported: bool,
    ) -> Self {
        let computed_active_count =
            active_count.unwrap_or_else(|| u32::try_from(reservations.len()).unwrap_or(u32::MAX));
        let stale_count = saturating_u32_from_usize(
            reservations
                .iter()
                .filter(|reservation| reservation.stale)
                .count(),
        );
        let expired_count = saturating_u32_from_usize(
            reservations
                .iter()
                .filter(|reservation| reservation.expired)
                .count(),
        );
        let state = reservation_hygiene_state(
            backend_degraded,
            reported,
            computed_active_count,
            stale_count,
            expired_count,
        );
        let force_release_requires_human = true;
        let safe_next_action = reservation_hygiene_safe_next_action(
            state,
            backend_degraded,
            computed_active_count,
            stale_count,
            expired_count,
        );
        let beads_comment = render_reservation_hygiene_beads_comment(
            state,
            backend_degraded,
            computed_active_count,
            stale_count,
            expired_count,
            &reservations,
            &safe_next_action,
        );
        let agent_mail_status_body = render_reservation_hygiene_agent_mail_body(
            state,
            backend_degraded,
            &reservations,
            &safe_next_action,
        );

        Self {
            state,
            backend_degraded,
            active_count: computed_active_count,
            stale_count,
            expired_count,
            reservations,
            force_release_requires_human,
            safe_next_action,
            beads_comment,
            agent_mail_status_body,
        }
    }
}

/// Structured Agent Mail coordination diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMailCoordinationSummary {
    /// Whether the coordination state is healthy enough for normal work.
    pub healthy: bool,
    /// Primary health state.
    pub health_state: AgentMailHealthState,
    /// Additional machine-readable signals observed during probing.
    pub signals: Vec<String>,
    /// Message count visible in the durable archive, when reported.
    pub archive_message_count: Option<u64>,
    /// Message count visible in the SQLite/indexed view, when reported.
    pub index_message_count: Option<u64>,
    /// Agent count visible in the durable archive, when reported.
    pub archive_agent_count: Option<u64>,
    /// Agent count visible in the SQLite/indexed view, when reported.
    pub index_agent_count: Option<u64>,
    /// PID holding a mailbox or repair lock, when reported.
    pub lock_owner_pid: Option<u32>,
    /// Command holding a mailbox or repair lock, when reported.
    pub lock_owner_command: Option<String>,
    /// Whether a repair flow is recommended by the health payload.
    pub repair_recommended: bool,
    /// Structured reservation leak and degraded-release diagnostics.
    pub reservation_hygiene: ReservationHygieneSummary,
    /// Safe next action for operators and agents.
    pub safe_next_action: String,
    /// Compact diagnostic detail for logs and Beads comments.
    pub detail: String,
}

impl AgentMailCoordinationSummary {
    #[must_use]
    pub fn from_legacy_health(healthy: bool) -> Self {
        if healthy {
            Self::healthy()
        } else {
            Self::degraded(
                AgentMailHealthState::Unknown,
                "agent_mail_coordination_degraded",
                "Inspect Agent Mail health and use Beads-visible handoff until coordination recovers.",
            )
        }
    }

    #[must_use]
    pub fn healthy() -> Self {
        let reservation_hygiene = ReservationHygieneSummary::not_reported(false);
        Self {
            healthy: true,
            health_state: AgentMailHealthState::Healthy,
            signals: vec!["agent_mail_health=healthy".to_string()],
            archive_message_count: None,
            index_message_count: None,
            archive_agent_count: None,
            index_agent_count: None,
            lock_owner_pid: None,
            lock_owner_command: None,
            repair_recommended: false,
            reservation_hygiene,
            safe_next_action: "No Agent Mail coordination action required.".to_string(),
            detail: "agent_mail_health=healthy".to_string(),
        }
    }

    #[must_use]
    pub fn degraded(
        health_state: AgentMailHealthState,
        detail: impl Into<String>,
        safe_next_action: impl Into<String>,
    ) -> Self {
        let detail = detail.into();
        let reservation_hygiene = ReservationHygieneSummary::not_reported(true);
        Self {
            healthy: false,
            health_state,
            signals: vec![health_state.as_str().to_string()],
            archive_message_count: None,
            index_message_count: None,
            archive_agent_count: None,
            index_agent_count: None,
            lock_owner_pid: None,
            lock_owner_command: None,
            repair_recommended: matches!(health_state, AgentMailHealthState::RepairRecommended),
            reservation_hygiene,
            safe_next_action: safe_next_action.into(),
            detail,
        }
    }

    #[must_use]
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::degraded(
            AgentMailHealthState::Unavailable,
            detail,
            "Use Beads-visible coordination and retry Agent Mail health after the service is available.",
        )
    }

    #[must_use]
    pub fn from_health_payload(payload: &serde_json::Value) -> Self {
        let archive_message_count = nested_u64(
            payload,
            &[
                &["archive_inventory", "messages"],
                &["archive_inventory", "message_count"],
                &["archive", "messages"],
                &["archive", "message_count"],
            ],
        );
        let index_message_count = nested_u64(
            payload,
            &[
                &["database_inventory", "messages"],
                &["database_inventory", "message_count"],
                &["index_inventory", "messages"],
                &["index_inventory", "message_count"],
                &["sqlite_inventory", "messages"],
                &["sqlite_inventory", "message_count"],
                &["database", "messages"],
                &["database", "message_count"],
            ],
        );
        let archive_agent_count = nested_u64(
            payload,
            &[
                &["archive_inventory", "agents"],
                &["archive_inventory", "agent_count"],
                &["archive", "agents"],
                &["archive", "agent_count"],
            ],
        );
        let index_agent_count = nested_u64(
            payload,
            &[
                &["database_inventory", "agents"],
                &["database_inventory", "agent_count"],
                &["index_inventory", "agents"],
                &["index_inventory", "agent_count"],
                &["sqlite_inventory", "agents"],
                &["sqlite_inventory", "agent_count"],
                &["database", "agents"],
                &["database", "agent_count"],
            ],
        );

        let status = first_nested_str(
            payload,
            &[
                &["status"],
                &["health_level"],
                &["semantic_readiness", "status"],
                &["readiness", "status"],
            ],
        );
        let durability_state = first_nested_str(
            payload,
            &[
                &["durability_state"],
                &["recovery_mode"],
                &["semantic_readiness", "recovery_mode"],
                &["readiness", "recovery_mode"],
            ],
        );
        let next_action = first_nested_str(
            payload,
            &[
                &["next_action"],
                &["semantic_readiness", "next_action"],
                &["readiness", "next_action"],
            ],
        );
        let lock_owner_pid = nested_u64(
            payload,
            &[
                &["lock_owner", "pid"],
                &["repair_lock_owner", "pid"],
                &["mailbox_lock_owner", "pid"],
                &["lock_owner_pid"],
            ],
        )
        .and_then(|pid| u32::try_from(pid).ok());
        let lock_owner_command = first_nested_str(
            payload,
            &[
                &["lock_owner", "command"],
                &["lock_owner", "cmd"],
                &["repair_lock_owner", "command"],
                &["mailbox_lock_owner", "command"],
                &["lock_owner_command"],
            ],
        )
        .map(ToString::to_string);

        let mut signals = Vec::new();
        if let Some(status) = status {
            push_signal(&mut signals, format!("agent_mail_status={status}"));
        }
        if let Some(durability_state) = durability_state {
            push_signal(
                &mut signals,
                format!("agent_mail_recovery_mode={durability_state}"),
            );
        }
        if archive_is_ahead(archive_message_count, index_message_count)
            || archive_is_ahead(archive_agent_count, index_agent_count)
        {
            push_signal(&mut signals, "archive_ahead_index".to_string());
        }
        if lock_owner_pid.is_some() || lock_owner_command.is_some() {
            push_signal(&mut signals, "lock_owner_active".to_string());
        }

        let degraded_read_only = matches!(
            durability_state.map(normalized_health_word).as_deref(),
            Some("degraded_read_only" | "read_only")
        );
        let repair_recommended = next_action
            .is_some_and(|value| value.to_ascii_lowercase().contains("repair"))
            || degraded_read_only;
        if repair_recommended {
            push_signal(&mut signals, "repair_recommended".to_string());
        }

        let health_state = if lock_owner_pid.is_some() || lock_owner_command.is_some() {
            AgentMailHealthState::LockOwnerActive
        } else if archive_is_ahead(archive_message_count, index_message_count)
            || archive_is_ahead(archive_agent_count, index_agent_count)
        {
            AgentMailHealthState::ArchiveAheadIndex
        } else if degraded_read_only {
            AgentMailHealthState::DegradedReadOnly
        } else if repair_recommended {
            AgentMailHealthState::RepairRecommended
        } else if matches!(
            status.map(normalized_health_word).as_deref(),
            Some("ready" | "healthy" | "ok" | "pass" | "green")
        ) {
            AgentMailHealthState::Healthy
        } else {
            AgentMailHealthState::Unknown
        };

        if signals.is_empty() {
            push_signal(&mut signals, health_state.as_str().to_string());
        }

        let healthy = matches!(health_state, AgentMailHealthState::Healthy);
        let reservation_hygiene = ReservationHygieneSummary::from_health_payload(payload, !healthy);
        if reservation_hygiene.has_reportable_details() {
            push_signal(
                &mut signals,
                format!("reservation_hygiene={}", reservation_hygiene.state.as_str()),
            );
        }
        let safe_next_action = safe_next_action_for_agent_mail(
            health_state,
            lock_owner_pid,
            lock_owner_command.as_deref(),
            next_action,
        );
        let detail = format_agent_mail_detail(
            health_state,
            &signals,
            archive_message_count,
            index_message_count,
            archive_agent_count,
            index_agent_count,
            lock_owner_pid,
            lock_owner_command.as_deref(),
            &reservation_hygiene,
        );

        Self {
            healthy,
            health_state,
            signals,
            archive_message_count,
            index_message_count,
            archive_agent_count,
            index_agent_count,
            lock_owner_pid,
            lock_owner_command,
            repair_recommended,
            reservation_hygiene,
            safe_next_action,
            detail,
        }
    }

    #[must_use]
    pub fn diagnostic_reason(&self) -> String {
        if self.reservation_hygiene.has_reportable_details() {
            format!(
                "{}; {}",
                self.detail,
                self.reservation_hygiene.diagnostic_reason()
            )
        } else {
            self.detail.clone()
        }
    }
}

fn nested_u64(payload: &serde_json::Value, paths: &[&[&str]]) -> Option<u64> {
    paths
        .iter()
        .find_map(|path| nested_value(payload, path).and_then(serde_json::Value::as_u64))
}

fn first_nested_str<'a>(payload: &'a serde_json::Value, paths: &[&[&str]]) -> Option<&'a str> {
    paths
        .iter()
        .find_map(|path| nested_value(payload, path).and_then(serde_json::Value::as_str))
}

fn nested_value<'a>(
    payload: &'a serde_json::Value,
    path: &[&str],
) -> Option<&'a serde_json::Value> {
    path.iter()
        .try_fold(payload, |current, key| current.get(*key))
}

fn normalized_health_word(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn archive_is_ahead(archive_count: Option<u64>, index_count: Option<u64>) -> bool {
    matches!((archive_count, index_count), (Some(archive), Some(index)) if archive > index)
}

fn first_nested_array<'a>(
    payload: &'a serde_json::Value,
    paths: &[&[&str]],
) -> Option<&'a Vec<serde_json::Value>> {
    paths
        .iter()
        .find_map(|path| nested_value(payload, path).and_then(serde_json::Value::as_array))
}

fn first_nested_owned_str(payload: &serde_json::Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        nested_value(payload, path).and_then(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        })
    })
}

fn first_nested_bool(payload: &serde_json::Value, paths: &[&[&str]]) -> Option<bool> {
    paths
        .iter()
        .find_map(|path| nested_value(payload, path).and_then(serde_json::Value::as_bool))
}

fn reservation_entries_from_payload(payload: &serde_json::Value) -> Vec<AgentMailReservationLease> {
    let Some(entries) = first_nested_array(
        payload,
        &[
            &["file_reservations", "active"],
            &["file_reservations", "leases"],
            &["file_reservations", "items"],
            &["active_reservations"],
            &["reservations"],
        ],
    ) else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(parse_reservation_entry)
        .take(MAX_DOCTOR_DIAGNOSTICS)
        .collect()
}

fn parse_reservation_entry(value: &serde_json::Value) -> Option<AgentMailReservationLease> {
    if value
        .get("released_ts")
        .is_some_and(|released_ts| !released_ts.is_null())
    {
        return None;
    }

    let reservation_id = first_nested_owned_str(
        value,
        &[
            &["reservation_id"],
            &["file_reservation_id"],
            &["id"],
            &["lease_id"],
        ],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let owner = first_nested_owned_str(
        value,
        &[
            &["agent_name"],
            &["owner"],
            &["holder"],
            &["holder", "agent_name"],
            &["holder", "name"],
        ],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let path_pattern = first_nested_owned_str(
        value,
        &[
            &["path_pattern"],
            &["path"],
            &["pattern"],
            &["affected_path"],
        ],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let expires_ts = first_nested_owned_str(value, &[&["expires_ts"], &["expires_at"]]);
    let expired = first_nested_bool(value, &[&["expired"], &["is_expired"]])
        .unwrap_or_else(|| expires_ts.as_deref().is_some_and(reservation_is_expired));
    let stale = first_nested_bool(value, &[&["stale"], &["is_stale"]]).unwrap_or(expired);

    Some(AgentMailReservationLease {
        reservation_id,
        owner,
        path_pattern,
        expires_ts,
        expired,
        stale,
    })
}

fn reservation_is_expired(expires_ts: &str) -> bool {
    DateTime::parse_from_rfc3339(expires_ts)
        .map(|expires_at| expires_at.with_timezone(&Utc) <= Utc::now())
        .unwrap_or(false)
}

fn saturating_u32_from_u64(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn saturating_u32_from_usize(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn reservation_hygiene_state(
    backend_degraded: bool,
    reported: bool,
    active_count: u32,
    stale_count: u32,
    expired_count: u32,
) -> ReservationHygieneState {
    if backend_degraded && (active_count > 0 || stale_count > 0 || expired_count > 0) {
        ReservationHygieneState::DegradedMail
    } else if stale_count > 0 || expired_count > 0 {
        ReservationHygieneState::StaleReservations
    } else if reported || active_count == 0 {
        ReservationHygieneState::Healthy
    } else {
        ReservationHygieneState::Unknown
    }
}

fn reservation_hygiene_safe_next_action(
    state: ReservationHygieneState,
    backend_degraded: bool,
    active_count: u32,
    stale_count: u32,
    expired_count: u32,
) -> String {
    match state {
        ReservationHygieneState::Healthy if active_count > 0 => {
            "Respect active Agent Mail reservations; contact the owner and wait for ack or renewal before editing overlapping paths.".to_string()
        }
        ReservationHygieneState::Healthy => {
            "No Agent Mail reservation hygiene action required.".to_string()
        }
        ReservationHygieneState::StaleReservations => format!(
            "Contact reservation owners and request release or renewal for {stale_count} stale / {expired_count} expired leases; force-release only after explicit human approval."
        ),
        ReservationHygieneState::DegradedMail if backend_degraded => format!(
            "Keep Beads-visible coordination, retry normal Agent Mail release after repair, and treat {active_count} active leases as protected; force-release only with explicit human approval."
        ),
        ReservationHygieneState::DegradedMail => {
            "Retry Agent Mail reservation probe before changing lease state; force-release only with explicit human approval.".to_string()
        }
        ReservationHygieneState::Unknown => {
            "Retry Agent Mail reservation probe and keep Beads-visible handoff until reservation ownership is known.".to_string()
        }
    }
}

fn render_reservation_hygiene_beads_comment(
    state: ReservationHygieneState,
    backend_degraded: bool,
    active_count: u32,
    stale_count: u32,
    expired_count: u32,
    reservations: &[AgentMailReservationLease],
    safe_next_action: &str,
) -> String {
    let mut lines = vec![
        format!("reservation_hygiene={}", state.as_str()),
        format!("active_reservations={active_count}"),
        format!("stale_reservations={stale_count}"),
        format!("expired_reservations={expired_count}"),
        format!("backend_degraded={backend_degraded}"),
        "force_release_requires_human=true".to_string(),
    ];
    for reservation in reservations.iter().take(5) {
        lines.push(format!(
            "reservation id={} owner={} path={} expires={} stale={} expired={}",
            reservation.reservation_id,
            reservation.owner,
            reservation.path_pattern,
            reservation.expires_ts.as_deref().unwrap_or("unknown"),
            reservation.stale,
            reservation.expired
        ));
    }
    lines.push(format!("safe_next_action={safe_next_action}"));
    lines.join("; ")
}

fn render_reservation_hygiene_agent_mail_body(
    state: ReservationHygieneState,
    backend_degraded: bool,
    reservations: &[AgentMailReservationLease],
    safe_next_action: &str,
) -> String {
    let mut body = format!(
        "Reservation hygiene: `{}`; backend_degraded={backend_degraded}; force_release_requires_human=true.\n\nSafe next action: {safe_next_action}",
        state.as_str()
    );
    if !reservations.is_empty() {
        body.push_str("\n\nActive reservations:");
        for reservation in reservations.iter().take(5) {
            body.push_str(&format!(
                "\n- id `{}` owner `{}` path `{}` expires `{}` stale={} expired={}",
                reservation.reservation_id,
                reservation.owner,
                reservation.path_pattern,
                reservation.expires_ts.as_deref().unwrap_or("unknown"),
                reservation.stale,
                reservation.expired
            ));
        }
    }
    body
}

fn push_signal(signals: &mut Vec<String>, signal: String) {
    if !signals.iter().any(|existing| existing == &signal) {
        push_bounded(signals, signal, MAX_DOCTOR_DIAGNOSTICS);
    }
}

fn safe_next_action_for_agent_mail(
    health_state: AgentMailHealthState,
    lock_owner_pid: Option<u32>,
    lock_owner_command: Option<&str>,
    next_action: Option<&str>,
) -> String {
    if let Some(pid) = lock_owner_pid {
        let command = lock_owner_command.unwrap_or("unknown command");
        return format!(
            "Wait for Agent Mail lock owner pid {pid} ({command}) or ask the human before interrupting it; then run `am doctor repair --dry-run`."
        );
    }

    match health_state {
        AgentMailHealthState::Healthy => "No Agent Mail coordination action required.".to_string(),
        AgentMailHealthState::LockOwnerActive => {
            "Wait for the Agent Mail lock owner or ask the human before interrupting it; then run `am doctor repair --dry-run`.".to_string()
        }
        AgentMailHealthState::ArchiveAheadIndex
        | AgentMailHealthState::DegradedReadOnly
        | AgentMailHealthState::RepairRecommended => next_action
            .map(|action| format!("Run `{action}` in dry-run/review mode first; keep Beads-visible handoff until Agent Mail is healthy."))
            .unwrap_or_else(|| {
                "Run `am doctor repair --dry-run` and keep Beads-visible handoff until Agent Mail is healthy.".to_string()
            }),
        AgentMailHealthState::Unavailable | AgentMailHealthState::Unknown => {
            "Use Beads-visible coordination and retry Agent Mail health before relying on mailbox state.".to_string()
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "diagnostic detail intentionally lists every optional Agent Mail probe field"
)]
fn format_agent_mail_detail(
    health_state: AgentMailHealthState,
    signals: &[String],
    archive_message_count: Option<u64>,
    index_message_count: Option<u64>,
    archive_agent_count: Option<u64>,
    index_agent_count: Option<u64>,
    lock_owner_pid: Option<u32>,
    lock_owner_command: Option<&str>,
    reservation_hygiene: &ReservationHygieneSummary,
) -> String {
    let mut parts = vec![format!("health_state={}", health_state.as_str())];
    if !signals.is_empty() {
        parts.push(format!("signals={}", signals.join(",")));
    }
    if let Some(count) = archive_message_count {
        parts.push(format!("archive_messages={count}"));
    }
    if let Some(count) = index_message_count {
        parts.push(format!("index_messages={count}"));
    }
    if let Some(count) = archive_agent_count {
        parts.push(format!("archive_agents={count}"));
    }
    if let Some(count) = index_agent_count {
        parts.push(format!("index_agents={count}"));
    }
    if let Some(pid) = lock_owner_pid {
        parts.push(format!("lock_owner_pid={pid}"));
    }
    if let Some(command) = lock_owner_command {
        parts.push(format!("lock_owner_command={command}"));
    }
    if reservation_hygiene.has_reportable_details() {
        parts.push(reservation_hygiene.diagnostic_reason());
    }
    parts.join("; ")
}

/// RCH worker status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RchStatus {
    /// Whether RCH is available.
    pub available: bool,
    /// Number of available worker slots (if known).
    pub available_slots: Option<u32>,
    /// Human-readable status description.
    pub status_desc: String,
}

/// Recommended action for operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    /// Action priority: "high", "medium", "low".
    pub priority: String,
    /// Short action description.
    pub action: String,
    /// Detailed explanation and rationale.
    pub explanation: String,
    /// Command to run (if applicable).
    pub command: Option<String>,
    /// Expected impact description.
    pub impact: String,
}

/// Complete doctor output for workspace pressure status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorOutput {
    /// Schema version for compatibility.
    pub schema_version: String,
    /// Timestamp when this report was generated.
    pub timestamp: DateTime<Utc>,
    /// Overall workspace health status.
    pub status: DoctorStatus,
    /// One-line summary of workspace state.
    pub summary: String,
    /// Resource utilization summary.
    pub resources: ResourceSummary,
    /// Policy decisions for different work classes.
    pub policy_decisions: BTreeMap<String, PolicyDecisionSummary>,
    /// Recommended actions for operator.
    pub recommended_actions: Vec<RecommendedAction>,
    /// Detailed diagnostic messages.
    pub diagnostics: Vec<String>,
    /// Machine-readable metadata.
    pub metadata: BTreeMap<String, String>,
}

/// Summary of policy decision for a work class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionSummary {
    /// Work class name.
    pub work_class: String,
    /// Current admission decision.
    pub admission: String,
    /// Reason for the decision.
    pub reason_code: String,
    /// Human-readable summary.
    pub summary: String,
    /// Decision confidence (0.0-1.0).
    pub confidence: f32,
    /// Number of cleanup candidates available.
    pub cleanup_candidates_count: usize,
}

/// Workspace pressure doctor for generating operator reports.
#[derive(Debug, Clone)]
pub struct WorkspacePressureDoctor {
    /// Policy engine for admission decisions.
    policy: WorkspacePressurePolicy,
}

impl WorkspacePressureDoctor {
    /// Create new doctor with balanced policy thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: WorkspacePressurePolicy::with_balanced_defaults(),
        }
    }

    /// Create new doctor with custom policy thresholds.
    #[must_use]
    pub fn with_thresholds(thresholds: PolicyThresholds) -> Self {
        Self {
            policy: WorkspacePressurePolicy::new(thresholds),
        }
    }

    /// Generate complete doctor report for current workspace state.
    pub fn generate_report(&self, inputs: &WorkspacePressureInputs) -> DoctorOutput {
        self.generate_report_with_agent_mail_coordination(
            inputs,
            AgentMailCoordinationSummary::from_legacy_health(inputs.coordination_healthy),
        )
    }

    /// Generate complete doctor report with structured Agent Mail coordination details.
    pub fn generate_report_with_agent_mail_coordination(
        &self,
        inputs: &WorkspacePressureInputs,
        agent_mail_coordination: AgentMailCoordinationSummary,
    ) -> DoctorOutput {
        let timestamp = Utc::now();
        let mut diagnostics = Vec::new();
        let mut recommended_actions = Vec::new();
        let mut metadata = BTreeMap::new();

        // Generate policy decisions for all work classes
        let work_classes = [
            (WorkCostClass::SourceOnly, 3),
            (WorkCostClass::DocsGate, 3),
            (WorkCostClass::Validation, 2),
            (WorkCostClass::Benchmark, 1),
            (WorkCostClass::Fuzzing, 1),
            (WorkCostClass::Cleanup, 2),
        ];

        let mut policy_decisions = BTreeMap::new();
        let mut has_critical_decisions = false;
        let mut has_degraded_decisions = false;
        let mut total_cleanup_candidates: usize = 0;

        for (work_class, priority) in &work_classes {
            let decision = self.policy.decide_admission(*work_class, *priority, inputs);
            let work_class_str = format!("{:?}", work_class);

            // Check for degraded/critical decisions
            match &decision.admission {
                AdmissionDecision::RefuseLocalFallback => has_critical_decisions = true,
                AdmissionDecision::Queue { .. } | AdmissionDecision::Wait { .. } => {
                    has_degraded_decisions = true;
                }
                _ => {}
            }

            total_cleanup_candidates =
                total_cleanup_candidates.saturating_add(decision.cleanup_candidates.len());

            // Add cleanup recommendations if candidates exist
            if !decision.cleanup_candidates.is_empty() {
                self.add_cleanup_recommendations(
                    &decision,
                    &mut recommended_actions,
                    &work_class_str,
                );
            }

            // Add decision diagnostics
            for diag in &decision.diagnostic_reasons {
                push_bounded(
                    &mut diagnostics,
                    format!("{}: {}", work_class_str, diag),
                    MAX_DOCTOR_DIAGNOSTICS,
                );
            }

            let decision_summary = PolicyDecisionSummary {
                work_class: work_class_str.clone(),
                admission: self.format_admission_decision(&decision.admission),
                reason_code: decision.reason_code,
                summary: decision.summary,
                confidence: decision.confidence,
                cleanup_candidates_count: decision.cleanup_candidates.len(),
            };

            policy_decisions.insert(work_class_str, decision_summary);
        }

        // Generate resource summary
        let resources = self.generate_resource_summary(inputs, agent_mail_coordination);
        if resources
            .agent_mail_coordination
            .reservation_hygiene
            .has_reportable_details()
        {
            push_bounded(
                &mut diagnostics,
                format!(
                    "AgentMailReservations: {}",
                    resources
                        .agent_mail_coordination
                        .reservation_hygiene
                        .diagnostic_reason()
                ),
                MAX_DOCTOR_DIAGNOSTICS,
            );
        }

        // Determine overall status
        let has_coordination_issues = !resources.agent_mail_coordination.healthy
            || !resources
                .agent_mail_coordination
                .reservation_hygiene
                .is_healthy();
        let status = if has_critical_decisions {
            DoctorStatus::Critical
        } else if has_degraded_decisions || inputs.memory_pressure > 0.8 || has_coordination_issues
        {
            DoctorStatus::Degraded
        } else if inputs.memory_pressure > 0.6 || total_cleanup_candidates > 0 {
            DoctorStatus::Warning
        } else {
            DoctorStatus::Healthy
        };

        // Generate summary
        let summary = self.generate_summary(&status, inputs, total_cleanup_candidates);

        // Add resource pressure recommendations
        self.add_resource_recommendations(inputs, &mut recommended_actions);
        self.add_coordination_recommendations(
            &resources.agent_mail_coordination,
            &mut recommended_actions,
        );

        // Populate metadata
        metadata.insert(
            "total_cleanup_candidates".to_string(),
            total_cleanup_candidates.to_string(),
        );
        metadata.insert(
            "policy_decisions_count".to_string(),
            policy_decisions.len().to_string(),
        );
        metadata.insert(
            "rch_available".to_string(),
            inputs.rch_available_slots.is_some().to_string(),
        );

        DoctorOutput {
            schema_version: DOCTOR_OUTPUT_SCHEMA_VERSION.to_string(),
            timestamp,
            status,
            summary,
            resources,
            policy_decisions,
            recommended_actions,
            diagnostics,
            metadata,
        }
    }

    /// Generate human-readable report text from doctor output.
    pub fn format_human_report(&self, output: &DoctorOutput) -> String {
        let mut report = String::new();

        // Header
        report.push_str(&format!(
            "{} Workspace Pressure Report ({})\n",
            output.status.emoji(),
            output.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        report.push_str(&format!(
            "Status: {} - {}\n\n",
            output.status.as_str(),
            output.summary
        ));

        // Resource summary
        report.push_str("📊 Resource Summary:\n");
        report.push_str(&format!(
            "  • Free Disk: {}\n",
            output.resources.free_disk_human
        ));
        report.push_str(&format!(
            "  • Target Dir: {}\n",
            output.resources.target_dir_human
        ));
        report.push_str(&format!(
            "  • Active Builds: {}\n",
            output.resources.active_builds
        ));
        report.push_str(&format!(
            "  • Memory Pressure: {:.1}%\n",
            output.resources.memory_pressure * 100.0
        ));
        report.push_str(&format!(
            "  • RCH Status: {}\n",
            output.resources.rch_status.status_desc
        ));
        report.push_str(&format!(
            "  • File Reservations: {}\n",
            output.resources.active_reservations
        ));
        report.push_str(&format!(
            "  • Coordination: {} ({})\n",
            if output.resources.coordination_healthy {
                "Healthy"
            } else {
                "Degraded"
            },
            output
                .resources
                .agent_mail_coordination
                .health_state
                .as_str()
        ));
        report.push_str(&format!(
            "  • Coordination Action: {}\n\n",
            output.resources.agent_mail_coordination.safe_next_action
        ));
        let reservation_hygiene = &output.resources.agent_mail_coordination.reservation_hygiene;
        report.push_str(&format!(
            "  • Reservation Hygiene: {} (active={}, stale={}, expired={}, mail_degraded={})\n",
            reservation_hygiene.state.as_str(),
            reservation_hygiene.active_count,
            reservation_hygiene.stale_count,
            reservation_hygiene.expired_count,
            reservation_hygiene.backend_degraded
        ));
        for reservation in reservation_hygiene.reservations.iter().take(5) {
            report.push_str(&format!(
                "    └─ id={} owner={} path={} expires={} stale={} expired={}\n",
                reservation.reservation_id,
                reservation.owner,
                reservation.path_pattern,
                reservation.expires_ts.as_deref().unwrap_or("unknown"),
                reservation.stale,
                reservation.expired
            ));
        }
        report.push_str(&format!(
            "  • Reservation Action: {}\n\n",
            reservation_hygiene.safe_next_action
        ));

        // Policy decisions
        if !output.policy_decisions.is_empty() {
            report.push_str("🎯 Policy Decisions:\n");
            for decision in output.policy_decisions.values() {
                let confidence_emoji = if decision.confidence >= 0.9 {
                    "🟢"
                } else if decision.confidence >= 0.7 {
                    "🟡"
                } else {
                    "🔴"
                };
                report.push_str(&format!(
                    "  • {}: {} {} (confidence: {:.0}%)\n",
                    decision.work_class,
                    decision.admission,
                    confidence_emoji,
                    decision.confidence * 100.0
                ));
                if decision.cleanup_candidates_count > 0 {
                    report.push_str(&format!(
                        "    └─ {} cleanup candidates available\n",
                        decision.cleanup_candidates_count
                    ));
                }
            }
            report.push('\n');
        }

        // Recommended actions
        if !output.recommended_actions.is_empty() {
            report.push_str("🔧 Recommended Actions:\n");
            for action in &output.recommended_actions {
                let priority_emoji = match action.priority.as_str() {
                    "high" => "🔴",
                    "medium" => "🟡",
                    "low" => "🟢",
                    _ => "⚪",
                };
                report.push_str(&format!("  {} {}\n", priority_emoji, action.action));
                report.push_str(&format!("    └─ {}\n", action.explanation));
                if let Some(command) = &action.command {
                    report.push_str(&format!("    └─ Run: {}\n", command));
                }
            }
            report.push('\n');
        }

        // Diagnostics (if any significant ones)
        if !output.diagnostics.is_empty() && output.status != DoctorStatus::Healthy {
            report.push_str("🔍 Diagnostics:\n");
            for (i, diag) in output.diagnostics.iter().enumerate() {
                if i >= 5 {
                    // Limit to top 5 for human readability
                    report.push_str(&format!(
                        "  ... and {} more\n",
                        output.diagnostics.len() - 5
                    ));
                    break;
                }
                report.push_str(&format!("  • {}\n", diag));
            }
            report.push('\n');
        }

        report.push_str(&format!(
            "Generated at {} with {} schema\n",
            output.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            output.schema_version
        ));

        report
    }

    fn generate_resource_summary(
        &self,
        inputs: &WorkspacePressureInputs,
        agent_mail_coordination: AgentMailCoordinationSummary,
    ) -> ResourceSummary {
        let rch_status = if let Some(slots) = inputs.rch_available_slots {
            RchStatus {
                available: true,
                available_slots: Some(slots),
                status_desc: if slots == 0 {
                    "Available (saturated)".to_string()
                } else {
                    format!("Available ({} slots)", slots)
                },
            }
        } else {
            RchStatus {
                available: false,
                available_slots: None,
                status_desc: "Unavailable".to_string(),
            }
        };

        ResourceSummary {
            free_disk_bytes: inputs.free_disk_bytes,
            free_disk_human: format_bytes(inputs.free_disk_bytes),
            target_dir_bytes: inputs.target_dir_bytes,
            target_dir_human: format_bytes(inputs.target_dir_bytes),
            active_builds: inputs.active_build_count,
            memory_pressure: inputs.memory_pressure,
            rch_status,
            active_reservations: inputs.active_reservations,
            coordination_healthy: inputs.coordination_healthy,
            agent_mail_coordination,
        }
    }

    fn generate_summary(
        &self,
        status: &DoctorStatus,
        inputs: &WorkspacePressureInputs,
        cleanup_candidates: usize,
    ) -> String {
        match status {
            DoctorStatus::Healthy => {
                "Workspace pressure is low, all systems operating normally".to_string()
            }
            DoctorStatus::Warning => {
                if cleanup_candidates > 0 {
                    format!(
                        "Minor resource pressure detected, {} cleanup opportunities available",
                        cleanup_candidates
                    )
                } else {
                    "Minor resource pressure detected, monitoring recommended".to_string()
                }
            }
            DoctorStatus::Degraded => {
                format!(
                    "Significant workspace pressure: {:.0}% memory, {} active builds",
                    inputs.memory_pressure * 100.0,
                    inputs.active_build_count
                )
            }
            DoctorStatus::Critical => {
                if inputs.free_disk_bytes < 100_000_000 {
                    // < 100MB
                    "Critical disk pressure detected, immediate cleanup required".to_string()
                } else {
                    "Critical workspace pressure, blocking high-cost operations".to_string()
                }
            }
        }
    }

    fn format_admission_decision(&self, admission: &AdmissionDecision) -> String {
        match admission {
            AdmissionDecision::AllowLocal => "ALLOW_LOCAL".to_string(),
            AdmissionDecision::RequireRch => "REQUIRE_RCH".to_string(),
            AdmissionDecision::Queue { retry_after_ms } => {
                format!("QUEUE (retry in {}ms)", retry_after_ms)
            }
            AdmissionDecision::Wait { retry_after_ms } => {
                format!("WAIT (retry in {}ms)", retry_after_ms)
            }
            AdmissionDecision::RefuseLocalFallback => "REFUSE_LOCAL_FALLBACK".to_string(),
        }
    }

    fn add_cleanup_recommendations(
        &self,
        decision: &PolicyDecision,
        recommendations: &mut Vec<RecommendedAction>,
        work_class: &str,
    ) {
        if decision.cleanup_candidates.is_empty() {
            return;
        }

        let total_size: u64 = decision
            .cleanup_candidates
            .iter()
            .map(|c| c.size_bytes)
            .sum();
        let priority = if total_size > 1_000_000_000 {
            // > 1GB
            "high"
        } else if total_size > 100_000_000 {
            // > 100MB
            "medium"
        } else {
            "low"
        };

        let action = RecommendedAction {
            priority: priority.to_string(),
            action: format!(
                "Clean up {} targets for {}",
                decision.cleanup_candidates.len(),
                work_class
            ),
            explanation: format!(
                "Review {} of approved cleanup candidates through the audited cleanup executor ({})",
                format_bytes(total_size),
                decision.cleanup_candidates[0].reason
            ),
            command: None,
            impact: format!(
                "Potentially free {} of disk space after explicit approved cleanup mode",
                format_bytes(total_size)
            ),
        };

        push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
    }

    fn add_resource_recommendations(
        &self,
        inputs: &WorkspacePressureInputs,
        recommendations: &mut Vec<RecommendedAction>,
    ) {
        // Memory pressure recommendations
        if inputs.memory_pressure > 0.9 {
            let action = RecommendedAction {
                priority: "high".to_string(),
                action: "Reduce memory pressure".to_string(),
                explanation: format!(
                    "Memory usage at {:.0}%, close to exhaustion",
                    inputs.memory_pressure * 100.0
                ),
                command: Some("killall -TERM cargo rustc".to_string()),
                impact: "Prevent OOM kills and system instability".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        } else if inputs.memory_pressure > 0.8 {
            let action = RecommendedAction {
                priority: "medium".to_string(),
                action: "Monitor memory usage".to_string(),
                explanation: format!(
                    "Memory usage at {:.0}%, approaching limits",
                    inputs.memory_pressure * 100.0
                ),
                command: Some("free -h && ps aux --sort=-%mem | head -10".to_string()),
                impact: "Prevent memory exhaustion".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }

        // Build pressure recommendations
        if inputs.active_build_count > 8 {
            let action = RecommendedAction {
                priority: "medium".to_string(),
                action: "Reduce concurrent builds".to_string(),
                explanation: format!(
                    "{} active builds detected, may cause resource contention",
                    inputs.active_build_count
                ),
                command: Some("pgrep -f 'cargo|rustc' | wc -l".to_string()),
                impact: "Improve build performance and reduce system load".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }

        // RCH recommendations
        if inputs.rch_available_slots.is_none() {
            let action = RecommendedAction {
                priority: "low".to_string(),
                action: "Check RCH availability".to_string(),
                explanation: "RCH workers unavailable, falling back to local builds".to_string(),
                command: Some("rch status".to_string()),
                impact: "Enable build offloading to reduce local resource usage".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }

        // Coordination health recommendations
        if !inputs.coordination_healthy {
            let action = RecommendedAction {
                priority: "medium".to_string(),
                action: "Check Agent Mail coordination".to_string(),
                explanation: "Agent coordination health degraded, may affect file reservations"
                    .to_string(),
                command: None,
                impact: "Restore reliable inter-agent coordination".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }
    }

    fn add_coordination_recommendations(
        &self,
        coordination: &AgentMailCoordinationSummary,
        recommendations: &mut Vec<RecommendedAction>,
    ) {
        if !coordination.reservation_hygiene.is_healthy() {
            let action = RecommendedAction {
                priority: "medium".to_string(),
                action: "Review Agent Mail reservations".to_string(),
                explanation: coordination.reservation_hygiene.safe_next_action.clone(),
                command: None,
                impact: "Avoid conflicting edits while preserving human-approved escalation for stale leases.".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }
    }
}

impl Default for WorkspacePressureDoctor {
    fn default() -> Self {
        Self::new()
    }
}

/// Format byte count as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx = unit_idx.saturating_add(1);
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}

/// Generate doctor report from workspace inputs and write to JSON file.
pub fn generate_doctor_report_file(
    inputs: &WorkspacePressureInputs,
    output_path: &Path,
) -> Result<DoctorOutput, Box<dyn std::error::Error>> {
    let doctor = WorkspacePressureDoctor::new();
    let output = doctor.generate_report(inputs);

    let json = serde_json::to_string_pretty(&output)?;
    fs::write(output_path, json)?;

    Ok(output)
}

/// Generate human-readable doctor report and write to text file.
pub fn generate_human_report_file(
    inputs: &WorkspacePressureInputs,
    output_path: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let doctor = WorkspacePressureDoctor::new();
    let output = doctor.generate_report(inputs);
    let human_report = doctor.format_human_report(&output);

    fs::write(output_path, &human_report)?;

    Ok(human_report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_doctor_status_formatting() {
        assert_eq!(DoctorStatus::Healthy.as_str(), "HEALTHY");
        assert_eq!(DoctorStatus::Warning.as_str(), "WARNING");
        assert_eq!(DoctorStatus::Degraded.as_str(), "DEGRADED");
        assert_eq!(DoctorStatus::Critical.as_str(), "CRITICAL");
    }

    #[test]
    fn test_doctor_output_healthy_scenario() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 10_000_000_000, // 10GB
            target_dir_bytes: 1_000_000_000, // 1GB
            active_build_count: 1,
            rch_available_slots: Some(4),
            memory_pressure: 0.3,
            active_reservations: 5,
            coordination_healthy: true,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        assert_eq!(output.status, DoctorStatus::Healthy);
        assert!(output.summary.contains("low"));
        assert_eq!(output.resources.active_builds, 1);
        assert_eq!(output.policy_decisions.len(), 6);
    }

    #[test]
    fn test_doctor_output_critical_scenario() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 50_000_000,     // 50MB - critical
            target_dir_bytes: 5_000_000_000, // 5GB
            active_build_count: 10,
            rch_available_slots: None,
            memory_pressure: 0.95,
            active_reservations: 50,
            coordination_healthy: false,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        assert_eq!(output.status, DoctorStatus::Critical);
        assert!(output.summary.contains("Critical"));
        assert!(!output.recommended_actions.is_empty());
        assert!(
            output
                .recommended_actions
                .iter()
                .any(|a| a.priority == "high")
        );
    }

    #[test]
    fn test_cleanup_recommendations_do_not_emit_destructive_shell_commands() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 50_000_000,      // 50MB - critical
            target_dir_bytes: 15_000_000_000, // 15GB
            active_build_count: 3,
            rch_available_slots: Some(2),
            memory_pressure: 0.7,
            active_reservations: 10,
            coordination_healthy: true,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);
        let human_report = doctor.format_human_report(&output);

        assert!(!output.recommended_actions.is_empty());
        for action in &output.recommended_actions {
            if let Some(command) = &action.command {
                assert!(!command.contains("rm -rf"));
                assert!(!command.contains("git clean"));
                assert!(!command.contains("git reset"));
            }
        }
        assert!(!human_report.contains("rm -rf"));
        assert!(!human_report.contains("git clean"));
        assert!(!human_report.contains("git reset"));
        assert!(
            output.recommended_actions.iter().any(|action| {
                action.action.starts_with("Clean up") && action.command.is_none()
            })
        );
    }

    #[test]
    fn test_human_report_formatting() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 2_000_000_000,  // 2GB
            target_dir_bytes: 3_000_000_000, // 3GB
            active_build_count: 3,
            rch_available_slots: Some(2),
            memory_pressure: 0.6,
            active_reservations: 10,
            coordination_healthy: true,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);
        let human_report = doctor.format_human_report(&output);

        assert!(human_report.contains("Workspace Pressure Report"));
        assert!(human_report.contains("📊 Resource Summary"));
        assert!(human_report.contains("🎯 Policy Decisions"));
        assert!(human_report.contains("2.0 GB")); // Free disk formatting
        assert!(human_report.contains("3.0 GB")); // Target dir formatting
        assert!(human_report.contains("60.0%")); // Memory pressure
    }

    #[test]
    fn agent_mail_summary_detects_archive_ahead_index_and_lock_owner() {
        let payload = serde_json::json!({
            "status": "error",
            "recovery_mode": "degraded_read_only",
            "next_action": "am doctor repair",
            "archive_inventory": {
                "messages": 17_017_u64,
                "agents": 1_760_u64
            },
            "database_inventory": {
                "messages": 0_u64,
                "agents": 0_u64
            },
            "lock_owner": {
                "pid": 4_134_220_u64,
                "command": "am"
            }
        });

        let summary = AgentMailCoordinationSummary::from_health_payload(&payload);

        assert!(!summary.healthy);
        assert_eq!(summary.health_state, AgentMailHealthState::LockOwnerActive);
        assert!(
            summary
                .signals
                .iter()
                .any(|signal| signal == "archive_ahead_index")
        );
        assert!(
            summary
                .signals
                .iter()
                .any(|signal| signal == "lock_owner_active")
        );
        assert!(
            summary
                .signals
                .iter()
                .any(|signal| signal == "repair_recommended")
        );
        assert_eq!(summary.archive_message_count, Some(17_017));
        assert_eq!(summary.index_message_count, Some(0));
        assert_eq!(summary.archive_agent_count, Some(1_760));
        assert_eq!(summary.index_agent_count, Some(0));
        assert_eq!(summary.lock_owner_pid, Some(4_134_220));
        assert_eq!(summary.lock_owner_command.as_deref(), Some("am"));
        assert!(summary.repair_recommended);
        assert!(
            summary
                .safe_next_action
                .contains("am doctor repair --dry-run")
        );
        assert!(summary.detail.contains("archive_messages=17017"));
        assert!(summary.detail.contains("index_messages=0"));
    }

    #[test]
    fn doctor_report_exposes_agent_mail_coordination_contract() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 2_000_000_000,
            target_dir_bytes: 3_000_000_000,
            active_build_count: 2,
            rch_available_slots: Some(4),
            memory_pressure: 0.4,
            active_reservations: 2,
            coordination_healthy: false,
        };
        let agent_mail_coordination =
            AgentMailCoordinationSummary::from_health_payload(&serde_json::json!({
                "status": "error",
                "recovery_mode": "degraded_read_only",
                "archive_inventory": {"messages": 9_u64, "agents": 3_u64},
                "database_inventory": {"messages": 1_u64, "agents": 1_u64},
                "next_action": "am doctor repair"
            }));

        let doctor = WorkspacePressureDoctor::new();
        let output =
            doctor.generate_report_with_agent_mail_coordination(&inputs, agent_mail_coordination);
        let json = serde_json::to_value(&output).expect("doctor report serializes");
        let human = doctor.format_human_report(&output);

        assert_eq!(
            json["resources"]["agent_mail_coordination"]["health_state"],
            "archive_ahead_index"
        );
        assert_eq!(
            json["resources"]["agent_mail_coordination"]["archive_message_count"],
            9
        );
        assert_eq!(
            json["resources"]["agent_mail_coordination"]["index_message_count"],
            1
        );
        assert!(
            json["resources"]["agent_mail_coordination"]["safe_next_action"]
                .as_str()
                .is_some_and(|action| action.contains("am doctor repair"))
        );
        assert!(human.contains("Coordination: Degraded (archive_ahead_index)"));
        assert!(human.contains("Coordination Action:"));
    }
}
