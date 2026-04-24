//! Rollout-state persistence for connector instances.
//!
//! Persists the combination of lifecycle state, health gate results,
//! rollout phase, and activation timestamp to a durable JSON file.
//! Supports versioned writes for conflict detection and deterministic
//! recovery replay.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::control_plane::control_epoch::{
    ControlEpoch, EpochArtifactEvent, EpochRejection, EpochRejectionReason, ValidityWindowPolicy,
    check_artifact_epoch,
};

use super::cancellation_protocol::CancellationPhase;
use super::health_gate::HealthGateResult;
use super::lifecycle::ConnectorState;
use super::obligation_tracker::{ObligationFlow, ObligationTracker};

/// Stable event codes for epoch-scoped validity checks.
pub mod epoch_event_codes {
    pub const EPOCH_CHECK_PASSED: &str = "EPV-001";
    pub const FUTURE_EPOCH_REJECTED: &str = "EPV-002";
    pub const STALE_EPOCH_REJECTED: &str = "EPV-003";
    pub const EPOCH_SCOPE_LOGGED: &str = "EPV-004";
}

const RESERVED_CONNECTOR_ID: &str = "<unknown>";
const ROLLOUT_PERSIST_TRACE_ID: &str = "rollout-state-persist";

fn invalid_connector_id_reason(connector_id: &str) -> Option<String> {
    let trimmed = connector_id.trim();
    if trimmed.is_empty() {
        return Some("connector_id must not be empty".to_string());
    }
    if trimmed == RESERVED_CONNECTOR_ID {
        return Some(format!("connector_id is reserved: {:?}", connector_id));
    }
    if trimmed != connector_id {
        return Some("connector_id contains leading or trailing whitespace".to_string());
    }
    None
}

/// Rollout phases for gradual traffic migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    Shadow,
    Canary,
    Ramp,
    Default,
}

impl RolloutPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Canary => "canary",
            Self::Ramp => "ramp",
            Self::Default => "default",
        }
    }
}

impl fmt::Display for RolloutPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The complete rollout state for a connector instance.
/// bd-1cs7: includes optional cancellation record for three-phase protocol tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutState {
    pub connector_id: String,
    #[serde(default = "default_rollout_epoch")]
    pub rollout_epoch: ControlEpoch,
    pub lifecycle_state: ConnectorState,
    pub health: HealthGateResult,
    pub rollout_phase: RolloutPhase,
    pub activated_at: Option<String>,
    pub persisted_at: String,
    pub version: u32,
    /// bd-1cs7: cancellation phase tracking for the three-phase protocol.
    #[serde(default)]
    pub cancel_phase: Option<CancellationPhase>,
}

impl RolloutState {
    /// Create a new rollout state at version 1.
    pub fn new(
        connector_id: String,
        lifecycle_state: ConnectorState,
        health: HealthGateResult,
        rollout_phase: RolloutPhase,
    ) -> Self {
        Self::new_with_epoch(
            connector_id,
            ControlEpoch::GENESIS,
            lifecycle_state,
            health,
            rollout_phase,
        )
    }

    /// Create a new rollout state with an explicit epoch stamp.
    pub fn new_with_epoch(
        connector_id: String,
        rollout_epoch: ControlEpoch,
        lifecycle_state: ConnectorState,
        health: HealthGateResult,
        rollout_phase: RolloutPhase,
    ) -> Self {
        Self {
            connector_id,
            rollout_epoch,
            lifecycle_state,
            health,
            rollout_phase,
            activated_at: None,
            persisted_at: now_iso8601(),
            version: 1,
            cancel_phase: None,
        }
    }

    /// bd-1cs7: Set the cancellation phase for three-phase protocol tracking.
    pub fn set_cancel_phase(&mut self, phase: CancellationPhase) {
        self.cancel_phase = Some(phase);
        self.bump_version();
    }

    /// bd-1cs7: Clear the cancellation phase (e.g., after finalization).
    pub fn clear_cancel_phase(&mut self) {
        self.cancel_phase = None;
        self.bump_version();
    }

    /// bd-1cs7: Check if cancellation is active.
    pub fn is_cancelling(&self) -> bool {
        matches!(
            self.cancel_phase,
            Some(CancellationPhase::Requested)
                | Some(CancellationPhase::Draining)
                | Some(CancellationPhase::Finalizing)
        )
    }

    /// Advance the version and update the persistence timestamp.
    pub fn bump_version(&mut self) {
        self.version = self.version.saturating_add(1);
        self.persisted_at = now_iso8601();
    }
}

fn default_rollout_epoch() -> ControlEpoch {
    ControlEpoch::GENESIS
}

/// Errors from rollout-state persistence operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum PersistError {
    #[serde(rename = "PERSIST_STALE_VERSION")]
    StaleVersion {
        current_version: u32,
        attempted_version: u32,
    },
    #[serde(rename = "PERSIST_IO_ERROR")]
    IoError { message: String },
    #[serde(rename = "REPLAY_MISMATCH")]
    ReplayMismatch {
        field: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for PersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleVersion {
                current_version,
                attempted_version,
            } => write!(
                f,
                "PERSIST_STALE_VERSION: attempted version {attempted_version} \
                 but current is {current_version}"
            ),
            Self::IoError { message } => write!(f, "PERSIST_IO_ERROR: {message}"),
            Self::ReplayMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "REPLAY_MISMATCH: field '{field}' expected '{expected}', got '{actual}'"
            ),
        }
    }
}

impl std::error::Error for PersistError {}

/// Structured epoch-scope log for accepted high-impact operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScopeLog {
    pub event_code: String,
    pub artifact_type: String,
    pub artifact_id: String,
    pub artifact_epoch: ControlEpoch,
    pub current_epoch: ControlEpoch,
    pub trace_id: String,
}

impl EpochScopeLog {
    fn for_rollout_plan(
        artifact_id: &str,
        artifact_epoch: ControlEpoch,
        current_epoch: ControlEpoch,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: epoch_event_codes::EPOCH_SCOPE_LOGGED.to_string(),
            artifact_type: "rollout_plan".to_string(),
            artifact_id: artifact_id.to_string(),
            artifact_epoch,
            current_epoch,
            trace_id: trace_id.to_string(),
        }
    }
}

/// Epoch-scoped persistence result for rollout plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScopedPersistResult {
    pub epoch_check_event_code: String,
    pub epoch_event: EpochArtifactEvent,
    pub scope_log: EpochScopeLog,
}

/// Error type for epoch-scoped rollout persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum EpochPersistError {
    #[serde(rename = "EPV-002")]
    FutureEpochRejected { rejection: EpochRejection },
    #[serde(rename = "EPV-003")]
    StaleEpochRejected { rejection: EpochRejection },
    #[serde(rename = "EPV-006")]
    InvalidArtifactId { rejection: EpochRejection },
    #[serde(rename = "EPV-005")]
    InvalidConnectorId { reason: String },
    #[serde(rename = "PERSIST_ERROR")]
    Persist { source: PersistError },
}

impl EpochPersistError {
    fn from_rejection(rejection: EpochRejection) -> Self {
        match rejection.rejection_reason {
            EpochRejectionReason::InvalidArtifactId => Self::InvalidArtifactId { rejection },
            EpochRejectionReason::FutureEpoch => Self::FutureEpochRejected { rejection },
            EpochRejectionReason::ExpiredEpoch => Self::StaleEpochRejected { rejection },
        }
    }
}

impl fmt::Display for EpochPersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConnectorId { reason } => {
                write!(f, "EPV_INVALID_CONNECTOR_ID: {reason}")
            }
            Self::FutureEpochRejected { rejection }
            | Self::StaleEpochRejected { rejection }
            | Self::InvalidArtifactId { rejection } => {
                let reason = match rejection.rejection_reason {
                    EpochRejectionReason::InvalidArtifactId => "invalid_artifact_id",
                    EpochRejectionReason::FutureEpoch => "future_epoch",
                    EpochRejectionReason::ExpiredEpoch => "expired_epoch",
                };
                write!(
                    f,
                    "{}: artifact={} artifact_epoch={} current_epoch={} reason={}",
                    rejection.code(),
                    rejection.artifact_id,
                    rejection.artifact_epoch.value(),
                    rejection.current_epoch.value(),
                    reason
                )
            }
            Self::Persist { source } => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for EpochPersistError {}

/// Persist rollout state after canonical epoch-window validation.
pub fn persist_epoch_scoped(
    state: &RolloutState,
    path: &Path,
    validity_policy: &ValidityWindowPolicy,
    trace_id: &str,
) -> Result<EpochScopedPersistResult, EpochPersistError> {
    if let Some(reason) = invalid_connector_id_reason(&state.connector_id) {
        return Err(EpochPersistError::InvalidConnectorId { reason });
    }
    let artifact_id = format!("rollout-plan:{}", state.connector_id);
    check_artifact_epoch(&artifact_id, state.rollout_epoch, validity_policy, trace_id)
        .map_err(EpochPersistError::from_rejection)?;

    persist(state, path).map_err(|source| EpochPersistError::Persist { source })?;

    let current_epoch = validity_policy.current_epoch();
    Ok(EpochScopedPersistResult {
        epoch_check_event_code: epoch_event_codes::EPOCH_CHECK_PASSED.to_string(),
        epoch_event: EpochArtifactEvent::accepted(
            &artifact_id,
            state.rollout_epoch,
            current_epoch,
            trace_id,
        ),
        scope_log: EpochScopeLog::for_rollout_plan(
            &artifact_id,
            state.rollout_epoch,
            current_epoch,
            trace_id,
        ),
    })
}

/// Serialize concurrent persist() calls to prevent TOCTOU races on the version check.
fn persist_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Shared obligation tracker for the legacy `persist()` entrypoint.
fn rollout_obligation_tracker() -> &'static Mutex<ObligationTracker> {
    static TRACKER: OnceLock<Mutex<ObligationTracker>> = OnceLock::new();
    TRACKER.get_or_init(|| Mutex::new(ObligationTracker::new()))
}

/// RAII guard that orphans a temp file on drop (unless defused after rename).
#[must_use]
struct TempFileGuard(Option<PathBuf>);

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn abandoned_path(path: &Path) -> PathBuf {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("rollout-state.json.tmp");
        path.with_file_name(format!("{file_name}.orphaned-{}", uuid::Uuid::now_v7()))
    }

    fn defuse(&mut self) {
        self.0 = None;
    }

    fn orphan_with(
        mut self,
        rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    ) -> Result<(), PersistError> {
        let Some(path) = self.0.take() else {
            return Ok(());
        };
        Self::orphan_path_with(&path, rename)
    }

    fn orphan_path_with(
        path: &Path,
        rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    ) -> Result<(), PersistError> {
        if !path.is_file() {
            return Ok(());
        }

        let abandoned_path = Self::abandoned_path(path);
        rename(path, &abandoned_path).map_err(|error| PersistError::IoError {
            message: format!(
                "failed to orphan rollout temp file {} to {}: {error}",
                path.display(),
                abandoned_path.display()
            ),
        })
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && path.is_file()
        {
            if let Err(error) = Self::orphan_path_with(&path, |from, to| std::fs::rename(from, to))
            {
                tracing::warn!(
                    error = %error,
                    path = %path.display(),
                    "failed to orphan abandoned rollout temp file"
                );
            }
        }
    }
}

/// Save rollout state to a JSON file atomically.
///
/// If a file already exists at `path`, the version in it must be less than
/// the version in `state`, otherwise `StaleVersion` is returned.
pub fn persist(state: &RolloutState, path: &Path) -> Result<(), PersistError> {
    let mut tracker = rollout_obligation_tracker()
        .lock()
        .map_err(|_| PersistError::IoError {
            message: "rollout obligation tracker lock poisoned".to_string(),
        })?;
    persist_with_obligation_tracker(state, path, &mut tracker, ROLLOUT_PERSIST_TRACE_ID)
}

fn persist_with_obligation_tracker(
    state: &RolloutState,
    path: &Path,
    tracker: &mut ObligationTracker,
    trace_id: &str,
) -> Result<(), PersistError> {
    persist_with_obligation_tracker_and_rename(state, path, tracker, trace_id, |from, to| {
        std::fs::rename(from, to)
    })
}

fn persist_with_obligation_tracker_and_rename(
    state: &RolloutState,
    path: &Path,
    tracker: &mut ObligationTracker,
    trace_id: &str,
    rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), PersistError> {
    persist_with_obligation_tracker_and_rename_and_orphan(
        state,
        path,
        tracker,
        trace_id,
        rename,
        |from, to| std::fs::rename(from, to),
    )
}

fn persist_with_obligation_tracker_and_rename_and_orphan(
    state: &RolloutState,
    path: &Path,
    tracker: &mut ObligationTracker,
    trace_id: &str,
    rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    orphan_rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), PersistError> {
    let _guard = persist_lock().lock().map_err(|_| PersistError::IoError {
        message: "persist lock poisoned".to_string(),
    })?;

    // Check for stale version if file exists
    if path.exists() {
        let existing = load(path)?;
        if existing.version >= state.version {
            return Err(PersistError::StaleVersion {
                current_version: existing.version,
                attempted_version: state.version,
            });
        }
    }

    let json = serde_json::to_string_pretty(state).map_err(|e| PersistError::IoError {
        message: e.to_string(),
    })?;
    let now_ms = now_unix_ms();
    let obligation_payload = rollout_obligation_payload(state, path)?;
    let obligation_guard = tracker
        .reserve_guard(
            ObligationFlow::Migration,
            obligation_payload,
            now_ms,
            trace_id,
        )
        .map_err(|message| PersistError::IoError { message })?;

    // Write to temp file then rename for atomicity (UUID suffix avoids collisions).
    // TempFileGuard ensures cleanup on rename failure.
    let tmp_path = path.with_extension(format!("tmp.{}", uuid::Uuid::now_v7()));
    let mut tmp_guard = TempFileGuard::new(tmp_path.clone());
    if let Err(error) = std::fs::write(&tmp_path, &json) {
        return Err(persist_error_with_orphan_result(
            format!(
                "failed to write rollout temp file {}: {error}",
                tmp_path.display()
            ),
            tmp_guard.orphan_with(orphan_rename),
        ));
    }
    if let Err(error) = rename(&tmp_path, path) {
        return Err(persist_error_with_orphan_result(
            format!(
                "failed to rename rollout temp file {} to {}: {error}",
                tmp_path.display(),
                path.display()
            ),
            tmp_guard.orphan_with(orphan_rename),
        ));
    }
    tmp_guard.defuse();
    obligation_guard
        .commit(now_unix_ms())
        .map_err(|message| PersistError::IoError { message })?;

    Ok(())
}

fn persist_error_with_orphan_result(
    primary_message: String,
    orphan_result: Result<(), PersistError>,
) -> PersistError {
    match orphan_result {
        Ok(()) => PersistError::IoError {
            message: primary_message,
        },
        Err(PersistError::IoError { message }) => PersistError::IoError {
            message: format!("{primary_message}; {message}"),
        },
        Err(other) => PersistError::IoError {
            message: format!("{primary_message}; temp orphan failed with {other}"),
        },
    }
}

#[cfg(feature = "test-support")]
pub fn persist_with_obligation_tracker_for_test(
    state: &RolloutState,
    path: &Path,
    tracker: &mut ObligationTracker,
    trace_id: &str,
) -> Result<(), PersistError> {
    persist_with_obligation_tracker(state, path, tracker, trace_id)
}

#[cfg(feature = "test-support")]
pub fn persist_with_obligation_tracker_and_rename_for_test(
    state: &RolloutState,
    path: &Path,
    tracker: &mut ObligationTracker,
    trace_id: &str,
    rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), PersistError> {
    persist_with_obligation_tracker_and_rename(state, path, tracker, trace_id, rename)
}

#[cfg(feature = "test-support")]
pub fn persist_with_obligation_tracker_and_rename_and_orphan_for_test(
    state: &RolloutState,
    path: &Path,
    tracker: &mut ObligationTracker,
    trace_id: &str,
    rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    orphan_rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), PersistError> {
    persist_with_obligation_tracker_and_rename_and_orphan(
        state,
        path,
        tracker,
        trace_id,
        rename,
        orphan_rename,
    )
}

fn rollout_obligation_payload(state: &RolloutState, path: &Path) -> Result<Vec<u8>, PersistError> {
    serde_json::to_vec(&serde_json::json!({
        "operation": "rollout_state_persist",
        "connector_id": state.connector_id,
        "version": state.version,
        "path": path.to_string_lossy(),
    }))
    .map_err(|e| PersistError::IoError {
        message: e.to_string(),
    })
}

/// Load rollout state from a JSON file.
pub fn load(path: &Path) -> Result<RolloutState, PersistError> {
    let content = std::fs::read_to_string(path).map_err(|e| PersistError::IoError {
        message: e.to_string(),
    })?;
    serde_json::from_str(&content).map_err(|e| PersistError::IoError {
        message: e.to_string(),
    })
}

fn replay_mismatch(field: &str, expected: String, actual: String) -> PersistError {
    PersistError::ReplayMismatch {
        field: field.to_string(),
        expected,
        actual,
    }
}

fn replay_value_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|e| format!("__serde_err:{e}"))
}

fn replay_option_string(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "<none>".to_string())
}

fn replay_cancel_phase(value: Option<CancellationPhase>) -> String {
    value.map_or_else(|| "<none>".to_string(), |phase| phase.to_string())
}

/// Verify that a loaded state matches an expected state for replay validation.
pub fn verify_replay(expected: &RolloutState, actual: &RolloutState) -> Result<(), PersistError> {
    if expected.connector_id != actual.connector_id {
        return Err(replay_mismatch(
            "connector_id",
            expected.connector_id.clone(),
            actual.connector_id.clone(),
        ));
    }
    if expected.rollout_epoch != actual.rollout_epoch {
        return Err(replay_mismatch(
            "rollout_epoch",
            expected.rollout_epoch.value().to_string(),
            actual.rollout_epoch.value().to_string(),
        ));
    }
    if expected.lifecycle_state != actual.lifecycle_state {
        return Err(replay_mismatch(
            "lifecycle_state",
            expected.lifecycle_state.to_string(),
            actual.lifecycle_state.to_string(),
        ));
    }
    if expected.health != actual.health {
        return Err(replay_mismatch(
            "health",
            replay_value_json(&expected.health),
            replay_value_json(&actual.health),
        ));
    }
    if expected.rollout_phase != actual.rollout_phase {
        return Err(replay_mismatch(
            "rollout_phase",
            expected.rollout_phase.to_string(),
            actual.rollout_phase.to_string(),
        ));
    }
    if expected.activated_at != actual.activated_at {
        return Err(replay_mismatch(
            "activated_at",
            replay_option_string(&expected.activated_at),
            replay_option_string(&actual.activated_at),
        ));
    }
    if expected.persisted_at != actual.persisted_at {
        return Err(replay_mismatch(
            "persisted_at",
            expected.persisted_at.clone(),
            actual.persisted_at.clone(),
        ));
    }
    if expected.version != actual.version {
        return Err(replay_mismatch(
            "version",
            expected.version.to_string(),
            actual.version.to_string(),
        ));
    }
    if expected.cancel_phase != actual.cancel_phase {
        return Err(replay_mismatch(
            "cancel_phase",
            replay_cancel_phase(expected.cancel_phase),
            replay_cancel_phase(actual.cancel_phase),
        ));
    }
    Ok(())
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn now_unix_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::health_gate::{HealthGateResult, standard_checks};
    use crate::control_plane::control_epoch::ValidityWindowPolicy;
    use tempfile::TempDir;

    fn sample_state() -> RolloutState {
        let checks = standard_checks(true, true, true, true);
        let health = HealthGateResult::evaluate(checks);
        RolloutState::new_with_epoch(
            "test-connector-1".to_string(),
            ControlEpoch::new(6),
            ConnectorState::Configured,
            health,
            RolloutPhase::Shadow,
        )
    }

    fn temp_leftovers(dir: &Path, marker: &str) -> Vec<String> {
        let mut leftovers = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return leftovers,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(marker) {
                leftovers.push(name);
            }
        }
        leftovers.sort();
        leftovers
    }

    #[test]
    fn new_state_has_version_1() {
        let state = sample_state();
        assert_eq!(state.version, 1);
        assert_eq!(state.rollout_epoch, ControlEpoch::new(6));
    }

    #[test]
    fn persisted_at_uses_rfc3339_and_not_unix_seconds() {
        let state = sample_state();
        chrono::DateTime::parse_from_rfc3339(&state.persisted_at)
            .expect("persisted_at should be RFC3339");
        assert!(state.persisted_at.contains('T'));
        assert!(state.persisted_at.ends_with('Z'));
        assert!(
            state.persisted_at.parse::<u64>().is_err(),
            "persisted_at must not be a unix-seconds integer string"
        );
    }

    #[test]
    fn bump_version_increments() {
        let mut state = sample_state();
        state.bump_version();
        assert_eq!(state.version, 2);
        state.bump_version();
        assert_eq!(state.version, 3);
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let state = sample_state();
        persist(&state, &path).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(state, loaded);
    }

    #[test]
    fn persist_cleans_temp_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let state = sample_state();
        persist(&state, &path).unwrap();

        let leftovers = temp_leftovers(dir.path(), ".tmp.");
        assert!(
            leftovers.is_empty(),
            "found temp rollout leftovers: {leftovers:?}"
        );
    }

    #[test]
    fn temp_file_guard_orphans_abandoned_temp_files() {
        let dir = TempDir::new().unwrap();
        let temp_path = dir.path().join("state.json.tmp");
        std::fs::write(&temp_path, "pending").unwrap();

        {
            let _guard = TempFileGuard::new(temp_path.clone());
        }

        assert!(!temp_path.exists(), "temp file should be moved aside");
        let leftovers = temp_leftovers(dir.path(), "state.json.tmp.orphaned-");
        assert_eq!(leftovers.len(), 1, "expected one orphaned temp artifact");
    }

    #[test]
    fn stale_version_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let mut state = sample_state();
        state.bump_version(); // version 2
        persist(&state, &path).unwrap();

        // Try to write version 1 (stale)
        let stale = sample_state(); // version 1
        let err = persist(&stale, &path).unwrap_err();
        assert!(matches!(err, PersistError::StaleVersion { .. }));
    }

    #[test]
    fn verify_replay_matching() {
        let state = sample_state();
        assert!(verify_replay(&state, &state).is_ok());
    }

    #[test]
    fn verify_replay_mismatch_state() {
        let state1 = sample_state();
        let mut state2 = state1.clone();
        state2.lifecycle_state = ConnectorState::Active;
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "lifecycle_state");
            }
            _ => unreachable!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn verify_replay_mismatch_phase() {
        let state1 = sample_state();
        let mut state2 = state1.clone();
        state2.rollout_phase = RolloutPhase::Default;
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "rollout_phase");
            }
            _ => unreachable!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn verify_replay_mismatch_epoch() {
        let state1 = sample_state();
        let mut state2 = state1.clone();
        state2.rollout_epoch = ControlEpoch::new(7);
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "rollout_epoch");
            }
            _ => unreachable!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn verify_replay_mismatch_health() {
        let state1 = sample_state();
        let mut state2 = state1.clone();
        state2.health = HealthGateResult::evaluate(standard_checks(true, false, true, true));
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "health");
            }
            _ => unreachable!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn verify_replay_mismatch_activated_at() {
        let state1 = sample_state();
        let mut state2 = state1.clone();
        state2.activated_at = Some("2026-01-01T00:00:00Z".to_string());
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "activated_at");
            }
            _ => unreachable!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn verify_replay_mismatch_persisted_at() {
        let state1 = sample_state();
        let mut state2 = state1.clone();
        state2.persisted_at = "2026-01-01T00:00:00Z".to_string();
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "persisted_at");
            }
            _ => unreachable!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn verify_replay_mismatch_cancel_phase() {
        let state1 = sample_state();
        let mut state2 = state1.clone();
        state2.cancel_phase = Some(CancellationPhase::Draining);
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "cancel_phase");
            }
            _ => unreachable!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn serde_roundtrip() {
        let state = sample_state();
        let json = serde_json::to_string(&state).unwrap();
        let parsed: RolloutState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }

    #[test]
    fn load_nonexistent_returns_error() {
        let err = load(Path::new("/nonexistent/state.json")).unwrap_err();
        assert!(matches!(err, PersistError::IoError { .. }));
    }

    #[test]
    fn persist_epoch_scoped_accepts_current_epoch() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch.json");
        let state = sample_state();
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let result = persist_epoch_scoped(&state, &path, &policy, "trace-rollout").unwrap();
        assert_eq!(
            result.epoch_check_event_code,
            epoch_event_codes::EPOCH_CHECK_PASSED
        );
        assert_eq!(
            result.scope_log.event_code,
            epoch_event_codes::EPOCH_SCOPE_LOGGED
        );
    }

    #[test]
    fn persist_epoch_scoped_rejects_future_epoch() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-future.json");
        let mut state = sample_state();
        state.rollout_epoch = ControlEpoch::new(10);
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&state, &path, &policy, "trace-rollout-future")
            .expect_err("future epoch must fail-closed");
        assert!(matches!(err, EpochPersistError::FutureEpochRejected { .. }));
    }

    #[test]
    fn persist_epoch_scoped_rejects_expired_epoch() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-expired.json");
        let mut state = sample_state();
        state.rollout_epoch = ControlEpoch::new(2);
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&state, &path, &policy, "trace-rollout-expired")
            .expect_err("stale epoch must be rejected");
        assert!(matches!(err, EpochPersistError::StaleEpochRejected { .. }));
    }

    #[test]
    fn epoch_persist_error_display_handles_invalid_artifact_id() {
        let err = EpochPersistError::from_rejection(EpochRejection {
            artifact_id: " rollout-plan:bad ".to_string(),
            artifact_epoch: ControlEpoch::new(7),
            current_epoch: ControlEpoch::new(7),
            rejection_reason: EpochRejectionReason::InvalidArtifactId,
            trace_id: "trace-rollout-invalid".to_string(),
        });

        let rendered = err.to_string();
        assert!(rendered.contains("EPOCH_REJECT_INVALID_ARTIFACT_ID"));
        assert!(rendered.contains("reason=invalid_artifact_id"));
    }

    #[test]
    fn persist_epoch_scoped_rejects_empty_connector_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-empty.json");
        let mut state = sample_state();
        state.connector_id.clear();
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&state, &path, &policy, "trace-rollout-empty")
            .expect_err("empty connector_id must be rejected");
        assert!(matches!(err, EpochPersistError::InvalidConnectorId { .. }));
    }

    #[test]
    fn persist_epoch_scoped_rejects_reserved_connector_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-reserved.json");
        let mut state = sample_state();
        state.connector_id = RESERVED_CONNECTOR_ID.to_string();
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&state, &path, &policy, "trace-rollout-reserved")
            .expect_err("reserved connector_id must be rejected");
        assert!(matches!(err, EpochPersistError::InvalidConnectorId { .. }));
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn persist_epoch_scoped_rejects_whitespace_connector_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-whitespace.json");
        let mut state = sample_state();
        state.connector_id = " connector-1 ".to_string();
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&state, &path, &policy, "trace-rollout-whitespace")
            .expect_err("whitespace connector_id must be rejected");
        assert!(matches!(err, EpochPersistError::InvalidConnectorId { .. }));
        assert!(err.to_string().contains("leading or trailing whitespace"));
    }

    #[test]
    fn persist_epoch_scoped_rejects_all_whitespace_connector_id_without_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-blank.json");
        let mut state = sample_state();
        state.connector_id = "\t \n".to_string();
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&state, &path, &policy, "trace-rollout-blank")
            .expect_err("blank connector_id must be rejected before persistence");

        assert!(matches!(
            err,
            EpochPersistError::InvalidConnectorId { reason } if reason.contains("must not be empty")
        ));
        assert!(!path.exists());
    }

    #[test]
    fn persist_epoch_scoped_rejects_future_epoch_without_creating_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-future-side-effect.json");
        let mut state = sample_state();
        state.rollout_epoch = ControlEpoch::new(99);
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&state, &path, &policy, "trace-rollout-future-side-effect")
            .expect_err("future epoch must be rejected before persistence");

        assert!(matches!(err, EpochPersistError::FutureEpochRejected { .. }));
        assert!(!path.exists());
        assert!(temp_leftovers(dir.path(), ".tmp.").is_empty());
    }

    #[test]
    fn persist_epoch_scoped_rejects_stale_epoch_without_creating_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-stale-side-effect.json");
        let mut state = sample_state();
        state.rollout_epoch = ControlEpoch::new(1);
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&state, &path, &policy, "trace-rollout-stale-side-effect")
            .expect_err("stale epoch must be rejected before persistence");

        assert!(matches!(err, EpochPersistError::StaleEpochRejected { .. }));
        assert!(!path.exists());
        assert!(temp_leftovers(dir.path(), ".tmp.").is_empty());
    }

    #[test]
    fn persist_epoch_scoped_stale_version_preserves_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state-epoch-stale-version.json");
        let mut existing = sample_state();
        existing.bump_version();
        persist(&existing, &path).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        let stale = sample_state();
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = persist_epoch_scoped(&stale, &path, &policy, "trace-rollout-stale-version")
            .expect_err("stale version must be surfaced through epoch-scoped persist");

        assert!(matches!(
            err,
            EpochPersistError::Persist {
                source: PersistError::StaleVersion {
                    current_version: 2,
                    attempted_version: 1
                }
            }
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn load_malformed_json_returns_io_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("malformed-state.json");
        std::fs::write(&path, "{not-json").unwrap();

        let err = load(&path).expect_err("malformed JSON must fail to load");

        assert!(matches!(err, PersistError::IoError { .. }));
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn verify_replay_mismatch_connector_id_reports_field_and_values() {
        let expected = sample_state();
        let mut actual = expected.clone();
        actual.connector_id = "other-connector".to_string();

        let err = verify_replay(&expected, &actual).unwrap_err();

        assert!(
            matches!(&err, PersistError::ReplayMismatch { .. }),
            "expected connector_id replay mismatch, got {err:?}"
        );
        if let PersistError::ReplayMismatch {
            field,
            expected,
            actual,
        } = err
        {
            assert_eq!(field, "connector_id");
            assert_eq!(expected, "test-connector-1");
            assert_eq!(actual, "other-connector");
        }
    }

    #[test]
    fn verify_replay_mismatch_version_reports_field_and_values() {
        let expected = sample_state();
        let mut actual = expected.clone();
        actual.bump_version();

        let err = verify_replay(&expected, &actual).unwrap_err();

        assert!(
            matches!(&err, PersistError::ReplayMismatch { .. }),
            "expected version replay mismatch, got {err:?}"
        );
        if let PersistError::ReplayMismatch {
            field,
            expected,
            actual,
        } = err
        {
            assert_eq!(field, "version");
            assert_eq!(expected, "1");
            assert_eq!(actual, "2");
        }
    }

    #[test]
    fn verify_replay_mismatch_missing_actual_cancel_phase_reports_none() {
        let mut expected = sample_state();
        expected.cancel_phase = Some(CancellationPhase::Finalizing);
        let actual = sample_state();

        let err = verify_replay(&expected, &actual).unwrap_err();

        assert!(
            matches!(&err, PersistError::ReplayMismatch { .. }),
            "expected cancel_phase replay mismatch, got {err:?}"
        );
        if let PersistError::ReplayMismatch {
            field,
            expected,
            actual,
        } = err
        {
            assert_eq!(field, "cancel_phase");
            assert_eq!(expected, "finalizing");
            assert_eq!(actual, "<none>");
        }
    }

    fn sample_state_value() -> serde_json::Value {
        serde_json::to_value(sample_state()).expect("sample rollout state should serialize")
    }

    #[test]
    fn malformed_rollout_state_missing_connector_id_is_rejected() {
        let mut payload = sample_state_value();
        payload
            .as_object_mut()
            .expect("rollout state fixture should be a JSON object")
            .remove("connector_id");

        let err = serde_json::from_value::<RolloutState>(payload).unwrap_err();

        assert!(err.to_string().contains("connector_id"));
    }

    #[test]
    fn malformed_rollout_state_missing_lifecycle_state_is_rejected() {
        let mut payload = sample_state_value();
        payload
            .as_object_mut()
            .expect("rollout state fixture should be a JSON object")
            .remove("lifecycle_state");

        let err = serde_json::from_value::<RolloutState>(payload).unwrap_err();

        assert!(err.to_string().contains("lifecycle_state"));
    }

    #[test]
    fn malformed_rollout_state_missing_health_is_rejected() {
        let mut payload = sample_state_value();
        payload
            .as_object_mut()
            .expect("rollout state fixture should be a JSON object")
            .remove("health");

        let err = serde_json::from_value::<RolloutState>(payload).unwrap_err();

        assert!(err.to_string().contains("health"));
    }

    #[test]
    fn malformed_rollout_state_unknown_rollout_phase_is_rejected() {
        let mut payload = sample_state_value();
        payload["rollout_phase"] = serde_json::json!("dark_launch");

        let err = serde_json::from_value::<RolloutState>(payload).unwrap_err();

        assert!(err.to_string().contains("dark_launch"));
    }

    #[test]
    fn malformed_rollout_state_non_numeric_version_is_rejected() {
        let mut payload = sample_state_value();
        payload["version"] = serde_json::json!("one");

        let err = serde_json::from_value::<RolloutState>(payload).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn malformed_rollout_state_unknown_cancel_phase_is_rejected() {
        let mut payload = sample_state_value();
        payload["cancel_phase"] = serde_json::json!("Paused");

        let err = serde_json::from_value::<RolloutState>(payload).unwrap_err();

        assert!(err.to_string().contains("Paused"));
    }
}
