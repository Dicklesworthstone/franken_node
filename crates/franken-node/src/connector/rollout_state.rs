//! Rollout-state persistence for connector instances.
//!
//! Persists the combination of lifecycle state, health gate results,
//! rollout phase, and activation timestamp to a durable JSON file.
//! Supports versioned writes for conflict detection and deterministic
//! recovery replay.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use crate::control_plane::control_epoch::{
    ControlEpoch, EpochArtifactEvent, EpochRejection, EpochRejectionReason, ValidityWindowPolicy,
    check_artifact_epoch,
};

use super::cancellation_protocol::CancellationPhase;
use super::health_gate::HealthGateResult;
use super::lifecycle::ConnectorState;

/// Stable event codes for epoch-scoped validity checks.
pub mod epoch_event_codes {
    pub const EPOCH_CHECK_PASSED: &str = "EPV-001";
    pub const FUTURE_EPOCH_REJECTED: &str = "EPV-002";
    pub const STALE_EPOCH_REJECTED: &str = "EPV-003";
    pub const EPOCH_SCOPE_LOGGED: &str = "EPV-004";
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
        self.version += 1;
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
    #[serde(rename = "PERSIST_ERROR")]
    Persist { source: PersistError },
}

impl EpochPersistError {
    fn from_rejection(rejection: EpochRejection) -> Self {
        match rejection.rejection_reason {
            EpochRejectionReason::FutureEpoch => Self::FutureEpochRejected { rejection },
            EpochRejectionReason::ExpiredEpoch => Self::StaleEpochRejected { rejection },
        }
    }
}

impl fmt::Display for EpochPersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FutureEpochRejected { rejection } | Self::StaleEpochRejected { rejection } => {
                write!(
                    f,
                    "{}: artifact={} artifact_epoch={} current_epoch={} reason={}",
                    rejection.code(),
                    rejection.artifact_id,
                    rejection.artifact_epoch.value(),
                    rejection.current_epoch.value(),
                    rejection.code()
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

/// Save rollout state to a JSON file atomically.
///
/// If a file already exists at `path`, the version in it must be less than
/// the version in `state`, otherwise `StaleVersion` is returned.
pub fn persist(state: &RolloutState, path: &Path) -> Result<(), PersistError> {
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

    // Write to temp file then rename for atomicity (UUID suffix avoids collisions).
    let tmp_path = path.with_extension(format!("tmp.{}", uuid::Uuid::now_v7()));
    std::fs::write(&tmp_path, &json).map_err(|e| PersistError::IoError {
        message: e.to_string(),
    })?;
    std::fs::rename(&tmp_path, path).map_err(|e| PersistError::IoError {
        message: e.to_string(),
    })?;

    Ok(())
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

/// Verify that a loaded state matches an expected state for replay validation.
pub fn verify_replay(expected: &RolloutState, actual: &RolloutState) -> Result<(), PersistError> {
    if expected.connector_id != actual.connector_id {
        return Err(PersistError::ReplayMismatch {
            field: "connector_id".to_string(),
            expected: expected.connector_id.clone(),
            actual: actual.connector_id.clone(),
        });
    }
    if expected.lifecycle_state != actual.lifecycle_state {
        return Err(PersistError::ReplayMismatch {
            field: "lifecycle_state".to_string(),
            expected: expected.lifecycle_state.to_string(),
            actual: actual.lifecycle_state.to_string(),
        });
    }
    if expected.rollout_phase != actual.rollout_phase {
        return Err(PersistError::ReplayMismatch {
            field: "rollout_phase".to_string(),
            expected: expected.rollout_phase.to_string(),
            actual: actual.rollout_phase.to_string(),
        });
    }
    if expected.version != actual.version {
        return Err(PersistError::ReplayMismatch {
            field: "version".to_string(),
            expected: expected.version.to_string(),
            actual: actual.version.to_string(),
        });
    }
    Ok(())
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
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
        assert_eq!(state.connector_id, loaded.connector_id);
        assert_eq!(state.lifecycle_state, loaded.lifecycle_state);
        assert_eq!(state.version, loaded.version);
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
        let mut state2 = sample_state();
        state2.lifecycle_state = ConnectorState::Active;
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "lifecycle_state");
            }
            _ => panic!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn verify_replay_mismatch_phase() {
        let state1 = sample_state();
        let mut state2 = sample_state();
        state2.rollout_phase = RolloutPhase::Default;
        let err = verify_replay(&state1, &state2).unwrap_err();
        match err {
            PersistError::ReplayMismatch { field, .. } => {
                assert_eq!(field, "rollout_phase");
            }
            _ => panic!("expected ReplayMismatch"),
        }
    }

    #[test]
    fn serde_roundtrip() {
        let state = sample_state();
        let json = serde_json::to_string(&state).unwrap();
        let parsed: RolloutState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.connector_id, parsed.connector_id);
        assert_eq!(state.rollout_epoch, parsed.rollout_epoch);
        assert_eq!(state.lifecycle_state, parsed.lifecycle_state);
        assert_eq!(state.rollout_phase, parsed.rollout_phase);
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
}
