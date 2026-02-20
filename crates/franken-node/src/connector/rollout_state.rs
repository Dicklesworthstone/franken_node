//! Rollout-state persistence for connector instances.
//!
//! Persists the combination of lifecycle state, health gate results,
//! rollout phase, and activation timestamp to a durable JSON file.
//! Supports versioned writes for conflict detection and deterministic
//! recovery replay.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

use super::health_gate::HealthGateResult;
use super::lifecycle::ConnectorState;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutState {
    pub connector_id: String,
    pub lifecycle_state: ConnectorState,
    pub health: HealthGateResult,
    pub rollout_phase: RolloutPhase,
    pub activated_at: Option<String>,
    pub persisted_at: String,
    pub version: u32,
}

impl RolloutState {
    /// Create a new rollout state at version 1.
    pub fn new(
        connector_id: String,
        lifecycle_state: ConnectorState,
        health: HealthGateResult,
        rollout_phase: RolloutPhase,
    ) -> Self {
        Self {
            connector_id,
            lifecycle_state,
            health,
            rollout_phase,
            activated_at: None,
            persisted_at: now_iso8601(),
            version: 1,
        }
    }

    /// Advance the version and update the persistence timestamp.
    pub fn bump_version(&mut self) {
        self.version += 1;
        self.persisted_at = now_iso8601();
    }
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

/// Save rollout state to a JSON file atomically.
///
/// If a file already exists at `path`, the version in it must be less than
/// the version in `state`, otherwise `StaleVersion` is returned.
pub fn persist(state: &RolloutState, path: &Path) -> Result<(), PersistError> {
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

    // Write to temp file then rename for atomicity
    let tmp_path = path.with_extension("tmp");
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
    // Simple UTC timestamp without external crate dependency
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::health_gate::{standard_checks, HealthGateResult};
    use tempfile::TempDir;

    fn sample_state() -> RolloutState {
        let checks = standard_checks(true, true, true, true);
        let health = HealthGateResult::evaluate(checks);
        RolloutState::new(
            "test-connector-1".to_string(),
            ConnectorState::Configured,
            health,
            RolloutPhase::Shadow,
        )
    }

    #[test]
    fn new_state_has_version_1() {
        let state = sample_state();
        assert_eq!(state.version, 1);
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
        assert_eq!(state.lifecycle_state, parsed.lifecycle_state);
        assert_eq!(state.rollout_phase, parsed.rollout_phase);
    }

    #[test]
    fn load_nonexistent_returns_error() {
        let err = load(Path::new("/nonexistent/state.json")).unwrap_err();
        assert!(matches!(err, PersistError::IoError { .. }));
    }
}
