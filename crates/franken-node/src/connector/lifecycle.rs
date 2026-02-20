//! Connector lifecycle FSM.
//!
//! Defines the eight lifecycle states a connector can occupy and the
//! deterministic transition table that governs legal state changes.
//! Illegal transitions are rejected with stable error codes.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The eight mutually exclusive lifecycle states for a connector instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorState {
    Discovered,
    Verified,
    Installed,
    Configured,
    Active,
    Paused,
    Stopped,
    Failed,
}

impl ConnectorState {
    /// All possible states, ordered by the canonical happy-path progression.
    pub const ALL: [ConnectorState; 8] = [
        Self::Discovered,
        Self::Verified,
        Self::Installed,
        Self::Configured,
        Self::Active,
        Self::Paused,
        Self::Stopped,
        Self::Failed,
    ];

    /// Returns the set of states that are legal targets from this state.
    pub fn legal_targets(&self) -> &'static [ConnectorState] {
        match self {
            Self::Discovered => &[Self::Verified, Self::Failed],
            Self::Verified => &[Self::Installed, Self::Failed],
            Self::Installed => &[Self::Configured, Self::Failed],
            Self::Configured => &[Self::Active, Self::Failed],
            Self::Active => &[Self::Paused, Self::Stopped, Self::Failed],
            Self::Paused => &[Self::Active, Self::Stopped, Self::Failed],
            Self::Stopped => &[Self::Configured, Self::Failed],
            Self::Failed => &[Self::Discovered],
        }
    }

    /// Returns true if transitioning from `self` to `target` is permitted.
    pub fn can_transition_to(&self, target: &ConnectorState) -> bool {
        self.legal_targets().contains(target)
    }

    /// Returns the string name used in error codes and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Verified => "verified",
            Self::Installed => "installed",
            Self::Configured => "configured",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for ConnectorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error codes for illegal lifecycle transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum LifecycleError {
    /// The requested (from, to) pair is not in the permitted transition set.
    #[serde(rename = "ILLEGAL_TRANSITION")]
    IllegalTransition {
        from: ConnectorState,
        to: ConnectorState,
        permitted: Vec<ConnectorState>,
    },
    /// Source and target are the same state.
    #[serde(rename = "SELF_TRANSITION")]
    SelfTransition { state: ConnectorState },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTransition {
                from,
                to,
                permitted,
            } => {
                let targets: Vec<&str> = permitted.iter().map(|s| s.as_str()).collect();
                write!(
                    f,
                    "ILLEGAL_TRANSITION: cannot transition from {from} to {to}; \
                     permitted targets: [{}]",
                    targets.join(", ")
                )
            }
            Self::SelfTransition { state } => {
                write!(
                    f,
                    "SELF_TRANSITION: cannot transition from {state} to itself"
                )
            }
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Attempt a lifecycle transition from `from` to `to`.
///
/// Returns the new state on success, or a stable error on failure.
/// This is the single authoritative transition gate for all connector
/// lifecycle changes.
pub fn transition(
    from: ConnectorState,
    to: ConnectorState,
) -> Result<ConnectorState, LifecycleError> {
    if from == to {
        return Err(LifecycleError::SelfTransition { state: from });
    }

    if from.can_transition_to(&to) {
        Ok(to)
    } else {
        Err(LifecycleError::IllegalTransition {
            from,
            to,
            permitted: from.legal_targets().to_vec(),
        })
    }
}

/// Build the full transition matrix as a serializable structure.
///
/// Returns a vec of (from, to, legal) triples covering every non-self pair.
pub fn transition_matrix() -> Vec<TransitionEntry> {
    let mut entries = Vec::new();
    for &from in &ConnectorState::ALL {
        for &to in &ConnectorState::ALL {
            if from == to {
                continue;
            }
            entries.push(TransitionEntry {
                from,
                to,
                legal: from.can_transition_to(&to),
            });
        }
    }
    entries
}

/// A single entry in the transition matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionEntry {
    pub from: ConnectorState,
    pub to: ConnectorState,
    pub legal: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_full_lifecycle() {
        let mut state = ConnectorState::Discovered;
        for next in [
            ConnectorState::Verified,
            ConnectorState::Installed,
            ConnectorState::Configured,
            ConnectorState::Active,
        ] {
            state = transition(state, next).unwrap();
        }
        assert_eq!(state, ConnectorState::Active);
    }

    #[test]
    fn self_transition_rejected() {
        for &s in &ConnectorState::ALL {
            let err = transition(s, s).unwrap_err();
            assert!(
                matches!(err, LifecycleError::SelfTransition { .. }),
                "expected SelfTransition for {s}"
            );
        }
    }

    #[test]
    fn illegal_transition_rejected() {
        // Discovered → Active is not legal (must go through intermediate states)
        let err = transition(ConnectorState::Discovered, ConnectorState::Active).unwrap_err();
        match err {
            LifecycleError::IllegalTransition {
                from,
                to,
                permitted,
            } => {
                assert_eq!(from, ConnectorState::Discovered);
                assert_eq!(to, ConnectorState::Active);
                assert!(permitted.contains(&ConnectorState::Verified));
                assert!(permitted.contains(&ConnectorState::Failed));
            }
            _ => panic!("expected IllegalTransition"),
        }
    }

    #[test]
    fn failed_resets_to_discovered() {
        let state = transition(ConnectorState::Failed, ConnectorState::Discovered).unwrap();
        assert_eq!(state, ConnectorState::Discovered);
    }

    #[test]
    fn paused_can_resume() {
        let state = transition(ConnectorState::Paused, ConnectorState::Active).unwrap();
        assert_eq!(state, ConnectorState::Active);
    }

    #[test]
    fn stopped_can_reconfigure() {
        let state = transition(ConnectorState::Stopped, ConnectorState::Configured).unwrap();
        assert_eq!(state, ConnectorState::Configured);
    }

    #[test]
    fn transition_matrix_covers_all_pairs() {
        let matrix = transition_matrix();
        // 8 states, 7 non-self targets each = 56 entries
        assert_eq!(matrix.len(), 56);
    }

    #[test]
    fn transition_matrix_legal_count() {
        let matrix = transition_matrix();
        let legal_count = matrix.iter().filter(|e| e.legal).count();
        // 17 legal transitions per the spec
        assert_eq!(legal_count, 17);
    }

    #[test]
    fn error_display_stable() {
        let err = LifecycleError::IllegalTransition {
            from: ConnectorState::Discovered,
            to: ConnectorState::Active,
            permitted: vec![ConnectorState::Verified, ConnectorState::Failed],
        };
        let msg = err.to_string();
        assert!(msg.contains("ILLEGAL_TRANSITION"));
        assert!(msg.contains("discovered"));
        assert!(msg.contains("active"));
    }

    #[test]
    fn serde_roundtrip() {
        for &state in &ConnectorState::ALL {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: ConnectorState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, parsed);
        }
    }
}
