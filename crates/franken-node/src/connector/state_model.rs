//! Canonical connector state root/object model.
//!
//! Defines state model types, the canonical state root object, and
//! cache divergence detection/reconciliation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// The state model type declared by each connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateModelType {
    Stateless,
    KeyValue,
    Document,
    AppendOnly,
}

impl StateModelType {
    pub const ALL: [StateModelType; 4] = [
        Self::Stateless,
        Self::KeyValue,
        Self::Document,
        Self::AppendOnly,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stateless => "stateless",
            Self::KeyValue => "key_value",
            Self::Document => "document",
            Self::AppendOnly => "append_only",
        }
    }
}

impl fmt::Display for StateModelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The canonical state root object for a connector instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRoot {
    pub connector_id: String,
    pub state_model: StateModelType,
    pub root_hash: String,
    pub version: u64,
    pub last_modified: String,
    pub head: serde_json::Value,
}

impl StateRoot {
    /// Create a new state root with computed hash.
    pub fn new(connector_id: String, state_model: StateModelType, head: serde_json::Value) -> Self {
        let root_hash = compute_hash(&head);
        Self {
            connector_id,
            state_model,
            root_hash,
            version: 1,
            last_modified: now_iso8601(),
            head,
        }
    }

    /// Update the head state, recompute hash, bump version.
    pub fn update_head(&mut self, new_head: serde_json::Value) {
        self.head = new_head;
        self.root_hash = compute_hash(&self.head);
        self.version += 1;
        self.last_modified = now_iso8601();
    }

    /// Verify that the stored root_hash matches the computed hash of head.
    pub fn verify_integrity(&self) -> bool {
        self.root_hash == compute_hash(&self.head)
    }
}

/// Cache divergence types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceType {
    None,
    Stale,
    SplitBrain,
    HashMismatch,
}

impl fmt::Display for DivergenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Stale => write!(f, "stale"),
            Self::SplitBrain => write!(f, "split_brain"),
            Self::HashMismatch => write!(f, "hash_mismatch"),
        }
    }
}

/// Result of checking cache divergence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceCheck {
    pub divergence_type: DivergenceType,
    pub local_version: u64,
    pub canonical_version: u64,
    pub local_hash: String,
    pub canonical_hash: String,
}

/// Reconciliation action for a detected divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileAction {
    NoAction,
    PullCanonical,
    FlagForReview,
    RepairHash,
}

/// Error codes for state model operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateModelError {
    #[serde(rename = "STATE_MODEL_MISSING")]
    StateModelMissing { connector_id: String },
    #[serde(rename = "ROOT_HASH_MISMATCH")]
    RootHashMismatch { expected: String, actual: String },
    #[serde(rename = "CACHE_STALE")]
    CacheStale {
        local_version: u64,
        canonical_version: u64,
    },
    #[serde(rename = "CACHE_SPLIT_BRAIN")]
    CacheSplitBrain {
        local_version: u64,
        canonical_version: u64,
    },
}

impl fmt::Display for StateModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateModelMissing { connector_id } => {
                write!(
                    f,
                    "STATE_MODEL_MISSING: connector '{connector_id}' has no declared state model"
                )
            }
            Self::RootHashMismatch { expected, actual } => {
                write!(
                    f,
                    "ROOT_HASH_MISMATCH: expected '{expected}', got '{actual}'"
                )
            }
            Self::CacheStale {
                local_version,
                canonical_version,
            } => {
                write!(
                    f,
                    "CACHE_STALE: local v{local_version} < canonical v{canonical_version}"
                )
            }
            Self::CacheSplitBrain {
                local_version,
                canonical_version,
            } => {
                write!(
                    f,
                    "CACHE_SPLIT_BRAIN: local v{local_version} > canonical v{canonical_version}"
                )
            }
        }
    }
}

impl std::error::Error for StateModelError {}

/// Detect divergence between a local cache and the canonical state root.
pub fn detect_divergence(local: &StateRoot, canonical: &StateRoot) -> DivergenceCheck {
    let divergence_type = if local.version < canonical.version {
        DivergenceType::Stale
    } else if local.version > canonical.version {
        DivergenceType::SplitBrain
    } else if local.root_hash != canonical.root_hash {
        DivergenceType::HashMismatch
    } else {
        DivergenceType::None
    };

    DivergenceCheck {
        divergence_type,
        local_version: local.version,
        canonical_version: canonical.version,
        local_hash: local.root_hash.clone(),
        canonical_hash: canonical.root_hash.clone(),
    }
}

/// Determine the reconciliation action for a divergence.
pub fn reconcile_action(check: &DivergenceCheck) -> ReconcileAction {
    match check.divergence_type {
        DivergenceType::None => ReconcileAction::NoAction,
        DivergenceType::Stale => ReconcileAction::PullCanonical,
        DivergenceType::SplitBrain => ReconcileAction::FlagForReview,
        DivergenceType::HashMismatch => ReconcileAction::RepairHash,
    }
}

/// Compute a SHA-256 hash of a JSON value.
fn compute_hash(value: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:064x}", hasher.finalize())
}

fn now_iso8601() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn four_state_model_types() {
        assert_eq!(StateModelType::ALL.len(), 4);
    }

    #[test]
    fn new_root_has_version_1() {
        let root = StateRoot::new(
            "conn-1".into(),
            StateModelType::Document,
            json!({"key": "val"}),
        );
        assert_eq!(root.version, 1);
    }

    #[test]
    fn new_root_hash_computed() {
        let root = StateRoot::new(
            "conn-1".into(),
            StateModelType::Document,
            json!({"key": "val"}),
        );
        assert!(!root.root_hash.is_empty());
    }

    #[test]
    fn update_head_bumps_version() {
        let mut root = StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({}));
        root.update_head(json!({"a": 1}));
        assert_eq!(root.version, 2);
    }

    #[test]
    fn update_head_changes_hash() {
        let mut root = StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({}));
        let old_hash = root.root_hash.clone();
        root.update_head(json!({"a": 1}));
        assert_ne!(root.root_hash, old_hash);
    }

    #[test]
    fn verify_integrity_passes() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"x": 1}));
        assert!(root.verify_integrity());
    }

    #[test]
    fn verify_integrity_fails_on_tamper() {
        let mut root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"x": 1}));
        root.root_hash = "tampered".to_string();
        assert!(!root.verify_integrity());
    }

    #[test]
    fn detect_no_divergence() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Stateless, json!(null));
        let check = detect_divergence(&root, &root);
        assert_eq!(check.divergence_type, DivergenceType::None);
    }

    #[test]
    fn detect_stale_cache() {
        let local = StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({}));
        let mut canonical = local.clone();
        canonical.update_head(json!({"updated": true}));
        let check = detect_divergence(&local, &canonical);
        assert_eq!(check.divergence_type, DivergenceType::Stale);
    }

    #[test]
    fn detect_split_brain() {
        let canonical = StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({}));
        let mut local = canonical.clone();
        local.update_head(json!({"local_only": true}));
        let check = detect_divergence(&local, &canonical);
        assert_eq!(check.divergence_type, DivergenceType::SplitBrain);
    }

    #[test]
    fn detect_hash_mismatch() {
        let canonical = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"a": 1}));
        let mut local = canonical.clone();
        local.root_hash = "wrong_hash".to_string();
        let check = detect_divergence(&local, &canonical);
        assert_eq!(check.divergence_type, DivergenceType::HashMismatch);
    }

    #[test]
    fn reconcile_stale_pulls() {
        let check = DivergenceCheck {
            divergence_type: DivergenceType::Stale,
            local_version: 1,
            canonical_version: 3,
            local_hash: "a".into(),
            canonical_hash: "b".into(),
        };
        assert_eq!(reconcile_action(&check), ReconcileAction::PullCanonical);
    }

    #[test]
    fn reconcile_split_brain_flags() {
        let check = DivergenceCheck {
            divergence_type: DivergenceType::SplitBrain,
            local_version: 5,
            canonical_version: 3,
            local_hash: "a".into(),
            canonical_hash: "b".into(),
        };
        assert_eq!(reconcile_action(&check), ReconcileAction::FlagForReview);
    }

    #[test]
    fn reconcile_hash_mismatch_repairs() {
        let check = DivergenceCheck {
            divergence_type: DivergenceType::HashMismatch,
            local_version: 3,
            canonical_version: 3,
            local_hash: "a".into(),
            canonical_hash: "b".into(),
        };
        assert_eq!(reconcile_action(&check), ReconcileAction::RepairHash);
    }

    #[test]
    fn serde_roundtrip_state_model_type() {
        for &smt in &StateModelType::ALL {
            let json = serde_json::to_string(&smt).unwrap();
            let parsed: StateModelType = serde_json::from_str(&json).unwrap();
            assert_eq!(smt, parsed);
        }
    }

    #[test]
    fn serde_roundtrip_state_root() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let json = serde_json::to_string(&root).unwrap();
        let parsed: StateRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "conn-1");
        assert_eq!(parsed.version, 1);
    }
}
