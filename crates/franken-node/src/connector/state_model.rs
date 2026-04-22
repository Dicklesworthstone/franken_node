//! Canonical connector state root/object model.
//!
//! Defines state model types, the canonical state root object, and
//! cache divergence detection/reconciliation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::security::constant_time;

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
        self.version = self.version.saturating_add(1);
        self.last_modified = now_iso8601();
    }

    /// Verify that the stored root_hash matches the computed hash of head.
    pub fn verify_integrity(&self) -> bool {
        constant_time::ct_eq(&self.root_hash, &compute_hash(&self.head))
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
    let divergence_type = if !canonical.verify_integrity() {
        DivergenceType::HashMismatch
    } else if local.version < canonical.version {
        DivergenceType::Stale
    } else if local.version > canonical.version {
        DivergenceType::SplitBrain
    } else if !local.verify_integrity()
        || local.connector_id != canonical.connector_id
        || local.state_model != canonical.state_model
        || !constant_time::ct_eq(&local.root_hash, &canonical.root_hash)
    {
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
    let canonical = serde_json::to_string(value).unwrap_or_else(|e| format!("__serde_err:{e}"));
    let mut hasher = Sha256::new();
    hasher.update(b"state_model_hash_v1:");
    hasher.update((canonical.len() as u64).to_le_bytes());
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

fn now_iso8601() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Convert days since epoch to date components
    // Algorithm: civil_from_days (Howard Hinnant)
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
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

    #[test]
    fn verify_integrity_fails_when_head_is_tampered_without_rehash() {
        let mut root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"x": 1}));
        let original_hash = root.root_hash.clone();

        root.head = json!({"x": 2});

        assert_eq!(root.root_hash, original_hash);
        assert!(!root.verify_integrity());
    }

    #[test]
    fn stale_version_takes_precedence_over_hash_mismatch() {
        let mut local = StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({"a": 1}));
        let mut canonical = local.clone();
        canonical.update_head(json!({"a": 2}));
        local.root_hash = "bad-local-hash".to_string();

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::Stale);
        assert_eq!(reconcile_action(&check), ReconcileAction::PullCanonical);
    }

    #[test]
    fn split_brain_version_takes_precedence_over_hash_mismatch() {
        let canonical = StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({"a": 1}));
        let mut local = canonical.clone();
        local.update_head(json!({"a": 2}));
        local.root_hash = "bad-local-hash".to_string();

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::SplitBrain);
        assert_eq!(reconcile_action(&check), ReconcileAction::FlagForReview);
    }

    #[test]
    fn corrupt_canonical_root_blocks_pull_canonical_even_when_newer() {
        let local = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut canonical = local.clone();
        canonical.update_head(json!({"k": "new"}));
        canonical.head = json!({"k": "tampered-after-hash"});

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::HashMismatch);
        assert_eq!(reconcile_action(&check), ReconcileAction::RepairHash);
    }

    #[test]
    fn same_hash_but_tampered_local_head_is_hash_mismatch() {
        let canonical =
            StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut local = canonical.clone();
        local.head = json!({"k": "tampered-with-stored-hash"});

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::HashMismatch);
        assert_eq!(reconcile_action(&check), ReconcileAction::RepairHash);
    }

    #[test]
    fn serde_rejects_unknown_state_model_type() {
        let err = serde_json::from_str::<StateModelType>("\"graph\"").unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_divergence_type() {
        let err = serde_json::from_str::<DivergenceType>("\"forked\"").unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_reconcile_action() {
        let err = serde_json::from_str::<ReconcileAction>("\"overwrite_canonical\"").unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn tampered_deserialized_state_root_fails_integrity() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut value = serde_json::to_value(&root).expect("state root should serialize");
        value["head"] = json!({"k": "tampered"});
        let parsed: StateRoot =
            serde_json::from_value(value).expect("tampered shape should still deserialize");

        assert!(!parsed.verify_integrity());
    }

    #[test]
    fn root_hash_mismatch_error_display_includes_expected_and_actual() {
        let err = StateModelError::RootHashMismatch {
            expected: "expected-hash".to_string(),
            actual: "actual-hash".to_string(),
        };
        let message = err.to_string();

        assert!(message.contains("ROOT_HASH_MISMATCH"));
        assert!(message.contains("expected-hash"));
        assert!(message.contains("actual-hash"));
    }

    #[test]
    fn connector_id_mismatch_with_same_head_is_divergence() {
        let local = StateRoot::new(
            "conn-local".into(),
            StateModelType::Document,
            json!({"k": "v"}),
        );
        let canonical = StateRoot::new(
            "conn-canonical".into(),
            StateModelType::Document,
            json!({"k": "v"}),
        );

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::HashMismatch);
        assert_eq!(reconcile_action(&check), ReconcileAction::RepairHash);
    }

    #[test]
    fn state_model_mismatch_with_same_head_is_divergence() {
        let local = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let canonical =
            StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({"k": "v"}));

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::HashMismatch);
        assert_eq!(reconcile_action(&check), ReconcileAction::RepairHash);
    }

    #[test]
    fn empty_local_hash_at_same_version_is_hash_mismatch() {
        let canonical =
            StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut local = canonical.clone();
        local.root_hash.clear();

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::HashMismatch);
    }

    #[test]
    fn empty_canonical_hash_at_same_version_is_hash_mismatch() {
        let local = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut canonical = local.clone();
        canonical.root_hash.clear();

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::HashMismatch);
    }

    #[test]
    fn serde_rejects_state_root_missing_head() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut value = serde_json::to_value(root).expect("state root should serialize");
        value.as_object_mut().unwrap().remove("head");

        let err = serde_json::from_value::<StateRoot>(value).unwrap_err();

        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn serde_rejects_state_root_version_type_confusion() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut value = serde_json::to_value(root).expect("state root should serialize");
        value["version"] = json!("2");

        let err = serde_json::from_value::<StateRoot>(value).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn serde_rejects_state_root_hash_type_confusion() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut value = serde_json::to_value(root).expect("state root should serialize");
        value["root_hash"] = json!(["not", "a", "string"]);

        let err = serde_json::from_value::<StateRoot>(value).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn update_head_saturates_version_at_u64_max() {
        let mut root = StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({"a": 1}));
        root.version = u64::MAX;

        root.update_head(json!({"a": 2}));

        assert_eq!(root.version, u64::MAX);
        assert!(root.verify_integrity());
    }

    #[test]
    fn serde_rejects_state_root_missing_connector_id() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut value = serde_json::to_value(root).expect("state root should serialize");
        value.as_object_mut().unwrap().remove("connector_id");

        let err = serde_json::from_value::<StateRoot>(value).unwrap_err();

        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn serde_rejects_state_root_missing_root_hash() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut value = serde_json::to_value(root).expect("state root should serialize");
        value.as_object_mut().unwrap().remove("root_hash");

        let err = serde_json::from_value::<StateRoot>(value).unwrap_err();

        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn serde_rejects_negative_state_root_version() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut value = serde_json::to_value(root).expect("state root should serialize");
        value["version"] = json!(-1);

        let err = serde_json::from_value::<StateRoot>(value).unwrap_err();

        assert!(err.to_string().contains("invalid value"));
    }

    #[test]
    fn serde_rejects_state_root_last_modified_type_confusion() {
        let root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut value = serde_json::to_value(root).expect("state root should serialize");
        value["last_modified"] = json!(1700000000u64);

        let err = serde_json::from_value::<StateRoot>(value).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn domainless_json_hash_cannot_spoof_integrity() {
        let mut root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let canonical = serde_json::to_string(&root.head).expect("head should serialize");
        let digest = Sha256::digest(canonical.as_bytes());
        root.root_hash = format!("{digest:064x}");

        assert!(!root.verify_integrity());
    }

    #[test]
    fn stale_connector_mismatch_still_requires_pull_canonical() {
        let local = StateRoot::new(
            "conn-local".into(),
            StateModelType::Document,
            json!({"k": "v"}),
        );
        let mut canonical = StateRoot::new(
            "conn-canonical".into(),
            StateModelType::Document,
            json!({"k": "v"}),
        );
        canonical.update_head(json!({"k": "new"}));

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::Stale);
        assert_eq!(reconcile_action(&check), ReconcileAction::PullCanonical);
    }

    #[test]
    fn split_brain_model_mismatch_still_requires_review() {
        let canonical =
            StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        let mut local =
            StateRoot::new("conn-1".into(), StateModelType::KeyValue, json!({"k": "v"}));
        local.update_head(json!({"k": "local"}));

        let check = detect_divergence(&local, &canonical);

        assert_eq!(check.divergence_type, DivergenceType::SplitBrain);
        assert_eq!(reconcile_action(&check), ReconcileAction::FlagForReview);
    }

    #[test]
    fn uppercase_root_hash_fails_constant_time_integrity_check() {
        let mut root = StateRoot::new("conn-1".into(), StateModelType::Document, json!({"k": "v"}));
        root.root_hash = root.root_hash.to_uppercase();

        assert!(!root.verify_integrity());
    }
}
