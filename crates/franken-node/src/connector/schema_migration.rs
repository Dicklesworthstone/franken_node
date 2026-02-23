//! State schema version contracts and deterministic migration hints.
//!
//! Version transitions require declared migration paths. Migrations are
//! idempotent, replay-stable, and failed migrations roll back cleanly.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A semantic version (major.minor.patch).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SchemaVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse a version string like "1.2.3".
    pub fn parse(s: &str) -> Result<Self, MigrationError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(MigrationError::SchemaVersionInvalid {
                version: s.to_string(),
                reason: "expected major.minor.patch".to_string(),
            });
        }
        let major = parts[0]
            .parse::<u32>()
            .map_err(|_| MigrationError::SchemaVersionInvalid {
                version: s.to_string(),
                reason: "invalid major version".to_string(),
            })?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|_| MigrationError::SchemaVersionInvalid {
                version: s.to_string(),
                reason: "invalid minor version".to_string(),
            })?;
        let patch = parts[2]
            .parse::<u32>()
            .map_err(|_| MigrationError::SchemaVersionInvalid {
                version: s.to_string(),
                reason: "invalid patch version".to_string(),
            })?;
        Ok(Self::new(major, minor, patch))
    }

    /// True if self > other (for forward-only enforcement).
    pub fn is_ahead_of(&self, other: &SchemaVersion) -> bool {
        (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Schema version contract for a connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaContract {
    pub connector_id: String,
    pub current_version: SchemaVersion,
    pub min_supported: SchemaVersion,
    pub max_supported: SchemaVersion,
}

impl SchemaContract {
    pub fn is_version_supported(&self, version: &SchemaVersion) -> bool {
        let v = (version.major, version.minor, version.patch);
        let min = (
            self.min_supported.major,
            self.min_supported.minor,
            self.min_supported.patch,
        );
        let max = (
            self.max_supported.major,
            self.max_supported.minor,
            self.max_supported.patch,
        );
        v >= min && v <= max
    }
}

/// Type of migration operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HintType {
    AddField,
    RemoveField,
    RenameField,
    Transform,
}

impl fmt::Display for HintType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddField => write!(f, "add_field"),
            Self::RemoveField => write!(f, "remove_field"),
            Self::RenameField => write!(f, "rename_field"),
            Self::Transform => write!(f, "transform"),
        }
    }
}

/// A migration hint describing a single version transition step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationHint {
    pub from_version: SchemaVersion,
    pub to_version: SchemaVersion,
    pub hint_type: HintType,
    pub description: String,
    pub idempotent: bool,
    pub rollback_safe: bool,
}

/// Result of applying a migration hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationOutcome {
    Applied,
    AlreadyApplied,
    RolledBack,
    Failed { reason: String },
}

/// A migration plan is an ordered sequence of hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub connector_id: String,
    pub from_version: SchemaVersion,
    pub to_version: SchemaVersion,
    pub steps: Vec<MigrationHint>,
}

/// Migration receipt recording the outcome of a migration attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub connector_id: String,
    pub from_version: SchemaVersion,
    pub to_version: SchemaVersion,
    pub outcome: MigrationOutcome,
    pub steps_applied: usize,
    pub steps_total: usize,
    pub timestamp: String,
}

/// Registry of migration hints, used to find paths between versions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationRegistry {
    pub hints: Vec<MigrationHint>,
}

impl MigrationRegistry {
    pub fn new() -> Self {
        Self { hints: Vec::new() }
    }

    pub fn register(&mut self, hint: MigrationHint) {
        self.hints.push(hint);
    }

    /// Find a migration path from source to target version.
    /// Uses BFS over the hint graph.
    pub fn find_path(
        &self,
        from: &SchemaVersion,
        to: &SchemaVersion,
    ) -> Result<Vec<MigrationHint>, MigrationError> {
        if from == to {
            return Ok(Vec::new());
        }

        let mut queue: Vec<(SchemaVersion, Vec<MigrationHint>)> = vec![(from.clone(), Vec::new())];
        let mut visited = std::collections::BTreeSet::new();
        visited.insert(from.clone());

        while let Some((current, path)) = queue.first().cloned() {
            queue.remove(0);

            for hint in &self.hints {
                if hint.from_version == current && !visited.contains(&hint.to_version) {
                    let mut new_path = path.clone();
                    new_path.push(hint.clone());

                    if hint.to_version == *to {
                        return Ok(new_path);
                    }

                    visited.insert(hint.to_version.clone());
                    queue.push((hint.to_version.clone(), new_path));
                }
            }
        }

        Err(MigrationError::MigrationPathMissing {
            from: from.to_string(),
            to: to.to_string(),
        })
    }

    /// Build a migration plan from source to target.
    pub fn build_plan(
        &self,
        connector_id: &str,
        from: &SchemaVersion,
        to: &SchemaVersion,
    ) -> Result<MigrationPlan, MigrationError> {
        let steps = self.find_path(from, to)?;
        Ok(MigrationPlan {
            connector_id: connector_id.to_string(),
            from_version: from.clone(),
            to_version: to.clone(),
            steps,
        })
    }
}

/// Execute a migration plan, producing a receipt.
/// In this scaffolding, execution is simulated — real connectors would
/// apply each hint's transformation to the state data.
pub fn execute_plan(plan: &MigrationPlan, timestamp: &str) -> MigrationReceipt {
    let total = plan.steps.len();

    // Simulate execution — check that all steps are valid
    for (i, step) in plan.steps.iter().enumerate() {
        // Verify chain: each step's to_version == next step's from_version
        if i + 1 < total && step.to_version != plan.steps[i + 1].from_version {
            return MigrationReceipt {
                connector_id: plan.connector_id.clone(),
                from_version: plan.from_version.clone(),
                to_version: plan.to_version.clone(),
                outcome: MigrationOutcome::Failed {
                    reason: format!(
                        "chain break at step {}: {} -> {} but next expects {}",
                        i,
                        step.from_version,
                        step.to_version,
                        plan.steps[i + 1].from_version
                    ),
                },
                steps_applied: i,
                steps_total: total,
                timestamp: timestamp.to_string(),
            };
        }
    }

    MigrationReceipt {
        connector_id: plan.connector_id.clone(),
        from_version: plan.from_version.clone(),
        to_version: plan.to_version.clone(),
        outcome: MigrationOutcome::Applied,
        steps_applied: total,
        steps_total: total,
        timestamp: timestamp.to_string(),
    }
}

/// Check idempotency: re-applying a migration to the target version
/// returns AlreadyApplied.
pub fn check_idempotency(
    current_version: &SchemaVersion,
    hint: &MigrationHint,
) -> MigrationOutcome {
    if current_version == &hint.to_version && hint.idempotent {
        MigrationOutcome::AlreadyApplied
    } else if current_version == &hint.to_version {
        MigrationOutcome::Failed {
            reason: "migration already applied but hint is not idempotent".to_string(),
        }
    } else {
        MigrationOutcome::Applied
    }
}

/// Errors for migration operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationError {
    #[serde(rename = "MIGRATION_PATH_MISSING")]
    MigrationPathMissing { from: String, to: String },
    #[serde(rename = "MIGRATION_ALREADY_APPLIED")]
    MigrationAlreadyApplied { version: String },
    #[serde(rename = "MIGRATION_ROLLBACK_FAILED")]
    MigrationRollbackFailed { version: String, reason: String },
    #[serde(rename = "SCHEMA_VERSION_INVALID")]
    SchemaVersionInvalid { version: String, reason: String },
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MigrationPathMissing { from, to } => {
                write!(f, "MIGRATION_PATH_MISSING: no path from {from} to {to}")
            }
            Self::MigrationAlreadyApplied { version } => {
                write!(f, "MIGRATION_ALREADY_APPLIED: version {version}")
            }
            Self::MigrationRollbackFailed { version, reason } => {
                write!(f, "MIGRATION_ROLLBACK_FAILED: version {version}: {reason}")
            }
            Self::SchemaVersionInvalid { version, reason } => {
                write!(f, "SCHEMA_VERSION_INVALID: '{version}': {reason}")
            }
        }
    }
}

impl std::error::Error for MigrationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u32, minor: u32, patch: u32) -> SchemaVersion {
        SchemaVersion::new(major, minor, patch)
    }

    fn sample_registry() -> MigrationRegistry {
        let mut reg = MigrationRegistry::new();
        reg.register(MigrationHint {
            from_version: v(1, 0, 0),
            to_version: v(1, 1, 0),
            hint_type: HintType::AddField,
            description: "Add email field".into(),
            idempotent: true,
            rollback_safe: true,
        });
        reg.register(MigrationHint {
            from_version: v(1, 1, 0),
            to_version: v(1, 2, 0),
            hint_type: HintType::RenameField,
            description: "Rename name to full_name".into(),
            idempotent: true,
            rollback_safe: true,
        });
        reg.register(MigrationHint {
            from_version: v(1, 2, 0),
            to_version: v(2, 0, 0),
            hint_type: HintType::Transform,
            description: "Major schema overhaul".into(),
            idempotent: false,
            rollback_safe: false,
        });
        reg
    }

    // === Version parsing ===

    #[test]
    fn parse_valid_version() {
        let v = SchemaVersion::parse("1.2.3").unwrap();
        assert_eq!(v, SchemaVersion::new(1, 2, 3));
    }

    #[test]
    fn parse_invalid_version() {
        let err = SchemaVersion::parse("1.2").unwrap_err();
        assert!(matches!(err, MigrationError::SchemaVersionInvalid { .. }));
    }

    #[test]
    fn parse_non_numeric() {
        let err = SchemaVersion::parse("1.x.3").unwrap_err();
        assert!(matches!(err, MigrationError::SchemaVersionInvalid { .. }));
    }

    #[test]
    fn version_display() {
        assert_eq!(v(1, 2, 3).to_string(), "1.2.3");
    }

    #[test]
    fn version_is_ahead_of() {
        assert!(v(2, 0, 0).is_ahead_of(&v(1, 9, 9)));
        assert!(!v(1, 0, 0).is_ahead_of(&v(1, 0, 0)));
        assert!(!v(1, 0, 0).is_ahead_of(&v(2, 0, 0)));
    }

    // === Schema contract ===

    #[test]
    fn version_in_range_supported() {
        let contract = SchemaContract {
            connector_id: "conn-1".into(),
            current_version: v(1, 2, 0),
            min_supported: v(1, 0, 0),
            max_supported: v(2, 0, 0),
        };
        assert!(contract.is_version_supported(&v(1, 1, 0)));
        assert!(contract.is_version_supported(&v(1, 0, 0)));
        assert!(contract.is_version_supported(&v(2, 0, 0)));
    }

    #[test]
    fn version_out_of_range_unsupported() {
        let contract = SchemaContract {
            connector_id: "conn-1".into(),
            current_version: v(1, 2, 0),
            min_supported: v(1, 0, 0),
            max_supported: v(2, 0, 0),
        };
        assert!(!contract.is_version_supported(&v(0, 9, 0)));
        assert!(!contract.is_version_supported(&v(2, 0, 1)));
    }

    // === Path finding ===

    #[test]
    fn find_direct_path() {
        let reg = sample_registry();
        let path = reg.find_path(&v(1, 0, 0), &v(1, 1, 0)).unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path[0].to_version, v(1, 1, 0));
    }

    #[test]
    fn find_multi_step_path() {
        let reg = sample_registry();
        let path = reg.find_path(&v(1, 0, 0), &v(2, 0, 0)).unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0].to_version, v(1, 1, 0));
        assert_eq!(path[1].to_version, v(1, 2, 0));
        assert_eq!(path[2].to_version, v(2, 0, 0));
    }

    #[test]
    fn no_path_returns_error() {
        let reg = sample_registry();
        let err = reg.find_path(&v(1, 0, 0), &v(3, 0, 0)).unwrap_err();
        assert!(matches!(err, MigrationError::MigrationPathMissing { .. }));
    }

    #[test]
    fn same_version_empty_path() {
        let reg = sample_registry();
        let path = reg.find_path(&v(1, 0, 0), &v(1, 0, 0)).unwrap();
        assert!(path.is_empty());
    }

    // === Plan building ===

    #[test]
    fn build_plan_success() {
        let reg = sample_registry();
        let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(1, 2, 0)).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.connector_id, "conn-1");
    }

    // === Plan execution ===

    #[test]
    fn execute_valid_plan() {
        let reg = sample_registry();
        let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(2, 0, 0)).unwrap();
        let receipt = execute_plan(&plan, "2026-01-01T00:00:00Z");
        assert_eq!(receipt.outcome, MigrationOutcome::Applied);
        assert_eq!(receipt.steps_applied, 3);
    }

    #[test]
    fn execute_empty_plan() {
        let plan = MigrationPlan {
            connector_id: "conn-1".into(),
            from_version: v(1, 0, 0),
            to_version: v(1, 0, 0),
            steps: vec![],
        };
        let receipt = execute_plan(&plan, "t");
        assert_eq!(receipt.outcome, MigrationOutcome::Applied);
        assert_eq!(receipt.steps_applied, 0);
    }

    // === Idempotency ===

    #[test]
    fn idempotent_hint_already_applied() {
        let hint = MigrationHint {
            from_version: v(1, 0, 0),
            to_version: v(1, 1, 0),
            hint_type: HintType::AddField,
            description: "test".into(),
            idempotent: true,
            rollback_safe: true,
        };
        let outcome = check_idempotency(&v(1, 1, 0), &hint);
        assert_eq!(outcome, MigrationOutcome::AlreadyApplied);
    }

    #[test]
    fn non_idempotent_hint_fails_on_reapply() {
        let hint = MigrationHint {
            from_version: v(1, 0, 0),
            to_version: v(1, 1, 0),
            hint_type: HintType::Transform,
            description: "test".into(),
            idempotent: false,
            rollback_safe: false,
        };
        let outcome = check_idempotency(&v(1, 1, 0), &hint);
        assert!(matches!(outcome, MigrationOutcome::Failed { .. }));
    }

    #[test]
    fn hint_applied_at_source_version() {
        let hint = MigrationHint {
            from_version: v(1, 0, 0),
            to_version: v(1, 1, 0),
            hint_type: HintType::AddField,
            description: "test".into(),
            idempotent: true,
            rollback_safe: true,
        };
        let outcome = check_idempotency(&v(1, 0, 0), &hint);
        assert_eq!(outcome, MigrationOutcome::Applied);
    }

    // === Serde roundtrip ===

    #[test]
    fn serde_roundtrip_hint() {
        let hint = MigrationHint {
            from_version: v(1, 0, 0),
            to_version: v(1, 1, 0),
            hint_type: HintType::AddField,
            description: "Add email".into(),
            idempotent: true,
            rollback_safe: true,
        };
        let json = serde_json::to_string(&hint).unwrap();
        let parsed: MigrationHint = serde_json::from_str(&json).unwrap();
        assert_eq!(hint, parsed);
    }

    #[test]
    fn serde_roundtrip_error() {
        let err = MigrationError::MigrationPathMissing {
            from: "1.0.0".into(),
            to: "3.0.0".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: MigrationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }

    #[test]
    fn error_display_messages() {
        let e1 = MigrationError::MigrationPathMissing {
            from: "1.0.0".into(),
            to: "3.0.0".into(),
        };
        assert!(e1.to_string().contains("MIGRATION_PATH_MISSING"));

        let e2 = MigrationError::SchemaVersionInvalid {
            version: "bad".into(),
            reason: "not semver".into(),
        };
        assert!(e2.to_string().contains("SCHEMA_VERSION_INVALID"));

        let e3 = MigrationError::MigrationRollbackFailed {
            version: "1.0.0".into(),
            reason: "io error".into(),
        };
        assert!(e3.to_string().contains("MIGRATION_ROLLBACK_FAILED"));
    }
}
