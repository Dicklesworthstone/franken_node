//! State schema version contracts and deterministic migration execution.
//!
//! Version transitions require declared migration paths. Migrations are
//! idempotent, replay-stable, and failed migrations roll back cleanly.
//! This module provides version-path planning primitives plus a deterministic
//! in-memory execution engine for connector-owned state capsules.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::storage::models::SchemaMigrationRecord;

const MAX_HINTS: usize = 4096;
const MAX_STEP_RESULTS: usize = 4096;
const MAX_JOURNAL_RECORDS: usize = 4096;
const RECEIPT_SCHEMA_VERSION: &str = "franken-node/schema-migration-receipt/v1";

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
}

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

/// Deterministic mutation payload for a migration hint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MutationSpec {
    AddField {
        field: String,
        value: Value,
    },
    RemoveField {
        field: String,
    },
    RenameField {
        from: String,
        to: String,
    },
    Transform {
        field: String,
        from: Value,
        to: Value,
    },
}

impl MutationSpec {
    fn canonicalized(&self) -> Result<Self, MigrationError> {
        match self {
            Self::AddField { field, value } => Ok(Self::AddField {
                field: normalize_field_name(field)?,
                value: canonicalize_value(value, &format!("mutation.add_field.{field}"))?,
            }),
            Self::RemoveField { field } => Ok(Self::RemoveField {
                field: normalize_field_name(field)?,
            }),
            Self::RenameField { from, to } => {
                let from = normalize_field_name(from)?;
                let to = normalize_field_name(to)?;
                if from == to {
                    return Err(MigrationError::PlanNormalizationFailed {
                        reason: "rename_field must change the destination field".to_string(),
                    });
                }
                Ok(Self::RenameField { from, to })
            }
            Self::Transform { field, from, to } => Ok(Self::Transform {
                field: normalize_field_name(field)?,
                from: canonicalize_value(from, &format!("mutation.transform.{field}.from"))?,
                to: canonicalize_value(to, &format!("mutation.transform.{field}.to"))?,
            }),
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::AddField { field, value } => {
                format!("add_field:{field}={}", render_json(value))
            }
            Self::RemoveField { field } => format!("remove_field:{field}"),
            Self::RenameField { from, to } => format!("rename_field:{from}->{to}"),
            Self::Transform { field, from, to } => {
                format!(
                    "transform:{field}:{}->{}",
                    render_json(from),
                    render_json(to)
                )
            }
        }
    }

    fn precondition_summary(&self) -> String {
        match self {
            Self::AddField { field, .. } => format!("field `{field}` must be absent"),
            Self::RemoveField { field } => format!("field `{field}` must exist"),
            Self::RenameField { from, to } => {
                format!("field `{from}` must exist and `{to}` must be absent")
            }
            Self::Transform { field, from, .. } => {
                format!("field `{field}` must equal {}", render_json(from))
            }
        }
    }

    fn postcondition_summary(&self) -> String {
        match self {
            Self::AddField { field, value } => {
                format!("field `{field}` equals {}", render_json(value))
            }
            Self::RemoveField { field } => format!("field `{field}` is absent"),
            Self::RenameField { from, to } => {
                format!("field `{from}` is absent and `{to}` is present")
            }
            Self::Transform { field, to, .. } => {
                format!("field `{field}` equals {}", render_json(to))
            }
        }
    }

    fn apply_to_state(&self, state: &mut BTreeMap<String, Value>) -> Result<(), MigrationError> {
        match self {
            Self::AddField { field, value } => {
                if state.contains_key(field) {
                    return Err(MigrationError::StateConflict {
                        reason: format!("add_field conflict: `{field}` already exists"),
                    });
                }
                state.insert(field.clone(), value.clone());
                Ok(())
            }
            Self::RemoveField { field } => {
                if state.remove(field).is_none() {
                    return Err(MigrationError::StateConflict {
                        reason: format!("remove_field conflict: `{field}` is absent"),
                    });
                }
                Ok(())
            }
            Self::RenameField { from, to } => {
                if state.contains_key(to) {
                    return Err(MigrationError::StateConflict {
                        reason: format!("rename_field conflict: destination `{to}` already exists"),
                    });
                }
                let Some(value) = state.remove(from) else {
                    return Err(MigrationError::StateConflict {
                        reason: format!("rename_field conflict: source `{from}` is absent"),
                    });
                };
                state.insert(to.clone(), value);
                Ok(())
            }
            Self::Transform { field, from, to } => {
                let Some(current) = state.get(field) else {
                    return Err(MigrationError::StateConflict {
                        reason: format!("transform conflict: `{field}` is absent"),
                    });
                };
                if current != from {
                    return Err(MigrationError::StateConflict {
                        reason: format!(
                            "transform conflict: `{field}` expected {} but found {}",
                            render_json(from),
                            render_json(current)
                        ),
                    });
                }
                state.insert(field.clone(), to.clone());
                Ok(())
            }
        }
    }

    fn matches_post_state(&self, state: &BTreeMap<String, Value>) -> bool {
        match self {
            Self::AddField { field, value } => state.get(field) == Some(value),
            Self::RemoveField { field } => !state.contains_key(field),
            Self::RenameField { from, to } => !state.contains_key(from) && state.contains_key(to),
            Self::Transform { field, to, .. } => state.get(field) == Some(to),
        }
    }
}

/// A migration hint describing a single version transition step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationHint {
    pub from_version: SchemaVersion,
    pub to_version: SchemaVersion,
    pub hint_type: HintType,
    pub description: String,
    pub idempotent: bool,
    pub rollback_safe: bool,
    pub mutation: MutationSpec,
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

/// Per-step execution status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStepStatus {
    Applied,
    AlreadyApplied,
    RolledBack,
    Failed,
}

/// Rollback result for the full plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackResult {
    NotNeeded,
    RestoredCheckpoint,
    Failed { step_id: String, reason: String },
}

/// Result for a single executable migration step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStepResult {
    pub step_id: String,
    pub from_version: SchemaVersion,
    pub to_version: SchemaVersion,
    pub status: MigrationStepStatus,
    pub step_idempotency_key: String,
    pub pre_state_hash: String,
    pub post_state_hash: String,
    pub checkpoint_ref: String,
    pub journal_record_id: Option<String>,
    pub error_detail: Option<String>,
}

/// A migration plan is an ordered sequence of hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub connector_id: String,
    pub from_version: SchemaVersion,
    pub to_version: SchemaVersion,
    pub steps: Vec<MigrationHint>,
}

/// A deterministic connector-owned state capsule for schema migration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorState {
    pub connector_id: String,
    pub schema_version: SchemaVersion,
    pub canonical_state: BTreeMap<String, Value>,
    pub state_hash: String,
    pub migration_journal: Vec<SchemaMigrationRecord>,
}

impl ConnectorState {
    pub fn new(
        connector_id: impl Into<String>,
        schema_version: SchemaVersion,
        canonical_state: BTreeMap<String, Value>,
    ) -> Result<Self, MigrationError> {
        Self::with_journal(connector_id, schema_version, canonical_state, Vec::new())
    }

    pub fn with_journal(
        connector_id: impl Into<String>,
        schema_version: SchemaVersion,
        canonical_state: BTreeMap<String, Value>,
        migration_journal: Vec<SchemaMigrationRecord>,
    ) -> Result<Self, MigrationError> {
        let connector_id = connector_id.into();
        if connector_id.trim().is_empty() {
            return Err(MigrationError::StateConflict {
                reason: "connector_id cannot be empty".to_string(),
            });
        }
        let canonical_state = canonicalize_state_map(&canonical_state)?;
        let mut state = Self {
            connector_id,
            schema_version,
            canonical_state,
            state_hash: String::new(),
            migration_journal,
        };
        state.refresh_state_hash()?;
        Ok(state)
    }

    pub fn refresh_state_hash(&mut self) -> Result<(), MigrationError> {
        self.state_hash = compute_state_hash(
            &self.connector_id,
            &self.schema_version,
            &self.canonical_state,
        )?;
        Ok(())
    }
}

/// Migration receipt recording the outcome of a migration attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub receipt_schema_version: String,
    pub receipt_id: String,
    pub connector_id: String,
    pub plan_id: String,
    pub plan_idempotency_key: String,
    pub from_version: SchemaVersion,
    pub to_version: SchemaVersion,
    pub outcome: MigrationOutcome,
    pub started_at: String,
    pub completed_at: String,
    pub initial_state_hash: String,
    pub final_state_hash: String,
    pub steps_applied: usize,
    pub steps_total: usize,
    pub steps_already_applied: usize,
    pub steps_rolled_back: usize,
    pub journal_record_ids: Vec<String>,
    pub rollback_result: RollbackResult,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub step_results: Vec<MigrationStepResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutableMigrationStep {
    pub step_id: String,
    pub from_version: SchemaVersion,
    pub to_version: SchemaVersion,
    pub hint_type: HintType,
    pub idempotent: bool,
    pub rollback_safe: bool,
    pub mutation_summary: String,
    pub precondition_summary: String,
    pub rollback_descriptor: String,
    pub mutation: MutationSpec,
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
        if hint.from_version == hint.to_version {
            return;
        }
        push_bounded(&mut self.hints, hint, MAX_HINTS);
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

        let mut queue: std::collections::VecDeque<(SchemaVersion, Vec<MigrationHint>)> =
            std::collections::VecDeque::new();
        queue.push_back((from.clone(), Vec::new()));
        let mut visited = std::collections::BTreeSet::new();
        visited.insert(from.clone());

        while let Some((current, path)) = queue.pop_front() {
            for hint in &self.hints {
                if hint.from_version == current && !visited.contains(&hint.to_version) {
                    let mut new_path = path.clone();
                    new_path.push(hint.clone());

                    if hint.to_version == *to {
                        return Ok(new_path);
                    }

                    visited.insert(hint.to_version.clone());
                    queue.push_back((hint.to_version.clone(), new_path));
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

/// Execute a migration plan against a deterministic connector state capsule.
pub fn execute_plan(
    plan: &MigrationPlan,
    state: &mut ConnectorState,
    timestamp: &str,
) -> MigrationReceipt {
    let started_at = timestamp.to_string();
    let completed_at = timestamp.to_string();
    let initial_state_hash = state.state_hash.clone();
    let total = plan.steps.len();
    let original_state = state.clone();

    let normalized = match normalize_plan(plan) {
        Ok(normalized) => normalized,
        Err(error) => {
            return failed_receipt(
                plan,
                String::new(),
                String::new(),
                started_at,
                completed_at,
                initial_state_hash.clone(),
                initial_state_hash,
                total,
                0,
                0,
                0,
                Vec::new(),
                RollbackResult::NotNeeded,
                Vec::new(),
                error,
            );
        }
    };

    let plan_id = compute_plan_id(plan, &normalized);
    let plan_idempotency_key = compute_plan_idempotency_key(&plan_id, &normalized);

    if state.connector_id != plan.connector_id {
        return failed_receipt(
            plan,
            plan_id,
            plan_idempotency_key,
            started_at,
            completed_at,
            initial_state_hash.clone(),
            initial_state_hash,
            total,
            0,
            0,
            0,
            Vec::new(),
            RollbackResult::NotNeeded,
            Vec::new(),
            MigrationError::StateConflict {
                reason: format!(
                    "connector mismatch: plan targets `{}` but state belongs to `{}`",
                    plan.connector_id, state.connector_id
                ),
            },
        );
    }

    if total == 0 {
        if state.schema_version != plan.from_version {
            return failed_receipt(
                plan,
                plan_id,
                plan_idempotency_key,
                started_at,
                completed_at,
                initial_state_hash.clone(),
                initial_state_hash,
                total,
                0,
                0,
                0,
                Vec::new(),
                RollbackResult::NotNeeded,
                Vec::new(),
                MigrationError::StateConflict {
                    reason: format!(
                        "empty plan requires state version {} but found {}",
                        plan.from_version, state.schema_version
                    ),
                },
            );
        }

        return applied_receipt(
            plan,
            &plan_id,
            &plan_idempotency_key,
            started_at,
            completed_at,
            initial_state_hash.clone(),
            initial_state_hash,
            total,
            0,
            0,
            0,
            Vec::new(),
            RollbackResult::NotNeeded,
            Vec::new(),
            MigrationOutcome::Applied,
        );
    }

    if state.schema_version == plan.to_version {
        if plan_replay_proven(state, &normalized) {
            let journal_record_ids = normalized
                .iter()
                .map(|step| step.step_id.clone())
                .collect::<Vec<_>>();
            let step_results = normalized
                .iter()
                .map(|step| MigrationStepResult {
                    step_id: step.step_id.clone(),
                    from_version: step.from_version.clone(),
                    to_version: step.to_version.clone(),
                    status: MigrationStepStatus::AlreadyApplied,
                    step_idempotency_key: compute_step_idempotency_key(
                        &plan_idempotency_key,
                        &step.step_id,
                        &state.state_hash,
                    ),
                    pre_state_hash: state.state_hash.clone(),
                    post_state_hash: state.state_hash.clone(),
                    checkpoint_ref: format!("checkpoint:{}", state.state_hash),
                    journal_record_id: Some(step.step_id.clone()),
                    error_detail: None,
                })
                .collect::<Vec<_>>();
            return applied_receipt(
                plan,
                &plan_id,
                &plan_idempotency_key,
                started_at,
                completed_at,
                initial_state_hash.clone(),
                initial_state_hash,
                total,
                0,
                total,
                0,
                journal_record_ids,
                RollbackResult::NotNeeded,
                step_results,
                MigrationOutcome::AlreadyApplied,
            );
        }

        return failed_receipt(
            plan,
            plan_id,
            plan_idempotency_key,
            started_at,
            completed_at,
            initial_state_hash.clone(),
            initial_state_hash,
            total,
            0,
            0,
            0,
            Vec::new(),
            RollbackResult::NotNeeded,
            Vec::new(),
            MigrationError::StateConflict {
                reason: format!(
                    "target version {} is present without journal/hash proof for plan replay",
                    plan.to_version
                ),
            },
        );
    }

    if state.schema_version != plan.from_version {
        return failed_receipt(
            plan,
            plan_id,
            plan_idempotency_key,
            started_at,
            completed_at,
            initial_state_hash.clone(),
            initial_state_hash,
            total,
            0,
            0,
            0,
            Vec::new(),
            RollbackResult::NotNeeded,
            Vec::new(),
            MigrationError::StateConflict {
                reason: format!(
                    "plan expects state version {} but found {}",
                    plan.from_version, state.schema_version
                ),
            },
        );
    }

    let mut steps_applied = 0;
    let mut steps_already_applied = 0;
    let mut step_results = Vec::new();
    let mut journal_record_ids = Vec::new();

    for step in &normalized {
        let checkpoint_ref = format!("checkpoint:{}", state.state_hash);
        let pre_state_hash = state.state_hash.clone();
        let step_idempotency_key =
            compute_step_idempotency_key(&plan_idempotency_key, &step.step_id, &pre_state_hash);

        if step_already_applied(state, step) {
            steps_already_applied += 1;
            push_bounded(
                &mut step_results,
                MigrationStepResult {
                    step_id: step.step_id.clone(),
                    from_version: step.from_version.clone(),
                    to_version: step.to_version.clone(),
                    status: MigrationStepStatus::AlreadyApplied,
                    step_idempotency_key,
                    pre_state_hash: pre_state_hash.clone(),
                    post_state_hash: pre_state_hash.clone(),
                    checkpoint_ref,
                    journal_record_id: Some(step.step_id.clone()),
                    error_detail: None,
                },
                MAX_STEP_RESULTS,
            );
            journal_record_ids.push(step.step_id.clone());
            continue;
        }

        if state.schema_version != step.from_version {
            push_bounded(
                &mut step_results,
                MigrationStepResult {
                    step_id: step.step_id.clone(),
                    from_version: step.from_version.clone(),
                    to_version: step.to_version.clone(),
                    status: MigrationStepStatus::Failed,
                    step_idempotency_key,
                    pre_state_hash: pre_state_hash.clone(),
                    post_state_hash: pre_state_hash.clone(),
                    checkpoint_ref,
                    journal_record_id: None,
                    error_detail: Some(format!(
                        "step expected schema version {} but found {}",
                        step.from_version, state.schema_version
                    )),
                },
                MAX_STEP_RESULTS,
            );
            return rollback_or_fail_receipt(
                plan,
                state,
                original_state,
                plan_id,
                plan_idempotency_key,
                started_at,
                completed_at,
                initial_state_hash,
                total,
                steps_applied,
                steps_already_applied,
                step_results,
                journal_record_ids,
                MigrationError::StateConflict {
                    reason: format!(
                        "step `{}` expected schema version {} but found {}",
                        step.step_id, step.from_version, state.schema_version
                    ),
                },
            );
        }

        let checkpoint = state.clone();
        match apply_executable_step(state, step, timestamp) {
            Ok(record) => {
                steps_applied += 1;
                let post_state_hash = state.state_hash.clone();
                let journal_record_id = record.migration_id.clone();
                push_bounded(&mut state.migration_journal, record, MAX_JOURNAL_RECORDS);
                push_bounded(
                    &mut step_results,
                    MigrationStepResult {
                        step_id: step.step_id.clone(),
                        from_version: step.from_version.clone(),
                        to_version: step.to_version.clone(),
                        status: MigrationStepStatus::Applied,
                        step_idempotency_key,
                        pre_state_hash,
                        post_state_hash: post_state_hash.clone(),
                        checkpoint_ref,
                        journal_record_id: Some(journal_record_id.clone()),
                        error_detail: None,
                    },
                    MAX_STEP_RESULTS,
                );
                journal_record_ids.push(journal_record_id);
                let _ = checkpoint;
            }
            Err(error) => {
                *state = checkpoint;
                push_bounded(
                    &mut step_results,
                    MigrationStepResult {
                        step_id: step.step_id.clone(),
                        from_version: step.from_version.clone(),
                        to_version: step.to_version.clone(),
                        status: MigrationStepStatus::Failed,
                        step_idempotency_key,
                        pre_state_hash: pre_state_hash.clone(),
                        post_state_hash: pre_state_hash,
                        checkpoint_ref,
                        journal_record_id: None,
                        error_detail: Some(error.to_string()),
                    },
                    MAX_STEP_RESULTS,
                );
                return rollback_or_fail_receipt(
                    plan,
                    state,
                    original_state,
                    plan_id,
                    plan_idempotency_key,
                    started_at,
                    completed_at,
                    initial_state_hash,
                    total,
                    steps_applied,
                    steps_already_applied,
                    step_results,
                    journal_record_ids,
                    error,
                );
            }
        }
    }

    applied_receipt(
        plan,
        &plan_id,
        &plan_idempotency_key,
        started_at,
        completed_at,
        initial_state_hash,
        state.state_hash.clone(),
        total,
        steps_applied,
        steps_already_applied,
        0,
        journal_record_ids,
        RollbackResult::NotNeeded,
        step_results,
        MigrationOutcome::Applied,
    )
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
    #[serde(rename = "MIGRATION_PLAN_INVALID")]
    PlanNormalizationFailed { reason: String },
    #[serde(rename = "MIGRATION_STATE_CONFLICT")]
    StateConflict { reason: String },
    #[serde(rename = "MIGRATION_STATE_NON_DETERMINISTIC")]
    NonDeterministicState { path: String },
    #[serde(rename = "MIGRATION_STEP_NOT_EXECUTABLE")]
    StepNotExecutable { step_id: String, reason: String },
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
            Self::PlanNormalizationFailed { reason } => {
                write!(f, "MIGRATION_PLAN_INVALID: {reason}")
            }
            Self::StateConflict { reason } => {
                write!(f, "MIGRATION_STATE_CONFLICT: {reason}")
            }
            Self::NonDeterministicState { path } => {
                write!(
                    f,
                    "MIGRATION_STATE_NON_DETERMINISTIC: non-canonical value at `{path}`"
                )
            }
            Self::StepNotExecutable { step_id, reason } => {
                write!(f, "MIGRATION_STEP_NOT_EXECUTABLE: {step_id}: {reason}")
            }
        }
    }
}

impl std::error::Error for MigrationError {}

impl MigrationError {
    fn code(&self) -> &'static str {
        match self {
            Self::MigrationPathMissing { .. } => "MIGRATION_PATH_MISSING",
            Self::MigrationAlreadyApplied { .. } => "MIGRATION_ALREADY_APPLIED",
            Self::MigrationRollbackFailed { .. } => "MIGRATION_ROLLBACK_FAILED",
            Self::SchemaVersionInvalid { .. } => "SCHEMA_VERSION_INVALID",
            Self::PlanNormalizationFailed { .. } => "MIGRATION_PLAN_INVALID",
            Self::StateConflict { .. } => "MIGRATION_STATE_CONFLICT",
            Self::NonDeterministicState { .. } => "MIGRATION_STATE_NON_DETERMINISTIC",
            Self::StepNotExecutable { .. } => "MIGRATION_STEP_NOT_EXECUTABLE",
        }
    }
}

fn normalize_field_name(field: &str) -> Result<String, MigrationError> {
    let trimmed = field.trim();
    if trimmed.is_empty() {
        return Err(MigrationError::PlanNormalizationFailed {
            reason: "mutation field names cannot be empty".to_string(),
        });
    }
    Ok(trimmed.to_string())
}

fn canonicalize_state_map(
    state: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, MigrationError> {
    state
        .iter()
        .map(|(key, value)| {
            Ok((
                normalize_field_name(key)?,
                canonicalize_value(value, &format!("state.{key}"))?,
            ))
        })
        .collect()
}

fn canonicalize_value(value: &Value, path: &str) -> Result<Value, MigrationError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(value.clone()),
        Value::Number(number) => {
            if number.is_f64() {
                return Err(MigrationError::NonDeterministicState {
                    path: path.to_string(),
                });
            }
            Ok(value.clone())
        }
        Value::Array(values) => Ok(Value::Array(
            values
                .iter()
                .enumerate()
                .map(|(index, item)| canonicalize_value(item, &format!("{path}[{index}]")))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Object(map) => {
            let ordered_keys = map
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            let mut ordered = serde_json::Map::new();
            for key in ordered_keys {
                let Some(value) = map.get(&key) else {
                    continue;
                };
                ordered.insert(
                    key.clone(),
                    canonicalize_value(value, &format!("{path}.{key}"))?,
                );
            }
            Ok(Value::Object(ordered))
        }
    }
}

fn render_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn stable_digest(prefix: &str, parts: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update((parts.len() as u64).to_le_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn compute_state_hash(
    connector_id: &str,
    schema_version: &SchemaVersion,
    state: &BTreeMap<String, Value>,
) -> Result<String, MigrationError> {
    let canonical = canonicalize_state_map(state)?;
    let serialized =
        serde_json::to_vec(&canonical).map_err(|err| MigrationError::StateConflict {
            reason: format!("failed serializing canonical state: {err}"),
        })?;
    let mut hasher = Sha256::new();
    hasher.update(b"schema_migration_state_v1:");
    hasher.update((connector_id.len() as u64).to_le_bytes());
    hasher.update(connector_id.as_bytes());
    hasher.update(schema_version.to_string().as_bytes());
    hasher.update((serialized.len() as u64).to_le_bytes());
    hasher.update(serialized);
    Ok(hex::encode(hasher.finalize()))
}

fn normalize_plan(plan: &MigrationPlan) -> Result<Vec<ExecutableMigrationStep>, MigrationError> {
    let mut executable = Vec::with_capacity(plan.steps.len());
    for hint in &plan.steps {
        if hint.description.trim().is_empty() {
            return Err(MigrationError::PlanNormalizationFailed {
                reason: format!(
                    "migration step {} -> {} must have a description",
                    hint.from_version, hint.to_version
                ),
            });
        }
        if hint.from_version == hint.to_version {
            return Err(MigrationError::PlanNormalizationFailed {
                reason: format!(
                    "migration step `{}` -> `{}` cannot be a self-loop",
                    hint.from_version, hint.to_version
                ),
            });
        }
        let mutation = hint.mutation.canonicalized()?;
        let mutation_summary = mutation.summary();
        let step_id = stable_digest(
            "schema_migration_step_v1:",
            &[
                plan.connector_id.clone(),
                hint.from_version.to_string(),
                hint.to_version.to_string(),
                hint.hint_type.to_string(),
                hint.description.clone(),
                mutation_summary.clone(),
            ],
        );
        executable.push(ExecutableMigrationStep {
            step_id,
            from_version: hint.from_version.clone(),
            to_version: hint.to_version.clone(),
            hint_type: hint.hint_type.clone(),
            idempotent: hint.idempotent,
            rollback_safe: hint.rollback_safe,
            mutation_summary,
            precondition_summary: mutation.precondition_summary(),
            rollback_descriptor: if hint.rollback_safe {
                "checkpoint_restore".to_string()
            } else {
                "rollback_unavailable".to_string()
            },
            mutation,
        });
    }

    if executable.is_empty() && plan.from_version != plan.to_version {
        return Err(MigrationError::PlanNormalizationFailed {
            reason: format!(
                "non-empty migration range {} -> {} requires at least one step",
                plan.from_version, plan.to_version
            ),
        });
    }

    if let Some(first) = executable.first()
        && first.from_version != plan.from_version
    {
        return Err(MigrationError::PlanNormalizationFailed {
            reason: format!(
                "first step starts at {} but plan starts at {}",
                first.from_version, plan.from_version
            ),
        });
    }

    if let Some(last) = executable.last()
        && last.to_version != plan.to_version
    {
        return Err(MigrationError::PlanNormalizationFailed {
            reason: format!(
                "last step ends at {} but plan ends at {}",
                last.to_version, plan.to_version
            ),
        });
    }

    for window in executable.windows(2) {
        if window[0].to_version != window[1].from_version {
            return Err(MigrationError::PlanNormalizationFailed {
                reason: format!(
                    "chain break: {} -> {} but next step expects {}",
                    window[0].from_version, window[0].to_version, window[1].from_version
                ),
            });
        }
    }

    for step in &executable {
        if !step.rollback_safe {
            return Err(MigrationError::StepNotExecutable {
                step_id: step.step_id.clone(),
                reason: "rollback_safe=false steps cannot enter the live executor".to_string(),
            });
        }
    }

    Ok(executable)
}

fn compute_plan_id(plan: &MigrationPlan, steps: &[ExecutableMigrationStep]) -> String {
    let mut parts = vec![
        plan.connector_id.clone(),
        plan.from_version.to_string(),
        plan.to_version.to_string(),
    ];
    parts.extend(steps.iter().map(|step| step.step_id.clone()));
    stable_digest("schema_migration_plan_v1:", &parts)
}

fn compute_plan_idempotency_key(plan_id: &str, steps: &[ExecutableMigrationStep]) -> String {
    let mut parts = vec![plan_id.to_string()];
    parts.extend(steps.iter().map(|step| step.step_id.clone()));
    stable_digest("schema_migration_plan_idempotency_v1:", &parts)
}

fn compute_step_idempotency_key(
    plan_idempotency_key: &str,
    step_id: &str,
    pre_state_hash: &str,
) -> String {
    stable_digest(
        "schema_migration_step_idempotency_v1:",
        &[
            plan_idempotency_key.to_string(),
            step_id.to_string(),
            pre_state_hash.to_string(),
        ],
    )
}

fn compute_receipt_id(
    connector_id: &str,
    plan_id: &str,
    initial_state_hash: &str,
    final_state_hash: &str,
    outcome: &MigrationOutcome,
    step_results: &[MigrationStepResult],
    completed_at: &str,
) -> String {
    stable_digest(
        "schema_migration_receipt_v1:",
        &[
            connector_id.to_string(),
            plan_id.to_string(),
            initial_state_hash.to_string(),
            final_state_hash.to_string(),
            serde_json::to_string(outcome).unwrap_or_else(|_| "\"failed\"".to_string()),
            serde_json::to_string(step_results).unwrap_or_else(|_| "[]".to_string()),
            completed_at.to_string(),
        ],
    )
}

fn plan_replay_proven(state: &ConnectorState, steps: &[ExecutableMigrationStep]) -> bool {
    let mut last_checksum = None::<String>;
    for step in steps {
        let Some(record) = state
            .migration_journal
            .iter()
            .rev()
            .find(|record| record.migration_id == step.step_id)
        else {
            return false;
        };
        if record.version_from != step.from_version.to_string()
            || record.version_to != step.to_version.to_string()
        {
            return false;
        }
        last_checksum = Some(record.checksum.clone());
    }

    last_checksum.is_some_and(|checksum| checksum == state.state_hash)
}

fn step_already_applied(state: &ConnectorState, step: &ExecutableMigrationStep) -> bool {
    if !step.idempotent || state.schema_version != step.to_version {
        return false;
    }

    state
        .migration_journal
        .iter()
        .rev()
        .find(|record| record.migration_id == step.step_id)
        .is_some_and(|record| record.checksum == state.state_hash)
}

fn apply_executable_step(
    state: &mut ConnectorState,
    step: &ExecutableMigrationStep,
    timestamp: &str,
) -> Result<SchemaMigrationRecord, MigrationError> {
    step.mutation.apply_to_state(&mut state.canonical_state)?;
    state.schema_version = step.to_version.clone();
    state.refresh_state_hash()?;

    if !step.mutation.matches_post_state(&state.canonical_state) {
        return Err(MigrationError::StateConflict {
            reason: format!(
                "postcondition failed for step `{}`: {}",
                step.step_id,
                step.mutation.postcondition_summary()
            ),
        });
    }

    Ok(SchemaMigrationRecord {
        migration_id: step.step_id.clone(),
        version_from: step.from_version.to_string(),
        version_to: step.to_version.to_string(),
        applied_at: timestamp.to_string(),
        checksum: state.state_hash.clone(),
        reversible: step.rollback_safe,
    })
}

#[allow(clippy::too_many_arguments)]
fn applied_receipt(
    plan: &MigrationPlan,
    plan_id: &str,
    plan_idempotency_key: &str,
    started_at: String,
    completed_at: String,
    initial_state_hash: String,
    final_state_hash: String,
    steps_total: usize,
    steps_applied: usize,
    steps_already_applied: usize,
    steps_rolled_back: usize,
    journal_record_ids: Vec<String>,
    rollback_result: RollbackResult,
    step_results: Vec<MigrationStepResult>,
    outcome: MigrationOutcome,
) -> MigrationReceipt {
    let receipt_id = compute_receipt_id(
        &plan.connector_id,
        plan_id,
        &initial_state_hash,
        &final_state_hash,
        &outcome,
        &step_results,
        &completed_at,
    );
    MigrationReceipt {
        receipt_schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id,
        connector_id: plan.connector_id.clone(),
        plan_id: plan_id.to_string(),
        plan_idempotency_key: plan_idempotency_key.to_string(),
        from_version: plan.from_version.clone(),
        to_version: plan.to_version.clone(),
        outcome,
        started_at,
        completed_at,
        initial_state_hash,
        final_state_hash,
        steps_applied,
        steps_total,
        steps_already_applied,
        steps_rolled_back,
        journal_record_ids,
        rollback_result,
        error_code: None,
        error_detail: None,
        step_results,
    }
}

#[allow(clippy::too_many_arguments)]
fn failed_receipt(
    plan: &MigrationPlan,
    plan_id: String,
    plan_idempotency_key: String,
    started_at: String,
    completed_at: String,
    initial_state_hash: String,
    final_state_hash: String,
    steps_total: usize,
    steps_applied: usize,
    steps_already_applied: usize,
    steps_rolled_back: usize,
    journal_record_ids: Vec<String>,
    rollback_result: RollbackResult,
    step_results: Vec<MigrationStepResult>,
    error: MigrationError,
) -> MigrationReceipt {
    let outcome = MigrationOutcome::Failed {
        reason: error.to_string(),
    };
    let receipt_id = compute_receipt_id(
        &plan.connector_id,
        &plan_id,
        &initial_state_hash,
        &final_state_hash,
        &outcome,
        &step_results,
        &completed_at,
    );
    MigrationReceipt {
        receipt_schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id,
        connector_id: plan.connector_id.clone(),
        plan_id,
        plan_idempotency_key,
        from_version: plan.from_version.clone(),
        to_version: plan.to_version.clone(),
        outcome,
        started_at,
        completed_at,
        initial_state_hash,
        final_state_hash,
        steps_applied,
        steps_total,
        steps_already_applied,
        steps_rolled_back,
        journal_record_ids,
        rollback_result,
        error_code: Some(error.code().to_string()),
        error_detail: Some(error.to_string()),
        step_results,
    }
}

#[allow(clippy::too_many_arguments)]
fn rollback_or_fail_receipt(
    plan: &MigrationPlan,
    state: &mut ConnectorState,
    original_state: ConnectorState,
    plan_id: String,
    plan_idempotency_key: String,
    started_at: String,
    completed_at: String,
    initial_state_hash: String,
    steps_total: usize,
    steps_applied: usize,
    steps_already_applied: usize,
    mut step_results: Vec<MigrationStepResult>,
    journal_record_ids: Vec<String>,
    error: MigrationError,
) -> MigrationReceipt {
    if steps_applied == 0 {
        return failed_receipt(
            plan,
            plan_id,
            plan_idempotency_key,
            started_at,
            completed_at,
            initial_state_hash.clone(),
            initial_state_hash,
            steps_total,
            steps_applied,
            steps_already_applied,
            0,
            journal_record_ids,
            RollbackResult::NotNeeded,
            step_results,
            error,
        );
    }

    let restored_hash = match compute_state_hash(
        &original_state.connector_id,
        &original_state.schema_version,
        &original_state.canonical_state,
    ) {
        Ok(hash) if hash == original_state.state_hash => hash,
        Ok(_) | Err(_) => {
            return failed_receipt(
                plan,
                plan_id,
                plan_idempotency_key,
                started_at,
                completed_at,
                initial_state_hash.clone(),
                state.state_hash.clone(),
                steps_total,
                steps_applied,
                steps_already_applied,
                0,
                journal_record_ids,
                RollbackResult::Failed {
                    step_id: step_results
                        .last()
                        .map(|result| result.step_id.clone())
                        .unwrap_or_default(),
                    reason: "failed validating rollback checkpoint integrity".to_string(),
                },
                step_results,
                MigrationError::MigrationRollbackFailed {
                    version: plan.to_version.to_string(),
                    reason: "failed validating rollback checkpoint integrity".to_string(),
                },
            );
        }
    };

    *state = original_state;
    for result in &mut step_results {
        if result.status == MigrationStepStatus::Applied {
            result.status = MigrationStepStatus::RolledBack;
            result.post_state_hash = restored_hash.clone();
        }
    }

    let receipt_id = compute_receipt_id(
        &plan.connector_id,
        &plan_id,
        &initial_state_hash,
        &restored_hash,
        &MigrationOutcome::RolledBack,
        &step_results,
        &completed_at,
    );
    MigrationReceipt {
        receipt_schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id,
        connector_id: plan.connector_id.clone(),
        plan_id,
        plan_idempotency_key,
        from_version: plan.from_version.clone(),
        to_version: plan.to_version.clone(),
        outcome: MigrationOutcome::RolledBack,
        started_at,
        completed_at,
        initial_state_hash,
        final_state_hash: restored_hash,
        steps_applied,
        steps_total,
        steps_already_applied,
        steps_rolled_back: steps_applied,
        journal_record_ids,
        rollback_result: RollbackResult::RestoredCheckpoint,
        error_code: Some(error.code().to_string()),
        error_detail: Some(error.to_string()),
        step_results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(major: u32, minor: u32, patch: u32) -> SchemaVersion {
        SchemaVersion::new(major, minor, patch)
    }

    fn sample_state() -> ConnectorState {
        ConnectorState::new(
            "conn-1",
            v(1, 0, 0),
            BTreeMap::from([
                ("name".to_string(), json!("Ada Lovelace")),
                ("profile_version".to_string(), json!(1)),
            ]),
        )
        .expect("state should build")
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
            mutation: MutationSpec::AddField {
                field: "email".into(),
                value: json!("unknown@example.invalid"),
            },
        });
        reg.register(MigrationHint {
            from_version: v(1, 1, 0),
            to_version: v(1, 2, 0),
            hint_type: HintType::RenameField,
            description: "Rename name to full_name".into(),
            idempotent: true,
            rollback_safe: true,
            mutation: MutationSpec::RenameField {
                from: "name".into(),
                to: "full_name".into(),
            },
        });
        reg.register(MigrationHint {
            from_version: v(1, 2, 0),
            to_version: v(2, 0, 0),
            hint_type: HintType::Transform,
            description: "Major schema overhaul".into(),
            idempotent: true,
            rollback_safe: true,
            mutation: MutationSpec::Transform {
                field: "profile_version".into(),
                from: json!(1),
                to: json!(2),
            },
        });
        reg
    }

    #[test]
    fn parse_valid_version() {
        let version = SchemaVersion::parse("1.2.3").unwrap();
        assert_eq!(version, SchemaVersion::new(1, 2, 3));
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

    #[test]
    fn build_plan_success() {
        let reg = sample_registry();
        let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(1, 2, 0)).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.connector_id, "conn-1");
    }

    #[test]
    fn execute_valid_plan() {
        let reg = sample_registry();
        let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(2, 0, 0)).unwrap();
        let mut state = sample_state();
        let receipt = execute_plan(&plan, &mut state, "2026-01-01T00:00:00Z");
        assert_eq!(receipt.outcome, MigrationOutcome::Applied);
        assert_eq!(receipt.steps_applied, 3);
        assert_eq!(state.schema_version, v(2, 0, 0));
        assert_eq!(state.canonical_state.get("name"), None);
        assert_eq!(
            state.canonical_state.get("full_name"),
            Some(&json!("Ada Lovelace"))
        );
        assert_eq!(
            state.canonical_state.get("email"),
            Some(&json!("unknown@example.invalid"))
        );
        assert_eq!(
            state.canonical_state.get("profile_version"),
            Some(&json!(2))
        );
        assert_eq!(state.migration_journal.len(), 3);
    }

    #[test]
    fn execute_empty_plan() {
        let plan = MigrationPlan {
            connector_id: "conn-1".into(),
            from_version: v(1, 0, 0),
            to_version: v(1, 0, 0),
            steps: vec![],
        };
        let mut state = sample_state();
        let receipt = execute_plan(&plan, &mut state, "t");
        assert_eq!(receipt.outcome, MigrationOutcome::Applied);
        assert_eq!(receipt.steps_applied, 0);
    }

    #[test]
    fn execute_rejects_rollback_unsafe_steps() {
        let plan = MigrationPlan {
            connector_id: "conn-1".into(),
            from_version: v(1, 0, 0),
            to_version: v(1, 1, 0),
            steps: vec![MigrationHint {
                from_version: v(1, 0, 0),
                to_version: v(1, 1, 0),
                hint_type: HintType::Transform,
                description: "Unsafe transform".into(),
                idempotent: false,
                rollback_safe: false,
                mutation: MutationSpec::Transform {
                    field: "profile_version".into(),
                    from: json!(1),
                    to: json!(2),
                },
            }],
        };
        let mut state = sample_state();
        let receipt = execute_plan(&plan, &mut state, "2026-01-01T00:00:00Z");
        assert!(matches!(receipt.outcome, MigrationOutcome::Failed { .. }));
        assert_eq!(
            receipt.error_code.as_deref(),
            Some("MIGRATION_STEP_NOT_EXECUTABLE")
        );
        assert_eq!(state.schema_version, v(1, 0, 0));
    }

    #[test]
    fn mid_plan_failure_rolls_back_prior_steps() {
        let plan = MigrationPlan {
            connector_id: "conn-1".into(),
            from_version: v(1, 0, 0),
            to_version: v(1, 2, 0),
            steps: vec![
                MigrationHint {
                    from_version: v(1, 0, 0),
                    to_version: v(1, 1, 0),
                    hint_type: HintType::AddField,
                    description: "Add email".into(),
                    idempotent: true,
                    rollback_safe: true,
                    mutation: MutationSpec::AddField {
                        field: "email".into(),
                        value: json!("unknown@example.invalid"),
                    },
                },
                MigrationHint {
                    from_version: v(1, 1, 0),
                    to_version: v(1, 2, 0),
                    hint_type: HintType::RenameField,
                    description: "Rename a missing field".into(),
                    idempotent: true,
                    rollback_safe: true,
                    mutation: MutationSpec::RenameField {
                        from: "missing_name".into(),
                        to: "full_name".into(),
                    },
                },
            ],
        };
        let mut state = sample_state();
        let original = state.clone();
        let receipt = execute_plan(&plan, &mut state, "2026-01-01T00:00:00Z");
        assert_eq!(receipt.outcome, MigrationOutcome::RolledBack);
        assert_eq!(receipt.steps_applied, 1);
        assert_eq!(receipt.steps_rolled_back, 1);
        assert_eq!(receipt.rollback_result, RollbackResult::RestoredCheckpoint);
        assert_eq!(state, original);
        assert!(
            receipt
                .step_results
                .iter()
                .any(|result| result.status == MigrationStepStatus::RolledBack)
        );
        assert!(
            receipt
                .step_results
                .iter()
                .any(|result| result.status == MigrationStepStatus::Failed)
        );
    }

    #[test]
    fn plan_replay_requires_journal_and_hash_proof() {
        let reg = sample_registry();
        let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(2, 0, 0)).unwrap();
        let mut state = sample_state();
        let first = execute_plan(&plan, &mut state, "2026-01-01T00:00:00Z");
        assert_eq!(first.outcome, MigrationOutcome::Applied);
        let second = execute_plan(&plan, &mut state, "2026-01-01T00:00:00Z");
        assert_eq!(second.outcome, MigrationOutcome::AlreadyApplied);
        assert_eq!(second.steps_already_applied, 3);
    }

    #[test]
    fn target_version_without_journal_proof_fails_closed() {
        let reg = sample_registry();
        let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(2, 0, 0)).unwrap();
        let mut state = ConnectorState::new(
            "conn-1",
            v(2, 0, 0),
            BTreeMap::from([
                ("email".to_string(), json!("unknown@example.invalid")),
                ("full_name".to_string(), json!("Ada Lovelace")),
                ("profile_version".to_string(), json!(2)),
            ]),
        )
        .unwrap();
        let receipt = execute_plan(&plan, &mut state, "2026-01-01T00:00:00Z");
        assert!(matches!(receipt.outcome, MigrationOutcome::Failed { .. }));
        assert_eq!(
            receipt.error_code.as_deref(),
            Some("MIGRATION_STATE_CONFLICT")
        );
    }

    #[test]
    fn idempotent_hint_already_applied() {
        let hint = MigrationHint {
            from_version: v(1, 0, 0),
            to_version: v(1, 1, 0),
            hint_type: HintType::AddField,
            description: "test".into(),
            idempotent: true,
            rollback_safe: true,
            mutation: MutationSpec::AddField {
                field: "email".into(),
                value: json!("test@example.invalid"),
            },
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
            rollback_safe: true,
            mutation: MutationSpec::Transform {
                field: "profile_version".into(),
                from: json!(1),
                to: json!(2),
            },
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
            mutation: MutationSpec::AddField {
                field: "email".into(),
                value: json!("test@example.invalid"),
            },
        };
        let outcome = check_idempotency(&v(1, 0, 0), &hint);
        assert_eq!(outcome, MigrationOutcome::Applied);
    }

    #[test]
    fn serde_roundtrip_hint() {
        let hint = MigrationHint {
            from_version: v(1, 0, 0),
            to_version: v(1, 1, 0),
            hint_type: HintType::AddField,
            description: "Add email".into(),
            idempotent: true,
            rollback_safe: true,
            mutation: MutationSpec::AddField {
                field: "email".into(),
                value: json!("add@example.invalid"),
            },
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
    fn migration_receipt_serde() {
        let reg = sample_registry();
        let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(1, 2, 0)).unwrap();
        let mut state = sample_state();
        let receipt = execute_plan(&plan, &mut state, "2026-01-01T00:00:00Z");
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: MigrationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "conn-1");
        assert_eq!(parsed.steps_applied, 2);
        assert_eq!(parsed.receipt_schema_version, RECEIPT_SCHEMA_VERSION);
    }

    #[test]
    fn connector_state_rejects_floats() {
        let state = ConnectorState::new(
            "conn-1",
            v(1, 0, 0),
            BTreeMap::from([("risk".to_string(), json!(1.25))]),
        );
        assert!(matches!(
            state.unwrap_err(),
            MigrationError::NonDeterministicState { .. }
        ));
    }

    #[test]
    fn normalize_plan_rejects_chain_breaks() {
        let plan = MigrationPlan {
            connector_id: "conn-1".into(),
            from_version: v(1, 0, 0),
            to_version: v(1, 3, 0),
            steps: vec![
                MigrationHint {
                    from_version: v(1, 0, 0),
                    to_version: v(1, 1, 0),
                    hint_type: HintType::AddField,
                    description: "step one".into(),
                    idempotent: true,
                    rollback_safe: true,
                    mutation: MutationSpec::AddField {
                        field: "email".into(),
                        value: json!("unknown@example.invalid"),
                    },
                },
                MigrationHint {
                    from_version: v(1, 2, 0),
                    to_version: v(1, 3, 0),
                    hint_type: HintType::RemoveField,
                    description: "step two".into(),
                    idempotent: true,
                    rollback_safe: true,
                    mutation: MutationSpec::RemoveField {
                        field: "email".into(),
                    },
                },
            ],
        };
        let err = normalize_plan(&plan).unwrap_err();
        assert!(matches!(
            err,
            MigrationError::PlanNormalizationFailed { .. }
        ));
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
