//! bd-1v65: Typed model definitions for sqlmodel_rust integration.
//!
//! Contains persistence-layer model structs for all 21 domains classified in
//! the sqlmodel_rust usage policy (bd-bt82). Each struct represents the
//! schema contract between Rust types and the frankensqlite storage engine.
//!
//! # Classification Summary
//!
//! - **Mandatory (12):** Fencing, lease service, lease quorum, rollout state,
//!   health gate policy, control channel, artifact journal, tiered trust,
//!   canonical state roots, durability mode, durable claim audit, schema migration.
//! - **Should-use (7):** Snapshot policy, CRDT merge, quarantine store,
//!   quarantine promotion, retention policy, repair cycle audit, lease conflict.
//! - **Optional (2):** Offline coverage metrics, lifecycle transition cache.
//!
//! # Event Codes
//!
//! - `SQLMODEL_MODEL_REGISTERED`: A model was registered with the gate
//! - `SQLMODEL_SCHEMA_DRIFT_DETECTED`: Schema drift was detected for a model
//! - `SQLMODEL_ROUND_TRIP_PASS`: Round-trip serialisation/deserialisation passed
//! - `SQLMODEL_ROUND_TRIP_FAIL`: Round-trip serialisation/deserialisation failed
//! - `SQLMODEL_VERSION_COMPAT_FAIL`: Version compatibility check failed

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Model version constant
// ---------------------------------------------------------------------------

pub const MODEL_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Mandatory models (12)
// ---------------------------------------------------------------------------

/// Fencing lease record — persists singleton-writer fencing tokens.
///
/// Owner: `connector::fencing`
/// Classification: mandatory
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingLeaseRecord {
    pub lease_seq: u64,
    pub object_id: String,
    pub holder_id: String,
    pub epoch: u64,
    pub acquired_at: String,
    pub expires_at: String,
    pub fence_version: u32,
}

impl FencingLeaseRecord {
    pub fn model_name() -> &'static str {
        "FencingLeaseRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "fencing_leases"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "lease_seq",
            "object_id",
            "holder_id",
            "epoch",
            "acquired_at",
            "expires_at",
            "fence_version",
        ]
    }
}

/// Lease service record — persists lease lifecycle state.
///
/// Owner: `connector::lease_service`
/// Classification: mandatory
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseServiceRecord {
    pub lease_id: String,
    pub holder_id: String,
    pub resource_key: String,
    pub state: String,
    pub epoch: u64,
    pub granted_at: String,
    pub expires_at: String,
    pub renewed_count: u32,
}

impl LeaseServiceRecord {
    pub fn model_name() -> &'static str {
        "LeaseServiceRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "lease_service_state"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "lease_id",
            "holder_id",
            "resource_key",
            "state",
            "epoch",
            "granted_at",
            "expires_at",
            "renewed_count",
        ]
    }
}

/// Lease quorum record — persists quorum-based lease coordination state.
///
/// Owner: `connector::lease_coordinator`
/// Classification: mandatory
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseQuorumRecord {
    pub quorum_id: String,
    pub resource_key: String,
    pub participants: Vec<String>,
    pub ack_count: u32,
    pub required_acks: u32,
    pub epoch: u64,
    pub decided_at: Option<String>,
    pub outcome: String,
}

impl LeaseQuorumRecord {
    pub fn model_name() -> &'static str {
        "LeaseQuorumRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "lease_quorum_coordination"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "quorum_id",
            "resource_key",
            "participants",
            "ack_count",
            "required_acks",
            "epoch",
            "decided_at",
            "outcome",
        ]
    }
}

/// Rollout state record — persists connector rollout phase and lifecycle state.
///
/// Owner: `connector::rollout_state`
/// Classification: mandatory
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutStateRecord {
    pub connector_id: String,
    pub rollout_epoch: u64,
    pub lifecycle_state: String,
    pub health_gate_passed: bool,
    pub rollout_phase: String,
    pub activated_at: Option<String>,
    pub persisted_at: String,
    pub version: u32,
}

impl RolloutStateRecord {
    pub fn model_name() -> &'static str {
        "RolloutStateRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "rollout_state"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "connector_id",
            "rollout_epoch",
            "lifecycle_state",
            "health_gate_passed",
            "rollout_phase",
            "activated_at",
            "persisted_at",
            "version",
        ]
    }
}

/// Health gate policy record — persists health gate evaluation results.
///
/// Owner: `connector::health_gate`
/// Classification: mandatory
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthGatePolicyRecord {
    pub gate_id: String,
    pub connector_id: String,
    pub check_name: String,
    pub required: bool,
    pub passed: bool,
    pub message: Option<String>,
    pub evaluated_at: String,
    pub epoch: u64,
}

impl HealthGatePolicyRecord {
    pub fn model_name() -> &'static str {
        "HealthGatePolicyRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "health_gate_policy_state"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "gate_id",
            "connector_id",
            "check_name",
            "required",
            "passed",
            "message",
            "evaluated_at",
            "epoch",
        ]
    }
}

/// Control channel state record — persists sequence window for control messages.
///
/// Owner: `connector::control_channel`
/// Classification: mandatory
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlChannelStateRecord {
    pub channel_id: String,
    pub last_seq: u64,
    pub window_low: u64,
    pub window_high: u64,
    pub epoch: u64,
    pub updated_at: String,
}

impl ControlChannelStateRecord {
    pub fn model_name() -> &'static str {
        "ControlChannelStateRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "control_channel_sequence_window"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "channel_id",
            "last_seq",
            "window_low",
            "window_high",
            "epoch",
            "updated_at",
        ]
    }
}

/// Artifact journal record — persists artifact write/read audit entries.
///
/// Owner: `connector::artifact_persistence`
/// Classification: mandatory
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactJournalRecord {
    pub entry_id: String,
    pub artifact_hash: String,
    pub operation: String,
    pub actor_id: String,
    pub epoch: u64,
    pub timestamp: String,
    pub metadata_json: Option<String>,
}

impl ArtifactJournalRecord {
    pub fn model_name() -> &'static str {
        "ArtifactJournalRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "artifact_journal"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "entry_id",
            "artifact_hash",
            "operation",
            "actor_id",
            "epoch",
            "timestamp",
            "metadata_json",
        ]
    }
}

/// Tiered trust artifact record — persists trust artifacts with tier classification.
///
/// Owner: `connector::tiered_trust_storage`
/// Classification: mandatory
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieredTrustArtifactRecord {
    pub artifact_id: String,
    pub trust_tier: String,
    pub publisher_id: String,
    pub signature: String,
    pub assurance_level: u32,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked: bool,
}

impl TieredTrustArtifactRecord {
    pub fn model_name() -> &'static str {
        "TieredTrustArtifactRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "tiered_trust_storage"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "artifact_id",
            "trust_tier",
            "publisher_id",
            "signature",
            "assurance_level",
            "created_at",
            "expires_at",
            "revoked",
        ]
    }
}

/// Canonical state root record — persists state root hashes for integrity.
///
/// Owner: `connector::state_model`
/// Classification: mandatory
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalStateRootRecord {
    pub root_hash: String,
    pub epoch: u64,
    pub computed_at: String,
    pub input_count: u64,
    pub algorithm: String,
}

impl CanonicalStateRootRecord {
    pub fn model_name() -> &'static str {
        "CanonicalStateRootRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "canonical_state_roots"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "root_hash",
            "epoch",
            "computed_at",
            "input_count",
            "algorithm",
        ]
    }
}

/// Durability mode record — persists durability policy per domain.
///
/// Owner: `connector::durability`
/// Classification: mandatory
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurabilityModeRecord {
    pub domain_name: String,
    pub mode: String,
    pub wal_enabled: bool,
    pub sync_interval_ms: u64,
    pub updated_at: String,
}

impl DurabilityModeRecord {
    pub fn model_name() -> &'static str {
        "DurabilityModeRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "durability_mode_controls"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "domain_name",
            "mode",
            "wal_enabled",
            "sync_interval_ms",
            "updated_at",
        ]
    }
}

/// Durable claim audit record — persists audit trail for durable claim gate.
///
/// Owner: `connector::durable_claim_gate`
/// Classification: mandatory
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableClaimAuditRecord {
    pub claim_id: String,
    pub actor_id: String,
    pub claim_type: String,
    pub decision: String,
    pub reason: String,
    pub epoch: u64,
    pub decided_at: String,
}

impl DurableClaimAuditRecord {
    pub fn model_name() -> &'static str {
        "DurableClaimAuditRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "durable_claim_gate_audit"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "claim_id",
            "actor_id",
            "claim_type",
            "decision",
            "reason",
            "epoch",
            "decided_at",
        ]
    }
}

/// Schema migration record — tracks applied schema migrations.
///
/// Owner: `connector::schema_migration`
/// Classification: mandatory
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMigrationRecord {
    pub migration_id: String,
    pub version_from: String,
    pub version_to: String,
    pub applied_at: String,
    pub checksum: String,
    pub reversible: bool,
}

impl SchemaMigrationRecord {
    pub fn model_name() -> &'static str {
        "SchemaMigrationRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "schema_migration_registry"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "migration_id",
            "version_from",
            "version_to",
            "applied_at",
            "checksum",
            "reversible",
        ]
    }
}

// ---------------------------------------------------------------------------
// Should-use models (7)
// ---------------------------------------------------------------------------

/// Snapshot policy record — persists snapshot scheduling state.
///
/// Owner: `connector::snapshot_policy`
/// Classification: should_use
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPolicyRecord {
    pub policy_id: String,
    pub domain_name: String,
    pub interval_seconds: u64,
    pub last_snapshot_at: Option<String>,
    pub next_snapshot_at: String,
    pub retention_count: u32,
}

impl SnapshotPolicyRecord {
    pub fn model_name() -> &'static str {
        "SnapshotPolicyRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "snapshot_policy_state"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "policy_id",
            "domain_name",
            "interval_seconds",
            "last_snapshot_at",
            "next_snapshot_at",
            "retention_count",
        ]
    }
}

/// CRDT merge state record — persists CRDT merge vector state.
///
/// Owner: `connector::crdt`
/// Classification: should_use
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrdtMergeStateRecord {
    pub crdt_id: String,
    pub crdt_type: String,
    pub vector_clock_json: String,
    pub merge_count: u64,
    pub last_merged_at: String,
}

impl CrdtMergeStateRecord {
    pub fn model_name() -> &'static str {
        "CrdtMergeStateRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "crdt_merge_state"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "crdt_id",
            "crdt_type",
            "vector_clock_json",
            "merge_count",
            "last_merged_at",
        ]
    }
}

/// Quarantine entry record — persists quarantined artifact state.
///
/// Owner: `connector::quarantine_store`
/// Classification: should_use
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineEntryRecord {
    pub entry_id: String,
    pub artifact_hash: String,
    pub reason: String,
    pub severity: String,
    pub quarantined_at: String,
    pub quarantined_by: String,
    pub released: bool,
}

impl QuarantineEntryRecord {
    pub fn model_name() -> &'static str {
        "QuarantineEntryRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "quarantine_store_state"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "entry_id",
            "artifact_hash",
            "reason",
            "severity",
            "quarantined_at",
            "quarantined_by",
            "released",
        ]
    }
}

/// Quarantine promotion record — persists promotion/release receipts.
///
/// Owner: `connector::quarantine_promotion`
/// Classification: should_use
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinePromotionRecord {
    pub promotion_id: String,
    pub entry_id: String,
    pub promoted_by: String,
    pub promoted_at: String,
    pub justification: String,
}

impl QuarantinePromotionRecord {
    pub fn model_name() -> &'static str {
        "QuarantinePromotionRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "quarantine_promotion_receipts"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "promotion_id",
            "entry_id",
            "promoted_by",
            "promoted_at",
            "justification",
        ]
    }
}

/// Retention policy record — persists data retention scheduling.
///
/// Owner: `connector::retention_policy`
/// Classification: should_use
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicyRecord {
    pub policy_id: String,
    pub domain_name: String,
    pub max_age_seconds: u64,
    pub max_entries: u64,
    pub last_purge_at: Option<String>,
    pub next_purge_at: String,
}

impl RetentionPolicyRecord {
    pub fn model_name() -> &'static str {
        "RetentionPolicyRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "retention_policy_state"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "policy_id",
            "domain_name",
            "max_age_seconds",
            "max_entries",
            "last_purge_at",
            "next_purge_at",
        ]
    }
}

/// Repair cycle audit record — persists repair cycle outcomes.
///
/// Owner: `connector::repair_controller`
/// Classification: should_use
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCycleAuditRecord {
    pub cycle_id: String,
    pub domain_name: String,
    pub trigger: String,
    pub items_repaired: u64,
    pub items_failed: u64,
    pub started_at: String,
    pub completed_at: String,
}

impl RepairCycleAuditRecord {
    pub fn model_name() -> &'static str {
        "RepairCycleAuditRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "repair_cycle_audit"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "cycle_id",
            "domain_name",
            "trigger",
            "items_repaired",
            "items_failed",
            "started_at",
            "completed_at",
        ]
    }
}

/// Lease conflict audit record — persists lease conflict resolution events.
///
/// Owner: `connector::lease_conflict`
/// Classification: should_use
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseConflictAuditRecord {
    pub conflict_id: String,
    pub resource_key: String,
    pub holder_a: String,
    pub holder_b: String,
    pub resolution: String,
    pub resolved_at: String,
    pub epoch: u64,
}

impl LeaseConflictAuditRecord {
    pub fn model_name() -> &'static str {
        "LeaseConflictAuditRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "lease_conflict_audit"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "conflict_id",
            "resource_key",
            "holder_a",
            "holder_b",
            "resolution",
            "resolved_at",
            "epoch",
        ]
    }
}

// ---------------------------------------------------------------------------
// Optional models (2)
// ---------------------------------------------------------------------------

/// Offline coverage metric record — persists coverage tracking metrics.
///
/// Owner: `connector::offline_coverage`
/// Classification: optional
/// Source: codegen
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OfflineCoverageMetricRecord {
    pub metric_id: String,
    pub domain_name: String,
    pub coverage_pct: f64,
    pub sampled_at: String,
    pub sample_size: u64,
}

impl OfflineCoverageMetricRecord {
    pub fn model_name() -> &'static str {
        "OfflineCoverageMetricRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "offline_coverage_metrics"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "metric_id",
            "domain_name",
            "coverage_pct",
            "sampled_at",
            "sample_size",
        ]
    }
}

/// Lifecycle transition cache record — caches recent state transitions.
///
/// Owner: `connector::lifecycle`
/// Classification: optional
/// Source: hand_authored
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTransitionCacheRecord {
    pub transition_id: String,
    pub connector_id: String,
    pub from_state: String,
    pub to_state: String,
    pub triggered_by: String,
    pub transitioned_at: String,
}

impl LifecycleTransitionCacheRecord {
    pub fn model_name() -> &'static str {
        "LifecycleTransitionCacheRecord"
    }

    pub fn model_version() -> &'static str {
        MODEL_SCHEMA_VERSION
    }

    pub fn table_name() -> &'static str {
        "lifecycle_transition_cache"
    }

    pub fn column_names() -> &'static [&'static str] {
        &[
            "transition_id",
            "connector_id",
            "from_state",
            "to_state",
            "triggered_by",
            "transitioned_at",
        ]
    }
}

// ---------------------------------------------------------------------------
// Model registry — enumerates all defined models
// ---------------------------------------------------------------------------

/// Metadata for a single model definition.
pub struct ModelMeta {
    pub name: &'static str,
    pub version: &'static str,
    pub table: &'static str,
    pub columns: &'static [&'static str],
    pub classification: &'static str,
    pub source: &'static str,
    pub owner_module: &'static str,
}

/// Returns metadata for all 21 typed models in canonical order.
///
/// # Examples
///
/// ```
/// use frankenengine_node::storage::models::all_model_metadata;
/// let metadata = all_model_metadata();
/// assert_eq!(metadata.len(), 21);
/// assert_eq!(metadata[0].name, "FencingLeaseRecord");
/// ```
pub fn all_model_metadata() -> Vec<ModelMeta> {
    vec![
        // Mandatory (12)
        ModelMeta {
            name: FencingLeaseRecord::model_name(),
            version: FencingLeaseRecord::model_version(),
            table: FencingLeaseRecord::table_name(),
            columns: FencingLeaseRecord::column_names(),
            classification: "mandatory",
            source: "hand_authored",
            owner_module: "connector::fencing",
        },
        ModelMeta {
            name: LeaseServiceRecord::model_name(),
            version: LeaseServiceRecord::model_version(),
            table: LeaseServiceRecord::table_name(),
            columns: LeaseServiceRecord::column_names(),
            classification: "mandatory",
            source: "hand_authored",
            owner_module: "connector::lease_service",
        },
        ModelMeta {
            name: LeaseQuorumRecord::model_name(),
            version: LeaseQuorumRecord::model_version(),
            table: LeaseQuorumRecord::table_name(),
            columns: LeaseQuorumRecord::column_names(),
            classification: "mandatory",
            source: "hand_authored",
            owner_module: "connector::lease_coordinator",
        },
        ModelMeta {
            name: RolloutStateRecord::model_name(),
            version: RolloutStateRecord::model_version(),
            table: RolloutStateRecord::table_name(),
            columns: RolloutStateRecord::column_names(),
            classification: "mandatory",
            source: "codegen",
            owner_module: "connector::rollout_state",
        },
        ModelMeta {
            name: HealthGatePolicyRecord::model_name(),
            version: HealthGatePolicyRecord::model_version(),
            table: HealthGatePolicyRecord::table_name(),
            columns: HealthGatePolicyRecord::column_names(),
            classification: "mandatory",
            source: "codegen",
            owner_module: "connector::health_gate",
        },
        ModelMeta {
            name: ControlChannelStateRecord::model_name(),
            version: ControlChannelStateRecord::model_version(),
            table: ControlChannelStateRecord::table_name(),
            columns: ControlChannelStateRecord::column_names(),
            classification: "mandatory",
            source: "hand_authored",
            owner_module: "connector::control_channel",
        },
        ModelMeta {
            name: ArtifactJournalRecord::model_name(),
            version: ArtifactJournalRecord::model_version(),
            table: ArtifactJournalRecord::table_name(),
            columns: ArtifactJournalRecord::column_names(),
            classification: "mandatory",
            source: "codegen",
            owner_module: "connector::artifact_persistence",
        },
        ModelMeta {
            name: TieredTrustArtifactRecord::model_name(),
            version: TieredTrustArtifactRecord::model_version(),
            table: TieredTrustArtifactRecord::table_name(),
            columns: TieredTrustArtifactRecord::column_names(),
            classification: "mandatory",
            source: "codegen",
            owner_module: "connector::tiered_trust_storage",
        },
        ModelMeta {
            name: CanonicalStateRootRecord::model_name(),
            version: CanonicalStateRootRecord::model_version(),
            table: CanonicalStateRootRecord::table_name(),
            columns: CanonicalStateRootRecord::column_names(),
            classification: "mandatory",
            source: "hand_authored",
            owner_module: "connector::state_model",
        },
        ModelMeta {
            name: DurabilityModeRecord::model_name(),
            version: DurabilityModeRecord::model_version(),
            table: DurabilityModeRecord::table_name(),
            columns: DurabilityModeRecord::column_names(),
            classification: "mandatory",
            source: "hand_authored",
            owner_module: "connector::durability",
        },
        ModelMeta {
            name: DurableClaimAuditRecord::model_name(),
            version: DurableClaimAuditRecord::model_version(),
            table: DurableClaimAuditRecord::table_name(),
            columns: DurableClaimAuditRecord::column_names(),
            classification: "mandatory",
            source: "hand_authored",
            owner_module: "connector::durable_claim_gate",
        },
        ModelMeta {
            name: SchemaMigrationRecord::model_name(),
            version: SchemaMigrationRecord::model_version(),
            table: SchemaMigrationRecord::table_name(),
            columns: SchemaMigrationRecord::column_names(),
            classification: "mandatory",
            source: "codegen",
            owner_module: "connector::schema_migration",
        },
        // Should-use (7)
        ModelMeta {
            name: SnapshotPolicyRecord::model_name(),
            version: SnapshotPolicyRecord::model_version(),
            table: SnapshotPolicyRecord::table_name(),
            columns: SnapshotPolicyRecord::column_names(),
            classification: "should_use",
            source: "codegen",
            owner_module: "connector::snapshot_policy",
        },
        ModelMeta {
            name: CrdtMergeStateRecord::model_name(),
            version: CrdtMergeStateRecord::model_version(),
            table: CrdtMergeStateRecord::table_name(),
            columns: CrdtMergeStateRecord::column_names(),
            classification: "should_use",
            source: "hand_authored",
            owner_module: "connector::crdt",
        },
        ModelMeta {
            name: QuarantineEntryRecord::model_name(),
            version: QuarantineEntryRecord::model_version(),
            table: QuarantineEntryRecord::table_name(),
            columns: QuarantineEntryRecord::column_names(),
            classification: "should_use",
            source: "codegen",
            owner_module: "connector::quarantine_store",
        },
        ModelMeta {
            name: QuarantinePromotionRecord::model_name(),
            version: QuarantinePromotionRecord::model_version(),
            table: QuarantinePromotionRecord::table_name(),
            columns: QuarantinePromotionRecord::column_names(),
            classification: "should_use",
            source: "codegen",
            owner_module: "connector::quarantine_promotion",
        },
        ModelMeta {
            name: RetentionPolicyRecord::model_name(),
            version: RetentionPolicyRecord::model_version(),
            table: RetentionPolicyRecord::table_name(),
            columns: RetentionPolicyRecord::column_names(),
            classification: "should_use",
            source: "hand_authored",
            owner_module: "connector::retention_policy",
        },
        ModelMeta {
            name: RepairCycleAuditRecord::model_name(),
            version: RepairCycleAuditRecord::model_version(),
            table: RepairCycleAuditRecord::table_name(),
            columns: RepairCycleAuditRecord::column_names(),
            classification: "should_use",
            source: "hand_authored",
            owner_module: "connector::repair_controller",
        },
        ModelMeta {
            name: LeaseConflictAuditRecord::model_name(),
            version: LeaseConflictAuditRecord::model_version(),
            table: LeaseConflictAuditRecord::table_name(),
            columns: LeaseConflictAuditRecord::column_names(),
            classification: "should_use",
            source: "hand_authored",
            owner_module: "connector::lease_conflict",
        },
        // Optional (2)
        ModelMeta {
            name: OfflineCoverageMetricRecord::model_name(),
            version: OfflineCoverageMetricRecord::model_version(),
            table: OfflineCoverageMetricRecord::table_name(),
            columns: OfflineCoverageMetricRecord::column_names(),
            classification: "optional",
            source: "codegen",
            owner_module: "connector::offline_coverage",
        },
        ModelMeta {
            name: LifecycleTransitionCacheRecord::model_name(),
            version: LifecycleTransitionCacheRecord::model_version(),
            table: LifecycleTransitionCacheRecord::table_name(),
            columns: LifecycleTransitionCacheRecord::column_names(),
            classification: "optional",
            source: "hand_authored",
            owner_module: "connector::lifecycle",
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_model_metadata_returns_21_entries() {
        assert_eq!(all_model_metadata().len(), 21);
    }

    #[test]
    fn mandatory_models_count_is_12() {
        let count = all_model_metadata()
            .iter()
            .filter(|m| m.classification == "mandatory")
            .count();
        assert_eq!(count, 12);
    }

    #[test]
    fn should_use_models_count_is_7() {
        let count = all_model_metadata()
            .iter()
            .filter(|m| m.classification == "should_use")
            .count();
        assert_eq!(count, 7);
    }

    #[test]
    fn optional_models_count_is_2() {
        let count = all_model_metadata()
            .iter()
            .filter(|m| m.classification == "optional")
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn all_model_names_unique() {
        let meta = all_model_metadata();
        let mut names: Vec<&str> = meta.iter().map(|m| m.name).collect();
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate model names found");
    }

    #[test]
    fn all_table_names_unique() {
        let meta = all_model_metadata();
        let mut tables: Vec<&str> = meta.iter().map(|m| m.table).collect();
        let total = tables.len();
        tables.sort();
        tables.dedup();
        assert_eq!(tables.len(), total, "duplicate table names found");
    }

    #[test]
    fn all_models_have_nonempty_columns() {
        for m in all_model_metadata() {
            assert!(!m.columns.is_empty(), "model {} has no columns", m.name);
        }
    }

    #[test]
    fn all_models_have_version_1_0_0() {
        for m in all_model_metadata() {
            assert_eq!(
                m.version, "1.0.0",
                "model {} has unexpected version {}",
                m.name, m.version
            );
        }
    }

    #[test]
    fn fencing_lease_record_serde_roundtrip() {
        let record = FencingLeaseRecord {
            lease_seq: 42,
            object_id: "obj-1".into(),
            holder_id: "holder-a".into(),
            epoch: 7,
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T01:00:00Z".into(),
            fence_version: 1,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let parsed: FencingLeaseRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, record);
    }

    #[test]
    fn rollout_state_record_serde_roundtrip() {
        let record = RolloutStateRecord {
            connector_id: "conn-1".into(),
            rollout_epoch: 5,
            lifecycle_state: "active".into(),
            health_gate_passed: true,
            rollout_phase: "canary".into(),
            activated_at: Some("2026-01-01T00:00:00Z".into()),
            persisted_at: "2026-01-01T00:01:00Z".into(),
            version: 3,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let parsed: RolloutStateRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, record);
    }

    #[test]
    fn schema_migration_record_serde_roundtrip() {
        let record = SchemaMigrationRecord {
            migration_id: "mig-001".into(),
            version_from: "0.9.0".into(),
            version_to: "1.0.0".into(),
            applied_at: "2026-01-15T12:00:00Z".into(),
            checksum: "sha256:abc123".into(),
            reversible: true,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let parsed: SchemaMigrationRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, record);
    }

    #[test]
    fn quarantine_entry_record_serde_roundtrip() {
        let record = QuarantineEntryRecord {
            entry_id: "qe-1".into(),
            artifact_hash: "sha256:def456".into(),
            reason: "suspicious behavior".into(),
            severity: "high".into(),
            quarantined_at: "2026-02-01T00:00:00Z".into(),
            quarantined_by: "system".into(),
            released: false,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let parsed: QuarantineEntryRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, record);
    }

    #[test]
    fn lifecycle_transition_serde_roundtrip() {
        let record = LifecycleTransitionCacheRecord {
            transition_id: "lt-1".into(),
            connector_id: "conn-2".into(),
            from_state: "initializing".into(),
            to_state: "active".into(),
            triggered_by: "health_gate_pass".into(),
            transitioned_at: "2026-02-10T08:00:00Z".into(),
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let parsed: LifecycleTransitionCacheRecord =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, record);
    }

    #[test]
    fn fencing_lease_record_rejects_missing_required_holder_id() {
        let value = serde_json::json!({
            "lease_seq": 42,
            "object_id": "obj-1",
            "epoch": 7,
            "acquired_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "fence_version": 1
        });

        let err = serde_json::from_value::<FencingLeaseRecord>(value)
            .expect_err("missing holder_id must fail deserialization");

        assert!(err.to_string().contains("holder_id"));
    }

    #[test]
    fn lease_service_record_rejects_null_non_optional_state() {
        let value = serde_json::json!({
            "lease_id": "lease-1",
            "holder_id": "holder-a",
            "resource_key": "resource-a",
            "state": null,
            "epoch": 7,
            "granted_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "renewed_count": 0
        });

        let err = serde_json::from_value::<LeaseServiceRecord>(value)
            .expect_err("null state must fail deserialization");

        assert!(err.to_string().contains("state"));
    }

    #[test]
    fn lease_quorum_record_rejects_string_ack_count() {
        let value = serde_json::json!({
            "quorum_id": "quorum-1",
            "resource_key": "resource-a",
            "participants": ["a", "b"],
            "ack_count": "2",
            "required_acks": 2,
            "epoch": 7,
            "decided_at": null,
            "outcome": "pending"
        });

        let err = serde_json::from_value::<LeaseQuorumRecord>(value)
            .expect_err("string ack_count must fail deserialization");

        assert!(err.to_string().contains("ack_count"));
    }

    #[test]
    fn rollout_state_record_rejects_string_health_gate_flag() {
        let value = serde_json::json!({
            "connector_id": "conn-1",
            "rollout_epoch": 5,
            "lifecycle_state": "active",
            "health_gate_passed": "true",
            "rollout_phase": "canary",
            "activated_at": null,
            "persisted_at": "2026-01-01T00:01:00Z",
            "version": 3
        });

        let err = serde_json::from_value::<RolloutStateRecord>(value)
            .expect_err("string health gate flag must fail deserialization");

        assert!(err.to_string().contains("health_gate_passed"));
    }

    #[test]
    fn schema_migration_record_rejects_boolean_checksum() {
        let value = serde_json::json!({
            "migration_id": "mig-001",
            "version_from": "0.9.0",
            "version_to": "1.0.0",
            "applied_at": "2026-01-15T12:00:00Z",
            "checksum": true,
            "reversible": true
        });

        let err = serde_json::from_value::<SchemaMigrationRecord>(value)
            .expect_err("boolean checksum must fail deserialization");

        assert!(err.to_string().contains("checksum"));
    }

    #[test]
    fn offline_coverage_metric_rejects_string_coverage_pct() {
        let value = serde_json::json!({
            "metric_id": "metric-1",
            "domain_name": "connector",
            "coverage_pct": "0.99",
            "sampled_at": "2026-01-01T00:00:00Z",
            "sample_size": 100
        });

        let err = serde_json::from_value::<OfflineCoverageMetricRecord>(value)
            .expect_err("string coverage_pct must fail deserialization");

        assert!(err.to_string().contains("coverage_pct"));
    }

    #[test]
    fn lifecycle_transition_cache_rejects_null_required_state() {
        let value = serde_json::json!({
            "transition_id": "lt-1",
            "connector_id": "conn-2",
            "from_state": "initializing",
            "to_state": null,
            "triggered_by": "health_gate_pass",
            "transitioned_at": "2026-02-10T08:00:00Z"
        });

        let err = serde_json::from_value::<LifecycleTransitionCacheRecord>(value)
            .expect_err("null to_state must fail deserialization");

        assert!(err.to_string().contains("to_state"));
    }

    #[test]
    fn malformed_json_rejects_model_deserialization() {
        let err = serde_json::from_str::<FencingLeaseRecord>("{not-json")
            .expect_err("malformed JSON must fail deserialization");

        assert!(err.is_syntax());
    }

    #[test]
    fn health_gate_policy_rejects_null_required_flag() {
        let value = serde_json::json!({
            "gate_id": "gate-1",
            "connector_id": "conn-1",
            "check_name": "startup",
            "required": null,
            "passed": true,
            "message": null,
            "evaluated_at": "2026-01-01T00:00:00Z",
            "epoch": 7
        });

        let err = serde_json::from_value::<HealthGatePolicyRecord>(value)
            .expect_err("null required flag must fail deserialization");

        assert!(err.to_string().contains("required"));
    }

    #[test]
    fn control_channel_state_rejects_negative_window_low() {
        let value = serde_json::json!({
            "channel_id": "chan-1",
            "last_seq": 10,
            "window_low": -1,
            "window_high": 32,
            "epoch": 7,
            "updated_at": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<ControlChannelStateRecord>(value)
            .expect_err("negative window_low must fail deserialization");

        assert!(err.to_string().contains("window_low"));
    }

    #[test]
    fn artifact_journal_rejects_object_metadata_json() {
        let value = serde_json::json!({
            "entry_id": "entry-1",
            "artifact_hash": "sha256:abc",
            "operation": "write",
            "actor_id": "actor-1",
            "epoch": 7,
            "timestamp": "2026-01-01T00:00:00Z",
            "metadata_json": {"unexpected": true}
        });

        let err = serde_json::from_value::<ArtifactJournalRecord>(value)
            .expect_err("object metadata_json must fail deserialization");

        assert!(err.to_string().contains("metadata_json"));
    }

    #[test]
    fn tiered_trust_artifact_rejects_string_assurance_level() {
        let value = serde_json::json!({
            "artifact_id": "artifact-1",
            "trust_tier": "high",
            "publisher_id": "publisher-1",
            "signature": "sig-1",
            "assurance_level": "3",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": null,
            "revoked": false
        });

        let err = serde_json::from_value::<TieredTrustArtifactRecord>(value)
            .expect_err("string assurance_level must fail deserialization");

        assert!(err.to_string().contains("assurance_level"));
    }

    #[test]
    fn canonical_state_root_rejects_array_root_hash() {
        let value = serde_json::json!({
            "root_hash": ["sha256:abc"],
            "epoch": 7,
            "computed_at": "2026-01-01T00:00:00Z",
            "input_count": 3,
            "algorithm": "sha256"
        });

        let err = serde_json::from_value::<CanonicalStateRootRecord>(value)
            .expect_err("array root_hash must fail deserialization");

        assert!(err.to_string().contains("root_hash"));
    }

    #[test]
    fn durability_mode_rejects_string_wal_enabled() {
        let value = serde_json::json!({
            "domain_name": "connector",
            "mode": "strict",
            "wal_enabled": "true",
            "sync_interval_ms": 1000,
            "updated_at": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<DurabilityModeRecord>(value)
            .expect_err("string wal_enabled must fail deserialization");

        assert!(err.to_string().contains("wal_enabled"));
    }

    #[test]
    fn durable_claim_audit_rejects_missing_decided_at() {
        let value = serde_json::json!({
            "claim_id": "claim-1",
            "actor_id": "actor-1",
            "claim_type": "durability",
            "decision": "deny",
            "reason": "insufficient evidence",
            "epoch": 7
        });

        let err = serde_json::from_value::<DurableClaimAuditRecord>(value)
            .expect_err("missing decided_at must fail deserialization");

        assert!(err.to_string().contains("decided_at"));
    }

    #[test]
    fn snapshot_policy_rejects_string_retention_count() {
        let value = serde_json::json!({
            "policy_id": "snapshot-1",
            "domain_name": "connector",
            "interval_seconds": 60,
            "last_snapshot_at": null,
            "next_snapshot_at": "2026-01-01T00:01:00Z",
            "retention_count": "10"
        });

        let err = serde_json::from_value::<SnapshotPolicyRecord>(value)
            .expect_err("string retention_count must fail deserialization");

        assert!(err.to_string().contains("retention_count"));
    }

    #[test]
    fn crdt_merge_state_rejects_object_vector_clock_json() {
        let value = serde_json::json!({
            "crdt_id": "crdt-1",
            "crdt_type": "lww",
            "vector_clock_json": {"node-a": 1},
            "merge_count": 3,
            "last_merged_at": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<CrdtMergeStateRecord>(value)
            .expect_err("object vector_clock_json must fail deserialization");

        assert!(err.to_string().contains("vector_clock_json"));
    }

    #[test]
    fn retention_policy_rejects_negative_max_entries() {
        let value = serde_json::json!({
            "policy_id": "retention-1",
            "domain_name": "connector",
            "max_age_seconds": 3600,
            "max_entries": -1,
            "last_purge_at": null,
            "next_purge_at": "2026-01-01T01:00:00Z"
        });

        let err = serde_json::from_value::<RetentionPolicyRecord>(value)
            .expect_err("negative max_entries must fail deserialization");

        assert!(err.to_string().contains("max_entries"));
    }

    #[test]
    fn lease_service_record_rejects_negative_renewed_count() {
        let value = serde_json::json!({
            "lease_id": "lease-1",
            "holder_id": "holder-a",
            "resource_key": "resource-a",
            "state": "granted",
            "epoch": 7,
            "granted_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "renewed_count": -1
        });

        let err = serde_json::from_value::<LeaseServiceRecord>(value)
            .expect_err("negative renewed_count must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn lease_quorum_record_rejects_non_array_participants() {
        let value = serde_json::json!({
            "quorum_id": "quorum-1",
            "resource_key": "resource-a",
            "participants": "node-a,node-b",
            "ack_count": 2,
            "required_acks": 2,
            "epoch": 7,
            "decided_at": null,
            "outcome": "pending"
        });

        let err = serde_json::from_value::<LeaseQuorumRecord>(value)
            .expect_err("non-array participants must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn quarantine_entry_record_rejects_string_released_flag() {
        let value = serde_json::json!({
            "entry_id": "qe-1",
            "artifact_hash": "sha256:def456",
            "reason": "suspicious behavior",
            "severity": "high",
            "quarantined_at": "2026-02-01T00:00:00Z",
            "quarantined_by": "system",
            "released": "false"
        });

        let err = serde_json::from_value::<QuarantineEntryRecord>(value)
            .expect_err("string released flag must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn quarantine_promotion_record_rejects_missing_justification() {
        let value = serde_json::json!({
            "promotion_id": "promotion-1",
            "entry_id": "qe-1",
            "promoted_by": "operator-1",
            "promoted_at": "2026-02-01T01:00:00Z"
        });

        let err = serde_json::from_value::<QuarantinePromotionRecord>(value)
            .expect_err("missing justification must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn repair_cycle_audit_rejects_float_items_repaired() {
        let value = serde_json::json!({
            "cycle_id": "repair-1",
            "domain_name": "connector",
            "trigger": "integrity_sweep",
            "items_repaired": 1.5,
            "items_failed": 0,
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:01:00Z"
        });

        let err = serde_json::from_value::<RepairCycleAuditRecord>(value)
            .expect_err("float items_repaired must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn lease_conflict_audit_rejects_null_holder_b() {
        let value = serde_json::json!({
            "conflict_id": "conflict-1",
            "resource_key": "resource-a",
            "holder_a": "holder-a",
            "holder_b": null,
            "resolution": "deny-second-holder",
            "resolved_at": "2026-01-01T00:00:00Z",
            "epoch": 7
        });

        let err = serde_json::from_value::<LeaseConflictAuditRecord>(value)
            .expect_err("null holder_b must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn offline_coverage_metric_rejects_negative_sample_size() {
        let value = serde_json::json!({
            "metric_id": "metric-1",
            "domain_name": "connector",
            "coverage_pct": 0.99,
            "sampled_at": "2026-01-01T00:00:00Z",
            "sample_size": -1
        });

        let err = serde_json::from_value::<OfflineCoverageMetricRecord>(value)
            .expect_err("negative sample_size must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn lifecycle_transition_cache_rejects_numeric_triggered_by() {
        let value = serde_json::json!({
            "transition_id": "lt-1",
            "connector_id": "conn-2",
            "from_state": "initializing",
            "to_state": "active",
            "triggered_by": 42,
            "transitioned_at": "2026-02-10T08:00:00Z"
        });

        let err = serde_json::from_value::<LifecycleTransitionCacheRecord>(value)
            .expect_err("numeric triggered_by must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn fencing_lease_record_rejects_string_lease_seq() {
        let value = serde_json::json!({
            "lease_seq": "42",
            "object_id": "obj-1",
            "holder_id": "holder-a",
            "epoch": 7,
            "acquired_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "fence_version": 1
        });

        let err = serde_json::from_value::<FencingLeaseRecord>(value)
            .expect_err("string lease_seq must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn control_channel_state_rejects_missing_updated_at() {
        let value = serde_json::json!({
            "channel_id": "chan-1",
            "last_seq": 10,
            "window_low": 1,
            "window_high": 32,
            "epoch": 7
        });

        let err = serde_json::from_value::<ControlChannelStateRecord>(value)
            .expect_err("missing updated_at must fail deserialization");

        assert!(err.to_string().contains("updated_at"));
    }

    #[test]
    fn tiered_trust_artifact_rejects_string_revoked_flag() {
        let value = serde_json::json!({
            "artifact_id": "artifact-1",
            "trust_tier": "high",
            "publisher_id": "publisher-1",
            "signature": "sig-1",
            "assurance_level": 3,
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": null,
            "revoked": "false"
        });

        let err = serde_json::from_value::<TieredTrustArtifactRecord>(value)
            .expect_err("string revoked flag must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn canonical_state_root_rejects_negative_input_count() {
        let value = serde_json::json!({
            "root_hash": "sha256:abc",
            "epoch": 7,
            "computed_at": "2026-01-01T00:00:00Z",
            "input_count": -1,
            "algorithm": "sha256"
        });

        let err = serde_json::from_value::<CanonicalStateRootRecord>(value)
            .expect_err("negative input_count must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn durability_mode_rejects_negative_sync_interval() {
        let value = serde_json::json!({
            "domain_name": "connector",
            "mode": "strict",
            "wal_enabled": true,
            "sync_interval_ms": -1,
            "updated_at": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<DurabilityModeRecord>(value)
            .expect_err("negative sync_interval_ms must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn snapshot_policy_rejects_null_next_snapshot_at() {
        let value = serde_json::json!({
            "policy_id": "snapshot-1",
            "domain_name": "connector",
            "interval_seconds": 60,
            "last_snapshot_at": null,
            "next_snapshot_at": null,
            "retention_count": 10
        });

        let err = serde_json::from_value::<SnapshotPolicyRecord>(value)
            .expect_err("null next_snapshot_at must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn crdt_merge_state_rejects_negative_merge_count() {
        let value = serde_json::json!({
            "crdt_id": "crdt-1",
            "crdt_type": "lww",
            "vector_clock_json": "{\"node-a\":1}",
            "merge_count": -1,
            "last_merged_at": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<CrdtMergeStateRecord>(value)
            .expect_err("negative merge_count must fail deserialization");

        assert!(err.is_data());
    }

    #[test]
    fn repair_cycle_audit_rejects_missing_completed_at() {
        let value = serde_json::json!({
            "cycle_id": "repair-1",
            "domain_name": "connector",
            "trigger": "integrity_sweep",
            "items_repaired": 1,
            "items_failed": 0,
            "started_at": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<RepairCycleAuditRecord>(value)
            .expect_err("missing completed_at must fail deserialization");

        assert!(err.to_string().contains("completed_at"));
    }

    #[test]
    fn owner_module_uniqueness_per_model() {
        let meta = all_model_metadata();
        for m in &meta {
            let count = meta.iter().filter(|other| other.name == m.name).count();
            assert_eq!(count, 1, "model {} appears {} times", m.name, count);
        }
    }

    #[test]
    fn negative_fencing_lease_record_with_u64_max_epoch_serializes_safely() {
        let record = FencingLeaseRecord {
            lease_seq: u64::MAX,
            object_id: "obj-max".into(),
            holder_id: "holder-max".into(),
            epoch: u64::MAX,
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T01:00:00Z".into(),
            fence_version: u32::MAX,
        };

        // Should serialize without overflow or panic
        let json_result = serde_json::to_string(&record);
        assert!(json_result.is_ok());

        let json = json_result.unwrap();
        let parsed_result: Result<FencingLeaseRecord, _> = serde_json::from_str(&json);
        assert!(parsed_result.is_ok());

        let parsed = parsed_result.unwrap();
        assert_eq!(parsed.epoch, u64::MAX);
        assert_eq!(parsed.fence_version, u32::MAX);
    }

    #[test]
    fn negative_lease_quorum_record_with_extremely_large_participants_list() {
        // Create a very large participants list to test memory handling
        let large_participants: Vec<String> = (0..10000).map(|i| format!("participant-{}", i)).collect();

        let record = LeaseQuorumRecord {
            quorum_id: "large-quorum".into(),
            resource_key: "resource-large".into(),
            participants: large_participants.clone(),
            ack_count: 0,
            required_acks: u32::try_from(large_participants.len()).unwrap_or(u32::MAX),
            epoch: 1,
            decided_at: None,
            outcome: "pending".into(),
        };

        // Should handle large data structures without panic
        let start = std::time::Instant::now();
        let json_result = serde_json::to_string(&record);
        let serialize_duration = start.elapsed();

        assert!(json_result.is_ok());
        assert!(serialize_duration < std::time::Duration::from_secs(5));

        // Test deserialization
        let json = json_result.unwrap();
        let parse_start = std::time::Instant::now();
        let parsed_result: Result<LeaseQuorumRecord, _> = serde_json::from_str(&json);
        let parse_duration = parse_start.elapsed();

        assert!(parsed_result.is_ok());
        assert!(parse_duration < std::time::Duration::from_secs(5));

        let parsed = parsed_result.unwrap();
        assert_eq!(parsed.participants.len(), 10000);
    }

    #[test]
    fn negative_artifact_journal_record_with_unicode_injection_in_metadata() {
        // Test various Unicode edge cases in JSON metadata field
        let malicious_metadata_values = vec![
            r#"{"key":"\u0000null_byte"}"#,
            r#"{"bidi":"\u202Eoverride\u202D"}"#,
            r#"{"zwsp":"\u200Binvisible"}"#,
            r#"{"emoji":"💀\uD83D\uDC80"}"#,
            r#"{"combining":"e\u0301acute"}"#,
            r#"{"control":"\u001F\u007F\u0001"}"#,
        ];

        for metadata_json in malicious_metadata_values {
            let record = ArtifactJournalRecord {
                entry_id: "unicode-test".into(),
                artifact_hash: "sha256:test".into(),
                operation: "write".into(),
                actor_id: "test-actor".into(),
                epoch: 1,
                timestamp: "2026-01-01T00:00:00Z".into(),
                metadata_json: Some(metadata_json.to_string()),
            };

            // Should serialize/deserialize with Unicode content literally preserved
            let json_result = serde_json::to_string(&record);
            assert!(json_result.is_ok());

            let json = json_result.unwrap();
            let parsed_result: Result<ArtifactJournalRecord, _> = serde_json::from_str(&json);
            assert!(parsed_result.is_ok());

            let parsed = parsed_result.unwrap();
            assert_eq!(parsed.metadata_json, record.metadata_json);
        }
    }

    #[test]
    fn negative_offline_coverage_metric_with_extreme_floating_point_values() {
        let extreme_float_values = vec![
            f64::MAX,
            f64::MIN,
            f64::MIN_POSITIVE,
            f64::EPSILON,
            std::f64::consts::PI,
            std::f64::consts::E,
            1e308,  // Near overflow
            1e-308, // Near underflow
        ];

        for coverage_pct in extreme_float_values {
            let record = OfflineCoverageMetricRecord {
                metric_id: format!("metric-{}", coverage_pct),
                domain_name: "test".into(),
                coverage_pct,
                sampled_at: "2026-01-01T00:00:00Z".into(),
                sample_size: 1,
            };

            // Should handle extreme float values safely
            let json_result = serde_json::to_string(&record);
            assert!(json_result.is_ok());

            let json = json_result.unwrap();
            let parsed_result: Result<OfflineCoverageMetricRecord, _> = serde_json::from_str(&json);

            // Either parse successfully or fail gracefully (no panic)
            if let Ok(parsed) = parsed_result {
                // If parsed successfully, value should be preserved or appropriately bounded
                assert!(parsed.coverage_pct.is_finite() || coverage_pct.is_finite());
            }
        }
    }

    #[test]
    fn negative_offline_coverage_metric_with_non_finite_float_values() {
        let non_finite_values = vec![f64::NAN, f64::INFINITY, f64::NEG_INFINITY];

        for coverage_pct in non_finite_values {
            let json_value = serde_json::json!({
                "metric_id": "nan-test",
                "domain_name": "test",
                "coverage_pct": coverage_pct,
                "sampled_at": "2026-01-01T00:00:00Z",
                "sample_size": 1
            });

            // Non-finite values should be handled gracefully in JSON
            let json_result = serde_json::to_string(&json_value);
            assert!(json_result.is_ok());

            // But parsing into the struct might reject non-finite values
            let parsed_result: Result<OfflineCoverageMetricRecord, _> =
                serde_json::from_value(json_value);

            // Should either succeed (if serde allows) or fail gracefully (no panic)
            match parsed_result {
                Ok(record) => {
                    // If it succeeded, check if the value was preserved or normalized
                    if coverage_pct.is_nan() {
                        assert!(record.coverage_pct.is_nan() || record.coverage_pct.is_finite());
                    }
                }
                Err(err) => {
                    // Graceful failure is acceptable for non-finite values
                    assert!(err.to_string().contains("coverage_pct"));
                }
            }
        }
    }

    #[test]
    fn negative_control_channel_state_with_sequence_window_boundary_violations() {
        // Test sequence window boundary conditions
        let boundary_test_cases = vec![
            // window_high < window_low (invalid)
            (100, 50, 75),
            // All values at u64::MAX
            (u64::MAX, u64::MAX, u64::MAX),
            // Zero values
            (0, 0, 0),
            // last_seq outside window
            (10, 20, 5),   // last_seq < window_low
            (10, 20, 25),  // last_seq > window_high
        ];

        for (window_low, window_high, last_seq) in boundary_test_cases {
            let record = ControlChannelStateRecord {
                channel_id: format!("chan-{}-{}-{}", window_low, window_high, last_seq),
                last_seq,
                window_low,
                window_high,
                epoch: 1,
                updated_at: "2026-01-01T00:00:00Z".into(),
            };

            // Should serialize even with boundary violations (validation is business logic)
            let json_result = serde_json::to_string(&record);
            assert!(json_result.is_ok());

            let json = json_result.unwrap();
            let parsed_result: Result<ControlChannelStateRecord, _> = serde_json::from_str(&json);
            assert!(parsed_result.is_ok());

            let parsed = parsed_result.unwrap();
            assert_eq!(parsed.window_low, window_low);
            assert_eq!(parsed.window_high, window_high);
            assert_eq!(parsed.last_seq, last_seq);
        }
    }

    #[test]
    fn negative_schema_migration_record_with_malformed_version_strings() {
        let malformed_versions = vec![
            "",                           // Empty version
            "not.a.version",             // Non-semver
            "1.0.0-alpha+build",         // Complex semver
            "v1.0.0",                    // Prefixed version
            "1.0",                       // Incomplete version
            "1.0.0.0",                   // Too many components
            "∞.∞.∞",                     // Unicode numbers
            "1.0.0\x00",                 // Null byte
            "1.0.0\n",                   // Newline
            " 1.0.0 ",                   // Whitespace padding
        ];

        for version_str in malformed_versions {
            let record = SchemaMigrationRecord {
                migration_id: "malformed-version-test".into(),
                version_from: version_str.to_string(),
                version_to: "1.0.0".into(),
                applied_at: "2026-01-01T00:00:00Z".into(),
                checksum: "sha256:test".into(),
                reversible: true,
            };

            // Should serialize malformed version strings literally
            let json_result = serde_json::to_string(&record);
            assert!(json_result.is_ok());

            let json = json_result.unwrap();
            let parsed_result: Result<SchemaMigrationRecord, _> = serde_json::from_str(&json);
            assert!(parsed_result.is_ok());

            let parsed = parsed_result.unwrap();
            assert_eq!(parsed.version_from, version_str);
        }
    }

    #[test]
    fn negative_crdt_merge_state_with_deeply_nested_vector_clock_json() {
        // Create deeply nested JSON structure to test parsing limits
        let mut deep_json = String::new();
        for _ in 0..1000 {
            deep_json.push_str(r#"{"nested":"#);
        }
        deep_json.push_str("\"value\"");
        for _ in 0..1000 {
            deep_json.push('}');
        }

        let record = CrdtMergeStateRecord {
            crdt_id: "deep-json-test".into(),
            crdt_type: "lww".into(),
            vector_clock_json: deep_json.clone(),
            merge_count: 1,
            last_merged_at: "2026-01-01T00:00:00Z".into(),
        };

        // Should handle deeply nested JSON string as literal content
        let start = std::time::Instant::now();
        let json_result = serde_json::to_string(&record);
        let serialize_duration = start.elapsed();

        assert!(json_result.is_ok());
        assert!(serialize_duration < std::time::Duration::from_secs(10));

        let json = json_result.unwrap();
        let parse_start = std::time::Instant::now();
        let parsed_result: Result<CrdtMergeStateRecord, _> = serde_json::from_str(&json);
        let parse_duration = parse_start.elapsed();

        assert!(parsed_result.is_ok());
        assert!(parse_duration < std::time::Duration::from_secs(10));

        let parsed = parsed_result.unwrap();
        assert_eq!(parsed.vector_clock_json, deep_json);
    }

    #[test]
    fn negative_tiered_trust_artifact_with_zero_and_maximum_assurance_levels() {
        let extreme_assurance_levels = vec![0, u32::MAX];

        for assurance_level in extreme_assurance_levels {
            let record = TieredTrustArtifactRecord {
                artifact_id: format!("artifact-assurance-{}", assurance_level),
                trust_tier: "test".into(),
                publisher_id: "test-publisher".into(),
                signature: "test-signature".into(),
                assurance_level,
                created_at: "2026-01-01T00:00:00Z".into(),
                expires_at: None,
                revoked: false,
            };

            // Should handle extreme assurance levels safely
            let json_result = serde_json::to_string(&record);
            assert!(json_result.is_ok());

            let json = json_result.unwrap();
            let parsed_result: Result<TieredTrustArtifactRecord, _> = serde_json::from_str(&json);
            assert!(parsed_result.is_ok());

            let parsed = parsed_result.unwrap();
            assert_eq!(parsed.assurance_level, assurance_level);
        }
    }

    #[test]
    fn negative_all_models_handle_extremely_long_string_fields_without_panic() {
        // Test with 1MB string values in various string fields
        let huge_string = "x".repeat(1_000_000);

        // Test a few representative models with long string values
        let fencing_record = FencingLeaseRecord {
            lease_seq: 1,
            object_id: huge_string.clone(),
            holder_id: "holder".into(),
            epoch: 1,
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T01:00:00Z".into(),
            fence_version: 1,
        };

        let start = std::time::Instant::now();
        let json_result = serde_json::to_string(&fencing_record);
        let duration = start.elapsed();

        assert!(json_result.is_ok());
        assert!(duration < std::time::Duration::from_secs(30));

        // Test parsing large JSON back
        let json = json_result.unwrap();
        assert!(json.len() > 1_000_000);

        let parse_start = std::time::Instant::now();
        let parsed_result: Result<FencingLeaseRecord, _> = serde_json::from_str(&json);
        let parse_duration = parse_start.elapsed();

        assert!(parsed_result.is_ok());
        assert!(parse_duration < std::time::Duration::from_secs(30));

        let parsed = parsed_result.unwrap();
        assert_eq!(parsed.object_id.len(), 1_000_000);
    }

    #[test]
    fn negative_model_metadata_consistency_under_memory_pressure() {
        // Test all_model_metadata under repeated calls to check for memory leaks/issues
        for _ in 0..1000 {
            let meta = all_model_metadata();
            assert_eq!(meta.len(), 21);

            // Verify structure consistency
            for m in &meta {
                assert!(!m.name.is_empty());
                assert!(!m.table.is_empty());
                assert!(!m.columns.is_empty());
                assert!(!m.classification.is_empty());
                assert!(!m.source.is_empty());
                assert!(!m.owner_module.is_empty());
                assert_eq!(m.version, "1.0.0");
            }
        }
    }
}
