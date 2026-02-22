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
        let json = serde_json::to_string(&record).unwrap();
        let parsed: FencingLeaseRecord = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&record).unwrap();
        let parsed: RolloutStateRecord = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&record).unwrap();
        let parsed: SchemaMigrationRecord = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&record).unwrap();
        let parsed: QuarantineEntryRecord = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&record).unwrap();
        let parsed: LifecycleTransitionCacheRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn owner_module_uniqueness_per_model() {
        let meta = all_model_metadata();
        for m in &meta {
            let count = meta.iter().filter(|other| other.name == m.name).count();
            assert_eq!(count, 1, "model {} appears {} times", m.name, count);
        }
    }
}
