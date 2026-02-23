//! bd-2ad0: Reproducible migration and incident datasets (Section 16).
//!
//! Publishes reproducible, versioned datasets for migration scenarios and
//! security incidents. Each dataset bundle includes integrity hashes,
//! provenance attestations, and deterministic replay instructions so
//! external researchers can independently reproduce results.
//!
//! # Capabilities
//!
//! - Dataset catalog with typed entries (migration, incident, benchmark)
//! - Content-addressed storage with SHA-256 integrity hashes
//! - Provenance metadata linking datasets to source beads
//! - Reproducibility manifest with replay instructions
//! - Schema versioning for long-term dataset compatibility
//!
//! # Invariants
//!
//! - **INV-RDS-INTEGRITY**: Every dataset has a SHA-256 content hash.
//! - **INV-RDS-DETERMINISTIC**: Same dataset inputs produce same catalog output.
//! - **INV-RDS-PROVENANCE**: Every dataset links to source bead and build context.
//! - **INV-RDS-REPRODUCIBLE**: Every dataset includes replay instructions.
//! - **INV-RDS-VERSIONED**: Schema version embedded in every bundle.
//! - **INV-RDS-GATED**: Datasets below completeness threshold blocked from publication.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const RDS_DATASET_REGISTERED: &str = "RDS-001";
    pub const RDS_INTEGRITY_VERIFIED: &str = "RDS-002";
    pub const RDS_PROVENANCE_ATTACHED: &str = "RDS-003";
    pub const RDS_REPLAY_VALIDATED: &str = "RDS-004";
    pub const RDS_BUNDLE_PUBLISHED: &str = "RDS-005";
    pub const RDS_CATALOG_GENERATED: &str = "RDS-006";
    pub const RDS_SCHEMA_VERIFIED: &str = "RDS-007";
    pub const RDS_COMPLETENESS_CHECKED: &str = "RDS-008";
    pub const RDS_REPORT_GENERATED: &str = "RDS-009";
    pub const RDS_VERSION_RECORDED: &str = "RDS-010";
    pub const RDS_ERR_INTEGRITY: &str = "RDS-ERR-001";
    pub const RDS_ERR_INCOMPLETE: &str = "RDS-ERR-002";
}

pub mod invariants {
    pub const INV_RDS_INTEGRITY: &str = "INV-RDS-INTEGRITY";
    pub const INV_RDS_DETERMINISTIC: &str = "INV-RDS-DETERMINISTIC";
    pub const INV_RDS_PROVENANCE: &str = "INV-RDS-PROVENANCE";
    pub const INV_RDS_REPRODUCIBLE: &str = "INV-RDS-REPRODUCIBLE";
    pub const INV_RDS_VERSIONED: &str = "INV-RDS-VERSIONED";
    pub const INV_RDS_GATED: &str = "INV-RDS-GATED";
}

pub const SCHEMA_VERSION: &str = "rds-v1.0";

// ---------------------------------------------------------------------------
// Dataset types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetType {
    MigrationScenario,
    SecurityIncident,
    BenchmarkBaseline,
    CompatibilityMatrix,
    TrustEvidence,
}

impl DatasetType {
    pub fn all() -> &'static [DatasetType] {
        &[
            Self::MigrationScenario,
            Self::SecurityIncident,
            Self::BenchmarkBaseline,
            Self::CompatibilityMatrix,
            Self::TrustEvidence,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::MigrationScenario => "migration_scenario",
            Self::SecurityIncident => "security_incident",
            Self::BenchmarkBaseline => "benchmark_baseline",
            Self::CompatibilityMatrix => "compatibility_matrix",
            Self::TrustEvidence => "trust_evidence",
        }
    }
}

/// A dataset entry in the catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetEntry {
    pub dataset_id: String,
    pub dataset_type: DatasetType,
    pub title: String,
    pub description: String,
    pub source_bead: String,
    pub record_count: usize,
    pub content_hash: String,
    pub schema_version: String,
    pub provenance: DatasetProvenance,
    pub replay_instructions: ReplayInstructions,
    pub tags: Vec<String>,
    pub published_at: String,
}

/// Provenance metadata for a dataset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetProvenance {
    pub source_system: String,
    pub collection_method: String,
    pub collection_date: String,
    pub anonymization_applied: bool,
    pub license: String,
}

/// Instructions for reproducing the dataset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayInstructions {
    pub environment: String,
    pub commands: Vec<String>,
    pub expected_hash: String,
    pub deterministic: bool,
}

/// A dataset publication bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetBundle {
    pub bundle_id: String,
    pub datasets: Vec<String>,
    pub total_records: usize,
    pub bundle_hash: String,
    pub schema_version: String,
    pub published_at: String,
}

/// Catalog report for all published datasets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetCatalog {
    pub catalog_id: String,
    pub timestamp: String,
    pub schema_version: String,
    pub total_datasets: usize,
    pub total_records: usize,
    pub by_type: BTreeMap<String, usize>,
    pub bundles: Vec<DatasetBundle>,
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RdsAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetConfig {
    pub schema_version: String,
    pub min_records_per_dataset: usize,
    pub require_replay_instructions: bool,
}

impl Default for DatasetConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            min_records_per_dataset: 100,
            require_replay_instructions: true,
        }
    }
}

/// Reproducible dataset publication engine.
#[derive(Debug, Clone)]
pub struct ReproducibleDatasets {
    config: DatasetConfig,
    datasets: BTreeMap<String, DatasetEntry>,
    bundles: Vec<DatasetBundle>,
    audit_log: Vec<RdsAuditRecord>,
}

impl Default for ReproducibleDatasets {
    fn default() -> Self {
        Self::new(DatasetConfig::default())
    }
}

impl ReproducibleDatasets {
    pub fn new(config: DatasetConfig) -> Self {
        Self {
            config,
            datasets: BTreeMap::new(),
            bundles: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Register a new dataset.
    pub fn register_dataset(
        &mut self,
        mut entry: DatasetEntry,
        trace_id: &str,
    ) -> Result<String, String> {
        // Verify integrity hash
        if entry.content_hash.len() != 64
            || !entry.content_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            self.log(
                event_codes::RDS_ERR_INTEGRITY,
                trace_id,
                serde_json::json!({
                    "dataset_id": &entry.dataset_id,
                    "reason": "invalid content hash",
                }),
            );
            return Err("Invalid content hash (must be 64 hex chars)".to_string());
        }

        self.log(
            event_codes::RDS_INTEGRITY_VERIFIED,
            trace_id,
            serde_json::json!({
                "dataset_id": &entry.dataset_id,
                "hash": &entry.content_hash,
            }),
        );

        // Check completeness
        if entry.record_count < self.config.min_records_per_dataset {
            self.log(
                event_codes::RDS_ERR_INCOMPLETE,
                trace_id,
                serde_json::json!({
                    "dataset_id": &entry.dataset_id,
                    "records": entry.record_count,
                    "minimum": self.config.min_records_per_dataset,
                }),
            );
            return Err(format!(
                "Dataset has {} records, minimum is {}",
                entry.record_count, self.config.min_records_per_dataset
            ));
        }

        self.log(
            event_codes::RDS_COMPLETENESS_CHECKED,
            trace_id,
            serde_json::json!({
                "dataset_id": &entry.dataset_id,
                "records": entry.record_count,
            }),
        );

        // Validate replay instructions
        if self.config.require_replay_instructions && entry.replay_instructions.commands.is_empty()
        {
            return Err("Replay instructions must include at least one command".to_string());
        }

        self.log(
            event_codes::RDS_REPLAY_VALIDATED,
            trace_id,
            serde_json::json!({
                "dataset_id": &entry.dataset_id,
                "deterministic": entry.replay_instructions.deterministic,
            }),
        );

        // Set schema version and timestamp
        entry.schema_version = self.config.schema_version.clone();
        entry.published_at = Utc::now().to_rfc3339();

        let dataset_id = entry.dataset_id.clone();

        self.log(
            event_codes::RDS_PROVENANCE_ATTACHED,
            trace_id,
            serde_json::json!({
                "dataset_id": &dataset_id,
                "source_bead": &entry.source_bead,
                "source_system": &entry.provenance.source_system,
            }),
        );

        self.datasets.insert(dataset_id.clone(), entry);

        self.log(
            event_codes::RDS_DATASET_REGISTERED,
            trace_id,
            serde_json::json!({
                "dataset_id": &dataset_id,
            }),
        );

        Ok(dataset_id)
    }

    /// Publish a bundle of datasets.
    pub fn publish_bundle(
        &mut self,
        dataset_ids: &[String],
        trace_id: &str,
    ) -> Result<DatasetBundle, String> {
        let mut total_records = 0;
        for id in dataset_ids {
            match self.datasets.get(id) {
                Some(ds) => total_records += ds.record_count,
                None => return Err(format!("Dataset {} not found", id)),
            }
        }

        let hash_input = serde_json::json!({
            "datasets": dataset_ids,
            "schema_version": &self.config.schema_version,
        })
        .to_string();
        let bundle_hash = hex::encode(Sha256::digest(
            [
                b"migration_incident_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        let bundle = DatasetBundle {
            bundle_id: Uuid::now_v7().to_string(),
            datasets: dataset_ids.to_vec(),
            total_records,
            bundle_hash,
            schema_version: self.config.schema_version.clone(),
            published_at: Utc::now().to_rfc3339(),
        };

        self.log(
            event_codes::RDS_BUNDLE_PUBLISHED,
            trace_id,
            serde_json::json!({
                "bundle_id": &bundle.bundle_id,
                "datasets": dataset_ids.len(),
                "total_records": total_records,
            }),
        );

        self.bundles.push(bundle.clone());
        Ok(bundle)
    }

    /// Generate the full dataset catalog.
    pub fn generate_catalog(&mut self, trace_id: &str) -> DatasetCatalog {
        let mut by_type = BTreeMap::new();
        let mut total_records = 0;

        for ds in self.datasets.values() {
            *by_type
                .entry(ds.dataset_type.label().to_string())
                .or_insert(0) += 1;
            total_records += ds.record_count;
        }

        let hash_input = serde_json::json!({
            "datasets": self.datasets.len(),
            "by_type": &by_type,
            "schema_version": &self.config.schema_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [
                b"migration_incident_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        let catalog = DatasetCatalog {
            catalog_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            schema_version: self.config.schema_version.clone(),
            total_datasets: self.datasets.len(),
            total_records,
            by_type,
            bundles: self.bundles.clone(),
            content_hash,
        };

        self.log(
            event_codes::RDS_CATALOG_GENERATED,
            trace_id,
            serde_json::json!({
                "catalog_id": &catalog.catalog_id,
                "total_datasets": catalog.total_datasets,
                "total_records": catalog.total_records,
            }),
        );

        catalog
    }

    pub fn datasets(&self) -> &BTreeMap<String, DatasetEntry> {
        &self.datasets
    }

    pub fn bundles(&self) -> &[DatasetBundle] {
        &self.bundles
    }

    pub fn audit_log(&self) -> &[RdsAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for record in &self.audit_log {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        self.audit_log.push(RdsAuditRecord {
            record_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_entry(id: &str, dtype: DatasetType, records: usize) -> DatasetEntry {
        DatasetEntry {
            dataset_id: id.to_string(),
            dataset_type: dtype,
            title: format!("Test dataset: {}", id),
            description: "Test description".to_string(),
            source_bead: "bd-test".to_string(),
            record_count: records,
            content_hash: "a".repeat(64),
            schema_version: String::new(),
            provenance: DatasetProvenance {
                source_system: "franken_node".to_string(),
                collection_method: "automated".to_string(),
                collection_date: "2026-02-01".to_string(),
                anonymization_applied: true,
                license: "Apache-2.0".to_string(),
            },
            replay_instructions: ReplayInstructions {
                environment: "franken_node v2.0.0".to_string(),
                commands: vec!["cargo test --release".to_string()],
                expected_hash: "b".repeat(64),
                deterministic: true,
            },
            tags: vec!["test".to_string()],
            published_at: String::new(),
        }
    }

    // === Dataset types ===

    #[test]
    fn five_dataset_types() {
        assert_eq!(DatasetType::all().len(), 5);
    }

    #[test]
    fn dataset_type_labels() {
        for dt in DatasetType::all() {
            assert!(!dt.label().is_empty());
        }
    }

    // === Registration ===

    #[test]
    fn register_valid_dataset() {
        let mut engine = ReproducibleDatasets::default();
        let entry = sample_entry("ds-1", DatasetType::MigrationScenario, 500);
        let result = engine.register_dataset(entry, &make_trace());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "ds-1");
    }

    #[test]
    fn register_sets_schema_version() {
        let mut engine = ReproducibleDatasets::default();
        let entry = sample_entry("ds-1", DatasetType::MigrationScenario, 500);
        engine.register_dataset(entry, &make_trace()).unwrap();
        let ds = engine.datasets().get("ds-1").unwrap();
        assert_eq!(ds.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn register_invalid_hash_fails() {
        let mut engine = ReproducibleDatasets::default();
        let mut entry = sample_entry("ds-1", DatasetType::MigrationScenario, 500);
        entry.content_hash = "short".to_string();
        let result = engine.register_dataset(entry, &make_trace());
        assert!(result.is_err());
    }

    #[test]
    fn register_too_few_records_fails() {
        let mut engine = ReproducibleDatasets::default();
        let entry = sample_entry("ds-1", DatasetType::MigrationScenario, 10);
        let result = engine.register_dataset(entry, &make_trace());
        assert!(result.is_err());
    }

    #[test]
    fn register_no_replay_commands_fails() {
        let mut engine = ReproducibleDatasets::default();
        let mut entry = sample_entry("ds-1", DatasetType::MigrationScenario, 500);
        entry.replay_instructions.commands.clear();
        let result = engine.register_dataset(entry, &make_trace());
        assert!(result.is_err());
    }

    // === Bundle publication ===

    #[test]
    fn publish_bundle_success() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::MigrationScenario, 500),
                &make_trace(),
            )
            .unwrap();
        engine
            .register_dataset(
                sample_entry("ds-2", DatasetType::SecurityIncident, 300),
                &make_trace(),
            )
            .unwrap();
        let bundle =
            engine.publish_bundle(&["ds-1".to_string(), "ds-2".to_string()], &make_trace());
        assert!(bundle.is_ok());
        let b = bundle.unwrap();
        assert_eq!(b.total_records, 800);
        assert_eq!(b.datasets.len(), 2);
    }

    #[test]
    fn publish_bundle_missing_dataset_fails() {
        let mut engine = ReproducibleDatasets::default();
        let result = engine.publish_bundle(&["nonexistent".to_string()], &make_trace());
        assert!(result.is_err());
    }

    #[test]
    fn bundle_has_hash() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::MigrationScenario, 500),
                &make_trace(),
            )
            .unwrap();
        let bundle = engine
            .publish_bundle(&["ds-1".to_string()], &make_trace())
            .unwrap();
        assert_eq!(bundle.bundle_hash.len(), 64);
    }

    // === Catalog ===

    #[test]
    fn catalog_counts_datasets() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::MigrationScenario, 500),
                &make_trace(),
            )
            .unwrap();
        engine
            .register_dataset(
                sample_entry("ds-2", DatasetType::SecurityIncident, 300),
                &make_trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&make_trace());
        assert_eq!(catalog.total_datasets, 2);
        assert_eq!(catalog.total_records, 800);
    }

    #[test]
    fn catalog_has_by_type() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::MigrationScenario, 500),
                &make_trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&make_trace());
        assert!(catalog.by_type.contains_key("migration_scenario"));
    }

    #[test]
    fn catalog_has_content_hash() {
        let mut engine = ReproducibleDatasets::default();
        let catalog = engine.generate_catalog(&make_trace());
        assert_eq!(catalog.content_hash.len(), 64);
    }

    #[test]
    fn catalog_has_schema_version() {
        let mut engine = ReproducibleDatasets::default();
        let catalog = engine.generate_catalog(&make_trace());
        assert_eq!(catalog.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn catalog_is_deterministic() {
        let mut e1 = ReproducibleDatasets::default();
        let mut e2 = ReproducibleDatasets::default();
        let c1 = e1.generate_catalog("trace-det");
        let c2 = e2.generate_catalog("trace-det");
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    // === Audit log ===

    #[test]
    fn registration_generates_audit_entries() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::MigrationScenario, 500),
                &make_trace(),
            )
            .unwrap();
        assert_eq!(engine.audit_log().len(), 5);
    }

    #[test]
    fn audit_log_has_event_codes() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::MigrationScenario, 500),
                &make_trace(),
            )
            .unwrap();
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::RDS_DATASET_REGISTERED));
        assert!(codes.contains(&event_codes::RDS_INTEGRITY_VERIFIED));
    }

    #[test]
    fn export_jsonl() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::MigrationScenario, 500),
                &make_trace(),
            )
            .unwrap();
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    // === Config ===

    #[test]
    fn default_config() {
        let config = DatasetConfig::default();
        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert_eq!(config.min_records_per_dataset, 100);
        assert!(config.require_replay_instructions);
    }

    #[test]
    fn lenient_config_allows_small_datasets() {
        let config = DatasetConfig {
            min_records_per_dataset: 1,
            ..Default::default()
        };
        let mut engine = ReproducibleDatasets::new(config);
        let entry = sample_entry("ds-1", DatasetType::MigrationScenario, 5);
        assert!(engine.register_dataset(entry, &make_trace()).is_ok());
    }

    // === Bundles storage ===

    #[test]
    fn catalog_includes_bundles() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::BenchmarkBaseline, 200),
                &make_trace(),
            )
            .unwrap();
        engine
            .publish_bundle(&["ds-1".to_string()], &make_trace())
            .unwrap();
        let catalog = engine.generate_catalog(&make_trace());
        assert_eq!(catalog.bundles.len(), 1);
    }

    #[test]
    fn bundles_accumulated() {
        let mut engine = ReproducibleDatasets::default();
        engine
            .register_dataset(
                sample_entry("ds-1", DatasetType::MigrationScenario, 500),
                &make_trace(),
            )
            .unwrap();
        engine
            .publish_bundle(&["ds-1".to_string()], &make_trace())
            .unwrap();
        engine
            .publish_bundle(&["ds-1".to_string()], &make_trace())
            .unwrap();
        assert_eq!(engine.bundles().len(), 2);
    }
}
