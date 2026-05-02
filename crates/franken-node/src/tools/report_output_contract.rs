//! bd-1sgr: Reproducible technical report output contract (Section 16).
//!
//! Delivers multiple publishable reports with reproducible artifact bundles.
//! Manages report output contracts, artifact manifests, and reproducibility
//! verification across published report collections.
//!
//! # Capabilities
//!
//! - Report output contract with required artifact types
//! - Artifact manifest with integrity hashes
//! - Reproducibility verification for each report bundle
//! - Collection catalog with completeness tracking
//! - Version-stamped output contracts
//!
//! # Invariants
//!
//! - **INV-ROC-COMPLETE**: Every report bundle contains all required artifacts.
//! - **INV-ROC-DETERMINISTIC**: Same inputs produce same catalog output.
//! - **INV-ROC-INTEGRITY**: Every artifact has a content hash.
//! - **INV-ROC-REPRODUCIBLE**: Every bundle includes reproduction instructions.
//! - **INV-ROC-VERSIONED**: Contract version embedded in every bundle.
//! - **INV-ROC-AUDITABLE**: Every operation produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
const REPORT_OUTPUT_HASH_DOMAIN: &[u8] = b"report_output_hash_v1:";

fn contains_nul_byte(value: &str) -> bool {
    value.contains('\0')
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn report_output_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REPORT_OUTPUT_HASH_DOMAIN);
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn missing_required_artifact_count(artifacts: &[ArtifactEntry]) -> usize {
    REQUIRED_ARTIFACT_TYPES
        .iter()
        .filter(|required| {
            !artifacts
                .iter()
                .any(|artifact| artifact.artifact_type.as_str() == **required)
        })
        .count()
}

pub mod event_codes {
    pub const ROC_BUNDLE_CREATED: &str = "ROC-001";
    pub const ROC_ARTIFACT_ADDED: &str = "ROC-002";
    pub const ROC_INTEGRITY_VERIFIED: &str = "ROC-003";
    pub const ROC_COMPLETENESS_CHECKED: &str = "ROC-004";
    pub const ROC_REPRODUCIBILITY_VERIFIED: &str = "ROC-005";
    pub const ROC_CATALOG_GENERATED: &str = "ROC-006";
    pub const ROC_VERSION_EMBEDDED: &str = "ROC-007";
    pub const ROC_CONTRACT_VALIDATED: &str = "ROC-008";
    pub const ROC_COLLECTION_PUBLISHED: &str = "ROC-009";
    pub const ROC_MANIFEST_GENERATED: &str = "ROC-010";
    pub const ROC_ERR_INCOMPLETE: &str = "ROC-ERR-001";
    pub const ROC_ERR_HASH_MISMATCH: &str = "ROC-ERR-002";
}

pub mod invariants {
    pub const INV_ROC_COMPLETE: &str = "INV-ROC-COMPLETE";
    pub const INV_ROC_DETERMINISTIC: &str = "INV-ROC-DETERMINISTIC";
    pub const INV_ROC_INTEGRITY: &str = "INV-ROC-INTEGRITY";
    pub const INV_ROC_REPRODUCIBLE: &str = "INV-ROC-REPRODUCIBLE";
    pub const INV_ROC_VERSIONED: &str = "INV-ROC-VERSIONED";
    pub const INV_ROC_AUDITABLE: &str = "INV-ROC-AUDITABLE";
}

pub const CONTRACT_VERSION: &str = "roc-v1.0";

pub const REQUIRED_ARTIFACT_TYPES: &[&str] = &[
    "report_pdf",
    "data_bundle",
    "reproduction_script",
    "verification_evidence",
    "methodology_doc",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    TechnicalAnalysis,
    SecurityAssessment,
    PerformanceBenchmark,
    ComplianceReport,
    IncidentPostmortem,
}

impl ReportType {
    pub fn all() -> &'static [ReportType] {
        &[
            Self::TechnicalAnalysis,
            Self::SecurityAssessment,
            Self::PerformanceBenchmark,
            Self::ComplianceReport,
            Self::IncidentPostmortem,
        ]
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::TechnicalAnalysis => "technical_analysis",
            Self::SecurityAssessment => "security_assessment",
            Self::PerformanceBenchmark => "performance_benchmark",
            Self::ComplianceReport => "compliance_report",
            Self::IncidentPostmortem => "incident_postmortem",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub artifact_type: String,
    pub path: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportBundle {
    pub bundle_id: String,
    pub report_type: ReportType,
    pub title: String,
    pub artifacts: Vec<ArtifactEntry>,
    pub reproduction_command: String,
    pub contract_version: String,
    pub is_complete: bool,
    pub bundle_hash: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutputCatalog {
    pub catalog_id: String,
    pub timestamp: String,
    pub contract_version: String,
    pub total_bundles: usize,
    pub complete_bundles: usize,
    pub by_type: BTreeMap<String, usize>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RocAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ReportOutputContract {
    contract_version: String,
    bundles: BTreeMap<String, ReportBundle>,
    audit_log: Vec<RocAuditRecord>,
}

impl Default for ReportOutputContract {
    fn default() -> Self {
        Self {
            contract_version: CONTRACT_VERSION.to_string(),
            bundles: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }
}

impl ReportOutputContract {
    pub fn create_bundle(
        &mut self,
        mut bundle: ReportBundle,
        trace_id: &str,
    ) -> Result<String, String> {
        if contains_nul_byte(trace_id) {
            return Err("Trace id must not contain NUL bytes".to_string());
        }

        if bundle.bundle_id.trim().is_empty() {
            return Err("Bundle id must not be empty".to_string());
        }

        if contains_nul_byte(&bundle.bundle_id) {
            return Err("Bundle id must not contain NUL bytes".to_string());
        }

        if self.bundles.contains_key(&bundle.bundle_id) {
            return Err(format!("Bundle {} already exists", bundle.bundle_id));
        }

        if bundle.title.trim().is_empty() {
            return Err("Bundle title must not be empty".to_string());
        }

        if contains_nul_byte(&bundle.title) {
            return Err("Bundle title must not contain NUL bytes".to_string());
        }

        if bundle.reproduction_command.trim().is_empty() {
            return Err("Reproduction command must not be empty".to_string());
        }

        if contains_nul_byte(&bundle.reproduction_command) {
            return Err("Reproduction command must not contain NUL bytes".to_string());
        }

        // Check artifact integrity
        for art in &bundle.artifacts {
            if art.artifact_type.trim().is_empty() {
                return Err("Artifact type must not be empty".to_string());
            }
            if contains_nul_byte(&art.artifact_type) {
                return Err("Artifact type must not contain NUL bytes".to_string());
            }
            if art.path.trim().is_empty() {
                return Err(format!(
                    "Artifact path must not be empty: {}",
                    art.artifact_type
                ));
            }
            if contains_nul_byte(&art.path) {
                return Err(format!(
                    "Artifact path must not contain NUL bytes: {}",
                    art.artifact_type
                ));
            }
            if art.size_bytes == 0 {
                return Err(format!(
                    "Artifact size must be positive: {}",
                    art.artifact_type
                ));
            }
            if contains_nul_byte(&art.content_hash) {
                return Err(format!(
                    "Artifact hash must not contain NUL bytes: {}",
                    art.artifact_type
                ));
            }
            if art.content_hash.len() != 64
                || !art
                    .content_hash
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
            {
                self.log(
                    event_codes::ROC_ERR_HASH_MISMATCH,
                    trace_id,
                    serde_json::json!({"artifact_type": &art.artifact_type}),
                );
                return Err(format!("Invalid hash for artifact: {}", art.artifact_type));
            }
        }

        self.log(
            event_codes::ROC_INTEGRITY_VERIFIED,
            trace_id,
            serde_json::json!({
                "bundle_id": &bundle.bundle_id,
                "artifacts": bundle.artifacts.len(),
            }),
        );

        // Check completeness
        let missing_count = missing_required_artifact_count(&bundle.artifacts);
        bundle.is_complete = missing_count == 0;

        if !bundle.is_complete {
            self.log(
                event_codes::ROC_ERR_INCOMPLETE,
                trace_id,
                serde_json::json!({"missing": missing_count}),
            );
        }

        self.log(
            event_codes::ROC_COMPLETENESS_CHECKED,
            trace_id,
            serde_json::json!({"complete": bundle.is_complete}),
        );
        self.log(
            event_codes::ROC_REPRODUCIBILITY_VERIFIED,
            trace_id,
            serde_json::json!({"command": &bundle.reproduction_command}),
        );

        let hash_input = serde_json::json!({
            "title": &bundle.title,
            "type": bundle.report_type.label(),
            "artifacts": bundle.artifacts.len(),
        })
        .to_string();
        bundle.bundle_hash = report_output_hash(hash_input.as_bytes());
        bundle.contract_version = self.contract_version.clone();
        bundle.created_at = Utc::now().to_rfc3339();

        let bid = bundle.bundle_id.clone();
        self.log(
            event_codes::ROC_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({"version": &bundle.contract_version}),
        );
        self.bundles.insert(bid.clone(), bundle);
        self.log(
            event_codes::ROC_BUNDLE_CREATED,
            trace_id,
            serde_json::json!({"bundle_id": &bid}),
        );

        Ok(bid)
    }

    pub fn generate_catalog(&mut self, trace_id: &str) -> OutputCatalog {
        let mut by_type = BTreeMap::new();
        let mut complete: usize = 0;
        for b in self.bundles.values() {
            let count = by_type
                .entry(b.report_type.label().to_string())
                .or_insert(0usize);
            *count = count.saturating_add(1);
            if b.is_complete {
                complete = complete.saturating_add(1);
            }
        }

        let content_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"report_output_catalog_hash_v1:");
            hasher.update(len_to_u64(self.contract_version.len()).to_le_bytes());
            hasher.update(self.contract_version.as_bytes());
            hasher.update(len_to_u64(self.bundles.len()).to_le_bytes());
            hasher.update(len_to_u64(complete).to_le_bytes());
            hasher.update(len_to_u64(by_type.len()).to_le_bytes());
            for (type_name, count) in &by_type {
                hasher.update(len_to_u64(type_name.len()).to_le_bytes());
                hasher.update(type_name.as_bytes());
                hasher.update(len_to_u64(*count).to_le_bytes());
            }
            hex::encode(hasher.finalize())
        };

        self.log(
            event_codes::ROC_CATALOG_GENERATED,
            trace_id,
            serde_json::json!({"total": self.bundles.len(), "complete": complete}),
        );

        OutputCatalog {
            catalog_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            contract_version: self.contract_version.clone(),
            total_bundles: self.bundles.len(),
            complete_bundles: complete,
            by_type,
            content_hash,
        }
    }

    pub fn bundles(&self) -> &BTreeMap<String, ReportBundle> {
        &self.bundles
    }
    pub fn audit_log(&self) -> &[RocAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for r in &self.audit_log {
            lines.push(serde_json::to_string(r)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        push_bounded(
            &mut self.audit_log,
            RocAuditRecord {
                record_id: Uuid::now_v7().to_string(),
                event_code: event_code.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                trace_id: trace_id.to_string(),
                details,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trace() -> String {
        Uuid::now_v7().to_string()
    }
    fn sample_artifact(atype: &str) -> ArtifactEntry {
        ArtifactEntry {
            artifact_type: atype.to_string(),
            path: format!("/out/{}", atype),
            content_hash: "a".repeat(64),
            size_bytes: 1024,
        }
    }
    fn complete_bundle(id: &str) -> ReportBundle {
        ReportBundle {
            bundle_id: id.to_string(),
            report_type: ReportType::TechnicalAnalysis,
            title: "Test Report".to_string(),
            artifacts: REQUIRED_ARTIFACT_TYPES
                .iter()
                .map(|t| sample_artifact(t))
                .collect(),
            reproduction_command: "make reproduce".to_string(),
            contract_version: String::new(),
            is_complete: false,
            bundle_hash: String::new(),
            created_at: String::new(),
        }
    }
    fn partial_bundle(id: &str) -> ReportBundle {
        let mut b = complete_bundle(id);
        b.artifacts.truncate(2);
        b
    }
    fn remove_artifact_type(bundle: &mut ReportBundle, artifact_type: &str) {
        bundle
            .artifacts
            .retain(|artifact| artifact.artifact_type != artifact_type);
    }

    #[test]
    fn five_report_types() {
        assert_eq!(ReportType::all().len(), 5);
    }
    #[test]
    fn five_required_artifact_types() {
        assert_eq!(REQUIRED_ARTIFACT_TYPES.len(), 5);
    }
    #[test]
    fn create_complete_bundle() {
        let mut e = ReportOutputContract::default();
        assert!(e.create_bundle(complete_bundle("b-1"), &trace()).is_ok());
        assert!(e.bundles().get("b-1").unwrap().is_complete);
    }
    #[test]
    fn create_partial_bundle_incomplete() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(partial_bundle("b-1"), &trace()).unwrap();
        assert!(!e.bundles().get("b-1").unwrap().is_complete);
    }
    #[test]
    fn create_empty_repro_command_fails() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-1");
        b.reproduction_command = String::new();
        assert!(e.create_bundle(b, &trace()).is_err());
    }
    #[test]
    fn create_bad_hash_fails() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-1");
        b.artifacts[0].content_hash = "short".to_string();
        assert!(e.create_bundle(b, &trace()).is_err());
    }
    #[test]
    fn push_bounded_zero_capacity_drops_existing_records() {
        let mut records = vec![1, 2];

        push_bounded(&mut records, 3, 0);

        assert!(records.is_empty());
    }
    #[test]
    fn push_bounded_overfull_input_keeps_newest_record_window() {
        let mut records = vec![1, 2, 3, 4];

        push_bounded(&mut records, 5, 2);

        assert_eq!(records, vec![4, 5]);
    }
    #[test]
    fn whitespace_reproduction_command_does_not_store_bundle() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-whitespace-command");
        b.reproduction_command = " \t ".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("whitespace reproduction command should fail");

        assert!(err.contains("Reproduction command"));
        assert!(!e.bundles().contains_key("b-whitespace-command"));
    }
    #[test]
    fn uppercase_artifact_digest_is_rejected_as_non_canonical() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-uppercase-digest");
        b.artifacts[0].content_hash = "A".repeat(64);

        let err = e
            .create_bundle(b, &trace())
            .expect_err("uppercase artifact digest should fail");

        assert!(err.contains("report_pdf"));
        assert!(!e.bundles().contains_key("b-uppercase-digest"));
    }
    #[test]
    fn report_type_deserialize_rejects_display_case_label() {
        let result: Result<ReportType, _> = serde_json::from_str("\"TechnicalAnalysis\"");

        assert!(result.is_err(), "report types must use snake_case");
    }
    #[test]
    fn artifact_entry_deserialize_rejects_string_size() {
        let raw = serde_json::json!({
            "artifact_type": "report_pdf",
            "path": "/out/report.pdf",
            "content_hash": "a".repeat(64),
            "size_bytes": "1024"
        });

        let result: Result<ArtifactEntry, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "artifact sizes must remain numeric");
    }
    #[test]
    fn report_bundle_deserialize_rejects_missing_artifacts() {
        let raw = serde_json::json!({
            "bundle_id": "b-missing-artifacts",
            "report_type": "technical_analysis",
            "title": "Missing artifacts",
            "reproduction_command": "make reproduce",
            "contract_version": CONTRACT_VERSION,
            "is_complete": false,
            "bundle_hash": "b".repeat(64),
            "created_at": "2026-04-17T00:00:00Z"
        });

        let result: Result<ReportBundle, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "artifacts are required in bundles");
    }
    #[test]
    fn output_catalog_deserialize_rejects_string_bundle_count() {
        let raw = serde_json::json!({
            "catalog_id": "catalog-1",
            "timestamp": "2026-04-17T00:00:00Z",
            "contract_version": CONTRACT_VERSION,
            "total_bundles": "1",
            "complete_bundles": 1_usize,
            "by_type": {"technical_analysis": 1_usize},
            "content_hash": "c".repeat(64)
        });

        let result: Result<OutputCatalog, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "bundle counts must remain numeric");
    }
    #[test]
    fn audit_record_deserialize_rejects_missing_details() {
        let raw = serde_json::json!({
            "record_id": "record-1",
            "event_code": event_codes::ROC_BUNDLE_CREATED,
            "timestamp": "2026-04-17T00:00:00Z",
            "trace_id": "trace-1"
        });

        let result: Result<RocAuditRecord, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "audit details are required");
    }
    #[test]
    fn empty_reproduction_command_does_not_store_bundle() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-empty-command");
        b.reproduction_command = String::new();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("empty reproduction command should fail");

        assert!(err.contains("Reproduction command"));
        assert!(!e.bundles().contains_key("b-empty-command"));
    }
    #[test]
    fn invalid_short_artifact_digest_does_not_store_bundle() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-short-digest");
        b.artifacts[0].content_hash = "short".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("short artifact digest should fail");

        assert!(err.contains("report_pdf"));
        assert!(!e.bundles().contains_key("b-short-digest"));
    }
    #[test]
    fn invalid_non_hex_artifact_digest_does_not_store_bundle() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-non-hex-digest");
        b.artifacts[0].content_hash = "z".repeat(64);

        let err = e
            .create_bundle(b, &trace())
            .expect_err("non-hex artifact digest should fail");

        assert!(err.contains("report_pdf"));
        assert!(!e.bundles().contains_key("b-non-hex-digest"));
    }
    #[test]
    fn invalid_later_artifact_digest_reports_offending_type() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-late-digest");
        b.artifacts[3].content_hash = "x".repeat(64);

        let err = e
            .create_bundle(b, &trace())
            .expect_err("invalid later artifact digest should fail");

        assert!(err.contains("verification_evidence"));
        assert!(!e.bundles().contains_key("b-late-digest"));
    }
    #[test]
    fn empty_artifact_manifest_is_marked_incomplete() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-empty-manifest");
        b.artifacts.clear();

        e.create_bundle(b, &trace())
            .expect("empty manifest is accepted as incomplete evidence");

        assert!(!e.bundles().get("b-empty-manifest").unwrap().is_complete);
    }
    #[test]
    fn missing_each_required_artifact_type_marks_bundle_incomplete() {
        for artifact_type in REQUIRED_ARTIFACT_TYPES {
            let mut e = ReportOutputContract::default();
            let mut b = complete_bundle(&format!("b-missing-{artifact_type}"));
            remove_artifact_type(&mut b, artifact_type);
            let id = b.bundle_id.clone();

            e.create_bundle(b, &trace())
                .expect("missing artifact type should still create incomplete bundle");

            assert!(!e.bundles().get(&id).unwrap().is_complete);
        }
    }
    #[test]
    fn duplicate_artifact_type_does_not_satisfy_missing_required_type() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-duplicate-type");
        remove_artifact_type(&mut b, "data_bundle");
        b.artifacts.push(sample_artifact("report_pdf"));

        e.create_bundle(b, &trace())
            .expect("duplicate artifact type should create incomplete bundle");

        assert!(!e.bundles().get("b-duplicate-type").unwrap().is_complete);
    }
    #[test]
    fn artifact_type_matching_is_case_sensitive_for_completeness() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-case-sensitive-type");
        b.artifacts[0].artifact_type = "REPORT_PDF".to_string();

        e.create_bundle(b, &trace())
            .expect("mis-cased artifact type should create incomplete bundle");

        assert!(
            !e.bundles()
                .get("b-case-sensitive-type")
                .unwrap()
                .is_complete
        );
    }
    #[test]
    fn empty_bundle_id_does_not_store_bundle_or_emit_audit() {
        let mut e = ReportOutputContract::default();

        let err = e
            .create_bundle(complete_bundle(""), &trace())
            .expect_err("empty bundle id should fail");

        assert!(err.contains("Bundle id"));
        assert!(e.bundles().is_empty());
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn whitespace_title_does_not_store_bundle_or_emit_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-blank-title");
        b.title = " \n ".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("blank title should fail");

        assert!(err.contains("title"));
        assert!(!e.bundles().contains_key("b-blank-title"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn duplicate_bundle_id_does_not_overwrite_original() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-dupe"), &trace())
            .expect("first bundle should be accepted");
        let original_hash = e.bundles()["b-dupe"].bundle_hash.clone();
        let original_created_at = e.bundles()["b-dupe"].created_at.clone();
        let audit_count_before = e.audit_log().len();
        let mut duplicate = complete_bundle("b-dupe");
        duplicate.title = "Replacement report".to_string();

        let err = e
            .create_bundle(duplicate, &trace())
            .expect_err("duplicate bundle id should fail");

        assert!(err.contains("already exists"));
        assert_ne!(e.bundles()["b-dupe"].title, "Replacement report");
        assert_eq!(e.bundles()["b-dupe"].bundle_hash, original_hash);
        assert_eq!(e.bundles()["b-dupe"].created_at, original_created_at);
        assert_eq!(e.audit_log().len(), audit_count_before);
    }
    #[test]
    fn blank_artifact_type_does_not_store_bundle_or_emit_integrity_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-blank-artifact-type");
        b.artifacts[0].artifact_type = " \t ".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("blank artifact type should fail");

        assert!(err.contains("Artifact type"));
        assert!(!e.bundles().contains_key("b-blank-artifact-type"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn blank_artifact_path_does_not_store_bundle_or_emit_integrity_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-blank-artifact-path");
        b.artifacts[0].path = "\n ".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("blank artifact path should fail");

        assert!(err.contains("Artifact path"));
        assert!(!e.bundles().contains_key("b-blank-artifact-path"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn zero_size_artifact_does_not_store_bundle_or_emit_integrity_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-zero-size-artifact");
        b.artifacts[0].size_bytes = 0;

        let err = e
            .create_bundle(b, &trace())
            .expect_err("zero-size artifact should fail");

        assert!(err.contains("Artifact size"));
        assert!(!e.bundles().contains_key("b-zero-size-artifact"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn nul_trace_id_does_not_store_bundle_or_emit_audit() {
        let mut e = ReportOutputContract::default();

        let err = e
            .create_bundle(complete_bundle("b-nul-trace"), "trace\0bad")
            .expect_err("trace id with embedded NUL should fail");

        assert!(err.contains("Trace id"));
        assert!(!e.bundles().contains_key("b-nul-trace"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn nul_bundle_id_does_not_store_bundle_or_emit_audit() {
        let mut e = ReportOutputContract::default();

        let err = e
            .create_bundle(complete_bundle("b\0nul-id"), &trace())
            .expect_err("bundle id with embedded NUL should fail");

        assert!(err.contains("Bundle id"));
        assert!(!e.bundles().contains_key("b\0nul-id"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn nul_title_does_not_store_bundle_or_emit_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-nul-title");
        b.title = "Title\0Hidden".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("title with embedded NUL should fail");

        assert!(err.contains("title"));
        assert!(!e.bundles().contains_key("b-nul-title"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn nul_reproduction_command_does_not_store_bundle_or_emit_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-nul-command");
        b.reproduction_command = "make reproduce\0--skip".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("reproduction command with embedded NUL should fail");

        assert!(err.contains("Reproduction command"));
        assert!(!e.bundles().contains_key("b-nul-command"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn nul_artifact_type_does_not_store_bundle_or_emit_integrity_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-nul-artifact-type");
        b.artifacts[0].artifact_type = "report_pdf\0shadow".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("artifact type with embedded NUL should fail");

        assert!(err.contains("Artifact type"));
        assert!(!e.bundles().contains_key("b-nul-artifact-type"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn nul_artifact_path_does_not_store_bundle_or_emit_integrity_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-nul-artifact-path");
        b.artifacts[0].path = "/out/report.pdf\0hidden".to_string();

        let err = e
            .create_bundle(b, &trace())
            .expect_err("artifact path with embedded NUL should fail");

        assert!(err.contains("Artifact path"));
        assert!(!e.bundles().contains_key("b-nul-artifact-path"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn nul_artifact_hash_does_not_store_bundle_or_emit_integrity_audit() {
        let mut e = ReportOutputContract::default();
        let mut b = complete_bundle("b-nul-artifact-hash");
        let mut malformed = "a".repeat(63);
        malformed.push('\0');
        b.artifacts[0].content_hash = malformed;

        let err = e
            .create_bundle(b, &trace())
            .expect_err("artifact hash with embedded NUL should fail before audit logging");

        assert!(err.contains("Artifact hash"));
        assert!(!e.bundles().contains_key("b-nul-artifact-hash"));
        assert!(e.audit_log().is_empty());
    }
    #[test]
    fn create_sets_version() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        assert_eq!(
            e.bundles().get("b-1").unwrap().contract_version,
            CONTRACT_VERSION
        );
    }
    #[test]
    fn create_sets_hash() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        assert_eq!(e.bundles().get("b-1").unwrap().bundle_hash.len(), 64);
    }
    #[test]
    fn catalog_empty() {
        let mut e = ReportOutputContract::default();
        let c = e.generate_catalog(&trace());
        assert_eq!(c.total_bundles, 0);
    }
    #[test]
    fn catalog_counts() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        e.create_bundle(partial_bundle("b-2"), &trace()).unwrap();
        let c = e.generate_catalog(&trace());
        assert_eq!(c.total_bundles, 2);
        assert_eq!(c.complete_bundles, 1);
    }
    #[test]
    fn catalog_by_type() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        let c = e.generate_catalog(&trace());
        assert!(c.by_type.contains_key("technical_analysis"));
    }
    #[test]
    fn catalog_has_hash() {
        let mut e = ReportOutputContract::default();
        assert_eq!(e.generate_catalog(&trace()).content_hash.len(), 64);
    }
    #[test]
    fn catalog_deterministic() {
        let mut e1 = ReportOutputContract::default();
        let mut e2 = ReportOutputContract::default();
        assert_eq!(
            e1.generate_catalog("t").content_hash,
            e2.generate_catalog("t").content_hash
        );
    }
    #[test]
    fn audit_populated() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        assert_eq!(e.audit_log().len(), 5);
    }
    #[test]
    fn audit_has_codes() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        let codes: Vec<&str> = e
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::ROC_BUNDLE_CREATED));
    }
    #[test]
    fn export_jsonl() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        let jsonl = e.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }
    #[test]
    fn type_labels_unique() {
        let labels: Vec<&str> = ReportType::all().iter().map(|t| t.label()).collect();
        let mut dedup = labels.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(labels.len(), dedup.len());
    }
    #[test]
    fn create_sets_timestamp() {
        let mut e = ReportOutputContract::default();
        e.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        assert!(!e.bundles().get("b-1").unwrap().created_at.is_empty());
    }

    // === bd-3by7l: catalog hash coverage regressions ===

    #[test]
    fn catalog_hash_changes_with_complete_bundles() {
        // Same total bundles and same type distribution but different
        // completeness counts must produce different catalog hashes.
        let mut e1 = ReportOutputContract::default();
        let mut e2 = ReportOutputContract::default();
        // e1: one complete bundle
        e1.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        // e2: one incomplete bundle (same type, same total count)
        e2.create_bundle(partial_bundle("b-1"), &trace()).unwrap();
        let c1 = e1.generate_catalog(&trace());
        let c2 = e2.generate_catalog(&trace());
        assert_ne!(
            c1.content_hash, c2.content_hash,
            "Different complete_bundles count must produce different catalog hash"
        );
    }

    #[test]
    fn catalog_hash_changes_with_type_distribution() {
        // Same total count but different type distributions
        // must produce different catalog hashes.
        let mut e1 = ReportOutputContract::default();
        let mut e2 = ReportOutputContract::default();
        e1.create_bundle(complete_bundle("b-1"), &trace()).unwrap();
        let mut sec_bundle = complete_bundle("b-1");
        sec_bundle.report_type = ReportType::SecurityAssessment;
        e2.create_bundle(sec_bundle, &trace()).unwrap();
        let c1 = e1.generate_catalog(&trace());
        let c2 = e2.generate_catalog(&trace());
        assert_ne!(
            c1.content_hash, c2.content_hash,
            "Different type distribution must change catalog hash"
        );
    }
}
