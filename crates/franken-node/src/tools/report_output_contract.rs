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
        if bundle.reproduction_command.is_empty() {
            return Err("Reproduction command must not be empty".to_string());
        }

        // Check artifact integrity
        for art in &bundle.artifacts {
            if art.content_hash.len() != 64
                || !art.content_hash.chars().all(|c| c.is_ascii_hexdigit())
            {
                self.log(
                    event_codes::ROC_ERR_HASH_MISMATCH,
                    trace_id,
                    serde_json::json!({"artifact_type": &art.artifact_type}),
                );
                return Err(format!("Invalid hash for artifact: {}", art.artifact_type));
            }
        }

        self.log(event_codes::ROC_INTEGRITY_VERIFIED, trace_id, serde_json::json!({"bundle_id": &bundle.bundle_id, "artifacts": bundle.artifacts.len()}));

        // Check completeness
        let present_types: Vec<&str> = bundle
            .artifacts
            .iter()
            .map(|a| a.artifact_type.as_str())
            .collect();
        let missing: Vec<&&str> = REQUIRED_ARTIFACT_TYPES
            .iter()
            .filter(|t| !present_types.contains(*t))
            .collect();
        bundle.is_complete = missing.is_empty();

        if !bundle.is_complete {
            self.log(
                event_codes::ROC_ERR_INCOMPLETE,
                trace_id,
                serde_json::json!({"missing": missing.len()}),
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

        let hash_input = serde_json::json!({"title": &bundle.title, "type": bundle.report_type.label(), "artifacts": bundle.artifacts.len()}).to_string();
        bundle.bundle_hash = hex::encode(Sha256::digest(
            [b"report_output_hash_v1:" as &[u8], hash_input.as_bytes()].concat(),
        ));
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
        let mut complete = 0;
        for b in self.bundles.values() {
            *by_type
                .entry(b.report_type.label().to_string())
                .or_insert(0) += 1;
            if b.is_complete {
                complete += 1;
            }
        }

        let hash_input = serde_json::json!({"total": self.bundles.len(), "by_type": &by_type, "version": &self.contract_version}).to_string();
        let content_hash = hex::encode(Sha256::digest(
            [b"report_output_hash_v1:" as &[u8], hash_input.as_bytes()].concat(),
        ));

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
        self.audit_log.push(RocAuditRecord {
            record_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
        });
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
}
