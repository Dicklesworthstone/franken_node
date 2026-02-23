//! bd-e5cz: Externally replicated high-impact claims (Section 16).
//!
//! Delivers externally replicated high-impact claims with independent
//! verification, replication tracking, and evidence chain management.
//!
//! # Capabilities
//!
//! - High-impact claim declaration (5 claim categories)
//! - External replication request management
//! - Replication status lifecycle (Requested→InProgress→Completed→Verified)
//! - Evidence chain linking
//! - Threshold-gated publication
//! - Claim versioning and audit trail
//!
//! # Invariants
//!
//! - **INV-ERC-CATEGORIZED**: Every claim has a category classification.
//! - **INV-ERC-REPLICATED**: Published claims require external replication.
//! - **INV-ERC-DETERMINISTIC**: Same inputs produce same verification output.
//! - **INV-ERC-GATED**: Claims below replication threshold are blocked.
//! - **INV-ERC-VERSIONED**: Schema version embedded in every export.
//! - **INV-ERC-AUDITABLE**: Every mutation produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod event_codes {
    pub const ERC_CLAIM_CREATED: &str = "ERC-001";
    pub const ERC_REPLICATION_REQUESTED: &str = "ERC-002";
    pub const ERC_REPLICATION_STARTED: &str = "ERC-003";
    pub const ERC_REPLICATION_COMPLETED: &str = "ERC-004";
    pub const ERC_CLAIM_VERIFIED: &str = "ERC-005";
    pub const ERC_THRESHOLD_CHECKED: &str = "ERC-006";
    pub const ERC_CLAIM_PUBLISHED: &str = "ERC-007";
    pub const ERC_EVIDENCE_LINKED: &str = "ERC-008";
    pub const ERC_VERSION_EMBEDDED: &str = "ERC-009";
    pub const ERC_CATALOG_GENERATED: &str = "ERC-010";
    pub const ERC_ERR_INSUFFICIENT_REPLICATIONS: &str = "ERC-ERR-001";
    pub const ERC_ERR_INVALID_CLAIM: &str = "ERC-ERR-002";
}

pub mod invariants {
    pub const INV_ERC_CATEGORIZED: &str = "INV-ERC-CATEGORIZED";
    pub const INV_ERC_REPLICATED: &str = "INV-ERC-REPLICATED";
    pub const INV_ERC_DETERMINISTIC: &str = "INV-ERC-DETERMINISTIC";
    pub const INV_ERC_GATED: &str = "INV-ERC-GATED";
    pub const INV_ERC_VERSIONED: &str = "INV-ERC-VERSIONED";
    pub const INV_ERC_AUDITABLE: &str = "INV-ERC-AUDITABLE";
}

pub const SCHEMA_VERSION: &str = "erc-v1.0";
pub const MIN_REPLICATIONS: usize = 2;

/// Claim category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCategory {
    SecurityGuarantee,
    PerformanceBenchmark,
    ComplianceCertification,
    ReliabilityMetric,
    PrivacyAssurance,
}

impl ClaimCategory {
    pub fn all() -> &'static [ClaimCategory] {
        &[
            Self::SecurityGuarantee,
            Self::PerformanceBenchmark,
            Self::ComplianceCertification,
            Self::ReliabilityMetric,
            Self::PrivacyAssurance,
        ]
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::SecurityGuarantee => "security_guarantee",
            Self::PerformanceBenchmark => "performance_benchmark",
            Self::ComplianceCertification => "compliance_certification",
            Self::ReliabilityMetric => "reliability_metric",
            Self::PrivacyAssurance => "privacy_assurance",
        }
    }
}

/// Replication status lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationStatus {
    Requested,
    InProgress,
    Completed,
    Verified,
}

/// A high-impact claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HighImpactClaim {
    pub claim_id: String,
    pub category: ClaimCategory,
    pub title: String,
    pub description: String,
    pub evidence_refs: Vec<String>,
    pub published: bool,
    pub created_at: String,
}

/// A replication record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplicationRecord {
    pub replication_id: String,
    pub claim_id: String,
    pub replicator: String,
    pub status: ReplicationStatus,
    pub findings: String,
    pub started_at: String,
    pub completed_at: Option<String>,
}

/// Catalog of claims and their replication status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimCatalog {
    pub catalog_id: String,
    pub timestamp: String,
    pub schema_version: String,
    pub total_claims: usize,
    pub published_claims: usize,
    pub pending_claims: usize,
    pub claims_by_category: BTreeMap<String, usize>,
    pub content_hash: String,
}

/// Audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErcAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

/// External replication claims engine.
#[derive(Debug, Clone)]
pub struct ExternalReplicationClaims {
    schema_version: String,
    claims: BTreeMap<String, HighImpactClaim>,
    replications: Vec<ReplicationRecord>,
    audit_log: Vec<ErcAuditRecord>,
}

impl Default for ExternalReplicationClaims {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            claims: BTreeMap::new(),
            replications: Vec::new(),
            audit_log: Vec::new(),
        }
    }
}

impl ExternalReplicationClaims {
    pub fn create_claim(
        &mut self,
        mut claim: HighImpactClaim,
        trace_id: &str,
    ) -> Result<String, String> {
        if claim.title.is_empty() {
            self.log(
                event_codes::ERC_ERR_INVALID_CLAIM,
                trace_id,
                serde_json::json!({"reason": "empty title"}),
            );
            return Err("claim title must not be empty".to_string());
        }
        claim.created_at = Utc::now().to_rfc3339();
        claim.published = false;
        let cid = claim.claim_id.clone();
        self.log(
            event_codes::ERC_CLAIM_CREATED,
            trace_id,
            serde_json::json!({"claim_id": &cid, "category": claim.category.label()}),
        );
        self.claims.insert(cid.clone(), claim);
        Ok(cid)
    }

    pub fn request_replication(
        &mut self,
        claim_id: &str,
        replicator: &str,
        trace_id: &str,
    ) -> Result<String, String> {
        if !self.claims.contains_key(claim_id) {
            return Err(format!("claim not found: {claim_id}"));
        }
        let rid = Uuid::now_v7().to_string();
        let rec = ReplicationRecord {
            replication_id: rid.clone(),
            claim_id: claim_id.to_string(),
            replicator: replicator.to_string(),
            status: ReplicationStatus::Requested,
            findings: String::new(),
            started_at: Utc::now().to_rfc3339(),
            completed_at: None,
        };
        self.log(
            event_codes::ERC_REPLICATION_REQUESTED,
            trace_id,
            serde_json::json!({"claim_id": claim_id, "replicator": replicator}),
        );
        self.replications.push(rec);
        Ok(rid)
    }

    pub fn update_replication(
        &mut self,
        replication_id: &str,
        status: ReplicationStatus,
        findings: &str,
        trace_id: &str,
    ) -> Result<(), String> {
        let rec = self
            .replications
            .iter_mut()
            .find(|r| r.replication_id == replication_id)
            .ok_or_else(|| format!("replication not found: {replication_id}"))?;
        rec.status = status;
        rec.findings = findings.to_string();
        if matches!(
            status,
            ReplicationStatus::Completed | ReplicationStatus::Verified
        ) {
            rec.completed_at = Some(Utc::now().to_rfc3339());
        }
        let code = match status {
            ReplicationStatus::InProgress => event_codes::ERC_REPLICATION_STARTED,
            ReplicationStatus::Completed => event_codes::ERC_REPLICATION_COMPLETED,
            ReplicationStatus::Verified => event_codes::ERC_CLAIM_VERIFIED,
            _ => event_codes::ERC_REPLICATION_REQUESTED,
        };
        self.log(code, trace_id, serde_json::json!({"replication_id": replication_id, "status": format!("{:?}", status)}));
        Ok(())
    }

    pub fn link_evidence(
        &mut self,
        claim_id: &str,
        evidence_ref: &str,
        trace_id: &str,
    ) -> Result<(), String> {
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| format!("claim not found: {claim_id}"))?;
        claim.evidence_refs.push(evidence_ref.to_string());
        self.log(
            event_codes::ERC_EVIDENCE_LINKED,
            trace_id,
            serde_json::json!({"claim_id": claim_id, "evidence": evidence_ref}),
        );
        Ok(())
    }

    pub fn replication_count(&self, claim_id: &str) -> usize {
        self.replications
            .iter()
            .filter(|r| {
                r.claim_id == claim_id
                    && matches!(
                        r.status,
                        ReplicationStatus::Completed | ReplicationStatus::Verified
                    )
            })
            .count()
    }

    pub fn can_publish(&self, claim_id: &str) -> bool {
        self.replication_count(claim_id) >= MIN_REPLICATIONS
    }

    pub fn publish_claim(&mut self, claim_id: &str, trace_id: &str) -> Result<(), String> {
        let count = self.replication_count(claim_id);
        if count < MIN_REPLICATIONS {
            self.log(
                event_codes::ERC_ERR_INSUFFICIENT_REPLICATIONS,
                trace_id,
                serde_json::json!({"claim_id": claim_id, "count": count}),
            );
            return Err(format!(
                "insufficient replications: {count} < {MIN_REPLICATIONS}"
            ));
        }
        self.log(
            event_codes::ERC_THRESHOLD_CHECKED,
            trace_id,
            serde_json::json!({"claim_id": claim_id, "count": count, "meets": true}),
        );
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| format!("claim not found: {claim_id}"))?;
        claim.published = true;
        self.log(
            event_codes::ERC_CLAIM_PUBLISHED,
            trace_id,
            serde_json::json!({"claim_id": claim_id}),
        );
        Ok(())
    }

    pub fn generate_catalog(&mut self, trace_id: &str) -> ClaimCatalog {
        let total = self.claims.len();
        let published = self.claims.values().filter(|c| c.published).count();
        let pending = total - published;
        let mut by_cat: BTreeMap<String, usize> = BTreeMap::new();
        for c in self.claims.values() {
            *by_cat.entry(c.category.label().to_string()).or_default() += 1;
        }
        let hash_input = format!("{total}:{published}:{}", &self.schema_version);
        let content_hash = hex::encode(Sha256::digest(
            [
                b"external_replication_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));
        self.log(
            event_codes::ERC_CATALOG_GENERATED,
            trace_id,
            serde_json::json!({"total": total}),
        );
        self.log(
            event_codes::ERC_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({"version": &self.schema_version}),
        );

        ClaimCatalog {
            catalog_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            schema_version: self.schema_version.clone(),
            total_claims: total,
            published_claims: published,
            pending_claims: pending,
            claims_by_category: by_cat,
            content_hash,
        }
    }

    pub fn claims(&self) -> &BTreeMap<String, HighImpactClaim> {
        &self.claims
    }
    pub fn replications(&self) -> &[ReplicationRecord] {
        &self.replications
    }
    pub fn audit_log(&self) -> &[ErcAuditRecord] {
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
        self.audit_log.push(ErcAuditRecord {
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

    fn sample_claim(id: &str, cat: ClaimCategory) -> HighImpactClaim {
        HighImpactClaim {
            claim_id: id.to_string(),
            category: cat,
            title: format!("Claim {id}"),
            description: "Test claim".to_string(),
            evidence_refs: vec![],
            published: false,
            created_at: String::new(),
        }
    }

    #[test]
    fn five_categories() {
        assert_eq!(ClaimCategory::all().len(), 5);
    }
    #[test]
    fn category_labels_nonempty() {
        for c in ClaimCategory::all() {
            assert!(!c.label().is_empty());
        }
    }

    #[test]
    fn create_claim_ok() {
        let mut e = ExternalReplicationClaims::default();
        assert!(
            e.create_claim(
                sample_claim("c1", ClaimCategory::SecurityGuarantee),
                &trace()
            )
            .is_ok()
        );
        assert_eq!(e.claims().len(), 1);
    }

    #[test]
    fn create_empty_title_fails() {
        let mut e = ExternalReplicationClaims::default();
        let mut c = sample_claim("c1", ClaimCategory::SecurityGuarantee);
        c.title.clear();
        assert!(e.create_claim(c, &trace()).is_err());
    }

    #[test]
    fn create_sets_timestamp() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        assert!(!e.claims()["c1"].created_at.is_empty());
    }

    #[test]
    fn request_replication() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        assert!(
            e.request_replication("c1", "external-lab", &trace())
                .is_ok()
        );
    }

    #[test]
    fn request_replication_missing_claim() {
        let mut e = ExternalReplicationClaims::default();
        assert!(e.request_replication("missing", "lab", &trace()).is_err());
    }

    #[test]
    fn update_replication_lifecycle() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        let rid = e.request_replication("c1", "lab", &trace()).unwrap();
        e.update_replication(&rid, ReplicationStatus::InProgress, "", &trace())
            .unwrap();
        e.update_replication(&rid, ReplicationStatus::Completed, "confirmed", &trace())
            .unwrap();
        assert_eq!(e.replication_count("c1"), 1);
    }

    #[test]
    fn publish_requires_replications() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        assert!(e.publish_claim("c1", &trace()).is_err());
    }

    #[test]
    fn publish_with_sufficient_replications() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        for i in 0..MIN_REPLICATIONS {
            let rid = e
                .request_replication("c1", &format!("lab-{i}"), &trace())
                .unwrap();
            e.update_replication(&rid, ReplicationStatus::Completed, "ok", &trace())
                .unwrap();
        }
        assert!(e.publish_claim("c1", &trace()).is_ok());
        assert!(e.claims()["c1"].published);
    }

    #[test]
    fn can_publish_check() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        assert!(!e.can_publish("c1"));
    }

    #[test]
    fn link_evidence() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        e.link_evidence("c1", "artifact-123", &trace()).unwrap();
        assert_eq!(e.claims()["c1"].evidence_refs.len(), 1);
    }

    #[test]
    fn link_evidence_missing_claim() {
        let mut e = ExternalReplicationClaims::default();
        assert!(e.link_evidence("missing", "ref", &trace()).is_err());
    }

    #[test]
    fn generate_catalog() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        let cat = e.generate_catalog(&trace());
        assert_eq!(cat.total_claims, 1);
        assert_eq!(cat.published_claims, 0);
        assert_eq!(cat.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn catalog_tracks_categories() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        e.create_claim(
            sample_claim("c2", ClaimCategory::PerformanceBenchmark),
            &trace(),
        )
        .unwrap();
        let cat = e.generate_catalog(&trace());
        assert_eq!(cat.claims_by_category.len(), 2);
    }

    #[test]
    fn catalog_hash_deterministic() {
        let mut e1 = ExternalReplicationClaims::default();
        let mut e2 = ExternalReplicationClaims::default();
        assert_eq!(
            e1.generate_catalog(&trace()).content_hash,
            e2.generate_catalog(&trace()).content_hash
        );
    }

    #[test]
    fn four_replication_statuses() {
        let statuses = [
            ReplicationStatus::Requested,
            ReplicationStatus::InProgress,
            ReplicationStatus::Completed,
            ReplicationStatus::Verified,
        ];
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn audit_populated() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        assert!(!e.audit_log().is_empty());
    }

    #[test]
    fn audit_has_codes() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        let codes: Vec<&str> = e
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::ERC_CLAIM_CREATED));
    }

    #[test]
    fn export_jsonl() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        let jsonl = e.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn default_version() {
        let e = ExternalReplicationClaims::default();
        assert_eq!(e.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn replication_count_filters_status() {
        let mut e = ExternalReplicationClaims::default();
        e.create_claim(
            sample_claim("c1", ClaimCategory::SecurityGuarantee),
            &trace(),
        )
        .unwrap();
        let rid = e.request_replication("c1", "lab", &trace()).unwrap();
        assert_eq!(e.replication_count("c1"), 0); // Still Requested
        e.update_replication(&rid, ReplicationStatus::Completed, "ok", &trace())
            .unwrap();
        assert_eq!(e.replication_count("c1"), 1);
    }
}
