//! bd-3id1: External red-team and independent evaluations (Section 16).
//!
//! Manages publication of external red-team reports and independent evaluation
//! results. Tracks engagement scope, finding severity, remediation status,
//! and evaluation confidence levels.
//!
//! # Capabilities
//!
//! - Red-team engagement registration with scope and rules of engagement
//! - Finding submission with severity classification (Critical/High/Medium/Low/Info)
//! - Remediation tracking (Open → InProgress → Resolved → Verified)
//! - Independent evaluation reports with confidence scoring
//! - Evaluation catalog with filtering by type and status
//! - Content-addressed integrity hashing
//!
//! # Invariants
//!
//! - **INV-RTE-SCOPED**: Every engagement has defined scope and rules.
//! - **INV-RTE-DETERMINISTIC**: Same inputs produce same catalog output.
//! - **INV-RTE-CLASSIFIED**: Every finding has severity classification.
//! - **INV-RTE-TRACKED**: Every finding has remediation status tracking.
//! - **INV-RTE-VERSIONED**: Schema version embedded in every report.
//! - **INV-RTE-AUDITABLE**: Every state change produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const RTE_ENGAGEMENT_CREATED: &str = "RTE-001";
    pub const RTE_FINDING_SUBMITTED: &str = "RTE-002";
    pub const RTE_SEVERITY_ASSIGNED: &str = "RTE-003";
    pub const RTE_REMEDIATION_UPDATED: &str = "RTE-004";
    pub const RTE_EVALUATION_PUBLISHED: &str = "RTE-005";
    pub const RTE_CATALOG_GENERATED: &str = "RTE-006";
    pub const RTE_INTEGRITY_VERIFIED: &str = "RTE-007";
    pub const RTE_VERSION_EMBEDDED: &str = "RTE-008";
    pub const RTE_CONFIDENCE_SCORED: &str = "RTE-009";
    pub const RTE_SCOPE_VALIDATED: &str = "RTE-010";
    pub const RTE_ERR_INVALID_TRANSITION: &str = "RTE-ERR-001";
    pub const RTE_ERR_MISSING_SCOPE: &str = "RTE-ERR-002";
}

pub mod invariants {
    pub const INV_RTE_SCOPED: &str = "INV-RTE-SCOPED";
    pub const INV_RTE_DETERMINISTIC: &str = "INV-RTE-DETERMINISTIC";
    pub const INV_RTE_CLASSIFIED: &str = "INV-RTE-CLASSIFIED";
    pub const INV_RTE_TRACKED: &str = "INV-RTE-TRACKED";
    pub const INV_RTE_VERSIONED: &str = "INV-RTE-VERSIONED";
    pub const INV_RTE_AUDITABLE: &str = "INV-RTE-AUDITABLE";
}

pub const SCHEMA_VERSION: &str = "rte-v1.0";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl FindingSeverity {
    pub fn all() -> &'static [FindingSeverity] {
        &[
            Self::Critical,
            Self::High,
            Self::Medium,
            Self::Low,
            Self::Informational,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Informational => "informational",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    Open,
    InProgress,
    Resolved,
    Verified,
}

impl RemediationStatus {
    pub fn valid_transitions(&self) -> &'static [RemediationStatus] {
        match self {
            Self::Open => &[Self::InProgress],
            Self::InProgress => &[Self::Open, Self::Resolved],
            Self::Resolved => &[Self::Verified, Self::InProgress],
            Self::Verified => &[],
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in_progress",
            Self::Resolved => "resolved",
            Self::Verified => "verified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationType {
    RedTeam,
    PenetrationTest,
    SecurityAudit,
    IndependentReview,
    FormalVerification,
}

impl EvaluationType {
    pub fn all() -> &'static [EvaluationType] {
        &[
            Self::RedTeam,
            Self::PenetrationTest,
            Self::SecurityAudit,
            Self::IndependentReview,
            Self::FormalVerification,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::RedTeam => "red_team",
            Self::PenetrationTest => "penetration_test",
            Self::SecurityAudit => "security_audit",
            Self::IndependentReview => "independent_review",
            Self::FormalVerification => "formal_verification",
        }
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Engagement {
    pub engagement_id: String,
    pub eval_type: EvaluationType,
    pub title: String,
    pub scope: Vec<String>,
    pub rules_of_engagement: String,
    pub evaluator: String,
    pub findings: Vec<Finding>,
    pub confidence_score: f64,
    pub schema_version: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub description: String,
    pub remediation_status: RemediationStatus,
    pub affected_components: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationCatalog {
    pub catalog_id: String,
    pub timestamp: String,
    pub schema_version: String,
    pub total_engagements: usize,
    pub total_findings: usize,
    pub by_type: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<String, usize>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RteAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RedTeamEvaluations {
    schema_version: String,
    engagements: BTreeMap<String, Engagement>,
    audit_log: Vec<RteAuditRecord>,
}

impl Default for RedTeamEvaluations {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            engagements: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }
}

impl RedTeamEvaluations {
    pub fn create_engagement(
        &mut self,
        mut engagement: Engagement,
        trace_id: &str,
    ) -> Result<String, String> {
        if engagement.scope.is_empty() {
            self.log(
                event_codes::RTE_ERR_MISSING_SCOPE,
                trace_id,
                serde_json::json!({
                    "engagement_id": &engagement.engagement_id,
                }),
            );
            return Err("Engagement must have at least one scope item".to_string());
        }

        if engagement.rules_of_engagement.is_empty() {
            return Err("Rules of engagement must not be empty".to_string());
        }

        self.log(
            event_codes::RTE_SCOPE_VALIDATED,
            trace_id,
            serde_json::json!({
                "engagement_id": &engagement.engagement_id,
                "scope_items": engagement.scope.len(),
            }),
        );

        if !(0.0..=1.0).contains(&engagement.confidence_score) {
            return Err("Confidence score must be between 0.0 and 1.0".to_string());
        }

        self.log(
            event_codes::RTE_CONFIDENCE_SCORED,
            trace_id,
            serde_json::json!({
                "engagement_id": &engagement.engagement_id,
                "confidence": engagement.confidence_score,
            }),
        );

        engagement.schema_version = self.schema_version.clone();
        engagement.created_at = Utc::now().to_rfc3339();
        let eid = engagement.engagement_id.clone();

        self.log(
            event_codes::RTE_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({
                "engagement_id": &eid,
                "schema_version": &engagement.schema_version,
            }),
        );

        self.engagements.insert(eid.clone(), engagement);

        self.log(
            event_codes::RTE_ENGAGEMENT_CREATED,
            trace_id,
            serde_json::json!({
                "engagement_id": &eid,
            }),
        );

        Ok(eid)
    }

    pub fn add_finding(
        &mut self,
        engagement_id: &str,
        finding: Finding,
        trace_id: &str,
    ) -> Result<(), String> {
        if !self.engagements.contains_key(engagement_id) {
            return Err(format!("Engagement {} not found", engagement_id));
        }

        let finding_id = finding.finding_id.clone();
        let severity = finding.severity;

        self.log(
            event_codes::RTE_FINDING_SUBMITTED,
            trace_id,
            serde_json::json!({
                "engagement_id": engagement_id,
                "finding_id": &finding_id,
            }),
        );

        self.log(
            event_codes::RTE_SEVERITY_ASSIGNED,
            trace_id,
            serde_json::json!({
                "finding_id": &finding_id,
                "severity": severity.label(),
            }),
        );

        self.engagements
            .get_mut(engagement_id)
            .expect("validated: engagement existence checked above")
            .findings
            .push(finding);
        Ok(())
    }

    pub fn update_remediation(
        &mut self,
        engagement_id: &str,
        finding_id: &str,
        new_status: RemediationStatus,
        trace_id: &str,
    ) -> Result<(), String> {
        let engagement = self
            .engagements
            .get(engagement_id)
            .ok_or_else(|| format!("Engagement {} not found", engagement_id))?;

        let finding = engagement
            .findings
            .iter()
            .find(|f| f.finding_id == finding_id)
            .ok_or_else(|| format!("Finding {} not found", finding_id))?;

        let current = finding.remediation_status;
        if !current.valid_transitions().contains(&new_status) {
            self.log(
                event_codes::RTE_ERR_INVALID_TRANSITION,
                trace_id,
                serde_json::json!({
                    "finding_id": finding_id,
                    "from": current.label(),
                    "to": new_status.label(),
                }),
            );
            return Err(format!(
                "Cannot transition from {} to {}",
                current.label(),
                new_status.label()
            ));
        }

        // Apply mutation — both engagement and finding validated via immutable get() above
        let engagement_mut = self
            .engagements
            .get_mut(engagement_id)
            .expect("validated: engagement checked via immutable get()");
        let finding_mut = engagement_mut
            .findings
            .iter_mut()
            .find(|f| f.finding_id == finding_id)
            .expect("validated: finding checked via immutable find()");
        finding_mut.remediation_status = new_status;

        self.log(
            event_codes::RTE_REMEDIATION_UPDATED,
            trace_id,
            serde_json::json!({
                "finding_id": finding_id,
                "new_status": new_status.label(),
            }),
        );

        Ok(())
    }

    pub fn generate_catalog(&mut self, trace_id: &str) -> EvaluationCatalog {
        let mut by_type = BTreeMap::new();
        let mut by_severity = BTreeMap::new();
        let mut total_findings = 0;

        for eng in self.engagements.values() {
            *by_type
                .entry(eng.eval_type.label().to_string())
                .or_insert(0) += 1;
            for f in &eng.findings {
                *by_severity
                    .entry(f.severity.label().to_string())
                    .or_insert(0) += 1;
                total_findings += 1;
            }
        }

        let hash_input = serde_json::json!({
            "total_engagements": self.engagements.len(),
            "total_findings": total_findings,
            "schema_version": &self.schema_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [
                b"redteam_evaluations_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        self.log(
            event_codes::RTE_CATALOG_GENERATED,
            trace_id,
            serde_json::json!({
                "total_engagements": self.engagements.len(),
                "total_findings": total_findings,
            }),
        );

        EvaluationCatalog {
            catalog_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            schema_version: self.schema_version.clone(),
            total_engagements: self.engagements.len(),
            total_findings,
            by_type,
            by_severity,
            content_hash,
        }
    }

    pub fn engagements(&self) -> &BTreeMap<String, Engagement> {
        &self.engagements
    }
    pub fn audit_log(&self) -> &[RteAuditRecord] {
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
        self.audit_log.push(RteAuditRecord {
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

    fn trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_engagement(id: &str) -> Engagement {
        Engagement {
            engagement_id: id.to_string(),
            eval_type: EvaluationType::RedTeam,
            title: format!("Red-team engagement: {}", id),
            scope: vec!["API layer".to_string(), "Authentication".to_string()],
            rules_of_engagement: "No production data access".to_string(),
            evaluator: "External Firm A".to_string(),
            findings: vec![],
            confidence_score: 0.85,
            schema_version: String::new(),
            created_at: String::new(),
        }
    }

    fn sample_finding(id: &str, severity: FindingSeverity) -> Finding {
        Finding {
            finding_id: id.to_string(),
            title: format!("Finding: {}", id),
            severity,
            description: "Test finding".to_string(),
            remediation_status: RemediationStatus::Open,
            affected_components: vec!["api".to_string()],
        }
    }

    #[test]
    fn five_severity_levels() {
        assert_eq!(FindingSeverity::all().len(), 5);
    }

    #[test]
    fn five_evaluation_types() {
        assert_eq!(EvaluationType::all().len(), 5);
    }

    #[test]
    fn remediation_transitions() {
        assert!(!RemediationStatus::Open.valid_transitions().is_empty());
        assert!(RemediationStatus::Verified.valid_transitions().is_empty());
    }

    #[test]
    fn create_valid_engagement() {
        let mut engine = RedTeamEvaluations::default();
        assert!(
            engine
                .create_engagement(sample_engagement("eng-1"), &trace())
                .is_ok()
        );
    }

    #[test]
    fn create_empty_scope_fails() {
        let mut engine = RedTeamEvaluations::default();
        let mut e = sample_engagement("eng-1");
        e.scope.clear();
        assert!(engine.create_engagement(e, &trace()).is_err());
    }

    #[test]
    fn create_empty_rules_fails() {
        let mut engine = RedTeamEvaluations::default();
        let mut e = sample_engagement("eng-1");
        e.rules_of_engagement = String::new();
        assert!(engine.create_engagement(e, &trace()).is_err());
    }

    #[test]
    fn create_invalid_confidence_fails() {
        let mut engine = RedTeamEvaluations::default();
        let mut e = sample_engagement("eng-1");
        e.confidence_score = 1.5;
        assert!(engine.create_engagement(e, &trace()).is_err());
    }

    #[test]
    fn create_sets_version() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        let stored = engine.engagements().get("eng-1").unwrap();
        assert_eq!(stored.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn add_finding_success() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        assert!(
            engine
                .add_finding(
                    "eng-1",
                    sample_finding("f-1", FindingSeverity::High),
                    &trace()
                )
                .is_ok()
        );
    }

    #[test]
    fn add_finding_missing_engagement_fails() {
        let mut engine = RedTeamEvaluations::default();
        assert!(
            engine
                .add_finding(
                    "nonexistent",
                    sample_finding("f-1", FindingSeverity::Low),
                    &trace()
                )
                .is_err()
        );
    }

    #[test]
    fn remediation_open_to_in_progress() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::High),
                &trace(),
            )
            .unwrap();
        assert!(
            engine
                .update_remediation("eng-1", "f-1", RemediationStatus::InProgress, &trace())
                .is_ok()
        );
    }

    #[test]
    fn remediation_invalid_transition_fails() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::High),
                &trace(),
            )
            .unwrap();
        assert!(
            engine
                .update_remediation("eng-1", "f-1", RemediationStatus::Verified, &trace())
                .is_err()
        );
    }

    #[test]
    fn catalog_empty() {
        let mut engine = RedTeamEvaluations::default();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.total_engagements, 0);
    }

    #[test]
    fn catalog_counts() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::High),
                &trace(),
            )
            .unwrap();
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-2", FindingSeverity::Low),
                &trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.total_engagements, 1);
        assert_eq!(catalog.total_findings, 2);
    }

    #[test]
    fn catalog_has_hash() {
        let mut engine = RedTeamEvaluations::default();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.content_hash.len(), 64);
    }

    #[test]
    fn catalog_deterministic() {
        let mut e1 = RedTeamEvaluations::default();
        let mut e2 = RedTeamEvaluations::default();
        let c1 = e1.generate_catalog("trace-det");
        let c2 = e2.generate_catalog("trace-det");
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn catalog_groups_by_type() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert!(catalog.by_type.contains_key("red_team"));
    }

    #[test]
    fn catalog_groups_by_severity() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::Critical),
                &trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert!(catalog.by_severity.contains_key("critical"));
    }

    #[test]
    fn create_sets_timestamp() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        let stored = engine.engagements().get("eng-1").unwrap();
        assert!(!stored.created_at.is_empty());
    }

    #[test]
    fn full_remediation_lifecycle() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::High),
                &trace(),
            )
            .unwrap();
        engine
            .update_remediation("eng-1", "f-1", RemediationStatus::InProgress, &trace())
            .unwrap();
        engine
            .update_remediation("eng-1", "f-1", RemediationStatus::Resolved, &trace())
            .unwrap();
        engine
            .update_remediation("eng-1", "f-1", RemediationStatus::Verified, &trace())
            .unwrap();
        let eng = engine.engagements().get("eng-1").unwrap();
        let f = &eng.findings[0];
        assert_eq!(f.remediation_status, RemediationStatus::Verified);
    }

    #[test]
    fn audit_log_populated() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        assert_eq!(engine.audit_log().len(), 4);
    }

    #[test]
    fn export_jsonl() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .unwrap();
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }
}
