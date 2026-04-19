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

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_FINDINGS_PER_ENGAGEMENT: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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
        if engagement.engagement_id.trim().is_empty() {
            return Err("Engagement id must not be empty".to_string());
        }

        if self.engagements.contains_key(&engagement.engagement_id) {
            return Err(format!(
                "Engagement {} already exists",
                engagement.engagement_id
            ));
        }

        if engagement.title.trim().is_empty() {
            return Err("Engagement title must not be empty".to_string());
        }

        if engagement.evaluator.trim().is_empty() {
            return Err("Evaluator must not be empty".to_string());
        }

        if engagement.scope.is_empty() || engagement.scope.iter().any(|item| item.trim().is_empty())
        {
            self.log(
                event_codes::RTE_ERR_MISSING_SCOPE,
                trace_id,
                serde_json::json!({
                    "engagement_id": &engagement.engagement_id,
                }),
            );
            return Err("Engagement must have at least one scope item".to_string());
        }

        if engagement.rules_of_engagement.trim().is_empty() {
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

        if !engagement.confidence_score.is_finite() {
            return Err("Confidence score must be finite (not NaN or infinite)".to_string());
        }
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

        if finding.finding_id.trim().is_empty() {
            return Err("Finding id must not be empty".to_string());
        }

        if finding.title.trim().is_empty() {
            return Err("Finding title must not be empty".to_string());
        }

        if finding.description.trim().is_empty() {
            return Err("Finding description must not be empty".to_string());
        }

        if finding.affected_components.is_empty()
            || finding
                .affected_components
                .iter()
                .any(|component| component.trim().is_empty())
        {
            return Err("Finding must have at least one affected component".to_string());
        }

        {
            let engagement = self
                .engagements
                .get(engagement_id)
                .ok_or_else(|| format!("Engagement {engagement_id} not found"))?;
            if engagement
                .findings
                .iter()
                .any(|existing| existing.finding_id == finding.finding_id)
            {
                return Err(format!("Finding {} already exists", finding.finding_id));
            }
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

        let eng = self
            .engagements
            .get_mut(engagement_id)
            .ok_or_else(|| format!("Engagement {engagement_id} not found"))?;
        push_bounded(&mut eng.findings, finding, MAX_FINDINGS_PER_ENGAGEMENT);
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
            .ok_or_else(|| format!("Engagement {engagement_id} not found"))?;
        let finding_mut = engagement_mut
            .findings
            .iter_mut()
            .find(|f| f.finding_id == finding_id)
            .ok_or_else(|| format!("Finding {finding_id} not found"))?;
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
        let mut total_findings: usize = 0;

        for eng in self.engagements.values() {
            let type_count = by_type
                .entry(eng.eval_type.label().to_string())
                .or_insert(0usize);
            *type_count = type_count.saturating_add(1);
            for f in &eng.findings {
                let severity_count = by_severity
                    .entry(f.severity.label().to_string())
                    .or_insert(0usize);
                *severity_count = severity_count.saturating_add(1);
                total_findings = total_findings.saturating_add(1);
            }
        }

        let content_hash = compute_catalog_content_hash(
            self.engagements.len(),
            total_findings,
            &self.schema_version,
            &by_type,
            &by_severity,
        );

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
        push_bounded(
            &mut self.audit_log,
            RteAuditRecord {
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

fn compute_catalog_content_hash(
    total_engagements: usize,
    total_findings: usize,
    schema_version: &str,
    by_type: &BTreeMap<String, usize>,
    by_severity: &BTreeMap<String, usize>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"redteam_evaluations_hash_v1:");

    // Length-prefix each variable-length field to prevent collision attacks
    hasher.update((total_engagements as u64).to_le_bytes());
    hasher.update((total_findings as u64).to_le_bytes());

    hasher.update((schema_version.len() as u64).to_le_bytes());
    hasher.update(schema_version.as_bytes());

    // Serialize maps deterministically with length prefixes
    let by_type_json = serde_json::to_string(by_type).unwrap_or_default();
    hasher.update((by_type_json.len() as u64).to_le_bytes());
    hasher.update(by_type_json.as_bytes());

    let by_severity_json = serde_json::to_string(by_severity).unwrap_or_default();
    hasher.update((by_severity_json.len() as u64).to_le_bytes());
    hasher.update(by_severity_json.as_bytes());

    hex::encode(hasher.finalize())
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
            .expect("should succeed");
        let stored = engine.engagements().get("eng-1").expect("should exist");
        assert_eq!(stored.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn add_finding_success() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");
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
            .expect("should succeed");
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::High),
                &trace(),
            )
            .expect("should succeed");
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
            .expect("should succeed");
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::High),
                &trace(),
            )
            .expect("should succeed");
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
            .expect("should succeed");
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::High),
                &trace(),
            )
            .expect("should succeed");
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-2", FindingSeverity::Low),
                &trace(),
            )
            .expect("should succeed");
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
            .expect("should succeed");
        let catalog = engine.generate_catalog(&trace());
        assert!(catalog.by_type.contains_key("red_team"));
    }

    #[test]
    fn catalog_groups_by_severity() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::Critical),
                &trace(),
            )
            .expect("should succeed");
        let catalog = engine.generate_catalog(&trace());
        assert!(catalog.by_severity.contains_key("critical"));
    }

    #[test]
    fn catalog_hash_changes_with_type_distribution() {
        let mut red_team = RedTeamEvaluations::default();
        let mut penetration = RedTeamEvaluations::default();

        red_team
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");

        let mut penetration_engagement = sample_engagement("eng-1");
        penetration_engagement.eval_type = EvaluationType::PenetrationTest;
        penetration
            .create_engagement(penetration_engagement, &trace())
            .expect("should succeed");

        let red_team_catalog = red_team.generate_catalog("trace-type-red-team");
        let penetration_catalog = penetration.generate_catalog("trace-type-pentest");

        assert_ne!(red_team_catalog.by_type, penetration_catalog.by_type);
        assert_eq!(
            red_team_catalog.total_engagements,
            penetration_catalog.total_engagements
        );
        assert_eq!(
            red_team_catalog.total_findings,
            penetration_catalog.total_findings
        );
        assert_ne!(
            red_team_catalog.content_hash,
            penetration_catalog.content_hash
        );
    }

    #[test]
    fn catalog_hash_changes_with_severity_distribution() {
        let mut critical_engine = RedTeamEvaluations::default();
        let mut low_engine = RedTeamEvaluations::default();

        critical_engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");
        critical_engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::Critical),
                &trace(),
            )
            .expect("should succeed");

        low_engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");
        low_engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::Low),
                &trace(),
            )
            .expect("should succeed");

        let critical_catalog = critical_engine.generate_catalog("trace-severity-critical");
        let low_catalog = low_engine.generate_catalog("trace-severity-low");

        assert_ne!(critical_catalog.by_severity, low_catalog.by_severity);
        assert_eq!(
            critical_catalog.total_engagements,
            low_catalog.total_engagements
        );
        assert_eq!(critical_catalog.total_findings, low_catalog.total_findings);
        assert_ne!(critical_catalog.content_hash, low_catalog.content_hash);
    }

    #[test]
    fn create_sets_timestamp() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");
        let stored = engine.engagements().get("eng-1").expect("should exist");
        assert!(!stored.created_at.is_empty());
    }

    #[test]
    fn full_remediation_lifecycle() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");
        engine
            .add_finding(
                "eng-1",
                sample_finding("f-1", FindingSeverity::High),
                &trace(),
            )
            .expect("should succeed");
        engine
            .update_remediation("eng-1", "f-1", RemediationStatus::InProgress, &trace())
            .expect("should succeed");
        engine
            .update_remediation("eng-1", "f-1", RemediationStatus::Resolved, &trace())
            .expect("should succeed");
        engine
            .update_remediation("eng-1", "f-1", RemediationStatus::Verified, &trace())
            .expect("should succeed");
        let eng = engine.engagements().get("eng-1").expect("should exist");
        let f = &eng.findings[0];
        assert_eq!(f.remediation_status, RemediationStatus::Verified);
    }

    #[test]
    fn audit_log_populated() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");
        assert_eq!(engine.audit_log().len(), 4);
    }

    #[test]
    fn export_jsonl() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-1"), &trace())
            .expect("should succeed");
        let jsonl = engine
            .export_audit_log_jsonl()
            .expect("jsonl export should succeed");
        let first: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().expect("should have at least one line"))
                .expect("json parse should succeed");
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn push_bounded_zero_capacity_discards_existing_items() {
        let mut items = vec!["old-a", "old-b"];

        push_bounded(&mut items, "new", 0);

        assert!(
            items.is_empty(),
            "zero-capacity buffers must not retain stale findings or audit entries"
        );
    }

    #[test]
    fn push_bounded_overfull_buffer_drops_oldest_items() {
        let mut items = vec!["one", "two", "three"];

        push_bounded(&mut items, "four", 2);

        assert_eq!(items, vec!["three", "four"]);
    }

    #[test]
    fn empty_engagement_id_rejected_without_audit_or_insert() {
        let mut engine = RedTeamEvaluations::default();

        let err = engine
            .create_engagement(sample_engagement(""), &trace())
            .expect_err("empty engagement id must be rejected");

        assert!(err.contains("Engagement id"));
        assert!(engine.engagements().is_empty());
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn whitespace_engagement_title_rejected_without_audit_or_insert() {
        let mut engine = RedTeamEvaluations::default();
        let mut engagement = sample_engagement("blank-title");
        engagement.title = " \t ".to_string();

        let err = engine
            .create_engagement(engagement, &trace())
            .expect_err("blank title must be rejected");

        assert!(err.contains("title"));
        assert!(!engine.engagements().contains_key("blank-title"));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn whitespace_evaluator_rejected_without_audit_or_insert() {
        let mut engine = RedTeamEvaluations::default();
        let mut engagement = sample_engagement("blank-evaluator");
        engagement.evaluator = "\n ".to_string();

        let err = engine
            .create_engagement(engagement, &trace())
            .expect_err("blank evaluator must be rejected");

        assert!(err.contains("Evaluator"));
        assert!(!engine.engagements().contains_key("blank-evaluator"));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn whitespace_scope_item_rejected_without_storing_engagement() {
        let mut engine = RedTeamEvaluations::default();
        let mut engagement = sample_engagement("blank-scope");
        engagement.scope = vec!["API".to_string(), " \t ".to_string()];

        let err = engine
            .create_engagement(engagement, "trace-blank-scope")
            .expect_err("blank scope items must be rejected");

        assert!(err.contains("scope"));
        assert!(!engine.engagements().contains_key("blank-scope"));
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::RTE_ERR_MISSING_SCOPE
        );
    }

    #[test]
    fn duplicate_engagement_rejected_without_overwrite() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("dupe-eng"), &trace())
            .expect("first engagement should be accepted");
        let original_title = engine.engagements()["dupe-eng"].title.clone();
        let original_created_at = engine.engagements()["dupe-eng"].created_at.clone();
        let mut duplicate = sample_engagement("dupe-eng");
        duplicate.title = "Replacement title".to_string();

        let err = engine
            .create_engagement(duplicate, &trace())
            .expect_err("duplicate engagement ids must be rejected");

        assert!(err.contains("already exists"));
        assert_eq!(engine.engagements()["dupe-eng"].title, original_title);
        assert_eq!(
            engine.engagements()["dupe-eng"].created_at,
            original_created_at
        );
    }

    #[test]
    fn empty_finding_id_rejected_without_submission_audit() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-empty-finding"), &trace())
            .expect("engagement should be created");
        let audit_count_before = engine.audit_log().len();

        let err = engine
            .add_finding(
                "eng-empty-finding",
                sample_finding("", FindingSeverity::Low),
                &trace(),
            )
            .expect_err("empty finding id must be rejected");

        assert!(err.contains("Finding id"));
        assert!(engine.engagements()["eng-empty-finding"].findings.is_empty());
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn whitespace_finding_description_rejected_without_submission_audit() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-blank-description"), &trace())
            .expect("engagement should be created");
        let audit_count_before = engine.audit_log().len();
        let mut finding = sample_finding("f-blank-description", FindingSeverity::Medium);
        finding.description = " \n ".to_string();

        let err = engine
            .add_finding("eng-blank-description", finding, &trace())
            .expect_err("blank finding descriptions must be rejected");

        assert!(err.contains("description"));
        assert!(engine.engagements()["eng-blank-description"]
            .findings
            .is_empty());
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn blank_affected_component_rejected_without_submission_audit() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-blank-component"), &trace())
            .expect("engagement should be created");
        let audit_count_before = engine.audit_log().len();
        let mut finding = sample_finding("f-blank-component", FindingSeverity::High);
        finding.affected_components = vec!["api".to_string(), "\t ".to_string()];

        let err = engine
            .add_finding("eng-blank-component", finding, &trace())
            .expect_err("blank affected components must be rejected");

        assert!(err.contains("affected component"));
        assert!(engine.engagements()["eng-blank-component"]
            .findings
            .is_empty());
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn duplicate_finding_rejected_without_overwrite_or_extra_submission_audit() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-dupe-finding"), &trace())
            .expect("engagement should be created");
        engine
            .add_finding(
                "eng-dupe-finding",
                sample_finding("f-dupe", FindingSeverity::Low),
                &trace(),
            )
            .expect("first finding should be accepted");
        let audit_count_before = engine.audit_log().len();
        let mut duplicate = sample_finding("f-dupe", FindingSeverity::Critical);
        duplicate.title = "Replacement finding".to_string();

        let err = engine
            .add_finding("eng-dupe-finding", duplicate, &trace())
            .expect_err("duplicate finding ids must be rejected");

        assert!(err.contains("already exists"));
        let findings = &engine.engagements()["eng-dupe-finding"].findings;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::Low);
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn nan_confidence_rejected_without_storing_engagement() {
        let mut engine = RedTeamEvaluations::default();
        let mut engagement = sample_engagement("nan-confidence");
        engagement.confidence_score = f64::NAN;

        let err = engine
            .create_engagement(engagement, &trace())
            .expect_err("NaN confidence must be rejected");

        assert!(err.contains("Confidence score"));
        assert!(!engine.engagements().contains_key("nan-confidence"));
        assert!(
            engine
                .audit_log()
                .iter()
                .all(|record| record.event_code != event_codes::RTE_ENGAGEMENT_CREATED),
            "invalid confidence must not emit an engagement-created audit record"
        );
    }

    #[test]
    fn infinite_confidence_rejected_before_confidence_audit() {
        let mut engine = RedTeamEvaluations::default();
        let mut engagement = sample_engagement("inf-confidence");
        engagement.confidence_score = f64::INFINITY;

        let err = engine
            .create_engagement(engagement, &trace())
            .expect_err("infinite confidence must be rejected");

        assert!(err.contains("Confidence score"));
        assert!(!engine.engagements().contains_key("inf-confidence"));
        assert!(
            engine
                .audit_log()
                .iter()
                .all(|record| record.event_code != event_codes::RTE_CONFIDENCE_SCORED),
            "out-of-range confidence must not emit a confidence-scored record"
        );
    }

    #[test]
    fn empty_rules_rejected_without_scope_or_created_audit() {
        let mut engine = RedTeamEvaluations::default();
        let mut engagement = sample_engagement("empty-rules");
        engagement.rules_of_engagement.clear();

        let err = engine
            .create_engagement(engagement, &trace())
            .expect_err("empty rules must be rejected");

        assert!(err.contains("Rules of engagement"));
        assert!(engine.audit_log().is_empty());
        assert!(!engine.engagements().contains_key("empty-rules"));
    }

    #[test]
    fn add_finding_missing_engagement_does_not_emit_audit_records() {
        let mut engine = RedTeamEvaluations::default();

        let err = engine
            .add_finding(
                "missing-engagement",
                sample_finding("f-missing", FindingSeverity::High),
                &trace(),
            )
            .expect_err("missing engagement must fail");

        assert!(err.contains("missing-engagement"));
        assert!(
            engine.audit_log().is_empty(),
            "missing engagement must fail before finding submission audit records"
        );
    }

    #[test]
    fn update_missing_finding_does_not_change_existing_finding() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-missing-finding"), &trace())
            .expect("engagement should be created");
        engine
            .add_finding(
                "eng-missing-finding",
                sample_finding("f-existing", FindingSeverity::Medium),
                &trace(),
            )
            .expect("finding should be added");
        let audit_count_before = engine.audit_log().len();

        let err = engine
            .update_remediation(
                "eng-missing-finding",
                "f-absent",
                RemediationStatus::InProgress,
                &trace(),
            )
            .expect_err("missing finding must fail");

        assert!(err.contains("f-absent"));
        let finding = &engine.engagements()["eng-missing-finding"].findings[0];
        assert_eq!(finding.remediation_status, RemediationStatus::Open);
        assert_eq!(
            engine.audit_log().len(),
            audit_count_before,
            "missing finding lookup must not append remediation audit records"
        );
    }

    #[test]
    fn update_missing_engagement_does_not_log_invalid_transition() {
        let mut engine = RedTeamEvaluations::default();

        let err = engine
            .update_remediation(
                "missing-engagement",
                "f-1",
                RemediationStatus::Verified,
                &trace(),
            )
            .expect_err("missing engagement must fail");

        assert!(err.contains("missing-engagement"));
        assert!(
            engine.audit_log().is_empty(),
            "missing engagement must fail before transition validation"
        );
    }

    #[test]
    fn verified_finding_cannot_reopen_and_status_is_preserved() {
        let mut engine = RedTeamEvaluations::default();
        engine
            .create_engagement(sample_engagement("eng-verified"), &trace())
            .expect("engagement should be created");
        engine
            .add_finding(
                "eng-verified",
                sample_finding("f-verified", FindingSeverity::Critical),
                &trace(),
            )
            .expect("finding should be added");
        engine
            .update_remediation(
                "eng-verified",
                "f-verified",
                RemediationStatus::InProgress,
                &trace(),
            )
            .expect("open -> in progress should succeed");
        engine
            .update_remediation(
                "eng-verified",
                "f-verified",
                RemediationStatus::Resolved,
                &trace(),
            )
            .expect("in progress -> resolved should succeed");
        engine
            .update_remediation(
                "eng-verified",
                "f-verified",
                RemediationStatus::Verified,
                &trace(),
            )
            .expect("resolved -> verified should succeed");

        let err = engine
            .update_remediation(
                "eng-verified",
                "f-verified",
                RemediationStatus::Open,
                &trace(),
            )
            .expect_err("verified findings must not reopen directly");

        assert!(err.contains("Cannot transition"));
        let finding = &engine.engagements()["eng-verified"].findings[0];
        assert_eq!(finding.remediation_status, RemediationStatus::Verified);
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::RTE_ERR_INVALID_TRANSITION),
            "invalid verified->open transition should be auditable"
        );
    }
}
