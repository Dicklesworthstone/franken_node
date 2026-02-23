//! bd-3mj9: Enterprise governance integrations (Section 15).
//!
//! Implements enterprise policy, audit, and compliance integration pillar.
//! Provides structured governance rule management, compliance assessment,
//! audit trail generation, and policy enforcement gating for enterprise
//! deployment scenarios.
//!
//! # Capabilities
//!
//! - Governance rule registration with enforcement levels
//! - Compliance assessment per rule with evidence capture
//! - Audit trail generation with immutable records
//! - Policy enforcement gating (block / warn / allow)
//! - Compliance report generation with category aggregation
//! - Evidence-based verification with content hashing
//!
//! # Invariants
//!
//! - **INV-EGI-ENFORCED**: Every rule has a defined enforcement level.
//! - **INV-EGI-ASSESSED**: Every assessment references a registered rule.
//! - **INV-EGI-DETERMINISTIC**: Same inputs produce same compliance report.
//! - **INV-EGI-GATED**: Non-compliant mandatory rules block deployment.
//! - **INV-EGI-VERSIONED**: Schema version embedded in every report.
//! - **INV-EGI-AUDITABLE**: Every state change produces audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const EGI_RULE_REGISTERED: &str = "EGI-001";
    pub const EGI_ASSESSMENT_RECORDED: &str = "EGI-002";
    pub const EGI_COMPLIANCE_CHECKED: &str = "EGI-003";
    pub const EGI_POLICY_GATED: &str = "EGI-004";
    pub const EGI_REPORT_GENERATED: &str = "EGI-005";
    pub const EGI_EVIDENCE_ATTACHED: &str = "EGI-006";
    pub const EGI_AUDIT_EXPORTED: &str = "EGI-007";
    pub const EGI_VERSION_EMBEDDED: &str = "EGI-008";
    pub const EGI_CATEGORY_AGGREGATED: &str = "EGI-009";
    pub const EGI_RULE_UPDATED: &str = "EGI-010";
    pub const EGI_ERR_RULE_NOT_FOUND: &str = "EGI-ERR-001";
    pub const EGI_ERR_GATE_BLOCKED: &str = "EGI-ERR-002";
}

pub mod invariants {
    pub const INV_EGI_ENFORCED: &str = "INV-EGI-ENFORCED";
    pub const INV_EGI_ASSESSED: &str = "INV-EGI-ASSESSED";
    pub const INV_EGI_DETERMINISTIC: &str = "INV-EGI-DETERMINISTIC";
    pub const INV_EGI_GATED: &str = "INV-EGI-GATED";
    pub const INV_EGI_VERSIONED: &str = "INV-EGI-VERSIONED";
    pub const INV_EGI_AUDITABLE: &str = "INV-EGI-AUDITABLE";
}

pub const SCHEMA_VERSION: &str = "egi-v1.0";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Governance rule category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    AccessControl,
    DataRetention,
    AuditLogging,
    ChangeManagement,
    IncidentResponse,
}

impl RuleCategory {
    pub fn all() -> &'static [RuleCategory] {
        &[
            Self::AccessControl,
            Self::DataRetention,
            Self::AuditLogging,
            Self::ChangeManagement,
            Self::IncidentResponse,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::AccessControl => "access_control",
            Self::DataRetention => "data_retention",
            Self::AuditLogging => "audit_logging",
            Self::ChangeManagement => "change_management",
            Self::IncidentResponse => "incident_response",
        }
    }
}

/// Enforcement level for a governance rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    Mandatory,
    Recommended,
    Advisory,
}

impl EnforcementLevel {
    pub fn all() -> &'static [EnforcementLevel] {
        &[Self::Mandatory, Self::Recommended, Self::Advisory]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Mandatory => "mandatory",
            Self::Recommended => "recommended",
            Self::Advisory => "advisory",
        }
    }
}

/// Compliance status for an assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotAssessed,
}

impl ComplianceStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Compliant => "compliant",
            Self::NonCompliant => "non_compliant",
            Self::PartiallyCompliant => "partially_compliant",
            Self::NotAssessed => "not_assessed",
        }
    }
}

/// Gate action for policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAction {
    Allow,
    Warn,
    Block,
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A governance rule definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceRule {
    pub rule_id: String,
    pub category: RuleCategory,
    pub enforcement: EnforcementLevel,
    pub title: String,
    pub description: String,
    pub created_at: String,
}

/// A compliance assessment for a specific rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceAssessment {
    pub assessment_id: String,
    pub rule_id: String,
    pub status: ComplianceStatus,
    pub evidence: String,
    pub assessor: String,
    pub timestamp: String,
}

/// Per-category compliance statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CategoryCompliance {
    pub category: RuleCategory,
    pub total_rules: usize,
    pub compliant: usize,
    pub non_compliant: usize,
    pub partially_compliant: usize,
    pub not_assessed: usize,
    pub compliance_rate: f64,
}

/// Full compliance report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: String,
    pub timestamp: String,
    pub schema_version: String,
    pub total_rules: usize,
    pub total_assessments: usize,
    pub categories: Vec<CategoryCompliance>,
    pub gate_action: GateAction,
    pub blocked_rules: Vec<String>,
    pub content_hash: String,
}

/// Audit record for governance operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgiAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Enterprise governance integration engine.
#[derive(Debug, Clone)]
pub struct EnterpriseGovernance {
    schema_version: String,
    rules: BTreeMap<String, GovernanceRule>,
    assessments: Vec<ComplianceAssessment>,
    audit_log: Vec<EgiAuditRecord>,
}

impl Default for EnterpriseGovernance {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            rules: BTreeMap::new(),
            assessments: Vec::new(),
            audit_log: Vec::new(),
        }
    }
}

impl EnterpriseGovernance {
    /// Register a new governance rule.
    pub fn register_rule(
        &mut self,
        mut rule: GovernanceRule,
        trace_id: &str,
    ) -> Result<String, String> {
        if rule.title.is_empty() || rule.description.is_empty() {
            return Err("Rule title and description must not be empty".to_string());
        }

        rule.created_at = Utc::now().to_rfc3339();
        let rid = rule.rule_id.clone();

        self.log(
            event_codes::EGI_RULE_REGISTERED,
            trace_id,
            serde_json::json!({
                "rule_id": &rid,
                "category": rule.category.label(),
                "enforcement": rule.enforcement.label(),
            }),
        );

        self.rules.insert(rid.clone(), rule);
        Ok(rid)
    }

    /// Record a compliance assessment for a rule.
    pub fn record_assessment(
        &mut self,
        mut assessment: ComplianceAssessment,
        trace_id: &str,
    ) -> Result<String, String> {
        if !self.rules.contains_key(&assessment.rule_id) {
            self.log(
                event_codes::EGI_ERR_RULE_NOT_FOUND,
                trace_id,
                serde_json::json!({
                    "rule_id": &assessment.rule_id,
                }),
            );
            return Err(format!("Rule {} not found", assessment.rule_id));
        }

        assessment.timestamp = Utc::now().to_rfc3339();
        let aid = assessment.assessment_id.clone();

        self.log(
            event_codes::EGI_ASSESSMENT_RECORDED,
            trace_id,
            serde_json::json!({
                "assessment_id": &aid,
                "rule_id": &assessment.rule_id,
                "status": assessment.status.label(),
            }),
        );

        self.log(
            event_codes::EGI_EVIDENCE_ATTACHED,
            trace_id,
            serde_json::json!({
                "assessment_id": &aid,
                "evidence_length": assessment.evidence.len(),
            }),
        );

        self.log(
            event_codes::EGI_COMPLIANCE_CHECKED,
            trace_id,
            serde_json::json!({
                "assessment_id": &aid,
                "compliant": assessment.status == ComplianceStatus::Compliant,
            }),
        );

        self.assessments.push(assessment);
        Ok(aid)
    }

    /// Generate a compliance report with policy gating.
    pub fn generate_report(&mut self, trace_id: &str) -> ComplianceReport {
        // Build latest assessment per rule
        let mut latest: BTreeMap<String, &ComplianceAssessment> = BTreeMap::new();
        for a in &self.assessments {
            latest.insert(a.rule_id.clone(), a);
        }

        // Aggregate by category — use owned data to avoid borrowing self.rules during self.log()
        let mut cat_data: BTreeMap<
            RuleCategory,
            Vec<(String, EnforcementLevel, ComplianceStatus)>,
        > = BTreeMap::new();
        for rule in self.rules.values() {
            let rule_status = latest
                .get(&rule.rule_id)
                .map(|a| a.status)
                .unwrap_or(ComplianceStatus::NotAssessed);
            cat_data.entry(rule.category).or_default().push((
                rule.rule_id.clone(),
                rule.enforcement,
                rule_status,
            ));
        }

        let mut categories = Vec::new();
        let mut blocked_rules = Vec::new();

        for (cat, entries) in &cat_data {
            let total = entries.len();
            let mut compliant = 0;
            let mut non_compliant = 0;
            let mut partial = 0;
            let mut not_assessed = 0;

            for (rule_id, enforcement, rule_status) in entries {
                match rule_status {
                    ComplianceStatus::Compliant => compliant += 1,
                    ComplianceStatus::NonCompliant => {
                        non_compliant += 1;
                        if *enforcement == EnforcementLevel::Mandatory {
                            blocked_rules.push(rule_id.clone());
                        }
                    }
                    ComplianceStatus::PartiallyCompliant => partial += 1,
                    ComplianceStatus::NotAssessed => not_assessed += 1,
                }
            }

            let rate = if total > 0 {
                compliant as f64 / total as f64
            } else {
                0.0
            };

            self.log(
                event_codes::EGI_CATEGORY_AGGREGATED,
                trace_id,
                serde_json::json!({
                    "category": cat.label(),
                    "total": total,
                    "compliant": compliant,
                }),
            );

            categories.push(CategoryCompliance {
                category: *cat,
                total_rules: total,
                compliant,
                non_compliant,
                partially_compliant: partial,
                not_assessed,
                compliance_rate: rate,
            });
        }

        // Determine gate action
        let gate_action = if !blocked_rules.is_empty() {
            self.log(
                event_codes::EGI_ERR_GATE_BLOCKED,
                trace_id,
                serde_json::json!({
                    "blocked_count": blocked_rules.len(),
                    "blocked_rules": &blocked_rules,
                }),
            );
            GateAction::Block
        } else if categories.iter().any(|c| c.partially_compliant > 0) {
            GateAction::Warn
        } else {
            GateAction::Allow
        };

        self.log(
            event_codes::EGI_POLICY_GATED,
            trace_id,
            serde_json::json!({
                "gate_action": format!("{:?}", gate_action),
            }),
        );

        let hash_input = serde_json::json!({
            "total_rules": self.rules.len(),
            "total_assessments": self.assessments.len(),
            "schema_version": &self.schema_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [
                b"enterprise_governance_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        self.log(
            event_codes::EGI_REPORT_GENERATED,
            trace_id,
            serde_json::json!({
                "total_rules": self.rules.len(),
                "categories": categories.len(),
            }),
        );

        self.log(
            event_codes::EGI_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({
                "schema_version": &self.schema_version,
            }),
        );

        ComplianceReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            schema_version: self.schema_version.clone(),
            total_rules: self.rules.len(),
            total_assessments: self.assessments.len(),
            categories,
            gate_action,
            blocked_rules,
            content_hash,
        }
    }

    pub fn rules(&self) -> &BTreeMap<String, GovernanceRule> {
        &self.rules
    }

    pub fn assessments(&self) -> &[ComplianceAssessment] {
        &self.assessments
    }

    pub fn audit_log(&self) -> &[EgiAuditRecord] {
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
        self.audit_log.push(EgiAuditRecord {
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

    fn sample_rule(id: &str, cat: RuleCategory, enforcement: EnforcementLevel) -> GovernanceRule {
        GovernanceRule {
            rule_id: id.to_string(),
            category: cat,
            enforcement,
            title: format!("Rule: {}", id),
            description: format!("Description for rule {}", id),
            created_at: String::new(),
        }
    }

    fn sample_assessment(
        id: &str,
        rule_id: &str,
        status: ComplianceStatus,
    ) -> ComplianceAssessment {
        ComplianceAssessment {
            assessment_id: id.to_string(),
            rule_id: rule_id.to_string(),
            status,
            evidence: "Evidence data".to_string(),
            assessor: "Auditor A".to_string(),
            timestamp: String::new(),
        }
    }

    // === Categories ===

    #[test]
    fn five_rule_categories() {
        assert_eq!(RuleCategory::all().len(), 5);
    }

    #[test]
    fn category_labels_nonempty() {
        for c in RuleCategory::all() {
            assert!(!c.label().is_empty());
        }
    }

    #[test]
    fn three_enforcement_levels() {
        assert_eq!(EnforcementLevel::all().len(), 3);
    }

    // === Rule registration ===

    #[test]
    fn register_valid_rule() {
        let mut engine = EnterpriseGovernance::default();
        assert!(
            engine
                .register_rule(
                    sample_rule(
                        "r-1",
                        RuleCategory::AccessControl,
                        EnforcementLevel::Mandatory
                    ),
                    &trace(),
                )
                .is_ok()
        );
    }

    #[test]
    fn register_empty_title_fails() {
        let mut engine = EnterpriseGovernance::default();
        let mut r = sample_rule(
            "r-1",
            RuleCategory::AccessControl,
            EnforcementLevel::Mandatory,
        );
        r.title = String::new();
        assert!(engine.register_rule(r, &trace()).is_err());
    }

    #[test]
    fn register_sets_timestamp() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        let stored = engine.rules().get("r-1").unwrap();
        assert!(!stored.created_at.is_empty());
    }

    // === Assessment ===

    #[test]
    fn record_assessment_success() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        assert!(
            engine
                .record_assessment(
                    sample_assessment("a-1", "r-1", ComplianceStatus::Compliant),
                    &trace(),
                )
                .is_ok()
        );
    }

    #[test]
    fn record_assessment_missing_rule_fails() {
        let mut engine = EnterpriseGovernance::default();
        assert!(
            engine
                .record_assessment(
                    sample_assessment("a-1", "nonexistent", ComplianceStatus::Compliant),
                    &trace(),
                )
                .is_err()
        );
    }

    #[test]
    fn assessment_sets_timestamp() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        engine
            .record_assessment(
                sample_assessment("a-1", "r-1", ComplianceStatus::Compliant),
                &trace(),
            )
            .unwrap();
        assert!(!engine.assessments()[0].timestamp.is_empty());
    }

    // === Report ===

    #[test]
    fn report_empty() {
        let mut engine = EnterpriseGovernance::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.total_rules, 0);
        assert_eq!(report.gate_action, GateAction::Allow);
    }

    #[test]
    fn report_compliant_allows() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        engine
            .record_assessment(
                sample_assessment("a-1", "r-1", ComplianceStatus::Compliant),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.gate_action, GateAction::Allow);
        assert!(report.blocked_rules.is_empty());
    }

    #[test]
    fn report_mandatory_non_compliant_blocks() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        engine
            .record_assessment(
                sample_assessment("a-1", "r-1", ComplianceStatus::NonCompliant),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.gate_action, GateAction::Block);
        assert!(report.blocked_rules.contains(&"r-1".to_string()));
    }

    #[test]
    fn report_advisory_non_compliant_allows() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::DataRetention,
                    EnforcementLevel::Advisory,
                ),
                &trace(),
            )
            .unwrap();
        engine
            .record_assessment(
                sample_assessment("a-1", "r-1", ComplianceStatus::NonCompliant),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.gate_action, GateAction::Allow);
    }

    #[test]
    fn report_partial_warns() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AuditLogging,
                    EnforcementLevel::Recommended,
                ),
                &trace(),
            )
            .unwrap();
        engine
            .record_assessment(
                sample_assessment("a-1", "r-1", ComplianceStatus::PartiallyCompliant),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.gate_action, GateAction::Warn);
    }

    #[test]
    fn report_groups_by_category() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        engine
            .register_rule(
                sample_rule(
                    "r-2",
                    RuleCategory::DataRetention,
                    EnforcementLevel::Recommended,
                ),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.categories.len(), 2);
    }

    #[test]
    fn report_has_content_hash() {
        let mut engine = EnterpriseGovernance::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.content_hash.len(), 64);
    }

    #[test]
    fn report_has_version() {
        let mut engine = EnterpriseGovernance::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_deterministic() {
        let mut e1 = EnterpriseGovernance::default();
        let mut e2 = EnterpriseGovernance::default();
        let r1 = e1.generate_report("trace-det");
        let r2 = e2.generate_report("trace-det");
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn compliance_rate() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        engine
            .register_rule(
                sample_rule(
                    "r-2",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        engine
            .record_assessment(
                sample_assessment("a-1", "r-1", ComplianceStatus::Compliant),
                &trace(),
            )
            .unwrap();
        engine
            .record_assessment(
                sample_assessment("a-2", "r-2", ComplianceStatus::NonCompliant),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        let cat = &report.categories[0];
        assert!((cat.compliance_rate - 0.5).abs() < f64::EPSILON);
    }

    // === Audit log ===

    #[test]
    fn audit_log_populated() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        assert!(!engine.audit_log().is_empty());
    }

    #[test]
    fn audit_has_event_codes() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::EGI_RULE_REGISTERED));
    }

    #[test]
    fn export_jsonl() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn default_schema_version() {
        let engine = EnterpriseGovernance::default();
        assert_eq!(engine.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn not_assessed_without_assessment() {
        let mut engine = EnterpriseGovernance::default();
        engine
            .register_rule(
                sample_rule(
                    "r-1",
                    RuleCategory::AccessControl,
                    EnforcementLevel::Mandatory,
                ),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.categories[0].not_assessed, 1);
    }
}
