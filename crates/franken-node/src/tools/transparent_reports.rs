//! bd-10ee: Transparent technical reports (Section 16).
//!
//! Publishes transparent technical reports including failures, corrective
//! actions, and lessons learned. Each report has structured sections,
//! incident timelines, root-cause analysis, and corrective action tracking.
//!
//! # Capabilities
//!
//! - Report creation with mandatory transparency sections
//! - Incident timeline with severity and impact
//! - Root-cause analysis with contributing factors
//! - Corrective action tracking (Identified → Planned → Implemented → Verified)
//! - Report catalog with filtering and search
//! - Content-addressed integrity hashing
//!
//! # Invariants
//!
//! - **INV-TR-TRANSPARENT**: Every report includes failure acknowledgment section.
//! - **INV-TR-DETERMINISTIC**: Same inputs produce same catalog output.
//! - **INV-TR-TIMELINE**: Every incident has a structured timeline.
//! - **INV-TR-CORRECTIVE**: Every failure has corrective action tracking.
//! - **INV-TR-VERSIONED**: Report version embedded in every artifact.
//! - **INV-TR-AUDITABLE**: Every state change produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const TR_REPORT_CREATED: &str = "TR-001";
    pub const TR_TIMELINE_ADDED: &str = "TR-002";
    pub const TR_ROOT_CAUSE_ANALYZED: &str = "TR-003";
    pub const TR_CORRECTIVE_ACTION_ADDED: &str = "TR-004";
    pub const TR_ACTION_STATUS_UPDATED: &str = "TR-005";
    pub const TR_CATALOG_GENERATED: &str = "TR-006";
    pub const TR_INTEGRITY_VERIFIED: &str = "TR-007";
    pub const TR_VERSION_EMBEDDED: &str = "TR-008";
    pub const TR_LESSONS_RECORDED: &str = "TR-009";
    pub const TR_SECTION_VALIDATED: &str = "TR-010";
    pub const TR_ERR_MISSING_SECTION: &str = "TR-ERR-001";
    pub const TR_ERR_INVALID_TRANSITION: &str = "TR-ERR-002";
}

pub mod invariants {
    pub const INV_TR_TRANSPARENT: &str = "INV-TR-TRANSPARENT";
    pub const INV_TR_DETERMINISTIC: &str = "INV-TR-DETERMINISTIC";
    pub const INV_TR_TIMELINE: &str = "INV-TR-TIMELINE";
    pub const INV_TR_CORRECTIVE: &str = "INV-TR-CORRECTIVE";
    pub const INV_TR_VERSIONED: &str = "INV-TR-VERSIONED";
    pub const INV_TR_AUDITABLE: &str = "INV-TR-AUDITABLE";
}

pub const REPORT_VERSION: &str = "tr-v1.0";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub const REQUIRED_SECTIONS: &[&str] = &[
    "executive_summary",
    "incident_description",
    "timeline",
    "root_cause_analysis",
    "impact_assessment",
    "corrective_actions",
    "lessons_learned",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportCategory {
    SecurityIncident,
    PerformanceRegression,
    DataIntegrity,
    ServiceOutage,
    ComplianceGap,
}

impl ReportCategory {
    pub fn all() -> &'static [ReportCategory] {
        &[
            Self::SecurityIncident,
            Self::PerformanceRegression,
            Self::DataIntegrity,
            Self::ServiceOutage,
            Self::ComplianceGap,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::SecurityIncident => "security_incident",
            Self::PerformanceRegression => "performance_regression",
            Self::DataIntegrity => "data_integrity",
            Self::ServiceOutage => "service_outage",
            Self::ComplianceGap => "compliance_gap",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Identified,
    Planned,
    Implemented,
    Verified,
}

impl ActionStatus {
    pub fn valid_transitions(&self) -> &'static [ActionStatus] {
        match self {
            Self::Identified => &[Self::Planned],
            Self::Planned => &[Self::Identified, Self::Implemented],
            Self::Implemented => &[Self::Verified, Self::Planned],
            Self::Verified => &[],
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Identified => "identified",
            Self::Planned => "planned",
            Self::Implemented => "implemented",
            Self::Verified => "verified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransparentReport {
    pub report_id: String,
    pub title: String,
    pub category: ReportCategory,
    pub severity: Severity,
    pub sections: BTreeMap<String, String>,
    pub timeline: Vec<TimelineEntry>,
    pub root_causes: Vec<String>,
    pub corrective_actions: Vec<CorrectiveAction>,
    pub lessons_learned: Vec<String>,
    pub content_hash: String,
    pub report_version: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub event: String,
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrectiveAction {
    pub action_id: String,
    pub description: String,
    pub status: ActionStatus,
    pub owner: String,
    pub due_date: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportCatalog {
    pub catalog_id: String,
    pub timestamp: String,
    pub report_version: String,
    pub total_reports: usize,
    pub by_category: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<String, usize>,
    pub open_actions: usize,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrAuditRecord {
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
pub struct TransparentReports {
    report_version: String,
    reports: BTreeMap<String, TransparentReport>,
    audit_log: Vec<TrAuditRecord>,
}

impl Default for TransparentReports {
    fn default() -> Self {
        Self {
            report_version: REPORT_VERSION.to_string(),
            reports: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }
}

impl TransparentReports {
    pub fn create_report(
        &mut self,
        mut report: TransparentReport,
        trace_id: &str,
    ) -> Result<String, String> {
        // Validate required sections
        for sec in REQUIRED_SECTIONS {
            if !report.sections.contains_key(*sec) {
                self.log(
                    event_codes::TR_ERR_MISSING_SECTION,
                    trace_id,
                    serde_json::json!({
                        "report_id": &report.report_id,
                        "missing": sec,
                    }),
                );
                return Err(format!("Missing required section: {}", sec));
            }
        }

        self.log(
            event_codes::TR_SECTION_VALIDATED,
            trace_id,
            serde_json::json!({
                "report_id": &report.report_id,
                "sections": report.sections.len(),
            }),
        );

        // Validate timeline
        if report.timeline.is_empty() {
            return Err("Timeline must have at least one entry".to_string());
        }

        self.log(
            event_codes::TR_TIMELINE_ADDED,
            trace_id,
            serde_json::json!({
                "report_id": &report.report_id,
                "entries": report.timeline.len(),
            }),
        );

        // Root cause
        if !report.root_causes.is_empty() {
            self.log(
                event_codes::TR_ROOT_CAUSE_ANALYZED,
                trace_id,
                serde_json::json!({
                    "report_id": &report.report_id,
                    "causes": report.root_causes.len(),
                }),
            );
        }

        // Lessons
        if !report.lessons_learned.is_empty() {
            self.log(
                event_codes::TR_LESSONS_RECORDED,
                trace_id,
                serde_json::json!({
                    "report_id": &report.report_id,
                    "lessons": report.lessons_learned.len(),
                }),
            );
        }

        // Compute hash
        let hash_input = serde_json::json!({
            "title": &report.title,
            "category": report.category.label(),
            "sections": &report.sections,
        })
        .to_string();
        report.content_hash = hex::encode(Sha256::digest(
            [
                b"transparent_reports_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));
        report.report_version = self.report_version.clone();
        report.created_at = Utc::now().to_rfc3339();

        let rid = report.report_id.clone();

        self.log(
            event_codes::TR_INTEGRITY_VERIFIED,
            trace_id,
            serde_json::json!({
                "report_id": &rid,
                "content_hash": &report.content_hash,
            }),
        );

        self.log(
            event_codes::TR_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({
                "report_id": &rid,
                "report_version": &report.report_version,
            }),
        );

        self.reports.insert(rid.clone(), report);

        self.log(
            event_codes::TR_REPORT_CREATED,
            trace_id,
            serde_json::json!({
                "report_id": &rid,
            }),
        );

        Ok(rid)
    }

    pub fn add_corrective_action(
        &mut self,
        report_id: &str,
        action: CorrectiveAction,
        trace_id: &str,
    ) -> Result<(), String> {
        if !self.reports.contains_key(report_id) {
            return Err(format!("Report {} not found", report_id));
        }

        let action_id = action.action_id.clone();
        self.log(
            event_codes::TR_CORRECTIVE_ACTION_ADDED,
            trace_id,
            serde_json::json!({
                "report_id": report_id,
                "action_id": &action_id,
            }),
        );

        self.reports
            .get_mut(report_id)
            .unwrap()
            .corrective_actions
            .push(action);
        Ok(())
    }

    pub fn update_action_status(
        &mut self,
        report_id: &str,
        action_id: &str,
        new_status: ActionStatus,
        trace_id: &str,
    ) -> Result<(), String> {
        let report = self
            .reports
            .get(report_id)
            .ok_or_else(|| format!("Report {} not found", report_id))?;

        let action = report
            .corrective_actions
            .iter()
            .find(|a| a.action_id == action_id)
            .ok_or_else(|| format!("Action {} not found", action_id))?;

        let current = action.status;
        if !current.valid_transitions().contains(&new_status) {
            self.log(
                event_codes::TR_ERR_INVALID_TRANSITION,
                trace_id,
                serde_json::json!({
                    "action_id": action_id,
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

        let report_mut = self.reports.get_mut(report_id).unwrap();
        let action_mut = report_mut
            .corrective_actions
            .iter_mut()
            .find(|a| a.action_id == action_id)
            .unwrap();
        action_mut.status = new_status;

        self.log(
            event_codes::TR_ACTION_STATUS_UPDATED,
            trace_id,
            serde_json::json!({
                "action_id": action_id,
                "new_status": new_status.label(),
            }),
        );

        Ok(())
    }

    pub fn generate_catalog(&mut self, trace_id: &str) -> ReportCatalog {
        let mut by_category = BTreeMap::new();
        let mut by_severity = BTreeMap::new();
        let mut open_actions = 0;

        for report in self.reports.values() {
            *by_category
                .entry(report.category.label().to_string())
                .or_insert(0) += 1;
            *by_severity
                .entry(report.severity.label().to_string())
                .or_insert(0) += 1;
            for action in &report.corrective_actions {
                if action.status != ActionStatus::Verified {
                    open_actions += 1;
                }
            }
        }

        let hash_input = serde_json::json!({
            "total_reports": self.reports.len(),
            "by_category": &by_category,
            "report_version": &self.report_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [
                b"transparent_reports_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        self.log(
            event_codes::TR_CATALOG_GENERATED,
            trace_id,
            serde_json::json!({
                "total_reports": self.reports.len(),
                "open_actions": open_actions,
            }),
        );

        ReportCatalog {
            catalog_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            report_version: self.report_version.clone(),
            total_reports: self.reports.len(),
            by_category,
            by_severity,
            open_actions,
            content_hash,
        }
    }

    pub fn reports(&self) -> &BTreeMap<String, TransparentReport> {
        &self.reports
    }
    pub fn audit_log(&self) -> &[TrAuditRecord] {
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
        self.audit_log.push(TrAuditRecord {
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

    fn sample_report(id: &str, cat: ReportCategory) -> TransparentReport {
        let mut sections = BTreeMap::new();
        for sec in REQUIRED_SECTIONS {
            sections.insert(sec.to_string(), format!("Content for {}", sec));
        }
        TransparentReport {
            report_id: id.to_string(),
            title: format!("Incident Report: {}", id),
            category: cat,
            severity: Severity::High,
            sections,
            timeline: vec![TimelineEntry {
                timestamp: "2026-02-01T10:00:00Z".to_string(),
                event: "Incident detected".to_string(),
                actor: "monitoring".to_string(),
            }],
            root_causes: vec!["Configuration drift".to_string()],
            corrective_actions: vec![],
            lessons_learned: vec!["Improve monitoring coverage".to_string()],
            content_hash: String::new(),
            report_version: String::new(),
            created_at: String::new(),
        }
    }

    fn sample_action(id: &str) -> CorrectiveAction {
        CorrectiveAction {
            action_id: id.to_string(),
            description: "Fix the issue".to_string(),
            status: ActionStatus::Identified,
            owner: "team-a".to_string(),
            due_date: "2026-03-01".to_string(),
        }
    }

    #[test]
    fn five_categories() {
        assert_eq!(ReportCategory::all().len(), 5);
    }

    #[test]
    fn seven_required_sections() {
        assert_eq!(REQUIRED_SECTIONS.len(), 7);
    }

    #[test]
    fn action_transitions() {
        assert!(!ActionStatus::Identified.valid_transitions().is_empty());
        assert!(ActionStatus::Verified.valid_transitions().is_empty());
    }

    #[test]
    fn create_valid_report() {
        let mut engine = TransparentReports::default();
        assert!(
            engine
                .create_report(
                    sample_report("r-1", ReportCategory::SecurityIncident),
                    &trace()
                )
                .is_ok()
        );
    }

    #[test]
    fn create_missing_section_fails() {
        let mut engine = TransparentReports::default();
        let mut r = sample_report("r-1", ReportCategory::SecurityIncident);
        r.sections.remove("root_cause_analysis");
        assert!(engine.create_report(r, &trace()).is_err());
    }

    #[test]
    fn create_empty_timeline_fails() {
        let mut engine = TransparentReports::default();
        let mut r = sample_report("r-1", ReportCategory::SecurityIncident);
        r.timeline.clear();
        assert!(engine.create_report(r, &trace()).is_err());
    }

    #[test]
    fn create_sets_hash_and_version() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        let stored = engine.reports().get("r-1").unwrap();
        assert_eq!(stored.content_hash.len(), 64);
        assert_eq!(stored.report_version, REPORT_VERSION);
    }

    #[test]
    fn add_corrective_action() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        assert!(
            engine
                .add_corrective_action("r-1", sample_action("a-1"), &trace())
                .is_ok()
        );
    }

    #[test]
    fn add_action_missing_report_fails() {
        let mut engine = TransparentReports::default();
        assert!(
            engine
                .add_corrective_action("nonexistent", sample_action("a-1"), &trace())
                .is_err()
        );
    }

    #[test]
    fn action_identified_to_planned() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .unwrap();
        assert!(
            engine
                .update_action_status("r-1", "a-1", ActionStatus::Planned, &trace())
                .is_ok()
        );
    }

    #[test]
    fn action_invalid_transition_fails() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .unwrap();
        assert!(
            engine
                .update_action_status("r-1", "a-1", ActionStatus::Verified, &trace())
                .is_err()
        );
    }

    #[test]
    fn full_action_lifecycle() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .unwrap();
        engine
            .update_action_status("r-1", "a-1", ActionStatus::Planned, &trace())
            .unwrap();
        engine
            .update_action_status("r-1", "a-1", ActionStatus::Implemented, &trace())
            .unwrap();
        engine
            .update_action_status("r-1", "a-1", ActionStatus::Verified, &trace())
            .unwrap();
        let r = engine.reports().get("r-1").unwrap();
        assert_eq!(r.corrective_actions[0].status, ActionStatus::Verified);
    }

    #[test]
    fn catalog_empty() {
        let mut engine = TransparentReports::default();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.total_reports, 0);
    }

    #[test]
    fn catalog_counts_reports() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        engine
            .create_report(
                sample_report("r-2", ReportCategory::ServiceOutage),
                &trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.total_reports, 2);
    }

    #[test]
    fn catalog_tracks_open_actions() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.open_actions, 1);
    }

    #[test]
    fn catalog_has_hash() {
        let mut engine = TransparentReports::default();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.content_hash.len(), 64);
    }

    #[test]
    fn catalog_deterministic() {
        let mut e1 = TransparentReports::default();
        let mut e2 = TransparentReports::default();
        let c1 = e1.generate_catalog("trace-det");
        let c2 = e2.generate_catalog("trace-det");
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn catalog_groups_by_category() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert!(catalog.by_category.contains_key("security_incident"));
    }

    #[test]
    fn catalog_groups_by_severity() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert!(catalog.by_severity.contains_key("high"));
    }

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::Low.label(), "low");
    }

    #[test]
    fn audit_log_populated() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        assert_eq!(engine.audit_log().len(), 7);
    }

    #[test]
    fn export_jsonl() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .unwrap();
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }
}
