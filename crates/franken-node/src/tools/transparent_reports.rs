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
use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
const MAX_CORRECTIVE_ACTIONS: usize = 256;

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

#[derive(Serialize)]
struct ReportContentHashView<'a> {
    report_id: &'a str,
    title: &'a str,
    category: &'static str,
    severity: &'static str,
    sections: &'a BTreeMap<String, String>,
    timeline: &'a [TimelineEntry],
    root_causes: &'a [String],
    corrective_actions: &'a [CorrectiveAction],
    lessons_learned: &'a [String],
    report_version: &'a str,
    created_at: &'a str,
}

fn compute_report_content_hash(report: &TransparentReport) -> Result<String, serde_json::Error> {
    let view = ReportContentHashView {
        report_id: &report.report_id,
        title: &report.title,
        category: report.category.label(),
        severity: report.severity.label(),
        sections: &report.sections,
        timeline: &report.timeline,
        root_causes: &report.root_causes,
        corrective_actions: &report.corrective_actions,
        lessons_learned: &report.lessons_learned,
        report_version: &report.report_version,
        created_at: &report.created_at,
    };
    let payload = serde_json::to_vec(&view)?;
    let mut hasher = Sha256::new();
    hasher.update(b"transparent_reports_report_content_hash_v1:");
    update_hash_len_prefixed(&mut hasher, &payload);
    Ok(hex::encode(hasher.finalize()))
}

fn compute_catalog_content_hash(
    report_version: &str,
    total_reports: usize,
    by_category: &BTreeMap<String, usize>,
    by_severity: &BTreeMap<String, usize>,
    open_actions: usize,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"transparent_reports_catalog_hash_v1:");
    update_hash_len_prefixed(&mut hasher, report_version.as_bytes());
    hasher.update((total_reports as u64).to_le_bytes());
    hasher.update((open_actions as u64).to_le_bytes());
    hasher.update((u64::try_from(by_category.len()).unwrap_or(u64::MAX)).to_le_bytes());
    for (category, count) in by_category {
        update_hash_len_prefixed(&mut hasher, category.as_bytes());
        hasher.update((*count as u64).to_le_bytes());
    }
    hasher.update((u64::try_from(by_severity.len()).unwrap_or(u64::MAX)).to_le_bytes());
    for (severity, count) in by_severity {
        update_hash_len_prefixed(&mut hasher, severity.as_bytes());
        hasher.update((*count as u64).to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

fn update_hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
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
        if report.report_id.trim().is_empty() {
            return Err("Report id must not be empty".to_string());
        }

        if self.reports.contains_key(&report.report_id) {
            return Err(format!("Report {} already exists", report.report_id));
        }

        if report.title.trim().is_empty() {
            return Err("Report title must not be empty".to_string());
        }

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
            if report
                .sections
                .get(*sec)
                .is_some_and(|section| section.trim().is_empty())
            {
                self.log(
                    event_codes::TR_ERR_MISSING_SECTION,
                    trace_id,
                    serde_json::json!({
                        "report_id": &report.report_id,
                        "empty": sec,
                    }),
                );
                return Err(format!("Empty required section: {}", sec));
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
        if report.timeline.iter().any(|entry| {
            entry.timestamp.trim().is_empty()
                || entry.event.trim().is_empty()
                || entry.actor.trim().is_empty()
        }) {
            return Err("Timeline entries must have timestamp, event, and actor".to_string());
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
        if report
            .root_causes
            .iter()
            .any(|cause| cause.trim().is_empty())
        {
            return Err("Root causes must not contain empty entries".to_string());
        }
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
        if report
            .lessons_learned
            .iter()
            .any(|lesson| lesson.trim().is_empty())
        {
            return Err("Lessons learned must not contain empty entries".to_string());
        }
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

        report.report_version = self.report_version.clone();
        report.created_at = Utc::now().to_rfc3339();
        report.content_hash =
            compute_report_content_hash(&report).map_err(|err| err.to_string())?;

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

        if action.action_id.trim().is_empty() {
            return Err("Action id must not be empty".to_string());
        }

        if action.description.trim().is_empty() {
            return Err("Action description must not be empty".to_string());
        }

        if action.owner.trim().is_empty() {
            return Err("Action owner must not be empty".to_string());
        }

        if action.due_date.trim().is_empty() {
            return Err("Action due date must not be empty".to_string());
        }

        let mut report = self
            .reports
            .get(report_id)
            .cloned()
            .ok_or_else(|| format!("Report {report_id} not found"))?;
        if report
            .corrective_actions
            .iter()
            .any(|existing| existing.action_id == action.action_id)
        {
            return Err(format!("Action {} already exists", action.action_id));
        }
        let action_id = action.action_id.clone();
        push_bounded(
            &mut report.corrective_actions,
            action,
            MAX_CORRECTIVE_ACTIONS,
        );
        report.content_hash =
            compute_report_content_hash(&report).map_err(|err| err.to_string())?;
        let content_hash = report.content_hash.clone();
        self.reports.insert(report_id.to_string(), report);

        self.log(
            event_codes::TR_CORRECTIVE_ACTION_ADDED,
            trace_id,
            serde_json::json!({
                "report_id": report_id,
                "action_id": &action_id,
            }),
        );
        self.log(
            event_codes::TR_INTEGRITY_VERIFIED,
            trace_id,
            serde_json::json!({
                "report_id": report_id,
                "content_hash": &content_hash,
            }),
        );
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

        let mut updated_report = report.clone();
        let action_mut = updated_report
            .corrective_actions
            .iter_mut()
            .find(|a| a.action_id == action_id)
            .ok_or_else(|| format!("Action {action_id} not found"))?;
        action_mut.status = new_status;
        updated_report.content_hash =
            compute_report_content_hash(&updated_report).map_err(|err| err.to_string())?;
        let content_hash = updated_report.content_hash.clone();
        self.reports.insert(report_id.to_string(), updated_report);

        self.log(
            event_codes::TR_ACTION_STATUS_UPDATED,
            trace_id,
            serde_json::json!({
                "action_id": action_id,
                "new_status": new_status.label(),
            }),
        );
        self.log(
            event_codes::TR_INTEGRITY_VERIFIED,
            trace_id,
            serde_json::json!({
                "report_id": report_id,
                "content_hash": &content_hash,
            }),
        );

        Ok(())
    }

    pub fn generate_catalog(&mut self, trace_id: &str) -> ReportCatalog {
        let mut by_category = BTreeMap::new();
        let mut by_severity = BTreeMap::new();
        let mut open_actions: usize = 0;

        for report in self.reports.values() {
            let category_count = by_category
                .entry(report.category.label().to_string())
                .or_insert(0usize);
            *category_count = category_count.saturating_add(1);

            let severity_count = by_severity
                .entry(report.severity.label().to_string())
                .or_insert(0usize);
            *severity_count = severity_count.saturating_add(1);
            for action in &report.corrective_actions {
                if action.status != ActionStatus::Verified {
                    open_actions = open_actions.saturating_add(1);
                }
            }
        }

        let content_hash = compute_catalog_content_hash(
            &self.report_version,
            self.reports.len(),
            &by_category,
            &by_severity,
            open_actions,
        );

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
        push_bounded(
            &mut self.audit_log,
            TrAuditRecord {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_unframed_transparent_hash(domain: &[u8], payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }

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
    fn push_bounded_zero_capacity_clears_existing_items() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn push_bounded_overfull_vector_keeps_newest_window() {
        let mut values = vec![1, 2, 3, 4];

        push_bounded(&mut values, 5, 2);

        assert_eq!(values, vec![4, 5]);
    }

    fn engine_with_identified_action() -> TransparentReports {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-action", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("report should be accepted");
        engine
            .add_corrective_action("r-action", sample_action("a-action"), &trace())
            .expect("action should be accepted");
        engine
    }

    fn advance_action(
        engine: &mut TransparentReports,
        action_id: &str,
        status: ActionStatus,
    ) -> Result<(), String> {
        engine.update_action_status("r-action", action_id, status, &trace())
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
    fn missing_each_required_section_is_rejected() {
        for missing_section in REQUIRED_SECTIONS {
            let mut engine = TransparentReports::default();
            let mut report = sample_report("r-missing-section", ReportCategory::ComplianceGap);
            report.sections.remove(*missing_section);

            let err = engine
                .create_report(report, &trace())
                .expect_err("missing mandatory section should fail");

            assert!(err.contains(*missing_section));
            assert!(engine.reports().is_empty());
        }
    }

    #[test]
    fn failed_missing_section_create_does_not_store_partial_report() {
        let mut engine = TransparentReports::default();
        let mut report = sample_report("r-partial", ReportCategory::ServiceOutage);
        report.sections.remove("impact_assessment");

        let result = engine.create_report(report, &trace());

        assert!(result.is_err());
        assert!(!engine.reports().contains_key("r-partial"));
    }

    #[test]
    fn failed_empty_timeline_create_does_not_store_partial_report() {
        let mut engine = TransparentReports::default();
        let mut report = sample_report("r-empty-timeline", ReportCategory::DataIntegrity);
        report.timeline.clear();

        let result = engine.create_report(report, &trace());

        assert!(result.is_err());
        assert!(!engine.reports().contains_key("r-empty-timeline"));
    }

    #[test]
    fn empty_report_id_does_not_store_or_audit() {
        let mut engine = TransparentReports::default();

        let err = engine
            .create_report(
                sample_report("", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect_err("empty report id must fail");

        assert!(err.contains("Report id"));
        assert!(engine.reports().is_empty());
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn whitespace_report_title_does_not_store_or_audit() {
        let mut engine = TransparentReports::default();
        let mut report = sample_report("r-blank-title", ReportCategory::ComplianceGap);
        report.title = " \t ".to_string();

        let err = engine
            .create_report(report, &trace())
            .expect_err("blank report titles must fail");

        assert!(err.contains("title"));
        assert!(!engine.reports().contains_key("r-blank-title"));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn duplicate_report_id_does_not_overwrite_original() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-dupe", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("first report should be accepted");
        let original_hash = engine.reports()["r-dupe"].content_hash.clone();
        let original_created_at = engine.reports()["r-dupe"].created_at.clone();
        let audit_count_before = engine.audit_log().len();
        let mut duplicate = sample_report("r-dupe", ReportCategory::ComplianceGap);
        duplicate.title = "Replacement title".to_string();

        let err = engine
            .create_report(duplicate, &trace())
            .expect_err("duplicate report ids must fail");

        assert!(err.contains("already exists"));
        assert_eq!(
            engine.reports()["r-dupe"].category,
            ReportCategory::SecurityIncident
        );
        assert_ne!(engine.reports()["r-dupe"].title, "Replacement title");
        assert_eq!(engine.reports()["r-dupe"].content_hash, original_hash);
        assert_eq!(engine.reports()["r-dupe"].created_at, original_created_at);
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn blank_required_section_is_rejected_without_storing_report() {
        let mut engine = TransparentReports::default();
        let mut report = sample_report("r-blank-section", ReportCategory::ServiceOutage);
        report
            .sections
            .insert("lessons_learned".to_string(), " \n ".to_string());

        let err = engine
            .create_report(report, "trace-blank-section")
            .expect_err("blank required sections must fail");

        assert!(err.contains("lessons_learned"));
        assert!(!engine.reports().contains_key("r-blank-section"));
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::TR_ERR_MISSING_SECTION
        );
    }

    #[test]
    fn blank_timeline_event_is_rejected_without_storing_report() {
        let mut engine = TransparentReports::default();
        let mut report = sample_report("r-blank-timeline", ReportCategory::DataIntegrity);
        report.timeline[0].event = " \t ".to_string();

        let err = engine
            .create_report(report, &trace())
            .expect_err("blank timeline events must fail");

        assert!(err.contains("Timeline entries"));
        assert!(!engine.reports().contains_key("r-blank-timeline"));
    }

    #[test]
    fn blank_root_cause_is_rejected_without_storing_report() {
        let mut engine = TransparentReports::default();
        let mut report = sample_report("r-blank-root-cause", ReportCategory::DataIntegrity);
        report.root_causes.push(" \n ".to_string());

        let err = engine
            .create_report(report, &trace())
            .expect_err("blank root causes must fail");

        assert!(err.contains("Root causes"));
        assert!(!engine.reports().contains_key("r-blank-root-cause"));
    }

    #[test]
    fn blank_lesson_is_rejected_without_storing_report() {
        let mut engine = TransparentReports::default();
        let mut report = sample_report("r-blank-lesson", ReportCategory::PerformanceRegression);
        report.lessons_learned.push(" \t ".to_string());

        let err = engine
            .create_report(report, &trace())
            .expect_err("blank lessons must fail");

        assert!(err.contains("Lessons learned"));
        assert!(!engine.reports().contains_key("r-blank-lesson"));
    }

    #[test]
    fn create_sets_hash_and_version() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("should succeed");
        let stored = engine.reports().get("r-1").expect("should exist");
        assert_eq!(stored.content_hash.len(), 64);
        assert_eq!(stored.report_version, REPORT_VERSION);
    }

    #[test]
    fn report_hash_changes_when_severity_changes() {
        let mut base = sample_report("r-1", ReportCategory::SecurityIncident);
        base.report_version = REPORT_VERSION.to_string();
        base.created_at = "2026-02-01T10:00:00Z".to_string();

        let mut changed = base.clone();
        changed.severity = Severity::Low;

        assert_ne!(
            compute_report_content_hash(&base).unwrap(),
            compute_report_content_hash(&changed).unwrap()
        );
    }

    #[test]
    fn report_hash_changes_when_timeline_changes() {
        let mut base = sample_report("r-1", ReportCategory::SecurityIncident);
        base.report_version = REPORT_VERSION.to_string();
        base.created_at = "2026-02-01T10:00:00Z".to_string();

        let mut changed = base.clone();
        changed.timeline[0].event = "Operator escalated incident".to_string();

        assert_ne!(
            compute_report_content_hash(&base).unwrap(),
            compute_report_content_hash(&changed).unwrap()
        );
    }

    #[test]
    fn report_hash_uses_length_prefixed_payload() {
        let mut report = sample_report("r-framed", ReportCategory::SecurityIncident);
        report.report_version = REPORT_VERSION.to_string();
        report.created_at = "2026-02-01T10:00:00Z".to_string();

        let view = ReportContentHashView {
            report_id: &report.report_id,
            title: &report.title,
            category: report.category.label(),
            severity: report.severity.label(),
            sections: &report.sections,
            timeline: &report.timeline,
            root_causes: &report.root_causes,
            corrective_actions: &report.corrective_actions,
            lessons_learned: &report.lessons_learned,
            report_version: &report.report_version,
            created_at: &report.created_at,
        };
        let payload = serde_json::to_vec(&view).expect("report hash view must serialize");
        let legacy = legacy_unframed_transparent_hash(b"transparent_reports_hash_v1:", &payload);

        assert_ne!(compute_report_content_hash(&report).unwrap(), legacy);
    }

    #[test]
    fn add_corrective_action() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("should succeed");
        assert!(
            engine
                .add_corrective_action("r-1", sample_action("a-1"), &trace())
                .is_ok()
        );
    }

    #[test]
    fn add_corrective_action_refreshes_content_hash() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("should succeed");
        let initial_hash = engine
            .reports()
            .get("r-1")
            .expect("report should exist")
            .content_hash
            .clone();

        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .expect("should succeed");

        let stored = engine.reports().get("r-1").expect("report should exist");
        assert_ne!(stored.content_hash, initial_hash);
        assert_eq!(
            stored.content_hash,
            compute_report_content_hash(stored).unwrap()
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
    fn empty_action_id_does_not_mutate_report_or_audit() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-empty-action", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("report should be accepted");
        let audit_count_before = engine.audit_log().len();

        let err = engine
            .add_corrective_action("r-empty-action", sample_action(""), &trace())
            .expect_err("empty action ids must fail");

        assert!(err.contains("Action id"));
        assert!(
            engine.reports()["r-empty-action"]
                .corrective_actions
                .is_empty()
        );
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn blank_action_owner_does_not_mutate_report_or_audit() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-blank-owner", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("report should be accepted");
        let audit_count_before = engine.audit_log().len();
        let mut action = sample_action("a-blank-owner");
        action.owner = " \n ".to_string();

        let err = engine
            .add_corrective_action("r-blank-owner", action, &trace())
            .expect_err("blank action owners must fail");

        assert!(err.contains("owner"));
        assert!(
            engine.reports()["r-blank-owner"]
                .corrective_actions
                .is_empty()
        );
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn duplicate_action_id_does_not_overwrite_existing_action() {
        let mut engine = engine_with_identified_action();
        let audit_count_before = engine.audit_log().len();
        let original_hash = engine.reports()["r-action"].content_hash.clone();
        let mut duplicate = sample_action("a-action");
        duplicate.description = "Replacement action".to_string();

        let err = engine
            .add_corrective_action("r-action", duplicate, &trace())
            .expect_err("duplicate action ids must fail");

        assert!(err.contains("already exists"));
        let actions = &engine.reports()["r-action"].corrective_actions;
        assert_eq!(actions.len(), 1);
        assert_ne!(actions[0].description, "Replacement action");
        assert_eq!(engine.reports()["r-action"].content_hash, original_hash);
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn action_identified_to_planned() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("should succeed");
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .expect("should succeed");
        assert!(
            engine
                .update_action_status("r-1", "a-1", ActionStatus::Planned, &trace())
                .is_ok()
        );
    }

    #[test]
    fn update_action_status_refreshes_content_hash() {
        let mut engine = TransparentReports::default();
        engine
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("should succeed");
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .expect("should succeed");
        let hash_after_add = engine
            .reports()
            .get("r-1")
            .expect("report should exist")
            .content_hash
            .clone();

        engine
            .update_action_status("r-1", "a-1", ActionStatus::Planned, &trace())
            .expect("should succeed");

        let stored = engine.reports().get("r-1").expect("report should exist");
        assert_ne!(stored.content_hash, hash_after_add);
        assert_eq!(
            stored.content_hash,
            compute_report_content_hash(stored).unwrap()
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
            .expect("should succeed");
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .expect("should succeed");
        assert!(
            engine
                .update_action_status("r-1", "a-1", ActionStatus::Verified, &trace())
                .is_err()
        );
    }

    #[test]
    fn update_action_status_missing_report_fails() {
        let mut engine = TransparentReports::default();

        let err = engine
            .update_action_status(
                "missing-report",
                "a-action",
                ActionStatus::Planned,
                &trace(),
            )
            .expect_err("missing report should fail");

        assert!(err.contains("Report missing-report not found"));
    }

    #[test]
    fn update_action_status_missing_action_fails() {
        let mut engine = engine_with_identified_action();

        let err = engine
            .update_action_status(
                "r-action",
                "missing-action",
                ActionStatus::Planned,
                &trace(),
            )
            .expect_err("missing action should fail");

        assert!(err.contains("Action missing-action not found"));
    }

    #[test]
    fn planned_action_cannot_skip_directly_to_verified() {
        let mut engine = engine_with_identified_action();
        advance_action(&mut engine, "a-action", ActionStatus::Planned)
            .expect("identified to planned should be valid");

        let result = advance_action(&mut engine, "a-action", ActionStatus::Verified);

        assert!(result.is_err());
        let stored = engine
            .reports()
            .get("r-action")
            .expect("report should exist");
        assert_eq!(stored.corrective_actions[0].status, ActionStatus::Planned);
    }

    #[test]
    fn implemented_action_cannot_revert_directly_to_identified() {
        let mut engine = engine_with_identified_action();
        advance_action(&mut engine, "a-action", ActionStatus::Planned)
            .expect("identified to planned should be valid");
        advance_action(&mut engine, "a-action", ActionStatus::Implemented)
            .expect("planned to implemented should be valid");

        let result = advance_action(&mut engine, "a-action", ActionStatus::Identified);

        assert!(result.is_err());
        let stored = engine
            .reports()
            .get("r-action")
            .expect("report should exist");
        assert_eq!(
            stored.corrective_actions[0].status,
            ActionStatus::Implemented
        );
    }

    #[test]
    fn verified_action_cannot_reopen_to_planned() {
        let mut engine = engine_with_identified_action();
        advance_action(&mut engine, "a-action", ActionStatus::Planned)
            .expect("identified to planned should be valid");
        advance_action(&mut engine, "a-action", ActionStatus::Implemented)
            .expect("planned to implemented should be valid");
        advance_action(&mut engine, "a-action", ActionStatus::Verified)
            .expect("implemented to verified should be valid");

        let result = advance_action(&mut engine, "a-action", ActionStatus::Planned);

        assert!(result.is_err());
        let stored = engine
            .reports()
            .get("r-action")
            .expect("report should exist");
        assert_eq!(stored.corrective_actions[0].status, ActionStatus::Verified);
    }

    #[test]
    fn invalid_transition_leaves_action_status_unchanged() {
        let mut engine = engine_with_identified_action();

        let result = advance_action(&mut engine, "a-action", ActionStatus::Verified);

        assert!(result.is_err());
        let stored = engine
            .reports()
            .get("r-action")
            .expect("report should exist");
        assert_eq!(
            stored.corrective_actions[0].status,
            ActionStatus::Identified
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
            .expect("should succeed");
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .expect("should succeed");
        engine
            .update_action_status("r-1", "a-1", ActionStatus::Planned, &trace())
            .expect("should succeed");
        engine
            .update_action_status("r-1", "a-1", ActionStatus::Implemented, &trace())
            .expect("should succeed");
        engine
            .update_action_status("r-1", "a-1", ActionStatus::Verified, &trace())
            .expect("should succeed");
        let r = engine.reports().get("r-1").expect("should exist");
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
            .expect("should succeed");
        engine
            .create_report(
                sample_report("r-2", ReportCategory::ServiceOutage),
                &trace(),
            )
            .expect("should succeed");
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
            .expect("should succeed");
        engine
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .expect("should succeed");
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
    fn catalog_hash_changes_when_open_actions_change() {
        let mut without_open_actions = TransparentReports::default();
        let mut with_open_actions = TransparentReports::default();
        without_open_actions
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("should succeed");
        with_open_actions
            .create_report(
                sample_report("r-1", ReportCategory::SecurityIncident),
                &trace(),
            )
            .expect("should succeed");
        with_open_actions
            .add_corrective_action("r-1", sample_action("a-1"), &trace())
            .expect("should succeed");

        let first = without_open_actions.generate_catalog(&trace());
        let second = with_open_actions.generate_catalog(&trace());

        assert_ne!(first.content_hash, second.content_hash);
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
            .expect("should succeed");
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
            .expect("should succeed");
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
            .expect("should succeed");
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
            .expect("should succeed");
        let jsonl = engine
            .export_audit_log_jsonl()
            .expect("jsonl export should succeed");
        let first: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().expect("should have line"))
                .expect("parse should succeed");
        assert!(first["event_code"].is_string());
    }
}
