//! bd-cv49: Published security/ops improvement case studies (Section 15).
//!
//! Implements a deterministic registry for case-study publication evidence.
//! Captures pre/post security + operational metrics, publication status,
//! and release-gate summaries consumable by section/program verification gates.
//!
//! # Invariants
//!
//! - **INV-CSC-PUBLISHED**: Registry includes at least three published case studies.
//! - **INV-CSC-MEASURED**: At least two studies show measurable security improvement.
//! - **INV-CSC-REVIEWED**: Every published study is reviewed by the featured org.
//! - **INV-CSC-DISTRIBUTED**: At least one study is submitted to external channels.
//! - **INV-CSC-TEMPLATE**: Case-study outputs follow a stable template contract.
//! - **INV-CSC-AUDITABLE**: Every mutation emits an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub mod event_codes {
    pub const CSC_CASE_REGISTERED: &str = "CSC-001";
    pub const CSC_CASE_REVIEWED: &str = "CSC-002";
    pub const CSC_CASE_PUBLISHED_WEBSITE: &str = "CSC-003";
    pub const CSC_CASE_SUBMITTED_EXTERNAL: &str = "CSC-004";
    pub const CSC_SECURITY_IMPROVEMENT_RECORDED: &str = "CSC-005";
    pub const CSC_OPS_IMPROVEMENT_RECORDED: &str = "CSC-006";
    pub const CSC_SUMMARY_GENERATED: &str = "CSC-007";
    pub const CSC_GATE_PASSED: &str = "CSC-008";
    pub const CSC_GATE_FAILED: &str = "CSC-009";
    pub const CSC_SCHEMA_VERSION_EMBEDDED: &str = "CSC-010";

    pub const CSC_ERR_DUPLICATE_CASE_ID: &str = "CSC-ERR-001";
    pub const CSC_ERR_INVALID_CASE_STUDY: &str = "CSC-ERR-002";
    pub const CSC_ERR_PUBLICATION_CONTRACT: &str = "CSC-ERR-003";
}

pub mod invariants {
    pub const INV_CSC_PUBLISHED: &str = "INV-CSC-PUBLISHED";
    pub const INV_CSC_MEASURED: &str = "INV-CSC-MEASURED";
    pub const INV_CSC_REVIEWED: &str = "INV-CSC-REVIEWED";
    pub const INV_CSC_DISTRIBUTED: &str = "INV-CSC-DISTRIBUTED";
    pub const INV_CSC_TEMPLATE: &str = "INV-CSC-TEMPLATE";
    pub const INV_CSC_AUDITABLE: &str = "INV-CSC-AUDITABLE";
}

pub const SCHEMA_VERSION: &str = "csc-v1.0";
pub const MIN_CASE_STUDIES: usize = 3;
pub const MIN_SECURITY_IMPROVEMENT_CASE_STUDIES: usize = 2;
pub const MIN_INDUSTRY_SUBMISSIONS: usize = 1;

/// Pre/post security and operational metrics used for case-study quantification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyMetrics {
    pub pre_vulnerability_count: u32,
    pub post_vulnerability_count: u32,
    pub pre_incident_containment_minutes: u32,
    pub post_incident_containment_minutes: u32,
    pub pre_deployments_per_week: u32,
    pub post_deployments_per_week: u32,
}

impl KeyMetrics {
    pub fn vulnerability_reduction_bps(&self) -> i64 {
        percent_delta_bps(
            self.pre_vulnerability_count,
            self.post_vulnerability_count,
            true,
        )
    }

    pub fn incident_response_improvement_bps(&self) -> i64 {
        percent_delta_bps(
            self.pre_incident_containment_minutes,
            self.post_incident_containment_minutes,
            true,
        )
    }

    pub fn deployment_frequency_improvement_bps(&self) -> i64 {
        percent_delta_bps(
            self.pre_deployments_per_week,
            self.post_deployments_per_week,
            false,
        )
    }

    pub fn has_measurable_security_improvement(&self) -> bool {
        self.vulnerability_reduction_bps() > 0
    }
}

/// Publication lifecycle metadata for one case study.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicationStatus {
    pub reviewed_by_featured_org: bool,
    pub reviewed_at: Option<String>,
    pub published_on_project_website: bool,
    pub submitted_to_industry_publication: bool,
    pub industry_publication_name: Option<String>,
    pub publication_url: String,
}

/// A single published case study with reproducible metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseStudy {
    pub case_study_id: String,
    pub title: String,
    pub organization_type: String,
    pub industry: String,
    pub anonymized: bool,
    pub migration_effort_days: u32,
    pub migration_timeline_days: u32,
    pub lessons_learned: Vec<String>,
    pub recommendations: Vec<String>,
    pub key_metrics: KeyMetrics,
    pub publication: PublicationStatus,
    pub content_hash: String,
}

impl CaseStudy {
    pub fn recompute_hash(&mut self) -> Result<(), String> {
        self.content_hash = compute_case_study_hash(self)?;
        Ok(())
    }

    pub fn has_measurable_security_improvement(&self) -> bool {
        self.key_metrics.has_measurable_security_improvement()
    }
}

#[derive(Debug, Clone, Serialize)]
struct CaseStudyHashView<'a> {
    case_study_id: &'a str,
    title: &'a str,
    organization_type: &'a str,
    industry: &'a str,
    anonymized: bool,
    migration_effort_days: u32,
    migration_timeline_days: u32,
    lessons_learned: &'a [String],
    recommendations: &'a [String],
    key_metrics: &'a KeyMetrics,
    publication: &'a PublicationStatus,
}

/// Deterministic summary consumed by section/program verification gates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseStudyRegistrySummary {
    pub schema_version: String,
    pub total_case_studies: usize,
    pub security_improvement_case_studies: usize,
    pub reviewed_case_studies: usize,
    pub website_published_case_studies: usize,
    pub industry_submissions: usize,
    pub overall_verdict: bool,
    pub unmet_criteria: Vec<String>,
    pub content_hash: String,
    pub generated_at: String,
}

/// Audit record for JSONL evidence export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseStudyAuditRecord {
    pub event_code: String,
    pub entity_id: String,
    pub detail: String,
    pub trace_id: String,
    pub timestamp: String,
}

/// Case-study registry engine.
#[derive(Debug, Clone)]
pub struct SecurityOpsCaseStudyRegistry {
    pub case_studies: BTreeMap<String, CaseStudy>,
    pub audit_log: Vec<CaseStudyAuditRecord>,
    pub schema_version: String,
}

impl Default for SecurityOpsCaseStudyRegistry {
    fn default() -> Self {
        Self {
            case_studies: BTreeMap::new(),
            audit_log: Vec::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }
}

impl SecurityOpsCaseStudyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_case_study(
        &mut self,
        mut case_study: CaseStudy,
        trace_id: &str,
    ) -> Result<String, String> {
        validate_case_study(&case_study)?;

        if self.case_studies.contains_key(&case_study.case_study_id) {
            self.log(
                event_codes::CSC_ERR_DUPLICATE_CASE_ID,
                &case_study.case_study_id,
                "duplicate case_study_id rejected",
                trace_id,
            );
            return Err(format!(
                "duplicate case_study_id: {}",
                case_study.case_study_id
            ));
        }

        case_study.recompute_hash()?;
        let case_study_id = case_study.case_study_id.clone();

        self.log(
            event_codes::CSC_CASE_REGISTERED,
            &case_study_id,
            &format!("title={}", case_study.title),
            trace_id,
        );

        if case_study.publication.reviewed_by_featured_org {
            self.log(
                event_codes::CSC_CASE_REVIEWED,
                &case_study_id,
                "reviewed_by_featured_org=true",
                trace_id,
            );
        }

        if case_study.publication.published_on_project_website {
            self.log(
                event_codes::CSC_CASE_PUBLISHED_WEBSITE,
                &case_study_id,
                &case_study.publication.publication_url,
                trace_id,
            );
        }

        if case_study.publication.submitted_to_industry_publication {
            let channel = case_study
                .publication
                .industry_publication_name
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            self.log(
                event_codes::CSC_CASE_SUBMITTED_EXTERNAL,
                &case_study_id,
                &channel,
                trace_id,
            );
        }

        let vuln_improvement = case_study.key_metrics.vulnerability_reduction_bps();
        self.log(
            event_codes::CSC_SECURITY_IMPROVEMENT_RECORDED,
            &case_study_id,
            &format!("vulnerability_reduction_bps={vuln_improvement}"),
            trace_id,
        );

        let ops_improvement = case_study.key_metrics.incident_response_improvement_bps();
        self.log(
            event_codes::CSC_OPS_IMPROVEMENT_RECORDED,
            &case_study_id,
            &format!("incident_response_improvement_bps={ops_improvement}"),
            trace_id,
        );

        self.case_studies.insert(case_study_id.clone(), case_study);
        Ok(case_study_id)
    }

    pub fn case_studies(&self) -> &BTreeMap<String, CaseStudy> {
        &self.case_studies
    }

    pub fn generate_summary(&mut self, trace_id: &str) -> CaseStudyRegistrySummary {
        let total_case_studies = self.case_studies.len();
        let security_improvement_case_studies = self
            .case_studies
            .values()
            .filter(|case_study| case_study.has_measurable_security_improvement())
            .count();
        let reviewed_case_studies = self
            .case_studies
            .values()
            .filter(|case_study| case_study.publication.reviewed_by_featured_org)
            .count();
        let website_published_case_studies = self
            .case_studies
            .values()
            .filter(|case_study| case_study.publication.published_on_project_website)
            .count();
        let industry_submissions = self
            .case_studies
            .values()
            .filter(|case_study| case_study.publication.submitted_to_industry_publication)
            .count();

        let mut unmet_criteria = Vec::new();

        if total_case_studies < MIN_CASE_STUDIES {
            unmet_criteria.push(format!(
                "requires >= {MIN_CASE_STUDIES} case studies (found {total_case_studies})"
            ));
        }
        if security_improvement_case_studies < MIN_SECURITY_IMPROVEMENT_CASE_STUDIES {
            unmet_criteria.push(format!(
                "requires >= {MIN_SECURITY_IMPROVEMENT_CASE_STUDIES} case studies with measurable security improvement (found {security_improvement_case_studies})"
            ));
        }
        if reviewed_case_studies != total_case_studies {
            unmet_criteria.push(format!(
                "requires all studies reviewed by featured organization ({reviewed_case_studies}/{total_case_studies})"
            ));
        }
        if website_published_case_studies < MIN_CASE_STUDIES {
            unmet_criteria.push(format!(
                "requires >= {MIN_CASE_STUDIES} studies published on project website (found {website_published_case_studies})"
            ));
        }
        if industry_submissions < MIN_INDUSTRY_SUBMISSIONS {
            unmet_criteria.push(format!(
                "requires >= {MIN_INDUSTRY_SUBMISSIONS} external industry submission (found {industry_submissions})"
            ));
        }

        let overall_verdict = unmet_criteria.is_empty();
        let hash_input = format!(
            "{SCHEMA_VERSION}:{total_case_studies}:{security_improvement_case_studies}:{reviewed_case_studies}:{website_published_case_studies}:{industry_submissions}:{overall_verdict}:{:?}",
            unmet_criteria
        );
        let content_hash = sha256_hex(hash_input.as_bytes());

        self.log(
            event_codes::CSC_SUMMARY_GENERATED,
            "registry",
            &format!("total_case_studies={total_case_studies}"),
            trace_id,
        );
        self.log(
            event_codes::CSC_SCHEMA_VERSION_EMBEDDED,
            "registry",
            SCHEMA_VERSION,
            trace_id,
        );
        if overall_verdict {
            self.log(
                event_codes::CSC_GATE_PASSED,
                "registry",
                "case-study gate satisfied",
                trace_id,
            );
        } else {
            self.log(
                event_codes::CSC_GATE_FAILED,
                "registry",
                &unmet_criteria.join("; "),
                trace_id,
            );
        }

        CaseStudyRegistrySummary {
            schema_version: self.schema_version.clone(),
            total_case_studies,
            security_improvement_case_studies,
            reviewed_case_studies,
            website_published_case_studies,
            industry_submissions,
            overall_verdict,
            unmet_criteria,
            content_hash,
            generated_at: Utc::now().to_rfc3339(),
        }
    }

    pub fn export_registry_json(&self) -> Result<String, String> {
        let mut exported: Vec<&CaseStudy> = self.case_studies.values().collect();
        exported.sort_by(|left, right| left.case_study_id.cmp(&right.case_study_id));
        serde_json::to_string_pretty(&exported)
            .map_err(|error| format!("failed to encode case-study registry: {error}"))
    }

    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|record| serde_json::to_string(record).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn log(&mut self, event_code: &str, entity_id: &str, detail: &str, trace_id: &str) {
        self.audit_log.push(CaseStudyAuditRecord {
            event_code: event_code.to_string(),
            entity_id: entity_id.to_string(),
            detail: detail.to_string(),
            trace_id: trace_id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        });
    }
}

fn validate_case_study(case_study: &CaseStudy) -> Result<(), String> {
    if case_study.case_study_id.trim().is_empty()
        || case_study.title.trim().is_empty()
        || case_study.organization_type.trim().is_empty()
        || case_study.industry.trim().is_empty()
    {
        return Err("case study identity fields must be non-empty".to_string());
    }

    if case_study.lessons_learned.is_empty() || case_study.recommendations.is_empty() {
        return Err("case study must include lessons_learned and recommendations".to_string());
    }

    if !case_study
        .publication
        .publication_url
        .starts_with("https://")
    {
        return Err("publication_url must start with https://".to_string());
    }

    if case_study.publication.submitted_to_industry_publication
        && case_study
            .publication
            .industry_publication_name
            .as_ref()
            .is_none_or(|name| name.trim().is_empty())
    {
        return Err(
            "industry_publication_name required when submitted_to_industry_publication=true"
                .to_string(),
        );
    }

    if case_study.publication.reviewed_by_featured_org
        && case_study
            .publication
            .reviewed_at
            .as_ref()
            .is_none_or(|timestamp| timestamp.trim().is_empty())
    {
        return Err("reviewed_at required when reviewed_by_featured_org=true".to_string());
    }

    Ok(())
}

fn compute_case_study_hash(case_study: &CaseStudy) -> Result<String, String> {
    let hash_view = CaseStudyHashView {
        case_study_id: &case_study.case_study_id,
        title: &case_study.title,
        organization_type: &case_study.organization_type,
        industry: &case_study.industry,
        anonymized: case_study.anonymized,
        migration_effort_days: case_study.migration_effort_days,
        migration_timeline_days: case_study.migration_timeline_days,
        lessons_learned: &case_study.lessons_learned,
        recommendations: &case_study.recommendations,
        key_metrics: &case_study.key_metrics,
        publication: &case_study.publication,
    };
    let encoded = serde_json::to_vec(&hash_view)
        .map_err(|error| format!("failed to encode case-study hash payload: {error}"))?;
    Ok(sha256_hex(&encoded))
}

fn percent_delta_bps(pre: u32, post: u32, lower_is_better: bool) -> i64 {
    if pre == 0 {
        return 0;
    }
    let pre_i64 = i64::from(pre);
    let post_i64 = i64::from(post);
    let raw_delta = if lower_is_better {
        pre_i64 - post_i64
    } else {
        post_i64 - pre_i64
    };
    (raw_delta * 10_000) / pre_i64
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!(
        "{:x}",
        Sha256::digest([b"security_ops_hash_v1:" as &[u8], bytes].concat())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication_status() -> PublicationStatus {
        PublicationStatus {
            reviewed_by_featured_org: true,
            reviewed_at: Some("2026-02-21T10:00:00Z".to_string()),
            published_on_project_website: true,
            submitted_to_industry_publication: true,
            industry_publication_name: Some("SRE Journal".to_string()),
            publication_url: "https://franken-node.dev/case-studies/cs-001".to_string(),
        }
    }

    fn sample_case_study(case_study_id: &str, vuln_pre: u32, vuln_post: u32) -> CaseStudy {
        CaseStudy {
            case_study_id: case_study_id.to_string(),
            title: format!("Case Study {case_study_id}"),
            organization_type: "SaaS".to_string(),
            industry: "FinTech".to_string(),
            anonymized: true,
            migration_effort_days: 21,
            migration_timeline_days: 35,
            lessons_learned: vec!["Phased rollout reduced migration risk".to_string()],
            recommendations: vec!["Adopt strict policy profile before cutover".to_string()],
            key_metrics: KeyMetrics {
                pre_vulnerability_count: vuln_pre,
                post_vulnerability_count: vuln_post,
                pre_incident_containment_minutes: 120,
                post_incident_containment_minutes: 45,
                pre_deployments_per_week: 4,
                post_deployments_per_week: 9,
            },
            publication: publication_status(),
            content_hash: String::new(),
        }
    }

    #[test]
    fn default_registry_uses_schema_version() {
        let registry = SecurityOpsCaseStudyRegistry::default();
        assert_eq!(registry.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn vulnerability_reduction_is_positive_when_post_is_lower() {
        let metrics = KeyMetrics {
            pre_vulnerability_count: 20,
            post_vulnerability_count: 10,
            pre_incident_containment_minutes: 100,
            post_incident_containment_minutes: 50,
            pre_deployments_per_week: 2,
            post_deployments_per_week: 3,
        };
        assert_eq!(metrics.vulnerability_reduction_bps(), 5000);
    }

    #[test]
    fn deployment_improvement_uses_higher_is_better_direction() {
        let metrics = KeyMetrics {
            pre_vulnerability_count: 10,
            post_vulnerability_count: 5,
            pre_incident_containment_minutes: 100,
            post_incident_containment_minutes: 50,
            pre_deployments_per_week: 4,
            post_deployments_per_week: 10,
        };
        assert_eq!(metrics.deployment_frequency_improvement_bps(), 15000);
    }

    #[test]
    fn register_case_study_succeeds() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        let id = registry
            .register_case_study(sample_case_study("cs-001", 14, 6), "trace-1")
            .expect("registration should succeed");
        assert_eq!(id, "cs-001");
        assert_eq!(registry.case_studies.len(), 1);
    }

    #[test]
    fn duplicate_case_study_id_is_rejected() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-001", 14, 6), "trace-1")
            .expect("first registration should succeed");
        let err = registry
            .register_case_study(sample_case_study("cs-001", 15, 7), "trace-2")
            .expect_err("duplicate id should fail");
        assert!(err.contains("duplicate case_study_id"));
    }

    #[test]
    fn empty_identity_fields_are_rejected() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        let mut case_study = sample_case_study("cs-001", 14, 6);
        case_study.title = String::new();
        let err = registry
            .register_case_study(case_study, "trace-1")
            .expect_err("empty title should fail");
        assert!(err.contains("identity fields"));
    }

    #[test]
    fn missing_lessons_are_rejected() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        let mut case_study = sample_case_study("cs-001", 14, 6);
        case_study.lessons_learned.clear();
        let err = registry
            .register_case_study(case_study, "trace-1")
            .expect_err("missing lessons should fail");
        assert!(err.contains("lessons_learned"));
    }

    #[test]
    fn publication_url_must_be_https() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        let mut case_study = sample_case_study("cs-001", 14, 6);
        case_study.publication.publication_url = "http://example.com".to_string();
        let err = registry
            .register_case_study(case_study, "trace-1")
            .expect_err("non-https url should fail");
        assert!(err.contains("https://"));
    }

    #[test]
    fn external_submission_requires_channel_name() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        let mut case_study = sample_case_study("cs-001", 14, 6);
        case_study.publication.industry_publication_name = None;
        let err = registry
            .register_case_study(case_study, "trace-1")
            .expect_err("missing channel should fail");
        assert!(err.contains("industry_publication_name"));
    }

    #[test]
    fn review_requires_timestamp() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        let mut case_study = sample_case_study("cs-001", 14, 6);
        case_study.publication.reviewed_at = None;
        let err = registry
            .register_case_study(case_study, "trace-1")
            .expect_err("missing reviewed_at should fail");
        assert!(err.contains("reviewed_at"));
    }

    #[test]
    fn generated_summary_fails_when_thresholds_not_met() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-001", 14, 13), "trace-1")
            .expect("registration should succeed");
        let summary = registry.generate_summary("trace-summary");
        assert!(!summary.overall_verdict);
        assert!(!summary.unmet_criteria.is_empty());
    }

    #[test]
    fn generated_summary_passes_with_three_valid_studies() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-001", 20, 10), "trace-1")
            .expect("registration should succeed");
        registry
            .register_case_study(sample_case_study("cs-002", 16, 8), "trace-2")
            .expect("registration should succeed");
        registry
            .register_case_study(sample_case_study("cs-003", 18, 17), "trace-3")
            .expect("registration should succeed");

        let summary = registry.generate_summary("trace-summary");
        assert!(summary.overall_verdict);
        assert_eq!(summary.total_case_studies, 3);
        // All 3 case studies have measurable improvement (cs-003: 18→17 = 555 bps > 0).
        assert_eq!(summary.security_improvement_case_studies, 3);
        assert_eq!(summary.reviewed_case_studies, 3);
        assert_eq!(summary.website_published_case_studies, 3);
        assert_eq!(summary.industry_submissions, 3);
    }

    #[test]
    fn summary_requires_industry_submission() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        let mut cs1 = sample_case_study("cs-001", 20, 10);
        let mut cs2 = sample_case_study("cs-002", 20, 10);
        let mut cs3 = sample_case_study("cs-003", 20, 10);
        cs1.publication.submitted_to_industry_publication = false;
        cs2.publication.submitted_to_industry_publication = false;
        cs3.publication.submitted_to_industry_publication = false;

        registry
            .register_case_study(cs1, "trace-1")
            .expect("registration should succeed");
        registry
            .register_case_study(cs2, "trace-2")
            .expect("registration should succeed");
        registry
            .register_case_study(cs3, "trace-3")
            .expect("registration should succeed");

        let summary = registry.generate_summary("trace-summary");
        assert!(!summary.overall_verdict);
        assert!(
            summary
                .unmet_criteria
                .iter()
                .any(|item| item.contains("external industry submission"))
        );
    }

    #[test]
    fn export_registry_json_is_valid() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-001", 20, 10), "trace-1")
            .expect("registration should succeed");
        let json = registry
            .export_registry_json()
            .expect("json export should succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("exported json should parse");
        assert!(parsed.is_array());
    }

    #[test]
    fn export_registry_json_is_sorted_by_case_id() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-002", 20, 10), "trace-2")
            .expect("registration should succeed");
        registry
            .register_case_study(sample_case_study("cs-001", 20, 10), "trace-1")
            .expect("registration should succeed");
        let json = registry
            .export_registry_json()
            .expect("json export should succeed");
        let parsed: Vec<CaseStudy> =
            serde_json::from_str(&json).expect("exported json should parse into case studies");
        assert_eq!(parsed[0].case_study_id, "cs-001");
        assert_eq!(parsed[1].case_study_id, "cs-002");
    }

    #[test]
    fn audit_log_jsonl_lines_are_valid_json() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-001", 20, 10), "trace-1")
            .expect("registration should succeed");
        let jsonl = registry.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        for line in jsonl.lines() {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("line should be valid json");
        }
    }

    #[test]
    fn case_hash_is_stable_for_same_payload() {
        let mut case_study_a = sample_case_study("cs-001", 20, 10);
        let mut case_study_b = sample_case_study("cs-001", 20, 10);
        case_study_a
            .recompute_hash()
            .expect("hash computation should succeed");
        case_study_b
            .recompute_hash()
            .expect("hash computation should succeed");
        assert_eq!(case_study_a.content_hash, case_study_b.content_hash);
    }

    #[test]
    fn case_hash_changes_when_metrics_change() {
        let mut case_study_a = sample_case_study("cs-001", 20, 10);
        let mut case_study_b = sample_case_study("cs-001", 20, 9);
        case_study_a
            .recompute_hash()
            .expect("hash computation should succeed");
        case_study_b
            .recompute_hash()
            .expect("hash computation should succeed");
        assert_ne!(case_study_a.content_hash, case_study_b.content_hash);
    }

    #[test]
    fn security_improvement_detection_works() {
        let case_study = sample_case_study("cs-001", 20, 10);
        assert!(case_study.has_measurable_security_improvement());
    }

    #[test]
    fn no_security_improvement_detection_works() {
        let case_study = sample_case_study("cs-001", 20, 20);
        assert!(!case_study.has_measurable_security_improvement());
    }

    #[test]
    fn zero_baseline_metrics_do_not_panic() {
        let metrics = KeyMetrics {
            pre_vulnerability_count: 0,
            post_vulnerability_count: 0,
            pre_incident_containment_minutes: 0,
            post_incident_containment_minutes: 0,
            pre_deployments_per_week: 0,
            post_deployments_per_week: 0,
        };
        assert_eq!(metrics.vulnerability_reduction_bps(), 0);
        assert_eq!(metrics.incident_response_improvement_bps(), 0);
        assert_eq!(metrics.deployment_frequency_improvement_bps(), 0);
    }

    #[test]
    fn summary_content_hash_is_present() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-001", 20, 10), "trace-1")
            .expect("registration should succeed");
        registry
            .register_case_study(sample_case_study("cs-002", 20, 10), "trace-2")
            .expect("registration should succeed");
        registry
            .register_case_study(sample_case_study("cs-003", 20, 10), "trace-3")
            .expect("registration should succeed");
        let summary = registry.generate_summary("trace-summary");
        assert!(!summary.content_hash.is_empty());
    }

    #[test]
    fn gate_failure_event_is_logged_for_failed_summary() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-001", 20, 20), "trace-1")
            .expect("registration should succeed");
        registry.generate_summary("trace-summary");
        assert!(
            registry
                .audit_log
                .iter()
                .any(|record| record.event_code == event_codes::CSC_GATE_FAILED)
        );
    }

    #[test]
    fn gate_pass_event_is_logged_for_passing_summary() {
        let mut registry = SecurityOpsCaseStudyRegistry::new();
        registry
            .register_case_study(sample_case_study("cs-001", 20, 10), "trace-1")
            .expect("registration should succeed");
        registry
            .register_case_study(sample_case_study("cs-002", 20, 10), "trace-2")
            .expect("registration should succeed");
        registry
            .register_case_study(sample_case_study("cs-003", 20, 19), "trace-3")
            .expect("registration should succeed");
        registry.generate_summary("trace-summary");
        assert!(
            registry
                .audit_log
                .iter()
                .any(|record| record.event_code == event_codes::CSC_GATE_PASSED)
        );
    }
}
