//! bd-sxt5: Deterministic migration validation on representative project cohorts (Section 15).
//!
//! Validates migration determinism across representative Node/Bun project
//! cohorts. Tracks cohort definitions, validation runs, and reproducibility
//! metrics to ensure migration outcomes are predictable.
//!
//! # Capabilities
//!
//! - Project cohort management (5 cohort categories)
//! - Deterministic validation run tracking
//! - Reproducibility metric computation
//! - Drift detection across repeated runs
//! - Cohort coverage analysis
//! - Validation versioning and audit trail
//!
//! # Invariants
//!
//! - **INV-MVC-COHORTED**: Every project belongs to a named cohort.
//! - **INV-MVC-DETERMINISTIC**: Repeated runs produce identical outcomes.
//! - **INV-MVC-REPRODUCIBLE**: Validation results include reproduction steps.
//! - **INV-MVC-GATED**: Cohorts below determinism threshold are flagged.
//! - **INV-MVC-VERSIONED**: Schema version embedded in every export.
//! - **INV-MVC-AUDITABLE**: Every mutation produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod event_codes {
    pub const MVC_COHORT_CREATED: &str = "MVC-001";
    pub const MVC_PROJECT_ADDED: &str = "MVC-002";
    pub const MVC_RUN_STARTED: &str = "MVC-003";
    pub const MVC_RUN_COMPLETED: &str = "MVC-004";
    pub const MVC_DETERMINISM_CHECKED: &str = "MVC-005";
    pub const MVC_DRIFT_DETECTED: &str = "MVC-006";
    pub const MVC_COVERAGE_COMPUTED: &str = "MVC-007";
    pub const MVC_REPORT_GENERATED: &str = "MVC-008";
    pub const MVC_VERSION_EMBEDDED: &str = "MVC-009";
    pub const MVC_CATALOG_GENERATED: &str = "MVC-010";
    pub const MVC_ERR_NONDETERMINISM: &str = "MVC-ERR-001";
    pub const MVC_ERR_INVALID_COHORT: &str = "MVC-ERR-002";
}

pub mod invariants {
    pub const INV_MVC_COHORTED: &str = "INV-MVC-COHORTED";
    pub const INV_MVC_DETERMINISTIC: &str = "INV-MVC-DETERMINISTIC";
    pub const INV_MVC_REPRODUCIBLE: &str = "INV-MVC-REPRODUCIBLE";
    pub const INV_MVC_GATED: &str = "INV-MVC-GATED";
    pub const INV_MVC_VERSIONED: &str = "INV-MVC-VERSIONED";
    pub const INV_MVC_AUDITABLE: &str = "INV-MVC-AUDITABLE";
}

pub const SCHEMA_VERSION: &str = "mvc-v1.0";
pub const MIN_DETERMINISM_RATE: f64 = 0.99;

/// Cohort category for project grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortCategory {
    NodeMinimal,
    NodeComplex,
    BunMinimal,
    BunComplex,
    Polyglot,
}

impl CohortCategory {
    pub fn all() -> &'static [CohortCategory] {
        &[
            Self::NodeMinimal,
            Self::NodeComplex,
            Self::BunMinimal,
            Self::BunComplex,
            Self::Polyglot,
        ]
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::NodeMinimal => "node_minimal",
            Self::NodeComplex => "node_complex",
            Self::BunMinimal => "bun_minimal",
            Self::BunComplex => "bun_complex",
            Self::Polyglot => "polyglot",
        }
    }
}

/// A project cohort definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectCohort {
    pub cohort_id: String,
    pub category: CohortCategory,
    pub name: String,
    pub project_ids: Vec<String>,
    pub created_at: String,
}

/// A single validation run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationRun {
    pub run_id: String,
    pub cohort_id: String,
    pub outcome_hash: String,
    pub deterministic: bool,
    pub reproduction_command: String,
    pub started_at: String,
    pub completed_at: Option<String>,
}

/// Cohort validation report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortReport {
    pub report_id: String,
    pub timestamp: String,
    pub schema_version: String,
    pub total_cohorts: usize,
    pub total_runs: usize,
    pub determinism_rate: f64,
    pub meets_threshold: bool,
    pub flagged_cohorts: Vec<String>,
    pub coverage_by_category: BTreeMap<String, usize>,
    pub content_hash: String,
}

/// Audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MvcAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

/// Migration validation cohorts engine.
#[derive(Debug, Clone)]
pub struct MigrationValidationCohorts {
    schema_version: String,
    cohorts: BTreeMap<String, ProjectCohort>,
    runs: Vec<ValidationRun>,
    audit_log: Vec<MvcAuditRecord>,
}

impl Default for MigrationValidationCohorts {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            cohorts: BTreeMap::new(),
            runs: Vec::new(),
            audit_log: Vec::new(),
        }
    }
}

impl MigrationValidationCohorts {
    pub fn create_cohort(
        &mut self,
        mut cohort: ProjectCohort,
        trace_id: &str,
    ) -> Result<String, String> {
        if cohort.name.is_empty() {
            self.log(
                event_codes::MVC_ERR_INVALID_COHORT,
                trace_id,
                serde_json::json!({"reason": "empty name"}),
            );
            return Err("cohort name must not be empty".to_string());
        }
        cohort.created_at = Utc::now().to_rfc3339();
        let cid = cohort.cohort_id.clone();
        self.log(
            event_codes::MVC_COHORT_CREATED,
            trace_id,
            serde_json::json!({"cohort_id": &cid, "category": cohort.category.label()}),
        );
        self.cohorts.insert(cid.clone(), cohort);
        Ok(cid)
    }

    pub fn add_project(
        &mut self,
        cohort_id: &str,
        project_id: &str,
        trace_id: &str,
    ) -> Result<(), String> {
        let cohort = self
            .cohorts
            .get_mut(cohort_id)
            .ok_or_else(|| format!("cohort not found: {cohort_id}"))?;
        cohort.project_ids.push(project_id.to_string());
        self.log(
            event_codes::MVC_PROJECT_ADDED,
            trace_id,
            serde_json::json!({"cohort_id": cohort_id, "project_id": project_id}),
        );
        Ok(())
    }

    pub fn start_run(
        &mut self,
        cohort_id: &str,
        reproduction_command: &str,
        trace_id: &str,
    ) -> Result<String, String> {
        if !self.cohorts.contains_key(cohort_id) {
            return Err(format!("cohort not found: {cohort_id}"));
        }
        let rid = Uuid::now_v7().to_string();
        let run = ValidationRun {
            run_id: rid.clone(),
            cohort_id: cohort_id.to_string(),
            outcome_hash: String::new(),
            deterministic: false,
            reproduction_command: reproduction_command.to_string(),
            started_at: Utc::now().to_rfc3339(),
            completed_at: None,
        };
        self.log(
            event_codes::MVC_RUN_STARTED,
            trace_id,
            serde_json::json!({"run_id": &rid, "cohort_id": cohort_id}),
        );
        self.runs.push(run);
        Ok(rid)
    }

    pub fn complete_run(
        &mut self,
        run_id: &str,
        outcome_hash: &str,
        trace_id: &str,
    ) -> Result<(), String> {
        let run = self
            .runs
            .iter_mut()
            .find(|r| r.run_id == run_id)
            .ok_or_else(|| format!("run not found: {run_id}"))?;
        run.outcome_hash = outcome_hash.to_string();
        run.completed_at = Some(Utc::now().to_rfc3339());

        // Check determinism against prior runs of same cohort
        let cohort_id = run.cohort_id.clone();
        let prior_hashes: Vec<&str> = self
            .runs
            .iter()
            .filter(|r| r.cohort_id == cohort_id && r.run_id != run_id && r.completed_at.is_some())
            .map(|r| r.outcome_hash.as_str())
            .collect();

        let det = prior_hashes.is_empty() || prior_hashes.iter().all(|h| *h == outcome_hash);
        let run = self.runs.iter_mut().find(|r| r.run_id == run_id).unwrap();
        run.deterministic = det;

        self.log(
            event_codes::MVC_RUN_COMPLETED,
            trace_id,
            serde_json::json!({"run_id": run_id, "deterministic": det}),
        );
        self.log(
            event_codes::MVC_DETERMINISM_CHECKED,
            trace_id,
            serde_json::json!({"cohort_id": &cohort_id, "hash": outcome_hash}),
        );

        if !det {
            self.log(
                event_codes::MVC_ERR_NONDETERMINISM,
                trace_id,
                serde_json::json!({"cohort_id": &cohort_id}),
            );
            self.log(
                event_codes::MVC_DRIFT_DETECTED,
                trace_id,
                serde_json::json!({"run_id": run_id}),
            );
        }
        Ok(())
    }

    pub fn generate_report(&mut self, trace_id: &str) -> CohortReport {
        let total_cohorts = self.cohorts.len();
        let completed_runs: Vec<&ValidationRun> = self
            .runs
            .iter()
            .filter(|r| r.completed_at.is_some())
            .collect();
        let total_runs = completed_runs.len();
        let deterministic_runs = completed_runs.iter().filter(|r| r.deterministic).count();
        let determinism_rate = if total_runs > 0 {
            deterministic_runs as f64 / total_runs as f64
        } else {
            1.0
        };
        let meets = determinism_rate >= MIN_DETERMINISM_RATE;

        let mut flagged = Vec::new();
        for cid in self.cohorts.keys() {
            let cohort_runs: Vec<&&ValidationRun> = completed_runs
                .iter()
                .filter(|r| &r.cohort_id == cid)
                .collect();
            if !cohort_runs.is_empty() && cohort_runs.iter().any(|r| !r.deterministic) {
                flagged.push(cid.clone());
            }
        }

        let mut coverage: BTreeMap<String, usize> = BTreeMap::new();
        for c in self.cohorts.values() {
            *coverage.entry(c.category.label().to_string()).or_default() += 1;
        }

        let hash_input = format!(
            "{total_cohorts}:{total_runs}:{determinism_rate}:{}",
            &self.schema_version
        );
        let content_hash = hex::encode(Sha256::digest(
            [
                b"migration_validation_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        self.log(
            event_codes::MVC_COVERAGE_COMPUTED,
            trace_id,
            serde_json::json!({"categories": coverage.len()}),
        );
        self.log(
            event_codes::MVC_REPORT_GENERATED,
            trace_id,
            serde_json::json!({"total_runs": total_runs}),
        );
        self.log(
            event_codes::MVC_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({"version": &self.schema_version}),
        );
        self.log(
            event_codes::MVC_CATALOG_GENERATED,
            trace_id,
            serde_json::json!({"cohorts": total_cohorts}),
        );

        CohortReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            schema_version: self.schema_version.clone(),
            total_cohorts,
            total_runs,
            determinism_rate,
            meets_threshold: meets,
            flagged_cohorts: flagged,
            coverage_by_category: coverage,
            content_hash,
        }
    }

    pub fn cohorts(&self) -> &BTreeMap<String, ProjectCohort> {
        &self.cohorts
    }
    pub fn runs(&self) -> &[ValidationRun] {
        &self.runs
    }
    pub fn audit_log(&self) -> &[MvcAuditRecord] {
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
        self.audit_log.push(MvcAuditRecord {
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

    fn sample_cohort(id: &str, cat: CohortCategory) -> ProjectCohort {
        ProjectCohort {
            cohort_id: id.to_string(),
            category: cat,
            name: format!("Cohort {id}"),
            project_ids: vec![],
            created_at: String::new(),
        }
    }

    #[test]
    fn five_categories() {
        assert_eq!(CohortCategory::all().len(), 5);
    }
    #[test]
    fn category_labels_nonempty() {
        for c in CohortCategory::all() {
            assert!(!c.label().is_empty());
        }
    }

    #[test]
    fn create_cohort_ok() {
        let mut e = MigrationValidationCohorts::default();
        assert!(
            e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
                .is_ok()
        );
        assert_eq!(e.cohorts().len(), 1);
    }

    #[test]
    fn create_empty_name_fails() {
        let mut e = MigrationValidationCohorts::default();
        let mut c = sample_cohort("c1", CohortCategory::NodeMinimal);
        c.name.clear();
        assert!(e.create_cohort(c, &trace()).is_err());
    }

    #[test]
    fn create_sets_timestamp() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        assert!(!e.cohorts()["c1"].created_at.is_empty());
    }

    #[test]
    fn add_project_ok() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        e.add_project("c1", "proj-1", &trace()).unwrap();
        assert_eq!(e.cohorts()["c1"].project_ids.len(), 1);
    }

    #[test]
    fn add_project_missing_cohort() {
        let mut e = MigrationValidationCohorts::default();
        assert!(e.add_project("missing", "proj-1", &trace()).is_err());
    }

    #[test]
    fn start_run_ok() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        assert!(e.start_run("c1", "make validate", &trace()).is_ok());
    }

    #[test]
    fn start_run_missing_cohort() {
        let mut e = MigrationValidationCohorts::default();
        assert!(e.start_run("missing", "cmd", &trace()).is_err());
    }

    #[test]
    fn complete_run_first_is_deterministic() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        let rid = e.start_run("c1", "cmd", &trace()).unwrap();
        e.complete_run(&rid, "hash-abc", &trace()).unwrap();
        assert!(e.runs()[0].deterministic);
    }

    #[test]
    fn complete_run_matching_hashes_deterministic() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        let r1 = e.start_run("c1", "cmd", &trace()).unwrap();
        e.complete_run(&r1, "hash-abc", &trace()).unwrap();
        let r2 = e.start_run("c1", "cmd", &trace()).unwrap();
        e.complete_run(&r2, "hash-abc", &trace()).unwrap();
        assert!(e.runs()[1].deterministic);
    }

    #[test]
    fn complete_run_mismatched_hashes_nondeterministic() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        let r1 = e.start_run("c1", "cmd", &trace()).unwrap();
        e.complete_run(&r1, "hash-abc", &trace()).unwrap();
        let r2 = e.start_run("c1", "cmd", &trace()).unwrap();
        e.complete_run(&r2, "hash-xyz", &trace()).unwrap();
        assert!(!e.runs()[1].deterministic);
    }

    #[test]
    fn report_empty() {
        let mut e = MigrationValidationCohorts::default();
        let r = e.generate_report(&trace());
        assert_eq!(r.total_cohorts, 0);
        assert!(r.meets_threshold);
    }

    #[test]
    fn report_determinism_rate() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        let r1 = e.start_run("c1", "cmd", &trace()).unwrap();
        e.complete_run(&r1, "h1", &trace()).unwrap();
        let report = e.generate_report(&trace());
        assert!((report.determinism_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn report_flags_nondeterministic() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        let r1 = e.start_run("c1", "cmd", &trace()).unwrap();
        e.complete_run(&r1, "h1", &trace()).unwrap();
        let r2 = e.start_run("c1", "cmd", &trace()).unwrap();
        e.complete_run(&r2, "h2", &trace()).unwrap();
        let report = e.generate_report(&trace());
        assert!(report.flagged_cohorts.contains(&"c1".to_string()));
    }

    #[test]
    fn report_coverage_by_category() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        e.create_cohort(sample_cohort("c2", CohortCategory::BunComplex), &trace())
            .unwrap();
        let r = e.generate_report(&trace());
        assert_eq!(r.coverage_by_category.len(), 2);
    }

    #[test]
    fn report_hash_deterministic() {
        let mut e1 = MigrationValidationCohorts::default();
        let mut e2 = MigrationValidationCohorts::default();
        assert_eq!(
            e1.generate_report(&trace()).content_hash,
            e2.generate_report(&trace()).content_hash
        );
    }

    #[test]
    fn audit_populated() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        assert!(!e.audit_log().is_empty());
    }

    #[test]
    fn audit_has_codes() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        let codes: Vec<&str> = e
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::MVC_COHORT_CREATED));
    }

    #[test]
    fn export_jsonl() {
        let mut e = MigrationValidationCohorts::default();
        e.create_cohort(sample_cohort("c1", CohortCategory::NodeMinimal), &trace())
            .unwrap();
        let jsonl = e.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn default_version() {
        let e = MigrationValidationCohorts::default();
        assert_eq!(e.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn complete_run_missing_fails() {
        let mut e = MigrationValidationCohorts::default();
        assert!(e.complete_run("missing", "hash", &trace()).is_err());
    }
}
