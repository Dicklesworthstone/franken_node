//! Checked application: capture -> plan -> compare -> recheck -> install.
//!
//! The production entrypoint uses installed Node and the explicitly selected
//! native product. Tests name Node on both sides, never a fake native runtime.
//! Validation is scoped to captured tests and persistent workspace changes;
//! it is not release certification, a sandbox or a globally atomic transaction.

use super::rewrite_transaction::{Edit, RewriteTransaction};
use super::validation_suite::rewrite_candidate::{Replacement, RewriteCandidate};
use super::validation_suite::SuiteReport;
use super::{MigrationRewriteAction, MigrationRewriteReport, MigrationValidateReport, run_rewrite, run_validate};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckedRewriteStatus { Applied, Unchanged, Rejected, Error }

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckedRewriteReport {
    pub schema_version: String,
    pub project_path: String,
    pub status: CheckedRewriteStatus,
    pub release_certification: bool,
    pub static_validation: Option<MigrationValidateReport>,
    pub rewrite: Option<MigrationRewriteReport>,
    pub validation: Option<SuiteReport>,
    pub errors: Vec<String>,
}

impl CheckedRewriteReport {
    pub fn is_success(&self) -> bool {
        matches!(self.status, CheckedRewriteStatus::Applied | CheckedRewriteStatus::Unchanged)
    }
}

/// Execute only after the caller has approved both project execution and apply.
/// Opening the writer may recover a previously interrupted installation first.
/// A rejected new plan never reaches installation. Reports contain the existing
/// planner's source preimages; treat exported JSON as sensitive project data.
pub fn run(project: &Path, native_executable: &Path) -> CheckedRewriteReport {
    run_with_validator(project, |candidate| candidate.validate_native(native_executable))
}

fn run_with_validator(project: &Path,
    validate: impl FnOnce(&RewriteCandidate) -> Result<SuiteReport>) -> CheckedRewriteReport {
    let mut report = CheckedRewriteReport {
        schema_version: "franken-node/checked-rewrite/v1".into(),
        project_path: project.to_string_lossy().into_owned(), status: CheckedRewriteStatus::Error,
        release_certification: false, static_validation: None, rewrite: None, validation: None, errors: Vec::new(),
    };
    let operation = (|| -> Result<()> {
        let project = project.canonicalize()?;
        report.project_path = project.to_string_lossy().into_owned();
        // Own recovery/planning/validation/commit as one cooperative operation.
        // The lock is not inherited by the runtime processes (CLOEXEC).
        let transaction = RewriteTransaction::open(&project)?;
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut candidate = RewriteCandidate::capture(&project, deadline)?;
        let temporary = tempfile::Builder::new().prefix("franken-checked-rewrite-").tempdir()?;
        let staged = temporary.path().join("project");
        candidate.stage_original(&staged)?;
        let mut prerequisites = run_validate(&staged, true)?;
        prerequisites.project_path.clone_from(&report.project_path);
        let prerequisites_passed = prerequisites.is_pass();
        report.static_validation = Some(prerequisites);
        if !prerequisites_passed {
            report.status = CheckedRewriteStatus::Rejected;
            report.errors.push("static prerequisites failed; no runtime or new rewrite installation attempted".into());
            return Ok(());
        }
        let mut plan = run_rewrite(&staged, false)?;
        plan.project_path.clone_from(&report.project_path);
        let manual_review = plan.manual_review_items;
        report.rewrite = Some(plan);
        if manual_review != 0 {
            report.status = CheckedRewriteStatus::Rejected;
            report.errors.push(format!("{manual_review} unresolved manual review items; checked apply refused"));
            return Ok(());
        }
        let plan = report.rewrite.as_ref().expect("plan just stored");
        ensure!(plan.rewrites_planned == plan.rollback_entries.len(), "rewrite plan and preimage inventory disagree");
        let replacements: Vec<_> = plan.rollback_entries.iter().map(|edit| Replacement {
            path: &edit.path, before: edit.original_content.as_bytes(), after: edit.rewritten_content.as_bytes(),
        }).collect();
        candidate.prepare(&replacements)?;
        let validation = validate(&candidate)?;
        // Bind the live executor's evidence to BOTH captured trees and the
        // exact test inventory. Never authorize from a summary-only result or
        // trust empty divergence lists over unequal process/workspace evidence.
        let admission = candidate.check_validation(&validation);
        let infrastructure_error = validation.verdict == "ERROR";
        report.validation = Some(validation);
        if let Err(error) = admission {
            report.status = if infrastructure_error { CheckedRewriteStatus::Error } else { CheckedRewriteStatus::Rejected };
            report.errors.push(format!("candidate did not pass complete process and filesystem comparison; new rewrites not installed: {error:#}"));
            return Ok(());
        }
        // Include unchanged dependencies/configuration in this check, not only
        // the edit preimages rechecked by the transaction writer itself.
        candidate.ensure_source_unchanged()?;
        let plan = report.rewrite.as_mut().expect("plan retained through validation");
        let edits: Vec<_> = plan.rollback_entries.iter().map(|entry| Edit {
            path: &entry.path, before: entry.original_content.as_bytes(), after: entry.rewritten_content.as_bytes(),
        }).collect();
        transaction.apply(&edits)?;
        plan.apply_mode = true;
        plan.rewrites_applied = plan.rewrites_planned;
        for entry in &mut plan.entries {
            entry.applied = matches!(entry.action, MigrationRewriteAction::PinNodeEngine
                | MigrationRewriteAction::RewritePackageScript | MigrationRewriteAction::RewriteCommonJsRequire
                | MigrationRewriteAction::RewriteEsmImport);
        }
        report.status = if plan.rewrites_applied == 0 { CheckedRewriteStatus::Unchanged }
            else { CheckedRewriteStatus::Applied };
        Ok(())
    })();
    if let Err(error) = operation {
        report.status = CheckedRewriteStatus::Error;
        report.errors.push(format!("{error:#}"));
    }
    report
}

pub fn render(report: &CheckedRewriteReport) -> String {
    let mut text = format!("franken-node migrate rewrite --apply --verify\ntarget: {}\nstatus: {:?}\n",
        report.project_path, report.status);
    if let Some(plan) = &report.rewrite {
        let _ = writeln!(text, "rewrites_planned={} rewrites_applied={} manual_review_items={}",
            plan.rewrites_planned, plan.rewrites_applied, plan.manual_review_items);
    }
    if let Some(validation) = &report.validation {
        let _ = writeln!(text, "validation={} tests={} passed={} failed={} errored={} skipped={}",
            validation.verdict, validation.total_tests, validation.passed, validation.failed,
            validation.errored, validation.skipped);
    }
    for error in &report.errors { let _ = writeln!(text, "{error}"); }
    let _ = writeln!(text, "Captured-test validation only; release_certification=false.");
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn project() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("package.json"), r#"{"name":"checked","type":"module","engines":{"node":">=20"}}"#).unwrap();
        fs::write(root.path().join("package-lock.json"), "{}\n").unwrap();
        fs::write(root.path().join("helper.mjs"), "import { basename } from \"path\";\nexport const value = basename('/tmp/42');\n").unwrap();
        fs::write(root.path().join("case.test.mjs"), "import { value } from './helper.mjs';\nconsole.log(value);\n").unwrap();
        root
    }
    fn node_pair(project: &Path) -> CheckedRewriteReport {
        run_with_validator(project, RewriteCandidate::validate_node_pair)
    }
    fn source(root: &Path) -> String { fs::read_to_string(root.join("helper.mjs")).unwrap() }

    #[test]
    fn measured_equivalent_rewrite_is_installed_with_original_backup_and_mode() {
        let root = project();
        let original = source(root.path());
        fs::set_permissions(root.path().join("helper.mjs"), fs::Permissions::from_mode(0o755)).unwrap();
        let report = node_pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Applied, "{report:#?}");
        assert!(source(root.path()).contains("from \"node:path\""));
        assert_eq!(fs::read_to_string(root.path().join(".migrate-backup/helper.mjs")).unwrap(), original);
        assert_eq!(fs::metadata(root.path().join("helper.mjs")).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 1);
        assert_eq!(report.validation.as_ref().unwrap().passed, 1);
        assert!(report.validation.as_ref().unwrap().filesystem_comparison);
        assert!(!report.release_certification);
    }

    #[test]
    fn generated_esm_in_cjs_is_rejected_without_installing_a_broken_file() {
        let root = project();
        let code = "const path = require('path');\nconsole.log(path.sep);\n";
        fs::write(root.path().join("broken.test.cjs"), code).unwrap();
        let original = source(root.path());
        let report = node_pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
        assert_eq!(source(root.path()), original);
        assert_eq!(fs::read_to_string(root.path().join("broken.test.cjs")).unwrap(), code);
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
        let row = &report.validation.as_ref().unwrap().cases[0];
        assert_eq!(row.reference.as_ref().unwrap().exit_code, Some(0));
        assert_ne!(row.native.as_ref().unwrap().exit_code, Some(0));
        assert!(!root.path().join(".migrate-backup/helper.mjs").exists());
    }

    #[test]
    fn identical_console_output_with_different_file_effects_cannot_be_applied() {
        let root = project();
        let original = source(root.path());
        fs::write(root.path().join("case.test.mjs"),
            "import fs from 'node:fs';\nconst text = fs.readFileSync('helper.mjs','utf8');\nfs.writeFileSync('artifact',text.includes('node:path')?'changed':'original');\n").unwrap();
        let report = node_pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
        let row = &report.validation.as_ref().unwrap().cases[0];
        assert_eq!(row.reference.as_ref().unwrap().exit_code, Some(0));
        assert_eq!(row.native.as_ref().unwrap().exit_code, Some(0));
        assert_eq!(row.reference.as_ref().unwrap().stdout, row.native.as_ref().unwrap().stdout);
        assert_eq!(row.divergences, ["filesystem:workspace_delta_mismatch"]);
        assert_eq!(source(root.path()), original);
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
        assert!(!root.path().join("artifact").exists());
    }

    #[test]
    fn unresolved_manual_review_blocks_runtime_execution() {
        let root = project();
        fs::write(root.path().join("manual.cjs"), "const name = 'path';\nconst value = require(name);\n").unwrap();
        let report = run_with_validator(root.path(), |_| panic!("review must precede runtime dispatch"));
        assert_eq!(report.status, CheckedRewriteStatus::Rejected);
        assert!(report.validation.is_none());
        assert!(report.rewrite.as_ref().unwrap().manual_review_items > 0);
    }

    #[test]
    fn risky_static_prerequisites_block_runtime_execution() {
        let root = project();
        fs::write(root.path().join("package.json"), r#"{"name":"blocked","scripts":{"postinstall":"echo blocked"}}"#).unwrap();
        let report = run_with_validator(root.path(), |_| panic!("static failure must not execute"));
        assert_eq!(report.status, CheckedRewriteStatus::Rejected);
        assert!(report.rewrite.is_none());
        assert!(report.validation.is_none());
    }

    #[test]
    fn missing_native_runtime_does_not_apply_the_candidate() {
        let root = project();
        let original = source(root.path());
        let report = run(root.path(), &root.path().join("absent-runtime"));
        assert_eq!(report.status, CheckedRewriteStatus::Error);
        assert_eq!(source(root.path()), original);
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
    }

    #[test]
    fn late_dependency_drift_blocks_a_previously_passing_candidate() {
        let root = project();
        fs::write(root.path().join("support.json"), "{}").unwrap();
        let original = source(root.path());
        let report = run_with_validator(root.path(), |candidate| {
            let measured = candidate.validate_node_pair()?;
            fs::write(root.path().join("support.json"), "{\"changed\":true}")?;
            Ok(measured)
        });
        assert_eq!(report.status, CheckedRewriteStatus::Error, "{report:#?}");
        assert_eq!(report.validation.as_ref().unwrap().verdict, "PASS");
        assert!(report.errors[0].contains("project changed"));
        assert_eq!(source(root.path()), original);
        assert_eq!(fs::read_to_string(root.path().join("support.json")).unwrap(), "{\"changed\":true}");
    }

    #[test]
    fn backup_conflict_after_validation_cannot_install_any_file() {
        let root = project();
        let original = source(root.path());
        fs::create_dir(root.path().join(".migrate-backup")).unwrap();
        fs::write(root.path().join(".migrate-backup/helper.mjs"), "previous unrelated backup").unwrap();
        let report = node_pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Error, "{report:#?}");
        assert_eq!(report.validation.as_ref().unwrap().verdict, "PASS");
        assert_eq!(source(root.path()), original);
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
        assert!(report.errors[0].contains("backup conflict"));
    }

    #[test]
    fn writer_lock_is_held_across_real_validation() {
        let root = project();
        let report = run_with_validator(root.path(), |candidate| {
            assert!(RewriteTransaction::open(root.path()).is_err());
            candidate.validate_node_pair()
        });
        assert!(report.is_success(), "{report:#?}");
        assert!(RewriteTransaction::open(root.path()).is_ok());
    }

    #[test]
    fn unchanged_plan_still_requires_a_complete_passing_measurement() {
        let root = project();
        let first = node_pair(root.path());
        assert_eq!(first.status, CheckedRewriteStatus::Applied, "{first:#?}");
        let second = node_pair(root.path());
        assert_eq!(second.status, CheckedRewriteStatus::Unchanged, "{second:#?}");
        assert_eq!(second.validation.as_ref().unwrap().passed, 1);
        assert_eq!(second.rewrite.as_ref().unwrap().rewrites_applied, 0);
    }

    #[test]
    fn matching_reference_and_candidate_failures_never_authorize_apply() {
        let root = project();
        fs::write(root.path().join("case.test.mjs"), "throw new Error('reference failure');\n").unwrap();
        let original = source(root.path());
        let report = node_pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Rejected);
        assert_eq!(source(root.path()), original);
        assert_eq!(report.validation.as_ref().unwrap().failed, 1);
    }

    #[test]
    fn empty_project_does_not_turn_into_a_smoke_approval() {
        let root = tempfile::tempdir().unwrap();
        let report = run_with_validator(root.path(), |_| panic!("empty suite must not execute"));
        assert_eq!(report.status, CheckedRewriteStatus::Error);
        assert!(report.errors[0].contains("nonempty test inventory"));
    }

    #[test]
    fn json_and_text_keep_rejected_measurements_without_claiming_apply() {
        let root = project();
        fs::write(root.path().join("case.test.mjs"), "throw new Error('fails');\n").unwrap();
        let report = node_pair(root.path());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["status"], "REJECTED");
        assert_eq!(json["rewrite"]["apply_mode"], false);
        assert_eq!(json["rewrite"]["rewrites_applied"], 0);
        assert_eq!(json["validation"]["total_tests"], 1);
        assert!(render(&report).contains("rewrites_applied=0"));
        let decoded: CheckedRewriteReport = serde_json::from_value(json).unwrap();
        assert!(!decoded.is_success());
    }

    #[test]
    fn inconsistent_passing_evidence_never_reaches_installation() {
        for mutate in [
            (|r: &mut SuiteReport| r.candidate_input_sha256.push('0')) as fn(&mut SuiteReport),
            |r| r.cases[0].test = "unmeasured.test.mjs".into(),
            |r| r.cases[0].native.as_mut().unwrap().stdout.sha256.push('0'),
            |r| r.cases[0].native.as_mut().unwrap().workspace_delta.as_mut().unwrap().sha256.push('0'),
            |r| r.filesystem_exclusions.push("**/*".into()),
        ] {
            let root = project();
            let original = source(root.path());
            let report = run_with_validator(root.path(), |candidate| {
                let mut measured = candidate.validate_node_pair()?;
                assert_eq!(measured.verdict, "PASS");
                mutate(&mut measured);
                Ok(measured)
            });
            assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
            assert_eq!(source(root.path()), original);
            assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
            assert!(!report.rewrite.as_ref().unwrap().apply_mode);
            assert!(!root.path().join(".migrate-backup/helper.mjs").exists());
            assert_eq!(report.validation.as_ref().unwrap().verdict, "PASS");
            assert!(report.errors[0].contains("new rewrites not installed"));
        }
    }
}
