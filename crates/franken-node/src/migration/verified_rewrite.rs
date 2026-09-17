//! Checked application: capture -> plan -> compare -> recheck -> install.
//!
//! The production entrypoint uses installed Node and the explicitly selected
//! native product, optionally requiring agreement with an explicit Bun runtime.
//! Validation is scoped to captured tests and persistent workspace changes;
//! it is not release certification, a sandbox or a globally atomic transaction.

use super::rewrite_transaction::{Edit, RewriteTransaction};
use super::validation_suite::rewrite_candidate::{Replacement, RewriteCandidate};
use super::validation_suite::{SuiteReport, product_oracle::ProductReport};
use super::{MigrationRewriteAction, MigrationRewriteReport, MigrationValidateReport, run_rewrite, run_validate};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Explicit primary-command opt-in. An invalid selection must not fall back to
/// the two-runtime checker. This is operator configuration, not project metadata.
pub const BUN_ENV: &str = "FRANKEN_NODE_CHECKED_REWRITE_BUN_BIN";

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
    /// Two-runtime measurements only. Never a projection of three-runtime data.
    pub validation: Option<SuiteReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_validation: Option<ProductReport>,
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
    let bun = std::env::var_os(BUN_ENV).map(PathBuf::from);
    let archive_requested = std::env::var_os(
        super::validation_suite::native_replay::failure_capture::DIRECTORY_ENV).is_some();
    run_selected(project, native_executable, bun.as_deref(), archive_requested)
}

/// Explicit library entrypoint, independent of primary-command environment
/// selection. Both reference runtimes must agree before any new installation.
/// No capsule is requested by this API. The complete measurement is retained
/// in product_validation; the primary entrypoint additionally supports opt-in
/// three-runtime failure retention through FRANKEN_NODE_MIGRATION_FAILURE_DIR.
pub fn run_product(project: &Path, native_executable: &Path, bun_executable: &Path) -> CheckedRewriteReport {
    run_selected(project, native_executable, Some(bun_executable), false)
}

fn run_selected(project: &Path, native_executable: &Path, bun: Option<&Path>,
    archive_requested: bool) -> CheckedRewriteReport {
    run_with_evidence(project, |candidate| {
        if let Some(bun) = bun {
            ensure!(bun.is_absolute(), "{BUN_ENV} requires an absolute trusted Bun executable path");
            let measured = if archive_requested {
                candidate.validate_product_retaining_failures(native_executable, bun)
            } else { candidate.validate_product(native_executable, bun) };
            measured.map(|report| ValidationEvidence::Product(Box::new(report)))
        } else {
            candidate.validate_native(native_executable)
                .map(|report| ValidationEvidence::Pair(Box::new(report)))
        }
    })
}

enum ValidationEvidence {
    Pair(Box<SuiteReport>),
    Product(Box<ProductReport>),
}

#[cfg(test)]
fn run_with_validator(project: &Path,
    validate: impl FnOnce(&RewriteCandidate) -> Result<SuiteReport>) -> CheckedRewriteReport {
    run_with_evidence(project, |candidate| validate(candidate)
        .map(|report| ValidationEvidence::Pair(Box::new(report))))
}

fn run_with_evidence(project: &Path,
    validate: impl FnOnce(&RewriteCandidate) -> Result<ValidationEvidence>) -> CheckedRewriteReport {
    let mut report = CheckedRewriteReport {
        schema_version: "franken-node/checked-rewrite/v1".into(),
        project_path: project.to_string_lossy().into_owned(), status: CheckedRewriteStatus::Error,
        release_certification: false, static_validation: None, rewrite: None, validation: None,
        product_validation: None, errors: Vec::new(),
    };
    let operation = (|| -> Result<()> {
        let project = project.canonicalize()?;
        report.project_path = project.to_string_lossy().into_owned();
        // Own recovery/planning/validation/commit as one cooperative operation.
        // The lock is not inherited by the runtime processes (CLOEXEC).
        let transaction = RewriteTransaction::open(&project)?;
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut candidate = RewriteCandidate::capture(&project, deadline)?;
        // This contains the complete captured source tree, even before any
        // runtime runs. Privacy cannot depend on a permissive caller umask.
        let temporary = tempfile::Builder::new().prefix("franken-checked-rewrite-")
            .permissions(std::fs::Permissions::from_mode(0o700)).tempdir()?;
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
        // The selected executor runs ONCE against these captured inputs. Keep
        // its evidence in its original schema and use the corresponding full
        // admission check. Never rerun a pair or drop Bun to rescue a failure.
        let (admission, infrastructure_error) = match validate(&candidate)? {
            ValidationEvidence::Pair(validation) => {
                let admission = candidate.check_validation(&validation);
                let infrastructure_error = validation.verdict == "ERROR";
                report.validation = Some(*validation);
                (admission, infrastructure_error)
            }
            ValidationEvidence::Product(validation) => {
                let admission = candidate.check_product_validation(&validation);
                let infrastructure_error = validation.verdict == "ERROR";
                report.product_validation = Some(*validation);
                (admission, infrastructure_error)
            }
        };
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
    if let Some(validation) = &report.product_validation {
        let _ = writeln!(text, "product_validation={} oracle={} tests={} passed={} failed={} errored={} skipped={}",
            validation.verdict, validation.oracle, validation.total_tests, validation.passed,
            validation.failed, validation.errored, validation.skipped);
        if let Some(capture) = &validation.failure_capture {
            let _ = writeln!(text, "product_failure_capture={capture:?}");
        }
    }
    for error in &report.errors { let _ = writeln!(text, "{error}"); }
    let _ = writeln!(text, "Captured-test validation only; release_certification=false.");
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        assert!(json.get("product_validation").is_none());
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

    fn runtime(name: &str) -> PathBuf {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|directory| directory.is_absolute()).map(|directory| directory.join(name))
            .find(|path| path.is_file()).unwrap_or_else(|| panic!("real {name} is required for checked product tests"))
            .canonicalize().unwrap()
    }

    fn product_measurement(candidate: &RewriteCandidate) -> Result<ValidationEvidence> {
        candidate.validate_node_bun_node(&runtime("bun"))
            .map(|report| ValidationEvidence::Product(Box::new(report)))
    }

    // Real Node/Bun/Node processes test the shared admission/installation path.
    // They do not claim successful native Franken execution. Negative public
    // entrypoint coverage below uses an explicitly failing native executable.
    #[test]
    fn product_equivalence_installs_once_with_full_evidence_backup_and_writer_lock() {
        let root = project();
        let outputs = tempfile::tempdir().unwrap();
        let marker = outputs.path().join("executions");
        fs::write(root.path().join("case.test.mjs"), format!(
            "import fs from 'node:fs';\nimport {{ value }} from './helper.mjs';\nfs.appendFileSync({}, (process.versions.bun ? 'bun' : 'node')+'\\n');\nconsole.log(value);\n",
            serde_json::to_string(&marker).unwrap())).unwrap();
        let original = source(root.path());
        fs::set_permissions(root.path().join("helper.mjs"), fs::Permissions::from_mode(0o755)).unwrap();
        let report = run_with_evidence(root.path(), |candidate| {
            assert!(RewriteTransaction::open(root.path()).is_err());
            product_measurement(candidate)
        });
        assert_eq!(report.status, CheckedRewriteStatus::Applied, "{report:#?}");
        assert_eq!(fs::read_to_string(marker).unwrap(), "node\nbun\nnode\n");
        assert!(report.validation.is_none());
        let measured = report.product_validation.as_ref().unwrap();
        assert_eq!(measured.verdict, "PASS");
        assert_eq!(measured.passed, 1);
        assert!(measured.distinct_reference_binaries && measured.filesystem_comparison);
        assert_ne!(measured.input_sha256, measured.candidate_input_sha256);
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 1);
        assert!(source(root.path()).contains("from \"node:path\""));
        assert_eq!(fs::read_to_string(root.path().join(".migrate-backup/helper.mjs")).unwrap(), original);
        assert_eq!(fs::metadata(root.path().join("helper.mjs")).unwrap().permissions().mode() & 0o777, 0o755);
        assert!(RewriteTransaction::open(root.path()).is_ok());
        assert!(render(&report).contains("product_validation=PASS oracle=L1-node-bun-franken-node"));
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["validation"].is_null());
        assert_eq!(json["product_validation"]["cases"][0]["bun"]["exit_code"], 0);
        let decoded: CheckedRewriteReport = serde_json::from_value(json).unwrap();
        assert!(decoded.is_success());
        assert!(!decoded.release_certification);
    }

    #[test]
    fn bun_output_or_filesystem_disagreement_cannot_be_rescued_by_node_native_agreement() {
        for code in [
            "console.log(process.versions.bun ? 'bun' : 'node');\n",
            "import fs from 'node:fs';\nfs.writeFileSync('artifact',process.versions.bun ? 'bun' : 'node');\nconsole.log('same');\n",
        ] {
            let root = project();
            fs::write(root.path().join("case.test.mjs"), code).unwrap();
            let original = source(root.path());
            let report = run_with_evidence(root.path(), product_measurement);
            assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
            assert!(report.validation.is_none());
            let measured = report.product_validation.as_ref().unwrap();
            assert_eq!(measured.verdict, "INCONCLUSIVE");
            assert_eq!(measured.reference_divergences, 1);
            assert_eq!(measured.cases[0].node, measured.cases[0].native);
            assert_ne!(measured.cases[0].node, measured.cases[0].bun);
            assert_eq!(source(root.path()), original);
            assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
            assert!(!root.path().join(".migrate-backup/helper.mjs").exists());
            assert!(!root.path().join("artifact").exists());
        }
    }

    #[test]
    fn inconsistent_product_pass_never_reaches_installation() {
        let root = project();
        fs::write(root.path().join("other.test.mjs"), "console.log(42);\n").unwrap();
        let original = source(root.path());
        let report = run_with_evidence(root.path(), |candidate| {
            let measured = candidate.validate_node_bun_node(&runtime("bun"))?;
            candidate.check_product_validation(&measured)?;
            for mutate in [
                (|r: &mut ProductReport| r.input_sha256.push('0')) as fn(&mut ProductReport),
                |r| r.candidate_input_sha256.push('0'),
                |r| r.schema_version = "unknown/v2".into(),
                |r| r.oracle = "node-native-only".into(),
                |r| r.scope = "stdout-only".into(),
                |r| r.filesystem_comparison = false,
                |r| r.filesystem_exclusions.push("**/*".into()),
                |r| r.distinct_reference_binaries = false,
                |r| r.bun_runtime.sha256.clone_from(&r.node_runtime.sha256),
                |r| r.release_certification = true,
                |r| r.skipped = 1,
                |r| r.failed = 1,
                |r| r.errored = 1,
                |r| r.reference_failures = 1,
                |r| r.reference_divergences = 1,
                |r| r.native_divergences = 1,
                |r| r.errors.push("identity recheck failed".into()),
                |r| { r.cases.pop(); r.total_tests -= 1; r.passed -= 1; },
                |r| r.cases[1] = r.cases[0].clone(),
                |r| r.cases[0].test = "unmeasured.test.mjs".into(),
                |r| r.cases[0].bun = None,
                |r| r.cases[0].bun.as_mut().unwrap().stdout.sha256 = "0".repeat(64),
                |r| r.cases[0].bun.as_mut().unwrap().stderr.bytes += 1,
                |r| r.cases[0].bun.as_mut().unwrap().workspace_delta = None,
                |r| r.cases[0].bun.as_mut().unwrap().workspace_delta.as_mut().unwrap().sha256 = "0".repeat(64),
                |r| r.cases[0].bun.as_mut().unwrap().exit_code = Some(7),
                |r| r.cases[0].node.as_mut().unwrap().signal = Some(9),
                |r| r.cases[0].native.as_mut().unwrap().stdout.bytes += 1,
                |r| r.cases[0].errors.push("incomplete".into()),
            ] {
                let mut changed = measured.clone();
                mutate(&mut changed);
                assert!(candidate.check_product_validation(&changed).is_err(), "{changed:#?}");
            }
            let mut changed = measured;
            changed.cases[0].bun.as_mut().unwrap().stdout.sha256 = "0".repeat(64);
            Ok(ValidationEvidence::Product(Box::new(changed)))
        });
        assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
        assert_eq!(report.product_validation.as_ref().unwrap().verdict, "PASS");
        assert!(report.validation.is_none());
        assert_eq!(source(root.path()), original);
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
        assert!(!root.path().join(".migrate-backup/helper.mjs").exists());
        assert!(report.errors[0].contains("unequal process or workspace"));
    }

    #[test]
    fn late_dependency_drift_blocks_a_complete_product_pass() {
        let root = project();
        fs::write(root.path().join("support.json"), "{}").unwrap();
        let original = source(root.path());
        let report = run_with_evidence(root.path(), |candidate| {
            let measured = product_measurement(candidate)?;
            fs::write(root.path().join("support.json"), "{\"changed\":true}")?;
            Ok(measured)
        });
        assert_eq!(report.status, CheckedRewriteStatus::Error, "{report:#?}");
        assert_eq!(report.product_validation.as_ref().unwrap().verdict, "PASS");
        assert!(report.errors[0].contains("project changed"));
        assert_eq!(source(root.path()), original);
        assert!(!root.path().join(".migrate-backup/helper.mjs").exists());
    }

    #[test]
    fn public_product_entrypoint_retains_native_failure_without_installing() {
        let root = project();
        let original = source(root.path());
        let report = run_product(root.path(), Path::new("/bin/false"), &runtime("bun"));
        assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
        let measured = report.product_validation.as_ref().unwrap();
        assert_eq!(measured.verdict, "FAIL");
        assert_eq!(measured.native_divergences, 1);
        assert_eq!(measured.cases[0].node.as_ref().unwrap().exit_code, Some(0));
        assert_eq!(measured.cases[0].bun.as_ref().unwrap().exit_code, Some(0));
        assert_eq!(measured.cases[0].native.as_ref().unwrap().exit_code, Some(1));
        assert!(report.validation.is_none());
        assert_eq!(source(root.path()), original);
        assert!(!root.path().join(".migrate-backup/helper.mjs").exists());
    }

    #[test]
    fn selected_missing_relative_or_aliased_bun_never_downgrades_to_two_runtimes() {
        let root = project();
        let original = source(root.path());
        for bun in [PathBuf::from("/absent/checked-bun"), PathBuf::from("relative-bun"), runtime("node")] {
            let report = run_selected(root.path(), Path::new("/bin/false"), Some(&bun), false);
            assert_eq!(report.status, CheckedRewriteStatus::Error, "{report:#?}");
            assert!(report.product_validation.is_none() && report.validation.is_none());
            assert_eq!(source(root.path()), original);
            assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
        }
        assert!(!root.path().join(".migrate-backup/helper.mjs").exists());
    }

    #[test]
    fn product_capture_selection_reaches_the_three_runtime_executor() {
        let root = project();
        let report = run_selected(root.path(), Path::new("/bin/false"), Some(&runtime("bun")), true);
        assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
        assert_eq!(report.product_validation.as_ref().unwrap().verdict, "FAIL");
        assert!(report.validation.is_none());
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
    }

    #[test]
    fn product_mode_keeps_static_and_manual_review_barriers_before_execution() {
        for manual in [false, true] {
            let root = project();
            if manual {
                fs::write(root.path().join("manual.cjs"), "const name='path';\nconst value=require(name);\n").unwrap();
            } else {
                fs::write(root.path().join("package.json"),
                    r#"{"scripts":{"postinstall":"echo blocked"}}"#).unwrap();
            }
            let report = run_with_evidence(root.path(), |_| panic!("barriers must precede every runtime"));
            assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
            assert!(report.product_validation.is_none() && report.validation.is_none());
        }
    }

    #[test]
    fn unchanged_product_plan_still_requires_all_three_measured_legs() {
        let root = project();
        let first = run_with_evidence(root.path(), product_measurement);
        assert_eq!(first.status, CheckedRewriteStatus::Applied, "{first:#?}");
        let second = run_with_evidence(root.path(), product_measurement);
        assert_eq!(second.status, CheckedRewriteStatus::Unchanged, "{second:#?}");
        assert_eq!(second.rewrite.as_ref().unwrap().rewrites_applied, 0);
        let measured = second.product_validation.as_ref().unwrap();
        assert_eq!(measured.passed, 1);
        assert!(measured.cases[0].node.is_some() && measured.cases[0].bun.is_some() && measured.cases[0].native.is_some());
        assert!(second.validation.is_none());
    }

    #[test]
    fn product_capture_environment_reaches_primary_checked_apply() {
        use super::super::validation_suite::native_replay::failure_capture::{DIRECTORY_ENV, FailureCapture, product};
        const CHILD_ROOT: &str = "FRANKEN_PRODUCT_CAPTURE_TEST_CHILD_ROOT";
        const CHILD_REPORT: &str = "FRANKEN_PRODUCT_CAPTURE_TEST_CHILD_REPORT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let report = run(Path::new(&root), Path::new("/bin/false"));
            assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
            fs::write(std::env::var_os(CHILD_REPORT).unwrap(), serde_json::to_vec(&report).unwrap()).unwrap();
            return;
        }
        let root = project();
        let out = tempfile::tempdir().unwrap();
        let original = source(root.path());
        let report_path = out.path().join("report.json");
        let marker = out.path().join("executions");
        fs::write(root.path().join("case.test.mjs"), format!(
            "import fs from 'node:fs';\nimport {{ value }} from './helper.mjs';\nfs.appendFileSync({},(process.versions.bun?'bun':'node')+'\\n');\nconsole.log(value);\n",
            serde_json::to_string(&marker).unwrap())).unwrap();
        // Configure a separate test process, never mutate the global test
        // environment. The child calls the actual primary entrypoint once.
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.arg("product_capture_environment_reaches_primary_checked_apply").arg("--nocapture")
            .env(CHILD_ROOT, root.path()).env(CHILD_REPORT, &report_path)
            .env(BUN_ENV, runtime("bun")).env(DIRECTORY_ENV, out.path());
        let output = super::super::smoke_supervisor::run_command_with_timeout(&mut command,
            Duration::from_secs(120), Duration::from_secs(1)).unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let report: CheckedRewriteReport = serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
        let measured = report.product_validation.as_ref().unwrap();
        let Some(FailureCapture::Saved { capsule_path, content_sha256 }) = &measured.failure_capture
            else { panic!("{report:#?}") };
        assert_eq!(fs::read_to_string(marker).unwrap(), "node\nbun\n");
        assert_eq!(product::inspect_any(capsule_path).unwrap().captured_verdict, "FAIL");
        let exported = product::export_any(capsule_path, content_sha256, &out.path().join("fixture")).unwrap();
        assert!(fs::read_to_string(exported.destination.join("candidate/helper.mjs")).unwrap().contains("node:path"));
        assert_eq!(source(root.path()), original);
        assert!(!root.path().join(".migrate-backup/helper.mjs").exists());
        assert!(report.validation.is_none());
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
    }
}
