#![forbid(unsafe_code)]

//! Reviewed, execution-checked installation of an independently migrated tree.
//! No imported report authorizes a write. The existing production capture,
//! three-runtime oracle and native transaction own the actual operations.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/smoke_supervisor.rs"]
mod smoke_supervisor;
#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/validation_suite.rs"]
pub mod validation_suite;
#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/rewrite_transaction.rs"]
pub mod rewrite_transaction;

#[derive(Parser)]
#[command(version, about = "Inspect or live-validate and install a reviewed migration candidate")]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Read both captured inventories and inspect supported changes. Executes and installs nothing.
    Inspect { project: PathBuf, candidate: PathBuf },
    /// Run Node/Bun on the original and native Franken on the candidate, then install on PASS only.
    Apply {
        project: PathBuf,
        candidate: PathBuf,
        #[arg(long)]
        expected_input_sha256: String,
        #[arg(long)]
        expected_candidate_input_sha256: String,
        #[arg(long)]
        native_bin: PathBuf,
        #[arg(long)]
        bun_bin: PathBuf,
        /// Consent to trusted project execution with ambient OS authority; not a sandbox.
        #[arg(long, required = true)]
        execute: bool,
    },
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::path::Path;
    use std::time::{Duration, Instant};
    use rewrite_transaction::{AppliedRewrite, Edit, RewriteTransaction};
    use validation_suite::{product_oracle::ProductReport, rewrite_candidate::RewriteCandidate};

    #[derive(Debug, Serialize)]
    pub(super) struct Report {
        schema_version: &'static str,
        status: &'static str,
        project: PathBuf,
        candidate: PathBuf,
        input_sha256: String,
        candidate_input_sha256: String,
        tests: Vec<PathBuf>,
        changes: Vec<Change>,
        execution_attempted: bool,
        release_certification: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        validation: Option<ProductReport>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_transaction: Option<AppliedRewrite>,
        errors: Vec<String>,
    }

    #[derive(Debug, Serialize)]
    struct Change {
        path: String,
        before_sha256: String,
        after_sha256: String,
        before_bytes: usize,
        after_bytes: usize,
    }

    struct Prepared {
        capture: RewriteCandidate,
        report: Report,
    }

    fn valid_pin(pin: &str) -> bool {
        pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    fn prepare(project: &Path, candidate: &Path, pins: Option<(&str, &str)>) -> Result<Prepared> {
        if let Some((original, proposed)) = pins {
            ensure!(valid_pin(original) && valid_pin(proposed), "both reviewed input hashes must be 64 lowercase hexadecimal characters");
        }
        let project = project.canonicalize().context("resolve original project")?;
        let candidate = candidate.canonicalize().context("resolve proposed migration")?;
        ensure!(project != candidate && !project.starts_with(&candidate) && !candidate.starts_with(&project),
            "original and candidate must be separate, non-nested directories");
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut capture = RewriteCandidate::capture(&project, deadline)?;
        let proposed = RewriteCandidate::capture(&candidate, deadline)?;
        if let Some((original, proposed_pin)) = pins {
            ensure!(capture.input_sha256() == original, "original project does not match reviewed input hash");
            ensure!(proposed.input_sha256() == proposed_pin, "proposed migration does not match reviewed candidate hash");
        }
        let candidate_input_sha256 = proposed.input_sha256().to_owned();
        drop(proposed);
        capture.prepare_project(&candidate, &candidate_input_sha256)?;
        let changes = capture.replacements()?.iter().map(|edit| Change {
            path: edit.path.into(),
            before_sha256: hex::encode(Sha256::digest(edit.before)),
            after_sha256: hex::encode(Sha256::digest(edit.after)),
            before_bytes: edit.before.len(),
            after_bytes: edit.after.len(),
        }).collect();
        capture.ensure_source_unchanged()?;
        capture.ensure_candidate_source_unchanged()?;
        let report = Report {
            schema_version: "franken-node/reviewed-migration-apply/v1",
            status: "INSPECTED", project, candidate,
            input_sha256: capture.input_sha256().into(), candidate_input_sha256,
            tests: capture.test_inventory()?, changes,
            execution_attempted: false, release_certification: false,
            validation: None, source_transaction: None, errors: Vec::new(),
        };
        Ok(Prepared { capture, report })
    }

    fn apply(project: &Path, candidate: &Path, pins: (&str, &str), native: &Path, bun: &Path, execute: bool) -> Result<Report> {
        ensure!(execute, "--execute is required before running project code");
        // Reject stale/unsupported approvals BEFORE opening the writer, and do
        // not implicitly recover an unrelated transaction merely to validate.
        let Prepared { capture, mut report } = prepare(project, candidate, Some(pins))?;
        let writer = RewriteTransaction::open_without_recovery(&report.project)?;
        capture.ensure_source_unchanged()?;
        capture.ensure_candidate_source_unchanged()?;
        report.status = "ERROR";
        let operation = (|| -> Result<()> {
            // One execution path, no imported PASS, fallback or hidden retry.
            report.execution_attempted = true;
            let measured = capture.validate_product(native, bun)?;
            let admission = capture.check_product_validation(&measured).and_then(|()| {
                ensure!(measured.native_runtime.sha256 != measured.node_runtime.sha256
                    && measured.native_runtime.sha256 != measured.bun_runtime.sha256,
                    "installation requires three distinct runtime executable hashes");
                Ok(())
            });
            report.status = if measured.verdict == "ERROR" { "ERROR" } else { "REJECTED" };
            report.validation = Some(measured);
            if let Err(error) = admission {
                report.errors.push(format!("candidate refused; sources not installed: {error:#}"));
                return Ok(());
            }
            report.status = "ERROR";
            capture.ensure_source_unchanged()?;
            capture.ensure_candidate_source_unchanged()?;
            let replacements = capture.replacements()?;
            let edits: Vec<_> = replacements.iter().map(|edit| Edit {
                path: edit.path, before: edit.before, after: edit.after,
            }).collect();
            report.source_transaction = writer.apply_with_receipt(&edits)?;
            report.status = if report.source_transaction.is_some() { "APPLIED" } else { "UNCHANGED" };
            Ok(())
        })();
        if let Err(error) = operation {
            report.errors.push(format!("{error:#}"));
        }
        Ok(report)
    }

    pub(super) fn run(args: Args) -> Result<Report> {
        match args.action {
            Action::Inspect { project, candidate } => Ok(prepare(&project, &candidate, None)?.report),
            Action::Apply { project, candidate, expected_input_sha256, expected_candidate_input_sha256, native_bin, bun_bin, execute } =>
                apply(&project, &candidate, (&expected_input_sha256, &expected_candidate_input_sha256), &native_bin, &bun_bin, execute),
        }
    }

    pub(super) fn success(report: &Report) -> bool {
        matches!(report.status, "INSPECTED" | "APPLIED" | "UNCHANGED")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};

        fn pair() -> (tempfile::TempDir, PathBuf, PathBuf) {
            let root = tempfile::tempdir().unwrap();
            let original = root.path().join("original");
            let candidate = root.path().join("candidate");
            for path in [&original, &candidate] {
                fs::create_dir(path).unwrap();
                fs::write(path.join("case.test.cjs"), "globalThis.answer = 40 + 2;\n").unwrap();
                fs::set_permissions(path.join("case.test.cjs"), fs::Permissions::from_mode(0o640)).unwrap();
            }
            fs::write(candidate.join("case.test.cjs"), "globalThis.answer = 42;\n").unwrap();
            (root, original, candidate)
        }

        #[test]
        fn inspection_never_executes_creates_a_writer_or_exports_source_bytes() {
            let (_root, original, candidate) = pair();
            let inspected = prepare(&original, &candidate, None).unwrap().report;
            assert_eq!(inspected.status, "INSPECTED");
            assert!(!inspected.execution_attempted);
            assert_eq!(inspected.changes.len(), 1);
            let raw = serde_json::to_string(&inspected).unwrap();
            assert!(!raw.contains("globalThis"));
            assert!(!original.join(".migrate-backup").exists());
            assert!(!candidate.join(".migrate-backup").exists());
        }

        #[test]
        fn stale_or_swapped_pins_fail_before_runtime_discovery_or_writer_creation() {
            let (_root, original, candidate) = pair();
            let report = prepare(&original, &candidate, None).unwrap().report;
            let wrong_pin = "0".repeat(64);
            for pins in [(&report.candidate_input_sha256, &report.input_sha256), (&wrong_pin, &report.candidate_input_sha256)] {
                assert!(apply(&original, &candidate, (pins.0, pins.1), Path::new("/missing-native"), Path::new("/missing-bun"), true).is_err());
                assert!(!original.join(".migrate-backup").exists());
            }
            assert!(apply(&original, &candidate, (&report.input_sha256, &report.candidate_input_sha256), Path::new("/bin/false"), Path::new("/bin/true"), false).is_err());
            assert!(!original.join(".migrate-backup").exists());
        }

        #[test]
        fn native_failure_preserves_both_trees_and_cannot_publish_a_transaction() {
            // Real process/oracle execution with deliberately selected test
            // executables. /bin/true and /bin/false are NOT Bun or Franken.
            let (_root, original, candidate) = pair();
            let inspected = prepare(&original, &candidate, None).unwrap().report;
            let report = apply(&original, &candidate, (&inspected.input_sha256, &inspected.candidate_input_sha256), Path::new("/bin/false"), Path::new("/bin/true"), true).unwrap();
            assert_eq!(report.status, "REJECTED", "{report:?}");
            assert_eq!(report.validation.as_ref().unwrap().verdict, "FAIL");
            assert!(report.source_transaction.is_none());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
            assert_eq!(fs::read(candidate.join("case.test.cjs")).unwrap(), b"globalThis.answer = 42;\n");
        }

        #[test]
        fn native_reference_alias_never_authorizes_installation() {
            let (_root, original, candidate) = pair();
            let inspected = prepare(&original, &candidate, None).unwrap().report;
            let report = apply(&original, &candidate, (&inspected.input_sha256, &inspected.candidate_input_sha256), Path::new("/bin/true"), Path::new("/bin/true"), true).unwrap();
            assert!(!success(&report));
            assert!(report.source_transaction.is_none());
            assert!(report.errors.iter().any(|error| error.contains("distinct runtime")));
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
        }

        #[test]
        fn captured_passing_installation_returns_exact_resumable_rollback_identity() {
            let (root, original, candidate) = pair();
            // A byte-distinct no-output test executable exercises installation
            // admission, not actual Franken compatibility. No product fallback.
            let native = root.path().join("test-native");
            fs::write(&native, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
            let inspected = prepare(&original, &candidate, None).unwrap().report;
            let pins = (&*inspected.input_sha256, &*inspected.candidate_input_sha256);
            let report = apply(&original, &candidate, pins, &native, Path::new("/bin/true"), true).unwrap();
            assert_eq!(report.status, "APPLIED", "{report:?}");
            assert_eq!(report.validation.as_ref().unwrap().verdict, "PASS");
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 42;\n");
            assert_eq!(fs::metadata(original.join("case.test.cjs")).unwrap().permissions().mode() & 0o777, 0o640);
            assert!(apply(&original, &candidate, pins, &native, Path::new("/bin/true"), true).is_err());
            let receipt = report.source_transaction.unwrap();
            let restored = rewrite_transaction::rollback::run_pinned(&original, &receipt.transaction_id, &receipt.journal_sha256, true);
            assert_eq!(restored.status, rewrite_transaction::rollback::RollbackStatus::RolledBack);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
            assert_eq!(fs::read(candidate.join("case.test.cjs")).unwrap(), b"globalThis.answer = 42;\n");
        }

        #[test]
        fn same_project_aliases_and_nested_inputs_fail_before_source_changes() {
            let (root, original, candidate) = pair();
            let alias = root.path().join("alias");
            symlink(&original, &alias).unwrap();
            assert!(prepare(&original, &alias, None).is_err());
            assert!(prepare(root.path(), &candidate, None).is_err());
            assert!(!original.join(".migrate-backup").exists());
        }

        #[test]
        fn a_live_pass_cannot_install_after_either_input_tree_changes() {
            for change_original in [false, true] {
                let (root, original, candidate) = pair();
                for path in [&original, &candidate] {
                    fs::write(path.join("config.json"), b"before").unwrap();
                }
                let affected = if change_original { &original } else { &candidate };
                let source = format!("require('fs').writeFileSync({},'guest change');\n",
                    serde_json::to_string(&affected.join("config.json")).unwrap());
                fs::write(original.join("case.test.cjs"), &source).unwrap();
                fs::write(candidate.join("case.test.cjs"), format!("{source}// proposed migration\n")).unwrap();
                // Distinct controlled executables test orchestration only.
                let native = root.path().join("test-native");
                fs::write(&native, "#!/bin/sh\nexit 0\n").unwrap();
                fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
                let inspected = prepare(&original, &candidate, None).unwrap().report;
                let report = apply(&original, &candidate,
                    (&inspected.input_sha256, &inspected.candidate_input_sha256),
                    &native, Path::new("/bin/true"), true).unwrap();
                assert_eq!(report.validation.as_ref().unwrap().verdict, "PASS");
                assert_eq!(report.status, "ERROR", "{report:?}");
                assert!(report.execution_attempted);
                assert!(report.source_transaction.is_none());
                assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), source.as_bytes());
                // No attempt to conceal guest ambient effects by restoring them.
                assert_eq!(fs::read(affected.join("config.json")).unwrap(), b"guest change");
            }
        }

        #[test]
        fn missing_native_runtime_keeps_installation_uncommitted() {
            let (_root, original, candidate) = pair();
            let inspected = prepare(&original, &candidate, None).unwrap().report;
            let report = apply(&original, &candidate,
                (&inspected.input_sha256, &inspected.candidate_input_sha256),
                Path::new("/missing-native"), Path::new("/bin/true"), true).unwrap();
            assert_eq!(report.status, "ERROR");
            assert!(report.execution_attempted);
            assert!(report.validation.is_none());
            assert!(report.source_transaction.is_none());
            assert!(!report.errors.is_empty());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
        }

        #[test]
        fn cli_requires_execution_consent_and_both_role_approvals() {
            assert!(Args::try_parse_from(["apply", "inspect", "/original", "/candidate"]).is_ok());
            let base = ["apply", "apply", "/original", "/candidate", "--native-bin", "/native", "--bun-bin", "/bun"];
            assert!(Args::try_parse_from(base).is_err());
            let mut args = base.to_vec();
            let hash = "a".repeat(64);
            args.extend(["--expected-input-sha256", &hash, "--expected-candidate-input-sha256", &hash]);
            assert!(Args::try_parse_from(&args).is_err());
            args.push("--execute");
            assert!(Args::try_parse_from(&args).is_ok());
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    {
        let (output, success) = match linux::run(args) {
            Ok(report) => {
                let success = linux::success(&report);
                (serde_json::to_value(report).expect("bounded JSON report"), success)
            }
            Err(error) => (serde_json::json!({
                "schema_version": "franken-node/reviewed-migration-apply/v1", "status": "ERROR",
                "release_certification": false, "errors": [format!("{error:#}")]
            }), false),
        };
        // A broken output pipe after a commit is not a rollback. The retained
        // native journal remains authoritative when command output is lost.
        if let Err(error) = serde_json::to_writer_pretty(std::io::stdout().lock(), &output) {
            eprintln!("cannot publish migration report; inspect retained transaction history: {error}");
            return ExitCode::from(1);
        }
        if success { ExitCode::SUCCESS } else { ExitCode::from(1) }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        eprintln!("reviewed migration installation is supported on Linux only");
        ExitCode::from(2)
    }
}
