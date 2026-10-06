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
    use std::os::unix::fs::PermissionsExt;
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
        deadline: Instant,
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
        Ok(Prepared { capture, report, deadline })
    }

    /// Predict only the native writer's own initialization on an immutable
    /// private copy, then require the live post-open tree to match it exactly.
    /// This is not a metadata exclusion or a redefinition of reviewed inputs:
    /// validation still executes the original pre-initialization snapshots.
    /// The returned guard binds every live byte, including the initialized
    /// writer state, through execution until the actual installation begins.
    fn initialize_writer(capture: &RewriteCandidate, project: &Path, deadline: Instant)
        -> Result<(RewriteTransaction, RewriteCandidate)>
    {
        let staged = tempfile::Builder::new()
            .prefix("franken-reviewed-writer-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let expected_root = staged.path().join("project");
        capture.stage_original(&expected_root)?;
        drop(RewriteTransaction::open_without_recovery(&expected_root)?);
        let expected = RewriteCandidate::capture(&expected_root, deadline)?;
        let writer = RewriteTransaction::open_without_recovery(project)?;
        let initialized = RewriteCandidate::capture(project, deadline)?;
        ensure!(initialized.input_sha256() == expected.input_sha256(),
            "project differs from the reviewed input plus exact native writer initialization");
        initialized.ensure_source_unchanged()?;
        Ok((writer, initialized))
    }

    fn apply(project: &Path, candidate: &Path, pins: (&str, &str), native: &Path, bun: &Path, execute: bool) -> Result<Report> {
        ensure!(execute, "--execute is required before running project code");
        // Reject stale/unsupported approvals BEFORE opening the writer, and do
        // not implicitly recover an unrelated transaction merely to validate.
        let Prepared { capture, mut report, deadline } = prepare(project, candidate, Some(pins))?;
        let (writer, initialized) = initialize_writer(&capture, &report.project, deadline)?;
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
            initialized.ensure_source_unchanged()?;
            capture.ensure_candidate_source_unchanged()?;
            let replacements = capture.replacements()?;
            let edits: Vec<_> = replacements.iter().map(|edit| Edit {
                path: edit.path, before: edit.before, after: edit.after,
            }).collect();
            // Each reviewed installation owns its immediate preimages. A
            // second migration must not conflict with or replace the first
            // migration's immutable originals; both remain independently
            // recoverable through the same pinned native rollback protocol.
            report.source_transaction = writer.apply_versioned_with_receipt(&edits)?;
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

        // Controlled, byte-distinct executables exercise actual capture,
        // process admission, writer and rollback integration. They are not
        // Bun/Franken implementations or evidence of runtime compatibility.
        fn controlled_native(root: &Path) -> PathBuf {
            let native = root.join("controlled-native");
            fs::write(&native, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
            native
        }

        fn apply_current(original: &Path, candidate: &Path, native: &Path) -> Report {
            let inspected = prepare(original, candidate, None).unwrap().report;
            apply(original, candidate,
                (&inspected.input_sha256, &inspected.candidate_input_sha256),
                native, Path::new("/bin/true"), true).unwrap()
        }

        fn next_candidate(original: &Path, destination: &Path, source: &[u8]) {
            // Preserve the full captured inventory, including retained native
            // history. Only intended ordinary source replacements may differ.
            RewriteCandidate::capture(original, Instant::now() + Duration::from_secs(30))
                .unwrap().stage_original(destination).unwrap();
            fs::write(destination.join("case.test.cjs"), source).unwrap();
        }

        fn receipt_directory(original: &Path, receipt: &AppliedRewrite) -> PathBuf {
            original.join(".migrate-backup/.franken-rewrite").join(&receipt.transaction_id)
        }

        fn restore(original: &Path, receipt: &AppliedRewrite) -> rewrite_transaction::rollback::RollbackReport {
            rewrite_transaction::rollback::run_pinned(original,
                &receipt.transaction_id, &receipt.journal_sha256, true)
        }

        #[test]
        fn successive_reviewed_installations_keep_independent_originals_and_reverse_recovery() {
            use rewrite_transaction::rollback::RollbackStatus;
            let (root, original, candidate) = pair();
            let native = controlled_native(root.path());
            let before = fs::read(original.join("case.test.cjs")).unwrap();
            let intermediate = fs::read(candidate.join("case.test.cjs")).unwrap();
            let first_report = apply_current(&original, &candidate, &native);
            assert_eq!(first_report.status, "APPLIED", "{first_report:?}");
            assert_eq!(first_report.validation.as_ref().unwrap().verdict, "PASS");
            let first = first_report.source_transaction.unwrap();
            let first_journal = fs::read(receipt_directory(&original, &first).join("applied.json")).unwrap();

            let final_source = b"globalThis.answer = 6 * 7;\n";
            let next = root.path().join("next-candidate");
            next_candidate(&original, &next, final_source);
            let second_report = apply_current(&original, &next, &native);
            assert_eq!(second_report.status, "APPLIED", "{second_report:?}");
            assert!(second_report.execution_attempted);
            assert_eq!(second_report.validation.as_ref().unwrap().verdict, "PASS");
            let second = second_report.source_transaction.unwrap();
            assert_ne!(first.transaction_id, second.transaction_id);
            assert_ne!(first.journal_sha256, second.journal_sha256);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), final_source);
            assert_eq!(fs::read(receipt_directory(&original, &first).join("applied.json")).unwrap(), first_journal);
            assert_eq!(fs::read(receipt_directory(&original, &first).join("0.before")).unwrap(), before);
            assert_eq!(fs::read(receipt_directory(&original, &second).join("0.before")).unwrap(), intermediate);
            assert!(!original.join(".migrate-backup/case.test.cjs").exists());

            assert_eq!(restore(&original, &first).status, RollbackStatus::Conflict);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), final_source);
            assert_eq!(restore(&original, &second).status, RollbackStatus::RolledBack);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), intermediate);
            assert_eq!(restore(&original, &first).status, RollbackStatus::RolledBack);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), before);
            assert_eq!(fs::metadata(original.join("case.test.cjs")).unwrap().permissions().mode() & 0o777, 0o640);
            assert_eq!(fs::read(candidate.join("case.test.cjs")).unwrap(), intermediate);
            assert_eq!(fs::read(next.join("case.test.cjs")).unwrap(), final_source);
            assert_eq!(rewrite_transaction::rollback::run(&original, None, false).history.len(), 2);
            fs::write(original.join("case.test.cjs"), b"independent later edit").unwrap();
            assert_eq!(restore(&original, &second).status, RollbackStatus::AlreadyRolledBack);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"independent later edit");
        }

        #[test]
        fn a_failed_second_validation_leaves_the_first_installation_and_its_recovery_intact() {
            let (root, original, candidate) = pair();
            let native = controlled_native(root.path());
            let first_report = apply_current(&original, &candidate, &native);
            assert_eq!(first_report.status, "APPLIED", "{first_report:?}");
            let first = first_report.source_transaction.unwrap();
            let first_journal = fs::read(receipt_directory(&original, &first).join("applied.json")).unwrap();
            let before = fs::read(original.join("case.test.cjs")).unwrap();
            let next = root.path().join("next-candidate");
            next_candidate(&original, &next, b"globalThis.answer = 21 + 21;\n");
            let rejected = apply_current(&original, &next, Path::new("/bin/false"));
            assert_eq!(rejected.status, "REJECTED", "{rejected:?}");
            assert_eq!(rejected.validation.as_ref().unwrap().verdict, "FAIL");
            assert!(rejected.source_transaction.is_none());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), before);
            assert_eq!(fs::read(receipt_directory(&original, &first).join("applied.json")).unwrap(), first_journal);
            let history = rewrite_transaction::rollback::run(&original, None, false);
            assert_eq!(history.history.len(), 1);
            assert!(history.pending_transaction_id.is_none());
            assert_eq!(restore(&original, &first).status, rewrite_transaction::rollback::RollbackStatus::RolledBack);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
        }

        #[test]
        fn repeated_identical_candidate_is_revalidated_without_creating_another_transaction() {
            let (root, original, candidate) = pair();
            let native = controlled_native(root.path());
            let first = apply_current(&original, &candidate, &native);
            assert_eq!(first.status, "APPLIED", "{first:?}");
            let receipt = first.source_transaction.unwrap();
            let journal = fs::read(receipt_directory(&original, &receipt).join("applied.json")).unwrap();
            let next = root.path().join("identical-candidate");
            next_candidate(&original, &next, b"globalThis.answer = 42;\n");
            let repeated = apply_current(&original, &next, &native);
            assert_eq!(repeated.status, "UNCHANGED", "{repeated:?}");
            assert!(repeated.execution_attempted);
            assert_eq!(repeated.validation.as_ref().unwrap().verdict, "PASS");
            assert!(repeated.changes.is_empty());
            assert!(repeated.source_transaction.is_none());
            assert_eq!(rewrite_transaction::rollback::run(&original, None, false).history.len(), 1);
            assert_eq!(fs::read(receipt_directory(&original, &receipt).join("applied.json")).unwrap(), journal);
            // Matching installed bytes do not waive a fresh runtime decision.
            let failed = apply_current(&original, &next, Path::new("/bin/false"));
            assert_eq!(failed.status, "REJECTED", "{failed:?}");
            assert!(failed.execution_attempted && failed.source_transaction.is_none());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 42;\n");
        }

        #[test]
        fn reviewed_installation_can_follow_a_legacy_writer_without_adopting_its_backup() {
            use rewrite_transaction::rollback::RollbackStatus;
            let (root, original, _candidate) = pair();
            let native = controlled_native(root.path());
            let before = fs::read(original.join("case.test.cjs")).unwrap();
            let middle = b"globalThis.answer = 42;\n";
            let legacy = {
                let writer = RewriteTransaction::open(&original).unwrap();
                writer.apply_with_receipt(&[Edit {
                    path: "case.test.cjs", before: &before, after: middle,
                }]).unwrap().unwrap()
            };
            let old_journal = fs::read(receipt_directory(&original, &legacy).join("applied.json")).unwrap();
            let candidate = root.path().join("next-candidate");
            next_candidate(&original, &candidate, b"globalThis.answer = 7 * 6;\n");
            let report = apply_current(&original, &candidate, &native);
            assert_eq!(report.status, "APPLIED", "{report:?}");
            let next = report.source_transaction.unwrap();
            assert_eq!(fs::read(original.join(".migrate-backup/case.test.cjs")).unwrap(), before);
            assert_eq!(fs::read(receipt_directory(&original, &legacy).join("applied.json")).unwrap(), old_journal);
            assert_eq!(fs::read(receipt_directory(&original, &next).join("0.before")).unwrap(), middle);
            assert_eq!(restore(&original, &next).status, RollbackStatus::RolledBack);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), middle);
            assert_eq!(restore(&original, &legacy).status, RollbackStatus::RolledBack);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), before);
        }

        #[test]
        fn writer_initialization_is_exact_without_redefining_reviewed_or_executed_inputs() {
            let (_root, original, candidate) = pair();
            let prepared = prepare(&original, &candidate, None).unwrap();
            let reviewed = prepared.report.input_sha256.clone();
            let (writer, initialized) = initialize_writer(&prepared.capture, &original, prepared.deadline).unwrap();
            assert_eq!(prepared.capture.input_sha256(), reviewed);
            assert_ne!(initialized.input_sha256(), reviewed);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
            let store = original.join(".migrate-backup/.franken-rewrite");
            assert_eq!(fs::read_dir(&store).unwrap().count(), 1);
            assert!(fs::read(store.join("lock")).unwrap().is_empty());
            initialized.ensure_source_unchanged().unwrap();
            // The pre-bootstrap capture has not been silently rebound.
            assert!(prepared.capture.ensure_source_unchanged().is_err());
            fs::write(store.join("unexpected.json"), b"not created by the writer").unwrap();
            assert!(initialized.ensure_source_unchanged().is_err());
            assert!(RewriteTransaction::open_without_recovery(&original).is_err());
            drop(writer);
        }

        #[test]
        fn a_live_pass_cannot_hide_guest_changes_to_initialized_writer_metadata() {
            let (root, original, candidate) = pair();
            let lock = original.join(".migrate-backup/.franken-rewrite/lock");
            let source = format!("require('fs').writeFileSync({},'guest metadata edit');\n",
                serde_json::to_string(&lock).unwrap());
            fs::write(original.join("case.test.cjs"), &source).unwrap();
            fs::write(candidate.join("case.test.cjs"), format!("{source}// candidate\n")).unwrap();
            let native = controlled_native(root.path());
            let report = apply_current(&original, &candidate, &native);
            assert_eq!(report.validation.as_ref().unwrap().verdict, "PASS");
            assert_eq!(report.status, "ERROR", "{report:?}");
            assert!(report.execution_attempted && report.source_transaction.is_none());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), source.as_bytes());
            assert_eq!(fs::read(lock).unwrap(), b"guest metadata edit");
            assert!(rewrite_transaction::rollback::run(&original, None, false).history.is_empty());
        }

        #[test]
        fn writer_bootstrap_does_not_exempt_other_changes_after_input_review() {
            let (_root, original, candidate) = pair();
            let prepared = prepare(&original, &candidate, None).unwrap();
            fs::write(original.join("unreviewed-config.json"), b"changed").unwrap();
            let result = initialize_writer(&prepared.capture, &original, prepared.deadline);
            let error = match result {
                Ok(_) => panic!("writer bootstrap admitted an unrelated input change"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("exact native writer initialization"), "{error:#}");
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
            assert_eq!(fs::read(original.join("unreviewed-config.json")).unwrap(), b"changed");
            assert!(rewrite_transaction::rollback::run(&original, None, false).history.is_empty());
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
