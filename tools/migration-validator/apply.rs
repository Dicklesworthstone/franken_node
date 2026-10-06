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
    use rewrite_transaction::{AppliedRewrite, CreateFile, Edit, RewriteTransaction};
    use validation_suite::{
        product_oracle::{CancellationToken, ProductReport},
        rewrite_candidate::RewriteCandidate,
    };

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
        cancellation_requested: bool,
        /// The journaled writer was entered, not proof that a file changed or
        /// that installation completed. Never infer no writes from exit 130.
        installation_started: bool,
        release_certification: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        validation: Option<ProductReport>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_transaction: Option<AppliedRewrite>,
        errors: Vec<String>,
    }

    #[derive(Debug, Serialize)]
    struct Change {
        kind: &'static str,
        path: String,
        before_sha256: Option<String>,
        after_sha256: String,
        before_bytes: Option<usize>,
        after_bytes: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        created_mode: Option<u32>,
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
        let changes = capture.changes()?;
        let mut descriptions: Vec<_> = changes.replacements.iter().map(|edit| Change {
            kind: "replace",
            path: edit.path.into(),
            before_sha256: Some(hex::encode(Sha256::digest(edit.before))),
            after_sha256: hex::encode(Sha256::digest(edit.after)),
            before_bytes: Some(edit.before.len()),
            after_bytes: edit.after.len(),
            created_mode: None,
        }).collect();
        descriptions.extend(changes.additions.iter().map(|addition| Change {
            kind: "create",
            path: addition.path.into(),
            before_sha256: None,
            after_sha256: hex::encode(Sha256::digest(addition.after)),
            before_bytes: None,
            after_bytes: addition.after.len(),
            created_mode: Some(addition.mode),
        }));
        descriptions.sort_by(|left, right| left.path.cmp(&right.path));
        drop(changes);
        capture.ensure_source_unchanged()?;
        capture.ensure_candidate_source_unchanged()?;
        let report = Report {
            schema_version: "franken-node/reviewed-migration-apply/v1",
            status: "INSPECTED", project, candidate,
            input_sha256: capture.input_sha256().into(), candidate_input_sha256,
            tests: capture.test_inventory()?, changes: descriptions,
            execution_attempted: false, release_certification: false,
            cancellation_requested: false, installation_started: false,
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

    #[cfg(test)]
    fn apply(project: &Path, candidate: &Path, pins: (&str, &str), native: &Path, bun: &Path, execute: bool) -> Result<Report> {
        apply_controlled(project, candidate, pins, native, bun, execute, &CancellationToken::default())
    }

    fn apply_controlled(
        project: &Path, candidate: &Path, pins: (&str, &str), native: &Path,
        bun: &Path, execute: bool, cancellation: &CancellationToken,
    ) -> Result<Report> {
        ensure!(execute, "--execute is required before running project code");
        cancellation.check()?;
        // Reject stale/unsupported approvals BEFORE opening the writer, and do
        // not implicitly recover an unrelated transaction merely to validate.
        let Prepared { capture, mut report, deadline } = prepare(project, candidate, Some(pins))?;
        cancellation.check()?;
        let (writer, initialized) = initialize_writer(&capture, &report.project, deadline)?;
        capture.ensure_candidate_source_unchanged()?;
        report.status = "ERROR";
        let operation = (|| -> Result<()> {
            cancellation.check()?;
            // One execution path, no imported PASS, fallback or hidden retry.
            report.execution_attempted = true;
            let measured = capture.validate_product_cancellable(native, bun, cancellation)?;
            let admission = capture.check_product_validation(&measured).and_then(|()| {
                ensure!(measured.native_runtime.sha256 != measured.node_runtime.sha256
                    && measured.native_runtime.sha256 != measured.bun_runtime.sha256,
                    "installation requires three distinct runtime executable hashes");
                Ok(())
            });
            report.status = if measured.verdict == "ERROR" { "ERROR" } else { "REJECTED" };
            report.validation = Some(measured);
            cancellation.check()?;
            if let Err(error) = admission {
                report.errors.push(format!("candidate refused; sources not installed: {error:#}"));
                return Ok(());
            }
            report.status = "ERROR";
            initialized.ensure_source_unchanged()?;
            cancellation.check()?;
            capture.ensure_candidate_source_unchanged()?;
            install_candidate(&writer, &capture, &mut report, cancellation)
        })();
        if let Err(error) = operation {
            report.errors.push(format!("{error:#}"));
        }
        record_cancellation(&mut report, cancellation);
        Ok(report)
    }

    /// The final successful cancellation check is the commit boundary. After
    /// it, defer cooperative signals through the existing durable native writer
    /// (including its recovery on failure); never inject an early return into
    /// write-ahead publication, live installation or restoration. An abrupt
    /// process/kernel failure still uses the retained native recovery protocol.
    fn install_candidate(
        writer: &RewriteTransaction, capture: &RewriteCandidate,
        report: &mut Report, cancellation: &CancellationToken,
    ) -> Result<()> {
        let changes = capture.changes()?;
        let edits: Vec<_> = changes.replacements.iter().map(|edit| Edit {
            path: edit.path, before: edit.before, after: edit.after,
        }).collect();
        let creations: Vec<_> = changes.additions.iter().map(|addition| CreateFile {
            path: addition.path, after: addition.after, mode: addition.mode,
        }).collect();
        cancellation.check()?;
        report.installation_started = true;
        // This call owns exact per-generation originals and returns the actual
        // journal identity. No cancellation checks are added inside the writer.
        report.source_transaction = writer.apply_with_creations_receipt(&edits, &creations)?;
        report.status = if report.source_transaction.is_some() { "APPLIED" } else { "UNCHANGED" };
        Ok(())
    }

    fn record_cancellation(report: &mut Report, cancellation: &CancellationToken) {
        report.cancellation_requested = cancellation.is_cancelled();
        if report.cancellation_requested && !report.installation_started {
            report.status = "CANCELLED";
        }
        // After the boundary, preserve APPLIED/UNCHANGED/ERROR and any journal
        // receipt. A cancellation flag is not a claim of restored source state.
    }

    pub(super) fn install_signal_handler(cancellation: &CancellationToken) -> Result<()> {
        let cancellation = cancellation.clone();
        ctrlc::try_set_handler(move || cancellation.cancel())
            .context("cannot install migration cancellation handler; refusing execution")
    }

    pub(super) fn run(args: Args, cancellation: &CancellationToken) -> Result<Report> {
        match args.action {
            Action::Inspect { project, candidate } => Ok(prepare(&project, &candidate, None)?.report),
            Action::Apply { project, candidate, expected_input_sha256, expected_candidate_input_sha256, native_bin, bun_bin, execute } =>
                apply_controlled(&project, &candidate, (&expected_input_sha256, &expected_candidate_input_sha256), &native_bin, &bun_bin, execute, cancellation),
        }
    }

    pub(super) fn success(report: &Report) -> bool {
        !report.cancellation_requested && matches!(report.status, "INSPECTED" | "APPLIED" | "UNCHANGED")
    }

    pub(super) fn exit_code(report: &Report) -> u8 {
        if report.cancellation_requested { 130 } else if success(report) { 0 } else { 1 }
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

        #[test]
        fn precancelled_apply_and_candidate_validation_do_not_open_a_writer() {
            let (_root, original, candidate) = pair();
            let prepared = prepare(&original, &candidate, None).unwrap();
            let cancellation = CancellationToken::default();
            cancellation.cancel();
            let error = apply_controlled(&original, &candidate,
                (&prepared.report.input_sha256, &prepared.report.candidate_input_sha256),
                Path::new("/missing-native"), Path::new("/missing-bun"), true, &cancellation)
                .unwrap_err();
            assert!(error.to_string().contains("MIGRATION_CANCELLED"));
            let error = prepared.capture.validate_product_cancellable(
                Path::new("/missing-native"), Path::new("/missing-bun"), &cancellation)
                .unwrap_err();
            assert!(error.to_string().contains("MIGRATION_CANCELLED"));
            assert!(!original.join(".migrate-backup").exists());
            assert!(!candidate.join(".migrate-backup").exists());
            prepared.capture.ensure_source_unchanged().unwrap();
        }

        fn waiting_native(root: &Path) -> PathBuf {
            let native = root.join("waiting-native");
            let ready = root.join("native-ready");
            // A controlled shell process is a lifecycle fixture, not a native
            // engine. The original Node and /bin/true legs emit no output.
            fs::write(&native, format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec /bin/sleep 30\n",
                ready.display())).unwrap();
            fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
            native
        }

        fn wait_ready(path: &Path) -> bool {
            let deadline = Instant::now() + Duration::from_secs(10);
            // Opening the marker precedes writing its PID. Do not cancel in
            // that gap and then mistake an empty marker for a cleanup defect.
            let observed = || fs::read_to_string(path).ok()
                .and_then(|raw| raw.parse::<u32>().ok()).is_some_and(|pid| pid > 1);
            while !observed() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            observed()
        }

        #[test]
        fn cancellation_during_native_execution_preserves_references_and_refuses_all_changes() {
            let (root, original, candidate) = pair();
            fs::write(candidate.join("helper.cjs"), b"new helper").unwrap();
            let native = waiting_native(root.path());
            let ready = root.path().join("native-ready");
            let prepared = prepare(&original, &candidate, None).unwrap();
            let cancellation = CancellationToken::default();
            let report = std::thread::scope(|scope| {
                let cancellation = &cancellation;
                let ready = &ready;
                let trigger = scope.spawn(move || {
                    let observed = wait_ready(ready);
                    cancellation.cancel();
                    assert!(observed, "native fixture never reached cancellation barrier");
                });
                let report = apply_controlled(&original, &candidate,
                    (&prepared.report.input_sha256, &prepared.report.candidate_input_sha256),
                    &native, Path::new("/bin/true"), true, cancellation).unwrap();
                trigger.join().unwrap();
                report
            });
            assert_eq!(report.status, "CANCELLED", "{report:?}");
            assert_eq!(exit_code(&report), 130);
            assert!(report.cancellation_requested && report.execution_attempted);
            assert!(!report.installation_started && report.source_transaction.is_none());
            let measured = report.validation.as_ref().unwrap();
            assert_eq!(measured.verdict, "ERROR");
            assert_eq!(measured.native_divergences, 0);
            assert!(measured.cases[0].node.is_some() && measured.cases[0].bun.is_some());
            assert!(measured.cases[0].native.is_none());
            assert!(!original.join("helper.cjs").exists());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
            let history = rewrite_transaction::rollback::run(&original, None, false);
            assert!(history.history.is_empty() && history.pending_transaction_id.is_none());
            // The exclusive owner reaped its child before the report escaped.
            let pid: u32 = fs::read_to_string(ready).unwrap().parse().unwrap();
            assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
        }

        #[test]
        fn cancellation_after_live_passing_evidence_still_blocks_writer_entry() {
            let (root, original, candidate) = pair();
            fs::write(candidate.join("helper.cjs"), b"new helper").unwrap();
            let Prepared { capture, mut report, deadline } = prepare(&original, &candidate, None).unwrap();
            let (writer, initialized) = initialize_writer(&capture, &original, deadline).unwrap();
            let cancellation = CancellationToken::default();
            let measured = capture.validate_product_cancellable(
                &controlled_native(root.path()), Path::new("/bin/true"), &cancellation).unwrap();
            capture.check_product_validation(&measured).unwrap();
            assert_eq!(measured.verdict, "PASS");
            report.validation = Some(measured);
            initialized.ensure_source_unchanged().unwrap();
            capture.ensure_candidate_source_unchanged().unwrap();
            cancellation.cancel();
            let error = install_candidate(&writer, &capture, &mut report, &cancellation).unwrap_err();
            assert!(error.to_string().contains("MIGRATION_CANCELLED"));
            record_cancellation(&mut report, &cancellation);
            assert_eq!(report.status, "CANCELLED");
            assert_eq!(exit_code(&report), 130);
            assert!(!report.installation_started && report.source_transaction.is_none());
            assert!(!original.join("helper.cjs").exists());
            assert_eq!(fs::read_dir(original.join(".migrate-backup/.franken-rewrite")).unwrap().count(), 1);
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
        }

        #[test]
        fn cancellation_observed_after_commit_preserves_applied_status_and_exact_recovery_receipt() {
            let (root, original, candidate) = pair();
            fs::write(candidate.join("helper.cjs"), b"retained creation").unwrap();
            let Prepared { capture, mut report, deadline } = prepare(&original, &candidate, None).unwrap();
            let (writer, initialized) = initialize_writer(&capture, &original, deadline).unwrap();
            let cancellation = CancellationToken::default();
            let measured = capture.validate_product_cancellable(
                &controlled_native(root.path()), Path::new("/bin/true"), &cancellation).unwrap();
            capture.check_product_validation(&measured).unwrap();
            report.validation = Some(measured);
            initialized.ensure_source_unchanged().unwrap();
            capture.ensure_candidate_source_unchanged().unwrap();
            install_candidate(&writer, &capture, &mut report, &cancellation).unwrap();
            cancellation.cancel();
            record_cancellation(&mut report, &cancellation);
            assert_eq!(report.status, "APPLIED");
            assert!(report.installation_started && report.cancellation_requested);
            assert_eq!(exit_code(&report), 130);
            assert!(!success(&report));
            assert_eq!(fs::read(original.join("helper.cjs")).unwrap(), b"retained creation");
            let receipt = report.source_transaction.unwrap();
            drop(writer);
            assert_eq!(restore(&original, &receipt).status, rewrite_transaction::rollback::RollbackStatus::RolledBack);
            assert!(!original.join("helper.cjs").exists());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
            assert!(receipt_directory(&original, &receipt).join("rolled-back.json").exists());
        }

        const SIGNAL_CHILD_ROOT: &str = "FRANKEN_MIGRATION_SIGNAL_TEST_ROOT";

        fn signal_child(test: &str, root: &Path) -> std::process::Command {
            let module = module_path!().split_once("::").map_or("", |(_, module)| module);
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child.args(["--exact", &format!("{module}::{test}"), "--nocapture"])
                .env(SIGNAL_CHILD_ROOT, root);
            child
        }

        #[test]
        fn operator_signals_cancel_live_guests_without_claiming_source_restoration() {
            use rustix::process::{Pid, Signal, kill_process};
            if let Some(root) = std::env::var_os(SIGNAL_CHILD_ROOT) {
                let root = PathBuf::from(root);
                let original = root.join("original");
                let candidate = root.join("candidate");
                let inspected = prepare(&original, &candidate, None).unwrap().report;
                let cancellation = CancellationToken::default();
                install_signal_handler(&cancellation).unwrap();
                let args = Args { action: Action::Apply {
                    project: original, candidate,
                    expected_input_sha256: inspected.input_sha256,
                    expected_candidate_input_sha256: inspected.candidate_input_sha256,
                    native_bin: root.join("waiting-native"), bun_bin: "/bin/true".into(), execute: true,
                }};
                let report = run(args, &cancellation).unwrap();
                assert_eq!(report.status, "CANCELLED", "{report:?}");
                assert!(!report.installation_started && report.source_transaction.is_none());
                fs::write(root.join("cancelled-report.json"), serde_json::to_vec(&report).unwrap()).unwrap();
                std::process::exit(i32::from(exit_code(&report)));
            }
            for signal in [Signal::INT, Signal::TERM, Signal::HUP] {
                let (root, original, candidate) = pair();
                fs::write(candidate.join("helper.cjs"), b"must not install").unwrap();
                waiting_native(root.path());
                let mut child = signal_child("operator_signals_cancel_live_guests_without_claiming_source_restoration", root.path());
                let completion = smoke_supervisor::supervise_with_observer(
                    &mut child, Duration::from_secs(20), Duration::from_secs(2),
                    |pid| {
                        ensure!(wait_ready(&root.path().join("native-ready")), "signal fixture did not start");
                        let pid = Pid::from_raw(i32::try_from(pid)?).context("invalid child PID")?;
                        // Signal ONLY the operator. Its separately owned native
                        // group must be stopped by the cancellation protocol.
                        kill_process(pid, signal)?;
                        Ok(())
                    }, |_, _| Ok(()),
                ).unwrap();
                assert_eq!(completion.reason, smoke_supervisor::StopReason::Exited);
                assert_eq!(completion.status.code(), Some(130));
                let report: serde_json::Value = serde_json::from_slice(
                    &fs::read(root.path().join("cancelled-report.json")).unwrap()).unwrap();
                assert_eq!(report["status"], "CANCELLED");
                assert_eq!(report["cancellation_requested"], true);
                assert_eq!(report["installation_started"], false);
                assert_eq!(report["validation"]["verdict"], "ERROR");
                assert!(report.get("source_transaction").is_none());
                assert!(!original.join("helper.cjs").exists());
                assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
                let pid: u32 = fs::read_to_string(root.path().join("native-ready")).unwrap().parse().unwrap();
                assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
                assert!(rewrite_transaction::rollback::run(&original, None, false).history.is_empty());
            }
        }

        #[test]
        fn cancellation_handler_registration_refuses_a_second_owner() {
            if std::env::var_os(SIGNAL_CHILD_ROOT).is_some() {
                let first = CancellationToken::default();
                install_signal_handler(&first).unwrap();
                let second = CancellationToken::default();
                assert!(install_signal_handler(&second).is_err());
                rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM).unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                while !first.is_cancelled() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert!(first.is_cancelled());
                assert!(!second.is_cancelled());
                return;
            }
            let root = tempfile::tempdir().unwrap();
            let output = smoke_supervisor::run_command_with_timeout(
                &mut signal_child("cancellation_handler_registration_refuses_a_second_owner", root.path()),
                Duration::from_secs(5), Duration::from_secs(1),
            ).unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(fs::read_dir(root.path()).unwrap().next().is_none());
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

        #[test]
        fn reviewed_helper_addition_is_executed_installed_and_retained_on_rollback() {
            use rewrite_transaction::rollback::RollbackStatus;
            let (root, original, candidate) = pair();
            let helper = b"module.exports = 42;\n";
            fs::write(candidate.join("helper.cjs"), helper).unwrap();
            fs::set_permissions(candidate.join("helper.cjs"), fs::Permissions::from_mode(0o640)).unwrap();
            fs::write(candidate.join("case.test.cjs"), b"globalThis.answer = require('./helper.cjs');\n").unwrap();
            let inspected = prepare(&original, &candidate, None).unwrap().report;
            assert_eq!(inspected.changes.len(), 2);
            let created = inspected.changes.iter().find(|change| change.kind == "create").unwrap();
            assert_eq!(created.path, "helper.cjs");
            assert!(created.before_sha256.is_none() && created.before_bytes.is_none());
            assert_eq!(created.created_mode, Some(0o640));
            assert!(!serde_json::to_string(&inspected).unwrap().contains("module.exports"));
            assert!(!original.join("helper.cjs").exists());
            assert!(!original.join(".migrate-backup").exists());
            // Controlled native-role executable checks the actual staged helper.
            // This measures production orchestration, not Franken JS semantics.
            let native = controlled_native(root.path());
            fs::write(&native, "#!/bin/sh\ntest -f helper.cjs && test \"$(/bin/cat helper.cjs)\" = 'module.exports = 42;'\n").unwrap();
            let report = apply(&original, &candidate,
                (&inspected.input_sha256, &inspected.candidate_input_sha256),
                &native, Path::new("/bin/true"), true).unwrap();
            assert_eq!(report.status, "APPLIED", "{report:?}");
            assert_eq!(report.validation.as_ref().unwrap().verdict, "PASS");
            assert_eq!(fs::read(original.join("helper.cjs")).unwrap(), helper);
            assert_eq!(fs::metadata(original.join("helper.cjs")).unwrap().permissions().mode() & 0o777, 0o640);
            let receipt = report.source_transaction.unwrap();
            assert_eq!(receipt.files, 2);
            assert_eq!(restore(&original, &receipt).status, RollbackStatus::RolledBack);
            assert!(!original.join("helper.cjs").exists());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
            assert_eq!(fs::read(receipt_directory(&original, &receipt).join("1.retired")).unwrap(), helper);
            assert_eq!(fs::read(candidate.join("helper.cjs")).unwrap(), helper);
            fs::write(original.join("helper.cjs"), b"later independent work").unwrap();
            assert_eq!(restore(&original, &receipt).status, RollbackStatus::AlreadyRolledBack);
            assert_eq!(fs::read(original.join("helper.cjs")).unwrap(), b"later independent work");
        }

        #[test]
        fn a_creation_only_plan_is_applied_not_reported_as_unchanged() {
            let (root, original, candidate) = pair();
            fs::write(candidate.join("case.test.cjs"), fs::read(original.join("case.test.cjs")).unwrap()).unwrap();
            fs::write(candidate.join("empty.dat"), b"").unwrap();
            fs::write(candidate.join("binary.dat"), [0_u8, 255, 10, 13]).unwrap();
            let native = controlled_native(root.path());
            let report = apply_current(&original, &candidate, &native);
            assert_eq!(report.status, "APPLIED", "{report:?}");
            assert!(report.changes.iter().all(|change| change.kind == "create"));
            assert_eq!(fs::read(original.join("empty.dat")).unwrap(), b"");
            assert_eq!(fs::read(original.join("binary.dat")).unwrap(), [0, 255, 10, 13]);
            let receipt = report.source_transaction.unwrap();
            assert_eq!(receipt.files, 2);
            assert_eq!(restore(&original, &receipt).status, rewrite_transaction::rollback::RollbackStatus::RolledBack);
            assert!(!original.join("empty.dat").exists() && !original.join("binary.dat").exists());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
        }

        #[test]
        fn a_failed_live_comparison_installs_neither_new_helpers_nor_replacements() {
            let (_root, original, candidate) = pair();
            fs::write(candidate.join("helper.cjs"), b"module.exports = 42;").unwrap();
            let rejected = apply_current(&original, &candidate, Path::new("/bin/false"));
            assert_eq!(rejected.status, "REJECTED", "{rejected:?}");
            assert_eq!(rejected.validation.as_ref().unwrap().verdict, "FAIL");
            assert!(rejected.source_transaction.is_none());
            assert!(!original.join("helper.cjs").exists());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
            assert!(rewrite_transaction::rollback::run(&original, None, false).history.is_empty());
        }

        #[test]
        fn a_passing_guest_cannot_redefine_a_new_file_or_overwrite_a_new_collision() {
            for original_target in [false, true] {
                let (root, original, candidate) = pair();
                fs::write(candidate.join("helper.cjs"), b"reviewed helper").unwrap();
                let target = if original_target { &original } else { &candidate };
                let source = format!("require('fs').writeFileSync({},'independent new bytes');\n",
                    serde_json::to_string(&target.join("helper.cjs")).unwrap());
                fs::write(original.join("case.test.cjs"), &source).unwrap();
                fs::write(candidate.join("case.test.cjs"), format!("{source}// candidate\n")).unwrap();
                let native = controlled_native(root.path());
                let report = apply_current(&original, &candidate, &native);
                assert_eq!(report.validation.as_ref().unwrap().verdict, "PASS");
                assert_eq!(report.status, "ERROR", "{report:?}");
                assert!(report.source_transaction.is_none());
                assert_eq!(fs::read(target.join("helper.cjs")).unwrap(), b"independent new bytes");
                assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), source.as_bytes());
                assert!(rewrite_transaction::rollback::run(&original, None, false).history.is_empty());
            }
        }

        #[test]
        fn later_reviewed_replacement_of_a_created_helper_preserves_reverse_recovery() {
            use rewrite_transaction::rollback::RollbackStatus;
            let (root, original, candidate) = pair();
            let native = controlled_native(root.path());
            fs::write(candidate.join("helper.cjs"), b"first helper").unwrap();
            let first_report = apply_current(&original, &candidate, &native);
            assert_eq!(first_report.status, "APPLIED", "{first_report:?}");
            let first = first_report.source_transaction.unwrap();
            let next = root.path().join("next-candidate");
            next_candidate(&original, &next, b"globalThis.answer = 42;\n");
            fs::write(next.join("helper.cjs"), b"second helper").unwrap();
            let second_report = apply_current(&original, &next, &native);
            assert_eq!(second_report.status, "APPLIED", "{second_report:?}");
            let second = second_report.source_transaction.unwrap();
            assert_eq!(restore(&original, &first).status, RollbackStatus::Conflict);
            assert_eq!(fs::read(original.join("helper.cjs")).unwrap(), b"second helper");
            assert_eq!(restore(&original, &second).status, RollbackStatus::RolledBack);
            assert_eq!(fs::read(original.join("helper.cjs")).unwrap(), b"first helper");
            assert_eq!(restore(&original, &first).status, RollbackStatus::RolledBack);
            assert!(!original.join("helper.cjs").exists());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"globalThis.answer = 40 + 2;\n");
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    {
        let cancellation = validation_suite::product_oracle::CancellationToken::default();
        let result = (|| {
            if matches!(&args.action, Action::Apply { .. }) {
                linux::install_signal_handler(&cancellation)?;
            }
            linux::run(args, &cancellation)
        })();
        let (output, exit_code) = match result {
            Ok(report) => {
                let exit_code = linux::exit_code(&report);
                (serde_json::to_value(report).expect("bounded JSON report"), exit_code)
            }
            Err(error) => {
                let cancelled = cancellation.is_cancelled();
                (serde_json::json!({
                    "schema_version": "franken-node/reviewed-migration-apply/v1",
                    "status": if cancelled { "CANCELLED" } else { "ERROR" },
                    "cancellation_requested": cancelled,
                    "installation_started": false,
                    "release_certification": false, "errors": [format!("{error:#}")]
                }), if cancelled { 130 } else { 1 })
            }
        };
        // A broken output pipe after a commit is not a rollback. The retained
        // native journal remains authoritative when command output is lost.
        if let Err(error) = serde_json::to_writer_pretty(std::io::stdout().lock(), &output) {
            eprintln!("cannot publish migration report; inspect retained transaction history: {error}");
            return ExitCode::from(1);
        }
        ExitCode::from(exit_code)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        eprintln!("reviewed migration installation is supported on Linux only");
        ExitCode::from(2)
    }
}
