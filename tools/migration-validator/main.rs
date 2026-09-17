#![forbid(unsafe_code)]

//! Native migration suite entrypoint. The implementation modules below are the
//! product's actual executor and supervisor, not copied or test-only substitutes.

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/smoke_supervisor.rs"]
mod smoke_supervisor;
#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/validation_suite.rs"]
pub mod validation_suite;

/// Compare original/rewritten project tests on Node and native franken-node.
/// Runs trusted code with your authority in independent workspace copies.
/// This is scoped behavioral comparison, not an OS sandbox or release certificate.
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Project directory, or a capsule file with --replay, --inspect-capsule or --export-inputs.
    project: PathBuf,
    /// Rewritten candidate tree. Defaults to the original captured input.
    #[arg(long)]
    migrated_project: Option<PathBuf>,
    /// Also compare persistent workspace changes; .git and root .franken-node excluded.
    #[arg(long)]
    compare_filesystem: bool,
    /// Trusted installed franken-node executable, outside both project trees.
    #[arg(long, required_unless_present_any = ["list_tests", "inspect_capsule", "export_inputs"])]
    native_bin: Option<PathBuf>,
    /// Select the trusted Bun reference for three-runtime comparison, capture or replay.
    #[arg(long, requires_all = ["execute", "native_bin"], conflicts_with_all = ["list_tests", "inspect_capsule", "export_inputs", "minimize_capsule", "source_file", "max_executions", "minimize_seconds", "confirmations"])]
    bun_bin: Option<PathBuf>,
    /// Approve execution of trusted project or captured code on the selected runtimes.
    #[arg(long)]
    execute: bool,
    /// Inspect the captured test inventory without resolving runtimes or executing project code.
    #[arg(long, conflicts_with_all = ["execute", "native_bin", "migrated_project", "compare_filesystem", "capture_capsule", "replay", "inspect_capsule"])]
    list_tests: bool,
    /// Save sensitive input bytes and complete measured evidence to a new private capsule.
    #[arg(long, requires = "execute", conflicts_with_all = ["list_tests", "replay", "inspect_capsule"])]
    capture_capsule: Option<PathBuf>,
    /// Inspect either capsule schema without resolving or running any recorded executable.
    #[arg(long, conflicts_with_all = ["execute", "native_bin", "migrated_project", "compare_filesystem", "capture_capsule", "list_tests", "replay"])]
    inspect_capsule: bool,
    /// Reexecute a capsule using trusted local runtimes, not commands imported from the capsule.
    #[arg(long, group = "pinned_capsule_mode", requires_all = ["execute", "expected_sha256"], conflicts_with_all = ["migrated_project", "compare_filesystem", "capture_capsule", "list_tests", "inspect_capsule"])]
    replay: bool,
    /// Independently trusted capsule content hash. A checksum from an untrusted capsule is not authentication.
    #[arg(long, requires = "pinned_capsule_mode")]
    expected_sha256: Option<String>,
    /// Export pinned original/candidate trees into a new private directory without running code.
    // Conflicts override requirements in Clap: requiring replay indirectly is
    // not enough when export itself conflicts with replay. State every unsafe
    // combination explicitly rather than relying on transitive requirements.
    #[arg(long, group = "pinned_capsule_mode", requires = "expected_sha256", conflicts_with_all = ["execute", "native_bin", "migrated_project", "compare_filesystem", "capture_capsule", "list_tests", "inspect_capsule", "replay", "verify_fix", "minimize_capsule", "source_file", "max_executions", "minimize_seconds", "confirmations"])]
    export_inputs: Option<PathBuf>,
    /// Permit a changed candidate runtime while requiring every reference observation to remain unchanged.
    #[arg(long, requires = "replay")]
    verify_fix: bool,
    /// Reduce a pinned two-runtime failing capsule and save a newly confirmed private replay capsule.
    #[arg(long, requires = "replay", conflicts_with = "verify_fix")]
    minimize_capsule: Option<PathBuf>,
    /// Source file to reduce in the captured trees; repeat to select supporting sources.
    #[arg(long, requires = "minimize_capsule")]
    source_file: Vec<String>,
    /// Maximum full-suite executions, including initial and final confirmations (default 128).
    #[arg(long, requires = "minimize_capsule")]
    max_executions: Option<usize>,
    /// Total reduction seconds, reserving 20 percent for final verification (default 120).
    #[arg(long, requires = "minimize_capsule")]
    minimize_seconds: Option<u64>,
    /// Repeated confirmations for seed, accepted reductions and final result (default 2).
    #[arg(long, requires = "minimize_capsule")]
    confirmations: Option<usize>,
    /// New private JSON report outside input projects. JSON is also printed.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn run(args: &Args) -> anyhow::Result<serde_json::Value> {
    use anyhow::{Context, ensure};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use validation_suite::native_replay;
    use native_replay::failure_capture::product;

    // Keep the same consent boundary for library/test callers that bypass Clap.
    ensure!(args.bun_bin.is_none() || (!args.list_tests && !args.inspect_capsule
        && args.export_inputs.is_none() && args.minimize_capsule.is_none()
        && args.source_file.is_empty() && args.max_executions.is_none()
        && args.minimize_seconds.is_none() && args.confirmations.is_none()),
        "--bun-bin cannot be combined with offline inspection/export or two-runtime minimization");
    let modes = u8::from(args.list_tests) + u8::from(args.inspect_capsule) + u8::from(args.replay)
        + u8::from(args.export_inputs.is_some());
    ensure!(modes <= 1, "--list-tests, --inspect-capsule, --export-inputs and --replay are mutually exclusive");
    let no_execution = args.list_tests || args.inspect_capsule || args.export_inputs.is_some();
    ensure!(!no_execution || (!args.execute && args.native_bin.is_none() && args.migrated_project.is_none()
        && !args.compare_filesystem && args.capture_capsule.is_none()),
        "--list-tests, --inspect-capsule and --export-inputs cannot be combined with execution or runtime-comparison options");
    ensure!(args.replay || args.export_inputs.is_some() || args.expected_sha256.is_none(),
        "--expected-sha256 requires --replay or --export-inputs");
    ensure!(args.replay || !args.verify_fix, "--verify-fix requires --replay");
    ensure!(args.export_inputs.is_none() || args.expected_sha256.is_some(), "--export-inputs requires --expected-sha256");
    ensure!(!args.replay || (args.expected_sha256.is_some() && args.migrated_project.is_none()
        && !args.compare_filesystem && args.capture_capsule.is_none()),
        "--replay requires --expected-sha256 and cannot override captured inputs or comparison scope");
    ensure!(no_execution || args.execute, "--execute is required: projects run with your authority");
    ensure!(no_execution || args.native_bin.is_some(), "--native-bin is required for execution");
    ensure!(args.minimize_capsule.is_none() || (args.replay && !args.verify_fix),
        "--minimize-capsule requires --replay and cannot be combined with --verify-fix");
    ensure!(args.minimize_capsule.is_some() || (args.source_file.is_empty()
        && args.max_executions.is_none() && args.minimize_seconds.is_none() && args.confirmations.is_none()),
        "reduction source and budget options require --minimize-capsule");
    let reduction_options = native_replay::minimizer::Options {
        source_files: args.source_file.clone(), max_executions: args.max_executions.unwrap_or(128),
        seconds: args.minimize_seconds.unwrap_or(120), confirmations: args.confirmations.unwrap_or(2),
    };
    if args.minimize_capsule.is_some() { reduction_options.validate()?; }

    let capsule_mode = args.inspect_capsule || args.replay || args.export_inputs.is_some();
    let project = if capsule_mode { None } else { Some(args.project.canonicalize().context("resolve project")?) };
    let migrated_project = args.migrated_project.as_deref().map(|path| path.canonicalize())
        .transpose().context("resolve migrated project")?;
    let roots: Vec<_> = project.iter().chain(migrated_project.iter()).map(PathBuf::as_path).collect();
    let destination = args.out.as_deref().map(|path| native_replay::output_destination(path, &roots)).transpose()?;
    let capsule_destination = args.capture_capsule.as_deref()
        .map(|path| native_replay::output_destination(path, &roots)).transpose()?;
    let reduced_destination = args.minimize_capsule.as_deref()
        .map(|path| native_replay::output_destination(path, &roots)).transpose()?;
    let export_destination = args.export_inputs.as_deref()
        .map(|path| native_replay::output_destination(path, &roots)).transpose()?;
    if let (Some(report), Some(capsule)) = (&destination, &capsule_destination) {
        ensure!(report != capsule, "report and capsule require distinct output paths");
    }
    if let (Some(report), Some(capsule)) = (&destination, &reduced_destination) {
        ensure!(report != capsule, "report and reduced capsule require distinct output paths");
    }
    if let (Some(report), Some(directory)) = (&destination, &export_destination) {
        ensure!(report != directory, "report and exported directory require distinct output paths");
    }

    let mut result = if let Some(destination) = &export_destination {
        serde_json::to_value(product::export_any(&args.project,
            args.expected_sha256.as_deref().context("trusted capsule hash missing")?, destination)?)?
    } else if args.inspect_capsule {
        // Keep the original path: do not canonicalize away an input symlink
        // before either capsule reader's NOFOLLOW/regular-file checks.
        let mut value = serde_json::to_value(product::inspect_any(&args.project)?)?;
        value["verdict"] = "INTEGRITY_VALID".into();
        value
    } else if let Some(path) = &reduced_destination {
        let reduced = native_replay::minimizer::minimize(&args.project,
            args.expected_sha256.as_deref().context("trusted capsule hash missing")?,
            args.native_bin.as_deref().context("native runtime missing")?, &reduction_options)?;
        let mut value = serde_json::to_value(&reduced.report)?;
        match reduced.write_capsule(path) {
            Ok(summary) => {
                value["capsule"] = serde_json::to_value(summary)?;
                value["capsule_path"] = path.to_string_lossy().as_ref().into();
            }
            Err(error) => {
                value["minimization_verdict"] = reduced.report.verdict.clone().into();
                value["verdict"] = "ERROR".into();
                value["capsule_publication_error"] = format!("{error:#}").into();
            }
        }
        value
    } else if args.replay {
        let pin = args.expected_sha256.as_deref().context("trusted capsule hash missing")?;
        let native = args.native_bin.as_deref().context("native runtime missing")?;
        // Explicit runtime selection determines the executable path. The
        // selected reader must accept the pinned schema; neither reader drops
        // observations or silently falls back to the other format.
        if let Some(bun) = args.bun_bin.as_deref() {
            serde_json::to_value(product::replay(&args.project, pin, native, bun, args.verify_fix)?)?
        } else {
            serde_json::to_value(native_replay::replay(&args.project, pin, native, args.verify_fix)?)?
        }
    } else if args.list_tests {
        use std::time::{Duration, Instant};
        let project = project.as_deref().context("project missing")?;
        let captured = validation_suite::rewrite_candidate::RewriteCandidate::capture(
            project, Instant::now() + Duration::from_secs(300))?;
        let tests = captured.test_inventory()?;
        serde_json::json!({
            "schema_version": "franken-node/migration-test-inventory/v1",
            "scope": "captured-test-inventory-only",
            "verdict": "INVENTORY",
            "project": project,
            "input_sha256": captured.input_sha256(),
            "total_tests": tests.len(),
            "tests": tests,
            "execution_performed": false,
            "release_certification": false,
        })
    } else if let Some(bun) = args.bun_bin.as_deref() {
        let project = project.as_deref().context("project missing")?;
        let native = args.native_bin.as_deref().context("native runtime missing")?;
        if let Some(path) = &capsule_destination {
            let captured = product::capture_project(project, migrated_project.as_deref(), native, bun, args.compare_filesystem)?;
            let mut value = serde_json::to_value(&captured.report)?;
            match captured.write_capsule(path) {
                Ok(summary) => {
                    value["capsule"] = serde_json::to_value(summary)?;
                    value["capsule_path"] = path.to_string_lossy().as_ref().into();
                }
                Err(error) => {
                    value["measured_verdict"] = captured.report.verdict.clone().into();
                    value["verdict"] = "ERROR".into();
                    value["capsule_publication_error"] = format!("{error:#}").into();
                }
            }
            value
        } else {
            serde_json::to_value(validation_suite::product_oracle::run_project_comparison(
                project, migrated_project.as_deref(), native, bun, args.compare_filesystem)?)?
        }
    } else if let Some(capsule_path) = &capsule_destination {
        let captured = native_replay::capture_project(project.as_deref().context("project missing")?,
            migrated_project.as_deref(), args.native_bin.as_deref().context("native runtime missing")?,
            args.compare_filesystem)?;
        let mut value = serde_json::to_value(&captured.report)?;
        match captured.write_capsule(capsule_path) {
            Ok(summary) => {
                value["capsule"] = serde_json::to_value(summary)?;
                value["capsule_path"] = capsule_path.to_string_lossy().as_ref().into();
            }
            Err(error) => {
                value["measured_verdict"] = captured.report.verdict.clone().into();
                value["verdict"] = "ERROR".into();
                value["capsule_publication_error"] = format!("{error:#}").into();
            }
        }
        value
    } else {
        serde_json::to_value(validation_suite::run_project_comparison(project.as_deref().context("project missing")?,
            migrated_project.as_deref(), args.native_bin.as_deref().context("native runtime missing")?,
            args.compare_filesystem)?)?
    };
    if let Some(destination) = destination {
        let publish = (|| -> anyhow::Result<()> {
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(&destination).context("create report without overwriting an existing file")?;
            serde_json::to_writer_pretty(&mut file, &result)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = publish {
            // Preserve completed measurements on stdout even if publication
            // fails. A partial new file may remain on I/O failure.
            result["verdict"] = "ERROR".into();
            result["publication_error"] = format!("{error:#}").into();
        } else {
            result["report_path"] = destination.to_string_lossy().as_ref().into();
        }
    }
    Ok(result)
}

#[cfg(not(target_os = "linux"))]
fn run(_args: &Args) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("native project suite supervision currently requires Linux")
}

fn result_exit_code(result: &serde_json::Value) -> u8 {
    match result["verdict"].as_str() {
        Some("PASS" | "INVENTORY" | "INTEGRITY_VALID" | "REPRODUCED" | "FIX_VERIFIED" | "REDUCED" | "EXPORTED") => 0,
        Some("FAIL" | "DIVERGED" | "FIX_NOT_VERIFIED" | "UNCHANGED") => 1,
        _ => 2,
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let result = run(&args).unwrap_or_else(|error| serde_json::json!({
        "schema_version": "franken-node/native-validation-suite-error/v1",
        "verdict": "ERROR", "error": format!("{error:#}"), "release_certification": false
    }));
    let exit = result_exit_code(&result);
    println!("{}", serde_json::to_string_pretty(&result).expect("serializable report"));
    ExitCode::from(exit)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn arguments(project: PathBuf) -> Args {
        Args { project, migrated_project: None, compare_filesystem: false,
            native_bin: Some("missing-runtime".into()), bun_bin: None, execute: true, list_tests: false,
            capture_capsule: None, inspect_capsule: false, replay: false,
            expected_sha256: None, export_inputs: None, verify_fix: false, minimize_capsule: None,
            source_file: Vec::new(), max_executions: None, minimize_seconds: None,
            confirmations: None, out: None }
    }

    fn inspection(project: PathBuf) -> Args {
        Args { native_bin: None, execute: false, list_tests: true, ..arguments(project) }
    }

    #[test]
    fn execution_requires_explicit_consent_before_any_project_access() {
        let args = Args { execute: false, ..arguments("missing-project".into()) };
        assert!(run(&args).unwrap_err().to_string().contains("--execute"));
    }

    #[test]
    fn existing_report_is_preserved_without_executing() {
        let project = tempfile::tempdir().unwrap();
        let destination = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(destination.path(), "keep").unwrap();
        let args = Args { out: Some(destination.path().into()), ..arguments(project.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(destination.path()).unwrap(), "keep");
    }

    #[test]
    fn report_under_input_tree_is_rejected_before_executing() {
        let project = tempfile::tempdir().unwrap();
        let args = Args { out: Some(project.path().join("report.json")), ..arguments(project.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("outside"));
        assert!(!project.path().join("report.json").exists());
    }

    #[test]
    fn empty_project_cannot_produce_a_passing_report() {
        let project = tempfile::tempdir().unwrap();
        let args = Args { native_bin: Some("/bin/false".into()), ..arguments(project.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("no tests"));
    }

    #[test]
    fn real_process_failure_exports_private_measurements_without_claiming_native_parity() {
        use std::os::unix::fs::PermissionsExt;
        let project = tempfile::tempdir().unwrap();
        let reports = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("case.test.js"), "console.log('reference');").unwrap();
        // A real deliberately failing executable proves the CLI retains FAIL.
        // It is not a fake franken-node implementation or a compatibility claim.
        let args = Args { native_bin: Some("/bin/false".into()), out: Some(reports.path().join("report.json")),
            ..arguments(project.path().into()) };
        let report = run(&args).unwrap();
        assert_eq!(report["verdict"], "FAIL");
        assert_eq!(report["failed"], 1);
        assert_eq!(report["cases"][0]["reference"]["exit_code"], 0);
        assert_eq!(report["cases"][0]["native"]["exit_code"], 1);
        let path = args.out.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let persisted: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(persisted["cases"], report["cases"]);
    }

    #[test]
    fn clap_exposes_rewritten_input_and_filesystem_comparison() {
        let args = Args::try_parse_from(["suite", "original", "--migrated-project", "rewritten",
            "--compare-filesystem", "--native-bin", "/trusted/franken-node", "--execute"]).unwrap();
        assert_eq!(args.migrated_project, Some(PathBuf::from("rewritten")));
        assert!(args.compare_filesystem);
        assert!(args.execute);
    }

    #[test]
    fn report_under_candidate_or_its_symlink_alias_is_rejected_before_execution() {
        let reference = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        let aliases = tempfile::tempdir().unwrap();
        let alias = aliases.path().join("candidate");
        std::os::unix::fs::symlink(candidate.path(), &alias).unwrap();
        for parent in [candidate.path(), alias.as_path()] {
            let args = Args { migrated_project: Some(candidate.path().into()), out: Some(parent.join("report.json")),
                ..arguments(reference.path().into()) };
            assert!(run(&args).unwrap_err().to_string().contains("outside"));
        }
        assert!(!candidate.path().join("report.json").exists());
    }

    #[test]
    fn cli_compares_both_input_identities_and_retains_filesystem_failure() {
        let reference = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        std::fs::write(reference.path().join("case.test.js"), "require('fs').writeFileSync('artifact','reference');").unwrap();
        std::fs::write(candidate.path().join("case.test.js"), "// deliberately not executed by /bin/false").unwrap();
        let args = Args { migrated_project: Some(candidate.path().into()), compare_filesystem: true,
            native_bin: Some("/bin/false".into()), ..arguments(reference.path().into()) };
        let report = run(&args).unwrap();
        assert_eq!(report["verdict"], "FAIL");
        assert_ne!(report["input_sha256"], report["candidate_input_sha256"]);
        assert_eq!(report["filesystem_comparison"], true);
        assert_eq!(report["cases"][0]["reference"]["workspace_delta"]["changed_paths"], 1);
        assert_eq!(report["cases"][0]["native"]["workspace_delta"]["changed_paths"], 0);
        assert!(report["cases"][0]["divergences"].as_array().unwrap().iter()
            .any(|entry| entry == "filesystem:workspace_delta_mismatch"));
        assert!(!reference.path().join("artifact").exists());
    }

    #[test]
    fn cli_inventory_errors_precede_native_resolution() {
        let reference = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        std::fs::write(reference.path().join("case.test.js"), "// original").unwrap();
        std::fs::write(candidate.path().join("different.test.js"), "// renamed").unwrap();
        let args = Args { migrated_project: Some(candidate.path().into()), ..arguments(reference.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("test inventories differ"));
    }

    #[test]
    fn clap_allows_inventory_without_a_runtime_but_not_ambiguous_execution() {
        let args = Args::try_parse_from(["suite", "project", "--list-tests"]).unwrap();
        assert!(args.list_tests);
        assert!(!args.execute);
        assert!(args.native_bin.is_none());
        for flags in [vec!["--execute"], vec!["--native-bin", "/trusted/runtime"],
            vec!["--migrated-project", "candidate"], vec!["--compare-filesystem"]] {
            let mut argv = vec!["suite", "project", "--list-tests"];
            argv.extend(flags);
            assert!(Args::try_parse_from(argv).is_err());
        }
        assert!(Args::try_parse_from(["suite", "project", "--execute"]).is_err());
    }

    #[test]
    fn inventory_inspection_never_executes_the_selected_code_or_resolves_a_runtime() {
        use std::os::unix::fs::PermissionsExt;
        let project = tempfile::tempdir().unwrap();
        let reports = tempfile::tempdir().unwrap();
        let marker = reports.path().join("executed");
        std::fs::create_dir(project.path().join("scripts")).unwrap();
        std::fs::create_dir(project.path().join(".franken-node")).unwrap();
        std::fs::write(project.path().join("scripts/check.js"), format!(
            "require('node:fs').writeFileSync({}, 'ran');",
            serde_json::to_string(&marker).unwrap())).unwrap();
        std::fs::write(project.path().join("fixture.test.js"), "throw new Error('helper');").unwrap();
        std::fs::write(project.path().join(".franken-node/migration-tests.json"),
            r#"{"schema_version":"franken-node/migration-tests/v1","tests":["scripts/check.js"]}"#).unwrap();
        let destination = reports.path().join("inventory.json");
        let args = Args { out: Some(destination.clone()), ..inspection(project.path().into()) };
        let report = run(&args).unwrap();
        assert_eq!(report["verdict"], "INVENTORY");
        assert_eq!(report["total_tests"], 1);
        assert_eq!(report["tests"], serde_json::json!(["scripts/check.js"]));
        assert_eq!(report["input_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(report["execution_performed"], false);
        assert_eq!(report["release_certification"], false);
        assert!(report.get("reference_runtime").is_none());
        assert!(report.get("native_runtime").is_none());
        assert!(!marker.exists());
        assert_eq!(std::fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o600);
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(destination).unwrap()).unwrap();
        assert_eq!(saved["tests"], report["tests"]);
        assert_eq!(result_exit_code(&report), 0);
    }

    #[test]
    fn inventory_errors_are_not_success_or_permission_to_execute() {
        let project = tempfile::tempdir().unwrap();
        assert!(run(&inspection(project.path().into())).unwrap_err().to_string().contains("nonempty"));
        std::fs::write(project.path().join("ok.test.js"), "console.log('ok');").unwrap();
        std::fs::create_dir(project.path().join(".franken-node")).unwrap();
        std::fs::write(project.path().join(".franken-node/migration-tests.json"), "{}").unwrap();
        assert!(run(&inspection(project.path().into())).unwrap_err().to_string().contains("invalid migration test manifest"));
        let ambiguous = Args { execute: true, ..inspection("missing-project".into()) };
        assert!(run(&ambiguous).unwrap_err().to_string().contains("--list-tests"));
        assert_eq!(result_exit_code(&serde_json::json!({"verdict": "ERROR"})), 2);
    }

    #[test]
    fn explicit_manifest_is_used_by_the_executing_cli_not_only_preflight() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("scripts")).unwrap();
        std::fs::create_dir(project.path().join(".franken-node")).unwrap();
        std::fs::write(project.path().join("scripts/check.js"), "console.log('reference');").unwrap();
        std::fs::write(project.path().join("fixture.test.js"), "process.exit(99);").unwrap();
        std::fs::write(project.path().join(".franken-node/migration-tests.json"),
            r#"{"schema_version":"franken-node/migration-tests/v1","tests":["scripts/check.js"]}"#).unwrap();
        let args = Args { native_bin: Some("/bin/false".into()), ..arguments(project.path().into()) };
        let report = run(&args).unwrap();
        assert_eq!(report["verdict"], "FAIL");
        assert_eq!(report["total_tests"], 1);
        assert_eq!(report["cases"][0]["test"], "scripts/check.js");
        assert_eq!(report["cases"][0]["reference"]["exit_code"], 0);
        assert_eq!(report["cases"][0]["native"]["exit_code"], 1);
    }

    #[test]
    fn clap_requires_explicit_replay_consent_and_hash_without_ambient_scope_overrides() {
        let inspect = Args::try_parse_from(["suite", "capsule.json", "--inspect-capsule"]).unwrap();
        assert!(inspect.inspect_capsule && !inspect.execute && inspect.native_bin.is_none());
        assert!(Args::try_parse_from(["suite", "capsule.json", "--replay", "--native-bin", "/bin/false"]).is_err());
        let pin = "0".repeat(64);
        let base = ["suite", "capsule.json", "--replay", "--native-bin", "/bin/false", "--execute", "--expected-sha256", &pin];
        let args = Args::try_parse_from(base).unwrap();
        assert!(args.replay && args.execute);
        for flags in [vec!["--compare-filesystem"], vec!["--migrated-project", "other"],
            vec!["--capture-capsule", "other.json"], vec!["--list-tests"], vec!["--inspect-capsule"]] {
            let mut argv = base.to_vec();
            argv.extend(flags);
            assert!(Args::try_parse_from(argv).is_err());
        }
        assert!(Args::try_parse_from(["suite", "project", "--native-bin", "/bin/false", "--verify-fix"]).is_err());
    }

    #[test]
    fn cli_captures_failure_inspects_offline_and_replays_from_archived_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let project = tempfile::tempdir().unwrap();
        let outputs = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("case.test.js"), "require('fs').writeFileSync('artifact','original');").unwrap();
        let capsule = outputs.path().join("capsule.json");
        let captured = run(&Args { native_bin: Some("/bin/false".into()), compare_filesystem: true,
            capture_capsule: Some(capsule.clone()), out: Some(outputs.path().join("capture-report.json")),
            ..arguments(project.path().into()) }).unwrap();
        assert_eq!(captured["verdict"], "FAIL");
        assert_eq!(result_exit_code(&captured), 1);
        assert_eq!(captured["capsule"]["captured_verdict"], "FAIL");
        assert_eq!(std::fs::metadata(&capsule).unwrap().permissions().mode() & 0o777, 0o600);
        let pin = captured["capsule"]["content_sha256"].as_str().unwrap().to_owned();
        let original_capsule = std::fs::read(&capsule).unwrap();
        std::fs::write(project.path().join("case.test.js"), "throw new Error('later source must not run');").unwrap();
        let inspected = run(&Args { native_bin: None, execute: false, inspect_capsule: true,
            ..arguments(capsule.clone()) }).unwrap();
        assert_eq!(inspected["verdict"], "INTEGRITY_VALID");
        assert_eq!(inspected["execution_performed"], false);
        assert_eq!(inspected["content_sha256"], pin);
        let replayed = run(&Args { native_bin: Some("/bin/false".into()), replay: true,
            expected_sha256: Some(pin.clone()), out: Some(outputs.path().join("replay-report.json")),
            ..arguments(capsule.clone()) }).unwrap();
        assert_eq!(replayed["verdict"], "REPRODUCED");
        assert_eq!(replayed["validation"]["verdict"], "FAIL");
        assert_eq!(replayed["validation"]["cases"], captured["cases"]);
        assert_eq!(result_exit_code(&replayed), 0);
        assert!(!project.path().join("artifact").exists());
        assert_eq!(std::fs::read(&capsule).unwrap(), original_capsule);
        // Byte-identical executable relocation is allowed without importing a
        // command from the capsule; this is still a deliberately failing tool.
        let relocated = outputs.path().join("relocated-false");
        std::fs::copy("/bin/false", &relocated).unwrap();
        let replayed = run(&Args { native_bin: Some(relocated), replay: true,
            expected_sha256: Some(pin), ..arguments(capsule) }).unwrap();
        assert_eq!(replayed["verdict"], "REPRODUCED");
    }

    #[test]
    fn capture_destinations_are_checked_before_execution_and_cannot_alias_reports() {
        let project = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let path = out.path().join("shared.json");
        let args = Args { out: Some(path.clone()), capture_capsule: Some(path.clone()),
            ..arguments(project.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("distinct"));
        assert!(!path.exists());
        let args = Args { capture_capsule: Some(project.path().join("capsule.json")),
            ..arguments(project.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("outside"));
        std::fs::write(&path, "preserve existing capsule").unwrap();
        let args = Args { capture_capsule: Some(path.clone()), ..arguments(project.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "preserve existing capsule");
    }

    #[test]
    fn programmatic_replay_refuses_missing_consent_hash_and_conflicting_modes_first() {
        for args in [
            Args { replay: true, ..arguments("missing".into()) },
            Args { replay: true, execute: false, expected_sha256: Some("0".repeat(64)), ..arguments("missing".into()) },
            Args { verify_fix: true, ..arguments("missing".into()) },
            Args { replay: true, list_tests: true, ..arguments("missing".into()) },
        ] { assert!(run(&args).is_err()); }
        for verdict in ["INTEGRITY_VALID", "REPRODUCED", "FIX_VERIFIED"] {
            assert_eq!(result_exit_code(&serde_json::json!({"verdict": verdict})), 0);
        }
        for verdict in ["DIVERGED", "FIX_NOT_VERIFIED"] {
            assert_eq!(result_exit_code(&serde_json::json!({"verdict": verdict})), 1);
        }
        assert_eq!(result_exit_code(&serde_json::json!({"verdict": "REFERENCE_DRIFT"})), 2);
    }

    #[test]
    fn incomplete_capture_keeps_process_errors_without_publishing_a_replayable_capsule() {
        let project = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("case.test.js"), "process.stdout.write('x'.repeat(17*1024*1024));").unwrap();
        let capsule = out.path().join("capsule.json");
        let report = run(&Args { native_bin: Some("/bin/false".into()), capture_capsule: Some(capsule.clone()),
            ..arguments(project.path().into()) }).unwrap();
        assert_eq!(report["verdict"], "ERROR");
        assert_eq!(report["measured_verdict"], "ERROR");
        assert!(report["cases"][0]["errors"].as_array().is_some_and(|errors| !errors.is_empty()));
        assert!(report["capsule_publication_error"].as_str().unwrap().contains("not replayable"));
        assert!(!capsule.exists());
        assert_eq!(result_exit_code(&report), 2);
    }

    #[test]
    fn clap_requires_pinned_replay_for_reduction_and_rejects_unrelated_tuning() {
        let pin = "0".repeat(64);
        let base = ["suite", "capsule.json", "--replay", "--execute", "--expected-sha256", &pin,
            "--native-bin", "/bin/false", "--minimize-capsule", "reduced.json"];
        let args = Args::try_parse_from(base).unwrap();
        assert_eq!(args.minimize_capsule, Some("reduced.json".into()));
        assert!(args.replay && args.execute && !args.verify_fix);
        let mut fix = base.to_vec();
        fix.push("--verify-fix");
        assert!(Args::try_parse_from(fix).is_err());
        assert!(Args::try_parse_from(["suite", "capsule.json", "--minimize-capsule", "reduced.json",
            "--native-bin", "/bin/false"]).is_err());
        for tuning in [vec!["--source-file", "helper.js"], vec!["--max-executions", "40"],
            vec!["--minimize-seconds", "60"], vec!["--confirmations", "3"]] {
            let mut valid = base.to_vec();
            valid.extend(tuning.iter().copied());
            assert!(Args::try_parse_from(valid).is_ok());
            let mut unrelated = vec!["suite", "project", "--native-bin", "/bin/false", "--execute"];
            unrelated.extend(tuning);
            assert!(Args::try_parse_from(unrelated).is_err());
        }
    }

    #[test]
    fn reduction_preflight_preserves_seed_and_rejects_aliased_output_before_execution() {
        let output = tempfile::tempdir().unwrap();
        let seed = output.path().join("seed.json");
        std::fs::write(&seed, "private seed must survive").unwrap();
        let reduced = output.path().join("reduced.json");
        let mut args = Args { replay: true, expected_sha256: Some("0".repeat(64)),
            minimize_capsule: Some(reduced.clone()), out: Some(reduced.clone()), ..arguments(seed.clone()) };
        assert!(run(&args).unwrap_err().to_string().contains("distinct"));
        assert!(!reduced.exists());
        args.out = None;
        args.minimize_capsule = Some(seed.clone());
        assert!(run(&args).unwrap_err().to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(seed).unwrap(), "private seed must survive");
    }

    #[test]
    fn programmatic_reduction_checks_consent_mode_and_limits_before_capsule_access() {
        let mut args = Args { replay: true, expected_sha256: Some("0".repeat(64)),
            minimize_capsule: Some("reduced.json".into()), ..arguments("absent-capsule".into()) };
        args.execute = false;
        assert!(run(&args).unwrap_err().to_string().contains("--execute"));
        args.execute = true;
        args.confirmations = Some(1);
        assert!(run(&args).unwrap_err().to_string().contains("confirmations"));
        args.confirmations = None;
        args.verify_fix = true;
        assert!(run(&args).unwrap_err().to_string().contains("--verify-fix"));
        args.verify_fix = false;
        args.minimize_capsule = None;
        args.max_executions = Some(40);
        assert!(run(&args).unwrap_err().to_string().contains("require --minimize-capsule"));
        assert_eq!(result_exit_code(&serde_json::json!({"verdict":"REDUCED"})), 0);
        assert_eq!(result_exit_code(&serde_json::json!({"verdict":"UNCHANGED"})), 1);
    }

    #[test]
    fn executing_cli_capture_reduction_inspection_and_replay_keep_the_measured_failure() {
        use std::os::unix::fs::PermissionsExt;
        let project = tempfile::tempdir().unwrap();
        let outputs = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("case.test.js"),
            "// removable\nconsole.log('reference');\n// removable tail\n").unwrap();
        let capsule = outputs.path().join("seed.json");
        // /bin/false deliberately fails; this proves orchestration and CLI
        // outcome preservation, not native Franken compatibility.
        let captured = run(&Args { native_bin: Some("/bin/false".into()), compare_filesystem: true,
            capture_capsule: Some(capsule.clone()), ..arguments(project.path().into()) }).unwrap();
        assert_eq!(captured["verdict"], "FAIL");
        let original_capsule = std::fs::read(&capsule).unwrap();
        std::fs::write(project.path().join("case.test.js"), "process.exit(99);").unwrap();
        let reduced_path = outputs.path().join("reduced.json");
        let report_path = outputs.path().join("reduction-report.json");
        let reduced = run(&Args { native_bin: Some("/bin/false".into()), replay: true,
            expected_sha256: Some(captured["capsule"]["content_sha256"].as_str().unwrap().into()),
            minimize_capsule: Some(reduced_path.clone()), max_executions: Some(32), minimize_seconds: Some(240),
            out: Some(report_path.clone()), ..arguments(capsule.clone()) }).unwrap();
        assert_eq!(reduced["verdict"], "REDUCED", "{reduced:#}");
        assert_eq!(reduced["validation"]["verdict"], "FAIL");
        assert_eq!(reduced["validation"]["cases"], captured["cases"]);
        assert!(reduced["reduced_source_bytes"].as_u64().unwrap() < reduced["original_source_bytes"].as_u64().unwrap());
        assert_eq!(result_exit_code(&reduced), 0);
        let inspected = run(&Args { native_bin: None, execute: false, inspect_capsule: true,
            ..arguments(reduced_path.clone()) }).unwrap();
        assert_eq!(inspected["content_sha256"], reduced["content_sha256"]);
        assert_eq!(inspected["captured_verdict"], "FAIL");
        let replayed = run(&Args { native_bin: Some("/bin/false".into()), replay: true,
            expected_sha256: Some(reduced["content_sha256"].as_str().unwrap().into()),
            ..arguments(reduced_path.clone()) }).unwrap();
        assert_eq!(replayed["verdict"], "REPRODUCED");
        assert_eq!(replayed["validation"]["cases"], captured["cases"]);
        for path in [&reduced_path, &report_path] {
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(std::fs::read(capsule).unwrap(), original_capsule);
        assert_eq!(std::fs::read_to_string(project.path().join("case.test.js")).unwrap(), "process.exit(99);");
    }

    #[test]
    fn clap_export_requires_a_pin_but_prohibits_runtime_execution_flags() {
        let pin = "0".repeat(64);
        let base = ["suite", "capsule.json", "--export-inputs", "fixture", "--expected-sha256", &pin];
        let args = Args::try_parse_from(base).unwrap();
        assert_eq!(args.export_inputs, Some("fixture".into()));
        assert!(!args.execute && args.native_bin.is_none());
        assert!(Args::try_parse_from(["suite", "capsule.json", "--export-inputs", "fixture"]).is_err());
        for flags in [vec!["--execute"], vec!["--native-bin", "/bin/false"], vec!["--inspect-capsule"],
            vec!["--list-tests"], vec!["--replay"], vec!["--verify-fix"], vec!["--compare-filesystem"],
            vec!["--source-file", "case.js"], vec!["--minimize-capsule", "reduced.json"],
            vec!["--max-executions", "40"], vec!["--minimize-seconds", "60"],
            vec!["--confirmations", "3"], vec!["--migrated-project", "candidate"],
            vec!["--capture-capsule", "capture.json"], vec!["--bun-bin", "/trusted/bun"]] {
            let mut argv = base.to_vec();
            argv.extend(flags);
            let error = Args::try_parse_from(&argv).expect_err("offline export must reject execution options");
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict, "{argv:?}: {error}");
        }
        assert!(Args::try_parse_from(["suite", "project", "--native-bin", "/bin/false",
            "--execute", "--expected-sha256", &pin]).is_err());
    }

    #[test]
    fn cli_export_restores_private_inputs_without_running_the_captured_program() {
        use std::os::unix::fs::PermissionsExt;
        let project = tempfile::tempdir().unwrap();
        let outputs = tempfile::tempdir().unwrap();
        let source = "require('fs').writeFileSync('executed','yes');";
        std::fs::write(project.path().join("case.test.js"), source).unwrap();
        let capsule = outputs.path().join("capsule.json");
        let captured = run(&Args { native_bin: Some("/bin/false".into()), compare_filesystem: true,
            capture_capsule: Some(capsule.clone()), ..arguments(project.path().into()) }).unwrap();
        let destination = outputs.path().join("fixture");
        let exported = run(&Args { execute: false, native_bin: None, export_inputs: Some(destination.clone()),
            expected_sha256: Some(captured["capsule"]["content_sha256"].as_str().unwrap().into()),
            ..arguments(capsule) }).unwrap();
        assert_eq!(exported["verdict"], "EXPORTED");
        assert_eq!(exported["execution_performed"], false);
        assert_eq!(exported["capsule"]["execution_performed"], false);
        assert_eq!(exported["capsule"]["captured_verdict"], "FAIL");
        assert_eq!(result_exit_code(&exported), 0);
        for tree in ["original", "candidate"] {
            assert_eq!(std::fs::read_to_string(destination.join(tree).join("case.test.js")).unwrap(), source);
            assert!(!destination.join(tree).join("executed").exists());
        }
        assert_eq!(std::fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(destination.join("reproducer.json").is_file());
    }

    #[test]
    fn programmatic_export_pin_and_destination_checks_precede_capsule_access() {
        let outputs = tempfile::tempdir().unwrap();
        let destination = outputs.path().join("fixture");
        let mut args = Args { execute: false, native_bin: None, export_inputs: Some(destination.clone()),
            ..arguments("missing-capsule".into()) };
        assert!(run(&args).unwrap_err().to_string().contains("requires --expected-sha256"));
        args.expected_sha256 = Some("0".repeat(64));
        args.out = Some(destination.clone());
        assert!(run(&args).unwrap_err().to_string().contains("distinct"));
        args.out = None;
        args.execute = true;
        assert!(run(&args).unwrap_err().to_string().contains("cannot be combined"));
        assert!(!destination.exists());
    }

    #[test]
    fn clap_three_runtime_comparison_and_capsules_require_explicit_execution() {
        let base = ["suite", "project", "--bun-bin", "/trusted/bun", "--native-bin", "/trusted/native", "--execute"];
        let args = Args::try_parse_from(base).unwrap();
        assert_eq!(args.bun_bin, Some("/trusted/bun".into()));
        assert!(Args::try_parse_from(["suite", "project", "--bun-bin", "/trusted/bun",
            "--native-bin", "/trusted/native"]).is_err());
        for flags in [vec!["--list-tests"], vec!["--inspect-capsule"], vec!["--replay"],
            vec!["--export-inputs", "export"], vec!["--verify-fix"], vec!["--minimize-capsule", "reduced.json"]] {
            let mut argv = base.to_vec();
            argv.extend(flags);
            assert!(Args::try_parse_from(&argv).is_err(), "{argv:?}");
        }
        let mut capture = base.to_vec();
        capture.extend(["--migrated-project", "candidate", "--compare-filesystem", "--capture-capsule", "capsule.json"]);
        assert!(Args::try_parse_from(capture).is_ok());
        let pin = "0".repeat(64);
        let mut replay = base.to_vec();
        replay.extend(["--replay", "--expected-sha256", &pin, "--verify-fix"]);
        assert!(Args::try_parse_from(replay).is_ok());
    }

    #[test]
    fn three_runtime_cli_keeps_failed_reference_evidence_and_nonzero_exit() {
        use std::os::unix::fs::PermissionsExt;
        let project = tempfile::tempdir().unwrap();
        let outputs = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("case.test.js"), "console.log(42);").unwrap();
        let destination = outputs.path().join("product.json");
        // Real failing executables test error classification, not Bun/Franken parity.
        let args = Args { native_bin: Some("/bin/false".into()), bun_bin: Some("/bin/false".into()),
            compare_filesystem: true, out: Some(destination.clone()), ..arguments(project.path().into()) };
        let report = run(&args).unwrap();
        assert_eq!(report["schema_version"], "franken-node/product-validation-suite/v1");
        assert_eq!(report["verdict"], "INCONCLUSIVE");
        assert_eq!(report["reference_failures"], 1);
        assert_eq!(report["cases"][0]["node"]["exit_code"], 0);
        assert_eq!(report["cases"][0]["bun"]["exit_code"], 1);
        assert_eq!(report["cases"][0]["native"]["exit_code"], 1);
        assert_eq!(report["release_certification"], false);
        assert_eq!(result_exit_code(&report), 2);
        assert_eq!(std::fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o600);
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(destination).unwrap()).unwrap();
        assert_eq!(saved["cases"], report["cases"]);
    }

    #[test]
    fn three_runtime_preflight_and_consent_precede_project_execution() {
        let mut args = Args { bun_bin: Some("missing-bun".into()), execute: false,
            ..arguments("missing-project".into()) };
        assert!(run(&args).unwrap_err().to_string().contains("--execute"));
        args.execute = true;
        args.minimize_capsule = Some("reduced.json".into());
        assert!(run(&args).unwrap_err().to_string().contains("two-runtime minimization"));
        let project = tempfile::tempdir().unwrap();
        let args = Args { bun_bin: Some("missing-bun".into()), out: Some(project.path().join("report.json")),
            ..arguments(project.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("outside"));
        assert!(!project.path().join("report.json").exists());
    }

    #[test]
    fn three_runtime_capsule_cli_retains_all_legs_through_replay_fix_and_offline_export() {
        use std::os::unix::fs::PermissionsExt;
        let project = tempfile::tempdir().unwrap();
        let outputs = tempfile::tempdir().unwrap();
        let source = "globalThis.answer = 42;";
        std::fs::write(project.path().join("case.test.js"), source).unwrap();
        let capsule = outputs.path().join("product-capsule.json");
        // Deliberately empty successful reference and failing candidate test
        // archive dispatch, not genuine Bun/Franken implementation semantics.
        let captured = run(&Args { bun_bin: Some("/bin/true".into()), native_bin: Some("/bin/false".into()),
            compare_filesystem: true, capture_capsule: Some(capsule.clone()), ..arguments(project.path().into()) }).unwrap();
        assert_eq!(captured["verdict"], "FAIL");
        assert_eq!(result_exit_code(&captured), 1);
        assert_eq!(captured["capsule"]["schema_version"], "franken-node/product-migration-capsule/v1");
        let pin = captured["capsule"]["content_sha256"].as_str().unwrap().to_owned();
        let saved_bytes = std::fs::read(&capsule).unwrap();
        std::fs::write(project.path().join("case.test.js"), "process.exit(99);").unwrap();
        let inspected = run(&Args { inspect_capsule: true, execute: false, native_bin: None,
            ..arguments(capsule.clone()) }).unwrap();
        assert_eq!(inspected["content_sha256"], pin);
        assert_eq!(inspected["execution_performed"], false);
        let mut replay = Args { replay: true, expected_sha256: Some(pin.clone()),
            bun_bin: Some("/bin/true".into()), native_bin: Some("/bin/false".into()), ..arguments(capsule.clone()) };
        let replayed = run(&replay).unwrap();
        assert_eq!(replayed["verdict"], "REPRODUCED");
        assert_eq!(replayed["validation"]["cases"], captured["cases"]);
        replay.verify_fix = true;
        replay.native_bin = Some("/bin/true".into());
        let fixed = run(&replay).unwrap();
        assert_eq!(fixed["verdict"], "FIX_VERIFIED");
        assert_eq!(fixed["validation"]["passed"], 1);
        let destination = outputs.path().join("fixture");
        let exported = run(&Args { native_bin: None, execute: false, expected_sha256: Some(pin),
            export_inputs: Some(destination.clone()), ..arguments(capsule.clone()) }).unwrap();
        assert_eq!(exported["verdict"], "EXPORTED");
        assert_eq!(std::fs::read_to_string(destination.join("original/case.test.js")).unwrap(), source);
        let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(destination.join("reproducer.json")).unwrap()).unwrap();
        assert_eq!(manifest["expected"]["cases"], captured["cases"]);
        assert_eq!(std::fs::metadata(&capsule).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(capsule).unwrap(), saved_bytes);
    }

    #[test]
    fn three_runtime_capsule_cannot_be_replayed_or_minimized_by_dropping_bun() {
        let project = tempfile::tempdir().unwrap();
        let outputs = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("case.test.js"), "console.log(42);").unwrap();
        let capsule = outputs.path().join("product-capsule.json");
        let captured = run(&Args { bun_bin: Some("/bin/true".into()), native_bin: Some("/bin/false".into()),
            capture_capsule: Some(capsule.clone()), ..arguments(project.path().into()) }).unwrap();
        assert_eq!(captured["verdict"], "INCONCLUSIVE");
        let mut args = Args { replay: true, expected_sha256: Some(captured["capsule"]["content_sha256"].as_str().unwrap().into()),
            native_bin: Some("/absent/native".into()), ..arguments(capsule) };
        assert!(run(&args).unwrap_err().to_string().contains("invalid native migration capsule"));
        args.minimize_capsule = Some(outputs.path().join("reduced.json"));
        assert!(run(&args).is_err());
        assert!(!outputs.path().join("reduced.json").exists());
        args.minimize_capsule = None;
        args.bun_bin = Some("/bin/true".into());
        args.execute = false;
        assert!(run(&args).unwrap_err().to_string().contains("--execute"));
    }

    #[test]
    fn three_runtime_capture_failure_preserves_errors_and_other_runtime_observations() {
        let project = tempfile::tempdir().unwrap();
        let outputs = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("case.test.js"), "process.stdout.write('x'.repeat(17*1024*1024));").unwrap();
        let capsule = outputs.path().join("incomplete.json");
        let report = run(&Args { native_bin: Some("/bin/false".into()), bun_bin: Some("/bin/true".into()),
            capture_capsule: Some(capsule.clone()), ..arguments(project.path().into()) }).unwrap();
        assert_eq!(report["verdict"], "ERROR");
        assert_eq!(report["measured_verdict"], "ERROR");
        assert_eq!(report["cases"][0]["bun"]["exit_code"], 0);
        assert!(!report["cases"][0]["errors"].as_array().unwrap().is_empty());
        assert!(report["capsule_publication_error"].as_str().unwrap().contains("not replayable"));
        assert!(!capsule.exists());
    }
}
