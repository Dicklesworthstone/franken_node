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
    /// Original project containing JS/TS test/spec files. No scripts are inferred.
    project: PathBuf,
    /// Rewritten candidate tree. Defaults to the original captured input.
    #[arg(long)]
    migrated_project: Option<PathBuf>,
    /// Also compare persistent workspace changes; .git and root .franken-node excluded.
    #[arg(long)]
    compare_filesystem: bool,
    /// Trusted installed franken-node executable, outside both project trees.
    #[arg(long)]
    native_bin: PathBuf,
    /// Approve execution of trusted project code on both runtimes.
    #[arg(long)]
    execute: bool,
    /// New private JSON report outside both projects. JSON is also printed.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn run(args: &Args) -> anyhow::Result<serde_json::Value> {
    use anyhow::{Context, ensure};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    ensure!(args.execute, "--execute is required: projects run with your authority");
    let project = args.project.canonicalize().context("resolve project")?;
    let migrated_project = args.migrated_project.as_deref().map(|path| path.canonicalize())
        .transpose().context("resolve migrated project")?;
    let candidate = migrated_project.as_deref().unwrap_or(&project);
    let destination = if let Some(destination) = &args.out {
        ensure!(std::fs::symlink_metadata(destination).is_err_and(|error|
            error.kind() == std::io::ErrorKind::NotFound), "report destination already exists or cannot be inspected");
        let parent = destination.parent().filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let parent = parent.canonicalize().context("resolve report parent")?;
        ensure!(!parent.starts_with(&project) && !parent.starts_with(candidate),
            "report must be outside both measured projects");
        Some(parent.join(destination.file_name().context("report filename missing")?))
    } else { None };
    let report = validation_suite::run_project_comparison(&project, migrated_project.as_deref(),
        &args.native_bin, args.compare_filesystem)?;
    let mut result = serde_json::to_value(&report)?;
    if let Some(destination) = destination {
        let publish = (|| -> anyhow::Result<()> {
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(&destination).context("create report without overwriting an existing file")?;
            serde_json::to_writer_pretty(&mut file, &report)?;
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

fn main() -> ExitCode {
    let args = Args::parse();
    let result = run(&args).unwrap_or_else(|error| serde_json::json!({
        "schema_version": "franken-node/native-validation-suite-error/v1",
        "verdict": "ERROR", "error": format!("{error:#}"), "release_certification": false
    }));
    let exit = match result["verdict"].as_str() { Some("PASS") => 0, Some("FAIL") => 1, _ => 2 };
    println!("{}", serde_json::to_string_pretty(&result).expect("serializable report"));
    ExitCode::from(exit)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn arguments(project: PathBuf) -> Args {
        Args { project, migrated_project: None, compare_filesystem: false,
            native_bin: "missing-runtime".into(), execute: true, out: None }
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
        let args = Args { native_bin: "/bin/false".into(), ..arguments(project.path().into()) };
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
        let args = Args { native_bin: "/bin/false".into(), out: Some(reports.path().join("report.json")),
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
            native_bin: "/bin/false".into(), ..arguments(reference.path().into()) };
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
}
