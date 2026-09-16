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

/// Compare project tests on Node and an explicitly selected native franken-node.
/// Runs trusted code with your authority in independent workspace copies.
/// This is exact process-output comparison, not an OS sandbox or release certificate.
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Project containing JS/TS test/spec files. No package scripts are inferred.
    project: PathBuf,
    /// Trusted installed franken-node executable, outside the project tree.
    #[arg(long)]
    native_bin: PathBuf,
    /// Approve execution of trusted project code on both runtimes.
    #[arg(long)]
    execute: bool,
    /// New private JSON report file, outside the project. JSON is also printed.
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
    let destination = if let Some(destination) = &args.out {
        ensure!(std::fs::symlink_metadata(destination).is_err_and(|error|
            error.kind() == std::io::ErrorKind::NotFound), "report destination already exists or cannot be inspected");
        let parent = destination.parent().filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let parent = parent.canonicalize().context("resolve report parent")?;
        ensure!(!parent.starts_with(&project), "report must be outside the measured project");
        Some(parent.join(destination.file_name().context("report filename missing")?))
    } else { None };
    let report = validation_suite::run_project(&project, &args.native_bin)?;
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
            // Preserve the completed measurements on stdout even if report
            // publication fails. A partial new file may remain on I/O failure.
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

    #[test]
    fn execution_requires_explicit_consent_before_any_project_access() {
        let args = Args { project: "missing-project".into(), native_bin: "missing-runtime".into(), execute: false, out: None };
        assert!(run(&args).unwrap_err().to_string().contains("--execute"));
    }

    #[test]
    fn existing_report_is_preserved_without_executing() {
        let project = tempfile::tempdir().unwrap();
        let destination = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(destination.path(), "keep").unwrap();
        let args = Args { project: project.path().into(), native_bin: "missing-runtime".into(), execute: true,
            out: Some(destination.path().into()) };
        assert!(run(&args).unwrap_err().to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(destination.path()).unwrap(), "keep");
    }

    #[test]
    fn report_under_input_tree_is_rejected_before_executing() {
        let project = tempfile::tempdir().unwrap();
        let args = Args { project: project.path().into(), native_bin: "missing-runtime".into(), execute: true,
            out: Some(project.path().join("report.json")) };
        assert!(run(&args).unwrap_err().to_string().contains("outside"));
        assert!(!project.path().join("report.json").exists());
    }

    #[test]
    fn empty_project_cannot_produce_a_passing_report() {
        let project = tempfile::tempdir().unwrap();
        let args = Args { project: project.path().into(), native_bin: "/bin/false".into(), execute: true, out: None };
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
        let args = Args { project: project.path().into(), native_bin: "/bin/false".into(), execute: true,
            out: Some(reports.path().join("report.json")) };
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
}
