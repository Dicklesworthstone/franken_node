#![forbid(unsafe_code)]

//! Check a proposed source repair against a pinned failure capsule. This command
//! neither installs source changes nor manufactures a new passing seed capsule.
//! It uses the product's capture, replay, observation and runtime checks.

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/dependency_admission.rs"]
pub mod dependency_admission;
#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/smoke_supervisor.rs"]
mod smoke_supervisor;
#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/migration/validation_suite.rs"]
pub mod validation_suite;

#[derive(Parser)]
#[command(version, about = "Verify a repaired project against an independently pinned migration failure")]
struct Args {
    /// Existing pair or product failure capsule. Never obtain the trusted pin from untrusted inspection.
    capsule: PathBuf,
    /// Proposed repaired project directory; captured once before any runtime is resolved.
    candidate: PathBuf,
    /// Independently trusted seed content SHA-256 (64 lowercase hexadecimal characters).
    #[arg(long)]
    expected_sha256: String,
    /// Trusted local native product executable, outside the repaired project. It may also be updated.
    #[arg(long)]
    native_bin: PathBuf,
    /// Required for product capsules; the Bun identity and every observation must match the seed.
    #[arg(long)]
    bun_bin: Option<PathBuf>,
    /// Consent to running both archived reference code and repaired code with your OS authority.
    #[arg(long, required = true)]
    execute: bool,
    /// New private JSON report outside the repaired project. JSON is also printed to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn run(args: &Args) -> anyhow::Result<serde_json::Value> {
    use anyhow::{Context, ensure};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use validation_suite::native_replay;
    use native_replay::failure_capture::product::source_fix;

    // Programmatic callers do not pass through Clap, so consent and pin shape
    // are checked before any path is read or created here as well.
    ensure!(args.execute, "--execute is required: archived and repaired code run with your authority");
    ensure!(args.expected_sha256.len() == 64 && args.expected_sha256.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "--expected-sha256 must be an independently trusted lowercase SHA-256");
    let destination = args.out.as_deref().map(|path|
        native_replay::output_destination(path, &[args.candidate.as_path()])).transpose()?;
    // Preserve the caller's capsule/candidate path: the backend must see and
    // reject final symlinks rather than having canonicalization erase them.
    let report = source_fix::verify(&args.capsule, &args.expected_sha256, &args.candidate,
        &args.native_bin, args.bun_bin.as_deref())?;
    let mut result = serde_json::to_value(report)?;
    if let Some(destination) = destination {
        let published = (|| -> anyhow::Result<()> {
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(&destination).context("create source-fix report without overwriting existing output")?;
            serde_json::to_writer_pretty(&mut file, &result)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        })();
        match published {
            Ok(()) => result["report_path"] = destination.to_string_lossy().as_ref().into(),
            Err(error) => {
                // Do not lose a completed comparison to an output-directory
                // failure, and do not claim a successful publication either.
                result["verification_verdict"] = result["verdict"].clone();
                result["verdict"] = "ERROR".into();
                result["publication_error"] = format!("{error:#}").into();
            }
        }
    }
    Ok(result)
}

#[cfg(not(target_os = "linux"))]
fn run(_args: &Args) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("native source-fix verification currently requires Linux")
}

fn result_exit_code(report: &serde_json::Value) -> u8 {
    match report["verdict"].as_str() {
        Some("FIX_VERIFIED") if report["candidate_source_unchanged"] == true => 0,
        Some("FIX_NOT_VERIFIED") => 1,
        _ => 2,
    }
}

fn main() -> ExitCode {
    let result = run(&Args::parse()).unwrap_or_else(|error| serde_json::json!({
        "schema_version": "franken-node/source-fix-error/v1", "verdict": "ERROR",
        "error": format!("{error:#}"), "release_certification": false,
    }));
    let exit = result_exit_code(&result);
    println!("{}", serde_json::to_string_pretty(&result).expect("serializable report"));
    ExitCode::from(exit)
}

#[cfg(all(test, target_os = "linux"))]
mod cli_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use validation_suite::native_replay;
    use native_replay::failure_capture::product;

    fn args(capsule: &Path, candidate: &Path, pin: &str) -> Args {
        Args { capsule: capsule.into(), candidate: candidate.into(), expected_sha256: pin.into(),
            native_bin: "/bin/false".into(), bun_bin: None, execute: true, out: None }
    }

    fn fixture(product: bool) -> (tempfile::TempDir, tempfile::TempDir, PathBuf, String) {
        let original = tempfile::tempdir().unwrap();
        let repaired = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        for root in [original.path(), repaired.path()] {
            fs::write(root.join("case.test.js"), "require('./helper.cjs');").unwrap();
        }
        fs::write(original.path().join("helper.cjs"), "globalThis.answer=42;").unwrap();
        fs::write(repaired.path().join("helper.cjs"), "globalThis.answer=6*7;").unwrap();
        let path = out.path().join("failure.json");
        // /bin/false deliberately fails the native role; /bin/true is an
        // explicitly empty second reference. Neither claims Franken/Bun parity.
        let pin = if product {
            product::capture_project(original.path(), None, Path::new("/bin/false"),
                Path::new("/bin/true"), true).unwrap().write_capsule(&path).unwrap().content_sha256
        } else {
            native_replay::capture_project(original.path(), None, Path::new("/bin/false"), true)
                .unwrap().write_capsule(&path).unwrap().content_sha256
        };
        (repaired, out, path, pin)
    }

    #[test]
    fn clap_requires_consent_pin_and_explicit_runtime_without_other_execution_modes() {
        let pin = "a".repeat(64);
        let base = ["fix", "seed.json", "repaired project", "--execute",
            "--expected-sha256", &pin, "--native-bin", "/trusted/native"];
        let parsed = Args::try_parse_from(base).unwrap();
        assert_eq!(parsed.candidate, PathBuf::from("repaired project"));
        for omitted in ["--execute", "--expected-sha256", "--native-bin"] {
            let mut remaining = Vec::new();
            let mut skip_value = false;
            for token in base {
                if skip_value { skip_value = false; continue; }
                if token == omitted { skip_value = token != "--execute"; continue; }
                remaining.push(token);
            }
            assert!(Args::try_parse_from(remaining).is_err(), "{omitted}");
        }
        for option in ["--list-tests", "--inspect-capsule", "--minimize-capsule", "--compare-filesystem"] {
            let mut flags = base.to_vec();
            flags.push(option);
            assert!(Args::try_parse_from(flags).is_err(), "{option}");
        }
    }

    #[test]
    fn programmatic_consent_and_pin_checks_precede_filesystem_access() {
        let mut options = args(Path::new("missing-seed"), Path::new("missing-repair"), &"a".repeat(64));
        options.execute = false;
        assert!(run(&options).unwrap_err().to_string().contains("--execute"));
        options.execute = true;
        for pin in ["", "a", &"A".repeat(64), &"z".repeat(64)] {
            options.expected_sha256 = pin.into();
            assert!(run(&options).unwrap_err().to_string().contains("--expected-sha256"));
        }
    }

    #[test]
    fn output_under_candidate_or_symlink_alias_is_refused_before_reading_seed() {
        let repaired = tempfile::tempdir().unwrap();
        let aliases = tempfile::tempdir().unwrap();
        let alias = aliases.path().join("candidate");
        symlink(repaired.path(), &alias).unwrap();
        for parent in [repaired.path(), alias.as_path()] {
            let mut options = args(Path::new("missing-seed"), repaired.path(), &"a".repeat(64));
            options.out = Some(parent.join("report.json"));
            let error = run(&options).unwrap_err();
            assert!(error.to_string().contains("outside captured input trees"), "{error:#}");
        }
        assert!(!repaired.path().join("report.json").exists());
    }

    #[test]
    fn an_existing_report_is_never_overwritten_or_used_as_execution_permission() {
        let repaired = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let report = out.path().join("report.json");
        fs::write(&report, "existing report").unwrap();
        let mut options = args(Path::new("missing-seed"), repaired.path(), &"a".repeat(64));
        options.out = Some(report.clone());
        assert!(run(&options).unwrap_err().to_string().contains("output already exists"));
        assert_eq!(fs::read_to_string(report).unwrap(), "existing report");
    }

    #[test]
    fn executing_command_keeps_repair_identity_full_evidence_and_private_output() {
        for (is_product, role) in [(false, "pair"), (true, "product")] {
            let (repaired, out, path, pin) = fixture(is_product);
            let original_capsule = fs::read(&path).unwrap();
            let original_source = fs::read(repaired.path().join("case.test.js")).unwrap();
            let mut options = args(&path, repaired.path(), &pin);
            if is_product { options.bun_bin = Some("/bin/true".into()); }
            options.out = Some(out.path().join("report.json"));
            let report = run(&options).unwrap();
            assert_eq!(report["verdict"], "FIX_NOT_VERIFIED");
            assert_eq!(result_exit_code(&report), 1);
            assert_eq!(report["seed_content_sha256"], pin);
            assert_ne!(report["candidate_input_sha256"], report["captured_candidate_input_sha256"]);
            assert_eq!(report["candidate_source_unchanged"], true);
            assert_eq!(report["native_runtime_changed"], false);
            assert_eq!(report["replay"]["oracle"], role);
            let validation = &report["replay"]["result"]["validation"];
            assert_eq!(validation["candidate_input_sha256"], report["candidate_input_sha256"]);
            assert_eq!(validation["cases"][0]["native"]["exit_code"], 1);
            if is_product { assert!(validation["cases"][0]["bun"].is_object()); }
            let destination = options.out.unwrap();
            assert_eq!(fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o600);
            let saved: serde_json::Value = serde_json::from_slice(&fs::read(destination).unwrap()).unwrap();
            assert_eq!(saved["replay"], report["replay"]);
            assert_eq!(fs::read(&path).unwrap(), original_capsule);
            assert_eq!(fs::read(repaired.path().join("case.test.js")).unwrap(), original_source);
            assert!(!repaired.path().join(".migrate-backup").exists());
        }
    }

    #[test]
    fn explicit_candidate_runtime_update_is_reported_and_only_complete_fix_exits_zero() {
        let (repaired, _out, path, pin) = fixture(false);
        let mut options = args(&path, repaired.path(), &pin);
        // This no-output fixture and explicit /bin/true test CLI plumbing,
        // NOT successful native engine execution of a repaired application.
        options.native_bin = "/bin/true".into();
        let report = run(&options).unwrap();
        assert_eq!(report["verdict"], "FIX_VERIFIED");
        assert_eq!(report["native_runtime_changed"], true);
        assert_eq!(result_exit_code(&report), 0);
        for verdict in ["ERROR", "REFERENCE_DRIFT", "SOURCE_DRIFT", "PASS", "REPRODUCED"] {
            assert_eq!(result_exit_code(&serde_json::json!({
                "verdict": verdict, "candidate_source_unchanged": true,
                "replay": {"result": {"verdict": "FIX_VERIFIED"}},
            })), 2);
        }
        assert_eq!(result_exit_code(&serde_json::json!({
            "verdict": "FIX_VERIFIED", "candidate_source_unchanged": false,
        })), 2);
    }

    #[test]
    fn missing_product_reference_never_falls_back_to_a_pair_measurement() {
        let (repaired, out, path, pin) = fixture(true);
        let mut options = args(&path, repaired.path(), &pin);
        options.out = Some(out.path().join("never.json"));
        let error = run(&options).unwrap_err();
        assert!(error.to_string().contains("native migration capsule"), "{error:#}");
        assert!(!options.out.unwrap().exists());
    }
}
