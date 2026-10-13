#![forbid(unsafe_code)]

//! Inspect a proposed repair, then verify precisely the reviewed source against
//! a pinned failure capsule. This command never installs source changes or
//! manufactures a new passing seed capsule. Both modes use product capture.

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
#[command(version, about = "Inspect and verify a repaired project against an independently pinned migration failure")]
struct Args {
    /// Existing pair or product failure capsule. Never obtain the trusted pin from untrusted inspection.
    capsule: PathBuf,
    /// Proposed repaired project directory; captured once before any runtime is resolved.
    candidate: PathBuf,
    /// Independently trusted seed content SHA-256 (64 lowercase hexadecimal characters).
    #[arg(long)]
    expected_sha256: String,
    /// Read repair hashes and changes without running code or resolving any runtime.
    #[arg(long, conflicts_with_all = ["execute", "native_bin", "bun_bin", "expected_candidate_input_sha256"])]
    inspect: bool,
    /// Reviewed complete repair hash from inspection; required for execution, never inferred automatically.
    #[arg(long, required_unless_present = "inspect")]
    expected_candidate_input_sha256: Option<String>,
    /// Trusted local native product executable, outside the repaired project. It may also be updated.
    #[arg(long, required_unless_present = "inspect")]
    native_bin: Option<PathBuf>,
    /// Required for product execution; Bun's identity and every observation must match the seed.
    #[arg(long, requires = "execute", conflicts_with = "inspect")]
    bun_bin: Option<PathBuf>,
    /// Consent to running both archived reference code and repaired code with your OS authority.
    #[arg(long, required_unless_present = "inspect")]
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

    // These checks also protect programmatic callers that bypass Clap. None
    // may read an input, reserve an output or resolve a runtime before consent.
    ensure!(!args.inspect || (!args.execute && args.native_bin.is_none()
        && args.bun_bin.is_none() && args.expected_candidate_input_sha256.is_none()),
        "--inspect cannot be combined with execution, runtime or approval options");
    ensure!(args.inspect || args.execute, "--execute is required: archived and repaired code run with your authority");
    let valid_pin = |pin: &str| pin.len() == 64 && pin.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    ensure!(valid_pin(&args.expected_sha256),
        "--expected-sha256 must be an independently trusted lowercase SHA-256");
    if !args.inspect {
        ensure!(args.expected_candidate_input_sha256.as_deref().is_some_and(valid_pin),
            "--expected-candidate-input-sha256 must be the reviewed repair hash");
        ensure!(args.native_bin.is_some(), "--native-bin is required for execution");
    }
    let destination = args.out.as_deref().map(|path|
        native_replay::output_destination(path, &[args.candidate.as_path()])).transpose()?;
    // Preserve final symlinks for the backend to refuse. Inspection dispatches
    // schemas without selecting runtimes; execution never drops a product leg.
    let mut result = if args.inspect {
        serde_json::to_value(source_fix::inspect(&args.capsule, &args.expected_sha256, &args.candidate)?)?
    } else {
        serde_json::to_value(source_fix::verify_reviewed(&args.capsule, &args.expected_sha256, &args.candidate,
            args.expected_candidate_input_sha256.as_deref().context("reviewed repair hash missing")?,
            args.native_bin.as_deref().context("native runtime missing")?, args.bun_bin.as_deref())?)?
    };
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
                // Keep completed inspection or execution evidence on stdout.
                result["operation_verdict"] = result["verdict"].clone();
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
        Some("INSPECTED") if report["execution_performed"] == false => 0,
        Some("FIX_VERIFIED") if report["candidate_source_unchanged"] == true
            && report["candidate_input_approved"] == true => 0,
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
    use native_replay::failure_capture::product::{self, source_fix};

    fn args(capsule: &Path, candidate: &Path, pin: &str) -> Args {
        Args { capsule: capsule.into(), candidate: candidate.into(), expected_sha256: pin.into(),
            inspect: false, expected_candidate_input_sha256: Some("a".repeat(64)),
            native_bin: Some("/bin/false".into()), bun_bin: None, execute: true, out: None }
    }

    fn approve(options: &mut Args) {
        options.expected_candidate_input_sha256 = Some(source_fix::inspect(&options.capsule,
            &options.expected_sha256, &options.candidate).unwrap().candidate_input_sha256);
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
    fn clap_requires_consent_both_pins_and_explicit_runtime_for_execution() {
        let pin = "a".repeat(64);
        let base = ["fix", "seed.json", "repaired project", "--execute",
            "--expected-sha256", &pin, "--expected-candidate-input-sha256", &pin,
            "--native-bin", "/trusted/native"];
        let parsed = Args::try_parse_from(base).unwrap();
        assert_eq!(parsed.candidate, PathBuf::from("repaired project"));
        for omitted in ["--execute", "--expected-sha256", "--expected-candidate-input-sha256", "--native-bin"] {
            let mut remaining = Vec::new();
            let mut skip_value = false;
            for token in base {
                if skip_value { skip_value = false; continue; }
                if token == omitted { skip_value = token != "--execute"; continue; }
                remaining.push(token);
            }
            assert!(Args::try_parse_from(remaining).is_err(), "{omitted}");
        }
        for option in ["--list-tests", "--inspect-capsule", "--minimize-capsule", "--compare-filesystem", "--inspect"] {
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
        options.expected_sha256 = "a".repeat(64);
        for pin in [None, Some(String::new()), Some("A".repeat(64)), Some("z".repeat(64))] {
            options.expected_candidate_input_sha256 = pin;
            assert!(run(&options).unwrap_err().to_string().contains("--expected-candidate-input-sha256"));
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
            approve(&mut options);
            if is_product { options.bun_bin = Some("/bin/true".into()); }
            options.out = Some(out.path().join("report.json"));
            let report = run(&options).unwrap();
            assert_eq!(report["verdict"], "FIX_NOT_VERIFIED");
            assert_eq!(result_exit_code(&report), 1);
            assert_eq!(report["seed_content_sha256"], pin);
            assert_ne!(report["candidate_input_sha256"], report["captured_candidate_input_sha256"]);
            assert_eq!(report["candidate_source_unchanged"], true);
            assert_eq!(report["candidate_input_approved"], true);
            assert_eq!(report["native_runtime_changed"], false);
            assert_eq!(report["source_changes"]["modified_paths"], 1);
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
        approve(&mut options);
        // This no-output fixture and explicit /bin/true test CLI plumbing,
        // NOT successful native engine execution of a repaired application.
        options.native_bin = Some("/bin/true".into());
        let report = run(&options).unwrap();
        assert_eq!(report["verdict"], "FIX_VERIFIED");
        assert_eq!(report["native_runtime_changed"], true);
        assert_eq!(result_exit_code(&report), 0);
        for verdict in ["ERROR", "REFERENCE_DRIFT", "SOURCE_DRIFT", "PASS", "REPRODUCED"] {
            assert_eq!(result_exit_code(&serde_json::json!({
                "verdict": verdict, "candidate_source_unchanged": true, "candidate_input_approved": true,
                "replay": {"result": {"verdict": "FIX_VERIFIED"}},
            })), 2);
        }
        for (unchanged, approved) in [(false, true), (true, false)] {
            assert_eq!(result_exit_code(&serde_json::json!({
                "verdict": "FIX_VERIFIED", "candidate_source_unchanged": unchanged,
                "candidate_input_approved": approved,
            })), 2);
        }
    }

    #[test]
    fn missing_product_reference_never_falls_back_to_a_pair_measurement() {
        let (repaired, out, path, pin) = fixture(true);
        let mut options = args(&path, repaired.path(), &pin);
        approve(&mut options);
        options.out = Some(out.path().join("never.json"));
        let error = run(&options).unwrap_err();
        assert!(error.to_string().contains("native migration capsule"), "{error:#}");
        assert!(!options.out.unwrap().exists());
    }

    #[test]
    fn inspection_clap_needs_no_runtime_and_rejects_every_execution_option() {
        let pin = "a".repeat(64);
        let base = ["fix", "seed.json", "repair", "--inspect", "--expected-sha256", &pin];
        let parsed = Args::try_parse_from(base).unwrap();
        assert!(parsed.inspect && !parsed.execute && parsed.native_bin.is_none());
        for flags in [vec!["--execute"], vec!["--native-bin", "/bin/false"],
            vec!["--bun-bin", "/bin/true"], vec!["--expected-candidate-input-sha256", &pin]] {
            let mut argv = base.to_vec();
            argv.extend(flags);
            assert!(Args::try_parse_from(argv).is_err());
        }
        let options = Args { inspect: true, ..args(Path::new("missing"), Path::new("missing"), &pin) };
        assert!(run(&options).unwrap_err().to_string().contains("--inspect cannot"));
    }

    #[test]
    fn inspection_of_both_schemas_reports_changes_privately_without_executing_repair() {
        for (is_product, role) in [(false, "pair"), (true, "product")] {
            let (repaired, out, path, pin) = fixture(is_product);
            let marker = out.path().join("executed");
            fs::write(repaired.path().join("helper.cjs"), format!(
                "require('fs').writeFileSync({}, 'must not run');", serde_json::to_string(&marker).unwrap())).unwrap();
            let options = Args { inspect: true, execute: false, native_bin: None,
                expected_candidate_input_sha256: None, out: Some(out.path().join("inspection.json")),
                ..args(&path, repaired.path(), &pin) };
            let before = fs::read(&path).unwrap();
            let report = run(&options).unwrap();
            assert_eq!(report["verdict"], "INSPECTED");
            assert_eq!(report["oracle"], role);
            assert_eq!(report["execution_performed"], false);
            assert_eq!(report["source_changes"]["changes"][0]["path"], "helper.cjs");
            assert_eq!(report["source_changes"]["modified_paths"], 1);
            assert!(report.get("replay").is_none());
            assert!(!serde_json::to_string(&report).unwrap().contains("must not run"));
            assert!(!marker.exists());
            assert_eq!(fs::read(&path).unwrap(), before);
            assert_eq!(result_exit_code(&report), 0);
            assert_eq!(fs::metadata(options.out.unwrap()).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn reviewed_execution_refuses_changed_source_before_resolving_a_missing_runtime() {
        let (repaired, out, path, pin) = fixture(false);
        let mut options = args(&path, repaired.path(), &pin);
        approve(&mut options);
        let marker = out.path().join("must-not-execute");
        fs::write(repaired.path().join("helper.cjs"), format!(
            "require('fs').writeFileSync({}, 'changed');", serde_json::to_string(&marker).unwrap())).unwrap();
        options.native_bin = Some("/definitely/missing/native".into());
        options.out = Some(out.path().join("never.json"));
        let error = run(&options).unwrap_err();
        assert!(error.to_string().contains("reviewed candidate input hash"), "{error:#}");
        assert!(!marker.exists() && !options.out.unwrap().exists());
    }

    #[test]
    fn even_a_newly_supplied_candidate_pin_cannot_authorize_replacing_the_harness() {
        let (repaired, _out, path, pin) = fixture(false);
        fs::write(repaired.path().join("case.test.js"), "void 0;").unwrap();
        let mut options = args(&path, repaired.path(), &pin);
        let captured = validation_suite::rewrite_candidate::RewriteCandidate::capture(repaired.path(),
            std::time::Instant::now() + std::time::Duration::from_secs(60)).unwrap();
        options.expected_candidate_input_sha256 = Some(captured.input_sha256().into());
        options.native_bin = Some("/definitely/missing/native".into());
        let error = run(&options).unwrap_err();
        assert!(error.to_string().contains("frozen test input"), "{error:#}");
    }
}
