//! Regression tests for captured, independent migration output oracles.
//! Node/Node execution tests exercise the actual suite orchestrator; they are
//! not evidence of native Franken compatibility or a release claim.

use super::super::{Invocation, Snapshot, execute_suite_pair, matched_tests, node_on_path};
use super::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

fn write(root: &Path, name: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn manifest(root: &Path, expectations: serde_json::Value) {
    write(
        root,
        MANIFEST_PATH,
        serde_json::json!({
            "schema_version": MANIFEST_SCHEMA,
            "tests": ["scripts/check.js"],
            "expectations": {"scripts/check.js": expectations}
        })
        .to_string(),
    );
}

fn capture(root: &Path) -> Snapshot {
    Snapshot::capture(root, Instant::now() + Duration::from_secs(60)).unwrap()
}

fn project(source: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "scripts/check.js", source);
    write(root.path(), "fixtures/stdout.bin", b"42\n");
    write(root.path(), "fixtures/stderr.bin", b"");
    manifest(
        root.path(),
        serde_json::json!({
            "stdout": "fixtures/stdout.bin", "stderr": "fixtures/stderr.bin"
        }),
    );
    root
}

fn output(stdout: &[u8], stderr: &[u8]) -> Output {
    Output {
        status: ExitStatus::from_raw(0),
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
    }
}

fn run_pair(snapshot: &Snapshot) -> super::super::SuiteReport {
    let node = Invocation {
        executable: node_on_path().expect("real Node required"),
        before: vec![],
        after: vec![],
    };
    execute_suite_pair(
        snapshot,
        snapshot,
        &node,
        &node,
        Instant::now() + Duration::from_secs(90),
        Duration::from_secs(5),
        false,
    )
    .unwrap()
}

#[test]
fn no_expectations_preserves_legacy_comparison_only_behavior() {
    let root = project("console.log('different');");
    write(
        root.path(),
        MANIFEST_PATH,
        serde_json::json!({
            "schema_version": MANIFEST_SCHEMA, "tests": ["scripts/check.js"]
        })
        .to_string(),
    );
    let snapshot = capture(root.path());
    let tests = inventory(&snapshot.entries).unwrap();
    tests.tests[Path::new("scripts/check.js")]
        .expectations
        .check(&snapshot, &output(b"anything", b"anything"))
        .unwrap();
}

#[test]
fn byte_exact_stream_assertions_support_binary_data_and_empty_stderr() {
    let root = project("");
    write(root.path(), "fixtures/stdout.bin", [0, 255, 10, 13]);
    let snapshot = capture(root.path());
    let tests = inventory(&snapshot.entries).unwrap();
    let expected = &tests.tests[Path::new("scripts/check.js")].expectations;
    expected.check(&snapshot, &output(&[0, 255, 10, 13], b"")).unwrap();
    assert!(expected.check(&snapshot, &output(&[0, 255, 10], b"")).is_err());
    assert!(expected.check(&snapshot, &output(&[0, 255, 10, 13], b"warning")).is_err());
}

#[test]
fn output_is_not_trimmed_decoded_or_normalized() {
    let root = project("");
    let snapshot = capture(root.path());
    let tests = inventory(&snapshot.entries).unwrap();
    let expected = &tests.tests[Path::new("scripts/check.js")].expectations;
    for wrong in [b"42".as_slice(), b"42\r\n", b" 42\n", b"", b"42\n\n"] {
        assert!(expected.check(&snapshot, &output(wrong, b"")).is_err());
    }
}

#[test]
fn mismatch_diagnostics_do_not_expose_expected_or_actual_bytes() {
    let root = project("");
    write(root.path(), "fixtures/stdout.bin", b"secret-expected-token");
    let snapshot = capture(root.path());
    let tests = inventory(&snapshot.entries).unwrap();
    let error = tests.tests[Path::new("scripts/check.js")]
        .expectations
        .check(&snapshot, &output(b"secret-actual-token", b""))
        .unwrap_err()
        .to_string();
    assert!(error.contains("stdout"));
    assert!(!error.contains("secret-"));
}

#[test]
fn explicitly_empty_null_unknown_and_ill_typed_expectations_fail_closed() {
    let root = project("");
    for value in [
        serde_json::json!({}),
        serde_json::json!(null),
        serde_json::json!({"stdout": null}),
        serde_json::json!({"stdout": 42}),
        serde_json::json!({"stdout": "fixtures/stdout.bin", "stderr": null}),
        serde_json::json!({"stdout": "fixtures/stdout.bin", "ignore_mismatch": true}),
        serde_json::json!({"stdout": ["fixtures/stdout.bin"]}),
    ] {
        manifest(root.path(), value.clone());
        assert!(discover(&capture(root.path()).entries).is_err(), "{value}");
    }
}

#[test]
fn duplicate_expectation_test_keys_and_duplicate_stream_fields_are_rejected() {
    let root = project("");
    for fields in [
        r#""expectations":{"scripts/check.js":{"stdout":"fixtures/stdout.bin"},"scripts/check.js":{"stderr":"fixtures/stderr.bin"}}"#,
        r#""expectations":{"scripts/check.js":{"stdout":"fixtures/stdout.bin","stdout":"fixtures/stderr.bin"}}"#,
        r#""expectations":{},"expectations":{}"#,
    ] {
        write(
            root.path(),
            MANIFEST_PATH,
            format!(
                r#"{{"schema_version":"{MANIFEST_SCHEMA}","tests":["scripts/check.js"],{fields}}}"#
            ),
        );
        assert!(discover(&capture(root.path()).entries).is_err(), "{fields}");
    }
}

#[test]
fn expectation_keys_must_be_selected_and_canonically_spelled() {
    let root = project("");
    for name in ["scripts/other.js", "scripts/./check.js", "./scripts/check.js", "scripts//check.js"] {
        write(
            root.path(),
            MANIFEST_PATH,
            serde_json::json!({
                "schema_version": MANIFEST_SCHEMA,
                "tests": ["scripts/check.js"],
                "expectations": {(name): {"stdout": "fixtures/stdout.bin"}}
            })
            .to_string(),
        );
        assert!(discover(&capture(root.path()).entries).is_err(), "{name}");
    }
}

#[test]
fn fixtures_cannot_escape_select_reserved_paths_or_use_noncanonical_names() {
    let root = project("");
    for name in [
        "", "../outside", "/tmp/outside", "./fixtures/stdout.bin",
        "fixtures//stdout.bin", "fixtures/stdout.bin/", "fixtures/../stdout.bin",
        "fixtures\\stdout.bin", "fixtures/out\n.bin", "missing.bin", "fixtures",
        "node_modules/result.bin", ".git/result.bin", ".franken-node/result.bin",
        ".migrate-backup/result.bin", ".franken-rewrite/result.bin", ".beads/result.bin",
    ] {
        manifest(root.path(), serde_json::json!({"stdout": name}));
        assert!(discover(&capture(root.path()).entries).is_err(), "{name:?}");
    }
}

#[test]
fn symlink_fixtures_and_symlink_directory_parents_are_refused() {
    let root = project("");
    symlink("stdout.bin", root.path().join("fixtures/link.bin")).unwrap();
    symlink("fixtures", root.path().join("linked")).unwrap();
    for name in ["fixtures/link.bin", "linked/stdout.bin"] {
        manifest(root.path(), serde_json::json!({"stdout": name}));
        assert!(discover(&capture(root.path()).entries).is_err(), "{name}");
    }
}

#[test]
fn fixture_size_limit_is_inclusive_and_oversize_fails_before_execution() {
    let root = project("");
    write(root.path(), "fixtures/stdout.bin", vec![0; MAX_EXPECTATION_BYTES]);
    assert!(discover(&capture(root.path()).entries).is_ok());
    write(root.path(), "fixtures/stdout.bin", vec![0; MAX_EXPECTATION_BYTES + 1]);
    let error = discover(&capture(root.path()).entries).unwrap_err().to_string();
    assert!(error.contains("1 MiB"), "{error}");
}

#[test]
fn candidate_cannot_change_expected_bytes_while_preserving_fixture_paths() {
    let original = project("console.log(42);");
    let candidate = project("console.log(43);");
    write(candidate.path(), "fixtures/stdout.bin", b"43\n");
    let error = matched_tests(&capture(original.path()), &capture(candidate.path()))
        .unwrap_err()
        .to_string();
    assert!(error.contains("expectation bytes differ"), "{error}");
}

#[test]
fn candidate_cannot_drop_or_redirect_an_assertion() {
    let original = project("");
    let candidate = project("");
    manifest(candidate.path(), serde_json::json!({"stdout": "fixtures/stdout.bin"}));
    assert!(matched_tests(&capture(original.path()), &capture(candidate.path())).is_err());
    write(candidate.path(), "fixtures/other.bin", b"42\n");
    manifest(candidate.path(), serde_json::json!({
        "stdout": "fixtures/other.bin", "stderr": "fixtures/stderr.bin"
    }));
    assert!(matched_tests(&capture(original.path()), &capture(candidate.path())).is_err());
}

#[test]
fn mutable_source_tree_cannot_rewrite_the_captured_oracle() {
    let root = project("");
    let snapshot = capture(root.path());
    write(root.path(), "fixtures/stdout.bin", b"wrong\n");
    let tests = inventory(&snapshot.entries).unwrap();
    tests.tests[Path::new("scripts/check.js")]
        .expectations
        .check(&snapshot, &output(b"42\n", b""))
        .unwrap();
}

#[test]
fn real_node_pair_passes_only_when_both_streams_match_captured_binary_fixtures() {
    let root = project("process.stdout.write(Buffer.from([0,255,10]));process.stderr.write('warn\\n');");
    write(root.path(), "fixtures/stdout.bin", [0, 255, 10]);
    write(root.path(), "fixtures/stderr.bin", b"warn\n");
    let report = run_pair(&capture(root.path()));
    assert_eq!(report.verdict, "PASS", "{report:#?}");
    assert_eq!(report.passed, 1);
    assert!(!report.release_certification);
}

#[test]
fn identical_wrong_successful_outputs_cannot_produce_a_green_verdict() {
    let root = project("// Both processes exit successfully without producing 42.");
    let report = run_pair(&capture(root.path()));
    assert_eq!(report.verdict, "ERROR", "{report:#?}");
    assert_eq!(report.passed, 0);
    assert_eq!(report.errored, 1);
    assert!(report.cases[0].errors.iter().any(|error| error.contains("stdout")));
}

#[test]
fn matched_goldens_never_turn_a_nonzero_process_exit_into_success() {
    let root = project("console.log(42);process.exitCode=7;");
    let report = run_pair(&capture(root.path()));
    assert_eq!(report.verdict, "FAIL", "{report:#?}");
    assert_eq!(report.cases[0].reference.as_ref().unwrap().exit_code, Some(7));
    assert_eq!(report.cases[0].native.as_ref().unwrap().exit_code, Some(7));
}

#[test]
fn guest_cannot_replace_its_workspace_fixture_to_bless_wrong_output() {
    let root = project("require('fs').writeFileSync('fixtures/stdout.bin','wrong\\n');console.log('wrong');");
    let report = run_pair(&capture(root.path()));
    assert_eq!(report.verdict, "ERROR", "{report:#?}");
    assert_eq!(report.passed, 0);
}

mod retained_output_tests {
    use super::super::*;
    use super::super::super::{execute_suite_pair, native_replay, node_on_path, product_oracle};
    use std::fs;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(120)
    }

    fn node(role: &str) -> Invocation {
        Invocation {
            executable: node_on_path().expect("real Node required"),
            before: Vec::new(),
            after: vec![role.into()],
        }
    }

    fn project(source: &str, expectations: serde_json::Value) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".franken-node")).unwrap();
        fs::write(root.path().join("a.test.cjs"), source).unwrap();
        fs::write(root.path().join("z.test.cjs"), "console.log('later case');").unwrap();
        fs::write(root.path().join("golden"), "expected\n").unwrap();
        fs::write(root.path().join(MANIFEST_PATH), serde_json::to_vec(&serde_json::json!({
            "schema_version": MANIFEST_SCHEMA,
            "tests": ["a.test.cjs", "z.test.cjs"],
            "expectations": {"a.test.cjs": expectations},
        })).unwrap()).unwrap();
        root
    }

    fn pair(root: &Path, filesystem: bool) -> super::super::super::SuiteReport {
        let deadline = deadline();
        let snapshot = Snapshot::capture(root, deadline).unwrap();
        execute_suite_pair(&snapshot, &snapshot, &node("reference"), &node("native"),
            deadline, Duration::from_secs(5), filesystem).unwrap()
    }

    #[test]
    fn strict_failure_retains_complete_bytes_once_without_logging_them() {
        let outside = tempfile::tempdir().unwrap();
        let marker = outside.path().join("executions");
        let source = format!(
            "require('fs').appendFileSync({}, 'once\\n');\nconsole.log('private-stdout'); console.error('private-stderr');",
            serde_json::to_string(&marker).unwrap(),
        );
        let root = project(&source, serde_json::json!({"stdout": "golden"}));
        let deadline = deadline();
        let snapshot = Snapshot::capture(root.path(), deadline).unwrap();
        let staged = outside.path().join("project");
        snapshot.stage(&staged, deadline).unwrap();
        let error = run_test(&snapshot, &node("reference"), Path::new("a.test.cjs"),
            &staged, &std::env::vars_os().collect(),
            (Duration::from_secs(5), Duration::from_secs(1))).unwrap_err();
        assert!(!format!("{error:#}").contains("private-stdout"));
        assert!(!format!("{error:#?}").contains("private-stderr"));
        let (output, check_error) = retain_completed_output(Err(error)).unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"private-stdout\n");
        assert_eq!(output.stderr, b"private-stderr\n");
        assert!(check_error.unwrap().to_string().contains("captured output expectation"));
        assert_eq!(fs::read_to_string(marker).unwrap(), "once\n");
    }

    #[test]
    fn equal_wrong_output_keeps_both_legs_but_never_becomes_a_pass() {
        let root = project(
            "console.log('private-wrong'); require('fs').writeFileSync('artifact','changed');",
            serde_json::json!({"stdout": "golden"}),
        );
        let report = pair(root.path(), true);
        assert_eq!(report.verdict, "ERROR");
        assert_eq!((report.total_tests, report.passed, report.errored, report.skipped), (2, 1, 1, 0));
        let row = &report.cases[0];
        assert_eq!(row.status, "ERROR");
        assert_eq!(row.errors.len(), 2);
        assert!(row.divergences.is_empty());
        assert_eq!(row.reference, row.native);
        assert_eq!(row.native.as_ref().unwrap().exit_code, Some(0));
        assert_eq!(row.native.as_ref().unwrap().workspace_delta.as_ref().unwrap().changed_paths, 1);
        assert_eq!(report.cases[1].status, "PASS");
        assert!(!serde_json::to_string(&report).unwrap().contains("private-wrong"));
        assert!(!root.path().join("artifact").exists());
    }

    #[test]
    fn native_only_assertion_failure_keeps_the_differential_observation() {
        let root = project(
            "console.log(process.argv.includes('native') ? 'wrong' : 'expected');",
            serde_json::json!({"stdout": "golden"}),
        );
        let report = pair(root.path(), false);
        let row = &report.cases[0];
        assert_eq!(report.verdict, "ERROR");
        assert_eq!(row.errors.len(), 1);
        assert!(row.errors[0].starts_with("native test checks failed"));
        assert!(row.divergences.iter().any(|s| s == "stdout:byte_mismatch"));
        assert_ne!(row.reference.as_ref().unwrap().stdout, row.native.as_ref().unwrap().stdout);
        assert_eq!(row.reference.as_ref().unwrap().exit_code, Some(0));
        assert_eq!(row.native.as_ref().unwrap().exit_code, Some(0));
    }

    #[test]
    fn failed_file_assertion_does_not_erase_process_or_workspace_evidence() {
        let root = project(
            "require('fs').writeFileSync('artifact', process.argv.includes('native') ? 'wrong' : 'expected\\n');",
            serde_json::json!({"files": {"artifact": "golden"}}),
        );
        let report = pair(root.path(), true);
        let row = &report.cases[0];
        assert_eq!(report.verdict, "ERROR");
        assert_eq!(row.errors.len(), 1);
        assert!(row.errors[0].contains("file output expectation failed"));
        assert_eq!(row.reference.as_ref().unwrap().stdout.bytes, 0);
        assert_eq!(row.native.as_ref().unwrap().stdout.bytes, 0);
        assert_ne!(row.reference.as_ref().unwrap().workspace_delta,
            row.native.as_ref().unwrap().workspace_delta);
        assert!(row.divergences.iter().any(|s| s == "filesystem:workspace_delta_mismatch"));
    }

    #[test]
    fn product_keeps_three_completed_legs_and_later_cases_after_assertion_errors() {
        // Three explicitly named real Node processes exercise orchestration.
        // This test does not substitute Node for Bun/Franken in production.
        let root = project("console.log(process.argv[2]);",
            serde_json::json!({"stdout": "golden"}));
        let deadline = deadline();
        let snapshot = Snapshot::capture(root.path(), deadline).unwrap();
        let reference = node("node");
        let second = node("second");
        let native = node("native");
        let identities = [reference.identity(deadline).unwrap(), second.identity(deadline).unwrap(),
            native.identity(deadline).unwrap()];
        let report = product_oracle::execute(&snapshot, &snapshot, [&reference, &second, &native],
            identities, deadline, Duration::from_secs(5), true).unwrap();
        assert_eq!(report.verdict, "ERROR");
        assert_eq!((report.passed, report.errored, report.skipped), (1, 1, 0));
        let row = &report.cases[0];
        assert_eq!(row.outcome, product_oracle::CaseOutcome::Error);
        assert_eq!(row.errors.len(), 3);
        assert!(row.errors.iter().all(|s| !s.contains("incomplete observation")));
        for observation in [&row.node, &row.bun, &row.native] {
            let observation = observation.as_ref().unwrap();
            assert_eq!(observation.exit_code, Some(0));
            assert!(observation.workspace_delta.is_some());
        }
        assert!(row.divergences.iter().any(|s| s == "node/bun:stdout:byte_mismatch"));
        assert!(row.divergences.iter().any(|s| s == "node/native:stdout:byte_mismatch"));
        assert!(report.check_admission(&report.input_sha256, &report.candidate_input_sha256,
            &snapshot.tests().unwrap()).is_err());
    }

    #[test]
    fn unsafe_file_check_is_an_error_with_observed_output_not_an_accepted_link() {
        let root = project(
            "console.log('completed'); require('fs').symlinkSync('golden','artifact');",
            serde_json::json!({"files": {"artifact": "golden"}}),
        );
        let report = pair(root.path(), false);
        let row = &report.cases[0];
        assert_eq!(report.verdict, "ERROR");
        assert_eq!(row.errors.len(), 2);
        assert_eq!(row.reference.as_ref().unwrap().stdout.bytes, 10);
        assert_eq!(row.native.as_ref().unwrap().exit_code, Some(0));
        assert!(!root.path().join("artifact").exists());
    }

    #[test]
    fn retained_assertion_errors_are_not_promoted_into_replayable_capsules() {
        let root = project("console.log('wrong');", serde_json::json!({"stdout": "golden"}));
        let outputs = tempfile::tempdir().unwrap();
        let captured = native_replay::capture_project(root.path(), None, Path::new("/bin/false"), true).unwrap();
        assert_eq!(captured.report.verdict, "ERROR");
        assert!(captured.report.cases[0].reference.is_some());
        assert!(captured.report.cases[0].native.is_some());
        let destination = outputs.path().join("must-not-exist.json");
        assert!(captured.write_capsule(&destination).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn unobserved_errors_cannot_manufacture_completed_execution() {
        let error = anyhow::anyhow!("runtime could not be launched");
        assert!(retain_completed_output(Err(error)).is_err());
    }
}
