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
