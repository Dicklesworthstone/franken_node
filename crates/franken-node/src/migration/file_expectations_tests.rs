//! Output-artifact assertions use real staged processes and descriptor-relative
//! reads, never expected bytes written by the guest. Node/Node is an explicit
//! orchestration test, not native compatibility certification.

use super::super::{Invocation, Snapshot, execute_suite_pair, matched_tests, node_on_path};
use super::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;

const TEST: &str = "scripts/check.js";

fn put(root: &Path, name: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn manifest(root: &Path, files: serde_json::Value) {
    put(root, MANIFEST_PATH, serde_json::json!({
        "schema_version": MANIFEST_SCHEMA,
        "tests": [TEST],
        "expectations": {(TEST): {"files": files}}
    }).to_string());
}

fn project(source: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), TEST, source);
    put(root.path(), "fixtures/result.bin", [0, 255, 10]);
    manifest(root.path(), serde_json::json!({"out/result.bin": "fixtures/result.bin"}));
    root
}

fn capture(root: &Path) -> Snapshot {
    Snapshot::capture(root, Instant::now() + Duration::from_secs(60)).unwrap()
}

fn check(root: &Path, target: &str, expected: &[u8]) -> Result<()> {
    check_output_file(
        &File::open(root).unwrap(), target, expected,
        Instant::now() + Duration::from_secs(5),
    )
}

fn pair(snapshot: &Snapshot) -> super::super::SuiteReport {
    let node = Invocation {
        executable: node_on_path().expect("real Node required"),
        before: vec![], after: vec![],
    };
    execute_suite_pair(snapshot, snapshot, &node, &node,
        Instant::now() + Duration::from_secs(90), Duration::from_secs(5), false).unwrap()
}

#[test]
fn newly_created_outputs_are_admitted_without_being_present_in_capture() {
    let root = project("");
    let snapshot = capture(root.path());
    assert!(!snapshot.entries.contains_key(Path::new("out")));
    assert_eq!(discover(&snapshot.entries).unwrap(), [PathBuf::from(TEST)]);
}

#[test]
fn empty_null_ill_typed_and_duplicate_file_assertions_fail_closed() {
    let root = project("");
    for files in [
        serde_json::json!({}), serde_json::json!(null), serde_json::json!([]),
        serde_json::json!({"out/result.bin": null}),
        serde_json::json!({"out/result.bin": 42}),
    ] {
        manifest(root.path(), files);
        assert!(discover(&capture(root.path()).entries).is_err());
    }
    put(root.path(), MANIFEST_PATH, format!(
        r#"{{"schema_version":"{MANIFEST_SCHEMA}","tests":["{TEST}"],"expectations":{{"{TEST}":{{"files":{{"out/result.bin":"fixtures/result.bin","out/result.bin":"fixtures/result.bin"}}}}}}}}"#
    ));
    assert!(discover(&capture(root.path()).entries).is_err());
}

#[test]
fn file_targets_must_be_canonical_relative_and_outside_reserved_state() {
    let root = project("");
    for target in ["", ".", "../escape", "/absolute", "./out/file", "out//file",
        "out/../file", "out/file/", "out\\file", "out/f\nile",
        ".franken-node/file", "node_modules/file", ".git/file", ".beads/file",
        ".migrate-backup/file", ".franken-rewrite/file"] {
        manifest(root.path(), serde_json::json!({(target): "fixtures/result.bin"}));
        assert!(discover(&capture(root.path()).entries).is_err(), "{target:?}");
    }
}

#[test]
fn file_fixture_admission_and_file_count_are_bounded() {
    let root = project("");
    for fixture in ["missing", "fixtures", "../result", ".franken-node/migration-tests.json"] {
        manifest(root.path(), serde_json::json!({"out/result.bin": fixture}));
        assert!(discover(&capture(root.path()).entries).is_err());
    }
    let mut files = serde_json::Map::new();
    for index in 0..MAX_EXPECTED_FILES {
        files.insert(format!("out/{index}"), "fixtures/result.bin".into());
    }
    manifest(root.path(), files.clone().into());
    assert!(discover(&capture(root.path()).entries).is_ok());
    files.insert("out/overflow".into(), "fixtures/result.bin".into());
    manifest(root.path(), files.into());
    assert!(discover(&capture(root.path()).entries).is_err());
}

#[test]
fn candidate_cannot_change_artifact_goldens_or_assertion_targets() {
    let original = project("");
    let candidate = project("");
    let snapshot = capture(original.path());
    matched_tests(&snapshot, &capture(candidate.path())).unwrap();
    put(candidate.path(), "fixtures/result.bin", b"replacement");
    assert!(matched_tests(&snapshot, &capture(candidate.path())).unwrap_err()
        .to_string().contains("expectation bytes differ"));
    put(candidate.path(), "fixtures/result.bin", [0, 255, 10]);
    manifest(candidate.path(), serde_json::json!({"out/other.bin": "fixtures/result.bin"}));
    assert!(matched_tests(&snapshot, &capture(candidate.path())).is_err());
}

#[test]
fn exact_binary_empty_and_maximum_size_outputs_are_checked_without_normalization() {
    let root = tempfile::tempdir().unwrap();
    for expected in [vec![], vec![0, 255, 10], vec![b'x'; MAX_EXPECTATION_BYTES]] {
        put(root.path(), "out/result", &expected);
        check(root.path(), "out/result", &expected).unwrap();
        let mut longer = expected.clone();
        longer.push(0);
        put(root.path(), "out/result", longer);
        assert!(check(root.path(), "out/result", &expected).is_err());
    }
    put(root.path(), "out/result", b"43\n");
    let error = check(root.path(), "out/result", b"42\n").unwrap_err().to_string();
    assert!(error.contains("does not match"));
    assert!(!error.contains("43"));
    assert!(!error.contains("42"));
}

#[test]
fn missing_directory_and_fifo_outputs_are_not_success_or_blocking_reads() {
    let root = tempfile::tempdir().unwrap();
    assert!(check(root.path(), "missing", b"").is_err());
    fs::create_dir(root.path().join("directory")).unwrap();
    assert!(check(root.path(), "directory", b"").is_err());
    assert!(Command::new("mkfifo").arg(root.path().join("fifo")).status().unwrap().success());
    assert!(check(root.path(), "fifo", b"").is_err());
}

#[test]
fn leaf_and_parent_symlinks_are_refused_even_when_the_destination_matches() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "real/result", b"golden");
    symlink("real/result", root.path().join("leaf")).unwrap();
    symlink("real", root.path().join("parent")).unwrap();
    assert!(check(root.path(), "leaf", b"golden").is_err());
    assert!(check(root.path(), "parent/result", b"golden").is_err());
    let outside = tempfile::tempdir().unwrap();
    put(outside.path(), "result", b"golden");
    symlink(outside.path(), root.path().join("external")).unwrap();
    assert!(check(root.path(), "external/result", b"golden").is_err());
}

#[test]
fn pinned_workspace_does_not_follow_a_later_root_path_replacement() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("workspace");
    put(&original, "result", b"correct");
    let expected = Expectations {
        files: BTreeMap::from([("result".into(), "fixtures/result.bin".into())]),
        ..Expectations::default()
    };
    let pinned = expected.pin_workspace(&original).unwrap().unwrap();
    let moved = root.path().join("moved");
    fs::rename(&original, &moved).unwrap();
    let impostor = root.path().join("impostor");
    put(&impostor, "result", b"incorrect");
    symlink(&impostor, &original).unwrap();
    check_output_file(&pinned, "result", b"correct", Instant::now() + Duration::from_secs(5)).unwrap();
    assert!(expected.pin_workspace(&original).is_err());
}

#[test]
fn output_checks_respect_the_existing_leg_deadline_even_for_empty_files() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "result", b"");
    assert!(check_output_file(&File::open(root.path()).unwrap(), "result", b"", Instant::now())
        .unwrap_err().to_string().contains("budget"));
}

#[test]
fn real_node_pair_checks_generated_artifacts_without_full_delta_comparison() {
    let root = project("const fs=require('fs');fs.mkdirSync('out');fs.writeFileSync('out/result.bin',Buffer.from([0,255,10]));");
    let report = pair(&capture(root.path()));
    assert_eq!(report.verdict, "PASS", "{report:#?}");
    assert!(!report.filesystem_comparison);
    assert!(!report.release_certification);
    assert!(!root.path().join("out").exists());
}

#[test]
fn identical_missing_or_wrong_artifacts_cannot_pass_by_runtime_agreement() {
    for source in ["// both programs exit zero but produce nothing", "const fs=require('fs');fs.mkdirSync('out');fs.writeFileSync('out/result.bin','bad');"] {
        let root = project(source);
        let report = pair(&capture(root.path()));
        assert_eq!(report.verdict, "ERROR", "{report:#?}");
        assert_eq!(report.passed, 0);
        assert!(report.cases[0].errors.iter().any(|error| error.contains("file output expectation")));
    }
}

#[test]
fn guest_mutation_of_artifact_goldens_cannot_change_the_captured_oracle() {
    let root = project("const fs=require('fs');fs.mkdirSync('out');fs.writeFileSync('fixtures/result.bin','bad');fs.writeFileSync('out/result.bin','bad');");
    let report = pair(&capture(root.path()));
    assert_eq!(report.verdict, "ERROR", "{report:#?}");
    assert_eq!(fs::read(root.path().join("fixtures/result.bin")).unwrap(), [0, 255, 10]);
}

#[test]
fn artifact_paths_are_root_relative_even_with_a_harness_working_directory() {
    let root = project("const fs=require('fs');fs.mkdirSync('../out');fs.writeFileSync('../out/result.bin',Buffer.from([0,255,10]));");
    put(root.path(), MANIFEST_PATH, serde_json::json!({
        "schema_version": MANIFEST_SCHEMA, "tests": [TEST],
        "execution": {(TEST): {"cwd": "scripts"}},
        "expectations": {(TEST): {"files": {"out/result.bin": "fixtures/result.bin"}}}
    }).to_string());
    let report = pair(&capture(root.path()));
    assert_eq!(report.verdict, "PASS", "{report:#?}");
}
