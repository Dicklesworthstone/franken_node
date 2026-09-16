//! Real Node/Node executions of the production paired-input orchestrator.
//! Deliberately different programs test comparison, not Franken compatibility.
use super::*;

fn project(source: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("case.test.js"), source).unwrap();
    root
}

fn node() -> Invocation {
    Invocation { executable: node_on_path().expect("real Node required"), before: vec![], after: vec![] }
}

fn measured(reference: &Path, candidate: &Path, filesystem: bool) -> SuiteReport {
    let deadline = Instant::now() + Duration::from_secs(90);
    let reference = Snapshot::capture(reference, deadline).unwrap();
    let candidate = Snapshot::capture(candidate, deadline).unwrap();
    execute_suite_pair(&reference, &candidate, &node(), &node(), deadline,
        Duration::from_secs(5), filesystem).unwrap()
}

#[test]
fn equivalent_rewrites_pass_without_comparing_unchanged_source_bytes_as_effects() {
    let reference = project("console.log(6*7);");
    let candidate = project("console.log(41+1);");
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "PASS", "{report:#?}");
    assert_ne!(report.input_sha256, report.candidate_input_sha256);
    assert_eq!(report.scope, "captured-test-process-and-workspace-delta");
    assert!(report.filesystem_comparison);
    assert!(!report.release_certification);
    for leg in [&report.cases[0].reference, &report.cases[0].native] {
        assert_eq!(leg.as_ref().unwrap().workspace_delta.as_ref().unwrap().changed_paths, 0);
    }
}

#[test]
fn console_agreement_cannot_hide_different_written_results() {
    let reference = project("require('fs').writeFileSync('result','original-secret');");
    let candidate = project("require('fs').writeFileSync('result','rewritten-secret');");
    let output_only = measured(reference.path(), candidate.path(), false);
    assert_eq!(output_only.verdict, "PASS");
    assert!(!output_only.filesystem_comparison);
    assert!(output_only.cases[0].native.as_ref().unwrap().workspace_delta.is_none());
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "FAIL");
    assert_eq!(report.cases[0].divergences, ["filesystem:workspace_delta_mismatch"]);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("original-secret"));
    assert!(!json.contains("rewritten-secret"));
    assert!(!reference.path().join("result").exists());
    assert!(!candidate.path().join("result").exists());
}

#[test]
fn equivalent_computed_writes_have_equal_deltas() {
    let reference = project("require('fs').writeFileSync('result',String(6*7));");
    let candidate = project("require('fs').writeFileSync('result',String(41+1));");
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "PASS", "{report:#?}");
    let first = report.cases[0].reference.as_ref().unwrap().workspace_delta.as_ref().unwrap();
    let second = report.cases[0].native.as_ref().unwrap().workspace_delta.as_ref().unwrap();
    assert_eq!(first, second);
    assert_eq!(first.changed_paths, 1);
    assert_eq!(first.changes[0].after.as_ref().unwrap().sha256,
        Some(hex::encode(Sha256::digest(b"42"))));
}

#[test]
fn both_source_trees_are_frozen_before_either_runtime_executes() {
    let reference = project("console.log(42);");
    let candidate = project("console.log(21*2);");
    let deadline = Instant::now() + Duration::from_secs(90);
    let first = Snapshot::capture(reference.path(), deadline).unwrap();
    let second = Snapshot::capture(candidate.path(), deadline).unwrap();
    fs::write(reference.path().join("case.test.js"), "process.exit(98);").unwrap();
    fs::write(candidate.path().join("case.test.js"), "process.exit(99);").unwrap();
    let report = execute_suite_pair(&first, &second, &node(), &node(), deadline,
        Duration::from_secs(5), true).unwrap();
    assert_eq!(report.verdict, "PASS", "{report:#?}");
    assert_eq!(fs::read_to_string(candidate.path().join("case.test.js")).unwrap(), "process.exit(99);");
}

#[test]
fn equal_counts_with_different_test_names_are_rejected_before_runtime_access() {
    let reference = project("console.log('reference');");
    let candidate = project("console.log('candidate');");
    fs::rename(candidate.path().join("case.test.js"), candidate.path().join("other.test.js")).unwrap();
    let error = run_project_comparison(reference.path(), Some(candidate.path()), Path::new("/missing/runtime"), false)
        .unwrap_err();
    assert!(error.to_string().contains("test inventories differ"), "{error:#}");
}

#[test]
fn added_or_removed_test_counterparts_cannot_shrink_the_suite() {
    let reference = project("console.log('ok');");
    let candidate = project("console.log('ok');");
    fs::write(candidate.path().join("extra.test.js"), "process.exit(8);").unwrap();
    for (before, after) in [(reference.path(), candidate.path()), (candidate.path(), reference.path())] {
        let error = run_project_comparison(before, Some(after), Path::new("/missing/runtime"), false).unwrap_err();
        assert!(error.to_string().contains("test inventories differ"), "{error:#}");
    }
}

#[test]
fn each_case_uses_its_own_original_and_candidate_dependencies() {
    let reference = project("console.log(require('./helper')); require('fs').writeFileSync('helper.js','module.exports=99');");
    let candidate = project("console.log(require('./helper')); require('fs').writeFileSync('helper.js','module.exports=99');");
    fs::write(reference.path().join("helper.js"), "module.exports=42;").unwrap();
    fs::write(candidate.path().join("helper.js"), "module.exports=21*2;").unwrap();
    for root in [reference.path(), candidate.path()] {
        fs::copy(root.join("case.test.js"), root.join("second.test.js")).unwrap();
    }
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!((report.passed, report.failed, report.errored, report.skipped), (2, 0, 0, 0), "{report:#?}");
    for row in &report.cases {
        assert_eq!(row.native.as_ref().unwrap().stdout.sha256, hex::encode(Sha256::digest(b"42\n")));
        assert_eq!(row.native.as_ref().unwrap().workspace_delta.as_ref().unwrap().changed_paths, 1);
    }
    assert_eq!(fs::read_to_string(candidate.path().join("helper.js")).unwrap(), "module.exports=21*2;");
}

#[test]
fn deletion_and_permission_only_divergence_block_pass() {
    for source in ["require('fs').unlinkSync('artifact');", "require('fs').chmodSync('artifact',0o600);"] {
        let reference = project(source);
        let candidate = project("// same console output, missing effect");
        for root in [reference.path(), candidate.path()] {
            fs::write(root.join("artifact"), "same bytes").unwrap();
            fs::set_permissions(root.join("artifact"), fs::Permissions::from_mode(0o644)).unwrap();
        }
        let report = measured(reference.path(), candidate.path(), true);
        assert_eq!(report.verdict, "FAIL", "{report:#?}");
        assert_eq!(report.cases[0].divergences, ["filesystem:workspace_delta_mismatch"]);
    }
}

#[test]
fn dangling_output_links_are_measured_as_links() {
    let reference = project("require('fs').symlinkSync('missing-a','artifact');");
    let candidate = project("require('fs').symlinkSync('missing-b','artifact');");
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "FAIL", "{report:#?}");
    assert_eq!(report.cases[0].divergences, ["filesystem:workspace_delta_mismatch"]);
    assert_eq!(report.cases[0].native.as_ref().unwrap().workspace_delta.as_ref().unwrap()
        .changes[0].after.as_ref().unwrap().kind, workspace_effects::NodeKind::Symlink);
}

#[test]
fn late_difference_beyond_report_preview_still_fails() {
    let common = "const fs=require('fs'); for(let i=0;i<25;i++)fs.writeFileSync('result-'+String(i).padStart(2,'0'),'same');";
    let reference = project(common);
    let candidate = project(&format!("{common} fs.writeFileSync('result-24','different');"));
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "FAIL", "{report:#?}");
    let first = report.cases[0].reference.as_ref().unwrap().workspace_delta.as_ref().unwrap();
    let second = report.cases[0].native.as_ref().unwrap().workspace_delta.as_ref().unwrap();
    assert_eq!(first.changed_paths, 25);
    assert_eq!(first.changes, second.changes);
    assert!(first.details_truncated);
    assert_ne!(first.sha256, second.sha256);
}

#[test]
fn filesystem_error_keeps_completed_process_evidence_and_later_cases() {
    let reference = project("console.log('ok');");
    let candidate = project("require('fs').linkSync('case.test.js','hardlink'); console.log('ok');");
    for root in [reference.path(), candidate.path()] {
        fs::write(root.join("later.test.js"), "console.log('later');").unwrap();
    }
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "ERROR", "{report:#?}");
    assert_eq!((report.errored, report.passed, report.skipped), (1, 1, 0));
    let row = &report.cases[0];
    assert_eq!(row.native.as_ref().unwrap().exit_code, Some(0));
    assert_eq!(row.native.as_ref().unwrap().stdout.bytes, 3);
    assert!(row.reference.as_ref().unwrap().workspace_delta.is_some());
    assert!(row.native.as_ref().unwrap().workspace_delta.is_none());
    assert!(row.errors[0].contains("final workspace observation"));
}

#[test]
fn product_state_exclusion_is_explicit_and_does_not_hide_guest_artifacts() {
    let reference = project("// no artifacts");
    let candidate = project("const fs=require('fs'); fs.mkdirSync('.franken-node'); fs.writeFileSync('.franken-node/receipt','native'); fs.writeFileSync('guest-output','changed');");
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "FAIL");
    assert_eq!(report.filesystem_exclusions, ["**/.git", ".franken-node"]);
    let delta = report.cases[0].native.as_ref().unwrap().workspace_delta.as_ref().unwrap();
    assert_eq!(delta.changed_paths, 1);
    assert_eq!(delta.changes[0].path, "guest-output");
}

#[test]
fn distinct_nested_projects_are_refused_before_runtime_resolution() {
    let reference = project("console.log('ok');");
    let nested = reference.path().join("rewritten");
    fs::create_dir(&nested).unwrap();
    let error = run_project_comparison(reference.path(), Some(&nested), Path::new("/missing/runtime"), true)
        .unwrap_err();
    assert!(error.to_string().contains("must not be nested"));
}
