//! Real Node/Node executions of the production paired-input orchestrator.
//! Deliberately different programs test comparison, not Franken compatibility.
use super::*;

fn project(source: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("case.test.js"), source).unwrap();
    root
}

fn node() -> Invocation {
    Invocation {
        executable: node_on_path().expect("real Node required"),
        before: vec![],
        after: vec![],
    }
}

fn measured(reference: &Path, candidate: &Path, filesystem: bool) -> SuiteReport {
    let deadline = Instant::now() + Duration::from_secs(90);
    let reference = Snapshot::capture(reference, deadline).unwrap();
    let candidate = Snapshot::capture(candidate, deadline).unwrap();
    execute_suite_pair(
        &reference,
        &candidate,
        &node(),
        &node(),
        deadline,
        Duration::from_secs(5),
        filesystem,
    )
    .unwrap()
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
        assert_eq!(
            leg.as_ref()
                .unwrap()
                .workspace_delta
                .as_ref()
                .unwrap()
                .changed_paths,
            0
        );
    }
}

#[test]
fn console_agreement_cannot_hide_different_written_results() {
    let reference = project("require('fs').writeFileSync('result','original-secret');");
    let candidate = project("require('fs').writeFileSync('result','rewritten-secret');");
    let output_only = measured(reference.path(), candidate.path(), false);
    assert_eq!(output_only.verdict, "PASS");
    assert!(!output_only.filesystem_comparison);
    assert!(
        output_only.cases[0]
            .native
            .as_ref()
            .unwrap()
            .workspace_delta
            .is_none()
    );
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "FAIL");
    assert_eq!(
        report.cases[0].divergences,
        ["filesystem:workspace_delta_mismatch"]
    );
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
    let first = report.cases[0]
        .reference
        .as_ref()
        .unwrap()
        .workspace_delta
        .as_ref()
        .unwrap();
    let second = report.cases[0]
        .native
        .as_ref()
        .unwrap()
        .workspace_delta
        .as_ref()
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.changed_paths, 1);
    assert_eq!(
        first.changes[0].after.as_ref().unwrap().sha256,
        Some(hex::encode(Sha256::digest(b"42")))
    );
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
    let report = execute_suite_pair(
        &first,
        &second,
        &node(),
        &node(),
        deadline,
        Duration::from_secs(5),
        true,
    )
    .unwrap();
    assert_eq!(report.verdict, "PASS", "{report:#?}");
    assert_eq!(
        fs::read_to_string(candidate.path().join("case.test.js")).unwrap(),
        "process.exit(99);"
    );
}

#[test]
fn equal_counts_with_different_test_names_are_rejected_before_runtime_access() {
    let reference = project("console.log('reference');");
    let candidate = project("console.log('candidate');");
    fs::rename(
        candidate.path().join("case.test.js"),
        candidate.path().join("other.test.js"),
    )
    .unwrap();
    let error = run_project_comparison(
        reference.path(),
        Some(candidate.path()),
        Path::new("/missing/runtime"),
        false,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("test inventories differ"),
        "{error:#}"
    );
}

#[test]
fn added_or_removed_test_counterparts_cannot_shrink_the_suite() {
    let reference = project("console.log('ok');");
    let candidate = project("console.log('ok');");
    fs::write(candidate.path().join("extra.test.js"), "process.exit(8);").unwrap();
    for (before, after) in [
        (reference.path(), candidate.path()),
        (candidate.path(), reference.path()),
    ] {
        let error =
            run_project_comparison(before, Some(after), Path::new("/missing/runtime"), false)
                .unwrap_err();
        assert!(
            error.to_string().contains("test inventories differ"),
            "{error:#}"
        );
    }
}

#[test]
fn each_case_uses_its_own_original_and_candidate_dependencies() {
    let reference = project(
        "console.log(require('./helper')); require('fs').writeFileSync('helper.js','module.exports=99');",
    );
    let candidate = project(
        "console.log(require('./helper')); require('fs').writeFileSync('helper.js','module.exports=99');",
    );
    fs::write(reference.path().join("helper.js"), "module.exports=42;").unwrap();
    fs::write(candidate.path().join("helper.js"), "module.exports=21*2;").unwrap();
    for root in [reference.path(), candidate.path()] {
        fs::copy(root.join("case.test.js"), root.join("second.test.js")).unwrap();
    }
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(
        (report.passed, report.failed, report.errored, report.skipped),
        (2, 0, 0, 0),
        "{report:#?}"
    );
    for row in &report.cases {
        assert_eq!(
            row.native.as_ref().unwrap().stdout.sha256,
            hex::encode(Sha256::digest(b"42\n"))
        );
        assert_eq!(
            row.native
                .as_ref()
                .unwrap()
                .workspace_delta
                .as_ref()
                .unwrap()
                .changed_paths,
            1
        );
    }
    assert_eq!(
        fs::read_to_string(candidate.path().join("helper.js")).unwrap(),
        "module.exports=21*2;"
    );
}

#[test]
fn deletion_and_permission_only_divergence_block_pass() {
    for source in [
        "require('fs').unlinkSync('artifact');",
        "require('fs').chmodSync('artifact',0o600);",
    ] {
        let reference = project(source);
        let candidate = project("// same console output, missing effect");
        for root in [reference.path(), candidate.path()] {
            fs::write(root.join("artifact"), "same bytes").unwrap();
            fs::set_permissions(root.join("artifact"), fs::Permissions::from_mode(0o644)).unwrap();
        }
        let report = measured(reference.path(), candidate.path(), true);
        assert_eq!(report.verdict, "FAIL", "{report:#?}");
        assert_eq!(
            report.cases[0].divergences,
            ["filesystem:workspace_delta_mismatch"]
        );
    }
}

#[test]
fn dangling_output_links_are_measured_as_links() {
    let reference = project("require('fs').symlinkSync('missing-a','artifact');");
    let candidate = project("require('fs').symlinkSync('missing-b','artifact');");
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "FAIL", "{report:#?}");
    assert_eq!(
        report.cases[0].divergences,
        ["filesystem:workspace_delta_mismatch"]
    );
    assert_eq!(
        report.cases[0]
            .native
            .as_ref()
            .unwrap()
            .workspace_delta
            .as_ref()
            .unwrap()
            .changes[0]
            .after
            .as_ref()
            .unwrap()
            .kind,
        workspace_effects::NodeKind::Symlink
    );
}

#[test]
fn late_difference_beyond_report_preview_still_fails() {
    let common = "const fs=require('fs'); for(let i=0;i<25;i++)fs.writeFileSync('result-'+String(i).padStart(2,'0'),'same');";
    let reference = project(common);
    let candidate = project(&format!(
        "{common} fs.writeFileSync('result-24','different');"
    ));
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "FAIL", "{report:#?}");
    let first = report.cases[0]
        .reference
        .as_ref()
        .unwrap()
        .workspace_delta
        .as_ref()
        .unwrap();
    let second = report.cases[0]
        .native
        .as_ref()
        .unwrap()
        .workspace_delta
        .as_ref()
        .unwrap();
    assert_eq!(first.changed_paths, 25);
    assert_eq!(first.changes, second.changes);
    assert!(first.details_truncated);
    assert_ne!(first.sha256, second.sha256);
}

#[test]
fn filesystem_error_keeps_completed_process_evidence_and_later_cases() {
    let reference = project("console.log('ok');");
    let candidate =
        project("require('fs').linkSync('case.test.js','hardlink'); console.log('ok');");
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
    let candidate = project(
        "const fs=require('fs'); fs.mkdirSync('.franken-node'); fs.writeFileSync('.franken-node/receipt','native'); fs.writeFileSync('guest-output','changed');",
    );
    let report = measured(reference.path(), candidate.path(), true);
    assert_eq!(report.verdict, "FAIL");
    assert_eq!(report.filesystem_exclusions, ["**/.git", ".franken-node"]);
    let delta = report.cases[0]
        .native
        .as_ref()
        .unwrap()
        .workspace_delta
        .as_ref()
        .unwrap();
    assert_eq!(delta.changed_paths, 1);
    assert_eq!(delta.changes[0].path, "guest-output");
}

#[test]
fn distinct_nested_projects_are_refused_before_runtime_resolution() {
    let reference = project("console.log('ok');");
    let nested = reference.path().join("rewritten");
    fs::create_dir(&nested).unwrap();
    let error = run_project_comparison(
        reference.path(),
        Some(&nested),
        Path::new("/missing/runtime"),
        true,
    )
    .unwrap_err();
    assert!(error.to_string().contains("must not be nested"));
}

mod concurrent_pairs {
    use super::*;

    fn write(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn manifest(root: &Path, tests: &[&str], concurrency: Option<usize>) {
        let mut value = serde_json::json!({
            "schema_version": "franken-node/migration-tests/v1", "tests": tests,
        });
        if let Some(concurrency) = concurrency {
            value["max_concurrent_tests"] = concurrency.into();
        }
        write(root, ".franken-node/migration-tests.json", value.to_string());
    }

    fn role(name: &str) -> Invocation {
        Invocation { after: vec![name.into()], ..node() }
    }

    fn run(snapshot: &Snapshot, timeout: Duration, filesystem: bool) -> SuiteReport {
        execute_suite_pair(snapshot, snapshot, &role("reference"), &role("native"),
            Instant::now() + Duration::from_secs(120), timeout, filesystem).unwrap()
    }

    #[test]
    fn pair_cases_overlap_from_the_captured_grant_and_each_role_runs_once() {
        // A bounded inter-process handshake proves overlap without a speedup
        // threshold. A serial first case cannot finish before its peer starts.
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let log = outside.path().join("runs");
        write(root.path(), "dependency", "captured");
        for name in ["a", "b"] {
            write(root.path(), &format!("{name}.test.cjs"), format!(r#"
const fs = require('fs');
const role = process.argv[2];
const marker = {} + '/' + role;
(async () => {{
    if ('{name}' === 'a') {{
        const deadline = Date.now() + 4000;
        while (!fs.existsSync(marker) && Date.now() < deadline)
            await new Promise(resolve => setTimeout(resolve, 5));
        if (!fs.existsSync(marker)) throw new Error('concurrent peer did not execute');
    }} else fs.writeFileSync(marker, 'ready');
    const value = fs.readFileSync('dependency');
    fs.writeFileSync('artifact', value);
    fs.writeFileSync('dependency', 'guest mutation');
    fs.appendFileSync({}, '{name}:' + role + '\n');
    process.stdout.write(value);
}})().catch(error => {{ console.error(error.message); process.exitCode = 1; }});
"#, serde_json::to_string(outside.path()).unwrap(), serde_json::to_string(&log).unwrap()));
        }
        manifest(root.path(), &["a.test.cjs", "b.test.cjs"], Some(2));
        let deadline = Instant::now() + Duration::from_secs(120);
        let captured = Snapshot::capture(root.path(), deadline).unwrap();
        // Selection and bytes are from capture, not this changed live tree.
        manifest(root.path(), &["a.test.cjs", "b.test.cjs"], Some(1));
        write(root.path(), "dependency", "later source");
        let report = execute_suite_pair(&captured, &captured, &role("reference"),
            &role("native"), deadline, Duration::from_secs(8), true).unwrap();
        assert_eq!(report.verdict, "PASS", "{report:#?}");
        assert_eq!((report.passed, report.errored, report.skipped), (2, 0, 0));
        assert_eq!(report.cases.iter().map(|row| row.test.as_str()).collect::<Vec<_>>(),
            ["a.test.cjs", "b.test.cjs"]);
        let runs = fs::read_to_string(log).unwrap();
        assert_eq!(runs.lines().count(), 4);
        for name in ["a", "b"] {
            assert_eq!(runs.lines().filter(|line| line.starts_with(name)).collect::<Vec<_>>(),
                [format!("{name}:reference"), format!("{name}:native")]);
        }
        for row in &report.cases {
            assert_eq!(row.reference, row.native);
            assert_eq!(row.reference.as_ref().unwrap().stdout.sha256,
                hex::encode(Sha256::digest(b"captured")));
            assert_eq!(row.native.as_ref().unwrap().workspace_delta.as_ref().unwrap().changed_paths, 2);
        }
        assert_eq!(fs::read(root.path().join("dependency")).unwrap(), b"later source");
        assert!(!root.path().join("artifact").exists());
    }

    #[test]
    fn absent_concurrency_grant_keeps_case_and_role_order() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let log = outside.path().join("runs");
        for name in ["a", "b"] {
            write(root.path(), &format!("{name}.test.cjs"), format!(
                "require('fs').appendFileSync({},'{name}:'+process.argv[2]+'\\n');console.log(42);",
                serde_json::to_string(&log).unwrap()));
        }
        manifest(root.path(), &["b.test.cjs", "a.test.cjs"], None);
        let snapshot = Snapshot::capture(root.path(), Instant::now() + Duration::from_secs(30)).unwrap();
        let report = run(&snapshot, Duration::from_secs(5), false);
        assert_eq!(report.verdict, "PASS");
        assert_eq!(fs::read_to_string(log).unwrap(), "a:reference\na:native\nb:reference\nb:native\n");
    }

    #[test]
    fn serial_and_parallel_pairs_preserve_binary_requests_cwd_and_oracles() {
        let root = tempfile::tempdir().unwrap();
        let tests = ["nested/a.test.cjs", "nested/b.test.cjs", "nested/c.test.cjs"];
        write(root.path(), "request.bin", [0, 255, 1, 10]);
        let mut value = serde_json::json!({
            "schema_version": "franken-node/migration-tests/v1", "tests": tests,
            "max_concurrent_tests": 1, "execution": {}, "expectations": {},
        });
        for test in tests {
            write(root.path(), test,
                "const fs=require('fs');if(process.env.APP_MODE!=='test'||require('path').basename(process.cwd())!=='nested'||JSON.stringify(process.argv.slice(2))!==JSON.stringify(['--literal','two words']))process.exit(9);const b=fs.readFileSync(0);fs.writeFileSync('result.bin',b);process.stdout.write(b);");
            value["execution"][test] = serde_json::json!({
                "cwd": "nested", "stdin": "request.bin", "stdin_mode": "pipe",
                "environment": {"APP_MODE": "test"}, "arguments": ["--literal", "two words"],
            });
            value["expectations"][test] = serde_json::json!({
                "stdout": "request.bin", "files": {"nested/result.bin": "request.bin"},
            });
        }
        let mut cases = None;
        for concurrency in [1, 3] {
            value["max_concurrent_tests"] = concurrency.into();
            write(root.path(), ".franken-node/migration-tests.json", value.to_string());
            let report = measured(root.path(), root.path(), true);
            assert_eq!(report.verdict, "PASS", "{report:#?}");
            assert_eq!(report.passed, 3);
            if let Some(expected) = &cases { assert_eq!(&report.cases, expected); }
            cases = Some(report.cases);
        }
        assert_eq!(fs::read(root.path().join("request.bin")).unwrap(), [0, 255, 1, 10]);
        assert!(!root.path().join("nested/result.bin").exists());
    }

    #[test]
    fn failed_and_assertion_error_cases_do_not_erase_peers_or_stop_later_batches() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.cjs", "console.log(process.argv[2]==='native'?'wrong':'expected');");
        write(root.path(), "b.test.cjs", "console.log('wrong golden');");
        write(root.path(), "c.test.cjs", "console.log('later pass');");
        write(root.path(), "d.test.cjs", "process.exit(7);");
        write(root.path(), "golden", "expected\n");
        write(root.path(), ".franken-node/migration-tests.json", serde_json::json!({
            "schema_version": "franken-node/migration-tests/v1",
            "tests": ["a.test.cjs", "b.test.cjs", "c.test.cjs", "d.test.cjs"],
            "max_concurrent_tests": 2,
            "expectations": {"b.test.cjs": {"stdout": "golden"}},
        }).to_string());
        let snapshot = Snapshot::capture(root.path(), Instant::now() + Duration::from_secs(30)).unwrap();
        let report = run(&snapshot, Duration::from_secs(5), true);
        assert_eq!(report.verdict, "ERROR", "{report:#?}");
        assert_eq!((report.total_tests, report.passed, report.failed, report.errored, report.skipped),
            (4, 1, 2, 1, 0));
        assert_eq!(report.cases.iter().map(|row| row.status.as_str()).collect::<Vec<_>>(),
            ["FAIL", "ERROR", "PASS", "FAIL"]);
        assert_eq!(report.cases[1].errors.len(), 2);
        assert!(report.cases.iter().all(|row| row.reference.is_some() && row.native.is_some()));
        assert!(report.errors.is_empty());
    }

    #[test]
    fn concurrent_timeout_preserves_peer_and_later_cases_without_a_fake_pass() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.cjs",
            "console.log(42);if(process.argv[2]==='native')setInterval(()=>{},1000);");
        for test in ["b.test.cjs", "c.test.cjs"] {
            write(root.path(), test, "console.log(42);");
        }
        manifest(root.path(), &["a.test.cjs", "b.test.cjs", "c.test.cjs"], Some(2));
        let snapshot = Snapshot::capture(root.path(), Instant::now() + Duration::from_secs(30)).unwrap();
        let report = run(&snapshot, Duration::from_secs(1), false);
        assert_eq!(report.verdict, "ERROR", "{report:#?}");
        assert_eq!((report.passed, report.errored, report.skipped), (2, 1, 0));
        assert!(report.cases[0].reference.is_some());
        assert!(report.cases[0].native.is_none());
        assert!(report.cases[0].errors[0].contains("timed out"));
        assert_eq!(report.cases[1].status, "PASS");
        assert_eq!(report.cases[2].status, "PASS");
    }

    #[test]
    fn pair_capsules_replay_the_captured_concurrency_and_inputs_not_the_live_manifest() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        for test in ["a.test.cjs", "b.test.cjs"] {
            write(root.path(), test, "console.log('captured');");
        }
        manifest(root.path(), &["a.test.cjs", "b.test.cjs"], Some(2));
        // The explicitly failing executable exercises capsule/runner plumbing,
        // not successful native Franken compatibility.
        let captured = native_replay::capture_project(root.path(), None, Path::new("/bin/false"), true).unwrap();
        assert_eq!((captured.report.failed, captured.report.errored, captured.report.skipped), (2, 0, 0));
        let capsule = output.path().join("pair.json");
        let summary = captured.write_capsule(&capsule).unwrap();
        let bytes = fs::read(&capsule).unwrap();
        manifest(root.path(), &["a.test.cjs", "b.test.cjs"], Some(1));
        write(root.path(), "a.test.cjs", "process.exit(99);");
        let replayed = native_replay::replay(&capsule, &summary.content_sha256, Path::new("/bin/false"), false).unwrap();
        assert_eq!(replayed.verdict, "REPRODUCED", "{replayed:#?}");
        assert_eq!(replayed.validation.cases, captured.report.cases);
        assert_eq!(replayed.validation.verdict, "FAIL");
        assert_eq!(fs::read(&capsule).unwrap(), bytes);
        assert_eq!(fs::read_to_string(root.path().join("a.test.cjs")).unwrap(), "process.exit(99);");
    }
}
