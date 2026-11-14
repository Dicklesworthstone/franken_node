//! Primary product-command regressions, not standalone-operator tests.
//! Uses the actual Cargo-built franken-node binary and installed Node. A
//! successful native case is required to demonstrate positive admission;
//! missing policy/engine capabilities must fail that test, never skip it.

#[path = "native_rewrite_transactions.rs"]
mod rewrite_transactions;

use super::{
    TempDir, franken_node_command, initialize_native_project, native_smoke_supervisor,
    parse_json_stdout, repo_root,
};
use std::path::Path;
use std::process::Output;
use std::time::Duration;

const FAILURE_DIRECTORY: &str = "FRANKEN_NODE_MIGRATION_FAILURE_DIR";

fn project(first_case: &str) -> TempDir {
    let project = TempDir::new().expect("project");
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"native-suite-regression","version":"1.0.0","engines":{"node":">=20"}}"#,
    )
    .expect("manifest");
    std::fs::write(
        project.path().join("package-lock.json"),
        "{\"lockfileVersion\":3,\"packages\":{\"\":{}}}\n",
    )
    .expect("lockfile");
    std::fs::write(
        project.path().join("index.js"),
        "console.log('smoke-only');\n",
    )
    .expect("entrypoint");
    std::fs::write(project.path().join("a.test.js"), first_case).expect("first case");
    std::fs::write(project.path().join("b.test.js"), "console.log(42);\n").expect("second case");
    project
}

fn invoke(path: &Path, report: bool, static_only: bool, empty_path: bool) -> Output {
    invoke_with_archive(path, report, static_only, empty_path, None)
}

fn invoke_with_archive(
    path: &Path,
    report: bool,
    static_only: bool,
    empty_path: bool,
    archive: Option<&Path>,
) -> Output {
    let mut command = franken_node_command();
    command
        .current_dir(repo_root())
        .env_remove(FAILURE_DIRECTORY);
    if let Some(directory) = archive {
        command.env(FAILURE_DIRECTORY, directory);
    }
    if report {
        command.arg("migrate-report");
    } else {
        command.args(["migrate", "validate"]);
    }
    command.arg(path).arg("--json");
    if static_only {
        command.arg("--static-only");
    }
    if empty_path {
        command.env("PATH", "");
    }
    native_smoke_supervisor::run_command_with_timeout(
        &mut command,
        Duration::from_secs(120),
        Duration::from_secs(1),
    )
    .expect("primary migration command must terminate within the bounded test")
}

fn assert_no_guest_state(project: &TempDir) {
    assert!(
        !project.path().join(".franken-node").exists(),
        "suite execution must use disposable copies, not the caller's tree"
    );
    assert!(!project.path().join("executed").exists());
}

#[test]
fn validate_reports_every_discovered_case_without_smoke_rescue() {
    let project = project("const = ;\n");
    initialize_native_project(project.path(), false);
    let output = invoke(project.path(), false, false, false);
    assert!(!output.status.success());
    let report = parse_json_stdout(&output, "primary suite validation");
    assert_eq!(report["status"], "fail", "{report}");
    let suite = &report["test_suite"];
    assert_eq!(suite["total_tests"], 2, "suite not reached: {report}");
    assert_eq!(suite["cases"].as_array().expect("cases").len(), 2);
    assert_eq!(suite["skipped"], 0);
    assert_eq!(suite["release_certification"], false);
    assert_eq!(suite["cases"][0]["test"], "a.test.js");
    assert_eq!(suite["cases"][1]["test"], "b.test.js");
    assert_ne!(suite["cases"][0]["status"], "PASS");
    assert_eq!(suite["cases"][1]["status"], "PASS", "{report}");
    assert!(
        suite["input_sha256"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("a.test.js")).expect("original case"),
        "const = ;\n"
    );
    assert_no_guest_state(&project);
}

#[test]
fn primary_report_keeps_rollout_blocked_after_suite_failure() {
    let project = project("const = ;\n");
    initialize_native_project(project.path(), false);
    let output = invoke(project.path(), true, false, false);
    // Report generation may succeed while its admission decision is no-go.
    let report = parse_json_stdout(&output, "primary report suite propagation");
    assert_eq!(
        report["validation"]["test_suite"]["total_tests"], 2,
        "{report}"
    );
    assert_eq!(report["validation"]["status"], "fail");
    assert_eq!(report["validation"]["test_suite"]["passed"], 1, "{report}");
    assert_eq!(report["validation"]["test_suite"]["failed"], 1, "{report}");
    assert_eq!(report["executive_summary"]["go_no_go"], "no_go");
    let rollout = report["rollout_plan"]["phases"]
        .as_array()
        .expect("phases")
        .iter()
        .find(|phase| phase["name"] == "rollout")
        .expect("rollout phase");
    assert_eq!(rollout["status"], "blocked");
    assert_no_guest_state(&project);
}

#[test]
fn static_only_is_independent_of_installed_runtimes_and_never_executes() {
    let project = project("require('fs').writeFileSync('executed','unexpected');\n");
    let output = invoke(project.path(), false, true, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report = parse_json_stdout(&output, "static-only suite project");
    assert_eq!(report["status"], "pass");
    assert!(report.get("test_suite").is_none());
    assert_eq!(report["checks"].as_array().expect("checks").len(), 4);
    assert_no_guest_state(&project);
}

#[test]
fn missing_reference_cannot_fall_back_to_native_entrypoint_smoke() {
    let project = project("require('fs').writeFileSync('executed','unexpected');\n");
    let output = invoke(project.path(), false, false, true);
    assert!(!output.status.success());
    let report = parse_json_stdout(&output, "missing reference");
    assert_eq!(report["status"], "fail");
    assert!(
        report["checks"][4]["message"]
            .as_str()
            .expect("message")
            .contains("requires Node")
    );
    assert!(report.get("test_suite").is_none());
    assert_no_guest_state(&project);
}

#[test]
fn invalid_capture_cannot_fall_back_to_entrypoint_smoke() {
    use std::os::unix::fs::symlink;
    let project = project("console.log('test');\n");
    let external = TempDir::new().expect("external input");
    let outside = external.path().join("outside");
    std::fs::write(&outside, "must not be captured").expect("external input");
    symlink(outside, project.path().join("external-link")).expect("external symlink");
    let output = invoke(project.path(), false, false, false);
    assert!(!output.status.success());
    let report = parse_json_stdout(&output, "invalid capture");
    assert_eq!(report["status"], "fail");
    assert!(
        report["checks"][4]["message"]
            .as_str()
            .expect("message")
            .contains("symlink")
    );
    assert!(report.get("test_suite").is_none());
    assert_no_guest_state(&project);
}

#[test]
fn static_prerequisites_block_all_runtime_dispatch() {
    let project = project("require('fs').writeFileSync('executed','unexpected');\n");
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"blocked","engines":{"node":">=20"},"scripts":{"postinstall":"echo blocked"}}"#,
    )
    .expect("risky manifest");
    let output = invoke(project.path(), false, false, true);
    assert!(!output.status.success());
    let report = parse_json_stdout(&output, "static prerequisite refusal");
    assert_eq!(report["status"], "fail");
    assert!(
        report["checks"][4]["message"]
            .as_str()
            .expect("message")
            .contains("static validation checks failed")
    );
    assert!(report.get("test_suite").is_none());
    assert_no_guest_state(&project);
}

fn invoke_autopilot(path: &Path, bun: &Path, apply: bool) -> Output {
    let mut command = franken_node_command();
    command
        .current_dir(repo_root())
        .env_remove(FAILURE_DIRECTORY)
        .env_remove("FRANKEN_NODE_CHECKED_REWRITE_BUN_BIN")
        .args(["migrate", "autopilot"])
        .arg(path)
        .args(["--execute", "--json", "--bun-bin"])
        .arg(bun);
    if apply {
        command.arg("--apply");
    }
    native_smoke_supervisor::run_command_with_timeout(
        &mut command,
        Duration::from_secs(360),
        Duration::from_secs(1),
    )
    .expect("migration autopilot must terminate within the bounded test")
}

#[test]
fn autopilot_missing_bun_cannot_downgrade_to_a_two_runtime_success() {
    let project = project("console.log(require('path').basename('/tmp/42'));\n");
    let absent = TempDir::new().expect("absent runtime directory");
    let bun = absent.path().join("reference-bun-unavailable");
    let original = std::fs::read(project.path().join("a.test.js")).unwrap();
    let output = invoke_autopilot(project.path(), &bun, false);
    assert!(!output.status.success());
    let report = parse_json_stdout(&output, "missing autopilot Bun reference");
    assert_eq!(
        report["schema_version"],
        "franken-node/migration-autopilot/v1"
    );
    assert_eq!(report["ok"], false);
    assert_eq!(report["mode"], "preview");
    let checked = &report["checked_rewrite"];
    assert_eq!(checked["status"], "ERROR");
    assert!(checked["validation"].is_null());
    assert!(checked.get("product_validation").is_none());
    assert!(checked.get("transaction").is_none());
    assert!(
        checked["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("resolve Bun executable")),
        "{report}"
    );
    assert_eq!(
        std::fs::read(project.path().join("a.test.js")).unwrap(),
        original
    );
    assert!(!project.path().join(".migrate-backup").exists());
    assert_no_guest_state(&project);
}

#[test]
fn autopilot_pending_rewrite_stops_preview_without_recovering_or_resolving_runtimes() {
    let project = project("console.log(42);\n");
    let pending = project
        .path()
        .join(".migrate-backup/.franken-rewrite/pending.json");
    std::fs::create_dir_all(pending.parent().unwrap()).unwrap();
    let retained = b"pending operation must remain untouched";
    std::fs::write(&pending, retained).unwrap();
    let output = invoke_autopilot(project.path(), Path::new("/absent-bun"), false);
    assert!(!output.status.success());
    let report = parse_json_stdout(&output, "autopilot pending recovery refusal");
    assert_eq!(report["checked_rewrite"]["status"], "ERROR");
    assert!(report["checked_rewrite"]["static_validation"].is_null());
    assert!(
        report["checked_rewrite"]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("unfinished rewrite")),
        "{report}"
    );
    assert_eq!(std::fs::read(&pending).unwrap(), retained);
    assert!(!pending.parent().unwrap().join("lock").exists());
    assert_no_guest_state(&project);
}

#[cfg(feature = "engine")]
#[test]
fn autopilot_real_triad_preview_apply_and_exact_transaction_rollback() {
    use frankenengine_node::migration::validation_suite::rewrite_candidate::RewriteCandidate;
    use std::time::Instant;

    let bun = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join("bun"))
        .find(|path| path.is_file())
        .expect("the native autopilot acceptance test requires installed Bun")
        .canonicalize()
        .unwrap();
    let source = "console.log(require('path').basename('/tmp/42'));\n";
    let project = project(source);
    initialize_native_project(project.path(), false);
    let captured =
        RewriteCandidate::capture(project.path(), Instant::now() + Duration::from_secs(30))
            .unwrap();
    let expected_native = std::fs::canonicalize(franken_node_command().get_program()).unwrap();

    let output = invoke_autopilot(project.path(), &bun, false);
    let preview = parse_json_stdout(&output, "actual native autopilot preview");
    assert!(output.status.success(), "{preview}");
    assert_eq!(preview["mode"], "preview");
    assert_eq!(preview["checked_rewrite"]["status"], "VALIDATED");
    assert_eq!(preview["checked_rewrite"]["rewrite"]["rewrites_planned"], 1);
    assert_eq!(preview["checked_rewrite"]["rewrite"]["rewrites_applied"], 0);
    assert!(preview["checked_rewrite"].get("transaction").is_none());
    assert!(!project.path().join(".migrate-backup").exists());
    captured.ensure_source_unchanged().unwrap();
    assert_no_guest_state(&project);

    let output = invoke_autopilot(project.path(), &bun, true);
    let applied = parse_json_stdout(&output, "actual native autopilot apply");
    assert!(output.status.success(), "{applied}");
    assert_eq!(applied["mode"], "apply");
    assert_eq!(applied["checked_rewrite"]["status"], "APPLIED");
    assert_eq!(applied["checked_rewrite"]["rewrite"]["rewrites_applied"], 1);
    assert!(
        std::fs::read_to_string(project.path().join("a.test.js"))
            .unwrap()
            .contains("node:path")
    );
    for report in [&preview, &applied] {
        assert_eq!(report["ok"], true);
        assert_eq!(report["release_certification"], false);
        let measured = &report["checked_rewrite"]["product_validation"];
        assert_eq!(measured["verdict"], "PASS");
        assert_eq!(measured["total_tests"], 2);
        assert_eq!(measured["passed"], 2);
        assert_eq!(measured["errored"], 0);
        assert_eq!(measured["skipped"], 0);
        assert_eq!(measured["filesystem_comparison"], true);
        assert_eq!(measured["distinct_reference_binaries"], true);
        assert_eq!(
            measured["native_runtime"]["executable"],
            expected_native.to_str().unwrap()
        );
        assert_ne!(
            measured["native_runtime"]["sha256"],
            measured["node_runtime"]["sha256"]
        );
        assert_ne!(
            measured["native_runtime"]["sha256"],
            measured["bun_runtime"]["sha256"]
        );
        assert_ne!(measured["input_sha256"], measured["candidate_input_sha256"]);
        for case in measured["cases"].as_array().unwrap() {
            assert_eq!(case["outcome"], "MATCH");
            for runtime in ["node", "bun", "native"] {
                assert_eq!(case[runtime]["exit_code"], 0);
                assert_eq!(case[runtime]["stdout"]["bytes"], 3);
                assert_eq!(case[runtime]["stdout"], case["node"]["stdout"]);
                assert_eq!(case[runtime]["stderr"], case["node"]["stderr"]);
                assert_eq!(
                    case[runtime]["workspace_delta"],
                    case["node"]["workspace_delta"]
                );
            }
        }
    }
    let transaction = &applied["checked_rewrite"]["transaction"];
    let id = transaction["transaction_id"].as_str().unwrap();
    let mut command = franken_node_command();
    command
        .current_dir(repo_root())
        .args(["migrate", "rollback"])
        .arg(project.path())
        .args(["--transaction", id, "--apply", "--json"]);
    let output = native_smoke_supervisor::run_command_with_timeout(
        &mut command,
        Duration::from_secs(60),
        Duration::from_secs(1),
    )
    .unwrap();
    let restored = parse_json_stdout(&output, "rollback exact autopilot installation");
    assert!(output.status.success(), "{restored}");
    assert_eq!(restored["status"], "ROLLED_BACK");
    assert_eq!(restored["transaction"]["transaction_id"], id);
    assert_eq!(
        restored["transaction"]["journal_sha256"],
        transaction["journal_sha256"]
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("a.test.js")).unwrap(),
        source
    );
}

#[cfg(feature = "engine")]
#[test]
fn successful_native_suite_requires_two_complete_measured_cases() {
    let project = project("console.log(6*7);\n");
    initialize_native_project(project.path(), false);
    let output = invoke(project.path(), false, false, false);
    let report = parse_json_stdout(&output, "successful primary native suite");
    assert!(
        output.status.success(),
        "native suite did not pass: {report}"
    );
    assert_eq!(report["status"], "pass");
    let suite = &report["test_suite"];
    assert_eq!(suite["verdict"], "PASS");
    assert_eq!(suite["passed"], 2);
    assert_eq!(suite["failed"], 0);
    assert_eq!(suite["errored"], 0);
    assert_eq!(suite["skipped"], 0);
    for row in suite["cases"].as_array().expect("cases") {
        assert_eq!(row["reference"]["exit_code"], 0);
        assert_eq!(row["native"]["exit_code"], 0);
        assert_eq!(row["native"]["stdout"]["bytes"], 3);
        assert_eq!(row["native"]["stdout"], row["reference"]["stdout"]);
        assert!(
            row["divergences"]
                .as_array()
                .expect("divergences")
                .is_empty()
        );
    }
    assert_no_guest_state(&project);
}

#[cfg(feature = "engine")]
#[test]
fn validate_and_report_execute_only_the_selected_nested_package_inventory() {
    let container = TempDir::new().expect("project container");
    let app = container.path().join("app");
    std::fs::create_dir_all(&app).expect("nested project");
    // Declared dependencies require actual authoritative trust state, even
    // when the selected test does not import those dependencies.
    initialize_native_project(&app, true);
    std::fs::create_dir_all(app.join(".franken-node")).expect("test inventory directory");
    let manifest = r#"{"name":"nested-suite","version":"1.0.0","engines":{"node":">=20"},"dependencies":{"ordinary":"^1"}}"#;
    let lock = r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"ordinary":"^1"}},"node_modules/ordinary":{"version":"1.2.3"}}}"#;
    let installed_manifest = r#"{"name":"ordinary","version":"1.2.3"}"#;
    let inventory =
        r#"{"schema_version":"franken-node/migration-tests/v1","tests":["inside.test.js"]}"#;
    let outside = "throw new Error('outside admitted package');\n";
    let ignored = "throw new Error('not selected by package inventory');\n";
    std::fs::write(app.join("package.json"), manifest).expect("manifest");
    std::fs::write(app.join("package-lock.json"), lock).expect("lockfile");
    std::fs::create_dir_all(app.join("node_modules/ordinary")).expect("installed package");
    std::fs::write(
        app.join("node_modules/ordinary/package.json"),
        installed_manifest,
    )
    .expect("installed manifest");
    std::fs::write(
        app.join("node_modules/ordinary/index.js"),
        "module.exports = 42;\n",
    )
    .expect("installed source");
    std::fs::write(app.join(".franken-node/migration-tests.json"), inventory)
        .expect("selected test inventory");
    std::fs::write(app.join("inside.test.js"), "console.log(42);\n").expect("selected case");
    std::fs::write(app.join("ignored.test.js"), ignored).expect("unselected case");
    std::fs::write(container.path().join("outside.test.js"), outside).expect("outside case");

    for report_mode in [false, true] {
        let output = invoke(container.path(), report_mode, false, false);
        let report = parse_json_stdout(&output, "nested package runtime scope");
        assert!(output.status.success(), "{report}");
        let validation = if report_mode {
            &report["validation"]
        } else {
            &report
        };
        assert_eq!(validation["status"], "pass", "{report}");
        let suite = &validation["test_suite"];
        assert_eq!(suite["verdict"], "PASS", "{report}");
        assert_eq!(suite["total_tests"], 1);
        assert_eq!(suite["passed"], 1);
        assert_eq!(suite["failed"], 0);
        assert_eq!(suite["errored"], 0);
        assert_eq!(suite["skipped"], 0);
        let cases = suite["cases"].as_array().expect("measured cases");
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0]["test"], "inside.test.js");
        assert_eq!(cases[0]["reference"]["exit_code"], 0);
        assert_eq!(cases[0]["native"]["exit_code"], 0);
        assert_eq!(cases[0]["native"]["stdout"]["bytes"], 3);
        assert_eq!(
            cases[0]["reference"]["stdout"],
            cases[0]["native"]["stdout"]
        );
        let inputs = validation["dependency_admission"]["inputs"]
            .as_array()
            .expect("audit evidence");
        assert!(
            inputs
                .iter()
                .all(|input| input["path"].as_str().unwrap().starts_with("app/"))
        );
        assert_eq!(
            std::fs::read_to_string(app.join("package.json")).unwrap(),
            manifest
        );
        assert_eq!(
            std::fs::read_to_string(app.join("package-lock.json")).unwrap(),
            lock
        );
        assert_eq!(
            std::fs::read_to_string(app.join("node_modules/ordinary/package.json")).unwrap(),
            installed_manifest,
        );
        assert_eq!(
            std::fs::read_to_string(app.join(".franken-node/migration-tests.json")).unwrap(),
            inventory
        );
        assert_eq!(
            std::fs::read_to_string(app.join("ignored.test.js")).unwrap(),
            ignored
        );
        assert_eq!(
            std::fs::read_to_string(container.path().join("outside.test.js")).unwrap(),
            outside
        );
        assert!(!container.path().join(".franken-node").exists());
        assert!(!container.path().join(".migrate-backup").exists());
    }
}

#[test]
fn primary_validate_and_report_retain_their_actual_failed_measurements_when_requested() {
    use std::os::unix::fs::PermissionsExt;
    for report_mode in [false, true] {
        let project = project("const = ;\n");
        let archives = TempDir::new().expect("private archive parent");
        let output = invoke_with_archive(
            project.path(),
            report_mode,
            false,
            false,
            Some(archives.path()),
        );
        let report = parse_json_stdout(&output, "automatic primary failure capture");
        let validation = if report_mode {
            &report["validation"]
        } else {
            &report
        };
        assert_eq!(validation["status"], "fail", "{report}");
        let suite = &validation["test_suite"];
        assert_eq!(suite["verdict"], "FAIL", "{report}");
        assert_eq!(suite["total_tests"], 2);
        let capture = &suite["failure_capture"];
        assert_eq!(capture["status"], "SAVED", "{report}");
        let path = Path::new(
            capture["capsule_path"]
                .as_str()
                .expect("retained capsule path"),
        );
        assert!(path.starts_with(archives.path()));
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let archive: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(archive["content_sha256"], capture["content_sha256"]);
        let expected = &archive["payload"]["expected"];
        assert_eq!(expected["cases"], suite["cases"]);
        assert_eq!(expected["input_sha256"], suite["input_sha256"]);
        assert_eq!(
            expected["candidate_input_sha256"],
            suite["candidate_input_sha256"]
        );
        assert_eq!(expected["reference_runtime"], suite["reference_runtime"]);
        assert_eq!(expected["native_runtime"], suite["native_runtime"]);
        assert!(
            expected.get("failure_capture").is_none(),
            "archive must not recursively refer to its own hash"
        );
        if report_mode {
            assert_eq!(report["executive_summary"]["go_no_go"], "no_go");
        } else {
            assert!(!output.status.success());
        }
        assert_no_guest_state(&project);
        assert_eq!(
            std::fs::read_to_string(project.path().join("a.test.js")).unwrap(),
            "const = ;\n"
        );
    }
}

#[test]
fn invalid_failure_storage_blocks_dispatch_instead_of_ignoring_the_requested_capture() {
    let project = project("require('fs').writeFileSync('executed','unexpected');\n");
    // An empty PATH also proves that storage preflight precedes Node discovery.
    let output = invoke_with_archive(project.path(), false, false, true, Some(project.path()));
    let report = parse_json_stdout(&output, "invalid failure storage");
    assert!(!output.status.success());
    assert_eq!(report["status"], "fail");
    assert!(report.get("test_suite").is_none());
    let message = report["checks"][4]["message"]
        .as_str()
        .expect("failure reason");
    assert!(message.contains(FAILURE_DIRECTORY), "{report}");
    assert!(
        !message.contains("requires Node"),
        "archive preflight must run first: {report}"
    );
    assert_no_guest_state(&project);
}

#[test]
fn static_only_and_failed_prerequisites_never_reserve_failure_storage() {
    let project = project("require('fs').writeFileSync('executed','unexpected');\n");
    // Even invalid capture configuration is irrelevant to static-only work.
    let output = invoke_with_archive(project.path(), false, true, true, Some(project.path()));
    let report = parse_json_stdout(&output, "static-only with capture configured");
    assert!(output.status.success(), "{report}");
    assert_eq!(report["status"], "pass");
    assert!(report.get("test_suite").is_none());
    let archives = TempDir::new().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"blocked","scripts":{"postinstall":"echo blocked"}}"#,
    )
    .unwrap();
    let output = invoke_with_archive(project.path(), false, false, true, Some(archives.path()));
    let report = parse_json_stdout(&output, "static prerequisite before failure storage");
    assert!(!output.status.success());
    assert!(
        report["checks"][4]["message"]
            .as_str()
            .unwrap()
            .contains("static validation checks failed")
    );
    assert_eq!(std::fs::read_dir(archives.path()).unwrap().count(), 0);
    assert_no_guest_state(&project);
}

#[test]
fn primary_attestation_flags_cannot_silently_downgrade_or_omit_execution_consent() {
    let project = TempDir::new().unwrap();
    let complete = [
        "--attest",
        "--bun-bin",
        "/missing-bun",
        "--signing-key",
        "/missing-key",
        "--out",
        "/missing-report",
        "--execute",
    ];
    let mut cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["--attest"], "--execute"),
        (complete[..complete.len() - 1].to_vec(), "--execute"),
        (vec!["--bun-bin", "/missing-bun"], "--attest"),
        (vec!["--signing-key", "/missing-key"], "--attest"),
        (vec!["--out", "/missing-report"], "--attest"),
        (vec!["--execute"], "--attest"),
        (vec!["--attest-regression"], "--attest"),
        (vec!["--expected-input-sha256", "a"], "--attest"),
        (vec!["--expected-candidate-input-sha256", "b"], "--attest"),
    ];
    let mut static_mode = complete.to_vec();
    static_mode.push("--static-only");
    cases.push((static_mode, "cannot be used with"));
    let mut candidate = complete.to_vec();
    candidate.extend(["--migrated-project", "/missing-candidate"]);
    cases.push((candidate.clone(), "--expected-input-sha256"));
    candidate.extend(["--expected-input-sha256", "a"]);
    cases.push((candidate, "--expected-candidate-input-sha256"));
    for (arguments, expected) in cases {
        let output = franken_node_command()
            .current_dir(repo_root())
            .args(["migrate", "validate"])
            .arg(project.path())
            .arg("--json")
            .args(&arguments)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "accepted invalid flags: {arguments:?}"
        );
        let error = parse_json_stdout(&output, "attested argument contract");
        assert_eq!(error["schema_version"], "franken-node/migrate-error-cli/v1");
        assert!(
            error["error"].as_str().unwrap().contains(expected),
            "{arguments:?}: {error}"
        );
    }
    assert_eq!(
        std::fs::read_dir(project.path()).unwrap().count(),
        0,
        "invalid flags must not execute or initialize a project"
    );
}

mod autopilot_rollout_cli {
    use super::*;
    use ed25519_dalek::SigningKey;
    use frankenengine_node::migration::report_attestation;
    use frankenengine_node::migration::validation_suite::rewrite_candidate::RewriteCandidate;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Instant;

    const ROLLOUT_ANCHOR: &str = ".franken-node/keys/migration-rollout.pub";

    struct Fixture {
        root: TempDir,
        project: PathBuf,
        validation_key: PathBuf,
        rollout_key: PathBuf,
        out: PathBuf,
    }

    impl Fixture {
        fn new(count: usize) -> Self {
            let root = TempDir::new().unwrap();
            let project = root.path().join("project");
            fs::create_dir(&project).unwrap();
            initialize_native_project(&project, false);
            fs::write(
                project.join("package.json"),
                r#"{"name":"autopilot-rollout","version":"1.0.0","engines":{"node":">=20"}}"#,
            )
            .unwrap();
            fs::write(
                project.join("package-lock.json"),
                r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
            )
            .unwrap();
            for index in 0..count {
                // Distinct curated tests exercise the real admission path;
                // they do not establish independent production samples.
                fs::write(
                    project.join(format!("case-{index:02}.test.js")),
                    format!("console.log(require('path').basename('/tmp/{index}'));\n"),
                )
                .unwrap();
            }
            fs::create_dir_all(project.join(".franken-node/keys")).unwrap();
            let validation_key = root.path().join("validator.seed");
            let rollout_key = root.path().join("operator.seed");
            for (path, seed) in [(&validation_key, 81_u8), (&rollout_key, 82_u8)] {
                fs::write(path, [seed; 32]).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            fs::write(
                project.join(report_attestation::PUBLIC_KEY_PATH),
                hex::encode(SigningKey::from_bytes(&[81; 32]).verifying_key().to_bytes()),
            )
            .unwrap();
            fs::write(
                project.join(ROLLOUT_ANCHOR),
                hex::encode(SigningKey::from_bytes(&[82; 32]).verifying_key().to_bytes()),
            )
            .unwrap();
            let out = root.path().join("installed-validation.signed.json");
            Self {
                root,
                project,
                validation_key,
                rollout_key,
                out,
            }
        }

        fn execute(&self, bun: &Path) -> Output {
            let mut command = franken_node_command();
            command
                .current_dir(repo_root())
                .env_remove(FAILURE_DIRECTORY)
                .env_remove("FRANKEN_NODE_CHECKED_REWRITE_BUN_BIN")
                .env_remove("FRANKEN_NODE_ROLLOUT_SIGNING_KEY")
                .env_remove("FRANKEN_NODE_ROLLOUT_EXPECTED_HEAD_SHA256")
                .args(["migrate", "autopilot"])
                .arg(&self.project)
                .args(["--execute", "--apply", "--rollout", "--json", "--bun-bin"])
                .arg(bun)
                .arg("--signing-key")
                .arg(&self.validation_key)
                .arg("--rollout-signing-key")
                .arg(&self.rollout_key)
                .arg("--out")
                .arg(&self.out);
            native_smoke_supervisor::run_command_with_timeout(
                &mut command,
                Duration::from_secs(660),
                Duration::from_secs(1),
            )
            .expect("the two bounded live validation phases must terminate")
        }

        #[cfg(feature = "engine")]
        fn measured_report(&self) -> serde_json::Value {
            let raw = fs::read(&self.out).unwrap();
            let verified = report_attestation::verify(
                &raw,
                &SigningKey::from_bytes(&[81; 32]).verifying_key(),
            )
            .unwrap();
            serde_json::from_slice(&verified).unwrap()
        }

        #[cfg(feature = "engine")]
        fn signed_state(
            &self,
            transaction: &str,
        ) -> (u64, frankenengine_node::migration::rollout::RolloutState) {
            let filename = format!("{transaction}.json");
            let raw = fs::read(
                self.project
                    .join(".franken-node/state/rollout")
                    .join(&filename),
            )
            .unwrap();
            let verified = report_attestation::rollout_receipt::verify(
                &raw,
                &SigningKey::from_bytes(&[82; 32]).verifying_key(),
                self.project.canonicalize().unwrap().to_str().unwrap(),
                &filename,
            )
            .unwrap();
            (
                verified.revision(),
                serde_json::from_slice(verified.state_bytes()).unwrap(),
            )
        }
    }

    #[cfg(feature = "engine")]
    fn real_bun() -> PathBuf {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|directory| directory.is_absolute())
            .map(|directory| directory.join("bun"))
            .find(|path| path.is_file())
            .expect("the native autopilot rollout acceptance tests require real installed Bun")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn autopilot_rollout_rejects_bad_authority_and_existing_report_before_installation() {
        for fault in 0..3 {
            let fixture = Fixture::new(2);
            let captured = RewriteCandidate::capture(
                &fixture.project,
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
            let expected = match fault {
                0 => {
                    fs::write(&fixture.validation_key, [91; 32]).unwrap();
                    "does not match"
                }
                1 => {
                    fs::write(&fixture.rollout_key, [92; 32]).unwrap();
                    "does not match"
                }
                2 => {
                    fs::write(&fixture.out, b"retained independent report").unwrap();
                    "already exists"
                }
                _ => unreachable!(),
            };
            let output = fixture.execute(&fixture.root.path().join("absent-bun"));
            assert!(!output.status.success());
            let report = parse_json_stdout(&output, "autopilot rollout authority preflight");
            assert_eq!(
                report["schema_version"],
                "franken-node/migrate-error-cli/v1"
            );
            assert_eq!(report["command"], "migrate.autopilot");
            assert!(
                report["error"].as_str().unwrap().contains(expected),
                "{report}"
            );
            assert!(!fixture.project.join(".migrate-backup").exists());
            assert!(!fixture.project.join(".franken-node/state").exists());
            captured.ensure_source_unchanged().unwrap();
            if fault == 2 {
                assert_eq!(
                    fs::read(&fixture.out).unwrap(),
                    b"retained independent report"
                );
            } else {
                assert!(!fixture.out.exists());
            }
        }
    }

    #[cfg(feature = "engine")]
    #[test]
    fn autopilot_rollout_signs_fresh_installed_inputs_but_keeps_low_sample_shadow() {
        let fixture = Fixture::new(2);
        let output = fixture.execute(&real_bun());
        let report = parse_json_stdout(&output, "autopilot low-sample rollout refusal");
        assert!(!output.status.success(), "{report}");
        assert_eq!(report["ok"], false);
        assert_eq!(report["phase"], "rollout-promotion");
        assert_eq!(report["checked_rewrite"]["status"], "APPLIED");
        assert_eq!(report["checked_rewrite"]["rewrite"]["rewrites_applied"], 2);
        assert_eq!(report["attestation"]["verdict"], "PASS");
        assert_eq!(report["attestation"]["total_tests"], 2);
        assert_eq!(report["rollout"]["stage"], "shadow");
        assert_eq!(report["rollout"]["status"], "pending");
        assert_eq!(report["rollout"]["rollback_triggered"], false);
        assert!(
            report["errors"].as_array().unwrap().iter().any(|error| {
                error
                    .as_str()
                    .unwrap()
                    .contains("insufficient cohort evidence")
            }),
            "{report}"
        );
        let measured = fixture.measured_report();
        assert_eq!(measured["verdict"], "PASS");
        assert_eq!(measured["input_sha256"], measured["candidate_input_sha256"]);
        assert_ne!(
            measured["candidate_input_sha256"],
            report["checked_rewrite"]["product_validation"]["candidate_input_sha256"]
        );
        let current =
            RewriteCandidate::capture(&fixture.project, Instant::now() + Duration::from_secs(30))
                .unwrap();
        assert_eq!(measured["candidate_input_sha256"], current.input_sha256());
        let transaction = &report["checked_rewrite"]["transaction"];
        let id = transaction["transaction_id"].as_str().unwrap();
        assert_eq!(report["rollout"]["source_rollback"]["transaction_id"], id);
        assert_eq!(
            report["rollout"]["source_rollback"]["journal_sha256"],
            transaction["journal_sha256"]
        );
        let (revision, state) = fixture.signed_state(id);
        assert_eq!(revision, 1);
        assert!(state.history.is_empty());
        assert!(!state.lockstep_verified);
        assert!(state.validation_confidence.is_none());
        assert!(
            fs::read_to_string(fixture.project.join("case-00.test.js"))
                .unwrap()
                .contains("node:path")
        );
        assert_eq!(report["release_certification"], false);
    }

    #[cfg(feature = "engine")]
    #[test]
    fn autopilot_rollout_reaches_canary_only_with_fresh_real_triad_and_signed_transition() {
        use frankenengine_node::migration::rollout::{RolloutStage, RolloutStatus};

        let fixture = Fixture::new(35);
        let output = fixture.execute(&real_bun());
        let report = parse_json_stdout(&output, "native autopilot signed canary");
        assert!(output.status.success(), "{report}");
        assert_eq!(report["ok"], true);
        assert_eq!(report["phase"], "complete");
        assert_eq!(report["checked_rewrite"]["status"], "APPLIED");
        assert_eq!(report["checked_rewrite"]["rewrite"]["rewrites_applied"], 35);
        assert_eq!(report["attestation"]["verdict"], "PASS");
        assert_eq!(report["attestation"]["total_tests"], 35);
        assert_eq!(report["rollout"]["stage"], "canary");
        assert_eq!(report["rollout"]["status"], "active");
        assert_eq!(report["rollout"]["ramp_pct"], 5);
        assert_eq!(report["rollout"]["lockstep_verified"], true);
        assert_eq!(report["rollout"]["rollback_triggered"], false);
        assert!(report["errors"].as_array().unwrap().is_empty());
        let measured = fixture.measured_report();
        assert_eq!(measured["verdict"], "PASS");
        assert_eq!(measured["total_tests"], 35);
        assert_eq!(measured["passed"], 35);
        assert_eq!(measured["errored"], 0);
        assert_eq!(measured["skipped"], 0);
        assert_eq!(measured["filesystem_comparison"], true);
        assert_eq!(measured["distinct_reference_binaries"], true);
        assert_eq!(measured["input_sha256"], measured["candidate_input_sha256"]);
        assert_ne!(
            measured["candidate_input_sha256"],
            report["checked_rewrite"]["product_validation"]["candidate_input_sha256"]
        );
        assert_ne!(
            measured["native_runtime"]["sha256"],
            measured["node_runtime"]["sha256"]
        );
        assert_ne!(
            measured["native_runtime"]["sha256"],
            measured["bun_runtime"]["sha256"]
        );
        let transaction = &report["checked_rewrite"]["transaction"];
        let id = transaction["transaction_id"].as_str().unwrap();
        let (revision, state) = fixture.signed_state(id);
        assert_eq!(revision, 2);
        assert_eq!(state.current_stage, RolloutStage::Canary);
        assert_eq!(state.status, RolloutStatus::Active);
        assert_eq!(state.rollback_plan_id.as_deref(), Some(id));
        assert_eq!(
            state.rollback_journal_sha256.as_deref(),
            transaction["journal_sha256"].as_str()
        );
        assert_eq!(state.history.len(), 1);
        state.history[0]
            .verify_transition_signature(id, &SigningKey::from_bytes(&[82; 32]).verifying_key())
            .unwrap();
        let confidence = state.validation_confidence.as_ref().unwrap();
        confidence.validate().unwrap();
        assert_eq!(confidence.total_tests, 35);
        assert_eq!(confidence.matched_tests, 35);
        assert!(confidence.wilson_lower_95 >= 0.90);
        assert!(!confidence.independent_sampling_verified);
        assert_eq!(
            confidence.candidate_input_sha256,
            measured["candidate_input_sha256"]
        );
        assert_eq!(report["release_certification"], false);
    }
}

#[cfg(feature = "engine")]
mod attested_validation_cli {
    use super::*;
    use ed25519_dalek::SigningKey;
    use frankenengine_node::migration::{report_attestation, rollout::cohort};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    struct Fixture {
        root: TempDir,
        project: PathBuf,
        key: PathBuf,
    }

    impl Fixture {
        fn new(count: usize, source: &str) -> Self {
            let root = TempDir::new().expect("attested validation fixture");
            let project = root.path().join("project");
            fs::create_dir(&project).unwrap();
            initialize_native_project(&project, false);
            fs::write(
                project.join("package.json"),
                r#"{"name":"attested-validation","version":"1.0.0","engines":{"node":">=20"}}"#,
            )
            .unwrap();
            fs::write(
                project.join("package-lock.json"),
                r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
            )
            .unwrap();
            for index in 0..count {
                fs::write(
                    project.join(format!("case-{index:02}.test.js")),
                    source.replace("CASE_INDEX", &index.to_string()),
                )
                .unwrap();
            }
            fs::create_dir_all(project.join(".franken-node/keys")).unwrap();
            let signing = SigningKey::from_bytes(&[71; 32]);
            let key = root.path().join("validator.seed");
            fs::write(&key, signing.to_bytes()).unwrap();
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(
                project.join(report_attestation::PUBLIC_KEY_PATH),
                hex::encode(signing.verifying_key().to_bytes()),
            )
            .unwrap();
            Self { root, project, key }
        }

        fn command(&self, bun: &Path, key: &Path, out: &Path) -> std::process::Command {
            let mut command = franken_node_command();
            command
                .current_dir(repo_root())
                .env_remove(FAILURE_DIRECTORY)
                .args(["migrate", "validate"])
                .arg(&self.project)
                .args(["--attest", "--execute", "--json", "--bun-bin"])
                .arg(bun)
                .arg("--signing-key")
                .arg(key)
                .arg("--out")
                .arg(out);
            command
        }

        fn validate(&self, bun: &Path, out: &Path, regression: bool) -> Output {
            let mut command = self.command(bun, &self.key, out);
            if regression {
                command.arg("--attest-regression");
            }
            native_smoke_supervisor::run_command_with_timeout(
                &mut command,
                Duration::from_secs(360),
                Duration::from_secs(1),
            )
            .expect("attested CLI must terminate within its total budget")
        }

        fn rollout(&self, action: &str, report: Option<&Path>) -> Output {
            let mut command = franken_node_command();
            command
                .current_dir(repo_root())
                .env_remove("FRANKEN_NODE_ROLLOUT_SIGNING_KEY")
                .env_remove("FRANKEN_NODE_ROLLOUT_EXPECTED_HEAD_SHA256")
                .args(["migrate", "rollout"])
                .arg(&self.project)
                .args([
                    "--migration-id",
                    "attested-cli",
                    "--action",
                    action,
                    "--json",
                ]);
            if let Some(report) = report {
                command.arg("--lockstep-report").arg(report);
            }
            command.output().expect("rollout CLI")
        }
    }

    fn actual_bun() -> PathBuf {
        let path = std::env::var_os("PATH").expect("real reference runtimes must be installed");
        std::env::split_paths(&path)
            .filter(|directory| directory.is_absolute())
            .map(|directory| directory.join("bun"))
            .find(|candidate| candidate.is_file())
            .expect("attested native CLI regressions require real Bun on an absolute PATH entry")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn primary_attestation_measures_real_cohort_and_enters_default_rollout_gate() {
        // These curated cases exercise the whole default admission pipeline;
        // they do not establish independent production samples or a safety KPI.
        let fixture = Fixture::new(35, "console.log(CASE_INDEX + 7);\n");
        let initialized = fixture.rollout("status", None);
        assert!(
            initialized.status.success(),
            "{}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        let out = fixture.root.path().join("canary.signed.json");
        let bun = actual_bun();
        let output = fixture.validate(&bun, &out, false);
        let summary = parse_json_stdout(&output, "primary attested validation");
        assert!(output.status.success(), "{summary}");
        assert_eq!(summary["schema_version"], report_attestation::SCHEMA);
        assert_eq!(summary["verdict"], "PASS");
        assert_eq!(summary["total_tests"], 35);
        assert_eq!(summary["regression_attested"], false);
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let envelope = fs::read(&out).unwrap();
        let raw = report_attestation::verify(
            &envelope,
            &report_attestation::project_key(&fixture.project).unwrap(),
        )
        .unwrap();
        let measured: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(measured["filesystem_comparison"], true);
        assert_eq!(measured["skipped"], 0);
        assert_eq!(measured["cases"].as_array().unwrap().len(), 35);
        let confidence = cohort::assess(&fixture.project, &envelope).unwrap();
        assert_eq!(confidence.matched_tests, 35);
        assert!(confidence.wilson_lower_95 > 0.90);
        assert!(!confidence.independent_sampling_verified);

        let existing = fixture.validate(&bun, &out, false);
        assert!(!existing.status.success());
        assert_eq!(fs::read(&out).unwrap(), envelope);
        let promoted = fixture.rollout("promote", Some(&out));
        let report = parse_json_stdout(&promoted, "rollout consumes primary attestation");
        assert!(promoted.status.success(), "{report}");
        assert_eq!(report["stage"], "canary");
        assert_eq!(report["validation_confidence"]["total_tests"], 35);
        assert!(
            !fixture.rollout("promote", Some(&out)).status.success(),
            "a later promotion must not reuse the old candidate identity"
        );
    }

    #[test]
    fn primary_attested_native_regression_retains_nonzero_exit_and_recovery_evidence() {
        let fixture = Fixture::new(
            1,
            "require('fs').writeFileSync('guest-output.txt','written');\n",
        );
        assert!(fixture.rollout("status", None).status.success());
        let bun = actual_bun();
        let unapproved = fixture.root.path().join("unsigned-regression.json");
        assert!(!fixture.validate(&bun, &unapproved, false).status.success());
        assert!(!unapproved.exists());

        let out = fixture.root.path().join("regression.signed.json");
        let output = fixture.validate(&bun, &out, true);
        let summary = parse_json_stdout(&output, "signed native regression");
        assert!(
            !output.status.success(),
            "publishing FAIL must remain a failed validation"
        );
        assert_eq!(summary["verdict"], "FAIL");
        assert_eq!(summary["regression_attested"], true);
        let raw = report_attestation::verify(
            &fs::read(&out).unwrap(),
            &report_attestation::project_key(&fixture.project).unwrap(),
        )
        .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(report["native_divergences"], 1);
        assert_eq!(report["reference_failures"], 0);
        assert_eq!(report["reference_divergences"], 0);
        assert!(!fixture.project.join("guest-output.txt").exists());
        assert!(!fixture.rollout("promote", Some(&out)).status.success());
        let state = parse_json_stdout(&fixture.rollout("status", None), "regression state");
        assert_eq!(state["stage"], "aborted");
        assert_eq!(state["status"], "rolled_back");
        assert!(
            state.get("source_rollback").is_none(),
            "an unbound rollout cannot claim restoration"
        );
    }

    #[test]
    fn primary_attestation_refuses_leaked_linked_and_untrusted_keys_before_execution() {
        let fixture = Fixture::new(1, "throw new Error('must not execute');\n");
        let out = fixture.root.path().join("report.json");
        let leaked = fixture.project.join("leaked.seed");
        fs::write(&leaked, [71; 32]).unwrap();
        fs::set_permissions(&leaked, fs::Permissions::from_mode(0o600)).unwrap();
        let linked = fixture.root.path().join("linked.seed");
        symlink(&fixture.key, &linked).unwrap();
        let untrusted = fixture.root.path().join("untrusted.seed");
        fs::write(&untrusted, [72; 32]).unwrap();
        fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o600)).unwrap();
        for (key, expected) in [
            (leaked, "outside both captured projects"),
            (linked, "not a symlink"),
            (untrusted, "does not match"),
        ] {
            let output = fixture
                .command(Path::new("/missing-bun"), &key, &out)
                .output()
                .unwrap();
            let error = parse_json_stdout(&output, "attestation admission refusal");
            assert!(!output.status.success());
            assert_eq!(error["schema_version"], "franken-node/migrate-error-cli/v1");
            assert!(
                error["error"].as_str().unwrap().contains(expected),
                "{error}"
            );
            assert!(!out.exists());
        }
    }
}
