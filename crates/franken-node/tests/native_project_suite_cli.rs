//! Primary product-command regressions, not standalone-operator tests.
//! Uses the actual Cargo-built franken-node binary and installed Node. A
//! successful native case is required to demonstrate positive admission;
//! missing policy/engine capabilities must fail that test, never skip it.

#[path = "native_rewrite_transactions.rs"]
mod rewrite_transactions;

use super::{TempDir, franken_node_command, native_smoke_supervisor, parse_json_stdout, repo_root};
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
    std::fs::write(project.path().join("package-lock.json"), "{}\n").expect("lockfile");
    std::fs::write(project.path().join("index.js"), "console.log('smoke-only');\n")
        .expect("entrypoint");
    std::fs::write(project.path().join("a.test.js"), first_case).expect("first case");
    std::fs::write(project.path().join("b.test.js"), "console.log(42);\n").expect("second case");
    project
}

fn invoke(path: &Path, report: bool, static_only: bool, empty_path: bool) -> Output {
    invoke_with_archive(path, report, static_only, empty_path, None)
}

fn invoke_with_archive(path: &Path, report: bool, static_only: bool, empty_path: bool,
    archive: Option<&Path>) -> Output {
    let mut command = franken_node_command();
    command.current_dir(repo_root()).env_remove(FAILURE_DIRECTORY);
    if let Some(directory) = archive { command.env(FAILURE_DIRECTORY, directory); }
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
    assert!(suite["input_sha256"].as_str().is_some_and(|hash| hash.len() == 64));
    assert_eq!(
        std::fs::read_to_string(project.path().join("a.test.js")).expect("original case"),
        "const = ;\n"
    );
    assert_no_guest_state(&project);
}

#[test]
fn primary_report_keeps_rollout_blocked_after_suite_failure() {
    let project = project("const = ;\n");
    let output = invoke(project.path(), true, false, false);
    // Report generation may succeed while its admission decision is no-go.
    let report = parse_json_stdout(&output, "primary report suite propagation");
    assert_eq!(report["validation"]["test_suite"]["total_tests"], 2, "{report}");
    assert_eq!(report["validation"]["status"], "fail");
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
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
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
    assert!(report["checks"][4]["message"].as_str().expect("message").contains("requires Node"));
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
    assert!(report["checks"][4]["message"].as_str().expect("message").contains("symlink"));
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
    assert!(report["checks"][4]["message"].as_str().expect("message").contains("static validation checks failed"));
    assert!(report.get("test_suite").is_none());
    assert_no_guest_state(&project);
}

#[cfg(feature = "engine")]
#[test]
fn successful_native_suite_requires_two_complete_measured_cases() {
    let project = project("console.log(6*7);\n");
    let output = invoke(project.path(), false, false, false);
    let report = parse_json_stdout(&output, "successful primary native suite");
    assert!(output.status.success(), "native suite did not pass: {report}");
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
        assert!(row["divergences"].as_array().expect("divergences").is_empty());
    }
    assert_no_guest_state(&project);
}

#[test]
fn primary_validate_and_report_retain_their_actual_failed_measurements_when_requested() {
    use std::os::unix::fs::PermissionsExt;
    for report_mode in [false, true] {
        let project = project("const = ;\n");
        let archives = TempDir::new().expect("private archive parent");
        let output = invoke_with_archive(project.path(), report_mode, false, false, Some(archives.path()));
        let report = parse_json_stdout(&output, "automatic primary failure capture");
        let validation = if report_mode { &report["validation"] } else { &report };
        assert_eq!(validation["status"], "fail", "{report}");
        let suite = &validation["test_suite"];
        assert_eq!(suite["verdict"], "FAIL", "{report}");
        assert_eq!(suite["total_tests"], 2);
        let capture = &suite["failure_capture"];
        assert_eq!(capture["status"], "SAVED", "{report}");
        let path = Path::new(capture["capsule_path"].as_str().expect("retained capsule path"));
        assert!(path.starts_with(archives.path()));
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        let archive: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(archive["content_sha256"], capture["content_sha256"]);
        let expected = &archive["payload"]["expected"];
        assert_eq!(expected["cases"], suite["cases"]);
        assert_eq!(expected["input_sha256"], suite["input_sha256"]);
        assert_eq!(expected["candidate_input_sha256"], suite["candidate_input_sha256"]);
        assert_eq!(expected["reference_runtime"], suite["reference_runtime"]);
        assert_eq!(expected["native_runtime"], suite["native_runtime"]);
        assert!(expected.get("failure_capture").is_none(), "archive must not recursively refer to its own hash");
        if report_mode {
            assert_eq!(report["executive_summary"]["go_no_go"], "no_go");
        } else {
            assert!(!output.status.success());
        }
        assert_no_guest_state(&project);
        assert_eq!(std::fs::read_to_string(project.path().join("a.test.js")).unwrap(), "const = ;\n");
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
    let message = report["checks"][4]["message"].as_str().expect("failure reason");
    assert!(message.contains(FAILURE_DIRECTORY), "{report}");
    assert!(!message.contains("requires Node"), "archive preflight must run first: {report}");
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
    std::fs::write(project.path().join("package.json"),
        r#"{"name":"blocked","scripts":{"postinstall":"echo blocked"}}"#).unwrap();
    let output = invoke_with_archive(project.path(), false, false, true, Some(archives.path()));
    let report = parse_json_stdout(&output, "static prerequisite before failure storage");
    assert!(!output.status.success());
    assert!(report["checks"][4]["message"].as_str().unwrap().contains("static validation checks failed"));
    assert_eq!(std::fs::read_dir(archives.path()).unwrap().count(), 0);
    assert_no_guest_state(&project);
}
