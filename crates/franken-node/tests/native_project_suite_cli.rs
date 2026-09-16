//! Primary product-command regressions, not standalone-operator tests.
//! Uses the actual Cargo-built franken-node binary and installed Node. A
//! successful native case is required to demonstrate positive admission;
//! missing policy/engine capabilities must fail that test, never skip it.

use super::{TempDir, franken_node_command, native_smoke_supervisor, parse_json_stdout, repo_root};
use std::path::Path;
use std::process::Output;
use std::time::Duration;

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
    let mut command = franken_node_command();
    command.current_dir(repo_root());
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
