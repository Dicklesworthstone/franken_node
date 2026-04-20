use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const POLICY_ACTIVATION_INPUT_ENV: &str = "FRANKEN_NODE_DOCTOR_POLICY_ACTIVATION_INPUT";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root().join("fixtures/policy_activation").join(name)
}

fn doctor_command(repo: &Path) -> Command {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        let mut command = Command::new(exe);
        command.current_dir(repo);
        command
    } else if repo.join("target/debug/franken-node").is_file() {
        let mut command = Command::new(repo.join("target/debug/franken-node"));
        command.current_dir(repo);
        command
    } else {
        let mut command = Command::new("cargo");
        command
            .current_dir(repo)
            .args(["run", "-q", "-p", "frankenengine-node", "--"]);
        command
    }
}

fn run_doctor_args(args: &[String], env_policy_input: Option<&Path>) -> Output {
    let repo = repo_root();
    let mut command = doctor_command(&repo);
    command.env_remove(POLICY_ACTIVATION_INPUT_ENV);
    if let Some(path) = env_policy_input {
        command.env(POLICY_ACTIVATION_INPUT_ENV, path);
    }
    command
        .args(args)
        .output()
        .expect("failed to run franken-node doctor")
}

fn parse_successful_json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "doctor command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("doctor output must be valid JSON")
}

fn parse_jsonl_lines(bytes: &[u8]) -> Vec<Value> {
    let stderr = String::from_utf8_lossy(bytes);
    stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("structured log line must be valid JSON"))
        .collect()
}

fn run_doctor(policy_input_path: &Path, trace_id: &str) -> Value {
    parse_successful_json(run_doctor_args(
        &[
            "doctor".to_string(),
            "--json".to_string(),
            "--trace-id".to_string(),
            trace_id.to_string(),
            "--policy-activation-input".to_string(),
            policy_input_path
                .to_str()
                .expect("policy fixture path must be utf-8")
                .to_string(),
        ],
        None,
    ))
}

fn run_doctor_without_policy_input(trace_id: &str, env_policy_input: Option<&Path>) -> Value {
    parse_successful_json(run_doctor_args(
        &[
            "doctor".to_string(),
            "--json".to_string(),
            "--trace-id".to_string(),
            trace_id.to_string(),
        ],
        env_policy_input,
    ))
}

fn run_doctor_with_policy_input_and_env(
    policy_input_path: &Path,
    trace_id: &str,
    env_policy_input: Option<&Path>,
) -> Value {
    parse_successful_json(run_doctor_args(
        &[
            "doctor".to_string(),
            "--json".to_string(),
            "--trace-id".to_string(),
            trace_id.to_string(),
            "--policy-activation-input".to_string(),
            policy_input_path
                .to_str()
                .expect("policy fixture path must be utf-8")
                .to_string(),
        ],
        env_policy_input,
    ))
}

fn check_status<'a>(report: &'a Value, code: &str) -> &'a str {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|entry| entry["code"].as_str() == Some(code))
        .and_then(|entry| entry["status"].as_str())
        .unwrap_or_else(|| panic!("missing doctor check {code}"))
}

fn check_message<'a>(report: &'a Value, code: &str) -> &'a str {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|entry| entry["code"].as_str() == Some(code))
        .and_then(|entry| entry["message"].as_str())
        .unwrap_or_else(|| panic!("missing doctor check message {code}"))
}

fn check_remediation<'a>(report: &'a Value, code: &str) -> &'a str {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|entry| entry["code"].as_str() == Some(code))
        .and_then(|entry| entry["remediation"].as_str())
        .unwrap_or_else(|| panic!("missing doctor check remediation {code}"))
}

fn check_codes(report: &Value) -> Vec<&str> {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .filter_map(|entry| entry["code"].as_str())
        .collect()
}

fn assert_policy_check_triad(report: &Value, status: &str) {
    assert_eq!(check_status(report, "DR-POLICY-009"), status);
    assert_eq!(check_status(report, "DR-POLICY-010"), status);
    assert_eq!(check_status(report, "DR-POLICY-011"), status);
}

#[test]
fn doctor_policy_activation_pass_path() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_pass.json"),
        "doctor-policy-e2e-pass",
    );

    assert_ne!(report["overall_status"], "fail");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "pass");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "pass");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "pass");

    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "allow"
    );
    assert_eq!(
        report["policy_activation"]["wording_validation"]["valid"],
        true
    );
    assert_eq!(
        report["policy_activation"]["top_ranked_candidate"],
        "balanced_patch"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["chosen"],
        "balanced_patch"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["reason"],
        "TopCandidateAccepted"
    );
}

#[test]
fn doctor_policy_activation_warn_path_surfaces_conformal_warning() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_warn.json"),
        "doctor-policy-e2e-warn",
    );

    assert_eq!(report["overall_status"], "warn");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "warn");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "pass");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "pass");

    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "warn"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["reason"],
        "TopCandidateAccepted"
    );

    let findings = report["policy_activation"]["guardrail_certificate"]["findings"]
        .as_array()
        .expect("guardrail findings array");
    let conformal = findings
        .iter()
        .find(|finding| finding["budget_id"].as_str() == Some("conformal_risk"))
        .expect("conformal_risk finding");
    assert_eq!(conformal["verdict"], "warn");
}

#[test]
fn doctor_policy_activation_block_path_blocks_on_conformal_risk() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_block.json"),
        "doctor-policy-e2e-block",
    );

    assert_eq!(report["overall_status"], "fail");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "pass");

    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "block"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["reason"],
        "AllCandidatesBlocked"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["chosen"],
        Value::Null
    );

    let blocked_budgets =
        report["policy_activation"]["guardrail_certificate"]["blocking_budget_ids"]
            .as_array()
            .expect("blocking budget ids");
    assert!(
        blocked_budgets
            .iter()
            .any(|entry| entry.as_str() == Some("conformal_risk"))
    );
}

#[test]
fn doctor_policy_activation_invalid_input_fails_safely() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_invalid.json"),
        "doctor-policy-e2e-invalid",
    );

    assert_eq!(report["overall_status"], "fail");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "fail");
    assert!(
        check_message(&report, "DR-POLICY-009").contains("failed parsing policy activation input")
    );
    assert!(report.get("policy_activation").is_none());
}

#[test]
fn doctor_policy_activation_pass_fixture_has_json_contract_shape() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_pass.json"),
        "doctor-policy-e2e-json-shape",
    );

    assert_eq!(report["command"], "doctor");
    assert_eq!(report["trace_id"], "doctor-policy-e2e-json-shape");
    assert!(report["generated_at_utc"].as_str().is_some());
    assert!(report["selected_profile"].as_str().is_some());
    assert!(report["status_counts"]["pass"].as_u64().is_some());
    assert!(report["status_counts"]["warn"].as_u64().is_some());
    assert!(report["status_counts"]["fail"].as_u64().is_some());
    assert!(
        report["checks"]
            .as_array()
            .is_some_and(|checks| !checks.is_empty())
    );
    assert!(
        report["structured_logs"]
            .as_array()
            .is_some_and(|logs| !logs.is_empty())
    );
    assert!(report["merge_decision_count"].as_u64().is_some());
    assert!(report["merge_decisions"].as_array().is_some());

    let policy = &report["policy_activation"];
    assert!(policy.is_object());
    assert!(policy["input_path"].as_str().is_some_and(|path| {
        path.ends_with("fixtures/policy_activation/doctor_policy_activation_pass.json")
    }));
    assert_eq!(policy["candidate_count"], 3);
    assert_eq!(policy["observation_count"], 6);
    assert_eq!(policy["prefiltered_candidate_count"], 0);
    assert_eq!(policy["guardrail_certificate"]["dominant_verdict"], "allow");
    assert!(
        policy["guardrail_certificate"]["findings"]
            .as_array()
            .is_some()
    );
    assert!(policy["decision_outcome"].is_object());
    assert!(policy["explanation"].is_object());
    assert!(policy["wording_validation"].is_object());
}

#[test]
fn doctor_structured_logs_jsonl_emits_parseable_stderr_events() {
    let output = run_doctor_args(
        &[
            "doctor".to_string(),
            "--json".to_string(),
            "--structured-logs-jsonl".to_string(),
            "--trace-id".to_string(),
            "doctor-policy-e2e-jsonl".to_string(),
            "--policy-activation-input".to_string(),
            fixture_path("doctor_policy_activation_block.json")
                .to_str()
                .expect("policy fixture path must be utf-8")
                .to_string(),
        ],
        None,
    );

    assert!(
        output.status.success(),
        "doctor command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout report JSON");
    let log_lines = parse_jsonl_lines(&output.stderr);
    let report_logs = report["structured_logs"]
        .as_array()
        .expect("report structured_logs array");

    assert_eq!(log_lines.len(), report_logs.len());
    assert!(!log_lines.is_empty());

    for (line, report_log) in log_lines.iter().zip(report_logs) {
        assert_eq!(line["trace_id"], "doctor-policy-e2e-jsonl");
        assert_eq!(line["event_code"], report_log["event_code"]);
        assert_eq!(line["check_code"], report_log["check_code"]);
        assert_eq!(line["scope"], report_log["scope"]);
        assert_eq!(line["status"], report_log["status"]);
        assert_eq!(line["surface"], "OPS-CLI");
        assert!(line["timestamp"].as_str().is_some());
        assert!(line["message"].as_str().is_some_and(|message| !message.is_empty()));
        assert_eq!(
            line["span_id"].as_str().map(str::len),
            Some(16),
            "span_id must be 16 lowercase hex chars"
        );
        assert!(
            line["metric_refs"]
                .as_array()
                .is_some_and(|metrics| !metrics.is_empty())
        );
        assert!(line["recovery_hint"].is_object());
    }

    assert!(log_lines.iter().any(|line| {
        line["level"] == "error"
            && line["error_code"]
                .as_str()
                .is_some_and(|code| code.starts_with("FRANKEN_DOCTOR_"))
            && line["recovery_hint"]["action"] == "escalate"
    }));
}

#[test]
fn doctor_policy_activation_block_fixture_has_fail_json_contract_shape() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_block.json"),
        "doctor-policy-e2e-json-block",
    );

    assert_eq!(report["overall_status"], "fail");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "pass");
    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "block"
    );
    assert!(
        report["policy_activation"]["guardrail_certificate"]["blocking_budget_ids"]
            .as_array()
            .is_some_and(|ids| !ids.is_empty())
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["reason"],
        "AllCandidatesBlocked"
    );
    assert_eq!(
        check_remediation(&report, "DR-POLICY-010"),
        "Reduce risk exposure or provide safer candidate actions."
    );
}

#[test]
fn doctor_policy_activation_env_var_input_runs_pipeline() {
    let report = run_doctor_without_policy_input(
        "doctor-policy-e2e-env-input",
        Some(&fixture_path("doctor_policy_activation_pass.json")),
    );

    assert_ne!(report["overall_status"], "fail");
    assert_eq!(report["trace_id"], "doctor-policy-e2e-env-input");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "pass");
    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "allow"
    );
    assert!(
        report["policy_activation"]["input_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("doctor_policy_activation_pass.json"))
    );
}

#[test]
fn doctor_policy_activation_cli_input_overrides_env_var_input() {
    let report = run_doctor_with_policy_input_and_env(
        &fixture_path("doctor_policy_activation_pass.json"),
        "doctor-policy-e2e-cli-over-env",
        Some(&fixture_path("doctor_policy_activation_block.json")),
    );

    assert_eq!(check_status(&report, "DR-POLICY-009"), "pass");
    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "allow"
    );
    assert!(
        report["policy_activation"]["input_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("doctor_policy_activation_pass.json"))
    );
}

#[test]
fn doctor_policy_activation_missing_file_falls_back_to_json_failure_report() {
    let missing_path = fixture_path("doctor_policy_activation_missing.json");
    let report = run_doctor(&missing_path, "doctor-policy-e2e-missing-input");

    assert_eq!(report["overall_status"], "fail");
    assert_policy_check_triad(&report, "fail");
    assert!(report.get("policy_activation").is_none());
    assert!(
        check_message(&report, "DR-POLICY-009").contains("failed reading policy activation input")
    );
    assert_eq!(
        check_remediation(&report, "DR-POLICY-009"),
        "Provide a valid JSON input via --policy-activation-input."
    );
}

#[test]
fn doctor_policy_activation_malformed_input_returns_structured_json_rejection() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_invalid.json"),
        "doctor-policy-e2e-malformed-json",
    );

    assert_eq!(report["command"], "doctor");
    assert_eq!(report["trace_id"], "doctor-policy-e2e-malformed-json");
    assert_eq!(report["overall_status"], "fail");
    assert_policy_check_triad(&report, "fail");
    assert!(report.get("policy_activation").is_none());
    assert!(
        check_message(&report, "DR-POLICY-009").contains("failed parsing policy activation input")
    );
    assert!(
        report["structured_logs"]
            .as_array()
            .expect("structured logs array")
            .iter()
            .any(
                |entry| entry["check_code"].as_str() == Some("DR-POLICY-009")
                    && entry["status"].as_str() == Some("fail")
            )
    );
}

#[test]
fn doctor_policy_activation_without_input_omits_policy_activation_checks() {
    let report = run_doctor_without_policy_input("doctor-policy-e2e-no-input", None);
    let codes = check_codes(&report);

    assert!(report.get("policy_activation").is_none());
    assert!(!codes.contains(&"DR-POLICY-009"));
    assert!(!codes.contains(&"DR-POLICY-010"));
    assert!(!codes.contains(&"DR-POLICY-011"));
    assert!(
        report["structured_logs"]
            .as_array()
            .expect("structured logs array")
            .iter()
            .all(|entry| entry["check_code"].as_str() != Some("DR-POLICY-009"))
    );
}
