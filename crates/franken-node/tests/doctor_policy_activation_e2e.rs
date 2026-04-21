use insta::assert_json_snapshot;
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
        panic!(
            "franken-node binary not found for e2e test. \
             Expected CARGO_BIN_EXE_franken-node env var or binary at target/debug/franken-node. \
             Run `cargo build --bin franken-node` or use `cargo test` to prepare the binary. \
             Refusing cargo-run fallback to maintain subprocess semantics and rch discipline."
        );
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

fn doctor_structured_log_args(trace_id: &str, extra_args: Vec<String>) -> Vec<String> {
    let mut args = vec![
        "doctor".to_string(),
        "--json".to_string(),
        "--structured-logs-jsonl".to_string(),
        "--trace-id".to_string(),
        trace_id.to_string(),
    ];
    args.extend(extra_args);
    args
}

fn run_doctor_structured_logs_jsonl(args: Vec<String>, trace_id: &str) -> (Value, Vec<Value>) {
    let output = run_doctor_args(&args, None);
    assert!(
        output.status.success(),
        "doctor command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout report JSON");
    let log_lines = parse_jsonl_lines(&output.stderr);
    assert_doctor_structured_log_contract(trace_id, &report, &log_lines);
    (report, log_lines)
}

fn assert_doctor_structured_log_contract(trace_id: &str, report: &Value, log_lines: &[Value]) {
    let report_logs = report["structured_logs"]
        .as_array()
        .expect("report structured_logs array");

    assert_eq!(log_lines.len(), report_logs.len());
    assert!(!log_lines.is_empty());

    for (line, report_log) in log_lines.iter().zip(report_logs) {
        assert_eq!(line["trace_id"], trace_id);
        assert_eq!(line["event_code"], report_log["event_code"]);
        assert_eq!(line["check_code"], report_log["check_code"]);
        assert_eq!(line["scope"], report_log["scope"]);
        assert_eq!(line["status"], report_log["status"]);
        assert_eq!(line["surface"], "OPS-CLI");
        assert!(line["timestamp"].as_str().is_some());
        assert!(
            line["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty())
        );
        assert!(line["span_id"].as_str().is_some_and(|span| {
            span.len() == 16
                && span
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        }));
        assert!(
            line["metric_refs"]
                .as_array()
                .is_some_and(|metrics| !metrics.is_empty())
        );
        assert!(line["recovery_hint"]["action"].as_str().is_some());
        assert!(
            line["recovery_hint"]["target"]
                .as_str()
                .is_some_and(|target| !target.is_empty())
        );
        assert!(
            line["recovery_hint"]["confidence"]
                .as_f64()
                .is_some_and(|confidence| (0.0..=1.0).contains(&confidence))
        );

        match line["level"].as_str().expect("structured log level") {
            "info" => assert!(line.get("error_code").is_none()),
            "warn" | "error" => assert!(
                line["error_code"]
                    .as_str()
                    .is_some_and(|code| code.starts_with("FRANKEN_DOCTOR_")),
                "warn/error log lines must include canonical doctor error_code: {line}"
            ),
            other => panic!("unexpected structured log level {other}"),
        }
    }
}

fn structured_log_for<'a>(log_lines: &'a [Value], check_code: &str) -> &'a Value {
    log_lines
        .iter()
        .find(|line| line["check_code"].as_str() == Some(check_code))
        .unwrap_or_else(|| panic!("missing structured log for {check_code}"))
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

fn canonicalize_doctor_snapshot(mut report: Value) -> Value {
    let repo_root_exact = repo_root().display().to_string();
    let repo_root_prefix = format!("{}/", repo_root().display());

    fn scrub(value: &mut Value, repo_root_exact: &str, repo_root_prefix: &str) {
        match value {
            Value::Array(items) => {
                for item in items {
                    scrub(item, repo_root_exact, repo_root_prefix);
                }
            }
            Value::Object(map) => {
                for (key, nested) in map {
                    match key.as_str() {
                        "generated_at_utc" => {
                            *nested = Value::String("[generated-at]".to_string());
                        }
                        "timestamp" => {
                            *nested = Value::String("[timestamp]".to_string());
                        }
                        "span_id" => {
                            *nested = Value::String("[span-id]".to_string());
                        }
                        "input_path" => {
                            if let Some(path) = nested.as_str() {
                                *nested = Value::String(
                                    path.strip_prefix(repo_root_prefix)
                                        .unwrap_or(path)
                                        .to_string(),
                                );
                            }
                        }
                        _ => scrub(nested, repo_root_exact, repo_root_prefix),
                    }
                }
            }
            Value::String(text) => {
                if let Some(path) = text.strip_prefix(repo_root_prefix) {
                    *value = Value::String(path.to_string());
                } else if text.contains(repo_root_exact) {
                    *value = Value::String(text.replace(repo_root_exact, "[repo-root]"));
                }
            }
            _ => {}
        }
    }

    scrub(&mut report, &repo_root_exact, &repo_root_prefix);
    report
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
fn doctor_policy_activation_pass_fixture_matches_snapshot() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_pass.json"),
        "doctor-policy-e2e-snapshot",
    );

    assert_json_snapshot!(
        "doctor_policy_activation_pass_report",
        canonicalize_doctor_snapshot(report)
    );
}

#[test]
fn doctor_structured_logs_jsonl_emits_parseable_stderr_events() {
    let (_report, log_lines) = run_doctor_structured_logs_jsonl(
        doctor_structured_log_args(
            "doctor-policy-e2e-jsonl",
            vec![
                "--policy-activation-input".to_string(),
                fixture_path("doctor_policy_activation_block.json")
                    .to_str()
                    .expect("policy fixture path must be utf-8")
                    .to_string(),
            ],
        ),
        "doctor-policy-e2e-jsonl",
    );

    assert!(log_lines.iter().any(|line| {
        line["level"] == "error"
            && line["error_code"]
                .as_str()
                .is_some_and(|code| code.starts_with("FRANKEN_DOCTOR_"))
            && line["recovery_hint"]["action"] == "escalate"
    }));
}

#[test]
fn doctor_structured_logs_jsonl_covers_policy_pass_missing_fixture_and_strict_profile_warning() {
    let mut covered_event_types = Vec::new();

    let (pass_report, pass_logs) = run_doctor_structured_logs_jsonl(
        doctor_structured_log_args(
            "doctor-structured-logs-policy-activation-pass",
            vec![
                "--policy-activation-input".to_string(),
                fixture_path("doctor_policy_activation_pass.json")
                    .to_str()
                    .expect("policy fixture path must be utf-8")
                    .to_string(),
            ],
        ),
        "doctor-structured-logs-policy-activation-pass",
    );
    assert_eq!(check_status(&pass_report, "DR-POLICY-009"), "pass");
    assert!(pass_report["policy_activation"].is_object());
    let policy_pass_log = structured_log_for(&pass_logs, "DR-POLICY-009");
    assert_eq!(policy_pass_log["level"], "info");
    assert!(policy_pass_log.get("error_code").is_none());
    assert_eq!(policy_pass_log["recovery_hint"]["action"], "ignore");
    covered_event_types.push("policy_activation_pass");

    let missing_path = fixture_path("doctor_policy_activation_missing.json");
    let (missing_report, missing_logs) = run_doctor_structured_logs_jsonl(
        doctor_structured_log_args(
            "doctor-structured-logs-missing-fixture-fallback",
            vec![
                "--policy-activation-input".to_string(),
                missing_path
                    .to_str()
                    .expect("missing fixture path must be utf-8")
                    .to_string(),
            ],
        ),
        "doctor-structured-logs-missing-fixture-fallback",
    );
    assert_eq!(missing_report["overall_status"], "fail");
    assert_eq!(check_status(&missing_report, "DR-POLICY-009"), "fail");
    assert!(missing_report.get("policy_activation").is_none());
    let missing_log = structured_log_for(&missing_logs, "DR-POLICY-009");
    assert_eq!(missing_log["level"], "error");
    assert_eq!(missing_log["error_code"], "FRANKEN_DOCTOR_DR_POLICY_009");
    assert_eq!(missing_log["recovery_hint"]["action"], "escalate");
    covered_event_types.push("missing_fixture_fallback");

    let (strict_report, strict_logs) = run_doctor_structured_logs_jsonl(
        doctor_structured_log_args(
            "doctor-structured-logs-strict-profile-warning",
            vec!["--profile".to_string(), "strict".to_string()],
        ),
        "doctor-structured-logs-strict-profile-warning",
    );
    assert_eq!(strict_report["selected_profile"], "strict");
    assert_eq!(check_status(&strict_report, "DR-PROFILE-003"), "pass");
    assert_eq!(check_status(&strict_report, "DR-CONFIG-002"), "warn");
    let strict_warning_log = structured_log_for(&strict_logs, "DR-CONFIG-002");
    assert_eq!(strict_warning_log["level"], "warn");
    assert_eq!(
        strict_warning_log["error_code"],
        "FRANKEN_DOCTOR_DR_CONFIG_002"
    );
    assert_eq!(strict_warning_log["recovery_hint"]["action"], "reconfigure");
    covered_event_types.push("strict_profile_warning");

    assert_eq!(
        covered_event_types,
        vec![
            "policy_activation_pass",
            "missing_fixture_fallback",
            "strict_profile_warning"
        ]
    );
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
