use insta::assert_json_snapshot;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const POLICY_ACTIVATION_INPUT_ENV: &str = "FRANKEN_NODE_DOCTOR_POLICY_ACTIVATION_INPUT";
const DEBUG_TRACE_POLICY_SCHEMA_VERSION: &str = "franken-node/debug-trace-policy/v1";
const DEBUG_TRACE_POLICY_ENGINE_DOCTOR_ACTIVATION: &str = "doctor_policy_activation";

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

fn log_phase(test_name: &str, phase: &str, detail: Value) {
    eprintln!(
        "{}",
        serde_json::to_string(&json!({
            "suite": "doctor_policy_activation_e2e",
            "test": test_name,
            "phase": phase,
            "detail": detail,
        }))
        .expect("structured test log serializes")
    );
}

fn run_cli_args(args: &[String], env_policy_input: Option<&Path>) -> Output {
    let repo = repo_root();
    let mut command = doctor_command(&repo);
    command.env_remove(POLICY_ACTIVATION_INPUT_ENV);
    if let Some(path) = env_policy_input {
        command.env(POLICY_ACTIVATION_INPUT_ENV, path);
    }
    command
        .args(args)
        .output()
        .expect("failed to run franken-node CLI")
}

fn run_doctor_args(args: &[String], env_policy_input: Option<&Path>) -> Output {
    run_cli_args(args, env_policy_input)
}

fn write_debug_trace_policy(dir: &Path, policy_engine: &str) -> PathBuf {
    let policy_path = dir.join("debug_trace_policy.json");
    std::fs::write(
        &policy_path,
        serde_json::to_string_pretty(&json!({
            "schema_version": DEBUG_TRACE_POLICY_SCHEMA_VERSION,
            "policy_engine": policy_engine,
        }))
        .expect("debug trace policy serializes"),
    )
    .expect("debug trace policy writes");
    policy_path
}

/// Copy a repo `fixtures/policy_activation/<fixture>` file into `workspace`
/// under `dest_name`, returning the workspace-relative name to pass on the CLI.
///
/// `debug trace --policy/--input` route through `cli::parse_safe_content_pathbuf`,
/// which rejects absolute paths for user content. Hermetic debug-trace coverage
/// therefore stages its inputs inside the process CWD (`workspace`) and
/// references them by relative name rather than by absolute tempdir path.
fn stage_fixture_in_workspace(workspace: &Path, fixture: &str, dest_name: &str) -> String {
    std::fs::copy(fixture_path(fixture), workspace.join(dest_name))
        .expect("stage policy-activation fixture into debug-trace workspace");
    dest_name.to_string()
}

/// Run `franken-node debug trace` with the process CWD pinned to `workspace`
/// so workspace-relative `--policy`/`--input` paths satisfy the user-content
/// path guard (which rejects absolute paths). All referenced files must live
/// under `workspace` (or intentionally not exist, for missing-file coverage).
fn run_debug_trace_in_workspace(workspace: &Path, args: &[String]) -> Output {
    let mut command = doctor_command(workspace);
    command.env_remove(POLICY_ACTIVATION_INPUT_ENV);
    command
        .args(args)
        .output()
        .expect("failed to run franken-node CLI")
}

/// Build the `debug trace` argument vector from workspace-relative file names.
fn debug_trace_args(
    policy_file: &str,
    input_file: &str,
    json: bool,
    trace_id: &str,
) -> Vec<String> {
    let mut args = vec![
        "debug".to_string(),
        "trace".to_string(),
        "--policy".to_string(),
        policy_file.to_string(),
        "--input".to_string(),
        input_file.to_string(),
    ];
    if json {
        args.push("--json".to_string());
    }
    args.push("--trace-id".to_string());
    args.push(trace_id.to_string());
    args
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

/// Doctor check scopes whose pass/fail reflects live host load — workspace
/// pressure (concurrent builds, disk headroom), benchmark throughput, and
/// resource-governor monitoring — rather than the policy-activation behavior
/// under test. These checks are only emitted when the host environment
/// surfaces them (e.g. stray benchmark artifacts, elevated build pressure), so
/// they are absent from the clean-host baseline. Policy-activation assertions
/// and the golden snapshot must exclude them to stay deterministic when this
/// suite runs under the concurrent build swarm.
const ENV_SENSITIVE_SCOPES: [&str; 3] = [
    "workspace.pressure",
    "benchmark.validation",
    "resource_governor.monitoring",
];

fn is_env_sensitive_scope(value: &Value) -> bool {
    value["scope"]
        .as_str()
        .is_some_and(|scope| ENV_SENSITIVE_SCOPES.contains(&scope))
}

/// Recompute the doctor aggregate status from only the deterministic (non
/// environment-sensitive) checks. A policy-activation test asserting on the
/// raw `overall_status` would flap whenever DR-WORKSPACE-001/DR-BENCH-015 fail
/// under concurrent build load; folding those out keeps the policy signal.
fn policy_relevant_overall_status(report: &Value) -> &'static str {
    let mut has_warn = false;
    for check in report["checks"].as_array().expect("checks array") {
        if is_env_sensitive_scope(check) {
            continue;
        }
        match check["status"].as_str() {
            Some("fail") => return "fail",
            Some("warn") => has_warn = true,
            _ => {}
        }
    }
    if has_warn { "warn" } else { "pass" }
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

    // Drop environment-sensitive checks and their structured-log twins so the
    // golden reflects the clean-host policy-activation baseline regardless of
    // live workspace/benchmark pressure. Then recompute the aggregate fields
    // from the surviving deterministic checks and pin their (already ~0)
    // durations so a busy host cannot perturb the snapshot.
    if let Some(checks) = report["checks"].as_array_mut() {
        checks.retain(|check| !is_env_sensitive_scope(check));
        for check in checks.iter_mut() {
            if let Some(duration) = check.get_mut("duration_ms") {
                *duration = json!(0);
            }
        }
    }
    if let Some(logs) = report["structured_logs"].as_array_mut() {
        logs.retain(|log| !is_env_sensitive_scope(log));
        for log in logs.iter_mut() {
            if let Some(duration) = log.get_mut("duration_ms") {
                *duration = json!(0);
            }
        }
    }

    let (mut pass, mut warn, mut fail) = (0_u64, 0_u64, 0_u64);
    if let Some(checks) = report["checks"].as_array() {
        for check in checks {
            match check["status"].as_str() {
                Some("pass") => pass += 1,
                Some("warn") => warn += 1,
                Some("fail") => fail += 1,
                _ => {}
            }
        }
    }
    report["status_counts"] = json!({ "pass": pass, "warn": warn, "fail": fail });
    report["overall_status"] = json!(if fail > 0 {
        "fail"
    } else if warn > 0 {
        "warn"
    } else {
        "pass"
    });

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

    // Assert on the policy-activation signal rather than the raw overall_status,
    // which also folds in environment-sensitive DR-WORKSPACE-001/DR-BENCH-015
    // checks that fail under concurrent build load (see ENV_SENSITIVE_SCOPES).
    assert_ne!(policy_relevant_overall_status(&report), "fail");
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

    // Policy-relevant aggregate (env-sensitive workspace/benchmark checks
    // excluded) so the warn signal is not masked by a live-load DR-* failure.
    assert_eq!(policy_relevant_overall_status(&report), "warn");
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
fn doctor_policy_activation_env_var_alone_does_not_drive_pipeline() {
    // `FRANKEN_NODE_DOCTOR_POLICY_ACTIVATION_INPUT` is NOT a policy input
    // channel: `doctor` runs the policy-activation pipeline only when
    // `--policy-activation-input` is passed on the CLI (cli.rs `policy_activation_input`
    // is `#[arg(long)]` with no clap `env=`; the env var has never been read in
    // prod). Setting it alone must leave the pipeline off, so guardrail input
    // cannot be injected out-of-band. bd-lmbt0 tracks wiring an env fallback if
    // that channel is ever wanted.
    let report = run_doctor_without_policy_input(
        "doctor-policy-e2e-env-input",
        Some(&fixture_path("doctor_policy_activation_pass.json")),
    );

    let codes = check_codes(&report);
    assert!(report.get("policy_activation").is_none());
    assert!(!codes.contains(&"DR-POLICY-009"));
    assert!(!codes.contains(&"DR-POLICY-010"));
    assert!(!codes.contains(&"DR-POLICY-011"));
}

#[test]
fn doctor_policy_activation_cli_input_drives_pipeline_env_var_ignored() {
    // With the CLI flag present, the pipeline runs on the CLI input and the
    // (deliberately unread) env var has no effect: the env var points at the
    // block fixture, yet the report reflects the CLI pass fixture (verdict
    // allow), confirming the env var is inert rather than merged/overriding.
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

#[test]
fn debug_trace_policy_activation_json_runs_real_policy_pipeline() {
    let test_name = "debug_trace_policy_activation_json_runs_real_policy_pipeline";
    let workspace = tempfile::tempdir().expect("debug trace workspace");
    let policy_path = write_debug_trace_policy(
        workspace.path(),
        DEBUG_TRACE_POLICY_ENGINE_DOCTOR_ACTIVATION,
    );
    let input_file = stage_fixture_in_workspace(
        workspace.path(),
        "doctor_policy_activation_pass.json",
        "policy_input.json",
    );
    log_phase(
        test_name,
        "fixtures_written",
        json!({
            "policy_path": policy_path.display().to_string(),
            "input_file": input_file,
        }),
    );

    let args = debug_trace_args("debug_trace_policy.json", &input_file, true, test_name);
    let output = run_debug_trace_in_workspace(workspace.path(), &args);
    log_phase(
        test_name,
        "command_executed",
        json!({
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr": String::from_utf8_lossy(&output.stderr),
        }),
    );
    assert!(
        output.status.success(),
        "debug trace --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("not_implemented"),
        "debug trace JSON must not emit preview/not_implemented output"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("debug trace stdout JSON");
    log_phase(
        test_name,
        "stdout_json_parsed",
        json!({
            "trace_id": report["trace_id"],
            "final_status": report["final_verdict"]["status"],
            "steps": report["trace_steps"].as_array().map_or(0, Vec::len),
        }),
    );

    assert_eq!(report["trace_id"], test_name);
    assert_eq!(
        report["policy_schema_version"],
        DEBUG_TRACE_POLICY_SCHEMA_VERSION
    );
    assert_eq!(
        report["policy_engine"],
        DEBUG_TRACE_POLICY_ENGINE_DOCTOR_ACTIVATION
    );
    assert_eq!(report["final_verdict"]["status"], "pass");
    assert_eq!(report["final_verdict"]["verdict"], "allow");
    assert_eq!(
        report["trace_steps"]
            .as_array()
            .expect("trace steps array")
            .iter()
            .map(|step| step["type"].as_str().expect("step type"))
            .collect::<Vec<_>>(),
        vec![
            "policy_load",
            "input_load",
            "guardrail_evaluation",
            "bayesian_ranking",
            "decision_engine",
            "explanation_wording",
        ]
    );
    assert_eq!(
        report["diagnostics"]["decision_outcome"]["reason"],
        "TopCandidateAccepted"
    );
    log_phase(
        test_name,
        "final_verdict_checked",
        json!({
            "verdict": report["final_verdict"]["verdict"],
            "reason": report["final_verdict"]["reason"],
        }),
    );
}

#[test]
fn debug_trace_policy_activation_human_uses_real_verdict() {
    let test_name = "debug_trace_policy_activation_human_uses_real_verdict";
    let workspace = tempfile::tempdir().expect("debug trace workspace");
    let policy_path = write_debug_trace_policy(
        workspace.path(),
        DEBUG_TRACE_POLICY_ENGINE_DOCTOR_ACTIVATION,
    );
    let input_file = stage_fixture_in_workspace(
        workspace.path(),
        "doctor_policy_activation_pass.json",
        "policy_input.json",
    );
    log_phase(
        test_name,
        "fixtures_written",
        json!({
            "policy_path": policy_path.display().to_string(),
            "input_file": input_file,
        }),
    );

    let args = debug_trace_args("debug_trace_policy.json", &input_file, false, test_name);
    let output = run_debug_trace_in_workspace(workspace.path(), &args);
    log_phase(
        test_name,
        "command_executed",
        json!({
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr": String::from_utf8_lossy(&output.stderr),
        }),
    );
    assert!(
        output.status.success(),
        "debug trace human output failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Debug Trace: Policy Evaluation"));
    assert!(stdout.contains("Step 3: Guardrail Evaluation"));
    assert!(stdout.contains("Step 5: Decision Engine"));
    assert!(stdout.contains("Final Verdict:"));
    assert!(stdout.contains("verdict=allow"));
    assert!(stdout.contains("reason=top_candidate_accepted"));
    assert!(!stdout.contains("not implemented"));
    assert!(!stdout.contains("preview"));
    log_phase(
        test_name,
        "human_output_checked",
        json!({
            "stdout_len": stdout.len(),
            "contains_verdict": stdout.contains("verdict=allow"),
        }),
    );
}

#[test]
fn debug_trace_unsupported_policy_engine_fails_closed() {
    let test_name = "debug_trace_unsupported_policy_engine_fails_closed";
    let workspace = tempfile::tempdir().expect("debug trace workspace");
    let policy_path = write_debug_trace_policy(workspace.path(), "preview_only");
    let input_file = stage_fixture_in_workspace(
        workspace.path(),
        "doctor_policy_activation_pass.json",
        "policy_input.json",
    );
    log_phase(
        test_name,
        "fixtures_written",
        json!({
            "policy_path": policy_path.display().to_string(),
            "input_file": input_file,
        }),
    );

    let args = debug_trace_args("debug_trace_policy.json", &input_file, true, test_name);
    let output = run_debug_trace_in_workspace(workspace.path(), &args);
    log_phase(
        test_name,
        "failure_path_checked",
        json!({
            "status": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
        }),
    );
    assert!(
        !output.status.success(),
        "unsupported policy engine must fail closed"
    );
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unsupported debug trace policy_engine `preview_only`")
    );
}

#[test]
fn debug_trace_malformed_input_json_fails_closed() {
    let test_name = "debug_trace_malformed_input_json_fails_closed";
    let workspace = tempfile::tempdir().expect("debug trace workspace");
    let policy_path = write_debug_trace_policy(
        workspace.path(),
        DEBUG_TRACE_POLICY_ENGINE_DOCTOR_ACTIVATION,
    );
    let input_file = "malformed_policy_input.json";
    std::fs::write(workspace.path().join(input_file), "{ invalid json")
        .expect("malformed input writes");
    log_phase(
        test_name,
        "fixtures_written",
        json!({
            "policy_path": policy_path.display().to_string(),
            "input_file": input_file,
        }),
    );

    let args = debug_trace_args("debug_trace_policy.json", input_file, true, test_name);
    let output = run_debug_trace_in_workspace(workspace.path(), &args);
    log_phase(
        test_name,
        "failure_path_checked",
        json!({
            "status": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
        }),
    );
    assert!(!output.status.success(), "malformed input must fail closed");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to parse input JSON from"));
}

#[test]
fn debug_trace_missing_input_file_fails_closed() {
    let test_name = "debug_trace_missing_input_file_fails_closed";
    let workspace = tempfile::tempdir().expect("debug trace workspace");
    let policy_path = write_debug_trace_policy(
        workspace.path(),
        DEBUG_TRACE_POLICY_ENGINE_DOCTOR_ACTIVATION,
    );
    // Intentionally NOT created under `workspace` so the read fails closed.
    let input_file = "missing_policy_input.json";
    log_phase(
        test_name,
        "fixtures_written",
        json!({
            "policy_path": policy_path.display().to_string(),
            "input_file": input_file,
        }),
    );

    let args = debug_trace_args("debug_trace_policy.json", input_file, true, test_name);
    let output = run_debug_trace_in_workspace(workspace.path(), &args);
    log_phase(
        test_name,
        "failure_path_checked",
        json!({
            "status": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
        }),
    );
    assert!(!output.status.success(), "missing input must fail closed");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to read input file"));
}
