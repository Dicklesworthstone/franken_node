use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root().join("fixtures/policy_activation").join(name)
}

fn run_doctor_stderr_jsonl(args: &[String]) -> (Option<i32>, Vec<Value>) {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(repo_root())
        .args(args)
        .output()
        .expect("failed to run franken-node doctor");

    let code = output.status.code();
    assert!(
        matches!(code, Some(0 | 1)),
        "doctor exit status must be 0 (pass/warn) or 1 (fail), got {code:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("doctor stderr must be UTF-8");
    assert!(
        !stderr.trim().is_empty(),
        "doctor --structured-logs-jsonl must emit JSONL to stderr"
    );

    let lines = stderr
        .lines()
        .enumerate()
        .map(|(index, line)| {
            assert!(
                !line.trim().is_empty(),
                "stderr JSONL line {index} is blank"
            );
            serde_json::from_str::<Value>(line).unwrap_or_else(|error| {
                panic!("stderr line {index} must parse as JSON: {error}; line={line:?}")
            })
        })
        .collect();
    (code, lines)
}

fn assert_doctor_check_log_schema(line: &Value, expected_trace_id: &str) {
    let object = line
        .as_object()
        .unwrap_or_else(|| panic!("structured log line must be an object: {line}"));

    if object.get("event_code").and_then(Value::as_str) == Some("FRANKENTUI_RENDER_COMPLETED") {
        assert_eq!(object["surface"].as_str(), Some("doctor_report"));
        return;
    }

    assert_eq!(
        object["trace_id"].as_str(),
        Some(expected_trace_id),
        "doctor check log must carry requested trace_id: {line}"
    );
    assert_eq!(object["surface"].as_str(), Some("OPS-CLI"));
    assert!(
        object["timestamp"]
            .as_str()
            .is_some_and(|ts| !ts.is_empty()),
        "structured log timestamp must be non-empty: {line}"
    );
    assert!(
        object["message"]
            .as_str()
            .is_some_and(|msg| !msg.is_empty()),
        "structured log message must be non-empty: {line}"
    );
    assert!(
        object["span_id"].as_str().is_some_and(|span| {
            span.len() == 16
                && span
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        }),
        "structured log span_id must be 16 lowercase hex chars: {line}"
    );
    assert!(
        object["event_code"]
            .as_str()
            .is_some_and(|code| !code.is_empty()),
        "structured log event_code must be non-empty: {line}"
    );
    assert!(
        object["check_code"]
            .as_str()
            .is_some_and(|code| code.starts_with("DR-")),
        "structured log check_code must start with DR-: {line}"
    );
    assert!(
        object["scope"]
            .as_str()
            .is_some_and(|scope| !scope.is_empty()),
        "structured log scope must be non-empty: {line}"
    );
    assert!(
        matches!(object["status"].as_str(), Some("pass" | "warn" | "fail")),
        "structured log status must be canonical: {line}"
    );
    assert!(
        object["duration_ms"].as_u64().is_some(),
        "structured log duration_ms must be u64: {line}"
    );
    assert!(
        object["metric_refs"]
            .as_array()
            .is_some_and(|metrics| !metrics.is_empty()),
        "structured log metric_refs must be non-empty: {line}"
    );
    assert!(object["recovery_hint"]["action"].as_str().is_some());
    assert!(
        object["recovery_hint"]["target"]
            .as_str()
            .is_some_and(|target| !target.is_empty())
    );
    assert!(
        object["recovery_hint"]["confidence"]
            .as_f64()
            .is_some_and(|confidence| (0.0..=1.0).contains(&confidence))
    );

    match object["level"].as_str() {
        Some("info") => assert!(
            object.get("error_code").is_none(),
            "info log line must omit error_code: {line}"
        ),
        Some("warn" | "error") => assert!(
            object["error_code"]
                .as_str()
                .is_some_and(|code| code.starts_with("FRANKEN_DOCTOR_")),
            "warn/error log lines must carry FRANKEN_DOCTOR_* error_code: {line}"
        ),
        other => panic!("unexpected structured log level {other:?}: {line}"),
    }
}

fn check_log_for<'a>(lines: &'a [Value], check_code: &str) -> &'a Value {
    lines
        .iter()
        .find(|line| line["check_code"].as_str() == Some(check_code))
        .unwrap_or_else(|| panic!("missing structured log line for {check_code}; lines={lines:?}"))
}

fn scenario_args(trace_id: &str, extra_args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut args = vec![
        "doctor".to_string(),
        "--structured-logs-jsonl".to_string(),
        "--trace-id".to_string(),
        trace_id.to_string(),
    ];
    args.extend(extra_args);
    args
}

#[test]
fn doctor_structured_logs_jsonl_emits_parseable_schema_events() {
    let policy_pass_fixture = fixture_path("doctor_policy_activation_pass.json");
    let missing_fixture = fixture_path("doctor_policy_activation_missing.json");

    assert!(
        policy_pass_fixture.is_file(),
        "policy activation pass fixture must exist"
    );
    assert!(
        !missing_fixture.exists(),
        "missing-fixture scenario requires absent fixture path"
    );

    // 1. Human output mode + valid policy activation fixture
    let pass_trace_id = "doctor-structured-jsonl-policy-pass";
    let (_, pass_lines) = run_doctor_stderr_jsonl(&scenario_args(
        pass_trace_id,
        [
            "--policy-activation-input".to_string(),
            policy_pass_fixture.display().to_string(),
        ],
    ));
    for line in &pass_lines {
        assert_doctor_check_log_schema(line, pass_trace_id);
    }
    let policy_pass_log = check_log_for(&pass_lines, "DR-POLICY-009");
    assert_eq!(policy_pass_log["status"], "pass");
    assert_eq!(policy_pass_log["level"], "info");
    assert_eq!(policy_pass_log["recovery_hint"]["action"], "ignore");

    // 2. Human output mode + missing policy activation fixture (must exit 1 and log error)
    let missing_trace_id = "doctor-structured-jsonl-missing-fixture";
    let (missing_exit, missing_lines) = run_doctor_stderr_jsonl(&scenario_args(
        missing_trace_id,
        [
            "--policy-activation-input".to_string(),
            missing_fixture.display().to_string(),
        ],
    ));
    assert_eq!(
        missing_exit,
        Some(1),
        "missing policy activation input must report overall fail (exit 1)"
    );
    for line in &missing_lines {
        assert_doctor_check_log_schema(line, missing_trace_id);
    }
    let missing_log = check_log_for(&missing_lines, "DR-POLICY-009");
    assert_eq!(missing_log["status"], "fail");
    assert_eq!(missing_log["level"], "error");
    assert_eq!(missing_log["error_code"], "FRANKEN_DOCTOR_DR_POLICY_009");
    assert_eq!(missing_log["recovery_hint"]["action"], "escalate");

    // 3. Operator screen mode + strict profile warning
    let strict_trace_id = "doctor-structured-jsonl-strict-profile";
    let (_, strict_lines) = run_doctor_stderr_jsonl(&scenario_args(
        strict_trace_id,
        [
            "--screen".to_string(),
            "--profile".to_string(),
            "strict".to_string(),
        ],
    ));
    for line in &strict_lines {
        assert_doctor_check_log_schema(line, strict_trace_id);
    }
    assert_eq!(
        check_log_for(&strict_lines, "DR-PROFILE-003")["status"],
        "pass"
    );
    let strict_warn_log = check_log_for(&strict_lines, "DR-CONFIG-002");
    assert_eq!(strict_warn_log["status"], "warn");
    assert_eq!(strict_warn_log["level"], "warn");
    assert_eq!(
        strict_warn_log["error_code"],
        "FRANKEN_DOCTOR_DR_CONFIG_002"
    );
    assert_eq!(strict_warn_log["recovery_hint"]["action"], "reconfigure");
}
