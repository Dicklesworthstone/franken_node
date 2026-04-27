//! Doctor JSON output schema conformance harness.
//!
//! The authoritative contract lives in `docs/specs/bootstrap_doctor_contract.md`,
//! with bootstrap check vectors in
//! `artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json`.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "doctor_policy_activation_golden_vectors_conformance.rs"]
mod doctor_policy_activation_golden_vectors_conformance;

const DOCTOR_SPEC: &str = include_str!("../../../docs/specs/bootstrap_doctor_contract.md");
const DOCTOR_CHECK_MATRIX: &str =
    include_str!("../../../artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json");
const DOCTOR_HEALTHY_REPORT: &str =
    include_str!("../../../artifacts/section_bootstrap/bd-1pk/doctor_report_healthy.json");
const DOCTOR_DEGRADED_REPORT: &str =
    include_str!("../../../artifacts/section_bootstrap/bd-1pk/doctor_report_degraded.json");
const DOCTOR_FAILURE_REPORT: &str =
    include_str!("../../../artifacts/section_bootstrap/bd-1pk/doctor_report_failure.json");
const DOCTOR_INVALID_INPUT_REPORT: &str =
    include_str!("../../../artifacts/section_bootstrap/bd-1pk/doctor_report_invalid_input.json");

const POLICY_ACTIVATION_INPUT_ENV: &str = "FRANKEN_NODE_DOCTOR_POLICY_ACTIVATION_INPUT";

const REQUIRED_TOP_LEVEL_FIELDS: &[&str] = &[
    "command",
    "trace_id",
    "generated_at_utc",
    "selected_profile",
    "source_path",
    "overall_status",
    "status_counts",
    "checks",
    "structured_logs",
    "merge_decision_count",
    "merge_decisions",
];

const REQUIRED_CHECK_FIELDS: &[&str] = &[
    "code",
    "event_code",
    "scope",
    "status",
    "message",
    "remediation",
    "duration_ms",
];

const REQUIRED_STRUCTURED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "event_code",
    "check_code",
    "scope",
    "status",
    "duration_ms",
];

const REQUIRED_JSONL_FIELDS: &[&str] = &[
    "timestamp",
    "level",
    "message",
    "trace_id",
    "span_id",
    "surface",
    "metric_refs",
    "recovery_hint",
    "event_code",
    "check_code",
    "scope",
    "status",
    "duration_ms",
];

const REQUIRED_POLICY_FIELDS: &[&str] = &[
    "input_path",
    "candidate_count",
    "observation_count",
    "prefiltered_candidate_count",
    "top_ranked_candidate",
    "guardrail_certificate",
    "decision_outcome",
    "explanation",
    "wording_validation",
];

#[derive(Debug, Clone, Copy)]
struct RequirementRow {
    section: &'static str,
    level: &'static str,
    clauses: usize,
    vectors: usize,
}

#[derive(Debug, Clone)]
struct DoctorVector {
    name: &'static str,
    trace_id: String,
    args: Vec<String>,
    policy: PolicyExpectation,
    structured_jsonl: bool,
}

#[derive(Debug, Clone, Copy)]
enum PolicyExpectation {
    Absent,
    Present,
    FailedToLoad,
}

#[derive(Debug, Clone)]
struct CheckVector {
    code: String,
    event_code: String,
    scope: String,
}

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
            "franken-node binary not found. Expected CARGO_BIN_EXE_franken-node \
             or target/debug/franken-node; run through cargo test so Cargo builds the binary."
        );
    }
}

fn run_doctor(args: &[String]) -> Output {
    let repo = repo_root();
    let mut command = doctor_command(&repo);
    command.env_remove(POLICY_ACTIVATION_INPUT_ENV);
    command
        .args(args)
        .output()
        .expect("run franken-node doctor")
}

fn run_doctor_with_env(args: &[String], env_pairs: &[(&str, String)]) -> Output {
    let repo = repo_root();
    let mut command = doctor_command(&repo);
    command.env_remove(POLICY_ACTIVATION_INPUT_ENV);
    command.env_remove("FRANKEN_NODE_PROFILE");
    command.env_remove("FRANKEN_NODE_MAX_MERGE_DECISIONS");
    for (key, value) in env_pairs {
        command.env(key, value);
    }
    command
        .args(args)
        .output()
        .expect("run franken-node doctor with env")
}

fn parse_report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "doctor command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("doctor stdout must be valid JSON")
}

fn canonicalize_doctor_runtime_metadata(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                match key.as_str() {
                    "generated_at_utc" | "timestamp" => {
                        *nested = Value::String("[TIMESTAMP]".to_string());
                    }
                    "duration_ms" => {
                        *nested = Value::Number(0_u64.into());
                    }
                    _ => canonicalize_doctor_runtime_metadata(nested),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                canonicalize_doctor_runtime_metadata(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn canonical_doctor_stdout_bytes(output: &Output) -> Vec<u8> {
    let mut report = parse_report(output);
    canonicalize_doctor_runtime_metadata(&mut report);
    serde_json::to_vec(&report).expect("canonical doctor JSON should serialize")
}

fn parse_jsonl(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|err| panic!("stderr JSONL line {index} is invalid: {err}"))
        })
        .collect()
}

fn doctor_args(trace_id: &str, extra: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut args = vec![
        "doctor".to_string(),
        "--json".to_string(),
        "--trace-id".to_string(),
        trace_id.to_string(),
    ];
    args.extend(extra);
    args
}

fn doctor_vectors() -> Vec<DoctorVector> {
    vec![
        DoctorVector {
            name: "defaults_without_policy_input",
            trace_id: "doctor-json-schema-default".to_string(),
            args: doctor_args("doctor-json-schema-default", []),
            policy: PolicyExpectation::Absent,
            structured_jsonl: false,
        },
        DoctorVector {
            name: "policy_activation_pass",
            trace_id: "doctor-json-schema-policy-pass".to_string(),
            args: doctor_args(
                "doctor-json-schema-policy-pass",
                [
                    "--policy-activation-input".to_string(),
                    fixture_path("doctor_policy_activation_pass.json")
                        .display()
                        .to_string(),
                ],
            ),
            policy: PolicyExpectation::Present,
            structured_jsonl: false,
        },
        DoctorVector {
            name: "policy_activation_malformed_input",
            trace_id: "doctor-json-schema-policy-invalid".to_string(),
            args: doctor_args(
                "doctor-json-schema-policy-invalid",
                [
                    "--policy-activation-input".to_string(),
                    fixture_path("doctor_policy_activation_invalid.json")
                        .display()
                        .to_string(),
                ],
            ),
            policy: PolicyExpectation::FailedToLoad,
            structured_jsonl: false,
        },
        DoctorVector {
            name: "structured_logs_jsonl_block",
            trace_id: "doctor-json-schema-jsonl-block".to_string(),
            args: doctor_args(
                "doctor-json-schema-jsonl-block",
                [
                    "--structured-logs-jsonl".to_string(),
                    "--policy-activation-input".to_string(),
                    fixture_path("doctor_policy_activation_block.json")
                        .display()
                        .to_string(),
                ],
            ),
            policy: PolicyExpectation::Present,
            structured_jsonl: true,
        },
    ]
}

fn coverage_rows() -> Vec<RequirementRow> {
    vec![
        RequirementRow {
            section: "Machine-Readable Report Schema / top-level fields",
            level: "MUST",
            clauses: REQUIRED_TOP_LEVEL_FIELDS.len(),
            vectors: doctor_vectors().len(),
        },
        RequirementRow {
            section: "Machine-Readable Report Schema / checks[]",
            level: "MUST",
            clauses: REQUIRED_CHECK_FIELDS.len(),
            vectors: doctor_vectors().len(),
        },
        RequirementRow {
            section: "Machine-Readable Report Schema / structured_logs[]",
            level: "MUST",
            clauses: REQUIRED_STRUCTURED_LOG_FIELDS.len(),
            vectors: doctor_vectors().len(),
        },
        RequirementRow {
            section: "Structured logs JSONL",
            level: "MUST",
            clauses: REQUIRED_JSONL_FIELDS.len(),
            vectors: 1,
        },
        RequirementRow {
            section: "Policy activation object",
            level: "MUST",
            clauses: REQUIRED_POLICY_FIELDS.len(),
            vectors: 2,
        },
    ]
}

fn check_matrix_vectors() -> Vec<CheckVector> {
    let matrix: Value =
        serde_json::from_str(DOCTOR_CHECK_MATRIX).expect("doctor check matrix must be JSON");
    matrix["checks"]
        .as_array()
        .expect("doctor check matrix checks array")
        .iter()
        .map(|entry| CheckVector {
            code: required_string(entry, "code").to_string(),
            event_code: required_string(entry, "event_code").to_string(),
            scope: required_string(entry, "scope").to_string(),
        })
        .collect()
}

fn required_object<'a>(value: &'a Value, context: &str) -> &'a serde_json::Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{context} must be a JSON object: {value}"))
}

fn required_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} must be a string in {value}"))
}

fn required_array<'a>(value: &'a Value, field: &str) -> &'a Vec<Value> {
    value[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} must be an array in {value}"))
}

fn required_u64(value: &Value, field: &str) -> u64 {
    value[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} must be an unsigned integer in {value}"))
}

fn assert_has_fields(value: &Value, fields: &[&str], context: &str) {
    let object = required_object(value, context);
    for field in fields {
        assert!(
            object.contains_key(*field),
            "{context} missing required field {field}: {value}"
        );
    }
}

fn assert_status(value: &Value, field: &str) {
    assert!(
        matches!(value[field].as_str(), Some("pass" | "warn" | "fail")),
        "{field} must be one of pass|warn|fail in {value}"
    );
}

fn assert_counted_overall_status(report: &Value) {
    let checks = required_array(report, "checks");
    let mut counts = BTreeMap::from([("pass", 0_u64), ("warn", 0), ("fail", 0)]);
    for check in checks {
        let status = required_string(check, "status");
        let count = counts
            .get_mut(status)
            .unwrap_or_else(|| panic!("unexpected doctor status {status} in {check}"));
        *count += 1;
    }

    for status in ["pass", "warn", "fail"] {
        assert_eq!(
            required_u64(&report["status_counts"], status),
            counts[status],
            "status_counts.{status} must match checks[]"
        );
    }

    let expected = if counts["fail"] > 0 {
        "fail"
    } else if counts["warn"] > 0 {
        "warn"
    } else {
        "pass"
    };
    assert_eq!(
        required_string(report, "overall_status"),
        expected,
        "overall_status must follow documented fail > warn > pass aggregation"
    );
}

fn assert_check_schema(check: &Value) {
    assert_has_fields(check, REQUIRED_CHECK_FIELDS, "doctor check");
    assert!(required_string(check, "code").starts_with("DR-"));
    assert!(required_string(check, "event_code").starts_with("DOC-"));
    assert!(!required_string(check, "scope").is_empty());
    assert_status(check, "status");
    assert!(!required_string(check, "message").is_empty());
    assert!(!required_string(check, "remediation").is_empty());
    required_u64(check, "duration_ms");
}

fn assert_report_structured_logs(report: &Value) {
    let checks = required_array(report, "checks");
    let logs = required_array(report, "structured_logs");
    assert_eq!(
        logs.len(),
        checks.len(),
        "structured_logs[] must contain one entry per doctor check"
    );

    for (check, log) in checks.iter().zip(logs) {
        assert_has_fields(log, REQUIRED_STRUCTURED_LOG_FIELDS, "doctor structured log");
        assert_eq!(log["trace_id"], report["trace_id"]);
        assert_eq!(log["event_code"], check["event_code"]);
        assert_eq!(log["check_code"], check["code"]);
        assert_eq!(log["scope"], check["scope"]);
        assert_eq!(log["status"], check["status"]);
        assert_eq!(log["duration_ms"], check["duration_ms"]);
    }
}

fn assert_policy_activation_schema(report: &Value, expectation: PolicyExpectation) {
    match expectation {
        PolicyExpectation::Absent | PolicyExpectation::FailedToLoad => {
            assert!(
                report.get("policy_activation").is_none(),
                "policy_activation must be absent for {expectation:?}: {report}"
            );
        }
        PolicyExpectation::Present => {
            let policy = &report["policy_activation"];
            assert_has_fields(policy, REQUIRED_POLICY_FIELDS, "policy_activation");
            assert!(required_string(policy, "input_path").ends_with(".json"));
            required_u64(policy, "candidate_count");
            required_u64(policy, "observation_count");
            required_u64(policy, "prefiltered_candidate_count");
            assert!(
                policy["top_ranked_candidate"].is_string()
                    || policy["top_ranked_candidate"].is_object()
                    || policy["top_ranked_candidate"].is_null(),
                "top_ranked_candidate must be a candidate id, detail object, or null: {policy}"
            );
            assert!(policy["guardrail_certificate"].is_object());
            assert!(policy["decision_outcome"].is_object());
            assert!(policy["explanation"].is_object());
            assert!(policy["wording_validation"].is_object());
        }
    }
}

fn assert_check_matrix_contract(report: &Value, expectation: PolicyExpectation) {
    let checks = required_array(report, "checks");
    let by_code = checks
        .iter()
        .map(|check| (required_string(check, "code"), check))
        .collect::<BTreeMap<_, _>>();

    for vector in check_matrix_vectors() {
        let policy_only = vector.code.starts_with("DR-POLICY-");
        if policy_only && matches!(expectation, PolicyExpectation::Absent) {
            assert!(
                !by_code.contains_key(vector.code.as_str()),
                "{} must be omitted when no policy activation input is supplied",
                vector.code
            );
            continue;
        }

        let check = by_code
            .get(vector.code.as_str())
            .unwrap_or_else(|| panic!("missing spec check vector {}", vector.code));
        assert_eq!(check["event_code"], vector.event_code);
        assert_eq!(check["scope"], vector.scope);
    }
}

fn assert_doctor_report_schema(report: &Value, vector: &DoctorVector) {
    assert_has_fields(report, REQUIRED_TOP_LEVEL_FIELDS, "doctor report");
    assert_eq!(report["command"], "doctor");
    assert_eq!(report["trace_id"], vector.trace_id);
    assert!(
        required_string(report, "generated_at_utc").contains('T'),
        "generated_at_utc must be an RFC3339-like timestamp"
    );
    assert!(!required_string(report, "selected_profile").is_empty());
    assert_status(report, "overall_status");
    assert!(report["source_path"].is_null() || report["source_path"].as_str().is_some());
    required_u64(report, "merge_decision_count");
    assert!(report["merge_decisions"].is_array());

    let checks = required_array(report, "checks");
    assert!(!checks.is_empty(), "doctor report must contain checks[]");
    let mut seen_codes = BTreeSet::new();
    for check in checks {
        assert_check_schema(check);
        assert!(
            seen_codes.insert(required_string(check, "code")),
            "doctor check codes must be unique: {check}"
        );
    }

    assert_counted_overall_status(report);
    assert_report_structured_logs(report);
    assert_policy_activation_schema(report, vector.policy);
    assert_check_matrix_contract(report, vector.policy);
}

fn assert_jsonl_contract(report: &Value, log_lines: &[Value]) {
    let report_logs = required_array(report, "structured_logs");
    assert_eq!(
        log_lines.len(),
        report_logs.len(),
        "--structured-logs-jsonl stderr must mirror report structured_logs[]"
    );
    assert!(
        !log_lines.is_empty(),
        "JSONL vector must emit at least one line"
    );

    for (line, report_log) in log_lines.iter().zip(report_logs) {
        assert_has_fields(line, REQUIRED_JSONL_FIELDS, "doctor stderr JSONL line");
        assert_eq!(line["trace_id"], report["trace_id"]);
        assert_eq!(line["event_code"], report_log["event_code"]);
        assert_eq!(line["check_code"], report_log["check_code"]);
        assert_eq!(line["scope"], report_log["scope"]);
        assert_eq!(line["status"], report_log["status"]);
        assert_eq!(line["duration_ms"], report_log["duration_ms"]);
        assert_eq!(line["surface"], "OPS-CLI");
        assert!(
            matches!(line["level"].as_str(), Some("info" | "warn" | "error")),
            "JSONL level must be canonical: {line}"
        );
        assert!(
            required_string(line, "span_id").len() == 16
                && required_string(line, "span_id")
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
            "span_id must be 16 lowercase hex chars: {line}"
        );
        assert!(!required_array(line, "metric_refs").is_empty());
        assert!(line["recovery_hint"].is_object());

        match required_string(line, "level") {
            "info" => assert!(
                line.get("error_code").is_none(),
                "info events must omit error_code: {line}"
            ),
            "warn" | "error" => assert!(
                line["error_code"]
                    .as_str()
                    .is_some_and(|code| code.starts_with("FRANKEN_DOCTOR_")),
                "warn/error events must include canonical FRANKEN_DOCTOR error_code: {line}"
            ),
            level => panic!("unexpected doctor JSONL level {level}"),
        }
    }
}

#[test]
fn doctor_json_schema_conformance_matrix_covers_spec_clauses() {
    for field in REQUIRED_TOP_LEVEL_FIELDS {
        let documented = match *field {
            "status_counts" => DOCTOR_SPEC.contains("`status_counts.{pass,warn,fail}`"),
            "checks" => DOCTOR_SPEC.contains("`checks[]`"),
            "structured_logs" => DOCTOR_SPEC.contains("`structured_logs[]`"),
            "merge_decisions" => DOCTOR_SPEC.contains("`merge_decisions[]`"),
            _ => DOCTOR_SPEC.contains(&format!("- `{field}`")),
        };
        assert!(
            documented,
            "doctor contract must document top-level field `{field}`"
        );
    }
    for field in REQUIRED_CHECK_FIELDS {
        assert!(
            DOCTOR_SPEC.contains(&format!("  - `{field}`")),
            "doctor contract must document checks[] field `{field}`"
        );
    }
    for field in REQUIRED_STRUCTURED_LOG_FIELDS {
        assert!(
            DOCTOR_SPEC.contains(&format!("  - `{field}`")),
            "doctor contract must document structured_logs[] field `{field}`"
        );
    }

    let rows = coverage_rows();
    assert!(
        rows.iter()
            .all(|row| row.level == "MUST" && row.clauses > 0 && row.vectors > 0),
        "all conformance rows must cover at least one MUST clause with live vectors: {rows:?}"
    );
    assert!(
        rows.iter()
            .map(|row| row.section)
            .collect::<BTreeSet<_>>()
            .len()
            == rows.len(),
        "coverage rows must be unique: {rows:?}"
    );

    let check_vectors = check_matrix_vectors();
    assert!(
        check_vectors.len() >= 11,
        "bootstrap doctor matrix must retain the documented check vectors"
    );
}

#[test]
fn doctor_json_spec_artifact_reports_match_schema() {
    for (name, artifact) in [
        ("healthy", DOCTOR_HEALTHY_REPORT),
        ("degraded", DOCTOR_DEGRADED_REPORT),
        ("failure", DOCTOR_FAILURE_REPORT),
        ("invalid_input", DOCTOR_INVALID_INPUT_REPORT),
    ] {
        let report: Value = serde_json::from_str(artifact)
            .unwrap_or_else(|err| panic!("{name} doctor artifact must be valid JSON: {err}"));
        let vector = DoctorVector {
            name,
            trace_id: required_string(&report, "trace_id").to_string(),
            args: Vec::new(),
            policy: if report.get("policy_activation").is_some() {
                PolicyExpectation::Present
            } else if required_array(&report, "checks")
                .iter()
                .any(|check| required_string(check, "code") == "DR-POLICY-009")
            {
                PolicyExpectation::FailedToLoad
            } else {
                PolicyExpectation::Absent
            },
            structured_jsonl: false,
        };
        assert_doctor_report_schema(&report, &vector);
    }
}

#[test]
fn doctor_json_live_vectors_match_schema() {
    for vector in doctor_vectors() {
        let output = run_doctor(&vector.args);
        let report = parse_report(&output);
        assert_doctor_report_schema(&report, &vector);
    }
}

#[test]
fn doctor_jsonl_stderr_mirrors_report_structured_logs() {
    let vector = doctor_vectors()
        .into_iter()
        .find(|vector| vector.structured_jsonl)
        .expect("structured JSONL vector");
    let output = run_doctor(&vector.args);
    let report = parse_report(&output);
    let log_lines = parse_jsonl(&output.stderr);

    assert_doctor_report_schema(&report, &vector);
    assert_jsonl_contract(&report, &log_lines);
}

#[test]
fn doctor_json_schema_validator_rejects_contract_drift() {
    let vector = doctor_vectors()
        .into_iter()
        .find(|vector| vector.name == "policy_activation_pass")
        .expect("policy activation pass vector");
    let output = run_doctor(&vector.args);
    let mut report = parse_report(&output);
    report["checks"][0]["status"] = Value::String("unknown".to_string());

    let result = std::panic::catch_unwind(|| assert_doctor_report_schema(&report, &vector));
    assert!(
        result.is_err(),
        "schema validator must reject statuses outside pass|warn|fail"
    );
}

#[cfg(test)]
mod doctor_json_metamorphic_tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct DeterministicRng {
        state: u64,
    }

    impl DeterministicRng {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self
                .state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.state
        }

        fn next_usize(&mut self, upper_bound: usize) -> usize {
            (self.next_u64() as usize) % upper_bound
        }
    }

    fn shuffled_env_pairs(
        seed: u64,
        profile: &str,
        max_merge_decisions: u64,
    ) -> Vec<(&'static str, String)> {
        let mut pairs = vec![
            ("FRANKEN_NODE_PROFILE", profile.to_string()),
            (
                "FRANKEN_NODE_MAX_MERGE_DECISIONS",
                max_merge_decisions.to_string(),
            ),
            ("ZZ_DOCTOR_RANDOM_ENV", format!("z-{seed:016x}")),
            ("AA_DOCTOR_RANDOM_ENV", format!("a-{seed:016x}")),
            ("MM_DOCTOR_RANDOM_ENV", format!("m-{seed:016x}")),
        ];
        let mut rng = DeterministicRng::new(seed ^ 0xa11c_e55e_d0c7_0123);
        for index in 0..pairs.len() {
            let swap_index = index + rng.next_usize(pairs.len() - index);
            pairs.swap(index, swap_index);
        }
        pairs
    }

    fn random_doctor_args(rng: &mut DeterministicRng, index: usize) -> Vec<String> {
        let mut args = doctor_args(&format!("doctor-metamorphic-{index:02x}"), []);
        match rng.next_usize(5) {
            0 => {}
            1 => {
                args.push("--profile".to_string());
                args.push("strict".to_string());
            }
            2 => {
                args.push("--profile".to_string());
                args.push("balanced".to_string());
            }
            3 => {
                args.push("--profile".to_string());
                args.push("legacy-risky".to_string());
            }
            _ => {
                args.push("--structured-logs-jsonl".to_string());
            }
        }

        match rng.next_usize(4) {
            0 => {}
            1 => {
                args.push("--policy-activation-input".to_string());
                args.push(
                    fixture_path("doctor_policy_activation_pass.json")
                        .display()
                        .to_string(),
                );
            }
            2 => {
                args.push("--policy-activation-input".to_string());
                args.push(
                    fixture_path("doctor_policy_activation_block.json")
                        .display()
                        .to_string(),
                );
            }
            _ => {
                args.push("--policy-activation-input".to_string());
                args.push(
                    fixture_path("doctor_policy_activation_invalid.json")
                        .display()
                        .to_string(),
                );
            }
        }

        args
    }

    #[test]
    fn doctor_json_output_canonicalization_is_metamorphically_stable() {
        let mut rng = DeterministicRng::new(0xd0c7_0c4f_e1f0_2026);

        for index in 0..56 {
            let seed = rng.next_u64();
            let args = random_doctor_args(&mut rng, index);
            let profile = match rng.next_usize(3) {
                0 => "strict",
                1 => "balanced",
                _ => "legacy-risky",
            };
            let max_merge_decisions = 1 + (rng.next_u64() % 32);
            let cold_env = shuffled_env_pairs(seed, profile, max_merge_decisions);
            let mut warm_env = cold_env.clone();
            warm_env.reverse();

            let cold_output = run_doctor_with_env(&args, &cold_env);
            let warm_output = run_doctor_with_env(&args, &warm_env);

            assert_eq!(
                canonical_doctor_stdout_bytes(&cold_output),
                canonical_doctor_stdout_bytes(&warm_output),
                "doctor JSON canonical output drifted for args={args:?} env={cold_env:?}"
            );
        }
    }
}
