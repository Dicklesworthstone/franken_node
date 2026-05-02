use super::{
    canonicalize_doctor_runtime_metadata, fixture_path, parse_jsonl, parse_report, required_array,
    required_string, run_doctor_with_env,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const DOCTOR_POLICY_ACTIVATION_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/doctor_policy_activation_golden_vectors.json");

#[derive(Debug, Deserialize)]
struct CoverageRow {
    clause: String,
    vectors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct PolicyLogExpectation {
    check_code: String,
    event_code: String,
    status: String,
    level: String,
    message: String,
    error_code: Option<String>,
    recovery_action: String,
}

#[derive(Debug, Deserialize)]
struct PolicyVector {
    name: String,
    trace_id: String,
    policy_input: String,
    golden_report_path: String,
    expected_policy_present: bool,
    expected_dominant_verdict: Option<String>,
    expected_decision_reason: Option<String>,
    expected_chosen_candidate: Option<String>,
    expected_blocking_budget_ids: Vec<String>,
    expected_policy_statuses: BTreeMap<String, String>,
    expected_policy_logs: Vec<PolicyLogExpectation>,
}

#[derive(Debug, Deserialize)]
struct VectorFile {
    schema_version: String,
    coverage: Vec<CoverageRow>,
    vectors: Vec<PolicyVector>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn load_vectors() -> VectorFile {
    serde_json::from_str(DOCTOR_POLICY_ACTIVATION_VECTORS_JSON)
        .expect("doctor policy activation vectors must parse")
}

fn doctor_args(vector: &PolicyVector) -> Vec<String> {
    vec![
        "doctor".to_string(),
        "--json".to_string(),
        "--structured-logs-jsonl".to_string(),
        "--trace-id".to_string(),
        vector.trace_id.clone(),
        "--policy-activation-input".to_string(),
        fixture_path(&vector.policy_input).display().to_string(),
    ]
}

fn load_golden_report(path: &str) -> Value {
    let raw = fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|err| panic!("failed reading golden doctor report {path}: {err}"));
    let mut value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("golden doctor report {path} must parse: {err}"));
    canonicalize_doctor_runtime_metadata(&mut value);
    value
}

fn run_vector(vector: &PolicyVector) -> (Value, Vec<Value>) {
    let output = run_doctor_with_env(&doctor_args(vector), &[]);
    let mut report = parse_report(&output);
    canonicalize_doctor_runtime_metadata(&mut report);
    let logs = parse_jsonl(&output.stderr);
    (report, logs)
}

fn policy_checks(report: &Value) -> Vec<Value> {
    let mut checks = required_array(report, "checks")
        .iter()
        .filter(|check| required_string(check, "code").starts_with("DR-POLICY-"))
        .cloned()
        .collect::<Vec<_>>();
    for check in &mut checks {
        normalize_policy_strings(check);
    }
    checks
}

fn policy_structured_logs(report: &Value) -> Vec<Value> {
    let mut logs = required_array(report, "structured_logs")
        .iter()
        .filter(|log| required_string(log, "check_code").starts_with("DR-POLICY-"))
        .cloned()
        .collect::<Vec<_>>();
    for log in &mut logs {
        normalize_policy_strings(log);
    }
    logs
}

fn actual_policy_log_expectations(logs: &[Value]) -> Vec<PolicyLogExpectation> {
    logs.iter()
        .filter(|log| required_string(log, "check_code").starts_with("DR-POLICY-"))
        .map(|log| PolicyLogExpectation {
            check_code: required_string(log, "check_code").to_string(),
            event_code: required_string(log, "event_code").to_string(),
            status: required_string(log, "status").to_string(),
            level: required_string(log, "level").to_string(),
            message: normalize_policy_fixture_string(required_string(log, "message")),
            error_code: log
                .get("error_code")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            recovery_action: log["recovery_hint"]["action"]
                .as_str()
                .expect("policy stderr log recovery action")
                .to_string(),
        })
        .collect()
}

fn normalize_policy_fixture_string(text: &str) -> String {
    const POLICY_FIXTURE_PREFIX: &str = "fixtures/policy_activation/";
    if let Some((_, suffix)) = text.split_once(POLICY_FIXTURE_PREFIX) {
        format!("{POLICY_FIXTURE_PREFIX}{suffix}")
    } else {
        text.to_string()
    }
}

fn normalize_policy_strings(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                normalize_policy_strings(item);
            }
        }
        Value::Object(map) => {
            for nested in map.values_mut() {
                normalize_policy_strings(nested);
            }
        }
        Value::String(text) => {
            *text = normalize_policy_fixture_string(text);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn normalized_policy_activation(report: &Value) -> Option<Value> {
    report.get("policy_activation").cloned().map(|mut value| {
        normalize_policy_strings(&mut value);
        value
    })
}

fn normalized_expected_policy_logs(vector: &PolicyVector) -> Vec<PolicyLogExpectation> {
    vector
        .expected_policy_logs
        .iter()
        .cloned()
        .map(|mut log| {
            log.message = normalize_policy_fixture_string(&log.message);
            log
        })
        .collect()
}

fn assert_policy_summary(report: &Value, vector: &PolicyVector) {
    let checks = policy_checks(report);
    let statuses = checks
        .iter()
        .map(|check| {
            (
                required_string(check, "code").to_string(),
                required_string(check, "status").to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        statuses, vector.expected_policy_statuses,
        "policy check status drift for {}",
        vector.name
    );

    if vector.expected_policy_present {
        let policy = report
            .get("policy_activation")
            .expect("policy_activation should be present");
        assert_eq!(
            policy["guardrail_certificate"]["dominant_verdict"]
                .as_str()
                .map(ToString::to_string),
            vector.expected_dominant_verdict,
            "dominant verdict drift for {}",
            vector.name
        );
        assert_eq!(
            policy["decision_outcome"]["reason"]
                .as_str()
                .map(ToString::to_string),
            vector.expected_decision_reason,
            "decision reason drift for {}",
            vector.name
        );
        assert_eq!(
            policy["decision_outcome"]["chosen"]
                .as_str()
                .map(ToString::to_string),
            vector.expected_chosen_candidate,
            "chosen candidate drift for {}",
            vector.name
        );
        let blocking_budget_ids = policy["guardrail_certificate"]["blocking_budget_ids"]
            .as_array()
            .expect("blocking_budget_ids array")
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .expect("blocking budget id string")
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            blocking_budget_ids, vector.expected_blocking_budget_ids,
            "blocking budget drift for {}",
            vector.name
        );
    } else {
        assert!(
            report.get("policy_activation").is_none(),
            "policy_activation must stay absent for {}",
            vector.name
        );
    }
}

#[test]
fn doctor_policy_activation_golden_vectors_cover_required_contract() {
    let vectors = load_vectors();
    assert_eq!(
        vectors.schema_version,
        "franken-node/doctor-policy-activation-conformance/v1"
    );
    assert_eq!(vectors.vectors.len(), 4, "expected four policy scenarios");

    let vector_names = vectors
        .vectors
        .iter()
        .map(|vector| vector.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        vector_names,
        BTreeSet::from([
            "policy_allow",
            "policy_warn",
            "policy_block",
            "policy_invalid_input",
        ])
    );

    let required_clauses = [
        "DOC-009 dominant verdict status mapping",
        "DOC-010 decision engine outcome mapping",
        "DOC-011 wording and pipeline failure mapping",
        "policy activation report slice matches checked-in doctor golden",
        "policy activation stderr JSONL slice uses canonical severity mapping",
    ];
    assert_eq!(vectors.coverage.len(), required_clauses.len());
    for clause in required_clauses {
        let row = vectors
            .coverage
            .iter()
            .find(|row| row.clause == clause)
            .unwrap_or_else(|| panic!("missing coverage clause {clause}"));
        assert_eq!(
            row.vectors.len(),
            vectors.vectors.len(),
            "coverage clause must reference every live vector: {clause}"
        );
        for name in &row.vectors {
            assert!(
                vector_names.contains(name.as_str()),
                "coverage clause references unknown vector {name}"
            );
        }
    }

    for vector in vectors.vectors {
        let expected_codes = BTreeSet::from(["DR-POLICY-009", "DR-POLICY-010", "DR-POLICY-011"]);
        let actual_codes = vector
            .expected_policy_statuses
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_codes, expected_codes, "policy status map drift");
        assert_eq!(
            vector.expected_policy_logs.len(),
            3,
            "each vector must freeze the policy stderr triplet"
        );
    }
}

#[test]
fn doctor_policy_activation_golden_vectors_match_live_policy_contract() {
    for vector in load_vectors().vectors {
        let (report, logs) = run_vector(&vector);
        let golden_report = load_golden_report(&vector.golden_report_path);

        assert_policy_summary(&report, &vector);
        assert_eq!(
            policy_checks(&report),
            policy_checks(&golden_report),
            "policy checks drifted from checked-in doctor golden for {}",
            vector.name
        );
        assert_eq!(
            policy_structured_logs(&report),
            policy_structured_logs(&golden_report),
            "policy structured_logs slice drifted from checked-in doctor golden for {}",
            vector.name
        );
        assert_eq!(
            normalized_policy_activation(&report),
            normalized_policy_activation(&golden_report),
            "policy activation object drifted from checked-in doctor golden for {}",
            vector.name
        );
        assert_eq!(
            actual_policy_log_expectations(&logs),
            normalized_expected_policy_logs(&vector),
            "policy stderr JSONL projection drifted for {}",
            vector.name
        );
    }
}
