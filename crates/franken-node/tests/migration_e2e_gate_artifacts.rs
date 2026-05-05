//! Mock-free E2E checks for migration gate artifact contracts.
//!
//! These tests load checked-in contract artifacts and replay their inputs
//! through the actual migration gate state machines. No mocks or synthetic
//! gate substitutes are used.

use std::{fs, path::PathBuf};

use frankenengine_node::migration::bpet_migration_gate as bpet_gate;
use frankenengine_node::migration::dgis_migration_gate as dgis_gate;
use serde_json::{Value, json};

const FLOAT_EPSILON: f64 = 1e-9;
const BPET_ARTIFACT_PATH: &str = "artifacts/10.21/bpet_migration_gate_results.json";
const DGIS_ARTIFACT_PATH: &str = "artifacts/10.20/dgis_migration_health_report.json";

fn log_phase(test_name: &str, phase: &str, detail: Value) {
    eprintln!(
        "{}",
        serde_json::to_string(&json!({
            "suite": "migration_e2e_gate_artifacts",
            "test": test_name,
            "phase": phase,
            "detail": detail,
        }))
        .expect("structured test log serializes")
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir must have workspace parent")
        .parent()
        .expect("workspace parent must have repository parent")
        .to_path_buf()
}

fn parse_json_artifact(path: &str) -> Value {
    let raw = fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|err| panic!("{path} must be readable from the checkout: {err}"));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("{path} must parse as JSON: {err}"))
}

fn f64_field(object: &Value, field: &str) -> f64 {
    object[field]
        .as_f64()
        .unwrap_or_else(|| panic!("field `{field}` must be a finite number"))
}

fn u32_field(object: &Value, field: &str) -> u32 {
    let value = object[field]
        .as_u64()
        .unwrap_or_else(|| panic!("field `{field}` must be an unsigned integer"));
    u32::try_from(value).unwrap_or_else(|_| panic!("field `{field}` must fit u32"))
}

fn i64_field(object: &Value, field: &str) -> i64 {
    object[field]
        .as_i64()
        .unwrap_or_else(|| panic!("field `{field}` must be a signed integer"))
}

fn assert_f64_close(actual: f64, expected: f64, field: &str) {
    assert!(
        (actual - expected).abs() <= FLOAT_EPSILON,
        "{field}: expected {expected}, got {actual}"
    );
}

fn bpet_snapshot(value: &Value) -> bpet_gate::TrajectorySnapshot {
    bpet_gate::TrajectorySnapshot {
        instability_score: f64_field(value, "instability_score"),
        drift_score: f64_field(value, "drift_score"),
        regime_shift_probability: f64_field(value, "regime_shift_probability"),
    }
}

fn bpet_thresholds(value: &Value) -> bpet_gate::StabilityThresholds {
    bpet_gate::StabilityThresholds {
        max_instability_delta_for_direct_admit: f64_field(
            value,
            "max_instability_delta_for_direct_admit",
        ),
        max_drift_score_for_direct_admit: f64_field(value, "max_drift_score_for_direct_admit"),
        max_regime_shift_probability_for_direct_admit: f64_field(
            value,
            "max_regime_shift_probability_for_direct_admit",
        ),
        max_instability_score_for_staged_rollout: f64_field(
            value,
            "max_instability_score_for_staged_rollout",
        ),
        max_regime_shift_probability_for_staged_rollout: f64_field(
            value,
            "max_regime_shift_probability_for_staged_rollout",
        ),
    }
}

fn dgis_snapshot(value: &Value) -> dgis_gate::GraphHealthSnapshot {
    dgis_gate::GraphHealthSnapshot {
        cascade_risk: f64_field(value, "cascade_risk"),
        fragility_findings: u32_field(value, "fragility_findings"),
        articulation_points: u32_field(value, "articulation_points"),
    }
}

fn dgis_thresholds(value: &Value) -> dgis_gate::MigrationGateThresholds {
    dgis_gate::MigrationGateThresholds {
        max_cascade_risk_delta: f64_field(value, "max_cascade_risk_delta"),
        max_new_fragility_findings: u32_field(value, "max_new_fragility_findings"),
        max_new_articulation_points: u32_field(value, "max_new_articulation_points"),
    }
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("value must be an array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("array item must be a string")
                .to_string()
        })
        .collect()
}

fn event_codes(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("events must be an array")
        .iter()
        .map(|event| {
            event["code"]
                .as_str()
                .expect("event code must be a string")
                .to_string()
        })
        .collect()
}

fn assert_bpet_delta_matches(actual: &Value, expected: &Value) {
    for field in ["instability_delta", "drift_delta", "regime_shift_delta"] {
        assert_f64_close(
            f64_field(actual, field),
            f64_field(expected, field),
            &format!("bpet.delta.{field}"),
        );
    }
}

fn assert_bpet_rollout_matches(actual: &Value, expected: &Value) {
    let actual_steps = actual["steps"]
        .as_array()
        .expect("actual steps must be array");
    let expected_steps = expected["steps"]
        .as_array()
        .expect("expected steps must be array");
    assert_eq!(actual_steps.len(), expected_steps.len());
    for (index, (actual_step, expected_step)) in actual_steps.iter().zip(expected_steps).enumerate()
    {
        assert_eq!(actual_step["phase"], expected_step["phase"]);
        assert_f64_close(
            f64_field(actual_step, "max_instability_score"),
            f64_field(expected_step, "max_instability_score"),
            &format!("bpet.rollout.steps[{index}].max_instability_score"),
        );
        assert_f64_close(
            f64_field(actual_step, "max_regime_shift_probability"),
            f64_field(expected_step, "max_regime_shift_probability"),
            &format!("bpet.rollout.steps[{index}].max_regime_shift_probability"),
        );
    }
    assert_eq!(actual["fallback"], expected["fallback"]);
}

fn assert_dgis_delta_matches(actual: &Value, expected: &Value, label: &str) {
    assert_f64_close(
        f64_field(actual, "cascade_risk_delta"),
        f64_field(expected, "cascade_risk_delta"),
        &format!("{label}.cascade_risk_delta"),
    );
    assert_eq!(
        i64_field(actual, "new_fragility_findings"),
        i64_field(expected, "new_fragility_findings"),
        "{label}.new_fragility_findings"
    );
    assert_eq!(
        i64_field(actual, "new_articulation_points"),
        i64_field(expected, "new_articulation_points"),
        "{label}.new_articulation_points"
    );
}

fn assert_replan_suggestions_match(actual: &Value, expected: &Value) {
    let actual_suggestions = actual.as_array().expect("actual suggestions must be array");
    let expected_suggestions = expected
        .as_array()
        .expect("expected suggestions must be array");
    assert_eq!(actual_suggestions.len(), expected_suggestions.len());
    for (index, (actual_suggestion, expected_suggestion)) in actual_suggestions
        .iter()
        .zip(expected_suggestions)
        .enumerate()
    {
        assert_eq!(actual_suggestion["path_id"], expected_suggestion["path_id"]);
        assert_dgis_delta_matches(
            &actual_suggestion["projected_delta"],
            &expected_suggestion["projected_delta"],
            &format!("dgis.replan_suggestions[{index}].projected_delta"),
        );
        assert_eq!(
            actual_suggestion["rationale"],
            expected_suggestion["rationale"]
        );
    }
}

#[test]
fn bpet_artifact_replays_through_actual_stability_gate() {
    let test_name = "bpet_artifact_replays_through_actual_stability_gate";
    let artifact = parse_json_artifact(BPET_ARTIFACT_PATH);
    let admission = &artifact["admission"];
    let output_dir = tempfile::tempdir().expect("temp output dir must be created");
    log_phase(
        test_name,
        "artifact_loaded",
        json!({"path": BPET_ARTIFACT_PATH, "migration_id": artifact["migration_id"]}),
    );

    let rollback_target = admission["staged_rollout"]["fallback"]["rollback_to_version"]
        .as_str()
        .expect("fallback rollback target must be a string");
    let target_version = rollback_target
        .strip_suffix("-previous")
        .expect("fallback target must end in -previous");
    let trace_id = admission["events"][0]["trace_id"]
        .as_str()
        .expect("artifact trace_id must be present");

    let decision = bpet_gate::evaluate_admission(
        trace_id,
        bpet_snapshot(&admission["baseline"]),
        bpet_snapshot(&admission["projected"]),
        bpet_thresholds(&admission["thresholds"]),
        target_version,
    );
    let actual = serde_json::to_value(&decision).expect("decision serializes");
    let output_path = output_dir.path().join("bpet_admission_decision.json");
    fs::write(
        &output_path,
        serde_json::to_vec_pretty(&actual).expect("decision JSON serializes"),
    )
    .expect("decision JSON writes to temp file");
    let persisted_actual: Value = serde_json::from_slice(
        &fs::read(&output_path).expect("decision JSON reads back from temp file"),
    )
    .expect("persisted decision JSON parses");

    assert_eq!(persisted_actual["verdict"], admission["verdict"]);
    assert_eq!(persisted_actual["baseline"], admission["baseline"]);
    assert_eq!(persisted_actual["projected"], admission["projected"]);
    assert_bpet_delta_matches(&persisted_actual["delta"], &admission["delta"]);
    assert_eq!(persisted_actual["thresholds"], admission["thresholds"]);
    assert_eq!(
        persisted_actual["additional_evidence_required"],
        admission["additional_evidence_required"]
    );
    assert_bpet_rollout_matches(
        &persisted_actual["staged_rollout"],
        &admission["staged_rollout"],
    );
    assert_eq!(
        event_codes(&persisted_actual["events"]),
        event_codes(&admission["events"])
    );
    assert_eq!(
        string_array(&actual["staged_rollout"]["fallback"]["required_artifacts"]),
        string_array(&admission["staged_rollout"]["fallback"]["required_artifacts"])
    );
    log_phase(
        test_name,
        "assert",
        json!({
            "verdict": persisted_actual["verdict"],
            "event_codes": event_codes(&persisted_actual["events"]),
            "output_path": output_path.display().to_string(),
        }),
    );
}

#[test]
fn dgis_artifact_replays_through_actual_health_gate() {
    let test_name = "dgis_artifact_replays_through_actual_health_gate";
    let artifact = parse_json_artifact(DGIS_ARTIFACT_PATH);
    let evaluation = &artifact["evaluation"];
    let output_dir = tempfile::tempdir().expect("temp output dir must be created");
    log_phase(
        test_name,
        "artifact_loaded",
        json!({"path": DGIS_ARTIFACT_PATH, "plan_id": artifact["plan_id"]}),
    );

    let baseline = dgis_snapshot(&evaluation["baseline"]);
    let suggestion = &evaluation["replan_suggestions"][0];
    let suggested_delta = &suggestion["projected_delta"];
    let candidate_projected = dgis_gate::GraphHealthSnapshot {
        cascade_risk: baseline.cascade_risk + f64_field(suggested_delta, "cascade_risk_delta"),
        fragility_findings: baseline
            .fragility_findings
            .saturating_add(u32_field(suggested_delta, "new_fragility_findings")),
        articulation_points: baseline
            .articulation_points
            .saturating_add(u32_field(suggested_delta, "new_articulation_points")),
    };
    let candidates = [dgis_gate::MigrationPathCandidate {
        path_id: suggestion["path_id"]
            .as_str()
            .expect("suggestion path_id must be a string")
            .to_string(),
        projected: candidate_projected,
        notes: "staged rollout + quarantine gate".to_string(),
    }];
    let trace_id = evaluation["events"][0]["trace_id"]
        .as_str()
        .expect("artifact trace_id must be present");

    let actual = dgis_gate::evaluate_admission(
        trace_id,
        baseline,
        dgis_snapshot(&evaluation["projected"]),
        dgis_thresholds(&evaluation["thresholds"]),
        &candidates,
    );
    let actual_value = serde_json::to_value(&actual).expect("evaluation serializes");
    let output_path = output_dir.path().join("dgis_gate_evaluation.json");
    fs::write(
        &output_path,
        serde_json::to_vec_pretty(&actual_value).expect("evaluation JSON serializes"),
    )
    .expect("evaluation JSON writes to temp file");
    let persisted_actual: Value = serde_json::from_slice(
        &fs::read(&output_path).expect("evaluation JSON reads back from temp file"),
    )
    .expect("persisted evaluation JSON parses");

    assert_eq!(persisted_actual["phase"], evaluation["phase"]);
    assert_eq!(persisted_actual["verdict"], evaluation["verdict"]);
    assert_eq!(persisted_actual["baseline"], evaluation["baseline"]);
    assert_eq!(persisted_actual["projected"], evaluation["projected"]);
    assert_dgis_delta_matches(
        &persisted_actual["delta"],
        &evaluation["delta"],
        "dgis.delta",
    );
    assert_eq!(persisted_actual["thresholds"], evaluation["thresholds"]);
    assert_eq!(
        event_codes(&persisted_actual["events"]),
        event_codes(&evaluation["events"])
    );

    let expected_reason_codes = evaluation["rejection_reasons"]
        .as_array()
        .expect("artifact rejection reasons must be an array")
        .iter()
        .map(|reason| {
            reason["code"]
                .as_str()
                .expect("reason code must be a string")
                .to_string()
        })
        .collect::<Vec<_>>();
    let actual_reason_codes = actual
        .rejection_reasons
        .iter()
        .map(|reason| reason.code.clone())
        .collect::<Vec<_>>();
    assert_eq!(actual_reason_codes, expected_reason_codes);
    assert_replan_suggestions_match(
        &persisted_actual["replan_suggestions"],
        &evaluation["replan_suggestions"],
    );
    log_phase(
        test_name,
        "assert",
        json!({
            "verdict": persisted_actual["verdict"],
            "rejection_codes": actual_reason_codes,
            "event_codes": event_codes(&persisted_actual["events"]),
            "output_path": output_path.display().to_string(),
        }),
    );
}
