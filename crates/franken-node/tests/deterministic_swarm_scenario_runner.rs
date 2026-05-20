use std::collections::BTreeSet;

use frankenengine_node::tools::swarm_scenario::{
    EVENT_ASSERTION_FAILED, EVENT_COMPLETED, EVENT_FAIL_CLOSED_CONFIRMED,
    EVENT_FLEET_ACTION_PUBLISHED, EVENT_OPERATOR_RECOMMENDATION_RECORDED, EVENT_REPLAY_BUILT,
    SwarmScenarioError, SwarmScenarioVerdict, all_green_fleet_replay_scenario_spec,
    high_contention_swarm_scenario_specs, recovery_fail_closed_scenario_spec,
    registered_swarm_scenarios, render_swarm_scenario_jsonl, run_deterministic_swarm_scenario,
};

type TestResult = Result<(), String>;

#[test]
fn registered_scenarios_cover_green_and_fail_closed_paths() {
    let scenarios = registered_swarm_scenarios();

    assert_eq!(scenarios.len(), 8);
    assert!(scenarios.iter().any(|scenario| scenario.fault.is_none()));
    assert!(scenarios.iter().any(|scenario| scenario.fault.is_some()));
    assert_eq!(high_contention_swarm_scenario_specs().len(), 6);
    assert!(
        scenarios
            .iter()
            .filter(|scenario| !scenario.operator_incidents.is_empty())
            .count()
            >= 6
    );
}

#[test]
fn all_green_fleet_replay_scenario_emits_deterministic_jsonl() -> TestResult {
    let spec = all_green_fleet_replay_scenario_spec();
    let first_root =
        tempfile::tempdir().map_err(|err| format!("failed creating first tempdir: {err}"))?;
    let second_root =
        tempfile::tempdir().map_err(|err| format!("failed creating second tempdir: {err}"))?;

    let first_report = run_deterministic_swarm_scenario(&spec, first_root.path())
        .map_err(|err| format!("first scenario run failed: {err}"))?;
    let second_report = run_deterministic_swarm_scenario(&spec, second_root.path())
        .map_err(|err| format!("second scenario run failed: {err}"))?;

    if first_report.verdict != SwarmScenarioVerdict::Pass {
        return Err(format!(
            "expected pass verdict, got {:?} with assertions {:?}",
            first_report.verdict, first_report.assertions
        ));
    }
    if first_report
        .assertions
        .iter()
        .any(|assertion| !assertion.success)
    {
        return Err(format!(
            "green scenario produced failed assertions: {:?}",
            first_report.assertions
        ));
    }

    let first_jsonl = render_swarm_scenario_jsonl(&first_report)
        .map_err(|err| format!("failed rendering first jsonl: {err}"))?;
    let second_jsonl = render_swarm_scenario_jsonl(&second_report)
        .map_err(|err| format!("failed rendering second jsonl: {err}"))?;
    if first_jsonl != second_jsonl {
        return Err(format!(
            "scenario JSONL must be byte-stable across temp roots\nfirst:\n{first_jsonl}\nsecond:\n{second_jsonl}"
        ));
    }

    let event_codes = first_report
        .logs
        .iter()
        .map(|log| log.event_code.as_str())
        .collect::<Vec<_>>();
    for expected in [
        EVENT_FLEET_ACTION_PUBLISHED,
        EVENT_REPLAY_BUILT,
        EVENT_COMPLETED,
    ] {
        if !event_codes.contains(&expected) {
            return Err(format!(
                "missing scenario event code {expected}: {event_codes:?}"
            ));
        }
    }
    if !first_report
        .artifacts
        .iter()
        .any(|artifact| artifact.artifact_path.as_str().eq("fleet/actions.jsonl"))
    {
        return Err(format!(
            "fleet action artifact missing: {:?}",
            first_report.artifacts
        ));
    }
    if !first_report
        .artifacts
        .iter()
        .all(|artifact| artifact.digest.starts_with("sha256:"))
    {
        return Err(format!(
            "all artifacts should carry sha256 digests: {:?}",
            first_report.artifacts
        ));
    }

    Ok(())
}

#[test]
fn tampered_replay_scenario_fails_closed_with_actionable_jsonl() -> TestResult {
    let spec = recovery_fail_closed_scenario_spec();
    let root = tempfile::tempdir().map_err(|err| format!("failed creating tempdir: {err}"))?;

    let report = run_deterministic_swarm_scenario(&spec, root.path())
        .map_err(|err| format!("scenario run failed: {err}"))?;

    if !matches!(report.verdict, SwarmScenarioVerdict::FailClosed) {
        return Err(format!(
            "expected fail-closed verdict, got {:?} with assertions {:?}",
            report.verdict, report.assertions
        ));
    }
    if !report
        .logs
        .iter()
        .any(|log| log.event_code == EVENT_FAIL_CLOSED_CONFIRMED && log.success)
    {
        return Err(format!(
            "fail-closed confirmation log missing: {:?}",
            report.logs
        ));
    }
    if !report.assertions.iter().any(|assertion| {
        assertion.event_code == EVENT_FAIL_CLOSED_CONFIRMED
            && assertion.expected == "ITR-REPLAY-INTEGRITY"
            && assertion.actual.contains("ITR-REPLAY-INTEGRITY")
            && assertion.artifact_path.ends_with("incident_timeline.json")
            && assertion.success
    }) {
        return Err(format!(
            "fail-closed assertion must include phase/event/expected/actual/artifact fields: {:?}",
            report.assertions
        ));
    }

    let jsonl = render_swarm_scenario_jsonl(&report)
        .map_err(|err| format!("failed rendering scenario jsonl: {err}"))?;
    if !jsonl.contains("ITR-REPLAY-INTEGRITY")
        || !jsonl.contains("expected")
        || !jsonl.contains("actual")
        || !jsonl.contains("artifact_path")
    {
        return Err(format!(
            "jsonl omitted actionable assertion fields:\n{jsonl}"
        ));
    }
    if jsonl.contains(EVENT_ASSERTION_FAILED) {
        return Err(format!(
            "fail-closed recovery should not be represented as assertion failure:\n{jsonl}"
        ));
    }

    Ok(())
}

#[test]
fn high_contention_scenario_pack_emits_reason_codes_trace_ids_and_operator_actions() -> TestResult {
    let specs = high_contention_swarm_scenario_specs();
    let expected_reason_codes = [
        "SWARM_BLOCKED_PROOF_CARGO_PRESSURE",
        "SWARM_COORDINATION_CORRUPT_BEAD_FALLBACK",
        "SWARM_QUIET_LANE_REPROOF_ADMITTED",
        "SWARM_SOURCE_ONLY_DURING_VALIDATION_SATURATION",
        "SWARM_STALE_RCH_PROGRESS_CLASSIFIED",
        "SWARM_TARGET_DIR_LEASE_SELECTED",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut actual_reason_codes = BTreeSet::new();

    if specs.len() != 6 {
        return Err(format!(
            "expected six high-contention specs, got {}",
            specs.len()
        ));
    }

    for spec in &specs {
        let root = tempfile::tempdir().map_err(|err| format!("failed creating tempdir: {err}"))?;
        let report = run_deterministic_swarm_scenario(spec, root.path())
            .map_err(|err| format!("scenario {} failed: {err}", spec.scenario_id))?;
        if !matches!(report.verdict, SwarmScenarioVerdict::Pass) {
            return Err(format!(
                "expected pass verdict for {}, got {:?} with assertions {:?}",
                spec.scenario_id, report.verdict, report.assertions
            ));
        }

        let incident = spec
            .operator_incidents
            .first()
            .ok_or_else(|| format!("{} did not declare an operator incident", spec.scenario_id))?;
        actual_reason_codes.insert(incident.reason_code.as_str());

        let jsonl = render_swarm_scenario_jsonl(&report)
            .map_err(|err| format!("failed rendering scenario jsonl: {err}"))?;
        for required in [
            EVENT_OPERATOR_RECOMMENDATION_RECORDED,
            "trace_id",
            "reason_code",
            "operator_action",
            incident.reason_code.as_str(),
            incident.operator_action.as_str(),
        ] {
            if !jsonl.contains(required) {
                return Err(format!(
                    "{} JSONL omitted required high-contention field {required}:\n{jsonl}",
                    spec.scenario_id
                ));
            }
        }
        if !report.operator_output.iter().any(|line| {
            line.contains(&incident.reason_code) && line.contains(&incident.operator_action)
        }) {
            return Err(format!(
                "{} operator output omitted actionable recommendation: {:?}",
                spec.scenario_id, report.operator_output
            ));
        }
    }

    if actual_reason_codes != expected_reason_codes {
        return Err(format!(
            "high-contention reason code set drifted: {actual_reason_codes:?}"
        ));
    }

    Ok(())
}

#[test]
fn high_contention_scenario_rejects_unsafe_operator_evidence_ref() -> TestResult {
    let mut spec = high_contention_swarm_scenario_specs()
        .into_iter()
        .next()
        .ok_or_else(|| "high-contention scenario pack was empty".to_string())?;
    let incident = spec
        .operator_incidents
        .get_mut(0)
        .ok_or_else(|| "high-contention scenario omitted operator incident".to_string())?;
    incident.evidence_ref = "../unsafe.json".to_string();
    let root = tempfile::tempdir().map_err(|err| format!("failed creating tempdir: {err}"))?;

    match run_deterministic_swarm_scenario(&spec, root.path()) {
        Err(SwarmScenarioError::UnsafeArtifactPath { path }) if path == "../unsafe.json" => Ok(()),
        other => Err(format!(
            "expected unsafe artifact path rejection for operator evidence ref, got {other:?}"
        )),
    }
}

#[test]
fn high_contention_scenario_rejects_missing_operator_evidence_ref() -> TestResult {
    let mut spec = high_contention_swarm_scenario_specs()
        .into_iter()
        .next()
        .ok_or_else(|| "high-contention scenario pack was empty".to_string())?;
    let incident = spec
        .operator_incidents
        .get_mut(0)
        .ok_or_else(|| "high-contention scenario omitted operator incident".to_string())?;
    incident.evidence_ref = "scenario_artifacts/missing/operator-evidence.json".to_string();
    let root = tempfile::tempdir().map_err(|err| format!("failed creating tempdir: {err}"))?;

    match run_deterministic_swarm_scenario(&spec, root.path()) {
        Err(SwarmScenarioError::MissingOperatorEvidenceRef { path, .. })
            if path == "scenario_artifacts/missing/operator-evidence.json" =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected missing generated artifact rejection for operator evidence ref, got {other:?}"
        )),
    }
}
