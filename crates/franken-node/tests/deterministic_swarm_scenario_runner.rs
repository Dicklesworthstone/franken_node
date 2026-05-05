use frankenengine_node::tools::swarm_scenario::{
    EVENT_ASSERTION_FAILED, EVENT_COMPLETED, EVENT_FAIL_CLOSED_CONFIRMED,
    EVENT_FLEET_ACTION_PUBLISHED, EVENT_REPLAY_BUILT, SwarmScenarioVerdict,
    all_green_fleet_replay_scenario_spec, recovery_fail_closed_scenario_spec,
    registered_swarm_scenarios, render_swarm_scenario_jsonl, run_deterministic_swarm_scenario,
};

type TestResult = Result<(), String>;

#[test]
fn registered_scenarios_cover_green_and_fail_closed_paths() {
    let scenarios = registered_swarm_scenarios();

    assert_eq!(scenarios.len(), 2);
    assert!(scenarios.iter().any(|scenario| scenario.fault.is_none()));
    assert!(scenarios.iter().any(|scenario| scenario.fault.is_some()));
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
