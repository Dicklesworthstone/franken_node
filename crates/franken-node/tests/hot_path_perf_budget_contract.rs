use frankenengine_node::policy::perf_budget_guard::{
    HOT_PATH_SMOKE_BEAD_ID, HOT_PATH_SMOKE_SCHEMA_VERSION, HotPathBudgetSmokeMode,
    PerformanceBudgetGuard, default_hot_path_budget_smoke_cases, hot_path_budget_smoke_policy,
    hot_path_budget_smoke_to_json, run_default_hot_path_budget_smoke, run_hot_path_budget_smoke,
};
use serde_json::{Value, json};

fn committed_evidence() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../artifacts/performance_budgets/bd-ncwlf_hot_path_budget_evidence.json"
    ))?)
}

#[test]
fn hot_path_budget_smoke_committed_evidence_matches_default_cases()
-> Result<(), Box<dyn std::error::Error>> {
    let report = run_default_hot_path_budget_smoke()?;
    let generated = serde_json::to_value(&report)?;
    let committed = committed_evidence()?;

    assert_eq!(
        committed["schema_version"],
        json!(HOT_PATH_SMOKE_SCHEMA_VERSION)
    );
    assert_eq!(committed["bead_id"], json!(HOT_PATH_SMOKE_BEAD_ID));
    assert_eq!(committed["verdict"], json!("PASS"));
    assert_eq!(committed["overall_pass"], json!(true));
    assert_eq!(committed["ci_suitable"], json!(true));
    assert_eq!(committed["skip_blocker"], Value::Null);
    assert_eq!(committed["cases"], generated["cases"]);
    assert_eq!(committed["gate_result"]["overall_pass"], json!(true));
    assert_eq!(committed["gate_result"]["paths_over_budget"], json!(0));
    assert_eq!(
        committed["gate_result"]["total_paths"],
        json!(report.cases.len())
    );
    assert!(
        committed["rch_command"]
            .as_str()
            .is_some_and(|command| command.contains("rch exec -- cargo"))
    );

    Ok(())
}

#[test]
fn hot_path_budget_smoke_pairs_every_metric_with_correctness_assertions()
-> Result<(), Box<dyn std::error::Error>> {
    let report = run_default_hot_path_budget_smoke()?;

    assert!(report.overall_pass);
    assert_eq!(report.cases.len(), 4);
    for case in &report.cases {
        assert!(!case.hot_path.is_empty());
        assert_eq!(case.unit, "deterministic_work_units");
        assert!(!case.source_beads.is_empty());
        assert!(
            case.correctness_assertions.len() >= 3,
            "missing correctness assertions for {}",
            case.hot_path
        );
        assert!(
            case.post_fix_p95_units < case.before_fix_p95_units,
            "post-fix p95 must improve for {}",
            case.hot_path
        );
        assert!(
            case.regression_guard.contains("must"),
            "regression guard should be prescriptive for {}",
            case.hot_path
        );
    }

    Ok(())
}

#[test]
fn hot_path_budget_smoke_json_is_stable_for_ci() -> Result<(), Box<dyn std::error::Error>> {
    let report = run_default_hot_path_budget_smoke()?;
    let first = hot_path_budget_smoke_to_json(&report)?;
    let second = hot_path_budget_smoke_to_json(&report)?;

    assert_eq!(first, second);
    assert!(first.contains("\"schema_version\": \"franken-node/hot-path-budget-smoke/v1\""));
    assert!(first.contains("\"trace_id\": \"trace-bd-ncwlf-hot-path-budget-smoke\""));

    Ok(())
}

#[test]
fn hot_path_budget_smoke_skip_mode_reports_explicit_blocker()
-> Result<(), Box<dyn std::error::Error>> {
    let report = run_hot_path_budget_smoke(HotPathBudgetSmokeMode::Skip {
        blocker: "RCH workers unavailable for perf smoke run".to_string(),
    })?;

    assert_eq!(report.mode, "skip");
    assert_eq!(report.verdict, "SKIP");
    assert!(!report.overall_pass);
    assert_eq!(
        report.skip_blocker.as_deref(),
        Some("RCH workers unavailable for perf smoke run")
    );
    assert!(report.gate_result.is_none());
    assert!(report.events.is_empty());
    assert_eq!(report.cases.len(), 4);

    Ok(())
}

#[test]
fn hot_path_budget_smoke_catches_order_of_magnitude_regression()
-> Result<(), Box<dyn std::error::Error>> {
    let mut cases = default_hot_path_budget_smoke_cases();
    assert!(
        !cases.is_empty(),
        "default smoke harness must include at least one case"
    );
    let Some(first) = cases.first_mut() else {
        return Err(std::io::Error::other("default smoke harness had no cases").into());
    };
    first.post_fix_p95_units = first.before_fix_p95_units * 20.0;
    first.post_fix_p99_units = first.before_fix_p99_units * 20.0;

    let measurements = cases
        .iter()
        .map(frankenengine_node::policy::perf_budget_guard::HotPathBudgetSmokeCase::measurement)
        .collect::<Vec<_>>();
    let policy = hot_path_budget_smoke_policy(&cases);
    let mut guard = PerformanceBudgetGuard::new(policy, "trace-bd-ncwlf-regression-test");
    let result = guard.evaluate(&measurements)?;

    assert!(!result.overall_pass);
    assert_eq!(result.paths_over_budget, 1);
    assert!(
        result.path_results[0]
            .violations
            .iter()
            .any(|violation| violation.contains("p95"))
    );

    Ok(())
}
