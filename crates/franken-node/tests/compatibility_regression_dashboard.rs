#[path = "../src/tools/compatibility_regression_dashboard.rs"]
mod compatibility_regression_dashboard;

use compatibility_regression_dashboard::{
    DASHBOARD_EVENT_CODE, DashboardError, FixtureResult, FixtureStatus, build_dashboard,
    build_dashboard_at, dashboard_from_corpus_report, fixtures_from_corpus_report, to_json_value,
};
use serde_json::Value;
use std::fs;
use std::path::Path;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TS: &str = "2026-05-13T04:50:00Z";

#[test]
fn rust_dashboard_generates_schema_backed_views_from_corpus_report() -> TestResult {
    let report = read_corpus_report()?;
    let fixtures = fixtures_from_corpus_report(&report)?;
    let live_timestamp_dashboard = build_dashboard(&fixtures, &[])?;
    let dashboard = dashboard_from_corpus_report(&report, &[], TS)?;
    let json = to_json_value(&dashboard)?;
    let expected_passing = report
        .pointer("/totals/passed_test_cases")
        .and_then(Value::as_u64)
        .ok_or("corpus report must declare totals.passed_test_cases")?;
    let expected_failing = report
        .pointer("/totals/failed_test_cases")
        .and_then(Value::as_u64)
        .ok_or("corpus report must declare totals.failed_test_cases")?;

    assert_eq!(DASHBOARD_EVENT_CODE, "DASH-RUST-001");
    assert_eq!(live_timestamp_dashboard.schema_version, "1.0");
    assert_eq!(dashboard.schema_version, "1.0");
    assert_eq!(dashboard.overall.total_behaviors, 560);
    assert_eq!(dashboard.overall.tested, 560);
    assert_eq!(dashboard.overall.passing, expected_passing);
    assert_eq!(dashboard.overall.failing, expected_failing);
    assert_eq!(
        json.get("schema_version").and_then(Value::as_str),
        Some("1.0")
    );
    assert!(json.get("overall").is_some());
    assert!(json.get("by_family").and_then(Value::as_array).is_some());
    assert!(json.get("by_band").and_then(Value::as_array).is_some());
    assert!(json.get("regressions").and_then(Value::as_array).is_some());

    let families = json
        .get("by_family")
        .and_then(Value::as_array)
        .ok_or("dashboard by_family must be an array")?;
    assert!(families.iter().any(|family| {
        family.get("family").and_then(Value::as_str) == Some("stream")
            && family.get("total_behaviors").and_then(Value::as_u64) == Some(65)
    }));

    let bands = json
        .get("by_band")
        .and_then(Value::as_array)
        .ok_or("dashboard by_band must be an array")?;
    assert!(bands.iter().any(|band| {
        band.get("band").and_then(Value::as_str) == Some("core")
            && band.get("target").and_then(Value::as_f64) == Some(1.0)
    }));

    Ok(())
}

#[test]
fn rust_dashboard_detects_pass_to_fail_regressions() -> TestResult {
    let previous = vec![
        fixture("tc::fs::read", "fs", "core", FixtureStatus::Pass)?,
        fixture(
            "tc::http::headers",
            "http",
            "high-value",
            FixtureStatus::Pass,
        )?,
    ];
    let current = vec![
        fixture("tc::fs::read", "fs", "core", FixtureStatus::Fail)?,
        fixture(
            "tc::http::headers",
            "http",
            "high-value",
            FixtureStatus::Pass,
        )?,
    ];

    let dashboard = build_dashboard_at(&current, &previous, TS)?;

    assert_eq!(dashboard.regressions.len(), 1);
    assert_eq!(dashboard.regressions[0].fixture_id, "tc::fs::read");
    assert_eq!(dashboard.regressions[0].previously, "pass");
    assert_eq!(dashboard.regressions[0].now, "fail");

    Ok(())
}

#[test]
fn rust_dashboard_rejects_malformed_corpus_rows() {
    let report = serde_json::json!({
        "per_test_results": [
            {"test_id": "tc::fs::read", "api_family": "fs", "band": "core", "status": "flaky"}
        ]
    });

    assert!(matches!(
        fixtures_from_corpus_report(&report),
        Err(DashboardError::InvalidField { field, .. }) if field == "status"
    ));
}

fn read_corpus_report() -> TestResult<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("artifacts/13/compatibility_corpus_results.json");
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn fixture(
    fixture_id: &str,
    api_family: &str,
    band: &str,
    status: FixtureStatus,
) -> Result<FixtureResult, DashboardError> {
    FixtureResult::new(fixture_id, api_family, band, status)
}
