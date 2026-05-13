//! Rust implementation of the compatibility regression dashboard contract.
//!
//! The dashboard consumes per-fixture compatibility results, aggregates them by
//! API family and compatibility band, and emits the schema-backed JSON report
//! described in `docs/COMPAT_DASHBOARD_SPEC.md`.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const DASHBOARD_SCHEMA_VERSION: &str = "1.0";
pub const DASHBOARD_EVENT_CODE: &str = "DASH-RUST-001";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardError {
    EmptyInput,
    DuplicateFixtureId(String),
    InvalidField { field: &'static str, reason: String },
    JsonField(String),
    CountTooLarge(&'static str),
}

impl fmt::Display for DashboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "dashboard input must contain at least one fixture"),
            Self::DuplicateFixtureId(id) => write!(f, "duplicate fixture id: {id}"),
            Self::InvalidField { field, reason } => {
                write!(f, "invalid dashboard field {field}: {reason}")
            }
            Self::JsonField(message) => write!(f, "{message}"),
            Self::CountTooLarge(label) => write!(f, "{label} does not fit in u32"),
        }
    }
}

impl std::error::Error for DashboardError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatus {
    Pass,
    Fail,
    Error,
    Skip,
}

impl FixtureStatus {
    pub fn parse(raw: &str) -> Result<Self, DashboardError> {
        match raw {
            "pass" => Ok(Self::Pass),
            "fail" => Ok(Self::Fail),
            "error" => Ok(Self::Error),
            "skip" => Ok(Self::Skip),
            other => Err(DashboardError::InvalidField {
                field: "status",
                reason: format!("unsupported status {other:?}"),
            }),
        }
    }

    pub fn is_tested(self) -> bool {
        !matches!(self, Self::Skip)
    }

    pub fn is_passing(self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn is_regression_from(self, previous: Self) -> bool {
        previous.is_passing() && matches!(self, Self::Fail | Self::Error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureResult {
    pub fixture_id: String,
    pub api_family: String,
    pub band: String,
    pub status: FixtureStatus,
}

impl FixtureResult {
    pub fn new(
        fixture_id: impl Into<String>,
        api_family: impl Into<String>,
        band: impl Into<String>,
        status: FixtureStatus,
    ) -> Result<Self, DashboardError> {
        let fixture_id = fixture_id.into();
        let api_family = api_family.into();
        let band = band.into();

        require_non_empty("fixture_id", &fixture_id)?;
        require_non_empty("api_family", &api_family)?;
        require_non_empty("band", &band)?;

        Ok(Self {
            fixture_id,
            api_family,
            band,
            status,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityDashboard {
    pub schema_version: String,
    pub timestamp: String,
    pub overall: OverallSummary,
    pub by_family: Vec<FamilySummary>,
    pub by_band: Vec<BandSummary>,
    pub regressions: Vec<RegressionSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverallSummary {
    pub total_behaviors: u64,
    pub tested: u64,
    pub passing: u64,
    pub failing: u64,
    pub pass_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FamilySummary {
    pub family: String,
    pub total_behaviors: u64,
    pub tested: u64,
    pub passing: u64,
    pub failing: u64,
    pub pass_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BandSummary {
    pub band: String,
    pub total_fixtures: u64,
    pub passing: u64,
    pub failing: u64,
    pub pass_rate: f64,
    pub target: f64,
    pub meets_target: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionSummary {
    pub fixture_id: String,
    pub band: String,
    pub previously: String,
    pub now: String,
    pub first_failed: String,
}

#[derive(Default)]
struct Accumulator {
    total_behaviors: u64,
    tested: u64,
    passing: u64,
    failing: u64,
}

impl Accumulator {
    fn record(&mut self, status: FixtureStatus) {
        self.total_behaviors = self.total_behaviors.saturating_add(1);
        if status.is_tested() {
            self.tested = self.tested.saturating_add(1);
            if status.is_passing() {
                self.passing = self.passing.saturating_add(1);
            } else {
                self.failing = self.failing.saturating_add(1);
            }
        }
    }
}

pub fn build_dashboard(
    current: &[FixtureResult],
    previous: &[FixtureResult],
) -> Result<CompatibilityDashboard, DashboardError> {
    build_dashboard_at(current, previous, Utc::now().to_rfc3339())
}

pub fn build_dashboard_at(
    current: &[FixtureResult],
    previous: &[FixtureResult],
    timestamp: impl Into<String>,
) -> Result<CompatibilityDashboard, DashboardError> {
    if current.is_empty() {
        return Err(DashboardError::EmptyInput);
    }

    let timestamp = timestamp.into();
    require_non_empty("timestamp", &timestamp)?;
    reject_duplicate_ids(current)?;

    let mut overall = Accumulator::default();
    let mut families: BTreeMap<String, Accumulator> = BTreeMap::new();
    let mut bands: BTreeMap<String, Accumulator> = BTreeMap::new();

    for fixture in current {
        overall.record(fixture.status);
        families
            .entry(fixture.api_family.clone())
            .or_default()
            .record(fixture.status);
        bands
            .entry(fixture.band.clone())
            .or_default()
            .record(fixture.status);
    }

    let previous_by_id: BTreeMap<&str, FixtureStatus> = previous
        .iter()
        .map(|fixture| (fixture.fixture_id.as_str(), fixture.status))
        .collect();
    let regressions = current
        .iter()
        .filter_map(|fixture| {
            previous_by_id
                .get(fixture.fixture_id.as_str())
                .copied()
                .filter(|previous_status| fixture.status.is_regression_from(*previous_status))
                .map(|previous_status| RegressionSummary {
                    fixture_id: fixture.fixture_id.clone(),
                    band: fixture.band.clone(),
                    previously: status_label(previous_status).to_string(),
                    now: status_label(fixture.status).to_string(),
                    first_failed: timestamp.clone(),
                })
        })
        .collect();

    Ok(CompatibilityDashboard {
        schema_version: DASHBOARD_SCHEMA_VERSION.to_string(),
        timestamp,
        overall: OverallSummary {
            total_behaviors: overall.total_behaviors,
            tested: overall.tested,
            passing: overall.passing,
            failing: overall.failing,
            pass_rate: pass_rate(overall.passing, overall.tested)?,
        },
        by_family: families
            .into_iter()
            .map(|(family, stats)| {
                Ok(FamilySummary {
                    family,
                    total_behaviors: stats.total_behaviors,
                    tested: stats.tested,
                    passing: stats.passing,
                    failing: stats.failing,
                    pass_rate: pass_rate(stats.passing, stats.tested)?,
                })
            })
            .collect::<Result<Vec<_>, DashboardError>>()?,
        by_band: bands
            .into_iter()
            .map(|(band, stats)| {
                let rate = pass_rate(stats.passing, stats.tested)?;
                let target = band_target(&band);
                Ok(BandSummary {
                    band,
                    total_fixtures: stats.total_behaviors,
                    passing: stats.passing,
                    failing: stats.failing,
                    pass_rate: rate,
                    target,
                    meets_target: rate >= target,
                })
            })
            .collect::<Result<Vec<_>, DashboardError>>()?,
        regressions,
    })
}

pub fn fixtures_from_corpus_report(
    report: &serde_json::Value,
) -> Result<Vec<FixtureResult>, DashboardError> {
    let rows = report
        .get("per_test_results")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            DashboardError::JsonField(
                "compatibility report per_test_results must be an array".into(),
            )
        })?;

    let mut fixtures = Vec::with_capacity(rows.len());
    for row in rows {
        let fixture_id = required_str(row, "test_id")?;
        let api_family = required_str(row, "api_family")?;
        let band = required_str(row, "band")?;
        let status = FixtureStatus::parse(required_str(row, "status")?)?;
        fixtures.push(FixtureResult::new(fixture_id, api_family, band, status)?);
    }
    reject_duplicate_ids(&fixtures)?;
    Ok(fixtures)
}

pub fn dashboard_from_corpus_report(
    report: &serde_json::Value,
    previous: &[FixtureResult],
    timestamp: impl Into<String>,
) -> Result<CompatibilityDashboard, DashboardError> {
    let fixtures = fixtures_from_corpus_report(report)?;
    build_dashboard_at(&fixtures, previous, timestamp)
}

pub fn to_json_value(
    dashboard: &CompatibilityDashboard,
) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(dashboard)
}

fn reject_duplicate_ids(fixtures: &[FixtureResult]) -> Result<(), DashboardError> {
    let mut seen = BTreeSet::new();
    for fixture in fixtures {
        if !seen.insert(fixture.fixture_id.as_str()) {
            return Err(DashboardError::DuplicateFixtureId(
                fixture.fixture_id.clone(),
            ));
        }
    }
    Ok(())
}

fn pass_rate(passing: u64, tested: u64) -> Result<f64, DashboardError> {
    if tested == 0 {
        return Ok(0.0);
    }
    let passing = u32::try_from(passing).map_err(|_| DashboardError::CountTooLarge("passing"))?;
    let tested = u32::try_from(tested).map_err(|_| DashboardError::CountTooLarge("tested"))?;
    Ok(f64::from(passing) / f64::from(tested))
}

fn band_target(band: &str) -> f64 {
    match band {
        "core" => 1.0,
        "high-value" => 0.95,
        "edge" => 0.90,
        "unsafe" => 0.0,
        _ => 0.80,
    }
}

fn required_str<'a>(
    row: &'a serde_json::Value,
    field: &'static str,
) -> Result<&'a str, DashboardError> {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| DashboardError::JsonField(format!("per-test row missing {field}")))
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), DashboardError> {
    if value.trim().is_empty() {
        Err(DashboardError::InvalidField {
            field,
            reason: "value must be non-empty".to_string(),
        })
    } else {
        Ok(())
    }
}

fn status_label(status: FixtureStatus) -> &'static str {
    match status {
        FixtureStatus::Pass => "pass",
        FixtureStatus::Fail => "fail",
        FixtureStatus::Error => "error",
        FixtureStatus::Skip => "skip",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "2026-05-13T04:50:00Z";

    fn fixture(id: &str, family: &str, band: &str, status: FixtureStatus) -> FixtureResult {
        FixtureResult::new(id, family, band, status).expect("valid fixture")
    }

    #[test]
    fn dashboard_aggregates_by_family_and_band() {
        let current = vec![
            fixture("fs-1", "fs", "core", FixtureStatus::Pass),
            fixture("fs-2", "fs", "core", FixtureStatus::Fail),
            fixture("http-1", "http", "high-value", FixtureStatus::Pass),
            fixture("http-2", "http", "high-value", FixtureStatus::Skip),
        ];

        let dashboard = build_dashboard_at(&current, &[], TS).expect("dashboard");

        assert_eq!(dashboard.schema_version, "1.0");
        assert_eq!(dashboard.overall.total_behaviors, 4);
        assert_eq!(dashboard.overall.tested, 3);
        assert_eq!(dashboard.overall.passing, 2);
        assert_eq!(dashboard.overall.failing, 1);
        assert_eq!(dashboard.by_family.len(), 2);
        assert_eq!(dashboard.by_family[0].family, "fs");
        assert_eq!(dashboard.by_family[0].tested, 2);
        assert_eq!(dashboard.by_family[1].family, "http");
        assert_eq!(dashboard.by_family[1].tested, 1);
        assert_eq!(dashboard.by_band[0].band, "core");
        assert!(!dashboard.by_band[0].meets_target);
        assert_eq!(dashboard.by_band[1].band, "high-value");
        assert!(dashboard.by_band[1].meets_target);
    }

    #[test]
    fn dashboard_detects_new_failures_from_previous_passes() {
        let previous = vec![
            fixture("stream-1", "stream", "high-value", FixtureStatus::Pass),
            fixture("stream-2", "stream", "high-value", FixtureStatus::Pass),
        ];
        let current = vec![
            fixture("stream-1", "stream", "high-value", FixtureStatus::Error),
            fixture("stream-2", "stream", "high-value", FixtureStatus::Pass),
        ];

        let dashboard = build_dashboard_at(&current, &previous, TS).expect("dashboard");

        assert_eq!(dashboard.regressions.len(), 1);
        assert_eq!(dashboard.regressions[0].fixture_id, "stream-1");
        assert_eq!(dashboard.regressions[0].previously, "pass");
        assert_eq!(dashboard.regressions[0].now, "error");
        assert_eq!(dashboard.regressions[0].first_failed, TS);
    }

    #[test]
    fn dashboard_output_is_schema_compatible() {
        let current = vec![fixture("path-1", "path", "edge", FixtureStatus::Pass)];
        let dashboard = build_dashboard_at(&current, &[], TS).expect("dashboard");
        let value = to_json_value(&dashboard).expect("json");
        let object = value.as_object().expect("object");

        assert_eq!(
            object.get("schema_version").and_then(|v| v.as_str()),
            Some("1.0")
        );
        assert!(object.contains_key("overall"));
        assert!(object.contains_key("by_family"));
        assert!(object.contains_key("by_band"));
        assert!(object.contains_key("regressions"));
        assert_eq!(object.len(), 6);
    }

    #[test]
    fn duplicate_fixture_ids_fail_closed() {
        let current = vec![
            fixture("dup", "fs", "core", FixtureStatus::Pass),
            fixture("dup", "path", "core", FixtureStatus::Pass),
        ];

        assert!(matches!(
            build_dashboard_at(&current, &[], TS),
            Err(DashboardError::DuplicateFixtureId(id)) if id == "dup"
        ));
    }

    #[test]
    fn corpus_report_rows_convert_to_dashboard_fixtures() {
        let report = serde_json::json!({
            "per_test_results": [
                {"test_id": "tc::fs::read", "api_family": "fs", "band": "core", "status": "pass"},
                {"test_id": "tc::stream::pipe", "api_family": "stream", "band": "high-value", "status": "fail"}
            ]
        });

        let fixtures = fixtures_from_corpus_report(&report).expect("fixtures");
        let dashboard = build_dashboard_at(&fixtures, &[], TS).expect("dashboard");

        assert_eq!(fixtures.len(), 2);
        assert_eq!(dashboard.overall.passing, 1);
        assert_eq!(dashboard.overall.failing, 1);
        assert_eq!(dashboard.by_family[1].family, "stream");
    }

    #[test]
    fn invalid_corpus_status_is_rejected() {
        let report = serde_json::json!({
            "per_test_results": [
                {"test_id": "tc::fs::read", "api_family": "fs", "band": "core", "status": "unknown"}
            ]
        });

        assert!(matches!(
            fixtures_from_corpus_report(&report),
            Err(DashboardError::InvalidField { field, .. }) if field == "status"
        ));
    }
}
