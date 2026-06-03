use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_EVENT_CODES: &[&str] = &["CCG-001", "CCG-002", "CCG-003", "CCG-004"];
const REQUIRED_RUNTIMES: &[&str] = &["node", "bun", "franken-node"];
const REQUIRED_STATUS_VALUES: &[&str] = &["pass", "fail", "error", "skip"];

#[test]
fn stream_corpus_manifest_is_fixture_backed_and_reported() -> TestResult {
    let corpus_root = corpus_root();
    let manifest = load_stream_manifest()?;
    let cases = stream_cases(&manifest)?;

    require(
        cases.len() == 20,
        "stream corpus must contain 20 fixture cases",
    )?;
    require(
        manifest
            .get("lockstep")
            .and_then(|lockstep| lockstep.get("harness"))
            .and_then(Value::as_str)
            .is_some_and(|command| command.contains("verify lockstep")),
        "stream corpus manifest must declare lockstep harness execution",
    )?;

    let mut manifest_ids = BTreeSet::new();
    for case in cases {
        let case_id = case
            .get("id")
            .and_then(Value::as_str)
            .ok_or("stream fixture case id must be a string")?;
        let fixture_file = case
            .get("file")
            .and_then(Value::as_str)
            .ok_or("stream fixture case file must be a string")?;
        require_local_mjs_fixture(fixture_file)?;
        let fixture_path = corpus_root.join(fixture_file);
        require(
            fixture_path.is_file(),
            format!("stream fixture missing: {}", fixture_path.display()),
        )?;
        let fixture_source = fs::read_to_string(&fixture_path)?;
        require(
            fixture_source.contains(case_id),
            format!("stream fixture {} must emit its manifest id", fixture_file),
        )?;
        require(
            manifest_ids.insert(case_id.to_string()),
            format!("duplicate stream fixture id: {case_id}"),
        )?;
    }

    let report = load_compatibility_report()?;
    let stream_family = stream_family(&report)?;
    require(
        stream_family.get("total").and_then(Value::as_u64) == Some(65),
        "stream family total must include the 20 fixture-backed stream cases",
    )?;

    let reported_ids: BTreeSet<String> = report
        .get("per_test_results")
        .and_then(Value::as_array)
        .ok_or("compatibility report per_test_results must be an array")?
        .iter()
        .filter_map(|row| row.get("test_id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    for case_id in manifest_ids {
        require(
            reported_ids.contains(&case_id),
            format!("compatibility report missing stream case {case_id}"),
        )?;
    }

    Ok(())
}

#[test]
fn stream_manifest_cases_have_complete_metadata() -> TestResult {
    let manifest = load_stream_manifest()?;
    let cases = stream_cases(&manifest)?;
    let mut files = BTreeSet::new();

    for case in cases {
        let case_id = required_str(case, "id", "stream fixture id")?;
        require(
            case_id.starts_with("tc::stream::"),
            format!("stream fixture id must use stream namespace: {case_id}"),
        )?;
        let fixture_file = required_str(case, "file", "stream fixture file")?;
        require_local_mjs_fixture(fixture_file)?;
        require(
            files.insert(fixture_file.to_string()),
            format!("duplicate stream fixture file: {fixture_file}"),
        )?;
        require(
            required_str(case, "api", "stream fixture api")?.starts_with("stream"),
            format!("stream fixture {case_id} must name a stream API"),
        )?;
        require(
            !required_str(case, "requirement", "stream fixture requirement")?
                .trim()
                .is_empty(),
            format!("stream fixture {case_id} must document its requirement"),
        )?;
        require(
            required_str(case, "band", "stream fixture band")? == "high-value",
            format!("stream fixture {case_id} must stay in the high-value band"),
        )?;
        require(
            required_str(case, "risk_band", "stream fixture risk band")? == "high",
            format!("stream fixture {case_id} must stay in the high risk band"),
        )?;
    }

    Ok(())
}

#[test]
fn stream_lockstep_manifest_names_all_required_runtimes() -> TestResult {
    let manifest = load_stream_manifest()?;
    let lockstep = manifest
        .get("lockstep")
        .and_then(Value::as_object)
        .ok_or("stream manifest lockstep must be an object")?;
    let runtimes = lockstep
        .get("runtimes")
        .and_then(Value::as_array)
        .ok_or("stream lockstep runtimes must be an array")?;
    let runtime_names: BTreeSet<&str> = runtimes.iter().filter_map(Value::as_str).collect();

    for runtime in REQUIRED_RUNTIMES {
        require(
            runtime_names.contains(runtime),
            format!("stream lockstep runtimes missing {runtime}"),
        )?;
    }

    let harness = lockstep
        .get("harness")
        .and_then(Value::as_str)
        .ok_or("stream lockstep harness must be a string")?;
    require(
        harness.contains("verify lockstep")
            && harness.contains("compat_corpus/stream")
            && harness.contains("node,bun,franken-node"),
        "stream lockstep harness must execute the stream corpus across declared runtimes",
    )?;

    Ok(())
}

#[test]
fn compatibility_report_totals_and_thresholds_match_gate_contract() -> TestResult {
    let report = load_compatibility_report()?;
    let totals = report
        .get("totals")
        .and_then(Value::as_object)
        .ok_or("compatibility report totals must be an object")?;
    let per_tests = per_test_results(&report)?;

    let total = required_u64(totals, "total_test_cases", "total test cases")?;
    let passed = required_u64(totals, "passed_test_cases", "passed test cases")?;
    let failed = required_u64(totals, "failed_test_cases", "failed test cases")?;
    let errored = required_u64(totals, "errored_test_cases", "errored test cases")?;
    let skipped = required_u64(totals, "skipped_test_cases", "skipped test cases")?;
    require(
        total >= 500,
        "compatibility corpus must keep at least 500 test cases",
    )?;
    require(
        total == passed + failed + errored + skipped,
        "compatibility corpus totals must partition cleanly",
    )?;
    require(
        usize_to_u64(per_tests.len(), "per-test result count")? == total,
        "per-test result count must match total_test_cases",
    )?;
    require(
        approx_eq(
            basis_points_to_percent(pass_rate_basis_points(passed, total)?)?,
            required_f64(totals, "overall_pass_rate_pct", "overall pass rate")?,
        ),
        "reported overall pass rate must match recomputed rate within 0.01%",
    )?;

    let thresholds = report
        .get("thresholds")
        .and_then(Value::as_object)
        .ok_or("compatibility report thresholds must be an object")?;
    require(
        approx_eq(
            required_f64(thresholds, "overall_pass_rate_min_pct", "overall threshold")?,
            95.0,
        ),
        "overall compatibility threshold must be 95%",
    )?;
    require(
        approx_eq(
            required_f64(
                thresholds,
                "per_family_pass_rate_min_pct",
                "family threshold",
            )?,
            80.0,
        ),
        "per-family compatibility floor must be 80%",
    )?;
    let band_thresholds = thresholds
        .get("band_pass_rate_min_pct")
        .and_then(Value::as_object)
        .ok_or("band pass-rate thresholds must be an object")?;
    for (band, expected) in [("core", 99.0), ("high-value", 95.0), ("edge", 90.0)] {
        require(
            approx_eq(
                required_f64(band_thresholds, band, "band threshold")?,
                expected,
            ),
            format!("band threshold mismatch for {band}"),
        )?;
    }

    Ok(())
}

#[test]
fn stream_family_report_matches_per_test_rows() -> TestResult {
    let report = load_compatibility_report()?;
    let stream_family = stream_family(&report)?;
    let per_tests = per_test_results(&report)?;
    let stream_rows: Vec<&Value> = per_tests
        .iter()
        .filter(|row| row.get("api_family").and_then(Value::as_str) == Some("stream"))
        .collect();
    let stream_passed = stream_rows
        .iter()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("pass"))
        .count();
    let stream_total = usize_to_u64(stream_rows.len(), "stream row count")?;
    let stream_passed = usize_to_u64(stream_passed, "stream passed row count")?;

    require(
        stream_total
            == stream_family
                .get("total")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        "stream family total must match per-test stream rows",
    )?;
    require(
        stream_passed
            == stream_family
                .get("passed")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        "stream family passed count must match per-test stream rows",
    )?;
    require(
        approx_eq(
            basis_points_to_percent(pass_rate_basis_points(stream_passed, stream_total)?)?,
            stream_family
                .get("pass_rate_pct")
                .and_then(Value::as_f64)
                .ok_or("stream pass_rate_pct must be numeric")?,
        ),
        "stream family pass rate must match recomputed per-test rows within 0.01%",
    )?;

    for row in stream_rows {
        let status = row
            .get("status")
            .and_then(Value::as_str)
            .ok_or("stream row status must be a string")?;
        require(
            REQUIRED_STATUS_VALUES.contains(&status),
            format!("stream row has invalid status {status}"),
        )?;
        require(
            row.get("band").and_then(Value::as_str) == Some("high-value"),
            "stream row band must be high-value",
        )?;
        require(
            row.get("risk_band").and_then(Value::as_str) == Some("high"),
            "stream row risk band must be high",
        )?;
    }

    Ok(())
}

#[test]
fn stream_fixture_cases_are_reported_as_passing_results() -> TestResult {
    let manifest = load_stream_manifest()?;
    let report = load_compatibility_report()?;
    let mut rows_by_id = BTreeMap::new();
    for row in per_test_results(&report)? {
        if let Some(test_id) = row.get("test_id").and_then(Value::as_str) {
            rows_by_id.insert(test_id, row);
        }
    }

    for case in stream_cases(&manifest)? {
        let case_id = required_str(case, "id", "stream fixture id")?;
        let row = rows_by_id
            .get(case_id)
            .ok_or_else(|| format!("compatibility report missing stream fixture case {case_id}"))?;
        require(
            row.get("status").and_then(Value::as_str) == Some("pass"),
            format!("stream fixture case {case_id} must be reported as passing"),
        )?;
        require(
            row.get("api_family").and_then(Value::as_str) == Some("stream")
                && row.get("band").and_then(Value::as_str) == Some("high-value")
                && row.get("risk_band").and_then(Value::as_str) == Some("high"),
            format!("stream fixture case {case_id} must retain stream/high-value/high tags"),
        )?;
    }

    Ok(())
}

#[test]
fn compatibility_gate_ratchet_ci_and_event_codes_are_release_safe() -> TestResult {
    let report = load_compatibility_report()?;
    let totals = report
        .get("totals")
        .and_then(Value::as_object)
        .ok_or("compatibility report totals must be an object")?;
    let current_rate = required_f64(totals, "overall_pass_rate_pct", "overall pass rate")?;
    let previous_rate = report
        .get("previous_release")
        .and_then(|previous| previous.get("overall_pass_rate_pct"))
        .and_then(Value::as_f64)
        .ok_or("previous release pass rate must be numeric")?;
    require(
        current_rate >= previous_rate,
        "compatibility corpus ratchet must reject pass-rate regression",
    )?;

    let ci_gate = report
        .get("ci_gate")
        .and_then(Value::as_object)
        .ok_or("compatibility report ci_gate must be an object")?;
    require(
        ci_gate.get("threshold_met").and_then(Value::as_bool) == Some(true),
        "compatibility CI gate must record threshold_met=true",
    )?;
    require(
        ci_gate.get("release_blocked").and_then(Value::as_bool) == Some(false),
        "compatibility CI gate must not block release when thresholds pass",
    )?;
    require(
        ci_gate.get("regression_detected").and_then(Value::as_bool) == Some(false),
        "compatibility CI gate must not record a regression",
    )?;

    let event_codes: BTreeSet<&str> = report
        .get("event_codes")
        .and_then(Value::as_array)
        .ok_or("compatibility report event_codes must be an array")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for event_code in REQUIRED_EVENT_CODES {
        require(
            event_codes.contains(event_code),
            format!("compatibility report missing event code {event_code}"),
        )?;
    }

    Ok(())
}

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_root() -> std::path::PathBuf {
    crate_root().join("tests/fixtures/compat_corpus/stream")
}

fn load_stream_manifest() -> TestResult<Value> {
    let manifest_path = corpus_root().join("manifest.json");
    Ok(serde_json::from_str(&fs::read_to_string(&manifest_path)?)?)
}

fn load_compatibility_report() -> TestResult<Value> {
    let report_path = crate_root()
        .join("../..")
        .join("artifacts/13/compatibility_corpus_results.json");
    Ok(serde_json::from_str(&fs::read_to_string(&report_path)?)?)
}

fn stream_cases(manifest: &Value) -> TestResult<&[Value]> {
    manifest
        .get("cases")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "stream manifest cases must be an array".into())
}

fn per_test_results(report: &Value) -> TestResult<&[Value]> {
    report
        .get("per_test_results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "compatibility report per_test_results must be an array".into())
}

fn stream_family(report: &Value) -> TestResult<&Value> {
    report
        .get("api_families")
        .and_then(Value::as_array)
        .and_then(|families| {
            families
                .iter()
                .find(|family| family.get("family").and_then(Value::as_str) == Some("stream"))
        })
        .ok_or_else(|| "compatibility report must contain stream family".into())
}

fn required_str<'a>(value: &'a Value, field: &str, label: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} must include string field {field}").into())
}

fn required_u64(
    object: &serde_json::Map<String, Value>,
    field: &str,
    label: &str,
) -> TestResult<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label} must include numeric field {field}").into())
}

fn required_f64(
    object: &serde_json::Map<String, Value>,
    field: &str,
    label: &str,
) -> TestResult<f64> {
    object
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("{label} must include numeric field {field}").into())
}

fn require_local_mjs_fixture(fixture_file: &str) -> TestResult {
    require(
        fixture_file.ends_with(".mjs")
            && !fixture_file.contains('/')
            && !fixture_file.contains('\\')
            && !fixture_file.contains(".."),
        format!("stream fixture file must be a local .mjs file: {fixture_file}"),
    )
}

fn pass_rate_basis_points(passed: u64, total: u64) -> TestResult<u64> {
    let Some(nonzero_total) = std::num::NonZeroU64::new(total) else {
        return Ok(0);
    };
    let total = nonzero_total.get();
    let numerator = passed
        .checked_mul(10_000)
        .and_then(|value| value.checked_add(total / 2))
        .ok_or("pass-rate numerator overflow")?;
    Ok(numerator / total)
}

fn basis_points_to_percent(basis_points: u64) -> TestResult<f64> {
    Ok(f64::from(u32::try_from(basis_points)?) / 100.0)
}

fn usize_to_u64(value: usize, label: &str) -> TestResult<u64> {
    u64::try_from(value).map_err(|_| format!("{label} does not fit in u64").into())
}

fn approx_eq(left: f64, right: f64) -> bool {
    (left - right).abs() < 0.000_001
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
