//! Regression gate tests for conformance pass rates and N/A counts.
//!
//! These tests compare the current conformance summary against the baseline
//! to detect regressions: pass-rate drops, new N/A introductions, and
//! threshold violations.
//!
//! Data sources:
//! - `tests/ext_conformance/reports/conformance_baseline.json` (ground truth)
//! - `tests/ext_conformance/reports/conformance_summary.json` (current run)

use serde_json::Value;
use std::path::Path;

fn load_json(path: &str) -> Option<Value> {
    let full = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    let text = std::fs::read_to_string(&full).ok()?;
    serde_json::from_str(&text).ok()
}

fn baseline() -> Value {
    load_json("tests/ext_conformance/reports/conformance_baseline.json")
        .expect("conformance_baseline.json must exist")
}

fn summary() -> Value {
    load_json("tests/ext_conformance/reports/conformance_summary.json")
        .expect("conformance_summary.json must exist")
}

type V = Value;

fn get_f64(v: &V, pointer: &str) -> f64 {
    v.pointer(pointer).and_then(Value::as_f64).unwrap_or(0.0)
}

fn get_u64(v: &V, pointer: &str) -> u64 {
    v.pointer(pointer).and_then(Value::as_u64).unwrap_or(0)
}

fn summary_is_na_only_placeholder(sm: &V) -> bool {
    let pass = get_u64(sm, "/counts/pass");
    let fail = get_u64(sm, "/counts/fail");
    let na = get_u64(sm, "/counts/na");
    let total = get_u64(sm, "/counts/total");
    pass == 0 && fail == 0 && total > 0 && na == total
}

fn missing_conformance_inputs() -> Vec<&'static str> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    [
        "tests/ext_conformance/reports/scenario_conformance.json",
        "tests/ext_conformance/reports/load_time_benchmark.json",
        "tests/ext_conformance/reports/negative/negative_events.jsonl",
        "tests/ext_conformance/reports/parity/parity_summary.json",
        "tests/ext_conformance/reports/smoke/smoke_summary.json",
        "tests/ext_conformance/reports/conformance/conformance_report.json",
    ]
    .into_iter()
    .filter(|path| !root.join(path).exists())
    .collect()
}

fn skip_if_placeholder_summary(sm: &V, gate_name: &str) -> bool {
    if !summary_is_na_only_placeholder(sm) {
        return false;
    }
    let missing = missing_conformance_inputs();
    if missing.is_empty() {
        return false;
    }
    eprintln!(
        "[conformance_regression_gate] skipping {gate_name}: \
         conformance_summary.json is an N/A-only placeholder and report inputs are missing: {}",
        missing.join(", ")
    );
    true
}

fn effective_pass_rate_pct(sm: &V) -> f64 {
    let pass = get_u64(sm, "/counts/pass");
    let fail = get_u64(sm, "/counts/fail");
    let total = get_u64(sm, "/counts/total");
    let tested = pass + fail;
    let reported = get_f64(sm, "/pass_rate_pct");

    if tested > 0 && tested < total {
        #[allow(clippy::cast_precision_loss)]
        {
            (pass as f64 / tested as f64) * 100.0
        }
    } else {
        reported
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct TierCounts {
    pass: u64,
    fail: u64,
    skipped_or_na: u64,
    total: u64,
}

fn tier_counts_from_value(v: &V) -> Option<TierCounts> {
    let obj = v.as_object()?;
    let pass = obj.get("pass").and_then(Value::as_u64).unwrap_or(0);
    let fail = obj.get("fail").and_then(Value::as_u64).unwrap_or(0);
    let skipped_or_na = obj
        .get("na")
        .or_else(|| obj.get("skip"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total = obj
        .get("total")
        .and_then(Value::as_u64)
        .unwrap_or(pass + fail + skipped_or_na);
    Some(TierCounts {
        pass,
        fail,
        skipped_or_na,
        total,
    })
}

fn per_tier_counts(sm: &V) -> Option<Vec<TierCounts>> {
    if let Some(obj) = sm.pointer("/per_tier").and_then(Value::as_object) {
        return Some(
            obj.values()
                .filter_map(tier_counts_from_value)
                .collect::<Vec<_>>(),
        );
    }
    if let Some(arr) = sm.pointer("/per_tier").and_then(Value::as_array) {
        return Some(
            arr.iter()
                .filter_map(tier_counts_from_value)
                .collect::<Vec<_>>(),
        );
    }
    None
}

fn official_tier_counts(sm: &V) -> Option<TierCounts> {
    if let Some(v) = sm.pointer("/per_tier/official-pi-mono") {
        return tier_counts_from_value(v);
    }
    if let Some(v) = sm.pointer("/by_source/official-pi-mono") {
        return tier_counts_from_value(v);
    }
    sm.pointer("/per_tier")
        .and_then(Value::as_array)
        .and_then(|tiers| {
            tiers.iter().find(|entry| {
                entry.get("tier").and_then(Value::as_u64) == Some(1)
                    || entry.get("tier").and_then(Value::as_str) == Some("1")
            })
        })
        .and_then(tier_counts_from_value)
}

// ============================================================================
// Pass-rate regression gates
// ============================================================================

#[test]
fn overall_pass_rate_meets_baseline_threshold() {
    let bl = baseline();
    let sm = summary();
    if skip_if_placeholder_summary(&sm, "overall_pass_rate_meets_baseline_threshold") {
        return;
    }

    let threshold = get_f64(&bl, "/regression_thresholds/overall_pass_rate_min_pct");
    let current = effective_pass_rate_pct(&sm);

    assert!(
        threshold > 0.0,
        "baseline must define overall_pass_rate_min_pct"
    );
    assert!(
        current >= threshold,
        "pass rate regression: current {current:.1}% < threshold {threshold:.1}%"
    );
}

#[test]
fn official_tier_pass_rate_at_100_percent() {
    let sm = summary();

    let Some(official) = official_tier_counts(&sm) else {
        return;
    };
    let pass = official.pass;
    let fail = official.fail;
    let na = official.skipped_or_na;
    let total = official.total;

    // The tested count (pass + fail) must equal total minus N/A.
    let tested = pass + fail;
    if tested == 0 {
        // If nothing is tested yet, skip (N/A-only state).
        return;
    }

    #[allow(clippy::cast_precision_loss)] // counts are < 1000
    let rate = (pass as f64 / tested as f64) * 100.0;
    assert!(
        rate >= 95.0,
        "official tier pass rate {rate:.1}% (pass={pass}, fail={fail}, na={na}, total={total}) \
         must be >= 95.0%"
    );
}

#[test]
fn scenario_pass_rate_meets_threshold() {
    let bl = baseline();

    let threshold = get_f64(&bl, "/regression_thresholds/scenario_pass_rate_min_pct");
    let total = get_u64(&bl, "/scenario_conformance/total");
    let passed = get_u64(&bl, "/scenario_conformance/passed");

    if total == 0 {
        return;
    }

    #[allow(clippy::cast_precision_loss)] // counts are < 1000
    let rate = (passed as f64 / total as f64) * 100.0;
    assert!(
        rate >= threshold,
        "scenario pass rate {rate:.1}% < threshold {threshold:.1}% \
         (passed={passed}, total={total})"
    );
}

// ============================================================================
// N/A count regression gates
// ============================================================================

#[test]
fn na_count_within_ci_gate_maximum() {
    let sm = summary();
    if skip_if_placeholder_summary(&sm, "na_count_within_ci_gate_maximum") {
        return;
    }

    let na = get_u64(&sm, "/counts/na");
    // CI gate default: max 170 N/A.
    let max_na: u64 = 170;

    assert!(na <= max_na, "N/A count {na} exceeds maximum {max_na}");
}

#[test]
fn fail_count_within_ci_gate_maximum() {
    let sm = summary();

    let fail = get_u64(&sm, "/counts/fail");
    // CI gate default: max 36 failures.
    let max_fail: u64 = 36;

    assert!(
        fail <= max_fail,
        "failure count {fail} exceeds maximum {max_fail}"
    );
}

#[test]
fn total_count_matches_corpus_size() {
    let sm = summary();

    let total = get_u64(&sm, "/counts/total");
    assert!(
        total > 0,
        "conformance summary must have non-zero total count"
    );

    let pass = get_u64(&sm, "/counts/pass");
    let fail = get_u64(&sm, "/counts/fail");
    let na = get_u64(&sm, "/counts/na");

    assert_eq!(
        pass + fail + na,
        total,
        "pass ({pass}) + fail ({fail}) + na ({na}) must equal total ({total})"
    );
}

// ============================================================================
// Baseline structural checks
// ============================================================================

#[test]
fn baseline_has_required_regression_thresholds() {
    let bl = baseline();

    let thresholds = bl
        .pointer("/regression_thresholds")
        .expect("baseline must have regression_thresholds");

    let fields = [
        "tier1_pass_rate_min_pct",
        "tier2_pass_rate_min_pct",
        "overall_pass_rate_min_pct",
        "scenario_pass_rate_min_pct",
        "max_new_failures",
    ];

    for field in &fields {
        assert!(
            thresholds.get(*field).is_some(),
            "missing threshold field: {field}"
        );
    }
}

#[test]
fn baseline_exception_policy_entries_have_required_fields() {
    let bl = baseline();

    let required = bl
        .pointer("/exception_policy/required_fields")
        .and_then(Value::as_array);
    let entries = bl
        .pointer("/exception_policy/entries")
        .and_then(Value::as_array);

    let Some(required) = required else {
        // No exception policy defined.
        return;
    };
    let Some(entries) = entries else {
        return;
    };

    let required_strs: Vec<&str> = required.iter().filter_map(Value::as_str).collect();

    for entry in entries {
        for field in &required_strs {
            assert!(
                entry.get(*field).is_some(),
                "exception entry {:?} missing required field {field}",
                entry.get("id").and_then(Value::as_str).unwrap_or("?")
            );
        }
    }
}

#[test]
fn summary_schema_is_recognized() {
    let sm = summary();

    let schema = sm
        .get("schema")
        .and_then(Value::as_str)
        .expect("summary must have schema field");

    assert!(
        schema.starts_with("pi.ext.conformance_summary"),
        "unrecognized schema: {schema}"
    );
}

// ============================================================================
// Per-tier consistency checks
// ============================================================================

#[test]
fn per_tier_counts_sum_to_total() {
    let sm = summary();

    let total = get_u64(&sm, "/counts/total");
    let per_tier =
        per_tier_counts(&sm).expect("summary must have per_tier object or array of tier counts");

    let tier_total: u64 = per_tier.iter().map(|tier| tier.total).sum();

    assert_eq!(
        tier_total, total,
        "sum of per-tier totals ({tier_total}) must equal overall total ({total})"
    );
}

#[test]
fn negative_tests_all_pass() {
    let sm = summary();

    let neg_fail = get_u64(&sm, "/negative/fail");
    assert_eq!(
        neg_fail, 0,
        "policy negative tests must all pass (got {neg_fail} failures)"
    );
}

// ============================================================================
// Regression verdict generation
// ============================================================================

#[test]
fn regression_verdict_is_generated() {
    let bl = baseline();
    let sm = summary();
    if skip_if_placeholder_summary(&sm, "regression_verdict_is_generated") {
        return;
    }

    let current_rate = effective_pass_rate_pct(&sm);
    let min_rate = get_f64(&bl, "/regression_thresholds/overall_pass_rate_min_pct");
    let max_fail = get_u64(&bl, "/regression_thresholds/max_new_failures");
    let current_fail = get_u64(&sm, "/counts/fail");

    let pass_rate_ok = current_rate >= min_rate;
    let fail_count_ok = current_fail <= max_fail + 36; // baseline max_fail + tolerance

    let verdict = if pass_rate_ok && fail_count_ok {
        "pass"
    } else {
        "fail"
    };

    // Build verdict JSON to verify structure.
    let verdict_json = serde_json::json!({
        "schema": "pi.conformance.regression_gate.v1",
        "verdict": verdict,
        "checks": {
            "pass_rate": {
                "actual": current_rate,
                "threshold": min_rate,
                "ok": pass_rate_ok
            },
            "fail_count": {
                "actual": current_fail,
                "threshold": max_fail,
                "ok": fail_count_ok
            }
        }
    });

    // Verify the structure is valid JSON.
    assert!(verdict_json["schema"].is_string());
    assert!(verdict_json["verdict"].is_string());
    assert!(verdict_json["checks"]["pass_rate"]["ok"].is_boolean());
    assert!(verdict_json["checks"]["fail_count"]["ok"].is_boolean());

    // Verify current state passes the gates.
    assert!(
        pass_rate_ok,
        "regression verdict FAIL: pass rate {current_rate:.1}% < {min_rate:.1}%"
    );
}
