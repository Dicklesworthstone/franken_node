//! `trust scan --deep` registry signals (bd-reality-20260923-26n9r.15/.14):
//! package recency and DGIS maintainer fragility read from npm packuments.
//! The packuments here are hermetic fixtures shaped like registry.npmjs.org
//! responses; they exercise parsing and assessment, not the network fetch.

use frankenengine_node::dgis::fragility_model::FragilityFactor;
use frankenengine_node::supply_chain::npm_registry_signals::{
    NEW_PACKAGE_DAYS, assess_registry_signals, parse_registry_signals,
};
use serde_json::json;

/// 2026-09-24T00:00:00Z
const NOW: u64 = 1_790_208_000;
const DAY: u64 = 86_400;

fn at(days_ago: u64) -> String {
    let secs = i64::try_from(NOW - days_ago * DAY).expect("fits");
    chrono::DateTime::from_timestamp(secs, 0)
        .expect("valid timestamp")
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[test]
fn new_single_maintainer_package_is_flagged_on_both_axes() {
    let packument = json!({
        "name": "fresh-helper",
        "maintainers": [{"name": "solo", "email": "solo@example.test"}],
        "time": {"created": at(5), "modified": at(5), "1.0.0": at(5)},
    });
    let findings = assess_registry_signals(&parse_registry_signals(&packument), NOW);
    assert_eq!(findings.new_package_age_days, Some(5));
    assert_eq!(
        findings.fragility.factors,
        vec![FragilityFactor::SingleMaintainer]
    );
    let described = findings.describe().join(" | ");
    assert!(
        described.contains("first published 5 day(s) ago"),
        "{described}"
    );
    assert!(
        described.contains("maintainer fragility 0.35 (DGIS): single_maintainer"),
        "{described}"
    );
}

#[test]
fn mature_well_maintained_package_has_no_findings() {
    let packument = json!({
        "maintainers": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
        "time": {"created": at(2000), "modified": at(3), "4.0.0": at(900), "4.1.0": at(10)},
    });
    let findings = assess_registry_signals(&parse_registry_signals(&packument), NOW);
    assert_eq!(findings.new_package_age_days, None);
    assert!(!findings.fragility.is_fragile());
    assert!(findings.describe().is_empty());
}

#[test]
fn abandoned_single_maintainer_package_is_fragile_not_new() {
    let packument = json!({
        "maintainers": [{"name": "gone"}],
        "time": {"created": at(2200), "modified": at(1), "0.9.0": at(1500), "1.0.0": at(800)},
    });
    let signals = parse_registry_signals(&packument);
    // `modified` (1 day ago) is bookkeeping, not a publish.
    assert_eq!(signals.last_published_at.as_deref(), Some(at(800).as_str()));
    let findings = assess_registry_signals(&signals, NOW);
    assert_eq!(findings.new_package_age_days, None);
    assert_eq!(
        findings.fragility.factors,
        vec![
            FragilityFactor::SingleMaintainer,
            FragilityFactor::StaleMaintainer {
                staleness_days: 800
            },
        ]
    );
    assert!((findings.fragility.total - 0.5).abs() < 1e-9);
    assert!(
        findings
            .describe()
            .join(" ")
            .contains("stale_maintainer (no publish in 800 days)")
    );
}

#[test]
fn package_with_no_maintainers_is_orphaned() {
    let packument = json!({
        "maintainers": [],
        "time": {"created": at(400), "1.0.0": at(400)},
    });
    let findings = assess_registry_signals(&parse_registry_signals(&packument), NOW);
    assert_eq!(
        findings.fragility.factors,
        vec![
            FragilityFactor::OrphanedPackage,
            FragilityFactor::StaleMaintainer {
                staleness_days: 400
            },
        ]
    );
}

#[test]
fn missing_fields_yield_no_findings_rather_than_guesses() {
    let findings = assess_registry_signals(&parse_registry_signals(&json!({"name": "x"})), NOW);
    assert_eq!(findings.new_package_age_days, None);
    assert!(!findings.fragility.is_fragile());

    let malformed = json!({"time": {"created": "not-a-date", "1.0.0": 7}, "maintainers": "x"});
    let signals = parse_registry_signals(&malformed);
    assert_eq!(signals.maintainer_count, None);
    assert_eq!(signals.last_published_at, None);
    assert_eq!(
        assess_registry_signals(&signals, NOW).new_package_age_days,
        None
    );
}

#[test]
fn future_creation_time_counts_as_brand_new_not_negative() {
    let packument = json!({"time": {"created": at(0).replace("2026", "2027")}});
    let findings = assess_registry_signals(&parse_registry_signals(&packument), NOW);
    assert_eq!(findings.new_package_age_days, Some(0));
}

#[test]
fn new_package_boundary_is_exclusive() {
    let at_boundary = json!({"time": {"created": at(NEW_PACKAGE_DAYS)}});
    assert_eq!(
        assess_registry_signals(&parse_registry_signals(&at_boundary), NOW).new_package_age_days,
        None
    );
    let just_inside = json!({"time": {"created": at(NEW_PACKAGE_DAYS - 1)}});
    assert_eq!(
        assess_registry_signals(&parse_registry_signals(&just_inside), NOW).new_package_age_days,
        Some(NEW_PACKAGE_DAYS - 1)
    );
}
