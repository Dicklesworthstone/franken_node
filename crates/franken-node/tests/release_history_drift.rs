//! Release-history drift scoring over hermetic snapshots of real npm
//! packuments (bd-reality-20260923-26n9r.15 deliverable 3). The fixtures in
//! `tests/fixtures/npm_release_history/` are registry.npmjs.org documents
//! trimmed to the fields the scorer reads; see each file's `_fixture` note.

use frankenengine_node::config::Profile;
use frankenengine_node::supply_chain::release_history::{
    assess_release_history, release_window, risk_bump_severity,
};
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/npm_release_history")
        .join(format!("{name}.json"));
    serde_json::from_slice(&std::fs::read(&path).expect("fixture")).expect("fixture json")
}

#[test]
fn esbuild_introducing_its_install_hook_is_high_severity_drift() {
    let esbuild = fixture("esbuild");
    let assessment = assess_release_history(&esbuild, "0.0.4")
        .expect("detector")
        .expect("six releases");
    assert!(
        assessment.max_severity >= risk_bump_severity(Profile::Balanced),
        "{assessment:?}"
    );
    assert!(
        assessment
            .changes
            .iter()
            .any(|change| change == "install_scripts 0 -> 1 by 0.0.13"),
        "{:?}",
        assessment.changes
    );
    assert_eq!(
        assessment
            .releases
            .first()
            .map(|release| release.version.as_str()),
        Some("0.0.0")
    );
}

#[test]
fn a_settled_install_hook_is_not_drift() {
    // Later in the same line the hook is part of the baseline consumers
    // already vetted.
    let esbuild = fixture("esbuild");
    let assessment = assess_release_history(&esbuild, "0.1.3")
        .expect("detector")
        .expect("six releases");
    assert!(assessment.max_severity < 0.5, "{assessment:?}");
    assert!(assessment.changes.is_empty(), "{:?}", assessment.changes);
}

#[test]
fn interleaved_major_lines_are_scored_separately() {
    let express = fixture("express");
    for version in ["5.3.0", "4.22.3"] {
        let window = release_window(&express, version);
        let major = version.split('.').next().expect("major");
        assert!(
            window
                .iter()
                .all(|release| release.version.split('.').next() == Some(major)),
            "{version}: {window:?}"
        );
        assert_eq!(
            window.last().map(|release| release.version.as_str()),
            Some(version)
        );
        let assessment = assess_release_history(&express, version)
            .expect("detector")
            .expect("enough releases");
        assert!(assessment.max_severity < 0.5, "{version}: {assessment:?}");
    }
}

#[test]
fn profile_thresholds_order_strict_below_balanced_below_legacy() {
    let strict = risk_bump_severity(Profile::Strict);
    let balanced = risk_bump_severity(Profile::Balanced);
    let legacy = risk_bump_severity(Profile::LegacyRisky);
    assert!(
        strict < balanced && balanced < legacy,
        "{strict} {balanced} {legacy}"
    );
    assert!((0.0..=1.0).contains(&strict) && (0.0..=1.0).contains(&legacy));
}

#[test]
fn unknown_or_prerelease_versions_are_not_scored() {
    let express = fixture("express");
    assert!(
        assess_release_history(&express, "9.9.9")
            .expect("detector")
            .is_none()
    );
    assert!(release_window(&express, "5.0.0-beta.1").is_empty());
}
