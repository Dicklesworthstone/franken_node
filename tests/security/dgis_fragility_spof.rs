//! Integration test for DGIS SPOF detector against the 10 fixture suite
//! (bd-2jns.1 sub-task 4 of 5).
//!
//! This test loads each fixture from
//! `tests/security/fragility_fixtures/<name>.json`, runs
//! [`evaluate_fixture`], and asserts:
//!
//! * For the five known-SPOF fixtures, the resulting [`FixtureVerdict`] is
//!   `passed` AND `actual_finding_counts` contains at least one entry for the
//!   expected [`SpofKindLabel`].
//! * For the five robust fixtures, [`FixtureVerdict::passed`] is true AND the
//!   detector emitted zero findings of any kind.
//! * The in-code `synthesize_*` constructors produce fixtures byte-equivalent
//!   to the JSON files on disk (so the inline unit tests in
//!   `fragility_fixtures.rs` stay synchronised with the on-disk suite).
//! * [`detect_spofs`] (via `evaluate_fixture`) is deterministic across two
//!   back-to-back runs on the same input.
//!
//! Hardening notes:
//!
//! * No mocks: this test exercises the REAL `MaintainerProfile`,
//!   `PublisherProfile`, `GraphNode`, `GraphEdge`, `SpofDetectorConfig`,
//!   and `detect_spofs` types from
//!   [`frankenengine_node::dgis::fragility_model`],
//!   [`frankenengine_node::dgis::graph_ingestion`], and
//!   [`frankenengine_node::dgis::spof_detection`].
//! * All filesystem reads go through [`std::fs::read_to_string`] with a
//!   canonical fixture directory and an explicit panic on missing files --
//!   no `unwrap()` shortcuts that would hide IO errors silently.
//! * The deterministic-replay assertion compares full [`FixtureVerdict`]
//!   values (which derive `PartialEq`) rather than hashing, so any
//!   divergence shows up structurally in the failure message.

use std::collections::BTreeMap;
use std::path::PathBuf;

use frankenengine_node::dgis::fragility_fixtures::{
    ExpectedFinding, FixtureVerdict, FragilityFixture, SpofKindLabel, evaluate_fixture,
    load_fixture_from_json, synthesize_active_maintainers_recent_commits,
    synthesize_dependency_chain_fragile, synthesize_diverse_org_ownership,
    synthesize_independent_packages_no_chains, synthesize_key_person_high_share,
    synthesize_multi_quorum_publishers, synthesize_org_concentrated, synthesize_orphaned_pkg,
    synthesize_single_maintainer_dominant, synthesize_well_distributed_maintainers,
};

/// Absolute-path-derived fixture directory.
///
/// Cargo sets `CARGO_MANIFEST_DIR` to the crate root (`crates/franken-node/`),
/// so we ascend two levels to reach the workspace root and descend into
/// `tests/security/fragility_fixtures/`. We do NOT call `canonicalize()` so
/// that symlinks in the workspace layout (e.g. agent worktrees) keep
/// resolving to the correct file.
fn fixture_dir() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo for integration tests");
    let mut p = PathBuf::from(manifest_dir);
    // crates/franken-node -> workspace root
    p.pop();
    p.pop();
    p.push("tests");
    p.push("security");
    p.push("fragility_fixtures");
    p
}

/// Load a fixture by stem name (e.g. `"single_maintainer_dominant"`).
///
/// Panics with a descriptive message if the JSON file is missing or fails
/// schema validation -- the test driver is meant to fail loudly here.
fn load_fixture_from_path(name: &str) -> FragilityFixture {
    let mut path = fixture_dir();
    path.push(format!("{}.json", name));
    let json =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {:?}: {}", path, e));
    load_fixture_from_json(&json).unwrap_or_else(|e| panic!("parse fixture {:?}: {:?}", path, e))
}

/// Convenience: collect the expected kinds declared by a fixture (so a SPOF
/// fixture exercises ONLY the kind it was designed to demonstrate when the
/// caller wants strict mode).
fn expected_kinds(fixture: &FragilityFixture) -> Vec<SpofKindLabel> {
    fixture
        .expected_findings
        .iter()
        .map(|ef: &ExpectedFinding| ef.kind)
        .collect()
}

/// Assert that `verdict.actual_finding_counts` contains at least one entry
/// for `label`. Fails with a structured message including the full
/// `actual_finding_counts` map so debugging is one stack-trace away.
fn assert_label_present(verdict: &FixtureVerdict, label: SpofKindLabel) {
    let n = verdict
        .actual_finding_counts
        .get(&label)
        .copied()
        .unwrap_or(0);
    assert!(
        n >= 1,
        "expected at least one {} finding, got counts={:?}, divergences={:?}",
        label.slug(),
        verdict.actual_finding_counts,
        verdict.divergences,
    );
}

/// Assert that the verdict reports zero findings (robust-fixture semantics).
fn assert_robust(verdict: &FixtureVerdict) {
    assert!(
        verdict.passed,
        "robust fixture must pass; divergences: {:?}",
        verdict.divergences
    );
    let total: usize = verdict
        .actual_finding_counts
        .values()
        .copied()
        .fold(0_usize, |acc, n| acc.saturating_add(n));
    assert_eq!(
        total, 0,
        "robust fixture must emit zero findings, got counts={:?}",
        verdict.actual_finding_counts
    );
}

// ===========================================================================
// 5 known-SPOF fixtures: each must produce >=1 finding of the expected kind
// ===========================================================================

#[test]
fn test_single_maintainer_dominant_fixture_detects_spof() {
    let fixture = load_fixture_from_path("single_maintainer_dominant");
    let kinds = expected_kinds(&fixture);
    assert!(
        kinds.contains(&SpofKindLabel::SingleMaintainer),
        "fixture must declare SingleMaintainer in expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate single_maintainer_dominant");
    assert!(
        verdict.passed,
        "expected verdict to pass; divergences: {:?}",
        verdict.divergences
    );
    assert_label_present(&verdict, SpofKindLabel::SingleMaintainer);
}

#[test]
fn test_key_person_high_share_fixture_detects_spof() {
    let fixture = load_fixture_from_path("key_person_high_share");
    let kinds = expected_kinds(&fixture);
    assert!(
        kinds.contains(&SpofKindLabel::KeyPerson),
        "fixture must declare KeyPerson in expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate key_person_high_share");
    assert!(
        verdict.passed,
        "expected verdict to pass; divergences: {:?}",
        verdict.divergences
    );
    assert_label_present(&verdict, SpofKindLabel::KeyPerson);
}

#[test]
fn test_dependency_chain_fragile_fixture_detects_spof() {
    let fixture = load_fixture_from_path("dependency_chain_fragile");
    let kinds = expected_kinds(&fixture);
    assert!(
        kinds.contains(&SpofKindLabel::DependencyChain),
        "fixture must declare DependencyChain in expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate dependency_chain_fragile");
    assert!(
        verdict.passed,
        "expected verdict to pass; divergences: {:?}",
        verdict.divergences
    );
    assert_label_present(&verdict, SpofKindLabel::DependencyChain);
}

#[test]
fn test_org_concentrated_fixture_detects_spof() {
    let fixture = load_fixture_from_path("org_concentrated");
    let kinds = expected_kinds(&fixture);
    assert!(
        kinds.contains(&SpofKindLabel::OrgConcentration),
        "fixture must declare OrgConcentration in expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate org_concentrated");
    assert!(
        verdict.passed,
        "expected verdict to pass; divergences: {:?}",
        verdict.divergences
    );
    assert_label_present(&verdict, SpofKindLabel::OrgConcentration);
}

#[test]
fn test_orphaned_pkg_fixture_detects_spof() {
    let fixture = load_fixture_from_path("orphaned_pkg");
    let kinds = expected_kinds(&fixture);
    assert!(
        kinds.contains(&SpofKindLabel::OrphanedPackage),
        "fixture must declare OrphanedPackage in expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate orphaned_pkg");
    assert!(
        verdict.passed,
        "expected verdict to pass; divergences: {:?}",
        verdict.divergences
    );
    assert_label_present(&verdict, SpofKindLabel::OrphanedPackage);
}

// ===========================================================================
// 5 robust fixtures: SpofReport must be empty
// ===========================================================================

#[test]
fn test_well_distributed_maintainers_is_robust() {
    let fixture = load_fixture_from_path("well_distributed_maintainers");
    assert!(
        fixture.expected_findings.is_empty(),
        "robust fixture must declare empty expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate well_distributed_maintainers");
    assert_robust(&verdict);
}

#[test]
fn test_diverse_org_ownership_is_robust() {
    let fixture = load_fixture_from_path("diverse_org_ownership");
    assert!(
        fixture.expected_findings.is_empty(),
        "robust fixture must declare empty expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate diverse_org_ownership");
    assert_robust(&verdict);
}

#[test]
fn test_active_maintainers_recent_commits_is_robust() {
    let fixture = load_fixture_from_path("active_maintainers_recent_commits");
    assert!(
        fixture.expected_findings.is_empty(),
        "robust fixture must declare empty expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate active_maintainers_recent_commits");
    assert_robust(&verdict);
}

#[test]
fn test_independent_packages_no_chains_is_robust() {
    let fixture = load_fixture_from_path("independent_packages_no_chains");
    assert!(
        fixture.expected_findings.is_empty(),
        "robust fixture must declare empty expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate independent_packages_no_chains");
    assert_robust(&verdict);
}

#[test]
fn test_multi_quorum_publishers_is_robust() {
    let fixture = load_fixture_from_path("multi_quorum_publishers");
    assert!(
        fixture.expected_findings.is_empty(),
        "robust fixture must declare empty expected_findings"
    );
    let verdict = evaluate_fixture(&fixture).expect("evaluate multi_quorum_publishers");
    assert_robust(&verdict);
}

// ===========================================================================
// Cross-checks: in-code synthesizers vs JSON fixtures
// ===========================================================================

/// Assert that the JSON fixture on disk and the in-code synthesizer agree on
/// every field they expose. The two must stay in lock-step so the inline
/// `synthesize_*` unit tests in `fragility_fixtures.rs` accurately model the
/// on-disk suite.
#[test]
fn test_in_code_synthesizers_match_json_fixtures() {
    let pairs: Vec<(&'static str, FragilityFixture)> = vec![
        (
            "single_maintainer_dominant",
            synthesize_single_maintainer_dominant(),
        ),
        ("key_person_high_share", synthesize_key_person_high_share()),
        (
            "dependency_chain_fragile",
            synthesize_dependency_chain_fragile(),
        ),
        ("org_concentrated", synthesize_org_concentrated()),
        ("orphaned_pkg", synthesize_orphaned_pkg()),
        (
            "well_distributed_maintainers",
            synthesize_well_distributed_maintainers(),
        ),
        ("diverse_org_ownership", synthesize_diverse_org_ownership()),
        (
            "active_maintainers_recent_commits",
            synthesize_active_maintainers_recent_commits(),
        ),
        (
            "independent_packages_no_chains",
            synthesize_independent_packages_no_chains(),
        ),
        (
            "multi_quorum_publishers",
            synthesize_multi_quorum_publishers(),
        ),
    ];

    for (name, in_code) in pairs {
        let on_disk = load_fixture_from_path(name);

        assert_eq!(
            on_disk.name, in_code.name,
            "fixture {}: name mismatch (disk={:?}, code={:?})",
            name, on_disk.name, in_code.name
        );
        assert_eq!(
            on_disk.now_ms, in_code.now_ms,
            "fixture {}: now_ms mismatch (disk={}, code={})",
            name, on_disk.now_ms, in_code.now_ms
        );
        assert_eq!(
            on_disk.maintainers, in_code.maintainers,
            "fixture {}: maintainers map mismatch",
            name
        );
        assert_eq!(
            on_disk.publishers, in_code.publishers,
            "fixture {}: publishers map mismatch",
            name
        );
        assert_eq!(
            on_disk.nodes, in_code.nodes,
            "fixture {}: nodes vec mismatch",
            name
        );
        assert_eq!(
            on_disk.edges, in_code.edges,
            "fixture {}: edges vec mismatch",
            name
        );
        assert_eq!(
            on_disk.config_overrides, in_code.config_overrides,
            "fixture {}: config_overrides mismatch",
            name
        );
        assert_eq!(
            on_disk.expected_findings, in_code.expected_findings,
            "fixture {}: expected_findings mismatch",
            name
        );
    }
}

// ===========================================================================
// Determinism: same input -> same SpofReport on two consecutive runs
// ===========================================================================

#[test]
fn test_detect_spofs_deterministic_across_two_runs() {
    // Use a SPOF fixture so there are non-trivial findings to compare. The
    // robust fixtures would also pass trivially with two empty reports.
    let fixture = load_fixture_from_path("dependency_chain_fragile");

    let first = evaluate_fixture(&fixture).expect("first evaluate");
    let second = evaluate_fixture(&fixture).expect("second evaluate");

    // FixtureVerdict derives PartialEq + Eq, so the comparison is total.
    assert_eq!(
        first, second,
        "detect_spofs must be deterministic across runs: first={:?}, second={:?}",
        first, second
    );
    assert!(
        first.passed,
        "fixture should pass deterministically; divergences: {:?}",
        first.divergences
    );

    // Sanity: count buckets must also be identical map-wise.
    let first_counts: BTreeMap<SpofKindLabel, usize> = first.actual_finding_counts.clone();
    let second_counts: BTreeMap<SpofKindLabel, usize> = second.actual_finding_counts.clone();
    assert_eq!(
        first_counts, second_counts,
        "actual_finding_counts map drift between runs"
    );
}
