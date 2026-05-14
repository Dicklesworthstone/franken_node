//! Integration test for the camouflage detector against canonical fixtures
//! (bd-35m7.1 sub-task 3/5).
//!
//! Each fixture under `tests/security/camouflage_fixtures/` is loaded via the
//! public [`load_camouflage_fixture`] surface, run through the in-process
//! [`detect_camouflage`] pipeline by [`evaluate_camouflage_fixture`], and
//! asserted to pass its declared `expected_hints` contract.
//!
//! Real types only: no mocks, no stubs, no hand-rolled detector replacement.

use frankenengine_node::security::bpet::camouflage_fixtures::{
    CamouflageFixture, evaluate_camouflage_fixture, load_camouflage_fixture,
};

const FIXTURE_DIR: &str = "tests/security/camouflage_fixtures";

fn load(name: &str) -> CamouflageFixture {
    // Resolve relative to the workspace root (where `cargo test` runs).
    let candidates = [
        format!("{}/{}.json", FIXTURE_DIR, name),
        format!("../../{}/{}.json", FIXTURE_DIR, name),
        format!("../../../{}/{}.json", FIXTURE_DIR, name),
    ];
    let mut last_err: Option<String> = None;
    for path in &candidates {
        match std::fs::read_to_string(path) {
            Ok(json) => {
                return load_camouflage_fixture(&json)
                    .unwrap_or_else(|e| panic!("fixture `{name}` at {path} failed to parse: {e}"));
            }
            Err(e) => last_err = Some(format!("{path}: {e}")),
        }
    }
    panic!(
        "fixture `{name}` not found relative to CWD={:?}; tried: {:?}; last_err={:?}",
        std::env::current_dir(),
        candidates,
        last_err
    );
}

fn assert_passes(fixture_name: &str) {
    let fixture = load(fixture_name);
    let verdict = evaluate_camouflage_fixture(&fixture).expect("detector did not error");
    assert!(
        verdict.passed,
        "fixture `{fixture_name}` failed:\n  divergences: {:#?}\n  counts: {:?}",
        verdict.divergences, verdict.actual_hint_counts
    );
}

// ---------------------------------------------------------------------------
// 5 known-camouflage cases
// ---------------------------------------------------------------------------

#[test]
fn fixture_phase_shift_clear_emits_phase_shift_hint() {
    assert_passes("phase_shift_clear");
}

#[test]
fn fixture_dropout_clear_emits_dropout_hint() {
    assert_passes("dropout_clear");
}

#[test]
fn fixture_distribution_mismatch_clear_emits_distribution_mismatch_hint() {
    assert_passes("distribution_mismatch_clear");
}

#[test]
fn fixture_gradual_creep_clear_emits_gradual_creep_hint() {
    assert_passes("gradual_creep_clear");
}

#[test]
fn fixture_multi_kind_emits_multiple_kinds() {
    assert_passes("multi_kind");
}

// ---------------------------------------------------------------------------
// 5 known-non-camouflage cases
// ---------------------------------------------------------------------------

#[test]
fn fixture_steady_state_emits_no_hints() {
    assert_passes("steady_state");
}

#[test]
fn fixture_coherent_drift_emits_no_hints() {
    assert_passes("coherent_drift");
}

#[test]
fn fixture_noisy_but_aligned_emits_no_hints() {
    assert_passes("noisy_but_aligned");
}

#[test]
fn fixture_partial_observation_emits_no_hints() {
    assert_passes("partial_observation");
}

#[test]
fn fixture_small_excursion_emits_no_hints() {
    assert_passes("small_excursion");
}
