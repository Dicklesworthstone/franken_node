//! Integration test for the camouflage detector against canonical fixtures
//! (bd-35m7.1 sub-task 3/5).
//!
//! Each fixture under `tests/security/camouflage_fixtures/` is loaded via the
//! public [`load_camouflage_fixture`] surface, run through the in-process
//! [`detect_camouflage`] pipeline by [`evaluate_camouflage_fixture`], and
//! asserted to pass its declared `expected_hints` contract.
//!
//! Real types only: no mocks, no stubs, no hand-rolled detector replacement.

use std::path::{Path, PathBuf};

use frankenengine_node::security::bpet::camouflage_fixtures::{
    CamouflageFixture, evaluate_camouflage_fixture, load_camouflage_fixture,
};

fn repo_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|e| format!("resolve repository root: {e}"))
}

fn load(name: &str) -> Result<CamouflageFixture, String> {
    let path = repo_root()?.join(format!("tests/security/camouflage_fixtures/{name}.json"));
    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read fixture {}: {e}", path.display()))?;
    load_camouflage_fixture(&json).map_err(|e| {
        format!(
            "fixture `{name}` at {} failed to parse: {e}",
            path.display()
        )
    })
}

fn assert_passes(fixture_name: &str) -> Result<(), String> {
    let fixture = load(fixture_name)?;
    let verdict = evaluate_camouflage_fixture(&fixture)
        .map_err(|e| format!("detector failed for fixture `{fixture_name}`: {e}"))?;
    assert!(
        verdict.passed,
        "fixture `{fixture_name}` failed:\n  divergences: {:#?}\n  counts: {:?}",
        verdict.divergences, verdict.actual_hint_counts
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 5 known-camouflage cases
// ---------------------------------------------------------------------------

#[test]
fn fixture_phase_shift_clear_emits_phase_shift_hint() -> Result<(), String> {
    assert_passes("phase_shift_clear")
}

#[test]
fn fixture_dropout_clear_emits_dropout_hint() -> Result<(), String> {
    assert_passes("dropout_clear")
}

#[test]
fn fixture_distribution_mismatch_clear_emits_distribution_mismatch_hint() -> Result<(), String> {
    assert_passes("distribution_mismatch_clear")
}

#[test]
fn fixture_gradual_creep_clear_emits_gradual_creep_hint() -> Result<(), String> {
    assert_passes("gradual_creep_clear")
}

#[test]
fn fixture_multi_kind_emits_multiple_kinds() -> Result<(), String> {
    assert_passes("multi_kind")
}

// ---------------------------------------------------------------------------
// 5 known-non-camouflage cases
// ---------------------------------------------------------------------------

#[test]
fn fixture_steady_state_emits_no_hints() -> Result<(), String> {
    assert_passes("steady_state")
}

#[test]
fn fixture_coherent_drift_emits_no_hints() -> Result<(), String> {
    assert_passes("coherent_drift")
}

#[test]
fn fixture_noisy_but_aligned_emits_no_hints() -> Result<(), String> {
    assert_passes("noisy_but_aligned")
}

#[test]
fn fixture_partial_observation_emits_no_hints() -> Result<(), String> {
    assert_passes("partial_observation")
}

#[test]
fn fixture_small_excursion_emits_no_hints() -> Result<(), String> {
    assert_passes("small_excursion")
}
