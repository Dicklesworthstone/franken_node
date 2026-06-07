//! BPET adversarial evolution integration suite (bd-ye4m.1 sub-task 4).
//!
//! Drives every JSON scenario fixture under
//! `tests/security/adversarial_scenarios/*.json` through the real
//! [`AdversarialHarness`] via [`evaluate_scenario_fixture`] and asserts the
//! declared [`ExpectedVerdict`] holds end-to-end (kind + at-step bounds).
//!
//! Coverage:
//!
//! * One `#[test]` per [`AdversaryKind`] (8 total) loading the on-disk JSON
//!   fixture and asserting the harness verdict matches the fixture's
//!   `expected_verdict`. Each test wires through the canonical loader so
//!   `serde_json` decoding + bounds validation are exercised on the real
//!   filesystem encoding, not just the in-code synthesizers.
//! * `test_in_code_synthesizers_match_json_fixtures` — proves the
//!   crate-internal `synthesize_*` helpers stay byte-identical to the JSON
//!   catalog so sub-task 5's verification gate can hash either form.
//! * `test_run_scenario_deterministic_across_two_runs` — same fixture +
//!   independent [`AdversarialHarness`] instances produce a byte-identical
//!   [`EvolutionResult`] (PartialEq holds).
//! * `test_invalid_at_step_bounds_rejected_at_load` — load-time + evaluator
//!   paths fail closed on a malformed `lower > upper` fixture.
//! * `test_all_eight_adversary_kinds_have_corresponding_scenario` — every
//!   [`AdversaryKind`] variant is covered by exactly one JSON fixture.
//!
//! Real types only, no mocks: every assertion runs against the production
//! [`run_scenario`] entry point.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_node::security::bpet::adversarial_evolution::{AdversarialError, AdversaryKind};
use frankenengine_node::security::bpet::adversarial_harness::{
    AdversarialHarness, AdversarialHarnessError, ScenarioVerdict, run_scenario,
};
use frankenengine_node::security::bpet::adversarial_scenarios::{
    AdversarialScenarioFixture, ExpectedVerdict, ScenarioVerdictMatch, all_synthesizers,
    evaluate_scenario_fixture, load_scenario_fixture,
    synthesize_capability_creep_disguised_as_feature, synthesize_eviction_via_trust_flooding,
    synthesize_false_recovery_claim, synthesize_indirect_via_dep,
    synthesize_labeled_corpus_records, synthesize_many_tiny_updates,
    synthesize_multi_persona_coordination, synthesize_signature_rollover,
    synthesize_slow_roll_drift,
};
use frankenengine_node::security::bpet::phenotype_extractor::{
    CorpusGroundTruthLabel, GENOME_DIMENSIONS, decode_canonical_corpus_record,
};

type TestResult = Result<(), String>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the workspace-relative JSON fixture directory.
///
/// `CARGO_MANIFEST_DIR` points at `crates/franken-node/`; the fixtures live
/// at `tests/security/adversarial_scenarios/` from the workspace root.
fn fixtures_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("tests")
        .join("security")
        .join("adversarial_scenarios")
}

/// Load `<fixtures_dir>/<name>.json` via the real
/// [`load_scenario_fixture`] surface with explicit fixture context on
/// I/O and validation failures.
fn load_scenario_from_path(name: &str) -> Result<AdversarialScenarioFixture, String> {
    let path = fixtures_dir().join(format!("{name}.json"));
    let json = fs::read_to_string(&path)
        .map_err(|e| format!("read fixture `{}` ({}): {e}", name, path.display()))?;
    load_scenario_fixture(&json)
        .map_err(|e| format!("load fixture `{}` ({}): {e:?}", name, path.display()))
}

/// Assert the verdict-kind axis matches.
fn verdict_kind_aligned(expected: &ExpectedVerdict, actual: &ScenarioVerdict) -> bool {
    matches!(
        (expected, actual),
        (
            ExpectedVerdict::CaughtEarly { .. },
            ScenarioVerdict::CaughtEarly { .. }
        ) | (
            ExpectedVerdict::CaughtLate { .. },
            ScenarioVerdict::CaughtLate { .. }
        ) | (
            ExpectedVerdict::MissedEntirely,
            ScenarioVerdict::MissedEntirely
        )
    )
}

/// Run the fixture, assert `passed`, kind-match, and (when bounded) the
/// at-step lies within the inclusive `[lower, upper]` window. Returns the
/// captured [`ScenarioVerdictMatch`] so callers can inspect diagnostics.
fn run_and_assert(
    name: &str,
    fixture: &AdversarialScenarioFixture,
) -> Result<ScenarioVerdictMatch, String> {
    let m = evaluate_scenario_fixture(fixture)
        .map_err(|e| format!("evaluate fixture `{name}`: {e:?}"))?;

    assert!(
        verdict_kind_aligned(&fixture.expected_verdict, &m.actual_verdict),
        "fixture `{}` verdict-kind mismatch: expected {:?}, actual {:?}, divergences={:?}",
        name,
        fixture.expected_verdict,
        m.actual_verdict,
        m.divergences,
    );

    assert!(
        m.passed,
        "fixture `{}` failed bounds: expected {:?}, actual {:?}, first_detection_at={:?}, divergences={:?}",
        name,
        fixture.expected_verdict,
        m.actual_verdict,
        m.actual_first_detection_at,
        m.divergences,
    );
    assert!(
        m.divergences.is_empty(),
        "fixture `{name}` divergences: {:?}",
        m.divergences
    );

    // Cross-check at-step bound semantics directly against the structured
    // verdict so a regression that loses the bounds inside
    // ScenarioVerdictMatch.passed still trips this test.
    match (&fixture.expected_verdict, &m.actual_verdict) {
        (
            ExpectedVerdict::CaughtEarly {
                at_step_lower,
                at_step_upper,
            },
            ScenarioVerdict::CaughtEarly { at_step },
        ) => {
            assert!(
                *at_step >= *at_step_lower && *at_step <= *at_step_upper,
                "fixture `{name}` caught_early at_step={at_step} outside [{at_step_lower}, {at_step_upper}]",
            );
            assert_eq!(m.actual_first_detection_at, Some(*at_step));
        }
        (
            ExpectedVerdict::CaughtLate {
                at_step_lower,
                at_step_upper,
            },
            ScenarioVerdict::CaughtLate {
                at_step,
                total_steps,
            },
        ) => {
            assert!(
                *at_step >= *at_step_lower && *at_step <= *at_step_upper,
                "fixture `{name}` caught_late at_step={at_step} outside [{at_step_lower}, {at_step_upper}]",
            );
            assert_eq!(*total_steps, fixture.scenario.n_steps);
            assert_eq!(m.actual_first_detection_at, Some(*at_step));
        }
        (ExpectedVerdict::MissedEntirely, ScenarioVerdict::MissedEntirely) => {
            assert!(
                m.actual_first_detection_at.is_none(),
                "fixture `{name}` missed_entirely should have no first_detection_at, got {:?}",
                m.actual_first_detection_at,
            );
        }
        (expected, actual) => {
            return Err(format!(
                "fixture `{name}` verdict-kind mismatch after alignment: expected {expected:?}, actual {actual:?}"
            ));
        }
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// Per-scenario tests (one per AdversaryKind)
// ---------------------------------------------------------------------------

#[test]
fn test_slow_roll_drift_caught_late_within_bounds() -> TestResult {
    let fixture = load_scenario_from_path("slow_roll_drift")?;
    assert_eq!(fixture.scenario.kind, AdversaryKind::SlowRollDrift);
    assert!(matches!(
        fixture.expected_verdict,
        ExpectedVerdict::CaughtLate { .. }
    ));
    run_and_assert("slow_roll_drift", &fixture)?;
    Ok(())
}

#[test]
fn test_capability_creep_disguised_as_feature_caught_late_within_bounds() -> TestResult {
    let fixture = load_scenario_from_path("capability_creep_disguised_as_feature")?;
    assert_eq!(
        fixture.scenario.kind,
        AdversaryKind::CapabilityCreepDisguisedAsFeature
    );
    assert!(matches!(
        fixture.expected_verdict,
        ExpectedVerdict::CaughtLate { .. }
    ));
    run_and_assert("capability_creep_disguised_as_feature", &fixture)?;
    Ok(())
}

#[test]
fn test_eviction_via_trust_flooding_caught_early_within_bounds() -> TestResult {
    let fixture = load_scenario_from_path("eviction_via_trust_flooding")?;
    assert_eq!(
        fixture.scenario.kind,
        AdversaryKind::EvictionViaTrustFlooding
    );
    assert!(matches!(
        fixture.expected_verdict,
        ExpectedVerdict::CaughtEarly { .. }
    ));
    run_and_assert("eviction_via_trust_flooding", &fixture)?;
    Ok(())
}

#[test]
fn test_many_tiny_updates_missed_entirely() -> TestResult {
    let fixture = load_scenario_from_path("many_tiny_updates")?;
    assert_eq!(fixture.scenario.kind, AdversaryKind::ManyTinyUpdates);
    assert!(matches!(
        fixture.expected_verdict,
        ExpectedVerdict::MissedEntirely
    ));
    let m = run_and_assert("many_tiny_updates", &fixture)?;
    assert_eq!(m.actual_verdict, ScenarioVerdict::MissedEntirely);
    assert!(m.actual_first_detection_at.is_none());
    Ok(())
}

#[test]
fn test_multi_persona_coordination_caught_early_within_bounds() -> TestResult {
    let fixture = load_scenario_from_path("multi_persona_coordination")?;
    assert_eq!(
        fixture.scenario.kind,
        AdversaryKind::MultiPersonaCoordination
    );
    assert!(matches!(
        fixture.expected_verdict,
        ExpectedVerdict::CaughtEarly { .. }
    ));
    run_and_assert("multi_persona_coordination", &fixture)?;
    Ok(())
}

#[test]
fn test_false_recovery_claim_caught_late_within_bounds() -> TestResult {
    let fixture = load_scenario_from_path("false_recovery_claim")?;
    assert_eq!(fixture.scenario.kind, AdversaryKind::FalseRecoveryClaim);
    assert!(matches!(
        fixture.expected_verdict,
        ExpectedVerdict::CaughtLate { .. }
    ));
    run_and_assert("false_recovery_claim", &fixture)?;
    Ok(())
}

#[test]
fn test_indirect_via_dep_caught_late_within_bounds() -> TestResult {
    let fixture = load_scenario_from_path("indirect_via_dep")?;
    assert_eq!(fixture.scenario.kind, AdversaryKind::IndirectViaDep);
    assert!(matches!(
        fixture.expected_verdict,
        ExpectedVerdict::CaughtLate { .. }
    ));
    run_and_assert("indirect_via_dep", &fixture)?;
    Ok(())
}

#[test]
fn test_signature_rollover_caught_early_within_bounds() -> TestResult {
    let fixture = load_scenario_from_path("signature_rollover")?;
    assert_eq!(fixture.scenario.kind, AdversaryKind::SignatureRollover);
    assert!(matches!(
        fixture.expected_verdict,
        ExpectedVerdict::CaughtEarly { .. }
    ));
    run_and_assert("signature_rollover", &fixture)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn test_in_code_synthesizers_match_json_fixtures() -> TestResult {
    // Map kind -> on-disk fixture name. Every variant must be present.
    let pairs: [(AdversaryKind, &str, AdversarialScenarioFixture); 8] = [
        (
            AdversaryKind::SlowRollDrift,
            "slow_roll_drift",
            synthesize_slow_roll_drift(),
        ),
        (
            AdversaryKind::CapabilityCreepDisguisedAsFeature,
            "capability_creep_disguised_as_feature",
            synthesize_capability_creep_disguised_as_feature(),
        ),
        (
            AdversaryKind::EvictionViaTrustFlooding,
            "eviction_via_trust_flooding",
            synthesize_eviction_via_trust_flooding(),
        ),
        (
            AdversaryKind::ManyTinyUpdates,
            "many_tiny_updates",
            synthesize_many_tiny_updates(),
        ),
        (
            AdversaryKind::MultiPersonaCoordination,
            "multi_persona_coordination",
            synthesize_multi_persona_coordination(),
        ),
        (
            AdversaryKind::FalseRecoveryClaim,
            "false_recovery_claim",
            synthesize_false_recovery_claim(),
        ),
        (
            AdversaryKind::IndirectViaDep,
            "indirect_via_dep",
            synthesize_indirect_via_dep(),
        ),
        (
            AdversaryKind::SignatureRollover,
            "signature_rollover",
            synthesize_signature_rollover(),
        ),
    ];

    for (kind, name, synthesized) in pairs {
        let loaded = load_scenario_from_path(name)?;
        assert_eq!(
            synthesized.scenario.kind, kind,
            "synthesizer for `{name}` reports wrong kind",
        );
        assert_eq!(
            loaded.scenario.kind, kind,
            "JSON fixture `{name}` reports wrong kind",
        );
        assert_eq!(
            loaded, synthesized,
            "JSON fixture `{name}` diverges from in-code synthesizer",
        );
    }
    Ok(())
}

#[test]
fn test_run_scenario_deterministic_across_two_runs() -> TestResult {
    // For each canonical fixture, two independent harness instances must
    // produce a byte-identical EvolutionResult. This locks the harness as
    // a pure function of (scenario, baseline, thresholds).
    for fixture in all_synthesizers() {
        let mut harness_a =
            AdversarialHarness::new(fixture.thresholds).expect("harness a constructs");
        let result_a = run_scenario(&mut harness_a, &fixture.scenario, &fixture.baseline)
            .map_err(|e| format!("run_scenario A `{}`: {e:?}", fixture.name))?;

        let mut harness_b =
            AdversarialHarness::new(fixture.thresholds).expect("harness b constructs");
        let result_b = run_scenario(&mut harness_b, &fixture.scenario, &fixture.baseline)
            .map_err(|e| format!("run_scenario B `{}`: {e:?}", fixture.name))?;

        assert_eq!(
            result_a, result_b,
            "fixture `{}` is non-deterministic across two runs",
            fixture.name,
        );

        // Determinism must also hold for the higher-level evaluator path.
        let m_a = evaluate_scenario_fixture(&fixture)
            .map_err(|e| format!("evaluate A `{}`: {e:?}", fixture.name))?;
        let m_b = evaluate_scenario_fixture(&fixture)
            .map_err(|e| format!("evaluate B `{}`: {e:?}", fixture.name))?;
        assert_eq!(
            m_a, m_b,
            "fixture `{}` evaluator output non-deterministic",
            fixture.name,
        );
    }
    Ok(())
}

#[test]
fn test_invalid_at_step_bounds_rejected_at_load() {
    // Hand-roll a fixture JSON with lower > upper and confirm both the
    // loader and the evaluator path fail closed before any harness work.
    let mut fixture = synthesize_slow_roll_drift();
    fixture.expected_verdict = ExpectedVerdict::CaughtLate {
        at_step_lower: 90,
        at_step_upper: 10,
    };

    // Direct validate() path.
    let err = fixture
        .validate()
        .expect_err("invalid bounds must reject at validate()");
    assert!(
        matches!(err, AdversarialError::TooManySteps { .. }),
        "expected TooManySteps alias on invalid bounds, got {err:?}",
    );

    // load_scenario_fixture() path — round-trip via JSON to mirror an
    // on-disk corruption.
    let json = serde_json::to_string(&fixture).expect("serialize malformed fixture");
    let err =
        load_scenario_fixture(&json).expect_err("loader must reject malformed at-step bounds");
    assert!(
        matches!(err, AdversarialError::TooManySteps { .. }),
        "loader returned wrong variant: {err:?}",
    );

    // evaluate_scenario_fixture() path — must surface
    // AdversarialHarnessError::InvalidScenario without constructing a
    // harness.
    let err = evaluate_scenario_fixture(&fixture)
        .expect_err("evaluator must reject malformed at-step bounds");
    assert!(
        matches!(err, AdversarialHarnessError::InvalidScenario(_)),
        "evaluator returned wrong variant: {err:?}",
    );

    // Also confirm the CaughtEarly arm is gated symmetrically.
    let mut fixture_early = synthesize_eviction_via_trust_flooding();
    fixture_early.expected_verdict = ExpectedVerdict::CaughtEarly {
        at_step_lower: 50,
        at_step_upper: 5,
    };
    let err = fixture_early
        .validate()
        .expect_err("CaughtEarly bounds must validate");
    assert!(
        matches!(err, AdversarialError::TooManySteps { .. }),
        "expected TooManySteps alias on CaughtEarly bounds, got {err:?}",
    );
}

#[test]
fn test_all_eight_adversary_kinds_have_corresponding_scenario() -> TestResult {
    // Every variant from the AdversaryKind enum must have a JSON fixture
    // on disk. We enumerate the variants statically so missing kinds break
    // the build (`AdversaryKind` is non-exhaustive at the match arm).
    let required: BTreeSet<AdversaryKind> = [
        AdversaryKind::SlowRollDrift,
        AdversaryKind::CapabilityCreepDisguisedAsFeature,
        AdversaryKind::EvictionViaTrustFlooding,
        AdversaryKind::ManyTinyUpdates,
        AdversaryKind::MultiPersonaCoordination,
        AdversaryKind::FalseRecoveryClaim,
        AdversaryKind::IndirectViaDep,
        AdversaryKind::SignatureRollover,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        required.len(),
        8,
        "AdversaryKind variant count drifted from 8"
    );

    // Walk the on-disk fixture directory and collect the kinds reported by
    // each loaded fixture. Filesystem walk uses the same loader path the
    // verification gate (sub-task 5) will exercise.
    let dir = fixtures_dir();
    let entries =
        fs::read_dir(&dir).map_err(|e| format!("read fixture dir `{}`: {e}", dir.display()))?;

    let mut observed: BTreeSet<AdversaryKind> = BTreeSet::new();
    let mut observed_files: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("read fixture dir entry `{}`: {e}", dir.display()))?;
        let path = entry.path();
        if !matches!(path.extension().and_then(|s| s.to_str()), Some("json")) {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("fixture file stem")
            .to_string();
        let fixture = load_scenario_from_path(&name)?;

        // `name` field must match the on-disk basename — guards against a
        // mis-shelved fixture impersonating a different kind.
        assert_eq!(
            fixture.name, name,
            "fixture `{name}` reports inconsistent `name = {}` on disk",
            fixture.name,
        );
        // kind <-> filename invariant via the kebab-case mapping.
        assert_eq!(
            fixture.scenario.kind.as_str(),
            name,
            "fixture `{name}` kind `{}` does not match filename",
            fixture.scenario.kind.as_str(),
        );

        observed.insert(fixture.scenario.kind);
        observed_files.insert(name);
    }

    assert_eq!(
        observed,
        required,
        "fixture directory `{}` does not cover all AdversaryKind variants. Missing: {:?}; extras: {:?}",
        dir.display(),
        required.difference(&observed).collect::<Vec<_>>(),
        observed.difference(&required).collect::<Vec<_>>(),
    );
    assert_eq!(
        observed_files.len(),
        8,
        "expected exactly 8 fixture files, found {}: {:?}",
        observed_files.len(),
        observed_files,
    );
    Ok(())
}

#[test]
fn test_synthetic_corpus_records_cover_all_attack_families_and_benign_controls() -> TestResult {
    let records = synthesize_labeled_corpus_records()
        .map_err(|e| format!("synthesize labeled corpus records: {e:?}"))?;

    let campaign_records: Vec<_> = records
        .iter()
        .filter(|record| record.ground_truth.label == CorpusGroundTruthLabel::CampaignMember)
        .collect();
    let benign_records: Vec<_> = records
        .iter()
        .filter(|record| record.ground_truth.label == CorpusGroundTruthLabel::Benign)
        .collect();

    assert_eq!(
        records.len(),
        16,
        "expected 8 campaigns + 8 benign controls"
    );
    assert_eq!(campaign_records.len(), 8, "campaign-member record count");
    assert_eq!(benign_records.len(), 8, "benign-control record count");

    let required_kinds: BTreeSet<String> = all_synthesizers()
        .iter()
        .map(|fixture| fixture.scenario.kind.as_str().to_string())
        .collect();
    let observed_campaign_kinds: BTreeSet<String> = campaign_records
        .iter()
        .filter_map(|record| record.ground_truth.campaign_id.as_deref())
        .filter_map(|campaign_id| campaign_id.strip_prefix("synthetic-bpet-campaign:"))
        .map(str::to_string)
        .collect();

    assert_eq!(
        observed_campaign_kinds, required_kinds,
        "campaign-member records must cover every adversary kind"
    );

    for record in &records {
        record
            .validate()
            .map_err(|e| format!("validate corpus record `{}`: {e:?}", record.record_id))?;
        assert_eq!(
            record.phenotype_features.len(),
            GENOME_DIMENSIONS.len(),
            "record `{}` must carry every BPET genome dimension",
            record.record_id
        );
        for dimension in GENOME_DIMENSIONS {
            assert!(
                record.phenotype_features.contains_key(dimension),
                "record `{}` missing phenotype dimension `{dimension}`",
                record.record_id
            );
        }
        let bytes = record
            .canonical_bytes()
            .map_err(|e| format!("canonicalize `{}`: {e:?}", record.record_id))?;
        let decoded = decode_canonical_corpus_record(&bytes)
            .map_err(|e| format!("decode canonical `{}`: {e:?}", record.record_id))?;
        assert_eq!(
            decoded, *record,
            "canonical round-trip changed `{}`",
            record.record_id
        );
    }

    Ok(())
}

#[test]
fn test_synthetic_corpus_records_are_byte_deterministic() -> TestResult {
    let first = synthesize_labeled_corpus_records()
        .map_err(|e| format!("first corpus generation: {e:?}"))?;
    let second = synthesize_labeled_corpus_records()
        .map_err(|e| format!("second corpus generation: {e:?}"))?;

    let first_bytes: Result<Vec<_>, _> = first
        .iter()
        .map(|record| {
            record
                .canonical_bytes()
                .map_err(|e| format!("canonicalize first `{}`: {e:?}", record.record_id))
        })
        .collect();
    let second_bytes: Result<Vec<_>, _> = second
        .iter()
        .map(|record| {
            record
                .canonical_bytes()
                .map_err(|e| format!("canonicalize second `{}`: {e:?}", record.record_id))
        })
        .collect();

    assert_eq!(
        first_bytes?, second_bytes?,
        "same synthetic corpus profile must emit byte-identical canonical records"
    );

    Ok(())
}
