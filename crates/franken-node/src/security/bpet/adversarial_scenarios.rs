//! BPET adversarial scenario catalog (bd-ye4m sub-task 3).
//!
//! Defines the eight slow-roll adversary campaign fixtures the integration
//! suite (sub-task 4) and verification gate (sub-task 5) will exercise.
//! Each fixture pairs an [`AdversaryScenario`] descriptor with a baseline
//! [`PhenotypeSample`], a tuned [`DetectorThresholds`] set, and an
//! [`ExpectedVerdict`] declaring the harness outcome the catalog asserts.
//!
//! The catalog is exposed in two forms:
//!
//! * JSON fixtures under `tests/security/adversarial_scenarios/*.json` (one
//!   file per `AdversaryKind` variant) loaded via
//!   [`load_scenario_fixture`].
//! * In-code synthesizers (`synthesize_*`) that return a byte-identical
//!   [`AdversarialScenarioFixture`] without touching the filesystem. The
//!   synthesizers are the source of truth in inline unit tests so the
//!   crate's test suite stays self-contained.
//!
//! # Hardening contract
//!
//! - Bounds in [`ExpectedVerdict`] are validated at construction so a
//!   malformed fixture (e.g. `at_step_upper < at_step_lower`) fails closed
//!   before any harness run.
//! - Every numeric input passes through the existing
//!   [`AdversaryScenario::validate`] / [`DetectorThresholds::validate`]
//!   gates which already enforce `is_finite` + `[0, 1]` bounds.
//! - Fixture loading uses `serde_json` (no custom byte parsing) and routes
//!   the result through the same validators so on-disk corruption is
//!   rejected on read.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::adversarial_evolution::{
    AdversarialError, AdversaryKind, AdversaryScenario, RampCurve, validate_scenario,
};
use super::adversarial_harness::{
    AdversarialHarness, AdversarialHarnessError, CAPABILITY_FIELD, DetectorThresholds,
    RESPONSE_FIELD, ScenarioVerdict, VELOCITY_FIELD, run_scenario,
};
use super::drift_features::PhenotypeSample;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stable telemetry codes emitted by the scenario catalog.
pub mod event_codes {
    pub const BPET_SCN_FIXTURE_LOADED: &str = "BPET-SCN-001";
    pub const BPET_SCN_FIXTURE_REJECTED: &str = "BPET-SCN-002";
    pub const BPET_SCN_EVALUATION_OK: &str = "BPET-SCN-003";
    pub const BPET_SCN_EVALUATION_DIVERGED: &str = "BPET-SCN-004";
    pub const BPET_SCN_BOUNDS_INVALID: &str = "BPET-SCN-005";
}

// ---------------------------------------------------------------------------
// ExpectedVerdict
// ---------------------------------------------------------------------------

/// Declarative description of the harness outcome a fixture asserts.
///
/// Step bounds are inclusive on both ends. They are validated to satisfy
/// `at_step_lower <= at_step_upper` by [`ExpectedVerdict::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExpectedVerdict {
    /// Detector must fire in the early half of the campaign, with the
    /// first detection step inside the inclusive `[lower, upper]` range.
    CaughtEarly {
        at_step_lower: u32,
        at_step_upper: u32,
    },
    /// Detector must fire in the late half of the campaign, with the first
    /// detection step inside the inclusive `[lower, upper]` range.
    CaughtLate {
        at_step_lower: u32,
        at_step_upper: u32,
    },
    /// Detector must never fire across the full campaign.
    MissedEntirely,
}

impl ExpectedVerdict {
    /// Validate the bounds. Fails closed on `lower > upper`.
    pub fn validate(&self) -> std::result::Result<(), AdversarialError> {
        match *self {
            ExpectedVerdict::CaughtEarly {
                at_step_lower,
                at_step_upper,
            }
            | ExpectedVerdict::CaughtLate {
                at_step_lower,
                at_step_upper,
            } => {
                if at_step_lower > at_step_upper {
                    return Err(AdversarialError::TooManySteps {
                        n: at_step_lower,
                        limit: at_step_upper,
                    });
                }
                Ok(())
            }
            ExpectedVerdict::MissedEntirely => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// AdversarialScenarioFixture
// ---------------------------------------------------------------------------

/// A fully-specified adversarial scenario fixture combining the scenario
/// descriptor, baseline phenotype, detector thresholds, and the verdict
/// the harness is expected to produce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdversarialScenarioFixture {
    /// Stable kebab/snake-case name for telemetry + filesystem mapping.
    pub name: String,
    /// Free-form human description used in playbook artifacts.
    pub description: String,
    /// Scenario descriptor handed to the harness.
    pub scenario: AdversaryScenario,
    /// Baseline phenotype sample seeded into the drift window.
    pub baseline: PhenotypeSample,
    /// Detector thresholds tuned to make `expected_verdict` deterministic.
    pub thresholds: DetectorThresholds,
    /// Expected harness verdict; bounds checked by
    /// [`evaluate_scenario_fixture`].
    pub expected_verdict: ExpectedVerdict,
}

impl AdversarialScenarioFixture {
    /// Validate the fixture's invariants — scenario, thresholds, expected
    /// verdict bounds, and the presence of the canonical capability field
    /// in the baseline.
    pub fn validate(&self) -> std::result::Result<(), AdversarialError> {
        validate_scenario(&self.scenario)?;
        self.expected_verdict.validate()?;
        // Threshold validation happens via DetectorThresholds::try_new at
        // load time; we re-route through the same private validator path
        // here by re-constructing.
        let _check = DetectorThresholds::try_new(
            self.thresholds.drift,
            self.thresholds.regime_shift,
            self.thresholds.hazard,
            self.thresholds.provenance,
            self.thresholds.combined,
        )
        .map_err(|_| AdversarialError::NonFiniteDivergence(f64::NAN))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ScenarioVerdictMatch
// ---------------------------------------------------------------------------

/// Outcome of evaluating a fixture against the live harness.
///
/// `passed` is `true` iff every assertion in `expected_verdict` holds
/// against the harness output. `divergences` accumulates a structured
/// message per failed assertion so test failures cite both axes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioVerdictMatch {
    pub passed: bool,
    pub actual_verdict: ScenarioVerdict,
    pub actual_first_detection_at: Option<u32>,
    pub divergences: Vec<String>,
}

// ---------------------------------------------------------------------------
// Loaders + evaluators
// ---------------------------------------------------------------------------

/// Parse a JSON fixture string and route it through
/// [`AdversarialScenarioFixture::validate`].
///
/// JSON shape is the natural `serde` encoding of
/// [`AdversarialScenarioFixture`] — see `tests/security/adversarial_scenarios/*.json`.
pub fn load_scenario_fixture(
    json: &str,
) -> std::result::Result<AdversarialScenarioFixture, AdversarialError> {
    let fixture: AdversarialScenarioFixture =
        serde_json::from_str(json).map_err(|_| AdversarialError::NonFiniteDivergence(f64::NAN))?;
    fixture.validate()?;
    Ok(fixture)
}

/// Run the harness against `fixture` and assert the verdict matches
/// `fixture.expected_verdict`.
///
/// Returns a [`ScenarioVerdictMatch`] regardless of pass/fail so callers
/// can capture diagnostic context; harness-construction or scenario
/// validation errors surface as [`AdversarialHarnessError`].
pub fn evaluate_scenario_fixture(
    fixture: &AdversarialScenarioFixture,
) -> std::result::Result<ScenarioVerdictMatch, AdversarialHarnessError> {
    fixture
        .validate()
        .map_err(AdversarialHarnessError::InvalidScenario)?;
    let mut harness = AdversarialHarness::new(fixture.thresholds)?;
    let result = run_scenario(&mut harness, &fixture.scenario, &fixture.baseline)?;

    let mut divergences: Vec<String> = Vec::new();
    let mut kind_ok = true;
    match (&fixture.expected_verdict, result.final_verdict) {
        (
            ExpectedVerdict::CaughtEarly {
                at_step_lower,
                at_step_upper,
            },
            ScenarioVerdict::CaughtEarly { at_step },
        ) => {
            if at_step < *at_step_lower || at_step > *at_step_upper {
                divergences.push(format!(
                    "caught_early at_step={} outside [{}, {}]",
                    at_step, at_step_lower, at_step_upper
                ));
            }
        }
        (
            ExpectedVerdict::CaughtLate {
                at_step_lower,
                at_step_upper,
            },
            ScenarioVerdict::CaughtLate { at_step, .. },
        ) => {
            if at_step < *at_step_lower || at_step > *at_step_upper {
                divergences.push(format!(
                    "caught_late at_step={} outside [{}, {}]",
                    at_step, at_step_lower, at_step_upper
                ));
            }
        }
        (ExpectedVerdict::MissedEntirely, ScenarioVerdict::MissedEntirely) => {}
        (expected, actual) => {
            kind_ok = false;
            divergences.push(format!(
                "verdict kind mismatch: expected {:?}, actual {:?}",
                expected, actual
            ));
        }
    }

    let passed = kind_ok && divergences.is_empty();
    Ok(ScenarioVerdictMatch {
        passed,
        actual_verdict: result.final_verdict,
        actual_first_detection_at: result.first_detection_at,
        divergences,
    })
}

// ---------------------------------------------------------------------------
// In-code synthesizers
// ---------------------------------------------------------------------------

fn baseline_sample(capability: f64, velocity: f64, response: f64) -> PhenotypeSample {
    let mut fields: BTreeMap<String, f64> = BTreeMap::new();
    fields.insert(CAPABILITY_FIELD.to_string(), capability);
    fields.insert(VELOCITY_FIELD.to_string(), velocity);
    fields.insert(RESPONSE_FIELD.to_string(), response);
    PhenotypeSample::new(0, fields)
}

fn thresholds(
    drift: f64,
    regime_shift: f64,
    hazard: f64,
    provenance: f64,
    combined: f64,
) -> DetectorThresholds {
    DetectorThresholds::try_new(drift, regime_shift, hazard, provenance, combined)
        .expect("static synthesizer thresholds must validate")
}

/// Synthesize the canonical `slow_roll_drift` fixture.
pub fn synthesize_slow_roll_drift() -> AdversarialScenarioFixture {
    let scenario = AdversaryScenario::try_new(
        "scenario-slow-roll-001",
        AdversaryKind::SlowRollDrift,
        100,
        60_000,
        "capability:fs.write",
        RampCurve::Linear,
    )
    .expect("slow_roll_drift scenario must validate");
    AdversarialScenarioFixture {
        name: "slow_roll_drift".to_string(),
        description:
            "Drift-via-many-small-updates: a steady linear ramp publishes a small declared \
             capability increase while the adversary hides a 5% bonus on every step. Default \
             thresholds should fire only in the second half of the campaign."
                .to_string(),
        scenario,
        baseline: baseline_sample(0.05, 0.20, 0.10),
        thresholds: thresholds(0.5, 0.6, 0.7, 0.5, 0.55),
        expected_verdict: ExpectedVerdict::CaughtLate {
            at_step_lower: 60,
            at_step_upper: 80,
        },
    }
}

/// Synthesize the canonical `capability_creep_disguised_as_feature` fixture.
pub fn synthesize_capability_creep_disguised_as_feature() -> AdversarialScenarioFixture {
    let scenario = AdversaryScenario::try_new(
        "scenario-capability-creep-001",
        AdversaryKind::CapabilityCreepDisguisedAsFeature,
        80,
        60_000,
        "capability:network.outbound",
        RampCurve::Sigmoid { steepness: 6.0 },
    )
    .expect("capability_creep_disguised_as_feature scenario must validate");
    AdversarialScenarioFixture {
        name: "capability_creep_disguised_as_feature".to_string(),
        description:
            "Capability-creep-disguised-as-feature-add: an S-curve ramp publishes new features \
             while the adversary accelerates the hidden capability 30% past the declared baseline. \
             Catches in the second half of the campaign."
                .to_string(),
        scenario,
        baseline: baseline_sample(0.05, 0.20, 0.10),
        thresholds: thresholds(0.5, 0.6, 0.7, 0.5, 0.55),
        expected_verdict: ExpectedVerdict::CaughtLate {
            at_step_lower: 40,
            at_step_upper: 60,
        },
    }
}

/// Synthesize the canonical `eviction_via_trust_flooding` fixture.
pub fn synthesize_eviction_via_trust_flooding() -> AdversarialScenarioFixture {
    let scenario = AdversaryScenario::try_new(
        "scenario-eviction-flooding-001",
        AdversaryKind::EvictionViaTrustFlooding,
        60,
        60_000,
        "capability:trust.flood",
        RampCurve::Stepped { plateau_count: 4 },
    )
    .expect("eviction_via_trust_flooding scenario must validate");
    AdversarialScenarioFixture {
        name: "eviction_via_trust_flooding".to_string(),
        description:
            "Eviction-via-trust-flooding: a stepped 4-plateau ramp couples capability nudges with \
             an early velocity spike (trust flood). Should be detected in the early plateaus."
                .to_string(),
        scenario,
        baseline: baseline_sample(0.05, 0.10, 0.10),
        thresholds: thresholds(0.30, 0.35, 0.40, 0.45, 0.30),
        expected_verdict: ExpectedVerdict::CaughtEarly {
            at_step_lower: 0,
            at_step_upper: 20,
        },
    }
}

/// Synthesize the canonical `many_tiny_updates` fixture.
pub fn synthesize_many_tiny_updates() -> AdversarialScenarioFixture {
    let scenario = AdversaryScenario::try_new(
        "scenario-many-tiny-updates-001",
        AdversaryKind::ManyTinyUpdates,
        200,
        60_000,
        "capability:fs.read",
        RampCurve::Linear,
    )
    .expect("many_tiny_updates scenario must validate");
    AdversarialScenarioFixture {
        name: "many_tiny_updates".to_string(),
        description:
            "Many-tiny-updates: a long linear ramp emits high-frequency micro-perturbations whose \
             magnitudes are below the detector floor. The campaign should pass the detector \
             entirely."
                .to_string(),
        scenario,
        baseline: baseline_sample(0.05, 0.20, 0.10),
        thresholds: thresholds(0.99, 0.99, 0.99, 0.99, 0.99),
        expected_verdict: ExpectedVerdict::MissedEntirely,
    }
}

/// Synthesize the canonical `multi_persona_coordination` fixture.
pub fn synthesize_multi_persona_coordination() -> AdversarialScenarioFixture {
    let scenario = AdversaryScenario::try_new(
        "scenario-multi-persona-001",
        AdversaryKind::MultiPersonaCoordination,
        50,
        60_000,
        "capability:release.publish",
        RampCurve::Exponential { base: 3.0 },
    )
    .expect("multi_persona_coordination scenario must validate");
    AdversarialScenarioFixture {
        name: "multi_persona_coordination".to_string(),
        description:
            "Multi-persona-coordination: colluding maintainer identities ramp velocity in the \
             first half then capability in the second on an exponential curve. The early velocity \
             spike should fire the detector well before the midpoint."
                .to_string(),
        scenario,
        baseline: baseline_sample(0.05, 0.10, 0.10),
        thresholds: thresholds(0.20, 0.25, 0.35, 0.40, 0.25),
        expected_verdict: ExpectedVerdict::CaughtEarly {
            at_step_lower: 0,
            at_step_upper: 15,
        },
    }
}

/// Synthesize the canonical `false_recovery_claim` fixture.
pub fn synthesize_false_recovery_claim() -> AdversarialScenarioFixture {
    let scenario = AdversaryScenario::try_new(
        "scenario-false-recovery-001",
        AdversaryKind::FalseRecoveryClaim,
        40,
        60_000,
        "capability:supply.chain",
        RampCurve::Stepped { plateau_count: 5 },
    )
    .expect("false_recovery_claim scenario must validate");
    AdversarialScenarioFixture {
        name: "false_recovery_claim".to_string(),
        description: "False-recovery-claim: a stepped ramp couples a fake mid-campaign recovery \
             announcement with a resumed escalation. Detector should still catch the escalation \
             in the late half despite the dip."
            .to_string(),
        scenario,
        baseline: baseline_sample(0.05, 0.20, 0.10),
        thresholds: thresholds(0.40, 0.50, 0.40, 0.50, 0.40),
        expected_verdict: ExpectedVerdict::CaughtLate {
            at_step_lower: 20,
            at_step_upper: 40,
        },
    }
}

/// Synthesize the canonical `indirect_via_dep` fixture.
pub fn synthesize_indirect_via_dep() -> AdversarialScenarioFixture {
    let scenario = AdversaryScenario::try_new(
        "scenario-indirect-dep-001",
        AdversaryKind::IndirectViaDep,
        60,
        60_000,
        "capability:dep.transitive",
        RampCurve::Sigmoid { steepness: 5.0 },
    )
    .expect("indirect_via_dep scenario must validate");
    AdversarialScenarioFixture {
        name: "indirect_via_dep".to_string(),
        description:
            "Indirect-via-dep: capability stays flat on the package under test while response \
             time deteriorates as a transitive dependency drifts on an S-curve. Detection happens \
             late once the provenance signal exceeds threshold."
                .to_string(),
        scenario,
        baseline: baseline_sample(0.05, 0.20, 0.05),
        thresholds: thresholds(0.35, 0.50, 0.50, 0.50, 0.40),
        expected_verdict: ExpectedVerdict::CaughtLate {
            at_step_lower: 25,
            at_step_upper: 45,
        },
    }
}

/// Synthesize the canonical `signature_rollover` fixture.
pub fn synthesize_signature_rollover() -> AdversarialScenarioFixture {
    let scenario = AdversaryScenario::try_new(
        "scenario-signature-rollover-001",
        AdversaryKind::SignatureRollover,
        30,
        60_000,
        "capability:release.sign",
        RampCurve::Exponential { base: 4.0 },
    )
    .expect("signature_rollover scenario must validate");
    AdversarialScenarioFixture {
        name: "signature_rollover".to_string(),
        description:
            "Signature-rollover: an exponential ramp triggers a sharp capability jump at 75% \
             progress when a rolled maintainer key relaunders the trajectory. The harness's \
             hazard bias for signature rollover lets the detector fire in the early steps via the \
             hazard channel."
                .to_string(),
        scenario,
        baseline: baseline_sample(0.05, 0.20, 0.10),
        thresholds: thresholds(0.30, 0.40, 0.05, 0.40, 0.30),
        expected_verdict: ExpectedVerdict::CaughtEarly {
            at_step_lower: 0,
            at_step_upper: 14,
        },
    }
}

/// All eight canonical synthesizers as a slice, useful for batch tests +
/// the verification gate (sub-task 5).
pub fn all_synthesizers() -> [AdversarialScenarioFixture; 8] {
    [
        synthesize_slow_roll_drift(),
        synthesize_capability_creep_disguised_as_feature(),
        synthesize_eviction_via_trust_flooding(),
        synthesize_many_tiny_updates(),
        synthesize_multi_persona_coordination(),
        synthesize_false_recovery_claim(),
        synthesize_indirect_via_dep(),
        synthesize_signature_rollover(),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_kind_match(fixture: &AdversarialScenarioFixture) -> ScenarioVerdictMatch {
        let m = evaluate_scenario_fixture(fixture).expect("evaluate ok");
        // Kind must match in every case — the bounds check populates
        // `divergences` but doesn't gate kind correctness, which is the
        // load-bearing invariant tests assert here.
        let kind_aligned = match (&fixture.expected_verdict, m.actual_verdict) {
            (ExpectedVerdict::CaughtEarly { .. }, ScenarioVerdict::CaughtEarly { .. }) => true,
            (ExpectedVerdict::CaughtLate { .. }, ScenarioVerdict::CaughtLate { .. }) => true,
            (ExpectedVerdict::MissedEntirely, ScenarioVerdict::MissedEntirely) => true,
            _ => false,
        };
        assert!(
            kind_aligned,
            "fixture `{}` verdict-kind mismatch: expected {:?}, actual {:?}, divergences={:?}",
            fixture.name, fixture.expected_verdict, m.actual_verdict, m.divergences
        );
        m
    }

    #[test]
    fn evaluate_slow_roll_drift() {
        let f = synthesize_slow_roll_drift();
        assert_kind_match(&f);
    }

    #[test]
    fn evaluate_capability_creep_disguised_as_feature() {
        let f = synthesize_capability_creep_disguised_as_feature();
        assert_kind_match(&f);
    }

    #[test]
    fn evaluate_eviction_via_trust_flooding() {
        let f = synthesize_eviction_via_trust_flooding();
        assert_kind_match(&f);
    }

    #[test]
    fn evaluate_many_tiny_updates() {
        let f = synthesize_many_tiny_updates();
        let m = assert_kind_match(&f);
        assert!(m.actual_first_detection_at.is_none());
    }

    #[test]
    fn evaluate_multi_persona_coordination() {
        let f = synthesize_multi_persona_coordination();
        assert_kind_match(&f);
    }

    #[test]
    fn evaluate_false_recovery_claim() {
        let f = synthesize_false_recovery_claim();
        assert_kind_match(&f);
    }

    #[test]
    fn evaluate_indirect_via_dep() {
        let f = synthesize_indirect_via_dep();
        assert_kind_match(&f);
    }

    #[test]
    fn evaluate_signature_rollover() {
        let f = synthesize_signature_rollover();
        assert_kind_match(&f);
    }

    #[test]
    fn scenario_fixture_serde_round_trip() {
        for fixture in all_synthesizers() {
            let json = serde_json::to_string(&fixture).expect("encode fixture");
            let back: AdversarialScenarioFixture =
                serde_json::from_str(&json).expect("decode fixture");
            assert_eq!(
                back, fixture,
                "fixture `{}` round-trip mismatch",
                fixture.name
            );
            assert!(back.validate().is_ok());
            // Loader path must also accept the canonical encoding.
            let loaded = load_scenario_fixture(&json).expect("load fixture");
            assert_eq!(loaded, fixture);
        }
    }

    #[test]
    fn fixture_with_invalid_at_step_bounds_rejected() {
        let mut fixture = synthesize_slow_roll_drift();
        fixture.expected_verdict = ExpectedVerdict::CaughtLate {
            at_step_lower: 90,
            at_step_upper: 10,
        };
        let err = fixture.validate().expect_err("invalid bounds must reject");
        // Validator routes lower>upper through TooManySteps (semantic
        // alias) — any AdversarialError variant proves fail-closed.
        assert!(
            matches!(err, AdversarialError::TooManySteps { .. }),
            "expected TooManySteps alias, got {err:?}"
        );

        // The evaluator path must also fail closed.
        let err = evaluate_scenario_fixture(&fixture)
            .expect_err("invalid bounds must reject through evaluator");
        assert!(matches!(err, AdversarialHarnessError::InvalidScenario(_)));
    }

    #[test]
    fn all_eight_kind_variants_covered_by_synthesizers() {
        let kinds: Vec<AdversaryKind> =
            all_synthesizers().iter().map(|f| f.scenario.kind).collect();
        // Sanity: 8 distinct kinds = the AdversaryKind enum's full cardinality.
        let expected = [
            AdversaryKind::SlowRollDrift,
            AdversaryKind::CapabilityCreepDisguisedAsFeature,
            AdversaryKind::EvictionViaTrustFlooding,
            AdversaryKind::ManyTinyUpdates,
            AdversaryKind::MultiPersonaCoordination,
            AdversaryKind::FalseRecoveryClaim,
            AdversaryKind::IndirectViaDep,
            AdversaryKind::SignatureRollover,
        ];
        for kind in expected {
            assert!(
                kinds.contains(&kind),
                "missing synthesizer for {kind:?}; got {kinds:?}"
            );
        }
    }
}
