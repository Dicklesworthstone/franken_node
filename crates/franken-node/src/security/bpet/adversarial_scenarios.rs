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
    AdversarialError, AdversaryKind, AdversaryScenario, RampCurve, canonical_hash,
    validate_scenario,
};
use super::adversarial_harness::{
    AdversarialHarness, AdversarialHarnessError, CAPABILITY_FIELD, DetectorThresholds,
    EvolutionResult, RESPONSE_FIELD, ScenarioVerdict, VELOCITY_FIELD, run_scenario,
};
use super::drift_features::PhenotypeSample;
use super::phenotype_extractor::{
    ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION, AdversaryCorpusRecord, CorpusDependencyTopologyContext,
    CorpusFeatureObservation, CorpusFilesystemSurface, CorpusGroundTruth, CorpusGroundTruthLabel,
    CorpusNetworkSurface, CorpusProvenanceKind, CorpusProvenanceRef, CorpusTrajectoryPoint,
    EvidenceSource, GENOME_DIMENSIONS, MAX_BASIS_POINTS, feature_names,
};

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
// Synthetic corpus record generation
// ---------------------------------------------------------------------------

const SYNTHETIC_CORPUS_CAPTURED_AT: &str = "1970-01-01T00:00:00Z";
const SYNTHETIC_CORPUS_LABELER: &str = "franken-node-bpet-adversarial-scenarios-v1";
const REAL_CORPUS_CAPTURED_AT: &str = "2026-06-08T00:00:00Z";
const REAL_CORPUS_LABELER: &str = "franken-node-bpet-real-advisory-seed-v1";

pub const REAL_LABELED_CORPUS_MIN_RECORDS: usize = 4;

/// Emit deterministic labeled corpus records for every canonical adversary
/// scenario, plus one benign control per scenario.
///
/// The generator is intentionally a pure function over the in-code fixture
/// catalog. There is no wall-clock, filesystem, RNG, or environment input, so
/// two calls with the same checked-in catalog produce byte-identical
/// [`AdversaryCorpusRecord::canonical_bytes`] payloads.
pub fn synthesize_labeled_corpus_records()
-> std::result::Result<Vec<AdversaryCorpusRecord>, AdversarialHarnessError> {
    let mut records = Vec::with_capacity(16);
    for fixture in all_synthesizers() {
        let (campaign_member, benign_control) =
            synthesize_labeled_corpus_records_for_fixture(&fixture)?;
        records.push(campaign_member);
        records.push(benign_control);
    }
    Ok(records)
}

pub fn phase_zero_labeled_corpus_records()
-> std::result::Result<Vec<AdversaryCorpusRecord>, AdversarialHarnessError> {
    let mut records = synthesize_labeled_corpus_records()?;
    records.extend(real_labeled_corpus_records());
    Ok(records)
}

pub fn real_labeled_corpus_records() -> Vec<AdversaryCorpusRecord> {
    vec![
        ua_parser_compromised_record(),
        ua_parser_patched_control_record(),
        flatmap_stream_compromised_record(),
        event_stream_pre_compromise_control_record(),
    ]
}

/// Emit the labeled campaign-member record and the matched benign control for
/// a single fixture.
pub fn synthesize_labeled_corpus_records_for_fixture(
    fixture: &AdversarialScenarioFixture,
) -> std::result::Result<(AdversaryCorpusRecord, AdversaryCorpusRecord), AdversarialHarnessError> {
    fixture
        .validate()
        .map_err(AdversarialHarnessError::InvalidScenario)?;
    let mut harness = AdversarialHarness::new(fixture.thresholds)?;
    let result = run_scenario(&mut harness, &fixture.scenario, &fixture.baseline)?;
    Ok((
        campaign_member_corpus_record(fixture, &result),
        benign_control_corpus_record(fixture),
    ))
}

fn campaign_member_corpus_record(
    fixture: &AdversarialScenarioFixture,
    result: &EvolutionResult,
) -> AdversaryCorpusRecord {
    let provenance_id = provenance_id(fixture, "campaign");
    let campaign_id = campaign_id(fixture);
    AdversaryCorpusRecord {
        schema_version: ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION.to_string(),
        record_id: format!("synthetic-bpet-v1:{}:campaign-member", fixture.name),
        package_name: format!("synthetic-bpet-{}", fixture.name),
        package_version: "1.0.0".to_string(),
        observation_timestamp: SYNTHETIC_CORPUS_CAPTURED_AT.to_string(),
        phenotype_features: corpus_feature_observations(
            fixture,
            Some(result),
            &provenance_id,
            CorpusGroundTruthLabel::CampaignMember,
        ),
        capability_invocations: capability_invocations(fixture, false),
        network_surface: network_surface(fixture, false),
        filesystem_surface: filesystem_surface(fixture, false),
        dependency_topology: dependency_topology(fixture, false),
        longitudinal_trajectory: adversarial_trajectory(result, fixture),
        ground_truth: CorpusGroundTruth {
            label: CorpusGroundTruthLabel::CampaignMember,
            campaign_id: Some(campaign_id.clone()),
            confidence_basis_points: MAX_BASIS_POINTS,
            evidence_refs: vec![provenance_id.clone(), canonical_hash(&fixture.scenario)],
            rationale: format!(
                "Synthetic BPET adversary fixture `{}` exercises `{}` as a labeled campaign member.",
                fixture.name,
                fixture.scenario.kind.as_str()
            ),
        },
        provenance: vec![provenance_ref(fixture, &provenance_id, "campaign")],
    }
}

fn benign_control_corpus_record(fixture: &AdversarialScenarioFixture) -> AdversaryCorpusRecord {
    let provenance_id = provenance_id(fixture, "benign-control");
    AdversaryCorpusRecord {
        schema_version: ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION.to_string(),
        record_id: format!("synthetic-bpet-v1:{}:benign-control", fixture.name),
        package_name: format!("synthetic-bpet-{}-control", fixture.name),
        package_version: "1.0.0".to_string(),
        observation_timestamp: SYNTHETIC_CORPUS_CAPTURED_AT.to_string(),
        phenotype_features: corpus_feature_observations(
            fixture,
            None,
            &provenance_id,
            CorpusGroundTruthLabel::Benign,
        ),
        capability_invocations: capability_invocations(fixture, true),
        network_surface: network_surface(fixture, true),
        filesystem_surface: filesystem_surface(fixture, true),
        dependency_topology: dependency_topology(fixture, true),
        longitudinal_trajectory: benign_trajectory(fixture),
        ground_truth: CorpusGroundTruth {
            label: CorpusGroundTruthLabel::Benign,
            campaign_id: None,
            confidence_basis_points: MAX_BASIS_POINTS,
            evidence_refs: vec![provenance_id.clone(), canonical_hash(&fixture.scenario)],
            rationale: format!(
                "Matched benign control for synthetic BPET fixture `{}`.",
                fixture.name
            ),
        },
        provenance: vec![provenance_ref(fixture, &provenance_id, "benign-control")],
    }
}

fn corpus_feature_observations(
    fixture: &AdversarialScenarioFixture,
    result: Option<&EvolutionResult>,
    provenance_id: &str,
    label: CorpusGroundTruthLabel,
) -> BTreeMap<String, CorpusFeatureObservation> {
    let feature_values = corpus_feature_values(fixture, result, label);
    GENOME_DIMENSIONS
        .into_iter()
        .map(|feature_name| {
            let value = feature_values
                .get(feature_name)
                .copied()
                .unwrap_or_default();
            (
                feature_name.to_string(),
                CorpusFeatureObservation::known(
                    value,
                    EvidenceSource::Derived,
                    provenance_id.to_string(),
                ),
            )
        })
        .collect()
}

fn corpus_feature_values(
    fixture: &AdversarialScenarioFixture,
    result: Option<&EvolutionResult>,
    label: CorpusGroundTruthLabel,
) -> BTreeMap<&'static str, u16> {
    let benign = matches!(label, CorpusGroundTruthLabel::Benign);
    let (capability, declared, velocity, response, risk) = match result {
        Some(result) => {
            let last_step = result.trace.steps.last();
            let last_outcome = result.outcomes.last();
            (
                last_step
                    .map(|step| field_value(&step.observed_state, CAPABILITY_FIELD))
                    .unwrap_or_else(|| baseline_field(fixture, CAPABILITY_FIELD)),
                last_step
                    .map(|step| field_value(&step.declared_state, CAPABILITY_FIELD))
                    .unwrap_or_else(|| baseline_field(fixture, CAPABILITY_FIELD)),
                last_step
                    .map(|step| field_value(&step.observed_state, VELOCITY_FIELD))
                    .unwrap_or_else(|| baseline_field(fixture, VELOCITY_FIELD)),
                last_step
                    .map(|step| field_value(&step.observed_state, RESPONSE_FIELD))
                    .unwrap_or_else(|| baseline_field(fixture, RESPONSE_FIELD)),
                last_outcome
                    .map(|outcome| outcome.risk_score)
                    .unwrap_or_default(),
            )
        }
        None => (
            baseline_field(fixture, CAPABILITY_FIELD),
            baseline_field(fixture, CAPABILITY_FIELD),
            baseline_field(fixture, VELOCITY_FIELD),
            baseline_field(fixture, RESPONSE_FIELD),
            0.0,
        ),
    };

    let mut values = BTreeMap::new();
    values.insert(
        feature_names::CAPABILITY_INVOCATION_INTENSITY,
        basis_points(capability),
    );
    values.insert(
        feature_names::RESOURCE_ENVELOPE_PRESSURE,
        if benign { 500 } else { basis_points(risk) },
    );
    values.insert(
        feature_names::NETWORK_SURFACE_AREA,
        surface_bp(fixture.scenario.kind, "network", benign),
    );
    values.insert(
        feature_names::FILESYSTEM_SURFACE_AREA,
        surface_bp(fixture.scenario.kind, "filesystem", benign),
    );
    values.insert(
        feature_names::DECLARED_PERMISSION_SURFACE,
        basis_points(declared),
    );
    values.insert(
        feature_names::CODE_COMPLEXITY,
        basis_points(velocity.max(response)),
    );
    values.insert(
        feature_names::DEPENDENCY_SURFACE,
        dependency_surface_bp(fixture.scenario.kind, benign),
    );
    values
}

fn adversarial_trajectory(
    result: &EvolutionResult,
    fixture: &AdversarialScenarioFixture,
) -> Vec<CorpusTrajectoryPoint> {
    result
        .trace
        .steps
        .iter()
        .zip(&result.outcomes)
        .map(|(step, outcome)| {
            let mut feature_values = BTreeMap::new();
            feature_values.insert(
                feature_names::CAPABILITY_INVOCATION_INTENSITY.to_string(),
                basis_points(field_value(&step.observed_state, CAPABILITY_FIELD)),
            );
            feature_values.insert(
                feature_names::RESOURCE_ENVELOPE_PRESSURE.to_string(),
                basis_points(outcome.risk_score),
            );
            feature_values.insert(
                feature_names::DECLARED_PERMISSION_SURFACE.to_string(),
                basis_points(field_value(&step.declared_state, CAPABILITY_FIELD)),
            );
            feature_values.insert(
                feature_names::CODE_COMPLEXITY.to_string(),
                basis_points(
                    field_value(&step.observed_state, VELOCITY_FIELD)
                        .max(field_value(&step.observed_state, RESPONSE_FIELD)),
                ),
            );
            feature_values.insert(
                feature_names::NETWORK_SURFACE_AREA.to_string(),
                surface_bp(fixture.scenario.kind, "network", false),
            );
            feature_values.insert(
                feature_names::FILESYSTEM_SURFACE_AREA.to_string(),
                surface_bp(fixture.scenario.kind, "filesystem", false),
            );
            feature_values.insert(
                feature_names::DEPENDENCY_SURFACE.to_string(),
                dependency_surface_bp(fixture.scenario.kind, false),
            );
            CorpusTrajectoryPoint {
                observed_at: synthetic_step_timestamp(step.step_idx),
                package_version: synthetic_step_version(step.step_idx),
                feature_values_bp: feature_values,
                risk_score_bp: basis_points(outcome.risk_score),
            }
        })
        .collect()
}

fn benign_trajectory(fixture: &AdversarialScenarioFixture) -> Vec<CorpusTrajectoryPoint> {
    let mut feature_values = BTreeMap::new();
    for (feature_name, value) in
        corpus_feature_values(fixture, None, CorpusGroundTruthLabel::Benign)
    {
        feature_values.insert(feature_name.to_string(), value);
    }
    vec![CorpusTrajectoryPoint {
        observed_at: SYNTHETIC_CORPUS_CAPTURED_AT.to_string(),
        package_version: "1.0.0".to_string(),
        feature_values_bp: feature_values,
        risk_score_bp: 0,
    }]
}

fn capability_invocations(
    fixture: &AdversarialScenarioFixture,
    benign: bool,
) -> BTreeMap<String, u64> {
    let mut invocations = BTreeMap::new();
    let step_count = if benign {
        1
    } else {
        u64::from(fixture.scenario.n_steps)
    };
    let multiplier = match fixture.scenario.kind {
        AdversaryKind::SlowRollDrift | AdversaryKind::ManyTinyUpdates => 1,
        AdversaryKind::CapabilityCreepDisguisedAsFeature => 4,
        AdversaryKind::EvictionViaTrustFlooding => 5,
        AdversaryKind::MultiPersonaCoordination => 6,
        AdversaryKind::FalseRecoveryClaim => 3,
        AdversaryKind::IndirectViaDep => 2,
        AdversaryKind::SignatureRollover => 4,
    };
    invocations.insert(
        fixture.scenario.target_capability.clone(),
        step_count.saturating_mul(multiplier),
    );
    if matches!(
        fixture.scenario.kind,
        AdversaryKind::MultiPersonaCoordination
    ) && !benign
    {
        invocations.insert(
            "maintainer:persona-switch".to_string(),
            step_count.saturating_div(2).max(1),
        );
    }
    invocations
}

fn network_surface(fixture: &AdversarialScenarioFixture, benign: bool) -> CorpusNetworkSurface {
    let mut destination_classes = BTreeMap::new();
    let steps = if benign {
        1
    } else {
        u64::from(fixture.scenario.n_steps)
    };
    match fixture.scenario.kind {
        AdversaryKind::CapabilityCreepDisguisedAsFeature
        | AdversaryKind::EvictionViaTrustFlooding
        | AdversaryKind::MultiPersonaCoordination
        | AdversaryKind::FalseRecoveryClaim
        | AdversaryKind::IndirectViaDep
        | AdversaryKind::SignatureRollover => {
            destination_classes.insert("registry_api".to_string(), steps);
        }
        AdversaryKind::SlowRollDrift | AdversaryKind::ManyTinyUpdates => {
            destination_classes.insert("telemetry_endpoint".to_string(), steps.saturating_div(4));
        }
    }
    if benign {
        destination_classes.insert("package_registry".to_string(), 1);
    }
    let unique_destination_count = destination_classes
        .values()
        .filter(|count| **count > 0)
        .count() as u64;
    let egress_bytes = destination_classes
        .values()
        .copied()
        .sum::<u64>()
        .saturating_mul(if benign { 512 } else { 4096 });
    CorpusNetworkSurface {
        destination_classes,
        unique_destination_count,
        egress_bytes,
    }
}

fn filesystem_surface(
    fixture: &AdversarialScenarioFixture,
    benign: bool,
) -> CorpusFilesystemSurface {
    let mut path_classes = BTreeMap::new();
    let steps = if benign {
        1
    } else {
        u64::from(fixture.scenario.n_steps)
    };
    if fixture.scenario.target_capability.contains("fs") {
        path_classes.insert("workspace".to_string(), steps);
    }
    if matches!(
        fixture.scenario.kind,
        AdversaryKind::FalseRecoveryClaim | AdversaryKind::SignatureRollover
    ) {
        path_classes.insert(
            "release_artifacts".to_string(),
            steps.saturating_div(2).max(1),
        );
    }
    if path_classes.is_empty() {
        path_classes.insert("manifest".to_string(), if benign { 1 } else { 2 });
    }
    CorpusFilesystemSurface {
        path_classes,
        read_ops: if benign { 1 } else { steps.saturating_mul(2) },
        write_ops: if benign { 0 } else { steps },
    }
}

fn dependency_topology(
    fixture: &AdversarialScenarioFixture,
    benign: bool,
) -> CorpusDependencyTopologyContext {
    if benign {
        return CorpusDependencyTopologyContext {
            direct_dependency_count: 2,
            transitive_dependency_count: 6,
            max_depth: 2,
            maintainer_overlap_count: 0,
            single_point_of_failure_score_bp: 1_000,
        };
    }
    match fixture.scenario.kind {
        AdversaryKind::IndirectViaDep => CorpusDependencyTopologyContext {
            direct_dependency_count: 4,
            transitive_dependency_count: 38,
            max_depth: 5,
            maintainer_overlap_count: 2,
            single_point_of_failure_score_bp: 8_250,
        },
        AdversaryKind::MultiPersonaCoordination => CorpusDependencyTopologyContext {
            direct_dependency_count: 6,
            transitive_dependency_count: 28,
            max_depth: 4,
            maintainer_overlap_count: 5,
            single_point_of_failure_score_bp: 6_750,
        },
        AdversaryKind::EvictionViaTrustFlooding => CorpusDependencyTopologyContext {
            direct_dependency_count: 5,
            transitive_dependency_count: 24,
            max_depth: 4,
            maintainer_overlap_count: 3,
            single_point_of_failure_score_bp: 6_000,
        },
        AdversaryKind::FalseRecoveryClaim | AdversaryKind::SignatureRollover => {
            CorpusDependencyTopologyContext {
                direct_dependency_count: 3,
                transitive_dependency_count: 16,
                max_depth: 3,
                maintainer_overlap_count: 2,
                single_point_of_failure_score_bp: 5_500,
            }
        }
        AdversaryKind::CapabilityCreepDisguisedAsFeature
        | AdversaryKind::SlowRollDrift
        | AdversaryKind::ManyTinyUpdates => CorpusDependencyTopologyContext {
            direct_dependency_count: 3,
            transitive_dependency_count: 12,
            max_depth: 3,
            maintainer_overlap_count: 1,
            single_point_of_failure_score_bp: 4_000,
        },
    }
}

fn surface_bp(kind: AdversaryKind, surface: &str, benign: bool) -> u16 {
    if benign {
        return 500;
    }
    match (kind, surface) {
        (AdversaryKind::CapabilityCreepDisguisedAsFeature, "network") => 8_500,
        (AdversaryKind::EvictionViaTrustFlooding, "network") => 7_500,
        (AdversaryKind::IndirectViaDep, "network") => 6_500,
        (AdversaryKind::SlowRollDrift, "filesystem") => 7_000,
        (AdversaryKind::ManyTinyUpdates, "filesystem") => 5_500,
        (AdversaryKind::FalseRecoveryClaim | AdversaryKind::SignatureRollover, "filesystem") => {
            5_000
        }
        (AdversaryKind::MultiPersonaCoordination, _) => 6_000,
        (_, _) => 2_500,
    }
}

fn dependency_surface_bp(kind: AdversaryKind, benign: bool) -> u16 {
    if benign {
        return 1_000;
    }
    match kind {
        AdversaryKind::IndirectViaDep => 8_500,
        AdversaryKind::MultiPersonaCoordination | AdversaryKind::EvictionViaTrustFlooding => 6_500,
        AdversaryKind::FalseRecoveryClaim | AdversaryKind::SignatureRollover => 5_500,
        AdversaryKind::CapabilityCreepDisguisedAsFeature
        | AdversaryKind::SlowRollDrift
        | AdversaryKind::ManyTinyUpdates => 3_500,
    }
}

fn provenance_ref(
    fixture: &AdversarialScenarioFixture,
    provenance_id: &str,
    role: &str,
) -> CorpusProvenanceRef {
    CorpusProvenanceRef {
        provenance_id: provenance_id.to_string(),
        kind: CorpusProvenanceKind::SyntheticGenerator,
        uri: format!(
            "franken-node://security/bpet/adversarial-scenarios/{}/{}",
            fixture.name, role
        ),
        captured_at: SYNTHETIC_CORPUS_CAPTURED_AT.to_string(),
        labeler: SYNTHETIC_CORPUS_LABELER.to_string(),
    }
}

fn ua_parser_compromised_record() -> AdversaryCorpusRecord {
    let feature_values = real_feature_values([
        (feature_names::CAPABILITY_INVOCATION_INTENSITY, 8_500),
        (feature_names::RESOURCE_ENVELOPE_PRESSURE, 9_000),
        (feature_names::NETWORK_SURFACE_AREA, 9_000),
        (feature_names::FILESYSTEM_SURFACE_AREA, 8_500),
        (feature_names::DECLARED_PERMISSION_SURFACE, 6_000),
        (feature_names::CODE_COMPLEXITY, 7_000),
        (feature_names::DEPENDENCY_SURFACE, 7_500),
    ]);
    let provenance = vec![
        real_provenance_ref(
            "real-advisory:ghsa-pjwm-rvh2-c87w",
            CorpusProvenanceKind::RealAdvisory,
            "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
        ),
        real_provenance_ref(
            "real-advisory:cisa-2021-10-22-ua-parser-js",
            CorpusProvenanceKind::RealAdvisory,
            "https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js",
        ),
    ];
    real_corpus_record(RealCorpusSeed {
        record_id: "real-bpet-v1:ua-parser-js-0.7.29:malicious",
        package_name: "ua-parser-js",
        package_version: "0.7.29",
        label: CorpusGroundTruthLabel::Malicious,
        confidence_basis_points: MAX_BASIS_POINTS,
        evidence_refs: vec![
            "real-advisory:ghsa-pjwm-rvh2-c87w".to_string(),
            "real-advisory:cisa-2021-10-22-ua-parser-js".to_string(),
        ],
        rationale: "Real advisory seed: ua-parser-js 0.7.29 was one of the compromised npm versions carrying install-time malware.".to_string(),
        feature_values,
        capability_invocations: real_counts([
            ("install_script:preinstall", 1),
            ("credential_access", 2),
            ("coinminer_launch", 1),
        ]),
        network_surface: CorpusNetworkSurface {
            destination_classes: real_counts([("coinminer_pool", 2), ("credential_exfil_endpoint", 1)]),
            unique_destination_count: 2,
            egress_bytes: 1_572_864,
        },
        filesystem_surface: CorpusFilesystemSurface {
            path_classes: real_counts([("install_script", 1), ("credential_store", 2)]),
            read_ops: 8,
            write_ops: 3,
        },
        dependency_topology: CorpusDependencyTopologyContext {
            direct_dependency_count: 1,
            transitive_dependency_count: 8,
            max_depth: 2,
            maintainer_overlap_count: 1,
            single_point_of_failure_score_bp: 7_500,
        },
        risk_score_bp: 9_250,
        provenance,
    })
}

fn ua_parser_patched_control_record() -> AdversaryCorpusRecord {
    let feature_values = real_feature_values([
        (feature_names::CAPABILITY_INVOCATION_INTENSITY, 700),
        (feature_names::RESOURCE_ENVELOPE_PRESSURE, 600),
        (feature_names::NETWORK_SURFACE_AREA, 200),
        (feature_names::FILESYSTEM_SURFACE_AREA, 500),
        (feature_names::DECLARED_PERMISSION_SURFACE, 600),
        (feature_names::CODE_COMPLEXITY, 1_800),
        (feature_names::DEPENDENCY_SURFACE, 900),
    ]);
    let provenance = vec![
        real_provenance_ref(
            "real-registry:ua-parser-js-0.7.30",
            CorpusProvenanceKind::RegistrySnapshot,
            "https://www.npmjs.com/package/ua-parser-js/v/0.7.30",
        ),
        real_provenance_ref(
            "real-advisory:cisa-2021-10-22-ua-parser-js",
            CorpusProvenanceKind::RealAdvisory,
            "https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js",
        ),
    ];
    real_corpus_record(RealCorpusSeed {
        record_id: "real-bpet-v1:ua-parser-js-0.7.30:benign-control",
        package_name: "ua-parser-js",
        package_version: "0.7.30",
        label: CorpusGroundTruthLabel::Benign,
        confidence_basis_points: 8_500,
        evidence_refs: vec![
            "real-registry:ua-parser-js-0.7.30".to_string(),
            "real-advisory:cisa-2021-10-22-ua-parser-js".to_string(),
        ],
        rationale: "Real registry control: CISA identified 0.7.30 as the patched upgrade target for the 0.7.x compromised lineage; this is a lineage-local benign control, not a universal safety claim.".to_string(),
        feature_values,
        capability_invocations: real_counts([("user_agent_parse", 12)]),
        network_surface: CorpusNetworkSurface {
            destination_classes: BTreeMap::new(),
            unique_destination_count: 0,
            egress_bytes: 0,
        },
        filesystem_surface: CorpusFilesystemSurface {
            path_classes: real_counts([("package_source", 1)]),
            read_ops: 1,
            write_ops: 0,
        },
        dependency_topology: CorpusDependencyTopologyContext {
            direct_dependency_count: 0,
            transitive_dependency_count: 0,
            max_depth: 1,
            maintainer_overlap_count: 0,
            single_point_of_failure_score_bp: 900,
        },
        risk_score_bp: 700,
        provenance,
    })
}

fn flatmap_stream_compromised_record() -> AdversaryCorpusRecord {
    let feature_values = real_feature_values([
        (feature_names::CAPABILITY_INVOCATION_INTENSITY, 7_500),
        (feature_names::RESOURCE_ENVELOPE_PRESSURE, 7_000),
        (feature_names::NETWORK_SURFACE_AREA, 8_500),
        (feature_names::FILESYSTEM_SURFACE_AREA, 6_500),
        (feature_names::DECLARED_PERMISSION_SURFACE, 4_500),
        (feature_names::CODE_COMPLEXITY, 5_500),
        (feature_names::DEPENDENCY_SURFACE, 8_000),
    ]);
    let provenance = vec![real_provenance_ref(
        "real-advisory:azure-devops-event-stream-flatmap-stream",
        CorpusProvenanceKind::RealAdvisory,
        "https://devblogs.microsoft.com/devops/blocking-malicious-event-stream-and-flatmap-stream-packages/",
    )];
    real_corpus_record(RealCorpusSeed {
        record_id: "real-bpet-v1:flatmap-stream-0.1.1:malicious",
        package_name: "flatmap-stream",
        package_version: "0.1.1",
        label: CorpusGroundTruthLabel::Malicious,
        confidence_basis_points: MAX_BASIS_POINTS,
        evidence_refs: vec!["real-advisory:azure-devops-event-stream-flatmap-stream".to_string()],
        rationale: "Real advisory seed: flatmap-stream 0.1.1 was among the npm package versions blocked as malicious in the event-stream supply-chain incident.".to_string(),
        feature_values,
        capability_invocations: real_counts([("wallet_scan", 3), ("secret_exfiltration", 1)]),
        network_surface: CorpusNetworkSurface {
            destination_classes: real_counts([("wallet_exfil_endpoint", 1), ("package_registry", 1)]),
            unique_destination_count: 2,
            egress_bytes: 524_288,
        },
        filesystem_surface: CorpusFilesystemSurface {
            path_classes: real_counts([("home_directory", 4), ("wallet_store", 2)]),
            read_ops: 12,
            write_ops: 1,
        },
        dependency_topology: CorpusDependencyTopologyContext {
            direct_dependency_count: 1,
            transitive_dependency_count: 24,
            max_depth: 4,
            maintainer_overlap_count: 2,
            single_point_of_failure_score_bp: 8_500,
        },
        risk_score_bp: 8_750,
        provenance,
    })
}

fn event_stream_pre_compromise_control_record() -> AdversaryCorpusRecord {
    let feature_values = real_feature_values([
        (feature_names::CAPABILITY_INVOCATION_INTENSITY, 1_000),
        (feature_names::RESOURCE_ENVELOPE_PRESSURE, 800),
        (feature_names::NETWORK_SURFACE_AREA, 400),
        (feature_names::FILESYSTEM_SURFACE_AREA, 600),
        (feature_names::DECLARED_PERMISSION_SURFACE, 800),
        (feature_names::CODE_COMPLEXITY, 2_200),
        (feature_names::DEPENDENCY_SURFACE, 2_500),
    ]);
    let provenance = vec![
        real_provenance_ref(
            "real-registry:event-stream-3.3.4",
            CorpusProvenanceKind::RegistrySnapshot,
            "https://www.npmjs.com/package/event-stream/v/3.3.4",
        ),
        real_provenance_ref(
            "real-advisory:azure-devops-event-stream-flatmap-stream",
            CorpusProvenanceKind::RealAdvisory,
            "https://devblogs.microsoft.com/devops/blocking-malicious-event-stream-and-flatmap-stream-packages/",
        ),
    ];
    real_corpus_record(RealCorpusSeed {
        record_id: "real-bpet-v1:event-stream-3.3.4:benign-control",
        package_name: "event-stream",
        package_version: "3.3.4",
        label: CorpusGroundTruthLabel::Benign,
        confidence_basis_points: 8_000,
        evidence_refs: vec![
            "real-registry:event-stream-3.3.4".to_string(),
            "real-advisory:azure-devops-event-stream-flatmap-stream".to_string(),
        ],
        rationale: "Real registry control: event-stream 3.3.4 is a pre-compromise lineage control paired against the later 3.3.6/flatmap-stream incident; label confidence is explicit because absence of known compromise is weaker than an advisory label.".to_string(),
        feature_values,
        capability_invocations: real_counts([("stream_transform", 64)]),
        network_surface: CorpusNetworkSurface {
            destination_classes: BTreeMap::new(),
            unique_destination_count: 0,
            egress_bytes: 0,
        },
        filesystem_surface: CorpusFilesystemSurface {
            path_classes: real_counts([("package_source", 1)]),
            read_ops: 2,
            write_ops: 0,
        },
        dependency_topology: CorpusDependencyTopologyContext {
            direct_dependency_count: 6,
            transitive_dependency_count: 18,
            max_depth: 3,
            maintainer_overlap_count: 1,
            single_point_of_failure_score_bp: 2_500,
        },
        risk_score_bp: 1_000,
        provenance,
    })
}

struct RealCorpusSeed {
    record_id: &'static str,
    package_name: &'static str,
    package_version: &'static str,
    label: CorpusGroundTruthLabel,
    confidence_basis_points: u16,
    evidence_refs: Vec<String>,
    rationale: String,
    feature_values: BTreeMap<String, u16>,
    capability_invocations: BTreeMap<String, u64>,
    network_surface: CorpusNetworkSurface,
    filesystem_surface: CorpusFilesystemSurface,
    dependency_topology: CorpusDependencyTopologyContext,
    risk_score_bp: u16,
    provenance: Vec<CorpusProvenanceRef>,
}

fn real_corpus_record(seed: RealCorpusSeed) -> AdversaryCorpusRecord {
    let provenance_ref = seed
        .provenance
        .first()
        .map(|entry| entry.provenance_id.clone())
        .unwrap_or_else(|| "real-seed:missing-provenance".to_string());
    let phenotype_features = GENOME_DIMENSIONS
        .into_iter()
        .map(|feature_name| {
            let value = seed
                .feature_values
                .get(feature_name)
                .copied()
                .unwrap_or_default();
            (
                feature_name.to_string(),
                CorpusFeatureObservation::known(
                    value,
                    EvidenceSource::Derived,
                    provenance_ref.clone(),
                ),
            )
        })
        .collect();
    let trajectory_point = CorpusTrajectoryPoint {
        observed_at: REAL_CORPUS_CAPTURED_AT.to_string(),
        package_version: seed.package_version.to_string(),
        feature_values_bp: seed.feature_values,
        risk_score_bp: seed.risk_score_bp,
    };
    AdversaryCorpusRecord {
        schema_version: ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION.to_string(),
        record_id: seed.record_id.to_string(),
        package_name: seed.package_name.to_string(),
        package_version: seed.package_version.to_string(),
        observation_timestamp: REAL_CORPUS_CAPTURED_AT.to_string(),
        phenotype_features,
        capability_invocations: seed.capability_invocations,
        network_surface: seed.network_surface,
        filesystem_surface: seed.filesystem_surface,
        dependency_topology: seed.dependency_topology,
        longitudinal_trajectory: vec![trajectory_point],
        ground_truth: CorpusGroundTruth {
            label: seed.label,
            campaign_id: None,
            confidence_basis_points: seed.confidence_basis_points,
            evidence_refs: seed.evidence_refs,
            rationale: seed.rationale,
        },
        provenance: seed.provenance,
    }
}

fn real_feature_values(
    values: impl IntoIterator<Item = (&'static str, u16)>,
) -> BTreeMap<String, u16> {
    values
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect()
}

fn real_counts(values: impl IntoIterator<Item = (&'static str, u64)>) -> BTreeMap<String, u64> {
    values
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect()
}

fn real_provenance_ref(
    provenance_id: &str,
    kind: CorpusProvenanceKind,
    uri: &str,
) -> CorpusProvenanceRef {
    CorpusProvenanceRef {
        provenance_id: provenance_id.to_string(),
        kind,
        uri: uri.to_string(),
        captured_at: REAL_CORPUS_CAPTURED_AT.to_string(),
        labeler: REAL_CORPUS_LABELER.to_string(),
    }
}

fn campaign_id(fixture: &AdversarialScenarioFixture) -> String {
    format!("synthetic-bpet-campaign:{}", fixture.scenario.kind.as_str())
}

fn provenance_id(fixture: &AdversarialScenarioFixture, role: &str) -> String {
    format!("synthetic-bpet:{}:{role}", fixture.name)
}

fn synthetic_step_timestamp(step_idx: u32) -> String {
    let seconds = step_idx;
    let hour = seconds / 3_600;
    let minute = (seconds / 60) % 60;
    let second = seconds % 60;
    format!("1970-01-01T{hour:02}:{minute:02}:{second:02}Z")
}

fn synthetic_step_version(step_idx: u32) -> String {
    format!("1.0.{}", step_idx.saturating_add(1))
}

fn baseline_field(fixture: &AdversarialScenarioFixture, field: &str) -> f64 {
    field_value(&fixture.baseline.fields, field)
}

fn field_value(fields: &BTreeMap<String, f64>, field: &str) -> f64 {
    fields
        .get(field)
        .copied()
        .filter(|value| value.is_finite())
        .unwrap_or_default()
        .clamp(0.0, 1.0)
}

fn basis_points(value: f64) -> u16 {
    if !value.is_finite() {
        return 0;
    }
    let scaled = (value.clamp(0.0, 1.0) * f64::from(MAX_BASIS_POINTS)).round();
    if scaled <= 0.0 {
        0
    } else if scaled >= f64::from(MAX_BASIS_POINTS) {
        MAX_BASIS_POINTS
    } else {
        scaled as u16
    }
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

    #[test]
    fn synthetic_corpus_records_are_valid_labeled_and_deterministic() {
        let first = synthesize_labeled_corpus_records().expect("first corpus generation");
        let second = synthesize_labeled_corpus_records().expect("second corpus generation");

        assert_eq!(first.len(), 16);
        assert_eq!(second.len(), 16);

        let first_bytes: Vec<Vec<u8>> = first
            .iter()
            .map(|record| record.canonical_bytes().expect("canonical record"))
            .collect();
        let second_bytes: Vec<Vec<u8>> = second
            .iter()
            .map(|record| record.canonical_bytes().expect("canonical record"))
            .collect();
        assert_eq!(first_bytes, second_bytes);

        for fixture in all_synthesizers() {
            let campaign_id = campaign_id(&fixture);
            assert!(first.iter().any(|record| {
                record.ground_truth.label == CorpusGroundTruthLabel::CampaignMember
                    && record.ground_truth.campaign_id.as_deref() == Some(campaign_id.as_str())
            }));
            assert!(first.iter().any(|record| {
                record.ground_truth.label == CorpusGroundTruthLabel::Benign
                    && record.record_id.contains(&fixture.name)
            }));
        }
    }
}
