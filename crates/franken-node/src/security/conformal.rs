//! Deterministic conformal calibration primitives for TNR risk scores.
//!
//! The module deliberately keeps every externally serialized value in integer
//! basis points. That preserves the canonical serializer's no-float contract
//! while still giving later Sentinel and verifier surfaces a stable split
//! conformal quantile artifact to recompute.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::connector::canonical_serializer::canonical_bytes;

pub const CONFORMAL_SAMPLE_SCHEMA_VERSION: &str = "conformal.score_sample.v1";
pub const CONFORMAL_FROZEN_QUANTILE_SCHEMA_VERSION: &str = "conformal.frozen_quantile_artifact.v1";
pub const CONFORMAL_ACI_STATE_SCHEMA_VERSION: &str = "conformal.aci_state.v1";
pub const CONFORMAL_GENERATED_AT: &str = "1970-01-01T00:00:00Z";
pub const MAX_BASIS_POINTS: u16 = 10_000;
pub const LABEL_BENIGN: &str = "benign";
pub const LABEL_POSITIVE: &str = "positive";

pub mod event_codes {
    pub const CONFORMAL_SET_EMITTED: &str = "FN-CONFORMAL-001";
    pub const ACI_QUANTILE_UPDATED: &str = "FN-CONFORMAL-002";
    pub const CONFORMAL_ARTIFACT_EMITTED: &str = "FN-CALIB-002";
}

#[derive(Debug, thiserror::Error)]
pub enum ConformalCalibrationError {
    #[error("conformal calibration sample set is empty")]
    EmptySamples,
    #[error("target alpha must be < 10000 basis points, got {0}")]
    InvalidTargetAlpha(u16),
    #[error("sample `{sample_id}` has invalid {field}: {reason}")]
    InvalidSample {
        sample_id: String,
        field: &'static str,
        reason: String,
    },
    #[error("duplicate sample id `{sample_id}` in risk class `{risk_class}`")]
    DuplicateSample {
        risk_class: String,
        sample_id: String,
    },
    #[error("risk class `{risk_class}` has no scored samples")]
    EmptyRiskClass { risk_class: String },
    #[error("missing conformal quantile for risk class `{risk_class}`")]
    MissingRiskClassQuantile { risk_class: String },
    #[error("risk class mismatch: quantile is `{expected}`, sample is `{actual}`")]
    RiskClassMismatch { expected: String, actual: String },
    #[error("ACI learning rate must be <= 10000 basis points, got {0}")]
    InvalidLearningRate(u16),
    #[error("failed to serialize conformal artifact: {source}")]
    Serialize { source: serde_json::Error },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalScoreSample {
    pub sample_id: String,
    pub risk_class: String,
    pub score_bp: u16,
    pub positive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonconformitySample {
    pub sample_id: String,
    pub risk_class: String,
    pub score_bp: u16,
    pub positive: bool,
    pub nonconformity_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenConformalQuantile {
    pub risk_class: String,
    pub sample_count: u64,
    pub positive_count: u64,
    pub negative_count: u64,
    pub target_alpha_bp: u16,
    pub quantile_rank: u64,
    pub quantile_bp: u16,
    pub min_nonconformity_bp: u16,
    pub max_nonconformity_bp: u16,
    pub finite_sample_coverage_floor_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenConformalArtifact {
    pub schema_version: String,
    pub generated_at: String,
    pub sample_schema_version: String,
    pub corpus_hash: String,
    pub sample_count: u64,
    pub risk_class_count: u64,
    pub target_alpha_bp: u16,
    pub quantiles: Vec<FrozenConformalQuantile>,
    pub event_codes: Vec<String>,
    pub audit_notes: Vec<String>,
}

impl FrozenConformalArtifact {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConformalCalibrationError> {
        canonical_artifact_bytes(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalRiskSet {
    pub event_code: String,
    pub sample_id: String,
    pub risk_class: String,
    pub score_bp: u16,
    pub quantile_bp: u16,
    pub included_labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AciCoverageObservation {
    pub sample_id: String,
    pub risk_class: String,
    pub covered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AciQuantileState {
    pub schema_version: String,
    pub risk_class: String,
    pub target_alpha_bp: u16,
    pub target_coverage_bp: u16,
    pub learning_rate_bp: u16,
    pub current_quantile_bp: u16,
    pub observations: u64,
    pub covered_count: u64,
    pub miss_count: u64,
    pub empirical_coverage_bp: u16,
    pub coverage_gap_bp: i16,
    pub last_event_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AciQuantileUpdate {
    pub event_code: String,
    pub sample_id: String,
    pub risk_class: String,
    pub covered: bool,
    pub previous_quantile_bp: u16,
    pub updated_quantile_bp: u16,
    pub delta_bp: i16,
    pub empirical_coverage_bp: u16,
    pub coverage_gap_bp: i16,
    pub observations: u64,
}

pub fn score_nonconformity(
    sample: &ConformalScoreSample,
) -> Result<NonconformitySample, ConformalCalibrationError> {
    validate_score_sample(sample)?;
    let nonconformity_bp = if sample.positive {
        MAX_BASIS_POINTS.saturating_sub(sample.score_bp)
    } else {
        sample.score_bp
    };

    Ok(NonconformitySample {
        sample_id: sample.sample_id.clone(),
        risk_class: sample.risk_class.clone(),
        score_bp: sample.score_bp,
        positive: sample.positive,
        nonconformity_bp,
    })
}

pub fn score_nonconformity_samples(
    samples: &[ConformalScoreSample],
) -> Result<Vec<NonconformitySample>, ConformalCalibrationError> {
    ordered_samples(samples)?
        .iter()
        .map(score_nonconformity)
        .collect()
}

pub fn freeze_quantiles(
    samples: &[ConformalScoreSample],
    target_alpha_bp: u16,
) -> Result<FrozenConformalArtifact, ConformalCalibrationError> {
    freeze_quantiles_with_generated_at(samples, target_alpha_bp, CONFORMAL_GENERATED_AT)
}

pub fn freeze_quantiles_with_generated_at(
    samples: &[ConformalScoreSample],
    target_alpha_bp: u16,
    generated_at: &str,
) -> Result<FrozenConformalArtifact, ConformalCalibrationError> {
    validate_target_alpha(target_alpha_bp)?;
    let ordered = ordered_samples(samples)?;
    let scored = ordered
        .iter()
        .map(score_nonconformity)
        .collect::<Result<Vec<_>, _>>()?;
    let mut by_class: BTreeMap<String, Vec<NonconformitySample>> = BTreeMap::new();
    for sample in scored {
        by_class
            .entry(sample.risk_class.clone())
            .or_default()
            .push(sample);
    }

    let mut quantiles = Vec::with_capacity(by_class.len());
    for (risk_class, class_samples) in by_class {
        quantiles.push(frozen_quantile_for_class(
            &risk_class,
            &class_samples,
            target_alpha_bp,
        )?);
    }

    Ok(FrozenConformalArtifact {
        schema_version: CONFORMAL_FROZEN_QUANTILE_SCHEMA_VERSION.to_string(),
        generated_at: generated_at.to_string(),
        sample_schema_version: CONFORMAL_SAMPLE_SCHEMA_VERSION.to_string(),
        corpus_hash: corpus_hash(&ordered)?,
        sample_count: u64::try_from(ordered.len()).unwrap_or(u64::MAX),
        risk_class_count: u64::try_from(quantiles.len()).unwrap_or(u64::MAX),
        target_alpha_bp,
        quantiles,
        event_codes: vec![
            event_codes::CONFORMAL_ARTIFACT_EMITTED.to_string(),
            event_codes::CONFORMAL_SET_EMITTED.to_string(),
        ],
        audit_notes: vec![
            "split conformal coverage assumes exchangeability; adversarial shift is tracked by ACI instead of overclaiming distribution-free guarantees".to_string(),
            "all scores, nonconformity values, and quantiles are integer basis points".to_string(),
        ],
    })
}

pub fn calibrated_binary_risk_set(
    sample_id: &str,
    risk_class: &str,
    score_bp: u16,
    quantile: &FrozenConformalQuantile,
) -> Result<ConformalRiskSet, ConformalCalibrationError> {
    if score_bp > MAX_BASIS_POINTS {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: sample_id.to_string(),
            field: "score_bp",
            reason: "score exceeds 10000 basis points".to_string(),
        });
    }
    if risk_class != quantile.risk_class {
        return Err(ConformalCalibrationError::RiskClassMismatch {
            expected: quantile.risk_class.clone(),
            actual: risk_class.to_string(),
        });
    }

    let mut included_labels = Vec::with_capacity(2);
    if score_bp <= quantile.quantile_bp {
        included_labels.push(LABEL_BENIGN.to_string());
    }
    if MAX_BASIS_POINTS.saturating_sub(score_bp) <= quantile.quantile_bp {
        included_labels.push(LABEL_POSITIVE.to_string());
    }

    Ok(ConformalRiskSet {
        event_code: event_codes::CONFORMAL_SET_EMITTED.to_string(),
        sample_id: sample_id.to_string(),
        risk_class: risk_class.to_string(),
        score_bp,
        quantile_bp: quantile.quantile_bp,
        included_labels,
    })
}

pub fn calibrated_mondrian_risk_set(
    sample_id: &str,
    risk_class: &str,
    score_bp: u16,
    artifact: &FrozenConformalArtifact,
) -> Result<ConformalRiskSet, ConformalCalibrationError> {
    let quantile = artifact
        .quantiles
        .iter()
        .find(|quantile| quantile.risk_class == risk_class)
        .ok_or_else(|| ConformalCalibrationError::MissingRiskClassQuantile {
            risk_class: risk_class.to_string(),
        })?;
    calibrated_binary_risk_set(sample_id, risk_class, score_bp, quantile)
}

pub fn initialize_aci_state(
    quantile: &FrozenConformalQuantile,
    learning_rate_bp: u16,
) -> Result<AciQuantileState, ConformalCalibrationError> {
    validate_target_alpha(quantile.target_alpha_bp)?;
    validate_learning_rate(learning_rate_bp)?;
    Ok(AciQuantileState {
        schema_version: CONFORMAL_ACI_STATE_SCHEMA_VERSION.to_string(),
        risk_class: quantile.risk_class.clone(),
        target_alpha_bp: quantile.target_alpha_bp,
        target_coverage_bp: MAX_BASIS_POINTS.saturating_sub(quantile.target_alpha_bp),
        learning_rate_bp,
        current_quantile_bp: quantile.quantile_bp,
        observations: 0,
        covered_count: 0,
        miss_count: 0,
        empirical_coverage_bp: 0,
        coverage_gap_bp: 0,
        last_event_code: event_codes::ACI_QUANTILE_UPDATED.to_string(),
    })
}

pub fn update_aci_quantile(
    state: &mut AciQuantileState,
    observation: &AciCoverageObservation,
) -> Result<AciQuantileUpdate, ConformalCalibrationError> {
    validate_aci_state(state)?;
    validate_aci_observation(observation)?;
    if state.risk_class != observation.risk_class {
        return Err(ConformalCalibrationError::RiskClassMismatch {
            expected: state.risk_class.clone(),
            actual: observation.risk_class.clone(),
        });
    }

    let previous_quantile_bp = state.current_quantile_bp;
    let miss_bp = if observation.covered {
        0_i32
    } else {
        i32::from(MAX_BASIS_POINTS)
    };
    let error_gap_bp = miss_bp - i32::from(state.target_alpha_bp);
    let delta_bp = signed_bp_product(state.learning_rate_bp, error_gap_bp);
    state.current_quantile_bp = clamp_quantile_delta(previous_quantile_bp, delta_bp);
    state.observations = state.observations.saturating_add(1);
    if observation.covered {
        state.covered_count = state.covered_count.saturating_add(1);
    } else {
        state.miss_count = state.miss_count.saturating_add(1);
    }
    state.empirical_coverage_bp = ratio_bp(state.covered_count, state.observations);
    state.coverage_gap_bp = coverage_gap_bp(state.empirical_coverage_bp, state.target_coverage_bp);
    state.last_event_code = event_codes::ACI_QUANTILE_UPDATED.to_string();

    Ok(AciQuantileUpdate {
        event_code: event_codes::ACI_QUANTILE_UPDATED.to_string(),
        sample_id: observation.sample_id.clone(),
        risk_class: observation.risk_class.clone(),
        covered: observation.covered,
        previous_quantile_bp,
        updated_quantile_bp: state.current_quantile_bp,
        delta_bp: clamp_i32_to_i16(delta_bp),
        empirical_coverage_bp: state.empirical_coverage_bp,
        coverage_gap_bp: state.coverage_gap_bp,
        observations: state.observations,
    })
}

pub fn canonical_artifact_bytes(
    artifact: &FrozenConformalArtifact,
) -> Result<Vec<u8>, ConformalCalibrationError> {
    let value = serde_json::to_value(artifact)
        .map_err(|source| ConformalCalibrationError::Serialize { source })?;
    Ok(canonical_bytes(&value))
}

fn frozen_quantile_for_class(
    risk_class: &str,
    samples: &[NonconformitySample],
    target_alpha_bp: u16,
) -> Result<FrozenConformalQuantile, ConformalCalibrationError> {
    if samples.is_empty() {
        return Err(ConformalCalibrationError::EmptyRiskClass {
            risk_class: risk_class.to_string(),
        });
    }

    let mut values = samples
        .iter()
        .map(|sample| sample.nonconformity_bp)
        .collect::<Vec<_>>();
    values.sort_unstable();
    let rank = conformal_quantile_rank(values.len(), target_alpha_bp)?;
    let quantile_bp = values[rank.saturating_sub(1)];
    let sample_count = u64::try_from(samples.len()).unwrap_or(u64::MAX);
    let positive_count =
        u64::try_from(samples.iter().filter(|sample| sample.positive).count()).unwrap_or(u64::MAX);

    Ok(FrozenConformalQuantile {
        risk_class: risk_class.to_string(),
        sample_count,
        positive_count,
        negative_count: sample_count.saturating_sub(positive_count),
        target_alpha_bp,
        quantile_rank: u64::try_from(rank).unwrap_or(u64::MAX),
        quantile_bp,
        min_nonconformity_bp: values[0],
        max_nonconformity_bp: values[values.len().saturating_sub(1)],
        finite_sample_coverage_floor_bp: ratio_bp(
            u64::try_from(rank).unwrap_or(u64::MAX),
            sample_count.saturating_add(1),
        ),
    })
}

fn conformal_quantile_rank(
    sample_count: usize,
    target_alpha_bp: u16,
) -> Result<usize, ConformalCalibrationError> {
    if sample_count == 0 {
        return Err(ConformalCalibrationError::EmptySamples);
    }
    validate_target_alpha(target_alpha_bp)?;
    let numerator = u128::try_from(sample_count.saturating_add(1))
        .unwrap_or(u128::MAX)
        .saturating_mul(u128::from(MAX_BASIS_POINTS.saturating_sub(target_alpha_bp)));
    let rank = ceil_div(numerator, u128::from(MAX_BASIS_POINTS));
    let rank = usize::try_from(rank).unwrap_or(usize::MAX);
    Ok(rank.clamp(1, sample_count))
}

fn ordered_samples(
    samples: &[ConformalScoreSample],
) -> Result<Vec<ConformalScoreSample>, ConformalCalibrationError> {
    if samples.is_empty() {
        return Err(ConformalCalibrationError::EmptySamples);
    }
    let mut ordered = BTreeMap::new();
    for sample in samples {
        validate_score_sample(sample)?;
        let key = (sample.risk_class.clone(), sample.sample_id.clone());
        if ordered.insert(key, sample.clone()).is_some() {
            return Err(ConformalCalibrationError::DuplicateSample {
                risk_class: sample.risk_class.clone(),
                sample_id: sample.sample_id.clone(),
            });
        }
    }
    Ok(ordered.into_values().collect())
}

fn validate_score_sample(sample: &ConformalScoreSample) -> Result<(), ConformalCalibrationError> {
    if sample.sample_id.trim().is_empty() {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: sample.sample_id.clone(),
            field: "sample_id",
            reason: "must not be empty".to_string(),
        });
    }
    if sample.risk_class.trim().is_empty() {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: sample.sample_id.clone(),
            field: "risk_class",
            reason: "must not be empty".to_string(),
        });
    }
    if sample.score_bp > MAX_BASIS_POINTS {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: sample.sample_id.clone(),
            field: "score_bp",
            reason: "score exceeds 10000 basis points".to_string(),
        });
    }
    Ok(())
}

fn validate_target_alpha(target_alpha_bp: u16) -> Result<(), ConformalCalibrationError> {
    if target_alpha_bp >= MAX_BASIS_POINTS {
        return Err(ConformalCalibrationError::InvalidTargetAlpha(
            target_alpha_bp,
        ));
    }
    Ok(())
}

fn validate_learning_rate(learning_rate_bp: u16) -> Result<(), ConformalCalibrationError> {
    if learning_rate_bp > MAX_BASIS_POINTS {
        return Err(ConformalCalibrationError::InvalidLearningRate(
            learning_rate_bp,
        ));
    }
    Ok(())
}

fn validate_aci_state(state: &AciQuantileState) -> Result<(), ConformalCalibrationError> {
    validate_target_alpha(state.target_alpha_bp)?;
    validate_learning_rate(state.learning_rate_bp)?;
    if state.risk_class.trim().is_empty() {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: "aci-state".to_string(),
            field: "risk_class",
            reason: "must not be empty".to_string(),
        });
    }
    if state.current_quantile_bp > MAX_BASIS_POINTS {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: "aci-state".to_string(),
            field: "current_quantile_bp",
            reason: "quantile exceeds 10000 basis points".to_string(),
        });
    }
    let expected_target_coverage_bp = MAX_BASIS_POINTS.saturating_sub(state.target_alpha_bp);
    if state.target_coverage_bp != expected_target_coverage_bp {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: "aci-state".to_string(),
            field: "target_coverage_bp",
            reason: format!("expected {expected_target_coverage_bp} basis points"),
        });
    }
    Ok(())
}

fn validate_aci_observation(
    observation: &AciCoverageObservation,
) -> Result<(), ConformalCalibrationError> {
    if observation.sample_id.trim().is_empty() {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: observation.sample_id.clone(),
            field: "sample_id",
            reason: "must not be empty".to_string(),
        });
    }
    if observation.risk_class.trim().is_empty() {
        return Err(ConformalCalibrationError::InvalidSample {
            sample_id: observation.sample_id.clone(),
            field: "risk_class",
            reason: "must not be empty".to_string(),
        });
    }
    Ok(())
}

fn corpus_hash(samples: &[ConformalScoreSample]) -> Result<String, ConformalCalibrationError> {
    let value = serde_json::to_value(samples)
        .map_err(|source| ConformalCalibrationError::Serialize { source })?;
    Ok(sha256_prefixed(
        b"conformal-calibration-corpus-v1",
        &canonical_bytes(&value),
    ))
}

fn sha256_prefixed(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(payload);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    if numerator == 0 {
        0
    } else {
        numerator.saturating_sub(1) / denominator + 1
    }
}

fn ratio_bp(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let scaled = u128::from(numerator).saturating_mul(u128::from(MAX_BASIS_POINTS));
    u16::try_from(scaled / u128::from(denominator)).unwrap_or(MAX_BASIS_POINTS)
}

fn signed_bp_product(learning_rate_bp: u16, error_gap_bp: i32) -> i32 {
    i32::from(learning_rate_bp).saturating_mul(error_gap_bp) / i32::from(MAX_BASIS_POINTS)
}

fn clamp_quantile_delta(quantile_bp: u16, delta_bp: i32) -> u16 {
    let updated = i32::from(quantile_bp).saturating_add(delta_bp);
    let clamped = updated.clamp(0, i32::from(MAX_BASIS_POINTS));
    u16::try_from(clamped).unwrap_or(MAX_BASIS_POINTS)
}

fn coverage_gap_bp(empirical_coverage_bp: u16, target_coverage_bp: u16) -> i16 {
    let gap = i32::from(empirical_coverage_bp) - i32::from(target_coverage_bp);
    clamp_i32_to_i16(gap)
}

fn clamp_i32_to_i16(value: i32) -> i16 {
    if value < i32::from(i16::MIN) {
        i16::MIN
    } else if value > i32::from(i16::MAX) {
        i16::MAX
    } else {
        i16::try_from(value).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, risk_class: &str, score_bp: u16, positive: bool) -> ConformalScoreSample {
        ConformalScoreSample {
            sample_id: id.to_string(),
            risk_class: risk_class.to_string(),
            score_bp,
            positive,
        }
    }

    fn base_samples() -> Vec<ConformalScoreSample> {
        vec![
            sample("s4", "evolution", 4_000, false),
            sample("s1", "evolution", 9_000, true),
            sample("s3", "evolution", 2_000, false),
            sample("s2", "evolution", 8_000, true),
            sample("c1", "camouflage", 6_000, true),
            sample("c2", "camouflage", 1_000, false),
        ]
    }

    #[test]
    fn nonconformity_scoring_is_label_symmetric() {
        let positive = score_nonconformity(&sample("p", "risk", 9_000, true)).unwrap();
        let benign = score_nonconformity(&sample("b", "risk", 9_000, false)).unwrap();

        assert_eq!(positive.nonconformity_bp, 1_000);
        assert_eq!(benign.nonconformity_bp, 9_000);
    }

    #[test]
    fn frozen_quantile_uses_split_conformal_rank_without_floats() {
        let artifact = freeze_quantiles(&base_samples()[0..4], 5_000).unwrap();
        let quantile = artifact
            .quantiles
            .iter()
            .find(|quantile| quantile.risk_class == "evolution")
            .unwrap();

        assert_eq!(quantile.sample_count, 4);
        assert_eq!(quantile.positive_count, 2);
        assert_eq!(quantile.negative_count, 2);
        assert_eq!(quantile.quantile_rank, 3);
        assert_eq!(quantile.quantile_bp, 2_000);
        assert_eq!(quantile.min_nonconformity_bp, 1_000);
        assert_eq!(quantile.max_nonconformity_bp, 4_000);
        assert_eq!(quantile.finite_sample_coverage_floor_bp, 6_000);
    }

    #[test]
    fn artifact_is_input_order_independent_and_canonical() {
        let forward = freeze_quantiles(&base_samples(), 2_000).unwrap();
        let mut reversed = base_samples();
        reversed.reverse();
        let reversed = freeze_quantiles(&reversed, 2_000).unwrap();

        assert_eq!(forward.corpus_hash, reversed.corpus_hash);
        assert_eq!(forward.quantiles, reversed.quantiles);
        assert_eq!(
            forward.canonical_bytes().unwrap(),
            reversed.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn duplicate_samples_are_rejected_per_risk_class() {
        let samples = vec![
            sample("same", "evolution", 1_000, false),
            sample("same", "evolution", 9_000, true),
        ];

        let err = freeze_quantiles(&samples, 1_000).unwrap_err();
        assert!(matches!(
            err,
            ConformalCalibrationError::DuplicateSample { .. }
        ));
    }

    #[test]
    fn calibrated_binary_set_can_represent_uncertainty() {
        let quantile = FrozenConformalQuantile {
            risk_class: "evolution".to_string(),
            sample_count: 10,
            positive_count: 5,
            negative_count: 5,
            target_alpha_bp: 1_000,
            quantile_rank: 10,
            quantile_bp: 6_000,
            min_nonconformity_bp: 500,
            max_nonconformity_bp: 6_000,
            finite_sample_coverage_floor_bp: 9_090,
        };

        let set = calibrated_binary_risk_set("candidate", "evolution", 5_000, &quantile).unwrap();

        assert_eq!(set.event_code, event_codes::CONFORMAL_SET_EMITTED);
        assert_eq!(
            set.included_labels,
            vec![LABEL_BENIGN.to_string(), LABEL_POSITIVE.to_string()]
        );
    }

    #[test]
    fn mondrian_risk_set_uses_matching_risk_class_quantile() {
        let mut artifact = freeze_quantiles(&base_samples(), 2_000).unwrap();
        artifact.quantiles = vec![
            FrozenConformalQuantile {
                risk_class: "critical".to_string(),
                sample_count: 8,
                positive_count: 4,
                negative_count: 4,
                target_alpha_bp: 1_000,
                quantile_rank: 4,
                quantile_bp: 4_000,
                min_nonconformity_bp: 500,
                max_nonconformity_bp: 4_000,
                finite_sample_coverage_floor_bp: 8_888,
            },
            FrozenConformalQuantile {
                risk_class: "low".to_string(),
                sample_count: 8,
                positive_count: 4,
                negative_count: 4,
                target_alpha_bp: 1_000,
                quantile_rank: 8,
                quantile_bp: 6_000,
                min_nonconformity_bp: 500,
                max_nonconformity_bp: 6_000,
                finite_sample_coverage_floor_bp: 8_888,
            },
        ];

        let critical =
            calibrated_mondrian_risk_set("candidate", "critical", 5_000, &artifact).unwrap();
        let low = calibrated_mondrian_risk_set("candidate", "low", 5_000, &artifact).unwrap();

        assert!(critical.included_labels.is_empty());
        assert_eq!(
            low.included_labels,
            vec![LABEL_BENIGN.to_string(), LABEL_POSITIVE.to_string()]
        );
    }

    #[test]
    fn mondrian_risk_set_rejects_missing_risk_class() {
        let artifact = freeze_quantiles(&base_samples(), 2_000).unwrap();

        let err =
            calibrated_mondrian_risk_set("candidate", "missing", 5_000, &artifact).unwrap_err();

        assert!(matches!(
            err,
            ConformalCalibrationError::MissingRiskClassQuantile { .. }
        ));
    }

    #[test]
    fn aci_update_increases_after_miss_and_decays_after_coverage() {
        let quantile = FrozenConformalQuantile {
            risk_class: "critical".to_string(),
            sample_count: 10,
            positive_count: 5,
            negative_count: 5,
            target_alpha_bp: 1_000,
            quantile_rank: 9,
            quantile_bp: 2_000,
            min_nonconformity_bp: 100,
            max_nonconformity_bp: 2_000,
            finite_sample_coverage_floor_bp: 8_181,
        };
        let mut state = initialize_aci_state(&quantile, 500).unwrap();

        let miss = update_aci_quantile(
            &mut state,
            &AciCoverageObservation {
                sample_id: "shifted-1".to_string(),
                risk_class: "critical".to_string(),
                covered: false,
            },
        )
        .unwrap();
        assert_eq!(miss.event_code, event_codes::ACI_QUANTILE_UPDATED);
        assert_eq!(miss.delta_bp, 450);
        assert_eq!(miss.updated_quantile_bp, 2_450);
        assert_eq!(state.miss_count, 1);

        let covered = update_aci_quantile(
            &mut state,
            &AciCoverageObservation {
                sample_id: "covered-1".to_string(),
                risk_class: "critical".to_string(),
                covered: true,
            },
        )
        .unwrap();
        assert_eq!(covered.delta_bp, -50);
        assert_eq!(covered.updated_quantile_bp, 2_400);
        assert_eq!(covered.empirical_coverage_bp, 5_000);
        assert_eq!(covered.coverage_gap_bp, -4_000);
        assert_eq!(state.observations, 2);
    }

    #[test]
    fn invalid_alpha_is_rejected() {
        let err = freeze_quantiles(&base_samples(), MAX_BASIS_POINTS).unwrap_err();
        assert!(matches!(
            err,
            ConformalCalibrationError::InvalidTargetAlpha(MAX_BASIS_POINTS)
        ));
    }
}
