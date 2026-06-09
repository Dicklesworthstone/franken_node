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
    #[error("risk class mismatch: quantile is `{expected}`, sample is `{actual}`")]
    RiskClassMismatch { expected: String, actual: String },
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
    fn invalid_alpha_is_rejected() {
        let err = freeze_quantiles(&base_samples(), MAX_BASIS_POINTS).unwrap_err();
        assert!(matches!(
            err,
            ConformalCalibrationError::InvalidTargetAlpha(MAX_BASIS_POINTS)
        ));
    }
}
