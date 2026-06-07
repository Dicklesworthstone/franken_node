//! Deterministic BPET calibration benchmark artifact generation.
//!
//! The harness calibrates the current Phase-0 corpus against the BPET
//! evolution-risk scorer, camouflage detector fixtures, and a topology-derived
//! DGIS/SPOF signal. All externally serialized metrics are integer basis
//! points so canonical artifact bytes are stable across platforms.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::connector::canonical_serializer::canonical_bytes;
use crate::security::bpet::adversarial_harness::AdversarialHarnessError;
use crate::security::bpet::adversarial_scenarios::synthesize_labeled_corpus_records;
use crate::security::bpet::camouflage_detector::detect_camouflage;
use crate::security::bpet::camouflage_fixtures::all_fixtures;
use crate::security::bpet::evolution_risk_scorer::{
    FeatureVector, ScorerError, WeightingPolicy, compute_risk_score,
};
use crate::security::bpet::phenotype_extractor::{
    AdversaryCorpusRecord, CorpusGroundTruthLabel, CorpusRecordError, MAX_BASIS_POINTS,
    feature_names,
};
use crate::security::constant_time::ct_eq;

pub const CALIBRATION_ARTIFACT_SCHEMA_VERSION: &str = "bpet.calibration_artifact.v1";
pub const CALIBRATION_UNSIGNED_SCHEMA_VERSION: &str = "bpet.calibration_unsigned.v1";
pub const CALIBRATION_GENERATED_AT: &str = "1970-01-01T00:00:00Z";
pub const CALIBRATION_TARGET_ALPHA_BP: u16 = 5_000;
pub const RELIABILITY_BIN_COUNT: usize = 5;
pub const RELIABILITY_BIN_WIDTH_BP: u16 = 2_000;
pub const CALIBRATION_SIGNATURE_KEY_ID: &str = "franken-node-bpet-calibration-harness-v1";
pub const CALIBRATION_SIGNATURE_ALGORITHM: &str = "sha256-deterministic-artifact-signature-v1";

const SIGNAL_EVOLUTION_RISK: &str = "bpet.evolution_risk_scorer";
const SIGNAL_CAMOUFLAGE: &str = "bpet.camouflage_detector";
const SIGNAL_DGIS_SPOF: &str = "dgis.spof_topology_signal";

#[derive(Debug, thiserror::Error)]
pub enum CalibrationBenchmarkError {
    #[error("calibration corpus is empty")]
    EmptyCorpus,
    #[error("calibration signal `{signal_id}` has no samples")]
    EmptySignal { signal_id: String },
    #[error("corpus record error: {source}")]
    Corpus { source: CorpusRecordError },
    #[error("adversarial corpus synthesis error: {source}")]
    Harness { source: AdversarialHarnessError },
    #[error("evolution risk scorer error: {source}")]
    Scorer { source: ScorerError },
    #[error("camouflage detector error: {source}")]
    Detector {
        source: crate::security::bpet::camouflage_detector::DetectorError,
    },
    #[error("failed to serialize calibration artifact: {source}")]
    Serialize { source: serde_json::Error },
}

impl From<CorpusRecordError> for CalibrationBenchmarkError {
    fn from(source: CorpusRecordError) -> Self {
        Self::Corpus { source }
    }
}

impl From<AdversarialHarnessError> for CalibrationBenchmarkError {
    fn from(source: AdversarialHarnessError) -> Self {
        Self::Harness { source }
    }
}

impl From<ScorerError> for CalibrationBenchmarkError {
    fn from(source: ScorerError) -> Self {
        Self::Scorer { source }
    }
}

impl From<crate::security::bpet::camouflage_detector::DetectorError> for CalibrationBenchmarkError {
    fn from(source: crate::security::bpet::camouflage_detector::DetectorError) -> Self {
        Self::Detector { source }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSample {
    pub sample_id: String,
    pub score_bp: u16,
    pub positive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityBin {
    pub lower_bp: u16,
    pub upper_bp: u16,
    pub sample_count: u64,
    pub positive_count: u64,
    pub mean_score_bp: u16,
    pub observed_positive_rate_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationMetrics {
    pub sample_count: u64,
    pub positive_count: u64,
    pub negative_count: u64,
    pub target_alpha_bp: u16,
    pub coverage_at_target_alpha_bp: u16,
    pub false_alarm_under_sequential_peeking_bp: u16,
    pub roc_auc_bp: u16,
    pub pr_auc_bp: u16,
    pub brier_score_bp: u16,
    pub expected_calibration_error_bp: u16,
    pub reliability_bins: Vec<ReliabilityBin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSignalReport {
    pub signal_id: String,
    pub signal_schema_version: String,
    pub metric_notes: Vec<String>,
    pub metrics: CalibrationMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedCalibrationArtifact {
    pub schema_version: String,
    pub generated_at: String,
    pub corpus_hash: String,
    pub corpus_record_count: u64,
    pub target_alpha_bp: u16,
    pub signals: Vec<CalibrationSignalReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationArtifactSignature {
    pub algorithm: String,
    pub key_id: String,
    pub payload_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCalibrationArtifact {
    pub schema_version: String,
    pub generated_at: String,
    pub corpus_hash: String,
    pub corpus_record_count: u64,
    pub target_alpha_bp: u16,
    pub signals: Vec<CalibrationSignalReport>,
    pub signature: CalibrationArtifactSignature,
}

impl SignedCalibrationArtifact {
    pub fn unsigned_payload(&self) -> UnsignedCalibrationArtifact {
        UnsignedCalibrationArtifact {
            schema_version: CALIBRATION_UNSIGNED_SCHEMA_VERSION.to_string(),
            generated_at: self.generated_at.clone(),
            corpus_hash: self.corpus_hash.clone(),
            corpus_record_count: self.corpus_record_count,
            target_alpha_bp: self.target_alpha_bp,
            signals: self.signals.clone(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CalibrationBenchmarkError> {
        canonical_artifact_bytes(self)
    }
}

pub fn generate_signed_calibration_artifact()
-> Result<SignedCalibrationArtifact, CalibrationBenchmarkError> {
    let records = synthesize_labeled_corpus_records()?;
    generate_signed_calibration_artifact_from_records(&records)
}

pub fn generate_signed_calibration_artifact_from_records(
    records: &[AdversaryCorpusRecord],
) -> Result<SignedCalibrationArtifact, CalibrationBenchmarkError> {
    if records.is_empty() {
        return Err(CalibrationBenchmarkError::EmptyCorpus);
    }
    for record in records {
        record.validate()?;
    }

    let unsigned = UnsignedCalibrationArtifact {
        schema_version: CALIBRATION_UNSIGNED_SCHEMA_VERSION.to_string(),
        generated_at: CALIBRATION_GENERATED_AT.to_string(),
        corpus_hash: corpus_hash(records)?,
        corpus_record_count: u64::try_from(records.len()).unwrap_or(u64::MAX),
        target_alpha_bp: CALIBRATION_TARGET_ALPHA_BP,
        signals: vec![
            evolution_risk_report(records)?,
            camouflage_report()?,
            dgis_spof_report(records)?,
        ],
    };
    sign_unsigned_artifact(unsigned)
}

pub fn canonical_artifact_bytes(
    artifact: &SignedCalibrationArtifact,
) -> Result<Vec<u8>, CalibrationBenchmarkError> {
    let value = serde_json::to_value(artifact)
        .map_err(|source| CalibrationBenchmarkError::Serialize { source })?;
    Ok(canonical_bytes(&value))
}

pub fn canonical_unsigned_artifact_bytes(
    artifact: &UnsignedCalibrationArtifact,
) -> Result<Vec<u8>, CalibrationBenchmarkError> {
    let value = serde_json::to_value(artifact)
        .map_err(|source| CalibrationBenchmarkError::Serialize { source })?;
    Ok(canonical_bytes(&value))
}

pub fn verify_signed_calibration_artifact(
    artifact: &SignedCalibrationArtifact,
) -> Result<bool, CalibrationBenchmarkError> {
    let expected = signature_for_unsigned(&artifact.unsigned_payload())?;
    Ok(ct_eq(&artifact.signature.algorithm, &expected.algorithm)
        && ct_eq(&artifact.signature.key_id, &expected.key_id)
        && ct_eq(&artifact.signature.payload_hash, &expected.payload_hash)
        && ct_eq(&artifact.signature.signature, &expected.signature))
}

fn sign_unsigned_artifact(
    unsigned: UnsignedCalibrationArtifact,
) -> Result<SignedCalibrationArtifact, CalibrationBenchmarkError> {
    let signature = signature_for_unsigned(&unsigned)?;
    Ok(SignedCalibrationArtifact {
        schema_version: CALIBRATION_ARTIFACT_SCHEMA_VERSION.to_string(),
        generated_at: unsigned.generated_at,
        corpus_hash: unsigned.corpus_hash,
        corpus_record_count: unsigned.corpus_record_count,
        target_alpha_bp: unsigned.target_alpha_bp,
        signals: unsigned.signals,
        signature,
    })
}

fn signature_for_unsigned(
    unsigned: &UnsignedCalibrationArtifact,
) -> Result<CalibrationArtifactSignature, CalibrationBenchmarkError> {
    let payload = canonical_unsigned_artifact_bytes(unsigned)?;
    let payload_hash = sha256_prefixed(b"bpet-calibration-artifact-payload-v1", &payload);
    let mut signature_preimage = Vec::new();
    signature_preimage.extend_from_slice(CALIBRATION_SIGNATURE_KEY_ID.as_bytes());
    signature_preimage.extend_from_slice(payload_hash.as_bytes());
    let signature = sha256_prefixed(
        b"bpet-calibration-artifact-signature-v1",
        &signature_preimage,
    );
    Ok(CalibrationArtifactSignature {
        algorithm: CALIBRATION_SIGNATURE_ALGORITHM.to_string(),
        key_id: CALIBRATION_SIGNATURE_KEY_ID.to_string(),
        payload_hash,
        signature,
    })
}

fn evolution_risk_report(
    records: &[AdversaryCorpusRecord],
) -> Result<CalibrationSignalReport, CalibrationBenchmarkError> {
    let policy = WeightingPolicy::policy_v1();
    let mut samples = Vec::with_capacity(records.len());
    for record in records {
        let features = evolution_features_from_record(record)?;
        let (score, _) = compute_risk_score(&features, &policy)?;
        samples.push(CalibrationSample {
            sample_id: record.record_id.clone(),
            score_bp: unit_to_basis_points(score),
            positive: is_positive(record),
        });
    }
    Ok(CalibrationSignalReport {
        signal_id: SIGNAL_EVOLUTION_RISK.to_string(),
        signal_schema_version: crate::security::bpet::evolution_risk_scorer::SCHEMA_VERSION
            .to_string(),
        metric_notes: vec![
            "scores are produced by compute_risk_score over corpus-derived four-factor vectors"
                .to_string(),
            "reliability and discrimination metrics use fixed integer basis-point arithmetic"
                .to_string(),
        ],
        metrics: compute_metrics(SIGNAL_EVOLUTION_RISK, &samples)?,
    })
}

fn camouflage_report() -> Result<CalibrationSignalReport, CalibrationBenchmarkError> {
    let fixtures = all_fixtures();
    let mut samples = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        let hints = detect_camouflage(&fixture.series, &fixture.config)?;
        let score_bp = hints
            .iter()
            .map(|hint| unit_to_basis_points(hint.severity))
            .max()
            .unwrap_or(0);
        samples.push(CalibrationSample {
            sample_id: fixture.name,
            score_bp,
            positive: !fixture.expected_hints.is_empty(),
        });
    }
    Ok(CalibrationSignalReport {
        signal_id: SIGNAL_CAMOUFLAGE.to_string(),
        signal_schema_version: "bpet.camouflage_detector.v1".to_string(),
        metric_notes: vec![
            "scores are max emitted hint severity over the canonical camouflage fixture catalog"
                .to_string(),
            "positive labels are fixtures with one or more expected camouflage hints".to_string(),
        ],
        metrics: compute_metrics(SIGNAL_CAMOUFLAGE, &samples)?,
    })
}

fn dgis_spof_report(
    records: &[AdversaryCorpusRecord],
) -> Result<CalibrationSignalReport, CalibrationBenchmarkError> {
    let samples = records
        .iter()
        .map(|record| CalibrationSample {
            sample_id: record.record_id.clone(),
            score_bp: dgis_spof_score(record),
            positive: is_positive(record),
        })
        .collect::<Vec<_>>();
    Ok(CalibrationSignalReport {
        signal_id: SIGNAL_DGIS_SPOF.to_string(),
        signal_schema_version: "dgis.spof_topology_signal.v1".to_string(),
        metric_notes: vec![
            "scores are topology-derived from corpus dependency depth, transitive fanout, maintainer overlap, and SPOF basis points".to_string(),
            "this is the deterministic corpus-side DGIS/SPOF calibration seam; full contagion simulation can be added without changing the artifact schema".to_string(),
        ],
        metrics: compute_metrics(SIGNAL_DGIS_SPOF, &samples)?,
    })
}

fn evolution_features_from_record(
    record: &AdversaryCorpusRecord,
) -> Result<FeatureVector, CalibrationBenchmarkError> {
    let capability = corpus_feature_bp(record, feature_names::CAPABILITY_INVOCATION_INTENSITY);
    let resource = corpus_feature_bp(record, feature_names::RESOURCE_ENVELOPE_PRESSURE);
    let declared = corpus_feature_bp(record, feature_names::DECLARED_PERMISSION_SURFACE);
    let code = corpus_feature_bp(record, feature_names::CODE_COMPLEXITY);
    let network = corpus_feature_bp(record, feature_names::NETWORK_SURFACE_AREA);
    let filesystem = corpus_feature_bp(record, feature_names::FILESYSTEM_SURFACE_AREA);
    let dependency = corpus_feature_bp(record, feature_names::DEPENDENCY_SURFACE)
        .max(record.dependency_topology.single_point_of_failure_score_bp);

    let drift = max_bp(capability, resource, code);
    let regime_shift = declared.max(resource);
    let hazard = max_bp(network, filesystem, dependency);
    let provenance = record
        .longitudinal_trajectory
        .last()
        .map(|point| point.risk_score_bp)
        .unwrap_or(resource);

    FeatureVector::try_new(
        bp_to_unit(drift),
        bp_to_unit(regime_shift),
        bp_to_unit(hazard),
        bp_to_unit(provenance),
    )
    .map_err(CalibrationBenchmarkError::from)
}

fn dgis_spof_score(record: &AdversaryCorpusRecord) -> u16 {
    let topology = &record.dependency_topology;
    let depth_bp = count_to_bp(topology.max_depth, 10);
    let transitive_bp = count_to_bp(topology.transitive_dependency_count, 500);
    let overlap_bp = count_to_bp(topology.maintainer_overlap_count, 50);
    weighted_average_bp(&[
        (topology.single_point_of_failure_score_bp, 5),
        (depth_bp, 2),
        (transitive_bp, 2),
        (overlap_bp, 1),
    ])
}

fn compute_metrics(
    signal_id: &str,
    samples: &[CalibrationSample],
) -> Result<CalibrationMetrics, CalibrationBenchmarkError> {
    if samples.is_empty() {
        return Err(CalibrationBenchmarkError::EmptySignal {
            signal_id: signal_id.to_string(),
        });
    }
    let sample_count = u64::try_from(samples.len()).unwrap_or(u64::MAX);
    let positive_count =
        u64::try_from(samples.iter().filter(|sample| sample.positive).count()).unwrap_or(u64::MAX);
    let negative_count = sample_count.saturating_sub(positive_count);
    let coverage_hits = u64::try_from(
        samples
            .iter()
            .filter(|sample| sample.positive && sample.score_bp >= CALIBRATION_TARGET_ALPHA_BP)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let false_alarms = u64::try_from(
        samples
            .iter()
            .filter(|sample| !sample.positive && sample.score_bp >= CALIBRATION_TARGET_ALPHA_BP)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let reliability_bins = reliability_bins(samples);
    let expected_calibration_error_bp = expected_calibration_error(samples, &reliability_bins);

    Ok(CalibrationMetrics {
        sample_count,
        positive_count,
        negative_count,
        target_alpha_bp: CALIBRATION_TARGET_ALPHA_BP,
        coverage_at_target_alpha_bp: ratio_bp(coverage_hits, positive_count),
        false_alarm_under_sequential_peeking_bp: ratio_bp(false_alarms, negative_count),
        roc_auc_bp: roc_auc_bp(samples),
        pr_auc_bp: pr_auc_bp(samples),
        brier_score_bp: brier_score_bp(samples),
        expected_calibration_error_bp,
        reliability_bins,
    })
}

fn reliability_bins(samples: &[CalibrationSample]) -> Vec<ReliabilityBin> {
    let mut bins = (0..RELIABILITY_BIN_COUNT)
        .map(|idx| {
            let lower = u16::try_from(idx)
                .unwrap_or(u16::MAX)
                .saturating_mul(RELIABILITY_BIN_WIDTH_BP);
            let upper = if idx == RELIABILITY_BIN_COUNT.saturating_sub(1) {
                MAX_BASIS_POINTS
            } else {
                lower
                    .saturating_add(RELIABILITY_BIN_WIDTH_BP)
                    .saturating_sub(1)
            };
            ReliabilityBin {
                lower_bp: lower,
                upper_bp: upper,
                sample_count: 0,
                positive_count: 0,
                mean_score_bp: 0,
                observed_positive_rate_bp: 0,
            }
        })
        .collect::<Vec<_>>();
    let mut score_sums = [0_u64; RELIABILITY_BIN_COUNT];
    for sample in samples {
        let idx = reliability_bin_index(sample.score_bp);
        let bin = &mut bins[idx];
        bin.sample_count = bin.sample_count.saturating_add(1);
        if sample.positive {
            bin.positive_count = bin.positive_count.saturating_add(1);
        }
        score_sums[idx] = score_sums[idx].saturating_add(u64::from(sample.score_bp));
    }
    for (idx, bin) in bins.iter_mut().enumerate() {
        if bin.sample_count == 0 {
            continue;
        }
        bin.mean_score_bp = ratio_bp(score_sums[idx], bin.sample_count);
        bin.observed_positive_rate_bp = ratio_bp(bin.positive_count, bin.sample_count);
    }
    bins
}

fn reliability_bin_index(score_bp: u16) -> usize {
    let width = usize::from(RELIABILITY_BIN_WIDTH_BP);
    let idx = usize::from(score_bp) / width.max(1);
    idx.min(RELIABILITY_BIN_COUNT.saturating_sub(1))
}

fn expected_calibration_error(samples: &[CalibrationSample], bins: &[ReliabilityBin]) -> u16 {
    let total = u64::try_from(samples.len()).unwrap_or(u64::MAX);
    if total == 0 {
        return 0;
    }
    let weighted = bins.iter().fold(0_u64, |acc, bin| {
        let delta = u64::from(abs_diff_bp(
            bin.mean_score_bp,
            bin.observed_positive_rate_bp,
        ));
        acc.saturating_add(bin.sample_count.saturating_mul(delta))
    });
    ratio_bp(weighted, total)
}

fn roc_auc_bp(samples: &[CalibrationSample]) -> u16 {
    let positives = samples
        .iter()
        .filter(|sample| sample.positive)
        .collect::<Vec<_>>();
    let negatives = samples
        .iter()
        .filter(|sample| !sample.positive)
        .collect::<Vec<_>>();
    if positives.is_empty() || negatives.is_empty() {
        return 0;
    }
    let mut pair_points = 0_u64;
    for positive in &positives {
        for negative in &negatives {
            pair_points =
                pair_points.saturating_add(match positive.score_bp.cmp(&negative.score_bp) {
                    std::cmp::Ordering::Greater => 2,
                    std::cmp::Ordering::Equal => 1,
                    std::cmp::Ordering::Less => 0,
                });
        }
    }
    let pair_count = u64::try_from(positives.len())
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::try_from(negatives.len()).unwrap_or(u64::MAX))
        .saturating_mul(2);
    ratio_bp(pair_points, pair_count)
}

fn pr_auc_bp(samples: &[CalibrationSample]) -> u16 {
    let positive_count =
        u64::try_from(samples.iter().filter(|sample| sample.positive).count()).unwrap_or(u64::MAX);
    if positive_count == 0 {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|left, right| {
        right
            .score_bp
            .cmp(&left.score_bp)
            .then_with(|| left.sample_id.cmp(&right.sample_id))
    });
    let mut true_positives = 0_u64;
    let mut precision_sum_bp = 0_u64;
    for (idx, sample) in sorted.iter().enumerate() {
        if !sample.positive {
            continue;
        }
        true_positives = true_positives.saturating_add(1);
        let rank = u64::try_from(idx.saturating_add(1)).unwrap_or(u64::MAX);
        precision_sum_bp =
            precision_sum_bp.saturating_add(u64::from(ratio_bp(true_positives, rank)));
    }
    ratio_bp(precision_sum_bp, positive_count)
}

fn brier_score_bp(samples: &[CalibrationSample]) -> u16 {
    if samples.is_empty() {
        return 0;
    }
    let mut sum = 0_u128;
    for sample in samples {
        let target = if sample.positive { MAX_BASIS_POINTS } else { 0 };
        let diff = u128::from(abs_diff_bp(sample.score_bp, target));
        sum = sum.saturating_add(diff.saturating_mul(diff));
    }
    let denom = u128::from(u64::try_from(samples.len()).unwrap_or(u64::MAX))
        .saturating_mul(u128::from(MAX_BASIS_POINTS));
    if denom == 0 {
        return 0;
    }
    let rounded = sum.saturating_add(denom / 2) / denom;
    u16::try_from(rounded.min(u128::from(MAX_BASIS_POINTS))).unwrap_or(MAX_BASIS_POINTS)
}

fn corpus_hash(records: &[AdversaryCorpusRecord]) -> Result<String, CalibrationBenchmarkError> {
    let mut hasher = Sha256::new();
    hasher.update(b"bpet-calibration-corpus-v1");
    for record in records {
        let bytes = record.canonical_bytes()?;
        update_len_prefixed(&mut hasher, &bytes);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn sha256_prefixed(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_len_prefixed(&mut hasher, payload);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

fn corpus_feature_bp(record: &AdversaryCorpusRecord, feature_name: &str) -> u16 {
    record
        .phenotype_features
        .get(feature_name)
        .and_then(|feature| feature.value_basis_points)
        .unwrap_or(0)
}

fn is_positive(record: &AdversaryCorpusRecord) -> bool {
    matches!(
        record.ground_truth.label,
        CorpusGroundTruthLabel::Malicious | CorpusGroundTruthLabel::CampaignMember
    )
}

fn bp_to_unit(value: u16) -> f64 {
    f64::from(value) / f64::from(MAX_BASIS_POINTS)
}

fn unit_to_basis_points(value: f64) -> u16 {
    if !value.is_finite() {
        return 0;
    }
    let scaled = (value.clamp(0.0, 1.0) * f64::from(MAX_BASIS_POINTS)).round();
    if scaled <= 0.0 {
        0
    } else if scaled >= f64::from(MAX_BASIS_POINTS) {
        MAX_BASIS_POINTS
    } else {
        rounded_float_to_bp(scaled)
    }
}

fn rounded_float_to_bp(value: f64) -> u16 {
    let mut low = 0_u16;
    let mut high = MAX_BASIS_POINTS;
    while low < high {
        let mid = low + ((high - low) / 2);
        if f64::from(mid) < value {
            low = mid.saturating_add(1);
        } else {
            high = mid;
        }
    }
    low
}

fn count_to_bp(value: u64, saturation: u64) -> u16 {
    if saturation == 0 {
        return 0;
    }
    ratio_bp(value.min(saturation), saturation)
}

fn weighted_average_bp(values: &[(u16, u64)]) -> u16 {
    let mut weighted = 0_u64;
    let mut total_weight = 0_u64;
    for (value, weight) in values {
        weighted = weighted.saturating_add(u64::from(*value).saturating_mul(*weight));
        total_weight = total_weight.saturating_add(*weight);
    }
    ratio_bp(weighted, total_weight)
}

fn max_bp(a: u16, b: u16, c: u16) -> u16 {
    a.max(b).max(c)
}

fn abs_diff_bp(left: u16, right: u16) -> u16 {
    left.max(right).saturating_sub(left.min(right))
}

fn ratio_bp(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let scaled = numerator
        .saturating_mul(u64::from(MAX_BASIS_POINTS))
        .saturating_add(denominator / 2)
        / denominator;
    u16::try_from(scaled.min(u64::from(MAX_BASIS_POINTS))).unwrap_or(MAX_BASIS_POINTS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_calibration_artifact_is_deterministic_and_verifiable() {
        let first = generate_signed_calibration_artifact().expect("first artifact");
        let second = generate_signed_calibration_artifact().expect("second artifact");

        assert_eq!(first, second);
        assert_eq!(
            first.canonical_bytes().expect("first canonical bytes"),
            second.canonical_bytes().expect("second canonical bytes")
        );
        assert!(verify_signed_calibration_artifact(&first).expect("verify signature"));
        assert_eq!(first.signals.len(), 3);
        assert!(first.corpus_hash.starts_with("sha256:"));
    }

    #[test]
    fn signature_verification_rejects_metric_tampering() {
        let mut artifact = generate_signed_calibration_artifact().expect("artifact");
        artifact.signals[0].metrics.sample_count =
            artifact.signals[0].metrics.sample_count.saturating_add(1);

        assert!(
            !verify_signed_calibration_artifact(&artifact).expect("tampered verification result")
        );
    }
}
