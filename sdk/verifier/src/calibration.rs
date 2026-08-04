//! Offline recomputation for BPET calibration artifacts.
//!
//! External verifiers use this module to recompute the calibration metrics
//! and deterministic artifact signature from published corpus bytes plus
//! per-signal calibration samples.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use subtle::ConstantTimeEq as _;

pub const CALIBRATION_ARTIFACT_SCHEMA_VERSION: &str = "bpet.calibration_artifact.v1";
pub const CALIBRATION_UNSIGNED_SCHEMA_VERSION: &str = "bpet.calibration_unsigned.v1";
pub const CALIBRATION_TARGET_ALPHA_BP: u16 = 5_000;
pub const RELIABILITY_BIN_COUNT: usize = 5;
pub const RELIABILITY_BIN_WIDTH_BP: u16 = 2_000;
pub const MAX_BASIS_POINTS: u16 = 10_000;
pub const CALIBRATION_SIGNATURE_KEY_ID: &str = "franken-node-bpet-calibration-harness-v1";
pub const CALIBRATION_SIGNATURE_ALGORITHM: &str = "sha256-deterministic-artifact-signature-v1";
pub const FN_VSDK_CALIBRATION_RECOMPUTE_START: &str = "FN-VSDK-CALIBRATION-RECOMPUTE-START";
pub const FN_VSDK_CALIBRATION_METRICS_RECOMPUTED: &str = "FN-VSDK-CALIBRATION-METRICS-RECOMPUTED";
pub const FN_VSDK_CALIBRATION_ARTIFACT_PASS: &str = "FN-VSDK-CALIBRATION-ARTIFACT-PASS";
pub const CONFORMAL_SAMPLE_SCHEMA_VERSION: &str = "conformal.score_sample.v1";
pub const CONFORMAL_FROZEN_QUANTILE_SCHEMA_VERSION: &str = "conformal.frozen_quantile_artifact.v1";
pub const CONFORMAL_LABEL_BENIGN: &str = "benign";
pub const CONFORMAL_LABEL_POSITIVE: &str = "positive";
pub const FN_VSDK_CONFORMAL_RECOMPUTE_START: &str = "FN-VSDK-CONFORMAL-RECOMPUTE-START";
pub const FN_VSDK_CONFORMAL_QUANTILES_RECOMPUTED: &str = "FN-VSDK-CONFORMAL-QUANTILES-RECOMPUTED";
pub const FN_VSDK_CONFORMAL_RISK_SET_RECOMPUTED: &str = "FN-VSDK-CONFORMAL-RISK-SET-RECOMPUTED";
pub const FN_VSDK_CONFORMAL_ARTIFACT_PASS: &str = "FN-VSDK-CONFORMAL-ARTIFACT-PASS";
pub const FN_CONFORMAL_SET_EMITTED: &str = "FN-CONFORMAL-001";
pub const FN_CONFORMAL_ARTIFACT_EMITTED: &str = "FN-CALIB-002";

const SHA256_PREFIX: &str = "sha256:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSample {
    pub sample_id: String,
    pub score_bp: u16,
    pub positive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalScoreSample {
    pub sample_id: String,
    pub risk_class: String,
    pub score_bp: u16,
    pub positive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSignalSamples {
    pub signal_id: String,
    pub signal_schema_version: String,
    pub metric_notes: Vec<String>,
    pub samples: Vec<CalibrationSample>,
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
pub struct ConformalFrozenQuantile {
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
pub struct ConformalFrozenArtifact {
    pub schema_version: String,
    pub generated_at: String,
    pub sample_schema_version: String,
    pub corpus_hash: String,
    pub sample_count: u64,
    pub risk_class_count: u64,
    pub target_alpha_bp: u16,
    pub quantiles: Vec<ConformalFrozenQuantile>,
    pub event_codes: Vec<String>,
    pub audit_notes: Vec<String>,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCalibrationArtifact {
    pub corpus_hash: String,
    pub corpus_record_count: u64,
    pub signal_count: usize,
    pub event_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedConformalArtifact {
    pub corpus_hash: String,
    pub sample_count: u64,
    pub risk_class_count: u64,
    pub target_alpha_bp: u16,
    pub event_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConformalNonconformitySample {
    positive: bool,
    nonconformity_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalibrationVerificationError {
    Json(String),
    NonCanonicalArtifact,
    NonCanonicalCorpusRecord {
        index: usize,
    },
    NonCanonicalConformalCorpus,
    NonCanonicalConformalRiskSet,
    FloatingPointValue {
        path: String,
    },
    EmptyCorpus,
    EmptyConformalSamples,
    EmptySignal {
        signal_id: String,
    },
    UnsupportedSchema {
        expected: String,
        actual: String,
    },
    InvalidField {
        field: &'static str,
        reason: String,
    },
    InvalidHash {
        field: &'static str,
        value: String,
    },
    DuplicateConformalSample {
        risk_class: String,
        sample_id: String,
    },
    MissingConformalRiskClass {
        risk_class: String,
    },
    ConformalRiskClassMismatch {
        expected: String,
        actual: String,
    },
    CorpusRecordCountMismatch {
        expected: u64,
        actual: u64,
    },
    CorpusHashMismatch {
        expected: String,
        actual: String,
    },
    ArtifactMismatch {
        surface: &'static str,
    },
    SignatureAlgorithmMismatch {
        expected: String,
        actual: String,
    },
    SignatureKeyMismatch {
        expected: String,
        actual: String,
    },
    SignaturePayloadHashMismatch {
        expected: String,
        actual: String,
    },
    SignatureMismatch {
        expected: String,
        actual: String,
    },
}

impl fmt::Display for CalibrationVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(source) => write!(formatter, "calibration JSON error: {source}"),
            Self::NonCanonicalArtifact => {
                write!(formatter, "calibration artifact bytes are not canonical")
            }
            Self::NonCanonicalCorpusRecord { index } => {
                write!(
                    formatter,
                    "calibration corpus record {index} is not canonical"
                )
            }
            Self::NonCanonicalConformalCorpus => {
                write!(formatter, "conformal corpus bytes are not canonical")
            }
            Self::NonCanonicalConformalRiskSet => {
                write!(formatter, "conformal risk-set bytes are not canonical")
            }
            Self::FloatingPointValue { path } => {
                write!(
                    formatter,
                    "calibration JSON contains floating point value at {path}"
                )
            }
            Self::EmptyCorpus => write!(formatter, "calibration corpus is empty"),
            Self::EmptyConformalSamples => write!(formatter, "conformal sample corpus is empty"),
            Self::EmptySignal { signal_id } => {
                write!(formatter, "calibration signal `{signal_id}` has no samples")
            }
            Self::UnsupportedSchema { expected, actual } => write!(
                formatter,
                "calibration artifact schema mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidField { field, reason } => {
                write!(formatter, "calibration field {field} is invalid: {reason}")
            }
            Self::InvalidHash { field, value } => {
                write!(
                    formatter,
                    "calibration field {field} is not canonical hash: {value}"
                )
            }
            Self::DuplicateConformalSample {
                risk_class,
                sample_id,
            } => write!(
                formatter,
                "duplicate conformal sample `{sample_id}` in risk class `{risk_class}`"
            ),
            Self::MissingConformalRiskClass { risk_class } => write!(
                formatter,
                "conformal artifact has no quantile for risk class `{risk_class}`"
            ),
            Self::ConformalRiskClassMismatch { expected, actual } => write!(
                formatter,
                "conformal risk class mismatch: expected `{expected}`, got `{actual}`"
            ),
            Self::CorpusRecordCountMismatch { expected, actual } => write!(
                formatter,
                "calibration corpus count mismatch: expected {expected}, got {actual}"
            ),
            Self::CorpusHashMismatch {
                expected: _,
                actual: _,
            } => write!(formatter, "calibration corpus hash mismatch"),
            Self::ArtifactMismatch { surface } => {
                write!(formatter, "calibration artifact mismatch at {surface}")
            }
            Self::SignatureAlgorithmMismatch { expected, actual } => write!(
                formatter,
                "calibration signature algorithm mismatch: expected {expected}, got {actual}"
            ),
            Self::SignatureKeyMismatch {
                expected: _,
                actual: _,
            } => write!(formatter, "calibration signature key mismatch"),
            Self::SignaturePayloadHashMismatch {
                expected: _,
                actual: _,
            } => write!(formatter, "calibration signature payload hash mismatch"),
            Self::SignatureMismatch {
                expected: _,
                actual: _,
            } => write!(formatter, "calibration signature mismatch"),
        }
    }
}

impl std::error::Error for CalibrationVerificationError {}

pub type CalibrationVerificationResult<T> = Result<T, CalibrationVerificationError>;

pub fn verify_calibration_artifact_recomputed(
    artifact_canonical_json: &[u8],
    corpus_record_canonical_json: &[Vec<u8>],
    signal_samples: &[CalibrationSignalSamples],
) -> CalibrationVerificationResult<VerifiedCalibrationArtifact> {
    let artifact: SignedCalibrationArtifact = serde_json::from_slice(artifact_canonical_json)
        .map_err(|source| CalibrationVerificationError::Json(source.to_string()))?;
    let canonical = canonical_json_bytes(&artifact)?;
    if canonical != artifact_canonical_json {
        return Err(CalibrationVerificationError::NonCanonicalArtifact);
    }
    validate_artifact(&artifact)?;
    if corpus_record_canonical_json.is_empty() {
        return Err(CalibrationVerificationError::EmptyCorpus);
    }

    let corpus_hash = corpus_hash_from_canonical_records(corpus_record_canonical_json)?;
    let actual_count = u64::try_from(corpus_record_canonical_json.len()).unwrap_or(u64::MAX);
    if artifact.corpus_record_count != actual_count {
        return Err(CalibrationVerificationError::CorpusRecordCountMismatch {
            expected: artifact.corpus_record_count,
            actual: actual_count,
        });
    }
    if !constant_time_eq(&artifact.corpus_hash, &corpus_hash) {
        return Err(CalibrationVerificationError::CorpusHashMismatch {
            expected: artifact.corpus_hash.clone(),
            actual: corpus_hash,
        });
    }

    let expected_unsigned = UnsignedCalibrationArtifact {
        schema_version: CALIBRATION_UNSIGNED_SCHEMA_VERSION.to_string(),
        generated_at: artifact.generated_at.clone(),
        corpus_hash: artifact.corpus_hash.clone(),
        corpus_record_count: artifact.corpus_record_count,
        target_alpha_bp: CALIBRATION_TARGET_ALPHA_BP,
        signals: signal_reports_from_samples(signal_samples)?,
    };
    if artifact.unsigned_payload() != expected_unsigned {
        return Err(CalibrationVerificationError::ArtifactMismatch {
            surface: "unsigned_payload",
        });
    }

    let expected_signature = signature_for_unsigned(&expected_unsigned)?;
    verify_signature_fields(&artifact.signature, &expected_signature)?;

    Ok(VerifiedCalibrationArtifact {
        corpus_hash: artifact.corpus_hash,
        corpus_record_count: artifact.corpus_record_count,
        signal_count: artifact.signals.len(),
        event_codes: vec![
            FN_VSDK_CALIBRATION_RECOMPUTE_START.to_string(),
            FN_VSDK_CALIBRATION_METRICS_RECOMPUTED.to_string(),
            FN_VSDK_CALIBRATION_ARTIFACT_PASS.to_string(),
        ],
    })
}

pub fn verify_conformal_artifact_recomputed(
    artifact_canonical_json: &[u8],
    corpus_samples_canonical_json: &[u8],
) -> CalibrationVerificationResult<VerifiedConformalArtifact> {
    let artifact: ConformalFrozenArtifact = serde_json::from_slice(artifact_canonical_json)
        .map_err(|source| CalibrationVerificationError::Json(source.to_string()))?;
    let canonical = canonical_json_bytes(&artifact)?;
    if canonical != artifact_canonical_json {
        return Err(CalibrationVerificationError::NonCanonicalArtifact);
    }
    validate_conformal_artifact(&artifact)?;
    validate_canonical_json_bytes(corpus_samples_canonical_json)
        .map_err(|_| CalibrationVerificationError::NonCanonicalConformalCorpus)?;

    let samples: Vec<ConformalScoreSample> = serde_json::from_slice(corpus_samples_canonical_json)
        .map_err(|source| CalibrationVerificationError::Json(source.to_string()))?;
    let expected =
        recompute_conformal_artifact(&samples, artifact.target_alpha_bp, &artifact.generated_at)?;
    if artifact != expected {
        return Err(CalibrationVerificationError::ArtifactMismatch {
            surface: "conformal_artifact",
        });
    }

    Ok(VerifiedConformalArtifact {
        corpus_hash: artifact.corpus_hash,
        sample_count: artifact.sample_count,
        risk_class_count: artifact.risk_class_count,
        target_alpha_bp: artifact.target_alpha_bp,
        event_codes: vec![
            FN_VSDK_CONFORMAL_RECOMPUTE_START.to_string(),
            FN_VSDK_CONFORMAL_QUANTILES_RECOMPUTED.to_string(),
            FN_VSDK_CONFORMAL_ARTIFACT_PASS.to_string(),
        ],
    })
}

pub fn recompute_conformal_artifact(
    samples: &[ConformalScoreSample],
    target_alpha_bp: u16,
    generated_at: &str,
) -> CalibrationVerificationResult<ConformalFrozenArtifact> {
    validate_conformal_target_alpha(target_alpha_bp)?;
    validate_nonempty("generated_at", generated_at)?;
    let ordered = ordered_conformal_samples(samples)?;
    let mut by_class: BTreeMap<String, Vec<ConformalNonconformitySample>> = BTreeMap::new();
    for sample in &ordered {
        let nonconformity_bp = if sample.positive {
            MAX_BASIS_POINTS.saturating_sub(sample.score_bp)
        } else {
            sample.score_bp
        };
        by_class
            .entry(sample.risk_class.clone())
            .or_default()
            .push(ConformalNonconformitySample {
                positive: sample.positive,
                nonconformity_bp,
            });
    }

    let mut quantiles = Vec::with_capacity(by_class.len());
    for (risk_class, class_samples) in by_class {
        quantiles.push(conformal_quantile_for_class(
            &risk_class,
            &class_samples,
            target_alpha_bp,
        )?);
    }

    Ok(ConformalFrozenArtifact {
        schema_version: CONFORMAL_FROZEN_QUANTILE_SCHEMA_VERSION.to_string(),
        generated_at: generated_at.to_string(),
        sample_schema_version: CONFORMAL_SAMPLE_SCHEMA_VERSION.to_string(),
        corpus_hash: conformal_corpus_hash(&ordered)?,
        sample_count: u64::try_from(ordered.len()).unwrap_or(u64::MAX),
        risk_class_count: u64::try_from(quantiles.len()).unwrap_or(u64::MAX),
        target_alpha_bp,
        quantiles,
        event_codes: vec![
            FN_CONFORMAL_ARTIFACT_EMITTED.to_string(),
            FN_CONFORMAL_SET_EMITTED.to_string(),
        ],
        audit_notes: vec![
            "split conformal coverage assumes exchangeability; adversarial shift is tracked by ACI instead of overclaiming distribution-free guarantees".to_string(),
            "all scores, nonconformity values, and quantiles are integer basis points".to_string(),
        ],
    })
}

pub fn verify_conformal_risk_set_recomputed(
    risk_set_canonical_json: &[u8],
    artifact: &ConformalFrozenArtifact,
) -> CalibrationVerificationResult<ConformalRiskSet> {
    let risk_set: ConformalRiskSet = serde_json::from_slice(risk_set_canonical_json)
        .map_err(|source| CalibrationVerificationError::Json(source.to_string()))?;
    let canonical = canonical_json_bytes(&risk_set)?;
    if canonical != risk_set_canonical_json {
        return Err(CalibrationVerificationError::NonCanonicalConformalRiskSet);
    }
    let expected = recompute_conformal_risk_set(
        &risk_set.sample_id,
        &risk_set.risk_class,
        risk_set.score_bp,
        artifact,
    )?;
    if risk_set != expected {
        return Err(CalibrationVerificationError::ArtifactMismatch {
            surface: "conformal_risk_set",
        });
    }
    Ok(risk_set)
}

pub fn recompute_conformal_risk_set(
    sample_id: &str,
    risk_class: &str,
    score_bp: u16,
    artifact: &ConformalFrozenArtifact,
) -> CalibrationVerificationResult<ConformalRiskSet> {
    validate_conformal_artifact(artifact)?;
    validate_nonempty("sample_id", sample_id)?;
    validate_nonempty("risk_class", risk_class)?;
    if score_bp > MAX_BASIS_POINTS {
        return Err(CalibrationVerificationError::InvalidField {
            field: "score_bp",
            reason: format!("must not exceed {MAX_BASIS_POINTS}"),
        });
    }
    let quantile = artifact
        .quantiles
        .iter()
        .find(|quantile| quantile.risk_class == risk_class)
        .ok_or_else(|| CalibrationVerificationError::MissingConformalRiskClass {
            risk_class: risk_class.to_string(),
        })?;

    let mut included_labels = Vec::with_capacity(2);
    if score_bp <= quantile.quantile_bp {
        included_labels.push(CONFORMAL_LABEL_BENIGN.to_string());
    }
    if MAX_BASIS_POINTS.saturating_sub(score_bp) <= quantile.quantile_bp {
        included_labels.push(CONFORMAL_LABEL_POSITIVE.to_string());
    }

    Ok(ConformalRiskSet {
        event_code: FN_CONFORMAL_SET_EMITTED.to_string(),
        sample_id: sample_id.to_string(),
        risk_class: risk_class.to_string(),
        score_bp,
        quantile_bp: quantile.quantile_bp,
        included_labels,
    })
}

fn validate_artifact(artifact: &SignedCalibrationArtifact) -> CalibrationVerificationResult<()> {
    if artifact.schema_version != CALIBRATION_ARTIFACT_SCHEMA_VERSION {
        return Err(CalibrationVerificationError::UnsupportedSchema {
            expected: CALIBRATION_ARTIFACT_SCHEMA_VERSION.to_string(),
            actual: artifact.schema_version.clone(),
        });
    }
    validate_nonempty("generated_at", &artifact.generated_at)?;
    validate_sha256_hash("corpus_hash", &artifact.corpus_hash)?;
    if artifact.target_alpha_bp != CALIBRATION_TARGET_ALPHA_BP {
        return Err(CalibrationVerificationError::InvalidField {
            field: "target_alpha_bp",
            reason: format!("must equal {CALIBRATION_TARGET_ALPHA_BP}"),
        });
    }
    if artifact.signals.is_empty() {
        return Err(CalibrationVerificationError::InvalidField {
            field: "signals",
            reason: "at least one signal is required".to_string(),
        });
    }
    validate_nonempty("signature.algorithm", &artifact.signature.algorithm)?;
    validate_nonempty("signature.key_id", &artifact.signature.key_id)?;
    validate_sha256_hash("signature.payload_hash", &artifact.signature.payload_hash)?;
    validate_sha256_hash("signature.signature", &artifact.signature.signature)
}

fn validate_conformal_artifact(
    artifact: &ConformalFrozenArtifact,
) -> CalibrationVerificationResult<()> {
    if artifact.schema_version != CONFORMAL_FROZEN_QUANTILE_SCHEMA_VERSION {
        return Err(CalibrationVerificationError::UnsupportedSchema {
            expected: CONFORMAL_FROZEN_QUANTILE_SCHEMA_VERSION.to_string(),
            actual: artifact.schema_version.clone(),
        });
    }
    validate_nonempty("generated_at", &artifact.generated_at)?;
    if artifact.sample_schema_version != CONFORMAL_SAMPLE_SCHEMA_VERSION {
        return Err(CalibrationVerificationError::UnsupportedSchema {
            expected: CONFORMAL_SAMPLE_SCHEMA_VERSION.to_string(),
            actual: artifact.sample_schema_version.clone(),
        });
    }
    validate_sha256_hash("corpus_hash", &artifact.corpus_hash)?;
    validate_conformal_target_alpha(artifact.target_alpha_bp)?;
    if artifact.quantiles.is_empty() {
        return Err(CalibrationVerificationError::InvalidField {
            field: "quantiles",
            reason: "at least one conformal quantile is required".to_string(),
        });
    }
    if artifact.risk_class_count != u64::try_from(artifact.quantiles.len()).unwrap_or(u64::MAX) {
        return Err(CalibrationVerificationError::InvalidField {
            field: "risk_class_count",
            reason: "must equal quantiles length".to_string(),
        });
    }
    let mut seen = BTreeMap::new();
    let mut sample_total = 0_u64;
    for quantile in &artifact.quantiles {
        validate_conformal_quantile(quantile)?;
        sample_total = sample_total.saturating_add(quantile.sample_count);
        if seen
            .insert(quantile.risk_class.as_str(), quantile.quantile_bp)
            .is_some()
        {
            return Err(CalibrationVerificationError::DuplicateConformalSample {
                risk_class: quantile.risk_class.clone(),
                sample_id: "quantile".to_string(),
            });
        }
    }
    if artifact.sample_count != sample_total {
        return Err(CalibrationVerificationError::InvalidField {
            field: "sample_count",
            reason: "must equal the sum of per-risk-class quantile sample counts".to_string(),
        });
    }
    Ok(())
}

fn validate_conformal_quantile(
    quantile: &ConformalFrozenQuantile,
) -> CalibrationVerificationResult<()> {
    validate_nonempty("risk_class", &quantile.risk_class)?;
    validate_conformal_target_alpha(quantile.target_alpha_bp)?;
    if quantile.sample_count == 0 {
        return Err(CalibrationVerificationError::InvalidField {
            field: "sample_count",
            reason: "must be greater than zero".to_string(),
        });
    }
    if quantile
        .positive_count
        .saturating_add(quantile.negative_count)
        != quantile.sample_count
    {
        return Err(CalibrationVerificationError::InvalidField {
            field: "sample_count",
            reason: "must equal positive_count + negative_count".to_string(),
        });
    }
    if quantile.quantile_rank == 0 || quantile.quantile_rank > quantile.sample_count {
        return Err(CalibrationVerificationError::InvalidField {
            field: "quantile_rank",
            reason: "must be in 1..=sample_count".to_string(),
        });
    }
    for (field, value) in [
        ("quantile_bp", quantile.quantile_bp),
        ("min_nonconformity_bp", quantile.min_nonconformity_bp),
        ("max_nonconformity_bp", quantile.max_nonconformity_bp),
        (
            "finite_sample_coverage_floor_bp",
            quantile.finite_sample_coverage_floor_bp,
        ),
    ] {
        if value > MAX_BASIS_POINTS {
            return Err(CalibrationVerificationError::InvalidField {
                field,
                reason: format!("must not exceed {MAX_BASIS_POINTS}"),
            });
        }
    }
    if quantile.min_nonconformity_bp > quantile.max_nonconformity_bp {
        return Err(CalibrationVerificationError::InvalidField {
            field: "min_nonconformity_bp",
            reason: "must not exceed max_nonconformity_bp".to_string(),
        });
    }
    Ok(())
}

fn validate_conformal_target_alpha(target_alpha_bp: u16) -> CalibrationVerificationResult<()> {
    if target_alpha_bp >= MAX_BASIS_POINTS {
        return Err(CalibrationVerificationError::InvalidField {
            field: "target_alpha_bp",
            reason: format!("must be less than {MAX_BASIS_POINTS}"),
        });
    }
    Ok(())
}

fn validate_nonempty(field: &'static str, value: &str) -> CalibrationVerificationResult<()> {
    if value.trim().is_empty() {
        return Err(CalibrationVerificationError::InvalidField {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    Ok(())
}

fn validate_sha256_hash(field: &'static str, value: &str) -> CalibrationVerificationResult<()> {
    let Some(hex) = value.strip_prefix(SHA256_PREFIX) else {
        return Err(CalibrationVerificationError::InvalidHash {
            field,
            value: value.to_string(),
        });
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CalibrationVerificationError::InvalidHash {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn verify_signature_fields(
    actual: &CalibrationArtifactSignature,
    expected: &CalibrationArtifactSignature,
) -> CalibrationVerificationResult<()> {
    if !constant_time_eq(&actual.algorithm, &expected.algorithm) {
        return Err(CalibrationVerificationError::SignatureAlgorithmMismatch {
            expected: expected.algorithm.clone(),
            actual: actual.algorithm.clone(),
        });
    }
    if !constant_time_eq(&actual.key_id, &expected.key_id) {
        return Err(CalibrationVerificationError::SignatureKeyMismatch {
            expected: expected.key_id.clone(),
            actual: actual.key_id.clone(),
        });
    }
    if !constant_time_eq(&actual.payload_hash, &expected.payload_hash) {
        return Err(CalibrationVerificationError::SignaturePayloadHashMismatch {
            expected: expected.payload_hash.clone(),
            actual: actual.payload_hash.clone(),
        });
    }
    if !constant_time_eq(&actual.signature, &expected.signature) {
        return Err(CalibrationVerificationError::SignatureMismatch {
            expected: expected.signature.clone(),
            actual: actual.signature.clone(),
        });
    }
    Ok(())
}

fn signal_reports_from_samples(
    signal_samples: &[CalibrationSignalSamples],
) -> CalibrationVerificationResult<Vec<CalibrationSignalReport>> {
    signal_samples
        .iter()
        .map(signal_report_from_samples)
        .collect()
}

fn signal_report_from_samples(
    signal_samples: &CalibrationSignalSamples,
) -> CalibrationVerificationResult<CalibrationSignalReport> {
    validate_nonempty("signal_id", &signal_samples.signal_id)?;
    validate_nonempty(
        "signal_schema_version",
        &signal_samples.signal_schema_version,
    )?;
    if signal_samples.samples.is_empty() {
        return Err(CalibrationVerificationError::EmptySignal {
            signal_id: signal_samples.signal_id.clone(),
        });
    }
    for sample in &signal_samples.samples {
        validate_nonempty("sample_id", &sample.sample_id)?;
        if sample.score_bp > MAX_BASIS_POINTS {
            return Err(CalibrationVerificationError::InvalidField {
                field: "score_bp",
                reason: format!("must not exceed {MAX_BASIS_POINTS}"),
            });
        }
    }
    Ok(CalibrationSignalReport {
        signal_id: signal_samples.signal_id.clone(),
        signal_schema_version: signal_samples.signal_schema_version.clone(),
        metric_notes: signal_samples.metric_notes.clone(),
        metrics: compute_metrics(&signal_samples.signal_id, &signal_samples.samples)?,
    })
}

fn compute_metrics(
    signal_id: &str,
    samples: &[CalibrationSample],
) -> CalibrationVerificationResult<CalibrationMetrics> {
    if samples.is_empty() {
        return Err(CalibrationVerificationError::EmptySignal {
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

fn ordered_conformal_samples(
    samples: &[ConformalScoreSample],
) -> CalibrationVerificationResult<Vec<ConformalScoreSample>> {
    if samples.is_empty() {
        return Err(CalibrationVerificationError::EmptyConformalSamples);
    }
    let mut ordered = BTreeMap::new();
    for sample in samples {
        validate_conformal_sample(sample)?;
        let key = (sample.risk_class.clone(), sample.sample_id.clone());
        if ordered.insert(key, sample.clone()).is_some() {
            return Err(CalibrationVerificationError::DuplicateConformalSample {
                risk_class: sample.risk_class.clone(),
                sample_id: sample.sample_id.clone(),
            });
        }
    }
    Ok(ordered.into_values().collect())
}

fn validate_conformal_sample(sample: &ConformalScoreSample) -> CalibrationVerificationResult<()> {
    validate_nonempty("sample_id", &sample.sample_id)?;
    validate_nonempty("risk_class", &sample.risk_class)?;
    if sample.score_bp > MAX_BASIS_POINTS {
        return Err(CalibrationVerificationError::InvalidField {
            field: "score_bp",
            reason: format!("must not exceed {MAX_BASIS_POINTS}"),
        });
    }
    Ok(())
}

fn conformal_quantile_for_class(
    risk_class: &str,
    samples: &[ConformalNonconformitySample],
    target_alpha_bp: u16,
) -> CalibrationVerificationResult<ConformalFrozenQuantile> {
    if samples.is_empty() {
        return Err(CalibrationVerificationError::MissingConformalRiskClass {
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

    Ok(ConformalFrozenQuantile {
        risk_class: risk_class.to_string(),
        sample_count,
        positive_count,
        negative_count: sample_count.saturating_sub(positive_count),
        target_alpha_bp,
        quantile_rank: u64::try_from(rank).unwrap_or(u64::MAX),
        quantile_bp,
        min_nonconformity_bp: values[0],
        max_nonconformity_bp: values[values.len().saturating_sub(1)],
        finite_sample_coverage_floor_bp: floor_ratio_bp(
            u64::try_from(rank).unwrap_or(u64::MAX),
            sample_count.saturating_add(1),
        ),
    })
}

fn conformal_quantile_rank(
    sample_count: usize,
    target_alpha_bp: u16,
) -> CalibrationVerificationResult<usize> {
    if sample_count == 0 {
        return Err(CalibrationVerificationError::EmptyConformalSamples);
    }
    validate_conformal_target_alpha(target_alpha_bp)?;
    let numerator = u128::try_from(sample_count.saturating_add(1))
        .unwrap_or(u128::MAX)
        .saturating_mul(u128::from(MAX_BASIS_POINTS.saturating_sub(target_alpha_bp)));
    let rank = ceil_div(numerator, u128::from(MAX_BASIS_POINTS));
    let rank = usize::try_from(rank).unwrap_or(usize::MAX);
    Ok(rank.clamp(1, sample_count))
}

fn conformal_corpus_hash(
    samples: &[ConformalScoreSample],
) -> CalibrationVerificationResult<String> {
    let payload = canonical_json_bytes(&samples.to_vec())?;
    Ok(sha256_zero_prefixed(
        b"conformal-calibration-corpus-v1",
        &payload,
    ))
}

fn corpus_hash_from_canonical_records(
    records: &[Vec<u8>],
) -> CalibrationVerificationResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"bpet-calibration-corpus-v1");
    for (index, record) in records.iter().enumerate() {
        validate_canonical_json_bytes(record)
            .map_err(|_| CalibrationVerificationError::NonCanonicalCorpusRecord { index })?;
        update_len_prefixed(&mut hasher, record);
    }
    Ok(format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize())))
}

fn signature_for_unsigned(
    unsigned: &UnsignedCalibrationArtifact,
) -> CalibrationVerificationResult<CalibrationArtifactSignature> {
    let payload = canonical_json_bytes(unsigned)?;
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

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    if numerator == 0 {
        0
    } else {
        numerator.saturating_sub(1) / denominator + 1
    }
}

fn canonical_json_bytes(value: &impl Serialize) -> CalibrationVerificationResult<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|source| CalibrationVerificationError::Json(source.to_string()))?;
    reject_float_values(&value, "$")?;
    canonical_json_value_bytes(value)
}

fn validate_canonical_json_bytes(bytes: &[u8]) -> CalibrationVerificationResult<()> {
    let value = serde_json::from_slice::<Value>(bytes)
        .map_err(|source| CalibrationVerificationError::Json(source.to_string()))?;
    reject_float_values(&value, "$")?;
    let canonical = canonical_json_value_bytes(value)?;
    if canonical != bytes {
        return Err(CalibrationVerificationError::NonCanonicalArtifact);
    }
    Ok(())
}

fn canonical_json_value_bytes(value: Value) -> CalibrationVerificationResult<Vec<u8>> {
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical)
        .map_err(|source| CalibrationVerificationError::Json(source.to_string()))
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut object = serde_json::Map::with_capacity(entries.len());
            for (key, value) in entries {
                object.insert(key, canonicalize_value(value));
            }
            Value::Object(object)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn reject_float_values(value: &Value, path: &str) -> CalibrationVerificationResult<()> {
    match value {
        Value::Number(number) if number.is_f64() => {
            Err(CalibrationVerificationError::FloatingPointValue {
                path: path.to_string(),
            })
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_float_values(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, item) in map {
                reject_float_values(item, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn sha256_prefixed(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_len_prefixed(&mut hasher, payload);
    format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn sha256_zero_prefixed(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(payload);
    format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
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

fn floor_ratio_bp(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let scaled = u128::from(numerator).saturating_mul(u128::from(MAX_BASIS_POINTS));
    u16::try_from(scaled / u128::from(denominator)).unwrap_or(MAX_BASIS_POINTS)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records() -> Vec<Vec<u8>> {
        vec![
            br#"{"record_id":"alpha"}"#.to_vec(),
            br#"{"record_id":"beta"}"#.to_vec(),
        ]
    }

    fn sample_signals() -> Vec<CalibrationSignalSamples> {
        vec![CalibrationSignalSamples {
            signal_id: "test.signal".to_string(),
            signal_schema_version: "test.signal.v1".to_string(),
            metric_notes: vec!["deterministic fixture samples".to_string()],
            samples: vec![
                CalibrationSample {
                    sample_id: "alpha".to_string(),
                    score_bp: 9_000,
                    positive: true,
                },
                CalibrationSample {
                    sample_id: "beta".to_string(),
                    score_bp: 1_000,
                    positive: false,
                },
            ],
        }]
    }

    fn signed_fixture(
        records: &[Vec<u8>],
        signals: &[CalibrationSignalSamples],
    ) -> SignedCalibrationArtifact {
        let unsigned = UnsignedCalibrationArtifact {
            schema_version: CALIBRATION_UNSIGNED_SCHEMA_VERSION.to_string(),
            generated_at: "1970-01-01T00:00:00Z".to_string(),
            corpus_hash: corpus_hash_from_canonical_records(records).expect("corpus hash"),
            corpus_record_count: u64::try_from(records.len()).unwrap_or(u64::MAX),
            target_alpha_bp: CALIBRATION_TARGET_ALPHA_BP,
            signals: signal_reports_from_samples(signals).expect("signal reports"),
        };
        let signature = signature_for_unsigned(&unsigned).expect("signature");
        SignedCalibrationArtifact {
            schema_version: CALIBRATION_ARTIFACT_SCHEMA_VERSION.to_string(),
            generated_at: unsigned.generated_at,
            corpus_hash: unsigned.corpus_hash,
            corpus_record_count: unsigned.corpus_record_count,
            target_alpha_bp: unsigned.target_alpha_bp,
            signals: unsigned.signals,
            signature,
        }
    }

    fn conformal_sample(
        sample_id: &str,
        risk_class: &str,
        score_bp: u16,
        positive: bool,
    ) -> ConformalScoreSample {
        ConformalScoreSample {
            sample_id: sample_id.to_string(),
            risk_class: risk_class.to_string(),
            score_bp,
            positive,
        }
    }

    fn conformal_samples() -> Vec<ConformalScoreSample> {
        vec![
            conformal_sample("s4", "evolution", 4_000, false),
            conformal_sample("s1", "evolution", 9_000, true),
            conformal_sample("s3", "evolution", 2_000, false),
            conformal_sample("s2", "evolution", 8_000, true),
            conformal_sample("c1", "camouflage", 6_000, true),
            conformal_sample("c2", "camouflage", 1_000, false),
        ]
    }

    fn conformal_bpet_trust_surface_samples() -> Vec<ConformalScoreSample> {
        vec![
            conformal_sample("e1", "bpet_evolution", 9_000, true),
            conformal_sample("e2", "bpet_evolution", 8_000, true),
            conformal_sample("e3", "bpet_evolution", 2_000, false),
            conformal_sample("e4", "bpet_evolution", 4_000, false),
            conformal_sample("c1", "bpet_camouflage", 9_500, true),
            conformal_sample("c2", "bpet_camouflage", 8_500, true),
            conformal_sample("c3", "bpet_camouflage", 1_500, false),
            conformal_sample("c4", "bpet_camouflage", 3_500, false),
            conformal_sample("d1", "bpet_dgis_fusion", 9_200, true),
            conformal_sample("d2", "bpet_dgis_fusion", 7_800, true),
            conformal_sample("d3", "bpet_dgis_fusion", 1_600, false),
            conformal_sample("d4", "bpet_dgis_fusion", 3_600, false),
        ]
    }

    #[test]
    fn recomputed_calibration_artifact_verifies() {
        let records = sample_records();
        let signals = sample_signals();
        let artifact = signed_fixture(&records, &signals);
        let artifact_bytes = canonical_json_bytes(&artifact).expect("canonical artifact");

        let verified = verify_calibration_artifact_recomputed(&artifact_bytes, &records, &signals)
            .expect("artifact verifies");

        assert_eq!(verified.corpus_record_count, 2);
        assert_eq!(verified.signal_count, 1);
        assert_eq!(
            verified.event_codes,
            vec![
                FN_VSDK_CALIBRATION_RECOMPUTE_START.to_string(),
                FN_VSDK_CALIBRATION_METRICS_RECOMPUTED.to_string(),
                FN_VSDK_CALIBRATION_ARTIFACT_PASS.to_string()
            ]
        );
    }

    #[test]
    fn sample_mismatch_fails_closed() {
        let records = sample_records();
        let signals = sample_signals();
        let artifact = signed_fixture(&records, &signals);
        let artifact_bytes = canonical_json_bytes(&artifact).expect("canonical artifact");
        let mut tampered_signals = signals;
        tampered_signals[0].samples[0].score_bp = 4_000;

        let error =
            verify_calibration_artifact_recomputed(&artifact_bytes, &records, &tampered_signals)
                .expect_err("tampered samples must fail");

        assert!(matches!(
            error,
            CalibrationVerificationError::ArtifactMismatch {
                surface: "unsigned_payload"
            }
        ));
    }

    #[test]
    fn noncanonical_corpus_record_fails_closed() {
        let records = vec![br#"{ "record_id":"alpha"}"#.to_vec()];
        let signals = sample_signals();
        let canonical_records = sample_records();
        let artifact = signed_fixture(&canonical_records, &signals);
        let artifact_bytes = canonical_json_bytes(&artifact).expect("canonical artifact");

        let error = verify_calibration_artifact_recomputed(&artifact_bytes, &records, &signals)
            .expect_err("noncanonical corpus must fail");

        assert!(matches!(
            error,
            CalibrationVerificationError::NonCanonicalCorpusRecord { index: 0 }
        ));
    }

    #[test]
    fn recomputed_conformal_artifact_and_risk_set_verify() {
        let samples = conformal_samples();
        let artifact =
            recompute_conformal_artifact(&samples, 2_000, "1970-01-01T00:00:00Z").unwrap();
        let artifact_bytes = canonical_json_bytes(&artifact).expect("canonical artifact");
        let sample_bytes = canonical_json_bytes(&samples).expect("canonical samples");

        let verified =
            verify_conformal_artifact_recomputed(&artifact_bytes, &sample_bytes).unwrap();

        assert_eq!(verified.sample_count, 6);
        assert_eq!(verified.risk_class_count, 2);
        assert_eq!(verified.target_alpha_bp, 2_000);
        assert_eq!(
            verified.event_codes,
            vec![
                FN_VSDK_CONFORMAL_RECOMPUTE_START.to_string(),
                FN_VSDK_CONFORMAL_QUANTILES_RECOMPUTED.to_string(),
                FN_VSDK_CONFORMAL_ARTIFACT_PASS.to_string()
            ]
        );

        let risk_set =
            recompute_conformal_risk_set("candidate", "evolution", 8_500, &artifact).unwrap();
        let risk_set_bytes = canonical_json_bytes(&risk_set).expect("canonical risk set");
        let verified_risk_set =
            verify_conformal_risk_set_recomputed(&risk_set_bytes, &artifact).unwrap();

        assert_eq!(verified_risk_set.quantile_bp, 4_000);
        assert_eq!(
            verified_risk_set.included_labels,
            vec![CONFORMAL_LABEL_POSITIVE.to_string()]
        );
    }

    #[test]
    fn bpet_trust_surface_conformal_sets_recompute_from_canonical_sdk_inputs() {
        let samples = conformal_bpet_trust_surface_samples();
        let artifact =
            recompute_conformal_artifact(&samples, 2_000, "1970-01-01T00:00:00Z").unwrap();
        let artifact_bytes = canonical_json_bytes(&artifact).expect("canonical artifact");
        let sample_bytes = canonical_json_bytes(&samples).expect("canonical samples");

        let verified =
            verify_conformal_artifact_recomputed(&artifact_bytes, &sample_bytes).unwrap();

        assert_eq!(verified.sample_count, 12);
        assert_eq!(verified.risk_class_count, 3);
        assert_eq!(
            artifact.event_codes,
            vec![
                FN_CONFORMAL_ARTIFACT_EMITTED.to_string(),
                FN_CONFORMAL_SET_EMITTED.to_string()
            ]
        );
        assert!(artifact.corpus_hash.starts_with("sha256:"));
        assert!(artifact.audit_notes.iter().any(|note| {
            note.contains("assumes exchangeability")
                && note.contains("ACI")
                && note.contains("distribution-free guarantees")
        }));

        for (sample_id, risk_class, score_bp, expected_quantile_bp) in [
            ("npm:@acme/evolution@1.0.0", "bpet_evolution", 10_000, 4_000),
            (
                "npm:@acme/camouflage@1.0.0",
                "bpet_camouflage",
                10_000,
                3_500,
            ),
            (
                "npm:@acme/critical-auth@1.0.0",
                "bpet_dgis_fusion",
                8_047,
                3_600,
            ),
        ] {
            let risk_set =
                recompute_conformal_risk_set(sample_id, risk_class, score_bp, &artifact).unwrap();
            let risk_set_bytes = canonical_json_bytes(&risk_set).expect("canonical risk set");
            let verified_risk_set =
                verify_conformal_risk_set_recomputed(&risk_set_bytes, &artifact).unwrap();

            assert_eq!(verified_risk_set.event_code, FN_CONFORMAL_SET_EMITTED);
            assert_eq!(verified_risk_set.risk_class, risk_class);
            assert_eq!(verified_risk_set.quantile_bp, expected_quantile_bp);
            assert_eq!(
                verified_risk_set.included_labels,
                vec![CONFORMAL_LABEL_POSITIVE.to_string()]
            );
        }
    }

    #[test]
    fn conformal_sample_mismatch_fails_closed() {
        let samples = conformal_samples();
        let artifact =
            recompute_conformal_artifact(&samples, 2_000, "1970-01-01T00:00:00Z").unwrap();
        let artifact_bytes = canonical_json_bytes(&artifact).expect("canonical artifact");
        let mut tampered_samples = samples;
        tampered_samples[0].score_bp = 9_999;
        let tampered_sample_bytes =
            canonical_json_bytes(&tampered_samples).expect("canonical samples");

        let error = verify_conformal_artifact_recomputed(&artifact_bytes, &tampered_sample_bytes)
            .expect_err("tampered conformal sample corpus must fail");

        assert!(matches!(
            error,
            CalibrationVerificationError::ArtifactMismatch {
                surface: "conformal_artifact"
            }
        ));
    }

    #[test]
    fn conformal_missing_risk_class_fails_closed() {
        let samples = conformal_samples();
        let artifact =
            recompute_conformal_artifact(&samples, 2_000, "1970-01-01T00:00:00Z").unwrap();

        let error =
            recompute_conformal_risk_set("candidate", "missing", 5_000, &artifact).unwrap_err();

        assert!(matches!(
            error,
            CalibrationVerificationError::MissingConformalRiskClass { .. }
        ));
    }
}
