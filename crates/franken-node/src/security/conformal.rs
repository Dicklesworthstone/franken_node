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
pub const CONFORMAL_CALIBRATION_RECEIPT_SCHEMA_VERSION: &str =
    "franken-node/conformal-calibration-receipt/v1";
pub const CONFORMAL_CALIBRATION_SIGNATURE_DOMAIN: &[u8] =
    b"franken-node:conformal-calibration-receipt:v1:";
pub const DEFAULT_MIN_CALIBRATION_SAMPLES: u64 = 16;
pub const STRICT_CONSERVATIVE_FALLBACK_MODE: &str = "strict_conservative";
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
    #[error("minimum calibration sample floor must be >= 1, got {0}")]
    InvalidMinSamples(u64),
    #[error("conformal receipt signature verification failed: {reason}")]
    InvalidSignature { reason: String },
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalClassCalibrationPolicy {
    pub risk_class: String,
    pub sample_count: u64,
    pub min_samples_required: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_mode: Option<String>,
    pub effective_benign_refusal_ceiling_bp: u16,
    pub quantile: FrozenConformalQuantile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalCandidateAdvisory {
    pub sample_id: String,
    pub risk_class: String,
    pub score_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalCandidateVerdict {
    pub sample_id: String,
    pub risk_class: String,
    pub score_bp: u16,
    pub decision: String,
    pub fallback_applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_set: Option<ConformalRiskSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalReceiptSignature {
    pub algorithm: String,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize)]
struct ConformalCalibrationUnsignedPayload<'a> {
    schema_version: &'a str,
    generated_at: &'a str,
    target_alpha_bp: u16,
    min_samples_required: u64,
    artifact: &'a FrozenConformalArtifact,
    class_policies: &'a [ConformalClassCalibrationPolicy],
    evaluations: &'a [ConformalCandidateVerdict],
    aci_updates: &'a [AciQuantileUpdate],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalCalibrationReceipt {
    pub schema_version: String,
    pub generated_at: String,
    pub target_alpha_bp: u16,
    pub min_samples_required: u64,
    pub artifact: FrozenConformalArtifact,
    pub class_policies: Vec<ConformalClassCalibrationPolicy>,
    pub evaluations: Vec<ConformalCandidateVerdict>,
    pub aci_updates: Vec<AciQuantileUpdate>,
    pub receipt_payload_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ConformalReceiptSignature>,
}

impl ConformalCalibrationReceipt {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ConformalCalibrationError> {
        let unsigned = ConformalCalibrationUnsignedPayload {
            schema_version: &self.schema_version,
            generated_at: &self.generated_at,
            target_alpha_bp: self.target_alpha_bp,
            min_samples_required: self.min_samples_required,
            artifact: &self.artifact,
            class_policies: &self.class_policies,
            evaluations: &self.evaluations,
            aci_updates: &self.aci_updates,
        };
        let value = serde_json::to_value(unsigned)
            .map_err(|source| ConformalCalibrationError::Serialize { source })?;
        Ok(canonical_bytes(&value))
    }

    pub fn sign_with_ed25519(
        &mut self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ConformalCalibrationError> {
        use ed25519_dalek::Signer as _;

        let payload_bytes = self.unsigned_canonical_bytes()?;
        let mut msg =
            Vec::with_capacity(CONFORMAL_CALIBRATION_SIGNATURE_DOMAIN.len() + payload_bytes.len());
        msg.extend_from_slice(CONFORMAL_CALIBRATION_SIGNATURE_DOMAIN);
        msg.extend_from_slice(&payload_bytes);
        let sig = signing_key.sign(&msg);
        self.signature = Some(ConformalReceiptSignature {
            algorithm: "ed25519".to_string(),
            signer_public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            signature_hex: hex::encode(sig.to_bytes()),
        });
        Ok(())
    }

    pub fn verify_ed25519_signature(
        &self,
        trusted_verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), ConformalCalibrationError> {
        use subtle::ConstantTimeEq as _;

        let sig =
            self.signature
                .as_ref()
                .ok_or_else(|| ConformalCalibrationError::InvalidSignature {
                    reason: "receipt carries no Ed25519 signature".to_string(),
                })?;
        if sig.algorithm != "ed25519" {
            return Err(ConformalCalibrationError::InvalidSignature {
                reason: format!("unsupported signature algorithm `{}`", sig.algorithm),
            });
        }
        let expected_pk_hex = hex::encode(trusted_verifying_key.to_bytes());
        if !bool::from(
            sig.signer_public_key_hex
                .as_bytes()
                .ct_eq(expected_pk_hex.as_bytes()),
        ) {
            return Err(ConformalCalibrationError::InvalidSignature {
                reason: "signer_public_key_hex does not match trusted verifying key".to_string(),
            });
        }
        let payload_bytes = self.unsigned_canonical_bytes()?;
        let expected_hash = sha256_prefixed(b"conformal.calibration_receipt.v1", &payload_bytes);
        if !bool::from(
            self.receipt_payload_sha256
                .as_bytes()
                .ct_eq(expected_hash.as_bytes()),
        ) {
            return Err(ConformalCalibrationError::InvalidSignature {
                reason: "receipt_payload_sha256 does not match unsigned canonical payload"
                    .to_string(),
            });
        }
        let sig_bytes: [u8; 64] = hex::decode(&sig.signature_hex)
            .map_err(|_| ConformalCalibrationError::InvalidSignature {
                reason: "signature_hex is not valid hex".to_string(),
            })?
            .try_into()
            .map_err(|_| ConformalCalibrationError::InvalidSignature {
                reason: "signature_hex must decode to 64 bytes".to_string(),
            })?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let mut msg =
            Vec::with_capacity(CONFORMAL_CALIBRATION_SIGNATURE_DOMAIN.len() + payload_bytes.len());
        msg.extend_from_slice(CONFORMAL_CALIBRATION_SIGNATURE_DOMAIN);
        msg.extend_from_slice(&payload_bytes);
        trusted_verifying_key
            .verify_strict(&msg, &ed_sig)
            .map_err(|_| ConformalCalibrationError::InvalidSignature {
                reason: "Ed25519 signature verification failed".to_string(),
            })
    }
}

/// Calibrate split-conformal quantiles (`q_{1-alpha}`) per risk class and evaluate
/// candidate advisories with conservative strict fallback whenever `n < min_samples_required`
/// (`bd-reality-20260923-26n9r.13`).
pub fn calibrate_advisories_with_fallback(
    samples: &[ConformalScoreSample],
    target_alpha_bp: u16,
    min_samples_required: u64,
    generated_at: &str,
    candidates: &[ConformalCandidateAdvisory],
    aci_learning_rate_bp: Option<u16>,
    aci_observations: &[AciCoverageObservation],
) -> Result<ConformalCalibrationReceipt, ConformalCalibrationError> {
    if min_samples_required == 0 {
        return Err(ConformalCalibrationError::InvalidMinSamples(0));
    }
    let artifact = freeze_quantiles_with_generated_at(samples, target_alpha_bp, generated_at)?;
    let mut class_policies = Vec::with_capacity(artifact.quantiles.len());
    for quantile in &artifact.quantiles {
        let under_sampled = quantile.sample_count < min_samples_required;
        let effective_benign_refusal_ceiling_bp =
            MAX_BASIS_POINTS.saturating_sub(quantile.finite_sample_coverage_floor_bp);
        class_policies.push(ConformalClassCalibrationPolicy {
            risk_class: quantile.risk_class.clone(),
            sample_count: quantile.sample_count,
            min_samples_required,
            fallback_mode: under_sampled.then(|| STRICT_CONSERVATIVE_FALLBACK_MODE.to_string()),
            effective_benign_refusal_ceiling_bp,
            quantile: quantile.clone(),
        });
    }

    let mut evaluations = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if candidate.sample_id.trim().is_empty() {
            return Err(ConformalCalibrationError::InvalidSample {
                sample_id: candidate.sample_id.clone(),
                field: "sample_id",
                reason: "must not be empty".to_string(),
            });
        }
        let policy = class_policies
            .iter()
            .find(|p| p.risk_class == candidate.risk_class)
            .ok_or_else(|| ConformalCalibrationError::MissingRiskClassQuantile {
                risk_class: candidate.risk_class.clone(),
            })?;
        if policy.fallback_mode.is_some() {
            // Conservative strict fallback when `n < n_min`: never rely on an
            // under-sampled conformal quantile; any nonzero anomaly score fails closed.
            let decision = if candidate.score_bp == 0 {
                "strict_fallback_allow_zero_score"
            } else {
                "strict_fallback_refuse"
            };
            evaluations.push(ConformalCandidateVerdict {
                sample_id: candidate.sample_id.clone(),
                risk_class: candidate.risk_class.clone(),
                score_bp: candidate.score_bp,
                decision: decision.to_string(),
                fallback_applied: true,
                risk_set: None,
            });
        } else {
            let risk_set = calibrated_binary_risk_set(
                &candidate.sample_id,
                &candidate.risk_class,
                candidate.score_bp,
                &policy.quantile,
            )?;
            let has_benign = risk_set.included_labels.iter().any(|l| l == LABEL_BENIGN);
            let has_positive = risk_set.included_labels.iter().any(|l| l == LABEL_POSITIVE);
            let decision = match (has_benign, has_positive) {
                (true, false) => "allow_benign",
                (false, true) => "refuse_positive",
                _ => "review_ambiguous",
            };
            evaluations.push(ConformalCandidateVerdict {
                sample_id: candidate.sample_id.clone(),
                risk_class: candidate.risk_class.clone(),
                score_bp: candidate.score_bp,
                decision: decision.to_string(),
                fallback_applied: false,
                risk_set: Some(risk_set),
            });
        }
    }

    let mut aci_updates = Vec::new();
    if let Some(lr_bp) = aci_learning_rate_bp {
        validate_learning_rate(lr_bp)?;
        let mut states: BTreeMap<String, AciQuantileState> = BTreeMap::new();
        for quantile in &artifact.quantiles {
            states.insert(
                quantile.risk_class.clone(),
                initialize_aci_state(quantile, lr_bp)?,
            );
        }
        for obs in aci_observations {
            let state = states.get_mut(&obs.risk_class).ok_or_else(|| {
                ConformalCalibrationError::MissingRiskClassQuantile {
                    risk_class: obs.risk_class.clone(),
                }
            })?;
            aci_updates.push(update_aci_quantile(state, obs)?);
        }
    }

    let mut receipt = ConformalCalibrationReceipt {
        schema_version: CONFORMAL_CALIBRATION_RECEIPT_SCHEMA_VERSION.to_string(),
        generated_at: generated_at.to_string(),
        target_alpha_bp,
        min_samples_required,
        artifact,
        class_policies,
        evaluations,
        aci_updates,
        receipt_payload_sha256: String::new(),
        signature: None,
    };
    let payload_bytes = receipt.unsigned_canonical_bytes()?;
    receipt.receipt_payload_sha256 =
        sha256_prefixed(b"conformal.calibration_receipt.v1", &payload_bytes);
    Ok(receipt)
}

/// Deterministic held-out benign + adversarial migration advisory corpus (`24` samples)
/// used when `--builtin-benign-corpus` is requested on `franken-node trust calibrate-conformal`.
#[must_use]
pub fn builtin_benign_migration_calibration_corpus() -> Vec<ConformalScoreSample> {
    let benign_scores_bp: [u16; 20] = [
        40, 65, 80, 95, 110, 125, 140, 155, 170, 185, 200, 215, 230, 250, 275, 300, 325, 360, 410,
        480,
    ];
    let positive_scores_bp: [u16; 4] = [9_100, 9_350, 9_600, 9_850];
    let mut out = Vec::with_capacity(benign_scores_bp.len() + positive_scores_bp.len());
    for (idx, score_bp) in benign_scores_bp.into_iter().enumerate() {
        out.push(ConformalScoreSample {
            sample_id: format!("benign-migration-{:02}", idx + 1),
            risk_class: "migration_advisory".to_string(),
            score_bp,
            positive: false,
        });
    }
    for (idx, score_bp) in positive_scores_bp.into_iter().enumerate() {
        out.push(ConformalScoreSample {
            sample_id: format!("exfil-probe-{:02}", idx + 1),
            risk_class: "migration_advisory".to_string(),
            score_bp,
            positive: true,
        });
    }
    out
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

    fn sample_from_nonconformity(
        id: &str,
        risk_class: &str,
        nonconformity_bp: u16,
        positive: bool,
    ) -> ConformalScoreSample {
        let score_bp = if positive {
            MAX_BASIS_POINTS.saturating_sub(nonconformity_bp)
        } else {
            nonconformity_bp
        };
        sample(id, risk_class, score_bp, positive)
    }

    fn calibration_samples_for_class(risk_class: &str) -> Vec<ConformalScoreSample> {
        [
            500_u16, 600, 700, 800, 900, 1_000, 1_500, 2_000, 3_000, 4_000,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, nonconformity_bp)| {
            sample_from_nonconformity(
                &format!("{risk_class}-cal-{index:02}"),
                risk_class,
                nonconformity_bp,
                index % 2 == 0,
            )
        })
        .collect()
    }

    fn heldout_samples_for_class(risk_class: &str) -> Vec<ConformalScoreSample> {
        [
            400_u16, 650, 750, 900, 1_100, 1_400, 1_800, 2_200, 3_000, 4_500,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, nonconformity_bp)| {
            sample_from_nonconformity(
                &format!("{risk_class}-heldout-{index:02}"),
                risk_class,
                nonconformity_bp,
                index % 2 == 0,
            )
        })
        .collect()
    }

    fn expected_label(sample: &ConformalScoreSample) -> &str {
        if sample.positive {
            LABEL_POSITIVE
        } else {
            LABEL_BENIGN
        }
    }

    fn risk_set_covers_sample(set: &ConformalRiskSet, sample: &ConformalScoreSample) -> bool {
        set.included_labels
            .iter()
            .any(|label| label == expected_label(sample))
    }

    fn empirical_coverage_bp(
        artifact: &FrozenConformalArtifact,
        samples: &[ConformalScoreSample],
    ) -> u16 {
        let covered = samples
            .iter()
            .filter(|sample| {
                let set = calibrated_mondrian_risk_set(
                    &sample.sample_id,
                    &sample.risk_class,
                    sample.score_bp,
                    artifact,
                )
                .expect("held-out sample has a matching quantile");
                risk_set_covers_sample(&set, sample)
            })
            .count();
        ratio_bp(
            u64::try_from(covered).unwrap_or(u64::MAX),
            u64::try_from(samples.len()).unwrap_or(u64::MAX),
        )
    }

    fn quantile_for<'a>(
        artifact: &'a FrozenConformalArtifact,
        risk_class: &str,
    ) -> &'a FrozenConformalQuantile {
        artifact
            .quantiles
            .iter()
            .find(|quantile| quantile.risk_class == risk_class)
            .expect("risk class quantile exists")
    }

    fn shifted_positive(sample_id: &str) -> ConformalScoreSample {
        sample(sample_id, "critical", 7_000, true)
    }

    fn covered_by_current_aci_state(
        state: &AciQuantileState,
        sample: &ConformalScoreSample,
    ) -> bool {
        let nonconformity_bp = if sample.positive {
            MAX_BASIS_POINTS.saturating_sub(sample.score_bp)
        } else {
            sample.score_bp
        };
        nonconformity_bp <= state.current_quantile_bp
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
    fn exchangeable_heldout_empirical_coverage_meets_target_without_overclaim() {
        let mut calibration = calibration_samples_for_class("critical");
        calibration.extend(calibration_samples_for_class("low"));
        let artifact = freeze_quantiles(&calibration, 2_000).unwrap();

        assert_eq!(quantile_for(&artifact, "critical").quantile_bp, 3_000);
        assert_eq!(quantile_for(&artifact, "low").quantile_bp, 3_000);
        assert!(
            artifact
                .audit_notes
                .iter()
                .any(|note| note.contains("assumes exchangeability"))
        );
        assert!(artifact.audit_notes.iter().any(|note| note.contains("ACI")));

        let mut heldout = heldout_samples_for_class("critical");
        heldout.extend(heldout_samples_for_class("low"));
        let coverage_bp = empirical_coverage_bp(&artifact, &heldout);

        assert_eq!(coverage_bp, 9_000);
        assert!(coverage_bp >= MAX_BASIS_POINTS.saturating_sub(artifact.target_alpha_bp));
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
    fn adversarial_shift_degrades_plain_split_conformal_and_aci_recovers_tail_coverage() {
        let quantile = FrozenConformalQuantile {
            risk_class: "critical".to_string(),
            sample_count: 10,
            positive_count: 5,
            negative_count: 5,
            target_alpha_bp: 2_000,
            quantile_rank: 8,
            quantile_bp: 1_000,
            min_nonconformity_bp: 100,
            max_nonconformity_bp: 1_000,
            finite_sample_coverage_floor_bp: 7_272,
        };
        let mut artifact = freeze_quantiles(&calibration_samples_for_class("critical"), 2_000)
            .expect("calibration artifact");
        artifact.quantiles = vec![quantile.clone()];

        let shifted = (0..50)
            .map(|index| shifted_positive(&format!("shifted-{index:02}")))
            .collect::<Vec<_>>();
        let plain_coverage_bp = empirical_coverage_bp(&artifact, &shifted);
        let target_coverage_bp = MAX_BASIS_POINTS.saturating_sub(quantile.target_alpha_bp);

        assert_eq!(plain_coverage_bp, 0);
        assert!(plain_coverage_bp < target_coverage_bp);

        let mut state = initialize_aci_state(&quantile, 1_000).unwrap();
        for index in 0..7 {
            let sample = shifted_positive(&format!("warmup-{index:02}"));
            let covered = covered_by_current_aci_state(&state, &sample);
            update_aci_quantile(
                &mut state,
                &AciCoverageObservation {
                    sample_id: sample.sample_id,
                    risk_class: sample.risk_class,
                    covered,
                },
            )
            .unwrap();
        }
        assert_eq!(state.current_quantile_bp, 3_600);

        let mut tail_covered = 0_u64;
        for sample in shifted {
            let covered = covered_by_current_aci_state(&state, &sample);
            if covered {
                tail_covered = tail_covered.saturating_add(1);
            }
            update_aci_quantile(
                &mut state,
                &AciCoverageObservation {
                    sample_id: sample.sample_id,
                    risk_class: sample.risk_class,
                    covered,
                },
            )
            .unwrap();
        }
        let tail_coverage_bp = ratio_bp(tail_covered, 50);

        assert_eq!(tail_coverage_bp, target_coverage_bp);
        assert_eq!(state.last_event_code, event_codes::ACI_QUANTILE_UPDATED);
        assert!(state.observations > 50);
    }

    #[test]
    fn invalid_alpha_is_rejected() {
        let err = freeze_quantiles(&base_samples(), MAX_BASIS_POINTS).unwrap_err();
        assert!(matches!(
            err,
            ConformalCalibrationError::InvalidTargetAlpha(MAX_BASIS_POINTS)
        ));
    }

    #[test]
    fn calibrate_advisories_enforces_small_sample_strict_fallback_and_ed25519_receipt() {
        let mut samples = builtin_benign_migration_calibration_corpus();
        samples.push(sample("tiny-class-1", "rare_advisory", 120, false));
        samples.push(sample("tiny-class-2", "rare_advisory", 240, false));

        let candidates = vec![
            ConformalCandidateAdvisory {
                sample_id: "cand-benign".to_string(),
                risk_class: "migration_advisory".to_string(),
                score_bp: 180,
            },
            ConformalCandidateAdvisory {
                sample_id: "cand-malicious".to_string(),
                risk_class: "migration_advisory".to_string(),
                score_bp: 9_700,
            },
            ConformalCandidateAdvisory {
                sample_id: "cand-undersampled".to_string(),
                risk_class: "rare_advisory".to_string(),
                score_bp: 50,
            },
        ];

        let mut receipt = calibrate_advisories_with_fallback(
            &samples,
            500,
            DEFAULT_MIN_CALIBRATION_SAMPLES,
            CONFORMAL_GENERATED_AT,
            &candidates,
            Some(1_000),
            &[AciCoverageObservation {
                sample_id: "obs-1".to_string(),
                risk_class: "migration_advisory".to_string(),
                covered: true,
            }],
        )
        .expect("calibrate advisories");

        let mig_policy = receipt
            .class_policies
            .iter()
            .find(|p| p.risk_class == "migration_advisory")
            .unwrap();
        assert!(mig_policy.fallback_mode.is_none());
        let rare_policy = receipt
            .class_policies
            .iter()
            .find(|p| p.risk_class == "rare_advisory")
            .unwrap();
        assert_eq!(
            rare_policy.fallback_mode.as_deref(),
            Some(STRICT_CONSERVATIVE_FALLBACK_MODE)
        );

        assert_eq!(receipt.evaluations[0].decision, "allow_benign");
        assert!(!receipt.evaluations[0].fallback_applied);
        assert_eq!(receipt.evaluations[1].decision, "refuse_positive");
        assert_eq!(receipt.evaluations[2].decision, "strict_fallback_refuse");
        assert!(receipt.evaluations[2].fallback_applied);

        let key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
        let wrong = ed25519_dalek::SigningKey::from_bytes(&[0x88; 32]);
        receipt.sign_with_ed25519(&key).expect("sign receipt");
        receipt
            .verify_ed25519_signature(&key.verifying_key())
            .expect("verify receipt");
        assert!(
            receipt
                .verify_ed25519_signature(&wrong.verifying_key())
                .is_err()
        );
    }
}
