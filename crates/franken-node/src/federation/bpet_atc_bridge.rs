//! BPET to ATC privacy-preserving temporal intelligence bridge.
//!
//! The bridge exports BPET trajectory risk as anonymized, bucketed summaries
//! and consumes federated temporal priors without sharing package names,
//! versions, trace IDs, raw sample timestamps, or raw longitudinal feature
//! values. The exchanged material is versioned and verifier-checkable through
//! stable event codes, invariant tags, and deterministic content hashes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::atc_sketches::{CountMinSketch, ErrorBound, MergeableSketch, SketchError};
use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
use crate::security::bpet::evolution_risk_scorer::{
    ExplanationVector, FeatureVector, ScorerError, feature_names,
};

pub const BPET_ATC_BRIDGE_SCHEMA_VERSION: &str = "bpet-atc-bridge-v1";
pub const BPET_ATC_PRIVACY_CONTRACT_VERSION: &str = "bpet-atc-privacy-contract-v1";

const HASH_DOMAIN: &[u8] = b"bpet_atc_bridge_v1:";
const SUMMARY_HASH_DOMAIN: &[u8] = b"bpet_atc_summary_v1:";
const REPORT_HASH_DOMAIN: &[u8] = b"bpet_atc_report_v1:";
const PRIOR_HASH_DOMAIN: &[u8] = b"bpet_atc_prior_v1:";
const ASSIMILATION_HASH_DOMAIN: &[u8] = b"bpet_atc_assimilation_v1:";
const MAX_STRING_BYTES: usize = 256;
const MAX_EXPORT_FEATURES_HARD_CAP: usize = 64;
const MAX_SUMMARIES_HARD_CAP: usize = 4096;
const DEFAULT_EPOCH_BUCKET_WIDTH: u64 = 16;

pub mod event_codes {
    pub const TRAJECTORY_ACCEPTED: &str = "BPET-ATC-001";
    pub const IDENTIFIERS_REDACTED: &str = "BPET-ATC-002";
    pub const SUMMARY_EXPORTED: &str = "BPET-ATC-003";
    pub const SKETCH_UPDATED: &str = "BPET-ATC-004";
    pub const PRIOR_DERIVED: &str = "BPET-ATC-005";
    pub const PRIOR_CONSUMED: &str = "BPET-ATC-006";
    pub const VERIFIER_CONTRACT_EMITTED: &str = "BPET-ATC-007";
    pub const INPUT_REJECTED: &str = "BPET-ATC-ERR-001";
    pub const PRIVACY_CONTRACT_REJECTED: &str = "BPET-ATC-ERR-002";
    pub const K_ANONYMITY_REJECTED: &str = "BPET-ATC-ERR-003";
    pub const PRIOR_REJECTED: &str = "BPET-ATC-ERR-004";
}

pub mod invariants {
    pub const INV_BPET_ATC_ANONYMIZED_ONLY: &str = "INV-BPET-ATC-ANONYMIZED-ONLY";
    pub const INV_BPET_ATC_NO_RAW_LONGITUDINAL_LEAKAGE: &str =
        "INV-BPET-ATC-NO-RAW-LONGITUDINAL-LEAKAGE";
    pub const INV_BPET_ATC_K_ANONYMITY: &str = "INV-BPET-ATC-K-ANONYMITY";
    pub const INV_BPET_ATC_DETERMINISTIC_HASHES: &str = "INV-BPET-ATC-DETERMINISTIC-HASHES";
    pub const INV_BPET_ATC_PRIOR_FAIL_CLOSED: &str = "INV-BPET-ATC-PRIOR-FAIL-CLOSED";
    pub const INV_BPET_ATC_VERSIONED_CONTRACT: &str = "INV-BPET-ATC-VERSIONED-CONTRACT";
}

#[derive(Debug, Error)]
pub enum BpetAtcBridgeError {
    #[error("field `{field}` must not be empty")]
    EmptyField { field: &'static str },
    #[error("field `{field}` exceeds {max} bytes")]
    FieldTooLong { field: &'static str, max: usize },
    #[error("field `{field}` contains a NUL byte")]
    NulByte { field: &'static str },
    #[error("field `{field}` is not finite: {value}")]
    NonFinite { field: &'static str, value: f64 },
    #[error("field `{field}` is outside [0, 1]: {value}")]
    UnitOutOfRange { field: &'static str, value: f64 },
    #[error("privacy policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error("exchange batch is empty")]
    EmptyBatch,
    #[error("exchange batch has {len} summaries, exceeding max {max}")]
    TooManySummaries { len: usize, max: usize },
    #[error("duplicate trajectory summary id: {0}")]
    DuplicateSummary(String),
    #[error("cohort/window group {cohort_window_hash} has {count} summaries, below k={min}")]
    CohortBelowK {
        cohort_window_hash: String,
        count: usize,
        min: usize,
    },
    #[error("no summaries match cohort/window group {0}")]
    NoMatchingCohortWindow(String),
    #[error("invalid federated prior: {0}")]
    InvalidPrior(String),
    #[error(transparent)]
    Sketch(#[from] SketchError),
    #[error(transparent)]
    Scorer(#[from] ScorerError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpetAtcPrivacyPolicy {
    pub contract_version: String,
    pub min_k_anonymity: usize,
    pub max_exported_features: usize,
    pub max_summaries_per_exchange: usize,
    pub risk_bucket_count: u16,
    pub sketch_depth: u32,
    pub sketch_width: u32,
    pub epoch_bucket_width: u64,
}

impl Default for BpetAtcPrivacyPolicy {
    fn default() -> Self {
        Self {
            contract_version: BPET_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
            min_k_anonymity: 2,
            max_exported_features: 4,
            max_summaries_per_exchange: 1024,
            risk_bucket_count: 20,
            sketch_depth: 4,
            sketch_width: 128,
            epoch_bucket_width: DEFAULT_EPOCH_BUCKET_WIDTH,
        }
    }
}

impl BpetAtcPrivacyPolicy {
    pub fn validate(&self) -> Result<(), BpetAtcBridgeError> {
        if !constant_time_str_eq(&self.contract_version, BPET_ATC_PRIVACY_CONTRACT_VERSION) {
            return Err(BpetAtcBridgeError::InvalidPolicy(format!(
                "contract_version must be {BPET_ATC_PRIVACY_CONTRACT_VERSION}"
            )));
        }
        if self.min_k_anonymity < 2 {
            return Err(BpetAtcBridgeError::InvalidPolicy(
                "min_k_anonymity must be at least 2".to_string(),
            ));
        }
        if self.max_exported_features == 0
            || self.max_exported_features > MAX_EXPORT_FEATURES_HARD_CAP
        {
            return Err(BpetAtcBridgeError::InvalidPolicy(format!(
                "max_exported_features must be in 1..={MAX_EXPORT_FEATURES_HARD_CAP}"
            )));
        }
        if self.max_summaries_per_exchange == 0
            || self.max_summaries_per_exchange > MAX_SUMMARIES_HARD_CAP
        {
            return Err(BpetAtcBridgeError::InvalidPolicy(format!(
                "max_summaries_per_exchange must be in 1..={MAX_SUMMARIES_HARD_CAP}"
            )));
        }
        if self.risk_bucket_count == 0 {
            return Err(BpetAtcBridgeError::InvalidPolicy(
                "risk_bucket_count must be > 0".to_string(),
            ));
        }
        if self.epoch_bucket_width == 0 {
            return Err(BpetAtcBridgeError::InvalidPolicy(
                "epoch_bucket_width must be > 0".to_string(),
            ));
        }
        CountMinSketch::new(self.sketch_depth, self.sketch_width)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetTrajectoryExchangeInput {
    pub package_name: String,
    pub version: String,
    pub cohort_id: String,
    pub window_id: String,
    pub source_epoch: u64,
    pub risk_score: f64,
    pub confidence: f64,
    pub feature_contributions: BTreeMap<String, f64>,
    pub dominant_feature: String,
    pub sample_count: u64,
    pub trace_id: String,
}

impl BpetTrajectoryExchangeInput {
    pub fn from_explanation(
        package_name: impl Into<String>,
        version: impl Into<String>,
        cohort_id: impl Into<String>,
        window_id: impl Into<String>,
        source_epoch: u64,
        risk_score: f64,
        confidence: f64,
        explanation: &ExplanationVector,
        sample_count: u64,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            package_name: package_name.into(),
            version: version.into(),
            cohort_id: cohort_id.into(),
            window_id: window_id.into(),
            source_epoch,
            risk_score,
            confidence,
            feature_contributions: explanation.feature_contributions.clone(),
            dominant_feature: explanation.dominant_feature.clone(),
            sample_count,
            trace_id: trace_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpetAtcBridgeEvent {
    pub event_code: String,
    pub trace_hash: String,
    pub summary_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymizedTrajectorySummary {
    pub schema_version: String,
    pub privacy_contract_version: String,
    pub summary_id: String,
    pub cohort_hash: String,
    pub window_hash: String,
    pub cohort_window_hash: String,
    pub trace_hash: String,
    pub epoch_bucket: u64,
    pub risk_bucket: u16,
    pub confidence_bucket: u16,
    pub sample_count_bucket: u8,
    pub dominant_feature: String,
    pub feature_buckets: BTreeMap<String, u16>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetAtcExchangeReport {
    pub schema_version: String,
    pub privacy_contract_version: String,
    pub exchange_id: String,
    pub risk_bucket_count: u16,
    pub summaries: Vec<AnonymizedTrajectorySummary>,
    pub aggregate_sketch: CountMinSketch,
    pub sketch_error_bound: ErrorBound,
    pub sketch_serialized_bytes: usize,
    pub verifier_checks: BTreeMap<String, bool>,
    pub invariant_markers: Vec<String>,
    pub events: Vec<BpetAtcBridgeEvent>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederatedTemporalPrior {
    pub schema_version: String,
    pub privacy_contract_version: String,
    pub prior_id: String,
    pub source_exchange_id: String,
    pub cohort_hash: String,
    pub window_hash: String,
    pub cohort_window_hash: String,
    pub risk_prior: f64,
    pub confidence_prior: f64,
    pub dominant_feature_priors: BTreeMap<String, f64>,
    pub contributor_count: usize,
    pub source_summary_count: usize,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriorAssimilationReport {
    pub schema_version: String,
    pub privacy_contract_version: String,
    pub prior_id: String,
    pub prior_weight: f64,
    pub original_features: FeatureVector,
    pub adjusted_features: FeatureVector,
    pub changed_features: BTreeMap<String, f64>,
    pub events: Vec<BpetAtcBridgeEvent>,
    pub content_hash: String,
}

pub fn export_anonymized_exchange(
    inputs: &[BpetTrajectoryExchangeInput],
    policy: &BpetAtcPrivacyPolicy,
) -> Result<BpetAtcExchangeReport, BpetAtcBridgeError> {
    policy.validate()?;
    if inputs.is_empty() {
        return Err(BpetAtcBridgeError::EmptyBatch);
    }
    if inputs.len() > policy.max_summaries_per_exchange {
        return Err(BpetAtcBridgeError::TooManySummaries {
            len: inputs.len(),
            max: policy.max_summaries_per_exchange,
        });
    }

    let mut summaries = Vec::with_capacity(inputs.len());
    let mut events = Vec::new();
    let mut seen = BTreeSet::new();
    let mut group_counts: BTreeMap<String, usize> = BTreeMap::new();

    for input in inputs {
        let prepared = anonymize_summary(input, policy)?;
        if !seen.insert(prepared.summary_id.clone()) {
            return Err(BpetAtcBridgeError::DuplicateSummary(prepared.summary_id));
        }
        *group_counts
            .entry(prepared.cohort_window_hash.clone())
            .or_insert(0) += 1;
        push_bounded(
            &mut events,
            BpetAtcBridgeEvent {
                event_code: event_codes::TRAJECTORY_ACCEPTED.to_string(),
                trace_hash: prepared.trace_hash.clone(),
                summary_id: Some(prepared.summary_id.clone()),
                detail: "trajectory accepted after validation".to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
        push_bounded(
            &mut events,
            BpetAtcBridgeEvent {
                event_code: event_codes::IDENTIFIERS_REDACTED.to_string(),
                trace_hash: prepared.trace_hash.clone(),
                summary_id: Some(prepared.summary_id.clone()),
                detail: "raw package, version, cohort, window, and trace identifiers hashed"
                    .to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
        summaries.push(prepared);
    }

    for (cohort_window_hash, count) in &group_counts {
        if *count < policy.min_k_anonymity {
            return Err(BpetAtcBridgeError::CohortBelowK {
                cohort_window_hash: cohort_window_hash.clone(),
                count: *count,
                min: policy.min_k_anonymity,
            });
        }
    }

    let mut sketch = CountMinSketch::new(policy.sketch_depth, policy.sketch_width)?;
    for summary in &summaries {
        update_sketch(&mut sketch, summary);
        push_bounded(
            &mut events,
            BpetAtcBridgeEvent {
                event_code: event_codes::SUMMARY_EXPORTED.to_string(),
                trace_hash: summary.trace_hash.clone(),
                summary_id: Some(summary.summary_id.clone()),
                detail: "anonymized trajectory summary exported".to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
        push_bounded(
            &mut events,
            BpetAtcBridgeEvent {
                event_code: event_codes::SKETCH_UPDATED.to_string(),
                trace_hash: summary.trace_hash.clone(),
                summary_id: Some(summary.summary_id.clone()),
                detail: "aggregate ATC sketch updated with bucketed summary keys".to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }

    let invariant_markers = invariant_markers();
    let mut verifier_checks = BTreeMap::new();
    verifier_checks.insert("k_anonymity_enforced".to_string(), true);
    verifier_checks.insert("raw_identifiers_absent".to_string(), true);
    verifier_checks.insert("bucketed_features_only".to_string(), true);
    verifier_checks.insert("versioned_contract".to_string(), true);
    verifier_checks.insert("deterministic_hashes".to_string(), true);

    push_bounded(
        &mut events,
        BpetAtcBridgeEvent {
            event_code: event_codes::VERIFIER_CONTRACT_EMITTED.to_string(),
            trace_hash: hash_text("exchange-verifier-contract"),
            summary_id: None,
            detail: "verifier checks and invariant markers emitted".to_string(),
        },
        MAX_AUDIT_LOG_ENTRIES,
    );

    let exchange_id = hash_serializable(REPORT_HASH_DOMAIN, &(&summaries, &verifier_checks));
    let content_hash = hash_serializable(
        REPORT_HASH_DOMAIN,
        &(
            BPET_ATC_BRIDGE_SCHEMA_VERSION,
            BPET_ATC_PRIVACY_CONTRACT_VERSION,
            &exchange_id,
            policy.risk_bucket_count,
            &summaries,
            &verifier_checks,
            &invariant_markers,
        ),
    );

    Ok(BpetAtcExchangeReport {
        schema_version: BPET_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
        privacy_contract_version: BPET_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
        exchange_id,
        risk_bucket_count: policy.risk_bucket_count,
        summaries,
        sketch_error_bound: sketch.error_bound(),
        sketch_serialized_bytes: sketch.serialized_size(),
        aggregate_sketch: sketch,
        verifier_checks,
        invariant_markers,
        events,
        content_hash,
    })
}

pub fn derive_federated_temporal_prior(
    report: &BpetAtcExchangeReport,
    cohort_hash: &str,
    window_hash: &str,
) -> Result<FederatedTemporalPrior, BpetAtcBridgeError> {
    validate_hash_field("cohort_hash", cohort_hash)?;
    validate_hash_field("window_hash", window_hash)?;
    if !constant_time_str_eq(&report.schema_version, BPET_ATC_BRIDGE_SCHEMA_VERSION) {
        return Err(BpetAtcBridgeError::InvalidPrior(
            "exchange report schema version mismatch".to_string(),
        ));
    }
    if report.risk_bucket_count == 0 {
        return Err(BpetAtcBridgeError::InvalidPrior(
            "risk bucket count must be > 0".to_string(),
        ));
    }

    let cohort_window_hash = hash_pair(cohort_hash, window_hash);
    let matching: Vec<&AnonymizedTrajectorySummary> = report
        .summaries
        .iter()
        .filter(|summary| summary.cohort_hash == cohort_hash && summary.window_hash == window_hash)
        .collect();
    if matching.is_empty() {
        return Err(BpetAtcBridgeError::NoMatchingCohortWindow(
            cohort_window_hash,
        ));
    }

    let denominator = report.risk_bucket_count as f64;
    let risk_prior = matching
        .iter()
        .map(|summary| summary.risk_bucket as f64 / denominator)
        .sum::<f64>()
        / matching.len() as f64;
    let confidence_prior = matching
        .iter()
        .map(|summary| summary.confidence_bucket as f64 / denominator)
        .sum::<f64>()
        / matching.len() as f64;

    let mut feature_counts: BTreeMap<String, usize> = BTreeMap::new();
    for summary in &matching {
        *feature_counts
            .entry(summary.dominant_feature.clone())
            .or_insert(0) += 1;
    }
    let dominant_feature_priors = feature_counts
        .into_iter()
        .map(|(name, count)| (name, count as f64 / matching.len() as f64))
        .collect::<BTreeMap<_, _>>();

    let prior_id = hash_serializable(
        PRIOR_HASH_DOMAIN,
        &(
            &report.exchange_id,
            cohort_hash,
            window_hash,
            risk_prior,
            confidence_prior,
            &dominant_feature_priors,
        ),
    );
    let content_hash = hash_serializable(
        PRIOR_HASH_DOMAIN,
        &(
            BPET_ATC_BRIDGE_SCHEMA_VERSION,
            BPET_ATC_PRIVACY_CONTRACT_VERSION,
            &prior_id,
            &report.exchange_id,
            cohort_hash,
            window_hash,
            risk_prior,
            confidence_prior,
            &dominant_feature_priors,
        ),
    );

    Ok(FederatedTemporalPrior {
        schema_version: BPET_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
        privacy_contract_version: BPET_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
        prior_id,
        source_exchange_id: report.exchange_id.clone(),
        cohort_hash: cohort_hash.to_string(),
        window_hash: window_hash.to_string(),
        cohort_window_hash: hash_pair(cohort_hash, window_hash),
        risk_prior,
        confidence_prior,
        dominant_feature_priors,
        contributor_count: matching.len(),
        source_summary_count: report.summaries.len(),
        content_hash,
    })
}

pub fn consume_federated_temporal_prior(
    local_features: &FeatureVector,
    prior: &FederatedTemporalPrior,
    prior_weight: f64,
) -> Result<PriorAssimilationReport, BpetAtcBridgeError> {
    local_features.validate()?;
    validate_prior(prior)?;
    let prior_weight = validate_unit("prior_weight", prior_weight)?;

    let original = *local_features;
    let mut adjusted = *local_features;
    let mut changed_features = BTreeMap::new();

    apply_prior_to_feature(
        feature_names::DRIFT,
        &mut adjusted.drift,
        prior,
        prior_weight,
        &mut changed_features,
    );
    apply_prior_to_feature(
        feature_names::REGIME_SHIFT,
        &mut adjusted.regime_shift,
        prior,
        prior_weight,
        &mut changed_features,
    );
    apply_prior_to_feature(
        feature_names::HAZARD,
        &mut adjusted.hazard,
        prior,
        prior_weight,
        &mut changed_features,
    );
    apply_prior_to_feature(
        feature_names::PROVENANCE,
        &mut adjusted.provenance,
        prior,
        prior_weight,
        &mut changed_features,
    );
    adjusted.validate()?;

    let mut events = Vec::new();
    push_bounded(
        &mut events,
        BpetAtcBridgeEvent {
            event_code: event_codes::PRIOR_CONSUMED.to_string(),
            trace_hash: hash_text(&prior.prior_id),
            summary_id: None,
            detail: "federated temporal prior consumed into local BPET feature vector".to_string(),
        },
        MAX_AUDIT_LOG_ENTRIES,
    );

    let content_hash = hash_serializable(
        ASSIMILATION_HASH_DOMAIN,
        &(
            &prior.prior_id,
            prior_weight,
            &original,
            &adjusted,
            &changed_features,
        ),
    );

    Ok(PriorAssimilationReport {
        schema_version: BPET_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
        privacy_contract_version: BPET_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
        prior_id: prior.prior_id.clone(),
        prior_weight,
        original_features: original,
        adjusted_features: adjusted,
        changed_features,
        events,
        content_hash,
    })
}

pub fn cohort_hash_for(cohort_id: &str) -> Result<String, BpetAtcBridgeError> {
    validate_text("cohort_id", cohort_id)?;
    Ok(hash_text(cohort_id))
}

pub fn window_hash_for(window_id: &str) -> Result<String, BpetAtcBridgeError> {
    validate_text("window_id", window_id)?;
    Ok(hash_text(window_id))
}

fn anonymize_summary(
    input: &BpetTrajectoryExchangeInput,
    policy: &BpetAtcPrivacyPolicy,
) -> Result<AnonymizedTrajectorySummary, BpetAtcBridgeError> {
    validate_text("package_name", &input.package_name)?;
    validate_text("version", &input.version)?;
    validate_text("cohort_id", &input.cohort_id)?;
    validate_text("window_id", &input.window_id)?;
    validate_text("trace_id", &input.trace_id)?;
    validate_text("dominant_feature", &input.dominant_feature)?;
    let risk_score = validate_unit("risk_score", input.risk_score)?;
    let confidence = validate_unit("confidence", input.confidence)?;
    if input.sample_count == 0 {
        return Err(BpetAtcBridgeError::InvalidPolicy(
            "sample_count must be > 0".to_string(),
        ));
    }

    let cohort_hash = hash_text(&input.cohort_id);
    let window_hash = hash_text(&input.window_id);
    let trace_hash = hash_text(&input.trace_id);
    let cohort_window_hash = hash_pair(&cohort_hash, &window_hash);
    let epoch_bucket = bucket_epoch(input.source_epoch, policy.epoch_bucket_width);
    let risk_bucket = bucket_unit(risk_score, policy.risk_bucket_count);
    let confidence_bucket = bucket_unit(confidence, policy.risk_bucket_count);
    let sample_count_bucket = sample_count_bucket(input.sample_count);
    let feature_buckets = bucket_features(
        &input.feature_contributions,
        policy.max_exported_features,
        policy.risk_bucket_count,
    )?;
    let summary_id = hash_serializable(
        SUMMARY_HASH_DOMAIN,
        &(
            &cohort_hash,
            &window_hash,
            &trace_hash,
            epoch_bucket,
            risk_bucket,
            confidence_bucket,
            sample_count_bucket,
            &input.dominant_feature,
            &feature_buckets,
        ),
    );
    let content_hash = hash_serializable(
        SUMMARY_HASH_DOMAIN,
        &(
            BPET_ATC_BRIDGE_SCHEMA_VERSION,
            BPET_ATC_PRIVACY_CONTRACT_VERSION,
            &summary_id,
            &cohort_hash,
            &window_hash,
            &cohort_window_hash,
            &trace_hash,
            epoch_bucket,
            risk_bucket,
            confidence_bucket,
            sample_count_bucket,
            &input.dominant_feature,
            &feature_buckets,
        ),
    );

    Ok(AnonymizedTrajectorySummary {
        schema_version: BPET_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
        privacy_contract_version: BPET_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
        summary_id,
        cohort_hash,
        window_hash,
        cohort_window_hash,
        trace_hash,
        epoch_bucket,
        risk_bucket,
        confidence_bucket,
        sample_count_bucket,
        dominant_feature: input.dominant_feature.clone(),
        feature_buckets,
        content_hash,
    })
}

fn update_sketch(sketch: &mut CountMinSketch, summary: &AnonymizedTrajectorySummary) {
    sketch.add(format!("risk_bucket:{}", summary.risk_bucket).as_bytes(), 1);
    sketch.add(
        format!("confidence_bucket:{}", summary.confidence_bucket).as_bytes(),
        1,
    );
    sketch.add(
        format!("dominant_feature:{}", summary.dominant_feature).as_bytes(),
        1,
    );
    sketch.add(
        format!("cohort_window:{}", summary.cohort_window_hash).as_bytes(),
        1,
    );
    for (feature, bucket) in &summary.feature_buckets {
        sketch.add(format!("feature:{feature}:{bucket}").as_bytes(), 1);
    }
}

fn bucket_features(
    contributions: &BTreeMap<String, f64>,
    max_features: usize,
    bucket_count: u16,
) -> Result<BTreeMap<String, u16>, BpetAtcBridgeError> {
    let mut ranked = Vec::with_capacity(contributions.len());
    for (feature, value) in contributions {
        validate_text("feature_contribution.name", feature)?;
        let value = validate_unit("feature_contribution.value", *value)?;
        ranked.push((feature.clone(), value));
    }
    ranked.sort_by(|(left_name, left), (right_name, right)| {
        right
            .partial_cmp(left)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left_name.cmp(right_name))
    });
    Ok(ranked
        .into_iter()
        .take(max_features)
        .map(|(feature, value)| (feature, bucket_unit(value, bucket_count)))
        .collect())
}

fn validate_prior(prior: &FederatedTemporalPrior) -> Result<(), BpetAtcBridgeError> {
    if !constant_time_str_eq(&prior.schema_version, BPET_ATC_BRIDGE_SCHEMA_VERSION) {
        return Err(BpetAtcBridgeError::InvalidPrior(
            "schema version mismatch".to_string(),
        ));
    }
    if !constant_time_str_eq(
        &prior.privacy_contract_version,
        BPET_ATC_PRIVACY_CONTRACT_VERSION,
    ) {
        return Err(BpetAtcBridgeError::InvalidPrior(
            "privacy contract version mismatch".to_string(),
        ));
    }
    validate_hash_field("prior_id", &prior.prior_id)?;
    validate_hash_field("cohort_hash", &prior.cohort_hash)?;
    validate_hash_field("window_hash", &prior.window_hash)?;
    validate_unit("risk_prior", prior.risk_prior)?;
    validate_unit("confidence_prior", prior.confidence_prior)?;
    if prior.contributor_count == 0 {
        return Err(BpetAtcBridgeError::InvalidPrior(
            "contributor_count must be > 0".to_string(),
        ));
    }
    for (feature, weight) in &prior.dominant_feature_priors {
        validate_text("dominant_feature_prior.name", feature)?;
        validate_unit("dominant_feature_prior.weight", *weight)?;
    }
    Ok(())
}

fn apply_prior_to_feature(
    feature: &'static str,
    current: &mut f64,
    prior: &FederatedTemporalPrior,
    prior_weight: f64,
    changed_features: &mut BTreeMap<String, f64>,
) {
    let Some(feature_prior_weight) = prior.dominant_feature_priors.get(feature).copied() else {
        return;
    };
    if prior.risk_prior <= *current {
        return;
    }
    let delta = (prior.risk_prior - *current) * prior_weight * feature_prior_weight;
    if delta <= 0.0 || !delta.is_finite() {
        return;
    }
    let next = (*current + delta).clamp(0.0, 1.0);
    if next > *current {
        changed_features.insert(feature.to_string(), next - *current);
        *current = next;
    }
}

fn validate_text(field: &'static str, value: &str) -> Result<(), BpetAtcBridgeError> {
    if value.trim().is_empty() {
        return Err(BpetAtcBridgeError::EmptyField { field });
    }
    if value.len() > MAX_STRING_BYTES {
        return Err(BpetAtcBridgeError::FieldTooLong {
            field,
            max: MAX_STRING_BYTES,
        });
    }
    if value.contains('\0') {
        return Err(BpetAtcBridgeError::NulByte { field });
    }
    Ok(())
}

fn validate_hash_field(field: &'static str, value: &str) -> Result<(), BpetAtcBridgeError> {
    validate_text(field, value)?;
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BpetAtcBridgeError::InvalidPrior(format!(
            "{field} must be a 64-byte hex hash"
        )));
    }
    Ok(())
}

fn validate_unit(field: &'static str, value: f64) -> Result<f64, BpetAtcBridgeError> {
    if !value.is_finite() {
        return Err(BpetAtcBridgeError::NonFinite { field, value });
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(BpetAtcBridgeError::UnitOutOfRange { field, value });
    }
    Ok(value)
}

fn constant_time_str_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn bucket_unit(value: f64, bucket_count: u16) -> u16 {
    (value.clamp(0.0, 1.0) * f64::from(bucket_count)).round() as u16
}

fn bucket_epoch(epoch: u64, width: u64) -> u64 {
    if width == 0 {
        return epoch;
    }
    (epoch / width).saturating_mul(width)
}

fn sample_count_bucket(sample_count: u64) -> u8 {
    if sample_count == 0 {
        return 0;
    }
    let bucket = u64::BITS - sample_count.leading_zeros();
    bucket.min(u8::MAX as u32) as u8
}

fn hash_pair(left: &str, right: &str) -> String {
    hash_serializable(HASH_DOMAIN, &(left, right))
}

fn hash_text(value: &str) -> String {
    hash_serializable(HASH_DOMAIN, &value)
}

fn hash_serializable<T: Serialize>(domain: &[u8], value: &T) -> String {
    let canonical = serde_json::to_vec(value).unwrap_or_else(|err| err.to_string().into_bytes());
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((canonical.len() as u64).to_le_bytes());
    hasher.update(canonical);
    hex::encode(hasher.finalize())
}

fn invariant_markers() -> Vec<String> {
    vec![
        invariants::INV_BPET_ATC_ANONYMIZED_ONLY.to_string(),
        invariants::INV_BPET_ATC_NO_RAW_LONGITUDINAL_LEAKAGE.to_string(),
        invariants::INV_BPET_ATC_K_ANONYMITY.to_string(),
        invariants::INV_BPET_ATC_DETERMINISTIC_HASHES.to_string(),
        invariants::INV_BPET_ATC_PRIOR_FAIL_CLOSED.to_string(),
        invariants::INV_BPET_ATC_VERSIONED_CONTRACT.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::bpet::evolution_risk_scorer::{WeightingPolicy, compute_risk_score};

    fn input(name: &str, trace: &str, drift: f64, hazard: f64) -> BpetTrajectoryExchangeInput {
        let features = FeatureVector {
            drift,
            regime_shift: 0.2,
            hazard,
            provenance: 0.1,
        };
        let (score, explanation) =
            compute_risk_score(&features, &WeightingPolicy::policy_v1()).unwrap();
        BpetTrajectoryExchangeInput::from_explanation(
            name,
            "1.2.3",
            "cohort-alpha",
            "window-2026-week-20",
            42,
            score,
            0.8,
            &explanation,
            16,
            trace,
        )
    }

    #[test]
    fn export_redacts_raw_identifiers() {
        let policy = BpetAtcPrivacyPolicy::default();
        let report = export_anonymized_exchange(
            &[
                input("package-secret-a", "trace-secret-a", 0.8, 0.7),
                input("package-secret-b", "trace-secret-b", 0.6, 0.7),
            ],
            &policy,
        )
        .unwrap();

        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("package-secret-a"));
        assert!(!encoded.contains("package-secret-b"));
        assert!(!encoded.contains("trace-secret-a"));
        assert!(!encoded.contains("trace-secret-b"));
        assert!(encoded.contains(BPET_ATC_PRIVACY_CONTRACT_VERSION));
    }

    #[test]
    fn k_anonymity_fails_closed_for_single_member_group() {
        let err = export_anonymized_exchange(
            &[input("package-a", "trace-a", 0.8, 0.7)],
            &Default::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BpetAtcBridgeError::CohortBelowK {
                count: 1,
                min: 2,
                ..
            }
        ));
    }

    #[test]
    fn export_is_deterministic_for_same_inputs() {
        let policy = BpetAtcPrivacyPolicy::default();
        let batch = vec![
            input("package-a", "trace-a", 0.8, 0.7),
            input("package-b", "trace-b", 0.6, 0.7),
        ];
        let first = export_anonymized_exchange(&batch, &policy).unwrap();
        let second = export_anonymized_exchange(&batch, &policy).unwrap();
        assert_eq!(first.exchange_id, second.exchange_id);
        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(first.summaries, second.summaries);
    }

    #[test]
    fn sketch_contains_bucketed_summary_keys() {
        let report = export_anonymized_exchange(
            &[
                input("package-a", "trace-a", 0.8, 0.7),
                input("package-b", "trace-b", 0.6, 0.7),
            ],
            &Default::default(),
        )
        .unwrap();
        let bucket = report.summaries[0].risk_bucket;
        let estimate = report
            .aggregate_sketch
            .estimate(format!("risk_bucket:{bucket}").as_bytes());
        assert!(estimate >= 1);
    }

    #[test]
    fn prior_consumption_only_raises_supported_features() {
        let report = export_anonymized_exchange(
            &[
                input("package-a", "trace-a", 0.95, 0.7),
                input("package-b", "trace-b", 0.95, 0.7),
            ],
            &Default::default(),
        )
        .unwrap();
        let cohort = cohort_hash_for("cohort-alpha").unwrap();
        let window = window_hash_for("window-2026-week-20").unwrap();
        let prior = derive_federated_temporal_prior(&report, &cohort, &window).unwrap();
        let local = FeatureVector {
            drift: 0.1,
            regime_shift: 0.1,
            hazard: 0.1,
            provenance: 0.1,
        };
        let assimilation = consume_federated_temporal_prior(&local, &prior, 0.5).unwrap();
        assert!(assimilation.adjusted_features.drift >= local.drift);
        assert!(!assimilation.changed_features.is_empty());
    }

    #[test]
    fn invalid_prior_weight_is_rejected() {
        let mut prior = FederatedTemporalPrior {
            schema_version: BPET_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
            privacy_contract_version: BPET_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
            prior_id: hash_text("prior"),
            source_exchange_id: hash_text("exchange"),
            cohort_hash: hash_text("cohort"),
            window_hash: hash_text("window"),
            cohort_window_hash: hash_text("cohort-window"),
            risk_prior: 0.8,
            confidence_prior: 0.9,
            dominant_feature_priors: BTreeMap::from([(feature_names::DRIFT.to_string(), 1.0)]),
            contributor_count: 2,
            source_summary_count: 2,
            content_hash: hash_text("content"),
        };
        let local = FeatureVector {
            drift: 0.1,
            regime_shift: 0.1,
            hazard: 0.1,
            provenance: 0.1,
        };
        let err = consume_federated_temporal_prior(&local, &prior, f64::NAN).unwrap_err();
        assert!(matches!(
            err,
            BpetAtcBridgeError::NonFinite {
                field: "prior_weight",
                ..
            }
        ));

        prior.schema_version = "old".to_string();
        let err = consume_federated_temporal_prior(&local, &prior, 0.5).unwrap_err();
        assert!(matches!(err, BpetAtcBridgeError::InvalidPrior(_)));
    }

    // Frozen SHA-256 hex outputs of TWO module-private hashing
    // functions in this file:
    //
    //   hash_text (bpet_atc_bridge.rs:844):
    //     SHA256(
    //       b"bpet_atc_bridge_v1:"
    //       || LE64(len(serde_json::to_vec(&value))) || serde_json::to_vec(&value)
    //     ).hex()
    //
    //   hash_pair (bpet_atc_bridge.rs:840):
    //     SHA256(
    //       b"bpet_atc_bridge_v1:"
    //       || LE64(len(serde_json::to_vec(&(left, right))))
    //       || serde_json::to_vec(&(left, right))
    //     ).hex()
    //
    // Both delegate to hash_serializable (L848) with HASH_DOMAIN =
    // b"bpet_atc_bridge_v1:".
    //
    // *** DISTINCTIVE FEATURE pinned by this golden ***
    //
    // These functions feed `serde_json::to_vec` OUTPUT into the
    // hasher — meaning the canonical bytes are JSON-serialized values:
    //   - hash_text("hello")     → JSON: b"\"hello\"" (with quotes)
    //   - hash_pair("a", "b")    → JSON: b"[\"a\",\"b\"]" (tuple as array)
    //
    // The serialized form depends on serde_json's encoding conventions:
    //   - strings are double-quoted with " " character escapes
    //   - tuples serialize as JSON arrays with NO whitespace separators
    //
    // This is the FIRST golden in the suite to pin serde_json
    // string/tuple encoding as part of the canonical-byte contract.
    // A future refactor that switched from serde_json to a different
    // serialization library (e.g., serde_cbor, postcard, bincode)
    // would silently flip every existing hash. Pinning these outputs
    // documents that serde_json IS the contract — not "any
    // serializer that produces deterministic bytes."
    //
    // Four frozen fixtures + structural invariants:
    //
    //   1. hash_text("") — empty string. JSON encoding is b"\"\"" (2
    //      bytes — just two quote marks). Locks v1 domain + LE64(2) +
    //      the 2-byte JSON empty-string encoding.
    //      Frozen: 08c6be0791473fe0511000c04491a55f01b9ba605038e4a7ff9272ffbf5c0ca5
    //
    //   2. hash_text("trace-bpet-1") — ASCII string. JSON encoding is
    //      b"\"trace-bpet-1\"" (14 bytes — 12 chars + 2 quotes).
    //      Frozen: 33224f5a0d842259941560a111e9ce8726262da30f678621519202be1ad8b8e3
    //
    //   3. hash_pair("alpha", "beta") — tuple. JSON encoding is
    //      b"[\"alpha\",\"beta\"]" (15 bytes — locks JSON array
    //      no-whitespace + comma-separator + double-quoted strings).
    //      Frozen: 9eaa2eec64584f1c9c088b7e8c972bb7a466c69af32c4bbb1e3236d9fa05982b
    //
    //   4. hash_pair("", "non-empty") — pair with empty first. JSON
    //      encoding is b"[\"\",\"non-empty\"]" (16 bytes).
    //      Frozen: 7b3ac3cacb40e009004d3d27a80195b58fc96642ca92750dcc6bdaadf9e7ea9d
    //
    //   5. SERDE-JSON-ENCODING INVARIANT: hash_text("a") MUST differ
    //      from hash_pair("a", "") because hash_text wraps "a" as
    //      `"a"` (JSON string) but hash_pair wraps as `["a",""]`
    //      (JSON array). Pins the JSON encoding distinction.
    //
    //   6. ORDER-SENSITIVITY: hash_pair("a", "b") MUST differ from
    //      hash_pair("b", "a") — JSON arrays preserve order.
    //
    //   7. 64-lowercase-hex length+casing contract.
    //
    // Goldens were derived offline from the canonical-byte spec via
    // Python's json.dumps (matching serde_json's default output
    // with no whitespace) — NOT captured from an unreviewed prior
    // run.
    //
    // Why this matters (the contract): hash_text and hash_pair are
    // the content-fingerprint primitives for the BPET-ATC bridge.
    // The functions ensure INV-BPET-ATC-DETERMINISTIC-HASHES — every
    // node MUST hash an identical text/pair to identical bytes. If
    // two nodes use different serde_json versions whose string-
    // encoding behavior differs (unlikely but possible), the hashes
    // diverge AND federation aggregation fails opaquely.
    #[test]
    fn bpet_atc_bridge_hash_primitives_frozen_canonical_byte_layout_golden() {
        // 1. hash_text(empty).
        assert_eq!(
            super::hash_text(""),
            "08c6be0791473fe0511000c04491a55f01b9ba605038e4a7ff9272ffbf5c0ca5",
            "hash_text(\"\") drifted — check the v1 domain separator \
             `bpet_atc_bridge_v1:`, the LE64-len framing on serde_json \
             output, OR the serde_json empty-string encoding b\"\\\"\\\"\" \
             (2 bytes)"
        );

        // 2. hash_text(ascii).
        assert_eq!(
            super::hash_text("trace-bpet-1"),
            "33224f5a0d842259941560a111e9ce8726262da30f678621519202be1ad8b8e3"
        );

        // 3. hash_pair(simple).
        assert_eq!(
            super::hash_pair("alpha", "beta"),
            "9eaa2eec64584f1c9c088b7e8c972bb7a466c69af32c4bbb1e3236d9fa05982b",
            "hash_pair(\"alpha\", \"beta\") drifted — check the \
             serde_json tuple-as-array encoding b\"[\\\"a\\\",\\\"b\\\"]\" \
             (NO whitespace, comma separator)"
        );

        // 4. hash_pair with empty first element.
        assert_eq!(
            super::hash_pair("", "non-empty"),
            "7b3ac3cacb40e009004d3d27a80195b58fc96642ca92750dcc6bdaadf9e7ea9d"
        );

        // 5. SERDE-JSON-ENCODING INVARIANT: hash_text("a") MUST differ
        // from hash_pair("a", "") — the JSON encodings are different
        // (`"a"` vs `["a",""]`).
        assert_ne!(
            super::hash_text("a"),
            super::hash_pair("a", ""),
            "hash_text(\"a\") and hash_pair(\"a\", \"\") MUST produce \
             different hashes — they encode differently in serde_json \
             (string \"a\" vs array [\"a\",\"\"])"
        );

        // 6. ORDER-SENSITIVITY: hash_pair("a", "b") != hash_pair("b", "a").
        assert_ne!(
            super::hash_pair("a", "b"),
            super::hash_pair("b", "a"),
            "hash_pair(L, R) MUST differ from hash_pair(R, L) — JSON \
             arrays preserve order"
        );

        // 7. 64-lowercase-hex length+casing contract.
        for h in [
            super::hash_text(""),
            super::hash_text("trace-bpet-1"),
            super::hash_pair("alpha", "beta"),
            super::hash_pair("", "non-empty"),
        ] {
            assert_eq!(h.len(), 64);
            assert!(
                h.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
        }
    }
}
