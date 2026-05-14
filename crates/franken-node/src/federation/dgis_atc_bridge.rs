//! DGIS to ATC privacy-preserving topology intelligence bridge.
//!
//! The bridge exports DGIS topology risk as anonymized, bucketed indicators
//! and consumes federated cascade priors without sharing package names,
//! versions, dependency edges, raw graph node identifiers, or trace IDs.
//! Exchanged payloads carry stable schema versions, event codes, invariant
//! markers, and deterministic content hashes so verifier tooling can audit
//! the contract without seeing the raw dependency graph.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::atc_sketches::{CountMinSketch, ErrorBound, MergeableSketch, SketchError};
use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
use crate::security::dgis::update_copilot::TopologyRiskMetrics;

pub const DGIS_ATC_BRIDGE_SCHEMA_VERSION: &str = "dgis-atc-bridge-v1";
pub const DGIS_ATC_PRIVACY_CONTRACT_VERSION: &str = "dgis-atc-privacy-contract-v1";

const HASH_DOMAIN: &[u8] = b"dgis_atc_bridge_v1:";
const INDICATOR_HASH_DOMAIN: &[u8] = b"dgis_atc_indicator_v1:";
const REPORT_HASH_DOMAIN: &[u8] = b"dgis_atc_report_v1:";
const PRIOR_HASH_DOMAIN: &[u8] = b"dgis_atc_prior_v1:";
const ASSIMILATION_HASH_DOMAIN: &[u8] = b"dgis_atc_assimilation_v1:";
const MAX_STRING_BYTES: usize = 256;
const MAX_INDICATORS_HARD_CAP: usize = 4096;
const DEFAULT_EPOCH_BUCKET_WIDTH: u64 = 16;
const FAN_OUT_SCALE: f64 = 100.0;
const LOG_COUNT_SCALE: f64 = 16.0;

pub mod event_codes {
    pub const TOPOLOGY_INPUT_ACCEPTED: &str = "DGIS-ATC-001";
    pub const RAW_GRAPH_REDACTED: &str = "DGIS-ATC-002";
    pub const INDICATOR_EXPORTED: &str = "DGIS-ATC-003";
    pub const SKETCH_UPDATED: &str = "DGIS-ATC-004";
    pub const PRIOR_DERIVED: &str = "DGIS-ATC-005";
    pub const PRIOR_CONSUMED: &str = "DGIS-ATC-006";
    pub const VERIFIER_CONTRACT_EMITTED: &str = "DGIS-ATC-007";
    pub const INPUT_REJECTED: &str = "DGIS-ATC-ERR-001";
    pub const PRIVACY_CONTRACT_REJECTED: &str = "DGIS-ATC-ERR-002";
    pub const K_ANONYMITY_REJECTED: &str = "DGIS-ATC-ERR-003";
    pub const PRIOR_REJECTED: &str = "DGIS-ATC-ERR-004";
}

pub mod invariants {
    pub const INV_DGIS_ATC_ANONYMIZED_ONLY: &str = "INV-DGIS-ATC-ANONYMIZED-ONLY";
    pub const INV_DGIS_ATC_NO_RAW_DEPENDENCY_LEAKAGE: &str =
        "INV-DGIS-ATC-NO-RAW-DEPENDENCY-LEAKAGE";
    pub const INV_DGIS_ATC_K_ANONYMITY: &str = "INV-DGIS-ATC-K-ANONYMITY";
    pub const INV_DGIS_ATC_DETERMINISTIC_HASHES: &str = "INV-DGIS-ATC-DETERMINISTIC-HASHES";
    pub const INV_DGIS_ATC_PRIOR_FAIL_CLOSED: &str = "INV-DGIS-ATC-PRIOR-FAIL-CLOSED";
    pub const INV_DGIS_ATC_VERSIONED_CONTRACT: &str = "INV-DGIS-ATC-VERSIONED-CONTRACT";
}

#[derive(Debug, Error)]
pub enum DgisAtcBridgeError {
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
    #[error("field `{field}` is negative: {value}")]
    NegativeMetric { field: &'static str, value: f64 },
    #[error("privacy policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error("topology exchange batch is empty")]
    EmptyBatch,
    #[error("topology exchange batch has {len} indicators, exceeding max {max}")]
    TooManyIndicators { len: usize, max: usize },
    #[error("duplicate topology indicator id: {0}")]
    DuplicateIndicator(String),
    #[error("region/window group {region_window_hash} has {count} indicators, below k={min}")]
    RegionBelowK {
        region_window_hash: String,
        count: usize,
        min: usize,
    },
    #[error("no topology indicators match region/window group {0}")]
    NoMatchingRegionWindow(String),
    #[error("invalid federated cascade prior: {0}")]
    InvalidPrior(String),
    #[error(transparent)]
    Sketch(#[from] SketchError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DgisAtcPrivacyPolicy {
    pub contract_version: String,
    pub min_k_anonymity: usize,
    pub max_indicators_per_exchange: usize,
    pub risk_bucket_count: u16,
    pub sketch_depth: u32,
    pub sketch_width: u32,
    pub epoch_bucket_width: u64,
}

impl Default for DgisAtcPrivacyPolicy {
    fn default() -> Self {
        Self {
            contract_version: DGIS_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
            min_k_anonymity: 2,
            max_indicators_per_exchange: 1024,
            risk_bucket_count: 20,
            sketch_depth: 4,
            sketch_width: 128,
            epoch_bucket_width: DEFAULT_EPOCH_BUCKET_WIDTH,
        }
    }
}

impl DgisAtcPrivacyPolicy {
    pub fn validate(&self) -> Result<(), DgisAtcBridgeError> {
        if !constant_time_str_eq(&self.contract_version, DGIS_ATC_PRIVACY_CONTRACT_VERSION) {
            return Err(DgisAtcBridgeError::InvalidPolicy(format!(
                "contract_version must be {DGIS_ATC_PRIVACY_CONTRACT_VERSION}"
            )));
        }
        if self.min_k_anonymity < 2 {
            return Err(DgisAtcBridgeError::InvalidPolicy(
                "min_k_anonymity must be at least 2".to_string(),
            ));
        }
        if self.max_indicators_per_exchange == 0
            || self.max_indicators_per_exchange > MAX_INDICATORS_HARD_CAP
        {
            return Err(DgisAtcBridgeError::InvalidPolicy(format!(
                "max_indicators_per_exchange must be in 1..={MAX_INDICATORS_HARD_CAP}"
            )));
        }
        if self.risk_bucket_count == 0 {
            return Err(DgisAtcBridgeError::InvalidPolicy(
                "risk_bucket_count must be > 0".to_string(),
            ));
        }
        if self.epoch_bucket_width == 0 {
            return Err(DgisAtcBridgeError::InvalidPolicy(
                "epoch_bucket_width must be > 0".to_string(),
            ));
        }
        CountMinSketch::new(self.sketch_depth, self.sketch_width)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DgisTopologyIndicatorInput {
    pub package_name: String,
    pub version: String,
    pub ecosystem_region: String,
    pub window_id: String,
    pub source_epoch: u64,
    pub metrics: TopologyRiskMetrics,
    pub cascade_risk: f64,
    pub confidence: f64,
    pub directly_affected_count: u32,
    pub trace_id: String,
}

impl DgisTopologyIndicatorInput {
    pub fn new(
        package_name: impl Into<String>,
        version: impl Into<String>,
        ecosystem_region: impl Into<String>,
        window_id: impl Into<String>,
        source_epoch: u64,
        metrics: TopologyRiskMetrics,
        cascade_risk: f64,
        confidence: f64,
        directly_affected_count: u32,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            package_name: package_name.into(),
            version: version.into(),
            ecosystem_region: ecosystem_region.into(),
            window_id: window_id.into(),
            source_epoch,
            metrics,
            cascade_risk,
            confidence,
            directly_affected_count,
            trace_id: trace_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DgisAtcBridgeEvent {
    pub event_code: String,
    pub trace_hash: String,
    pub indicator_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymizedTopologyIndicator {
    pub schema_version: String,
    pub privacy_contract_version: String,
    pub indicator_id: String,
    pub region_hash: String,
    pub window_hash: String,
    pub region_window_hash: String,
    pub trace_hash: String,
    pub epoch_bucket: u64,
    pub topology_risk_bucket: u16,
    pub cascade_risk_bucket: u16,
    pub confidence_bucket: u16,
    pub fan_out_bucket: u16,
    pub betweenness_bucket: u16,
    pub trust_bottleneck_bucket: u16,
    pub transitive_dependency_bucket: u16,
    pub max_depth_bucket: u16,
    pub directly_affected_bucket: u16,
    pub articulation_point: bool,
    pub content_hash: String,
}

#[derive(Serialize)]
struct IndicatorIdHashFields<'a> {
    region_hash: &'a str,
    window_hash: &'a str,
    trace_hash: &'a str,
    epoch_bucket: u64,
    topology_risk_bucket: u16,
    cascade_risk_bucket: u16,
    confidence_bucket: u16,
    fan_out_bucket: u16,
    betweenness_bucket: u16,
    trust_bottleneck_bucket: u16,
    transitive_dependency_bucket: u16,
    max_depth_bucket: u16,
    directly_affected_bucket: u16,
    articulation_point: bool,
}

#[derive(Serialize)]
struct IndicatorContentHashFields<'a> {
    schema_version: &'static str,
    privacy_contract_version: &'static str,
    indicator_id: &'a str,
    region_hash: &'a str,
    window_hash: &'a str,
    region_window_hash: &'a str,
    trace_hash: &'a str,
    epoch_bucket: u64,
    topology_risk_bucket: u16,
    cascade_risk_bucket: u16,
    confidence_bucket: u16,
    fan_out_bucket: u16,
    betweenness_bucket: u16,
    trust_bottleneck_bucket: u16,
    transitive_dependency_bucket: u16,
    max_depth_bucket: u16,
    directly_affected_bucket: u16,
    articulation_point: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DgisAtcExchangeReport {
    pub schema_version: String,
    pub privacy_contract_version: String,
    pub exchange_id: String,
    pub risk_bucket_count: u16,
    pub indicators: Vec<AnonymizedTopologyIndicator>,
    pub aggregate_sketch: CountMinSketch,
    pub sketch_error_bound: ErrorBound,
    pub sketch_serialized_bytes: usize,
    pub verifier_checks: BTreeMap<String, bool>,
    pub invariant_markers: Vec<String>,
    pub events: Vec<DgisAtcBridgeEvent>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederatedCascadePrior {
    pub schema_version: String,
    pub privacy_contract_version: String,
    pub prior_id: String,
    pub source_exchange_id: String,
    pub region_hash: String,
    pub window_hash: String,
    pub region_window_hash: String,
    pub risk_prior: f64,
    pub confidence_prior: f64,
    pub metric_priors: BTreeMap<String, f64>,
    pub articulation_rate: f64,
    pub contributor_count: usize,
    pub source_indicator_count: usize,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CascadePriorAssimilationReport {
    pub schema_version: String,
    pub privacy_contract_version: String,
    pub prior_id: String,
    pub prior_weight: f64,
    pub original_metrics: TopologyRiskMetrics,
    pub adjusted_metrics: TopologyRiskMetrics,
    pub changed_metrics: BTreeMap<String, f64>,
    pub events: Vec<DgisAtcBridgeEvent>,
    pub content_hash: String,
}

pub fn export_topology_indicators(
    inputs: &[DgisTopologyIndicatorInput],
    policy: &DgisAtcPrivacyPolicy,
) -> Result<DgisAtcExchangeReport, DgisAtcBridgeError> {
    policy.validate()?;
    if inputs.is_empty() {
        return Err(DgisAtcBridgeError::EmptyBatch);
    }
    if inputs.len() > policy.max_indicators_per_exchange {
        return Err(DgisAtcBridgeError::TooManyIndicators {
            len: inputs.len(),
            max: policy.max_indicators_per_exchange,
        });
    }

    let mut indicators = Vec::with_capacity(inputs.len());
    let mut seen = BTreeSet::new();
    let mut group_counts: BTreeMap<String, usize> = BTreeMap::new();

    for input in inputs {
        let prepared = anonymize_indicator(input, policy)?;
        if !seen.insert(prepared.indicator_id.clone()) {
            return Err(DgisAtcBridgeError::DuplicateIndicator(
                prepared.indicator_id,
            ));
        }
        *group_counts
            .entry(prepared.region_window_hash.clone())
            .or_insert(0) += 1;
        indicators.push(prepared);
    }

    for (region_window_hash, count) in &group_counts {
        if *count < policy.min_k_anonymity {
            return Err(DgisAtcBridgeError::RegionBelowK {
                region_window_hash: region_window_hash.clone(),
                count: *count,
                min: policy.min_k_anonymity,
            });
        }
    }

    indicators.sort_by(|left, right| left.indicator_id.cmp(&right.indicator_id));

    let mut events = Vec::new();
    let mut sketch = CountMinSketch::new(policy.sketch_depth, policy.sketch_width)?;
    for indicator in &indicators {
        push_bounded(
            &mut events,
            DgisAtcBridgeEvent {
                event_code: event_codes::TOPOLOGY_INPUT_ACCEPTED.to_string(),
                trace_hash: indicator.trace_hash.clone(),
                indicator_id: Some(indicator.indicator_id.clone()),
                detail: "topology indicator accepted after validation".to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
        push_bounded(
            &mut events,
            DgisAtcBridgeEvent {
                event_code: event_codes::RAW_GRAPH_REDACTED.to_string(),
                trace_hash: indicator.trace_hash.clone(),
                indicator_id: Some(indicator.indicator_id.clone()),
                detail: "raw package, version, graph node, window, trace, and edge data excluded"
                    .to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
        update_sketch(&mut sketch, indicator);
        push_bounded(
            &mut events,
            DgisAtcBridgeEvent {
                event_code: event_codes::INDICATOR_EXPORTED.to_string(),
                trace_hash: indicator.trace_hash.clone(),
                indicator_id: Some(indicator.indicator_id.clone()),
                detail: "anonymized topology indicator exported".to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
        push_bounded(
            &mut events,
            DgisAtcBridgeEvent {
                event_code: event_codes::SKETCH_UPDATED.to_string(),
                trace_hash: indicator.trace_hash.clone(),
                indicator_id: Some(indicator.indicator_id.clone()),
                detail: "aggregate ATC sketch updated with bucketed topology keys".to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }

    let invariant_markers = invariant_markers();
    let mut verifier_checks = BTreeMap::new();
    verifier_checks.insert("k_anonymity_enforced".to_string(), true);
    verifier_checks.insert("raw_dependency_graph_absent".to_string(), true);
    verifier_checks.insert("bucketed_topology_metrics_only".to_string(), true);
    verifier_checks.insert("versioned_contract".to_string(), true);
    verifier_checks.insert("deterministic_hashes".to_string(), true);

    push_bounded(
        &mut events,
        DgisAtcBridgeEvent {
            event_code: event_codes::VERIFIER_CONTRACT_EMITTED.to_string(),
            trace_hash: hash_text("dgis-atc-verifier-contract"),
            indicator_id: None,
            detail: "verifier checks and invariant markers emitted".to_string(),
        },
        MAX_AUDIT_LOG_ENTRIES,
    );

    let exchange_id = hash_serializable(REPORT_HASH_DOMAIN, &(&indicators, &verifier_checks));
    let content_hash = hash_serializable(
        REPORT_HASH_DOMAIN,
        &(
            DGIS_ATC_BRIDGE_SCHEMA_VERSION,
            DGIS_ATC_PRIVACY_CONTRACT_VERSION,
            &exchange_id,
            policy.risk_bucket_count,
            &indicators,
            &verifier_checks,
            &invariant_markers,
        ),
    );

    Ok(DgisAtcExchangeReport {
        schema_version: DGIS_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
        privacy_contract_version: DGIS_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
        exchange_id,
        risk_bucket_count: policy.risk_bucket_count,
        indicators,
        sketch_error_bound: sketch.error_bound(),
        sketch_serialized_bytes: sketch.serialized_size(),
        aggregate_sketch: sketch,
        verifier_checks,
        invariant_markers,
        events,
        content_hash,
    })
}

pub fn derive_federated_cascade_prior(
    report: &DgisAtcExchangeReport,
    region_hash: &str,
    window_hash: &str,
) -> Result<FederatedCascadePrior, DgisAtcBridgeError> {
    validate_hash_field("region_hash", region_hash)?;
    validate_hash_field("window_hash", window_hash)?;
    if !constant_time_str_eq(&report.schema_version, DGIS_ATC_BRIDGE_SCHEMA_VERSION) {
        return Err(DgisAtcBridgeError::InvalidPrior(
            "exchange report schema version mismatch".to_string(),
        ));
    }
    if !constant_time_str_eq(
        &report.privacy_contract_version,
        DGIS_ATC_PRIVACY_CONTRACT_VERSION,
    ) {
        return Err(DgisAtcBridgeError::InvalidPrior(
            "exchange report privacy contract mismatch".to_string(),
        ));
    }
    if report.risk_bucket_count == 0 {
        return Err(DgisAtcBridgeError::InvalidPrior(
            "risk bucket count must be > 0".to_string(),
        ));
    }

    let region_window_hash = hash_pair(region_hash, window_hash);
    let matching: Vec<&AnonymizedTopologyIndicator> = report
        .indicators
        .iter()
        .filter(|indicator| {
            indicator.region_hash == region_hash && indicator.window_hash == window_hash
        })
        .collect();
    if matching.is_empty() {
        return Err(DgisAtcBridgeError::NoMatchingRegionWindow(
            region_window_hash,
        ));
    }

    let denominator = f64::from(report.risk_bucket_count);
    let avg_bucket = |selector: fn(&AnonymizedTopologyIndicator) -> u16| -> f64 {
        matching
            .iter()
            .map(|indicator| f64::from(selector(indicator)) / denominator)
            .sum::<f64>()
            / matching.len() as f64
    };
    let topology_prior = avg_bucket(|indicator| indicator.topology_risk_bucket);
    let cascade_prior = avg_bucket(|indicator| indicator.cascade_risk_bucket);
    let risk_prior = topology_prior.max(cascade_prior).clamp(0.0, 1.0);
    let confidence_prior = avg_bucket(|indicator| indicator.confidence_bucket).clamp(0.0, 1.0);
    let articulation_rate = matching
        .iter()
        .filter(|indicator| indicator.articulation_point)
        .count() as f64
        / matching.len() as f64;

    let metric_priors = BTreeMap::from([
        ("aggregate_risk".to_string(), topology_prior.clamp(0.0, 1.0)),
        ("cascade_risk".to_string(), cascade_prior.clamp(0.0, 1.0)),
        (
            "fan_out".to_string(),
            avg_bucket(|indicator| indicator.fan_out_bucket).clamp(0.0, 1.0),
        ),
        (
            "betweenness_centrality".to_string(),
            avg_bucket(|indicator| indicator.betweenness_bucket).clamp(0.0, 1.0),
        ),
        (
            "trust_bottleneck_score".to_string(),
            avg_bucket(|indicator| indicator.trust_bottleneck_bucket).clamp(0.0, 1.0),
        ),
        (
            "transitive_dependency_count".to_string(),
            avg_bucket(|indicator| indicator.transitive_dependency_bucket).clamp(0.0, 1.0),
        ),
        (
            "max_depth_in_graph".to_string(),
            avg_bucket(|indicator| indicator.max_depth_bucket).clamp(0.0, 1.0),
        ),
    ]);

    let prior_id = hash_serializable(
        PRIOR_HASH_DOMAIN,
        &(
            &report.exchange_id,
            region_hash,
            window_hash,
            risk_prior,
            confidence_prior,
            &metric_priors,
            articulation_rate,
        ),
    );
    let content_hash = hash_serializable(
        PRIOR_HASH_DOMAIN,
        &(
            DGIS_ATC_BRIDGE_SCHEMA_VERSION,
            DGIS_ATC_PRIVACY_CONTRACT_VERSION,
            &prior_id,
            &report.exchange_id,
            region_hash,
            window_hash,
            risk_prior,
            confidence_prior,
            &metric_priors,
            articulation_rate,
        ),
    );

    Ok(FederatedCascadePrior {
        schema_version: DGIS_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
        privacy_contract_version: DGIS_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
        prior_id,
        source_exchange_id: report.exchange_id.clone(),
        region_hash: region_hash.to_string(),
        window_hash: window_hash.to_string(),
        region_window_hash: hash_pair(region_hash, window_hash),
        risk_prior,
        confidence_prior,
        metric_priors,
        articulation_rate,
        contributor_count: matching.len(),
        source_indicator_count: report.indicators.len(),
        content_hash,
    })
}

pub fn consume_federated_cascade_prior(
    local_metrics: &TopologyRiskMetrics,
    prior: &FederatedCascadePrior,
    prior_weight: f64,
) -> Result<CascadePriorAssimilationReport, DgisAtcBridgeError> {
    validate_metrics(local_metrics)?;
    validate_prior(prior)?;
    let prior_weight = validate_unit("prior_weight", prior_weight)?;

    let original = local_metrics.clone();
    let mut adjusted = local_metrics.clone();
    let mut changed_metrics = BTreeMap::new();

    apply_scaled_prior(
        "fan_out",
        &mut adjusted.fan_out,
        FAN_OUT_SCALE,
        prior,
        prior_weight,
        &mut changed_metrics,
    );
    apply_unit_prior(
        "betweenness_centrality",
        &mut adjusted.betweenness_centrality,
        prior,
        prior_weight,
        &mut changed_metrics,
    );
    apply_unit_prior(
        "trust_bottleneck_score",
        &mut adjusted.trust_bottleneck_score,
        prior,
        prior_weight,
        &mut changed_metrics,
    );
    apply_count_prior(
        "transitive_dependency_count",
        &mut adjusted.transitive_dependency_count,
        prior,
        prior_weight,
        &mut changed_metrics,
    );
    apply_count_prior(
        "max_depth_in_graph",
        &mut adjusted.max_depth_in_graph,
        prior,
        prior_weight,
        &mut changed_metrics,
    );
    if !adjusted.articulation_point && prior.articulation_rate >= 0.5 {
        adjusted.articulation_point = true;
        changed_metrics.insert("articulation_point".to_string(), 1.0);
    }
    validate_metrics(&adjusted)?;

    let mut events = Vec::new();
    push_bounded(
        &mut events,
        DgisAtcBridgeEvent {
            event_code: event_codes::PRIOR_CONSUMED.to_string(),
            trace_hash: hash_text(&prior.prior_id),
            indicator_id: None,
            detail: "federated cascade prior consumed into local DGIS topology metrics".to_string(),
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
            &changed_metrics,
        ),
    );

    Ok(CascadePriorAssimilationReport {
        schema_version: DGIS_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
        privacy_contract_version: DGIS_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
        prior_id: prior.prior_id.clone(),
        prior_weight,
        original_metrics: original,
        adjusted_metrics: adjusted,
        changed_metrics,
        events,
        content_hash,
    })
}

pub fn region_hash_for(region_id: &str) -> Result<String, DgisAtcBridgeError> {
    validate_text("ecosystem_region", region_id)?;
    Ok(hash_text(region_id))
}

pub fn window_hash_for(window_id: &str) -> Result<String, DgisAtcBridgeError> {
    validate_text("window_id", window_id)?;
    Ok(hash_text(window_id))
}

fn anonymize_indicator(
    input: &DgisTopologyIndicatorInput,
    policy: &DgisAtcPrivacyPolicy,
) -> Result<AnonymizedTopologyIndicator, DgisAtcBridgeError> {
    validate_text("package_name", &input.package_name)?;
    validate_text("version", &input.version)?;
    validate_text("ecosystem_region", &input.ecosystem_region)?;
    validate_text("window_id", &input.window_id)?;
    validate_text("trace_id", &input.trace_id)?;
    validate_metrics(&input.metrics)?;
    let cascade_risk = validate_unit("cascade_risk", input.cascade_risk)?;
    let confidence = validate_unit("confidence", input.confidence)?;

    let region_hash = hash_text(&input.ecosystem_region);
    let window_hash = hash_text(&input.window_id);
    let trace_hash = hash_text(&input.trace_id);
    let region_window_hash = hash_pair(&region_hash, &window_hash);
    let epoch_bucket = bucket_epoch(input.source_epoch, policy.epoch_bucket_width);
    let topology_risk_bucket =
        bucket_unit(input.metrics.aggregate_risk(), policy.risk_bucket_count);
    let cascade_risk_bucket = bucket_unit(cascade_risk, policy.risk_bucket_count);
    let confidence_bucket = bucket_unit(confidence, policy.risk_bucket_count);
    let fan_out_bucket = bucket_scaled(
        input.metrics.fan_out,
        FAN_OUT_SCALE,
        policy.risk_bucket_count,
    );
    let betweenness_bucket = bucket_unit(
        input.metrics.betweenness_centrality,
        policy.risk_bucket_count,
    );
    let trust_bottleneck_bucket = bucket_unit(
        input.metrics.trust_bottleneck_score,
        policy.risk_bucket_count,
    );
    let transitive_dependency_bucket = bucket_count(
        input.metrics.transitive_dependency_count,
        policy.risk_bucket_count,
    );
    let max_depth_bucket = bucket_count(input.metrics.max_depth_in_graph, policy.risk_bucket_count);
    let directly_affected_bucket =
        bucket_count(input.directly_affected_count, policy.risk_bucket_count);
    let indicator_id = hash_serializable(
        INDICATOR_HASH_DOMAIN,
        &IndicatorIdHashFields {
            region_hash: &region_hash,
            window_hash: &window_hash,
            trace_hash: &trace_hash,
            epoch_bucket,
            topology_risk_bucket,
            cascade_risk_bucket,
            confidence_bucket,
            fan_out_bucket,
            betweenness_bucket,
            trust_bottleneck_bucket,
            transitive_dependency_bucket,
            max_depth_bucket,
            directly_affected_bucket,
            articulation_point: input.metrics.articulation_point,
        },
    );
    let content_hash = hash_serializable(
        INDICATOR_HASH_DOMAIN,
        &IndicatorContentHashFields {
            schema_version: DGIS_ATC_BRIDGE_SCHEMA_VERSION,
            privacy_contract_version: DGIS_ATC_PRIVACY_CONTRACT_VERSION,
            indicator_id: &indicator_id,
            region_hash: &region_hash,
            window_hash: &window_hash,
            region_window_hash: &region_window_hash,
            trace_hash: &trace_hash,
            epoch_bucket,
            topology_risk_bucket,
            cascade_risk_bucket,
            confidence_bucket,
            fan_out_bucket,
            betweenness_bucket,
            trust_bottleneck_bucket,
            transitive_dependency_bucket,
            max_depth_bucket,
            directly_affected_bucket,
            articulation_point: input.metrics.articulation_point,
        },
    );

    Ok(AnonymizedTopologyIndicator {
        schema_version: DGIS_ATC_BRIDGE_SCHEMA_VERSION.to_string(),
        privacy_contract_version: DGIS_ATC_PRIVACY_CONTRACT_VERSION.to_string(),
        indicator_id,
        region_hash,
        window_hash,
        region_window_hash,
        trace_hash,
        epoch_bucket,
        topology_risk_bucket,
        cascade_risk_bucket,
        confidence_bucket,
        fan_out_bucket,
        betweenness_bucket,
        trust_bottleneck_bucket,
        transitive_dependency_bucket,
        max_depth_bucket,
        directly_affected_bucket,
        articulation_point: input.metrics.articulation_point,
        content_hash,
    })
}

fn update_sketch(sketch: &mut CountMinSketch, indicator: &AnonymizedTopologyIndicator) {
    sketch.add(
        format!("topology_risk_bucket:{}", indicator.topology_risk_bucket).as_bytes(),
        1,
    );
    sketch.add(
        format!("cascade_risk_bucket:{}", indicator.cascade_risk_bucket).as_bytes(),
        1,
    );
    sketch.add(
        format!("confidence_bucket:{}", indicator.confidence_bucket).as_bytes(),
        1,
    );
    sketch.add(
        format!("region_window:{}", indicator.region_window_hash).as_bytes(),
        1,
    );
    sketch.add(
        format!("articulation:{}", indicator.articulation_point).as_bytes(),
        1,
    );
    for (metric, bucket) in [
        ("fan_out", indicator.fan_out_bucket),
        ("betweenness", indicator.betweenness_bucket),
        ("trust_bottleneck", indicator.trust_bottleneck_bucket),
        (
            "transitive_dependency",
            indicator.transitive_dependency_bucket,
        ),
        ("max_depth", indicator.max_depth_bucket),
    ] {
        sketch.add(format!("metric:{metric}:{bucket}").as_bytes(), 1);
    }
}

fn validate_prior(prior: &FederatedCascadePrior) -> Result<(), DgisAtcBridgeError> {
    if !constant_time_str_eq(&prior.schema_version, DGIS_ATC_BRIDGE_SCHEMA_VERSION) {
        return Err(DgisAtcBridgeError::InvalidPrior(
            "schema version mismatch".to_string(),
        ));
    }
    if !constant_time_str_eq(
        &prior.privacy_contract_version,
        DGIS_ATC_PRIVACY_CONTRACT_VERSION,
    ) {
        return Err(DgisAtcBridgeError::InvalidPrior(
            "privacy contract version mismatch".to_string(),
        ));
    }
    validate_hash_field("prior_id", &prior.prior_id)?;
    validate_hash_field("source_exchange_id", &prior.source_exchange_id)?;
    validate_hash_field("region_hash", &prior.region_hash)?;
    validate_hash_field("window_hash", &prior.window_hash)?;
    validate_hash_field("region_window_hash", &prior.region_window_hash)?;
    validate_unit("risk_prior", prior.risk_prior)?;
    validate_unit("confidence_prior", prior.confidence_prior)?;
    validate_unit("articulation_rate", prior.articulation_rate)?;
    if prior.contributor_count == 0 {
        return Err(DgisAtcBridgeError::InvalidPrior(
            "contributor_count must be > 0".to_string(),
        ));
    }
    if prior.source_indicator_count < prior.contributor_count {
        return Err(DgisAtcBridgeError::InvalidPrior(
            "source_indicator_count must be >= contributor_count".to_string(),
        ));
    }
    for (metric, value) in &prior.metric_priors {
        validate_text("metric_prior.name", metric)?;
        validate_unit("metric_prior.value", *value)?;
    }
    Ok(())
}

fn apply_unit_prior(
    metric: &'static str,
    current: &mut f64,
    prior: &FederatedCascadePrior,
    prior_weight: f64,
    changed_metrics: &mut BTreeMap<String, f64>,
) {
    let Some(prior_value) = prior.metric_priors.get(metric).copied() else {
        return;
    };
    if prior_value <= *current {
        return;
    }
    let delta = (prior_value - *current) * prior_weight * prior.confidence_prior;
    if delta <= 0.0 || !delta.is_finite() {
        return;
    }
    let next = (*current + delta).clamp(0.0, 1.0);
    if next > *current {
        changed_metrics.insert(metric.to_string(), next - *current);
        *current = next;
    }
}

fn apply_scaled_prior(
    metric: &'static str,
    current: &mut f64,
    scale: f64,
    prior: &FederatedCascadePrior,
    prior_weight: f64,
    changed_metrics: &mut BTreeMap<String, f64>,
) {
    if scale <= 0.0 || !scale.is_finite() {
        return;
    }
    let Some(prior_value) = prior.metric_priors.get(metric).copied() else {
        return;
    };
    let current_norm = (*current / scale).clamp(0.0, 1.0);
    if prior_value <= current_norm {
        return;
    }
    let delta = (prior_value - current_norm) * prior_weight * prior.confidence_prior;
    if delta <= 0.0 || !delta.is_finite() {
        return;
    }
    let next_norm = (current_norm + delta).clamp(0.0, 1.0);
    let next = next_norm * scale;
    if next > *current {
        changed_metrics.insert(metric.to_string(), next - *current);
        *current = next;
    }
}

fn apply_count_prior(
    metric: &'static str,
    current: &mut u32,
    prior: &FederatedCascadePrior,
    prior_weight: f64,
    changed_metrics: &mut BTreeMap<String, f64>,
) {
    let Some(prior_value) = prior.metric_priors.get(metric).copied() else {
        return;
    };
    let current_norm = count_unit(*current);
    if prior_value <= current_norm {
        return;
    }
    let delta = (prior_value - current_norm) * prior_weight * prior.confidence_prior;
    if delta <= 0.0 || !delta.is_finite() {
        return;
    }
    let increment = (delta * 128.0).ceil() as u32;
    if increment == 0 {
        return;
    }
    let next = current.saturating_add(increment);
    if next > *current {
        changed_metrics.insert(metric.to_string(), f64::from(next.saturating_sub(*current)));
        *current = next;
    }
}

fn validate_metrics(metrics: &TopologyRiskMetrics) -> Result<(), DgisAtcBridgeError> {
    validate_non_negative_finite("fan_out", metrics.fan_out)?;
    validate_unit("betweenness_centrality", metrics.betweenness_centrality)?;
    validate_unit("trust_bottleneck_score", metrics.trust_bottleneck_score)?;
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), DgisAtcBridgeError> {
    if value.trim().is_empty() {
        return Err(DgisAtcBridgeError::EmptyField { field });
    }
    if value.len() > MAX_STRING_BYTES {
        return Err(DgisAtcBridgeError::FieldTooLong {
            field,
            max: MAX_STRING_BYTES,
        });
    }
    if value.contains('\0') {
        return Err(DgisAtcBridgeError::NulByte { field });
    }
    Ok(())
}

fn validate_hash_field(field: &'static str, value: &str) -> Result<(), DgisAtcBridgeError> {
    validate_text(field, value)?;
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DgisAtcBridgeError::InvalidPrior(format!(
            "{field} must be a 64-byte hex hash"
        )));
    }
    Ok(())
}

fn validate_unit(field: &'static str, value: f64) -> Result<f64, DgisAtcBridgeError> {
    if !value.is_finite() {
        return Err(DgisAtcBridgeError::NonFinite { field, value });
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(DgisAtcBridgeError::UnitOutOfRange { field, value });
    }
    Ok(value)
}

fn validate_non_negative_finite(
    field: &'static str,
    value: f64,
) -> Result<f64, DgisAtcBridgeError> {
    if !value.is_finite() {
        return Err(DgisAtcBridgeError::NonFinite { field, value });
    }
    if value < 0.0 {
        return Err(DgisAtcBridgeError::NegativeMetric { field, value });
    }
    Ok(value)
}

fn constant_time_str_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn bucket_unit(value: f64, bucket_count: u16) -> u16 {
    (value.clamp(0.0, 1.0) * f64::from(bucket_count)).round() as u16
}

fn bucket_scaled(value: f64, scale: f64, bucket_count: u16) -> u16 {
    if scale <= 0.0 || !scale.is_finite() {
        return 0;
    }
    bucket_unit((value / scale).clamp(0.0, 1.0), bucket_count)
}

fn bucket_count(count: u32, bucket_count: u16) -> u16 {
    bucket_unit(count_unit(count), bucket_count)
}

fn count_unit(count: u32) -> f64 {
    let normalized = f64::from(count.saturating_add(1)).log2() / LOG_COUNT_SCALE;
    normalized.clamp(0.0, 1.0)
}

fn bucket_epoch(epoch: u64, width: u64) -> u64 {
    if width == 0 {
        return epoch;
    }
    (epoch / width).saturating_mul(width)
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
        invariants::INV_DGIS_ATC_ANONYMIZED_ONLY.to_string(),
        invariants::INV_DGIS_ATC_NO_RAW_DEPENDENCY_LEAKAGE.to_string(),
        invariants::INV_DGIS_ATC_K_ANONYMITY.to_string(),
        invariants::INV_DGIS_ATC_DETERMINISTIC_HASHES.to_string(),
        invariants::INV_DGIS_ATC_PRIOR_FAIL_CLOSED.to_string(),
        invariants::INV_DGIS_ATC_VERSIONED_CONTRACT.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(fan_out: f64, betweenness: f64, trust: f64) -> TopologyRiskMetrics {
        TopologyRiskMetrics {
            fan_out,
            betweenness_centrality: betweenness,
            articulation_point: fan_out > 40.0,
            trust_bottleneck_score: trust,
            transitive_dependency_count: 120,
            max_depth_in_graph: 8,
        }
    }

    fn input(name: &str, trace: &str, fan_out: f64) -> DgisTopologyIndicatorInput {
        DgisTopologyIndicatorInput::new(
            name,
            "1.2.3",
            "npm-critical-auth-region",
            "2026-05-week-20",
            72,
            metrics(fan_out, 0.72, 0.81),
            0.88,
            0.9,
            24,
            trace,
        )
    }

    #[test]
    fn export_redacts_raw_dependency_identifiers() {
        let report = export_topology_indicators(
            &[
                input("secret-auth-package-a", "trace-secret-a", 76.0),
                input("secret-auth-package-b", "trace-secret-b", 68.0),
            ],
            &DgisAtcPrivacyPolicy::default(),
        )
        .unwrap();

        let encoded = serde_json::to_string(&report).unwrap();
        for forbidden in [
            "secret-auth-package-a",
            "secret-auth-package-b",
            "trace-secret-a",
            "trace-secret-b",
            "npm-critical-auth-region",
            "2026-05-week-20",
            "1.2.3",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "topology exchange leaked raw identifier {forbidden}"
            );
        }
    }

    #[test]
    fn export_is_deterministic_for_same_inputs() {
        let batch = vec![
            input("pkg-a", "trace-a", 76.0),
            input("pkg-b", "trace-b", 68.0),
        ];
        let first = export_topology_indicators(&batch, &DgisAtcPrivacyPolicy::default()).unwrap();
        let second = export_topology_indicators(&batch, &DgisAtcPrivacyPolicy::default()).unwrap();
        assert_eq!(first.exchange_id, second.exchange_id);
        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(first.indicators, second.indicators);
    }

    #[test]
    fn k_anonymity_fails_closed_for_single_region_member() {
        let err =
            export_topology_indicators(&[input("pkg-a", "trace-a", 76.0)], &Default::default())
                .unwrap_err();
        assert!(matches!(
            err,
            DgisAtcBridgeError::RegionBelowK {
                count: 1,
                min: 2,
                ..
            }
        ));
    }

    #[test]
    fn prior_consumption_raises_bounded_topology_metrics() {
        let report = export_topology_indicators(
            &[
                input("pkg-a", "trace-a", 90.0),
                input("pkg-b", "trace-b", 86.0),
            ],
            &DgisAtcPrivacyPolicy::default(),
        )
        .unwrap();
        let region = region_hash_for("npm-critical-auth-region").unwrap();
        let window = window_hash_for("2026-05-week-20").unwrap();
        let prior = derive_federated_cascade_prior(&report, &region, &window).unwrap();
        let local = metrics(10.0, 0.1, 0.1);
        let assimilation = consume_federated_cascade_prior(&local, &prior, 0.5).unwrap();

        assert!(assimilation.adjusted_metrics.fan_out >= local.fan_out);
        assert!(
            assimilation.adjusted_metrics.betweenness_centrality >= local.betweenness_centrality
        );
        assert!(assimilation.adjusted_metrics.trust_bottleneck_score <= 1.0);
        assert!(!assimilation.changed_metrics.is_empty());
    }
}
