//! BPET to DGIS priority fusion (bd-kwwg, section 10.21).
//!
//! This module joins BPET trajectory risk with DGIS topology risk metrics so a
//! suspicious trajectory on a high-centrality node is prioritized ahead of the
//! same trajectory on a low-impact leaf. The output is deterministic,
//! schema-versioned, and carries expected-loss context for policy and operator
//! consumers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security::dgis::update_copilot::TopologyRiskMetrics;

pub const DGIS_FUSION_SCHEMA_VERSION: &str = "bpet-dgis-fusion-v1";
pub const DEFAULT_MAX_LOSS_MULTIPLIER: f64 = 3.0;
pub const DEFAULT_ELEVATED_THRESHOLD: f64 = 0.40;
pub const DEFAULT_HIGH_THRESHOLD: f64 = 0.65;
pub const DEFAULT_CRITICAL_THRESHOLD: f64 = 0.80;
pub const DEFAULT_CRITICAL_EXPECTED_LOSS_USD: f64 = 2_000_000.0;

const BASIS_POINTS_SCALE: f64 = 10_000.0;
const WEIGHT_SUM_TOLERANCE: f64 = 1.0e-9;
const TRANSITIVE_DEPENDENT_NORMALIZER: f64 = 10_000.0;
const DEPTH_NORMALIZER: f64 = 64.0;

pub mod event_codes {
    pub const INPUT_ACCEPTED: &str = "BPET-DGIS-001";
    pub const TOPOLOGY_AMPLIFIED: &str = "BPET-DGIS-002";
    pub const PRIORITY_ESCALATED: &str = "BPET-DGIS-003";
    pub const REPLAY_FINGERPRINT_EMITTED: &str = "BPET-DGIS-004";
    pub const INPUT_REJECTED: &str = "BPET-DGIS-ERR-001";
    pub const POLICY_REJECTED: &str = "BPET-DGIS-ERR-002";
}

pub mod invariants {
    pub const INV_BPET_DGIS_SCHEMA_VERSIONED: &str = "INV-BPET-DGIS-SCHEMA-VERSIONED";
    pub const INV_BPET_DGIS_FAIL_CLOSED_NUMERICS: &str = "INV-BPET-DGIS-FAIL-CLOSED-NUMERICS";
    pub const INV_BPET_DGIS_DETERMINISTIC_REPLAY: &str = "INV-BPET-DGIS-DETERMINISTIC-REPLAY";
    pub const INV_BPET_DGIS_EXPECTED_LOSS_CONTEXT: &str = "INV-BPET-DGIS-EXPECTED-LOSS-CONTEXT";
    pub const INV_BPET_DGIS_TOPOLOGY_AMPLIFICATION: &str = "INV-BPET-DGIS-TOPOLOGY-AMPLIFICATION";
}

#[derive(Debug, thiserror::Error)]
pub enum DgisFusionError {
    #[error("package_id is empty")]
    EmptyPackageId,
    #[error("trace_id is empty")]
    EmptyTraceId,
    #[error("field `{field}` is not finite: {value}")]
    NonFinite { field: &'static str, value: f64 },
    #[error("field `{field}` is outside [0, 1]: {value}")]
    UnitOutOfRange { field: &'static str, value: f64 },
    #[error("field `{field}` is negative: {value}")]
    Negative { field: &'static str, value: f64 },
    #[error("fusion weights must sum to 1.0 within {tolerance:e}, got {actual}")]
    WeightsDoNotSumToOne { actual: f64, tolerance: f64 },
    #[error("policy thresholds must satisfy elevated <= high <= critical")]
    InvalidThresholdOrder,
    #[error("replay fingerprint serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationLevel {
    Monitor,
    Elevated,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetDgisFusionPolicy {
    pub bpet_weight: f64,
    pub topology_weight: f64,
    pub max_loss_multiplier: f64,
    pub elevated_threshold: f64,
    pub high_threshold: f64,
    pub critical_threshold: f64,
    pub critical_expected_loss_usd: f64,
}

impl Default for BpetDgisFusionPolicy {
    fn default() -> Self {
        Self {
            bpet_weight: 0.60,
            topology_weight: 0.40,
            max_loss_multiplier: DEFAULT_MAX_LOSS_MULTIPLIER,
            elevated_threshold: DEFAULT_ELEVATED_THRESHOLD,
            high_threshold: DEFAULT_HIGH_THRESHOLD,
            critical_threshold: DEFAULT_CRITICAL_THRESHOLD,
            critical_expected_loss_usd: DEFAULT_CRITICAL_EXPECTED_LOSS_USD,
        }
    }
}

impl BpetDgisFusionPolicy {
    pub fn validate(&self) -> Result<(), DgisFusionError> {
        finite_nonnegative("policy.bpet_weight", self.bpet_weight)?;
        finite_nonnegative("policy.topology_weight", self.topology_weight)?;
        finite_nonnegative("policy.max_loss_multiplier", self.max_loss_multiplier)?;
        finite_nonnegative(
            "policy.critical_expected_loss_usd",
            self.critical_expected_loss_usd,
        )?;
        finite_unit("policy.elevated_threshold", self.elevated_threshold)?;
        finite_unit("policy.high_threshold", self.high_threshold)?;
        finite_unit("policy.critical_threshold", self.critical_threshold)?;

        let weight_sum = self.bpet_weight + self.topology_weight;
        if !weight_sum.is_finite() || (weight_sum - 1.0).abs() > WEIGHT_SUM_TOLERANCE {
            return Err(DgisFusionError::WeightsDoNotSumToOne {
                actual: weight_sum,
                tolerance: WEIGHT_SUM_TOLERANCE,
            });
        }
        if self.elevated_threshold > self.high_threshold
            || self.high_threshold > self.critical_threshold
        {
            return Err(DgisFusionError::InvalidThresholdOrder);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetDgisFusionInput {
    pub package_id: String,
    pub bpet_risk_score: f64,
    pub bpet_confidence: f64,
    pub expected_loss_if_compromised_usd: f64,
    pub topology_metrics: TopologyRiskMetrics,
    pub trace_id: String,
}

impl BpetDgisFusionInput {
    pub fn validate(&self) -> Result<(), DgisFusionError> {
        if self.package_id.trim().is_empty() {
            return Err(DgisFusionError::EmptyPackageId);
        }
        if self.trace_id.trim().is_empty() {
            return Err(DgisFusionError::EmptyTraceId);
        }
        finite_unit("input.bpet_risk_score", self.bpet_risk_score)?;
        finite_unit("input.bpet_confidence", self.bpet_confidence)?;
        finite_nonnegative(
            "input.expected_loss_if_compromised_usd",
            self.expected_loss_if_compromised_usd,
        )?;
        validate_topology_metrics(&self.topology_metrics)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyAmplification {
    pub topology_pressure: f64,
    pub attribution: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpectedLossContext {
    pub base_expected_loss_usd: f64,
    pub topology_multiplier: f64,
    pub amplified_expected_loss_usd: f64,
    pub confidence_basis_points: u16,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetDgisPriorityEscalation {
    pub schema_version: String,
    pub package_id: String,
    pub trace_id: String,
    pub combined_priority_score: f64,
    pub escalation_level: EscalationLevel,
    pub expected_loss: ExpectedLossContext,
    pub priority_attribution: BTreeMap<String, f64>,
    pub topology_attribution: BTreeMap<String, f64>,
    pub recommended_action: String,
    pub event_codes: Vec<String>,
    pub invariant_markers: Vec<String>,
    pub replay_fingerprint: String,
}

#[derive(Serialize)]
struct ReplayMaterial<'a> {
    schema_version: &'static str,
    input: &'a BpetDgisFusionInput,
    policy: &'a BpetDgisFusionPolicy,
    combined_priority_score: f64,
    escalation_level: EscalationLevel,
    priority_attribution: &'a BTreeMap<String, f64>,
    topology_attribution: &'a BTreeMap<String, f64>,
    amplified_expected_loss_usd: f64,
}

pub fn compute_topology_amplification(
    metrics: &TopologyRiskMetrics,
) -> Result<TopologyAmplification, DgisFusionError> {
    validate_topology_metrics(metrics)?;

    let dgis_aggregate = metrics.aggregate_risk().clamp(0.0, 1.0);
    let transitive_pressure = (f64::from(metrics.transitive_dependency_count)
        / TRANSITIVE_DEPENDENT_NORMALIZER)
        .clamp(0.0, 1.0);
    let depth_pressure = (f64::from(metrics.max_depth_in_graph) / DEPTH_NORMALIZER).clamp(0.0, 1.0);
    let articulation_pressure = if metrics.articulation_point { 1.0 } else { 0.0 };
    let trust_bottleneck_pressure = metrics.trust_bottleneck_score.clamp(0.0, 1.0);

    let mut attribution = BTreeMap::new();
    attribution.insert("dgis_aggregate_risk".to_string(), dgis_aggregate * 0.50);
    attribution.insert(
        "transitive_dependency_pressure".to_string(),
        transitive_pressure * 0.20,
    );
    attribution.insert("graph_depth_pressure".to_string(), depth_pressure * 0.10);
    attribution.insert(
        "articulation_pressure".to_string(),
        articulation_pressure * 0.10,
    );
    attribution.insert(
        "trust_bottleneck_pressure".to_string(),
        trust_bottleneck_pressure * 0.10,
    );

    let topology_pressure = attribution.values().sum::<f64>().clamp(0.0, 1.0);

    Ok(TopologyAmplification {
        topology_pressure,
        attribution,
    })
}

pub fn prioritize_with_dgis(
    input: &BpetDgisFusionInput,
    policy: &BpetDgisFusionPolicy,
) -> Result<BpetDgisPriorityEscalation, DgisFusionError> {
    input.validate()?;
    policy.validate()?;

    let topology = compute_topology_amplification(&input.topology_metrics)?;
    let bpet_contribution = input.bpet_risk_score * policy.bpet_weight;
    let topology_contribution = topology.topology_pressure * policy.topology_weight;
    let combined_priority_score = (bpet_contribution + topology_contribution).clamp(0.0, 1.0);

    let topology_multiplier = 1.0 + topology.topology_pressure * policy.max_loss_multiplier;
    let amplified_expected_loss_usd = input.expected_loss_if_compromised_usd * topology_multiplier;
    if !amplified_expected_loss_usd.is_finite() {
        return Err(DgisFusionError::NonFinite {
            field: "output.amplified_expected_loss_usd",
            value: amplified_expected_loss_usd,
        });
    }

    let escalation_level = escalation_for(
        combined_priority_score,
        amplified_expected_loss_usd,
        input.topology_metrics.articulation_point,
        policy,
    );

    let mut priority_attribution = BTreeMap::new();
    priority_attribution.insert("bpet_trajectory_risk".to_string(), bpet_contribution);
    priority_attribution.insert("dgis_topology_pressure".to_string(), topology_contribution);

    let expected_loss = ExpectedLossContext {
        base_expected_loss_usd: input.expected_loss_if_compromised_usd,
        topology_multiplier,
        amplified_expected_loss_usd,
        confidence_basis_points: unit_to_basis_points(input.bpet_confidence),
        rationale: format!(
            "BPET risk {:.3} on DGIS topology pressure {:.3}; articulation_point={}",
            input.bpet_risk_score,
            topology.topology_pressure,
            input.topology_metrics.articulation_point
        ),
    };

    let recommended_action = recommended_action(escalation_level);
    let invariant_markers = vec![
        invariants::INV_BPET_DGIS_SCHEMA_VERSIONED.to_string(),
        invariants::INV_BPET_DGIS_FAIL_CLOSED_NUMERICS.to_string(),
        invariants::INV_BPET_DGIS_DETERMINISTIC_REPLAY.to_string(),
        invariants::INV_BPET_DGIS_EXPECTED_LOSS_CONTEXT.to_string(),
        invariants::INV_BPET_DGIS_TOPOLOGY_AMPLIFICATION.to_string(),
    ];
    let event_codes = vec![
        event_codes::INPUT_ACCEPTED.to_string(),
        event_codes::TOPOLOGY_AMPLIFIED.to_string(),
        event_codes::PRIORITY_ESCALATED.to_string(),
        event_codes::REPLAY_FINGERPRINT_EMITTED.to_string(),
    ];

    let replay_fingerprint = replay_fingerprint(&ReplayMaterial {
        schema_version: DGIS_FUSION_SCHEMA_VERSION,
        input,
        policy,
        combined_priority_score,
        escalation_level,
        priority_attribution: &priority_attribution,
        topology_attribution: &topology.attribution,
        amplified_expected_loss_usd,
    })?;

    Ok(BpetDgisPriorityEscalation {
        schema_version: DGIS_FUSION_SCHEMA_VERSION.to_string(),
        package_id: input.package_id.clone(),
        trace_id: input.trace_id.clone(),
        combined_priority_score,
        escalation_level,
        expected_loss,
        priority_attribution,
        topology_attribution: topology.attribution,
        recommended_action,
        event_codes,
        invariant_markers,
        replay_fingerprint,
    })
}

fn validate_topology_metrics(metrics: &TopologyRiskMetrics) -> Result<(), DgisFusionError> {
    finite_nonnegative("topology.fan_out", metrics.fan_out)?;
    finite_unit(
        "topology.betweenness_centrality",
        metrics.betweenness_centrality,
    )?;
    finite_unit(
        "topology.trust_bottleneck_score",
        metrics.trust_bottleneck_score,
    )?;
    Ok(())
}

fn finite_nonnegative(field: &'static str, value: f64) -> Result<(), DgisFusionError> {
    if !value.is_finite() {
        return Err(DgisFusionError::NonFinite { field, value });
    }
    if value < 0.0 {
        return Err(DgisFusionError::Negative { field, value });
    }
    Ok(())
}

fn finite_unit(field: &'static str, value: f64) -> Result<(), DgisFusionError> {
    if !value.is_finite() {
        return Err(DgisFusionError::NonFinite { field, value });
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(DgisFusionError::UnitOutOfRange { field, value });
    }
    Ok(())
}

fn escalation_for(
    combined_priority_score: f64,
    amplified_expected_loss_usd: f64,
    articulation_point: bool,
    policy: &BpetDgisFusionPolicy,
) -> EscalationLevel {
    if combined_priority_score >= policy.critical_threshold
        || (articulation_point && amplified_expected_loss_usd >= policy.critical_expected_loss_usd)
    {
        EscalationLevel::Critical
    } else if combined_priority_score >= policy.high_threshold {
        EscalationLevel::High
    } else if combined_priority_score >= policy.elevated_threshold {
        EscalationLevel::Elevated
    } else {
        EscalationLevel::Monitor
    }
}

fn recommended_action(level: EscalationLevel) -> String {
    match level {
        EscalationLevel::Monitor => "continue longitudinal monitoring".to_string(),
        EscalationLevel::Elevated => "raise operator review priority".to_string(),
        EscalationLevel::High => {
            "pre-stage DGIS barriers and require maintainer review".to_string()
        }
        EscalationLevel::Critical => {
            "quarantine candidate and require DGIS barrier plan before release".to_string()
        }
    }
}

fn unit_to_basis_points(score: f64) -> u16 {
    (score.clamp(0.0, 1.0) * BASIS_POINTS_SCALE).round() as u16
}

fn replay_fingerprint<T: Serialize>(value: &T) -> Result<String, DgisFusionError> {
    let bytes =
        serde_json::to_vec(value).map_err(|err| DgisFusionError::Serialization(err.to_string()))?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn high_centrality_metrics() -> TopologyRiskMetrics {
        TopologyRiskMetrics {
            fan_out: 84.0,
            betweenness_centrality: 0.82,
            articulation_point: true,
            trust_bottleneck_score: 0.91,
            transitive_dependency_count: 4_200,
            max_depth_in_graph: 17,
        }
    }

    fn low_centrality_metrics() -> TopologyRiskMetrics {
        TopologyRiskMetrics {
            fan_out: 4.0,
            betweenness_centrality: 0.05,
            articulation_point: false,
            trust_bottleneck_score: 0.10,
            transitive_dependency_count: 3,
            max_depth_in_graph: 2,
        }
    }

    fn input(metrics: TopologyRiskMetrics) -> BpetDgisFusionInput {
        BpetDgisFusionInput {
            package_id: "npm:@acme/critical-auth".to_string(),
            bpet_risk_score: 0.84,
            bpet_confidence: 0.88,
            expected_loss_if_compromised_usd: 750_000.0,
            topology_metrics: metrics,
            trace_id: "trace-bpet-dgis-fusion".to_string(),
        }
    }

    #[test]
    fn high_centrality_bpet_anomaly_escalates_to_critical() {
        let output = prioritize_with_dgis(
            &input(high_centrality_metrics()),
            &BpetDgisFusionPolicy::default(),
        )
        .expect("high centrality fusion should succeed");

        assert_eq!(output.schema_version, DGIS_FUSION_SCHEMA_VERSION);
        assert_eq!(output.escalation_level, EscalationLevel::Critical);
        assert!(output.combined_priority_score >= DEFAULT_CRITICAL_THRESHOLD);
        assert!(output.expected_loss.amplified_expected_loss_usd > 2_000_000.0);
        assert!(
            output
                .priority_attribution
                .get("dgis_topology_pressure")
                .copied()
                .unwrap_or_default()
                > 0.25
        );
        assert!(
            output
                .invariant_markers
                .contains(&invariants::INV_BPET_DGIS_EXPECTED_LOSS_CONTEXT.to_string())
        );
    }

    #[test]
    fn same_bpet_score_on_low_centrality_node_is_not_critical() {
        let output = prioritize_with_dgis(
            &input(low_centrality_metrics()),
            &BpetDgisFusionPolicy::default(),
        )
        .expect("low centrality fusion should succeed");

        assert_eq!(output.escalation_level, EscalationLevel::Elevated);
        assert!(output.combined_priority_score < DEFAULT_HIGH_THRESHOLD);
        assert!(output.expected_loss.amplified_expected_loss_usd < 850_000.0);
    }

    #[test]
    fn replay_fingerprint_is_deterministic() {
        let input = input(high_centrality_metrics());
        let policy = BpetDgisFusionPolicy::default();

        let a = prioritize_with_dgis(&input, &policy).expect("first run");
        let b = prioritize_with_dgis(&input, &policy).expect("second run");

        assert_eq!(a, b);
        assert!(a.replay_fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn non_finite_bpet_risk_is_rejected() {
        let mut input = input(high_centrality_metrics());
        input.bpet_risk_score = f64::NAN;

        let err = prioritize_with_dgis(&input, &BpetDgisFusionPolicy::default())
            .expect_err("NaN BPET risk must fail closed");

        assert!(matches!(
            err,
            DgisFusionError::NonFinite {
                field: "input.bpet_risk_score",
                ..
            }
        ));
    }

    #[test]
    fn invalid_policy_weight_sum_is_rejected() {
        let policy = BpetDgisFusionPolicy {
            bpet_weight: 0.9,
            topology_weight: 0.9,
            ..BpetDgisFusionPolicy::default()
        };

        let err = prioritize_with_dgis(&input(high_centrality_metrics()), &policy)
            .expect_err("invalid policy must fail closed");

        assert!(matches!(err, DgisFusionError::WeightsDoNotSumToOne { .. }));
    }
}
