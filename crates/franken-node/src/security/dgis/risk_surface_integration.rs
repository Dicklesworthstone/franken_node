//! DGIS topological risk surface integration.
//!
//! This module materializes topology context for trust-card style risk
//! surfaces, adversary posterior updates, and extension risk UI snapshots. It
//! deliberately stays separate from the trust-card persistence module so
//! existing cards can consume DGIS context without changing their wire format.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security::dgis::update_copilot::{RiskDelta, TopologyRiskMetrics};

pub const RISK_SURFACE_SCHEMA_VERSION: &str = "dgis-risk-surface-v1";
const MAX_IDENTIFIER_BYTES: usize = 512;
const EPSILON: f64 = 1.0e-9;

pub mod event_codes {
    pub const INPUT_ACCEPTED: &str = "DGIS-RISK-SURFACE-001";
    pub const TRUST_CONTEXT_COMPUTED: &str = "DGIS-RISK-SURFACE-002";
    pub const POSTERIOR_UPDATED: &str = "DGIS-RISK-SURFACE-003";
    pub const UI_SNAPSHOT_EMITTED: &str = "DGIS-RISK-SURFACE-004";
    pub const INPUT_REJECTED: &str = "DGIS-RISK-SURFACE-ERR-001";
}

pub mod invariants {
    pub const SCHEMA_VERSIONED: &str = "INV-DGIS-RISK-SURFACE-SCHEMA-VERSIONED";
    pub const FAIL_CLOSED_NUMERICS: &str = "INV-DGIS-RISK-SURFACE-FAIL-CLOSED-NUMERICS";
    pub const DETERMINISTIC_REPLAY: &str = "INV-DGIS-RISK-SURFACE-DETERMINISTIC-REPLAY";
    pub const TOPOLOGY_ATTRIBUTION: &str = "INV-DGIS-RISK-SURFACE-TOPOLOGY-ATTRIBUTION";
}

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum RiskSurfaceError {
    #[error("invalid identifier {field}: {reason}")]
    InvalidIdentifier {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid metric {field}: {value}")]
    InvalidMetric { field: &'static str, value: f64 },
    #[error("invalid posterior: {0}")]
    InvalidPosterior(f64),
    #[error("risk surface requires at least one planned topology change")]
    EmptyPlannedChanges,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedChangeKind {
    AddDependency,
    UpdateVersion,
    RemoveDependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSurfaceTier {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedTopologyChange {
    pub change_kind: PlannedChangeKind,
    pub package_name: String,
    pub from_version: String,
    pub to_version: String,
    pub post_update_metrics: TopologyRiskMetrics,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskSurfaceInput {
    pub extension_id: String,
    pub trace_id: String,
    pub base_adversary_posterior: f64,
    pub current_metrics: TopologyRiskMetrics,
    pub planned_changes: Vec<PlannedTopologyChange>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustCardTopologyContext {
    pub extension_id: String,
    pub aggregate_risk_score: f64,
    pub risk_tier: RiskSurfaceTier,
    pub downstream_transitive_dependents: u32,
    pub upstream_risk_exposure: f64,
    pub articulation_point: bool,
    pub max_depth_in_graph: u32,
    pub operator_summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PosteriorTopologyUpdate {
    pub base_posterior: f64,
    pub topology_adjusted_posterior: f64,
    pub topology_risk_score: f64,
    pub attribution_percentages: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedRiskDelta {
    pub change_kind: PlannedChangeKind,
    pub package_name: String,
    pub from_version: String,
    pub to_version: String,
    pub pre_update_risk: f64,
    pub post_update_risk: f64,
    pub risk_delta: f64,
    pub risk_increased: bool,
    pub per_metric_deltas: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskUiSnapshot {
    pub headline: String,
    pub risk_tier: RiskSurfaceTier,
    pub overlays: BTreeMap<String, String>,
    pub delta_heatmap: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskSurfaceEvent {
    pub event_code: String,
    pub detail: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskSurfaceSnapshot {
    pub schema_version: String,
    pub extension_id: String,
    pub trace_id: String,
    pub trust_card_context: TrustCardTopologyContext,
    pub posterior_update: PosteriorTopologyUpdate,
    pub planned_update_deltas: Vec<PlannedRiskDelta>,
    pub risk_ui: RiskUiSnapshot,
    pub invariant_markers: Vec<String>,
    pub audit_events: Vec<RiskSurfaceEvent>,
    pub replay_fingerprint: String,
}

pub fn build_risk_surface_snapshot(
    input: RiskSurfaceInput,
) -> Result<RiskSurfaceSnapshot, RiskSurfaceError> {
    validate_identifier("extension_id", &input.extension_id)?;
    validate_identifier("trace_id", &input.trace_id)?;
    validate_posterior(input.base_adversary_posterior)?;
    validate_metrics("current", &input.current_metrics)?;
    if input.planned_changes.is_empty() {
        return Err(RiskSurfaceError::EmptyPlannedChanges);
    }

    let current_risk = input.current_metrics.aggregate_risk();
    let trust_card_context =
        build_trust_card_context(&input.extension_id, &input.current_metrics, current_risk);
    let posterior_update = build_posterior_update(
        input.base_adversary_posterior,
        &input.current_metrics,
        current_risk,
    );

    let mut planned_changes = input.planned_changes.clone();
    planned_changes.sort_by(|left, right| {
        left.change_kind
            .cmp(&right.change_kind)
            .then(left.package_name.cmp(&right.package_name))
            .then(left.to_version.cmp(&right.to_version))
    });

    let mut planned_update_deltas = Vec::with_capacity(planned_changes.len());
    for change in planned_changes {
        validate_identifier("planned.package_name", &change.package_name)?;
        validate_identifier("planned.from_version", &change.from_version)?;
        validate_identifier("planned.to_version", &change.to_version)?;
        validate_metrics("planned.post_update", &change.post_update_metrics)?;
        planned_update_deltas.push(build_planned_delta(&input.current_metrics, change));
    }

    let risk_ui = build_risk_ui_snapshot(
        &input.extension_id,
        &trust_card_context,
        &posterior_update,
        &planned_update_deltas,
    );
    let audit_events = vec![
        RiskSurfaceEvent {
            event_code: event_codes::INPUT_ACCEPTED.to_string(),
            detail: "topology risk surface input accepted".to_string(),
            trace_id: input.trace_id.clone(),
        },
        RiskSurfaceEvent {
            event_code: event_codes::TRUST_CONTEXT_COMPUTED.to_string(),
            detail: "trust-card topology context computed".to_string(),
            trace_id: input.trace_id.clone(),
        },
        RiskSurfaceEvent {
            event_code: event_codes::POSTERIOR_UPDATED.to_string(),
            detail: "adversary posterior updated with topology attribution".to_string(),
            trace_id: input.trace_id.clone(),
        },
        RiskSurfaceEvent {
            event_code: event_codes::UI_SNAPSHOT_EMITTED.to_string(),
            detail: "extension risk UI snapshot emitted".to_string(),
            trace_id: input.trace_id.clone(),
        },
    ];
    let invariant_markers = vec![
        invariants::SCHEMA_VERSIONED.to_string(),
        invariants::FAIL_CLOSED_NUMERICS.to_string(),
        invariants::DETERMINISTIC_REPLAY.to_string(),
        invariants::TOPOLOGY_ATTRIBUTION.to_string(),
    ];
    let replay_fingerprint = replay_fingerprint(
        &input,
        &trust_card_context,
        &posterior_update,
        &planned_update_deltas,
    );

    Ok(RiskSurfaceSnapshot {
        schema_version: RISK_SURFACE_SCHEMA_VERSION.to_string(),
        extension_id: input.extension_id,
        trace_id: input.trace_id,
        trust_card_context,
        posterior_update,
        planned_update_deltas,
        risk_ui,
        invariant_markers,
        audit_events,
        replay_fingerprint,
    })
}

fn build_trust_card_context(
    extension_id: &str,
    metrics: &TopologyRiskMetrics,
    aggregate_risk_score: f64,
) -> TrustCardTopologyContext {
    let risk_tier = classify_risk(aggregate_risk_score);
    TrustCardTopologyContext {
        extension_id: extension_id.to_string(),
        aggregate_risk_score,
        risk_tier,
        downstream_transitive_dependents: metrics.transitive_dependency_count,
        upstream_risk_exposure: metrics.trust_bottleneck_score.clamp(0.0, 1.0),
        articulation_point: metrics.articulation_point,
        max_depth_in_graph: metrics.max_depth_in_graph,
        operator_summary: format!(
            "{extension_id} is {risk_tier:?}: {} transitive dependents, articulation_point={}, upstream_exposure={:.3}",
            metrics.transitive_dependency_count,
            metrics.articulation_point,
            metrics.trust_bottleneck_score.clamp(0.0, 1.0),
        ),
    }
}

fn build_posterior_update(
    base_posterior: f64,
    metrics: &TopologyRiskMetrics,
    topology_risk: f64,
) -> PosteriorTopologyUpdate {
    let adjusted = (base_posterior + ((1.0 - base_posterior) * topology_risk)).clamp(0.0, 1.0);
    PosteriorTopologyUpdate {
        base_posterior,
        topology_adjusted_posterior: adjusted,
        topology_risk_score: topology_risk,
        attribution_percentages: attribution_percentages(metrics),
    }
}

fn build_planned_delta(
    current_metrics: &TopologyRiskMetrics,
    change: PlannedTopologyChange,
) -> PlannedRiskDelta {
    let delta = RiskDelta::compute(
        &change.package_name,
        &change.from_version,
        &change.to_version,
        current_metrics.clone(),
        change.post_update_metrics,
    );
    PlannedRiskDelta {
        change_kind: change.change_kind,
        package_name: delta.package_name,
        from_version: delta.from_version,
        to_version: delta.to_version,
        pre_update_risk: delta.pre_update.aggregate_risk(),
        post_update_risk: delta.post_update.aggregate_risk(),
        risk_delta: delta.risk_delta,
        risk_increased: delta.risk_increased,
        per_metric_deltas: delta.per_metric_deltas,
    }
}

fn build_risk_ui_snapshot(
    extension_id: &str,
    trust_card_context: &TrustCardTopologyContext,
    posterior_update: &PosteriorTopologyUpdate,
    planned_update_deltas: &[PlannedRiskDelta],
) -> RiskUiSnapshot {
    let mut overlays = BTreeMap::new();
    overlays.insert(
        "blast_radius".to_string(),
        format!(
            "{} downstream dependents across depth {}",
            trust_card_context.downstream_transitive_dependents,
            trust_card_context.max_depth_in_graph
        ),
    );
    overlays.insert(
        "posterior_shift".to_string(),
        format!(
            "{:.3} -> {:.3}",
            posterior_update.base_posterior, posterior_update.topology_adjusted_posterior
        ),
    );
    overlays.insert(
        "topology_attribution".to_string(),
        attribution_summary(&posterior_update.attribution_percentages),
    );

    let mut delta_heatmap = BTreeMap::new();
    for delta in planned_update_deltas {
        delta_heatmap.insert(
            format!("{}:{:?}", delta.package_name, delta.change_kind),
            delta.risk_delta,
        );
    }

    RiskUiSnapshot {
        headline: format!(
            "{extension_id} topology risk: {:?}",
            trust_card_context.risk_tier
        ),
        risk_tier: trust_card_context.risk_tier,
        overlays,
        delta_heatmap,
    }
}

fn attribution_percentages(metrics: &TopologyRiskMetrics) -> BTreeMap<String, f64> {
    let fan_out = (metrics.fan_out / 100.0).clamp(0.0, 1.0) * 0.20;
    let betweenness = metrics.betweenness_centrality.clamp(0.0, 1.0) * 0.25;
    let articulation = if metrics.articulation_point {
        0.30
    } else {
        0.0
    };
    let trust = metrics.trust_bottleneck_score.clamp(0.0, 1.0) * 0.25;

    let mut attribution = BTreeMap::new();
    attribution.insert("articulation_point".to_string(), articulation);
    attribution.insert("betweenness_centrality".to_string(), betweenness);
    attribution.insert("fan_out".to_string(), fan_out);
    attribution.insert("trust_bottleneck_score".to_string(), trust);
    normalize_attribution(&mut attribution);
    attribution
}

fn normalize_attribution(attribution: &mut BTreeMap<String, f64>) {
    let sum: f64 = attribution.values().copied().sum();
    if sum <= EPSILON || !sum.is_finite() {
        return;
    }
    for value in attribution.values_mut() {
        *value = (*value / sum).clamp(0.0, 1.0);
    }
}

fn attribution_summary(attribution: &BTreeMap<String, f64>) -> String {
    attribution
        .iter()
        .map(|(feature, share)| format!("{feature}={share:.3}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn classify_risk(score: f64) -> RiskSurfaceTier {
    if score >= 0.75 {
        RiskSurfaceTier::Critical
    } else if score >= 0.50 {
        RiskSurfaceTier::High
    } else if score >= 0.25 {
        RiskSurfaceTier::Medium
    } else {
        RiskSurfaceTier::Low
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), RiskSurfaceError> {
    if value.trim().is_empty() {
        return Err(RiskSurfaceError::InvalidIdentifier {
            field,
            reason: "empty",
        });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(RiskSurfaceError::InvalidIdentifier {
            field,
            reason: "too_long",
        });
    }
    if value.contains('\0') {
        return Err(RiskSurfaceError::InvalidIdentifier {
            field,
            reason: "nul_byte",
        });
    }
    Ok(())
}

fn validate_posterior(value: f64) -> Result<(), RiskSurfaceError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(RiskSurfaceError::InvalidPosterior(value));
    }
    Ok(())
}

fn validate_metrics(
    label: &'static str,
    metrics: &TopologyRiskMetrics,
) -> Result<(), RiskSurfaceError> {
    validate_non_negative_finite(label, "fan_out", metrics.fan_out)?;
    validate_unit_finite(
        label,
        "betweenness_centrality",
        metrics.betweenness_centrality,
    )?;
    validate_unit_finite(
        label,
        "trust_bottleneck_score",
        metrics.trust_bottleneck_score,
    )?;
    Ok(())
}

fn validate_non_negative_finite(
    label: &'static str,
    name: &'static str,
    value: f64,
) -> Result<(), RiskSurfaceError> {
    if !value.is_finite() || value < 0.0 {
        return Err(RiskSurfaceError::InvalidMetric {
            field: metric_field(label, name),
            value,
        });
    }
    Ok(())
}

fn validate_unit_finite(
    label: &'static str,
    name: &'static str,
    value: f64,
) -> Result<(), RiskSurfaceError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(RiskSurfaceError::InvalidMetric {
            field: metric_field(label, name),
            value,
        });
    }
    Ok(())
}

fn metric_field(label: &'static str, name: &'static str) -> &'static str {
    match (label, name) {
        ("current", "fan_out") => "current.fan_out",
        ("current", "betweenness_centrality") => "current.betweenness_centrality",
        ("current", "trust_bottleneck_score") => "current.trust_bottleneck_score",
        ("planned.post_update", "fan_out") => "planned.post_update.fan_out",
        ("planned.post_update", "betweenness_centrality") => {
            "planned.post_update.betweenness_centrality"
        }
        ("planned.post_update", "trust_bottleneck_score") => {
            "planned.post_update.trust_bottleneck_score"
        }
        _ => "metric",
    }
}

fn replay_fingerprint(
    input: &RiskSurfaceInput,
    context: &TrustCardTopologyContext,
    posterior: &PosteriorTopologyUpdate,
    deltas: &[PlannedRiskDelta],
) -> String {
    let mut hasher = Sha256::new();
    update_str_len_prefixed(&mut hasher, RISK_SURFACE_SCHEMA_VERSION);
    update_str_len_prefixed(&mut hasher, &input.extension_id);
    update_str_len_prefixed(&mut hasher, &input.trace_id);
    update_f64(&mut hasher, context.aggregate_risk_score);
    update_f64(&mut hasher, posterior.base_posterior);
    update_f64(&mut hasher, posterior.topology_adjusted_posterior);
    update_len(&mut hasher, posterior.attribution_percentages.len());
    for (feature, share) in &posterior.attribution_percentages {
        update_str_len_prefixed(&mut hasher, feature);
        update_f64(&mut hasher, *share);
    }
    update_len(&mut hasher, deltas.len());
    for delta in deltas {
        update_str_len_prefixed(&mut hasher, &format!("{:?}", delta.change_kind));
        update_str_len_prefixed(&mut hasher, &delta.package_name);
        update_str_len_prefixed(&mut hasher, &delta.from_version);
        update_str_len_prefixed(&mut hasher, &delta.to_version);
        update_f64(&mut hasher, delta.risk_delta);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn update_len(hasher: &mut Sha256, len: usize) {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
}

fn update_bytes_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    update_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn update_str_len_prefixed(hasher: &mut Sha256, value: &str) {
    update_bytes_len_prefixed(hasher, value.as_bytes());
}

fn update_f64(hasher: &mut Sha256, value: f64) {
    hasher.update(value.to_bits().to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(
        fan_out: f64,
        betweenness: f64,
        articulation_point: bool,
        trust: f64,
        transitive_count: u32,
    ) -> TopologyRiskMetrics {
        TopologyRiskMetrics {
            fan_out,
            betweenness_centrality: betweenness,
            articulation_point,
            trust_bottleneck_score: trust,
            transitive_dependency_count: transitive_count,
            max_depth_in_graph: 9,
        }
    }

    fn sample_input() -> RiskSurfaceInput {
        RiskSurfaceInput {
            extension_id: "npm:@acme/auth-guard".to_string(),
            trace_id: "trace-risk-surface".to_string(),
            base_adversary_posterior: 0.22,
            current_metrics: metrics(80.0, 0.72, true, 0.64, 1840),
            planned_changes: vec![
                PlannedTopologyChange {
                    change_kind: PlannedChangeKind::AddDependency,
                    package_name: "npm:@acme/auth-guard".to_string(),
                    from_version: "1.2.3".to_string(),
                    to_version: "1.3.0-add-oauth".to_string(),
                    post_update_metrics: metrics(95.0, 0.80, true, 0.74, 2050),
                },
                PlannedTopologyChange {
                    change_kind: PlannedChangeKind::RemoveDependency,
                    package_name: "npm:@acme/auth-guard".to_string(),
                    from_version: "1.2.3".to_string(),
                    to_version: "1.2.4-prune".to_string(),
                    post_update_metrics: metrics(40.0, 0.44, false, 0.40, 720),
                },
            ],
        }
    }

    #[test]
    fn high_topology_risk_surfaces_critical_trust_context() {
        let snapshot = build_risk_surface_snapshot(sample_input()).expect("snapshot");
        assert_eq!(snapshot.schema_version, RISK_SURFACE_SCHEMA_VERSION);
        assert_eq!(
            snapshot.trust_card_context.risk_tier,
            RiskSurfaceTier::Critical
        );
        assert_eq!(
            snapshot.trust_card_context.downstream_transitive_dependents,
            1840
        );
        assert!(snapshot.posterior_update.topology_adjusted_posterior > 0.84);
        assert!(snapshot.risk_ui.overlays.contains_key("blast_radius"));
    }

    #[test]
    fn planned_delta_outputs_are_sorted_and_deterministic() {
        let first = build_risk_surface_snapshot(sample_input()).expect("first");
        let second = build_risk_surface_snapshot(sample_input()).expect("second");
        assert_eq!(first.replay_fingerprint, second.replay_fingerprint);
        assert_eq!(
            first.planned_update_deltas[0].change_kind,
            PlannedChangeKind::AddDependency
        );
        assert_eq!(
            first.planned_update_deltas[1].change_kind,
            PlannedChangeKind::RemoveDependency
        );
    }

    #[test]
    fn attribution_percentages_sum_to_one() {
        let snapshot = build_risk_surface_snapshot(sample_input()).expect("snapshot");
        let total: f64 = snapshot
            .posterior_update
            .attribution_percentages
            .values()
            .copied()
            .sum();
        assert!((total - 1.0).abs() < 1.0e-9);
    }

    #[test]
    fn non_finite_metrics_are_rejected_before_snapshot() {
        let mut input = sample_input();
        input.current_metrics.betweenness_centrality = f64::NAN;
        let err = build_risk_surface_snapshot(input).expect_err("NaN must reject");
        assert!(matches!(
            err,
            RiskSurfaceError::InvalidMetric {
                field: "current.betweenness_centrality",
                ..
            }
        ));
    }
}
