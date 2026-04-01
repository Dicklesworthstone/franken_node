//! bd-274s: Deterministic Bayesian adversary graph.
//!
//! This module tracks adversary risk posterior values from evidence observations.
//! The update order and reduction are deterministic so identical evidence yields
//! identical posterior states.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    if !(0.0..=1.0).contains(&likelihood) {
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
    let successes = ((likelihood * evidence_weight as f64).round() as u64).min(evidence_weight);
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
    let payload =
        format!("{previous_hash}|{evidence_ref}|{trace_id}|{likelihood:.12}|{evidence_weight}");
    let digest = Sha256::digest(payload.as_bytes());
    format!("sha256:{digest:x}")
}

fn project_posterior(principal_id: &str, node: &AdversaryNode) -> AdversaryPosterior {
    let posterior = (node.alpha as f64) / ((node.alpha + node.beta) as f64);
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
}
