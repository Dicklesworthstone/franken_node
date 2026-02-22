//! bd-274s: Bayesian adversary graph with risk posterior tracking.
//!
//! This module models entities (publishers, extensions, maintainers,
//! dependencies) as nodes in a directed graph where edges represent trust
//! relationships. Each node carries a Bayesian risk posterior that is updated
//! deterministically from evidence events.
//!
//! # Determinism Guarantee
//!
//! Given identical evidence sequences, the posterior for every node is
//! bit-identical. The update rule uses a closed-form Beta-Bernoulli conjugate
//! model: `posterior = (alpha) / (alpha + beta)` where alpha starts at 1.0
//! (prior "bad" observations) and beta starts at 9.0 (prior "good"
//! observations). Each piece of positive evidence increments alpha; each piece
//! of negative evidence increments beta. The mean of the Beta distribution
//! is used as the point estimate for the risk posterior.
//!
//! # Event Codes
//!
//! - ADV-001: Node added to adversary graph.
//! - ADV-002: Edge (trust relationship) added to adversary graph.
//! - ADV-003: Evidence ingested and posterior updated.
//! - ADV-004: Risk posterior crossed policy threshold.
//! - ADV-005: Quarantine action triggered.
//!
//! # Invariants
//!
//! - **INV-ADV-DETERMINISTIC**: Identical evidence sequences produce identical
//!   posteriors across all nodes.
//! - **INV-ADV-PRIOR-BOUNDED**: Initial prior risk is always in (0, 1).
//! - **INV-ADV-MONOTONE-EVIDENCE**: Evidence count is monotonically
//!   non-decreasing.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// ADV-001: Node added to adversary graph.
pub const ADV_001_NODE_ADDED: &str = "ADV-001";
/// ADV-002: Trust edge added between nodes.
pub const ADV_002_EDGE_ADDED: &str = "ADV-002";
/// ADV-003: Evidence ingested and posterior updated.
pub const ADV_003_EVIDENCE_INGESTED: &str = "ADV-003";
/// ADV-004: Risk posterior crossed a policy threshold.
pub const ADV_004_THRESHOLD_CROSSED: &str = "ADV-004";
/// ADV-005: Quarantine action triggered by controller.
pub const ADV_005_ACTION_TRIGGERED: &str = "ADV-005";
/// ADV-006: Node removed from adversary graph.
pub const ADV_006_NODE_REMOVED: &str = "ADV-006";
/// ADV-007: Evidence replay completed for determinism check.
pub const ADV_007_REPLAY_COMPLETED: &str = "ADV-007";
/// ADV-008: Signed evidence entry appended to log.
pub const ADV_008_SIGNED_EVIDENCE: &str = "ADV-008";

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

/// INV-ADV-DETERMINISTIC: Identical evidence → identical posteriors.
pub const INV_ADV_DETERMINISTIC: &str = "INV-ADV-DETERMINISTIC";
/// INV-ADV-PRIOR-BOUNDED: Initial prior risk is in (0, 1).
pub const INV_ADV_PRIOR_BOUNDED: &str = "INV-ADV-PRIOR-BOUNDED";
/// INV-ADV-MONOTONE-EVIDENCE: Evidence count is monotonically non-decreasing.
pub const INV_ADV_MONOTONE_EVIDENCE: &str = "INV-ADV-MONOTONE-EVIDENCE";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Node not found in the adversary graph.
pub const ERR_ADV_NODE_NOT_FOUND: &str = "ERR_ADV_NODE_NOT_FOUND";
/// Duplicate node ID insertion attempted.
pub const ERR_ADV_DUPLICATE_NODE: &str = "ERR_ADV_DUPLICATE_NODE";
/// Edge references a non-existent node.
pub const ERR_ADV_DANGLING_EDGE: &str = "ERR_ADV_DANGLING_EDGE";
/// Evidence has an invalid weight (not in [0, 1]).
pub const ERR_ADV_INVALID_EVIDENCE_WEIGHT: &str = "ERR_ADV_INVALID_EVIDENCE_WEIGHT";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Opaque entity identifier (string-based for flexibility).
pub type EntityId = String;

/// The type of entity tracked in the adversary graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Publisher,
    Extension,
    Maintainer,
    Dependency,
}

/// A node in the adversary graph representing an entity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdversaryNode {
    /// Unique entity identifier.
    pub id: EntityId,
    /// Classification of the entity.
    pub entity_type: EntityType,
    /// Current Bayesian risk posterior (mean of Beta distribution).
    pub risk_posterior: f64,
    /// Number of evidence events ingested for this node.
    pub evidence_count: u64,
    /// Epoch timestamp of the last evidence update.
    pub last_updated: u64,
    /// Beta-Bernoulli alpha parameter (adverse evidence count + prior).
    alpha: f64,
    /// Beta-Bernoulli beta parameter (benign evidence count + prior).
    beta: f64,
}

impl AdversaryNode {
    /// Create a new adversary node with a weak prior (alpha=1, beta=9).
    ///
    /// Initial risk posterior = 1/(1+9) = 0.1.
    pub fn new(id: EntityId, entity_type: EntityType, timestamp: u64) -> Self {
        let alpha = 1.0_f64;
        let beta = 9.0_f64;
        let risk_posterior = alpha / (alpha + beta);
        Self {
            id,
            entity_type,
            risk_posterior,
            evidence_count: 0,
            last_updated: timestamp,
            alpha,
            beta,
        }
    }

    /// Ingest one piece of evidence. `adverse_weight` in [0.0, 1.0] where
    /// 1.0 means fully adverse and 0.0 means fully benign.
    ///
    /// Returns the old and new posteriors for threshold checking.
    pub fn ingest_evidence(&mut self, adverse_weight: f64, timestamp: u64) -> (f64, f64) {
        let clamped = adverse_weight.clamp(0.0, 1.0);
        let old_posterior = self.risk_posterior;
        self.alpha += clamped;
        self.beta += 1.0 - clamped;
        self.risk_posterior = self.alpha / (self.alpha + self.beta);
        self.evidence_count += 1;
        self.last_updated = timestamp;
        (old_posterior, self.risk_posterior)
    }
}

/// A directed trust edge between two entities in the adversary graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustEdge {
    /// Source entity (the truster).
    pub from: EntityId,
    /// Target entity (the trustee).
    pub to: EntityId,
    /// Label describing the trust relationship.
    pub relationship: String,
    /// Timestamp when the edge was created.
    pub created_at: u64,
}

/// An evidence event that can be replayed deterministically.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidenceEvent {
    /// Trace identifier for correlation.
    pub trace_id: String,
    /// Target entity for this evidence.
    pub entity_id: EntityId,
    /// Adverse weight in [0.0, 1.0].
    pub adverse_weight: f64,
    /// Description of the evidence source.
    pub source: String,
    /// Epoch timestamp of the evidence event.
    pub timestamp: u64,
}

/// A signed evidence entry wrapping an evidence event with an HMAC signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedEvidenceEntry {
    /// The underlying evidence event.
    pub event: EvidenceEvent,
    /// Event code associated with this entry.
    pub event_code: String,
    /// HMAC-SHA256 hex signature over the canonical JSON of the event.
    pub signature: String,
    /// Sequence number within the evidence log (monotonic).
    pub sequence: u64,
}

/// Policy thresholds that map risk posteriors to quarantine actions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyThreshold {
    /// Risk posterior at which throttling begins.
    pub throttle: f64,
    /// Risk posterior at which isolation begins.
    pub isolate: f64,
    /// Risk posterior at which revocation begins.
    pub revoke: f64,
    /// Risk posterior at which full quarantine begins.
    pub quarantine: f64,
}

impl Default for PolicyThreshold {
    fn default() -> Self {
        Self {
            throttle: 0.3,
            isolate: 0.5,
            revoke: 0.7,
            quarantine: 0.9,
        }
    }
}

/// Control action determined by the quarantine controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineAction {
    None,
    Throttle,
    Isolate,
    Revoke,
    Quarantine,
}

impl std::fmt::Display for QuarantineAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Throttle => write!(f, "throttle"),
            Self::Isolate => write!(f, "isolate"),
            Self::Revoke => write!(f, "revoke"),
            Self::Quarantine => write!(f, "quarantine"),
        }
    }
}

/// Determine the quarantine action for a given risk posterior.
pub fn action_for_risk(posterior: f64, thresholds: &PolicyThreshold) -> QuarantineAction {
    if posterior >= thresholds.quarantine {
        QuarantineAction::Quarantine
    } else if posterior >= thresholds.revoke {
        QuarantineAction::Revoke
    } else if posterior >= thresholds.isolate {
        QuarantineAction::Isolate
    } else if posterior >= thresholds.throttle {
        QuarantineAction::Throttle
    } else {
        QuarantineAction::None
    }
}

/// Structured log entry emitted by the adversary graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdversaryLogEntry {
    pub trace_id: String,
    pub event_code: String,
    pub entity_id: String,
    pub detail: String,
    pub risk_posterior: Option<f64>,
    pub action: Option<QuarantineAction>,
    pub timestamp: u64,
}

/// The Bayesian adversary graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdversaryGraph {
    nodes: HashMap<EntityId, AdversaryNode>,
    edges: Vec<TrustEdge>,
    thresholds: PolicyThreshold,
    log: Vec<AdversaryLogEntry>,
}

impl AdversaryGraph {
    /// Create a new empty adversary graph with the given thresholds.
    pub fn new(thresholds: PolicyThreshold) -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            thresholds,
            log: Vec::new(),
        }
    }

    /// Create an adversary graph with default policy thresholds.
    pub fn with_default_thresholds() -> Self {
        Self::new(PolicyThreshold::default())
    }

    /// Return a reference to the policy thresholds.
    pub fn thresholds(&self) -> &PolicyThreshold {
        &self.thresholds
    }

    /// Return the number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Return a reference to a node by ID, if present.
    pub fn get_node(&self, id: &str) -> Option<&AdversaryNode> {
        self.nodes.get(id)
    }

    /// Return the structured log entries.
    pub fn log_entries(&self) -> &[AdversaryLogEntry] {
        &self.log
    }

    /// Add a node to the graph. Returns an error string if a node with the
    /// same ID already exists.
    pub fn add_node(
        &mut self,
        id: EntityId,
        entity_type: EntityType,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        if self.nodes.contains_key(&id) {
            return Err(format!("{ERR_ADV_DUPLICATE_NODE}: {id}"));
        }
        let node = AdversaryNode::new(id.clone(), entity_type, timestamp);
        self.nodes.insert(id.clone(), node);
        self.log.push(AdversaryLogEntry {
            trace_id: trace_id.to_string(),
            event_code: ADV_001_NODE_ADDED.to_string(),
            entity_id: id,
            detail: format!("Node added, type={entity_type:?}"),
            risk_posterior: Some(0.1),
            action: None,
            timestamp,
        });
        Ok(())
    }

    /// Add a directed trust edge. Returns an error string if either endpoint
    /// does not exist.
    pub fn add_edge(
        &mut self,
        from: EntityId,
        to: EntityId,
        relationship: String,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        if !self.nodes.contains_key(&from) {
            return Err(format!("{ERR_ADV_DANGLING_EDGE}: source node {from} not found"));
        }
        if !self.nodes.contains_key(&to) {
            return Err(format!("{ERR_ADV_DANGLING_EDGE}: target node {to} not found"));
        }
        self.edges.push(TrustEdge {
            from: from.clone(),
            to: to.clone(),
            relationship: relationship.clone(),
            created_at: timestamp,
        });
        self.log.push(AdversaryLogEntry {
            trace_id: trace_id.to_string(),
            event_code: ADV_002_EDGE_ADDED.to_string(),
            entity_id: format!("{from}->{to}"),
            detail: format!("Edge added: {relationship}"),
            risk_posterior: None,
            action: None,
            timestamp,
        });
        Ok(())
    }

    /// Ingest evidence for a specific entity. Returns the quarantine action
    /// triggered (if any) and the new posterior, or an error string if the
    /// entity is not found or the weight is invalid.
    pub fn ingest_evidence(
        &mut self,
        event: &EvidenceEvent,
    ) -> Result<(QuarantineAction, f64), String> {
        if !(0.0..=1.0).contains(&event.adverse_weight) {
            return Err(format!(
                "{ERR_ADV_INVALID_EVIDENCE_WEIGHT}: {}",
                event.adverse_weight
            ));
        }
        let node = self
            .nodes
            .get_mut(&event.entity_id)
            .ok_or_else(|| format!("{ERR_ADV_NODE_NOT_FOUND}: {}", event.entity_id))?;
        let (old_posterior, new_posterior) =
            node.ingest_evidence(event.adverse_weight, event.timestamp);

        self.log.push(AdversaryLogEntry {
            trace_id: event.trace_id.clone(),
            event_code: ADV_003_EVIDENCE_INGESTED.to_string(),
            entity_id: event.entity_id.clone(),
            detail: format!(
                "Evidence ingested, weight={:.4}, posterior={:.6}->={:.6}",
                event.adverse_weight, old_posterior, new_posterior
            ),
            risk_posterior: Some(new_posterior),
            action: None,
            timestamp: event.timestamp,
        });

        let old_action = action_for_risk(old_posterior, &self.thresholds);
        let new_action = action_for_risk(new_posterior, &self.thresholds);

        if new_action != old_action {
            self.log.push(AdversaryLogEntry {
                trace_id: event.trace_id.clone(),
                event_code: ADV_004_THRESHOLD_CROSSED.to_string(),
                entity_id: event.entity_id.clone(),
                detail: format!(
                    "Threshold crossed: {old_action} -> {new_action} at posterior={new_posterior:.6}"
                ),
                risk_posterior: Some(new_posterior),
                action: Some(new_action),
                timestamp: event.timestamp,
            });
        }

        Ok((new_action, new_posterior))
    }

    /// Replay a sequence of evidence events and return the final state of all
    /// nodes. This is the core determinism primitive: given the same sequence
    /// the result is bit-identical.
    pub fn replay_evidence(
        &mut self,
        events: &[EvidenceEvent],
        trace_id: &str,
    ) -> Result<HashMap<EntityId, f64>, String> {
        for event in events {
            self.ingest_evidence(event)?;
        }
        let snapshot: HashMap<EntityId, f64> = self
            .nodes
            .iter()
            .map(|(id, node)| (id.clone(), node.risk_posterior))
            .collect();
        self.log.push(AdversaryLogEntry {
            trace_id: trace_id.to_string(),
            event_code: ADV_007_REPLAY_COMPLETED.to_string(),
            entity_id: "graph".to_string(),
            detail: format!("Replay completed, {} events processed", events.len()),
            risk_posterior: None,
            action: None,
            timestamp: events.last().map_or(0, |e| e.timestamp),
        });
        Ok(snapshot)
    }

    /// Return a JSON-serializable state snapshot of the adversary graph.
    pub fn state_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "node_count": self.nodes.len(),
            "edge_count": self.edges.len(),
            "thresholds": self.thresholds,
            "nodes": self.nodes.values().collect::<Vec<_>>(),
            "edges": &self.edges,
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_graph() -> AdversaryGraph {
        AdversaryGraph::with_default_thresholds()
    }

    #[test]
    fn initial_prior_is_bounded() {
        let node = AdversaryNode::new("test".into(), EntityType::Publisher, 0);
        assert!(node.risk_posterior > 0.0);
        assert!(node.risk_posterior < 1.0);
        assert!((node.risk_posterior - 0.1).abs() < 1e-9);
    }

    #[test]
    fn evidence_ingestion_increases_adverse_posterior() {
        let mut node = AdversaryNode::new("test".into(), EntityType::Extension, 0);
        let initial = node.risk_posterior;
        node.ingest_evidence(1.0, 1);
        assert!(node.risk_posterior > initial);
        assert!(node.risk_posterior <= 1.0);
    }

    #[test]
    fn evidence_ingestion_decreases_benign_posterior() {
        let mut node = AdversaryNode::new("test".into(), EntityType::Maintainer, 0);
        let initial = node.risk_posterior;
        node.ingest_evidence(0.0, 1);
        assert!(node.risk_posterior < initial);
        assert!(node.risk_posterior >= 0.0);
    }

    #[test]
    fn determinism_identical_evidence_identical_posteriors() {
        let events = vec![
            EvidenceEvent {
                trace_id: "t1".into(),
                entity_id: "pub-a".into(),
                adverse_weight: 0.8,
                source: "scan".into(),
                timestamp: 1,
            },
            EvidenceEvent {
                trace_id: "t2".into(),
                entity_id: "pub-a".into(),
                adverse_weight: 0.2,
                source: "audit".into(),
                timestamp: 2,
            },
            EvidenceEvent {
                trace_id: "t3".into(),
                entity_id: "pub-a".into(),
                adverse_weight: 0.6,
                source: "report".into(),
                timestamp: 3,
            },
        ];

        let mut g1 = make_graph();
        g1.add_node("pub-a".into(), EntityType::Publisher, 0, "init")
            .unwrap();
        let snap1 = g1.replay_evidence(&events, "replay-1").unwrap();

        let mut g2 = make_graph();
        g2.add_node("pub-a".into(), EntityType::Publisher, 0, "init")
            .unwrap();
        let snap2 = g2.replay_evidence(&events, "replay-2").unwrap();

        assert_eq!(snap1["pub-a"].to_bits(), snap2["pub-a"].to_bits());
    }

    #[test]
    fn duplicate_node_rejected() {
        let mut g = make_graph();
        g.add_node("n1".into(), EntityType::Publisher, 0, "t").unwrap();
        let err = g.add_node("n1".into(), EntityType::Publisher, 1, "t").unwrap_err();
        assert!(err.contains(ERR_ADV_DUPLICATE_NODE));
    }

    #[test]
    fn dangling_edge_rejected() {
        let mut g = make_graph();
        g.add_node("n1".into(), EntityType::Publisher, 0, "t").unwrap();
        let err = g
            .add_edge("n1".into(), "n2".into(), "trusts".into(), 1, "t")
            .unwrap_err();
        assert!(err.contains(ERR_ADV_DANGLING_EDGE));
    }

    #[test]
    fn invalid_evidence_weight_rejected() {
        let mut g = make_graph();
        g.add_node("n1".into(), EntityType::Extension, 0, "t").unwrap();
        // NaN is not in [0, 1]
        let ev = EvidenceEvent {
            trace_id: "t".into(),
            entity_id: "n1".into(),
            adverse_weight: f64::NAN,
            source: "test".into(),
            timestamp: 1,
        };
        let err = g.ingest_evidence(&ev).unwrap_err();
        assert!(err.contains(ERR_ADV_INVALID_EVIDENCE_WEIGHT));
    }

    #[test]
    fn evidence_count_is_monotonic() {
        let mut g = make_graph();
        g.add_node("n1".into(), EntityType::Dependency, 0, "t").unwrap();
        assert_eq!(g.get_node("n1").unwrap().evidence_count, 0);
        let ev1 = EvidenceEvent {
            trace_id: "t".into(),
            entity_id: "n1".into(),
            adverse_weight: 0.5,
            source: "s".into(),
            timestamp: 1,
        };
        g.ingest_evidence(&ev1).unwrap();
        assert_eq!(g.get_node("n1").unwrap().evidence_count, 1);
        g.ingest_evidence(&ev1).unwrap();
        assert_eq!(g.get_node("n1").unwrap().evidence_count, 2);
    }

    #[test]
    fn action_for_risk_thresholds_correct() {
        let t = PolicyThreshold::default();
        assert_eq!(action_for_risk(0.0, &t), QuarantineAction::None);
        assert_eq!(action_for_risk(0.29, &t), QuarantineAction::None);
        assert_eq!(action_for_risk(0.3, &t), QuarantineAction::Throttle);
        assert_eq!(action_for_risk(0.49, &t), QuarantineAction::Throttle);
        assert_eq!(action_for_risk(0.5, &t), QuarantineAction::Isolate);
        assert_eq!(action_for_risk(0.69, &t), QuarantineAction::Isolate);
        assert_eq!(action_for_risk(0.7, &t), QuarantineAction::Revoke);
        assert_eq!(action_for_risk(0.89, &t), QuarantineAction::Revoke);
        assert_eq!(action_for_risk(0.9, &t), QuarantineAction::Quarantine);
        assert_eq!(action_for_risk(1.0, &t), QuarantineAction::Quarantine);
    }

    #[test]
    fn threshold_crossing_emits_log_entry() {
        let mut g = make_graph();
        g.add_node("n1".into(), EntityType::Publisher, 0, "t").unwrap();
        // Pump posterior above throttle threshold (0.3) with many adverse events
        for i in 1..=20 {
            let ev = EvidenceEvent {
                trace_id: format!("t{i}"),
                entity_id: "n1".into(),
                adverse_weight: 1.0,
                source: "attack".into(),
                timestamp: i,
            };
            g.ingest_evidence(&ev).unwrap();
        }
        let threshold_events: Vec<_> = g
            .log_entries()
            .iter()
            .filter(|e| e.event_code == ADV_004_THRESHOLD_CROSSED)
            .collect();
        assert!(!threshold_events.is_empty(), "expected threshold crossing events");
    }

    #[test]
    fn state_snapshot_is_serializable() {
        let mut g = make_graph();
        g.add_node("n1".into(), EntityType::Publisher, 0, "t").unwrap();
        g.add_node("n2".into(), EntityType::Extension, 0, "t").unwrap();
        g.add_edge("n1".into(), "n2".into(), "publishes".into(), 0, "t")
            .unwrap();
        let snap = g.state_snapshot();
        let json_str = serde_json::to_string_pretty(&snap).unwrap();
        assert!(json_str.contains("node_count"));
        assert!(json_str.contains("edge_count"));
    }

    #[test]
    fn edge_addition_logged() {
        let mut g = make_graph();
        g.add_node("a".into(), EntityType::Publisher, 0, "t").unwrap();
        g.add_node("b".into(), EntityType::Extension, 0, "t").unwrap();
        g.add_edge("a".into(), "b".into(), "trusts".into(), 1, "t").unwrap();
        let edge_logs: Vec<_> = g
            .log_entries()
            .iter()
            .filter(|e| e.event_code == ADV_002_EDGE_ADDED)
            .collect();
        assert_eq!(edge_logs.len(), 1);
    }

    #[test]
    fn replay_evidence_populates_snapshot() {
        let mut g = make_graph();
        g.add_node("x".into(), EntityType::Maintainer, 0, "t").unwrap();
        let events = vec![
            EvidenceEvent {
                trace_id: "t".into(),
                entity_id: "x".into(),
                adverse_weight: 0.5,
                source: "s".into(),
                timestamp: 1,
            },
        ];
        let snap = g.replay_evidence(&events, "replay").unwrap();
        assert!(snap.contains_key("x"));
        let replay_logs: Vec<_> = g
            .log_entries()
            .iter()
            .filter(|e| e.event_code == ADV_007_REPLAY_COMPLETED)
            .collect();
        assert_eq!(replay_logs.len(), 1);
    }

    #[test]
    fn node_not_found_evidence_error() {
        let mut g = make_graph();
        let ev = EvidenceEvent {
            trace_id: "t".into(),
            entity_id: "nonexistent".into(),
            adverse_weight: 0.5,
            source: "s".into(),
            timestamp: 1,
        };
        let err = g.ingest_evidence(&ev).unwrap_err();
        assert!(err.contains(ERR_ADV_NODE_NOT_FOUND));
    }
}
