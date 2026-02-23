//! bd-1961: Reputation graph APIs (Section 15).
//!
//! Implements reputation graph API pillar for ecosystem trust and incident
//! response. Provides reputation nodes, edges, scoring, and query APIs.
//!
//! # Capabilities
//!
//! - Reputation node management (5 node types)
//! - Directed edge creation with weight/evidence
//! - Composite reputation scoring with decay
//! - Threshold-gated trust decisions
//! - Graph query: neighbors, paths, subgraphs
//! - Metric versioning and audit trail
//!
//! # Invariants
//!
//! - **INV-RGA-TYPED**: Every node carries a type classification.
//! - **INV-RGA-WEIGHTED**: Every edge carries a signed weight.
//! - **INV-RGA-DETERMINISTIC**: Same graph + query = same score output.
//! - **INV-RGA-GATED**: Trust decisions reference minimum score thresholds.
//! - **INV-RGA-VERSIONED**: Schema version embedded in every export.
//! - **INV-RGA-AUDITABLE**: Every mutation produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub mod event_codes {
    pub const RGA_NODE_ADDED: &str = "RGA-001";
    pub const RGA_EDGE_ADDED: &str = "RGA-002";
    pub const RGA_SCORE_COMPUTED: &str = "RGA-003";
    pub const RGA_THRESHOLD_CHECKED: &str = "RGA-004";
    pub const RGA_QUERY_EXECUTED: &str = "RGA-005";
    pub const RGA_GRAPH_EXPORTED: &str = "RGA-006";
    pub const RGA_DECAY_APPLIED: &str = "RGA-007";
    pub const RGA_NODE_UPDATED: &str = "RGA-008";
    pub const RGA_VERSION_EMBEDDED: &str = "RGA-009";
    pub const RGA_SUBGRAPH_EXTRACTED: &str = "RGA-010";
    pub const RGA_ERR_DUPLICATE_NODE: &str = "RGA-ERR-001";
    pub const RGA_ERR_MISSING_NODE: &str = "RGA-ERR-002";
}

pub mod invariants {
    pub const INV_RGA_TYPED: &str = "INV-RGA-TYPED";
    pub const INV_RGA_WEIGHTED: &str = "INV-RGA-WEIGHTED";
    pub const INV_RGA_DETERMINISTIC: &str = "INV-RGA-DETERMINISTIC";
    pub const INV_RGA_GATED: &str = "INV-RGA-GATED";
    pub const INV_RGA_VERSIONED: &str = "INV-RGA-VERSIONED";
    pub const INV_RGA_AUDITABLE: &str = "INV-RGA-AUDITABLE";
}

pub const SCHEMA_VERSION: &str = "rga-v1.0";
pub const MIN_TRUST_SCORE: f64 = 0.6;
pub const DECAY_FACTOR: f64 = 0.95;

/// Node type in the reputation graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    Operator,
    Extension,
    Verifier,
    DataSource,
    Infrastructure,
}

impl NodeType {
    pub fn all() -> &'static [NodeType] {
        &[
            Self::Operator,
            Self::Extension,
            Self::Verifier,
            Self::DataSource,
            Self::Infrastructure,
        ]
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Extension => "extension",
            Self::Verifier => "verifier",
            Self::DataSource => "data_source",
            Self::Infrastructure => "infrastructure",
        }
    }
}

/// A node in the reputation graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationNode {
    pub node_id: String,
    pub node_type: NodeType,
    pub display_name: String,
    pub base_score: f64,
    pub created_at: String,
}

/// A directed edge between two nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationEdge {
    pub edge_id: String,
    pub source: String,
    pub target: String,
    pub weight: f64,
    pub evidence: String,
    pub created_at: String,
}

/// Composite reputation score result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationScore {
    pub node_id: String,
    pub composite_score: f64,
    pub meets_threshold: bool,
    pub edge_count: usize,
    pub content_hash: String,
}

/// Graph export snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub snapshot_id: String,
    pub timestamp: String,
    pub schema_version: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub content_hash: String,
}

/// Audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RgaAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

/// Reputation graph API engine.
#[derive(Debug, Clone)]
pub struct ReputationGraphApis {
    schema_version: String,
    nodes: BTreeMap<String, ReputationNode>,
    edges: Vec<ReputationEdge>,
    audit_log: Vec<RgaAuditRecord>,
}

impl Default for ReputationGraphApis {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            audit_log: Vec::new(),
        }
    }
}

impl ReputationGraphApis {
    pub fn add_node(&mut self, node: ReputationNode, trace_id: &str) -> Result<String, String> {
        if self.nodes.contains_key(&node.node_id) {
            self.log(
                event_codes::RGA_ERR_DUPLICATE_NODE,
                trace_id,
                serde_json::json!({"node_id": &node.node_id}),
            );
            return Err(format!("duplicate node: {}", node.node_id));
        }
        let nid = node.node_id.clone();
        self.log(
            event_codes::RGA_NODE_ADDED,
            trace_id,
            serde_json::json!({"node_id": &nid, "type": node.node_type.label()}),
        );
        self.nodes.insert(nid.clone(), node);
        Ok(nid)
    }

    pub fn update_node_score(
        &mut self,
        node_id: &str,
        new_score: f64,
        trace_id: &str,
    ) -> Result<(), String> {
        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| format!("node not found: {node_id}"))?;
        node.base_score = new_score;
        self.log(
            event_codes::RGA_NODE_UPDATED,
            trace_id,
            serde_json::json!({"node_id": node_id, "score": new_score}),
        );
        Ok(())
    }

    pub fn add_edge(&mut self, mut edge: ReputationEdge, trace_id: &str) -> Result<String, String> {
        if !self.nodes.contains_key(&edge.source) {
            self.log(
                event_codes::RGA_ERR_MISSING_NODE,
                trace_id,
                serde_json::json!({"node_id": &edge.source}),
            );
            return Err(format!("source node not found: {}", edge.source));
        }
        if !self.nodes.contains_key(&edge.target) {
            self.log(
                event_codes::RGA_ERR_MISSING_NODE,
                trace_id,
                serde_json::json!({"node_id": &edge.target}),
            );
            return Err(format!("target node not found: {}", edge.target));
        }
        edge.created_at = Utc::now().to_rfc3339();
        let eid = edge.edge_id.clone();
        self.log(
            event_codes::RGA_EDGE_ADDED,
            trace_id,
            serde_json::json!({"edge_id": &eid, "weight": edge.weight}),
        );
        self.edges.push(edge);
        Ok(eid)
    }

    pub fn compute_score(
        &mut self,
        node_id: &str,
        trace_id: &str,
    ) -> Result<ReputationScore, String> {
        let base = self
            .nodes
            .get(node_id)
            .ok_or_else(|| format!("node not found: {node_id}"))?
            .base_score;

        let incoming: Vec<&ReputationEdge> =
            self.edges.iter().filter(|e| e.target == node_id).collect();
        let edge_count = incoming.len();

        let weighted_sum: f64 = incoming.iter().map(|e| e.weight).sum();
        let composite = if edge_count > 0 {
            (base + weighted_sum / edge_count as f64) / 2.0
        } else {
            base
        };

        let meets = composite >= MIN_TRUST_SCORE;
        let hash_input = format!(
            "{node_id}:{composite}:{edge_count}:{}",
            &self.schema_version
        );
        let content_hash = hex::encode(Sha256::digest(
            [b"reputation_graph_hash_v1:" as &[u8], hash_input.as_bytes()].concat(),
        ));

        self.log(
            event_codes::RGA_SCORE_COMPUTED,
            trace_id,
            serde_json::json!({"node_id": node_id, "score": composite}),
        );
        self.log(
            event_codes::RGA_THRESHOLD_CHECKED,
            trace_id,
            serde_json::json!({"meets": meets}),
        );

        Ok(ReputationScore {
            node_id: node_id.to_string(),
            composite_score: composite,
            meets_threshold: meets,
            edge_count,
            content_hash,
        })
    }

    pub fn neighbors(&mut self, node_id: &str, trace_id: &str) -> Vec<String> {
        let mut out = BTreeSet::new();
        for e in &self.edges {
            if e.source == node_id {
                out.insert(e.target.clone());
            }
            if e.target == node_id {
                out.insert(e.source.clone());
            }
        }
        self.log(
            event_codes::RGA_QUERY_EXECUTED,
            trace_id,
            serde_json::json!({"query": "neighbors", "node": node_id}),
        );
        out.into_iter().collect()
    }

    pub fn apply_decay(&mut self, trace_id: &str) {
        for edge in &mut self.edges {
            edge.weight *= DECAY_FACTOR;
        }
        self.log(
            event_codes::RGA_DECAY_APPLIED,
            trace_id,
            serde_json::json!({"factor": DECAY_FACTOR}),
        );
    }

    pub fn subgraph(
        &mut self,
        node_ids: &[&str],
        trace_id: &str,
    ) -> (Vec<ReputationNode>, Vec<ReputationEdge>) {
        let set: BTreeSet<&str> = node_ids.iter().copied().collect();
        let nodes: Vec<ReputationNode> = self
            .nodes
            .values()
            .filter(|n| set.contains(n.node_id.as_str()))
            .cloned()
            .collect();
        let edges: Vec<ReputationEdge> = self
            .edges
            .iter()
            .filter(|e| set.contains(e.source.as_str()) && set.contains(e.target.as_str()))
            .cloned()
            .collect();
        self.log(
            event_codes::RGA_SUBGRAPH_EXTRACTED,
            trace_id,
            serde_json::json!({"nodes": nodes.len(), "edges": edges.len()}),
        );
        (nodes, edges)
    }

    pub fn export_snapshot(&mut self, trace_id: &str) -> GraphSnapshot {
        let hash_input = format!(
            "{}:{}:{}:{}",
            self.nodes.len(),
            self.edges.len(),
            self.schema_version,
            self.audit_log.len()
        );
        let content_hash = hex::encode(Sha256::digest(
            [b"reputation_graph_hash_v1:" as &[u8], hash_input.as_bytes()].concat(),
        ));
        self.log(
            event_codes::RGA_GRAPH_EXPORTED,
            trace_id,
            serde_json::json!({"nodes": self.nodes.len()}),
        );
        self.log(
            event_codes::RGA_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({"version": &self.schema_version}),
        );
        GraphSnapshot {
            snapshot_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            schema_version: self.schema_version.clone(),
            node_count: self.nodes.len(),
            edge_count: self.edges.len(),
            content_hash,
        }
    }

    pub fn nodes(&self) -> &BTreeMap<String, ReputationNode> {
        &self.nodes
    }
    pub fn edges(&self) -> &[ReputationEdge] {
        &self.edges
    }
    pub fn audit_log(&self) -> &[RgaAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for r in &self.audit_log {
            lines.push(serde_json::to_string(r)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        self.audit_log.push(RgaAuditRecord {
            record_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_node(id: &str, nt: NodeType) -> ReputationNode {
        ReputationNode {
            node_id: id.to_string(),
            node_type: nt,
            display_name: id.to_string(),
            base_score: 0.8,
            created_at: Utc::now().to_rfc3339(),
        }
    }

    fn sample_edge(id: &str, src: &str, tgt: &str, w: f64) -> ReputationEdge {
        ReputationEdge {
            edge_id: id.to_string(),
            source: src.to_string(),
            target: tgt.to_string(),
            weight: w,
            evidence: "test-evidence".to_string(),
            created_at: String::new(),
        }
    }

    #[test]
    fn five_node_types() {
        assert_eq!(NodeType::all().len(), 5);
    }
    #[test]
    fn node_labels_nonempty() {
        for n in NodeType::all() {
            assert!(!n.label().is_empty());
        }
    }

    #[test]
    fn add_node_ok() {
        let mut g = ReputationGraphApis::default();
        assert!(
            g.add_node(sample_node("n1", NodeType::Operator), &trace())
                .is_ok()
        );
        assert_eq!(g.nodes().len(), 1);
    }

    #[test]
    fn add_duplicate_node_fails() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        assert!(
            g.add_node(sample_node("n1", NodeType::Verifier), &trace())
                .is_err()
        );
    }

    #[test]
    fn add_edge_ok() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        assert!(
            g.add_edge(sample_edge("e1", "n1", "n2", 0.9), &trace())
                .is_ok()
        );
    }

    #[test]
    fn add_edge_missing_source() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        assert!(
            g.add_edge(sample_edge("e1", "n1", "n2", 0.5), &trace())
                .is_err()
        );
    }

    #[test]
    fn add_edge_missing_target() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        assert!(
            g.add_edge(sample_edge("e1", "n1", "n2", 0.5), &trace())
                .is_err()
        );
    }

    #[test]
    fn compute_score_no_edges() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        let s = g.compute_score("n1", &trace()).unwrap();
        assert!((s.composite_score - 0.8).abs() < 0.01);
        assert!(s.meets_threshold);
    }

    #[test]
    fn compute_score_with_edges() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        g.add_edge(sample_edge("e1", "n2", "n1", 1.0), &trace())
            .unwrap();
        let s = g.compute_score("n1", &trace()).unwrap();
        assert!(s.edge_count == 1);
        assert!(s.composite_score > 0.0);
    }

    #[test]
    fn compute_score_missing_node() {
        let mut g = ReputationGraphApis::default();
        assert!(g.compute_score("missing", &trace()).is_err());
    }

    #[test]
    fn score_below_threshold() {
        let mut g = ReputationGraphApis::default();
        let mut n = sample_node("n1", NodeType::Operator);
        n.base_score = 0.3;
        g.add_node(n, &trace()).unwrap();
        let s = g.compute_score("n1", &trace()).unwrap();
        assert!(!s.meets_threshold);
    }

    #[test]
    fn neighbors_query() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        g.add_edge(sample_edge("e1", "n1", "n2", 0.5), &trace())
            .unwrap();
        let nb = g.neighbors("n1", &trace());
        assert!(nb.contains(&"n2".to_string()));
    }

    #[test]
    fn apply_decay() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        g.add_edge(sample_edge("e1", "n1", "n2", 1.0), &trace())
            .unwrap();
        g.apply_decay(&trace());
        assert!((g.edges()[0].weight - DECAY_FACTOR).abs() < 0.001);
    }

    #[test]
    fn subgraph_extraction() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        g.add_node(sample_node("n3", NodeType::Verifier), &trace())
            .unwrap();
        g.add_edge(sample_edge("e1", "n1", "n2", 0.5), &trace())
            .unwrap();
        let (nodes, edges) = g.subgraph(&["n1", "n2"], &trace());
        assert_eq!(nodes.len(), 2);
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn export_snapshot() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        let snap = g.export_snapshot(&trace());
        assert_eq!(snap.node_count, 1);
        assert_eq!(snap.schema_version, SCHEMA_VERSION);
        assert_eq!(snap.content_hash.len(), 64);
    }

    #[test]
    fn update_node_score() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.update_node_score("n1", 0.5, &trace()).unwrap();
        assert!((g.nodes()["n1"].base_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn update_missing_node_fails() {
        let mut g = ReputationGraphApis::default();
        assert!(g.update_node_score("missing", 0.5, &trace()).is_err());
    }

    #[test]
    fn score_hash_deterministic() {
        let mut g1 = ReputationGraphApis::default();
        let mut g2 = ReputationGraphApis::default();
        g1.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g2.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        assert_eq!(
            g1.compute_score("n1", &trace()).unwrap().content_hash,
            g2.compute_score("n1", &trace()).unwrap().content_hash
        );
    }

    #[test]
    fn audit_populated() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        assert!(!g.audit_log().is_empty());
    }

    #[test]
    fn audit_has_codes() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        let codes: Vec<&str> = g
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::RGA_NODE_ADDED));
    }

    #[test]
    fn export_jsonl() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        let jsonl = g.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn default_version() {
        let g = ReputationGraphApis::default();
        assert_eq!(g.schema_version, SCHEMA_VERSION);
    }
}
