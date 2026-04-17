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
    pub const RGA_ERR_INVALID_NODE: &str = "RGA-ERR-003";
    pub const RGA_ERR_INVALID_EDGE: &str = "RGA-ERR-004";
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
use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_EDGES: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    let overflow = items.len().saturating_add(1).saturating_sub(cap);
    if overflow > 0 {
        items.drain(0..overflow);
    }
    items.push(item);
}

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
        if node.node_id.trim().is_empty() {
            self.log(
                event_codes::RGA_ERR_INVALID_NODE,
                trace_id,
                serde_json::json!({"reason": "empty node_id"}),
            );
            return Err("node id must not be empty".to_string());
        }
        if node.node_id.trim() != node.node_id {
            self.log(
                event_codes::RGA_ERR_INVALID_NODE,
                trace_id,
                serde_json::json!({"node_id": &node.node_id, "reason": "malformed node_id"}),
            );
            return Err("node id must not include surrounding whitespace".to_string());
        }
        if node.display_name.trim().is_empty() {
            self.log(
                event_codes::RGA_ERR_INVALID_NODE,
                trace_id,
                serde_json::json!({"node_id": &node.node_id, "reason": "empty display_name"}),
            );
            return Err("display name must not be empty".to_string());
        }
        if !node.base_score.is_finite() {
            self.log(
                event_codes::RGA_ERR_INVALID_NODE,
                trace_id,
                serde_json::json!({"node_id": &node.node_id, "reason": "non-finite base_score"}),
            );
            return Err("base score must be finite".to_string());
        }
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
        if !new_score.is_finite() {
            self.log(
                event_codes::RGA_ERR_INVALID_NODE,
                trace_id,
                serde_json::json!({"node_id": node_id, "reason": "non-finite base_score"}),
            );
            return Err("base score must be finite".to_string());
        }
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
        if edge.edge_id.trim().is_empty() {
            self.log(
                event_codes::RGA_ERR_INVALID_EDGE,
                trace_id,
                serde_json::json!({"reason": "empty edge_id"}),
            );
            return Err("edge id must not be empty".to_string());
        }
        if edge.edge_id.trim() != edge.edge_id {
            self.log(
                event_codes::RGA_ERR_INVALID_EDGE,
                trace_id,
                serde_json::json!({"edge_id": &edge.edge_id, "reason": "malformed edge_id"}),
            );
            return Err("edge id must not include surrounding whitespace".to_string());
        }
        if self
            .edges
            .iter()
            .any(|existing| existing.edge_id == edge.edge_id)
        {
            self.log(
                event_codes::RGA_ERR_INVALID_EDGE,
                trace_id,
                serde_json::json!({"edge_id": &edge.edge_id, "reason": "duplicate edge_id"}),
            );
            return Err(format!("duplicate edge: {}", edge.edge_id));
        }
        if edge.source == edge.target {
            self.log(
                event_codes::RGA_ERR_INVALID_EDGE,
                trace_id,
                serde_json::json!({"edge_id": &edge.edge_id, "reason": "self loop"}),
            );
            return Err("edge source and target must be different".to_string());
        }
        if !edge.weight.is_finite() {
            self.log(
                event_codes::RGA_ERR_INVALID_EDGE,
                trace_id,
                serde_json::json!({"edge_id": &edge.edge_id, "reason": "non-finite weight"}),
            );
            return Err("edge weight must be finite".to_string());
        }
        if edge.evidence.trim().is_empty() {
            self.log(
                event_codes::RGA_ERR_INVALID_EDGE,
                trace_id,
                serde_json::json!({"edge_id": &edge.edge_id, "reason": "empty evidence"}),
            );
            return Err("edge evidence must not be empty".to_string());
        }
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
        push_bounded(&mut self.edges, edge, MAX_EDGES);
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

        let weighted_sum: f64 = incoming
            .iter()
            .map(|e| if e.weight.is_finite() { e.weight } else { 0.0 })
            .sum();
        let safe_base = if base.is_finite() { base } else { 0.0 };
        let composite = if edge_count > 0 {
            let raw = (safe_base + weighted_sum / edge_count as f64) / 2.0;
            if raw.is_finite() { raw } else { safe_base }
        } else {
            safe_base
        };

        let meets = composite >= MIN_TRUST_SCORE;
        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"reputation_graph_hash_v1:");
            h.update((node_id.len() as u64).to_le_bytes());
            h.update(node_id.as_bytes());
            h.update(composite.to_le_bytes());
            h.update((edge_count as u64).to_le_bytes());
            h.update((self.schema_version.len() as u64).to_le_bytes());
            h.update(self.schema_version.as_bytes());
            hex::encode(h.finalize())
        };

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
        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"reputation_graph_hash_v1:");
            h.update((self.nodes.len() as u64).to_le_bytes());
            h.update((self.edges.len() as u64).to_le_bytes());
            h.update((self.schema_version.len() as u64).to_le_bytes());
            h.update(self.schema_version.as_bytes());
            h.update((self.audit_log.len() as u64).to_le_bytes());
            hex::encode(h.finalize())
        };
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
        push_bounded(
            &mut self.audit_log,
            RgaAuditRecord {
                record_id: Uuid::now_v7().to_string(),
                event_code: event_code.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                trace_id: trace_id.to_string(),
                details,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
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
    fn push_bounded_zero_capacity_drops_existing_and_new_items() {
        let mut items = vec!["old-1", "old-2"];

        push_bounded(&mut items, "new", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_preexisting_overflow_keeps_newest_items() {
        let mut items = vec!["old-1", "old-2", "old-3", "old-4"];

        push_bounded(&mut items, "new", 3);

        assert_eq!(items, vec!["old-3", "old-4", "new"]);
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
    fn add_empty_node_id_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        let err = g
            .add_node(sample_node("", NodeType::Operator), "trace-empty-node")
            .unwrap_err();

        assert!(err.contains("node id"));
        assert!(g.nodes().is_empty());
        assert_eq!(g.audit_log().len(), 1);
        assert_eq!(
            g.audit_log()[0].event_code,
            event_codes::RGA_ERR_INVALID_NODE
        );
        assert_eq!(
            g.audit_log()[0].details["reason"].as_str(),
            Some("empty node_id")
        );
    }

    #[test]
    fn add_empty_display_name_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        let mut node = sample_node("n-empty-name", NodeType::Verifier);
        node.display_name.clear();
        let err = g.add_node(node, "trace-empty-name").unwrap_err();

        assert!(err.contains("display name"));
        assert!(g.nodes().is_empty());
        assert_eq!(
            g.audit_log()[0].event_code,
            event_codes::RGA_ERR_INVALID_NODE
        );
        assert_eq!(
            g.audit_log()[0].details["reason"].as_str(),
            Some("empty display_name")
        );
    }

    #[test]
    fn add_nan_base_score_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        let mut node = sample_node("n-nan", NodeType::DataSource);
        node.base_score = f64::NAN;
        let err = g.add_node(node, "trace-nan-node").unwrap_err();

        assert!(err.contains("base score"));
        assert!(g.nodes().is_empty());
        assert_eq!(
            g.audit_log()[0].details["reason"].as_str(),
            Some("non-finite base_score")
        );
    }

    #[test]
    fn duplicate_node_rejection_preserves_original_node() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        let mut replacement = sample_node("n1", NodeType::Verifier);
        replacement.display_name = "replacement".to_string();
        replacement.base_score = 0.1;
        let err = g.add_node(replacement, "trace-duplicate").unwrap_err();

        assert!(err.contains("duplicate"));
        assert_eq!(g.nodes().len(), 1);
        assert_eq!(g.nodes()["n1"].node_type, NodeType::Operator);
        assert_eq!(g.nodes()["n1"].display_name, "n1");
        assert!((g.nodes()["n1"].base_score - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn add_whitespace_node_id_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        let err = g
            .add_node(sample_node(" \t ", NodeType::Operator), "trace-space-node")
            .unwrap_err();

        assert!(err.contains("node id"));
        assert!(g.nodes().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_NODE
            && record.details["reason"].as_str() == Some("empty node_id")));
    }

    #[test]
    fn add_trim_required_node_id_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        let err = g
            .add_node(sample_node(" n1", NodeType::Operator), "trace-trim-node")
            .unwrap_err();

        assert!(err.contains("surrounding whitespace"));
        assert!(g.nodes().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_NODE
            && record.details["reason"].as_str() == Some("malformed node_id")));
    }

    #[test]
    fn add_whitespace_display_name_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        let mut node = sample_node("n-space-name", NodeType::Verifier);
        node.display_name = " \n ".to_string();
        let err = g.add_node(node, "trace-space-name").unwrap_err();

        assert!(err.contains("display name"));
        assert!(g.nodes().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_NODE
            && record.details["reason"].as_str() == Some("empty display_name")));
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
    fn add_empty_edge_id_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        let err = g
            .add_edge(sample_edge("", "n1", "n2", 0.5), "trace-empty-edge")
            .unwrap_err();

        assert!(err.contains("edge id"));
        assert!(g.edges().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_EDGE
            && record.details["reason"].as_str() == Some("empty edge_id")));
    }

    #[test]
    fn add_whitespace_edge_id_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        let err = g
            .add_edge(sample_edge("\t ", "n1", "n2", 0.5), "trace-space-edge")
            .unwrap_err();

        assert!(err.contains("edge id"));
        assert!(g.edges().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_EDGE
            && record.details["reason"].as_str() == Some("empty edge_id")));
    }

    #[test]
    fn add_trim_required_edge_id_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        let err = g
            .add_edge(sample_edge(" e-trim", "n1", "n2", 0.5), "trace-trim-edge")
            .unwrap_err();

        assert!(err.contains("surrounding whitespace"));
        assert!(g.edges().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_EDGE
            && record.details["reason"].as_str() == Some("malformed edge_id")));
    }

    #[test]
    fn add_self_loop_edge_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        let err = g
            .add_edge(sample_edge("e-self", "n1", "n1", 0.5), "trace-self-loop")
            .unwrap_err();

        assert!(err.contains("different"));
        assert!(g.edges().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_EDGE
            && record.details["reason"].as_str() == Some("self loop")));
    }

    #[test]
    fn add_nonfinite_edge_weight_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        let err = g
            .add_edge(
                sample_edge("e-inf", "n1", "n2", f64::INFINITY),
                "trace-inf-edge",
            )
            .unwrap_err();

        assert!(err.contains("weight"));
        assert!(g.edges().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_EDGE
            && record.details["reason"].as_str() == Some("non-finite weight")));
    }

    #[test]
    fn add_empty_evidence_edge_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        let mut edge = sample_edge("e-empty-evidence", "n1", "n2", 0.5);
        edge.evidence.clear();
        let err = g.add_edge(edge, "trace-empty-evidence").unwrap_err();

        assert!(err.contains("evidence"));
        assert!(g.edges().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_EDGE
            && record.details["reason"].as_str() == Some("empty evidence")));
    }

    #[test]
    fn add_whitespace_evidence_edge_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        let mut edge = sample_edge("e-space-evidence", "n1", "n2", 0.5);
        edge.evidence = " \r\n ".to_string();
        let err = g.add_edge(edge, "trace-space-evidence").unwrap_err();

        assert!(err.contains("evidence"));
        assert!(g.edges().is_empty());
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_EDGE
            && record.details["reason"].as_str() == Some("empty evidence")));
    }

    #[test]
    fn duplicate_edge_id_rejected_without_insert() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        g.add_node(sample_node("n3", NodeType::Verifier), &trace())
            .unwrap();
        g.add_edge(sample_edge("e-duplicate", "n1", "n2", 0.5), &trace())
            .unwrap();
        let err = g
            .add_edge(
                sample_edge("e-duplicate", "n2", "n3", 0.7),
                "trace-duplicate-edge",
            )
            .unwrap_err();

        assert!(err.contains("duplicate edge"));
        assert_eq!(g.edges().len(), 1);
        assert_eq!(g.edges()[0].edge_id, "e-duplicate");
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_EDGE
            && record.details["reason"].as_str() == Some("duplicate edge_id")));
    }

    #[test]
    fn missing_target_edge_rejection_preserves_existing_edges() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        g.add_node(sample_node("n2", NodeType::Extension), &trace())
            .unwrap();
        g.add_edge(sample_edge("e-good", "n1", "n2", 0.5), &trace())
            .unwrap();
        let err = g
            .add_edge(sample_edge("e-bad", "n1", "missing", 0.7), "trace-missing")
            .unwrap_err();

        assert!(err.contains("target node"));
        assert_eq!(g.edges().len(), 1);
        assert_eq!(g.edges()[0].edge_id, "e-good");
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
    fn compute_score_missing_node_does_not_emit_success_audit() {
        let mut g = ReputationGraphApis::default();
        let err = g
            .compute_score("missing", "trace-missing-score")
            .unwrap_err();

        assert!(err.contains("node not found"));
        assert!(g.audit_log().iter().all(|record| {
            record.event_code != event_codes::RGA_SCORE_COMPUTED
                && record.event_code != event_codes::RGA_THRESHOLD_CHECKED
        }));
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
    fn neighbors_missing_node_returns_empty_result() {
        let mut g = ReputationGraphApis::default();

        let neighbors = g.neighbors("missing", "trace-missing-neighbors");

        assert!(neighbors.is_empty());
        assert!(g.audit_log().iter().any(|record| {
            record.event_code == event_codes::RGA_QUERY_EXECUTED
                && record.details["query"].as_str() == Some("neighbors")
                && record.details["node"].as_str() == Some("missing")
        }));
    }

    #[test]
    fn subgraph_unknown_nodes_returns_empty_result() {
        let mut g = ReputationGraphApis::default();

        let (nodes, edges) = g.subgraph(&["missing-a", "missing-b"], "trace-missing-subgraph");

        assert!(nodes.is_empty());
        assert!(edges.is_empty());
        assert!(g.audit_log().iter().any(|record| {
            record.event_code == event_codes::RGA_SUBGRAPH_EXTRACTED
                && record.details["nodes"].as_u64() == Some(0)
                && record.details["edges"].as_u64() == Some(0)
        }));
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
    fn update_missing_node_score_does_not_emit_success_audit() {
        let mut g = ReputationGraphApis::default();
        let err = g
            .update_node_score("missing", 0.5, "trace-missing-update")
            .unwrap_err();

        assert!(err.contains("node not found"));
        assert!(g.audit_log().is_empty());
    }

    #[test]
    fn update_node_score_infinity_rejected_without_mutation() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        let before_score = g.nodes()["n1"].base_score;
        let err = g
            .update_node_score("n1", f64::INFINITY, "trace-update-inf")
            .unwrap_err();

        assert!(err.contains("base score"));
        assert!((g.nodes()["n1"].base_score - before_score).abs() < f64::EPSILON);
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_NODE
            && record.details["reason"].as_str() == Some("non-finite base_score")));
    }

    #[test]
    fn update_node_score_nan_rejected_without_mutation() {
        let mut g = ReputationGraphApis::default();
        g.add_node(sample_node("n1", NodeType::Operator), &trace())
            .unwrap();
        let err = g
            .update_node_score("n1", f64::NAN, "trace-update-nan")
            .unwrap_err();

        assert!(err.contains("base score"));
        assert!((g.nodes()["n1"].base_score - 0.8).abs() < f64::EPSILON);
        assert!(g.audit_log().iter().any(|record| record.event_code
            == event_codes::RGA_ERR_INVALID_NODE
            && record.details["reason"].as_str() == Some("non-finite base_score")));
        assert!(
            !g.audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::RGA_NODE_UPDATED)
        );
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
    fn export_empty_audit_log_is_empty_string() {
        let g = ReputationGraphApis::default();

        assert_eq!(g.export_audit_log_jsonl().unwrap(), "");
    }

    #[test]
    fn default_version() {
        let g = ReputationGraphApis::default();
        assert_eq!(g.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn node_type_deserialize_rejects_unknown_variant() {
        let result: Result<NodeType, _> = serde_json::from_str("\"unknown_node_type\"");

        assert!(result.is_err());
    }

    #[test]
    fn node_type_deserialize_rejects_display_case_label() {
        let result: Result<NodeType, _> = serde_json::from_str("\"DataSource\"");

        assert!(result.is_err());
    }

    #[test]
    fn reputation_node_deserialize_rejects_string_base_score() {
        let raw = serde_json::json!({
            "node_id": "n-string-score",
            "node_type": "operator",
            "display_name": "string score",
            "base_score": "0.8",
            "created_at": "2026-04-17T00:00:00Z"
        });

        let result: Result<ReputationNode, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn reputation_edge_deserialize_rejects_missing_evidence() {
        let raw = serde_json::json!({
            "edge_id": "e-missing-evidence",
            "source": "n1",
            "target": "n2",
            "weight": 0.7,
            "created_at": "2026-04-17T00:00:00Z"
        });

        let result: Result<ReputationEdge, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn reputation_score_deserialize_rejects_string_edge_count() {
        let raw = serde_json::json!({
            "node_id": "n1",
            "composite_score": 0.8,
            "meets_threshold": true,
            "edge_count": "1",
            "content_hash": "a".repeat(64)
        });

        let result: Result<ReputationScore, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn graph_snapshot_deserialize_rejects_missing_schema_version() {
        let raw = serde_json::json!({
            "snapshot_id": "snapshot-1",
            "timestamp": "2026-04-17T00:00:00Z",
            "node_count": 1_usize,
            "edge_count": 0_usize,
            "content_hash": "a".repeat(64)
        });

        let result: Result<GraphSnapshot, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn audit_record_deserialize_rejects_missing_details() {
        let raw = serde_json::json!({
            "record_id": "rga-audit-1",
            "event_code": event_codes::RGA_NODE_ADDED,
            "timestamp": "2026-04-17T00:00:00Z",
            "trace_id": "trace-1"
        });

        let result: Result<RgaAuditRecord, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }
}
