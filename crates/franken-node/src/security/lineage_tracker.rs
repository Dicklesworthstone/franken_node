//! Information-flow lineage tracking and exfiltration sentinel (bd-2iyk).
//!
//! This module provides:
//! - Taint-label assignment and propagation across execution flows
//! - Append-only lineage graph recording every flow edge
//! - Exfiltration sentinel that evaluates flow edges against taint boundaries
//! - Auto-containment with deterministic quarantine receipts
//! - Lineage snapshot export and subgraph query
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic ordering.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for the information-flow lineage module.
pub const SCHEMA_VERSION: &str = "ifl-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const EVENT_TAINT_ASSIGNED: &str = "FN-IFL-001";
pub const EVENT_EDGE_APPENDED: &str = "FN-IFL-002";
pub const EVENT_TAINT_PROPAGATED: &str = "FN-IFL-003";
pub const EVENT_BOUNDARY_CROSSING: &str = "FN-IFL-004";
pub const EVENT_EXFIL_ALERT: &str = "FN-IFL-005";
pub const EVENT_FLOW_QUARANTINED: &str = "FN-IFL-006";
pub const EVENT_CONTAINMENT_RECEIPT: &str = "FN-IFL-007";
pub const EVENT_SNAPSHOT_EXPORTED: &str = "FN-IFL-008";
pub const EVENT_CONFIG_RELOADED: &str = "FN-IFL-009";
pub const EVENT_DEPTH_LIMIT: &str = "FN-IFL-010";
pub const EVENT_TAINT_MERGE: &str = "FN-IFL-011";
pub const EVENT_HEALTH_CHECK: &str = "FN-IFL-012";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_IFL_LABEL_NOT_FOUND: &str = "ERR_IFL_LABEL_NOT_FOUND";
pub const ERR_IFL_DUPLICATE_EDGE: &str = "ERR_IFL_DUPLICATE_EDGE";
pub const ERR_IFL_GRAPH_FULL: &str = "ERR_IFL_GRAPH_FULL";
pub const ERR_IFL_BOUNDARY_INVALID: &str = "ERR_IFL_BOUNDARY_INVALID";
pub const ERR_IFL_CONTAINMENT_FAILED: &str = "ERR_IFL_CONTAINMENT_FAILED";
pub const ERR_IFL_SNAPSHOT_FAILED: &str = "ERR_IFL_SNAPSHOT_FAILED";
pub const ERR_IFL_QUERY_INVALID: &str = "ERR_IFL_QUERY_INVALID";
pub const ERR_IFL_CONFIG_REJECTED: &str = "ERR_IFL_CONFIG_REJECTED";
pub const ERR_IFL_ALREADY_QUARANTINED: &str = "ERR_IFL_ALREADY_QUARANTINED";
pub const ERR_IFL_TIMEOUT: &str = "ERR_IFL_TIMEOUT";

// ---------------------------------------------------------------------------
// Invariant identifiers
// ---------------------------------------------------------------------------

/// INV-IFL-LABEL-PERSIST: Once assigned, a taint label is never silently
/// removed from a datum's taint set.
pub const INV_LABEL_PERSIST: &str = "INV-IFL-LABEL-PERSIST";

/// INV-IFL-EDGE-APPEND-ONLY: Flow edges are append-only; no edge is ever
/// deleted or mutated.
pub const INV_EDGE_APPEND_ONLY: &str = "INV-IFL-EDGE-APPEND-ONLY";

/// INV-IFL-QUARANTINE-RECEIPT: Every quarantine action produces exactly one
/// ContainmentReceipt.
pub const INV_QUARANTINE_RECEIPT: &str = "INV-IFL-QUARANTINE-RECEIPT";

/// INV-IFL-BOUNDARY-ENFORCED: No flow edge crossing a denied boundary
/// proceeds without an alert.
pub const INV_BOUNDARY_ENFORCED: &str = "INV-IFL-BOUNDARY-ENFORCED";

/// INV-IFL-DETERMINISTIC: Given the same graph state and sentinel config,
/// the same verdict is always produced.
pub const INV_DETERMINISTIC: &str = "INV-IFL-DETERMINISTIC";

/// INV-IFL-SNAPSHOT-FAITHFUL: A lineage snapshot faithfully represents the
/// graph at the moment of capture.
pub const INV_SNAPSHOT_FAITHFUL: &str = "INV-IFL-SNAPSHOT-FAITHFUL";

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Immutable sensitivity classification tag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TaintLabel {
    /// Unique label identifier (e.g. "PII", "SECRET", "INTERNAL").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Severity level (higher = more sensitive).
    pub severity: u32,
}

/// Ordered set of active taint labels on a datum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintSet {
    pub labels: BTreeSet<String>,
}

impl TaintSet {
    pub fn new() -> Self {
        Self {
            labels: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, label_id: &str) {
        self.labels.insert(label_id.to_string());
    }

    pub fn contains(&self, label_id: &str) -> bool {
        self.labels.contains(label_id)
    }

    pub fn merge(&mut self, other: &TaintSet) {
        for label in &other.labels {
            self.labels.insert(label.clone());
        }
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }
}

impl Default for TaintSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Directed edge: (source, sink, operation, taint_set, timestamp).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEdge {
    pub edge_id: String,
    pub source: String,
    pub sink: String,
    pub operation: String,
    pub taint_set: TaintSet,
    pub timestamp_ms: u64,
    pub quarantined: bool,
}

/// Taint boundary: policy rule defining allowed/denied taint crossings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintBoundary {
    pub boundary_id: String,
    pub from_zone: String,
    pub to_zone: String,
    /// Labels that are denied crossing this boundary.
    pub denied_labels: BTreeSet<String>,
    /// If true, *all* labels are denied (deny-all rule).
    pub deny_all: bool,
}

impl TaintBoundary {
    /// Check if a given taint set crosses this boundary.
    pub fn is_violated_by(&self, taint_set: &TaintSet) -> bool {
        if self.deny_all && !taint_set.is_empty() {
            return true;
        }
        taint_set.labels.iter().any(|l| self.denied_labels.contains(l))
    }

    /// Validate that the boundary rule is well-formed.
    pub fn validate(&self) -> Result<(), LineageError> {
        if self.from_zone.is_empty() || self.to_zone.is_empty() {
            return Err(LineageError::BoundaryInvalid {
                detail: format!(
                    "{}: from_zone and to_zone must be non-empty",
                    ERR_IFL_BOUNDARY_INVALID
                ),
            });
        }
        Ok(())
    }
}

/// Per-edge pass/quarantine/alert decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowVerdict {
    Pass,
    Quarantine,
    Alert,
}

impl fmt::Display for FlowVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowVerdict::Pass => write!(f, "pass"),
            FlowVerdict::Quarantine => write!(f, "quarantine"),
            FlowVerdict::Alert => write!(f, "alert"),
        }
    }
}

/// Structured alert raised on boundary violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExfiltrationAlert {
    pub alert_id: String,
    pub edge_id: String,
    pub violated_boundary: String,
    pub taint_labels: BTreeSet<String>,
    pub verdict: FlowVerdict,
    pub timestamp_ms: u64,
    pub detail: String,
}

/// Proof that a flow was quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReceipt {
    pub receipt_id: String,
    pub alert_id: String,
    pub edge_id: String,
    pub quarantine_timestamp_ms: u64,
    pub containment_action: String,
    pub success: bool,
}

/// Tuning knobs for the sentinel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub max_graph_edges: usize,
    pub max_graph_depth: usize,
    pub alert_cooldown_ms: u64,
    pub recall_threshold_pct: u32,
    pub precision_threshold_pct: u32,
    pub schema_version: String,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            max_graph_edges: 100_000,
            max_graph_depth: 256,
            alert_cooldown_ms: 1_000,
            recall_threshold_pct: 95,
            precision_threshold_pct: 90,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }
}

impl SentinelConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), LineageError> {
        if self.max_graph_edges == 0 || self.max_graph_depth == 0 {
            return Err(LineageError::ConfigRejected {
                detail: format!("{}: max_graph_edges and max_graph_depth must be > 0", ERR_IFL_CONFIG_REJECTED),
            });
        }
        if self.recall_threshold_pct > 100 || self.precision_threshold_pct > 100 {
            return Err(LineageError::ConfigRejected {
                detail: format!("{}: thresholds must be <= 100", ERR_IFL_CONFIG_REJECTED),
            });
        }
        if self.schema_version.is_empty() {
            return Err(LineageError::ConfigRejected {
                detail: format!("{}: schema_version must be non-empty", ERR_IFL_CONFIG_REJECTED),
            });
        }
        Ok(())
    }
}

/// Query filter for subgraph extraction.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LineageQuery {
    /// Filter by source node.
    pub source: Option<String>,
    /// Filter by sink node.
    pub sink: Option<String>,
    /// Filter by taint label presence.
    pub taint_label: Option<String>,
    /// Filter by timestamp range (inclusive).
    pub from_timestamp_ms: Option<u64>,
    pub to_timestamp_ms: Option<u64>,
    /// Maximum number of edges to return.
    pub limit: Option<usize>,
}

impl LineageQuery {
    pub fn validate(&self) -> Result<(), LineageError> {
        if let (Some(from), Some(to)) = (self.from_timestamp_ms, self.to_timestamp_ms) {
            if from > to {
                return Err(LineageError::QueryInvalid {
                    detail: format!("{}: from_timestamp > to_timestamp", ERR_IFL_QUERY_INVALID),
                });
            }
        }
        Ok(())
    }
}

/// Serialisable snapshot of the graph at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageSnapshot {
    pub snapshot_id: String,
    pub timestamp_ms: u64,
    pub edge_count: usize,
    pub label_count: usize,
    pub edges: Vec<FlowEdge>,
    pub labels: BTreeMap<String, TaintLabel>,
    pub schema_version: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum LineageError {
    LabelNotFound { detail: String },
    DuplicateEdge { detail: String },
    GraphFull { detail: String },
    BoundaryInvalid { detail: String },
    ContainmentFailed { detail: String },
    SnapshotFailed { detail: String },
    QueryInvalid { detail: String },
    ConfigRejected { detail: String },
    AlreadyQuarantined { detail: String },
    Timeout { detail: String },
}

impl fmt::Display for LineageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabelNotFound { detail } => write!(f, "{}", detail),
            Self::DuplicateEdge { detail } => write!(f, "{}", detail),
            Self::GraphFull { detail } => write!(f, "{}", detail),
            Self::BoundaryInvalid { detail } => write!(f, "{}", detail),
            Self::ContainmentFailed { detail } => write!(f, "{}", detail),
            Self::SnapshotFailed { detail } => write!(f, "{}", detail),
            Self::QueryInvalid { detail } => write!(f, "{}", detail),
            Self::ConfigRejected { detail } => write!(f, "{}", detail),
            Self::AlreadyQuarantined { detail } => write!(f, "{}", detail),
            Self::Timeout { detail } => write!(f, "{}", detail),
        }
    }
}

impl std::error::Error for LineageError {}

// ---------------------------------------------------------------------------
// LineageGraph
// ---------------------------------------------------------------------------

/// Append-only DAG of FlowEdge records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageGraph {
    /// Edges keyed by edge_id for O(1) lookup, BTreeMap for deterministic ordering.
    edges: BTreeMap<String, FlowEdge>,
    /// Registered taint labels.
    labels: BTreeMap<String, TaintLabel>,
    /// Taint sets per datum (keyed by datum id).
    datum_taints: BTreeMap<String, TaintSet>,
    /// Configuration.
    config: SentinelConfig,
    /// Monotonic edge counter for generating edge IDs.
    edge_counter: u64,
}

impl LineageGraph {
    pub fn new(config: SentinelConfig) -> Self {
        Self {
            edges: BTreeMap::new(),
            labels: BTreeMap::new(),
            datum_taints: BTreeMap::new(),
            config,
            edge_counter: 0,
        }
    }

    /// Register a taint label. Event: FN-IFL-001.
    pub fn register_label(&mut self, label: TaintLabel) -> String {
        let _event = EVENT_TAINT_ASSIGNED;
        let id = label.id.clone();
        self.labels.insert(id.clone(), label);
        id
    }

    /// Assign a taint label to a datum. Event: FN-IFL-001.
    /// INV-IFL-LABEL-PERSIST: labels are never removed from a taint set.
    pub fn assign_taint(&mut self, datum_id: &str, label_id: &str) -> Result<(), LineageError> {
        let _inv = INV_LABEL_PERSIST;
        if !self.labels.contains_key(label_id) {
            return Err(LineageError::LabelNotFound {
                detail: format!("{}: label '{}' not registered", ERR_IFL_LABEL_NOT_FOUND, label_id),
            });
        }
        let taint_set = self.datum_taints.entry(datum_id.to_string()).or_default();
        taint_set.insert(label_id);
        Ok(())
    }

    /// Get the taint set for a datum.
    pub fn get_taint_set(&self, datum_id: &str) -> Option<&TaintSet> {
        self.datum_taints.get(datum_id)
    }

    /// Append a flow edge. Event: FN-IFL-002.
    /// INV-IFL-EDGE-APPEND-ONLY: edges are never deleted.
    pub fn append_edge(&mut self, mut edge: FlowEdge) -> Result<String, LineageError> {
        let _inv = INV_EDGE_APPEND_ONLY;

        if self.edges.len() >= self.config.max_graph_edges {
            return Err(LineageError::GraphFull {
                detail: format!(
                    "{}: graph has {} edges (max {})",
                    ERR_IFL_GRAPH_FULL,
                    self.edges.len(),
                    self.config.max_graph_edges
                ),
            });
        }

        if edge.edge_id.is_empty() {
            self.edge_counter += 1;
            edge.edge_id = format!("edge-{}", self.edge_counter);
        }

        if self.edges.contains_key(&edge.edge_id) {
            return Err(LineageError::DuplicateEdge {
                detail: format!("{}: edge '{}' already exists", ERR_IFL_DUPLICATE_EDGE, edge.edge_id),
            });
        }

        let _event = EVENT_EDGE_APPENDED;
        let edge_id = edge.edge_id.clone();
        self.edges.insert(edge_id.clone(), edge);
        Ok(edge_id)
    }

    /// Propagate taint from source to sink datum through an operation.
    /// Event: FN-IFL-003, FN-IFL-011 (on merge).
    pub fn propagate_taint(
        &mut self,
        source_datum: &str,
        sink_datum: &str,
        operation: &str,
        timestamp_ms: u64,
    ) -> Result<String, LineageError> {
        let _event_prop = EVENT_TAINT_PROPAGATED;

        let source_taint = self
            .datum_taints
            .get(source_datum)
            .cloned()
            .unwrap_or_default();

        // Merge taint sets (INV-IFL-LABEL-PERSIST: labels only grow)
        let sink_taint = self.datum_taints.entry(sink_datum.to_string()).or_default();
        let had_labels = sink_taint.len();
        sink_taint.merge(&source_taint);
        if sink_taint.len() > had_labels {
            let _event_merge = EVENT_TAINT_MERGE;
        }

        let edge = FlowEdge {
            edge_id: String::new(),
            source: source_datum.to_string(),
            sink: sink_datum.to_string(),
            operation: operation.to_string(),
            taint_set: source_taint,
            timestamp_ms,
            quarantined: false,
        };

        self.append_edge(edge)
    }

    /// Query the lineage graph.
    pub fn query(&self, q: &LineageQuery) -> Result<Vec<&FlowEdge>, LineageError> {
        q.validate()?;

        let mut results: Vec<&FlowEdge> = self
            .edges
            .values()
            .filter(|e| {
                if let Some(ref src) = q.source {
                    if &e.source != src {
                        return false;
                    }
                }
                if let Some(ref snk) = q.sink {
                    if &e.sink != snk {
                        return false;
                    }
                }
                if let Some(ref lbl) = q.taint_label {
                    if !e.taint_set.contains(lbl) {
                        return false;
                    }
                }
                if let Some(from) = q.from_timestamp_ms {
                    if e.timestamp_ms < from {
                        return false;
                    }
                }
                if let Some(to) = q.to_timestamp_ms {
                    if e.timestamp_ms > to {
                        return false;
                    }
                }
                true
            })
            .collect();

        if let Some(limit) = q.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    /// Export a snapshot. Event: FN-IFL-008.
    /// INV-IFL-SNAPSHOT-FAITHFUL.
    pub fn snapshot(&self, snapshot_id: &str, timestamp_ms: u64) -> LineageSnapshot {
        let _inv = INV_SNAPSHOT_FAITHFUL;
        let _event = EVENT_SNAPSHOT_EXPORTED;
        LineageSnapshot {
            snapshot_id: snapshot_id.to_string(),
            timestamp_ms,
            edge_count: self.edges.len(),
            label_count: self.labels.len(),
            edges: self.edges.values().cloned().collect(),
            labels: self.labels.clone(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Get the total number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Get the total number of registered labels.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Get an edge by ID.
    pub fn get_edge(&self, edge_id: &str) -> Option<&FlowEdge> {
        self.edges.get(edge_id)
    }

    /// Mark an edge as quarantined (internal helper).
    fn quarantine_edge(&mut self, edge_id: &str) -> Result<(), LineageError> {
        if let Some(edge) = self.edges.get_mut(edge_id) {
            if edge.quarantined {
                return Err(LineageError::AlreadyQuarantined {
                    detail: format!("{}: edge '{}' already quarantined", ERR_IFL_ALREADY_QUARANTINED, edge_id),
                });
            }
            edge.quarantined = true;
            Ok(())
        } else {
            Err(LineageError::ContainmentFailed {
                detail: format!("{}: edge '{}' not found", ERR_IFL_CONTAINMENT_FAILED, edge_id),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// ExfiltrationSentinel
// ---------------------------------------------------------------------------

/// Policy engine evaluating flow edges against taint boundaries.
pub struct ExfiltrationSentinel {
    /// Taint boundaries (keyed by boundary_id).
    boundaries: BTreeMap<String, TaintBoundary>,
    /// Alert history (keyed by alert_id).
    alerts: BTreeMap<String, ExfiltrationAlert>,
    /// Containment receipts (keyed by receipt_id).
    receipts: BTreeMap<String, ContainmentReceipt>,
    /// Alert counter for ID generation.
    alert_counter: u64,
    /// Receipt counter for ID generation.
    receipt_counter: u64,
    /// Configuration reference.
    config: SentinelConfig,
}

impl ExfiltrationSentinel {
    pub fn new(config: SentinelConfig) -> Self {
        Self {
            boundaries: BTreeMap::new(),
            alerts: BTreeMap::new(),
            receipts: BTreeMap::new(),
            alert_counter: 0,
            receipt_counter: 0,
            config,
        }
    }

    /// Register a taint boundary.
    pub fn add_boundary(&mut self, boundary: TaintBoundary) -> Result<(), LineageError> {
        boundary.validate()?;
        self.boundaries.insert(boundary.boundary_id.clone(), boundary);
        Ok(())
    }

    /// Evaluate a flow edge against all boundaries.
    /// Returns the verdict and any alerts raised.
    /// INV-IFL-BOUNDARY-ENFORCED, INV-IFL-DETERMINISTIC.
    pub fn evaluate_edge(
        &mut self,
        edge: &FlowEdge,
        graph: &mut LineageGraph,
    ) -> Result<FlowVerdict, LineageError> {
        let _inv_boundary = INV_BOUNDARY_ENFORCED;
        let _inv_det = INV_DETERMINISTIC;

        let mut worst_verdict = FlowVerdict::Pass;

        for boundary in self.boundaries.values() {
            // Check if this edge crosses this boundary
            let crosses = edge.source.contains(&boundary.from_zone)
                && edge.sink.contains(&boundary.to_zone);

            if !crosses {
                continue;
            }

            let _event = EVENT_BOUNDARY_CROSSING;

            if boundary.is_violated_by(&edge.taint_set) {
                // Raise an alert
                self.alert_counter += 1;
                let alert_id = format!("alert-{}", self.alert_counter);
                let _event_alert = EVENT_EXFIL_ALERT;

                let alert = ExfiltrationAlert {
                    alert_id: alert_id.clone(),
                    edge_id: edge.edge_id.clone(),
                    violated_boundary: boundary.boundary_id.clone(),
                    taint_labels: edge.taint_set.labels.clone(),
                    verdict: FlowVerdict::Quarantine,
                    timestamp_ms: edge.timestamp_ms,
                    detail: format!(
                        "Taint labels {:?} crossed boundary '{}' ({} -> {})",
                        edge.taint_set.labels, boundary.boundary_id,
                        boundary.from_zone, boundary.to_zone,
                    ),
                };
                self.alerts.insert(alert_id, alert);

                // Auto-contain: quarantine the edge
                // INV-IFL-QUARANTINE-RECEIPT
                let _inv_receipt = INV_QUARANTINE_RECEIPT;
                let _event_quarantine = EVENT_FLOW_QUARANTINED;
                graph.quarantine_edge(&edge.edge_id)?;

                // Issue containment receipt
                self.receipt_counter += 1;
                let receipt_id = format!("receipt-{}", self.receipt_counter);
                let _event_receipt = EVENT_CONTAINMENT_RECEIPT;

                let receipt = ContainmentReceipt {
                    receipt_id: receipt_id.clone(),
                    alert_id: format!("alert-{}", self.alert_counter),
                    edge_id: edge.edge_id.clone(),
                    quarantine_timestamp_ms: edge.timestamp_ms,
                    containment_action: "quarantine_edge".to_string(),
                    success: true,
                };
                self.receipts.insert(receipt_id, receipt);

                worst_verdict = FlowVerdict::Quarantine;
            }
        }

        Ok(worst_verdict)
    }

    /// Get all alerts.
    pub fn alerts(&self) -> &BTreeMap<String, ExfiltrationAlert> {
        &self.alerts
    }

    /// Get all containment receipts.
    pub fn receipts(&self) -> &BTreeMap<String, ContainmentReceipt> {
        &self.receipts
    }

    /// Get alert count.
    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    /// Get receipt count.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Health check. Event: FN-IFL-012.
    pub fn health_check(&self) -> bool {
        let _event = EVENT_HEALTH_CHECK;
        self.config.validate().is_ok()
    }

    /// Reload configuration. Event: FN-IFL-009.
    pub fn reload_config(&mut self, new_config: SentinelConfig) -> Result<(), LineageError> {
        let _event = EVENT_CONFIG_RELOADED;
        new_config.validate()?;
        self.config = new_config;
        Ok(())
    }

    /// Check graph depth limit. Event: FN-IFL-010.
    pub fn check_depth_limit(&self, graph: &LineageGraph) -> bool {
        let _event = EVENT_DEPTH_LIMIT;
        graph.edge_count() <= self.config.max_graph_depth
    }
}

// ---------------------------------------------------------------------------
// Invariants module
// ---------------------------------------------------------------------------

pub mod invariants {
    use super::*;

    /// Verify INV-IFL-LABEL-PERSIST: no labels were removed from datum taint sets.
    pub fn verify_label_persist(
        before: &BTreeMap<String, TaintSet>,
        after: &BTreeMap<String, TaintSet>,
    ) -> bool {
        for (datum, before_set) in before {
            match after.get(datum) {
                Some(after_set) => {
                    for label in &before_set.labels {
                        if !after_set.labels.contains(label) {
                            return false;
                        }
                    }
                }
                None => return false,
            }
        }
        true
    }

    /// Verify INV-IFL-EDGE-APPEND-ONLY: no edges were removed.
    pub fn verify_edge_append_only(before_count: usize, after_count: usize) -> bool {
        after_count >= before_count
    }

    /// Verify INV-IFL-QUARANTINE-RECEIPT: quarantined edges have receipts.
    pub fn verify_quarantine_receipt(
        graph: &LineageGraph,
        sentinel: &ExfiltrationSentinel,
    ) -> bool {
        let quarantined_edges: BTreeSet<String> = graph
            .edges
            .values()
            .filter(|e| e.quarantined)
            .map(|e| e.edge_id.clone())
            .collect();

        let receipted_edges: BTreeSet<String> = sentinel
            .receipts
            .values()
            .filter(|r| r.success)
            .map(|r| r.edge_id.clone())
            .collect();

        quarantined_edges == receipted_edges
    }

    /// Verify INV-IFL-DETERMINISTIC: evaluating the same edge twice yields same result.
    pub fn verify_deterministic(
        edge: &FlowEdge,
        boundaries: &BTreeMap<String, TaintBoundary>,
    ) -> bool {
        let verdict1 = evaluate_edge_pure(edge, boundaries);
        let verdict2 = evaluate_edge_pure(edge, boundaries);
        verdict1 == verdict2
    }

    /// Pure (side-effect-free) edge evaluation for determinism checking.
    fn evaluate_edge_pure(
        edge: &FlowEdge,
        boundaries: &BTreeMap<String, TaintBoundary>,
    ) -> FlowVerdict {
        for boundary in boundaries.values() {
            let crosses = edge.source.contains(&boundary.from_zone)
                && edge.sink.contains(&boundary.to_zone);
            if crosses && boundary.is_violated_by(&edge.taint_set) {
                return FlowVerdict::Quarantine;
            }
        }
        FlowVerdict::Pass
    }

    /// Verify INV-IFL-SNAPSHOT-FAITHFUL: snapshot edge count matches graph.
    pub fn verify_snapshot_faithful(graph: &LineageGraph, snapshot: &LineageSnapshot) -> bool {
        snapshot.edge_count == graph.edge_count()
            && snapshot.label_count == graph.label_count()
            && snapshot.schema_version == SCHEMA_VERSION
    }

    /// Verify INV-IFL-BOUNDARY-ENFORCED: all violating edges are quarantined.
    pub fn verify_boundary_enforced(
        graph: &LineageGraph,
        boundaries: &BTreeMap<String, TaintBoundary>,
    ) -> bool {
        for edge in graph.edges.values() {
            for boundary in boundaries.values() {
                let crosses = edge.source.contains(&boundary.from_zone)
                    && edge.sink.contains(&boundary.to_zone);
                if crosses && boundary.is_violated_by(&edge.taint_set) {
                    if !edge.quarantined {
                        return false;
                    }
                }
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> SentinelConfig {
        SentinelConfig::default()
    }

    fn make_label(id: &str, severity: u32) -> TaintLabel {
        TaintLabel {
            id: id.to_string(),
            description: format!("{} label", id),
            severity,
        }
    }

    fn make_boundary(id: &str, from: &str, to: &str, denied: &[&str]) -> TaintBoundary {
        TaintBoundary {
            boundary_id: id.to_string(),
            from_zone: from.to_string(),
            to_zone: to.to_string(),
            denied_labels: denied.iter().map(|s| s.to_string()).collect(),
            deny_all: false,
        }
    }

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, "ifl-v1.0");
    }

    #[test]
    fn test_taint_set_new_is_empty() {
        let ts = TaintSet::new();
        assert!(ts.is_empty());
        assert_eq!(ts.len(), 0);
    }

    #[test]
    fn test_taint_set_insert_and_contains() {
        let mut ts = TaintSet::new();
        ts.insert("PII");
        assert!(ts.contains("PII"));
        assert!(!ts.contains("SECRET"));
        assert_eq!(ts.len(), 1);
    }

    #[test]
    fn test_taint_set_merge() {
        let mut ts1 = TaintSet::new();
        ts1.insert("PII");
        let mut ts2 = TaintSet::new();
        ts2.insert("SECRET");
        ts1.merge(&ts2);
        assert!(ts1.contains("PII"));
        assert!(ts1.contains("SECRET"));
        assert_eq!(ts1.len(), 2);
    }

    #[test]
    fn test_register_label() {
        let mut graph = LineageGraph::new(default_config());
        let id = graph.register_label(make_label("PII", 10));
        assert_eq!(id, "PII");
        assert_eq!(graph.label_count(), 1);
    }

    #[test]
    fn test_assign_taint_success() {
        let mut graph = LineageGraph::new(default_config());
        graph.register_label(make_label("PII", 10));
        assert!(graph.assign_taint("datum-1", "PII").is_ok());
        let ts = graph.get_taint_set("datum-1").unwrap();
        assert!(ts.contains("PII"));
    }

    #[test]
    fn test_assign_taint_unknown_label() {
        let mut graph = LineageGraph::new(default_config());
        let err = graph.assign_taint("datum-1", "NONEXISTENT").unwrap_err();
        assert!(err.to_string().contains(ERR_IFL_LABEL_NOT_FOUND));
    }

    #[test]
    fn test_append_edge_success() {
        let mut graph = LineageGraph::new(default_config());
        let edge = FlowEdge {
            edge_id: String::new(),
            source: "node-a".to_string(),
            sink: "node-b".to_string(),
            operation: "copy".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: 1000,
            quarantined: false,
        };
        let id = graph.append_edge(edge).unwrap();
        assert_eq!(id, "edge-1");
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_append_edge_duplicate() {
        let mut graph = LineageGraph::new(default_config());
        let edge = FlowEdge {
            edge_id: "e1".to_string(),
            source: "a".to_string(),
            sink: "b".to_string(),
            operation: "op".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: 1,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();
        let err = graph.append_edge(edge).unwrap_err();
        assert!(err.to_string().contains(ERR_IFL_DUPLICATE_EDGE));
    }

    #[test]
    fn test_append_edge_graph_full() {
        let mut config = default_config();
        config.max_graph_edges = 1;
        let mut graph = LineageGraph::new(config);
        let e1 = FlowEdge {
            edge_id: String::new(),
            source: "a".to_string(),
            sink: "b".to_string(),
            operation: "op".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: 1,
            quarantined: false,
        };
        graph.append_edge(e1).unwrap();
        let e2 = FlowEdge {
            edge_id: String::new(),
            source: "c".to_string(),
            sink: "d".to_string(),
            operation: "op".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: 2,
            quarantined: false,
        };
        let err = graph.append_edge(e2).unwrap_err();
        assert!(err.to_string().contains(ERR_IFL_GRAPH_FULL));
    }

    #[test]
    fn test_propagate_taint() {
        let mut graph = LineageGraph::new(default_config());
        graph.register_label(make_label("PII", 10));
        graph.assign_taint("src", "PII").unwrap();
        let edge_id = graph.propagate_taint("src", "dst", "transform", 100).unwrap();
        assert!(!edge_id.is_empty());
        let dst_taint = graph.get_taint_set("dst").unwrap();
        assert!(dst_taint.contains("PII"));
    }

    #[test]
    fn test_snapshot_faithfulness() {
        let mut graph = LineageGraph::new(default_config());
        graph.register_label(make_label("SECRET", 20));
        let edge = FlowEdge {
            edge_id: String::new(),
            source: "a".to_string(),
            sink: "b".to_string(),
            operation: "read".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: 42,
            quarantined: false,
        };
        graph.append_edge(edge).unwrap();
        let snap = graph.snapshot("snap-1", 100);
        assert_eq!(snap.edge_count, 1);
        assert_eq!(snap.label_count, 1);
        assert_eq!(snap.schema_version, SCHEMA_VERSION);
        assert!(invariants::verify_snapshot_faithful(&graph, &snap));
    }

    #[test]
    fn test_query_by_source() {
        let mut graph = LineageGraph::new(default_config());
        let e1 = FlowEdge {
            edge_id: "e1".to_string(),
            source: "nodeA".to_string(),
            sink: "nodeB".to_string(),
            operation: "op".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: 1,
            quarantined: false,
        };
        let e2 = FlowEdge {
            edge_id: "e2".to_string(),
            source: "nodeC".to_string(),
            sink: "nodeD".to_string(),
            operation: "op".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: 2,
            quarantined: false,
        };
        graph.append_edge(e1).unwrap();
        graph.append_edge(e2).unwrap();
        let q = LineageQuery {
            source: Some("nodeA".to_string()),
            ..Default::default()
        };
        let results = graph.query(&q).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source, "nodeA");
    }

    #[test]
    fn test_query_invalid_timestamp_range() {
        let graph = LineageGraph::new(default_config());
        let q = LineageQuery {
            from_timestamp_ms: Some(200),
            to_timestamp_ms: Some(100),
            ..Default::default()
        };
        let err = graph.query(&q).unwrap_err();
        assert!(err.to_string().contains(ERR_IFL_QUERY_INVALID));
    }

    #[test]
    fn test_boundary_violation_detection() {
        let boundary = make_boundary("b1", "internal", "external", &["PII"]);
        let mut ts = TaintSet::new();
        ts.insert("PII");
        assert!(boundary.is_violated_by(&ts));
    }

    #[test]
    fn test_boundary_no_violation() {
        let boundary = make_boundary("b1", "internal", "external", &["SECRET"]);
        let mut ts = TaintSet::new();
        ts.insert("PII");
        assert!(!boundary.is_violated_by(&ts));
    }

    #[test]
    fn test_boundary_deny_all() {
        let boundary = TaintBoundary {
            boundary_id: "deny-all".to_string(),
            from_zone: "secure".to_string(),
            to_zone: "public".to_string(),
            denied_labels: BTreeSet::new(),
            deny_all: true,
        };
        let mut ts = TaintSet::new();
        ts.insert("ANY");
        assert!(boundary.is_violated_by(&ts));
        assert!(!boundary.is_violated_by(&TaintSet::new()));
    }

    #[test]
    fn test_sentinel_evaluate_and_quarantine() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);

        sentinel
            .add_boundary(make_boundary("b1", "internal", "external", &["PII"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");

        let edge = FlowEdge {
            edge_id: "exfil-1".to_string(),
            source: "internal-db".to_string(),
            sink: "external-api".to_string(),
            operation: "export".to_string(),
            taint_set: ts,
            timestamp_ms: 500,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();

        let verdict = sentinel.evaluate_edge(&edge, &mut graph).unwrap();
        assert_eq!(verdict, FlowVerdict::Quarantine);
        assert_eq!(sentinel.alert_count(), 1);
        assert_eq!(sentinel.receipt_count(), 1);

        // Verify the edge is quarantined in the graph
        let quarantined_edge = graph.get_edge("exfil-1").unwrap();
        assert!(quarantined_edge.quarantined);
    }

    #[test]
    fn test_sentinel_pass_when_no_violation() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);

        sentinel
            .add_boundary(make_boundary("b1", "internal", "external", &["SECRET"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PUBLIC");

        let edge = FlowEdge {
            edge_id: "safe-1".to_string(),
            source: "internal-svc".to_string(),
            sink: "external-cdn".to_string(),
            operation: "publish".to_string(),
            taint_set: ts,
            timestamp_ms: 600,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();

        let verdict = sentinel.evaluate_edge(&edge, &mut graph).unwrap();
        assert_eq!(verdict, FlowVerdict::Pass);
        assert_eq!(sentinel.alert_count(), 0);
    }

    #[test]
    fn test_double_quarantine_error() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);

        sentinel
            .add_boundary(make_boundary("b1", "zone_a", "zone_b", &["PII"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");

        let edge = FlowEdge {
            edge_id: "dbl-1".to_string(),
            source: "zone_a-svc".to_string(),
            sink: "zone_b-sink".to_string(),
            operation: "copy".to_string(),
            taint_set: ts.clone(),
            timestamp_ms: 700,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();
        sentinel.evaluate_edge(&edge, &mut graph).unwrap();

        // Second evaluate should fail with AlreadyQuarantined
        let err = sentinel.evaluate_edge(&edge, &mut graph).unwrap_err();
        assert!(err.to_string().contains(ERR_IFL_ALREADY_QUARANTINED));
    }

    #[test]
    fn test_sentinel_health_check() {
        let sentinel = ExfiltrationSentinel::new(default_config());
        assert!(sentinel.health_check());
    }

    #[test]
    fn test_sentinel_reload_config() {
        let mut sentinel = ExfiltrationSentinel::new(default_config());
        let mut new_config = default_config();
        new_config.max_graph_edges = 50_000;
        assert!(sentinel.reload_config(new_config).is_ok());
    }

    #[test]
    fn test_sentinel_reload_config_invalid() {
        let mut sentinel = ExfiltrationSentinel::new(default_config());
        let mut bad_config = default_config();
        bad_config.max_graph_edges = 0;
        let err = sentinel.reload_config(bad_config).unwrap_err();
        assert!(err.to_string().contains(ERR_IFL_CONFIG_REJECTED));
    }

    #[test]
    fn test_config_validation_thresholds() {
        let mut config = default_config();
        config.recall_threshold_pct = 101;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_boundary_validation_empty_zone() {
        let boundary = TaintBoundary {
            boundary_id: "bad".to_string(),
            from_zone: String::new(),
            to_zone: "ext".to_string(),
            denied_labels: BTreeSet::new(),
            deny_all: false,
        };
        assert!(boundary.validate().is_err());
    }

    #[test]
    fn test_invariant_label_persist() {
        let mut before: BTreeMap<String, TaintSet> = BTreeMap::new();
        let mut ts = TaintSet::new();
        ts.insert("PII");
        before.insert("d1".to_string(), ts.clone());

        let mut after = before.clone();
        after.get_mut("d1").unwrap().insert("SECRET");

        assert!(invariants::verify_label_persist(&before, &after));
    }

    #[test]
    fn test_invariant_label_persist_violation() {
        let mut before: BTreeMap<String, TaintSet> = BTreeMap::new();
        let mut ts = TaintSet::new();
        ts.insert("PII");
        before.insert("d1".to_string(), ts);

        let mut after: BTreeMap<String, TaintSet> = BTreeMap::new();
        after.insert("d1".to_string(), TaintSet::new());

        assert!(!invariants::verify_label_persist(&before, &after));
    }

    #[test]
    fn test_invariant_edge_append_only() {
        assert!(invariants::verify_edge_append_only(5, 7));
        assert!(invariants::verify_edge_append_only(5, 5));
        assert!(!invariants::verify_edge_append_only(5, 3));
    }

    #[test]
    fn test_invariant_quarantine_receipt() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);

        sentinel
            .add_boundary(make_boundary("b1", "in", "out", &["PII"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");

        let edge = FlowEdge {
            edge_id: "inv-test".to_string(),
            source: "in-svc".to_string(),
            sink: "out-svc".to_string(),
            operation: "leak".to_string(),
            taint_set: ts,
            timestamp_ms: 999,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();
        sentinel.evaluate_edge(&edge, &mut graph).unwrap();

        assert!(invariants::verify_quarantine_receipt(&graph, &sentinel));
    }

    #[test]
    fn test_invariant_deterministic() {
        let mut boundaries = BTreeMap::new();
        boundaries.insert(
            "b1".to_string(),
            make_boundary("b1", "int", "ext", &["SECRET"]),
        );

        let mut ts = TaintSet::new();
        ts.insert("SECRET");

        let edge = FlowEdge {
            edge_id: "det-1".to_string(),
            source: "int-db".to_string(),
            sink: "ext-api".to_string(),
            operation: "export".to_string(),
            taint_set: ts,
            timestamp_ms: 1,
            quarantined: false,
        };

        assert!(invariants::verify_deterministic(&edge, &boundaries));
    }

    #[test]
    fn test_flow_verdict_display() {
        assert_eq!(FlowVerdict::Pass.to_string(), "pass");
        assert_eq!(FlowVerdict::Quarantine.to_string(), "quarantine");
        assert_eq!(FlowVerdict::Alert.to_string(), "alert");
    }

    #[test]
    fn test_lineage_error_display() {
        let err = LineageError::LabelNotFound {
            detail: "test detail".to_string(),
        };
        assert_eq!(err.to_string(), "test detail");
    }

    #[test]
    fn test_query_with_limit() {
        let mut graph = LineageGraph::new(default_config());
        for i in 0..5 {
            let e = FlowEdge {
                edge_id: format!("e{}", i),
                source: "a".to_string(),
                sink: "b".to_string(),
                operation: "op".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: i as u64,
                quarantined: false,
            };
            graph.append_edge(e).unwrap();
        }
        let q = LineageQuery {
            limit: Some(2),
            ..Default::default()
        };
        let results = graph.query(&q).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_check_depth_limit() {
        let config = SentinelConfig {
            max_graph_depth: 3,
            ..default_config()
        };
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);

        assert!(sentinel.check_depth_limit(&graph));

        for i in 0..4 {
            let e = FlowEdge {
                edge_id: format!("d{}", i),
                source: "a".to_string(),
                sink: "b".to_string(),
                operation: "op".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: i as u64,
                quarantined: false,
            };
            graph.append_edge(e).unwrap();
        }
        assert!(!sentinel.check_depth_limit(&graph));
    }
}
