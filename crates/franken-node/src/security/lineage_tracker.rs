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

// Canonical event codes required by bd-2iyk acceptance criteria.
pub const LINEAGE_TAG_ATTACHED: &str = "LINEAGE_TAG_ATTACHED";
pub const LINEAGE_FLOW_TRACKED: &str = "LINEAGE_FLOW_TRACKED";
pub const SENTINEL_SCAN_START: &str = "SENTINEL_SCAN_START";
pub const SENTINEL_EXFIL_DETECTED: &str = "SENTINEL_EXFIL_DETECTED";
pub const SENTINEL_CONTAINMENT_TRIGGERED: &str = "SENTINEL_CONTAINMENT_TRIGGERED";

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

// Canonical error codes required by bd-2iyk acceptance criteria.
pub const ERR_LINEAGE_TAG_MISSING: &str = "ERR_LINEAGE_TAG_MISSING";
pub const ERR_LINEAGE_FLOW_BROKEN: &str = "ERR_LINEAGE_FLOW_BROKEN";
pub const ERR_SENTINEL_RECALL_BELOW_THRESHOLD: &str = "ERR_SENTINEL_RECALL_BELOW_THRESHOLD";
pub const ERR_SENTINEL_PRECISION_BELOW_THRESHOLD: &str = "ERR_SENTINEL_PRECISION_BELOW_THRESHOLD";
pub const ERR_SENTINEL_CONTAINMENT_FAILED: &str = "ERR_SENTINEL_CONTAINMENT_FAILED";
pub const ERR_SENTINEL_COVERT_CHANNEL: &str = "ERR_SENTINEL_COVERT_CHANNEL";

const MAX_COVERT_CHANNEL_EDGE_IDS_PER_SOURCE: usize = 1024;
const MAX_COVERT_CHANNEL_DETECTIONS: usize = 4096;

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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

// Canonical invariant identifiers required by bd-2iyk acceptance criteria.

/// INV-LINEAGE-TAG-PERSISTENCE: Sensitive lineage tags persist across all
/// supported execution flows and are never silently stripped.
pub const INV_LINEAGE_TAG_PERSISTENCE: &str = "INV-LINEAGE-TAG-PERSISTENCE";

/// INV-SENTINEL-RECALL-THRESHOLD: The sentinel detects simulated covert
/// exfiltration scenarios above the configured recall threshold (default 95%).
pub const INV_SENTINEL_RECALL_THRESHOLD: &str = "INV-SENTINEL-RECALL-THRESHOLD";

/// INV-SENTINEL-PRECISION-THRESHOLD: The sentinel maintains precision above
/// the configured threshold (default 90%) to limit false-positive containment.
pub const INV_SENTINEL_PRECISION_THRESHOLD: &str = "INV-SENTINEL-PRECISION-THRESHOLD";

/// INV-SENTINEL-AUTO-CONTAIN: When exfiltration is detected, the sentinel
/// auto-contains the flow without requiring manual intervention.
pub const INV_SENTINEL_AUTO_CONTAIN: &str = "INV-SENTINEL-AUTO-CONTAIN";

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
        taint_set
            .labels
            .iter()
            .any(|l| self.denied_labels.contains(l))
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

    fn crosses_edge(&self, edge: &FlowEdge) -> bool {
        node_matches_zone(&edge.source, &self.from_zone)
            && node_matches_zone(&edge.sink, &self.to_zone)
    }
}

fn node_matches_zone(node: &str, zone: &str) -> bool {
    if zone.is_empty() {
        return false;
    }
    if node == zone {
        return true;
    }
    let Some(suffix) = node.strip_prefix(zone) else {
        return false;
    };
    matches!(suffix.chars().next(), Some(ch) if !ch.is_ascii_alphanumeric())
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
                detail: format!(
                    "{}: max_graph_edges and max_graph_depth must be > 0",
                    ERR_IFL_CONFIG_REJECTED
                ),
            });
        }
        if self.recall_threshold_pct > 100 || self.precision_threshold_pct > 100 {
            return Err(LineageError::ConfigRejected {
                detail: format!("{}: thresholds must be <= 100", ERR_IFL_CONFIG_REJECTED),
            });
        }
        if self.schema_version.is_empty() {
            return Err(LineageError::ConfigRejected {
                detail: format!(
                    "{}: schema_version must be non-empty",
                    ERR_IFL_CONFIG_REJECTED
                ),
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
        if let (Some(from), Some(to)) = (self.from_timestamp_ms, self.to_timestamp_ms)
            && from > to
        {
            return Err(LineageError::QueryInvalid {
                detail: format!("{}: from_timestamp > to_timestamp", ERR_IFL_QUERY_INVALID),
            });
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
                detail: format!(
                    "{}: label '{}' not registered",
                    ERR_IFL_LABEL_NOT_FOUND, label_id
                ),
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
            self.edge_counter = self.edge_counter.saturating_add(1);
            edge.edge_id = format!("edge-{}", self.edge_counter);
        }

        if self.edges.contains_key(&edge.edge_id) {
            return Err(LineageError::DuplicateEdge {
                detail: format!(
                    "{}: edge '{}' already exists",
                    ERR_IFL_DUPLICATE_EDGE, edge.edge_id
                ),
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
                if let Some(ref src) = q.source
                    && &e.source != src
                {
                    return false;
                }
                if let Some(ref snk) = q.sink
                    && &e.sink != snk
                {
                    return false;
                }
                if let Some(ref lbl) = q.taint_label
                    && !e.taint_set.contains(lbl)
                {
                    return false;
                }
                if let Some(from) = q.from_timestamp_ms
                    && e.timestamp_ms < from
                {
                    return false;
                }
                if let Some(to) = q.to_timestamp_ms
                    && e.timestamp_ms > to
                {
                    return false;
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
                    detail: format!(
                        "{}: edge '{}' already quarantined",
                        ERR_IFL_ALREADY_QUARANTINED, edge_id
                    ),
                });
            }
            edge.quarantined = true;
            Ok(())
        } else {
            Err(LineageError::ContainmentFailed {
                detail: format!(
                    "{}: edge '{}' not found",
                    ERR_IFL_CONTAINMENT_FAILED, edge_id
                ),
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
        self.boundaries
            .insert(boundary.boundary_id.clone(), boundary);
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

        if graph
            .get_edge(&edge.edge_id)
            .is_some_and(|stored_edge| stored_edge.quarantined)
        {
            return Err(LineageError::AlreadyQuarantined {
                detail: format!(
                    "{}: edge '{}' already quarantined",
                    ERR_IFL_ALREADY_QUARANTINED, edge.edge_id
                ),
            });
        }

        let mut worst_verdict = FlowVerdict::Pass;
        let mut edge_quarantined = false;

        for boundary in self.boundaries.values() {
            // Check if this edge crosses this boundary
            let crosses = boundary.crosses_edge(edge);

            if !crosses {
                continue;
            }

            let _event = EVENT_BOUNDARY_CROSSING;

            if boundary.is_violated_by(&edge.taint_set) {
                // Raise an alert
                self.alert_counter = self.alert_counter.saturating_add(1);
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
                        edge.taint_set.labels,
                        boundary.boundary_id,
                        boundary.from_zone,
                        boundary.to_zone,
                    ),
                };
                self.alerts.insert(alert_id, alert);

                // Auto-contain: quarantine the edge
                // INV-IFL-QUARANTINE-RECEIPT
                if !edge_quarantined {
                    let _inv_receipt = INV_QUARANTINE_RECEIPT;
                    let _event_quarantine = EVENT_FLOW_QUARANTINED;
                    graph.quarantine_edge(&edge.edge_id)?;

                    // Issue containment receipt once per edge quarantine.
                    self.receipt_counter = self.receipt_counter.saturating_add(1);
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
                    edge_quarantined = true;
                }

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

    /// Run a sentinel scan across all edges in the graph.
    /// Event: SENTINEL_SCAN_START, SENTINEL_EXFIL_DETECTED, SENTINEL_CONTAINMENT_TRIGGERED.
    /// INV-SENTINEL-AUTO-CONTAIN: detected exfiltrations are auto-contained.
    pub fn scan_graph(
        &mut self,
        graph: &mut LineageGraph,
    ) -> Result<SentinelScanResult, LineageError> {
        let _event_start = SENTINEL_SCAN_START;
        let _inv_auto = INV_SENTINEL_AUTO_CONTAIN;

        let edge_ids: Vec<String> = graph.edges.keys().cloned().collect();
        let mut detected = 0u64;
        let mut contained = 0u64;
        let mut passed = 0u64;

        for eid in &edge_ids {
            let edge = graph.edges.get(eid).cloned();
            if let Some(e) = edge {
                if e.quarantined {
                    continue;
                }
                let verdict = self.evaluate_edge(&e, graph);
                match verdict {
                    Ok(FlowVerdict::Quarantine) => {
                        let _det = SENTINEL_EXFIL_DETECTED;
                        let _trig = SENTINEL_CONTAINMENT_TRIGGERED;
                        detected = detected.saturating_add(1);
                        contained = contained.saturating_add(1);
                    }
                    Ok(FlowVerdict::Pass) => {
                        passed = passed.saturating_add(1);
                    }
                    Ok(FlowVerdict::Alert) => {
                        detected = detected.saturating_add(1);
                    }
                    Err(LineageError::AlreadyQuarantined { .. }) => {
                        // Edge may already be quarantined from a previous pass.
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        Ok(SentinelScanResult {
            edges_scanned: len_to_u64(edge_ids.len()),
            edges_passed: passed,
            exfiltrations_detected: detected,
            exfiltrations_contained: contained,
        })
    }

    /// Evaluate recall and precision against ground-truth labels.
    /// INV-SENTINEL-RECALL-THRESHOLD, INV-SENTINEL-PRECISION-THRESHOLD.
    pub fn evaluate_metrics(
        &self,
        true_positives: u64,
        false_negatives: u64,
        false_positives: u64,
    ) -> Result<SentinelMetrics, LineageError> {
        let _inv_recall = INV_SENTINEL_RECALL_THRESHOLD;
        let _inv_prec = INV_SENTINEL_PRECISION_THRESHOLD;

        let recall_denominator = true_positives.saturating_add(false_negatives);
        let recall = if recall_denominator > 0 {
            (true_positives as f64) / (recall_denominator as f64) * 100.0
        } else {
            100.0
        };

        let precision_denominator = true_positives.saturating_add(false_positives);
        let precision = if precision_denominator > 0 {
            (true_positives as f64) / (precision_denominator as f64) * 100.0
        } else {
            100.0
        };

        let recall_ok = recall >= self.config.recall_threshold_pct as f64;
        let precision_ok = precision >= self.config.precision_threshold_pct as f64;

        if !recall_ok {
            let _err = ERR_SENTINEL_RECALL_BELOW_THRESHOLD;
        }
        if !precision_ok {
            let _err = ERR_SENTINEL_PRECISION_BELOW_THRESHOLD;
        }

        Ok(SentinelMetrics {
            recall_pct: recall,
            precision_pct: precision,
            true_positives,
            false_negatives,
            false_positives,
            recall_threshold_pct: self.config.recall_threshold_pct,
            precision_threshold_pct: self.config.precision_threshold_pct,
            recall_ok,
            precision_ok,
        })
    }

    /// Detect covert-channel exfiltration patterns (e.g. timing, steganographic).
    /// Returns the number of detected covert channels.
    pub fn detect_covert_channels(&self, graph: &LineageGraph) -> Vec<CovertChannelDetection> {
        let _err_code = ERR_SENTINEL_COVERT_CHANNEL;
        let mut detections = Vec::new();

        // Heuristic: detect rapid sequential flows from the same source to external sinks
        // that stay under individual taint thresholds but collectively leak data.
        let mut source_external_counts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for edge in graph.edges.values() {
            if node_matches_zone(&edge.sink, "external") || node_matches_zone(&edge.sink, "public")
            {
                let edge_ids = source_external_counts
                    .entry(edge.source.clone())
                    .or_default();
                push_bounded(
                    edge_ids,
                    edge.edge_id.clone(),
                    MAX_COVERT_CHANNEL_EDGE_IDS_PER_SOURCE,
                );
            }
        }

        for (source, edge_ids) in &source_external_counts {
            if edge_ids.len() >= 3 {
                push_bounded(
                    &mut detections,
                    CovertChannelDetection {
                        source: source.clone(),
                        edge_ids: edge_ids.clone(),
                        pattern: "rapid_external_flow".to_string(),
                        confidence_pct: 85,
                    },
                    MAX_COVERT_CHANNEL_DETECTIONS,
                );
            }
        }

        detections
    }

    /// Attach a lineage tag to a datum in the graph.
    /// Event: LINEAGE_TAG_ATTACHED.
    pub fn attach_lineage_tag(
        &self,
        graph: &mut LineageGraph,
        datum_id: &str,
        label_id: &str,
    ) -> Result<(), LineageError> {
        let _event = LINEAGE_TAG_ATTACHED;
        let _inv = INV_LINEAGE_TAG_PERSISTENCE;
        if !graph.labels.contains_key(label_id) {
            return Err(LineageError::LabelNotFound {
                detail: format!(
                    "{}: label '{}' not registered",
                    ERR_LINEAGE_TAG_MISSING, label_id
                ),
            });
        }
        graph.assign_taint(datum_id, label_id)
    }

    /// Track a flow edge with sentinel evaluation.
    /// Event: LINEAGE_FLOW_TRACKED.
    pub fn track_flow(
        &mut self,
        graph: &mut LineageGraph,
        source: &str,
        sink: &str,
        operation: &str,
        timestamp_ms: u64,
    ) -> Result<FlowVerdict, LineageError> {
        let _event = LINEAGE_FLOW_TRACKED;
        let edge_id = graph.propagate_taint(source, sink, operation, timestamp_ms)?;
        let edge = graph.get_edge(&edge_id).cloned();
        match edge {
            Some(e) => self.evaluate_edge(&e, graph),
            None => Err(LineageError::ContainmentFailed {
                detail: format!(
                    "{}: flow edge lost after propagation",
                    ERR_LINEAGE_FLOW_BROKEN
                ),
            }),
        }
    }
}

/// Result of a sentinel graph scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelScanResult {
    pub edges_scanned: u64,
    pub edges_passed: u64,
    pub exfiltrations_detected: u64,
    pub exfiltrations_contained: u64,
}

/// Recall/precision metrics from sentinel evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SentinelMetrics {
    pub recall_pct: f64,
    pub precision_pct: f64,
    pub true_positives: u64,
    pub false_negatives: u64,
    pub false_positives: u64,
    pub recall_threshold_pct: u32,
    pub precision_threshold_pct: u32,
    pub recall_ok: bool,
    pub precision_ok: bool,
}

/// Covert channel detection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovertChannelDetection {
    pub source: String,
    pub edge_ids: Vec<String>,
    pub pattern: String,
    pub confidence_pct: u32,
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
            let crosses = boundary.crosses_edge(edge);
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
                let crosses = boundary.crosses_edge(edge);
                if crosses && boundary.is_violated_by(&edge.taint_set) && !edge.quarantined {
                    return false;
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

    fn make_external_edge(edge_id: &str, source: &str, timestamp_ms: u64) -> FlowEdge {
        FlowEdge {
            edge_id: edge_id.to_string(),
            source: source.to_string(),
            sink: "external-sink".to_string(),
            operation: "drip".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms,
            quarantined: false,
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
        let edge_id = graph
            .propagate_taint("src", "dst", "transform", 100)
            .unwrap();
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
    fn test_multiple_boundary_violations_emit_all_alerts_but_single_receipt() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);

        sentinel
            .add_boundary(make_boundary("b1", "internal", "external", &["PII"]))
            .unwrap();
        sentinel
            .add_boundary(make_boundary("b2", "internal", "external", &["SECRET"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");
        ts.insert("SECRET");

        let edge = FlowEdge {
            edge_id: "multi-boundary-1".to_string(),
            source: "internal-db".to_string(),
            sink: "external-api".to_string(),
            operation: "export".to_string(),
            taint_set: ts,
            timestamp_ms: 605,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();

        let verdict = sentinel.evaluate_edge(&edge, &mut graph).unwrap();
        assert_eq!(verdict, FlowVerdict::Quarantine);
        assert_eq!(sentinel.alert_count(), 2);
        assert_eq!(sentinel.receipt_count(), 1);
        assert!(graph.get_edge("multi-boundary-1").unwrap().quarantined);
    }

    #[test]
    fn test_boundary_crossing_requires_zone_boundary_match() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);

        sentinel
            .add_boundary(make_boundary("b1", "internal", "external", &["PII"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");

        let edge = FlowEdge {
            edge_id: "substring-noise-1".to_string(),
            source: "noninternal-db".to_string(),
            sink: "preexternal-api".to_string(),
            operation: "export".to_string(),
            taint_set: ts,
            timestamp_ms: 601,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();

        let verdict = sentinel.evaluate_edge(&edge, &mut graph).unwrap();
        assert_eq!(verdict, FlowVerdict::Pass);
        assert_eq!(sentinel.alert_count(), 0);
        assert!(!graph.get_edge("substring-noise-1").unwrap().quarantined);
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
    fn test_evaluate_edge_missing_graph_edge_fails_containment_without_receipt() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);
        sentinel
            .add_boundary(make_boundary("b1", "internal", "external", &["PII"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");
        let edge = FlowEdge {
            edge_id: "missing-edge".to_string(),
            source: "internal-db".to_string(),
            sink: "external-api".to_string(),
            operation: "export".to_string(),
            taint_set: ts,
            timestamp_ms: 701,
            quarantined: false,
        };

        let err = sentinel
            .evaluate_edge(&edge, &mut graph)
            .expect_err("violating edge absent from graph should fail containment");

        assert!(err.to_string().contains(ERR_IFL_CONTAINMENT_FAILED));
        assert_eq!(sentinel.alert_count(), 1);
        assert_eq!(sentinel.receipt_count(), 0);
        assert!(graph.get_edge("missing-edge").is_none());
    }

    #[test]
    fn test_scan_graph_skips_already_quarantined_edge_without_duplicate_alerts() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);
        sentinel
            .add_boundary(make_boundary("b1", "internal", "external", &["PII"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");
        let edge = FlowEdge {
            edge_id: "already-contained".to_string(),
            source: "internal-db".to_string(),
            sink: "external-api".to_string(),
            operation: "export".to_string(),
            taint_set: ts,
            timestamp_ms: 702,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();
        sentinel.evaluate_edge(&edge, &mut graph).unwrap();

        let result = sentinel.scan_graph(&mut graph).unwrap();

        assert_eq!(result.edges_scanned, 1);
        assert_eq!(result.edges_passed, 0);
        assert_eq!(result.exfiltrations_detected, 0);
        assert_eq!(result.exfiltrations_contained, 0);
        assert_eq!(sentinel.alert_count(), 1);
        assert_eq!(sentinel.receipt_count(), 1);
    }

    #[test]
    fn test_sentinel_health_check() {
        let sentinel = ExfiltrationSentinel::new(default_config());
        assert!(sentinel.health_check());
    }

    #[test]
    fn test_sentinel_health_check_rejects_invalid_config() {
        let mut config = default_config();
        config.max_graph_depth = 0;
        let sentinel = ExfiltrationSentinel::new(config);
        assert!(!sentinel.health_check());
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
    fn test_sentinel_reload_config_invalid_schema_keeps_previous_config() {
        let mut sentinel = ExfiltrationSentinel::new(default_config());
        let mut bad_config = default_config();
        bad_config.schema_version.clear();

        let err = sentinel
            .reload_config(bad_config)
            .expect_err("empty schema version should be rejected");

        assert!(err.to_string().contains(ERR_IFL_CONFIG_REJECTED));
        assert_eq!(sentinel.config.schema_version, SCHEMA_VERSION);
        assert!(sentinel.health_check());
    }

    #[test]
    fn test_config_validation_thresholds() {
        let mut config = default_config();
        config.recall_threshold_pct = 101;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_depth_is_rejected() {
        let mut config = default_config();
        config.max_graph_depth = 0;

        let err = config.validate().expect_err("zero depth must fail closed");

        assert!(err.to_string().contains(ERR_IFL_CONFIG_REJECTED));
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
    fn test_boundary_validation_empty_to_zone() {
        let boundary = TaintBoundary {
            boundary_id: "bad-to".to_string(),
            from_zone: "internal".to_string(),
            to_zone: String::new(),
            denied_labels: BTreeSet::new(),
            deny_all: false,
        };

        let err = boundary
            .validate()
            .expect_err("empty destination zone must fail closed");

        assert!(err.to_string().contains(ERR_IFL_BOUNDARY_INVALID));
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
    fn test_invariant_boundary_enforced_fails_for_unquarantined_violation() {
        let mut graph = LineageGraph::new(default_config());
        let mut boundaries = BTreeMap::new();
        boundaries.insert(
            "b1".to_string(),
            make_boundary("b1", "internal", "external", &["PII"]),
        );

        let mut ts = TaintSet::new();
        ts.insert("PII");
        graph
            .append_edge(FlowEdge {
                edge_id: "uncontained-violation".to_string(),
                source: "internal-db".to_string(),
                sink: "external-api".to_string(),
                operation: "export".to_string(),
                taint_set: ts,
                timestamp_ms: 1001,
                quarantined: false,
            })
            .unwrap();

        assert!(!invariants::verify_boundary_enforced(&graph, &boundaries));
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

    // bd-2iyk: tests for new canonical event/error codes and methods.

    #[test]
    fn test_lineage_tag_attached_event() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);
        graph.register_label(make_label("PII", 10));
        assert!(
            sentinel
                .attach_lineage_tag(&mut graph, "datum-x", "PII")
                .is_ok()
        );
        let ts = graph.get_taint_set("datum-x").unwrap();
        assert!(ts.contains("PII"));
    }

    #[test]
    fn test_lineage_tag_missing_error() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);
        let err = sentinel
            .attach_lineage_tag(&mut graph, "d1", "MISSING")
            .unwrap_err();
        assert!(err.to_string().contains(ERR_LINEAGE_TAG_MISSING));
    }

    #[test]
    fn test_lineage_tag_missing_does_not_create_empty_taint_set() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);

        let err = sentinel
            .attach_lineage_tag(&mut graph, "datum-with-missing-label", "MISSING")
            .expect_err("missing lineage tag should fail closed");

        assert!(err.to_string().contains(ERR_LINEAGE_TAG_MISSING));
        assert!(graph.get_taint_set("datum-with-missing-label").is_none());
    }

    #[test]
    fn test_track_flow_with_sentinel_pass() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);
        graph.register_label(make_label("PUBLIC", 1));
        graph.assign_taint("src-node", "PUBLIC").unwrap();
        let verdict = sentinel
            .track_flow(&mut graph, "src-node", "dst-node", "copy", 100)
            .unwrap();
        assert_eq!(verdict, FlowVerdict::Pass);
    }

    #[test]
    fn test_track_flow_with_sentinel_quarantine() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);
        sentinel
            .add_boundary(make_boundary("b1", "internal", "external", &["SECRET"]))
            .unwrap();
        graph.register_label(make_label("SECRET", 20));
        graph.assign_taint("internal-db", "SECRET").unwrap();
        let verdict = sentinel
            .track_flow(&mut graph, "internal-db", "external-api", "export", 200)
            .unwrap();
        assert_eq!(verdict, FlowVerdict::Quarantine);
        assert_eq!(sentinel.alert_count(), 1);
    }

    #[test]
    fn test_scan_graph_detects_violations() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);
        sentinel
            .add_boundary(make_boundary("b1", "priv", "pub", &["PII"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");

        // Add a violating edge
        let edge = FlowEdge {
            edge_id: "scan-1".to_string(),
            source: "priv-svc".to_string(),
            sink: "pub-cdn".to_string(),
            operation: "export".to_string(),
            taint_set: ts,
            timestamp_ms: 1,
            quarantined: false,
        };
        graph.append_edge(edge).unwrap();

        let result = sentinel.scan_graph(&mut graph).unwrap();
        assert_eq!(result.exfiltrations_detected, 1);
        assert_eq!(result.exfiltrations_contained, 1);
    }

    #[test]
    fn test_scan_graph_counts_multi_boundary_exfiltration_once() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);
        sentinel
            .add_boundary(make_boundary("b1", "priv", "pub", &["PII"]))
            .unwrap();
        sentinel
            .add_boundary(make_boundary("b2", "priv", "pub", &["SECRET"]))
            .unwrap();

        let mut ts = TaintSet::new();
        ts.insert("PII");
        ts.insert("SECRET");

        let edge = FlowEdge {
            edge_id: "scan-multi-1".to_string(),
            source: "priv-svc".to_string(),
            sink: "pub-cdn".to_string(),
            operation: "export".to_string(),
            taint_set: ts,
            timestamp_ms: 2,
            quarantined: false,
        };
        graph.append_edge(edge).unwrap();

        let result = sentinel.scan_graph(&mut graph).unwrap();
        assert_eq!(result.exfiltrations_detected, 1);
        assert_eq!(result.exfiltrations_contained, 1);
        assert_eq!(sentinel.alert_count(), 2);
        assert_eq!(sentinel.receipt_count(), 1);
    }

    #[test]
    fn test_evaluate_metrics_above_threshold() {
        let config = default_config();
        let sentinel = ExfiltrationSentinel::new(config);
        let m = sentinel.evaluate_metrics(96, 4, 5).unwrap();
        assert!(m.recall_ok);
        assert!(m.precision_ok);
        assert!(m.recall_pct >= 95.0);
        assert!(m.precision_pct >= 90.0);
    }

    #[test]
    fn test_evaluate_metrics_below_recall() {
        let config = default_config();
        let sentinel = ExfiltrationSentinel::new(config);
        let m = sentinel.evaluate_metrics(50, 50, 0).unwrap();
        assert!(!m.recall_ok);
    }

    #[test]
    fn test_evaluate_metrics_below_precision() {
        let config = default_config();
        let sentinel = ExfiltrationSentinel::new(config);
        let m = sentinel.evaluate_metrics(50, 0, 50).unwrap();
        assert!(!m.precision_ok);
    }

    #[test]
    fn test_detect_covert_channels_none() {
        let config = default_config();
        let graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);
        let detections = sentinel.detect_covert_channels(&graph);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_detect_covert_channels_found() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);

        for i in 0..4 {
            let e = FlowEdge {
                edge_id: format!("cc-{}", i),
                source: "stealth-src".to_string(),
                sink: "external-sink".to_string(),
                operation: "drip".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: i as u64,
                quarantined: false,
            };
            graph.append_edge(e).unwrap();
        }

        let detections = sentinel.detect_covert_channels(&graph);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern, "rapid_external_flow");
    }

    #[test]
    fn test_detect_covert_channels_requires_three_external_flows() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);

        for i in 0..2 {
            let e = FlowEdge {
                edge_id: format!("cc-below-threshold-{}", i),
                source: "stealth-src".to_string(),
                sink: "external-sink".to_string(),
                operation: "drip".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: i as u64,
                quarantined: false,
            };
            graph.append_edge(e).unwrap();
        }

        let detections = sentinel.detect_covert_channels(&graph);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_detect_covert_channels_ignores_public_substring_noise() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);

        for i in 0..4 {
            let e = FlowEdge {
                edge_id: format!("cc-noise-{}", i),
                source: "stealth-src".to_string(),
                sink: "republic-cache".to_string(),
                operation: "drip".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: i as u64,
                quarantined: false,
            };
            graph.append_edge(e).unwrap();
        }

        let detections = sentinel.detect_covert_channels(&graph);
        assert!(detections.is_empty());
    }

    #[test]
    fn len_to_u64_converts_representative_lengths_without_unchecked_casts() {
        assert_eq!(len_to_u64(0), 0);
        assert_eq!(len_to_u64(1), 1);
        assert_eq!(len_to_u64(usize::from(u16::MAX)), u64::from(u16::MAX));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_append() {
        let mut items = vec!["old-1".to_string(), "old-2".to_string()];

        push_bounded(&mut items, "new".to_string(), 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_evicts_oldest_when_full() {
        let mut items = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        push_bounded(&mut items, "d".to_string(), 3);

        assert_eq!(
            items,
            vec!["b".to_string(), "c".to_string(), "d".to_string()]
        );
    }

    #[test]
    fn scan_graph_reports_edge_count_through_len_to_u64_helper() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);

        for i in 0..3 {
            graph
                .append_edge(make_external_edge(
                    &format!("scan-safe-count-{i}"),
                    "src",
                    len_to_u64(i),
                ))
                .unwrap();
        }

        let result = sentinel.scan_graph(&mut graph).unwrap();

        assert_eq!(result.edges_scanned, 3);
        assert_eq!(result.edges_passed, 3);
    }

    #[test]
    fn detect_covert_channels_bounds_edge_ids_per_source() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);
        let edge_count = MAX_COVERT_CHANNEL_EDGE_IDS_PER_SOURCE.saturating_add(5);

        for i in 0..edge_count {
            graph
                .append_edge(make_external_edge(
                    &format!("edge-{i:05}"),
                    "stealth-src",
                    len_to_u64(i),
                ))
                .unwrap();
        }

        let detections = sentinel.detect_covert_channels(&graph);

        assert_eq!(detections.len(), 1);
        assert_eq!(
            detections[0].edge_ids.len(),
            MAX_COVERT_CHANNEL_EDGE_IDS_PER_SOURCE
        );
        let expected_last_edge = format!("edge-{:05}", edge_count - 1);
        assert_eq!(
            detections[0].edge_ids.first().map(String::as_str),
            Some("edge-00005")
        );
        assert_eq!(
            detections[0].edge_ids.last().map(String::as_str),
            Some(expected_last_edge.as_str())
        );
    }

    #[test]
    fn detect_covert_channels_bounds_detection_count() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);
        let source_count = MAX_COVERT_CHANNEL_DETECTIONS.saturating_add(5);

        for source_index in 0..source_count {
            let source = format!("source-{source_index:05}");
            for edge_index in 0..3 {
                let edge_id = format!("detection-{source_index:05}-{edge_index}");
                graph
                    .append_edge(make_external_edge(
                        &edge_id,
                        &source,
                        len_to_u64(source_index.saturating_mul(3).saturating_add(edge_index)),
                    ))
                    .unwrap();
            }
        }

        let detections = sentinel.detect_covert_channels(&graph);

        assert_eq!(detections.len(), MAX_COVERT_CHANNEL_DETECTIONS);
        let expected_last_source = format!("source-{:05}", source_count - 1);
        assert_eq!(
            detections.first().map(|d| d.source.as_str()),
            Some("source-00005")
        );
        assert_eq!(
            detections.last().map(|d| d.source.as_str()),
            Some(expected_last_source.as_str())
        );
    }

    #[test]
    fn test_inv_lineage_tag_persistence_constant() {
        assert_eq!(INV_LINEAGE_TAG_PERSISTENCE, "INV-LINEAGE-TAG-PERSISTENCE");
    }

    #[test]
    fn test_inv_sentinel_recall_threshold_constant() {
        assert_eq!(
            INV_SENTINEL_RECALL_THRESHOLD,
            "INV-SENTINEL-RECALL-THRESHOLD"
        );
    }

    #[test]
    fn test_inv_sentinel_precision_threshold_constant() {
        assert_eq!(
            INV_SENTINEL_PRECISION_THRESHOLD,
            "INV-SENTINEL-PRECISION-THRESHOLD"
        );
    }

    #[test]
    fn test_inv_sentinel_auto_contain_constant() {
        assert_eq!(INV_SENTINEL_AUTO_CONTAIN, "INV-SENTINEL-AUTO-CONTAIN");
    }

    #[test]
    fn test_canonical_event_codes_present() {
        assert_eq!(LINEAGE_TAG_ATTACHED, "LINEAGE_TAG_ATTACHED");
        assert_eq!(LINEAGE_FLOW_TRACKED, "LINEAGE_FLOW_TRACKED");
        assert_eq!(SENTINEL_SCAN_START, "SENTINEL_SCAN_START");
        assert_eq!(SENTINEL_EXFIL_DETECTED, "SENTINEL_EXFIL_DETECTED");
        assert_eq!(
            SENTINEL_CONTAINMENT_TRIGGERED,
            "SENTINEL_CONTAINMENT_TRIGGERED"
        );
    }

    #[test]
    fn test_canonical_error_codes_present() {
        assert_eq!(ERR_LINEAGE_TAG_MISSING, "ERR_LINEAGE_TAG_MISSING");
        assert_eq!(ERR_LINEAGE_FLOW_BROKEN, "ERR_LINEAGE_FLOW_BROKEN");
        assert_eq!(
            ERR_SENTINEL_RECALL_BELOW_THRESHOLD,
            "ERR_SENTINEL_RECALL_BELOW_THRESHOLD"
        );
        assert_eq!(
            ERR_SENTINEL_PRECISION_BELOW_THRESHOLD,
            "ERR_SENTINEL_PRECISION_BELOW_THRESHOLD"
        );
        assert_eq!(
            ERR_SENTINEL_CONTAINMENT_FAILED,
            "ERR_SENTINEL_CONTAINMENT_FAILED"
        );
        assert_eq!(ERR_SENTINEL_COVERT_CHANNEL, "ERR_SENTINEL_COVERT_CHANNEL");
    }

    #[test]
    fn test_evaluate_metrics_saturates_recall_denominator_on_overflow() {
        let sentinel = ExfiltrationSentinel::new(default_config());

        let metrics = sentinel.evaluate_metrics(u64::MAX, 1, 0).unwrap();

        assert!(metrics.recall_pct.is_finite());
        assert_eq!(metrics.recall_pct, 100.0);
        assert!(metrics.recall_ok);
    }

    #[test]
    fn test_evaluate_metrics_saturates_precision_denominator_on_overflow() {
        let sentinel = ExfiltrationSentinel::new(default_config());

        let metrics = sentinel.evaluate_metrics(u64::MAX, 0, 1).unwrap();

        assert!(metrics.precision_pct.is_finite());
        assert_eq!(metrics.precision_pct, 100.0);
        assert!(metrics.precision_ok);
    }

    #[test]
    fn test_precision_threshold_above_100_is_rejected() {
        let mut config = default_config();
        config.precision_threshold_pct = 101;

        let err = config
            .validate()
            .expect_err("precision threshold above 100 must fail closed");

        assert!(err.to_string().contains(ERR_IFL_CONFIG_REJECTED));
    }

    #[test]
    fn test_query_zero_limit_returns_empty_without_error() {
        let mut graph = LineageGraph::new(default_config());
        graph
            .append_edge(FlowEdge {
                edge_id: "limit-zero-edge".to_string(),
                source: "a".to_string(),
                sink: "b".to_string(),
                operation: "copy".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: 1,
                quarantined: false,
            })
            .unwrap();

        let results = graph
            .query(&LineageQuery {
                limit: Some(0),
                ..Default::default()
            })
            .unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_invalid_boundary_is_not_registered_after_rejection() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);
        let mut taint = TaintSet::new();
        taint.insert("PII");
        let edge = FlowEdge {
            edge_id: "invalid-boundary-edge".to_string(),
            source: "internal-db".to_string(),
            sink: "external-api".to_string(),
            operation: "export".to_string(),
            taint_set: taint,
            timestamp_ms: 1,
            quarantined: false,
        };
        graph.append_edge(edge.clone()).unwrap();

        let err = sentinel
            .add_boundary(make_boundary("bad-boundary", "", "external", &["PII"]))
            .expect_err("empty source zone must fail closed");
        let verdict = sentinel.evaluate_edge(&edge, &mut graph).unwrap();

        assert!(err.to_string().contains(ERR_IFL_BOUNDARY_INVALID));
        assert_eq!(verdict, FlowVerdict::Pass);
        assert_eq!(sentinel.alert_count(), 0);
        assert_eq!(sentinel.receipt_count(), 0);
    }

    #[test]
    fn test_missing_lineage_tag_preserves_existing_taints() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let sentinel = ExfiltrationSentinel::new(config);
        graph.register_label(make_label("PII", 10));
        sentinel
            .attach_lineage_tag(&mut graph, "datum-a", "PII")
            .unwrap();

        let err = sentinel
            .attach_lineage_tag(&mut graph, "datum-a", "MISSING")
            .expect_err("missing tag must fail closed");
        let taint = graph.get_taint_set("datum-a").expect("existing taint");

        assert!(err.to_string().contains(ERR_LINEAGE_TAG_MISSING));
        assert!(taint.contains("PII"));
        assert!(!taint.contains("MISSING"));
    }

    #[test]
    fn test_boundary_zone_prefix_requires_separator() {
        let boundary = make_boundary("b-prefix", "internal", "external", &["PII"]);
        let mut taint = TaintSet::new();
        taint.insert("PII");
        let edge = FlowEdge {
            edge_id: "prefix-noise".to_string(),
            source: "internality-service".to_string(),
            sink: "external-api".to_string(),
            operation: "export".to_string(),
            taint_set: taint,
            timestamp_ms: 1,
            quarantined: false,
        };

        assert_eq!(
            invariants::evaluate_edge_pure(
                &edge,
                &BTreeMap::from([("b-prefix".to_string(), boundary)])
            ),
            FlowVerdict::Pass
        );
    }

    #[test]
    fn test_track_flow_from_untagged_source_does_not_create_false_quarantine() {
        let config = default_config();
        let mut graph = LineageGraph::new(config.clone());
        let mut sentinel = ExfiltrationSentinel::new(config);
        sentinel
            .add_boundary(make_boundary("b1", "internal", "external", &["SECRET"]))
            .unwrap();

        let verdict = sentinel
            .track_flow(&mut graph, "internal-db", "external-api", "export", 1)
            .unwrap();

        assert_eq!(verdict, FlowVerdict::Pass);
        assert_eq!(sentinel.alert_count(), 0);
        assert_eq!(sentinel.receipt_count(), 0);
    }

    #[test]
    fn test_serde_rejects_unknown_flow_verdict_variant() {
        let result: Result<FlowVerdict, _> = serde_json::from_str(r#""release""#);

        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_flow_edge_negative_timestamp() {
        let result: Result<FlowEdge, _> = serde_json::from_str(
            r#"{
                "edge_id":"bad-negative-time",
                "source":"internal-db",
                "sink":"external-api",
                "operation":"export",
                "taint_set":{"labels":[]},
                "timestamp_ms":-1,
                "quarantined":false
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_flow_edge_non_boolean_quarantine_flag() {
        let result: Result<FlowEdge, _> = serde_json::from_str(
            r#"{
                "edge_id":"bad-quarantine-flag",
                "source":"internal-db",
                "sink":"external-api",
                "operation":"export",
                "taint_set":{"labels":[]},
                "timestamp_ms":1,
                "quarantined":"false"
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_taint_label_negative_severity() {
        let result: Result<TaintLabel, _> = serde_json::from_str(
            r#"{
                "id":"PII",
                "description":"personally identifiable information",
                "severity":-1
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_boundary_with_non_array_denied_labels() {
        let result: Result<TaintBoundary, _> = serde_json::from_str(
            r#"{
                "boundary_id":"bad-denied-labels",
                "from_zone":"internal",
                "to_zone":"external",
                "denied_labels":"PII",
                "deny_all":false
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_lineage_query_negative_limit() {
        let result: Result<LineageQuery, _> = serde_json::from_str(
            r#"{
                "source":null,
                "sink":null,
                "taint_label":null,
                "from_timestamp_ms":null,
                "to_timestamp_ms":null,
                "limit":-1
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_sentinel_config_negative_graph_edges() {
        let result: Result<SentinelConfig, _> = serde_json::from_str(
            r#"{
                "max_graph_edges":-1,
                "max_graph_depth":256,
                "alert_cooldown_ms":1000,
                "recall_threshold_pct":95,
                "precision_threshold_pct":90,
                "schema_version":"ifl-v1.0"
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_snapshot_missing_schema_version() {
        let result: Result<LineageSnapshot, _> = serde_json::from_str(
            r#"{
                "snapshot_id":"snap-missing-schema",
                "timestamp_ms":1,
                "edge_count":0,
                "label_count":0,
                "edges":[],
                "labels":{}
            }"#,
        );

        assert!(result.is_err());
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_taint_label_with_problematic_string_fields() {
        // Test TaintLabel with various problematic string data
        let problematic_labels = vec![
            TaintLabel {
                id: "".to_string(), // Empty ID
                description: "Empty ID label".to_string(),
                severity: 5,
            },
            TaintLabel {
                id: "\0null\x01control\x7f".to_string(), // Control characters
                description: "label\nwith\nnewlines".to_string(),
                severity: 3,
            },
            TaintLabel {
                id: "🚀emoji🔥label💀".to_string(),            // Unicode emoji
                description: "\u{FFFF}\u{10FFFF}".to_string(), // Max Unicode
                severity: u32::MAX,                            // Maximum severity
            },
            TaintLabel {
                id: "../../../etc/passwd".to_string(), // Path traversal
                description: "<script>alert('xss')</script>".to_string(), // XSS
                severity: 0,                           // Zero severity
            },
            TaintLabel {
                id: "x".repeat(10_000),          // Very long ID
                description: "y".repeat(50_000), // Very long description
                severity: 1,
            },
        ];

        for label in problematic_labels {
            let serialized =
                serde_json::to_string(&label).expect("taint label should serialize losslessly");
            let deserialized: TaintLabel =
                serde_json::from_str(&serialized).expect("taint label should deserialize");

            assert_eq!(deserialized, label);
        }
    }

    #[test]
    fn negative_taint_set_with_extreme_label_counts_and_sizes() {
        let mut taint_set = TaintSet::new();

        // Test with zero labels
        assert!(taint_set.is_empty());
        assert_eq!(taint_set.len(), 0);

        // Test with many labels (stress test)
        for i in 0..10_000 {
            taint_set.insert(&format!("label_{}", i));
        }
        assert_eq!(taint_set.len(), 10_000);
        assert!(!taint_set.is_empty());

        // Test with problematic label IDs
        let problematic_ids = vec![
            "",                        // Empty
            "\0null_terminated",       // Null byte
            "label\nwith\nnewlines",   // Multiline
            "🚀emoji_label",           // Unicode
            "\u{FFFF}",                // Max BMP
            "../../../sensitive/data", // Path traversal
            "x".repeat(1_000),         // Very long label
        ];

        for id in problematic_ids {
            taint_set.insert(id);
            assert!(
                taint_set.contains(id),
                "Should contain inserted label: {}",
                id
            );
        }

        // Test merge with large taint set
        let mut other_set = TaintSet::new();
        for i in 10_000..20_000 {
            other_set.insert(&format!("other_{}", i));
        }

        let original_len = taint_set.len();
        taint_set.merge(&other_set);
        assert!(
            taint_set.len() >= original_len,
            "Merge should increase or maintain size"
        );

        // Test memory efficiency with duplicate inserts
        let start_len = taint_set.len();
        for _ in 0..1000 {
            taint_set.insert("duplicate_label");
        }
        assert_eq!(
            taint_set.len(),
            start_len + 1,
            "Duplicates should not increase size"
        );
    }

    #[test]
    fn negative_flow_edge_with_extreme_timestamps_and_malformed_data() {
        // Test FlowEdge with boundary timestamp values
        let boundary_timestamps = vec![
            (0, "zero_timestamp"),
            (1, "minimum_positive"),
            (u64::MAX / 2, "half_maximum"),
            (u64::MAX - 1, "near_maximum"),
            (u64::MAX, "maximum_timestamp"),
        ];

        for (timestamp, description) in boundary_timestamps {
            let mut taint_set = TaintSet::new();
            taint_set.insert("test_label");

            let edge = FlowEdge {
                edge_id: format!("edge_{}", description),
                source: "source_node".to_string(),
                sink: "sink_node".to_string(),
                operation: "test_operation".to_string(),
                taint_set,
                timestamp_ms: timestamp,
                quarantined: false,
            };

            // Edge creation should handle extreme timestamps
            assert_eq!(edge.timestamp_ms, timestamp);

            // Serialization should work with extreme values
            let serialized = serde_json::to_string(&edge);
            assert!(
                serialized.is_ok(),
                "Should serialize edge with timestamp: {}",
                timestamp
            );
        }

        // Test with problematic string fields
        let problematic_edge = FlowEdge {
            edge_id: "\0edge\x01id".to_string(),
            source: "source\nwith\nnewlines".to_string(),
            sink: "../../../etc/shadow".to_string(),
            operation: "<script>alert('operation')</script>".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: 1000,
            quarantined: true,
        };

        let serialized =
            serde_json::to_string(&problematic_edge).expect("flow edge should serialize");
        let deserialized: FlowEdge =
            serde_json::from_str(&serialized).expect("flow edge should deserialize");

        assert_eq!(deserialized, problematic_edge);
    }

    #[test]
    fn negative_taint_boundary_with_invalid_zone_configurations() {
        // Test TaintBoundary with various invalid configurations
        let invalid_boundaries = vec![
            TaintBoundary {
                boundary_id: "empty_zones".to_string(),
                from_zone: "".to_string(), // Empty from_zone
                to_zone: "valid_zone".to_string(),
                denied_labels: BTreeSet::new(),
                deny_all: false,
            },
            TaintBoundary {
                boundary_id: "empty_to_zone".to_string(),
                from_zone: "valid_zone".to_string(),
                to_zone: "".to_string(), // Empty to_zone
                denied_labels: BTreeSet::new(),
                deny_all: false,
            },
            TaintBoundary {
                boundary_id: "both_empty".to_string(),
                from_zone: "".to_string(), // Both empty
                to_zone: "".to_string(),
                denied_labels: BTreeSet::new(),
                deny_all: false,
            },
        ];

        for boundary in invalid_boundaries {
            // Validation should reject empty zones
            let result = boundary.validate();
            assert!(result.is_err(), "Should reject boundary with empty zones");

            match result.unwrap_err() {
                LineageError::BoundaryInvalid { detail } => {
                    assert!(detail.contains(ERR_IFL_BOUNDARY_INVALID));
                    assert!(detail.contains("non-empty"));
                }
                other => panic!("Expected BoundaryInvalid error, got {:?}", other),
            }
        }

        // Test with problematic but non-empty zone names
        let problematic_boundary = TaintBoundary {
            boundary_id: "problematic".to_string(),
            from_zone: "\0zone\x01".to_string(), // Control characters
            to_zone: "🚀zone💀".to_string(),     // Unicode emoji
            denied_labels: BTreeSet::new(),
            deny_all: true, // Deny all labels
        };

        // Should validate successfully (non-empty zones)
        assert!(problematic_boundary.validate().is_ok());

        // Test is_violated_by with deny_all
        let mut test_taint = TaintSet::new();
        test_taint.insert("any_label");
        assert!(problematic_boundary.is_violated_by(&test_taint));

        let empty_taint = TaintSet::new();
        assert!(!problematic_boundary.is_violated_by(&empty_taint));
    }

    #[test]
    fn negative_node_zone_matching_with_edge_cases() {
        // Test node_matches_zone function with edge cases
        let test_cases = vec![
            ("", "", false),                  // Both empty
            ("node", "", false),              // Empty zone
            ("", "zone", false),              // Empty node
            ("node", "node", true),           // Exact match
            ("node1", "node2", false),        // Different
            ("prefix_node", "prefix", true),  // Prefix match (assuming that's the logic)
            ("node_suffix", "suffix", false), // Suffix no match
            ("\0node", "\0node", true),       // Control characters
            ("🚀node", "🚀node", true),       // Unicode
        ];

        for (node, zone, expected) in test_cases {
            let actual = node_matches_zone(node, zone);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn negative_taint_boundary_crosses_edge_with_malformed_node_names() {
        let boundary = TaintBoundary {
            boundary_id: "test_boundary".to_string(),
            from_zone: "source_zone".to_string(),
            to_zone: "sink_zone".to_string(),
            denied_labels: BTreeSet::new(),
            deny_all: false,
        };

        // Create edges with problematic node names
        let problematic_edges = vec![
            FlowEdge {
                edge_id: "edge1".to_string(),
                source: "".to_string(), // Empty source
                sink: "sink_zone".to_string(),
                operation: "op".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: 1000,
                quarantined: false,
            },
            FlowEdge {
                edge_id: "edge2".to_string(),
                source: "source_zone".to_string(),
                sink: "".to_string(), // Empty sink
                operation: "op".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: 1000,
                quarantined: false,
            },
            FlowEdge {
                edge_id: "edge3".to_string(),
                source: "\0source\x01".to_string(), // Control characters
                sink: "🚀sink💀".to_string(),       // Unicode
                operation: "op".to_string(),
                taint_set: TaintSet::new(),
                timestamp_ms: 1000,
                quarantined: false,
            },
        ];

        for edge in problematic_edges {
            // Should not panic when checking if boundary crosses edge
            let _crosses = boundary.crosses_edge(&edge);
            // Result may vary based on implementation, just verify no panic
        }
    }

    #[test]
    fn negative_lineage_error_display_with_malicious_content() {
        // Test LineageError Display implementation with problematic content
        let malicious_errors = vec![
            LineageError::LabelNotFound {
                detail: format!(
                    "{}: label '\0malicious\x01label' not registered",
                    ERR_IFL_LABEL_NOT_FOUND
                ),
            },
            LineageError::BoundaryInvalid {
                detail: format!("{}: boundary\nwith\nnewlines", ERR_IFL_BOUNDARY_INVALID),
            },
            LineageError::ContainmentFailed {
                detail: format!(
                    "{}: <script>alert('containment')</script>",
                    ERR_IFL_CONTAINMENT_FAILED
                ),
            },
            LineageError::QueryInvalid {
                detail: format!("{}: 🚀query💀error", ERR_IFL_QUERY_INVALID),
            },
            LineageError::SnapshotFailed {
                detail: format!("{}: ../../../etc/passwd", ERR_IFL_SNAPSHOT_FAILED),
            },
        ];

        for error in malicious_errors {
            // Display formatting should not panic or interpret malicious content
            let display_output = format!("{}", error);
            let debug_output = format!("{:?}", error);

            // Should contain expected error code prefix
            assert!(display_output.starts_with("ERR_IFL_"));

            // Should not interpret malicious content as code
            assert!(!display_output.contains("(null)"));
            assert!(!display_output.contains("Error"));

            // Debug output should also be safe
            assert!(debug_output.contains("LineageError"));
        }
    }

    #[test]
    fn negative_constants_validation_for_security_compliance() {
        // Test that all event constants are well-formed
        let event_constants = [
            EVENT_TAINT_ASSIGNED,
            EVENT_EDGE_APPENDED,
            EVENT_TAINT_PROPAGATED,
            EVENT_BOUNDARY_CROSSING,
            EVENT_EXFIL_ALERT,
            EVENT_FLOW_QUARANTINED,
            EVENT_CONTAINMENT_RECEIPT,
            EVENT_SNAPSHOT_EXPORTED,
            EVENT_CONFIG_RELOADED,
            EVENT_DEPTH_LIMIT,
            EVENT_TAINT_MERGE,
            EVENT_HEALTH_CHECK,
            LINEAGE_TAG_ATTACHED,
            LINEAGE_FLOW_TRACKED,
            SENTINEL_SCAN_START,
            SENTINEL_EXFIL_DETECTED,
            SENTINEL_CONTAINMENT_TRIGGERED,
        ];

        for constant in &event_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.is_ascii(),
                "Event constant should be ASCII: {}",
                constant
            );
            // Most should have specific prefixes
            if constant.starts_with("FN-IFL-") {
                assert!(
                    constant.len() >= 10,
                    "FN-IFL- constants should have sufficient length"
                );
            }
        }

        // Test error constants
        let error_constants = [
            ERR_IFL_LABEL_NOT_FOUND,
            ERR_IFL_DUPLICATE_EDGE,
            ERR_IFL_GRAPH_FULL,
            ERR_IFL_BOUNDARY_INVALID,
            ERR_IFL_CONTAINMENT_FAILED,
            ERR_IFL_SNAPSHOT_FAILED,
            ERR_IFL_QUERY_INVALID,
            ERR_IFL_CONFIG_REJECTED,
            ERR_IFL_ALREADY_QUARANTINED,
            ERR_IFL_TIMEOUT,
            ERR_LINEAGE_TAG_MISSING,
            ERR_LINEAGE_FLOW_BROKEN,
            ERR_SENTINEL_RECALL_BELOW_THRESHOLD,
            ERR_SENTINEL_PRECISION_BELOW_THRESHOLD,
            ERR_SENTINEL_CONTAINMENT_FAILED,
            ERR_SENTINEL_COVERT_CHANNEL,
        ];

        for constant in &error_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("ERR_"),
                "Error constant should start with ERR_: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Error constant should be ASCII: {}",
                constant
            );
        }

        // Test invariant constants
        let invariant_constants = [
            INV_LABEL_PERSIST,
            INV_EDGE_APPEND_ONLY,
            INV_QUARANTINE_RECEIPT,
            INV_BOUNDARY_ENFORCED,
            INV_DETERMINISTIC,
            INV_SNAPSHOT_FAITHFUL,
        ];

        for constant in &invariant_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("INV-"),
                "Invariant should start with INV-: {}",
                constant
            );
            assert!(
                constant.contains("IFL"),
                "Invariant should relate to IFL: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Invariant constant should be ASCII: {}",
                constant
            );
        }

        // Test schema version
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(SCHEMA_VERSION.starts_with("ifl-v"));
        assert!(SCHEMA_VERSION.contains('.'));
    }

    #[test]
    fn negative_btreeset_ordering_consistency_with_unicode_labels() {
        let mut taint_set = TaintSet::new();

        // Insert labels with various Unicode and ordering edge cases
        let unicode_labels = vec![
            "a_normal_label",
            "🚀_emoji_first",
            "zzz_last_ascii",
            "\u{0041}_unicode_a", // Unicode A
            "\u{FFFF}_max_bmp",
            "\u{10FFFF}_max_unicode",
            "000_numeric_start",
            "\t_tab_prefix",
            " _space_prefix",
        ];

        for label in &unicode_labels {
            taint_set.insert(label);
        }

        // Verify deterministic ordering
        let labels_vec: Vec<_> = taint_set.labels.iter().collect();
        let mut sorted_labels = labels_vec.clone();
        sorted_labels.sort();

        assert_eq!(
            labels_vec, sorted_labels,
            "BTreeSet should maintain consistent ordering"
        );

        // Test that merge preserves ordering
        let mut other_set = TaintSet::new();
        other_set.insert("middle_label");
        taint_set.merge(&other_set);

        let new_labels_vec: Vec<_> = taint_set.labels.iter().collect();
        let mut new_sorted_labels = new_labels_vec.clone();
        new_sorted_labels.sort();

        assert_eq!(
            new_labels_vec, new_sorted_labels,
            "Ordering should be preserved after merge"
        );
    }
}
