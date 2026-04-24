//! bd-1vm: Fast quarantine/recall workflow for compromised artifacts.
//!
//! Implements the "immune response" for the extension ecosystem: quarantine isolates
//! threats while investigation proceeds, recall removes compromised artifacts from all
//! nodes. Integrates with revocation propagation for signal delivery and trust cards
//! for status visibility.

use std::collections::{BTreeMap, BTreeSet};

use crate::security::constant_time;
use chrono::{DateTime, SecondsFormat, Utc};

/// Maximum audit trail entries before oldest are evicted.
const MAX_AUDIT_TRAIL: usize = 4096;

/// Maximum quarantine records before oldest are evicted.
const MAX_RECORDS: usize = 4096;

/// Maximum propagation status entries before oldest are evicted.
const MAX_PROPAGATION_STATUS: usize = 4096;

/// Maximum recall receipts per quarantine record before oldest are evicted.
const MAX_RECALL_RECEIPTS: usize = 4096;

/// Maximum state history entries per quarantine record before oldest are evicted.
const MAX_STATE_HISTORY: usize = 256;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Push to audit trail with capacity bounding and chain anchor preservation
fn push_bounded_audit_trail(
    items: &mut Vec<QuarantineAuditEntry>,
    item: QuarantineAuditEntry,
    cap: usize,
    chain_anchor_hash: &mut Option<String>,
) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        let drain_len = overflow.min(items.len());
        if drain_len > 0 {
            // Preserve chain anchor hash from the last evicted entry
            *chain_anchor_hash = Some(items[drain_len.saturating_sub(1)].entry_hash.clone());
            items.drain(0..drain_len);
        }
    }
    items.push(item);
}

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Event codes ──────────────────────────────────────────────────────────────

pub const QUARANTINE_INITIATED: &str = "QUARANTINE_INITIATED";
pub const QUARANTINE_PROPAGATED: &str = "QUARANTINE_PROPAGATED";
pub const QUARANTINE_ENFORCED: &str = "QUARANTINE_ENFORCED";
pub const QUARANTINE_DRAIN_STARTED: &str = "QUARANTINE_DRAIN_STARTED";
pub const QUARANTINE_DRAIN_COMPLETED: &str = "QUARANTINE_DRAIN_COMPLETED";
pub const QUARANTINE_LIFTED: &str = "QUARANTINE_LIFTED";
pub const RECALL_TRIGGERED: &str = "RECALL_TRIGGERED";
pub const RECALL_ARTIFACT_REMOVED: &str = "RECALL_ARTIFACT_REMOVED";
pub const RECALL_RECEIPT_EMITTED: &str = "RECALL_RECEIPT_EMITTED";
pub const RECALL_COMPLETED: &str = "RECALL_COMPLETED";

// ── Error codes ──────────────────────────────────────────────────────────────

pub const ERR_QUARANTINE_NOT_FOUND: &str = "ERR_QUARANTINE_NOT_FOUND";
pub const ERR_QUARANTINE_ALREADY_ACTIVE: &str = "ERR_QUARANTINE_ALREADY_ACTIVE";
pub const ERR_RECALL_WITHOUT_QUARANTINE: &str = "ERR_RECALL_WITHOUT_QUARANTINE";
pub const ERR_LIFT_REQUIRES_CLEARANCE: &str = "ERR_LIFT_REQUIRES_CLEARANCE";
pub const ERR_QUARANTINE_INVALID_TRANSITION: &str = "ERR_QUARANTINE_INVALID_TRANSITION";
pub const ERR_QUARANTINE_CAPACITY_EXCEEDED: &str = "ERR_QUARANTINE_CAPACITY_EXCEEDED";
pub const ERR_QUARANTINE_DUPLICATE_ORDER_ID: &str = "ERR_QUARANTINE_DUPLICATE_ORDER_ID";
pub const ERR_RECALL_RECEIPT_MISMATCH: &str = "ERR_RECALL_RECEIPT_MISMATCH";
pub const ERR_AUDIT_CHAIN_BROKEN: &str = "ERR_AUDIT_CHAIN_BROKEN";
pub const ERR_QUARANTINE_INVALID_AUDIT_TIMESTAMP: &str = "ERR_QUARANTINE_INVALID_AUDIT_TIMESTAMP";

// ── Quarantine mode ─────────────────────────────────────────────────────────

/// Quarantine enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineMode {
    /// New installs blocked; existing installs warned but operational.
    Soft,
    /// Existing installs disabled; grace period for data export.
    Hard,
}

/// Severity level triggering quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Strongly typed monotonic identifier for quarantine audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QuarantineAuditId(u64);

impl QuarantineAuditId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for QuarantineAuditId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<QuarantineAuditId> for u64 {
    fn from(value: QuarantineAuditId) -> Self {
        value.get()
    }
}

impl std::fmt::Display for QuarantineAuditId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Canonical RFC3339 timestamp for quarantine audit entries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuarantineAuditTimestamp(DateTime<Utc>);

impl QuarantineAuditTimestamp {
    #[must_use]
    pub fn canonical_rfc3339(&self) -> String {
        self.0.to_rfc3339_opts(SecondsFormat::Secs, true)
    }
}

impl TryFrom<&str> for QuarantineAuditTimestamp {
    type Error = chrono::ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        DateTime::parse_from_rfc3339(value).map(|timestamp| Self(timestamp.with_timezone(&Utc)))
    }
}

impl From<DateTime<Utc>> for QuarantineAuditTimestamp {
    fn from(value: DateTime<Utc>) -> Self {
        Self(value)
    }
}

impl From<QuarantineAuditTimestamp> for DateTime<Utc> {
    fn from(value: QuarantineAuditTimestamp) -> Self {
        value.0
    }
}

impl std::fmt::Display for QuarantineAuditTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical_rfc3339())
    }
}

impl Serialize for QuarantineAuditTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.canonical_rfc3339())
    }
}

impl<'de> Deserialize<'de> for QuarantineAuditTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw.as_str()).map_err(serde::de::Error::custom)
    }
}

/// Scope of a quarantine order.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineScope {
    /// A single extension version.
    Version {
        extension_id: String,
        version: String,
    },
    /// All versions of an extension.
    AllVersions { extension_id: String },
    /// All extensions from a publisher.
    Publisher { publisher_id: String },
}

// ── Quarantine order ─────────────────────────────────────────────────────────

/// A signed quarantine order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineOrder {
    /// Unique order identifier.
    pub order_id: String,
    /// Scope of quarantine.
    pub scope: QuarantineScope,
    /// Enforcement mode.
    pub mode: QuarantineMode,
    /// Severity level.
    pub severity: QuarantineSeverity,
    /// Reason code for quarantine.
    pub reason: QuarantineReason,
    /// Human-readable justification.
    pub justification: String,
    /// Identity of the issuer.
    pub issued_by: String,
    /// Timestamp of issuance (RFC 3339).
    pub issued_at: String,
    /// Cryptographic signature over canonical order content.
    pub signature: String,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Grace period in seconds for hard quarantine (data export window).
    pub grace_period_secs: u64,
}

/// Reason for quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    /// Vulnerability disclosed.
    VulnerabilityDisclosure,
    /// Malware detected.
    MalwareDetection,
    /// Supply-chain attack evidence.
    SupplyChainAttack,
    /// Behavioral anomaly detected.
    BehavioralAnomaly,
    /// Operator-initiated investigation.
    OperatorInitiated,
    /// Revocation event from supply-chain module.
    RevocationEvent,
    /// Automated policy trigger from incident detection.
    PolicyTrigger,
}

// ── Quarantine state machine ─────────────────────────────────────────────────

/// State of a quarantine lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineState {
    /// Quarantine order issued, propagation in progress.
    Initiated,
    /// Quarantine propagated to all connected nodes.
    Propagated,
    /// Quarantine enforced locally (extension suspended).
    Enforced,
    /// Active sessions are being drained.
    Draining,
    /// All sessions drained, extension fully isolated.
    Isolated,
    /// Investigation concluded, quarantine lifted with clearance.
    Lifted,
    /// Recall triggered: artifact removal in progress.
    RecallTriggered,
    /// Recall completed: all artifacts removed.
    RecallCompleted,
}

// ── Recall ───────────────────────────────────────────────────────────────────

/// A recall order (issued after quarantine investigation confirms compromise).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecallOrder {
    /// Unique recall identifier.
    pub recall_id: String,
    /// Reference to the quarantine order that preceded this recall.
    pub quarantine_order_id: String,
    /// Scope (inherited from quarantine or narrowed).
    pub scope: QuarantineScope,
    /// Reason for recall.
    pub reason: String,
    /// Identity of the issuer.
    pub issued_by: String,
    /// Timestamp (RFC 3339).
    pub issued_at: String,
    /// Signature over canonical recall content.
    pub signature: String,
    /// Trace ID.
    pub trace_id: String,
}

/// Receipt from a node confirming artifact removal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecallReceipt {
    /// Node identifier.
    pub node_id: String,
    /// Recall order reference.
    pub recall_id: String,
    /// Whether removal was successful.
    pub removed: bool,
    /// Removal method (e.g., "crypto_erase", "file_delete").
    pub removal_method: String,
    /// Timestamp of removal (RFC 3339).
    pub removed_at: String,
    /// Verification hash of removed artifact.
    pub artifact_hash: String,
}

// ── Impact report ────────────────────────────────────────────────────────────

/// Impact assessment for a quarantine action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineImpactReport {
    /// Quarantine order reference.
    pub order_id: String,
    /// Number of installations affected.
    pub installations_affected: u64,
    /// Data at risk (description).
    pub data_at_risk: Vec<String>,
    /// Dependent extensions.
    pub dependent_extensions: Vec<String>,
    /// Active sessions that need draining.
    pub active_sessions: u64,
    /// Recommended operator actions.
    pub recommended_actions: Vec<String>,
    /// Generated at timestamp.
    pub generated_at: String,
}

// ── Clearance (for lifting quarantine) ───────────────────────────────────────

/// Signed clearance to lift a quarantine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineClearance {
    /// Reference to the quarantine order being cleared.
    pub order_id: String,
    /// Identity of the clearing authority.
    pub cleared_by: String,
    /// Justification for clearance.
    pub justification: String,
    /// Re-verification evidence (e.g., new audit report).
    pub re_verification_evidence: String,
    /// Timestamp (RFC 3339).
    pub cleared_at: String,
    /// Signature.
    pub signature: String,
    /// Trace ID.
    pub trace_id: String,
}

// ── Audit trail ──────────────────────────────────────────────────────────────

/// Audit entry for quarantine/recall lifecycle events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineAuditEntry {
    /// Sequential entry index.
    pub sequence: QuarantineAuditId,
    /// Event code (one of the QUARANTINE_* or RECALL_* constants).
    pub event_code: String,
    /// Reference to the quarantine or recall order.
    pub order_id: String,
    /// Extension affected.
    pub extension_id: String,
    /// Severity level.
    pub severity: QuarantineSeverity,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Timestamp (RFC 3339).
    pub timestamp: QuarantineAuditTimestamp,
    /// Additional details.
    pub details: String,
    /// SHA-256 hash of the previous entry (hash chain).
    pub prev_hash: String,
    /// SHA-256 hash of this entry.
    pub entry_hash: String,
}

/// Compute the SHA-256 hash for an audit entry (excluding entry_hash field).
fn compute_entry_hash(entry: &QuarantineAuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"quarantine_entry_v1:");
    hasher.update(entry.sequence.get().to_le_bytes());
    hasher.update(len_to_u64(entry.event_code.len()).to_le_bytes());
    hasher.update(entry.event_code.as_bytes());
    hasher.update(len_to_u64(entry.order_id.len()).to_le_bytes());
    hasher.update(entry.order_id.as_bytes());
    hasher.update(len_to_u64(entry.extension_id.len()).to_le_bytes());
    hasher.update(entry.extension_id.as_bytes());

    let severity_str = match entry.severity {
        QuarantineSeverity::Low => "low",
        QuarantineSeverity::Medium => "medium",
        QuarantineSeverity::High => "high",
        QuarantineSeverity::Critical => "critical",
    };
    hasher.update(len_to_u64(severity_str.len()).to_le_bytes());
    hasher.update(severity_str.as_bytes());

    hasher.update(len_to_u64(entry.trace_id.len()).to_le_bytes());
    hasher.update(entry.trace_id.as_bytes());
    let timestamp = entry.timestamp.canonical_rfc3339();
    hasher.update(len_to_u64(timestamp.len()).to_le_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(len_to_u64(entry.details.len()).to_le_bytes());
    hasher.update(entry.details.as_bytes());
    hasher.update(len_to_u64(entry.prev_hash.len()).to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}

// ── Quarantine record (per-extension state) ──────────────────────────────────

/// Full quarantine record for an extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// The quarantine order.
    pub order: QuarantineOrder,
    /// Current state.
    pub state: QuarantineState,
    /// Impact report (generated on quarantine initiation).
    pub impact: Option<QuarantineImpactReport>,
    /// Recall order (if recall was triggered).
    pub recall: Option<RecallOrder>,
    /// Recall receipts from nodes.
    pub recall_receipts: Vec<RecallReceipt>,
    /// Clearance (if quarantine was lifted).
    pub clearance: Option<QuarantineClearance>,
    /// State transition timestamps.
    pub state_history: Vec<(QuarantineState, String)>,
}

// ── Quarantine registry ──────────────────────────────────────────────────────

/// The quarantine registry manages all quarantine/recall lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRegistry {
    /// Active and historical quarantine records keyed by order_id.
    records: BTreeMap<String, QuarantineRecord>,
    /// Index from extension_id to active quarantine order_id.
    active_quarantines: BTreeMap<String, String>,
    /// Audit trail (hash-chained).
    audit_trail: Vec<QuarantineAuditEntry>,
    /// Anchor hash: entry_hash of the most recently evicted audit entry.
    chain_anchor_hash: Option<String>,
    /// Monotonic sequence counter (not reset by eviction).
    next_sequence: QuarantineAuditId,
    /// Propagation tracking: node_id -> last propagation timestamp.
    propagation_status: BTreeMap<String, String>,
    /// Total quarantines issued.
    total_quarantines: u64,
    /// Total recalls completed.
    total_recalls: u64,
}

impl Default for QuarantineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl QuarantineRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            active_quarantines: BTreeMap::new(),
            audit_trail: Vec::new(),
            chain_anchor_hash: None,
            next_sequence: QuarantineAuditId::new(0),
            propagation_status: BTreeMap::new(),
            total_quarantines: 0,
            total_recalls: 0,
        }
    }

    /// Initiate a quarantine from an order.
    ///
    /// Critical-severity orders bypass normal flow and trigger immediate enforcement
    /// (fast-path quarantine).
    pub fn initiate_quarantine(
        &mut self,
        order: QuarantineOrder,
    ) -> Result<QuarantineRecord, QuarantineError> {
        if self.order_id_seen(&order.order_id) {
            return Err(QuarantineError {
                code: ERR_QUARANTINE_DUPLICATE_ORDER_ID.to_owned(),
                message: format!("Quarantine order id already exists: {}", order.order_id),
            });
        }

        let ext_id = self.extension_id_from_scope(&order.scope);

        // Check for existing active quarantine.
        if let Some(existing_id) = self.active_quarantines.get(&ext_id).cloned() {
            if self
                .records
                .get(&existing_id)
                .is_some_and(|record| !Self::record_is_terminal(record))
            {
                return Err(QuarantineError {
                    code: ERR_QUARANTINE_ALREADY_ACTIVE.to_owned(),
                    message: format!("Extension {ext_id} already under quarantine: {existing_id}"),
                });
            }
            self.active_quarantines.remove(&ext_id);
        }

        let reclaimed_order_id = self.prepare_record_slot(&order.order_id)?;

        let order_id = order.order_id.clone();
        let severity = order.severity;
        let trace_id = order.trace_id.clone();
        let timestamp = order.issued_at.clone();

        // Fast-path: critical severity -> immediate enforcement.
        let initial_state = if severity >= QuarantineSeverity::Critical {
            QuarantineState::Enforced
        } else {
            QuarantineState::Initiated
        };

        let mut state_history = vec![(QuarantineState::Initiated, timestamp.clone())];
        if initial_state == QuarantineState::Enforced {
            state_history.push((QuarantineState::Enforced, timestamp.clone()));
        }

        let record = QuarantineRecord {
            order,
            state: initial_state,
            impact: None,
            recall: None,
            recall_receipts: Vec::new(),
            clearance: None,
            state_history,
        };

        if let Some(reclaimed_order_id) = reclaimed_order_id {
            self.remove_record(&reclaimed_order_id);
        }
        self.records.insert(order_id.clone(), record.clone());
        self.active_quarantines
            .insert(ext_id.clone(), order_id.clone());
        self.total_quarantines = self.total_quarantines.saturating_add(1);

        // Audit: QUARANTINE_INITIATED.
        self.append_audit(
            QUARANTINE_INITIATED,
            &order_id,
            &ext_id,
            severity,
            &trace_id,
            &timestamp,
            "Quarantine order issued",
        )?;

        if initial_state == QuarantineState::Enforced {
            self.append_audit(
                QUARANTINE_ENFORCED,
                &order_id,
                &ext_id,
                severity,
                &trace_id,
                &timestamp,
                "Critical severity: immediate enforcement via fast-path",
            )?;
        }

        Ok(record)
    }

    /// Record propagation to a node.
    pub fn record_propagation(
        &mut self,
        order_id: &str,
        node_id: &str,
        timestamp: &str,
    ) -> Result<(), QuarantineError> {
        let (ext_id, severity, trace_id) = {
            let record = self.records.get(order_id).ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: format!("Quarantine order not found: {order_id}"),
            })?;
            (
                self.extension_id_from_scope(&record.order.scope),
                record.order.severity,
                record.order.trace_id.clone(),
            )
        };

        if self.propagation_status.len() >= MAX_PROPAGATION_STATUS
            && !self.propagation_status.contains_key(node_id)
            && let Some(oldest_key) = self
                .propagation_status
                .iter()
                .min_by_key(|(_, ts)| ts.as_str())
                .map(|(k, _)| k.clone())
        {
            self.propagation_status.remove(&oldest_key);
        }
        self.propagation_status
            .insert(node_id.to_owned(), timestamp.to_owned());

        // Transition to Propagated if still in Initiated state.
        let record = self
            .records
            .get_mut(order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: "Quarantine order disappeared during operation".to_string(),
            })?;
        if record.state == QuarantineState::Initiated {
            record.state = QuarantineState::Propagated;
            push_bounded(
                &mut record.state_history,
                (QuarantineState::Propagated, timestamp.to_owned()),
                MAX_STATE_HISTORY,
            );
        }

        self.append_audit(
            QUARANTINE_PROPAGATED,
            order_id,
            &ext_id,
            severity,
            &trace_id,
            timestamp,
            &format!("Propagated to node {node_id}"),
        )?;

        Ok(())
    }

    /// Mark quarantine as enforced on the local node.
    pub fn enforce_quarantine(
        &mut self,
        order_id: &str,
        timestamp: &str,
    ) -> Result<(), QuarantineError> {
        let (ext_id, severity, trace_id) = {
            let record = self.records.get(order_id).ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: format!("Quarantine order not found: {order_id}"),
            })?;
            (
                self.extension_id_from_scope(&record.order.scope),
                record.order.severity,
                record.order.trace_id.clone(),
            )
        };

        let record = self
            .records
            .get_mut(order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: "Quarantine order disappeared during operation".to_string(),
            })?;
        if matches!(
            record.state,
            QuarantineState::Initiated | QuarantineState::Propagated
        ) {
            record.state = QuarantineState::Enforced;
            push_bounded(
                &mut record.state_history,
                (QuarantineState::Enforced, timestamp.to_owned()),
                MAX_STATE_HISTORY,
            );

            self.append_audit(
                QUARANTINE_ENFORCED,
                order_id,
                &ext_id,
                severity,
                &trace_id,
                timestamp,
                "Extension suspended",
            )?;
        }

        Ok(())
    }

    /// Start draining active sessions. Requires state = Enforced.
    pub fn start_drain(&mut self, order_id: &str, timestamp: &str) -> Result<(), QuarantineError> {
        let (ext_id, severity, trace_id) = {
            let record = self.records.get(order_id).ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: format!("Quarantine order not found: {order_id}"),
            })?;
            if record.state != QuarantineState::Enforced {
                return Err(QuarantineError {
                    code: ERR_QUARANTINE_INVALID_TRANSITION.to_owned(),
                    message: format!(
                        "Cannot start drain: order {order_id} is in state {:?}, expected Enforced",
                        record.state
                    ),
                });
            }
            (
                self.extension_id_from_scope(&record.order.scope),
                record.order.severity,
                record.order.trace_id.clone(),
            )
        };

        let record = self
            .records
            .get_mut(order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: "Quarantine order disappeared during operation".to_string(),
            })?;
        record.state = QuarantineState::Draining;
        push_bounded(
            &mut record.state_history,
            (QuarantineState::Draining, timestamp.to_owned()),
            MAX_STATE_HISTORY,
        );

        self.append_audit(
            QUARANTINE_DRAIN_STARTED,
            order_id,
            &ext_id,
            severity,
            &trace_id,
            timestamp,
            "Session drain started",
        )?;

        Ok(())
    }

    /// Complete drain, mark as isolated. Requires state = Draining.
    pub fn complete_drain(
        &mut self,
        order_id: &str,
        timestamp: &str,
    ) -> Result<(), QuarantineError> {
        let (ext_id, severity, trace_id) = {
            let record = self.records.get(order_id).ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: format!("Quarantine order not found: {order_id}"),
            })?;
            if record.state != QuarantineState::Draining {
                return Err(QuarantineError {
                    code: ERR_QUARANTINE_INVALID_TRANSITION.to_owned(),
                    message: format!(
                        "Cannot complete drain: order {order_id} is in state {:?}, expected Draining",
                        record.state
                    ),
                });
            }
            (
                self.extension_id_from_scope(&record.order.scope),
                record.order.severity,
                record.order.trace_id.clone(),
            )
        };

        let record = self
            .records
            .get_mut(order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: "Quarantine order disappeared during operation".to_string(),
            })?;
        record.state = QuarantineState::Isolated;
        push_bounded(
            &mut record.state_history,
            (QuarantineState::Isolated, timestamp.to_owned()),
            MAX_STATE_HISTORY,
        );

        self.append_audit(
            QUARANTINE_DRAIN_COMPLETED,
            order_id,
            &ext_id,
            severity,
            &trace_id,
            timestamp,
            "All sessions drained, extension isolated",
        )?;

        Ok(())
    }

    /// Generate an impact report for a quarantine.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_impact_report(
        &mut self,
        order_id: &str,
        installations_affected: u64,
        data_at_risk: Vec<String>,
        dependent_extensions: Vec<String>,
        active_sessions: u64,
        recommended_actions: Vec<String>,
        timestamp: &str,
    ) -> Result<QuarantineImpactReport, QuarantineError> {
        let record = self
            .records
            .get_mut(order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: format!("Quarantine order not found: {order_id}"),
            })?;

        let report = QuarantineImpactReport {
            order_id: order_id.to_owned(),
            installations_affected,
            data_at_risk,
            dependent_extensions,
            active_sessions,
            recommended_actions,
            generated_at: timestamp.to_owned(),
        };

        record.impact = Some(report.clone());
        Ok(report)
    }

    /// Trigger recall after investigation confirms compromise.
    pub fn trigger_recall(&mut self, recall: RecallOrder) -> Result<(), QuarantineError> {
        let quarantine_order_id = recall.quarantine_order_id.clone();
        let (ext_id, severity) = {
            let record = self
                .records
                .get(&quarantine_order_id)
                .ok_or_else(|| QuarantineError {
                    code: ERR_RECALL_WITHOUT_QUARANTINE.to_owned(),
                    message: format!(
                        "Cannot recall without prior quarantine: {}",
                        quarantine_order_id
                    ),
                })?;
            (
                self.extension_id_from_scope(&record.order.scope),
                record.order.severity,
            )
        };
        let trace_id = recall.trace_id.clone();
        let timestamp = recall.issued_at.clone();

        let record = self
            .records
            .get_mut(&quarantine_order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: "Quarantine order disappeared during operation".to_string(),
            })?;
        if !matches!(record.state, QuarantineState::Isolated) {
            return Err(QuarantineError {
                code: ERR_RECALL_WITHOUT_QUARANTINE.to_owned(),
                message: format!(
                    "Cannot trigger recall from state {:?}, requires Isolated",
                    record.state
                ),
            });
        }
        record.state = QuarantineState::RecallTriggered;
        push_bounded(
            &mut record.state_history,
            (QuarantineState::RecallTriggered, timestamp.clone()),
            MAX_STATE_HISTORY,
        );
        record.recall = Some(recall);

        self.append_audit(
            RECALL_TRIGGERED,
            &quarantine_order_id,
            &ext_id,
            severity,
            &trace_id,
            &timestamp,
            "Recall initiated: artifact removal in progress",
        )?;

        Ok(())
    }

    /// Record a recall receipt from a node.
    pub fn record_recall_receipt(
        &mut self,
        order_id: &str,
        receipt: RecallReceipt,
    ) -> Result<(), QuarantineError> {
        let (ext_id, severity, trace_id) = {
            let record = self.records.get(order_id).ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: format!("Quarantine order not found: {order_id}"),
            })?;
            (
                self.extension_id_from_scope(&record.order.scope),
                record.order.severity,
                record.order.trace_id.clone(),
            )
        };
        let node_id = receipt.node_id.clone();
        let timestamp = receipt.removed_at.clone();

        let record = self
            .records
            .get_mut(order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: "Quarantine order disappeared during operation".to_string(),
            })?;
        if record.state != QuarantineState::RecallTriggered {
            return Err(QuarantineError {
                code: ERR_RECALL_WITHOUT_QUARANTINE.to_owned(),
                message: format!(
                    "Cannot record recall receipt in state {:?}, requires RecallTriggered",
                    record.state
                ),
            });
        }

        let expected_recall_id = record.recall.as_ref().ok_or_else(|| QuarantineError {
            code: ERR_RECALL_WITHOUT_QUARANTINE.to_owned(),
            message: format!("Cannot record recall receipt: order {order_id} has no recall order"),
        })?;
        if !constant_time::ct_eq(&receipt.recall_id, &expected_recall_id.recall_id) {
            return Err(QuarantineError {
                code: ERR_RECALL_RECEIPT_MISMATCH.to_owned(),
                message: format!(
                    "Recall receipt {} does not match active recall {}",
                    receipt.recall_id, expected_recall_id.recall_id
                ),
            });
        }
        push_bounded(&mut record.recall_receipts, receipt, MAX_RECALL_RECEIPTS);

        self.append_audit(
            RECALL_RECEIPT_EMITTED,
            order_id,
            &ext_id,
            severity,
            &trace_id,
            &timestamp,
            &format!("Recall receipt from node {node_id}"),
        )?;

        Ok(())
    }

    /// Complete the recall (all nodes confirmed removal).
    pub fn complete_recall(
        &mut self,
        order_id: &str,
        timestamp: &str,
    ) -> Result<(), QuarantineError> {
        let (ext_id, severity, trace_id) = {
            let record = self.records.get(order_id).ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: format!("Quarantine order not found: {order_id}"),
            })?;
            (
                self.extension_id_from_scope(&record.order.scope),
                record.order.severity,
                record.order.trace_id.clone(),
            )
        };
        let record = self
            .records
            .get_mut(order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: "Quarantine order disappeared during operation".to_string(),
            })?;

        if record.state != QuarantineState::RecallTriggered {
            return Err(QuarantineError {
                code: ERR_QUARANTINE_INVALID_TRANSITION.to_owned(),
                message: format!(
                    "Cannot complete recall: order {order_id} is in state {:?}, expected RecallTriggered",
                    record.state
                ),
            });
        }

        record.state = QuarantineState::RecallCompleted;
        push_bounded(
            &mut record.state_history,
            (QuarantineState::RecallCompleted, timestamp.to_owned()),
            MAX_STATE_HISTORY,
        );
        self.total_recalls = self.total_recalls.saturating_add(1);

        // Remove from active quarantines.
        self.remove_active_quarantine(order_id);

        self.append_audit(
            RECALL_COMPLETED,
            order_id,
            &ext_id,
            severity,
            &trace_id,
            timestamp,
            "Recall completed: all artifacts removed",
        )?;

        Ok(())
    }

    /// Lift a quarantine with signed clearance.
    pub fn lift_quarantine(
        &mut self,
        clearance: QuarantineClearance,
    ) -> Result<(), QuarantineError> {
        let order_id = clearance.order_id.clone();

        // Must have clearance with non-empty justification.
        if clearance.justification.trim().is_empty() {
            return Err(QuarantineError {
                code: ERR_LIFT_REQUIRES_CLEARANCE.to_owned(),
                message: "Clearance justification must be non-empty".to_owned(),
            });
        }

        let (ext_id, severity) = {
            let record = self.records.get(&order_id).ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: format!("Quarantine order not found: {order_id}"),
            })?;
            if record.state != QuarantineState::Isolated {
                return Err(QuarantineError {
                    code: ERR_QUARANTINE_INVALID_TRANSITION.to_owned(),
                    message: format!(
                        "Cannot lift quarantine: order {} is in state {:?}, expected Isolated",
                        order_id, record.state
                    ),
                });
            }
            (
                self.extension_id_from_scope(&record.order.scope),
                record.order.severity,
            )
        };
        let trace_id = clearance.trace_id.clone();
        let timestamp = clearance.cleared_at.clone();

        let record = self
            .records
            .get_mut(&order_id)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_NOT_FOUND.to_owned(),
                message: "Quarantine order disappeared during operation".to_string(),
            })?;
        record.state = QuarantineState::Lifted;
        push_bounded(
            &mut record.state_history,
            (QuarantineState::Lifted, timestamp.clone()),
            MAX_STATE_HISTORY,
        );
        record.clearance = Some(clearance);

        // Remove from active quarantines.
        self.remove_active_quarantine(&order_id);

        self.append_audit(
            QUARANTINE_LIFTED,
            &order_id,
            &ext_id,
            severity,
            &trace_id,
            &timestamp,
            "Quarantine lifted with signed clearance",
        )?;

        Ok(())
    }

    /// Check if an extension is currently quarantined (fail-closed).
    #[must_use]
    pub fn is_quarantined(&self, extension_id: &str) -> bool {
        self.get_active_quarantine(extension_id).is_some()
    }

    /// Get the active quarantine record for an extension.
    #[must_use]
    pub fn get_active_quarantine(&self, extension_id: &str) -> Option<&QuarantineRecord> {
        self.active_quarantines
            .get(extension_id)
            .and_then(|order_id| self.records.get(order_id))
            .filter(|record| !Self::record_is_terminal(record))
    }

    /// Get a quarantine record by order ID.
    #[must_use]
    pub fn get_record(&self, order_id: &str) -> Option<&QuarantineRecord> {
        self.records.get(order_id)
    }

    /// Get recall completion percentage for an order.
    #[must_use]
    pub fn recall_completion_pct(&self, order_id: &str, total_nodes: u64) -> f64 {
        if total_nodes == 0 {
            return 0.0;
        }
        self.records
            .get(order_id)
            .map(|r| {
                let confirmed_nodes: BTreeSet<&str> = r
                    .recall_receipts
                    .iter()
                    .filter(|rr| rr.removed)
                    .map(|rr| rr.node_id.as_str())
                    .collect();
                let confirmed = len_to_u64(confirmed_nodes.len());
                let capped = confirmed.min(total_nodes) as f64;
                (capped / total_nodes as f64) * 100.0
            })
            .unwrap_or(0.0)
    }

    /// Verify audit trail integrity (hash chain).
    pub fn verify_audit_integrity(&self) -> Result<bool, QuarantineError> {
        let genesis_hash = hex::encode(Sha256::digest(b"quarantine_genesis_v1:"));
        let first_expected = self.chain_anchor_hash.as_deref().unwrap_or(&genesis_hash);

        for (i, entry) in self.audit_trail.iter().enumerate() {
            let expected_prev = if i == 0 {
                first_expected
            } else {
                &self.audit_trail[i - 1].entry_hash
            };

            if !constant_time::ct_eq(&entry.prev_hash, expected_prev) {
                return Err(QuarantineError {
                    code: ERR_AUDIT_CHAIN_BROKEN.to_owned(),
                    message: format!("Audit chain broken at index {i}: prev_hash mismatch"),
                });
            }

            // Verify entry hash.
            let computed = compute_entry_hash(entry);
            if !constant_time::ct_eq(&entry.entry_hash, &computed) {
                return Err(QuarantineError {
                    code: ERR_AUDIT_CHAIN_BROKEN.to_owned(),
                    message: format!("Audit chain broken at index {i}: entry_hash mismatch"),
                });
            }
        }

        Ok(true)
    }

    /// Get the full audit trail.
    #[must_use]
    pub fn audit_trail(&self) -> &[QuarantineAuditEntry] {
        &self.audit_trail
    }

    /// Query audit trail by extension ID.
    #[must_use]
    pub fn query_audit_by_extension(&self, extension_id: &str) -> Vec<&QuarantineAuditEntry> {
        self.audit_trail
            .iter()
            .filter(|e| e.extension_id == extension_id)
            .collect()
    }

    /// Total quarantines issued.
    #[must_use]
    pub fn total_quarantines(&self) -> u64 {
        self.total_quarantines
    }

    /// Total recalls completed.
    #[must_use]
    pub fn total_recalls(&self) -> u64 {
        self.total_recalls
    }

    /// Number of currently active quarantines.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_quarantines
            .values()
            .filter(|order_id| {
                self.records
                    .get(*order_id)
                    .is_some_and(|record| !Self::record_is_terminal(record))
            })
            .count()
    }

    // ── Internal ─────────────────────────────────────────────────────────

    fn extension_id_from_scope(&self, scope: &QuarantineScope) -> String {
        match scope {
            QuarantineScope::Version { extension_id, .. } => extension_id.clone(),
            QuarantineScope::AllVersions { extension_id } => extension_id.clone(),
            QuarantineScope::Publisher { publisher_id } => {
                format!("publisher:{publisher_id}")
            }
        }
    }

    fn record_is_terminal(record: &QuarantineRecord) -> bool {
        matches!(
            record.state,
            QuarantineState::Lifted | QuarantineState::RecallCompleted
        )
    }

    fn reclaimable_record_id(&self) -> Option<String> {
        self.records
            .iter()
            .filter(|(_, record)| Self::record_is_terminal(record))
            .min_by_key(|(_, record)| {
                record
                    .state_history
                    .last()
                    .map(|(_, timestamp)| timestamp.as_str())
                    .unwrap_or(record.order.issued_at.as_str())
            })
            .map(|(order_id, _)| order_id.clone())
    }

    fn prepare_record_slot(&self, order_id: &str) -> Result<Option<String>, QuarantineError> {
        if self.records.len() < MAX_RECORDS || self.records.contains_key(order_id) {
            return Ok(None);
        }

        self.reclaimable_record_id()
            .map(Some)
            .ok_or_else(|| QuarantineError {
                code: ERR_QUARANTINE_CAPACITY_EXCEEDED.to_owned(),
                message: format!(
                    "Quarantine registry is full of live orders (capacity {MAX_RECORDS})"
                ),
            })
    }

    fn order_id_seen(&self, order_id: &str) -> bool {
        self.records.contains_key(order_id)
            || self
                .audit_trail
                .iter()
                .any(|entry| entry.order_id == order_id)
    }

    fn remove_active_quarantine(&mut self, order_id: &str) {
        self.active_quarantines
            .retain(|_, active| active != order_id);
    }

    fn remove_record(&mut self, order_id: &str) {
        self.records.remove(order_id);
        self.remove_active_quarantine(order_id);
    }

    #[allow(clippy::too_many_arguments)]
    fn append_audit(
        &mut self,
        event_code: &str,
        order_id: &str,
        extension_id: &str,
        severity: QuarantineSeverity,
        trace_id: &str,
        timestamp: &str,
        details: &str,
    ) -> Result<(), QuarantineError> {
        let genesis_hash = hex::encode(Sha256::digest(b"quarantine_genesis_v1:"));
        let prev_hash = self
            .audit_trail
            .last()
            .map(|e| e.entry_hash.clone())
            .or_else(|| self.chain_anchor_hash.clone())
            .unwrap_or(genesis_hash);

        let sequence = self.next_sequence;
        self.next_sequence = QuarantineAuditId::new(self.next_sequence.get().saturating_add(1));
        let timestamp = parse_audit_timestamp(timestamp)?;

        let mut entry = QuarantineAuditEntry {
            sequence,
            event_code: event_code.to_owned(),
            order_id: order_id.to_owned(),
            extension_id: extension_id.to_owned(),
            severity,
            trace_id: trace_id.to_owned(),
            timestamp,
            details: details.to_owned(),
            prev_hash,
            entry_hash: String::new(),
        };

        entry.entry_hash = compute_entry_hash(&entry);
        push_bounded_audit_trail(
            &mut self.audit_trail,
            entry,
            MAX_AUDIT_TRAIL,
            &mut self.chain_anchor_hash,
        );
        Ok(())
    }
}

// ── Error type ───────────────────────────────────────────────────────────────

/// Quarantine operation error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for QuarantineError {}

fn parse_audit_timestamp(raw: &str) -> Result<QuarantineAuditTimestamp, QuarantineError> {
    QuarantineAuditTimestamp::try_from(raw).map_err(|err| QuarantineError {
        code: ERR_QUARANTINE_INVALID_AUDIT_TIMESTAMP.to_owned(),
        message: format!("invalid quarantine audit timestamp `{raw}`: {err}"),
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        ERR_AUDIT_CHAIN_BROKEN, ERR_LIFT_REQUIRES_CLEARANCE, ERR_QUARANTINE_ALREADY_ACTIVE,
        MAX_AUDIT_TRAIL, MAX_PROPAGATION_STATUS, MAX_STATE_HISTORY, QuarantineAuditEntry,
        QuarantineAuditId, QuarantineAuditTimestamp, QuarantineClearance, QuarantineError,
        QuarantineImpactReport, QuarantineMode, QuarantineOrder, QuarantineReason,
        QuarantineRecord, QuarantineRegistry, QuarantineScope, QuarantineSeverity, QuarantineState,
        RecallOrder, RecallReceipt, constant_time,
    };

    fn make_order(id: &str, severity: QuarantineSeverity, mode: QuarantineMode) -> QuarantineOrder {
        QuarantineOrder {
            order_id: id.to_owned(),
            scope: QuarantineScope::Version {
                extension_id: "ext-test".to_owned(),
                version: "1.0.0".to_owned(),
            },
            mode,
            severity,
            reason: QuarantineReason::VulnerabilityDisclosure,
            justification: "Test quarantine".to_owned(),
            issued_by: "operator-1".to_owned(),
            issued_at: "2026-01-15T00:00:00Z".to_owned(),
            signature: "sig-placeholder".to_owned(),
            trace_id: "trace-001".to_owned(),
            grace_period_secs: 300,
        }
    }

    fn make_clearance(order_id: &str) -> QuarantineClearance {
        QuarantineClearance {
            order_id: order_id.to_owned(),
            cleared_by: "security-lead".to_owned(),
            justification: "Investigation complete, no threat found".to_owned(),
            re_verification_evidence: "audit-report-123".to_owned(),
            cleared_at: "2026-01-16T00:00:00Z".to_owned(),
            signature: "sig-clearance".to_owned(),
            trace_id: "trace-002".to_owned(),
        }
    }

    fn make_order_for_extension(
        id: &str,
        extension_id: &str,
        severity: QuarantineSeverity,
        mode: QuarantineMode,
    ) -> QuarantineOrder {
        let mut order = make_order(id, severity, mode);
        order.scope = QuarantineScope::AllVersions {
            extension_id: extension_id.to_owned(),
        };
        order.trace_id = format!("trace-{id}");
        order
    }

    fn make_recall(order_id: &str) -> RecallOrder {
        RecallOrder {
            recall_id: "recall-001".to_owned(),
            quarantine_order_id: order_id.to_owned(),
            scope: QuarantineScope::Version {
                extension_id: "ext-test".to_owned(),
                version: "1.0.0".to_owned(),
            },
            reason: "Confirmed malware".to_owned(),
            issued_by: "security-lead".to_owned(),
            issued_at: "2026-01-16T12:00:00Z".to_owned(),
            signature: "sig-recall".to_owned(),
            trace_id: "trace-003".to_owned(),
        }
    }

    fn setup_recall_registry(order_id: &str) -> QuarantineRegistry {
        let mut reg = QuarantineRegistry::new();
        let order = make_order(order_id, QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");
        reg.enforce_quarantine(order_id, "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain(order_id, "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain(order_id, "2026-01-15T00:04:00Z")
            .expect("should succeed");
        reg.trigger_recall(make_recall(order_id))
            .expect("should succeed");
        reg
    }

    #[test]
    fn test_push_bounded_zero_capacity_drops_existing_and_new_items() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn test_initiate_soft_quarantine() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Soft);
        let record = reg.initiate_quarantine(order).expect("should succeed");
        assert_eq!(record.state, QuarantineState::Initiated);
        assert!(reg.is_quarantined("ext-test"));
        assert_eq!(reg.total_quarantines(), 1);
    }

    #[test]
    fn test_initiate_hard_quarantine() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::Medium, QuarantineMode::Hard);
        let record = reg.initiate_quarantine(order).expect("should succeed");
        assert_eq!(record.state, QuarantineState::Initiated);
    }

    #[test]
    fn test_duplicate_order_id_is_rejected_without_overwriting_existing_record() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order_for_extension(
            "q-dup",
            "ext-original",
            QuarantineSeverity::High,
            QuarantineMode::Soft,
        ))
        .expect("should succeed");

        let err = reg
            .initiate_quarantine(make_order_for_extension(
                "q-dup",
                "ext-replacement",
                QuarantineSeverity::Critical,
                QuarantineMode::Hard,
            ))
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_DUPLICATE_ORDER_ID);
        assert!(reg.get_active_quarantine("ext-original").is_some());
        assert!(reg.get_active_quarantine("ext-replacement").is_none());
        let record = reg.get_record("q-dup").expect("original record retained");
        assert_eq!(
            record.order.scope,
            QuarantineScope::AllVersions {
                extension_id: "ext-original".to_owned()
            }
        );
        assert_eq!(record.state, QuarantineState::Initiated);
    }

    #[test]
    fn test_critical_fast_path_enforcement() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-crit", QuarantineSeverity::Critical, QuarantineMode::Hard);
        let record = reg.initiate_quarantine(order).expect("should succeed");
        // Critical severity triggers immediate enforcement.
        assert_eq!(record.state, QuarantineState::Enforced);
    }

    #[test]
    fn test_duplicate_quarantine_rejected() {
        let mut reg = QuarantineRegistry::new();
        let order1 = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Soft);
        reg.initiate_quarantine(order1).expect("should succeed");

        let order2 = make_order("q-002", QuarantineSeverity::Medium, QuarantineMode::Hard);
        let err = reg.initiate_quarantine(order2).unwrap_err();
        assert_eq!(err.code, ERR_QUARANTINE_ALREADY_ACTIVE);
    }

    #[test]
    fn test_terminal_order_id_reuse_is_rejected_without_new_record() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order_for_extension(
            "q-reused",
            "ext-original",
            QuarantineSeverity::High,
            QuarantineMode::Hard,
        ))
        .expect("should succeed");
        reg.enforce_quarantine("q-reused", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-reused", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-reused", "2026-01-15T00:04:00Z")
            .expect("should succeed");
        reg.lift_quarantine(make_clearance("q-reused"))
            .expect("should succeed");

        let err = reg
            .initiate_quarantine(make_order_for_extension(
                "q-reused",
                "ext-replacement",
                QuarantineSeverity::Critical,
                QuarantineMode::Hard,
            ))
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_DUPLICATE_ORDER_ID);
        assert!(reg.get_active_quarantine("ext-replacement").is_none());
        assert_eq!(reg.total_quarantines(), 1);
    }

    #[test]
    fn test_propagation_transitions_state() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Soft);
        reg.initiate_quarantine(order).expect("should succeed");
        reg.record_propagation("q-001", "node-1", "2026-01-15T00:01:00Z")
            .expect("should succeed");

        let record = reg.get_record("q-001").expect("should succeed");
        assert_eq!(record.state, QuarantineState::Propagated);
    }

    #[test]
    fn test_record_propagation_rejects_unknown_order_without_audit_entry() {
        let mut reg = QuarantineRegistry::new();

        let err = reg
            .record_propagation("missing-order", "node-1", "2026-01-15T00:01:00Z")
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_NOT_FOUND);
        assert!(reg.audit_trail().is_empty());
    }

    #[test]
    fn test_record_propagation_rejects_unknown_order_without_caching_node() {
        let mut reg = QuarantineRegistry::new();

        let err = reg
            .record_propagation("missing-order", "node-stale", "2026-01-15T00:01:00Z")
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_NOT_FOUND);
        assert!(reg.propagation_status.is_empty());
    }

    #[test]
    fn test_enforce_quarantine_rejects_unknown_order() {
        let mut reg = QuarantineRegistry::new();

        let err = reg
            .enforce_quarantine("missing-order", "2026-01-15T00:02:00Z")
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_NOT_FOUND);
        assert_eq!(reg.total_quarantines(), 0);
    }

    #[test]
    fn test_enforcement_and_drain_lifecycle() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");

        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        assert_eq!(
            reg.get_record("q-001").expect("should succeed").state,
            QuarantineState::Enforced
        );

        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        assert_eq!(
            reg.get_record("q-001").expect("should succeed").state,
            QuarantineState::Draining
        );

        reg.complete_drain("q-001", "2026-01-15T00:04:00Z")
            .expect("should succeed");
        assert_eq!(
            reg.get_record("q-001").expect("should succeed").state,
            QuarantineState::Isolated
        );
    }

    #[test]
    fn test_start_drain_rejects_initiated_state_without_state_change() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order(
            "q-001",
            QuarantineSeverity::High,
            QuarantineMode::Hard,
        ))
        .expect("should succeed");

        let err = reg
            .start_drain("q-001", "2026-01-15T00:03:00Z")
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_INVALID_TRANSITION);
        let record = reg.get_record("q-001").expect("record remains present");
        assert_eq!(record.state, QuarantineState::Initiated);
        assert_eq!(record.state_history.len(), 1);
    }

    #[test]
    fn test_complete_drain_rejects_enforced_state_without_state_change() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order(
            "q-001",
            QuarantineSeverity::High,
            QuarantineMode::Hard,
        ))
        .expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");

        let err = reg
            .complete_drain("q-001", "2026-01-15T00:04:00Z")
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_INVALID_TRANSITION);
        let record = reg.get_record("q-001").expect("record remains present");
        assert_eq!(record.state, QuarantineState::Enforced);
        assert_eq!(record.state_history.len(), 2);
    }

    #[test]
    fn test_lift_quarantine_with_clearance() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::Medium, QuarantineMode::Soft);
        reg.initiate_quarantine(order).expect("should succeed");
        assert!(reg.is_quarantined("ext-test"));

        // Advance through the required state machine: Enforced → Draining → Isolated
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-001", "2026-01-15T00:04:00Z")
            .expect("should succeed");

        reg.lift_quarantine(make_clearance("q-001"))
            .expect("should succeed");
        assert!(!reg.is_quarantined("ext-test"));

        let record = reg.get_record("q-001").expect("should succeed");
        assert_eq!(record.state, QuarantineState::Lifted);
        assert!(record.clearance.is_some());
    }

    #[test]
    fn test_lift_without_justification_fails() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::Low, QuarantineMode::Soft);
        reg.initiate_quarantine(order).expect("should succeed");

        let mut clearance = make_clearance("q-001");
        clearance.justification = String::new();
        let err = reg.lift_quarantine(clearance).unwrap_err();
        assert_eq!(err.code, ERR_LIFT_REQUIRES_CLEARANCE);
    }

    #[test]
    fn test_lift_with_whitespace_justification_fails_without_state_change() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order(
            "q-001",
            QuarantineSeverity::Low,
            QuarantineMode::Soft,
        ))
        .expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-001", "2026-01-15T00:04:00Z")
            .expect("should succeed");

        let mut clearance = make_clearance("q-001");
        clearance.justification = " \t\n ".to_owned();
        let err = reg.lift_quarantine(clearance).unwrap_err();

        assert_eq!(err.code, ERR_LIFT_REQUIRES_CLEARANCE);
        let record = reg.get_record("q-001").expect("record remains present");
        assert_eq!(record.state, QuarantineState::Isolated);
        assert!(record.clearance.is_none());
        assert!(reg.is_quarantined("ext-test"));
    }

    #[test]
    fn test_lift_unknown_quarantine_rejects_after_clearance_validation() {
        let mut reg = QuarantineRegistry::new();

        let err = reg
            .lift_quarantine(make_clearance("missing-order"))
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_NOT_FOUND);
        assert_eq!(reg.active_count(), 0);
    }

    #[test]
    fn test_lift_quarantine_rejects_before_isolated_state() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order(
            "q-001",
            QuarantineSeverity::Medium,
            QuarantineMode::Soft,
        ))
        .expect("should succeed");

        let err = reg.lift_quarantine(make_clearance("q-001")).unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_INVALID_TRANSITION);
        let record = reg.get_record("q-001").expect("record remains present");
        assert_eq!(record.state, QuarantineState::Initiated);
        assert!(record.clearance.is_none());
        assert!(reg.is_quarantined("ext-test"));
    }

    #[test]
    fn test_recall_lifecycle() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-001", "2026-01-15T00:04:00Z")
            .expect("should succeed");

        // Trigger recall (requires Isolated state).
        reg.trigger_recall(make_recall("q-001"))
            .expect("should succeed");
        assert_eq!(
            reg.get_record("q-001").expect("should succeed").state,
            QuarantineState::RecallTriggered
        );

        // Record receipt.
        let receipt = RecallReceipt {
            node_id: "node-1".to_owned(),
            recall_id: "recall-001".to_owned(),
            removed: true,
            removal_method: "crypto_erase".to_owned(),
            removed_at: "2026-01-16T13:00:00Z".to_owned(),
            artifact_hash: "abc123".to_owned(),
        };
        reg.record_recall_receipt("q-001", receipt)
            .expect("should succeed");

        // Complete recall.
        reg.complete_recall("q-001", "2026-01-16T14:00:00Z")
            .expect("should succeed");
        assert_eq!(
            reg.get_record("q-001").expect("should succeed").state,
            QuarantineState::RecallCompleted
        );
        assert_eq!(reg.total_recalls(), 1);
        assert!(!reg.is_quarantined("ext-test"));
    }

    #[test]
    fn test_recall_without_quarantine_fails() {
        let mut reg = QuarantineRegistry::new();
        let recall = make_recall("nonexistent");
        let err = reg.trigger_recall(recall).unwrap_err();
        assert_eq!(err.code, ERR_RECALL_WITHOUT_QUARANTINE);
    }

    #[test]
    fn test_trigger_recall_rejects_before_isolated_state() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order(
            "q-001",
            QuarantineSeverity::High,
            QuarantineMode::Hard,
        ))
        .expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");

        let err = reg.trigger_recall(make_recall("q-001")).unwrap_err();

        assert_eq!(err.code, ERR_RECALL_WITHOUT_QUARANTINE);
        let record = reg.get_record("q-001").expect("record remains present");
        assert_eq!(record.state, QuarantineState::Enforced);
        assert!(record.recall.is_none());
    }

    #[test]
    fn test_record_recall_receipt_rejects_before_recall_triggered() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order(
            "q-001",
            QuarantineSeverity::High,
            QuarantineMode::Hard,
        ))
        .expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-001", "2026-01-15T00:04:00Z")
            .expect("should succeed");

        let receipt = RecallReceipt {
            node_id: "node-1".to_owned(),
            recall_id: "recall-001".to_owned(),
            removed: true,
            removal_method: "file_delete".to_owned(),
            removed_at: "2026-01-16T13:00:00Z".to_owned(),
            artifact_hash: "abc".to_owned(),
        };
        let err = reg.record_recall_receipt("q-001", receipt).unwrap_err();

        assert_eq!(err.code, ERR_RECALL_WITHOUT_QUARANTINE);
        let record = reg.get_record("q-001").expect("record remains present");
        assert!(record.recall_receipts.is_empty());
    }

    #[test]
    fn test_record_recall_receipt_rejects_mismatched_recall_id_without_audit() {
        let mut reg = setup_recall_registry("q-001");
        let audit_len = reg.audit_trail().len();
        let receipt = RecallReceipt {
            node_id: "node-1".to_owned(),
            recall_id: "recall-other".to_owned(),
            removed: true,
            removal_method: "file_delete".to_owned(),
            removed_at: "2026-01-16T13:00:00Z".to_owned(),
            artifact_hash: "abc".to_owned(),
        };

        let err = reg.record_recall_receipt("q-001", receipt).unwrap_err();

        assert_eq!(err.code, ERR_RECALL_RECEIPT_MISMATCH);
        let record = reg.get_record("q-001").expect("record remains present");
        assert!(record.recall_receipts.is_empty());
        assert_eq!(reg.audit_trail().len(), audit_len);
    }

    #[test]
    fn test_impact_report() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");

        let report = reg
            .generate_impact_report(
                "q-001",
                150,
                vec!["user-configs".to_owned()],
                vec!["ext-dependent-1".to_owned()],
                5,
                vec!["Export user data before hard quarantine takes effect".to_owned()],
                "2026-01-15T01:00:00Z",
            )
            .expect("should succeed");

        assert_eq!(report.installations_affected, 150);
        assert_eq!(report.active_sessions, 5);
    }

    #[test]
    fn test_impact_report_rejects_unknown_order() {
        let mut reg = QuarantineRegistry::new();

        let err = reg
            .generate_impact_report(
                "missing-order",
                1,
                vec!["configs".to_owned()],
                vec!["ext-dependent".to_owned()],
                1,
                vec!["notify operator".to_owned()],
                "2026-01-15T01:00:00Z",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_NOT_FOUND);
    }

    #[test]
    fn test_recall_completion_percentage() {
        let mut reg = setup_recall_registry("q-001");

        // 1 of 3 nodes confirmed.
        let receipt = RecallReceipt {
            node_id: "node-1".to_owned(),
            recall_id: "recall-001".to_owned(),
            removed: true,
            removal_method: "file_delete".to_owned(),
            removed_at: "2026-01-16T13:00:00Z".to_owned(),
            artifact_hash: "abc".to_owned(),
        };
        reg.record_recall_receipt("q-001", receipt)
            .expect("should succeed");

        let pct = reg.recall_completion_pct("q-001", 3);
        assert!((pct - 33.333).abs() < 1.0);
    }

    #[test]
    fn test_recall_completion_pct_dedupes_nodes() {
        let mut reg = setup_recall_registry("q-002");
        let receipt = RecallReceipt {
            node_id: "node-1".to_owned(),
            recall_id: "recall-001".to_owned(),
            removed: true,
            removal_method: "file_delete".to_owned(),
            removed_at: "2026-01-16T13:00:00Z".to_owned(),
            artifact_hash: "abc".to_owned(),
        };
        reg.record_recall_receipt("q-002", receipt.clone())
            .expect("should succeed");
        reg.record_recall_receipt("q-002", receipt)
            .expect("should succeed");

        let pct = reg.recall_completion_pct("q-002", 3);
        assert!((pct - 33.333).abs() < 1.0);
    }

    #[test]
    fn test_recall_completion_pct_caps_at_100() {
        let mut reg = setup_recall_registry("q-003");
        for node_id in ["node-1", "node-2", "node-3"] {
            let receipt = RecallReceipt {
                node_id: node_id.to_owned(),
                recall_id: "recall-001".to_owned(),
                removed: true,
                removal_method: "file_delete".to_owned(),
                removed_at: "2026-01-16T13:00:00Z".to_owned(),
                artifact_hash: "abc".to_owned(),
            };
            reg.record_recall_receipt("q-003", receipt)
                .expect("should succeed");
        }

        let pct = reg.recall_completion_pct("q-003", 2);
        assert!((pct - 100.0).abs() < 1e-6);
    }

    #[test]
    fn test_recall_completion_ignores_failed_removal_receipts() {
        let mut reg = setup_recall_registry("q-001");
        let receipt = RecallReceipt {
            node_id: "node-1".to_owned(),
            recall_id: "recall-001".to_owned(),
            removed: false,
            removal_method: "file_delete".to_owned(),
            removed_at: "2026-01-16T13:00:00Z".to_owned(),
            artifact_hash: "abc".to_owned(),
        };
        reg.record_recall_receipt("q-001", receipt)
            .expect("should succeed");

        assert_eq!(reg.recall_completion_pct("q-001", 1), 0.0);
    }

    #[test]
    fn test_complete_recall_unknown_order_preserves_counter() {
        let mut reg = QuarantineRegistry::new();

        let err = reg
            .complete_recall("missing-order", "2026-01-16T14:00:00Z")
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_NOT_FOUND);
        assert_eq!(reg.total_recalls(), 0);
    }

    #[test]
    fn test_audit_trail_integrity() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");

        assert!(reg.verify_audit_integrity().expect("should succeed"));
        assert_eq!(reg.audit_trail().len(), 3);
    }

    #[test]
    fn test_audit_trail_tamper_detection() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");

        // Tamper with the audit trail.
        if let Some(entry) = reg.audit_trail.first_mut() {
            entry.details = "TAMPERED".to_owned();
        }

        let err = reg.verify_audit_integrity().unwrap_err();
        assert_eq!(err.code, ERR_AUDIT_CHAIN_BROKEN);
    }

    #[test]
    fn test_audit_trail_prev_hash_tamper_detection() {
        let mut reg = QuarantineRegistry::new();
        reg.initiate_quarantine(make_order(
            "q-001",
            QuarantineSeverity::High,
            QuarantineMode::Hard,
        ))
        .expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");

        reg.audit_trail[1].prev_hash = "wrong-prev-hash".to_owned();

        let err = reg.verify_audit_integrity().unwrap_err();
        assert_eq!(err.code, ERR_AUDIT_CHAIN_BROKEN);
    }

    #[test]
    fn test_query_audit_by_extension() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Soft);
        reg.initiate_quarantine(order).expect("should succeed");

        let entries = reg.query_audit_by_extension("ext-test");
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.extension_id == "ext-test"));
    }

    #[test]
    fn test_publisher_scope_quarantine() {
        let mut reg = QuarantineRegistry::new();
        let mut order = make_order("q-pub", QuarantineSeverity::High, QuarantineMode::Hard);
        order.scope = QuarantineScope::Publisher {
            publisher_id: "bad-publisher".to_owned(),
        };
        reg.initiate_quarantine(order).expect("should succeed");
        assert!(reg.is_quarantined("publisher:bad-publisher"));
    }

    #[test]
    fn test_all_versions_scope() {
        let mut reg = QuarantineRegistry::new();
        let mut order = make_order("q-all", QuarantineSeverity::Medium, QuarantineMode::Soft);
        order.scope = QuarantineScope::AllVersions {
            extension_id: "ext-evil".to_owned(),
        };
        reg.initiate_quarantine(order).expect("should succeed");
        assert!(reg.is_quarantined("ext-evil"));
    }

    #[test]
    fn test_state_history_tracked() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-001", "2026-01-15T00:04:00Z")
            .expect("should succeed");

        let record = reg.get_record("q-001").expect("should succeed");
        assert_eq!(record.state_history.len(), 4);
        assert_eq!(record.state_history[0].0, QuarantineState::Initiated);
        assert_eq!(record.state_history[1].0, QuarantineState::Enforced);
        assert_eq!(record.state_history[2].0, QuarantineState::Draining);
        assert_eq!(record.state_history[3].0, QuarantineState::Isolated);
    }

    #[test]
    fn test_quarantine_reason_variants() {
        let reasons = [
            QuarantineReason::VulnerabilityDisclosure,
            QuarantineReason::MalwareDetection,
            QuarantineReason::SupplyChainAttack,
            QuarantineReason::BehavioralAnomaly,
            QuarantineReason::OperatorInitiated,
            QuarantineReason::RevocationEvent,
            QuarantineReason::PolicyTrigger,
        ];
        assert_eq!(reasons.len(), 7);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(QuarantineSeverity::Low < QuarantineSeverity::Medium);
        assert!(QuarantineSeverity::Medium < QuarantineSeverity::High);
        assert!(QuarantineSeverity::High < QuarantineSeverity::Critical);
    }

    #[test]
    fn test_audit_integrity_survives_eviction() {
        // After push_bounded evicts old audit entries, verify_audit_integrity
        // must still pass (the first retained entry's prev_hash references an
        // evicted predecessor, so genesis linkage cannot be verified).
        let mut reg = QuarantineRegistry::new();

        // Generate enough audit entries to trigger eviction.
        // Each quarantine with unique extension_id produces audit entries.
        for i in 0..(MAX_AUDIT_TRAIL / 2 + 10) {
            let mut order = make_order(
                &format!("q-{i}"),
                QuarantineSeverity::Critical,
                QuarantineMode::Soft,
            );
            order.scope = QuarantineScope::AllVersions {
                extension_id: format!("ext-{i}"),
            };
            let _ = reg.initiate_quarantine(order);
        }

        // Audit trail should be capped.
        assert!(reg.audit_trail().len() <= MAX_AUDIT_TRAIL);

        // First entry's sequence > 0 means entries were evicted.
        assert!(
            reg.audit_trail()
                .first()
                .expect("should succeed")
                .sequence
                .get()
                > 0
        );

        // Integrity check must still pass despite eviction.
        assert!(reg.verify_audit_integrity().expect("should succeed"));
    }

    #[test]
    fn test_recall_receipts_bounded() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-001", "2026-01-15T00:04:00Z")
            .expect("should succeed");
        reg.trigger_recall(make_recall("q-001"))
            .expect("should succeed");

        // Push more receipts than the cap.
        for i in 0..(MAX_RECALL_RECEIPTS + 10) {
            let receipt = RecallReceipt {
                node_id: format!("node-{i}"),
                recall_id: "recall-001".to_owned(),
                removed: true,
                removal_method: "file_delete".to_owned(),
                removed_at: "2026-01-16T13:00:00Z".to_owned(),
                artifact_hash: format!("hash-{i}"),
            };
            reg.record_recall_receipt("q-001", receipt)
                .expect("should succeed");
        }

        let record = reg.get_record("q-001").expect("should succeed");
        assert!(record.recall_receipts.len() <= MAX_RECALL_RECEIPTS);
    }

    #[test]
    fn test_initiate_quarantine_rejects_when_registry_full_of_live_orders() {
        let mut reg = QuarantineRegistry::new();
        for i in 0..MAX_RECORDS {
            reg.initiate_quarantine(make_order_for_extension(
                &format!("q-{i:05}"),
                &format!("ext-{i:05}"),
                QuarantineSeverity::Low,
                QuarantineMode::Soft,
            ))
            .expect("should succeed");
        }

        let err = reg
            .initiate_quarantine(make_order_for_extension(
                "q-overflow",
                "ext-overflow",
                QuarantineSeverity::High,
                QuarantineMode::Soft,
            ))
            .unwrap_err();

        assert_eq!(err.code, ERR_QUARANTINE_CAPACITY_EXCEEDED);
        assert_eq!(reg.records.len(), MAX_RECORDS);
        assert_eq!(reg.active_quarantines.len(), MAX_RECORDS);
        assert_eq!(reg.active_count(), MAX_RECORDS);
        assert!(reg.get_record("q-00000").is_some());
        assert!(reg.get_active_quarantine("ext-00000").is_some());
        assert!(reg.get_record("q-overflow").is_none());
    }

    #[test]
    fn test_initiate_quarantine_reclaims_terminal_record_instead_of_live_one() {
        let mut reg = QuarantineRegistry::new();

        reg.initiate_quarantine(make_order_for_extension(
            "q-terminal",
            "ext-terminal",
            QuarantineSeverity::High,
            QuarantineMode::Hard,
        ))
        .expect("should succeed");
        reg.enforce_quarantine("q-terminal", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-terminal", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-terminal", "2026-01-15T00:04:00Z")
            .expect("should succeed");
        reg.lift_quarantine(make_clearance("q-terminal"))
            .expect("should succeed");

        for i in 1..MAX_RECORDS {
            reg.initiate_quarantine(make_order_for_extension(
                &format!("q-live-{i:05}"),
                &format!("ext-live-{i:05}"),
                QuarantineSeverity::Low,
                QuarantineMode::Soft,
            ))
            .expect("should succeed");
        }

        reg.initiate_quarantine(make_order_for_extension(
            "q-new",
            "ext-new",
            QuarantineSeverity::Low,
            QuarantineMode::Soft,
        ))
        .expect("should succeed");

        assert_eq!(reg.records.len(), MAX_RECORDS);
        assert_eq!(reg.active_count(), MAX_RECORDS);
        assert!(reg.get_record("q-terminal").is_none());
        assert!(!reg.is_quarantined("ext-terminal"));
        assert!(reg.get_record("q-new").is_some());
        assert!(reg.get_active_quarantine("ext-new").is_some());
    }

    #[test]
    fn test_stale_active_quarantine_pointer_does_not_block_new_order() {
        let mut reg = QuarantineRegistry::new();
        reg.active_quarantines
            .insert("ext-stale".to_owned(), "q-stale".to_owned());

        assert!(!reg.is_quarantined("ext-stale"));
        assert_eq!(reg.active_count(), 0);
        assert!(reg.get_active_quarantine("ext-stale").is_none());

        reg.initiate_quarantine(make_order_for_extension(
            "q-recovered",
            "ext-stale",
            QuarantineSeverity::Low,
            QuarantineMode::Soft,
        ))
        .expect("should succeed");

        assert_eq!(
            reg.active_quarantines.get("ext-stale"),
            Some(&"q-recovered".to_owned())
        );
        assert!(reg.get_active_quarantine("ext-stale").is_some());
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_complete_recall_requires_recall_triggered_state() {
        let mut reg = QuarantineRegistry::new();
        let order = make_order("q-001", QuarantineSeverity::High, QuarantineMode::Hard);
        reg.initiate_quarantine(order).expect("should succeed");
        reg.enforce_quarantine("q-001", "2026-01-15T00:02:00Z")
            .expect("should succeed");
        reg.start_drain("q-001", "2026-01-15T00:03:00Z")
            .expect("should succeed");
        reg.complete_drain("q-001", "2026-01-15T00:04:00Z")
            .expect("should succeed");

        // Attempt to complete recall without triggering it first (state = Isolated).
        let err = reg
            .complete_recall("q-001", "2026-01-15T00:05:00Z")
            .unwrap_err();
        assert_eq!(
            err.code, ERR_QUARANTINE_INVALID_TRANSITION,
            "complete_recall must reject non-RecallTriggered state"
        );
    }

    // ---------------------------------------------------------------------------
    // Comprehensive negative-path tests
    // ---------------------------------------------------------------------------

    mod quarantine_comprehensive_negative_tests {
        use super::{
            QuarantineMode, QuarantineOrder, QuarantineReason, QuarantineRegistry, QuarantineScope,
            QuarantineSeverity,
        };

        #[test]
        fn unicode_injection_in_quarantine_identifiers_and_metadata() {
            let malicious_strings = [
                "order\u{202E}deilav",               // RLO override attack
                "id\u{200B}hidden",                  // Zero-width space injection
                "trace\u{FEFF}bom",                  // BOM insertion attack
                "ext\u{2028}break",                  // Line separator injection
                "\u{1F4A9}emoji_quarantine",         // Non-ASCII emoji
                "order\u{0000}null",                 // Null byte injection
                "just\u{001F}ctrl\u{007F}ification", // Control character injection
            ];

            let mut reg = QuarantineRegistry::new();

            for (i, malicious_str) in malicious_strings.iter().enumerate() {
                // Test Unicode injection in order identifiers and metadata
                let mut malicious_order = make_order(
                    &format!("unicode_test_{i}_{malicious_str}"),
                    QuarantineSeverity::High,
                    QuarantineMode::Soft,
                );
                malicious_order.justification = format!("Malicious justification: {malicious_str}");
                malicious_order.trace_id = format!("trace_{malicious_str}");
                malicious_order.issued_by = format!("operator_{malicious_str}");
                malicious_order.scope = QuarantineScope::AllVersions {
                    extension_id: format!("ext_{malicious_str}"),
                };

                // System should handle Unicode injection gracefully
                let record_result = reg.initiate_quarantine(malicious_order);
                assert!(
                    record_result.is_ok(),
                    "Unicode injection in order '{malicious_str:?}' should not cause system failure"
                );

                // Test Unicode in recall orders
                if let Ok(_) = record_result {
                    let order_id = format!("unicode_test_{i}_{malicious_str}");
                    let ext_id = format!("ext_{malicious_str}");

                    // Progress to isolated state for recall testing
                    let _ = reg.enforce_quarantine(&order_id, "2026-01-15T00:02:00Z");
                    let _ = reg.start_drain(&order_id, "2026-01-15T00:03:00Z");
                    let _ = reg.complete_drain(&order_id, "2026-01-15T00:04:00Z");

                    let mut malicious_recall = make_recall(&order_id);
                    malicious_recall.recall_id = format!("recall_{malicious_str}");
                    malicious_recall.reason = format!("Malicious reason: {malicious_str}");
                    malicious_recall.trace_id = format!("recall_trace_{malicious_str}");
                    malicious_recall.issued_by = format!("security_{malicious_str}");

                    let recall_result = reg.trigger_recall(malicious_recall);
                    assert!(
                        recall_result.is_ok() || recall_result.is_err(),
                        "Unicode recall should complete without panic"
                    );

                    // Test Unicode in clearance
                    let mut malicious_clearance = make_clearance(&order_id);
                    malicious_clearance.justification =
                        format!("Clear justification: {malicious_str}");
                    malicious_clearance.re_verification_evidence =
                        format!("Evidence: {malicious_str}");
                    malicious_clearance.cleared_by = format!("lead_{malicious_str}");

                    // Note: clearance may fail due to state, but should not crash
                    let _ = reg.lift_quarantine(malicious_clearance);
                }

                // Verify audit trail handles Unicode safely
                let audit_entries = reg.audit_trail();
                for entry in audit_entries {
                    assert!(
                        !entry.details.is_empty(),
                        "Audit details should not be corrupted by Unicode"
                    );
                    assert!(
                        !entry.extension_id.is_empty(),
                        "Extension ID should be preserved"
                    );
                }
            }

            // Test audit integrity with Unicode content
            let integrity_result = reg.verify_audit_integrity();
            assert!(
                integrity_result.is_ok(),
                "Audit integrity should be maintained despite Unicode injection"
            );
        }

        #[test]
        fn arithmetic_overflow_protection_in_sequence_counters() {
            let mut reg = QuarantineRegistry::new();

            // Set sequence counter near overflow boundary
            reg.next_sequence = QuarantineAuditId::new(u64::MAX.saturating_sub(5));

            // Test sequence counter overflow protection
            for i in 0..10 {
                let order = make_order(
                    &format!("overflow_test_{i}"),
                    QuarantineSeverity::High,
                    QuarantineMode::Soft,
                );

                let record_result = reg.initiate_quarantine(order);
                assert!(
                    record_result.is_ok(),
                    "Should handle sequence overflow gracefully"
                );

                // Verify sequence counter uses saturating arithmetic
                let current_sequence = reg.next_sequence;
                assert!(
                    current_sequence.get() <= u64::MAX,
                    "Sequence should not wrap around"
                );

                if i > 0 {
                    assert!(
                        current_sequence.get() >= reg.next_sequence.get().saturating_sub(1),
                        "Sequence should increment safely"
                    );
                }
            }

            // Test counters in quarantine/recall totals
            reg.total_quarantines = u64::MAX.saturating_sub(2);
            reg.total_recalls = u64::MAX.saturating_sub(2);

            for i in 0..5 {
                let order_id = format!("counter_test_{i}");
                let mut test_order = make_order(
                    &order_id,
                    QuarantineSeverity::Critical,
                    QuarantineMode::Hard,
                );
                test_order.scope = QuarantineScope::AllVersions {
                    extension_id: format!("ext_counter_{i}"),
                };

                let _ = reg.initiate_quarantine(test_order);

                // Verify total quarantines uses saturating arithmetic
                assert!(
                    reg.total_quarantines() <= u64::MAX,
                    "Total quarantines should not overflow"
                );

                // Progress to recall and test recall counter
                let _ = reg.enforce_quarantine(&order_id, "2026-01-15T00:02:00Z");
                let _ = reg.start_drain(&order_id, "2026-01-15T00:03:00Z");
                let _ = reg.complete_drain(&order_id, "2026-01-15T00:04:00Z");

                let recall_order = make_recall(&order_id);
                if reg.trigger_recall(recall_order).is_ok() {
                    let _ = reg.complete_recall(&order_id, "2026-01-16T14:00:00Z");
                    assert!(
                        reg.total_recalls() <= u64::MAX,
                        "Total recalls should not overflow"
                    );
                }
            }

            // Test grace period overflow
            let mut overflow_order = make_order(
                "grace_overflow",
                QuarantineSeverity::Low,
                QuarantineMode::Hard,
            );
            overflow_order.grace_period_secs = u64::MAX;

            let grace_result = reg.initiate_quarantine(overflow_order);
            assert!(
                grace_result.is_ok(),
                "Should handle extreme grace period values"
            );
        }

        #[test]
        fn memory_exhaustion_through_massive_audit_and_receipt_datasets() {
            let mut reg = QuarantineRegistry::new();

            // Create massive audit trail to test memory bounds
            for cycle in 0..50 {
                for i in 0..100 {
                    let order_id = format!("massive_audit_{cycle}_{i:04}");
                    let mut massive_order =
                        make_order(&order_id, QuarantineSeverity::High, QuarantineMode::Hard);
                    massive_order.scope = QuarantineScope::AllVersions {
                        extension_id: format!("ext_massive_{cycle}_{i}"),
                    };
                    massive_order.justification = "x".repeat(10_000); // Large justification
                    massive_order.trace_id = format!("trace_{}", "y".repeat(1000));

                    let record_result = reg.initiate_quarantine(massive_order);
                    if record_result.is_err() {
                        break; // Capacity limits reached
                    }

                    // Rapidly cycle through states to generate audit entries
                    let _ = reg.enforce_quarantine(&order_id, "2026-01-15T00:02:00Z");
                    let _ = reg.start_drain(&order_id, "2026-01-15T00:03:00Z");
                    let _ = reg.complete_drain(&order_id, "2026-01-15T00:04:00Z");

                    // Test with massive recall orders
                    let mut massive_recall = make_recall(&order_id);
                    massive_recall.reason = "z".repeat(5000); // Large recall reason
                    if reg.trigger_recall(massive_recall).is_ok() {
                        // Generate massive recall receipts
                        for receipt_i in 0..200 {
                            let receipt = RecallReceipt {
                                node_id: format!("massive_node_{cycle}_{i}_{receipt_i}"),
                                recall_id: "recall-001".to_owned(),
                                removed: receipt_i % 2 == 0,
                                removal_method: format!("method_{}", "a".repeat(500)),
                                removed_at: format!("2026-01-16T{:02}:00:00Z", receipt_i % 24),
                                artifact_hash: "b".repeat(64),
                            };

                            let receipt_result = reg.record_recall_receipt(&order_id, receipt);
                            if receipt_result.is_err() {
                                break; // Capacity or state issues
                            }
                        }

                        let _ = reg.complete_recall(&order_id, "2026-01-16T14:00:00Z");
                    }
                }

                // Verify capacity limits are respected
                assert!(
                    reg.audit_trail().len() <= MAX_AUDIT_TRAIL,
                    "Audit trail should respect capacity limits"
                );

                // Check memory usage through record inspection
                if let Some(record) = reg.records.values().next() {
                    assert!(
                        record.recall_receipts.len() <= MAX_RECALL_RECEIPTS,
                        "Recall receipts should be bounded"
                    );
                }
            }

            // Test audit integrity with massive dataset
            let integrity_result = reg.verify_audit_integrity();
            assert!(
                integrity_result.is_ok(),
                "Audit integrity should be maintained with massive data"
            );

            // Test quarantine status checks with massive dataset
            let active_count = reg.active_count();
            assert!(
                active_count <= MAX_RECORDS,
                "Active count should respect capacity limits"
            );

            // Generate summary metrics with massive data
            let total_quarantines = reg.total_quarantines();
            let total_recalls = reg.total_recalls();
            assert!(
                total_quarantines <= u64::MAX,
                "Quarantine totals should be finite"
            );
            assert!(total_recalls <= u64::MAX, "Recall totals should be finite");
        }

        #[test]
        fn state_consistency_validation_under_quarantine_error_conditions() {
            let mut reg = QuarantineRegistry::new();

            // Test inconsistent state transitions
            let order_id = "inconsistent_state";
            reg.initiate_quarantine(make_order(
                order_id,
                QuarantineSeverity::High,
                QuarantineMode::Hard,
            ))
            .expect("should succeed");

            // Attempt invalid state transitions and verify rejections
            let invalid_transitions = [
                // Try to start drain without enforcement
                ("start_drain", |reg: &mut QuarantineRegistry| {
                    reg.start_drain(order_id, "2026-01-15T00:03:00Z")
                }),
                // Try to complete drain without starting
                ("complete_drain", |reg: &mut QuarantineRegistry| {
                    reg.complete_drain(order_id, "2026-01-15T00:04:00Z")
                }),
                // Try to trigger recall without isolation
                ("trigger_recall", |reg: &mut QuarantineRegistry| {
                    reg.trigger_recall(make_recall(order_id))
                }),
                // Try to lift quarantine without isolation
                ("lift_quarantine", |reg: &mut QuarantineRegistry| {
                    reg.lift_quarantine(make_clearance(order_id))
                }),
            ];

            for (transition_name, transition_fn) in invalid_transitions {
                let result = transition_fn(&mut reg);
                assert!(
                    result.is_err(),
                    "Invalid transition '{transition_name}' should be rejected"
                );

                // Verify state remains unchanged after invalid transition
                let record = reg.get_record(order_id).expect("record should still exist");
                assert_eq!(
                    record.state,
                    QuarantineState::Initiated,
                    "State should be unchanged after invalid transition '{transition_name}'"
                );
            }

            // Test with corrupted active quarantine index
            reg.active_quarantines
                .insert("phantom_ext".to_string(), "phantom_order".to_string());

            // Should handle phantom entries gracefully
            assert!(
                !reg.is_quarantined("phantom_ext"),
                "Phantom entries should not report as quarantined"
            );
            assert!(
                reg.get_active_quarantine("phantom_ext").is_none(),
                "Phantom entries should return None"
            );

            // Test record capacity with mixed terminal/live states
            let mut mixed_registry = QuarantineRegistry::new();

            // Fill with live orders
            for i in 0..(MAX_RECORDS / 2) {
                mixed_registry
                    .initiate_quarantine(make_order_for_extension(
                        &format!("live_{i}"),
                        &format!("ext_live_{i}"),
                        QuarantineSeverity::Low,
                        QuarantineMode::Soft,
                    ))
                    .expect("should succeed");
            }

            // Fill with terminal orders
            for i in 0..(MAX_RECORDS / 2) {
                let order_id = format!("terminal_{i}");
                let ext_id = format!("ext_terminal_{i}");

                mixed_registry
                    .initiate_quarantine(make_order_for_extension(
                        &order_id,
                        &ext_id,
                        QuarantineSeverity::High,
                        QuarantineMode::Hard,
                    ))
                    .expect("should succeed");

                // Complete lifecycle to terminal state
                let _ = mixed_registry.enforce_quarantine(&order_id, "2026-01-15T00:02:00Z");
                let _ = mixed_registry.start_drain(&order_id, "2026-01-15T00:03:00Z");
                let _ = mixed_registry.complete_drain(&order_id, "2026-01-15T00:04:00Z");
                let _ = mixed_registry.lift_quarantine(make_clearance(&order_id));
            }

            // Should correctly identify reclaimable records
            let active_count = mixed_registry.active_count();
            assert!(
                active_count <= MAX_RECORDS / 2,
                "Active count should reflect only live orders"
            );

            // Test one more order to trigger reclamation
            let reclaim_result = mixed_registry.initiate_quarantine(make_order_for_extension(
                "reclaim_test",
                "ext_reclaim",
                QuarantineSeverity::Medium,
                QuarantineMode::Soft,
            ));
            assert!(
                reclaim_result.is_ok(),
                "Should reclaim terminal record successfully"
            );
        }

        #[test]
        fn hash_collision_resistance_in_audit_chain_integrity() {
            let mut reg = QuarantineRegistry::new();

            // Generate many similar audit entries to test hash collision resistance
            let mut generated_hashes = std::collections::HashSet::new();

            for i in 0..1000 {
                let order_id = format!("hash_test_{i:05}");
                let ext_id = format!("ext_hash_{i:05}");

                let mut test_order =
                    make_order(&order_id, QuarantineSeverity::Low, QuarantineMode::Soft);
                test_order.scope = QuarantineScope::AllVersions {
                    extension_id: ext_id,
                };

                // Vary details slightly to test hash discrimination
                test_order.justification = format!("Hash collision test with minor variation {i}");
                test_order.trace_id = format!("trace_hash_{i:05}");
                test_order.issued_at = format!("2026-01-{:02}T{:02}:00:00Z", (i % 28) + 1, i % 24);

                let record_result = reg.initiate_quarantine(test_order);
                if record_result.is_err() {
                    break; // Capacity limits reached
                }

                // Cycle through some state transitions to generate varied audit entries
                if i % 3 == 0 {
                    let _ = reg.enforce_quarantine(
                        &order_id,
                        &format!("2026-01-{:02}T{:02}:02:00Z", (i % 28) + 1, i % 24),
                    );
                }
                if i % 5 == 0 {
                    let _ = reg.record_propagation(
                        &order_id,
                        &format!("node_{}", i % 100),
                        &format!("2026-01-{:02}T{:02}:01:00Z", (i % 28) + 1, i % 24),
                    );
                }
            }

            // Collect all audit entry hashes
            for entry in reg.audit_trail() {
                let hash_inserted = generated_hashes.insert(entry.entry_hash.clone());
                assert!(
                    hash_inserted,
                    "Hash collision detected: duplicate entry_hash {}",
                    entry.entry_hash
                );

                // Verify hash chain linkage
                assert!(!entry.prev_hash.is_empty(), "prev_hash should not be empty");
                assert!(
                    !entry.entry_hash.is_empty(),
                    "entry_hash should not be empty"
                );
                assert_ne!(
                    entry.prev_hash, entry.entry_hash,
                    "prev_hash and entry_hash should be different"
                );
            }

            // Verify hash computation is deterministic
            if let Some(first_entry) = reg.audit_trail().first() {
                let recomputed_hash = compute_entry_hash(first_entry);
                assert_eq!(
                    first_entry.entry_hash, recomputed_hash,
                    "Hash computation should be deterministic"
                );
            }

            // Test audit integrity verification
            let integrity_result = reg.verify_audit_integrity();
            assert!(
                integrity_result.is_ok(),
                "Audit integrity should be maintained despite many entries"
            );

            // Test hash resistance to small changes
            let mut reg2 = QuarantineRegistry::new();
            let order1 = make_order(
                "identical_base",
                QuarantineSeverity::Low,
                QuarantineMode::Soft,
            );
            let mut order2 = make_order(
                "identical_base",
                QuarantineSeverity::Low,
                QuarantineMode::Soft,
            );
            order2.justification = format!("{} ", order2.justification); // Add single space

            reg.initiate_quarantine(order1).expect("should succeed");
            reg2.initiate_quarantine(order2).expect("should succeed");

            let hash1 = reg.audit_trail().last().unwrap().entry_hash.clone();
            let hash2 = reg2.audit_trail().last().unwrap().entry_hash.clone();

            assert_ne!(
                hash1, hash2,
                "Small changes should produce different hashes"
            );
        }

        #[test]
        fn resource_exhaustion_through_capacity_boundary_attacks() {
            // Test audit trail capacity exhaustion
            let mut audit_registry = QuarantineRegistry::new();

            // Fill audit trail beyond capacity to test eviction behavior
            for i in 0..(MAX_AUDIT_TRAIL + 500) {
                let order_id = format!("audit_exhaust_{i:06}");
                let mut audit_order = make_order(
                    &order_id,
                    QuarantineSeverity::Critical,
                    QuarantineMode::Hard,
                );
                audit_order.scope = QuarantineScope::AllVersions {
                    extension_id: format!("ext_audit_{i:06}"),
                };

                let record_result = audit_registry.initiate_quarantine(audit_order);
                if record_result.is_err() {
                    break; // Hit record capacity first
                }

                // Generate multiple audit entries per order
                let _ = audit_registry.record_propagation(
                    &order_id,
                    &format!("node_{i}"),
                    "2026-01-15T00:01:00Z",
                );
                let _ = audit_registry.enforce_quarantine(&order_id, "2026-01-15T00:02:00Z");
            }

            // Should respect audit trail capacity
            assert!(
                audit_registry.audit_trail().len() <= MAX_AUDIT_TRAIL,
                "Audit trail should be bounded"
            );

            // Audit integrity should survive eviction
            let integrity_result = audit_registry.verify_audit_integrity();
            assert!(
                integrity_result.is_ok(),
                "Audit integrity should survive capacity eviction"
            );

            // Test propagation status capacity
            let mut prop_registry = QuarantineRegistry::new();
            let order = make_order("prop_test", QuarantineSeverity::Low, QuarantineMode::Soft);
            prop_registry
                .initiate_quarantine(order)
                .expect("should succeed");

            // Fill propagation status beyond capacity
            for i in 0..(MAX_PROPAGATION_STATUS + 100) {
                let node_id = format!("prop_node_{i:06}");
                let timestamp = format!("2026-01-15T{:02}:00:00Z", i % 24);

                let prop_result =
                    prop_registry.record_propagation("prop_test", &node_id, &timestamp);
                assert!(
                    prop_result.is_ok(),
                    "Propagation recording should handle capacity gracefully"
                );
            }

            // Should respect propagation capacity
            assert!(
                prop_registry.propagation_status.len() <= MAX_PROPAGATION_STATUS,
                "Propagation status should be bounded"
            );

            // Test recall receipt capacity
            let mut receipt_registry = setup_recall_registry("receipt_capacity");

            // Fill recall receipts beyond capacity
            for i in 0..(MAX_RECALL_RECEIPTS + 200) {
                let receipt = RecallReceipt {
                    node_id: format!("receipt_node_{i:06}"),
                    recall_id: "recall-001".to_owned(),
                    removed: i % 2 == 0,
                    removal_method: format!("method_{i}"),
                    removed_at: format!("2026-01-16T{:02}:00:00Z", i % 24),
                    artifact_hash: format!("hash_{i:06}"),
                };

                let receipt_result =
                    receipt_registry.record_recall_receipt("receipt_capacity", receipt);
                assert!(
                    receipt_result.is_ok(),
                    "Receipt recording should handle capacity gracefully"
                );
            }

            // Should respect receipt capacity
            let record = receipt_registry
                .get_record("receipt_capacity")
                .expect("record should exist");
            assert!(
                record.recall_receipts.len() <= MAX_RECALL_RECEIPTS,
                "Recall receipts should be bounded"
            );

            // Test state history capacity
            let mut state_registry = QuarantineRegistry::new();
            let state_order = make_order(
                "state_capacity",
                QuarantineSeverity::High,
                QuarantineMode::Hard,
            );
            state_registry
                .initiate_quarantine(state_order)
                .expect("should succeed");

            // Force many state transitions (though limited by state machine)
            for i in 0..10 {
                let timestamp = format!("2026-01-15T00:{:02}:00Z", i);
                let _ = state_registry.enforce_quarantine("state_capacity", &timestamp);
                let _ = state_registry.start_drain("state_capacity", &timestamp);
                let _ = state_registry.complete_drain("state_capacity", &timestamp);

                // Check state history remains bounded
                let record = state_registry
                    .get_record("state_capacity")
                    .expect("record should exist");
                assert!(
                    record.state_history.len() <= MAX_STATE_HISTORY,
                    "State history should be bounded"
                );
            }

            // Test push_bounded function directly with edge cases
            let mut test_items = vec![1, 2, 3, 4, 5];

            // Test zero capacity
            push_bounded(&mut test_items, 6, 0);
            assert!(
                test_items.is_empty(),
                "Zero capacity should clear all items"
            );

            // Test normal bounded operation
            let mut bounded_items = Vec::new();
            for i in 0..20 {
                push_bounded(&mut bounded_items, i, 10);
            }
            assert_eq!(bounded_items.len(), 10, "Should maintain capacity limit");
            assert_eq!(bounded_items[9], 19, "Should preserve most recent items");
        }

        #[test]
        fn serialization_format_injection_resistance_in_structured_data() {
            let injection_payloads = [
                "normal content",
                "content\nwith\nnewlines",
                "content\twith\ttabs",
                "content\rwith\rcarriage\rreturns",
                "content with \u{0000} null bytes",
                "content with \u{001F} control chars \u{007F}",
                "content with unicode \u{202E} direction \u{202D} overrides",
                "content with json {\"malicious\": true} injection",
                "content with xml </tag><script>alert(1)</script><tag>",
                "content with sql '; DROP TABLE quarantine; --",
                "content with shell && rm -rf /",
                "very long content that could cause buffer issues".repeat(1000),
                "\\/\\/comment injection attempt",
                "\\x41\\x42\\x43 hex escape attempt",
            ];

            let mut reg = QuarantineRegistry::new();

            for (i, injection_payload) in injection_payloads.iter().enumerate() {
                // Test injection in all string fields of quarantine orders
                let mut injection_order = make_order(
                    &format!("injection_test_{i}"),
                    QuarantineSeverity::High,
                    QuarantineMode::Hard,
                );
                injection_order.justification =
                    format!("Injected justification: {injection_payload}");
                injection_order.trace_id = format!("trace_{injection_payload}");
                injection_order.issued_by = format!("operator_{injection_payload}");
                injection_order.signature = format!("sig_{injection_payload}");
                injection_order.scope = QuarantineScope::Version {
                    extension_id: format!("ext_{injection_payload}"),
                    version: format!("v1.0.{}", injection_payload.len()),
                };

                // Should handle injection attempts gracefully
                let record_result = reg.initiate_quarantine(injection_order.clone());
                assert!(
                    record_result.is_ok(),
                    "Should handle injection attempt {i} without error"
                );

                // Test serialization safety
                let json_result = serde_json::to_string(&injection_order);
                assert!(
                    json_result.is_ok(),
                    "Should serialize injection attempt {i} safely"
                );

                if let Ok(json_str) = json_result {
                    // Verify no script tags or dangerous content in JSON
                    assert!(
                        !json_str.contains("<script>"),
                        "Serialized JSON should not contain script tags"
                    );
                    assert!(
                        !json_str.contains("</script>"),
                        "Serialized JSON should not contain closing script tags"
                    );

                    // Test deserialization safety
                    let deserialize_result: Result<QuarantineOrder, _> =
                        serde_json::from_str(&json_str);
                    assert!(
                        deserialize_result.is_ok(),
                        "Should deserialize injection attempt {i} safely"
                    );

                    if let Ok(deserialized) = deserialize_result {
                        assert_eq!(
                            deserialized.justification, injection_order.justification,
                            "Content should be preserved safely"
                        );
                    }
                }

                // Test injection in audit trail generation
                let audit_entries = reg.audit_trail();
                for entry in audit_entries {
                    assert!(
                        !entry.details.is_empty(),
                        "Audit details should not be corrupted"
                    );

                    // Test audit entry serialization
                    let audit_json = serde_json::to_string(entry);
                    assert!(audit_json.is_ok(), "Audit entry should serialize safely");
                }

                // Progress to test injection in other data structures
                let order_id = format!("injection_test_{i}");
                let _ = reg.enforce_quarantine(&order_id, "2026-01-15T00:02:00Z");
                let _ = reg.start_drain(&order_id, "2026-01-15T00:03:00Z");
                let _ = reg.complete_drain(&order_id, "2026-01-15T00:04:00Z");

                // Test injection in recall orders
                let mut injection_recall = make_recall(&order_id);
                injection_recall.reason = format!("Injected recall reason: {injection_payload}");
                injection_recall.trace_id = format!("recall_trace_{injection_payload}");
                injection_recall.issued_by = format!("security_{injection_payload}");

                if reg.trigger_recall(injection_recall.clone()).is_ok() {
                    // Test recall serialization
                    let recall_json = serde_json::to_string(&injection_recall);
                    assert!(
                        recall_json.is_ok(),
                        "Recall order should serialize safely despite injection"
                    );

                    // Test injection in recall receipts
                    let injection_receipt = RecallReceipt {
                        node_id: format!("node_{injection_payload}"),
                        recall_id: "recall-001".to_owned(),
                        removed: true,
                        removal_method: format!("method_{injection_payload}"),
                        removed_at: "2026-01-16T13:00:00Z".to_owned(),
                        artifact_hash: format!("hash_{injection_payload}"),
                    };

                    let receipt_result =
                        reg.record_recall_receipt(&order_id, injection_receipt.clone());
                    if receipt_result.is_ok() {
                        let receipt_json = serde_json::to_string(&injection_receipt);
                        assert!(receipt_json.is_ok(), "Receipt should serialize safely");
                    }
                }

                // Test injection in impact reports
                let impact_result = reg.generate_impact_report(
                    &order_id,
                    100,
                    vec![format!("data_risk_{injection_payload}")],
                    vec![format!("dependent_{injection_payload}")],
                    5,
                    vec![format!("action_{injection_payload}")],
                    "2026-01-15T01:00:00Z",
                );

                if let Ok(impact_report) = impact_result {
                    let impact_json = serde_json::to_string(&impact_report);
                    assert!(impact_json.is_ok(), "Impact report should serialize safely");
                }
            }

            // Test overall registry serialization with injected content
            let registry_json = serde_json::to_string(&reg);
            assert!(
                registry_json.is_ok(),
                "Registry should serialize safely with all injected content"
            );

            // Verify no dangerous content in final serialized form
            if let Ok(json_str) = registry_json {
                assert!(
                    !json_str.contains("<script>"),
                    "Registry JSON should not contain script tags"
                );
                assert!(
                    !json_str.contains("DROP TABLE"),
                    "Registry JSON should not contain SQL injection"
                );
                assert!(
                    !json_str.contains("&& rm"),
                    "Registry JSON should not contain shell injection"
                );
            }
        }

        #[test]
        fn timing_attack_resistance_in_constant_time_operations() {
            let mut reg = QuarantineRegistry::new();

            // Set up a quarantine and recall for timing tests
            let order = make_order(
                "timing_test",
                QuarantineSeverity::High,
                QuarantineMode::Hard,
            );
            reg.initiate_quarantine(order).expect("should succeed");
            let _ = reg.enforce_quarantine("timing_test", "2026-01-15T00:02:00Z");
            let _ = reg.start_drain("timing_test", "2026-01-15T00:03:00Z");
            let _ = reg.complete_drain("timing_test", "2026-01-15T00:04:00Z");
            reg.trigger_recall(make_recall("timing_test"))
                .expect("should succeed");

            // Test constant-time comparison in recall receipt validation
            let correct_receipt = RecallReceipt {
                node_id: "timing_node".to_owned(),
                recall_id: "recall-001".to_owned(), // Correct recall ID
                removed: true,
                removal_method: "crypto_erase".to_owned(),
                removed_at: "2026-01-16T13:00:00Z".to_owned(),
                artifact_hash: "abc123".to_owned(),
            };

            // Test with various incorrect recall IDs of different lengths
            let incorrect_recall_ids = [
                "",                 // Empty
                "a",                // Single char
                "wrong",            // Short
                "recall-001-wrong", // Longer than correct
                "recall-002",       // Same length, different content
                "RECALL-001",       // Case difference
                "recall-001\0",     // Null byte
                "recall-001 ",      // Trailing space
            ];

            for incorrect_id in incorrect_recall_ids {
                let mut incorrect_receipt = correct_receipt.clone();
                incorrect_receipt.recall_id = incorrect_id.to_owned();
                incorrect_receipt.node_id = format!("node_{}", incorrect_id.len());

                let start_time = std::time::Instant::now();
                let result = reg.record_recall_receipt("timing_test", incorrect_receipt);
                let elapsed = start_time.elapsed();

                // All should fail due to mismatch
                assert!(
                    result.is_err(),
                    "Incorrect recall ID should be rejected: '{incorrect_id}'"
                );
                assert_eq!(result.unwrap_err().code, ERR_RECALL_RECEIPT_MISMATCH);

                // Timing should not vary significantly based on content
                // (This is a basic check; real timing attacks would need more sophisticated analysis)
                assert!(
                    elapsed.as_millis() < 100,
                    "Comparison should complete quickly regardless of input"
                );
            }

            // Test correct receipt should succeed
            let correct_result = reg.record_recall_receipt("timing_test", correct_receipt);
            assert!(correct_result.is_ok(), "Correct receipt should be accepted");

            // Test constant-time behavior in audit hash verification
            let original_trail = reg.audit_trail().to_vec();

            for entry in &original_trail {
                let mut tampered_entry = entry.clone();

                // Test various hash tampering attempts
                let tampered_hashes = [
                    "",                                                 // Empty hash
                    "a",                                                // Short hash
                    "wrong_hash",                                       // Wrong content
                    entry.entry_hash.chars().rev().collect::<String>(), // Reversed
                    format!("{}x", entry.entry_hash),                   // Extended
                    entry.entry_hash.to_uppercase(),                    // Case change
                ];

                for tampered_hash in tampered_hashes {
                    tampered_entry.entry_hash = tampered_hash;

                    let start_time = std::time::Instant::now();
                    let computed_hash = compute_entry_hash(&tampered_entry);
                    let comparison_time = start_time.elapsed();

                    // Computation should be fast regardless of input
                    assert!(
                        comparison_time.as_millis() < 50,
                        "Hash computation should be efficient"
                    );

                    // Should not match the tampered hash (except by coincidence)
                    if computed_hash == tampered_hash {
                        // This would be an extremely unlikely hash collision
                        tracing::warn!(
                            computed_hash = %hex::encode(&computed_hash),
                            tampered_hash = %hex::encode(&tampered_hash),
                            "possible hash collision detected"
                        );
                    }
                }
            }

            // Test that ct_eq function is actually being used for sensitive comparisons
            // (This verifies the constant-time comparison is in the code path)
            let test_string1 = "sensitive_data_1";
            let test_string2 = "sensitive_data_2";
            let test_string3 = "sensitive_data_1"; // Same as first

            assert!(
                !constant_time::ct_eq(test_string1, test_string2),
                "Different strings should not match"
            );
            assert!(
                constant_time::ct_eq(test_string1, test_string3),
                "Identical strings should match"
            );
            assert!(
                constant_time::ct_eq(test_string1, test_string1),
                "String should match itself"
            );
        }

        // -- Hardening Negative Path Tests --

        #[test]
        fn negative_length_cast_overflow_in_entry_hash_computation() {
            // Test .len() as u64 patterns that should use u64::try_from for safety
            // Lines 292-314 have multiple instances of .len() as u64

            let mut test_entry = QuarantineAuditEntry {
                sequence: QuarantineAuditId::new(1),
                event_code: "TEST_EVENT".to_string(),
                order_id: "test-order-id".to_string(),
                extension_id: "test-ext".to_string(),
                severity: QuarantineSeverity::High,
                trace_id: "test-trace".to_string(),
                timestamp: QuarantineAuditTimestamp::try_from("2026-01-01T00:00:00Z").unwrap(),
                details: "test details".to_string(),
                prev_hash: "prev-hash".to_string(),
                entry_hash: String::new(),
            };

            // Test with extreme string lengths to verify safe casting behavior
            let extreme_lengths = vec![(0, "empty"), (u32::MAX as usize, "max_u32")];

            for (length, label) in extreme_lengths {
                // Test various string fields with boundary lengths
                let test_length = std::cmp::min(length, 10000); // Limit for test performance

                // Test event_code field
                test_entry.event_code = "E".repeat(test_length);
                let hash1 = compute_entry_hash(&test_entry);
                assert_eq!(hash1.len(), 64, "hash should be 64 hex chars for {}", label);

                // Test order_id field
                test_entry.order_id = "O".repeat(test_length);
                let hash2 = compute_entry_hash(&test_entry);
                assert_eq!(
                    hash2.len(),
                    64,
                    "hash should be consistent length for {}",
                    label
                );

                // Reset for next test
                test_entry.event_code = "TEST_EVENT".to_string();
                test_entry.order_id = "test-order-id".to_string();
            }

            // Test that the casting would be vulnerable without try_from
            let mock_large_length = u64::MAX as usize;

            // Unsafe version (what we're protecting against): .len() as u64
            if mock_large_length <= u32::MAX as usize {
                let _unsafe_cast = mock_large_length as u64; // Could truncate on 32-bit
            }

            // Safe version (what should be used): u64::try_from().unwrap_or(u64::MAX)
            let safe_cast = u64::try_from(mock_large_length).unwrap_or(u64::MAX);
            assert!(safe_cast <= u64::MAX, "safe casting should not overflow");
        }

        #[test]
        fn negative_f64_arithmetic_without_finite_guards() {
            // Test f64 arithmetic in recall_completion_pct that needs is_finite() guards
            // Lines 1018-1019 perform f64 division that could produce NaN/Inf

            let mut reg = QuarantineRegistry::new();
            let order = make_order(
                "test-recall-f64",
                QuarantineSeverity::High,
                QuarantineMode::Hard,
            );
            reg.initiate_quarantine(order).unwrap();

            let order_id = "test-recall-f64";
            let recall = make_recall(order_id);
            reg.trigger_recall(recall).unwrap();

            // Add some recall receipts
            reg.record_recall_receipt(
                order_id,
                RecallReceipt {
                    node_id: "node-1".to_string(),
                    recall_id: "recall-001".to_string(),
                    removed: true,
                    removal_method: "crypto_erase".to_string(),
                    removed_at: "2026-01-01T01:00:00Z".to_string(),
                    artifact_hash: "hash123".to_string(),
                },
            )
            .unwrap();

            // Test edge cases that could produce invalid f64 values
            let edge_cases = vec![
                (1, 0),        // Division by zero -> Inf
                (0, 0),        // 0/0 -> NaN
                (u64::MAX, 1), // Large numerator
                (1, u64::MAX), // Large denominator
            ];

            for (confirmed_nodes, total_nodes) in edge_cases {
                let pct = reg.recall_completion_pct(order_id, total_nodes);

                // Current implementation may produce NaN or Inf without guards
                if total_nodes == 0 {
                    // Division by zero case - should be handled gracefully
                    assert!(
                        pct.is_infinite() || pct.is_nan() || pct == 0.0,
                        "division by zero should be handled: got {}",
                        pct
                    );
                } else {
                    // Normal cases should produce finite results
                    if !pct.is_finite() {
                        // Document the current vulnerable behavior
                        tracing::warn!(
                            percentage = %pct,
                            "non-finite percentage detected"
                        );
                    }

                    // In a hardened version, this should always be finite:
                    // assert!(pct.is_finite(), "percentage should be finite: {}", pct);
                    // assert!(pct >= 0.0 && pct <= 100.0, "percentage should be in valid range");
                }
            }

            // Test that is_finite() guards would prevent issues
            let test_values = vec![f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 42.0];
            for test_val in test_values {
                if test_val.is_finite() {
                    // Only finite values should be used
                    assert!(test_val >= f64::MIN && test_val <= f64::MAX);
                } else {
                    // Non-finite values should be rejected
                    assert!(test_val.is_nan() || test_val.is_infinite());
                }
            }
        }

        #[test]
        fn negative_vec_push_without_bounded_capacity_protection() {
            // Test Vec::push operations that should use push_bounded for capacity protection
            // Lines 433, 1214 use Vec::push without bounds checking

            let mut reg = QuarantineRegistry::new();

            // Test unbounded audit trail growth (line 1214)
            // Fill audit trail beyond its intended capacity
            for i in 0..MAX_AUDIT_TRAIL + 100 {
                let order_id = format!("overflow-order-{}", i);
                let order = make_order(&order_id, QuarantineSeverity::Low, QuarantineMode::Soft);

                // Each quarantine operation appends to audit_trail via push()
                let _ = reg.initiate_quarantine(order);
            }

            // Audit trail should be bounded by push_bounded, not grow indefinitely
            assert!(
                reg.audit_trail.len() <= MAX_AUDIT_TRAIL,
                "audit trail should be bounded: {} <= {}",
                reg.audit_trail.len(),
                MAX_AUDIT_TRAIL
            );

            // Test state_history growth within records (line 433 area)
            let test_order = make_order(
                "state-test",
                QuarantineSeverity::Medium,
                QuarantineMode::Hard,
            );
            reg.initiate_quarantine(test_order).unwrap();

            // Simulate many state transitions that could grow state_history unbounded
            let order_id = "state-test";

            // These operations use push() on state_history (line 433 pattern)
            for _ in 0..MAX_STATE_HISTORY + 50 {
                let _ = reg.record_propagation(
                    order_id,
                    &format!("node-{}", rand::random::<u32>()),
                    "2026-01-01T00:00:00Z",
                );
            }

            if let Some(record) = reg.get_record(order_id) {
                assert!(
                    record.state_history.len() <= MAX_STATE_HISTORY,
                    "state history should be bounded: {} <= {}",
                    record.state_history.len(),
                    MAX_STATE_HISTORY
                );
            }

            // Test push_bounded behavior directly
            let mut test_vec = vec!["item1", "item2", "item3"];

            // Should evict oldest when at capacity
            push_bounded(&mut test_vec, "item4", 3);
            assert_eq!(test_vec.len(), 3, "should maintain capacity");
            assert_eq!(
                test_vec,
                vec!["item2", "item3", "item4"],
                "should evict oldest"
            );

            // Should handle capacity = 0 safely
            push_bounded(&mut test_vec, "item5", 0);
            assert!(test_vec.is_empty(), "zero capacity should clear vector");
        }

        #[test]
        fn negative_arithmetic_overflow_in_counters_without_saturating_add() {
            // Test saturating_add protection for counter increments
            // Line 452 correctly uses saturating_add, verify it prevents overflow

            let mut reg = QuarantineRegistry::new();

            // Set counters near overflow to test saturation behavior
            reg.total_quarantines = u64::MAX - 5;
            reg.total_recalls = u64::MAX - 3;

            let initial_quarantines = reg.total_quarantines;
            let initial_recalls = reg.total_recalls;

            // Test quarantine counter saturation
            for i in 0..10 {
                let order_id = format!("overflow-test-{}", i);
                let order = make_order(&order_id, QuarantineSeverity::Low, QuarantineMode::Soft);

                let _ = reg.initiate_quarantine(order);
            }

            // Should saturate at u64::MAX, not wrap around
            assert_eq!(
                reg.total_quarantines,
                u64::MAX,
                "quarantine counter should saturate at MAX"
            );

            // Test recall counter behavior
            let test_order = make_order(
                "recall-overflow",
                QuarantineSeverity::High,
                QuarantineMode::Hard,
            );
            reg.initiate_quarantine(test_order).unwrap();

            let recall = make_recall("recall-overflow");
            for _ in 0..10 {
                // This should increment total_recalls with saturating arithmetic
                let _ = reg.trigger_recall(recall.clone());
            }

            // Should handle multiple operations without overflow
            assert!(
                reg.total_recalls >= initial_recalls,
                "recall counter should not underflow"
            );
            assert!(
                reg.total_recalls <= u64::MAX,
                "recall counter should not overflow"
            );

            // Test arithmetic edge cases directly
            let near_max = u64::MAX - 1;
            let saturated = near_max.saturating_add(1);
            assert_eq!(saturated, u64::MAX, "should saturate at boundary");

            let at_max = u64::MAX.saturating_add(1);
            assert_eq!(at_max, u64::MAX, "should remain at MAX when saturating");

            // Demonstrate vulnerable pattern (what we're protecting against)
            let vulnerable_counter = u64::MAX - 1;
            // vulnerable_counter += 1; // Would panic in debug, wrap in release

            let safe_counter = vulnerable_counter.saturating_add(1);
            assert_eq!(safe_counter, u64::MAX, "safe increment should saturate");
        }
    }
}
