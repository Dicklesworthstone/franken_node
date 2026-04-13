//! bd-1vm: Fast quarantine/recall workflow for compromised artifacts.
//!
//! Implements the "immune response" for the extension ecosystem: quarantine isolates
//! threats while investigation proceeds, recall removes compromised artifacts from all
//! nodes. Integrates with revocation propagation for signal delivery and trust cards
//! for status visibility.

use std::collections::{BTreeMap, BTreeSet};

use crate::security::constant_time::ct_eq;

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
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
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
pub const ERR_AUDIT_CHAIN_BROKEN: &str = "ERR_AUDIT_CHAIN_BROKEN";

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
    pub sequence: u64,
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
    pub timestamp: String,
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
    hasher.update(entry.sequence.to_le_bytes());
    hasher.update((entry.event_code.len() as u64).to_le_bytes());
    hasher.update(entry.event_code.as_bytes());
    hasher.update((entry.order_id.len() as u64).to_le_bytes());
    hasher.update(entry.order_id.as_bytes());
    hasher.update((entry.extension_id.len() as u64).to_le_bytes());
    hasher.update(entry.extension_id.as_bytes());

    let severity_str = match entry.severity {
        QuarantineSeverity::Low => "low",
        QuarantineSeverity::Medium => "medium",
        QuarantineSeverity::High => "high",
        QuarantineSeverity::Critical => "critical",
    };
    hasher.update((severity_str.len() as u64).to_le_bytes());
    hasher.update(severity_str.as_bytes());

    hasher.update((entry.trace_id.len() as u64).to_le_bytes());
    hasher.update(entry.trace_id.as_bytes());
    hasher.update((entry.timestamp.len() as u64).to_le_bytes());
    hasher.update(entry.timestamp.as_bytes());
    hasher.update((entry.details.len() as u64).to_le_bytes());
    hasher.update(entry.details.as_bytes());
    hasher.update((entry.prev_hash.len() as u64).to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    format!("{:x}", hasher.finalize())
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
    next_sequence: u64,
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
            next_sequence: 0,
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
        );

        if initial_state == QuarantineState::Enforced {
            self.append_audit(
                QUARANTINE_ENFORCED,
                &order_id,
                &ext_id,
                severity,
                &trace_id,
                &timestamp,
                "Critical severity: immediate enforcement via fast-path",
            );
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
        );

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
            );
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
        );

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
        );

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
        );

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
        push_bounded(&mut record.recall_receipts, receipt, MAX_RECALL_RECEIPTS);

        self.append_audit(
            RECALL_RECEIPT_EMITTED,
            order_id,
            &ext_id,
            severity,
            &trace_id,
            &timestamp,
            &format!("Recall receipt from node {node_id}"),
        );

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
        );

        Ok(())
    }

    /// Lift a quarantine with signed clearance.
    pub fn lift_quarantine(
        &mut self,
        clearance: QuarantineClearance,
    ) -> Result<(), QuarantineError> {
        let order_id = clearance.order_id.clone();

        // Must have clearance with non-empty justification.
        if clearance.justification.is_empty() {
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
        );

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
                let confirmed = confirmed_nodes.len() as u64;
                let capped = confirmed.min(total_nodes) as f64;
                (capped / total_nodes as f64) * 100.0
            })
            .unwrap_or(0.0)
    }

    /// Verify audit trail integrity (hash chain).
    pub fn verify_audit_integrity(&self) -> Result<bool, QuarantineError> {
        let genesis_hash = format!("{:x}", Sha256::digest(b"quarantine_genesis_v1:"));
        let first_expected = self.chain_anchor_hash.as_deref().unwrap_or(&genesis_hash);

        for (i, entry) in self.audit_trail.iter().enumerate() {
            let expected_prev = if i == 0 {
                first_expected
            } else {
                &self.audit_trail[i - 1].entry_hash
            };

            if !ct_eq(&entry.prev_hash, expected_prev) {
                return Err(QuarantineError {
                    code: ERR_AUDIT_CHAIN_BROKEN.to_owned(),
                    message: format!("Audit chain broken at index {i}: prev_hash mismatch"),
                });
            }

            // Verify entry hash.
            let computed = compute_entry_hash(entry);
            if !ct_eq(&entry.entry_hash, &computed) {
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
    ) {
        let genesis_hash = format!("{:x}", Sha256::digest(b"quarantine_genesis_v1:"));
        let prev_hash = self
            .audit_trail
            .last()
            .map(|e| e.entry_hash.clone())
            .or_else(|| self.chain_anchor_hash.clone())
            .unwrap_or(genesis_hash);

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);

        let mut entry = QuarantineAuditEntry {
            sequence,
            event_code: event_code.to_owned(),
            order_id: order_id.to_owned(),
            extension_id: extension_id.to_owned(),
            severity,
            trace_id: trace_id.to_owned(),
            timestamp: timestamp.to_owned(),
            details: details.to_owned(),
            prev_hash,
            entry_hash: String::new(),
        };

        entry.entry_hash = compute_entry_hash(&entry);
        self.audit_trail.push(entry);
        if self.audit_trail.len() > MAX_AUDIT_TRAIL {
            let overflow = self.audit_trail.len() - MAX_AUDIT_TRAIL;
            self.chain_anchor_hash = Some(self.audit_trail[overflow - 1].entry_hash.clone());
            self.audit_trail.drain(0..overflow);
        }
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(reg.audit_trail().first().expect("should succeed").sequence > 0);

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
}
