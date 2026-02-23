//! bd-2ah: Canonical obligation-tracked two-phase channel contracts for critical flows.
//!
//! Adopts the obligation-tracked two-phase protocol (from bd-1n5p in section 10.15)
//! at the product-runtime layer. Provides `ObligationChannel`, `ObligationLedger`,
//! and `TwoPhaseFlow` abstractions that compose into prepare/commit workflows with
//! deadline tracking, timeout policies, and closure proofs.
//!
//! # Invariants
//!
//! - INV-OCH-TRACKED: every obligation sent through a channel is tracked in the ledger
//! - INV-OCH-DEADLINE: every channel obligation has an explicit deadline
//! - INV-OCH-LEDGER-COMPLETE: the ledger records every state transition
//! - INV-OCH-CLOSURE-SIGNED: closure proofs list all obligations and their terminal states
//! - INV-OCH-TWO-PHASE: critical flows use prepare/commit (never single-shot)
//! - INV-OCH-ROLLBACK-ATOMIC: rollback releases all prepared obligations atomically

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Schema version for the obligation channel protocol.
pub const SCHEMA_VERSION: &str = "och-v1.0";

/// Default deadline in milliseconds for channel obligations.
pub const DEFAULT_DEADLINE_MS: u64 = 30_000;

// ── Invariant constants ─────────────────────────────────────────────────────

/// INV-OCH-TRACKED: every obligation sent through a channel is tracked in the ledger.
pub const INV_OCH_TRACKED: &str = "INV-OCH-TRACKED";

/// INV-OCH-DEADLINE: every channel obligation has an explicit deadline.
pub const INV_OCH_DEADLINE: &str = "INV-OCH-DEADLINE";

/// INV-OCH-LEDGER-COMPLETE: the ledger records every state transition.
pub const INV_OCH_LEDGER_COMPLETE: &str = "INV-OCH-LEDGER-COMPLETE";

/// INV-OCH-CLOSURE-SIGNED: closure proofs list all obligations and their terminal states.
pub const INV_OCH_CLOSURE_SIGNED: &str = "INV-OCH-CLOSURE-SIGNED";

/// INV-OCH-TWO-PHASE: critical flows use prepare/commit (never single-shot).
pub const INV_OCH_TWO_PHASE: &str = "INV-OCH-TWO-PHASE";

/// INV-OCH-ROLLBACK-ATOMIC: rollback releases all prepared obligations atomically.
pub const INV_OCH_ROLLBACK_ATOMIC: &str = "INV-OCH-ROLLBACK-ATOMIC";

// ── Event codes ─────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Obligation created and queued in channel.
    pub const FN_OB_001: &str = "FN-OB-001";
    /// Obligation sent to receiver.
    pub const FN_OB_002: &str = "FN-OB-002";
    /// Obligation fulfilled by receiver.
    pub const FN_OB_003: &str = "FN-OB-003";
    /// Obligation rejected by receiver.
    pub const FN_OB_004: &str = "FN-OB-004";
    /// Obligation timed out.
    pub const FN_OB_005: &str = "FN-OB-005";
    /// Obligation cancelled by sender.
    pub const FN_OB_006: &str = "FN-OB-006";
    /// Two-phase prepare initiated.
    pub const FN_OB_007: &str = "FN-OB-007";
    /// Two-phase prepare succeeded.
    pub const FN_OB_008: &str = "FN-OB-008";
    /// Two-phase commit completed.
    pub const FN_OB_009: &str = "FN-OB-009";
    /// Two-phase rollback completed.
    pub const FN_OB_010: &str = "FN-OB-010";
    /// Closure proof generated.
    pub const FN_OB_011: &str = "FN-OB-011";
    /// Ledger query executed.
    pub const FN_OB_012: &str = "FN-OB-012";
}

// ── Error codes ─────────────────────────────────────────────────────────────

pub mod error_codes {
    pub const ERR_OCH_NOT_FOUND: &str = "ERR_OCH_NOT_FOUND";
    pub const ERR_OCH_ALREADY_FULFILLED: &str = "ERR_OCH_ALREADY_FULFILLED";
    pub const ERR_OCH_ALREADY_REJECTED: &str = "ERR_OCH_ALREADY_REJECTED";
    pub const ERR_OCH_TIMED_OUT: &str = "ERR_OCH_TIMED_OUT";
    pub const ERR_OCH_CANCELLED: &str = "ERR_OCH_CANCELLED";
    pub const ERR_OCH_PREPARE_FAILED: &str = "ERR_OCH_PREPARE_FAILED";
    pub const ERR_OCH_COMMIT_FAILED: &str = "ERR_OCH_COMMIT_FAILED";
    pub const ERR_OCH_ROLLBACK_FAILED: &str = "ERR_OCH_ROLLBACK_FAILED";
    pub const ERR_OCH_DEADLINE_EXCEEDED: &str = "ERR_OCH_DEADLINE_EXCEEDED";
    pub const ERR_OCH_INVALID_TRANSITION: &str = "ERR_OCH_INVALID_TRANSITION";
}

// ── Types ───────────────────────────────────────────────────────────────────

/// Lifecycle status of a channel obligation. INV-OCH-LEDGER-COMPLETE
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObligationStatus {
    /// Obligation has been created but not yet dispatched.
    Created,
    /// Obligation has been fulfilled by the receiver.
    Fulfilled,
    /// Obligation was explicitly rejected by the receiver.
    Rejected,
    /// Obligation exceeded its deadline without resolution.
    TimedOut,
    /// Obligation was cancelled by the sender before resolution.
    Cancelled,
}

impl fmt::Display for ObligationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "Created"),
            Self::Fulfilled => write!(f, "Fulfilled"),
            Self::Rejected => write!(f, "Rejected"),
            Self::TimedOut => write!(f, "TimedOut"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

impl ObligationStatus {
    /// Returns `true` when the status is a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Fulfilled | Self::Rejected | Self::TimedOut | Self::Cancelled
        )
    }
}

/// Timeout policy for obligations that exceed their deadline. INV-OCH-DEADLINE
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TimeoutPolicy {
    /// Retry the obligation up to a configured number of times.
    Retry,
    /// Execute a compensating action.
    Compensate,
    /// Escalate to an operator or higher-level coordinator.
    Escalate,
}

impl fmt::Display for TimeoutPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry => write!(f, "Retry"),
            Self::Compensate => write!(f, "Compensate"),
            Self::Escalate => write!(f, "Escalate"),
        }
    }
}

/// Result of a two-phase prepare operation. INV-OCH-TWO-PHASE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrepareResult {
    /// All obligations in the flow were successfully prepared.
    Ready {
        flow_id: String,
        obligation_ids: Vec<String>,
    },
    /// One or more obligations failed to prepare.
    Failed { flow_id: String, reason: String },
}

/// Result of a two-phase commit operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitResult {
    /// All obligations committed successfully.
    Committed {
        flow_id: String,
        obligation_ids: Vec<String>,
    },
    /// Commit failed; rollback was executed.
    RolledBack { flow_id: String, reason: String },
}

/// A single tracked obligation within a channel. INV-OCH-TRACKED
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelObligation {
    /// Unique obligation identifier.
    pub obligation_id: String,
    /// Deadline in epoch milliseconds.
    pub deadline: u64,
    /// Distributed trace identifier.
    pub trace_id: String,
    /// Current status.
    pub status: ObligationStatus,
    /// Timestamp when created (epoch ms).
    pub created_at_ms: u64,
    /// Timestamp when resolved (epoch ms), if resolved.
    pub resolved_at_ms: Option<u64>,
    /// Timeout policy for this obligation.
    pub timeout_policy: TimeoutPolicy,
    /// Schema version.
    pub schema_version: String,
}

/// Closure proof attesting that all obligations reached a terminal state. INV-OCH-CLOSURE-SIGNED
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureProof {
    /// Flow identifier this closure covers.
    pub flow_id: String,
    /// All obligations and their terminal states.
    pub obligations: BTreeMap<String, ObligationStatus>,
    /// Timestamp when the proof was generated (epoch ms).
    pub generated_at_ms: u64,
    /// Whether every obligation reached a terminal state.
    pub complete: bool,
    /// Schema version.
    pub schema_version: String,
}

/// Audit record for channel obligation events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelAuditRecord {
    /// Event code (FN-OB-001 through FN-OB-012).
    pub event_code: String,
    /// Obligation ID this event relates to (empty for flow-level events).
    pub obligation_id: String,
    /// Status after this event.
    pub status: String,
    /// Trace ID.
    pub trace_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Human-readable detail.
    pub detail: String,
}

// ── ObligationChannel ───────────────────────────────────────────────────────

/// A typed channel wrapping inter-service communication with tracked obligations.
/// INV-OCH-TRACKED, INV-OCH-DEADLINE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationChannel<T: Clone + Serialize> {
    /// Channel identifier.
    pub channel_id: String,
    /// Queued messages paired with their obligation tracking.
    queue: Vec<(ChannelObligation, T)>,
    /// Default deadline for obligations on this channel.
    default_deadline_ms: u64,
    /// Default timeout policy.
    default_timeout_policy: TimeoutPolicy,
    /// Audit log.
    audit_log: Vec<ChannelAuditRecord>,
    /// Next obligation ID sequence number.
    next_id: u64,
}

impl<T: Clone + Serialize> ObligationChannel<T> {
    /// Create a new channel with defaults.
    #[must_use]
    pub fn new(channel_id: &str) -> Self {
        Self {
            channel_id: channel_id.to_string(),
            queue: Vec::new(),
            default_deadline_ms: DEFAULT_DEADLINE_MS,
            default_timeout_policy: TimeoutPolicy::Escalate,
            audit_log: Vec::new(),
            next_id: 1,
        }
    }

    /// Create a new channel with a custom deadline.
    #[must_use]
    pub fn with_deadline(channel_id: &str, deadline_ms: u64) -> Self {
        let mut ch = Self::new(channel_id);
        ch.default_deadline_ms = deadline_ms;
        ch
    }

    /// Send a message through the channel, creating a tracked obligation.
    /// INV-OCH-TRACKED, INV-OCH-DEADLINE
    pub fn send(&mut self, message: T, now_ms: u64, trace_id: &str) -> String {
        let obligation_id = format!("och-{}-{}", self.channel_id, self.next_id);
        self.next_id = self.next_id.saturating_add(1);

        let obligation = ChannelObligation {
            obligation_id: obligation_id.clone(),
            deadline: now_ms + self.default_deadline_ms,
            trace_id: trace_id.to_string(),
            status: ObligationStatus::Created,
            created_at_ms: now_ms,
            resolved_at_ms: None,
            timeout_policy: self.default_timeout_policy,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        self.audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_001.to_string(),
            obligation_id: obligation_id.clone(),
            status: "Created".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: "obligation created and queued".to_string(),
        });

        self.audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_002.to_string(),
            obligation_id: obligation_id.clone(),
            status: "Created".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: "obligation sent to receiver".to_string(),
        });

        self.queue.push((obligation, message));
        obligation_id
    }

    /// Mark an obligation as fulfilled. INV-OCH-LEDGER-COMPLETE
    pub fn fulfill(
        &mut self,
        obligation_id: &str,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let entry = self
            .queue
            .iter_mut()
            .find(|(o, _)| o.obligation_id == obligation_id)
            .ok_or_else(|| error_codes::ERR_OCH_NOT_FOUND.to_string())?;

        match entry.0.status {
            ObligationStatus::Created => {}
            ObligationStatus::Fulfilled => {
                return Err(error_codes::ERR_OCH_ALREADY_FULFILLED.to_string());
            }
            ObligationStatus::Rejected => {
                return Err(error_codes::ERR_OCH_ALREADY_REJECTED.to_string());
            }
            ObligationStatus::TimedOut => {
                return Err(error_codes::ERR_OCH_TIMED_OUT.to_string());
            }
            ObligationStatus::Cancelled => {
                return Err(error_codes::ERR_OCH_CANCELLED.to_string());
            }
        }

        entry.0.status = ObligationStatus::Fulfilled;
        entry.0.resolved_at_ms = Some(now_ms);

        self.audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_003.to_string(),
            obligation_id: obligation_id.to_string(),
            status: "Fulfilled".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: "obligation fulfilled".to_string(),
        });

        Ok(())
    }

    /// Mark an obligation as rejected. INV-OCH-LEDGER-COMPLETE
    pub fn reject(
        &mut self,
        obligation_id: &str,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let entry = self
            .queue
            .iter_mut()
            .find(|(o, _)| o.obligation_id == obligation_id)
            .ok_or_else(|| error_codes::ERR_OCH_NOT_FOUND.to_string())?;

        match entry.0.status {
            ObligationStatus::Created => {}
            ObligationStatus::Fulfilled => {
                return Err(error_codes::ERR_OCH_ALREADY_FULFILLED.to_string());
            }
            ObligationStatus::Rejected => {
                return Err(error_codes::ERR_OCH_ALREADY_REJECTED.to_string());
            }
            ObligationStatus::TimedOut => {
                return Err(error_codes::ERR_OCH_TIMED_OUT.to_string());
            }
            ObligationStatus::Cancelled => {
                return Err(error_codes::ERR_OCH_CANCELLED.to_string());
            }
        }

        entry.0.status = ObligationStatus::Rejected;
        entry.0.resolved_at_ms = Some(now_ms);

        self.audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_004.to_string(),
            obligation_id: obligation_id.to_string(),
            status: "Rejected".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: "obligation rejected".to_string(),
        });

        Ok(())
    }

    /// Cancel an obligation before it is resolved. INV-OCH-LEDGER-COMPLETE
    pub fn cancel(
        &mut self,
        obligation_id: &str,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let entry = self
            .queue
            .iter_mut()
            .find(|(o, _)| o.obligation_id == obligation_id)
            .ok_or_else(|| error_codes::ERR_OCH_NOT_FOUND.to_string())?;

        if entry.0.status.is_terminal() {
            return Err(error_codes::ERR_OCH_INVALID_TRANSITION.to_string());
        }

        entry.0.status = ObligationStatus::Cancelled;
        entry.0.resolved_at_ms = Some(now_ms);

        self.audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_006.to_string(),
            obligation_id: obligation_id.to_string(),
            status: "Cancelled".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: "obligation cancelled".to_string(),
        });

        Ok(())
    }

    /// Scan for obligations that have exceeded their deadline and mark them timed out.
    pub fn sweep_timeouts(&mut self, now_ms: u64, trace_id: &str) -> Vec<String> {
        let mut timed_out = Vec::new();
        for (obligation, _) in &mut self.queue {
            if obligation.status == ObligationStatus::Created && now_ms > obligation.deadline {
                obligation.status = ObligationStatus::TimedOut;
                obligation.resolved_at_ms = Some(now_ms);
                timed_out.push(obligation.obligation_id.clone());
            }
        }

        for id in &timed_out {
            self.audit_log.push(ChannelAuditRecord {
                event_code: event_codes::FN_OB_005.to_string(),
                obligation_id: id.clone(),
                status: "TimedOut".to_string(),
                trace_id: trace_id.to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
                detail: "obligation timed out".to_string(),
            });
        }

        timed_out
    }

    /// Get a specific obligation by ID.
    #[must_use]
    pub fn get_obligation(&self, obligation_id: &str) -> Option<&ChannelObligation> {
        self.queue
            .iter()
            .find(|(o, _)| o.obligation_id == obligation_id)
            .map(|(o, _)| o)
    }

    /// Count obligations by status.
    #[must_use]
    pub fn count_by_status(&self, status: ObligationStatus) -> usize {
        self.queue
            .iter()
            .filter(|(o, _)| o.status == status)
            .count()
    }

    /// Total number of obligations in the channel.
    #[must_use]
    pub fn total_obligations(&self) -> usize {
        self.queue.len()
    }

    /// Read-only access to the audit log.
    #[must_use]
    pub fn audit_log(&self) -> &[ChannelAuditRecord] {
        &self.audit_log
    }
}

// ── ObligationLedger ────────────────────────────────────────────────────────

/// Ledger tracking all outstanding obligations with queryable state.
/// INV-OCH-LEDGER-COMPLETE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationLedger {
    /// All obligations indexed by their ID.
    obligations: BTreeMap<String, ChannelObligation>,
    /// Audit trail of all events.
    audit_log: Vec<ChannelAuditRecord>,
}

impl ObligationLedger {
    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }

    /// Record an obligation in the ledger. INV-OCH-TRACKED
    pub fn record(&mut self, obligation: ChannelObligation) {
        let id = obligation.obligation_id.clone();
        self.audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_001.to_string(),
            obligation_id: id.clone(),
            status: obligation.status.to_string(),
            trace_id: obligation.trace_id.clone(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: "obligation recorded in ledger".to_string(),
        });
        self.obligations.insert(id, obligation);
    }

    /// Update the status of an obligation. INV-OCH-LEDGER-COMPLETE
    pub fn update_status(
        &mut self,
        obligation_id: &str,
        status: ObligationStatus,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let obligation = self
            .obligations
            .get_mut(obligation_id)
            .ok_or_else(|| error_codes::ERR_OCH_NOT_FOUND.to_string())?;

        obligation.status = status;
        obligation.resolved_at_ms = Some(now_ms);

        self.audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_003.to_string(),
            obligation_id: obligation_id.to_string(),
            status: status.to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: format!("obligation status updated to {status}"),
        });

        Ok(())
    }

    /// Query all outstanding (non-terminal) obligations. INV-OCH-LEDGER-COMPLETE
    #[must_use]
    pub fn query_outstanding(&self) -> Vec<&ChannelObligation> {
        self.obligations
            .values()
            .filter(|o| !o.status.is_terminal())
            .collect()
    }

    /// Query obligations by status.
    #[must_use]
    pub fn query_by_status(&self, status: ObligationStatus) -> Vec<&ChannelObligation> {
        self.obligations
            .values()
            .filter(|o| o.status == status)
            .collect()
    }

    /// Get the total number of obligations in the ledger.
    #[must_use]
    pub fn total(&self) -> usize {
        self.obligations.len()
    }

    /// Get a specific obligation by ID.
    #[must_use]
    pub fn get(&self, obligation_id: &str) -> Option<&ChannelObligation> {
        self.obligations.get(obligation_id)
    }

    /// Generate a closure proof for a given flow. INV-OCH-CLOSURE-SIGNED
    #[must_use]
    pub fn generate_closure_proof(
        &self,
        flow_id: &str,
        obligation_ids: &[String],
        now_ms: u64,
    ) -> ClosureProof {
        let mut obligations_map = BTreeMap::new();
        let mut complete = true;

        for id in obligation_ids {
            if let Some(obligation) = self.obligations.get(id) {
                obligations_map.insert(id.clone(), obligation.status);
                if !obligation.status.is_terminal() {
                    complete = false;
                }
            } else {
                obligations_map.insert(id.clone(), ObligationStatus::Created);
                complete = false;
            }
        }

        ClosureProof {
            flow_id: flow_id.to_string(),
            obligations: obligations_map,
            generated_at_ms: now_ms,
            complete,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Read-only access to the audit log.
    #[must_use]
    pub fn audit_log(&self) -> &[ChannelAuditRecord] {
        &self.audit_log
    }
}

impl Default for ObligationLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ── TwoPhaseFlow ────────────────────────────────────────────────────────────

/// Builder composing obligation channels into multi-step prepare/commit workflows.
/// INV-OCH-TWO-PHASE, INV-OCH-ROLLBACK-ATOMIC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoPhaseFlow {
    /// Flow identifier.
    pub flow_id: String,
    /// Obligation IDs participating in this flow.
    obligation_ids: Vec<String>,
    /// Whether the flow has been prepared.
    prepared: bool,
    /// Whether the flow has been committed.
    committed: bool,
    /// Whether the flow has been rolled back.
    rolled_back: bool,
    /// Ledger tracking obligations.
    ledger: ObligationLedger,
    /// Audit log for flow-level events.
    flow_audit_log: Vec<ChannelAuditRecord>,
}

impl TwoPhaseFlow {
    /// Create a new two-phase flow.
    #[must_use]
    pub fn new(flow_id: &str) -> Self {
        Self {
            flow_id: flow_id.to_string(),
            obligation_ids: Vec::new(),
            prepared: false,
            committed: false,
            rolled_back: false,
            ledger: ObligationLedger::new(),
            flow_audit_log: Vec::new(),
        }
    }

    /// Add an obligation to the flow.
    pub fn add_obligation(&mut self, obligation: ChannelObligation) {
        let id = obligation.obligation_id.clone();
        self.ledger.record(obligation);
        self.obligation_ids.push(id);
    }

    /// Execute the prepare phase. INV-OCH-TWO-PHASE
    ///
    /// Verifies all obligations are in Created state and marks the flow as prepared.
    pub fn prepare(&mut self, now_ms: u64, trace_id: &str) -> PrepareResult {
        self.flow_audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_007.to_string(),
            obligation_id: String::new(),
            status: "Preparing".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: format!("prepare initiated for flow {}", self.flow_id),
        });

        // Verify all obligations are in Created state
        for id in &self.obligation_ids {
            match self.ledger.get(id) {
                Some(o) if o.status == ObligationStatus::Created => {}
                Some(o) => {
                    return PrepareResult::Failed {
                        flow_id: self.flow_id.clone(),
                        reason: format!(
                            "{}: obligation {} in unexpected state {}",
                            error_codes::ERR_OCH_PREPARE_FAILED,
                            id,
                            o.status
                        ),
                    };
                }
                None => {
                    return PrepareResult::Failed {
                        flow_id: self.flow_id.clone(),
                        reason: format!(
                            "{}: obligation {} not found",
                            error_codes::ERR_OCH_PREPARE_FAILED,
                            id
                        ),
                    };
                }
            }
        }

        // Check deadlines
        for id in &self.obligation_ids {
            if let Some(o) = self.ledger.get(id)
                && now_ms > o.deadline
            {
                return PrepareResult::Failed {
                    flow_id: self.flow_id.clone(),
                    reason: format!(
                        "{}: obligation {} deadline exceeded",
                        error_codes::ERR_OCH_DEADLINE_EXCEEDED,
                        id
                    ),
                };
            }
        }

        self.prepared = true;

        self.flow_audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_008.to_string(),
            obligation_id: String::new(),
            status: "Prepared".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: format!("prepare succeeded for flow {}", self.flow_id),
        });

        PrepareResult::Ready {
            flow_id: self.flow_id.clone(),
            obligation_ids: self.obligation_ids.clone(),
        }
    }

    /// Execute the commit phase. INV-OCH-TWO-PHASE
    ///
    /// Transitions all obligations to Fulfilled and generates a closure proof.
    pub fn commit(&mut self, now_ms: u64, trace_id: &str) -> CommitResult {
        if !self.prepared {
            return CommitResult::RolledBack {
                flow_id: self.flow_id.clone(),
                reason: format!("{}: flow not prepared", error_codes::ERR_OCH_COMMIT_FAILED),
            };
        }

        if self.committed {
            return CommitResult::RolledBack {
                flow_id: self.flow_id.clone(),
                reason: format!(
                    "{}: flow already committed",
                    error_codes::ERR_OCH_COMMIT_FAILED
                ),
            };
        }

        if self.rolled_back {
            return CommitResult::RolledBack {
                flow_id: self.flow_id.clone(),
                reason: format!(
                    "{}: flow already rolled back",
                    error_codes::ERR_OCH_COMMIT_FAILED
                ),
            };
        }

        // Fulfill all obligations (clone IDs to avoid borrow conflict with do_rollback)
        let ids: Vec<String> = self.obligation_ids.clone();
        for id in &ids {
            if let Err(_e) =
                self.ledger
                    .update_status(id, ObligationStatus::Fulfilled, now_ms, trace_id)
            {
                // On commit failure, rollback atomically. INV-OCH-ROLLBACK-ATOMIC
                self.do_rollback(now_ms, trace_id);
                return CommitResult::RolledBack {
                    flow_id: self.flow_id.clone(),
                    reason: format!(
                        "{}: failed to fulfill obligation {}",
                        error_codes::ERR_OCH_COMMIT_FAILED,
                        id
                    ),
                };
            }
        }

        self.committed = true;

        self.flow_audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_009.to_string(),
            obligation_id: String::new(),
            status: "Committed".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: format!("commit completed for flow {}", self.flow_id),
        });

        CommitResult::Committed {
            flow_id: self.flow_id.clone(),
            obligation_ids: self.obligation_ids.clone(),
        }
    }

    /// Execute the rollback phase. INV-OCH-ROLLBACK-ATOMIC
    ///
    /// Cancels all non-terminal obligations atomically.
    pub fn rollback(&mut self, now_ms: u64, trace_id: &str) -> Result<(), String> {
        if self.committed {
            return Err(format!(
                "{}: cannot rollback committed flow",
                error_codes::ERR_OCH_ROLLBACK_FAILED
            ));
        }

        self.do_rollback(now_ms, trace_id);
        Ok(())
    }

    /// Internal rollback helper.
    fn do_rollback(&mut self, now_ms: u64, trace_id: &str) {
        for id in &self.obligation_ids {
            if let Some(o) = self.ledger.get(id)
                && !o.status.is_terminal()
            {
                let _ =
                    self.ledger
                        .update_status(id, ObligationStatus::Cancelled, now_ms, trace_id);
            }
        }

        self.rolled_back = true;

        self.flow_audit_log.push(ChannelAuditRecord {
            event_code: event_codes::FN_OB_010.to_string(),
            obligation_id: String::new(),
            status: "RolledBack".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: format!("rollback completed for flow {}", self.flow_id),
        });
    }

    /// Generate a closure proof for this flow. INV-OCH-CLOSURE-SIGNED
    #[must_use]
    pub fn closure_proof(&self, now_ms: u64) -> ClosureProof {
        self.ledger
            .generate_closure_proof(&self.flow_id, &self.obligation_ids, now_ms)
    }

    /// Query outstanding (non-terminal) obligations in this flow.
    #[must_use]
    pub fn query_outstanding(&self) -> Vec<&ChannelObligation> {
        self.ledger.query_outstanding()
    }

    /// Whether the flow has been prepared.
    #[must_use]
    pub fn is_prepared(&self) -> bool {
        self.prepared
    }

    /// Whether the flow has been committed.
    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Whether the flow has been rolled back.
    #[must_use]
    pub fn is_rolled_back(&self) -> bool {
        self.rolled_back
    }

    /// Get the ledger for this flow.
    #[must_use]
    pub fn ledger(&self) -> &ObligationLedger {
        &self.ledger
    }

    /// Read-only access to the flow audit log.
    #[must_use]
    pub fn flow_audit_log(&self) -> &[ChannelAuditRecord] {
        &self.flow_audit_log
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_obligation(id: &str, deadline: u64, trace_id: &str) -> ChannelObligation {
        ChannelObligation {
            obligation_id: id.to_string(),
            deadline,
            trace_id: trace_id.to_string(),
            status: ObligationStatus::Created,
            created_at_ms: 1000,
            resolved_at_ms: None,
            timeout_policy: TimeoutPolicy::Escalate,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    // 1. schema version is correct
    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "och-v1.0");
    }

    // 2. invariant constants are defined
    #[test]
    fn test_invariant_constants() {
        assert_eq!(INV_OCH_TRACKED, "INV-OCH-TRACKED");
        assert_eq!(INV_OCH_DEADLINE, "INV-OCH-DEADLINE");
        assert_eq!(INV_OCH_LEDGER_COMPLETE, "INV-OCH-LEDGER-COMPLETE");
        assert_eq!(INV_OCH_CLOSURE_SIGNED, "INV-OCH-CLOSURE-SIGNED");
        assert_eq!(INV_OCH_TWO_PHASE, "INV-OCH-TWO-PHASE");
        assert_eq!(INV_OCH_ROLLBACK_ATOMIC, "INV-OCH-ROLLBACK-ATOMIC");
    }

    // 3. event codes are defined and non-empty
    #[test]
    fn test_event_codes_defined() {
        assert!(!event_codes::FN_OB_001.is_empty());
        assert!(!event_codes::FN_OB_002.is_empty());
        assert!(!event_codes::FN_OB_003.is_empty());
        assert!(!event_codes::FN_OB_004.is_empty());
        assert!(!event_codes::FN_OB_005.is_empty());
        assert!(!event_codes::FN_OB_006.is_empty());
        assert!(!event_codes::FN_OB_007.is_empty());
        assert!(!event_codes::FN_OB_008.is_empty());
        assert!(!event_codes::FN_OB_009.is_empty());
        assert!(!event_codes::FN_OB_010.is_empty());
        assert!(!event_codes::FN_OB_011.is_empty());
        assert!(!event_codes::FN_OB_012.is_empty());
    }

    // 4. error codes are defined and non-empty
    #[test]
    fn test_error_codes_defined() {
        assert!(!error_codes::ERR_OCH_NOT_FOUND.is_empty());
        assert!(!error_codes::ERR_OCH_ALREADY_FULFILLED.is_empty());
        assert!(!error_codes::ERR_OCH_ALREADY_REJECTED.is_empty());
        assert!(!error_codes::ERR_OCH_TIMED_OUT.is_empty());
        assert!(!error_codes::ERR_OCH_CANCELLED.is_empty());
        assert!(!error_codes::ERR_OCH_PREPARE_FAILED.is_empty());
        assert!(!error_codes::ERR_OCH_COMMIT_FAILED.is_empty());
        assert!(!error_codes::ERR_OCH_ROLLBACK_FAILED.is_empty());
        assert!(!error_codes::ERR_OCH_DEADLINE_EXCEEDED.is_empty());
        assert!(!error_codes::ERR_OCH_INVALID_TRANSITION.is_empty());
    }

    // 5. ObligationStatus display and terminal state
    #[test]
    fn test_obligation_status_display_and_terminal() {
        assert_eq!(ObligationStatus::Created.to_string(), "Created");
        assert_eq!(ObligationStatus::Fulfilled.to_string(), "Fulfilled");
        assert_eq!(ObligationStatus::Rejected.to_string(), "Rejected");
        assert_eq!(ObligationStatus::TimedOut.to_string(), "TimedOut");
        assert_eq!(ObligationStatus::Cancelled.to_string(), "Cancelled");

        assert!(!ObligationStatus::Created.is_terminal());
        assert!(ObligationStatus::Fulfilled.is_terminal());
        assert!(ObligationStatus::Rejected.is_terminal());
        assert!(ObligationStatus::TimedOut.is_terminal());
        assert!(ObligationStatus::Cancelled.is_terminal());
    }

    // 6. TimeoutPolicy display
    #[test]
    fn test_timeout_policy_display() {
        assert_eq!(TimeoutPolicy::Retry.to_string(), "Retry");
        assert_eq!(TimeoutPolicy::Compensate.to_string(), "Compensate");
        assert_eq!(TimeoutPolicy::Escalate.to_string(), "Escalate");
    }

    // 7. ObligationChannel send creates tracked obligation
    #[test]
    fn test_channel_send_creates_obligation() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("test-ch");
        let id = ch.send("hello".to_string(), 1000, "trace-1");
        assert!(id.starts_with("och-test-ch-"));
        assert_eq!(ch.total_obligations(), 1);
        let obl = ch.get_obligation(&id).unwrap();
        assert_eq!(obl.status, ObligationStatus::Created);
        assert_eq!(obl.deadline, 1000 + DEFAULT_DEADLINE_MS);
    }

    // 8. Channel fulfill transitions status
    #[test]
    fn test_channel_fulfill() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-ful");
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        ch.fulfill(&id, 1050, "trace-2").unwrap();
        let obl = ch.get_obligation(&id).unwrap();
        assert_eq!(obl.status, ObligationStatus::Fulfilled);
        assert_eq!(obl.resolved_at_ms, Some(1050));
    }

    // 9. Channel reject transitions status
    #[test]
    fn test_channel_reject() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-rej");
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        ch.reject(&id, 1050, "trace-2").unwrap();
        let obl = ch.get_obligation(&id).unwrap();
        assert_eq!(obl.status, ObligationStatus::Rejected);
    }

    // 10. Double fulfill errors
    #[test]
    fn test_double_fulfill_errors() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-df");
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        ch.fulfill(&id, 1050, "trace-2").unwrap();
        let err = ch.fulfill(&id, 1100, "trace-3").unwrap_err();
        assert_eq!(err, error_codes::ERR_OCH_ALREADY_FULFILLED);
    }

    // 11. Not found error
    #[test]
    fn test_not_found_error() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-nf");
        let err = ch.fulfill("nonexistent", 1000, "trace-1").unwrap_err();
        assert_eq!(err, error_codes::ERR_OCH_NOT_FOUND);
    }

    // 12. Timeout sweep marks obligations timed out
    #[test]
    fn test_timeout_sweep() {
        let mut ch: ObligationChannel<String> = ObligationChannel::with_deadline("ch-sw", 100);
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        // Advance past deadline (1000 + 100 = 1100)
        let timed_out = ch.sweep_timeouts(1200, "trace-2");
        assert_eq!(timed_out.len(), 1);
        assert!(timed_out.contains(&id));
        let obl = ch.get_obligation(&id).unwrap();
        assert_eq!(obl.status, ObligationStatus::TimedOut);
    }

    // 13. Cancel obligation
    #[test]
    fn test_cancel_obligation() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-can");
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        ch.cancel(&id, 1050, "trace-2").unwrap();
        let obl = ch.get_obligation(&id).unwrap();
        assert_eq!(obl.status, ObligationStatus::Cancelled);
    }

    // 14. Cannot cancel terminal obligation
    #[test]
    fn test_cannot_cancel_terminal() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-ct");
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        ch.fulfill(&id, 1050, "trace-2").unwrap();
        let err = ch.cancel(&id, 1100, "trace-3").unwrap_err();
        assert_eq!(err, error_codes::ERR_OCH_INVALID_TRANSITION);
    }

    // 15. ObligationLedger tracks obligations
    #[test]
    fn test_ledger_tracks_obligations() {
        let mut ledger = ObligationLedger::new();
        let obl = make_obligation("obl-1", 5000, "trace-1");
        ledger.record(obl);
        assert_eq!(ledger.total(), 1);
        assert!(ledger.get("obl-1").is_some());
    }

    // 16. Ledger query_outstanding returns non-terminal
    #[test]
    fn test_ledger_query_outstanding() {
        let mut ledger = ObligationLedger::new();
        ledger.record(make_obligation("obl-1", 5000, "trace-1"));
        ledger.record(make_obligation("obl-2", 5000, "trace-2"));
        ledger
            .update_status("obl-1", ObligationStatus::Fulfilled, 2000, "trace-3")
            .unwrap();

        let outstanding = ledger.query_outstanding();
        assert_eq!(outstanding.len(), 1);
        assert_eq!(outstanding[0].obligation_id, "obl-2");
    }

    // 17. Ledger closure proof generation
    #[test]
    fn test_closure_proof_complete() {
        let mut ledger = ObligationLedger::new();
        ledger.record(make_obligation("obl-1", 5000, "trace-1"));
        ledger.record(make_obligation("obl-2", 5000, "trace-2"));
        ledger
            .update_status("obl-1", ObligationStatus::Fulfilled, 2000, "trace-3")
            .unwrap();
        ledger
            .update_status("obl-2", ObligationStatus::Rejected, 2000, "trace-4")
            .unwrap();

        let ids = vec!["obl-1".to_string(), "obl-2".to_string()];
        let proof = ledger.generate_closure_proof("flow-1", &ids, 3000);
        assert!(proof.complete);
        assert_eq!(proof.obligations.len(), 2);
        assert_eq!(proof.schema_version, SCHEMA_VERSION);
    }

    // 18. Closure proof incomplete when obligations pending
    #[test]
    fn test_closure_proof_incomplete() {
        let mut ledger = ObligationLedger::new();
        ledger.record(make_obligation("obl-1", 5000, "trace-1"));
        let ids = vec!["obl-1".to_string()];
        let proof = ledger.generate_closure_proof("flow-1", &ids, 2000);
        assert!(!proof.complete);
    }

    // 19. TwoPhaseFlow prepare/commit lifecycle
    #[test]
    fn test_two_phase_prepare_commit() {
        let mut flow = TwoPhaseFlow::new("flow-1");
        flow.add_obligation(make_obligation("obl-1", 5000, "trace-1"));
        flow.add_obligation(make_obligation("obl-2", 5000, "trace-2"));

        let prep = flow.prepare(1500, "trace-3");
        assert!(matches!(prep, PrepareResult::Ready { .. }));
        assert!(flow.is_prepared());

        let commit = flow.commit(2000, "trace-4");
        assert!(matches!(commit, CommitResult::Committed { .. }));
        assert!(flow.is_committed());

        let proof = flow.closure_proof(2500);
        assert!(proof.complete);
    }

    // 20. TwoPhaseFlow rollback cancels all obligations
    #[test]
    fn test_two_phase_rollback() {
        let mut flow = TwoPhaseFlow::new("flow-rb");
        flow.add_obligation(make_obligation("obl-1", 5000, "trace-1"));
        flow.add_obligation(make_obligation("obl-2", 5000, "trace-2"));

        let _prep = flow.prepare(1500, "trace-3");
        flow.rollback(2000, "trace-4").unwrap();

        assert!(flow.is_rolled_back());
        assert!(flow.query_outstanding().is_empty());

        let proof = flow.closure_proof(2500);
        assert!(proof.complete);
    }

    // 21. Commit without prepare fails
    #[test]
    fn test_commit_without_prepare_fails() {
        let mut flow = TwoPhaseFlow::new("flow-np");
        flow.add_obligation(make_obligation("obl-1", 5000, "trace-1"));

        let result = flow.commit(2000, "trace-2");
        assert!(matches!(result, CommitResult::RolledBack { .. }));
    }

    // 22. Cannot rollback committed flow
    #[test]
    fn test_cannot_rollback_committed() {
        let mut flow = TwoPhaseFlow::new("flow-rc");
        flow.add_obligation(make_obligation("obl-1", 5000, "trace-1"));
        flow.prepare(1500, "trace-2");
        flow.commit(2000, "trace-3");

        let err = flow.rollback(2500, "trace-4").unwrap_err();
        assert!(err.contains(error_codes::ERR_OCH_ROLLBACK_FAILED));
    }

    // 23. Prepare fails when obligation deadline exceeded
    #[test]
    fn test_prepare_deadline_exceeded() {
        let mut flow = TwoPhaseFlow::new("flow-dl");
        flow.add_obligation(make_obligation("obl-1", 2000, "trace-1"));

        // now_ms (3000) > deadline (2000)
        let result = flow.prepare(3000, "trace-2");
        assert!(matches!(result, PrepareResult::Failed { .. }));
    }

    // 24. Audit log captures flow events
    #[test]
    fn test_audit_log_captures_events() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-audit");
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        ch.fulfill(&id, 1050, "trace-2").unwrap();

        let log = ch.audit_log();
        assert!(log.len() >= 3); // create + send + fulfill
        assert!(log.iter().any(|r| r.event_code == event_codes::FN_OB_001));
        assert!(log.iter().any(|r| r.event_code == event_codes::FN_OB_003));
    }

    // 25. Two-phase flow audit log
    #[test]
    fn test_flow_audit_log() {
        let mut flow = TwoPhaseFlow::new("flow-al");
        flow.add_obligation(make_obligation("obl-1", 5000, "trace-1"));
        flow.prepare(1500, "trace-2");
        flow.commit(2000, "trace-3");

        let log = flow.flow_audit_log();
        assert!(log.iter().any(|r| r.event_code == event_codes::FN_OB_007));
        assert!(log.iter().any(|r| r.event_code == event_codes::FN_OB_008));
        assert!(log.iter().any(|r| r.event_code == event_codes::FN_OB_009));
    }

    // 26. Channel count_by_status
    #[test]
    fn test_channel_count_by_status() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-cbs");
        let id1 = ch.send("a".to_string(), 1000, "t1");
        let _id2 = ch.send("b".to_string(), 1000, "t2");
        ch.fulfill(&id1, 1050, "t3").unwrap();

        assert_eq!(ch.count_by_status(ObligationStatus::Created), 1);
        assert_eq!(ch.count_by_status(ObligationStatus::Fulfilled), 1);
    }

    // 27. Multiple sends produce unique IDs
    #[test]
    fn test_unique_ids() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-uid");
        let id1 = ch.send("a".to_string(), 1000, "t1");
        let id2 = ch.send("b".to_string(), 1001, "t2");
        let id3 = ch.send("c".to_string(), 1002, "t3");
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    // 28. Ledger default is empty
    #[test]
    fn test_ledger_default_empty() {
        let ledger = ObligationLedger::default();
        assert_eq!(ledger.total(), 0);
        assert!(ledger.query_outstanding().is_empty());
    }

    // 29. Serde roundtrip for ChannelObligation
    #[test]
    fn test_serde_roundtrip_obligation() {
        let obl = make_obligation("obl-serde", 5000, "trace-serde");
        let json = serde_json::to_string(&obl).unwrap();
        let parsed: ChannelObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.obligation_id, obl.obligation_id);
        assert_eq!(parsed.status, obl.status);
    }

    // 30. Serde roundtrip for ClosureProof
    #[test]
    fn test_serde_roundtrip_closure_proof() {
        let mut obligations = BTreeMap::new();
        obligations.insert("obl-1".to_string(), ObligationStatus::Fulfilled);
        let proof = ClosureProof {
            flow_id: "flow-serde".to_string(),
            obligations,
            generated_at_ms: 3000,
            complete: true,
            schema_version: SCHEMA_VERSION.to_string(),
        };
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: ClosureProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.flow_id, proof.flow_id);
        assert!(parsed.complete);
    }

    // 31. Invariant names present in module source
    #[test]
    fn test_invariant_names_present_in_source() {
        let src = include_str!("obligation_channel.rs");
        assert!(src.contains("INV-OCH-TRACKED"));
        assert!(src.contains("INV-OCH-DEADLINE"));
        assert!(src.contains("INV-OCH-LEDGER-COMPLETE"));
        assert!(src.contains("INV-OCH-CLOSURE-SIGNED"));
        assert!(src.contains("INV-OCH-TWO-PHASE"));
        assert!(src.contains("INV-OCH-ROLLBACK-ATOMIC"));
    }

    // 32. Event code values match FN-OB-NNN pattern
    #[test]
    fn test_event_code_format() {
        let codes = [
            event_codes::FN_OB_001,
            event_codes::FN_OB_002,
            event_codes::FN_OB_003,
            event_codes::FN_OB_004,
            event_codes::FN_OB_005,
            event_codes::FN_OB_006,
            event_codes::FN_OB_007,
            event_codes::FN_OB_008,
            event_codes::FN_OB_009,
            event_codes::FN_OB_010,
            event_codes::FN_OB_011,
            event_codes::FN_OB_012,
        ];
        for code in &codes {
            assert!(
                code.starts_with("FN-OB-"),
                "code {code} must start with FN-OB-"
            );
        }
    }

    // 33. Channel with custom deadline
    #[test]
    fn test_channel_custom_deadline() {
        let mut ch: ObligationChannel<String> = ObligationChannel::with_deadline("ch-dl", 500);
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        let obl = ch.get_obligation(&id).unwrap();
        assert_eq!(obl.deadline, 1500);
    }

    // 34. Ledger query_by_status
    #[test]
    fn test_ledger_query_by_status() {
        let mut ledger = ObligationLedger::new();
        ledger.record(make_obligation("obl-1", 5000, "trace-1"));
        ledger.record(make_obligation("obl-2", 5000, "trace-2"));
        ledger
            .update_status("obl-1", ObligationStatus::Fulfilled, 2000, "trace-3")
            .unwrap();

        let fulfilled = ledger.query_by_status(ObligationStatus::Fulfilled);
        assert_eq!(fulfilled.len(), 1);
        assert_eq!(fulfilled[0].obligation_id, "obl-1");

        let created = ledger.query_by_status(ObligationStatus::Created);
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].obligation_id, "obl-2");
    }

    // 35. Reject then fulfill errors
    #[test]
    fn test_reject_then_fulfill_errors() {
        let mut ch: ObligationChannel<String> = ObligationChannel::new("ch-rf");
        let id = ch.send("msg".to_string(), 1000, "trace-1");
        ch.reject(&id, 1050, "trace-2").unwrap();
        let err = ch.fulfill(&id, 1100, "trace-3").unwrap_err();
        assert_eq!(err, error_codes::ERR_OCH_ALREADY_REJECTED);
    }
}
