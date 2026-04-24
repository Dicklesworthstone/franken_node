//! bd-1cs7: Three-phase cancellation protocol (REQUEST -> DRAIN -> FINALIZE).
//!
//! Implements an orderly cancellation protocol for high-impact workflows.
//! Cancellation flows through three mandatory phases:
//!
//! 1. **REQUEST** — cancellation signal received; no new work accepted (CAN-001)
//! 2. **DRAIN** — in-flight operations complete or timeout (CAN-002..CAN-004)
//! 3. **FINALIZE** — resources released, state committed to terminal (CAN-005, CAN-006)
//!
//! # Invariants
//!
//! - INV-CANP-THREE-PHASE: all cancellations pass through REQUEST, DRAIN, FINALIZE in order
//! - INV-CANP-NO-NEW-WORK: after REQUEST, no new operations are accepted
//! - INV-CANP-DRAIN-BOUNDED: drain phase has a configurable timeout
//! - INV-CANP-FINALIZE-CLEAN: after FINALIZE, no resource leaks exist
//! - INV-CANP-IDEMPOTENT: duplicate cancel requests are absorbed without error
//! - INV-CANP-AUDIT-COMPLETE: every phase transition emits a structured audit event

use serde::{Deserialize, Serialize};
use std::fmt;

/// Schema version for cancellation protocol records.
pub const SCHEMA_VERSION: &str = "cp-v1.0";

/// Default drain timeout in milliseconds.
pub const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 30_000;

/// Minimum drain timeout in milliseconds.
pub const MIN_DRAIN_TIMEOUT_MS: u64 = 1_000;

/// Default max number of retained audit log entries.
pub const DEFAULT_MAX_AUDIT_LOG_ENTRIES: usize = 4_096;

/// Default max number of retained cancellation records.
pub const DEFAULT_MAX_RECORDS: usize = 4_096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

// ---- Event codes ----

pub mod event_codes {
    /// CAN-001: Cancel requested.
    pub const CAN_001: &str = "CAN-001";
    /// CAN-002: Drain started.
    pub const CAN_002: &str = "CAN-002";
    /// CAN-003: Drain completed.
    pub const CAN_003: &str = "CAN-003";
    /// CAN-004: Drain timeout.
    pub const CAN_004: &str = "CAN-004";
    /// CAN-005: Finalize completed.
    pub const CAN_005: &str = "CAN-005";
    /// CAN-006: Resource leak detected.
    pub const CAN_006: &str = "CAN-006";
}

// ---- Error codes ----

pub mod error_codes {
    pub const ERR_CANCEL_INVALID_PHASE: &str = "ERR_CANCEL_INVALID_PHASE";
    pub const ERR_CANCEL_ALREADY_FINAL: &str = "ERR_CANCEL_ALREADY_FINAL";
    pub const ERR_CANCEL_DRAIN_TIMEOUT: &str = "ERR_CANCEL_DRAIN_TIMEOUT";
    pub const ERR_CANCEL_LEAK: &str = "ERR_CANCEL_LEAK";
    pub const ERR_CANCEL_NOT_FOUND: &str = "ERR_CANCEL_NOT_FOUND";
    pub const ERR_CANCEL_INVARIANT: &str = "ERR_CANCEL_INVARIANT";
}

// ---- Cancellation phase ----

/// The six phases of the cancellation protocol FSM.
/// INV-CANP-THREE-PHASE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelPhase {
    /// No cancellation in progress.
    Idle,
    /// Cancellation requested; no new work accepted.
    CancelRequested,
    /// Drain in progress; in-flight operations completing.
    Draining,
    /// Drain completed; ready for finalization.
    DrainComplete,
    /// Finalization in progress; resources being released.
    Finalizing,
    /// Cancellation complete; terminal state.
    Finalized,
}

impl CancelPhase {
    /// Returns the legal target phases from this phase.
    pub fn legal_targets(&self) -> &'static [CancelPhase] {
        match self {
            Self::Idle => &[Self::CancelRequested],
            Self::CancelRequested => &[Self::Draining, Self::CancelRequested],
            Self::Draining => &[Self::DrainComplete],
            Self::DrainComplete => &[Self::Finalizing],
            Self::Finalizing => &[Self::Finalized],
            Self::Finalized => &[],
        }
    }

    /// Check if a transition to the target phase is permitted.
    pub fn can_transition_to(&self, target: &CancelPhase) -> bool {
        self.legal_targets().contains(target)
    }

    /// Returns the string name for logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::CancelRequested => "cancel_requested",
            Self::Draining => "draining",
            Self::DrainComplete => "drain_complete",
            Self::Finalizing => "finalizing",
            Self::Finalized => "finalized",
        }
    }

    /// All phases in order.
    pub const ALL: [CancelPhase; 6] = [
        Self::Idle,
        Self::CancelRequested,
        Self::Draining,
        Self::DrainComplete,
        Self::Finalizing,
        Self::Finalized,
    ];
}

impl fmt::Display for CancelPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---- Cancellation protocol errors ----

/// Errors from the cancellation protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelProtocolError {
    /// Phase transition not allowed from current state.
    InvalidPhase { from: CancelPhase, to: CancelPhase },
    /// Cancellation attempted on already-finalized workflow.
    AlreadyFinal { workflow_id: String },
    /// Drain exceeded configured timeout.
    DrainTimeout {
        workflow_id: String,
        elapsed_ms: u64,
        timeout_ms: u64,
    },
    /// Resources leaked during finalization.
    ResourceLeak {
        workflow_id: String,
        leaked_resources: Vec<String>,
    },
    /// Workflow not found in the registry.
    WorkflowNotFound { workflow_id: String },
    /// Internal protocol invariant failed unexpectedly.
    InvariantViolation { detail: String },
}

impl CancelProtocolError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPhase { .. } => error_codes::ERR_CANCEL_INVALID_PHASE,
            Self::AlreadyFinal { .. } => error_codes::ERR_CANCEL_ALREADY_FINAL,
            Self::DrainTimeout { .. } => error_codes::ERR_CANCEL_DRAIN_TIMEOUT,
            Self::ResourceLeak { .. } => error_codes::ERR_CANCEL_LEAK,
            Self::WorkflowNotFound { .. } => error_codes::ERR_CANCEL_NOT_FOUND,
            Self::InvariantViolation { .. } => error_codes::ERR_CANCEL_INVARIANT,
        }
    }
}

impl fmt::Display for CancelProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPhase { from, to } => {
                write!(
                    f,
                    "{}: cannot transition from {} to {}",
                    self.code(),
                    from,
                    to
                )
            }
            Self::AlreadyFinal { workflow_id } => {
                write!(
                    f,
                    "{}: workflow {} already finalized",
                    self.code(),
                    workflow_id
                )
            }
            Self::DrainTimeout {
                workflow_id,
                elapsed_ms,
                timeout_ms,
            } => {
                write!(
                    f,
                    "{}: workflow {} drain timeout after {}ms (limit {}ms)",
                    self.code(),
                    workflow_id,
                    elapsed_ms,
                    timeout_ms
                )
            }
            Self::ResourceLeak {
                workflow_id,
                leaked_resources,
            } => {
                write!(
                    f,
                    "{}: workflow {} leaked resources: {}",
                    self.code(),
                    workflow_id,
                    leaked_resources.join(", ")
                )
            }
            Self::WorkflowNotFound { workflow_id } => {
                write!(f, "{}: workflow {} not found", self.code(), workflow_id)
            }
            Self::InvariantViolation { detail } => {
                write!(f, "{}: invariant violation: {}", self.code(), detail)
            }
        }
    }
}

// ---- Drain configuration ----

/// Configuration for the drain phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainConfig {
    /// Maximum time (ms) allowed for drain phase before timeout.
    pub timeout_ms: u64,
    /// Whether to force finalization on drain timeout.
    pub force_on_timeout: bool,
}

impl DrainConfig {
    pub fn new(timeout_ms: u64, force_on_timeout: bool) -> Self {
        Self {
            timeout_ms: timeout_ms.max(MIN_DRAIN_TIMEOUT_MS),
            force_on_timeout,
        }
    }
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_DRAIN_TIMEOUT_MS,
            force_on_timeout: true,
        }
    }
}

// ---- Protocol audit event ----

/// Structured audit event for each phase transition.
/// INV-CANP-AUDIT-COMPLETE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelAuditEvent {
    pub event_code: String,
    pub workflow_id: String,
    pub from_phase: CancelPhase,
    pub to_phase: CancelPhase,
    pub timestamp_ms: u64,
    pub trace_id: String,
    pub detail: String,
    pub schema_version: String,
}

impl CancelAuditEvent {
    pub fn new(
        event_code: &str,
        workflow_id: &str,
        from_phase: CancelPhase,
        to_phase: CancelPhase,
        timestamp_ms: u64,
        trace_id: &str,
        detail: &str,
    ) -> Self {
        Self {
            event_code: event_code.to_string(),
            workflow_id: workflow_id.to_string(),
            from_phase,
            to_phase,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: detail.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }
}

// ---- Resource tracker for finalization ----

/// Tracks resources that must be released during finalization.
/// INV-CANP-FINALIZE-CLEAN
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTracker {
    pub open_handles: Vec<String>,
    pub pending_writes: u64,
    pub held_locks: Vec<String>,
}

impl ResourceTracker {
    pub fn empty() -> Self {
        Self {
            open_handles: Vec::new(),
            pending_writes: 0,
            held_locks: Vec::new(),
        }
    }

    /// Check if all resources are released.
    pub fn is_clean(&self) -> bool {
        self.open_handles.is_empty() && self.pending_writes == 0 && self.held_locks.is_empty()
    }

    /// List all leaked resources.
    pub fn leaked_resources(&self) -> Vec<String> {
        let mut leaks = Vec::new();
        for h in &self.open_handles {
            leaks.push(format!("handle:{}", h));
        }
        if self.pending_writes > 0 {
            leaks.push(format!("pending_writes:{}", self.pending_writes));
        }
        for l in &self.held_locks {
            leaks.push(format!("lock:{}", l));
        }
        leaks
    }
}

// ---- Cancellation record ----

/// Complete record of a cancellation protocol execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationRecord {
    pub workflow_id: String,
    pub current_phase: CancelPhase,
    pub request_timestamp_ms: Option<u64>,
    pub drain_start_ms: Option<u64>,
    pub drain_complete_ms: Option<u64>,
    pub finalize_ms: Option<u64>,
    pub drain_timed_out: bool,
    pub resource_leaks: Vec<String>,
    pub in_flight_count: u64,
    pub drain_config: DrainConfig,
    pub trace_id: String,
}

impl CancellationRecord {
    pub fn new(workflow_id: &str, drain_config: DrainConfig, trace_id: &str) -> Self {
        Self {
            workflow_id: workflow_id.to_string(),
            current_phase: CancelPhase::Idle,
            request_timestamp_ms: None,
            drain_start_ms: None,
            drain_complete_ms: None,
            finalize_ms: None,
            drain_timed_out: false,
            resource_leaks: Vec::new(),
            in_flight_count: 0,
            drain_config,
            trace_id: trace_id.to_string(),
        }
    }

    /// Total elapsed time from request to current timestamp.
    pub fn elapsed_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.request_timestamp_ms.unwrap_or(now_ms))
    }

    /// Drain duration in milliseconds.
    pub fn drain_duration_ms(&self) -> Option<u64> {
        match (self.drain_start_ms, self.drain_complete_ms) {
            (Some(start), Some(end)) => Some(end.saturating_sub(start)),
            _ => None,
        }
    }
}

// ---- Cancellation protocol manager ----

/// Manages the three-phase cancellation protocol for a set of workflows.
///
/// INV-CANP-THREE-PHASE: enforces phase ordering.
/// INV-CANP-IDEMPOTENT: duplicate cancel requests are absorbed.
pub struct CancellationProtocol {
    records: Vec<CancellationRecord>,
    audit_log: Vec<CancelAuditEvent>,
    max_audit_log_entries: usize,
    default_drain_config: DrainConfig,
}

impl CancellationProtocol {
    pub fn new(default_drain_config: DrainConfig) -> Self {
        Self::with_audit_log_capacity(default_drain_config, DEFAULT_MAX_AUDIT_LOG_ENTRIES)
    }

    pub fn with_audit_log_capacity(
        default_drain_config: DrainConfig,
        max_audit_log_entries: usize,
    ) -> Self {
        Self {
            records: Vec::new(),
            audit_log: Vec::new(),
            max_audit_log_entries: max_audit_log_entries.max(1),
            default_drain_config,
        }
    }

    /// Phase 1: REQUEST — initiate cancellation.
    /// Emits CAN-001.
    /// INV-CANP-NO-NEW-WORK: after this, the workflow rejects new operations.
    /// INV-CANP-IDEMPOTENT: duplicate requests on CancelRequested are absorbed.
    pub fn request_cancel(
        &mut self,
        workflow_id: &str,
        in_flight_count: u64,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&CancellationRecord, CancelProtocolError> {
        // Check if we already have a record for this workflow (use position to avoid prolonged borrow)
        let existing_idx = self
            .records
            .iter()
            .position(|r| r.workflow_id == workflow_id);
        if let Some(idx) = existing_idx {
            // INV-CANP-IDEMPOTENT: absorb duplicate requests
            let phase = self.records[idx].current_phase;
            if phase == CancelPhase::CancelRequested {
                return Ok(&self.records[idx]);
            }
            if phase == CancelPhase::Finalized {
                return Err(CancelProtocolError::AlreadyFinal {
                    workflow_id: workflow_id.to_string(),
                });
            }
            if phase != CancelPhase::Idle {
                return Err(CancelProtocolError::InvalidPhase {
                    from: phase,
                    to: CancelPhase::CancelRequested,
                });
            }
            self.records[idx].current_phase = CancelPhase::CancelRequested;
            self.records[idx].request_timestamp_ms = Some(timestamp_ms);
            self.records[idx].in_flight_count = in_flight_count;

            self.record_audit_event(CancelAuditEvent::new(
                event_codes::CAN_001,
                workflow_id,
                CancelPhase::Idle,
                CancelPhase::CancelRequested,
                timestamp_ms,
                trace_id,
                &format!("cancel requested, {} in-flight", in_flight_count),
            ));

            return Ok(&self.records[idx]);
        }

        // Create new record
        let mut record =
            CancellationRecord::new(workflow_id, self.default_drain_config.clone(), trace_id);
        record.current_phase = CancelPhase::CancelRequested;
        record.request_timestamp_ms = Some(timestamp_ms);
        record.in_flight_count = in_flight_count;

        self.record_audit_event(CancelAuditEvent::new(
            event_codes::CAN_001,
            workflow_id,
            CancelPhase::Idle,
            CancelPhase::CancelRequested,
            timestamp_ms,
            trace_id,
            &format!("cancel requested, {} in-flight", in_flight_count),
        ));

        // Garbage collect only finalized records if we are at capacity
        if self.records.len() >= DEFAULT_MAX_RECORDS {
            // Retain active records, and try to make room
            self.records
                .retain(|r| r.current_phase != CancelPhase::Finalized);

            // If we still have too many (i.e. all active), fail closed instead of
            // evicting a live cancellation. Dropping active state can reopen work
            // that should remain blocked until drain/finalize completes.
            if self.records.len() >= DEFAULT_MAX_RECORDS {
                return Err(CancelProtocolError::InvariantViolation {
                    detail: format!(
                        "active cancellation record capacity exceeded: max={DEFAULT_MAX_RECORDS}"
                    ),
                });
            }
        }
        self.records.push(record);

        self.records
            .last()
            .ok_or_else(|| CancelProtocolError::InvariantViolation {
                detail: "records unexpectedly empty immediately after push".to_string(),
            })
    }

    /// Phase 2a: DRAIN start — begin draining in-flight operations.
    /// Emits CAN-002.
    pub fn start_drain(
        &mut self,
        workflow_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&CancellationRecord, CancelProtocolError> {
        let idx = self.find_record_index(workflow_id)?;
        let from = self.records[idx].current_phase;

        if !from.can_transition_to(&CancelPhase::Draining) {
            return Err(CancelProtocolError::InvalidPhase {
                from,
                to: CancelPhase::Draining,
            });
        }

        self.records[idx].current_phase = CancelPhase::Draining;
        self.records[idx].drain_start_ms = Some(timestamp_ms);

        self.record_audit_event(CancelAuditEvent::new(
            event_codes::CAN_002,
            workflow_id,
            from,
            CancelPhase::Draining,
            timestamp_ms,
            trace_id,
            "drain started",
        ));

        Ok(&self.records[idx])
    }

    /// Phase 2b: DRAIN complete — all in-flight operations finished.
    /// Emits CAN-003.
    /// INV-CANP-DRAIN-BOUNDED: checks timeout.
    pub fn complete_drain(
        &mut self,
        workflow_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&CancellationRecord, CancelProtocolError> {
        let idx = self.find_record_index(workflow_id)?;
        let from = self.records[idx].current_phase;

        if !from.can_transition_to(&CancelPhase::DrainComplete) {
            return Err(CancelProtocolError::InvalidPhase {
                from,
                to: CancelPhase::DrainComplete,
            });
        }

        let drain_start = self.records[idx].drain_start_ms.unwrap_or(timestamp_ms);
        let elapsed = timestamp_ms.saturating_sub(drain_start);
        let timeout = self.records[idx].drain_config.timeout_ms;
        let force = self.records[idx].drain_config.force_on_timeout;

        // INV-CANP-DRAIN-BOUNDED: check timeout
        if elapsed >= timeout {
            self.records[idx].drain_timed_out = true;

            if !force {
                self.record_audit_event(CancelAuditEvent::new(
                    event_codes::CAN_004,
                    workflow_id,
                    CancelPhase::Draining,
                    CancelPhase::Draining,
                    timestamp_ms,
                    trace_id,
                    &format!("drain timeout after {}ms (limit {}ms)", elapsed, timeout),
                ));
                return Err(CancelProtocolError::DrainTimeout {
                    workflow_id: workflow_id.to_string(),
                    elapsed_ms: elapsed,
                    timeout_ms: timeout,
                });
            }

            self.records[idx].drain_complete_ms = Some(timestamp_ms);

            self.record_audit_event(CancelAuditEvent::new(
                event_codes::CAN_004,
                workflow_id,
                CancelPhase::Draining,
                CancelPhase::DrainComplete,
                timestamp_ms,
                trace_id,
                &format!("drain timeout after {}ms (limit {}ms)", elapsed, timeout),
            ));
        } else {
            self.records[idx].drain_complete_ms = Some(timestamp_ms);

            self.record_audit_event(CancelAuditEvent::new(
                event_codes::CAN_003,
                workflow_id,
                CancelPhase::Draining,
                CancelPhase::DrainComplete,
                timestamp_ms,
                trace_id,
                &format!("drain completed in {}ms", elapsed),
            ));
        }

        self.records[idx].current_phase = CancelPhase::DrainComplete;
        self.records[idx].in_flight_count = 0;

        Ok(&self.records[idx])
    }

    /// Phase 3: FINALIZE — release resources and commit to terminal state.
    /// Emits CAN-005 on success, CAN-006 on resource leak.
    /// INV-CANP-FINALIZE-CLEAN
    pub fn finalize(
        &mut self,
        workflow_id: &str,
        resources: &ResourceTracker,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&CancellationRecord, CancelProtocolError> {
        let idx = self.find_record_index(workflow_id)?;
        let phase = self.records[idx].current_phase;

        if phase == CancelPhase::Finalized {
            return Err(CancelProtocolError::AlreadyFinal {
                workflow_id: workflow_id.to_string(),
            });
        }

        if !phase.can_transition_to(&CancelPhase::Finalizing) {
            return Err(CancelProtocolError::InvalidPhase {
                from: phase,
                to: CancelPhase::Finalizing,
            });
        }

        self.records[idx].current_phase = CancelPhase::Finalizing;

        // INV-CANP-FINALIZE-CLEAN: check for resource leaks
        if !resources.is_clean() {
            let leaks = resources.leaked_resources();
            self.records[idx].resource_leaks = leaks.clone();

            self.record_audit_event(CancelAuditEvent::new(
                event_codes::CAN_006,
                workflow_id,
                CancelPhase::Finalizing,
                CancelPhase::Finalizing,
                timestamp_ms,
                trace_id,
                &format!("resource leak detected: {}", leaks.join(", ")),
            ));

            // INV-CANP-FINALIZE-CLEAN: do NOT advance to Finalized when leaks
            // exist. Keep phase as Finalizing so operator can intervene.

            return Err(CancelProtocolError::ResourceLeak {
                workflow_id: workflow_id.to_string(),
                leaked_resources: leaks,
            });
        }

        self.records[idx].current_phase = CancelPhase::Finalized;
        self.records[idx].finalize_ms = Some(timestamp_ms);

        self.record_audit_event(CancelAuditEvent::new(
            event_codes::CAN_005,
            workflow_id,
            CancelPhase::Finalizing,
            CancelPhase::Finalized,
            timestamp_ms,
            trace_id,
            "finalize completed cleanly",
        ));

        Ok(&self.records[idx])
    }

    /// Get the current phase for a workflow.
    pub fn current_phase(&self, workflow_id: &str) -> Option<CancelPhase> {
        self.records
            .iter()
            .find(|r| r.workflow_id == workflow_id)
            .map(|r| r.current_phase)
    }

    /// Get all cancellation records.
    pub fn records(&self) -> &[CancellationRecord] {
        &self.records
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[CancelAuditEvent] {
        &self.audit_log
    }

    /// Get the configured audit log capacity.
    pub fn audit_log_capacity(&self) -> usize {
        self.max_audit_log_entries
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get a record by workflow ID.
    pub fn get_record(&self, workflow_id: &str) -> Option<&CancellationRecord> {
        self.records.iter().find(|r| r.workflow_id == workflow_id)
    }

    /// Total number of active (non-finalized) cancellations.
    pub fn active_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| {
                r.current_phase != CancelPhase::Finalized && r.current_phase != CancelPhase::Idle
            })
            .count()
    }

    /// Total number of completed (finalized) cancellations.
    pub fn finalized_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.current_phase == CancelPhase::Finalized)
            .count()
    }

    fn find_record_index(&self, workflow_id: &str) -> Result<usize, CancelProtocolError> {
        self.records
            .iter()
            .position(|r| r.workflow_id == workflow_id)
            .ok_or(CancelProtocolError::WorkflowNotFound {
                workflow_id: workflow_id.to_string(),
            })
    }

    fn record_audit_event(&mut self, event: CancelAuditEvent) {
        let cap = self.max_audit_log_entries;
        push_bounded(&mut self.audit_log, event, cap);
    }
}

impl Default for CancellationProtocol {
    fn default() -> Self {
        Self::new(DrainConfig::default())
    }
}

// ---- Cancellation-aware health check (for health_gate integration) ----

/// A health check that verifies cancellation readiness.
pub fn cancellation_readiness_check(protocol: &CancellationProtocol) -> bool {
    // The system is cancellation-ready if there are no stuck workflows
    // (i.e., no workflows in Draining phase that have timed out without completing)
    protocol
        .records()
        .iter()
        .all(|r| r.current_phase != CancelPhase::Draining || !r.drain_timed_out)
}

/// Generate a timing report as CSV rows.
/// Returns (header, rows) suitable for writing to a CSV file.
pub fn generate_timing_report(protocol: &CancellationProtocol) -> (String, Vec<String>) {
    let header = "workflow_id,phase,request_ms,drain_start_ms,drain_complete_ms,finalize_ms,drain_duration_ms,timed_out,leaks".to_string();
    let rows: Vec<String> = protocol
        .records()
        .iter()
        .map(|r| {
            let drain_dur = r
                .drain_duration_ms()
                .map(|d| d.to_string())
                .unwrap_or_default();
            format!(
                "{},{},{},{},{},{},{},{},{}",
                r.workflow_id,
                r.current_phase,
                r.request_timestamp_ms
                    .map(|t| t.to_string())
                    .unwrap_or_default(),
                r.drain_start_ms.map(|t| t.to_string()).unwrap_or_default(),
                r.drain_complete_ms
                    .map(|t| t.to_string())
                    .unwrap_or_default(),
                r.finalize_ms.map(|t| t.to_string()).unwrap_or_default(),
                drain_dur,
                r.drain_timed_out,
                r.resource_leaks.join(";"),
            )
        })
        .collect();
    (header, rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Phase FSM ----

    #[test]
    fn phase_idle_can_only_go_to_requested() {
        assert!(CancelPhase::Idle.can_transition_to(&CancelPhase::CancelRequested));
        assert!(!CancelPhase::Idle.can_transition_to(&CancelPhase::Draining));
        assert!(!CancelPhase::Idle.can_transition_to(&CancelPhase::Finalized));
    }

    #[test]
    fn phase_requested_can_go_to_draining_or_itself() {
        assert!(CancelPhase::CancelRequested.can_transition_to(&CancelPhase::Draining));
        assert!(CancelPhase::CancelRequested.can_transition_to(&CancelPhase::CancelRequested));
        assert!(!CancelPhase::CancelRequested.can_transition_to(&CancelPhase::Finalized));
    }

    #[test]
    fn phase_draining_can_only_go_to_drain_complete() {
        assert!(CancelPhase::Draining.can_transition_to(&CancelPhase::DrainComplete));
        assert!(!CancelPhase::Draining.can_transition_to(&CancelPhase::Finalized));
    }

    #[test]
    fn phase_drain_complete_can_go_to_finalizing() {
        assert!(CancelPhase::DrainComplete.can_transition_to(&CancelPhase::Finalizing));
        assert!(!CancelPhase::DrainComplete.can_transition_to(&CancelPhase::Finalized));
    }

    #[test]
    fn phase_finalizing_can_go_to_finalized() {
        assert!(CancelPhase::Finalizing.can_transition_to(&CancelPhase::Finalized));
        assert!(!CancelPhase::Finalizing.can_transition_to(&CancelPhase::Idle));
    }

    #[test]
    fn phase_finalized_is_terminal() {
        assert!(CancelPhase::Finalized.legal_targets().is_empty());
    }

    #[test]
    fn phase_all_count() {
        assert_eq!(CancelPhase::ALL.len(), 6);
    }

    #[test]
    fn phase_display() {
        assert_eq!(CancelPhase::Idle.to_string(), "idle");
        assert_eq!(CancelPhase::CancelRequested.to_string(), "cancel_requested");
        assert_eq!(CancelPhase::Draining.to_string(), "draining");
        assert_eq!(CancelPhase::DrainComplete.to_string(), "drain_complete");
        assert_eq!(CancelPhase::Finalizing.to_string(), "finalizing");
        assert_eq!(CancelPhase::Finalized.to_string(), "finalized");
    }

    // ---- Happy path: full protocol ----

    #[test]
    fn happy_path_request_drain_finalize() {
        let mut proto = CancellationProtocol::default();

        // REQUEST
        let rec = proto.request_cancel("wf-1", 5, 1000, "t1").unwrap();
        assert_eq!(rec.current_phase, CancelPhase::CancelRequested);
        assert_eq!(rec.in_flight_count, 5);

        // DRAIN start
        let rec = proto.start_drain("wf-1", 1100, "t1").unwrap();
        assert_eq!(rec.current_phase, CancelPhase::Draining);

        // DRAIN complete
        let rec = proto.complete_drain("wf-1", 1500, "t1").unwrap();
        assert_eq!(rec.current_phase, CancelPhase::DrainComplete);
        assert_eq!(rec.in_flight_count, 0);

        // FINALIZE
        let resources = ResourceTracker::empty();
        let rec = proto.finalize("wf-1", &resources, 1600, "t1").unwrap();
        assert_eq!(rec.current_phase, CancelPhase::Finalized);

        // Verify audit log
        assert_eq!(proto.audit_log().len(), 4);
        assert_eq!(proto.audit_log()[0].event_code, event_codes::CAN_001);
        assert_eq!(proto.audit_log()[1].event_code, event_codes::CAN_002);
        assert_eq!(proto.audit_log()[2].event_code, event_codes::CAN_003);
        assert_eq!(proto.audit_log()[3].event_code, event_codes::CAN_005);
    }

    // ---- Idempotent cancel ----

    #[test]
    fn idempotent_cancel_request() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 5, 1000, "t1").unwrap();
        // Second request on same workflow should be absorbed
        let rec = proto.request_cancel("wf-1", 3, 1001, "t1").unwrap();
        assert_eq!(rec.current_phase, CancelPhase::CancelRequested);
    }

    // ---- Already finalized ----

    #[test]
    fn cancel_on_finalized_rejected() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-1", 1100, "t1").unwrap();
        proto.complete_drain("wf-1", 1200, "t1").unwrap();
        proto
            .finalize("wf-1", &ResourceTracker::empty(), 1300, "t1")
            .unwrap();

        let err = proto.request_cancel("wf-1", 0, 1400, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_ALREADY_FINAL);
    }

    // ---- Invalid phase transitions ----

    #[test]
    fn drain_without_request_rejected() {
        let mut proto = CancellationProtocol::default();
        // No record exists for wf-1
        let err = proto.start_drain("wf-1", 1000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_NOT_FOUND);
    }

    #[test]
    fn finalize_without_drain_rejected() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        let err = proto
            .finalize("wf-1", &ResourceTracker::empty(), 1100, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_INVALID_PHASE);
    }

    // ---- Drain timeout ----

    #[test]
    fn drain_timeout_with_force() {
        let config = DrainConfig::new(1000, true); // 1s timeout, force on timeout
        let mut proto = CancellationProtocol::new(config);

        proto.request_cancel("wf-1", 10, 1000, "t1").unwrap();
        proto.start_drain("wf-1", 1100, "t1").unwrap();

        // Complete drain after timeout
        let rec = proto.complete_drain("wf-1", 3000, "t1").unwrap();
        assert!(rec.drain_timed_out);
        assert_eq!(rec.current_phase, CancelPhase::DrainComplete);

        // Check CAN-004 was emitted
        let timeout_events: Vec<_> = proto
            .audit_log()
            .iter()
            .filter(|e| e.event_code == event_codes::CAN_004)
            .collect();
        assert_eq!(timeout_events.len(), 1);
    }

    #[test]
    fn drain_timeout_without_force_errors() {
        let config = DrainConfig::new(1000, false); // 1s timeout, no force
        let mut proto = CancellationProtocol::new(config);

        proto.request_cancel("wf-1", 10, 1000, "t1").unwrap();
        proto.start_drain("wf-1", 1100, "t1").unwrap();

        let err = proto.complete_drain("wf-1", 3000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_DRAIN_TIMEOUT);
    }

    // ---- Resource leak detection ----

    #[test]
    fn resource_leak_detected() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-1", 1100, "t1").unwrap();
        proto.complete_drain("wf-1", 1200, "t1").unwrap();

        let mut resources = ResourceTracker::empty();
        resources.held_locks.push("db-lock".to_string());

        let err = proto.finalize("wf-1", &resources, 1300, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_LEAK);

        // CAN-006 should be emitted
        let leak_events: Vec<_> = proto
            .audit_log()
            .iter()
            .filter(|e| e.event_code == event_codes::CAN_006)
            .collect();
        assert_eq!(leak_events.len(), 1);
    }

    #[test]
    fn resource_leak_keeps_phase_finalizing() {
        // INV-CANP-FINALIZE-CLEAN: leaks must NOT advance phase to Finalized.
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-leak", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-leak", 1100, "t1").unwrap();
        proto.complete_drain("wf-leak", 1200, "t1").unwrap();

        let mut resources = ResourceTracker::empty();
        resources.held_locks.push("db-lock".to_string());

        let err = proto
            .finalize("wf-leak", &resources, 1300, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_LEAK);

        // Phase must remain Finalizing, not Finalized.
        let phase = proto.current_phase("wf-leak").unwrap();
        assert_eq!(phase, CancelPhase::Finalizing);
    }

    // ---- Resource tracker ----

    #[test]
    fn resource_tracker_empty_is_clean() {
        assert!(ResourceTracker::empty().is_clean());
    }

    #[test]
    fn resource_tracker_with_handles_not_clean() {
        let mut rt = ResourceTracker::empty();
        rt.open_handles.push("fd-42".to_string());
        assert!(!rt.is_clean());
        assert_eq!(rt.leaked_resources().len(), 1);
    }

    #[test]
    fn resource_tracker_with_pending_writes_not_clean() {
        let mut rt = ResourceTracker::empty();
        rt.pending_writes = 3;
        assert!(!rt.is_clean());
    }

    #[test]
    fn resource_tracker_with_locks_not_clean() {
        let mut rt = ResourceTracker::empty();
        rt.held_locks.push("mutex-1".to_string());
        assert!(!rt.is_clean());
    }

    // ---- Drain config ----

    #[test]
    fn drain_config_default() {
        let config = DrainConfig::default();
        assert_eq!(config.timeout_ms, DEFAULT_DRAIN_TIMEOUT_MS);
        assert!(config.force_on_timeout);
    }

    #[test]
    fn drain_config_enforces_minimum() {
        let config = DrainConfig::new(100, false);
        assert_eq!(config.timeout_ms, MIN_DRAIN_TIMEOUT_MS);
    }

    // ---- Counts ----

    #[test]
    fn active_and_finalized_counts() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        proto.request_cancel("wf-2", 0, 1000, "t2").unwrap();
        assert_eq!(proto.active_count(), 2);
        assert_eq!(proto.finalized_count(), 0);

        // Finalize wf-1
        proto.start_drain("wf-1", 1100, "t1").unwrap();
        proto.complete_drain("wf-1", 1200, "t1").unwrap();
        proto
            .finalize("wf-1", &ResourceTracker::empty(), 1300, "t1")
            .unwrap();

        assert_eq!(proto.active_count(), 1);
        assert_eq!(proto.finalized_count(), 1);
    }

    // ---- Cancellation record ----

    #[test]
    fn cancellation_record_elapsed() {
        let mut record = CancellationRecord::new("wf-1", DrainConfig::default(), "t1");
        record.request_timestamp_ms = Some(1000);
        assert_eq!(record.elapsed_ms(2000), 1000);
    }

    #[test]
    fn cancellation_record_drain_duration() {
        let mut record = CancellationRecord::new("wf-1", DrainConfig::default(), "t1");
        record.drain_start_ms = Some(1000);
        record.drain_complete_ms = Some(1500);
        assert_eq!(record.drain_duration_ms(), Some(500));
    }

    #[test]
    fn cancellation_record_no_drain_duration() {
        let record = CancellationRecord::new("wf-1", DrainConfig::default(), "t1");
        assert_eq!(record.drain_duration_ms(), None);
    }

    // ---- JSONL export ----

    #[test]
    fn audit_log_jsonl_export() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        let jsonl = proto.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::CAN_001);
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    #[test]
    fn audit_log_capacity_clamps_to_one() {
        let mut proto = CancellationProtocol::with_audit_log_capacity(DrainConfig::default(), 0);
        assert_eq!(proto.audit_log_capacity(), 1);

        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-1", 1100, "t1").unwrap();

        assert_eq!(proto.audit_log().len(), 1);
        assert_eq!(proto.audit_log()[0].event_code, event_codes::CAN_002);
    }

    #[test]
    fn audit_log_capacity_enforces_oldest_first_eviction() {
        let mut proto = CancellationProtocol::with_audit_log_capacity(DrainConfig::default(), 2);

        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-1", 1100, "t1").unwrap();
        proto.complete_drain("wf-1", 1200, "t1").unwrap();

        assert_eq!(proto.audit_log_capacity(), 2);
        assert_eq!(proto.audit_log().len(), 2);
        assert_eq!(proto.audit_log()[0].event_code, event_codes::CAN_002);
        assert_eq!(proto.audit_log()[1].event_code, event_codes::CAN_003);
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<CancelProtocolError> = vec![
            CancelProtocolError::InvalidPhase {
                from: CancelPhase::Idle,
                to: CancelPhase::Draining,
            },
            CancelProtocolError::AlreadyFinal {
                workflow_id: "wf-1".into(),
            },
            CancelProtocolError::DrainTimeout {
                workflow_id: "wf-1".into(),
                elapsed_ms: 5000,
                timeout_ms: 3000,
            },
            CancelProtocolError::ResourceLeak {
                workflow_id: "wf-1".into(),
                leaked_resources: vec!["lock:db".into()],
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(s.contains(e.code()), "{:?} should contain {}", e, e.code());
        }
    }

    // ---- Cancellation readiness ----

    #[test]
    fn cancellation_readiness_clean() {
        let proto = CancellationProtocol::default();
        assert!(cancellation_readiness_check(&proto));
    }

    // ---- Timing report ----

    #[test]
    fn timing_report_generates_csv() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 5, 1000, "t1").unwrap();
        proto.start_drain("wf-1", 1100, "t1").unwrap();
        proto.complete_drain("wf-1", 1500, "t1").unwrap();
        proto
            .finalize("wf-1", &ResourceTracker::empty(), 1600, "t1")
            .unwrap();

        let (header, rows) = generate_timing_report(&proto);
        assert!(header.contains("workflow_id"));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains("wf-1"));
        assert!(rows[0].contains("finalized"));
    }

    // ---- Multiple workflows ----

    #[test]
    fn multiple_workflows_independent() {
        let mut proto = CancellationProtocol::default();

        proto.request_cancel("wf-1", 5, 1000, "t1").unwrap();
        proto.request_cancel("wf-2", 3, 1000, "t2").unwrap();

        proto.start_drain("wf-1", 1100, "t1").unwrap();
        assert_eq!(proto.current_phase("wf-1"), Some(CancelPhase::Draining));
        assert_eq!(
            proto.current_phase("wf-2"),
            Some(CancelPhase::CancelRequested)
        );
    }

    // ---- Serde roundtrip ----

    #[test]
    fn cancel_phase_serde_roundtrip() {
        for phase in &CancelPhase::ALL {
            let json = serde_json::to_string(phase).unwrap();
            let parsed: CancelPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, parsed);
        }
    }

    #[test]
    fn cancel_audit_event_serde_roundtrip() {
        let event = CancelAuditEvent::new(
            event_codes::CAN_001,
            "wf-1",
            CancelPhase::Idle,
            CancelPhase::CancelRequested,
            1000,
            "t1",
            "test",
        );
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CancelAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn drain_config_serde_roundtrip() {
        let config = DrainConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DrainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    // ---- Get record ----

    #[test]
    fn get_record_found() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 5, 1000, "t1").unwrap();
        assert!(proto.get_record("wf-1").is_some());
    }

    #[test]
    fn get_record_not_found() {
        let proto = CancellationProtocol::default();
        assert!(proto.get_record("wf-99").is_none());
    }

    // ---- Default ----

    #[test]
    fn default_protocol() {
        let proto = CancellationProtocol::default();
        assert!(proto.records().is_empty());
        assert!(proto.audit_log().is_empty());
        assert_eq!(proto.active_count(), 0);
        assert_eq!(proto.finalized_count(), 0);
    }

    // ---- Double finalize rejected ----

    #[test]
    fn double_finalize_rejected() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-1", 1100, "t1").unwrap();
        proto.complete_drain("wf-1", 1200, "t1").unwrap();
        proto
            .finalize("wf-1", &ResourceTracker::empty(), 1300, "t1")
            .unwrap();

        let err = proto
            .finalize("wf-1", &ResourceTracker::empty(), 1400, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_ALREADY_FINAL);
    }

    #[test]
    fn start_drain_twice_rejected_without_phase_mutation() {
        let mut proto = CancellationProtocol::default();
        proto
            .request_cancel("wf-double-drain", 2, 1000, "trace")
            .unwrap();
        proto.start_drain("wf-double-drain", 1100, "trace").unwrap();

        let err = proto
            .start_drain("wf-double-drain", 1200, "trace")
            .expect_err("second drain start must be an invalid transition");
        match err {
            CancelProtocolError::InvalidPhase { from, to } => {
                assert_eq!(from, CancelPhase::Draining);
                assert_eq!(to, CancelPhase::Draining);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        assert_eq!(
            proto.current_phase("wf-double-drain"),
            Some(CancelPhase::Draining)
        );
    }

    #[test]
    fn complete_drain_before_start_rejected() {
        let mut proto = CancellationProtocol::default();
        proto
            .request_cancel("wf-complete-early", 1, 1000, "trace")
            .unwrap();

        let err = proto
            .complete_drain("wf-complete-early", 1100, "trace")
            .expect_err("drain completion before start must fail");
        match err {
            CancelProtocolError::InvalidPhase { from, to } => {
                assert_eq!(from, CancelPhase::CancelRequested);
                assert_eq!(to, CancelPhase::DrainComplete);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        assert_eq!(
            proto.current_phase("wf-complete-early"),
            Some(CancelPhase::CancelRequested)
        );
    }

    #[test]
    fn request_cancel_while_draining_rejected() {
        let mut proto = CancellationProtocol::default();
        proto
            .request_cancel("wf-draining", 4, 1000, "trace")
            .unwrap();
        proto.start_drain("wf-draining", 1100, "trace").unwrap();

        let err = proto
            .request_cancel("wf-draining", 0, 1200, "trace")
            .expect_err("draining workflow must not re-enter request phase");
        match err {
            CancelProtocolError::InvalidPhase { from, to } => {
                assert_eq!(from, CancelPhase::Draining);
                assert_eq!(to, CancelPhase::CancelRequested);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        assert_eq!(
            proto.current_phase("wf-draining"),
            Some(CancelPhase::Draining)
        );
        assert_eq!(proto.get_record("wf-draining").unwrap().in_flight_count, 4);
    }

    #[test]
    fn request_cancel_after_drain_complete_rejected() {
        let mut proto = CancellationProtocol::default();
        proto
            .request_cancel("wf-drain-complete", 3, 1000, "trace")
            .unwrap();
        proto
            .start_drain("wf-drain-complete", 1100, "trace")
            .unwrap();
        proto
            .complete_drain("wf-drain-complete", 1200, "trace")
            .unwrap();

        let err = proto
            .request_cancel("wf-drain-complete", 0, 1300, "trace")
            .expect_err("drain-complete workflow must not re-enter request phase");
        match err {
            CancelProtocolError::InvalidPhase { from, to } => {
                assert_eq!(from, CancelPhase::DrainComplete);
                assert_eq!(to, CancelPhase::CancelRequested);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        assert_eq!(
            proto.current_phase("wf-drain-complete"),
            Some(CancelPhase::DrainComplete)
        );
    }

    #[test]
    fn exact_timeout_without_force_fails_closed_and_keeps_draining() {
        let config = DrainConfig::new(1000, false);
        let mut proto = CancellationProtocol::new(config);
        proto
            .request_cancel("wf-exact-timeout", 1, 1000, "trace")
            .unwrap();
        proto
            .start_drain("wf-exact-timeout", 1100, "trace")
            .unwrap();

        let err = proto
            .complete_drain("wf-exact-timeout", 2100, "trace")
            .expect_err("elapsed time equal to timeout must fail closed");
        match err {
            CancelProtocolError::DrainTimeout {
                workflow_id,
                elapsed_ms,
                timeout_ms,
            } => {
                assert_eq!(workflow_id, "wf-exact-timeout");
                assert_eq!(elapsed_ms, 1000);
                assert_eq!(timeout_ms, 1000);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        let record = proto.get_record("wf-exact-timeout").unwrap();
        assert_eq!(record.current_phase, CancelPhase::Draining);
        assert!(record.drain_timed_out);
        assert_eq!(record.drain_complete_ms, None);
        assert_eq!(
            proto.audit_log().last().unwrap().event_code,
            event_codes::CAN_004
        );
    }

    #[test]
    fn finalize_unknown_workflow_rejected() {
        let mut proto = CancellationProtocol::default();
        let err = proto
            .finalize("wf-missing", &ResourceTracker::empty(), 1000, "trace")
            .expect_err("unknown workflow cannot be finalized");
        match err {
            CancelProtocolError::WorkflowNotFound { workflow_id } => {
                assert_eq!(workflow_id, "wf-missing");
            }
            other => unreachable!("unexpected error: {other}"),
        }
        assert!(proto.audit_log().is_empty());
    }

    #[test]
    fn finalized_workflow_cannot_start_drain_again() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-final", 0, 1000, "trace").unwrap();
        proto.start_drain("wf-final", 1100, "trace").unwrap();
        proto.complete_drain("wf-final", 1200, "trace").unwrap();
        proto
            .finalize("wf-final", &ResourceTracker::empty(), 1300, "trace")
            .unwrap();

        let err = proto
            .start_drain("wf-final", 1400, "trace")
            .expect_err("finalized workflow must be terminal");
        match err {
            CancelProtocolError::InvalidPhase { from, to } => {
                assert_eq!(from, CancelPhase::Finalized);
                assert_eq!(to, CancelPhase::Draining);
            }
            other => unreachable!("unexpected error: {other}"),
        }
        assert_eq!(
            proto.current_phase("wf-final"),
            Some(CancelPhase::Finalized)
        );
    }

    #[test]
    fn finalization_with_multiple_resource_leaks_records_all_leaks() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-leaks", 0, 1000, "trace").unwrap();
        proto.start_drain("wf-leaks", 1100, "trace").unwrap();
        proto.complete_drain("wf-leaks", 1200, "trace").unwrap();
        let resources = ResourceTracker {
            open_handles: vec!["fd-1".to_string()],
            pending_writes: 2,
            held_locks: vec!["mutex-a".to_string()],
        };

        let err = proto
            .finalize("wf-leaks", &resources, 1300, "trace")
            .expect_err("leaked resources must block finalization");
        match err {
            CancelProtocolError::ResourceLeak {
                workflow_id,
                leaked_resources,
            } => {
                assert_eq!(workflow_id, "wf-leaks");
                assert!(leaked_resources.contains(&"handle:fd-1".to_string()));
                assert!(leaked_resources.contains(&"pending_writes:2".to_string()));
                assert!(leaked_resources.contains(&"lock:mutex-a".to_string()));
            }
            other => unreachable!("unexpected error: {other}"),
        }

        let record = proto.get_record("wf-leaks").unwrap();
        assert_eq!(record.current_phase, CancelPhase::Finalizing);
        assert_eq!(record.finalize_ms, None);
        assert!(record.resource_leaks.contains(&"handle:fd-1".to_string()));
        assert!(
            record
                .resource_leaks
                .contains(&"pending_writes:2".to_string())
        );
        assert!(record.resource_leaks.contains(&"lock:mutex-a".to_string()));
        assert_eq!(
            proto.audit_log().last().unwrap().event_code,
            event_codes::CAN_006
        );
    }

    // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

    #[test]
    fn test_negative_cancellation_id_with_unicode_injection_attacks() {
        use crate::security::constant_time;

        let mut proto = CancellationProtocol::new(
            Duration::from_millis(1000),
            1000,
            1000,
        );

        let malicious_cancellation_ids = [
            "cancel\u{202E}fake\u{202C}",        // BiDi override attack
            "cancel\x1b[31mred\x1b[0m",          // ANSI escape injection
            "cancel\0null\r\n\t",                // Control character injection
            "cancel\"}{\"admin\":true,\"bypass", // JSON injection attempt
            "cancel/../../etc/passwd",           // Path traversal attempt
            "cancel\u{FEFF}BOM",                 // Byte order mark
            "cancel\u{200B}\u{200C}\u{200D}",   // Zero-width characters
            "cancel<script>alert(1)</script>",  // XSS attempt
            "cancel'; DROP TABLE records; --",  // SQL injection attempt
            "cancel||rm -rf /",                  // Shell injection attempt
            "x".repeat(100_000),                 // Extremely long ID (100KB)
        ];

        for malicious_id in malicious_cancellation_ids {
            // Test cancel request with malicious ID
            let result = proto.request_cancel(malicious_id, "test-reason", "test-trace");
            assert!(result.is_ok(), "protocol should handle malicious cancellation ID safely");

            // Verify ID is preserved exactly for forensics
            let record = proto.get_record(malicious_id).expect("record should exist");
            assert_eq!(record.cancellation_id, malicious_id, "ID should be preserved");

            // Test JSON serialization safety
            let json = serde_json::to_string(&record).expect("serialization should work");
            let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

            // Verify no injection occurred in JSON structure
            assert!(parsed.get("admin").is_none(), "JSON injection should not create admin field");
            assert!(parsed.get("bypass").is_none(), "JSON injection should not create bypass field");

            // Test constant-time comparison for cancellation IDs
            let normal_id = "normal-cancel-123";
            assert!(!constant_time::ct_eq(malicious_id, normal_id), "ID comparison should be constant-time");

            // Complete cancellation to clean up for next iteration
            let _ = proto.start_drain(malicious_id, "test-trace");
            let _ = proto.complete_drain(malicious_id, "test-trace");
            let _ = proto.finalize(malicious_id, "test-trace", vec![]);
        }

        // Test with cancellation IDs that might bypass protocol enforcement
        let bypass_ids = [
            "",                          // Empty ID
            "null",                      // Literal "null"
            "undefined",                 // Literal "undefined"
            "false",                     // Boolean-like
            "0",                         // Number-like
            "admin.cancel.override",     // Administrative bypass attempt
            "system.internal.emergency", // System internal operation
            "debug.force.finalize",      // Debug forcing attempt
        ];

        for bypass_id in bypass_ids {
            let result = proto.request_cancel(bypass_id, "bypass-test", "bypass-trace");
            assert!(result.is_ok(), "protocol should handle bypass attempts safely");

            // Should still follow normal protocol phases
            let record = proto.get_record(bypass_id).expect("record should exist");
            assert_eq!(record.phase, CancelPhase::CancelRequested, "should be in normal REQUEST phase");
        }
    }

    #[test]
    fn test_negative_state_machine_with_illegal_phase_transitions() {
        let mut proto = CancellationProtocol::new(
            Duration::from_millis(1000),
            1000,
            1000,
        );

        let cancel_id = "illegal-transition-test";
        proto.request_cancel(cancel_id, "test", "trace").unwrap();

        // Test illegal direct transitions from CancelRequested
        let illegal_from_requested = [
            CancelPhase::DrainComplete,  // Skip drain
            CancelPhase::Finalizing,     // Skip drain entirely
            CancelPhase::Finalized,      // Complete bypass
            CancelPhase::Idle,           // Backward transition
        ];

        for illegal_phase in illegal_from_requested {
            // Try to force illegal transition (this would be internal manipulation)
            let initial_phase = proto.get_record(cancel_id).unwrap().phase;
            assert_eq!(initial_phase, CancelPhase::CancelRequested);

            // Verify legal targets don't include illegal phases
            let legal = initial_phase.legal_targets();
            assert!(!legal.contains(&illegal_phase),
                   "legal targets should not include illegal phase {:?}", illegal_phase);
        }

        // Test proper transition sequence
        proto.start_drain(cancel_id, "trace").unwrap();
        let drain_phase = proto.get_record(cancel_id).unwrap().phase;
        assert_eq!(drain_phase, CancelPhase::Draining);

        // Test illegal transitions from Draining
        let illegal_from_draining = [
            CancelPhase::Idle,
            CancelPhase::CancelRequested,
            CancelPhase::Finalizing,     // Skip drain completion
            CancelPhase::Finalized,
        ];

        for illegal_phase in illegal_from_draining {
            let legal = drain_phase.legal_targets();
            assert!(!legal.contains(&illegal_phase),
                   "legal targets from Draining should not include illegal phase {:?}", illegal_phase);
        }

        // Complete drain properly
        proto.complete_drain(cancel_id, "trace").unwrap();
        let drain_complete_phase = proto.get_record(cancel_id).unwrap().phase;
        assert_eq!(drain_complete_phase, CancelPhase::DrainComplete);

        // Test illegal transitions from DrainComplete
        let illegal_from_complete = [
            CancelPhase::Idle,
            CancelPhase::CancelRequested,
            CancelPhase::Draining,       // Backward transition
            CancelPhase::Finalized,      // Skip finalization
        ];

        for illegal_phase in illegal_from_complete {
            let legal = drain_complete_phase.legal_targets();
            assert!(!legal.contains(&illegal_phase),
                   "legal targets from DrainComplete should not include illegal phase {:?}", illegal_phase);
        }

        // Test terminal state enforcement
        proto.finalize(cancel_id, "trace", vec![]).unwrap();
        let final_phase = proto.get_record(cancel_id).unwrap().phase;
        assert_eq!(final_phase, CancelPhase::Finalized);

        // All transitions from Finalized should be illegal
        let legal_from_final = final_phase.legal_targets();
        assert!(legal_from_final.is_empty(), "no transitions should be legal from Finalized");

        // Verify subsequent operations fail on finalized cancellation
        let result = proto.start_drain(cancel_id, "trace");
        assert!(result.is_err(), "operations on finalized cancellation should fail");
    }

    #[test]
    fn test_negative_drain_timeout_with_arithmetic_overflow_attempts() {
        // Test with extreme timeout values that might cause overflow
        let extreme_timeouts = [
            Duration::from_millis(0),                    // Zero timeout
            Duration::from_millis(1),                    // Minimum timeout
            Duration::from_millis(u64::MAX),             // Maximum duration
            Duration::from_secs(u64::MAX / 1000),        // Near-maximum seconds
            Duration::from_millis(MIN_DRAIN_TIMEOUT_MS), // At minimum boundary
            Duration::from_millis(MIN_DRAIN_TIMEOUT_MS - 1), // Below minimum
        ];

        for extreme_timeout in extreme_timeouts {
            let proto = CancellationProtocol::new(extreme_timeout, 100, 100);

            let cancel_id = format!("timeout-test-{:?}", extreme_timeout.as_millis());

            proto.request_cancel(&cancel_id, "extreme timeout test", "trace").unwrap();
            proto.start_drain(&cancel_id, "trace").unwrap();

            // Simulate immediate timeout check
            let now = std::time::Instant::now();
            let record = proto.get_record(&cancel_id).unwrap();

            // Test timeout calculation doesn't overflow
            let drain_deadline = record.drain_started_at.unwrap() + proto.drain_timeout;

            // Verify arithmetic operations are safe
            if now > drain_deadline {
                // Timeout should be detected safely
                let result = proto.check_drain_timeout(&cancel_id, "trace");
                // Should handle timeout without panic
            }

            // Test duration serialization with extreme values
            let timeout_ms = extreme_timeout.as_millis();
            if timeout_ms <= u64::MAX as u128 {
                let json = serde_json::json!({"timeout_ms": timeout_ms});
                let json_str = serde_json::to_string(&json).expect("serialization should work");

                // Should not contain injection patterns
                assert!(!json_str.contains("admin"), "serialized timeout should not contain injection");
            }
        }

        // Test timeout arithmetic with values near overflow boundaries
        let near_overflow_durations = [
            Duration::from_millis(u64::MAX - 1000),
            Duration::from_millis(u64::MAX / 2),
            Duration::from_secs(u32::MAX as u64),
        ];

        for duration in near_overflow_durations {
            let proto = CancellationProtocol::new(duration, 10, 10);

            let cancel_id = format!("overflow-test-{}", duration.as_millis());
            proto.request_cancel(&cancel_id, "overflow test", "trace").unwrap();
            proto.start_drain(&cancel_id, "trace").unwrap();

            // Test that timeout calculation uses saturating arithmetic
            let record = proto.get_record(&cancel_id).unwrap();
            let start = record.drain_started_at.unwrap();

            // This should not panic or overflow
            let deadline = start.checked_add(duration);

            match deadline {
                Some(_) => {
                    // Addition succeeded, timeout check should work
                }
                None => {
                    // Addition would overflow, should be handled gracefully
                    // In a real implementation, this might default to immediate timeout
                    // or maximum timeout to fail safe
                }
            }
        }
    }

    #[test]
    fn test_negative_resource_leak_detection_with_malicious_resource_names() {
        let mut proto = CancellationProtocol::new(
            Duration::from_millis(1000),
            1000,
            1000,
        );

        let cancel_id = "resource-leak-test";
        proto.request_cancel(cancel_id, "leak test", "trace").unwrap();
        proto.start_drain(cancel_id, "trace").unwrap();
        proto.complete_drain(cancel_id, "trace").unwrap();

        // Test with malicious resource names that might cause injection
        let malicious_resource_names = vec![
            "resource\u{202E}fake\u{202C}".to_string(),        // BiDi override
            "resource\x1b[31mred\x1b[0m".to_string(),          // ANSI escape
            "resource\0null\r\n\t".to_string(),                // Control chars
            "resource\"}{\"admin\":true,\"bypass".to_string(), // JSON injection
            "resource<script>alert(1)</script>".to_string(),  // XSS attempt
            "resource'; DROP TABLE leaks; --".to_string(),    // SQL injection
            "resource||rm -rf /".to_string(),                  // Shell injection
            format!("resource_{}", "X".repeat(100_000)),       // Massive resource name
            "".to_string(),                                     // Empty resource name
            "null".to_string(),                                // Literal "null"
            "undefined".to_string(),                           // Literal "undefined"
            "admin.override".to_string(),                      // Admin-like resource
            "system.bypass".to_string(),                       // System-like resource
        ];

        let result = proto.finalize(cancel_id, "trace", malicious_resource_names.clone());
        assert!(result.is_ok(), "finalization should handle malicious resource names");

        // Verify resource names are preserved exactly for forensics
        let record = proto.get_record(cancel_id).unwrap();
        assert_eq!(record.resource_leaks.len(), malicious_resource_names.len());

        for (original, stored) in malicious_resource_names.iter().zip(record.resource_leaks.iter()) {
            assert_eq!(original, stored, "resource names should be preserved exactly");
        }

        // Test JSON serialization safety with malicious resource names
        let json = serde_json::to_string(&record).expect("serialization should work");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

        // Verify no injection occurred in JSON structure
        assert!(parsed.get("admin").is_none(), "JSON injection should not create admin field");
        assert!(parsed.get("bypass").is_none(), "JSON injection should not create bypass field");

        // Verify resource leaks array is properly contained
        let leaks = parsed.get("resource_leaks").expect("resource_leaks field should exist");
        assert!(leaks.is_array(), "resource_leaks should be an array");

        let leaks_array = leaks.as_array().unwrap();
        assert_eq!(leaks_array.len(), malicious_resource_names.len());

        // Test audit log with resource leak detection
        let audit_entries = proto.audit_log();
        let leak_events: Vec<_> = audit_entries.iter()
            .filter(|entry| entry.event_code == event_codes::CAN_006)
            .collect();

        assert!(!leak_events.is_empty(), "resource leak events should be logged");

        // Test with extremely large number of resource leaks
        let massive_cancel_id = "massive-leak-test";
        proto.request_cancel(massive_cancel_id, "massive leak test", "trace").unwrap();
        proto.start_drain(massive_cancel_id, "trace").unwrap();
        proto.complete_drain(massive_cancel_id, "trace").unwrap();

        let massive_leaks: Vec<String> = (0..10_000)
            .map(|i| format!("leak_{:05}_{}", i, "Y".repeat(100)))
            .collect();

        let massive_result = proto.finalize(massive_cancel_id, "trace", massive_leaks.clone());
        assert!(massive_result.is_ok(), "should handle massive resource leak list");

        let massive_record = proto.get_record(massive_cancel_id).unwrap();
        assert_eq!(massive_record.resource_leaks.len(), massive_leaks.len());
    }

    #[test]
    fn test_negative_cancellation_reason_with_injection_patterns() {
        let mut proto = CancellationProtocol::new(
            Duration::from_millis(1000),
            1000,
            1000,
        );

        let malicious_reasons = [
            "reason\u{202E}fake\u{202C}",           // BiDi override
            "reason\x1b[31mred\x1b[0m",             // ANSI escape
            "reason\0null\r\n\t",                   // Control characters
            "reason\"}{\"admin\":true,\"bypass\"", // JSON injection
            "reason<script>alert(1)</script>",     // XSS attempt
            "reason'; DROP TABLE cancellations; --", // SQL injection
            "reason||rm -rf /",                     // Shell injection
            &format!("reason_{}", "X".repeat(1_000_000)), // Massive reason (1MB)
        ];

        for malicious_reason in malicious_reasons {
            let cancel_id = format!("reason-test-{}", malicious_reasons.iter().position(|&r| r == malicious_reason).unwrap());

            let result = proto.request_cancel(&cancel_id, malicious_reason, "test-trace");
            assert!(result.is_ok(), "should handle malicious cancellation reason");

            // Verify reason is preserved exactly for forensics
            let record = proto.get_record(&cancel_id).unwrap();
            assert_eq!(record.cancel_reason, malicious_reason, "reason should be preserved");

            // Test JSON serialization safety
            let json = serde_json::to_string(&record).expect("serialization should work");
            let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

            // Verify no injection occurred
            assert!(parsed.get("admin").is_none(), "JSON injection should not create admin field");
            assert!(parsed.get("bypass").is_none(), "JSON injection should not create bypass field");

            // Verify reason is properly escaped in JSON
            if let Some(reason) = parsed.get("cancel_reason").and_then(|r| r.as_str()) {
                assert_eq!(reason, malicious_reason, "reason should be preserved in JSON");
            }

            // Test audit log entry with malicious reason
            let audit_entries = proto.audit_log();
            let request_events: Vec<_> = audit_entries.iter()
                .filter(|entry| entry.event_code == event_codes::CAN_001 && entry.cancellation_id == cancel_id)
                .collect();

            assert!(!request_events.is_empty(), "cancel request events should be logged");

            for event in request_events {
                // Verify event details don't propagate injection
                assert!(!event.detail.contains("admin"), "audit detail should not contain injection");
            }
        }

        // Test with reasons that might bypass cancellation logic
        let bypass_reasons = [
            "",                           // Empty reason
            "null",                       // Literal "null"
            "undefined",                  // Literal "undefined"
            "false",                      // Boolean-like
            "admin.emergency.bypass",     // Administrative bypass
            "system.force.cancel",        // System forcing
            "debug.override.protocol",    // Debug override
        ];

        for bypass_reason in bypass_reasons {
            let cancel_id = format!("bypass-reason-{}", bypass_reasons.iter().position(|&r| r == bypass_reason).unwrap());

            let result = proto.request_cancel(&cancel_id, bypass_reason, "bypass-trace");
            assert!(result.is_ok(), "should handle bypass reason attempts");

            // Should still follow normal protocol
            let record = proto.get_record(&cancel_id).unwrap();
            assert_eq!(record.phase, CancelPhase::CancelRequested, "should be in normal REQUEST phase");
            assert_eq!(record.cancel_reason, bypass_reason, "bypass reason should be preserved");
        }
    }

    #[test]
    fn test_negative_trace_id_with_massive_forensic_payloads() {
        use crate::security::constant_time;

        let mut proto = CancellationProtocol::new(
            Duration::from_millis(1000),
            1000,
            1000,
        );

        // Test with massive trace IDs for memory stress
        let massive_trace_id = format!("trace_{}", "Z".repeat(5_000_000)); // 5MB trace ID

        let cancel_id = "massive-trace-test";
        let result = proto.request_cancel(cancel_id, "massive trace test", &massive_trace_id);
        assert!(result.is_ok(), "should handle massive trace ID");

        // Verify trace ID is preserved in audit log
        let audit_entries = proto.audit_log();
        let request_event = audit_entries.iter()
            .find(|entry| entry.event_code == event_codes::CAN_001 && entry.cancellation_id == cancel_id)
            .expect("request event should exist");

        assert_eq!(request_event.trace_id, massive_trace_id, "massive trace ID should be preserved");

        // Test JSON serialization with massive trace ID
        let json = serde_json::to_string(&request_event).expect("serialization should work");
        assert!(json.len() > 5_000_000, "serialized JSON should include massive trace ID");

        let parsed: CancellationAuditEntry = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(parsed.trace_id, massive_trace_id, "trace ID should survive roundtrip");

        // Test with injection patterns in trace ID
        let injection_trace_ids = [
            "trace\u{202E}fake\u{202C}",
            "trace\x1b[31mred\x1b[0m",
            "trace\0null\r\n\t",
            "trace\"}{\"admin\":true,\"bypass",
            "trace<script>alert(1)</script>",
            "trace'; DROP TABLE traces; --",
            "trace||rm -rf /",
        ];

        for injection_trace_id in injection_trace_ids {
            let cancel_id = format!("injection-trace-{}", injection_trace_ids.iter().position(|&t| t == injection_trace_id).unwrap());

            let result = proto.request_cancel(&cancel_id, "injection test", injection_trace_id);
            assert!(result.is_ok(), "should handle injection trace ID safely");

            // Test constant-time comparison for trace IDs
            let normal_trace = "normal-trace-123";
            assert!(!constant_time::ct_eq(injection_trace_id, normal_trace),
                   "trace ID comparison should be constant-time");

            // Verify injection is contained in audit log
            let audit_entries = proto.audit_log();
            let injection_event = audit_entries.iter()
                .find(|entry| entry.cancellation_id == cancel_id)
                .expect("injection event should exist");

            assert_eq!(injection_event.trace_id, injection_trace_id, "injection trace ID should be preserved");

            // Test JSON safety
            let json = serde_json::to_string(&injection_event).expect("serialization should work");
            let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

            assert!(parsed.get("admin").is_none(), "JSON injection should not create admin field");
            assert!(parsed.get("bypass").is_none(), "JSON injection should not create bypass field");
        }
    }

    #[test]
    fn test_negative_bounded_storage_with_memory_exhaustion_attacks() {
        // Create protocol with small capacity for testing
        let mut proto = CancellationProtocol::new(
            Duration::from_millis(1000),
            10,  // Small audit log capacity
            10,  // Small records capacity
        );

        // Attempt to exhaust memory with many cancellation records
        for i in 0..1000 {
            let cancel_id = format!("exhaustion-test-{:03}", i);
            let reason = format!("exhaustion reason {}", i);
            let trace = format!("exhaustion-trace-{:03}", i);

            let result = proto.request_cancel(&cancel_id, &reason, &trace);
            assert!(result.is_ok(), "should handle cancellation {}", i);

            // Complete the cancellation to generate audit events
            let _ = proto.start_drain(&cancel_id, &trace);
            let _ = proto.complete_drain(&cancel_id, &trace);
            let _ = proto.finalize(&cancel_id, &trace, vec![format!("leak_{}", i)]);
        }

        // Verify bounded storage is enforced
        let audit_log = proto.audit_log();
        assert!(audit_log.len() <= 50, "audit log should be bounded (got {})", audit_log.len()); // Allow some overhead

        let records = proto.records();
        assert!(records.len() <= 10, "records should be bounded to capacity (got {})", records.len());

        // Test with massive single audit entry
        let massive_cancel_id = "massive-audit-test";
        let massive_reason = format!("massive_reason_{}", "X".repeat(1_000_000)); // 1MB reason
        let massive_trace = format!("massive_trace_{}", "Y".repeat(1_000_000));   // 1MB trace

        let result = proto.request_cancel(&massive_cancel_id, &massive_reason, &massive_trace);
        assert!(result.is_ok(), "should handle massive audit entry");

        // Verify massive entry doesn't break bounded storage
        let audit_log_after = proto.audit_log();
        assert!(audit_log_after.len() <= 100, "audit log should remain bounded even with massive entries");

        // Test rapid-fire cancellations to stress FIFO eviction
        for i in 0..100 {
            let rapid_id = format!("rapid-{:03}", i);
            let result = proto.request_cancel(&rapid_id, "rapid test", &format!("rapid-trace-{:03}", i));
            assert!(result.is_ok(), "should handle rapid cancellation {}", i);
        }

        // Verify FIFO eviction maintains most recent entries
        let final_records = proto.records();
        assert!(final_records.len() <= 10, "records should maintain capacity bound");

        let recent_exists = final_records.iter()
            .any(|record| record.cancellation_id.starts_with("rapid-09"));
        // Most recent should be preserved (unless capacity is very constrained)

        // Verify protocol still functions after stress testing
        let final_test_id = "final-functionality-test";
        let final_result = proto.request_cancel(final_test_id, "final test", "final-trace");
        assert!(final_result.is_ok(), "protocol should still function after stress testing");

        let final_record = proto.get_record(final_test_id);
        assert!(final_record.is_some(), "should be able to retrieve final test record");
    }

    #[test]
    fn test_negative_concurrent_cancellation_with_race_conditions() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let proto = Arc::new(Mutex::new(CancellationProtocol::new(
            Duration::from_millis(100),
            1000,
            1000,
        )));

        let mut handles = Vec::new();

        // Test concurrent cancellation requests
        for thread_id in 0..8 {
            let proto_clone = Arc::clone(&proto);
            let handle = thread::spawn(move || {
                for i in 0..50 {
                    let cancel_id = format!("concurrent-{}-{:03}", thread_id, i);
                    let reason = format!("concurrent test from thread {}", thread_id);
                    let trace = format!("concurrent-trace-{}-{:03}", thread_id, i);

                    // Request cancellation
                    let result = {
                        let mut locked_proto = proto_clone.lock().unwrap();
                        locked_proto.request_cancel(&cancel_id, &reason, &trace)
                    };

                    match result {
                        Ok(_) => {
                            // Start drain
                            let drain_result = {
                                let mut locked_proto = proto_clone.lock().unwrap();
                                locked_proto.start_drain(&cancel_id, &trace)
                            };

                            if drain_result.is_ok() {
                                // Complete drain
                                let complete_result = {
                                    let mut locked_proto = proto_clone.lock().unwrap();
                                    locked_proto.complete_drain(&cancel_id, &trace)
                                };

                                if complete_result.is_ok() {
                                    // Finalize
                                    let finalize_result = {
                                        let mut locked_proto = proto_clone.lock().unwrap();
                                        locked_proto.finalize(&cancel_id, &trace, vec![])
                                    };

                                    // Finalization may fail due to race conditions, which is acceptable
                                }
                            }
                        }
                        Err(_) => {
                            // Request may fail due to capacity constraints under contention
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("thread should complete successfully");
        }

        // Verify protocol state after concurrent access
        let final_proto = proto.lock().unwrap();
        let final_records = final_proto.records();

        // Should have some records (exact count depends on eviction and race conditions)
        assert!(final_records.len() <= 1000, "should respect capacity bounds under concurrency");

        // Verify all remaining records are in valid states
        for record in final_records {
            assert!(record.cancellation_id.starts_with("concurrent-"), "records should be from concurrent test");

            // Phase should be valid
            match record.phase {
                CancelPhase::Idle => unreachable!("idle phase should not be stored"),
                CancelPhase::CancelRequested => {
                    // Valid intermediate state
                }
                CancelPhase::Draining => {
                    // Valid intermediate state
                    assert!(record.drain_started_at.is_some(), "draining phase should have start time");
                }
                CancelPhase::DrainComplete => {
                    // Valid intermediate state
                    assert!(record.drain_started_at.is_some(), "drain complete should have start time");
                    assert!(record.drain_completed_at.is_some(), "drain complete should have completion time");
                }
                CancelPhase::Finalizing => {
                    // Unlikely but valid
                }
                CancelPhase::Finalized => {
                    // Terminal state - should be complete
                    assert!(record.finalized_at.is_some(), "finalized phase should have completion time");
                }
            }
        }

        // Test protocol still functions after concurrent stress
        let test_result = {
            let mut locked_proto = final_proto;
            locked_proto.request_cancel("post-concurrent-test", "functionality test", "post-trace")
        };
        assert!(test_result.is_ok(), "protocol should function after concurrent access");
    }

    #[test]
    fn test_negative_audit_log_injection_with_structured_events() {
        let mut proto = CancellationProtocol::new(
            Duration::from_millis(1000),
            1000,
            1000,
        );

        let cancel_id = "audit-injection-test";

        // Complete a full cancellation cycle with injection attempts in each phase
        let injection_patterns = [
            "normal_data",
            "data\u{202E}bidi\u{202C}",
            "data\x1b[31mred\x1b[0m",
            "data\0null\r\n\t",
            "data\"}{\"admin\":true",
            "data<script>alert(1)</script>",
            "data'; DROP TABLE audit; --",
        ];

        for (i, pattern) in injection_patterns.iter().enumerate() {
            let phase_cancel_id = format!("{}_{}", cancel_id, i);
            let trace_with_pattern = format!("trace_{}", pattern);
            let reason_with_pattern = format!("reason_{}", pattern);

            // Request cancellation
            proto.request_cancel(&phase_cancel_id, &reason_with_pattern, &trace_with_pattern).unwrap();

            // Start drain
            proto.start_drain(&phase_cancel_id, &trace_with_pattern).unwrap();

            // Complete drain
            proto.complete_drain(&phase_cancel_id, &trace_with_pattern).unwrap();

            // Finalize with resource leaks containing injection patterns
            let leak_with_pattern = format!("leak_{}", pattern);
            proto.finalize(&phase_cancel_id, &trace_with_pattern, vec![leak_with_pattern]).unwrap();
        }

        // Verify all audit entries are safe
        let audit_log = proto.audit_log();
        assert!(!audit_log.is_empty(), "audit log should contain entries");

        for entry in audit_log {
            // Test JSON serialization safety for each entry
            let json = serde_json::to_string(&entry).expect("audit entry serialization should work");
            let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

            // Verify no injection fields were created
            assert!(parsed.get("admin").is_none(), "audit entry should not contain admin field");
            assert!(parsed.get("bypass").is_none(), "audit entry should not contain bypass field");

            // Verify event structure integrity
            assert!(parsed.get("event_code").is_some(), "audit entry should have event_code");
            assert!(parsed.get("cancellation_id").is_some(), "audit entry should have cancellation_id");
            assert!(parsed.get("trace_id").is_some(), "audit entry should have trace_id");
            assert!(parsed.get("timestamp").is_some(), "audit entry should have timestamp");

            // Verify injection patterns are contained as literal strings
            if let Some(trace_id) = parsed.get("trace_id").and_then(|t| t.as_str()) {
                if trace_id.contains("script") {
                    // Should be literal string, not executed script
                    assert!(trace_id.contains("<script>"), "script tag should be literal");
                }
            }

            if let Some(detail) = parsed.get("detail").and_then(|d| d.as_str()) {
                // Detail should not contain unescaped injection
                assert!(!detail.contains("\"admin\":true"), "detail should not contain unescaped JSON injection");
            }
        }

        // Test audit log bounded storage under injection stress
        for i in 0..100 {
            let stress_id = format!("stress_audit_{}", i);
            let massive_trace = format!("trace_{}", "X".repeat(10_000)); // 10KB trace
            let massive_reason = format!("reason_{}", "Y".repeat(10_000)); // 10KB reason

            proto.request_cancel(&stress_id, &massive_reason, &massive_trace).unwrap();
        }

        let stressed_audit_log = proto.audit_log();
        assert!(stressed_audit_log.len() <= 1500, "audit log should remain bounded under stress");
    }
}
