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
    DrainTimeout { workflow_id: String, elapsed_ms: u64, timeout_ms: u64 },
    /// Resources leaked during finalization.
    ResourceLeak { workflow_id: String, leaked_resources: Vec<String> },
}

impl CancelProtocolError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPhase { .. } => error_codes::ERR_CANCEL_INVALID_PHASE,
            Self::AlreadyFinal { .. } => error_codes::ERR_CANCEL_ALREADY_FINAL,
            Self::DrainTimeout { .. } => error_codes::ERR_CANCEL_DRAIN_TIMEOUT,
            Self::ResourceLeak { .. } => error_codes::ERR_CANCEL_LEAK,
        }
    }
}

impl fmt::Display for CancelProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPhase { from, to } => {
                write!(f, "{}: cannot transition from {} to {}", self.code(), from, to)
            }
            Self::AlreadyFinal { workflow_id } => {
                write!(f, "{}: workflow {} already finalized", self.code(), workflow_id)
            }
            Self::DrainTimeout { workflow_id, elapsed_ms, timeout_ms } => {
                write!(
                    f,
                    "{}: workflow {} drain timeout after {}ms (limit {}ms)",
                    self.code(), workflow_id, elapsed_ms, timeout_ms
                )
            }
            Self::ResourceLeak { workflow_id, leaked_resources } => {
                write!(
                    f,
                    "{}: workflow {} leaked resources: {}",
                    self.code(),
                    workflow_id,
                    leaked_resources.join(", ")
                )
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
    default_drain_config: DrainConfig,
}

impl CancellationProtocol {
    pub fn new(default_drain_config: DrainConfig) -> Self {
        Self {
            records: Vec::new(),
            audit_log: Vec::new(),
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
        let existing_idx = self.records.iter().position(|r| r.workflow_id == workflow_id);
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

            self.audit_log.push(CancelAuditEvent::new(
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
        let mut record = CancellationRecord::new(
            workflow_id,
            self.default_drain_config.clone(),
            trace_id,
        );
        record.current_phase = CancelPhase::CancelRequested;
        record.request_timestamp_ms = Some(timestamp_ms);
        record.in_flight_count = in_flight_count;

        self.audit_log.push(CancelAuditEvent::new(
            event_codes::CAN_001,
            workflow_id,
            CancelPhase::Idle,
            CancelPhase::CancelRequested,
            timestamp_ms,
            trace_id,
            &format!("cancel requested, {} in-flight", in_flight_count),
        ));

        self.records.push(record);
        Ok(self.records.last().unwrap())
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

        self.audit_log.push(CancelAuditEvent::new(
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
        if elapsed > timeout {
            self.records[idx].drain_timed_out = true;
            self.records[idx].drain_complete_ms = Some(timestamp_ms);

            self.audit_log.push(CancelAuditEvent::new(
                event_codes::CAN_004,
                workflow_id,
                CancelPhase::Draining,
                CancelPhase::DrainComplete,
                timestamp_ms,
                trace_id,
                &format!("drain timeout after {}ms (limit {}ms)", elapsed, timeout),
            ));

            if !force {
                return Err(CancelProtocolError::DrainTimeout {
                    workflow_id: workflow_id.to_string(),
                    elapsed_ms: elapsed,
                    timeout_ms: timeout,
                });
            }
        } else {
            self.records[idx].drain_complete_ms = Some(timestamp_ms);

            self.audit_log.push(CancelAuditEvent::new(
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

            self.audit_log.push(CancelAuditEvent::new(
                event_codes::CAN_006,
                workflow_id,
                CancelPhase::Finalizing,
                CancelPhase::Finalized,
                timestamp_ms,
                trace_id,
                &format!("resource leak detected: {}", leaks.join(", ")),
            ));

            self.records[idx].current_phase = CancelPhase::Finalized;
            self.records[idx].finalize_ms = Some(timestamp_ms);

            return Err(CancelProtocolError::ResourceLeak {
                workflow_id: workflow_id.to_string(),
                leaked_resources: leaks,
            });
        }

        self.records[idx].current_phase = CancelPhase::Finalized;
        self.records[idx].finalize_ms = Some(timestamp_ms);

        self.audit_log.push(CancelAuditEvent::new(
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
            .filter(|r| r.current_phase != CancelPhase::Finalized && r.current_phase != CancelPhase::Idle)
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
            .ok_or_else(|| CancelProtocolError::InvalidPhase {
                from: CancelPhase::Idle,
                to: CancelPhase::CancelRequested,
            })
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
    protocol.records().iter().all(|r| {
        r.current_phase != CancelPhase::Draining || !r.drain_timed_out
    })
}

/// Generate a timing report as CSV rows.
/// Returns (header, rows) suitable for writing to a CSV file.
pub fn generate_timing_report(protocol: &CancellationProtocol) -> (String, Vec<String>) {
    let header = "workflow_id,phase,request_ms,drain_start_ms,drain_complete_ms,finalize_ms,drain_duration_ms,timed_out,leaks".to_string();
    let rows: Vec<String> = protocol
        .records()
        .iter()
        .map(|r| {
            let drain_dur = r.drain_duration_ms().map(|d| d.to_string()).unwrap_or_default();
            format!(
                "{},{},{},{},{},{},{},{},{}",
                r.workflow_id,
                r.current_phase,
                r.request_timestamp_ms.map(|t| t.to_string()).unwrap_or_default(),
                r.drain_start_ms.map(|t| t.to_string()).unwrap_or_default(),
                r.drain_complete_ms.map(|t| t.to_string()).unwrap_or_default(),
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
        proto.finalize("wf-1", &ResourceTracker::empty(), 1300, "t1").unwrap();

        let err = proto.request_cancel("wf-1", 0, 1400, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_ALREADY_FINAL);
    }

    // ---- Invalid phase transitions ----

    #[test]
    fn drain_without_request_rejected() {
        let mut proto = CancellationProtocol::default();
        // No record exists for wf-1
        let err = proto.start_drain("wf-1", 1000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_INVALID_PHASE);
    }

    #[test]
    fn finalize_without_drain_rejected() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-1", 0, 1000, "t1").unwrap();
        let err = proto.finalize("wf-1", &ResourceTracker::empty(), 1100, "t1").unwrap_err();
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
        let timeout_events: Vec<_> = proto.audit_log().iter()
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
        let leak_events: Vec<_> = proto.audit_log().iter()
            .filter(|e| e.event_code == event_codes::CAN_006)
            .collect();
        assert_eq!(leak_events.len(), 1);
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
        proto.finalize("wf-1", &ResourceTracker::empty(), 1300, "t1").unwrap();

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
        let parsed: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::CAN_001);
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
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
        proto.finalize("wf-1", &ResourceTracker::empty(), 1600, "t1").unwrap();

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
        assert_eq!(proto.current_phase("wf-2"), Some(CancelPhase::CancelRequested));
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
        proto.finalize("wf-1", &ResourceTracker::empty(), 1300, "t1").unwrap();

        let err = proto.finalize("wf-1", &ResourceTracker::empty(), 1400, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_ALREADY_FINAL);
    }
}
