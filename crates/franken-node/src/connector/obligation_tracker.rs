//! bd-1n5p: Obligation-tracked two-phase channels for critical connector operations.
//!
//! Replaces ad hoc publish/revoke/quarantine/migration messaging with a
//! reserve/commit/rollback protocol that prevents obligation leaks, partial
//! commits, and orphaned state transitions.
//!
//! # Invariants
//!
//! - INV-OBL-TWO-PHASE: every side-effecting operation goes through reserve/commit/rollback
//! - INV-OBL-NO-LEAK: no obligation remains in Reserved state beyond the leak timeout
//! - INV-OBL-BUDGET-BOUND: total concurrent reservations per flow are bounded by a configurable budget
//! - INV-OBL-DROP-SAFE: dropping an uncommitted ObligationGuard triggers automatic rollback
//! - INV-OBL-ATOMIC-COMMIT: commit is all-or-nothing; partial commits are impossible
//! - INV-OBL-ROLLBACK-SAFE: rollback is idempotent and always succeeds
//! - INV-OBL-AUDIT-COMPLETE: every reserve/commit/rollback emits an auditable event
//! - INV-OBL-SCAN-PERIODIC: the leak oracle runs on a configurable interval

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Schema version for the obligation tracker.
pub const SCHEMA_VERSION: &str = "obl-v1.0";

/// Default leak timeout in seconds.
pub const DEFAULT_LEAK_TIMEOUT_SECS: u64 = 30;

/// Default per-flow budget for concurrent reservations. INV-OBL-BUDGET-BOUND
pub const DEFAULT_FLOW_BUDGET: usize = 256;

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_OBLIGATIONS};

/// Maximum scan results before oldest are evicted.
const MAX_SCAN_RESULTS: usize = 1024;

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

// ── Event codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Obligation reserved (two-phase: phase 1).
    pub const OBL_RESERVED: &str = "OBL-001";
    /// Obligation committed (two-phase: phase 2a).
    pub const OBL_COMMITTED: &str = "OBL-002";
    /// Obligation rolled back (two-phase: phase 2b).
    pub const OBL_ROLLED_BACK: &str = "OBL-003";
    /// Obligation leak detected and force-rolled-back.
    pub const OBL_LEAK_DETECTED: &str = "OBL-004";
    /// Leak scan completed.
    pub const OBL_SCAN_COMPLETED: &str = "OBL-005";
    /// Guard drop observed an already-terminal or missing obligation and skipped rollback.
    pub const OBL_DROP_SKIPPED: &str = "OBL-006";
}

// ── Error codes ──────────────────────────────────────────────────────────────

pub mod error_codes {
    pub const ERR_OBL_ALREADY_COMMITTED: &str = "ERR_OBL_ALREADY_COMMITTED";
    pub const ERR_OBL_ALREADY_ROLLED_BACK: &str = "ERR_OBL_ALREADY_ROLLED_BACK";
    pub const ERR_OBL_NOT_FOUND: &str = "ERR_OBL_NOT_FOUND";
    pub const ERR_OBL_LEAK_TIMEOUT: &str = "ERR_OBL_LEAK_TIMEOUT";
    pub const ERR_OBL_DUPLICATE_RESERVE: &str = "ERR_OBL_DUPLICATE_RESERVE";
    pub const ERR_OBL_BUDGET_EXCEEDED: &str = "ERR_OBL_BUDGET_EXCEEDED";
    pub const ERR_OBL_CAPACITY_EXCEEDED: &str = "ERR_OBL_CAPACITY_EXCEEDED";
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Unique obligation identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObligationId(pub String);

impl fmt::Display for ObligationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The tracked connector flows that require two-phase semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObligationFlow {
    /// Trust object publication.
    Publish,
    /// Trust object revocation.
    Revoke,
    /// Quarantine entry/exit.
    Quarantine,
    /// Schema or data migration step.
    Migration,
    /// Fencing token lifecycle.
    Fencing,
}

impl ObligationFlow {
    /// All tracked flows.
    pub fn all() -> &'static [ObligationFlow] {
        &[
            Self::Publish,
            Self::Revoke,
            Self::Quarantine,
            Self::Migration,
            Self::Fencing,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Revoke => "revoke",
            Self::Quarantine => "quarantine",
            Self::Migration => "migration",
            Self::Fencing => "fencing",
        }
    }
}

impl fmt::Display for ObligationFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Lifecycle state of an obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationState {
    /// Phase 1: resources tentatively held, not yet visible.
    Reserved,
    /// Phase 2a: effect is permanent and visible.
    Committed,
    /// Phase 2b: tentative resources released.
    RolledBack,
    /// Detected by leak oracle and force-rolled-back.
    Leaked,
}

impl fmt::Display for ObligationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reserved => write!(f, "Reserved"),
            Self::Committed => write!(f, "Committed"),
            Self::RolledBack => write!(f, "RolledBack"),
            Self::Leaked => write!(f, "Leaked"),
        }
    }
}

/// A single tracked obligation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    /// Unique identifier.
    pub id: ObligationId,
    /// Which flow this obligation belongs to.
    pub flow: ObligationFlow,
    /// Current lifecycle state.
    pub state: ObligationState,
    /// Operation-specific payload (opaque bytes).
    pub payload: Vec<u8>,
    /// Timestamp (epoch millis) when the obligation was reserved.
    pub reserved_at_ms: u64,
    /// Timestamp (epoch millis) when the obligation was committed or rolled back.
    pub resolved_at_ms: Option<u64>,
    /// Trace ID for distributed tracing.
    pub trace_id: String,
}

/// Audit record for obligation lifecycle events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationAuditRecord {
    /// Event code (OBL-001 through OBL-005).
    pub event_code: String,
    /// Obligation ID this event relates to (empty for scan events).
    pub obligation_id: String,
    /// Flow name.
    pub flow: String,
    /// State after this event.
    pub state: String,
    /// Distributed trace ID.
    pub trace_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Result of a leak scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakScanResult {
    /// Number of obligations scanned.
    pub scanned: usize,
    /// Number of leaked obligations detected and force-rolled-back.
    pub leaked: usize,
    /// IDs of leaked obligations.
    pub leaked_ids: Vec<String>,
    /// Timestamp of the scan (epoch millis).
    pub scan_at_ms: u64,
    /// Schema version.
    pub schema_version: String,
}

/// Per-flow obligation counts for the leak oracle report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowObligationCounts {
    /// Flow name.
    pub flow: String,
    /// Number of obligations reserved in this flow.
    pub reserved: usize,
    /// Number of obligations committed in this flow.
    pub committed: usize,
    /// Number of obligations rolled back in this flow.
    pub rolled_back: usize,
    /// Number of obligations leaked in this flow.
    pub leaked: usize,
}

/// Report aggregating leak scan results for the oracle artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakOracleReport {
    /// Bead identifier.
    pub bead_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Total scans performed.
    pub total_scans: usize,
    /// Total leaks detected across all scans.
    pub total_leaks: usize,
    /// Per-flow obligation counts.
    pub per_flow_counts: Vec<FlowObligationCounts>,
    /// Per-scan results.
    pub scans: Vec<LeakScanResult>,
    /// Overall verdict.
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrackerState {
    obligations: BTreeMap<String, Obligation>,
    audit_log: Vec<ObligationAuditRecord>,
    next_id: u64,
    leak_timeout_secs: u64,
    scan_results: Vec<LeakScanResult>,
    /// Per-flow budget for concurrent reservations. INV-OBL-BUDGET-BOUND
    flow_budget: usize,
}

fn lock_tracker_state(tracker: &Arc<Mutex<TrackerState>>) -> MutexGuard<'_, TrackerState> {
    match tracker.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl TrackerState {
    fn new() -> Self {
        Self {
            obligations: BTreeMap::new(),
            audit_log: Vec::new(),
            next_id: 1,
            leak_timeout_secs: DEFAULT_LEAK_TIMEOUT_SECS,
            scan_results: Vec::new(),
            flow_budget: DEFAULT_FLOW_BUDGET,
        }
    }

    fn push_audit(&mut self, record: ObligationAuditRecord) {
        push_bounded(&mut self.audit_log, record, MAX_AUDIT_LOG_ENTRIES);
    }

    /// Count of currently reserved obligations for a specific flow.
    fn reserved_count_for_flow(&self, flow: &ObligationFlow) -> usize {
        self.obligations
            .values()
            .filter(|o| o.state == ObligationState::Reserved && &o.flow == flow)
            .count()
    }

    fn evict_oldest_terminal_obligation(&mut self) -> bool {
        let terminal_key = self
            .obligations
            .iter()
            .filter(|(_, obligation)| {
                matches!(
                    obligation.state,
                    ObligationState::Committed
                        | ObligationState::RolledBack
                        | ObligationState::Leaked
                )
            })
            .min_by_key(|(id, obligation)| {
                (
                    obligation
                        .resolved_at_ms
                        .unwrap_or(obligation.reserved_at_ms),
                    obligation.reserved_at_ms,
                    id.as_str(),
                )
            })
            .map(|(id, _)| id.clone());

        terminal_key
            .and_then(|id| self.obligations.remove(&id))
            .is_some()
    }

    fn mark_expired_reserved_as_leaked(&mut self, now_ms: u64, trace_id: &str) -> Vec<String> {
        let timeout_ms = self.leak_timeout_secs.saturating_mul(1000);
        let leaked_ids: Vec<String> = self
            .obligations
            .iter()
            .filter(|(_, obligation)| {
                obligation.state == ObligationState::Reserved
                    && now_ms.saturating_sub(obligation.reserved_at_ms) >= timeout_ms
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in &leaked_ids {
            let flow = if let Some(obligation) = self.obligations.get_mut(id) {
                obligation.state = ObligationState::Leaked;
                obligation.resolved_at_ms = Some(now_ms);
                obligation.flow.as_str().to_string()
            } else {
                continue;
            };

            self.push_audit(ObligationAuditRecord {
                event_code: event_codes::OBL_LEAK_DETECTED.to_string(),
                obligation_id: id.clone(),
                flow,
                state: "Leaked".to_string(),
                trace_id: trace_id.to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
                detail: format!(
                    "leak detected: obligation exceeded {}s timeout",
                    self.leak_timeout_secs
                ),
            });
        }

        leaked_ids
    }

    fn ensure_capacity_for_reserve(&mut self, now_ms: u64, trace_id: &str) -> Result<(), String> {
        if self.obligations.len() < MAX_OBLIGATIONS {
            return Ok(());
        }

        if self.evict_oldest_terminal_obligation() {
            return Ok(());
        }

        if !self
            .mark_expired_reserved_as_leaked(now_ms, trace_id)
            .is_empty()
            && self.evict_oldest_terminal_obligation()
        {
            return Ok(());
        }

        Err(error_codes::ERR_OBL_CAPACITY_EXCEEDED.to_string())
    }

    /// Reserve an obligation slot (phase 1). INV-OBL-AUDIT-COMPLETE
    ///
    /// Returns the `ObligationId` for subsequent commit/rollback.
    fn reserve(
        &mut self,
        flow: ObligationFlow,
        payload: Vec<u8>,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<ObligationId, String> {
        self.ensure_capacity_for_reserve(now_ms, trace_id)?;

        if self.next_id == u64::MAX {
            return Err("ERR_OBL_ID_EXHAUSTED: obligation ID counter exhausted".to_string());
        }

        let id = ObligationId(format!("obl-{}", self.next_id));
        self.next_id = self.next_id.saturating_add(1);

        if self.obligations.contains_key(&id.0) {
            return Err(error_codes::ERR_OBL_DUPLICATE_RESERVE.to_string());
        }

        let obligation = Obligation {
            id: id.clone(),
            flow: flow.clone(),
            state: ObligationState::Reserved,
            payload,
            reserved_at_ms: now_ms,
            resolved_at_ms: None,
            trace_id: trace_id.to_string(),
        };
        self.obligations.insert(id.0.clone(), obligation);

        self.push_audit(ObligationAuditRecord {
            event_code: event_codes::OBL_RESERVED.to_string(),
            obligation_id: id.0.clone(),
            flow: flow.as_str().to_string(),
            state: "Reserved".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: "obligation reserved".to_string(),
        });

        Ok(id)
    }

    /// Reserve with budget enforcement. INV-OBL-BUDGET-BOUND
    ///
    /// Like `reserve()`, but returns an error if the per-flow budget is exceeded.
    fn try_reserve(
        &mut self,
        flow: ObligationFlow,
        payload: Vec<u8>,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<ObligationId, String> {
        if self.reserved_count_for_flow(&flow) >= self.flow_budget {
            return Err(error_codes::ERR_OBL_BUDGET_EXCEEDED.to_string());
        }
        self.reserve(flow, payload, now_ms, trace_id)
    }

    /// Commit an obligation (phase 2a). INV-OBL-ATOMIC-COMMIT
    ///
    /// # Errors
    /// - `ERR_OBL_NOT_FOUND` if the obligation ID is unknown
    /// - `ERR_OBL_ALREADY_COMMITTED` if already committed
    /// - `ERR_OBL_ALREADY_ROLLED_BACK` if already rolled back
    fn commit(&mut self, id: &ObligationId, now_ms: u64, trace_id: &str) -> Result<(), String> {
        let obligation = self
            .obligations
            .get_mut(&id.0)
            .ok_or_else(|| error_codes::ERR_OBL_NOT_FOUND.to_string())?;

        match obligation.state {
            ObligationState::Reserved => {}
            ObligationState::Committed => {
                return Err(error_codes::ERR_OBL_ALREADY_COMMITTED.to_string());
            }
            ObligationState::RolledBack | ObligationState::Leaked => {
                return Err(error_codes::ERR_OBL_ALREADY_ROLLED_BACK.to_string());
            }
        }

        obligation.state = ObligationState::Committed;
        obligation.resolved_at_ms = Some(now_ms);

        let flow_str = obligation.flow.as_str().to_string();

        self.push_audit(ObligationAuditRecord {
            event_code: event_codes::OBL_COMMITTED.to_string(),
            obligation_id: id.0.clone(),
            flow: flow_str,
            state: "Committed".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: "obligation committed".to_string(),
        });

        Ok(())
    }

    /// Rollback an obligation (phase 2b). INV-OBL-ROLLBACK-SAFE
    ///
    /// Idempotent: rolling back an already-rolled-back obligation is a no-op.
    ///
    /// # Errors
    /// - `ERR_OBL_NOT_FOUND` if the obligation ID is unknown
    /// - `ERR_OBL_ALREADY_COMMITTED` if already committed
    fn rollback(&mut self, id: &ObligationId, now_ms: u64, trace_id: &str) -> Result<(), String> {
        self.rollback_with_detail(id, now_ms, trace_id, "obligation rolled back")
    }

    fn rollback_with_detail(
        &mut self,
        id: &ObligationId,
        now_ms: u64,
        trace_id: &str,
        detail: &str,
    ) -> Result<(), String> {
        let obligation = self
            .obligations
            .get_mut(&id.0)
            .ok_or_else(|| error_codes::ERR_OBL_NOT_FOUND.to_string())?;

        match obligation.state {
            ObligationState::Reserved => {}
            ObligationState::RolledBack | ObligationState::Leaked => {
                // Idempotent: already rolled back
                return Ok(());
            }
            ObligationState::Committed => {
                return Err(error_codes::ERR_OBL_ALREADY_COMMITTED.to_string());
            }
        }

        obligation.state = ObligationState::RolledBack;
        obligation.resolved_at_ms = Some(now_ms);

        let flow_str = obligation.flow.as_str().to_string();

        self.push_audit(ObligationAuditRecord {
            event_code: event_codes::OBL_ROLLED_BACK.to_string(),
            obligation_id: id.0.clone(),
            flow: flow_str,
            state: "RolledBack".to_string(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: detail.to_string(),
        });

        Ok(())
    }

    /// Run the leak oracle scan. INV-OBL-NO-LEAK, INV-OBL-SCAN-PERIODIC
    ///
    /// Detects obligations that have remained in `Reserved` state longer than
    /// `leak_timeout_secs` and force-rolls them back.
    fn run_leak_scan(&mut self, now_ms: u64, trace_id: &str) -> LeakScanResult {
        let leaked_ids = self.mark_expired_reserved_as_leaked(now_ms, trace_id);

        let scanned = self.obligations.len();
        let leaked = leaked_ids.len();

        self.push_audit(ObligationAuditRecord {
            event_code: event_codes::OBL_SCAN_COMPLETED.to_string(),
            obligation_id: String::new(),
            flow: String::new(),
            state: String::new(),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            detail: format!("scan complete: scanned={} leaked={}", scanned, leaked),
        });

        let result = LeakScanResult {
            scanned,
            leaked,
            leaked_ids,
            scan_at_ms: now_ms,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        push_bounded(&mut self.scan_results, result.clone(), MAX_SCAN_RESULTS);
        result
    }

    /// Get an obligation by ID.
    fn get_obligation(&self, id: &ObligationId) -> Option<Obligation> {
        self.obligations.get(&id.0).cloned()
    }

    /// Count obligations in a given state.
    fn count_in_state(&self, state: ObligationState) -> usize {
        self.obligations
            .values()
            .filter(|o| o.state == state)
            .count()
    }

    /// Total number of tracked obligations.
    fn total_obligations(&self) -> usize {
        self.obligations.len()
    }

    /// Export audit log as JSONL.
    fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Compute per-flow obligation counts for the oracle report.
    fn per_flow_counts(&self) -> Vec<FlowObligationCounts> {
        ObligationFlow::all()
            .iter()
            .map(|flow| {
                let obligations_for_flow: Vec<&Obligation> = self
                    .obligations
                    .values()
                    .filter(|o| &o.flow == flow)
                    .collect();

                FlowObligationCounts {
                    flow: flow.as_str().to_string(),
                    reserved: obligations_for_flow
                        .iter()
                        .filter(|o| o.state == ObligationState::Reserved)
                        .count(),
                    committed: obligations_for_flow
                        .iter()
                        .filter(|o| o.state == ObligationState::Committed)
                        .count(),
                    rolled_back: obligations_for_flow
                        .iter()
                        .filter(|o| o.state == ObligationState::RolledBack)
                        .count(),
                    leaked: obligations_for_flow
                        .iter()
                        .filter(|o| o.state == ObligationState::Leaked)
                        .count(),
                }
            })
            .collect()
    }

    /// Generate the leak oracle report artifact.
    fn generate_leak_oracle_report(&self) -> LeakOracleReport {
        let total_leaks: usize = self
            .scan_results
            .iter()
            .fold(0usize, |acc, s| acc.saturating_add(s.leaked));
        let verdict = if total_leaks == 0 { "PASS" } else { "FAIL" }.to_string();

        LeakOracleReport {
            bead_id: "bd-1n5p".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            total_scans: self.scan_results.len(),
            total_leaks,
            per_flow_counts: self.per_flow_counts(),
            scans: self.scan_results.clone(),
            verdict,
        }
    }

    /// Export the leak oracle report as JSON.
    fn export_leak_oracle_report_json(&self) -> String {
        let report = self.generate_leak_oracle_report();
        serde_json::to_string_pretty(&report).unwrap_or_default()
    }

    /// Get the configured leak timeout in seconds.
    fn leak_timeout_secs(&self) -> u64 {
        self.leak_timeout_secs
    }

    /// Get the configured per-flow budget.
    fn flow_budget(&self) -> usize {
        self.flow_budget
    }

    /// Count of audit log entries.
    fn audit_log_count(&self) -> usize {
        self.audit_log.len()
    }
}

/// The obligation tracker managing two-phase channels. INV-OBL-TWO-PHASE
#[derive(Debug, Clone)]
pub struct ObligationTracker {
    inner: Arc<Mutex<TrackerState>>,
}

impl Serialize for ObligationTracker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&*self.lock_state(), serializer)
    }
}

impl<'de> Deserialize<'de> for ObligationTracker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let state = TrackerState::deserialize(deserializer)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(state)),
        })
    }
}

impl ObligationTracker {
    /// Create a new tracker with the default leak timeout.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrackerState::new())),
        }
    }

    /// Create a tracker with a custom leak timeout.
    pub fn with_leak_timeout(leak_timeout_secs: u64) -> Self {
        let tracker = Self::new();
        tracker.with_inner_mut(|state| {
            state.leak_timeout_secs = leak_timeout_secs;
        });
        tracker
    }

    /// Create a tracker with a custom per-flow budget. INV-OBL-BUDGET-BOUND
    pub fn with_flow_budget(flow_budget: usize) -> Self {
        let tracker = Self::new();
        tracker.with_inner_mut(|state| {
            state.flow_budget = flow_budget;
        });
        tracker
    }

    fn lock_state(&self) -> MutexGuard<'_, TrackerState> {
        lock_tracker_state(&self.inner)
    }

    fn with_inner<R>(&self, f: impl FnOnce(&TrackerState) -> R) -> R {
        let state = self.lock_state();
        f(&state)
    }

    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut TrackerState) -> R) -> R {
        let mut state = self.lock_state();
        f(&mut state)
    }

    /// Reserve an obligation slot (phase 1). INV-OBL-AUDIT-COMPLETE
    pub fn reserve(
        &mut self,
        flow: ObligationFlow,
        payload: Vec<u8>,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<ObligationId, String> {
        self.with_inner_mut(|state| state.reserve(flow, payload, now_ms, trace_id))
    }

    /// Reserve an obligation and bind its lifecycle to an RAII guard.
    pub fn reserve_guard(
        &mut self,
        flow: ObligationFlow,
        payload: Vec<u8>,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<ObligationGuard, String> {
        let obligation_id = self.reserve(flow, payload, now_ms, trace_id)?;
        Ok(ObligationGuard::new(self, obligation_id, trace_id))
    }

    /// Reserve with budget enforcement. INV-OBL-BUDGET-BOUND
    pub fn try_reserve(
        &mut self,
        flow: ObligationFlow,
        payload: Vec<u8>,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<ObligationId, String> {
        self.with_inner_mut(|state| state.try_reserve(flow, payload, now_ms, trace_id))
    }

    /// Reserve with budget enforcement and bind the lifecycle to an RAII guard.
    pub fn try_reserve_guard(
        &mut self,
        flow: ObligationFlow,
        payload: Vec<u8>,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<ObligationGuard, String> {
        let obligation_id = self.try_reserve(flow, payload, now_ms, trace_id)?;
        Ok(ObligationGuard::new(self, obligation_id, trace_id))
    }

    /// Commit an obligation (phase 2a). INV-OBL-ATOMIC-COMMIT
    pub fn commit(&mut self, id: &ObligationId, now_ms: u64, trace_id: &str) -> Result<(), String> {
        self.with_inner_mut(|state| state.commit(id, now_ms, trace_id))
    }

    /// Roll back an obligation (phase 2b). INV-OBL-ROLLBACK-SAFE
    pub fn rollback(
        &mut self,
        id: &ObligationId,
        now_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        self.with_inner_mut(|state| state.rollback(id, now_ms, trace_id))
    }

    /// Run the leak oracle scan. INV-OBL-NO-LEAK, INV-OBL-SCAN-PERIODIC
    pub fn run_leak_scan(&mut self, now_ms: u64, trace_id: &str) -> LeakScanResult {
        self.with_inner_mut(|state| state.run_leak_scan(now_ms, trace_id))
    }

    /// Get an obligation by ID.
    pub fn get_obligation(&self, id: &ObligationId) -> Option<Obligation> {
        self.with_inner(|state| state.get_obligation(id))
    }

    /// Count obligations in a given state.
    pub fn count_in_state(&self, state: ObligationState) -> usize {
        self.with_inner(|inner| inner.count_in_state(state))
    }

    /// Total number of tracked obligations.
    pub fn total_obligations(&self) -> usize {
        self.with_inner(TrackerState::total_obligations)
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.with_inner(TrackerState::export_audit_log_jsonl)
    }

    /// Compute per-flow obligation counts for the oracle report.
    pub fn per_flow_counts(&self) -> Vec<FlowObligationCounts> {
        self.with_inner(TrackerState::per_flow_counts)
    }

    /// Generate the leak oracle report artifact.
    pub fn generate_leak_oracle_report(&self) -> LeakOracleReport {
        self.with_inner(TrackerState::generate_leak_oracle_report)
    }

    /// Export the leak oracle report as JSON.
    pub fn export_leak_oracle_report_json(&self) -> String {
        self.with_inner(TrackerState::export_leak_oracle_report_json)
    }

    /// Get the configured leak timeout in seconds.
    pub fn leak_timeout_secs(&self) -> u64 {
        self.with_inner(TrackerState::leak_timeout_secs)
    }

    /// Get the configured per-flow budget.
    pub fn flow_budget(&self) -> usize {
        self.with_inner(TrackerState::flow_budget)
    }

    /// Count of audit log entries.
    pub fn audit_log_count(&self) -> usize {
        self.with_inner(TrackerState::audit_log_count)
    }
}

impl Default for ObligationTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── ObligationGuard ──────────────────────────────────────────────────────────

/// RAII guard for a reserved obligation. INV-OBL-DROP-SAFE
///
/// If the guard is dropped without an explicit `commit()` or `rollback()`,
/// it resolves the reservation through the shared tracker state immediately.
/// The preferred constructor is `ObligationTracker::reserve_guard()`.
#[derive(Debug)]
pub struct ObligationGuard {
    tracker: Arc<Mutex<TrackerState>>,
    /// The obligation ID this guard protects.
    pub obligation_id: ObligationId,
    /// Whether the guard has been explicitly resolved (committed or rolled back).
    resolved: bool,
    /// Trace ID for the automatic rollback on drop.
    trace_id: String,
}

impl ObligationGuard {
    /// Create a new guard for a reserved obligation.
    pub fn new(tracker: &ObligationTracker, obligation_id: ObligationId, trace_id: &str) -> Self {
        Self {
            tracker: Arc::clone(&tracker.inner),
            obligation_id,
            resolved: false,
            trace_id: trace_id.to_string(),
        }
    }

    /// Commit the guarded reservation and disarm the drop rollback path.
    pub fn commit(mut self, now_ms: u64) -> Result<(), String> {
        let result = {
            let mut state = lock_tracker_state(&self.tracker);
            state.commit(&self.obligation_id, now_ms, &self.trace_id)
        };
        if result.is_ok() {
            self.resolved = true;
        }
        result
    }

    /// Roll back the guarded reservation and disarm the drop rollback path.
    pub fn rollback(mut self, now_ms: u64) -> Result<(), String> {
        let result = {
            let mut state = lock_tracker_state(&self.tracker);
            state.rollback(&self.obligation_id, now_ms, &self.trace_id)
        };
        if result.is_ok() {
            self.resolved = true;
        }
        result
    }

    /// Check whether the guard has been resolved.
    pub fn is_resolved(&self) -> bool {
        self.resolved
    }

    /// Consume the guard, returning the obligation ID without triggering drop rollback.
    pub fn into_id(mut self) -> ObligationId {
        self.resolved = true;
        self.obligation_id.clone()
    }
}

impl Drop for ObligationGuard {
    fn drop(&mut self) {
        if !self.resolved {
            let now_ms = now_unix_ms();
            let mut state = lock_tracker_state(&self.tracker);
            let current = state
                .obligations
                .get(&self.obligation_id.0)
                .map(|obligation| (obligation.state, obligation.flow.as_str().to_string()));

            match current {
                Some((ObligationState::Reserved, _)) => {
                    let _ = state.rollback_with_detail(
                        &self.obligation_id,
                        now_ms,
                        &self.trace_id,
                        "obligation rolled back by guard drop",
                    );
                }
                Some((state_name, flow)) => {
                    state.push_audit(ObligationAuditRecord {
                        event_code: event_codes::OBL_DROP_SKIPPED.to_string(),
                        obligation_id: self.obligation_id.0.clone(),
                        flow,
                        state: state_name.to_string(),
                        trace_id: self.trace_id.clone(),
                        schema_version: SCHEMA_VERSION.to_string(),
                        detail: format!(
                            "guard drop observed terminal state {state_name}; rollback skipped"
                        ),
                    });
                }
                None => {
                    state.push_audit(ObligationAuditRecord {
                        event_code: event_codes::OBL_DROP_SKIPPED.to_string(),
                        obligation_id: self.obligation_id.0.clone(),
                        flow: String::new(),
                        state: String::new(),
                        trace_id: self.trace_id.clone(),
                        schema_version: SCHEMA_VERSION.to_string(),
                        detail: "guard drop found no tracked obligation; rollback skipped"
                            .to_string(),
                    });
                }
            }

            self.resolved = true;
        }
    }
}

/// Push an item to a bounded Vec, evicting oldest entries if at capacity.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max: usize) {
    vec.push(item);
    if vec.len() > max {
        let overflow = vec.len() - max;
        vec.drain(0..overflow);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker() -> ObligationTracker {
        ObligationTracker::with_leak_timeout(5)
    }

    fn reserve_ok(
        tracker: &mut ObligationTracker,
        flow: ObligationFlow,
        payload: Vec<u8>,
        now_ms: u64,
        trace_id: &str,
    ) -> ObligationId {
        tracker
            .reserve(flow, payload, now_ms, trace_id)
            .expect("reserve should succeed")
    }

    // 1. default creates empty tracker
    #[test]
    fn test_default_creates_empty() {
        let t = ObligationTracker::default();
        assert_eq!(t.total_obligations(), 0);
        assert_eq!(t.leak_timeout_secs(), DEFAULT_LEAK_TIMEOUT_SECS);
        assert_eq!(t.flow_budget(), DEFAULT_FLOW_BUDGET);
    }

    // 2. reserve returns unique ID
    #[test]
    fn test_reserve_returns_unique_id() {
        let mut t = make_tracker();
        let id1 = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        let id2 = reserve_ok(&mut t, ObligationFlow::Revoke, vec![], 1001, "t2");
        assert_ne!(id1, id2);
        assert_eq!(t.total_obligations(), 2);
    }

    // 3. reserve sets state to Reserved
    #[test]
    fn test_reserve_state() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Publish, vec![1, 2, 3], 1000, "t1");
        let o = t.get_obligation(&id).unwrap();
        assert_eq!(o.state, ObligationState::Reserved);
        assert_eq!(o.payload, vec![1, 2, 3]);
        assert_eq!(o.reserved_at_ms, 1000);
        assert!(o.resolved_at_ms.is_none());
    }

    // 4. commit transitions to Committed
    #[test]
    fn test_commit_transitions() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        t.commit(&id, 1050, "t2").unwrap();
        let o = t.get_obligation(&id).unwrap();
        assert_eq!(o.state, ObligationState::Committed);
        assert_eq!(o.resolved_at_ms, Some(1050));
    }

    // 5. rollback transitions to RolledBack
    #[test]
    fn test_rollback_transitions() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Revoke, vec![], 1000, "t1");
        t.rollback(&id, 1050, "t2").unwrap();
        let o = t.get_obligation(&id).unwrap();
        assert_eq!(o.state, ObligationState::RolledBack);
        assert_eq!(o.resolved_at_ms, Some(1050));
    }

    // 6. commit on already-committed errors
    #[test]
    fn test_commit_already_committed() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        t.commit(&id, 1050, "t2").unwrap();
        let err = t.commit(&id, 1100, "t3").unwrap_err();
        assert_eq!(err, error_codes::ERR_OBL_ALREADY_COMMITTED);
    }

    // 7. rollback on already-committed errors
    #[test]
    fn test_rollback_already_committed() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        t.commit(&id, 1050, "t2").unwrap();
        let err = t.rollback(&id, 1100, "t3").unwrap_err();
        assert_eq!(err, error_codes::ERR_OBL_ALREADY_COMMITTED);
    }

    // 8. commit on already-rolled-back errors
    #[test]
    fn test_commit_already_rolled_back() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Migration, vec![], 1000, "t1");
        t.rollback(&id, 1050, "t2").unwrap();
        let err = t.commit(&id, 1100, "t3").unwrap_err();
        assert_eq!(err, error_codes::ERR_OBL_ALREADY_ROLLED_BACK);
    }

    // 9. rollback is idempotent (INV-OBL-ROLLBACK-SAFE)
    #[test]
    fn test_rollback_idempotent() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Quarantine, vec![], 1000, "t1");
        t.rollback(&id, 1050, "t2").unwrap();
        // Second rollback is a no-op
        t.rollback(&id, 1100, "t3").unwrap();
        let o = t.get_obligation(&id).unwrap();
        assert_eq!(o.state, ObligationState::RolledBack);
    }

    // 10. not found errors
    #[test]
    fn test_not_found_errors() {
        let mut t = make_tracker();
        let fake = ObligationId("obl-999".to_string());
        assert_eq!(
            t.commit(&fake, 1000, "t1").unwrap_err(),
            error_codes::ERR_OBL_NOT_FOUND
        );
        assert_eq!(
            t.rollback(&fake, 1000, "t1").unwrap_err(),
            error_codes::ERR_OBL_NOT_FOUND
        );
    }

    // 11. leak scan detects stale reservations (INV-OBL-NO-LEAK)
    #[test]
    fn test_leak_scan_detects_stale() {
        let mut t = ObligationTracker::with_leak_timeout(2); // 2 second timeout
        let id = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        // Advance time past timeout (2s = 2000ms)
        let result = t.run_leak_scan(4000, "scan1");
        assert_eq!(result.leaked, 1);
        assert!(result.leaked_ids.contains(&id.0));
        // Obligation should be marked as Leaked
        let o = t.get_obligation(&id).unwrap();
        assert_eq!(o.state, ObligationState::Leaked);
    }

    // 12. leak scan does not touch committed/rolledback
    #[test]
    fn test_leak_scan_ignores_resolved() {
        let mut t = ObligationTracker::with_leak_timeout(1);
        let id1 = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        let id2 = reserve_ok(&mut t, ObligationFlow::Revoke, vec![], 1000, "t2");
        t.commit(&id1, 1050, "t3").unwrap();
        t.rollback(&id2, 1050, "t4").unwrap();
        // Scan well past timeout -- nothing should be detected
        let result = t.run_leak_scan(100000, "scan1");
        assert_eq!(result.leaked, 0);
    }

    // 13. count_in_state works correctly
    #[test]
    fn test_count_in_state() {
        let mut t = make_tracker();
        let id1 = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        let id2 = reserve_ok(&mut t, ObligationFlow::Revoke, vec![], 1001, "t2");
        let _id3 = reserve_ok(&mut t, ObligationFlow::Quarantine, vec![], 1002, "t3");

        t.commit(&id1, 1050, "t4").unwrap();
        t.rollback(&id2, 1050, "t5").unwrap();

        assert_eq!(t.count_in_state(ObligationState::Reserved), 1);
        assert_eq!(t.count_in_state(ObligationState::Committed), 1);
        assert_eq!(t.count_in_state(ObligationState::RolledBack), 1);
    }

    // 14. all flows are representable
    #[test]
    fn test_all_flows() {
        assert_eq!(ObligationFlow::all().len(), 5);
        let names: Vec<&str> = ObligationFlow::all().iter().map(|f| f.as_str()).collect();
        assert!(names.contains(&"publish"));
        assert!(names.contains(&"revoke"));
        assert!(names.contains(&"quarantine"));
        assert!(names.contains(&"migration"));
        assert!(names.contains(&"fencing"));
    }

    // 15. obligation flow display
    #[test]
    fn test_flow_display() {
        assert_eq!(ObligationFlow::Publish.to_string(), "publish");
        assert_eq!(ObligationFlow::Revoke.to_string(), "revoke");
        assert_eq!(ObligationFlow::Quarantine.to_string(), "quarantine");
        assert_eq!(ObligationFlow::Migration.to_string(), "migration");
        assert_eq!(ObligationFlow::Fencing.to_string(), "fencing");
    }

    // 16. obligation state display (including Leaked)
    #[test]
    fn test_state_display() {
        assert_eq!(ObligationState::Reserved.to_string(), "Reserved");
        assert_eq!(ObligationState::Committed.to_string(), "Committed");
        assert_eq!(ObligationState::RolledBack.to_string(), "RolledBack");
        assert_eq!(ObligationState::Leaked.to_string(), "Leaked");
    }

    // 17. audit log captures reserve events
    #[test]
    fn test_audit_log_reserve() {
        let mut t = make_tracker();
        reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        assert_eq!(t.audit_log_count(), 1);
        let jsonl = t.export_audit_log_jsonl();
        assert!(jsonl.contains(event_codes::OBL_RESERVED));
    }

    // 18. audit log captures commit events
    #[test]
    fn test_audit_log_commit() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Revoke, vec![], 1000, "t1");
        t.commit(&id, 1050, "t2").unwrap();
        assert_eq!(t.audit_log_count(), 2);
        let jsonl = t.export_audit_log_jsonl();
        assert!(jsonl.contains(event_codes::OBL_COMMITTED));
    }

    // 19. audit log captures rollback events
    #[test]
    fn test_audit_log_rollback() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Fencing, vec![], 1000, "t1");
        t.rollback(&id, 1050, "t2").unwrap();
        let jsonl = t.export_audit_log_jsonl();
        assert!(jsonl.contains(event_codes::OBL_ROLLED_BACK));
    }

    // 20. audit log captures leak events
    #[test]
    fn test_audit_log_leak() {
        let mut t = ObligationTracker::with_leak_timeout(1);
        reserve_ok(&mut t, ObligationFlow::Migration, vec![], 1000, "t1");
        t.run_leak_scan(5000, "scan1");
        let jsonl = t.export_audit_log_jsonl();
        assert!(jsonl.contains(event_codes::OBL_LEAK_DETECTED));
        assert!(jsonl.contains(event_codes::OBL_SCAN_COMPLETED));
    }

    // 21. leak oracle report generation
    #[test]
    fn test_leak_oracle_report() {
        let mut t = make_tracker();
        let _id = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        t.run_leak_scan(2000, "scan1"); // Not yet leaked (5s timeout)
        let report = t.generate_leak_oracle_report();
        assert_eq!(report.bead_id, "bd-1n5p");
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.total_scans, 1);
        assert_eq!(report.total_leaks, 0);
        assert_eq!(report.verdict, "PASS");
    }

    // 22. leak oracle report with leaks
    #[test]
    fn test_leak_oracle_report_with_leaks() {
        let mut t = ObligationTracker::with_leak_timeout(1);
        reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        t.run_leak_scan(5000, "scan1");
        let report = t.generate_leak_oracle_report();
        assert_eq!(report.total_leaks, 1);
        assert_eq!(report.verdict, "FAIL");
    }

    // 23. export leak oracle report JSON
    #[test]
    fn test_export_leak_oracle_json() {
        let mut t = make_tracker();
        t.run_leak_scan(1000, "scan1");
        let json = t.export_leak_oracle_report_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["bead_id"], "bd-1n5p");
        assert_eq!(parsed["verdict"], "PASS");
    }

    // 24. schema version correct
    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "obl-v1.0");
    }

    // 25. multiple flows in one tracker
    #[test]
    fn test_multiple_flows() {
        let mut t = make_tracker();
        for flow in ObligationFlow::all() {
            let id = reserve_ok(&mut t, flow.clone(), vec![], 1000, "t1");
            t.commit(&id, 1050, "t2").unwrap();
        }
        assert_eq!(t.total_obligations(), 5);
        assert_eq!(t.count_in_state(ObligationState::Committed), 5);
    }

    // 26. obligation ID display
    #[test]
    fn test_obligation_id_display() {
        let id = ObligationId("obl-42".to_string());
        assert_eq!(format!("{}", id), "obl-42");
    }

    // 27. invariant names present in module
    #[test]
    fn test_invariant_names_present() {
        let src = include_str!("obligation_tracker.rs");
        assert!(src.contains("INV-OBL-TWO-PHASE"));
        assert!(src.contains("INV-OBL-NO-LEAK"));
        assert!(src.contains("INV-OBL-BUDGET-BOUND"));
        assert!(src.contains("INV-OBL-DROP-SAFE"));
        assert!(src.contains("INV-OBL-ATOMIC-COMMIT"));
        assert!(src.contains("INV-OBL-ROLLBACK-SAFE"));
        assert!(src.contains("INV-OBL-AUDIT-COMPLETE"));
        assert!(src.contains("INV-OBL-SCAN-PERIODIC"));
    }

    // 28. event codes are defined and non-empty
    #[test]
    fn test_event_codes_defined() {
        assert!(!event_codes::OBL_RESERVED.is_empty());
        assert!(!event_codes::OBL_COMMITTED.is_empty());
        assert!(!event_codes::OBL_ROLLED_BACK.is_empty());
        assert!(!event_codes::OBL_LEAK_DETECTED.is_empty());
        assert!(!event_codes::OBL_SCAN_COMPLETED.is_empty());
        assert!(!event_codes::OBL_DROP_SKIPPED.is_empty());
    }

    // 29. error codes are defined and non-empty
    #[test]
    fn test_error_codes_defined() {
        assert!(!error_codes::ERR_OBL_ALREADY_COMMITTED.is_empty());
        assert!(!error_codes::ERR_OBL_ALREADY_ROLLED_BACK.is_empty());
        assert!(!error_codes::ERR_OBL_NOT_FOUND.is_empty());
        assert!(!error_codes::ERR_OBL_LEAK_TIMEOUT.is_empty());
        assert!(!error_codes::ERR_OBL_DUPLICATE_RESERVE.is_empty());
        assert!(!error_codes::ERR_OBL_CAPACITY_EXCEEDED.is_empty());
    }

    // 30. full two-phase lifecycle: reserve -> commit
    #[test]
    fn test_full_lifecycle_commit() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Publish, vec![42], 1000, "trace-1");
        assert_eq!(t.count_in_state(ObligationState::Reserved), 1);

        t.commit(&id, 1050, "trace-1").unwrap();
        assert_eq!(t.count_in_state(ObligationState::Reserved), 0);
        assert_eq!(t.count_in_state(ObligationState::Committed), 1);

        // Verify audit trail is complete
        assert_eq!(t.audit_log_count(), 2);
    }

    // 31. full two-phase lifecycle: reserve -> rollback
    #[test]
    fn test_full_lifecycle_rollback() {
        let mut t = make_tracker();
        let id = reserve_ok(&mut t, ObligationFlow::Quarantine, vec![], 1000, "trace-2");
        assert_eq!(t.count_in_state(ObligationState::Reserved), 1);

        t.rollback(&id, 1050, "trace-2").unwrap();
        assert_eq!(t.count_in_state(ObligationState::Reserved), 0);
        assert_eq!(t.count_in_state(ObligationState::RolledBack), 1);
    }

    // 32. leak scan with mixed states
    #[test]
    fn test_leak_scan_mixed() {
        let mut t = ObligationTracker::with_leak_timeout(2);

        // Create obligations at different times
        let id1 = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        let id2 = reserve_ok(&mut t, ObligationFlow::Revoke, vec![], 2000, "t2");
        let id3 = reserve_ok(&mut t, ObligationFlow::Quarantine, vec![], 3000, "t3");

        // Commit id2 so it's no longer reserved
        t.commit(&id2, 2050, "t4").unwrap();

        // Scan at 5000ms: id1 reserved at 1000 -> 4s elapsed >= 2s timeout -> leaked
        //                  id3 reserved at 3000 -> 2s elapsed >= 2s timeout -> leaked (fail-closed at boundary)
        let result = t.run_leak_scan(5000, "scan1");
        assert_eq!(result.leaked, 2);
        assert!(result.leaked_ids.contains(&id1.0));
        assert!(result.leaked_ids.contains(&id3.0));
    }

    // 33. ObligationGuard commit updates shared tracker state
    #[test]
    fn test_guard_commit_updates_tracker_state() {
        let mut t = make_tracker();
        let guard = t
            .reserve_guard(ObligationFlow::Publish, vec![1], 1000, "trace-1")
            .unwrap();
        let id = guard.obligation_id.clone();
        assert!(!guard.is_resolved());
        guard.commit(1050).unwrap();
        let obligation = t.get_obligation(&id).unwrap();
        assert_eq!(obligation.state, ObligationState::Committed);
    }

    // 34. ObligationGuard rollback updates shared tracker state
    #[test]
    fn test_guard_rollback_updates_tracker_state() {
        let mut t = make_tracker();
        let guard = t
            .reserve_guard(ObligationFlow::Revoke, vec![], 1000, "trace-1")
            .unwrap();
        let id = guard.obligation_id.clone();
        guard.rollback(1050).unwrap();
        let obligation = t.get_obligation(&id).unwrap();
        assert_eq!(obligation.state, ObligationState::RolledBack);
    }

    // 35. ObligationGuard drop triggers rollback when still reserved
    #[test]
    fn test_guard_drop_rolls_back_reserved_obligation() {
        let mut t = make_tracker();
        let id = {
            let guard = t
                .reserve_guard(ObligationFlow::Migration, vec![], 1000, "trace-1")
                .unwrap();
            guard.obligation_id.clone()
        };

        let obligation = t.get_obligation(&id).unwrap();
        assert_eq!(obligation.state, ObligationState::RolledBack);
        assert!(
            t.export_audit_log_jsonl()
                .contains("obligation rolled back by guard drop")
        );
    }

    // 36. ObligationGuard into_id consumes without drop rollback
    #[test]
    fn test_guard_into_id() {
        let mut t = make_tracker();
        let guard = t
            .reserve_guard(ObligationFlow::Fencing, vec![], 1000, "trace-1")
            .unwrap();
        let id = guard.obligation_id.clone();
        let extracted = guard.into_id();
        assert_eq!(extracted, id);
        assert_eq!(
            t.get_obligation(&id).unwrap().state,
            ObligationState::Reserved
        );
    }

    // 37. ObligationGuard drop path records diagnostics for terminal external state
    #[test]
    fn test_guard_drop_skips_when_obligation_already_committed() {
        let mut t = make_tracker();
        let id = t
            .reserve(ObligationFlow::Publish, vec![], 1000, "trace-1")
            .unwrap();
        let guard = ObligationGuard::new(&t, id.clone(), "trace-1");
        t.commit(&id, 1050, "trace-1").unwrap();
        drop(guard);

        assert_eq!(
            t.get_obligation(&id).unwrap().state,
            ObligationState::Committed
        );
        assert!(t.export_audit_log_jsonl().contains("rollback skipped"));
    }

    // 38. ObligationGuard has Drop implementation (INV-OBL-DROP-SAFE)
    #[test]
    fn test_guard_drop_impl_exists() {
        let src = include_str!("obligation_tracker.rs");
        assert!(src.contains("impl Drop for ObligationGuard"));
        assert!(src.contains("INV-OBL-DROP-SAFE"));
    }

    // 39. per_flow_counts returns counts for all flows
    #[test]
    fn test_per_flow_counts() {
        let mut t = make_tracker();
        let id1 = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        let _id2 = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1001, "t2");
        let id3 = reserve_ok(&mut t, ObligationFlow::Revoke, vec![], 1002, "t3");
        t.commit(&id1, 1050, "t4").unwrap();
        t.rollback(&id3, 1050, "t5").unwrap();

        let counts = t.per_flow_counts();
        assert_eq!(counts.len(), 5); // one per flow

        let publish = counts.iter().find(|c| c.flow == "publish").unwrap();
        assert_eq!(publish.committed, 1);
        assert_eq!(publish.reserved, 1);

        let revoke = counts.iter().find(|c| c.flow == "revoke").unwrap();
        assert_eq!(revoke.rolled_back, 1);
    }

    // 40. Leaked state in counts
    #[test]
    fn test_leaked_state_count() {
        let mut t = ObligationTracker::with_leak_timeout(1);
        reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        t.run_leak_scan(5000, "scan1");
        assert_eq!(t.count_in_state(ObligationState::Leaked), 1);

        let counts = t.per_flow_counts();
        let publish = counts.iter().find(|c| c.flow == "publish").unwrap();
        assert_eq!(publish.leaked, 1);
    }

    // 41. budget enforcement via try_reserve (INV-OBL-BUDGET-BOUND)
    #[test]
    fn test_try_reserve_budget_enforcement() {
        let mut t = ObligationTracker::with_flow_budget(2);
        t.try_reserve(ObligationFlow::Publish, vec![], 1000, "t1")
            .unwrap();
        t.try_reserve(ObligationFlow::Publish, vec![], 1001, "t2")
            .unwrap();
        // Third reservation should fail
        let err = t
            .try_reserve(ObligationFlow::Publish, vec![], 1002, "t3")
            .unwrap_err();
        assert_eq!(err, error_codes::ERR_OBL_BUDGET_EXCEEDED);
        // Different flow should still work
        t.try_reserve(ObligationFlow::Revoke, vec![], 1003, "t4")
            .unwrap();
    }

    // 42. budget is per-flow, not global
    #[test]
    fn test_budget_per_flow() {
        let mut t = ObligationTracker::with_flow_budget(1);
        t.try_reserve(ObligationFlow::Publish, vec![], 1000, "t1")
            .unwrap();
        t.try_reserve(ObligationFlow::Revoke, vec![], 1001, "t2")
            .unwrap();
        t.try_reserve(ObligationFlow::Quarantine, vec![], 1002, "t3")
            .unwrap();
        assert_eq!(t.total_obligations(), 3);
    }

    // 43. leak oracle report includes per_flow_counts
    #[test]
    fn test_leak_oracle_report_has_per_flow_counts() {
        let mut t = make_tracker();
        reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        t.run_leak_scan(1500, "scan1");
        let report = t.generate_leak_oracle_report();
        assert_eq!(report.per_flow_counts.len(), 5);
        let json = t.export_leak_oracle_report_json();
        assert!(json.contains("per_flow_counts"));
    }

    // 44. error code for budget exceeded is defined
    #[test]
    fn test_budget_exceeded_error_code() {
        assert!(!error_codes::ERR_OBL_BUDGET_EXCEEDED.is_empty());
    }

    #[test]
    fn test_reserve_rejects_when_registry_full_of_live_entries() {
        let mut t = make_tracker();
        t.with_inner_mut(|state| {
            state.next_id = MAX_OBLIGATIONS as u64 + 1;

            for i in 0..MAX_OBLIGATIONS {
                let id = format!("obl-live-{i}");
                state.obligations.insert(
                    id.clone(),
                    Obligation {
                        id: ObligationId(id),
                        flow: ObligationFlow::Publish,
                        state: ObligationState::Reserved,
                        payload: Vec::new(),
                        reserved_at_ms: 10_000,
                        resolved_at_ms: None,
                        trace_id: "seed".to_string(),
                    },
                );
            }
        });

        let err = t
            .reserve(ObligationFlow::Revoke, vec![], 12_000, "trace-cap")
            .unwrap_err();

        assert_eq!(err, error_codes::ERR_OBL_CAPACITY_EXCEEDED);
        assert_eq!(t.total_obligations(), MAX_OBLIGATIONS);
        assert_eq!(t.count_in_state(ObligationState::Reserved), MAX_OBLIGATIONS);
    }

    #[test]
    fn test_reserve_reclaims_expired_obligations_before_inserting() {
        let mut t = ObligationTracker::with_leak_timeout(1);
        t.with_inner_mut(|state| {
            state.next_id = MAX_OBLIGATIONS as u64 + 1;

            for i in 0..MAX_OBLIGATIONS {
                let id = format!("obl-stale-{i}");
                state.obligations.insert(
                    id.clone(),
                    Obligation {
                        id: ObligationId(id),
                        flow: ObligationFlow::Publish,
                        state: ObligationState::Reserved,
                        payload: Vec::new(),
                        reserved_at_ms: 1_000,
                        resolved_at_ms: None,
                        trace_id: "seed".to_string(),
                    },
                );
            }
        });

        let inserted = t
            .reserve(ObligationFlow::Revoke, vec![], 4_000, "trace-reclaim")
            .expect("expired reservations should be reclaimed");

        assert_eq!(t.total_obligations(), MAX_OBLIGATIONS);
        assert!(t.get_obligation(&inserted).is_some());
        assert_eq!(t.count_in_state(ObligationState::Reserved), 1);
        assert_eq!(
            t.count_in_state(ObligationState::Leaked),
            MAX_OBLIGATIONS - 1
        );
    }

    // 43. Regression: obligation reserved exactly at timeout boundary must be detected as leaked.
    // Before fix: `>` missed the exact boundary, requiring timeout_ms + 1 to detect.
    #[test]
    fn test_leak_scan_exact_timeout_boundary() {
        let mut t = ObligationTracker::with_leak_timeout(2); // 2s = 2000ms timeout
        let id = reserve_ok(&mut t, ObligationFlow::Publish, vec![], 1000, "t1");
        // Scan at exactly reserved_at + timeout = 1000 + 2000 = 3000
        let result = t.run_leak_scan(3000, "boundary-scan");
        assert_eq!(
            result.leaked, 1,
            "obligation at exact timeout boundary must be detected as leaked (fail-closed)"
        );
        assert!(result.leaked_ids.contains(&id.0));
    }
}
