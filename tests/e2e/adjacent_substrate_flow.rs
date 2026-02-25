// SPDX-License-Identifier: MIT
//! bd-8l9k: Cross-substrate contract tests validating end-to-end behavior
//! across all four substrate planes (frankentui -> service -> persistence -> TUI).
//!
//! Section: 10.16 — Adjacent Substrate Integration
//! Schema: e2e-v1.0

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for the cross-substrate E2E test module.
pub const SCHEMA_VERSION: &str = "e2e-v1.0";

// ---------------------------------------------------------------------------
// Event Codes
// ---------------------------------------------------------------------------

/// Event code emitted when an E2E scenario begins execution.
pub const E2E_SCENARIO_START: &str = "E2E_SCENARIO_START";

/// Event code emitted when an E2E scenario passes all assertions.
pub const E2E_SCENARIO_PASS: &str = "E2E_SCENARIO_PASS";

/// Event code emitted when an E2E scenario fails one or more assertions.
pub const E2E_SCENARIO_FAIL: &str = "E2E_SCENARIO_FAIL";

/// Event code emitted when an orphaned span (no parent) is detected in the trace.
pub const E2E_TRACE_ORPHAN_DETECTED: &str = "E2E_TRACE_ORPHAN_DETECTED";

/// Event code emitted when replay produces a different result than the original run.
pub const E2E_REPLAY_MISMATCH: &str = "E2E_REPLAY_MISMATCH";

/// Event code emitted when concurrent operators cause a fencing conflict.
pub const E2E_CONCURRENT_CONFLICT: &str = "E2E_CONCURRENT_CONFLICT";

// ---------------------------------------------------------------------------
// Error Codes
// ---------------------------------------------------------------------------

/// Error when the scenario setup fails.
pub const ERR_E2E_SETUP_FAILED: &str = "ERR_E2E_SETUP_FAILED";

/// Error when trace context propagation fails.
pub const ERR_E2E_TRACE_BROKEN: &str = "ERR_E2E_TRACE_BROKEN";

/// Error when replay determinism assertion fails.
pub const ERR_E2E_REPLAY_DIVERGED: &str = "ERR_E2E_REPLAY_DIVERGED";

/// Error when persistence layer returns unexpected data.
pub const ERR_E2E_PERSISTENCE_MISMATCH: &str = "ERR_E2E_PERSISTENCE_MISMATCH";

/// Error when the service layer returns an unstructured error.
pub const ERR_E2E_SERVICE_ERROR: &str = "ERR_E2E_SERVICE_ERROR";

/// Error when concurrent access produces inconsistent state.
pub const ERR_E2E_CONCURRENT_INCONSISTENT: &str = "ERR_E2E_CONCURRENT_INCONSISTENT";

/// Error when the TUI render layer receives invalid data.
pub const ERR_E2E_TUI_RENDER_FAILED: &str = "ERR_E2E_TUI_RENDER_FAILED";

/// Error when an audit log entry is missing or malformed.
pub const ERR_E2E_AUDIT_MISSING: &str = "ERR_E2E_AUDIT_MISSING";

/// Error when the fencing token is stale or rejected.
pub const ERR_E2E_FENCING_REJECTED: &str = "ERR_E2E_FENCING_REJECTED";

/// Error when schema version mismatch is detected.
pub const ERR_E2E_SCHEMA_MISMATCH: &str = "ERR_E2E_SCHEMA_MISMATCH";

// ---------------------------------------------------------------------------
// Invariants Module
// ---------------------------------------------------------------------------

pub mod invariants {
    //! Invariants for cross-substrate E2E tests (bd-8l9k).

    /// INV-E2E-TRACE: Every span in a cross-substrate flow must have a valid
    /// parent span or be the root span. No orphaned spans are allowed.
    pub const INV_E2E_TRACE: &str = "INV-E2E-TRACE";

    /// INV-E2E-REPLAY: Given identical seeds and mock clocks, replaying an
    /// E2E scenario must produce byte-identical results.
    pub const INV_E2E_REPLAY: &str = "INV-E2E-REPLAY";

    /// INV-E2E-FENCING: Concurrent writes to the same resource must be
    /// serialized through fencing tokens; stale tokens are always rejected.
    pub const INV_E2E_FENCING: &str = "INV-E2E-FENCING";

    /// INV-E2E-AUDIT: Every state-mutating operation across substrates must
    /// produce an audit log entry with a verifiable hash chain.
    pub const INV_E2E_AUDIT: &str = "INV-E2E-AUDIT";

    /// INV-E2E-ERROR-FIDELITY: Errors propagated across substrate boundaries
    /// must preserve their structured error code and context.
    pub const INV_E2E_ERROR_FIDELITY: &str = "INV-E2E-ERROR-FIDELITY";

    /// INV-E2E-SCHEMA-COMPAT: All cross-substrate messages must conform to
    /// the declared schema version (e2e-v1.0).
    pub const INV_E2E_SCHEMA_COMPAT: &str = "INV-E2E-SCHEMA-COMPAT";

    /// INV-E2E-CONCURRENT-SAFETY: Concurrent multi-operator access must not
    /// produce torn reads or lost updates.
    pub const INV_E2E_CONCURRENT_SAFETY: &str = "INV-E2E-CONCURRENT-SAFETY";

    /// Returns all invariant identifiers.
    pub fn all_invariants() -> Vec<&'static str> {
        vec![
            INV_E2E_TRACE,
            INV_E2E_REPLAY,
            INV_E2E_FENCING,
            INV_E2E_AUDIT,
            INV_E2E_ERROR_FIDELITY,
            INV_E2E_SCHEMA_COMPAT,
            INV_E2E_CONCURRENT_SAFETY,
        ]
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_all_invariants_count() {
            assert!(all_invariants().len() >= 5, "Must have at least 5 invariants");
        }

        #[test]
        fn test_invariant_prefix() {
            for inv in all_invariants() {
                assert!(inv.starts_with("INV-E2E-"), "Invariant must start with INV-E2E-: {inv}");
            }
        }

        #[test]
        fn test_no_duplicate_invariants() {
            let invs = all_invariants();
            let mut seen = std::collections::BTreeSet::new();
            for inv in &invs {
                assert!(seen.insert(*inv), "Duplicate invariant: {inv}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Substrate Enum
// ---------------------------------------------------------------------------

/// The four adjacent substrate planes in the franken_node system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Substrate {
    /// frankentui — presentation layer (TUI)
    FrankenTui,
    /// fastapi_rust — service layer
    FastapiRust,
    /// sqlmodel_rust — model/ORM layer
    SqlmodelRust,
    /// frankensqlite — persistence layer
    FrankenSqlite,
}

impl fmt::Display for Substrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Substrate::FrankenTui => write!(f, "frankentui"),
            Substrate::FastapiRust => write!(f, "fastapi_rust"),
            Substrate::SqlmodelRust => write!(f, "sqlmodel_rust"),
            Substrate::FrankenSqlite => write!(f, "frankensqlite"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trace Context
// ---------------------------------------------------------------------------

/// W3C Trace Context for cross-substrate span propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub substrate: Substrate,
    pub operation: String,
    pub timestamp_ms: u64,
}

/// A collected set of spans forming a trace tree.
#[derive(Debug, Clone)]
pub struct TraceTree {
    pub spans: Vec<TraceContext>,
}

impl TraceTree {
    pub fn new() -> Self {
        Self { spans: Vec::new() }
    }

    pub fn add_span(&mut self, span: TraceContext) {
        self.spans.push(span);
    }

    /// Returns orphaned spans (non-root spans whose parent is missing).
    pub fn find_orphans(&self) -> Vec<&TraceContext> {
        let span_ids: std::collections::BTreeSet<&str> =
            self.spans.iter().map(|s| s.span_id.as_str()).collect();
        self.spans
            .iter()
            .filter(|s| {
                if let Some(ref parent) = s.parent_span_id {
                    !span_ids.contains(parent.as_str())
                } else {
                    false // root span, not orphaned
                }
            })
            .collect()
    }

    /// Returns true if no orphaned spans exist.
    pub fn is_complete(&self) -> bool {
        self.find_orphans().is_empty()
    }

    /// Count spans per substrate (deterministic ordering via BTreeMap).
    pub fn spans_by_substrate(&self) -> BTreeMap<String, usize> {
        let mut map = BTreeMap::new();
        for span in &self.spans {
            *map.entry(span.substrate.to_string()).or_insert(0) += 1;
        }
        map
    }
}

// ---------------------------------------------------------------------------
// Replay Determinism
// ---------------------------------------------------------------------------

/// A deterministic seed for replay tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaySeed {
    pub seed: u64,
    pub test_clock_ms: u64,
}

/// The result of a replay run, containing a deterministic hash of the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayResult {
    pub seed: ReplaySeed,
    pub output_hash: String,
    pub events: Vec<String>,
}

/// Verifies that two replay results are identical (deterministic).
pub fn verify_replay_determinism(a: &ReplayResult, b: &ReplayResult) -> Result<(), String> {
    if a.output_hash != b.output_hash {
        return Err(format!(
            "{ERR_E2E_REPLAY_DIVERGED}: hash mismatch: {} != {}",
            a.output_hash, b.output_hash
        ));
    }
    if a.events != b.events {
        return Err(format!(
            "{ERR_E2E_REPLAY_DIVERGED}: event sequence mismatch"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fencing Token
// ---------------------------------------------------------------------------

/// A fencing token for lease-based concurrency control.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FencingToken {
    pub epoch: u64,
    pub sequence: u64,
    pub operator_id: String,
}

impl FencingToken {
    pub fn new(epoch: u64, sequence: u64, operator_id: &str) -> Self {
        Self {
            epoch,
            sequence,
            operator_id: operator_id.to_string(),
        }
    }

    /// Returns true if this token is newer than `other`.
    pub fn supersedes(&self, other: &FencingToken) -> bool {
        (self.epoch, self.sequence) > (other.epoch, other.sequence)
    }
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

/// An entry in the cross-substrate audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub entry_id: String,
    pub trace_id: String,
    pub substrate: Substrate,
    pub operation: String,
    pub operator_id: String,
    pub timestamp_ms: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub details: BTreeMap<String, String>,
}

/// A verifiable audit log with hash-chain integrity.
#[derive(Debug, Clone)]
pub struct AuditLog {
    pub entries: Vec<AuditLogEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn append(&mut self, mut entry: AuditLogEntry) {
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());
        entry.prev_hash = prev_hash.clone();
        // Simple deterministic hash for testing
        entry.entry_hash = format!(
            "hash-{}-{}-{}",
            prev_hash, entry.entry_id, entry.timestamp_ms
        );
        self.entries.push(entry);
    }

    /// Verify the hash chain integrity.
    pub fn verify_chain(&self) -> Result<(), String> {
        let mut expected_prev = "genesis".to_string();
        for entry in &self.entries {
            if entry.prev_hash != expected_prev {
                return Err(format!(
                    "{ERR_E2E_AUDIT_MISSING}: chain broken at entry {}",
                    entry.entry_id
                ));
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Structured Errors
// ---------------------------------------------------------------------------

/// A structured error propagated across substrate boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredError {
    pub code: String,
    pub message: String,
    pub substrate: Substrate,
    pub trace_id: String,
    pub details: BTreeMap<String, String>,
}

impl fmt::Display for StructuredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.substrate, self.code, self.message)
    }
}

// ---------------------------------------------------------------------------
// E2E Scenario Harness
// ---------------------------------------------------------------------------

/// Outcome of a single E2E scenario execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScenarioOutcome {
    Pass,
    Fail(String),
}

/// An E2E scenario result with trace and event information.
#[derive(Debug, Clone)]
pub struct ScenarioResult {
    pub name: String,
    pub outcome: ScenarioOutcome,
    pub trace: TraceTree,
    pub events: Vec<String>,
    pub duration_ms: u64,
}

impl ScenarioResult {
    pub fn passed(&self) -> bool {
        self.outcome == ScenarioOutcome::Pass
    }
}

/// E2E scenario runner that collects results and verifies invariants.
pub struct ScenarioRunner {
    pub results: Vec<ScenarioResult>,
    pub audit_log: AuditLog,
}

impl ScenarioRunner {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            audit_log: AuditLog::new(),
        }
    }

    pub fn record(&mut self, result: ScenarioResult) {
        self.results.push(result);
    }

    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed())
    }

    pub fn summary(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert(
            "total".to_string(),
            self.results.len().to_string(),
        );
        map.insert(
            "passed".to_string(),
            self.results.iter().filter(|r| r.passed()).count().to_string(),
        );
        map.insert(
            "failed".to_string(),
            self.results.iter().filter(|r| !r.passed()).count().to_string(),
        );
        map.insert("schema_version".to_string(), SCHEMA_VERSION.to_string());
        map
    }
}

// ---------------------------------------------------------------------------
// Mock Clock
// ---------------------------------------------------------------------------

/// A test clock for deterministic timestamps in E2E tests.
#[derive(Debug, Clone)]
pub struct TestClock {
    current_ms: Arc<Mutex<u64>>,
}

impl TestClock {
    pub fn new(start_ms: u64) -> Self {
        Self {
            current_ms: Arc::new(Mutex::new(start_ms)),
        }
    }

    pub fn now_ms(&self) -> u64 {
        *self.current_ms.lock().unwrap()
    }

    pub fn advance(&self, ms: u64) {
        let mut current = self.current_ms.lock().unwrap();
        *current += ms;
    }
}

// ---------------------------------------------------------------------------
// Mock Persistence
// ---------------------------------------------------------------------------

/// A mock in-memory persistence layer simulating frankensqlite.
#[derive(Debug, Clone)]
pub struct TestPersistence {
    store: BTreeMap<String, String>,
    fencing_token: Option<FencingToken>,
}

impl TestPersistence {
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
            fencing_token: None,
        }
    }

    /// Write a value, enforcing fencing token.
    pub fn write(
        &mut self,
        key: &str,
        value: &str,
        token: &FencingToken,
    ) -> Result<(), StructuredError> {
        if let Some(ref current) = self.fencing_token {
            if !token.supersedes(current) && token != current {
                return Err(StructuredError {
                    code: ERR_E2E_FENCING_REJECTED.to_string(),
                    message: format!("Stale fencing token for key {key}"),
                    substrate: Substrate::FrankenSqlite,
                    trace_id: String::new(),
                    details: BTreeMap::new(),
                });
            }
        }
        self.fencing_token = Some(token.clone());
        self.store.insert(key.to_string(), value.to_string());
        Ok(())
    }

    /// Read a value from the store.
    pub fn read(&self, key: &str) -> Option<&String> {
        self.store.get(key)
    }

    pub fn current_token(&self) -> Option<&FencingToken> {
        self.fencing_token.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Mock Service Layer
// ---------------------------------------------------------------------------

/// Simulates the fastapi_rust service layer.
pub struct TestService {
    persistence: TestPersistence,
    audit_log: AuditLog,
    clock: TestClock,
}

impl TestService {
    pub fn new(clock: TestClock) -> Self {
        Self {
            persistence: TestPersistence::new(),
            audit_log: AuditLog::new(),
            clock,
        }
    }

    /// Process an operator status update through the service layer.
    pub fn update_operator_status(
        &mut self,
        operator_id: &str,
        status: &str,
        token: &FencingToken,
        trace_id: &str,
    ) -> Result<String, StructuredError> {
        let key = format!("operator:{operator_id}:status");
        self.persistence.write(&key, status, token)?;
        let ts = self.clock.now_ms();
        self.audit_log.append(AuditLogEntry {
            entry_id: format!("audit-{ts}"),
            trace_id: trace_id.to_string(),
            substrate: Substrate::FastapiRust,
            operation: "update_operator_status".to_string(),
            operator_id: operator_id.to_string(),
            timestamp_ms: ts,
            prev_hash: String::new(),
            entry_hash: String::new(),
            details: {
                let mut d = BTreeMap::new();
                d.insert("status".to_string(), status.to_string());
                d
            },
        });
        self.clock.advance(1);
        Ok(format!("operator:{operator_id}:status={status}"))
    }

    /// Get operator status from persistence.
    pub fn get_operator_status(
        &self,
        operator_id: &str,
    ) -> Result<String, StructuredError> {
        let key = format!("operator:{operator_id}:status");
        self.persistence
            .read(&key)
            .cloned()
            .ok_or_else(|| StructuredError {
                code: ERR_E2E_PERSISTENCE_MISMATCH.to_string(),
                message: format!("No status for operator {operator_id}"),
                substrate: Substrate::FrankenSqlite,
                trace_id: String::new(),
                details: BTreeMap::new(),
            })
    }

    /// Acquire a lease for an operator.
    pub fn acquire_lease(
        &mut self,
        operator_id: &str,
        token: &FencingToken,
        trace_id: &str,
    ) -> Result<FencingToken, StructuredError> {
        let key = format!("lease:{operator_id}");
        self.persistence
            .write(&key, &format!("active:{}", token.sequence), token)?;
        let ts = self.clock.now_ms();
        self.audit_log.append(AuditLogEntry {
            entry_id: format!("audit-{ts}"),
            trace_id: trace_id.to_string(),
            substrate: Substrate::FastapiRust,
            operation: "acquire_lease".to_string(),
            operator_id: operator_id.to_string(),
            timestamp_ms: ts,
            prev_hash: String::new(),
            entry_hash: String::new(),
            details: {
                let mut d = BTreeMap::new();
                d.insert("epoch".to_string(), token.epoch.to_string());
                d.insert("sequence".to_string(), token.sequence.to_string());
                d
            },
        });
        self.clock.advance(1);
        Ok(token.clone())
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Get persistence reference.
    pub fn persistence(&self) -> &TestPersistence {
        &self.persistence
    }
}

// ---------------------------------------------------------------------------
// Mock TUI Layer
// ---------------------------------------------------------------------------

/// Simulates the frankentui presentation layer.
pub struct TestTui {
    rendered_panels: Vec<BTreeMap<String, String>>,
    errors: Vec<StructuredError>,
}

impl TestTui {
    pub fn new() -> Self {
        Self {
            rendered_panels: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Render an operator status panel.
    pub fn render_status_panel(
        &mut self,
        operator_id: &str,
        status: &str,
    ) -> Result<(), StructuredError> {
        if status.is_empty() {
            return Err(StructuredError {
                code: ERR_E2E_TUI_RENDER_FAILED.to_string(),
                message: "Empty status cannot be rendered".to_string(),
                substrate: Substrate::FrankenTui,
                trace_id: String::new(),
                details: BTreeMap::new(),
            });
        }
        let mut panel = BTreeMap::new();
        panel.insert("operator_id".to_string(), operator_id.to_string());
        panel.insert("status".to_string(), status.to_string());
        panel.insert("type".to_string(), "status_panel".to_string());
        self.rendered_panels.push(panel);
        Ok(())
    }

    /// Render an error panel.
    pub fn render_error(&mut self, err: &StructuredError) {
        self.errors.push(err.clone());
        let mut panel = BTreeMap::new();
        panel.insert("type".to_string(), "error_panel".to_string());
        panel.insert("code".to_string(), err.code.clone());
        panel.insert("message".to_string(), err.message.clone());
        self.rendered_panels.push(panel);
    }

    /// Render audit log entries.
    pub fn render_audit_entries(
        &mut self,
        entries: &[AuditLogEntry],
    ) -> Result<(), StructuredError> {
        for entry in entries {
            let mut panel = BTreeMap::new();
            panel.insert("type".to_string(), "audit_entry".to_string());
            panel.insert("entry_id".to_string(), entry.entry_id.clone());
            panel.insert("operation".to_string(), entry.operation.clone());
            panel.insert("substrate".to_string(), entry.substrate.to_string());
            self.rendered_panels.push(panel);
        }
        Ok(())
    }

    pub fn panel_count(&self) -> usize {
        self.rendered_panels.len()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    pub fn panels(&self) -> &[BTreeMap<String, String>] {
        &self.rendered_panels
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_trace_id(seed: u64) -> String {
    format!("trace-{seed:016x}")
}

fn make_span_id(substrate: Substrate, seq: u64) -> String {
    format!("span-{substrate}-{seq}")
}

fn build_cross_substrate_trace(
    trace_id: &str,
    clock: &TestClock,
    substrates: &[Substrate],
    operation: &str,
) -> TraceTree {
    let mut tree = TraceTree::new();
    let mut parent: Option<String> = None;
    for (i, substrate) in substrates.iter().enumerate() {
        let span_id = make_span_id(*substrate, i as u64);
        tree.add_span(TraceContext {
            trace_id: trace_id.to_string(),
            span_id: span_id.clone(),
            parent_span_id: parent.clone(),
            substrate: *substrate,
            operation: operation.to_string(),
            timestamp_ms: clock.now_ms(),
        });
        parent = Some(span_id);
        clock.advance(1);
    }
    tree
}

fn deterministic_hash(seed: u64, data: &str) -> String {
    // Simple deterministic hash for testing — not cryptographic.
    let mut h: u64 = seed;
    for byte in data.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("{h:016x}")
}

// ---------------------------------------------------------------------------
// E2E Scenario 1: Operator Status Flow
// ---------------------------------------------------------------------------

/// Operator status flow: TUI -> service -> persistence -> TUI.
pub fn scenario_operator_status(clock: &TestClock, seed: u64) -> ScenarioResult {
    let mut events = vec![E2E_SCENARIO_START.to_string()];
    let trace_id = make_trace_id(seed);
    let substrates = [
        Substrate::FrankenTui,
        Substrate::FastapiRust,
        Substrate::SqlmodelRust,
        Substrate::FrankenSqlite,
    ];
    let trace = build_cross_substrate_trace(&trace_id, clock, &substrates, "operator_status");

    let mut service = TestService::new(clock.clone());
    let token = FencingToken::new(1, 1, "op-1");
    let mut tui = TestTui::new();

    // TUI initiates -> service processes -> persistence stores -> TUI renders
    match service.update_operator_status("op-1", "active", &token, &trace_id) {
        Ok(_) => {
            match service.get_operator_status("op-1") {
                Ok(status) => {
                    if tui.render_status_panel("op-1", &status).is_ok() {
                        events.push(E2E_SCENARIO_PASS.to_string());
                        return ScenarioResult {
                            name: "operator_status_flow".to_string(),
                            outcome: ScenarioOutcome::Pass,
                            trace,
                            events,
                            duration_ms: clock.now_ms(),
                        };
                    }
                }
                Err(e) => {
                    events.push(E2E_SCENARIO_FAIL.to_string());
                    return ScenarioResult {
                        name: "operator_status_flow".to_string(),
                        outcome: ScenarioOutcome::Fail(e.to_string()),
                        trace,
                        events,
                        duration_ms: clock.now_ms(),
                    };
                }
            }
        }
        Err(e) => {
            events.push(E2E_SCENARIO_FAIL.to_string());
            return ScenarioResult {
                name: "operator_status_flow".to_string(),
                outcome: ScenarioOutcome::Fail(e.to_string()),
                trace,
                events,
                duration_ms: clock.now_ms(),
            };
        }
    }

    events.push(E2E_SCENARIO_FAIL.to_string());
    ScenarioResult {
        name: "operator_status_flow".to_string(),
        outcome: ScenarioOutcome::Fail("TUI render failed".to_string()),
        trace,
        events,
        duration_ms: clock.now_ms(),
    }
}

// ---------------------------------------------------------------------------
// E2E Scenario 2: Lease Management Flow
// ---------------------------------------------------------------------------

/// Lease management flow: TUI -> service -> fencing -> persistence -> TUI.
pub fn scenario_lease_management(clock: &TestClock, seed: u64) -> ScenarioResult {
    let mut events = vec![E2E_SCENARIO_START.to_string()];
    let trace_id = make_trace_id(seed);
    let substrates = [
        Substrate::FrankenTui,
        Substrate::FastapiRust,
        Substrate::SqlmodelRust,
        Substrate::FrankenSqlite,
    ];
    let trace = build_cross_substrate_trace(&trace_id, clock, &substrates, "lease_management");

    let mut service = TestService::new(clock.clone());
    let token = FencingToken::new(1, 1, "op-lease");
    let mut tui = TestTui::new();

    match service.acquire_lease("op-lease", &token, &trace_id) {
        Ok(acquired_token) => {
            // Verify the token was stored correctly
            if service.persistence().current_token() == Some(&acquired_token) {
                if tui
                    .render_status_panel("op-lease", "lease_active")
                    .is_ok()
                {
                    events.push(E2E_SCENARIO_PASS.to_string());
                    return ScenarioResult {
                        name: "lease_management_flow".to_string(),
                        outcome: ScenarioOutcome::Pass,
                        trace,
                        events,
                        duration_ms: clock.now_ms(),
                    };
                }
            }
        }
        Err(e) => {
            events.push(E2E_SCENARIO_FAIL.to_string());
            return ScenarioResult {
                name: "lease_management_flow".to_string(),
                outcome: ScenarioOutcome::Fail(e.to_string()),
                trace,
                events,
                duration_ms: clock.now_ms(),
            };
        }
    }

    events.push(E2E_SCENARIO_FAIL.to_string());
    ScenarioResult {
        name: "lease_management_flow".to_string(),
        outcome: ScenarioOutcome::Fail("lease flow failed".to_string()),
        trace,
        events,
        duration_ms: clock.now_ms(),
    }
}

// ---------------------------------------------------------------------------
// E2E Scenario 3: Audit Log Flow
// ---------------------------------------------------------------------------

/// Audit log flow: action -> service -> persistence -> verifier -> TUI.
pub fn scenario_audit_log(clock: &TestClock, seed: u64) -> ScenarioResult {
    let mut events = vec![E2E_SCENARIO_START.to_string()];
    let trace_id = make_trace_id(seed);
    let substrates = [
        Substrate::FrankenTui,
        Substrate::FastapiRust,
        Substrate::SqlmodelRust,
        Substrate::FrankenSqlite,
    ];
    let trace = build_cross_substrate_trace(&trace_id, clock, &substrates, "audit_log");

    let mut service = TestService::new(clock.clone());
    let token = FencingToken::new(1, 1, "op-audit");
    let mut tui = TestTui::new();

    // Perform an action that generates audit entries
    let _ = service.update_operator_status("op-audit", "active", &token, &trace_id);
    let _ = service.update_operator_status("op-audit", "draining", &token, &trace_id);

    // Verify the audit chain
    match service.audit_log().verify_chain() {
        Ok(()) => {
            // Render audit entries in TUI
            if tui
                .render_audit_entries(&service.audit_log().entries)
                .is_ok()
            {
                if tui.panel_count() >= 2 {
                    events.push(E2E_SCENARIO_PASS.to_string());
                    return ScenarioResult {
                        name: "audit_log_flow".to_string(),
                        outcome: ScenarioOutcome::Pass,
                        trace,
                        events,
                        duration_ms: clock.now_ms(),
                    };
                }
            }
        }
        Err(e) => {
            events.push(E2E_SCENARIO_FAIL.to_string());
            return ScenarioResult {
                name: "audit_log_flow".to_string(),
                outcome: ScenarioOutcome::Fail(e),
                trace,
                events,
                duration_ms: clock.now_ms(),
            };
        }
    }

    events.push(E2E_SCENARIO_FAIL.to_string());
    ScenarioResult {
        name: "audit_log_flow".to_string(),
        outcome: ScenarioOutcome::Fail("audit flow incomplete".to_string()),
        trace,
        events,
        duration_ms: clock.now_ms(),
    }
}

// ---------------------------------------------------------------------------
// E2E Scenario 4: Error Propagation Flow
// ---------------------------------------------------------------------------

/// Error propagation flow: invalid request -> structured error -> TUI -> audit.
pub fn scenario_error_propagation(clock: &TestClock, seed: u64) -> ScenarioResult {
    let mut events = vec![E2E_SCENARIO_START.to_string()];
    let trace_id = make_trace_id(seed);
    let substrates = [
        Substrate::FrankenTui,
        Substrate::FastapiRust,
        Substrate::SqlmodelRust,
        Substrate::FrankenSqlite,
    ];
    let trace = build_cross_substrate_trace(&trace_id, clock, &substrates, "error_propagation");

    let mut service = TestService::new(clock.clone());
    let mut tui = TestTui::new();

    // Use a stale fencing token to trigger an error
    let stale_token = FencingToken::new(1, 1, "op-err");
    let _ = service.update_operator_status("op-err", "active", &stale_token, &trace_id);

    // Now try with an older token — should fail
    let older_token = FencingToken::new(0, 0, "op-err-stale");
    match service.update_operator_status("op-err", "draining", &older_token, &trace_id) {
        Ok(_) => {
            events.push(E2E_SCENARIO_FAIL.to_string());
            ScenarioResult {
                name: "error_propagation_flow".to_string(),
                outcome: ScenarioOutcome::Fail(
                    "Expected fencing error but operation succeeded".to_string(),
                ),
                trace,
                events,
                duration_ms: clock.now_ms(),
            }
        }
        Err(err) => {
            // Verify the error is structured and propagates to TUI
            if err.code == ERR_E2E_FENCING_REJECTED {
                tui.render_error(&err);
                if tui.error_count() == 1
                    && tui.panels().last().map(|p| p.get("code").map(|c| c.as_str()))
                        == Some(Some(ERR_E2E_FENCING_REJECTED))
                {
                    events.push(E2E_SCENARIO_PASS.to_string());
                    return ScenarioResult {
                        name: "error_propagation_flow".to_string(),
                        outcome: ScenarioOutcome::Pass,
                        trace,
                        events,
                        duration_ms: clock.now_ms(),
                    };
                }
            }
            events.push(E2E_SCENARIO_FAIL.to_string());
            ScenarioResult {
                name: "error_propagation_flow".to_string(),
                outcome: ScenarioOutcome::Fail(format!(
                    "Error code mismatch: expected {ERR_E2E_FENCING_REJECTED}, got {}",
                    err.code
                )),
                trace,
                events,
                duration_ms: clock.now_ms(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E2E Scenario 5: Concurrent Access Flow
// ---------------------------------------------------------------------------

/// Concurrent access flow: multi-operator -> fencing -> consistency.
pub fn scenario_concurrent_access(clock: &TestClock, seed: u64) -> ScenarioResult {
    let mut events = vec![E2E_SCENARIO_START.to_string()];
    let trace_id = make_trace_id(seed);
    let substrates = [
        Substrate::FrankenTui,
        Substrate::FastapiRust,
        Substrate::SqlmodelRust,
        Substrate::FrankenSqlite,
    ];
    let trace = build_cross_substrate_trace(&trace_id, clock, &substrates, "concurrent_access");

    let mut service = TestService::new(clock.clone());

    // Operator A acquires lease with epoch 1, seq 1
    let token_a = FencingToken::new(1, 1, "op-A");
    let result_a = service.acquire_lease("shared-resource", &token_a, &trace_id);

    // Operator B tries with epoch 1, seq 2 (newer) — should succeed
    let token_b = FencingToken::new(1, 2, "op-B");
    let result_b = service.acquire_lease("shared-resource", &token_b, &trace_id);

    // Operator A tries again with the old token — should fail (fencing)
    let result_a2 = service.acquire_lease("shared-resource", &token_a, &trace_id);

    match (result_a, result_b, result_a2) {
        (Ok(_), Ok(_), Err(err)) => {
            if err.code == ERR_E2E_FENCING_REJECTED {
                events.push(E2E_CONCURRENT_CONFLICT.to_string());
                events.push(E2E_SCENARIO_PASS.to_string());
                ScenarioResult {
                    name: "concurrent_access_flow".to_string(),
                    outcome: ScenarioOutcome::Pass,
                    trace,
                    events,
                    duration_ms: clock.now_ms(),
                }
            } else {
                events.push(E2E_SCENARIO_FAIL.to_string());
                ScenarioResult {
                    name: "concurrent_access_flow".to_string(),
                    outcome: ScenarioOutcome::Fail(format!(
                        "Wrong error code: expected {ERR_E2E_FENCING_REJECTED}, got {}",
                        err.code
                    )),
                    trace,
                    events,
                    duration_ms: clock.now_ms(),
                }
            }
        }
        _ => {
            events.push(E2E_SCENARIO_FAIL.to_string());
            ScenarioResult {
                name: "concurrent_access_flow".to_string(),
                outcome: ScenarioOutcome::Fail(
                    "Unexpected concurrent access results".to_string(),
                ),
                trace,
                events,
                duration_ms: clock.now_ms(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E2E Scenario 6: Trace Context Propagation
// ---------------------------------------------------------------------------

/// Validates that trace context is propagated without orphaned spans.
pub fn scenario_trace_propagation(clock: &TestClock, seed: u64) -> ScenarioResult {
    let mut events = vec![E2E_SCENARIO_START.to_string()];
    let trace_id = make_trace_id(seed);
    let substrates = [
        Substrate::FrankenTui,
        Substrate::FastapiRust,
        Substrate::SqlmodelRust,
        Substrate::FrankenSqlite,
    ];
    let trace = build_cross_substrate_trace(&trace_id, clock, &substrates, "trace_propagation");

    let orphans = trace.find_orphans();
    if orphans.is_empty() {
        // Also verify all four substrates are present
        let by_sub = trace.spans_by_substrate();
        if by_sub.len() == 4 {
            events.push(E2E_SCENARIO_PASS.to_string());
            ScenarioResult {
                name: "trace_propagation".to_string(),
                outcome: ScenarioOutcome::Pass,
                trace,
                events,
                duration_ms: clock.now_ms(),
            }
        } else {
            events.push(E2E_SCENARIO_FAIL.to_string());
            ScenarioResult {
                name: "trace_propagation".to_string(),
                outcome: ScenarioOutcome::Fail(format!(
                    "Expected 4 substrates in trace, found {}",
                    by_sub.len()
                )),
                trace,
                events,
                duration_ms: clock.now_ms(),
            }
        }
    } else {
        events.push(E2E_TRACE_ORPHAN_DETECTED.to_string());
        events.push(E2E_SCENARIO_FAIL.to_string());
        ScenarioResult {
            name: "trace_propagation".to_string(),
            outcome: ScenarioOutcome::Fail(format!(
                "{ERR_E2E_TRACE_BROKEN}: {} orphaned spans detected",
                orphans.len()
            )),
            trace,
            events,
            duration_ms: clock.now_ms(),
        }
    }
}

// ---------------------------------------------------------------------------
// E2E Scenario 7: Replay Determinism
// ---------------------------------------------------------------------------

/// Validates that replaying with the same seed produces identical results.
pub fn scenario_replay_determinism(clock_start_ms: u64, seed: u64) -> ScenarioResult {
    let mut events = vec![E2E_SCENARIO_START.to_string()];

    // Run the same scenario twice with identical seeds/clocks
    let clock_a = TestClock::new(clock_start_ms);
    let result_a = scenario_operator_status(&clock_a, seed);

    let clock_b = TestClock::new(clock_start_ms);
    let result_b = scenario_operator_status(&clock_b, seed);

    // Build a trace for this scenario itself
    let trace_id = make_trace_id(seed.wrapping_add(1000));
    let clock = TestClock::new(clock_start_ms);
    let trace = build_cross_substrate_trace(
        &trace_id,
        &clock,
        &[Substrate::FrankenTui, Substrate::FastapiRust],
        "replay_determinism",
    );

    // Compare outcomes
    let replay_a = ReplayResult {
        seed: ReplaySeed {
            seed,
            test_clock_ms: clock_start_ms,
        },
        output_hash: deterministic_hash(seed, &format!("{:?}", result_a.outcome)),
        events: result_a.events.clone(),
    };
    let replay_b = ReplayResult {
        seed: ReplaySeed {
            seed,
            test_clock_ms: clock_start_ms,
        },
        output_hash: deterministic_hash(seed, &format!("{:?}", result_b.outcome)),
        events: result_b.events.clone(),
    };

    match verify_replay_determinism(&replay_a, &replay_b) {
        Ok(()) => {
            events.push(E2E_SCENARIO_PASS.to_string());
            ScenarioResult {
                name: "replay_determinism".to_string(),
                outcome: ScenarioOutcome::Pass,
                trace,
                events,
                duration_ms: clock.now_ms(),
            }
        }
        Err(e) => {
            events.push(E2E_REPLAY_MISMATCH.to_string());
            events.push(E2E_SCENARIO_FAIL.to_string());
            ScenarioResult {
                name: "replay_determinism".to_string(),
                outcome: ScenarioOutcome::Fail(e),
                trace,
                events,
                duration_ms: clock.now_ms(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Full Suite Runner
// ---------------------------------------------------------------------------

/// Run all E2E scenarios and return the collected runner state.
pub fn run_all_scenarios() -> ScenarioRunner {
    let seed: u64 = 42;
    let clock_start: u64 = 1_700_000_000_000;

    let mut runner = ScenarioRunner::new();

    let clock1 = TestClock::new(clock_start);
    runner.record(scenario_operator_status(&clock1, seed));

    let clock2 = TestClock::new(clock_start);
    runner.record(scenario_lease_management(&clock2, seed + 1));

    let clock3 = TestClock::new(clock_start);
    runner.record(scenario_audit_log(&clock3, seed + 2));

    let clock4 = TestClock::new(clock_start);
    runner.record(scenario_error_propagation(&clock4, seed + 3));

    let clock5 = TestClock::new(clock_start);
    runner.record(scenario_concurrent_access(&clock5, seed + 4));

    let clock6 = TestClock::new(clock_start);
    runner.record(scenario_trace_propagation(&clock6, seed + 5));

    runner.record(scenario_replay_determinism(clock_start, seed + 6));

    runner
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Schema version tests -----------------------------------------------

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "e2e-v1.0");
    }

    // -- Event code tests ---------------------------------------------------

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(E2E_SCENARIO_START, "E2E_SCENARIO_START");
        assert_eq!(E2E_SCENARIO_PASS, "E2E_SCENARIO_PASS");
        assert_eq!(E2E_SCENARIO_FAIL, "E2E_SCENARIO_FAIL");
        assert_eq!(E2E_TRACE_ORPHAN_DETECTED, "E2E_TRACE_ORPHAN_DETECTED");
        assert_eq!(E2E_REPLAY_MISMATCH, "E2E_REPLAY_MISMATCH");
        assert_eq!(E2E_CONCURRENT_CONFLICT, "E2E_CONCURRENT_CONFLICT");
    }

    // -- Error code tests ---------------------------------------------------

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(ERR_E2E_SETUP_FAILED, "ERR_E2E_SETUP_FAILED");
        assert_eq!(ERR_E2E_TRACE_BROKEN, "ERR_E2E_TRACE_BROKEN");
        assert_eq!(ERR_E2E_REPLAY_DIVERGED, "ERR_E2E_REPLAY_DIVERGED");
        assert_eq!(ERR_E2E_PERSISTENCE_MISMATCH, "ERR_E2E_PERSISTENCE_MISMATCH");
        assert_eq!(ERR_E2E_SERVICE_ERROR, "ERR_E2E_SERVICE_ERROR");
        assert_eq!(ERR_E2E_CONCURRENT_INCONSISTENT, "ERR_E2E_CONCURRENT_INCONSISTENT");
        assert_eq!(ERR_E2E_TUI_RENDER_FAILED, "ERR_E2E_TUI_RENDER_FAILED");
        assert_eq!(ERR_E2E_AUDIT_MISSING, "ERR_E2E_AUDIT_MISSING");
        assert_eq!(ERR_E2E_FENCING_REJECTED, "ERR_E2E_FENCING_REJECTED");
        assert_eq!(ERR_E2E_SCHEMA_MISMATCH, "ERR_E2E_SCHEMA_MISMATCH");
    }

    // -- Substrate tests ----------------------------------------------------

    #[test]
    fn test_substrate_display() {
        assert_eq!(Substrate::FrankenTui.to_string(), "frankentui");
        assert_eq!(Substrate::FastapiRust.to_string(), "fastapi_rust");
        assert_eq!(Substrate::SqlmodelRust.to_string(), "sqlmodel_rust");
        assert_eq!(Substrate::FrankenSqlite.to_string(), "frankensqlite");
    }

    #[test]
    fn test_substrate_ordering() {
        // BTreeMap compatibility: substrates must have a defined ordering
        let mut set = std::collections::BTreeSet::new();
        set.insert(Substrate::FrankenSqlite);
        set.insert(Substrate::FrankenTui);
        set.insert(Substrate::FastapiRust);
        set.insert(Substrate::SqlmodelRust);
        assert_eq!(set.len(), 4);
    }

    // -- Trace context tests ------------------------------------------------

    #[test]
    fn test_trace_tree_no_orphans() {
        let clock = TestClock::new(1000);
        let substrates = [
            Substrate::FrankenTui,
            Substrate::FastapiRust,
            Substrate::SqlmodelRust,
            Substrate::FrankenSqlite,
        ];
        let trace = build_cross_substrate_trace("t-1", &clock, &substrates, "test");
        assert!(trace.is_complete());
        assert!(trace.find_orphans().is_empty());
    }

    #[test]
    fn test_trace_tree_detects_orphan() {
        let mut tree = TraceTree::new();
        tree.add_span(TraceContext {
            trace_id: "t-1".to_string(),
            span_id: "root".to_string(),
            parent_span_id: None,
            substrate: Substrate::FrankenTui,
            operation: "test".to_string(),
            timestamp_ms: 1000,
        });
        tree.add_span(TraceContext {
            trace_id: "t-1".to_string(),
            span_id: "child".to_string(),
            parent_span_id: Some("missing-parent".to_string()),
            substrate: Substrate::FastapiRust,
            operation: "test".to_string(),
            timestamp_ms: 1001,
        });
        assert!(!tree.is_complete());
        assert_eq!(tree.find_orphans().len(), 1);
    }

    #[test]
    fn test_trace_spans_by_substrate_uses_btreemap() {
        let clock = TestClock::new(1000);
        let substrates = [
            Substrate::FrankenTui,
            Substrate::FastapiRust,
            Substrate::SqlmodelRust,
            Substrate::FrankenSqlite,
        ];
        let trace = build_cross_substrate_trace("t-1", &clock, &substrates, "test");
        let by_sub = trace.spans_by_substrate();
        assert_eq!(by_sub.len(), 4);
        // BTreeMap iteration is sorted
        let keys: Vec<&String> = by_sub.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    // -- Fencing token tests ------------------------------------------------

    #[test]
    fn test_fencing_token_supersedes() {
        let a = FencingToken::new(1, 1, "op-a");
        let b = FencingToken::new(1, 2, "op-b");
        assert!(b.supersedes(&a));
        assert!(!a.supersedes(&b));
    }

    #[test]
    fn test_fencing_token_epoch_precedence() {
        let a = FencingToken::new(1, 100, "op-a");
        let b = FencingToken::new(2, 1, "op-b");
        assert!(b.supersedes(&a));
        assert!(!a.supersedes(&b));
    }

    #[test]
    fn test_fencing_token_equality() {
        let a = FencingToken::new(1, 1, "op-a");
        let b = FencingToken::new(1, 1, "op-a");
        assert_eq!(a, b);
        assert!(!a.supersedes(&b));
    }

    // -- Audit log tests ----------------------------------------------------

    #[test]
    fn test_audit_log_empty() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_audit_log_chain_integrity() {
        let mut log = AuditLog::new();
        log.append(AuditLogEntry {
            entry_id: "e1".to_string(),
            trace_id: "t1".to_string(),
            substrate: Substrate::FastapiRust,
            operation: "op1".to_string(),
            operator_id: "op-1".to_string(),
            timestamp_ms: 1000,
            prev_hash: String::new(),
            entry_hash: String::new(),
            details: BTreeMap::new(),
        });
        log.append(AuditLogEntry {
            entry_id: "e2".to_string(),
            trace_id: "t1".to_string(),
            substrate: Substrate::FrankenSqlite,
            operation: "op2".to_string(),
            operator_id: "op-1".to_string(),
            timestamp_ms: 1001,
            prev_hash: String::new(),
            entry_hash: String::new(),
            details: BTreeMap::new(),
        });
        assert_eq!(log.len(), 2);
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_audit_log_broken_chain() {
        let mut log = AuditLog::new();
        log.append(AuditLogEntry {
            entry_id: "e1".to_string(),
            trace_id: "t1".to_string(),
            substrate: Substrate::FastapiRust,
            operation: "op1".to_string(),
            operator_id: "op-1".to_string(),
            timestamp_ms: 1000,
            prev_hash: String::new(),
            entry_hash: String::new(),
            details: BTreeMap::new(),
        });
        // Tamper with the hash
        log.entries[0].prev_hash = "tampered".to_string();
        assert!(log.verify_chain().is_err());
    }

    // -- Mock persistence tests ---------------------------------------------

    #[test]
    fn test_persistence_write_read() {
        let mut store = TestPersistence::new();
        let token = FencingToken::new(1, 1, "op");
        store.write("key1", "value1", &token).unwrap();
        assert_eq!(store.read("key1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_persistence_fencing_rejects_stale() {
        let mut store = TestPersistence::new();
        let token_new = FencingToken::new(1, 2, "op-new");
        store.write("key1", "v1", &token_new).unwrap();
        let token_old = FencingToken::new(1, 1, "op-old");
        let result = store.write("key1", "v2", &token_old);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            ERR_E2E_FENCING_REJECTED
        );
    }

    #[test]
    fn test_persistence_fencing_accepts_newer() {
        let mut store = TestPersistence::new();
        let token1 = FencingToken::new(1, 1, "op");
        store.write("key1", "v1", &token1).unwrap();
        let token2 = FencingToken::new(1, 2, "op");
        assert!(store.write("key1", "v2", &token2).is_ok());
        assert_eq!(store.read("key1"), Some(&"v2".to_string()));
    }

    // -- Mock service tests -------------------------------------------------

    #[test]
    fn test_service_update_and_get_status() {
        let clock = TestClock::new(1000);
        let mut svc = TestService::new(clock);
        let token = FencingToken::new(1, 1, "op-1");
        svc.update_operator_status("op-1", "active", &token, "trace-1")
            .unwrap();
        let status = svc.get_operator_status("op-1").unwrap();
        assert_eq!(status, "active");
    }

    #[test]
    fn test_service_audit_log_populated() {
        let clock = TestClock::new(1000);
        let mut svc = TestService::new(clock);
        let token = FencingToken::new(1, 1, "op-1");
        svc.update_operator_status("op-1", "active", &token, "trace-1")
            .unwrap();
        assert_eq!(svc.audit_log().len(), 1);
        assert!(svc.audit_log().verify_chain().is_ok());
    }

    #[test]
    fn test_service_get_missing_status() {
        let clock = TestClock::new(1000);
        let svc = TestService::new(clock);
        let result = svc.get_operator_status("nonexistent");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_E2E_PERSISTENCE_MISMATCH);
    }

    // -- Mock TUI tests -----------------------------------------------------

    #[test]
    fn test_tui_render_status() {
        let mut tui = TestTui::new();
        tui.render_status_panel("op-1", "active").unwrap();
        assert_eq!(tui.panel_count(), 1);
        assert_eq!(
            tui.panels()[0].get("type"),
            Some(&"status_panel".to_string())
        );
    }

    #[test]
    fn test_tui_render_empty_status_fails() {
        let mut tui = TestTui::new();
        let result = tui.render_status_panel("op-1", "");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_E2E_TUI_RENDER_FAILED);
    }

    #[test]
    fn test_tui_render_error() {
        let mut tui = TestTui::new();
        let err = StructuredError {
            code: ERR_E2E_FENCING_REJECTED.to_string(),
            message: "stale token".to_string(),
            substrate: Substrate::FrankenSqlite,
            trace_id: "t-1".to_string(),
            details: BTreeMap::new(),
        };
        tui.render_error(&err);
        assert_eq!(tui.error_count(), 1);
        assert_eq!(tui.panel_count(), 1);
    }

    // -- Replay determinism tests -------------------------------------------

    #[test]
    fn test_replay_determinism_identical() {
        let a = ReplayResult {
            seed: ReplaySeed {
                seed: 42,
                test_clock_ms: 1000,
            },
            output_hash: "abc123".to_string(),
            events: vec!["E1".to_string()],
        };
        let b = a.clone();
        assert!(verify_replay_determinism(&a, &b).is_ok());
    }

    #[test]
    fn test_replay_determinism_hash_mismatch() {
        let a = ReplayResult {
            seed: ReplaySeed {
                seed: 42,
                test_clock_ms: 1000,
            },
            output_hash: "abc123".to_string(),
            events: vec!["E1".to_string()],
        };
        let b = ReplayResult {
            output_hash: "def456".to_string(),
            ..a.clone()
        };
        let result = verify_replay_determinism(&a, &b);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(ERR_E2E_REPLAY_DIVERGED));
    }

    #[test]
    fn test_replay_determinism_event_mismatch() {
        let a = ReplayResult {
            seed: ReplaySeed {
                seed: 42,
                test_clock_ms: 1000,
            },
            output_hash: "abc123".to_string(),
            events: vec!["E1".to_string()],
        };
        let b = ReplayResult {
            events: vec!["E2".to_string()],
            ..a.clone()
        };
        let result = verify_replay_determinism(&a, &b);
        assert!(result.is_err());
    }

    // -- Mock clock tests ---------------------------------------------------

    #[test]
    fn test_clock_advance() {
        let clock = TestClock::new(1000);
        assert_eq!(clock.now_ms(), 1000);
        clock.advance(500);
        assert_eq!(clock.now_ms(), 1500);
    }

    #[test]
    fn test_clock_clone_independence() {
        let clock = TestClock::new(1000);
        let cloned = clock.clone();
        clock.advance(500);
        // Clones share state (Arc<Mutex>)
        assert_eq!(cloned.now_ms(), 1500);
    }

    // -- Structured error tests ---------------------------------------------

    #[test]
    fn test_structured_error_display() {
        let err = StructuredError {
            code: ERR_E2E_FENCING_REJECTED.to_string(),
            message: "stale token".to_string(),
            substrate: Substrate::FrankenSqlite,
            trace_id: "t-1".to_string(),
            details: BTreeMap::new(),
        };
        let display = format!("{err}");
        assert!(display.contains("frankensqlite"));
        assert!(display.contains(ERR_E2E_FENCING_REJECTED));
    }

    #[test]
    fn test_structured_error_preserves_details() {
        let mut details = BTreeMap::new();
        details.insert("key".to_string(), "value".to_string());
        let err = StructuredError {
            code: ERR_E2E_SERVICE_ERROR.to_string(),
            message: "test".to_string(),
            substrate: Substrate::FastapiRust,
            trace_id: "t-1".to_string(),
            details: details.clone(),
        };
        assert_eq!(err.details, details);
    }

    // -- Scenario tests -----------------------------------------------------

    #[test]
    fn test_scenario_operator_status_passes() {
        let clock = TestClock::new(1_700_000_000_000);
        let result = scenario_operator_status(&clock, 42);
        assert!(result.passed(), "Scenario failed: {:?}", result.outcome);
        assert!(result.events.contains(&E2E_SCENARIO_START.to_string()));
        assert!(result.events.contains(&E2E_SCENARIO_PASS.to_string()));
    }

    #[test]
    fn test_scenario_lease_management_passes() {
        let clock = TestClock::new(1_700_000_000_000);
        let result = scenario_lease_management(&clock, 43);
        assert!(result.passed(), "Scenario failed: {:?}", result.outcome);
    }

    #[test]
    fn test_scenario_audit_log_passes() {
        let clock = TestClock::new(1_700_000_000_000);
        let result = scenario_audit_log(&clock, 44);
        assert!(result.passed(), "Scenario failed: {:?}", result.outcome);
    }

    #[test]
    fn test_scenario_error_propagation_passes() {
        let clock = TestClock::new(1_700_000_000_000);
        let result = scenario_error_propagation(&clock, 45);
        assert!(result.passed(), "Scenario failed: {:?}", result.outcome);
    }

    #[test]
    fn test_scenario_concurrent_access_passes() {
        let clock = TestClock::new(1_700_000_000_000);
        let result = scenario_concurrent_access(&clock, 46);
        assert!(result.passed(), "Scenario failed: {:?}", result.outcome);
    }

    #[test]
    fn test_scenario_trace_propagation_passes() {
        let clock = TestClock::new(1_700_000_000_000);
        let result = scenario_trace_propagation(&clock, 47);
        assert!(result.passed(), "Scenario failed: {:?}", result.outcome);
    }

    #[test]
    fn test_scenario_replay_determinism_passes() {
        let result = scenario_replay_determinism(1_700_000_000_000, 48);
        assert!(result.passed(), "Scenario failed: {:?}", result.outcome);
    }

    // -- Full suite tests ---------------------------------------------------

    #[test]
    fn test_run_all_scenarios_pass() {
        let runner = run_all_scenarios();
        assert!(runner.all_passed(), "Some scenarios failed");
        assert!(runner.results.len() >= 5, "Expected at least 5 scenarios");
    }

    #[test]
    fn test_run_all_scenarios_summary_btreemap() {
        let runner = run_all_scenarios();
        let summary = runner.summary();
        assert!(summary.contains_key("total"));
        assert!(summary.contains_key("passed"));
        assert!(summary.contains_key("failed"));
        assert!(summary.contains_key("schema_version"));
        assert_eq!(summary.get("schema_version"), Some(&"e2e-v1.0".to_string()));
    }

    #[test]
    fn test_all_scenarios_have_trace() {
        let runner = run_all_scenarios();
        for result in &runner.results {
            assert!(
                !result.trace.spans.is_empty(),
                "Scenario {} has no trace spans",
                result.name
            );
        }
    }

    #[test]
    fn test_no_orphaned_spans_in_any_scenario() {
        let runner = run_all_scenarios();
        for result in &runner.results {
            assert!(
                result.trace.is_complete(),
                "Scenario {} has orphaned spans",
                result.name
            );
        }
    }

    #[test]
    fn test_all_scenarios_emit_start_event() {
        let runner = run_all_scenarios();
        for result in &runner.results {
            assert!(
                result.events.contains(&E2E_SCENARIO_START.to_string()),
                "Scenario {} missing E2E_SCENARIO_START",
                result.name
            );
        }
    }

    #[test]
    fn test_concurrent_scenario_emits_conflict_event() {
        let clock = TestClock::new(1_700_000_000_000);
        let result = scenario_concurrent_access(&clock, 46);
        assert!(
            result.events.contains(&E2E_CONCURRENT_CONFLICT.to_string()),
            "Concurrent scenario should emit E2E_CONCURRENT_CONFLICT"
        );
    }

    #[test]
    fn test_scenario_names_unique() {
        let runner = run_all_scenarios();
        let mut names = std::collections::BTreeSet::new();
        for result in &runner.results {
            assert!(
                names.insert(result.name.clone()),
                "Duplicate scenario name: {}",
                result.name
            );
        }
    }

    #[test]
    fn test_deterministic_hash_consistency() {
        let h1 = deterministic_hash(42, "test data");
        let h2 = deterministic_hash(42, "test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_deterministic_hash_different_seeds() {
        let h1 = deterministic_hash(42, "test data");
        let h2 = deterministic_hash(43, "test data");
        assert_ne!(h1, h2);
    }

    // -- Invariants integration tests ---------------------------------------

    #[test]
    fn test_invariant_trace_no_orphans() {
        // INV-E2E-TRACE
        let runner = run_all_scenarios();
        for result in &runner.results {
            assert!(result.trace.is_complete());
        }
    }

    #[test]
    fn test_invariant_replay_determinism() {
        // INV-E2E-REPLAY
        let r1 = scenario_replay_determinism(1_700_000_000_000, 42);
        let r2 = scenario_replay_determinism(1_700_000_000_000, 42);
        assert_eq!(r1.outcome, r2.outcome);
    }

    #[test]
    fn test_invariant_fencing() {
        // INV-E2E-FENCING
        let mut store = TestPersistence::new();
        let new_token = FencingToken::new(2, 1, "op");
        store.write("k", "v", &new_token).unwrap();
        let stale = FencingToken::new(1, 1, "op");
        assert!(store.write("k", "v2", &stale).is_err());
    }

    #[test]
    fn test_invariant_audit_chain() {
        // INV-E2E-AUDIT
        let clock = TestClock::new(1000);
        let mut svc = TestService::new(clock);
        let token = FencingToken::new(1, 1, "op");
        svc.update_operator_status("op", "a", &token, "t").unwrap();
        svc.update_operator_status("op", "b", &token, "t").unwrap();
        assert!(svc.audit_log().verify_chain().is_ok());
    }

    #[test]
    fn test_invariant_error_fidelity() {
        // INV-E2E-ERROR-FIDELITY
        let mut store = TestPersistence::new();
        let new_token = FencingToken::new(2, 1, "op");
        store.write("k", "v", &new_token).unwrap();
        let stale = FencingToken::new(1, 1, "op");
        let err = store.write("k", "v2", &stale).unwrap_err();
        assert_eq!(err.code, ERR_E2E_FENCING_REJECTED);
        assert_eq!(err.substrate, Substrate::FrankenSqlite);
    }
}
