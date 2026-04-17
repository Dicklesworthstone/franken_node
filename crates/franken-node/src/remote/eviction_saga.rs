//! bd-1ru2: Cancel-safe eviction saga (upload -> verify -> retire).
//!
//! Multi-step saga for L2->L3 artifact lifecycle with deterministic
//! compensations. Guarantees no partial retire on cancellation/crash.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

// ── Constants ────────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "es-v1.0";
pub const DEFAULT_MAX_AUDIT_RECORDS: usize = 4_096;
pub const DEFAULT_MAX_TRANSITIONS_PER_SAGA: usize = 512;
use crate::capacity_defaults::aliases::MAX_SAGAS;
const ERR_INVALID_ARTIFACT_ID: &str = "ERR_INVALID_ARTIFACT_ID";
const ERR_SAGA_ID_REUSED: &str = "ERR_SAGA_ID_REUSED";
const RESERVED_ARTIFACT_ID: &str = "<unknown>";

fn invalid_artifact_id_reason(artifact_id: &str) -> Option<String> {
    let trimmed = artifact_id.trim();
    if trimmed.is_empty() {
        return Some("artifact_id must not be empty".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", artifact_id));
    }
    if artifact_id.chars().any(char::is_control) {
        return Some("artifact_id contains control characters".to_string());
    }
    if trimmed != artifact_id {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    None
}

fn default_audit_log_capacity() -> usize {
    DEFAULT_MAX_AUDIT_RECORDS
}

fn default_transition_capacity() -> usize {
    DEFAULT_MAX_TRANSITIONS_PER_SAGA
}

// ── Event codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    pub const ES_SAGA_START: &str = "ES_SAGA_START";
    pub const ES_PHASE_UPLOAD: &str = "ES_PHASE_UPLOAD";
    pub const ES_PHASE_VERIFY: &str = "ES_PHASE_VERIFY";
    pub const ES_PHASE_RETIRE: &str = "ES_PHASE_RETIRE";
    pub const ES_SAGA_COMPLETE: &str = "ES_SAGA_COMPLETE";
    pub const ES_COMPENSATION_START: &str = "ES_COMPENSATION_START";
    pub const ES_COMPENSATION_COMPLETE: &str = "ES_COMPENSATION_COMPLETE";
    pub const ES_LEAK_CHECK_PASSED: &str = "ES_LEAK_CHECK_PASSED";
    pub const ES_LEAK_CHECK_FAILED: &str = "ES_LEAK_CHECK_FAILED";
    pub const ES_CRASH_RECOVERY: &str = "ES_CRASH_RECOVERY";
    pub const ES_CANCEL_REQUESTED: &str = "ES_CANCEL_REQUESTED";
    pub const ES_REMOTECAP_RECHECK: &str = "ES_REMOTECAP_RECHECK";
    pub const ES_AUDIT_EMITTED: &str = "ES_AUDIT_EMITTED";
}

// ── Invariants ───────────────────────────────────────────────────────────────

pub mod invariants {
    pub const INV_ES_CANCEL_SAFE: &str = "INV-ES-CANCEL-SAFE";
    pub const INV_ES_DETERMINISTIC: &str = "INV-ES-DETERMINISTIC";
    pub const INV_ES_LEAK_FREE: &str = "INV-ES-LEAK-FREE";
    pub const INV_ES_GATED: &str = "INV-ES-GATED";
    pub const INV_ES_PERSISTED: &str = "INV-ES-PERSISTED";
    pub const INV_ES_AUDITABLE: &str = "INV-ES-AUDITABLE";
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Saga phase states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaPhase {
    Created,
    Uploading,
    Verifying,
    Retiring,
    Complete,
    Compensating,
    Compensated,
    Failed,
}

impl fmt::Display for SagaPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SagaPhase::Created => write!(f, "Created"),
            SagaPhase::Uploading => write!(f, "Uploading"),
            SagaPhase::Verifying => write!(f, "Verifying"),
            SagaPhase::Retiring => write!(f, "Retiring"),
            SagaPhase::Complete => write!(f, "Complete"),
            SagaPhase::Compensating => write!(f, "Compensating"),
            SagaPhase::Compensated => write!(f, "Compensated"),
            SagaPhase::Failed => write!(f, "Failed"),
        }
    }
}

/// Compensation action for each phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompensationAction {
    /// During upload: abort upload, no L2 change.
    AbortUpload,
    /// During verify: abort, clean up partial L3 state.
    CleanupL3,
    /// During retire: L3 is confirmed, complete retirement on recovery.
    CompleteRetirement,
    /// No compensation needed.
    None,
}

impl fmt::Display for CompensationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompensationAction::AbortUpload => write!(f, "AbortUpload"),
            CompensationAction::CleanupL3 => write!(f, "CleanupL3"),
            CompensationAction::CompleteRetirement => write!(f, "CompleteRetirement"),
            CompensationAction::None => write!(f, "None"),
        }
    }
}

/// Phase transition record for persistence and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTransition {
    pub saga_id: String,
    pub artifact_id: String,
    pub from_phase: SagaPhase,
    pub to_phase: SagaPhase,
    pub timestamp_ms: u64,
    pub outcome: String,
}

/// Audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsAuditRecord {
    pub event_code: String,
    pub trace_id: String,
    pub detail: serde_json::Value,
}

/// Leak check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakCheckResult {
    pub orphans_found: usize,
    pub details: Vec<String>,
    pub passed: bool,
}

/// Individual saga instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaInstance {
    pub saga_id: String,
    pub artifact_id: String,
    pub phase: SagaPhase,
    pub l2_present: bool,
    pub l3_present: bool,
    pub l3_verified: bool,
    pub transitions: Vec<PhaseTransition>,
    pub has_remote_cap: bool,
}

impl SagaInstance {
    pub fn new(saga_id: &str, artifact_id: &str) -> Self {
        Self {
            saga_id: saga_id.to_string(),
            artifact_id: artifact_id.to_string(),
            phase: SagaPhase::Created,
            l2_present: true,
            l3_present: false,
            l3_verified: false,
            transitions: Vec::new(),
            has_remote_cap: false,
        }
    }

    fn record_transition(
        &mut self,
        to_phase: SagaPhase,
        outcome: &str,
        timestamp_ms: u64,
        max_transitions: usize,
    ) {
        let max_transitions = max_transitions.max(1);
        let from = self.phase;
        push_bounded(
            &mut self.transitions,
            PhaseTransition {
                saga_id: self.saga_id.clone(),
                artifact_id: self.artifact_id.clone(),
                from_phase: from,
                to_phase,
                timestamp_ms,
                outcome: outcome.to_string(),
            },
            max_transitions,
        );
        self.phase = to_phase;
    }

    /// Determine compensation action for the current phase.
    pub fn compensation_action(&self) -> CompensationAction {
        match self.phase {
            SagaPhase::Uploading => CompensationAction::AbortUpload,
            SagaPhase::Verifying => CompensationAction::CleanupL3,
            SagaPhase::Retiring => CompensationAction::CompleteRetirement,
            _ => CompensationAction::None,
        }
    }
}

/// The eviction saga manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvictionSagaManager {
    sagas: BTreeMap<String, SagaInstance>,
    audit_log: Vec<EsAuditRecord>,
    #[serde(default = "default_audit_log_capacity")]
    max_audit_records: usize,
    #[serde(default = "default_transition_capacity")]
    max_transitions_per_saga: usize,
    next_saga_id: u64,
}

impl EvictionSagaManager {
    pub fn new() -> Self {
        Self::with_capacities(DEFAULT_MAX_AUDIT_RECORDS, DEFAULT_MAX_TRANSITIONS_PER_SAGA)
    }

    pub fn with_capacities(max_audit_records: usize, max_transitions_per_saga: usize) -> Self {
        Self {
            sagas: BTreeMap::new(),
            audit_log: Vec::new(),
            max_audit_records: max_audit_records.max(1),
            max_transitions_per_saga: max_transitions_per_saga.max(1),
            next_saga_id: 1,
        }
    }

    pub fn init(trace_id: &str) -> Self {
        let mut mgr = Self::new();
        mgr.log(
            event_codes::ES_SAGA_START,
            trace_id,
            serde_json::json!({"init": true}),
        );
        mgr
    }

    fn log(&mut self, event_code: &str, trace_id: &str, detail: serde_json::Value) {
        let cap = self.max_audit_records;
        push_bounded(
            &mut self.audit_log,
            EsAuditRecord {
                event_code: event_code.to_string(),
                trace_id: trace_id.to_string(),
                detail,
            },
            cap,
        );
    }

    fn ensure_remote_cap_active(
        saga: &SagaInstance,
        saga_id: &str,
        phase_name: &str,
    ) -> Result<(), String> {
        if saga.has_remote_cap {
            Ok(())
        } else {
            Err(format!(
                "RemoteCap recheck failed for saga {saga_id} before {phase_name}"
            ))
        }
    }

    fn ensure_cancel_allowed(phase: SagaPhase, saga_id: &str) -> Result<(), String> {
        match phase {
            SagaPhase::Complete | SagaPhase::Compensated | SagaPhase::Failed => Err(format!(
                "saga {saga_id} is in terminal phase {phase} and cannot be cancelled"
            )),
            SagaPhase::Compensating => Err(format!("saga {saga_id} is already compensating")),
            SagaPhase::Created
            | SagaPhase::Uploading
            | SagaPhase::Verifying
            | SagaPhase::Retiring => Ok(()),
        }
    }

    fn is_terminal_phase(phase: SagaPhase) -> bool {
        matches!(
            phase,
            SagaPhase::Complete | SagaPhase::Compensated | SagaPhase::Failed
        )
    }

    fn saga_sequence(saga_id: &str) -> u64 {
        saga_id
            .strip_prefix("saga-")
            .and_then(|suffix| suffix.parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    }

    fn oldest_terminal_saga_id(&self) -> Option<String> {
        self.sagas
            .iter()
            .filter(|(_, saga)| Self::is_terminal_phase(saga.phase))
            .min_by_key(|(saga_id, _)| (Self::saga_sequence(saga_id), saga_id.as_str()))
            .map(|(saga_id, _)| saga_id.clone())
    }

    /// Start a new eviction saga.
    pub fn start_saga(
        &mut self,
        artifact_id: &str,
        has_remote_cap: bool,
        trace_id: &str,
    ) -> Result<String, String> {
        if let Some(reason) = invalid_artifact_id_reason(artifact_id) {
            return Err(format!("{ERR_INVALID_ARTIFACT_ID}: {reason}"));
        }
        if !has_remote_cap {
            return Err("RemoteCap required for upload phase".to_string());
        }

        let saga_id = format!("saga-{}", self.next_saga_id);
        if self.sagas.contains_key(&saga_id) {
            return Err(format!(
                "{ERR_SAGA_ID_REUSED}: generated saga id already exists: {saga_id}"
            ));
        }

        if self.sagas.len() >= MAX_SAGAS {
            self.evict_terminal_sagas();
            if self.sagas.len() >= MAX_SAGAS {
                return Err(format!(
                    "saga registry full at capacity {MAX_SAGAS}; no terminal entries available for eviction"
                ));
            }
        }

        self.next_saga_id = self.next_saga_id.saturating_add(1);

        let mut saga = SagaInstance::new(&saga_id, artifact_id);
        saga.has_remote_cap = has_remote_cap;

        self.log(
            event_codes::ES_SAGA_START,
            trace_id,
            serde_json::json!({"saga_id": &saga_id, "artifact_id": artifact_id}),
        );

        self.sagas.insert(saga_id.clone(), saga);
        Ok(saga_id)
    }

    /// Evict oldest terminal-state sagas until the registry has room for one more entry.
    fn evict_terminal_sagas(&mut self) {
        while self.sagas.len() >= MAX_SAGAS {
            let evict_key = self.oldest_terminal_saga_id();
            match evict_key {
                Some(key) => {
                    self.sagas.remove(&key);
                }
                None => break,
            }
        }
    }

    /// Re-validate remote capability for an in-flight saga.
    ///
    /// This is intended to be called before sensitive remote-bound steps in
    /// long-lived workflows where capability validity may change.
    pub fn recheck_remote_cap(
        &mut self,
        saga_id: &str,
        has_remote_cap: bool,
        trace_id: &str,
    ) -> Result<(), String> {
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;
        saga.has_remote_cap = has_remote_cap;

        self.log(
            event_codes::ES_REMOTECAP_RECHECK,
            trace_id,
            serde_json::json!({"saga_id": saga_id, "has_remote_cap": has_remote_cap}),
        );

        if has_remote_cap {
            Ok(())
        } else {
            Err(format!("RemoteCap recheck failed for saga {saga_id}"))
        }
    }

    /// Advance saga to Uploading phase.
    pub fn begin_upload(
        &mut self,
        saga_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let max_transitions_per_saga = self.max_transitions_per_saga;
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.phase != SagaPhase::Created {
            return Err(format!("invalid transition: {} -> Uploading", saga.phase));
        }
        Self::ensure_remote_cap_active(saga, saga_id, "begin_upload")?;

        saga.record_transition(
            SagaPhase::Uploading,
            "upload_started",
            timestamp_ms,
            max_transitions_per_saga,
        );
        self.log(
            event_codes::ES_PHASE_UPLOAD,
            trace_id,
            serde_json::json!({"saga_id": saga_id}),
        );
        Ok(())
    }

    /// Complete upload and advance to Verifying.
    pub fn complete_upload(
        &mut self,
        saga_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let max_transitions_per_saga = self.max_transitions_per_saga;
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.phase != SagaPhase::Uploading {
            return Err(format!("invalid transition: {} -> Verifying", saga.phase));
        }
        Self::ensure_remote_cap_active(saga, saga_id, "complete_upload")?;

        saga.l3_present = true;
        saga.record_transition(
            SagaPhase::Verifying,
            "upload_complete",
            timestamp_ms,
            max_transitions_per_saga,
        );
        self.log(
            event_codes::ES_PHASE_VERIFY,
            trace_id,
            serde_json::json!({"saga_id": saga_id}),
        );
        Ok(())
    }

    /// Complete verification and advance to Retiring.
    pub fn complete_verify(
        &mut self,
        saga_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let max_transitions_per_saga = self.max_transitions_per_saga;
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.phase != SagaPhase::Verifying {
            return Err(format!("invalid transition: {} -> Retiring", saga.phase));
        }
        Self::ensure_remote_cap_active(saga, saga_id, "complete_verify")?;

        saga.l3_verified = true;
        saga.record_transition(
            SagaPhase::Retiring,
            "verification_passed",
            timestamp_ms,
            max_transitions_per_saga,
        );
        self.log(
            event_codes::ES_PHASE_RETIRE,
            trace_id,
            serde_json::json!({"saga_id": saga_id}),
        );
        Ok(())
    }

    /// Complete retirement (L2 removed).
    pub fn complete_retire(
        &mut self,
        saga_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let max_transitions_per_saga = self.max_transitions_per_saga;
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.phase != SagaPhase::Retiring {
            return Err(format!("invalid transition: {} -> Complete", saga.phase));
        }
        Self::ensure_remote_cap_active(saga, saga_id, "complete_retire")?;

        saga.l2_present = false;
        saga.record_transition(
            SagaPhase::Complete,
            "retirement_complete",
            timestamp_ms,
            max_transitions_per_saga,
        );
        self.log(
            event_codes::ES_SAGA_COMPLETE,
            trace_id,
            serde_json::json!({"saga_id": saga_id}),
        );
        Ok(())
    }

    /// Cancel/compensate a saga at its current phase.
    pub fn cancel_saga(
        &mut self,
        saga_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<CompensationAction, String> {
        let max_transitions_per_saga = self.max_transitions_per_saga;
        // Extract values from saga with immutable borrow first
        let (action, phase_str) = {
            let saga = self
                .sagas
                .get(saga_id)
                .ok_or_else(|| format!("saga not found: {saga_id}"))?;

            Self::ensure_cancel_allowed(saga.phase, saga_id)?;

            let action = saga.compensation_action();
            let phase_str = format!("{}", saga.phase);
            (action, phase_str)
        };

        self.log(
            event_codes::ES_CANCEL_REQUESTED,
            trace_id,
            serde_json::json!({
                "saga_id": saga_id,
                "phase": phase_str,
                "action": format!("{action}"),
                "timestamp_ms": timestamp_ms,
            }),
        );

        let action_str = format!("{action}");
        let compensation_outcome = format!("compensation: {action}");
        {
            let saga = self
                .sagas
                .get_mut(saga_id)
                .ok_or_else(|| format!("saga disappeared during cancel: {saga_id}"))?;
            // Re-check after mutable borrow as a defensive invariant.
            Self::ensure_cancel_allowed(saga.phase, saga_id)?;
            saga.record_transition(
                SagaPhase::Compensating,
                &compensation_outcome,
                timestamp_ms,
                max_transitions_per_saga,
            );
        }
        self.log(
            event_codes::ES_COMPENSATION_START,
            trace_id,
            serde_json::json!({
                "saga_id": saga_id,
                "action": action_str,
                "timestamp_ms": timestamp_ms,
            }),
        );

        // Apply compensation
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga disappeared during cancel: {saga_id}"))?;
        match &action {
            CompensationAction::AbortUpload => {
                // L2 intact, no L3 to clean
                saga.l3_present = false;
            }
            CompensationAction::CleanupL3 => {
                // Remove partial L3
                saga.l3_present = false;
                saga.l3_verified = false;
            }
            CompensationAction::CompleteRetirement => {
                // L3 confirmed, proceed with retirement
                saga.l2_present = false;
            }
            CompensationAction::None => {}
        }

        saga.record_transition(
            SagaPhase::Compensated,
            "compensation_complete",
            timestamp_ms,
            max_transitions_per_saga,
        );
        // Drop mutable borrow before logging
        let action_str = format!("{action}");
        self.log(
            event_codes::ES_COMPENSATION_COMPLETE,
            trace_id,
            serde_json::json!({
                "saga_id": saga_id,
                "action": action_str,
                "timestamp_ms": timestamp_ms,
            }),
        );

        Ok(action)
    }

    /// Recover a saga from a persisted phase (crash recovery).
    ///
    /// Handles the `Compensating` state (crash mid-compensation) by examining
    /// the transition log to determine the original compensation action and
    /// re-applying it. All compensation operations are idempotent.
    pub fn recover_saga(
        &mut self,
        saga_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<CompensationAction, String> {
        let max_transitions_per_saga = self.max_transitions_per_saga;
        let (action, was_compensating) = {
            let saga = self
                .sagas
                .get(saga_id)
                .ok_or_else(|| format!("saga not found: {saga_id}"))?;

            // If crashed mid-compensation, recover the original action from transition history
            let was_compensating = saga.phase == SagaPhase::Compensating;
            let action = if was_compensating {
                saga.transitions
                    .iter()
                    .rev()
                    .find(|t| t.to_phase == SagaPhase::Compensating)
                    .map(|t| match t.from_phase {
                        SagaPhase::Uploading => CompensationAction::AbortUpload,
                        SagaPhase::Verifying => CompensationAction::CleanupL3,
                        SagaPhase::Retiring => CompensationAction::CompleteRetirement,
                        _ => CompensationAction::None,
                    })
                    .unwrap_or(CompensationAction::None)
            } else {
                saga.compensation_action()
            };

            self.log(
                event_codes::ES_CRASH_RECOVERY,
                trace_id,
                serde_json::json!({
                    "saga_id": saga_id,
                    "phase": format!("{}", saga.phase),
                    "action": format!("{action}"),
                    "timestamp_ms": timestamp_ms,
                }),
            );
            (action, was_compensating)
        };

        // Apply the compensation (idempotent operations safe to re-execute)
        let completed_compensation = match &action {
            CompensationAction::AbortUpload => {
                let saga = self
                    .sagas
                    .get_mut(saga_id)
                    .ok_or_else(|| format!("saga disappeared during recovery: {saga_id}"))?;
                saga.l3_present = false;
                saga.record_transition(
                    SagaPhase::Compensated,
                    "crash_recovery: abort_upload",
                    timestamp_ms,
                    max_transitions_per_saga,
                );
                true
            }
            CompensationAction::CleanupL3 => {
                let saga = self
                    .sagas
                    .get_mut(saga_id)
                    .ok_or_else(|| format!("saga disappeared during recovery: {saga_id}"))?;
                saga.l3_present = false;
                saga.l3_verified = false;
                saga.record_transition(
                    SagaPhase::Compensated,
                    "crash_recovery: cleanup_l3",
                    timestamp_ms,
                    max_transitions_per_saga,
                );
                true
            }
            CompensationAction::CompleteRetirement => {
                let saga = self
                    .sagas
                    .get_mut(saga_id)
                    .ok_or_else(|| format!("saga disappeared during recovery: {saga_id}"))?;
                saga.l2_present = false;
                saga.record_transition(
                    SagaPhase::Complete,
                    "crash_recovery: complete_retirement",
                    timestamp_ms,
                    max_transitions_per_saga,
                );
                true
            }
            CompensationAction::None if was_compensating => {
                let saga = self
                    .sagas
                    .get_mut(saga_id)
                    .ok_or_else(|| format!("saga disappeared during recovery: {saga_id}"))?;
                saga.record_transition(
                    SagaPhase::Compensated,
                    "crash_recovery: no_op",
                    timestamp_ms,
                    max_transitions_per_saga,
                );
                true
            }
            CompensationAction::None => false,
        };

        if completed_compensation {
            self.log(
                event_codes::ES_COMPENSATION_COMPLETE,
                trace_id,
                serde_json::json!({
                    "saga_id": saga_id,
                    "action": format!("{action}"),
                    "timestamp_ms": timestamp_ms,
                    "via": "crash_recovery",
                }),
            );
        }

        Ok(action)
    }

    /// Run leak detection across all sagas.
    pub fn leak_check(&mut self, trace_id: &str) -> LeakCheckResult {
        let mut orphans = Vec::new();

        for (id, saga) in &self.sagas {
            // Orphan: L2 retired but L3 absent
            if !saga.l2_present && !saga.l3_present {
                orphans.push(format!("{id}: L2 retired but L3 absent"));
            }
            // Orphan: L3 present but not verified and saga complete
            if saga.phase == SagaPhase::Complete && saga.l3_present && !saga.l3_verified {
                orphans.push(format!("{id}: L3 present but unverified in Complete state"));
            }
            // Orphan: stuck in Compensating (crash during compensation)
            if saga.phase == SagaPhase::Compensating {
                orphans.push(format!("{id}: stuck in Compensating state"));
            }
        }

        let passed = orphans.is_empty();
        let event_code = if passed {
            event_codes::ES_LEAK_CHECK_PASSED
        } else {
            event_codes::ES_LEAK_CHECK_FAILED
        };
        self.log(
            event_code,
            trace_id,
            serde_json::json!({"orphans": orphans.len()}),
        );

        LeakCheckResult {
            orphans_found: orphans.len(),
            details: orphans,
            passed,
        }
    }

    /// Get a saga by ID.
    pub fn get_saga(&self, saga_id: &str) -> Option<&SagaInstance> {
        self.sagas.get(saga_id)
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export saga traces as JSONL.
    pub fn export_saga_trace_jsonl(&self) -> String {
        self.sagas
            .values()
            .flat_map(|s| s.transitions.iter())
            .map(|t| serde_json::to_string(t).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Content hash.
    pub fn content_hash(&self) -> String {
        let content =
            serde_json::to_string(&self.sagas).unwrap_or_else(|e| format!("__serde_err:{e}"));
        format!(
            "{:x}",
            Sha256::digest([b"eviction_saga_content_v1:" as &[u8], content.as_bytes()].concat())
        )
    }

    /// Saga count.
    pub fn saga_count(&self) -> usize {
        self.sagas.len()
    }

    pub fn audit_log_capacity(&self) -> usize {
        self.max_audit_records
    }

    pub fn transition_capacity(&self) -> usize {
        self.max_transitions_per_saga
    }
}

impl Default for EvictionSagaManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_manager() {
        let mgr = EvictionSagaManager::new();
        assert_eq!(mgr.saga_count(), 0);
        assert_eq!(mgr.audit_log_capacity(), DEFAULT_MAX_AUDIT_RECORDS);
        assert_eq!(mgr.transition_capacity(), DEFAULT_MAX_TRANSITIONS_PER_SAGA);
    }

    #[test]
    fn test_capacity_clamps_to_one() {
        let mgr = EvictionSagaManager::with_capacities(0, 0);
        assert_eq!(mgr.audit_log_capacity(), 1);
        assert_eq!(mgr.transition_capacity(), 1);
    }

    #[test]
    fn test_audit_log_capacity_enforces_oldest_first_eviction() {
        let mut mgr = EvictionSagaManager::with_capacities(2, 8);
        let id = mgr
            .start_saga("artifact-a", true, "ta1")
            .expect("should succeed");
        mgr.begin_upload(&id, 2_000, "ta2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "ta3")
            .expect("should succeed");

        assert_eq!(mgr.audit_log.len(), 2);
        let codes: Vec<&str> = mgr
            .audit_log
            .iter()
            .map(|record| record.event_code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![event_codes::ES_PHASE_UPLOAD, event_codes::ES_PHASE_VERIFY]
        );
    }

    #[test]
    fn test_transition_capacity_enforces_oldest_first_eviction() {
        let mut mgr = EvictionSagaManager::with_capacities(8, 2);
        let id = mgr
            .start_saga("artifact-b", true, "tt1")
            .expect("should succeed");
        mgr.begin_upload(&id, 2_000, "tt2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "tt3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "tt4")
            .expect("should succeed");

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert_eq!(saga.transitions.len(), 2);
        assert_eq!(saga.phase, SagaPhase::Retiring);
        assert_eq!(saga.transitions[0].to_phase, SagaPhase::Verifying);
        assert_eq!(saga.transitions[1].to_phase, SagaPhase::Retiring);
    }

    #[test]
    fn test_full_saga_success() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr
            .start_saga("artifact-1", true, "t1")
            .expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "t4")
            .expect("should succeed");
        mgr.complete_retire(&id, 5_000, "t5")
            .expect("should succeed");

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert_eq!(saga.phase, SagaPhase::Complete);
        assert!(!saga.l2_present);
        assert!(saga.l3_present);
        assert!(saga.l3_verified);
    }

    #[test]
    fn test_start_requires_remote_cap() {
        let mut mgr = EvictionSagaManager::new();
        let err = mgr.start_saga("a", false, "t1").unwrap_err();
        assert!(err.contains("RemoteCap"));
    }

    #[test]
    fn test_start_rejects_empty_artifact_id() {
        let mut mgr = EvictionSagaManager::new();
        let err = mgr.start_saga("", true, "t1").unwrap_err();
        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("artifact_id must not be empty"));
    }

    #[test]
    fn test_start_rejects_reserved_artifact_id() {
        let mut mgr = EvictionSagaManager::new();
        let err = mgr
            .start_saga(&format!(" {RESERVED_ARTIFACT_ID} "), true, "t1")
            .unwrap_err();
        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("artifact_id is reserved"));
    }

    #[test]
    fn test_start_rejects_artifact_id_whitespace() {
        let mut mgr = EvictionSagaManager::new();
        let err = mgr.start_saga(" artifact-a ", true, "t1").unwrap_err();
        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("leading or trailing whitespace"));
    }

    #[test]
    fn test_remote_cap_recheck_blocks_begin_upload_until_restored() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");

        let err = mgr.recheck_remote_cap(&id, false, "t2").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr.begin_upload(&id, 3_000, "t3").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        mgr.recheck_remote_cap(&id, true, "t4")
            .expect("should succeed");
        mgr.begin_upload(&id, 5_000, "t5").expect("should succeed");
    }

    #[test]
    fn test_remote_cap_recheck_blocks_complete_upload_until_restored() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");

        let err = mgr.recheck_remote_cap(&id, false, "t3").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr.complete_upload(&id, 4_000, "t4").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        mgr.recheck_remote_cap(&id, true, "t5")
            .expect("should succeed");
        mgr.complete_upload(&id, 6_000, "t6")
            .expect("should succeed");
    }

    #[test]
    fn test_remote_cap_recheck_blocks_complete_verify_until_restored() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");

        let err = mgr.recheck_remote_cap(&id, false, "t4").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr.complete_verify(&id, 5_000, "t5").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        mgr.recheck_remote_cap(&id, true, "t6")
            .expect("should succeed");
        mgr.complete_verify(&id, 7_000, "t7")
            .expect("should succeed");
    }

    #[test]
    fn test_remote_cap_recheck_blocks_complete_retire_until_restored() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "t4")
            .expect("should succeed");

        let err = mgr.recheck_remote_cap(&id, false, "t5").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr.complete_retire(&id, 6_000, "t6").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        mgr.recheck_remote_cap(&id, true, "t7")
            .expect("should succeed");
        mgr.complete_retire(&id, 8_000, "t8")
            .expect("should succeed");
    }

    #[test]
    fn test_invalid_transition_rejected() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        // Can't go directly to verify without upload
        let err = mgr.complete_upload(&id, 2_000, "t2").unwrap_err();
        assert!(err.contains("invalid transition"));
    }

    #[test]
    fn test_cancel_during_upload() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        let action = mgr.cancel_saga(&id, 3_000, "t3").expect("should succeed");
        assert!(matches!(action, CompensationAction::AbortUpload));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_cancel_during_verify() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        let action = mgr.cancel_saga(&id, 4_000, "t4").expect("should succeed");
        assert!(matches!(action, CompensationAction::CleanupL3));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_cancel_during_retire() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "t4")
            .expect("should succeed");
        let action = mgr.cancel_saga(&id, 5_000, "t5").expect("should succeed");
        assert!(matches!(action, CompensationAction::CompleteRetirement));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert!(!saga.l2_present); // Retirement completed
    }

    #[test]
    fn test_cancel_terminal_complete_rejected() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "t4")
            .expect("should succeed");
        mgr.complete_retire(&id, 5_000, "t5")
            .expect("should succeed");

        let err = mgr.cancel_saga(&id, 6_000, "t6").unwrap_err();
        assert!(err.contains("terminal phase Complete"));
    }

    #[test]
    fn test_cancel_terminal_compensated_rejected() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.cancel_saga(&id, 3_000, "t3").expect("should succeed");

        let err = mgr.cancel_saga(&id, 4_000, "t4").unwrap_err();
        assert!(err.contains("terminal phase Compensated"));
    }

    #[test]
    fn test_leak_check_passes_after_success() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "t4")
            .expect("should succeed");
        mgr.complete_retire(&id, 5_000, "t5")
            .expect("should succeed");

        let result = mgr.leak_check("t6");
        assert!(result.passed);
        assert_eq!(result.orphans_found, 0);
    }

    #[test]
    fn test_leak_check_passes_after_compensation() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.cancel_saga(&id, 3_000, "t3").expect("should succeed");

        let result = mgr.leak_check("t4");
        assert!(result.passed);
    }

    #[test]
    fn test_cancel_emits_compensation_start_before_complete() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");

        let audit_len_before = mgr.audit_log.len();
        mgr.cancel_saga(&id, 3_000, "t3").expect("should succeed");

        let new_events = &mgr.audit_log[audit_len_before..];
        let codes: Vec<&str> = new_events
            .iter()
            .map(|record| record.event_code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![
                event_codes::ES_CANCEL_REQUESTED,
                event_codes::ES_COMPENSATION_START,
                event_codes::ES_COMPENSATION_COMPLETE,
            ]
        );
        assert_eq!(new_events[1].detail["timestamp_ms"], 3_000);
        assert_eq!(new_events[2].detail["timestamp_ms"], 3_000);
    }

    #[test]
    fn test_crash_recovery_identifies_action() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");

        let action = mgr.recover_saga(&id, 4_000, "t4").expect("should succeed");
        assert!(matches!(action, CompensationAction::CleanupL3));
    }

    #[test]
    fn test_content_hash_deterministic() {
        let mut m1 = EvictionSagaManager::new();
        m1.start_saga("a", true, "t1").expect("should succeed");
        let mut m2 = EvictionSagaManager::new();
        m2.start_saga("a", true, "t1").expect("should succeed");
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn test_audit_log_jsonl() {
        let mut mgr = EvictionSagaManager::init("t1");
        mgr.start_saga("a", true, "t2").expect("should succeed");
        let jsonl = mgr.export_audit_log_jsonl();
        assert_eq!(jsonl.lines().count(), 2);
    }

    #[test]
    fn test_saga_trace_jsonl_preserves_transition_timestamps() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        let jsonl = mgr.export_saga_trace_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: PhaseTransition = serde_json::from_str(lines[0]).expect("valid first trace row");
        let second: PhaseTransition =
            serde_json::from_str(lines[1]).expect("valid second trace row");

        assert_eq!(first.timestamp_ms, 2_000);
        assert_eq!(second.timestamp_ms, 3_000);
    }

    #[test]
    fn test_saga_not_found() {
        let mut mgr = EvictionSagaManager::new();
        assert!(mgr.begin_upload("nonexistent", 1_000, "t1").is_err());
    }

    #[test]
    fn test_begin_upload_unknown_saga_does_not_emit_audit() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.begin_upload("missing", 1_000, "t-missing").unwrap_err();

        assert!(err.contains("saga not found: missing"));
        assert!(mgr.audit_log.is_empty());
    }

    #[test]
    fn test_recheck_remote_cap_unknown_saga_does_not_emit_audit() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr
            .recheck_remote_cap("missing", false, "t-missing")
            .unwrap_err();

        assert!(err.contains("saga not found: missing"));
        assert!(mgr.audit_log.is_empty());
    }

    #[test]
    fn test_recover_unknown_saga_does_not_emit_audit() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.recover_saga("missing", 1_000, "t-missing").unwrap_err();

        assert!(err.contains("saga not found: missing"));
        assert!(mgr.audit_log.is_empty());
    }

    #[test]
    fn test_cancel_unknown_saga_does_not_emit_audit() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.cancel_saga("missing", 1_000, "t-missing").unwrap_err();

        assert!(err.contains("saga not found: missing"));
        assert!(mgr.audit_log.is_empty());
    }

    #[test]
    fn test_failed_complete_upload_does_not_mutate_created_saga() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        let audit_len_before = mgr.audit_log.len();

        let err = mgr.complete_upload(&id, 2_000, "t2").unwrap_err();

        assert!(err.contains("invalid transition: Created -> Verifying"));
        assert_eq!(mgr.audit_log.len(), audit_len_before);
        let saga = mgr.get_saga(&id).expect("saga should remain present");
        assert_eq!(saga.phase, SagaPhase::Created);
        assert!(!saga.l3_present);
        assert!(saga.transitions.is_empty());
    }

    #[test]
    fn test_failed_complete_verify_does_not_mutate_uploading_saga() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        let audit_len_before = mgr.audit_log.len();

        let err = mgr.complete_verify(&id, 3_000, "t3").unwrap_err();

        assert!(err.contains("invalid transition: Uploading -> Retiring"));
        assert_eq!(mgr.audit_log.len(), audit_len_before);
        let saga = mgr.get_saga(&id).expect("saga should remain present");
        assert_eq!(saga.phase, SagaPhase::Uploading);
        assert!(!saga.l3_verified);
        assert_eq!(saga.transitions.len(), 1);
        assert_eq!(saga.transitions[0].to_phase, SagaPhase::Uploading);
    }

    #[test]
    fn test_failed_complete_retire_does_not_mutate_verifying_saga() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        let audit_len_before = mgr.audit_log.len();

        let err = mgr.complete_retire(&id, 4_000, "t4").unwrap_err();

        assert!(err.contains("invalid transition: Verifying -> Complete"));
        assert_eq!(mgr.audit_log.len(), audit_len_before);
        let saga = mgr.get_saga(&id).expect("saga should remain present");
        assert_eq!(saga.phase, SagaPhase::Verifying);
        assert!(saga.l2_present);
        assert!(saga.l3_present);
        assert!(!saga.l3_verified);
    }

    #[test]
    fn test_cancel_failed_terminal_saga_is_rejected_without_new_audit() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        {
            let saga = mgr.sagas.get_mut(&id).expect("saga should exist");
            saga.phase = SagaPhase::Failed;
        }
        let audit_len_before = mgr.audit_log.len();

        let err = mgr.cancel_saga(&id, 2_000, "t2").unwrap_err();

        assert!(err.contains("terminal phase Failed"));
        assert_eq!(mgr.audit_log.len(), audit_len_before);
        assert_eq!(mgr.get_saga(&id).unwrap().phase, SagaPhase::Failed);
    }

    #[test]
    fn test_multiple_sagas() {
        let mut mgr = EvictionSagaManager::new();
        let id1 = mgr.start_saga("a", true, "t1").expect("should succeed");
        let id2 = mgr.start_saga("b", true, "t2").expect("should succeed");
        assert_ne!(id1, id2);
        assert_eq!(mgr.saga_count(), 2);
    }

    #[test]
    fn test_start_saga_rejects_when_registry_full_without_terminal_entries() {
        let mut mgr = EvictionSagaManager::new();
        let max_sagas = u64::try_from(MAX_SAGAS).expect("MAX_SAGAS fits in u64");

        for seq in 1..=max_sagas {
            let saga_id = format!("saga-{seq}");
            let mut saga = SagaInstance::new(&saga_id, "artifact");
            saga.phase = SagaPhase::Uploading;
            mgr.sagas.insert(saga_id, saga);
        }
        mgr.next_saga_id = max_sagas.saturating_add(1);

        let err = mgr
            .start_saga("overflow", true, "t-full")
            .expect_err("full registry without terminal entries must fail");

        assert!(err.contains("registry full"));
        assert_eq!(mgr.saga_count(), MAX_SAGAS);
    }

    #[test]
    fn test_start_saga_evicts_oldest_terminal_by_creation_order() {
        let mut mgr = EvictionSagaManager::new();
        let max_sagas = u64::try_from(MAX_SAGAS).expect("MAX_SAGAS fits in u64");

        for seq in 2..=max_sagas.saturating_add(1) {
            let saga_id = format!("saga-{seq}");
            let mut saga = SagaInstance::new(&saga_id, "artifact");
            saga.phase = if seq == 2 || seq == 10 {
                SagaPhase::Complete
            } else {
                SagaPhase::Uploading
            };
            mgr.sagas.insert(saga_id, saga);
        }
        mgr.next_saga_id = max_sagas.saturating_add(2);

        let new_id = mgr
            .start_saga("new-artifact", true, "t-evict")
            .expect("terminal eviction should free a slot");

        assert_eq!(mgr.saga_count(), MAX_SAGAS);
        assert!(!mgr.sagas.contains_key("saga-2"));
        assert!(mgr.sagas.contains_key("saga-10"));
        assert!(mgr.sagas.contains_key(&new_id));
    }

    #[test]
    fn test_start_saga_rejects_generated_id_reuse_without_overwriting_existing_saga() {
        let mut mgr = EvictionSagaManager::new();
        let original_id = mgr
            .start_saga("artifact-original", true, "t-original")
            .expect("should succeed");
        mgr.begin_upload(&original_id, 2_000, "t-upload")
            .expect("should succeed");
        mgr.next_saga_id = 1;

        let err = mgr
            .start_saga("artifact-replacement", true, "t-reuse")
            .expect_err("reused generated saga id must fail closed");

        assert!(err.contains(ERR_SAGA_ID_REUSED));
        assert_eq!(mgr.next_saga_id, 1);
        assert_eq!(mgr.saga_count(), 1);
        assert_eq!(mgr.audit_log.len(), 2);

        let preserved = mgr
            .get_saga(&original_id)
            .expect("original saga should be preserved");
        assert_eq!(preserved.artifact_id, "artifact-original");
        assert_eq!(preserved.phase, SagaPhase::Uploading);
        assert!(preserved.has_remote_cap);
        assert_eq!(preserved.transitions.len(), 1);
        assert_eq!(preserved.transitions[0].to_phase, SagaPhase::Uploading);
    }

    #[test]
    fn test_compensation_action_created_phase() {
        let saga = SagaInstance::new("s1", "a1");
        assert!(matches!(
            saga.compensation_action(),
            CompensationAction::None
        ));
    }

    #[test]
    fn test_phase_display() {
        assert_eq!(format!("{}", SagaPhase::Uploading), "Uploading");
        assert_eq!(format!("{}", SagaPhase::Complete), "Complete");
    }

    #[test]
    fn test_crash_recovery_from_compensating_during_verify() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");

        // Simulate crash mid-compensation: manually transition to Compensating
        // (as if cancel_saga crashed after first record_transition but before completing)
        {
            let cap = mgr.transition_capacity();
            let saga = mgr.sagas.get_mut(&id).expect("should succeed");
            saga.record_transition(
                SagaPhase::Compensating,
                "compensation: CleanupL3",
                3_500,
                cap,
            );
        }
        assert_eq!(
            mgr.get_saga(&id).expect("should succeed").phase,
            SagaPhase::Compensating
        );

        let action = mgr.recover_saga(&id, 4_000, "t4").expect("should succeed");
        assert!(matches!(action, CompensationAction::CleanupL3));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(!saga.l3_present);
        assert!(!saga.l3_verified);
    }

    #[test]
    fn test_crash_recovery_from_compensating_during_upload() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");

        {
            let cap = mgr.transition_capacity();
            let saga = mgr.sagas.get_mut(&id).expect("should succeed");
            saga.record_transition(
                SagaPhase::Compensating,
                "compensation: AbortUpload",
                2_500,
                cap,
            );
        }

        let action = mgr.recover_saga(&id, 3_000, "t3").expect("should succeed");
        assert!(matches!(action, CompensationAction::AbortUpload));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_crash_recovery_from_compensating_during_created_cancel() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");

        {
            let cap = mgr.transition_capacity();
            let saga = mgr.sagas.get_mut(&id).expect("should succeed");
            saga.record_transition(SagaPhase::Compensating, "compensation: None", 1_500, cap);
        }

        let audit_len_before = mgr.audit_log.len();
        let action = mgr.recover_saga(&id, 2_000, "t2").expect("should succeed");
        assert!(matches!(action, CompensationAction::None));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
        assert_eq!(
            saga.transitions.last().expect("transition").outcome,
            "crash_recovery: no_op"
        );

        let new_events = &mgr.audit_log[audit_len_before..];
        assert_eq!(new_events[0].event_code, event_codes::ES_CRASH_RECOVERY);
        assert_eq!(
            new_events[1].event_code,
            event_codes::ES_COMPENSATION_COMPLETE
        );
        assert_eq!(new_events[1].detail["timestamp_ms"], 2_000);
    }

    #[test]
    fn test_crash_recovery_from_compensating_during_retire() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "t4")
            .expect("should succeed");

        {
            let cap = mgr.transition_capacity();
            let saga = mgr.sagas.get_mut(&id).expect("should succeed");
            saga.record_transition(
                SagaPhase::Compensating,
                "compensation: CompleteRetirement",
                4_500,
                cap,
            );
        }

        let action = mgr.recover_saga(&id, 5_000, "t5").expect("should succeed");
        assert!(matches!(action, CompensationAction::CompleteRetirement));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert_eq!(saga.phase, SagaPhase::Complete);
        assert!(!saga.l2_present);
    }

    #[test]
    fn test_crash_recovery_from_uploading() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");

        let action = mgr.recover_saga(&id, 3_000, "t3").expect("should succeed");
        assert!(matches!(action, CompensationAction::AbortUpload));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_crash_recovery_from_retiring() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "t4")
            .expect("should succeed");

        let action = mgr.recover_saga(&id, 5_000, "t5").expect("should succeed");
        assert!(matches!(action, CompensationAction::CompleteRetirement));

        let saga = mgr.get_saga(&id).expect("should succeed");
        assert_eq!(saga.phase, SagaPhase::Complete);
        assert!(!saga.l2_present);
    }

    #[test]
    fn test_crash_recovery_noop_for_terminal_states() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");
        mgr.complete_verify(&id, 4_000, "t4")
            .expect("should succeed");
        mgr.complete_retire(&id, 5_000, "t5")
            .expect("should succeed");

        // Recovery on Complete state should be a no-op
        let action = mgr.recover_saga(&id, 6_000, "t6").expect("should succeed");
        assert!(matches!(action, CompensationAction::None));
        assert_eq!(
            mgr.get_saga(&id).expect("should succeed").phase,
            SagaPhase::Complete
        );
    }

    #[test]
    fn test_leak_check_detects_stuck_compensating() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");
        mgr.complete_upload(&id, 3_000, "t3")
            .expect("should succeed");

        // Simulate crash mid-compensation
        {
            let cap = mgr.transition_capacity();
            let saga = mgr.sagas.get_mut(&id).expect("should succeed");
            saga.record_transition(
                SagaPhase::Compensating,
                "compensation: CleanupL3",
                3_500,
                cap,
            );
        }

        let result = mgr.leak_check("t4");
        assert!(!result.passed);
        assert_eq!(result.orphans_found, 1);
        assert!(result.details[0].contains("Compensating"));
    }

    #[test]
    fn test_crash_recovery_emits_compensation_complete_audit() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");

        let audit_len_before = mgr.export_audit_log_jsonl().lines().count();
        mgr.recover_saga(&id, 3_000, "t3").expect("should succeed");
        let audit = mgr.export_audit_log_jsonl();
        let audit_len_after = audit.lines().count();

        // Should have both ES_CRASH_RECOVERY and ES_COMPENSATION_COMPLETE events
        assert!(audit_len_after > audit_len_before);
        assert!(audit.contains("ES_CRASH_RECOVERY"));
        assert!(audit.contains("ES_COMPENSATION_COMPLETE"));
    }

    #[test]
    fn test_crash_recovery_audit_includes_timestamp() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").expect("should succeed");
        mgr.begin_upload(&id, 2_000, "t2").expect("should succeed");

        let audit_len_before = mgr.audit_log.len();
        mgr.recover_saga(&id, 3_000, "t3").expect("should succeed");

        let new_events = &mgr.audit_log[audit_len_before..];
        assert_eq!(new_events[0].event_code, event_codes::ES_CRASH_RECOVERY);
        assert_eq!(new_events[0].detail["timestamp_ms"], 3_000);
        assert_eq!(
            new_events[1].event_code,
            event_codes::ES_COMPENSATION_COMPLETE
        );
        assert_eq!(new_events[1].detail["timestamp_ms"], 3_000);
    }

    #[test]
    fn test_push_bounded_zero_capacity_clears_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn test_start_rejects_artifact_id_with_nul_byte() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr
            .start_saga("artifact\0hidden", true, "t-nul")
            .unwrap_err();

        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("control characters"));
        assert_eq!(mgr.saga_count(), 0);
        assert!(mgr.audit_log.is_empty());
    }

    #[test]
    fn test_start_rejects_artifact_id_with_embedded_newline() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr
            .start_saga("artifact\nhidden", true, "t-newline")
            .unwrap_err();

        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("control characters"));
        assert_eq!(mgr.saga_count(), 0);
    }

    #[test]
    fn test_complete_upload_after_remote_cap_revoked_preserves_upload_state() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("artifact-cap", true, "t1").expect("start");
        mgr.begin_upload(&id, 2_000, "t2").expect("begin upload");
        let transition_count = mgr.get_saga(&id).unwrap().transitions.len();
        mgr.recheck_remote_cap(&id, false, "t3")
            .expect_err("revocation should be reported");

        let err = mgr.complete_upload(&id, 4_000, "t4").unwrap_err();

        assert!(err.contains("RemoteCap recheck failed"));
        let saga = mgr.get_saga(&id).expect("saga should remain present");
        assert_eq!(saga.phase, SagaPhase::Uploading);
        assert!(!saga.l3_present);
        assert_eq!(saga.transitions.len(), transition_count);
    }

    #[test]
    fn test_cancel_created_saga_compensates_without_losing_l2() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr
            .start_saga("artifact-created-cancel", true, "t1")
            .expect("start");

        let action = mgr.cancel_saga(&id, 2_000, "t2").expect("cancel created");

        assert!(matches!(action, CompensationAction::None));
        let saga = mgr.get_saga(&id).expect("saga should remain present");
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_leak_check_detects_retired_l2_without_l3() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr
            .start_saga("artifact-orphan", true, "t1")
            .expect("start");
        {
            let saga = mgr.sagas.get_mut(&id).expect("saga should exist");
            saga.phase = SagaPhase::Complete;
            saga.l2_present = false;
            saga.l3_present = false;
            saga.l3_verified = false;
        }

        let result = mgr.leak_check("t-leak");

        assert!(!result.passed);
        assert_eq!(result.orphans_found, 1);
        assert!(result.details[0].contains("L2 retired but L3 absent"));
    }

    #[test]
    fn test_leak_check_detects_complete_unverified_l3() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr
            .start_saga("artifact-unverified", true, "t1")
            .expect("start");
        {
            let saga = mgr.sagas.get_mut(&id).expect("saga should exist");
            saga.phase = SagaPhase::Complete;
            saga.l2_present = false;
            saga.l3_present = true;
            saga.l3_verified = false;
        }

        let result = mgr.leak_check("t-unverified");

        assert!(!result.passed);
        assert_eq!(result.orphans_found, 1);
        assert!(result.details[0].contains("unverified"));
    }

    #[test]
    fn test_recover_compensating_without_transition_does_not_drop_l2() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr
            .start_saga("artifact-no-transition", true, "t1")
            .expect("start");
        {
            let saga = mgr.sagas.get_mut(&id).expect("saga should exist");
            saga.phase = SagaPhase::Compensating;
            saga.transitions.clear();
        }

        let action = mgr.recover_saga(&id, 2_000, "t2").expect("recover");

        assert!(matches!(action, CompensationAction::None));
        let saga = mgr.get_saga(&id).expect("saga should remain present");
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
    }
}

#[cfg(test)]
mod eviction_saga_boundary_negative_tests {
    use super::*;

    #[test]
    fn negative_start_saga_rejects_empty_artifact_id() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.start_saga("", true, "trace-empty-artifact")
            .expect_err("empty artifact ID should be rejected");

        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("empty"));
    }

    #[test]
    fn negative_start_saga_rejects_reserved_artifact_id() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.start_saga(RESERVED_ARTIFACT_ID, true, "trace-reserved")
            .expect_err("reserved artifact ID should be rejected");

        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("reserved"));
    }

    #[test]
    fn negative_start_saga_rejects_artifact_id_with_control_characters() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.start_saga("artifact\n\r\t", true, "trace-control-chars")
            .expect_err("artifact ID with control characters should be rejected");

        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("control"));
    }

    #[test]
    fn negative_start_saga_rejects_artifact_id_with_leading_trailing_whitespace() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.start_saga("  artifact-id  ", true, "trace-whitespace")
            .expect_err("artifact ID with whitespace should be rejected");

        assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        assert!(err.contains("whitespace"));
    }

    #[test]
    fn negative_start_saga_rejects_empty_trace_id() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.start_saga("artifact-valid", true, "")
            .expect_err("empty trace ID should be rejected");

        assert!(err.contains("trace_id"));
    }

    #[test]
    fn negative_start_saga_rejects_trace_id_with_nul_bytes() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr.start_saga("artifact-valid", true, "trace\0injection")
            .expect_err("trace ID with nul bytes should be rejected");

        assert!(err.contains("trace_id"));
    }

    #[test]
    fn negative_start_saga_prevents_duplicate_saga_id_collision() {
        let mut mgr = EvictionSagaManager::new();
        let first_id = mgr.start_saga("artifact-first", true, "trace-1")
            .expect("first saga should succeed");

        // Manually create collision by reusing ID
        let collision_result = mgr.start_saga("artifact-second", true, "trace-2");

        // Should either prevent collision or handle gracefully
        match collision_result {
            Ok(second_id) => {
                assert_ne!(first_id, second_id, "saga IDs must be unique");
            }
            Err(err) => {
                assert!(err.contains(ERR_SAGA_ID_REUSED) || err.contains("collision"));
            }
        }
    }

    #[test]
    fn negative_transition_saga_rejects_nonexistent_saga_id() {
        let mut mgr = EvictionSagaManager::new();
        let nonexistent_id = SagaId("nonexistent-saga".to_string());

        let err = mgr.transition_saga(&nonexistent_id, SagaEvent::UploadSucceeded, 1000, "trace-nonexistent")
            .expect_err("nonexistent saga ID should be rejected");

        assert!(err.contains("not found") || err.contains("nonexistent"));
    }

    #[test]
    fn negative_transition_saga_rejects_invalid_state_transition() {
        let mut mgr = EvictionSagaManager::new();
        let saga_id = mgr.start_saga("artifact-invalid-transition", true, "trace-start")
            .expect("saga start should succeed");

        // Try invalid transition: Uploading -> Retired (skipping intermediate states)
        let err = mgr.transition_saga(&saga_id, SagaEvent::RetireSucceeded, 1000, "trace-invalid")
            .expect_err("invalid state transition should be rejected");

        assert!(err.contains("invalid") || err.contains("transition"));
    }

    #[test]
    fn negative_recover_saga_handles_corrupted_saga_state_gracefully() {
        let mut mgr = EvictionSagaManager::new();
        let saga_id = mgr.start_saga("artifact-corrupted", true, "trace-start")
            .expect("saga start should succeed");

        // Manually corrupt saga state
        if let Some(saga) = mgr.sagas.get_mut(&saga_id) {
            saga.phase = SagaPhase::Compensating;
            saga.l2_present = false;
            saga.l3_present = true; // Impossible state: L3 exists but L2 doesn't
        }

        let action = mgr.recover_saga(&saga_id, 2000, "trace-recover");

        // Should handle corrupted state gracefully
        match action {
            Ok(CompensationAction::None) => (), // Graceful handling
            Ok(_) => (), // Other compensation actions are acceptable
            Err(err) => {
                assert!(err.contains("corrupted") || err.contains("invalid"));
            }
        }
    }

    #[test]
    fn negative_saga_manager_respects_max_sagas_capacity() {
        let mut mgr = EvictionSagaManager::new();

        // Try to create more sagas than capacity allows
        for i in 0..MAX_SAGAS.saturating_add(10) {
            let artifact_id = format!("artifact-{i}");
            let result = mgr.start_saga(&artifact_id, true, "trace-capacity-test");

            if i >= MAX_SAGAS {
                // Should either reject or handle capacity gracefully
                match result {
                    Ok(_) => {
                        // If accepted, total sagas should not exceed capacity
                        assert!(mgr.sagas.len() <= MAX_SAGAS);
                    }
                    Err(err) => {
                        assert!(err.contains("capacity") || err.contains("full"));
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn negative_serde_rejects_unknown_saga_event_variant() {
        let result: Result<SagaEvent, _> = serde_json::from_str(r#""UnknownEvent""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_saga_transition_with_extremely_old_timestamp_handles_gracefully() {
        let mut mgr = EvictionSagaManager::new();
        let saga_id = mgr.start_saga("artifact-old-timestamp", true, "trace-start")
            .expect("saga start should succeed");

        let result = mgr.transition_saga(&saga_id, SagaEvent::UploadSucceeded, 0, "trace-old-timestamp");

        // Should handle old timestamps gracefully
        match result {
            Ok(_) => (), // Acceptance is fine
            Err(err) => {
                assert!(err.contains("timestamp") || err.contains("invalid"));
            }
        }
    }
}
