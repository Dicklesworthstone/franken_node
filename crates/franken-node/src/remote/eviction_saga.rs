//! bd-1ru2: Cancel-safe eviction saga (upload -> verify -> retire).
//!
//! Multi-step saga for L2->L3 artifact lifecycle with deterministic
//! compensations. Guarantees no partial retire on cancellation/crash.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Constants ────────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "es-v1.0";

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

    fn record_transition(&mut self, to_phase: SagaPhase, outcome: &str) {
        let from = self.phase;
        self.transitions.push(PhaseTransition {
            saga_id: self.saga_id.clone(),
            artifact_id: self.artifact_id.clone(),
            from_phase: from,
            to_phase,
            timestamp_ms: 0, // Caller provides real timestamp
            outcome: outcome.to_string(),
        });
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
    next_saga_id: u64,
}

impl EvictionSagaManager {
    pub fn new() -> Self {
        Self {
            sagas: BTreeMap::new(),
            audit_log: Vec::new(),
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
        self.audit_log.push(EsAuditRecord {
            event_code: event_code.to_string(),
            trace_id: trace_id.to_string(),
            detail,
        });
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

    /// Start a new eviction saga.
    pub fn start_saga(
        &mut self,
        artifact_id: &str,
        has_remote_cap: bool,
        trace_id: &str,
    ) -> Result<String, String> {
        if !has_remote_cap {
            return Err("RemoteCap required for upload phase".to_string());
        }

        let saga_id = format!("saga-{}", self.next_saga_id);
        self.next_saga_id += 1;

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
    pub fn begin_upload(&mut self, saga_id: &str, trace_id: &str) -> Result<(), String> {
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.phase != SagaPhase::Created {
            return Err(format!("invalid transition: {} -> Uploading", saga.phase));
        }
        Self::ensure_remote_cap_active(saga, saga_id, "begin_upload")?;

        saga.record_transition(SagaPhase::Uploading, "upload_started");
        self.log(
            event_codes::ES_PHASE_UPLOAD,
            trace_id,
            serde_json::json!({"saga_id": saga_id}),
        );
        Ok(())
    }

    /// Complete upload and advance to Verifying.
    pub fn complete_upload(&mut self, saga_id: &str, trace_id: &str) -> Result<(), String> {
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.phase != SagaPhase::Uploading {
            return Err(format!("invalid transition: {} -> Verifying", saga.phase));
        }
        Self::ensure_remote_cap_active(saga, saga_id, "complete_upload")?;

        saga.l3_present = true;
        saga.record_transition(SagaPhase::Verifying, "upload_complete");
        self.log(
            event_codes::ES_PHASE_VERIFY,
            trace_id,
            serde_json::json!({"saga_id": saga_id}),
        );
        Ok(())
    }

    /// Complete verification and advance to Retiring.
    pub fn complete_verify(&mut self, saga_id: &str, trace_id: &str) -> Result<(), String> {
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.phase != SagaPhase::Verifying {
            return Err(format!("invalid transition: {} -> Retiring", saga.phase));
        }
        Self::ensure_remote_cap_active(saga, saga_id, "complete_verify")?;

        saga.l3_verified = true;
        saga.record_transition(SagaPhase::Retiring, "verification_passed");
        self.log(
            event_codes::ES_PHASE_RETIRE,
            trace_id,
            serde_json::json!({"saga_id": saga_id}),
        );
        Ok(())
    }

    /// Complete retirement (L2 removed).
    pub fn complete_retire(&mut self, saga_id: &str, trace_id: &str) -> Result<(), String> {
        let saga = self
            .sagas
            .get_mut(saga_id)
            .ok_or_else(|| format!("saga not found: {saga_id}"))?;

        if saga.phase != SagaPhase::Retiring {
            return Err(format!("invalid transition: {} -> Complete", saga.phase));
        }
        Self::ensure_remote_cap_active(saga, saga_id, "complete_retire")?;

        saga.l2_present = false;
        saga.record_transition(SagaPhase::Complete, "retirement_complete");
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
        trace_id: &str,
    ) -> Result<CompensationAction, String> {
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

        self.log(event_codes::ES_CANCEL_REQUESTED, trace_id,
            serde_json::json!({"saga_id": saga_id, "phase": phase_str, "action": format!("{action}")}));

        // Re-borrow mutably for state updates
        let saga = self
            .sagas
            .get_mut(saga_id)
            .expect("saga existence verified above");
        // Re-check after mutable borrow as a defensive invariant.
        Self::ensure_cancel_allowed(saga.phase, saga_id)?;
        saga.record_transition(SagaPhase::Compensating, &format!("compensation: {action}"));

        // Apply compensation
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

        saga.record_transition(SagaPhase::Compensated, "compensation_complete");
        // Drop mutable borrow before logging
        let action_str = format!("{action}");
        self.log(
            event_codes::ES_COMPENSATION_COMPLETE,
            trace_id,
            serde_json::json!({"saga_id": saga_id, "action": action_str}),
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
        trace_id: &str,
    ) -> Result<CompensationAction, String> {
        let action = {
            let saga = self
                .sagas
                .get(saga_id)
                .ok_or_else(|| format!("saga not found: {saga_id}"))?;

            // If crashed mid-compensation, recover the original action from transition history
            let action = if saga.phase == SagaPhase::Compensating {
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

            self.log(event_codes::ES_CRASH_RECOVERY, trace_id,
                serde_json::json!({"saga_id": saga_id, "phase": format!("{}", saga.phase), "action": format!("{action}")}));
            action
        };

        // Apply the compensation (idempotent operations safe to re-execute)
        match &action {
            CompensationAction::AbortUpload => {
                let saga = self
                    .sagas
                    .get_mut(saga_id)
                    .expect("saga existence verified above");
                saga.l3_present = false;
                saga.record_transition(SagaPhase::Compensated, "crash_recovery: abort_upload");
            }
            CompensationAction::CleanupL3 => {
                let saga = self
                    .sagas
                    .get_mut(saga_id)
                    .expect("saga existence verified above");
                saga.l3_present = false;
                saga.l3_verified = false;
                saga.record_transition(SagaPhase::Compensated, "crash_recovery: cleanup_l3");
            }
            CompensationAction::CompleteRetirement => {
                let saga = self
                    .sagas
                    .get_mut(saga_id)
                    .expect("saga existence verified above");
                saga.l2_present = false;
                saga.record_transition(SagaPhase::Complete, "crash_recovery: complete_retirement");
            }
            CompensationAction::None => {}
        }

        if !matches!(action, CompensationAction::None) {
            self.log(
                event_codes::ES_COMPENSATION_COMPLETE,
                trace_id,
                serde_json::json!({"saga_id": saga_id, "action": format!("{action}"), "via": "crash_recovery"}),
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
        let content = serde_json::to_string(&self.sagas).unwrap_or_default();
        format!(
            "{:x}",
            Sha256::digest([b"eviction_saga_content_v1:" as &[u8], content.as_bytes()].concat())
        )
    }

    /// Saga count.
    pub fn saga_count(&self) -> usize {
        self.sagas.len()
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
    }

    #[test]
    fn test_full_saga_success() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("artifact-1", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        mgr.complete_verify(&id, "t4").unwrap();
        mgr.complete_retire(&id, "t5").unwrap();

        let saga = mgr.get_saga(&id).unwrap();
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
    fn test_remote_cap_recheck_blocks_begin_upload_until_restored() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();

        let err = mgr.recheck_remote_cap(&id, false, "t2").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr.begin_upload(&id, "t3").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        mgr.recheck_remote_cap(&id, true, "t4").unwrap();
        mgr.begin_upload(&id, "t5").unwrap();
    }

    #[test]
    fn test_remote_cap_recheck_blocks_complete_upload_until_restored() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();

        let err = mgr.recheck_remote_cap(&id, false, "t3").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr.complete_upload(&id, "t4").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        mgr.recheck_remote_cap(&id, true, "t5").unwrap();
        mgr.complete_upload(&id, "t6").unwrap();
    }

    #[test]
    fn test_remote_cap_recheck_blocks_complete_verify_until_restored() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();

        let err = mgr.recheck_remote_cap(&id, false, "t4").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr.complete_verify(&id, "t5").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        mgr.recheck_remote_cap(&id, true, "t6").unwrap();
        mgr.complete_verify(&id, "t7").unwrap();
    }

    #[test]
    fn test_remote_cap_recheck_blocks_complete_retire_until_restored() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        mgr.complete_verify(&id, "t4").unwrap();

        let err = mgr.recheck_remote_cap(&id, false, "t5").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr.complete_retire(&id, "t6").unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        mgr.recheck_remote_cap(&id, true, "t7").unwrap();
        mgr.complete_retire(&id, "t8").unwrap();
    }

    #[test]
    fn test_invalid_transition_rejected() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        // Can't go directly to verify without upload
        let err = mgr.complete_upload(&id, "t2").unwrap_err();
        assert!(err.contains("invalid transition"));
    }

    #[test]
    fn test_cancel_during_upload() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        let action = mgr.cancel_saga(&id, "t3").unwrap();
        assert!(matches!(action, CompensationAction::AbortUpload));

        let saga = mgr.get_saga(&id).unwrap();
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_cancel_during_verify() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        let action = mgr.cancel_saga(&id, "t4").unwrap();
        assert!(matches!(action, CompensationAction::CleanupL3));

        let saga = mgr.get_saga(&id).unwrap();
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_cancel_during_retire() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        mgr.complete_verify(&id, "t4").unwrap();
        let action = mgr.cancel_saga(&id, "t5").unwrap();
        assert!(matches!(action, CompensationAction::CompleteRetirement));

        let saga = mgr.get_saga(&id).unwrap();
        assert!(!saga.l2_present); // Retirement completed
    }

    #[test]
    fn test_cancel_terminal_complete_rejected() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        mgr.complete_verify(&id, "t4").unwrap();
        mgr.complete_retire(&id, "t5").unwrap();

        let err = mgr.cancel_saga(&id, "t6").unwrap_err();
        assert!(err.contains("terminal phase Complete"));
    }

    #[test]
    fn test_cancel_terminal_compensated_rejected() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.cancel_saga(&id, "t3").unwrap();

        let err = mgr.cancel_saga(&id, "t4").unwrap_err();
        assert!(err.contains("terminal phase Compensated"));
    }

    #[test]
    fn test_leak_check_passes_after_success() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        mgr.complete_verify(&id, "t4").unwrap();
        mgr.complete_retire(&id, "t5").unwrap();

        let result = mgr.leak_check("t6");
        assert!(result.passed);
        assert_eq!(result.orphans_found, 0);
    }

    #[test]
    fn test_leak_check_passes_after_compensation() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.cancel_saga(&id, "t3").unwrap();

        let result = mgr.leak_check("t4");
        assert!(result.passed);
    }

    #[test]
    fn test_crash_recovery_identifies_action() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();

        let action = mgr.recover_saga(&id, "t4").unwrap();
        assert!(matches!(action, CompensationAction::CleanupL3));
    }

    #[test]
    fn test_content_hash_deterministic() {
        let mut m1 = EvictionSagaManager::new();
        m1.start_saga("a", true, "t1").unwrap();
        let mut m2 = EvictionSagaManager::new();
        m2.start_saga("a", true, "t1").unwrap();
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn test_audit_log_jsonl() {
        let mut mgr = EvictionSagaManager::init("t1");
        mgr.start_saga("a", true, "t2").unwrap();
        let jsonl = mgr.export_audit_log_jsonl();
        assert_eq!(jsonl.lines().count(), 2);
    }

    #[test]
    fn test_saga_trace_jsonl() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        let jsonl = mgr.export_saga_trace_jsonl();
        assert_eq!(jsonl.lines().count(), 2);
    }

    #[test]
    fn test_saga_not_found() {
        let mut mgr = EvictionSagaManager::new();
        assert!(mgr.begin_upload("nonexistent", "t1").is_err());
    }

    #[test]
    fn test_multiple_sagas() {
        let mut mgr = EvictionSagaManager::new();
        let id1 = mgr.start_saga("a", true, "t1").unwrap();
        let id2 = mgr.start_saga("b", true, "t2").unwrap();
        assert_ne!(id1, id2);
        assert_eq!(mgr.saga_count(), 2);
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
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();

        // Simulate crash mid-compensation: manually transition to Compensating
        // (as if cancel_saga crashed after first record_transition but before completing)
        {
            let saga = mgr.sagas.get_mut(&id).unwrap();
            saga.record_transition(SagaPhase::Compensating, "compensation: CleanupL3");
        }
        assert_eq!(mgr.get_saga(&id).unwrap().phase, SagaPhase::Compensating);

        let action = mgr.recover_saga(&id, "t4").unwrap();
        assert!(matches!(action, CompensationAction::CleanupL3));

        let saga = mgr.get_saga(&id).unwrap();
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(!saga.l3_present);
        assert!(!saga.l3_verified);
    }

    #[test]
    fn test_crash_recovery_from_compensating_during_upload() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();

        {
            let saga = mgr.sagas.get_mut(&id).unwrap();
            saga.record_transition(SagaPhase::Compensating, "compensation: AbortUpload");
        }

        let action = mgr.recover_saga(&id, "t3").unwrap();
        assert!(matches!(action, CompensationAction::AbortUpload));

        let saga = mgr.get_saga(&id).unwrap();
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(saga.l2_present);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_crash_recovery_from_compensating_during_retire() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        mgr.complete_verify(&id, "t4").unwrap();

        {
            let saga = mgr.sagas.get_mut(&id).unwrap();
            saga.record_transition(SagaPhase::Compensating, "compensation: CompleteRetirement");
        }

        let action = mgr.recover_saga(&id, "t5").unwrap();
        assert!(matches!(action, CompensationAction::CompleteRetirement));

        let saga = mgr.get_saga(&id).unwrap();
        assert_eq!(saga.phase, SagaPhase::Complete);
        assert!(!saga.l2_present);
    }

    #[test]
    fn test_crash_recovery_from_uploading() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();

        let action = mgr.recover_saga(&id, "t3").unwrap();
        assert!(matches!(action, CompensationAction::AbortUpload));

        let saga = mgr.get_saga(&id).unwrap();
        assert_eq!(saga.phase, SagaPhase::Compensated);
        assert!(!saga.l3_present);
    }

    #[test]
    fn test_crash_recovery_from_retiring() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        mgr.complete_verify(&id, "t4").unwrap();

        let action = mgr.recover_saga(&id, "t5").unwrap();
        assert!(matches!(action, CompensationAction::CompleteRetirement));

        let saga = mgr.get_saga(&id).unwrap();
        assert_eq!(saga.phase, SagaPhase::Complete);
        assert!(!saga.l2_present);
    }

    #[test]
    fn test_crash_recovery_noop_for_terminal_states() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();
        mgr.complete_verify(&id, "t4").unwrap();
        mgr.complete_retire(&id, "t5").unwrap();

        // Recovery on Complete state should be a no-op
        let action = mgr.recover_saga(&id, "t6").unwrap();
        assert!(matches!(action, CompensationAction::None));
        assert_eq!(mgr.get_saga(&id).unwrap().phase, SagaPhase::Complete);
    }

    #[test]
    fn test_leak_check_detects_stuck_compensating() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();
        mgr.complete_upload(&id, "t3").unwrap();

        // Simulate crash mid-compensation
        {
            let saga = mgr.sagas.get_mut(&id).unwrap();
            saga.record_transition(SagaPhase::Compensating, "compensation: CleanupL3");
        }

        let result = mgr.leak_check("t4");
        assert!(!result.passed);
        assert_eq!(result.orphans_found, 1);
        assert!(result.details[0].contains("Compensating"));
    }

    #[test]
    fn test_crash_recovery_emits_compensation_complete_audit() {
        let mut mgr = EvictionSagaManager::new();
        let id = mgr.start_saga("a", true, "t1").unwrap();
        mgr.begin_upload(&id, "t2").unwrap();

        let audit_len_before = mgr.export_audit_log_jsonl().lines().count();
        mgr.recover_saga(&id, "t3").unwrap();
        let audit = mgr.export_audit_log_jsonl();
        let audit_len_after = audit.lines().count();

        // Should have both ES_CRASH_RECOVERY and ES_COMPENSATION_COMPLETE events
        assert!(audit_len_after > audit_len_before);
        assert!(audit.contains("ES_CRASH_RECOVERY"));
        assert!(audit.contains("ES_COMPENSATION_COMPLETE"));
    }
}
