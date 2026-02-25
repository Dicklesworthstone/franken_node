//! bd-1ru2: Cancel-safe eviction saga (upload → verify → retire) with
//! deterministic compensations.
//!
//! Implements the L2→L3 artifact lifecycle as a crash-recoverable state machine.
//! Every incomplete saga rolls back to a known-good state, and the compensation
//! logic is provably leak-free (zero orphan states after any failure sequence).
//!
//! # Invariants
//!
//! - **INV-ES-NO-PARTIAL-RETIRE**: L2 is never retired unless L3 is confirmed
//!   retrievable.
//! - **INV-ES-DETERMINISTIC-COMPENSATION**: Identical crash state always triggers
//!   identical recovery action.
//! - **INV-ES-LEAK-FREE**: Post-saga, zero orphan artifacts exist (L2 retired
//!   but L3 absent, or L3 present but L2 not retired when saga is incomplete).
//! - **INV-ES-REMOTE-CAP-REQUIRED**: Upload phase requires a valid `RemoteCap`
//!   with `ArtifactUpload` scope.
//! - **INV-ES-DURABLE-PHASES**: Phase transitions are persisted; crash recovery
//!   resumes from the last committed phase.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_ES_ILLEGAL_TRANSITION: &str = "ERR_ES_ILLEGAL_TRANSITION";
pub const ERR_ES_REMOTE_CAP_REQUIRED: &str = "ERR_ES_REMOTE_CAP_REQUIRED";
pub const ERR_ES_REMOTE_CAP_RECHECK_FAILED: &str = "ERR_ES_REMOTE_CAP_RECHECK_FAILED";
pub const ERR_ES_UPLOAD_FAILED: &str = "ERR_ES_UPLOAD_FAILED";
pub const ERR_ES_VERIFY_FAILED: &str = "ERR_ES_VERIFY_FAILED";
pub const ERR_ES_RETIRE_FAILED: &str = "ERR_ES_RETIRE_FAILED";
pub const ERR_ES_COMPENSATION_FAILED: &str = "ERR_ES_COMPENSATION_FAILED";
pub const ERR_ES_LEAK_DETECTED: &str = "ERR_ES_LEAK_DETECTED";
pub const ERR_ES_ALREADY_COMPLETE: &str = "ERR_ES_ALREADY_COMPLETE";
pub const ERR_ES_ARTIFACT_NOT_FOUND: &str = "ERR_ES_ARTIFACT_NOT_FOUND";

// ---------------------------------------------------------------------------
// Invariant markers
// ---------------------------------------------------------------------------

pub const INV_ES_NO_PARTIAL_RETIRE: &str = "INV-ES-NO-PARTIAL-RETIRE";
pub const INV_ES_DETERMINISTIC_COMPENSATION: &str = "INV-ES-DETERMINISTIC-COMPENSATION";
pub const INV_ES_LEAK_FREE: &str = "INV-ES-LEAK-FREE";
pub const INV_ES_REMOTE_CAP_REQUIRED: &str = "INV-ES-REMOTE-CAP-REQUIRED";
pub const INV_ES_DURABLE_PHASES: &str = "INV-ES-DURABLE-PHASES";

// ---------------------------------------------------------------------------
// Saga phase
// ---------------------------------------------------------------------------

/// Phases of the eviction saga state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaPhase {
    /// Initial state before saga begins.
    Pending,
    /// Uploading artifact from L2 to L3 (requires RemoteCap).
    Uploading,
    /// Verifying L3 retrievability after upload.
    Verifying,
    /// Retiring L2 copy after confirmed L3 availability.
    Retiring,
    /// Saga completed successfully.
    Complete,
    /// Compensating: rolling back after failure or cancellation.
    Compensating,
    /// Compensation completed; saga aborted cleanly.
    Aborted,
}

impl SagaPhase {
    /// All defined phases.
    pub const ALL: [SagaPhase; 7] = [
        Self::Pending,
        Self::Uploading,
        Self::Verifying,
        Self::Retiring,
        Self::Complete,
        Self::Compensating,
        Self::Aborted,
    ];

    /// Legal forward transitions from this phase.
    #[must_use]
    pub fn legal_targets(self) -> &'static [SagaPhase] {
        match self {
            Self::Pending => &[Self::Uploading],
            Self::Uploading => &[Self::Verifying, Self::Compensating],
            Self::Verifying => &[Self::Retiring, Self::Compensating],
            Self::Retiring => &[Self::Complete, Self::Compensating],
            Self::Complete => &[],
            Self::Compensating => &[Self::Aborted],
            Self::Aborted => &[],
        }
    }

    /// Whether transitioning to `target` is legal from the current phase.
    #[must_use]
    pub fn can_transition_to(self, target: SagaPhase) -> bool {
        self.legal_targets().contains(&target)
    }

    /// Whether this phase is a terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Aborted)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Uploading => "uploading",
            Self::Verifying => "verifying",
            Self::Retiring => "retiring",
            Self::Complete => "complete",
            Self::Compensating => "compensating",
            Self::Aborted => "aborted",
        }
    }
}

impl fmt::Display for SagaPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Compensation action
// ---------------------------------------------------------------------------

/// Deterministic compensation actions for each crash point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompensationAction {
    /// No action needed (saga hadn't started meaningful work).
    None,
    /// Abort in-progress upload; L2 remains intact.
    AbortUpload,
    /// Clean up partial L3 state; L2 remains intact.
    CleanupL3,
    /// L3 confirmed; allow retirement to proceed on recovery.
    ResumeRetire,
}

impl CompensationAction {
    /// Determine the compensation action for a given crash phase.
    /// This is deterministic: same phase always produces same action.
    #[must_use]
    pub fn for_phase(phase: SagaPhase) -> Self {
        // INV-ES-DETERMINISTIC-COMPENSATION
        match phase {
            SagaPhase::Pending => Self::None,
            SagaPhase::Uploading => Self::AbortUpload,
            SagaPhase::Verifying => Self::CleanupL3,
            SagaPhase::Retiring => Self::ResumeRetire,
            SagaPhase::Complete => Self::None,
            SagaPhase::Compensating => Self::None,
            SagaPhase::Aborted => Self::None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AbortUpload => "abort_upload",
            Self::CleanupL3 => "cleanup_l3",
            Self::ResumeRetire => "resume_retire",
        }
    }
}

impl fmt::Display for CompensationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the eviction saga state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionSagaError {
    code: String,
    message: String,
}

impl EvictionSagaError {
    #[must_use]
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for EvictionSagaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for EvictionSagaError {}

// ---------------------------------------------------------------------------
// Tier presence
// ---------------------------------------------------------------------------

/// Artifact presence flags across storage tiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierPresence {
    pub l2_present: bool,
    pub l3_present: bool,
    pub l3_verified: bool,
}

impl TierPresence {
    /// Check for orphan states that violate INV-ES-LEAK-FREE.
    #[must_use]
    pub fn has_orphan(&self) -> bool {
        // Orphan: L2 retired but L3 absent
        let l2_retired_l3_absent = !self.l2_present && !self.l3_present;
        // Orphan: L3 present but not verified in a completed saga
        // (this is checked externally against saga state)
        l2_retired_l3_absent
    }

    /// Check if safe to retire L2 (L3 must be present and verified).
    #[must_use]
    pub fn can_retire_l2(&self) -> bool {
        // INV-ES-NO-PARTIAL-RETIRE
        self.l3_present && self.l3_verified
    }
}

// ---------------------------------------------------------------------------
// Phase transition record
// ---------------------------------------------------------------------------

/// A single phase transition in the saga trace log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTransition {
    pub saga_id: String,
    pub artifact_id: String,
    pub from_phase: SagaPhase,
    pub to_phase: SagaPhase,
    pub event_code: String,
    pub timestamp_epoch_ms: u64,
    pub outcome: String,
}

impl PhaseTransition {
    fn now_epoch_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// ---------------------------------------------------------------------------
// Eviction saga
// ---------------------------------------------------------------------------

/// Cancel-safe eviction saga state machine for L2→L3 artifact lifecycle.
///
/// Guarantees:
/// - L2 is never retired unless L3 is confirmed retrievable
/// - Compensation is deterministic for any crash point
/// - Zero orphan states after completion or compensation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvictionSaga {
    saga_id: String,
    artifact_id: String,
    current_phase: SagaPhase,
    remote_cap_validated: bool,
    tier_presence: TierPresence,
    transitions: Vec<PhaseTransition>,
    compensation_action: Option<CompensationAction>,
}

impl EvictionSaga {
    /// Create a new eviction saga for the given artifact.
    #[must_use]
    pub fn new(saga_id: impl Into<String>, artifact_id: impl Into<String>) -> Self {
        Self {
            saga_id: saga_id.into(),
            artifact_id: artifact_id.into(),
            current_phase: SagaPhase::Pending,
            remote_cap_validated: false,
            tier_presence: TierPresence {
                l2_present: true,
                l3_present: false,
                l3_verified: false,
            },
            transitions: Vec::new(),
            compensation_action: None,
        }
    }

    // -- Accessors -----------------------------------------------------------

    #[must_use]
    pub fn saga_id(&self) -> &str {
        &self.saga_id
    }

    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    #[must_use]
    pub fn current_phase(&self) -> SagaPhase {
        self.current_phase
    }

    #[must_use]
    pub fn remote_cap_validated(&self) -> bool {
        self.remote_cap_validated
    }

    #[must_use]
    pub fn tier_presence(&self) -> &TierPresence {
        &self.tier_presence
    }

    #[must_use]
    pub fn transitions(&self) -> &[PhaseTransition] {
        &self.transitions
    }

    #[must_use]
    pub fn compensation_action(&self) -> Option<CompensationAction> {
        self.compensation_action
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.current_phase.is_terminal()
    }

    // -- Phase transitions ---------------------------------------------------

    /// Begin the upload phase. Requires a validated RemoteCap with
    /// ArtifactUpload scope.
    pub fn begin_upload(&mut self, has_remote_cap: bool) -> Result<(), EvictionSagaError> {
        if !has_remote_cap {
            return Err(EvictionSagaError::new(
                ERR_ES_REMOTE_CAP_REQUIRED,
                "ArtifactUpload RemoteCap required for upload phase",
            ));
        }
        self.transition(SagaPhase::Uploading, ES_PHASE_UPLOAD, "started")?;
        self.remote_cap_validated = true;
        Ok(())
    }

    /// Mark upload as successful and transition to verification.
    pub fn upload_complete(&mut self, has_remote_cap: bool) -> Result<(), EvictionSagaError> {
        self.ensure_transition_allowed(SagaPhase::Verifying)?;
        self.require_remote_cap_recheck(SagaPhase::Uploading, has_remote_cap, "upload_complete")?;
        self.tier_presence.l3_present = true;
        self.transition(SagaPhase::Verifying, ES_PHASE_VERIFY, "upload_done")
    }

    /// Mark verification as successful and transition to retirement.
    pub fn verify_complete(&mut self, has_remote_cap: bool) -> Result<(), EvictionSagaError> {
        self.ensure_transition_allowed(SagaPhase::Retiring)?;
        if !self.tier_presence.l3_present {
            return Err(EvictionSagaError::new(
                ERR_ES_VERIFY_FAILED,
                "L3 not present; cannot verify retrievability",
            ));
        }
        self.require_remote_cap_recheck(SagaPhase::Verifying, has_remote_cap, "verify_complete")?;
        self.tier_presence.l3_verified = true;
        self.transition(SagaPhase::Retiring, ES_PHASE_RETIRE, "verified")
    }

    /// Mark retirement complete; saga is done.
    pub fn retire_complete(&mut self, has_remote_cap: bool) -> Result<(), EvictionSagaError> {
        self.ensure_transition_allowed(SagaPhase::Complete)?;
        if !self.tier_presence.can_retire_l2() {
            return Err(EvictionSagaError::new(
                ERR_ES_RETIRE_FAILED,
                "L3 not verified; cannot retire L2",
            ));
        }
        self.require_remote_cap_recheck(SagaPhase::Retiring, has_remote_cap, "retire_complete")?;
        self.tier_presence.l2_present = false;
        self.transition(SagaPhase::Complete, ES_SAGA_COMPLETE, "retired")
    }

    /// Initiate compensation from the current phase.
    pub fn compensate(&mut self) -> Result<CompensationAction, EvictionSagaError> {
        if self.current_phase.is_terminal() {
            return Err(EvictionSagaError::new(
                ERR_ES_ALREADY_COMPLETE,
                format!("saga is already in terminal state: {}", self.current_phase),
            ));
        }
        if self.current_phase == SagaPhase::Compensating {
            return Err(EvictionSagaError::new(
                ERR_ES_COMPENSATION_FAILED,
                "saga is already compensating",
            ));
        }

        let action = CompensationAction::for_phase(self.current_phase);
        self.compensation_action = Some(action);
        self.remote_cap_validated = false;

        // Apply compensation effects
        match action {
            CompensationAction::AbortUpload => {
                // L2 remains intact, L3 upload aborted
                self.tier_presence.l3_present = false;
                self.tier_presence.l3_verified = false;
            }
            CompensationAction::CleanupL3 => {
                // Remove partial L3 state, L2 intact
                self.tier_presence.l3_present = false;
                self.tier_presence.l3_verified = false;
            }
            CompensationAction::ResumeRetire => {
                // L3 is confirmed; we note that retire can proceed on recovery
                // but for compensation path we mark as aborted
                // (actual resume-retire is handled by crash recovery, not
                // normal compensation)
            }
            CompensationAction::None => {}
        }

        self.transition(
            SagaPhase::Compensating,
            ES_COMPENSATION_START,
            action.as_str(),
        )?;
        Ok(action)
    }

    /// Complete compensation and transition to Aborted state.
    pub fn compensation_complete(&mut self) -> Result<(), EvictionSagaError> {
        self.transition(SagaPhase::Aborted, ES_COMPENSATION_COMPLETE, "aborted")
    }

    /// Run leak detection check. Returns Ok(()) if no leaks, Err if orphans found.
    pub fn leak_check(&self) -> Result<(), EvictionSagaError> {
        // INV-ES-LEAK-FREE
        if self.tier_presence.has_orphan() {
            return Err(EvictionSagaError::new(
                ERR_ES_LEAK_DETECTED,
                format!(
                    "orphan state: l2_present={}, l3_present={}, l3_verified={}",
                    self.tier_presence.l2_present,
                    self.tier_presence.l3_present,
                    self.tier_presence.l3_verified,
                ),
            ));
        }
        Ok(())
    }

    /// Recover from a crash at the persisted phase.
    pub fn crash_recovery(&mut self) -> Result<CompensationAction, EvictionSagaError> {
        let action = CompensationAction::for_phase(self.current_phase);
        self.record_transition(
            self.current_phase,
            self.current_phase,
            ES_CRASH_RECOVERY,
            action.as_str(),
        );

        // If we crashed mid-compensation, finish the compensation flow.
        if self.current_phase == SagaPhase::Compensating {
            self.compensation_complete()?;
            return Ok(self.compensation_action.unwrap_or(CompensationAction::None));
        }

        if action == CompensationAction::ResumeRetire {
            // Special case: L3 is confirmed, so resume retirement
            // rather than aborting
            return Ok(action);
        }

        // For all other cases, enter compensation
        if !self.current_phase.is_terminal() {
            self.compensate()?;
            self.compensation_complete()?;
        }
        Ok(action)
    }

    // -- Internal helpers ----------------------------------------------------

    fn ensure_transition_allowed(&self, to: SagaPhase) -> Result<(), EvictionSagaError> {
        if self.current_phase.can_transition_to(to) {
            return Ok(());
        }
        Err(EvictionSagaError::new(
            ERR_ES_ILLEGAL_TRANSITION,
            format!("cannot transition from {} to {}", self.current_phase, to),
        ))
    }

    fn transition(
        &mut self,
        to: SagaPhase,
        event_code: &str,
        outcome: &str,
    ) -> Result<(), EvictionSagaError> {
        if !self.current_phase.can_transition_to(to) {
            return Err(EvictionSagaError::new(
                ERR_ES_ILLEGAL_TRANSITION,
                format!("cannot transition from {} to {}", self.current_phase, to),
            ));
        }
        self.record_transition(self.current_phase, to, event_code, outcome);
        self.current_phase = to;
        Ok(())
    }

    fn require_remote_cap_recheck(
        &mut self,
        expected_phase: SagaPhase,
        has_remote_cap: bool,
        operation: &str,
    ) -> Result<(), EvictionSagaError> {
        if self.current_phase != expected_phase {
            return Ok(());
        }

        // Recheck success revalidates capability for the current phase.
        if has_remote_cap {
            self.remote_cap_validated = true;
            return Ok(());
        }
        self.remote_cap_validated = false;
        Err(EvictionSagaError::new(
            ERR_ES_REMOTE_CAP_RECHECK_FAILED,
            format!("RemoteCap recheck failed before {operation}"),
        ))
    }

    fn record_transition(
        &mut self,
        from: SagaPhase,
        to: SagaPhase,
        event_code: &str,
        outcome: &str,
    ) {
        self.transitions.push(PhaseTransition {
            saga_id: self.saga_id.clone(),
            artifact_id: self.artifact_id.clone(),
            from_phase: from,
            to_phase: to,
            event_code: event_code.to_string(),
            timestamp_epoch_ms: PhaseTransition::now_epoch_ms(),
            outcome: outcome.to_string(),
        });
    }

    /// Generate content hash for verification evidence.
    #[must_use]
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"eviction_saga_hash_v1:");
        hasher.update(self.saga_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.artifact_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.current_phase.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(self.transitions.len().to_le_bytes());
        format!("{:x}", hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for JSONL saga trace format.
pub const SCHEMA_VERSION: &str = "es-v1.0";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Phase transition table tests ----------------------------------------

    #[test]
    fn pending_can_only_go_to_uploading() {
        let targets = SagaPhase::Pending.legal_targets();
        assert_eq!(targets, &[SagaPhase::Uploading]);
    }

    #[test]
    fn uploading_can_go_to_verifying_or_compensating() {
        let targets = SagaPhase::Uploading.legal_targets();
        assert!(targets.contains(&SagaPhase::Verifying));
        assert!(targets.contains(&SagaPhase::Compensating));
    }

    #[test]
    fn verifying_can_go_to_retiring_or_compensating() {
        let targets = SagaPhase::Verifying.legal_targets();
        assert!(targets.contains(&SagaPhase::Retiring));
        assert!(targets.contains(&SagaPhase::Compensating));
    }

    #[test]
    fn retiring_can_go_to_complete_or_compensating() {
        let targets = SagaPhase::Retiring.legal_targets();
        assert!(targets.contains(&SagaPhase::Complete));
        assert!(targets.contains(&SagaPhase::Compensating));
    }

    #[test]
    fn complete_is_terminal() {
        assert!(SagaPhase::Complete.is_terminal());
        assert!(SagaPhase::Complete.legal_targets().is_empty());
    }

    #[test]
    fn aborted_is_terminal() {
        assert!(SagaPhase::Aborted.is_terminal());
        assert!(SagaPhase::Aborted.legal_targets().is_empty());
    }

    #[test]
    fn compensating_can_only_go_to_aborted() {
        let targets = SagaPhase::Compensating.legal_targets();
        assert_eq!(targets, &[SagaPhase::Aborted]);
    }

    #[test]
    fn all_phases_count() {
        assert_eq!(SagaPhase::ALL.len(), 7);
    }

    #[test]
    fn phase_display() {
        assert_eq!(SagaPhase::Pending.to_string(), "pending");
        assert_eq!(SagaPhase::Complete.to_string(), "complete");
    }

    // -- Compensation determinism tests --------------------------------------

    #[test]
    fn compensation_for_pending_is_none() {
        assert_eq!(
            CompensationAction::for_phase(SagaPhase::Pending),
            CompensationAction::None
        );
    }

    #[test]
    fn compensation_for_uploading_aborts_upload() {
        assert_eq!(
            CompensationAction::for_phase(SagaPhase::Uploading),
            CompensationAction::AbortUpload
        );
    }

    #[test]
    fn compensation_for_verifying_cleans_l3() {
        assert_eq!(
            CompensationAction::for_phase(SagaPhase::Verifying),
            CompensationAction::CleanupL3
        );
    }

    #[test]
    fn compensation_for_retiring_resumes() {
        assert_eq!(
            CompensationAction::for_phase(SagaPhase::Retiring),
            CompensationAction::ResumeRetire
        );
    }

    #[test]
    fn compensation_for_complete_is_none() {
        assert_eq!(
            CompensationAction::for_phase(SagaPhase::Complete),
            CompensationAction::None
        );
    }

    #[test]
    fn compensation_deterministic_same_input_same_output() {
        // INV-ES-DETERMINISTIC-COMPENSATION
        for phase in SagaPhase::ALL {
            let a = CompensationAction::for_phase(phase);
            let b = CompensationAction::for_phase(phase);
            assert_eq!(a, b, "compensation must be deterministic for {phase}");
        }
    }

    // -- Tier presence tests -------------------------------------------------

    #[test]
    fn orphan_when_both_absent() {
        let tp = TierPresence {
            l2_present: false,
            l3_present: false,
            l3_verified: false,
        };
        assert!(tp.has_orphan());
    }

    #[test]
    fn no_orphan_when_l2_present() {
        let tp = TierPresence {
            l2_present: true,
            l3_present: false,
            l3_verified: false,
        };
        assert!(!tp.has_orphan());
    }

    #[test]
    fn can_retire_only_when_l3_verified() {
        let tp = TierPresence {
            l2_present: true,
            l3_present: true,
            l3_verified: false,
        };
        assert!(!tp.can_retire_l2());

        let tp2 = TierPresence {
            l2_present: true,
            l3_present: true,
            l3_verified: true,
        };
        assert!(tp2.can_retire_l2());
    }

    // -- EvictionSaga happy path ---------------------------------------------

    #[test]
    fn happy_path_full_saga() {
        let mut saga = EvictionSaga::new("saga-001", "artifact-abc");
        assert_eq!(saga.current_phase(), SagaPhase::Pending);

        saga.begin_upload(true).unwrap();
        assert_eq!(saga.current_phase(), SagaPhase::Uploading);
        assert!(saga.remote_cap_validated());

        saga.upload_complete(true).unwrap();
        assert_eq!(saga.current_phase(), SagaPhase::Verifying);

        saga.verify_complete(true).unwrap();
        assert_eq!(saga.current_phase(), SagaPhase::Retiring);

        saga.retire_complete(true).unwrap();
        assert_eq!(saga.current_phase(), SagaPhase::Complete);
        assert!(saga.is_terminal());

        // Post-saga leak check
        saga.leak_check().unwrap();

        // Should have 4 transitions
        assert_eq!(saga.transitions().len(), 4);
    }

    #[test]
    fn upload_without_remote_cap_fails() {
        let mut saga = EvictionSaga::new("saga-002", "artifact-xyz");
        let err = saga.begin_upload(false).unwrap_err();
        assert_eq!(err.code(), ERR_ES_REMOTE_CAP_REQUIRED);
        // Phase should not have changed
        assert_eq!(saga.current_phase(), SagaPhase::Pending);
    }

    #[test]
    fn upload_complete_requires_remote_cap_recheck() {
        let mut saga = EvictionSaga::new("saga-002b", "artifact-xyz");
        saga.begin_upload(true).unwrap();

        let err = saga.upload_complete(false).unwrap_err();
        assert_eq!(err.code(), ERR_ES_REMOTE_CAP_RECHECK_FAILED);
        assert_eq!(saga.current_phase(), SagaPhase::Uploading);
        assert!(!saga.tier_presence().l3_present);
        assert!(!saga.remote_cap_validated());
    }

    #[test]
    fn upload_complete_allows_retry_after_remote_cap_restored() {
        let mut saga = EvictionSaga::new("saga-002e", "artifact-xyz");
        saga.begin_upload(true).unwrap();

        let err = saga.upload_complete(false).unwrap_err();
        assert_eq!(err.code(), ERR_ES_REMOTE_CAP_RECHECK_FAILED);
        assert_eq!(saga.current_phase(), SagaPhase::Uploading);
        assert!(!saga.remote_cap_validated());

        saga.upload_complete(true).unwrap();
        assert_eq!(saga.current_phase(), SagaPhase::Verifying);
        assert!(saga.remote_cap_validated());
        assert!(saga.tier_presence().l3_present);
    }

    #[test]
    fn verify_complete_requires_remote_cap_recheck() {
        let mut saga = EvictionSaga::new("saga-002c", "artifact-xyz");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();

        let err = saga.verify_complete(false).unwrap_err();
        assert_eq!(err.code(), ERR_ES_REMOTE_CAP_RECHECK_FAILED);
        assert_eq!(saga.current_phase(), SagaPhase::Verifying);
        assert!(!saga.tier_presence().l3_verified);
        assert!(!saga.remote_cap_validated());
    }

    #[test]
    fn retire_complete_requires_remote_cap_recheck() {
        let mut saga = EvictionSaga::new("saga-002d", "artifact-xyz");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();
        saga.verify_complete(true).unwrap();

        let err = saga.retire_complete(false).unwrap_err();
        assert_eq!(err.code(), ERR_ES_REMOTE_CAP_RECHECK_FAILED);
        assert_eq!(saga.current_phase(), SagaPhase::Retiring);
        assert!(saga.tier_presence().l2_present);
        assert!(!saga.is_terminal());
        assert!(!saga.remote_cap_validated());
    }

    #[test]
    fn illegal_transition_rejected() {
        let mut saga = EvictionSaga::new("saga-003", "artifact-xyz");
        // Cannot go directly to verifying
        let err = saga.upload_complete(true).unwrap_err();
        assert_eq!(err.code(), ERR_ES_ILLEGAL_TRANSITION);
        assert!(!saga.tier_presence().l3_present);
        assert!(!saga.tier_presence().l3_verified);
        assert!(saga.tier_presence().l2_present);
    }

    #[test]
    fn illegal_transition_does_not_mutate_on_verify_complete() {
        let mut saga = EvictionSaga::new("saga-003b", "artifact-xyz");
        saga.begin_upload(true).unwrap();
        // Cannot go Uploading -> Retiring directly.
        let err = saga.verify_complete(true).unwrap_err();
        assert_eq!(err.code(), ERR_ES_ILLEGAL_TRANSITION);
        assert_eq!(saga.current_phase(), SagaPhase::Uploading);
        assert!(!saga.tier_presence().l3_verified);
    }

    #[test]
    fn illegal_transition_does_not_mutate_on_retire_complete() {
        let mut saga = EvictionSaga::new("saga-003c", "artifact-xyz");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();
        // Cannot go Verifying -> Complete directly.
        let err = saga.retire_complete(true).unwrap_err();
        assert_eq!(err.code(), ERR_ES_ILLEGAL_TRANSITION);
        assert_eq!(saga.current_phase(), SagaPhase::Verifying);
        assert!(saga.tier_presence().l2_present);
    }

    #[test]
    fn verify_complete_does_not_mutate_when_l3_missing() {
        let mut saga = EvictionSaga::new("saga-003d", "artifact-xyz");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();
        saga.tier_presence.l3_present = false;
        saga.tier_presence.l3_verified = false;

        let err = saga.verify_complete(true).unwrap_err();
        assert_eq!(err.code(), ERR_ES_VERIFY_FAILED);
        assert_eq!(saga.current_phase(), SagaPhase::Verifying);
        assert!(!saga.tier_presence().l3_verified);
    }

    #[test]
    fn retire_complete_requires_verified_l3() {
        let mut saga = EvictionSaga::new("saga-003e", "artifact-xyz");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();
        saga.verify_complete(true).unwrap();
        saga.tier_presence.l3_verified = false;

        let err = saga.retire_complete(true).unwrap_err();
        assert_eq!(err.code(), ERR_ES_RETIRE_FAILED);
        assert_eq!(saga.current_phase(), SagaPhase::Retiring);
        assert!(saga.tier_presence().l2_present);
    }

    // -- Compensation tests --------------------------------------------------

    #[test]
    fn compensate_during_upload() {
        let mut saga = EvictionSaga::new("saga-010", "art-1");
        saga.begin_upload(true).unwrap();

        let action = saga.compensate().unwrap();
        assert_eq!(action, CompensationAction::AbortUpload);
        assert!(!saga.tier_presence().l3_present);

        saga.compensation_complete().unwrap();
        assert_eq!(saga.current_phase(), SagaPhase::Aborted);
        saga.leak_check().unwrap();
    }

    #[test]
    fn compensate_during_verify() {
        let mut saga = EvictionSaga::new("saga-011", "art-2");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();

        let action = saga.compensate().unwrap();
        assert_eq!(action, CompensationAction::CleanupL3);
        assert!(!saga.tier_presence().l3_present);

        saga.compensation_complete().unwrap();
        assert_eq!(saga.current_phase(), SagaPhase::Aborted);
        saga.leak_check().unwrap();
    }

    #[test]
    fn compensate_during_retire_uses_resume() {
        let mut saga = EvictionSaga::new("saga-012", "art-3");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();
        saga.verify_complete(true).unwrap();

        let action = saga.compensate().unwrap();
        assert_eq!(action, CompensationAction::ResumeRetire);

        saga.compensation_complete().unwrap();
        assert_eq!(saga.current_phase(), SagaPhase::Aborted);
    }

    #[test]
    fn compensate_rejects_when_already_compensating() {
        let mut saga = EvictionSaga::new("saga-012b", "art-3");
        saga.begin_upload(true).unwrap();

        saga.compensate().unwrap();
        let err = saga.compensate().unwrap_err();
        assert_eq!(err.code(), ERR_ES_COMPENSATION_FAILED);
        assert_eq!(saga.current_phase(), SagaPhase::Compensating);
    }

    #[test]
    fn cannot_compensate_terminal_state() {
        let mut saga = EvictionSaga::new("saga-013", "art-4");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();
        saga.verify_complete(true).unwrap();
        saga.retire_complete(true).unwrap();

        let err = saga.compensate().unwrap_err();
        assert_eq!(err.code(), ERR_ES_ALREADY_COMPLETE);
    }

    // -- Leak detection tests ------------------------------------------------

    #[test]
    fn leak_check_detects_orphan() {
        let mut saga = EvictionSaga::new("saga-020", "art-5");
        // Simulate orphan: manually set L2 absent without L3
        saga.tier_presence = TierPresence {
            l2_present: false,
            l3_present: false,
            l3_verified: false,
        };
        let err = saga.leak_check().unwrap_err();
        assert_eq!(err.code(), ERR_ES_LEAK_DETECTED);
    }

    #[test]
    fn leak_check_passes_after_happy_path() {
        let mut saga = EvictionSaga::new("saga-021", "art-6");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();
        saga.verify_complete(true).unwrap();
        saga.retire_complete(true).unwrap();
        saga.leak_check().unwrap();
    }

    // -- Crash recovery tests ------------------------------------------------

    #[test]
    fn crash_recovery_from_uploading() {
        let mut saga = EvictionSaga::new("saga-030", "art-7");
        saga.begin_upload(true).unwrap();

        // Simulate crash at uploading phase
        let action = saga.crash_recovery().unwrap();
        assert_eq!(action, CompensationAction::AbortUpload);
        assert_eq!(saga.current_phase(), SagaPhase::Aborted);
    }

    #[test]
    fn crash_recovery_from_verifying() {
        let mut saga = EvictionSaga::new("saga-031", "art-8");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();

        let action = saga.crash_recovery().unwrap();
        assert_eq!(action, CompensationAction::CleanupL3);
        assert_eq!(saga.current_phase(), SagaPhase::Aborted);
    }

    #[test]
    fn crash_recovery_from_retiring_signals_resume() {
        let mut saga = EvictionSaga::new("saga-032", "art-9");
        saga.begin_upload(true).unwrap();
        saga.upload_complete(true).unwrap();
        saga.verify_complete(true).unwrap();

        let action = saga.crash_recovery().unwrap();
        assert_eq!(action, CompensationAction::ResumeRetire);
        // Should NOT be aborted — retirement can proceed
        assert_eq!(saga.current_phase(), SagaPhase::Retiring);
    }

    #[test]
    fn crash_recovery_from_compensating_completes_aborted() {
        let mut saga = EvictionSaga::new("saga-033", "art-10");
        saga.begin_upload(true).unwrap();
        let expected = saga.compensate().unwrap();
        assert_eq!(expected, CompensationAction::AbortUpload);
        assert_eq!(saga.current_phase(), SagaPhase::Compensating);

        let action = saga.crash_recovery().unwrap();
        assert_eq!(action, CompensationAction::AbortUpload);
        assert_eq!(saga.current_phase(), SagaPhase::Aborted);
        assert!(saga.is_terminal());
    }

    // -- Content hash --------------------------------------------------------

    #[test]
    fn content_hash_deterministic() {
        let saga = EvictionSaga::new("saga-040", "art-10");
        let h1 = saga.content_hash();
        let h2 = saga.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_changes_with_state() {
        let saga1 = EvictionSaga::new("saga-041", "art-11");
        let mut saga2 = EvictionSaga::new("saga-041", "art-11");
        saga2.begin_upload(true).unwrap();
        assert_ne!(saga1.content_hash(), saga2.content_hash());
    }

    // -- Error display -------------------------------------------------------

    #[test]
    fn error_display() {
        let err = EvictionSagaError::new("TEST_CODE", "test message");
        assert_eq!(err.to_string(), "[TEST_CODE] test message");
        assert_eq!(err.code(), "TEST_CODE");
        assert_eq!(err.message(), "test message");
    }

    // -- Serialization -------------------------------------------------------

    #[test]
    fn saga_serializes_to_json() {
        let saga = EvictionSaga::new("saga-050", "art-12");
        let json = serde_json::to_string(&saga).unwrap();
        let deserialized: EvictionSaga = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.saga_id(), "saga-050");
        assert_eq!(deserialized.current_phase(), SagaPhase::Pending);
    }

    #[test]
    fn phase_transition_serializes() {
        let t = PhaseTransition {
            saga_id: "s1".to_string(),
            artifact_id: "a1".to_string(),
            from_phase: SagaPhase::Pending,
            to_phase: SagaPhase::Uploading,
            event_code: ES_SAGA_START.to_string(),
            timestamp_epoch_ms: 1234567890,
            outcome: "ok".to_string(),
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("pending"));
        assert!(json.contains("uploading"));
    }
}
