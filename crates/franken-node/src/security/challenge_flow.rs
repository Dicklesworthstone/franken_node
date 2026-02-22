//! bd-29yx: Suspicious-artifact challenge flow.
//!
//! When an artifact appears suspicious (unexpected provenance, age anomaly,
//! format deviation), the system defers trust promotion and issues a challenge
//! requesting specific proof artifacts. Promotion proceeds only after proof
//! verification succeeds. Unresolved challenges timeout to denial.
//!
//! # Invariants
//!
//! - **INV-CHALLENGE-DEFER**: Suspicious artifacts are never promoted without proof.
//! - **INV-CHALLENGE-TIMEOUT-DENY**: Unresolved challenges default to denial.
//! - **INV-CHALLENGE-AUDIT**: All state transitions are persisted to an audit log.
//! - **INV-CHALLENGE-VALID-TRANSITIONS**: State machine rejects invalid transitions.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const CHALLENGE_ISSUED: &str = "CHALLENGE_ISSUED";
pub const CHALLENGE_PROOF_RECEIVED: &str = "CHALLENGE_PROOF_RECEIVED";
pub const CHALLENGE_VERIFIED: &str = "CHALLENGE_VERIFIED";
pub const CHALLENGE_TIMED_OUT: &str = "CHALLENGE_TIMED_OUT";
pub const CHALLENGE_DENIED: &str = "CHALLENGE_DENIED";
pub const CHALLENGE_PROMOTED: &str = "CHALLENGE_PROMOTED";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_INVALID_TRANSITION: &str = "ERR_INVALID_TRANSITION";
pub const ERR_CHALLENGE_ACTIVE: &str = "ERR_CHALLENGE_ACTIVE";
pub const ERR_NO_ACTIVE_CHALLENGE: &str = "ERR_NO_ACTIVE_CHALLENGE";

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

/// INV-CHALLENGE-DEFER: Suspicious artifacts never promoted without proof.
pub const INV_CHALLENGE_DEFER: &str = "INV-CHALLENGE-DEFER";
/// INV-CHALLENGE-TIMEOUT-DENY: Unresolved challenges default to denial.
pub const INV_CHALLENGE_TIMEOUT_DENY: &str = "INV-CHALLENGE-TIMEOUT-DENY";
/// INV-CHALLENGE-AUDIT: All transitions logged.
pub const INV_CHALLENGE_AUDIT: &str = "INV-CHALLENGE-AUDIT";
/// INV-CHALLENGE-VALID-TRANSITIONS: Invalid transitions rejected.
pub const INV_CHALLENGE_VALID_TRANSITIONS: &str = "INV-CHALLENGE-VALID-TRANSITIONS";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique challenge identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChallengeId(pub String);

impl ChallengeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Unique artifact identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub String);

impl ArtifactId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reason an artifact was flagged as suspicious.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspicionReason {
    /// Provenance metadata doesn't match expected source.
    UnexpectedProvenance,
    /// Artifact age is outside acceptable window.
    AgeAnomaly,
    /// Format deviates from expected schema.
    FormatDeviation,
    /// Operator manually flagged for review.
    OperatorOverride,
    /// Policy rule triggered.
    PolicyRule(String),
}

impl SuspicionReason {
    pub fn label(&self) -> &str {
        match self {
            Self::UnexpectedProvenance => "unexpected_provenance",
            Self::AgeAnomaly => "age_anomaly",
            Self::FormatDeviation => "format_deviation",
            Self::OperatorOverride => "operator_override",
            Self::PolicyRule(_) => "policy_rule",
        }
    }
}

/// Type of proof artifact required to resolve a challenge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequiredProofType {
    ProvenanceAttestation,
    IntegrityProof,
    EpochBoundaryProof,
    OriginSignature,
    Custom(String),
}

impl RequiredProofType {
    pub fn label(&self) -> &str {
        match self {
            Self::ProvenanceAttestation => "provenance_attestation",
            Self::IntegrityProof => "integrity_proof",
            Self::EpochBoundaryProof => "epoch_boundary_proof",
            Self::OriginSignature => "origin_signature",
            Self::Custom(_) => "custom",
        }
    }
}

/// State of a challenge flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChallengeState {
    Pending,
    ChallengeIssued,
    ProofReceived,
    ProofVerified,
    Denied,
    Promoted,
}

impl ChallengeState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ChallengeIssued => "challenge_issued",
            Self::ProofReceived => "proof_received",
            Self::ProofVerified => "proof_verified",
            Self::Denied => "denied",
            Self::Promoted => "promoted",
        }
    }

    /// Whether this state is terminal (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Denied | Self::Promoted)
    }

    /// Valid successor states from this state.
    pub fn valid_transitions(&self) -> &'static [ChallengeState] {
        match self {
            Self::Pending => &[Self::ChallengeIssued, Self::Denied],
            Self::ChallengeIssued => &[Self::ProofReceived, Self::Denied],
            Self::ProofReceived => &[Self::ProofVerified, Self::Denied],
            Self::ProofVerified => &[Self::Promoted, Self::Denied],
            Self::Denied => &[],
            Self::Promoted => &[],
        }
    }

    /// Check if a transition to `next` is valid.
    pub fn can_transition_to(&self, next: ChallengeState) -> bool {
        self.valid_transitions().contains(&next)
    }
}

impl std::fmt::Display for ChallengeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Submitted proof artifact for challenge resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSubmission {
    pub proof_type: RequiredProofType,
    pub data_hash: String,
    pub submitter_id: String,
    pub submitted_at_ms: u64,
}

/// Configuration for challenge flow policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    /// Timeout in milliseconds before challenge is auto-denied.
    pub timeout_ms: u64,
    /// Whether to auto-deny on timeout (true) or leave pending (false).
    pub deny_on_timeout: bool,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000, // 30 seconds
            deny_on_timeout: true,
        }
    }
}

/// Audit log entry for challenge state transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeAuditEntry {
    pub challenge_id: String,
    pub artifact_id: String,
    pub from_state: ChallengeState,
    pub to_state: ChallengeState,
    pub event_code: String,
    pub actor_id: String,
    pub timestamp_ms: u64,
    pub detail: String,
    /// Hash of the previous entry for tamper-evidence.
    pub prev_hash: String,
}

impl ChallengeAuditEntry {
    /// Compute the hash of this entry for chain integrity.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.challenge_id.as_bytes());
        hasher.update(self.artifact_id.as_bytes());
        hasher.update(self.from_state.label().as_bytes());
        hasher.update(self.to_state.label().as_bytes());
        hasher.update(self.event_code.as_bytes());
        hasher.update(self.timestamp_ms.to_le_bytes());
        hasher.update(self.prev_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Error type for challenge flow operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeError {
    pub code: String,
    pub message: String,
}

impl ChallengeError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn invalid_transition(from: ChallengeState, to: ChallengeState) -> Self {
        Self::new(
            ERR_INVALID_TRANSITION,
            format!("Invalid transition: {} -> {}", from, to),
        )
    }
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Metrics counters for challenge flow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChallengeMetrics {
    pub challenges_issued_total: u64,
    pub challenges_resolved_total: u64,
    pub challenges_timed_out_total: u64,
    pub challenges_promoted_total: u64,
    pub challenges_denied_total: u64,
}

// ---------------------------------------------------------------------------
// Challenge record
// ---------------------------------------------------------------------------

/// A single challenge instance tracking an artifact through the flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge_id: ChallengeId,
    pub artifact_id: ArtifactId,
    pub state: ChallengeState,
    pub reason: SuspicionReason,
    pub required_proofs: Vec<RequiredProofType>,
    pub received_proofs: Vec<ProofSubmission>,
    pub created_at_ms: u64,
    pub timeout_ms: u64,
    pub trace_id: String,
}

impl Challenge {
    pub fn is_timed_out(&self, current_time_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.created_at_ms) >= self.timeout_ms
    }
}

// ---------------------------------------------------------------------------
// ChallengeFlowController
// ---------------------------------------------------------------------------

/// Controller managing challenge flows for suspicious artifacts.
///
/// Enforces state machine transitions, audit logging, and timeout policy.
pub struct ChallengeFlowController {
    challenges: HashMap<ChallengeId, Challenge>,
    audit_log: Vec<ChallengeAuditEntry>,
    config: ChallengeConfig,
    metrics: ChallengeMetrics,
    next_id: u64,
}

impl ChallengeFlowController {
    pub fn new(config: ChallengeConfig) -> Self {
        Self {
            challenges: HashMap::new(),
            audit_log: Vec::new(),
            config,
            metrics: ChallengeMetrics::default(),
            next_id: 1,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(ChallengeConfig::default())
    }

    /// Issue a challenge for a suspicious artifact.
    pub fn issue_challenge(
        &mut self,
        artifact_id: ArtifactId,
        reason: SuspicionReason,
        required_proofs: Vec<RequiredProofType>,
        actor_id: &str,
        timestamp_ms: u64,
    ) -> Result<ChallengeId, ChallengeError> {
        // Check for existing active challenge on same artifact.
        for ch in self.challenges.values() {
            if ch.artifact_id == artifact_id && !ch.state.is_terminal() {
                return Err(ChallengeError::new(
                    ERR_CHALLENGE_ACTIVE,
                    format!(
                        "Active challenge {} already exists for artifact {}",
                        ch.challenge_id, artifact_id
                    ),
                ));
            }
        }

        let challenge_id = ChallengeId::new(format!("ch-{}", self.next_id));
        self.next_id += 1;

        let challenge = Challenge {
            challenge_id: challenge_id.clone(),
            artifact_id: artifact_id.clone(),
            state: ChallengeState::ChallengeIssued,
            reason,
            required_proofs,
            received_proofs: Vec::new(),
            created_at_ms: timestamp_ms,
            timeout_ms: self.config.timeout_ms,
            trace_id: format!("trace-{}", challenge_id),
        };

        self.challenges.insert(challenge_id.clone(), challenge);
        self.metrics.challenges_issued_total += 1;

        self.log_transition(
            &challenge_id,
            &artifact_id,
            ChallengeState::Pending,
            ChallengeState::ChallengeIssued,
            CHALLENGE_ISSUED,
            actor_id,
            timestamp_ms,
            "Challenge issued for suspicious artifact",
        );

        Ok(challenge_id)
    }

    /// Submit proof for an active challenge.
    pub fn submit_proof(
        &mut self,
        challenge_id: &ChallengeId,
        proof: ProofSubmission,
        actor_id: &str,
        timestamp_ms: u64,
    ) -> Result<(), ChallengeError> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| ChallengeError::new(ERR_NO_ACTIVE_CHALLENGE, "Challenge not found"))?;

        if !challenge
            .state
            .can_transition_to(ChallengeState::ProofReceived)
        {
            return Err(ChallengeError::invalid_transition(
                challenge.state,
                ChallengeState::ProofReceived,
            ));
        }

        let artifact_id = challenge.artifact_id.clone();
        let old_state = challenge.state;
        challenge.received_proofs.push(proof);
        challenge.state = ChallengeState::ProofReceived;

        self.log_transition(
            challenge_id,
            &artifact_id,
            old_state,
            ChallengeState::ProofReceived,
            CHALLENGE_PROOF_RECEIVED,
            actor_id,
            timestamp_ms,
            "Proof artifact received",
        );

        Ok(())
    }

    /// Mark proof as verified for a challenge.
    pub fn verify_proof(
        &mut self,
        challenge_id: &ChallengeId,
        actor_id: &str,
        timestamp_ms: u64,
    ) -> Result<(), ChallengeError> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| ChallengeError::new(ERR_NO_ACTIVE_CHALLENGE, "Challenge not found"))?;

        if !challenge
            .state
            .can_transition_to(ChallengeState::ProofVerified)
        {
            return Err(ChallengeError::invalid_transition(
                challenge.state,
                ChallengeState::ProofVerified,
            ));
        }

        let artifact_id = challenge.artifact_id.clone();
        let old_state = challenge.state;
        challenge.state = ChallengeState::ProofVerified;

        self.log_transition(
            challenge_id,
            &artifact_id,
            old_state,
            ChallengeState::ProofVerified,
            CHALLENGE_VERIFIED,
            actor_id,
            timestamp_ms,
            "Proof verified successfully",
        );

        Ok(())
    }

    /// Promote an artifact after successful proof verification.
    pub fn promote(
        &mut self,
        challenge_id: &ChallengeId,
        actor_id: &str,
        timestamp_ms: u64,
    ) -> Result<(), ChallengeError> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| ChallengeError::new(ERR_NO_ACTIVE_CHALLENGE, "Challenge not found"))?;

        if !challenge.state.can_transition_to(ChallengeState::Promoted) {
            return Err(ChallengeError::invalid_transition(
                challenge.state,
                ChallengeState::Promoted,
            ));
        }

        let artifact_id = challenge.artifact_id.clone();
        let old_state = challenge.state;
        challenge.state = ChallengeState::Promoted;
        self.metrics.challenges_resolved_total += 1;
        self.metrics.challenges_promoted_total += 1;

        self.log_transition(
            challenge_id,
            &artifact_id,
            old_state,
            ChallengeState::Promoted,
            CHALLENGE_PROMOTED,
            actor_id,
            timestamp_ms,
            "Artifact promoted after proof verification",
        );

        Ok(())
    }

    /// Deny an artifact (explicit denial or timeout).
    pub fn deny(
        &mut self,
        challenge_id: &ChallengeId,
        actor_id: &str,
        timestamp_ms: u64,
        reason: &str,
    ) -> Result<(), ChallengeError> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| ChallengeError::new(ERR_NO_ACTIVE_CHALLENGE, "Challenge not found"))?;

        if !challenge.state.can_transition_to(ChallengeState::Denied) {
            return Err(ChallengeError::invalid_transition(
                challenge.state,
                ChallengeState::Denied,
            ));
        }

        let artifact_id = challenge.artifact_id.clone();
        let old_state = challenge.state;
        challenge.state = ChallengeState::Denied;
        self.metrics.challenges_resolved_total += 1;
        self.metrics.challenges_denied_total += 1;

        self.log_transition(
            challenge_id,
            &artifact_id,
            old_state,
            ChallengeState::Denied,
            CHALLENGE_DENIED,
            actor_id,
            timestamp_ms,
            reason,
        );

        Ok(())
    }

    /// Check for timed-out challenges and deny them.
    pub fn enforce_timeouts(&mut self, current_time_ms: u64) -> Vec<ChallengeId> {
        if !self.config.deny_on_timeout {
            return Vec::new();
        }

        let timed_out: Vec<(ChallengeId, ArtifactId, ChallengeState)> = self
            .challenges
            .values()
            .filter(|ch| !ch.state.is_terminal() && ch.is_timed_out(current_time_ms))
            .map(|ch| (ch.challenge_id.clone(), ch.artifact_id.clone(), ch.state))
            .collect();

        let mut denied_ids = Vec::new();
        for (cid, aid, old_state) in timed_out {
            if let Some(ch) = self.challenges.get_mut(&cid) {
                ch.state = ChallengeState::Denied;
                self.metrics.challenges_timed_out_total += 1;
                self.metrics.challenges_resolved_total += 1;
                self.metrics.challenges_denied_total += 1;

                self.log_transition(
                    &cid,
                    &aid,
                    old_state,
                    ChallengeState::Denied,
                    CHALLENGE_TIMED_OUT,
                    "system",
                    current_time_ms,
                    "Challenge timed out, denied by policy",
                );

                denied_ids.push(cid);
            }
        }

        denied_ids
    }

    /// Query full audit history for an artifact.
    pub fn audit_query(&self, artifact_id: &ArtifactId) -> Vec<&ChallengeAuditEntry> {
        self.audit_log
            .iter()
            .filter(|e| e.artifact_id == artifact_id.as_str())
            .collect()
    }

    /// Query full audit history for a challenge.
    pub fn challenge_audit(&self, challenge_id: &ChallengeId) -> Vec<&ChallengeAuditEntry> {
        self.audit_log
            .iter()
            .filter(|e| e.challenge_id == challenge_id.as_str())
            .collect()
    }

    /// Get a challenge by ID.
    pub fn get_challenge(&self, challenge_id: &ChallengeId) -> Option<&Challenge> {
        self.challenges.get(challenge_id)
    }

    /// Get all active (non-terminal) challenges.
    pub fn active_challenges(&self) -> Vec<&Challenge> {
        self.challenges
            .values()
            .filter(|ch| !ch.state.is_terminal())
            .collect()
    }

    /// Current metrics snapshot.
    pub fn metrics(&self) -> &ChallengeMetrics {
        &self.metrics
    }

    /// Full audit log.
    pub fn audit_log(&self) -> &[ChallengeAuditEntry] {
        &self.audit_log
    }

    // -- Internal -----------------------------------------------------------

    fn log_transition(
        &mut self,
        challenge_id: &ChallengeId,
        artifact_id: &ArtifactId,
        from_state: ChallengeState,
        to_state: ChallengeState,
        event_code: &str,
        actor_id: &str,
        timestamp_ms: u64,
        detail: &str,
    ) {
        let prev_hash = self
            .audit_log
            .last()
            .map(|e| e.hash())
            .unwrap_or_else(|| "0".repeat(64));

        let entry = ChallengeAuditEntry {
            challenge_id: challenge_id.as_str().to_string(),
            artifact_id: artifact_id.as_str().to_string(),
            from_state,
            to_state,
            event_code: event_code.to_string(),
            actor_id: actor_id.to_string(),
            timestamp_ms,
            detail: detail.to_string(),
            prev_hash,
        };

        self.audit_log.push(entry);
    }
}

// ---------------------------------------------------------------------------
// Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<ChallengeFlowController>();
    assert_sync::<ChallengeFlowController>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_controller() -> ChallengeFlowController {
        ChallengeFlowController::with_defaults()
    }

    fn issue_basic(ctrl: &mut ChallengeFlowController, ts: u64) -> ChallengeId {
        ctrl.issue_challenge(
            ArtifactId::new("art-1"),
            SuspicionReason::UnexpectedProvenance,
            vec![RequiredProofType::ProvenanceAttestation],
            "operator-1",
            ts,
        )
        .unwrap()
    }

    fn make_proof(ts: u64) -> ProofSubmission {
        ProofSubmission {
            proof_type: RequiredProofType::ProvenanceAttestation,
            data_hash: "abc123".to_string(),
            submitter_id: "prover-1".to_string(),
            submitted_at_ms: ts,
        }
    }

    // -- ChallengeState transitions --

    #[test]
    fn test_pending_valid_transitions() {
        let valid = ChallengeState::Pending.valid_transitions();
        assert!(valid.contains(&ChallengeState::ChallengeIssued));
        assert!(valid.contains(&ChallengeState::Denied));
    }

    #[test]
    fn test_issued_valid_transitions() {
        let valid = ChallengeState::ChallengeIssued.valid_transitions();
        assert!(valid.contains(&ChallengeState::ProofReceived));
        assert!(valid.contains(&ChallengeState::Denied));
    }

    #[test]
    fn test_received_valid_transitions() {
        let valid = ChallengeState::ProofReceived.valid_transitions();
        assert!(valid.contains(&ChallengeState::ProofVerified));
        assert!(valid.contains(&ChallengeState::Denied));
    }

    #[test]
    fn test_verified_valid_transitions() {
        let valid = ChallengeState::ProofVerified.valid_transitions();
        assert!(valid.contains(&ChallengeState::Promoted));
        assert!(valid.contains(&ChallengeState::Denied));
    }

    #[test]
    fn test_denied_is_terminal() {
        assert!(ChallengeState::Denied.is_terminal());
        assert!(ChallengeState::Denied.valid_transitions().is_empty());
    }

    #[test]
    fn test_promoted_is_terminal() {
        assert!(ChallengeState::Promoted.is_terminal());
        assert!(ChallengeState::Promoted.valid_transitions().is_empty());
    }

    #[test]
    fn test_denied_to_promoted_invalid() {
        assert!(!ChallengeState::Denied.can_transition_to(ChallengeState::Promoted));
    }

    #[test]
    fn test_promoted_to_denied_invalid() {
        assert!(!ChallengeState::Promoted.can_transition_to(ChallengeState::Denied));
    }

    #[test]
    fn test_state_labels() {
        assert_eq!(ChallengeState::Pending.label(), "pending");
        assert_eq!(ChallengeState::ChallengeIssued.label(), "challenge_issued");
        assert_eq!(ChallengeState::ProofReceived.label(), "proof_received");
        assert_eq!(ChallengeState::ProofVerified.label(), "proof_verified");
        assert_eq!(ChallengeState::Denied.label(), "denied");
        assert_eq!(ChallengeState::Promoted.label(), "promoted");
    }

    // -- Issue challenge --

    #[test]
    fn test_issue_challenge() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        let ch = ctrl.get_challenge(&cid).unwrap();
        assert_eq!(ch.state, ChallengeState::ChallengeIssued);
        assert_eq!(ch.artifact_id, ArtifactId::new("art-1"));
    }

    #[test]
    fn test_issue_increments_metrics() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);
        assert_eq!(ctrl.metrics().challenges_issued_total, 1);
    }

    #[test]
    fn test_duplicate_challenge_rejected() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);
        let result = ctrl.issue_challenge(
            ArtifactId::new("art-1"),
            SuspicionReason::AgeAnomaly,
            vec![],
            "op",
            2000,
        );
        assert_eq!(result.unwrap_err().code, ERR_CHALLENGE_ACTIVE);
    }

    #[test]
    fn test_can_issue_after_resolved() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.deny(&cid, "op", 2000, "test").unwrap();
        // Now should allow a new challenge on same artifact
        let cid2 = ctrl
            .issue_challenge(
                ArtifactId::new("art-1"),
                SuspicionReason::FormatDeviation,
                vec![],
                "op",
                3000,
            )
            .unwrap();
        assert_ne!(cid, cid2);
    }

    // -- Full happy path --

    #[test]
    fn test_full_happy_path() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);

        ctrl.submit_proof(&cid, make_proof(2000), "prover-1", 2000)
            .unwrap();
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::ProofReceived
        );

        ctrl.verify_proof(&cid, "verifier-1", 3000).unwrap();
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::ProofVerified
        );

        ctrl.promote(&cid, "operator-1", 4000).unwrap();
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Promoted
        );

        assert_eq!(ctrl.metrics().challenges_promoted_total, 1);
        assert_eq!(ctrl.metrics().challenges_resolved_total, 1);
    }

    // -- Denial paths --

    #[test]
    fn test_deny_from_issued() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.deny(&cid, "op", 2000, "manual denial").unwrap();
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
        assert_eq!(ctrl.metrics().challenges_denied_total, 1);
    }

    #[test]
    fn test_deny_from_proof_received() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "p", 2000)
            .unwrap();
        ctrl.deny(&cid, "op", 3000, "proof invalid").unwrap();
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
    }

    #[test]
    fn test_deny_from_verified() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "p", 2000)
            .unwrap();
        ctrl.verify_proof(&cid, "v", 3000).unwrap();
        ctrl.deny(&cid, "op", 4000, "operator override").unwrap();
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
    }

    // -- Invalid transitions --

    #[test]
    fn test_promote_from_issued_fails() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        let err = ctrl.promote(&cid, "op", 2000).unwrap_err();
        assert_eq!(err.code, ERR_INVALID_TRANSITION);
    }

    #[test]
    fn test_promote_from_proof_received_fails() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "p", 2000)
            .unwrap();
        let err = ctrl.promote(&cid, "op", 3000).unwrap_err();
        assert_eq!(err.code, ERR_INVALID_TRANSITION);
    }

    #[test]
    fn test_verify_from_issued_fails() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        let err = ctrl.verify_proof(&cid, "v", 2000).unwrap_err();
        assert_eq!(err.code, ERR_INVALID_TRANSITION);
    }

    #[test]
    fn test_submit_proof_to_denied_fails() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.deny(&cid, "op", 2000, "x").unwrap();
        let err = ctrl
            .submit_proof(&cid, make_proof(3000), "p", 3000)
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_TRANSITION);
    }

    // -- Timeout --

    #[test]
    fn test_timeout_denies_challenge() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        let denied = ctrl.enforce_timeouts(32_000);
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0], cid);
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
        assert_eq!(ctrl.metrics().challenges_timed_out_total, 1);
    }

    #[test]
    fn test_no_timeout_before_deadline() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);
        let denied = ctrl.enforce_timeouts(15_000);
        assert!(denied.is_empty());
    }

    #[test]
    fn test_timeout_does_not_affect_terminal() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.deny(&cid, "op", 2000, "x").unwrap();
        let denied = ctrl.enforce_timeouts(100_000);
        assert!(denied.is_empty());
    }

    #[test]
    fn test_timeout_disabled() {
        let config = ChallengeConfig {
            deny_on_timeout: false,
            ..Default::default()
        };
        let mut ctrl = ChallengeFlowController::new(config);
        issue_basic(&mut ctrl, 1000);
        let denied = ctrl.enforce_timeouts(100_000);
        assert!(denied.is_empty());
    }

    // -- Audit log --

    #[test]
    fn test_audit_log_populated() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "p", 2000)
            .unwrap();
        assert!(ctrl.audit_log().len() >= 2);
    }

    #[test]
    fn test_audit_query_by_artifact() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "p", 2000)
            .unwrap();
        let entries = ctrl.audit_query(&ArtifactId::new("art-1"));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_audit_query_by_challenge() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.deny(&cid, "op", 2000, "x").unwrap();
        let entries = ctrl.challenge_audit(&cid);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_audit_hash_chain() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "p", 2000)
            .unwrap();
        let log = ctrl.audit_log();
        // Second entry should reference first entry's hash
        assert_eq!(log[1].prev_hash, log[0].hash());
    }

    #[test]
    fn test_audit_first_entry_has_zero_prev_hash() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);
        let log = ctrl.audit_log();
        assert_eq!(log[0].prev_hash, "0".repeat(64));
    }

    // -- Active challenges --

    #[test]
    fn test_active_challenges() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);
        assert_eq!(ctrl.active_challenges().len(), 1);
    }

    #[test]
    fn test_active_challenges_excludes_terminal() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.deny(&cid, "op", 2000, "x").unwrap();
        assert!(ctrl.active_challenges().is_empty());
    }

    // -- Suspicion reasons --

    #[test]
    fn test_suspicion_reason_labels() {
        assert_eq!(
            SuspicionReason::UnexpectedProvenance.label(),
            "unexpected_provenance"
        );
        assert_eq!(SuspicionReason::AgeAnomaly.label(), "age_anomaly");
        assert_eq!(SuspicionReason::FormatDeviation.label(), "format_deviation");
        assert_eq!(
            SuspicionReason::OperatorOverride.label(),
            "operator_override"
        );
        assert_eq!(
            SuspicionReason::PolicyRule("x".into()).label(),
            "policy_rule"
        );
    }

    // -- RequiredProofType --

    #[test]
    fn test_required_proof_type_labels() {
        assert_eq!(
            RequiredProofType::ProvenanceAttestation.label(),
            "provenance_attestation"
        );
        assert_eq!(RequiredProofType::IntegrityProof.label(), "integrity_proof");
        assert_eq!(
            RequiredProofType::EpochBoundaryProof.label(),
            "epoch_boundary_proof"
        );
        assert_eq!(
            RequiredProofType::OriginSignature.label(),
            "origin_signature"
        );
        assert_eq!(RequiredProofType::Custom("x".into()).label(), "custom");
    }

    // -- Event codes --

    #[test]
    fn test_event_codes_defined() {
        assert!(!CHALLENGE_ISSUED.is_empty());
        assert!(!CHALLENGE_PROOF_RECEIVED.is_empty());
        assert!(!CHALLENGE_VERIFIED.is_empty());
        assert!(!CHALLENGE_TIMED_OUT.is_empty());
        assert!(!CHALLENGE_DENIED.is_empty());
        assert!(!CHALLENGE_PROMOTED.is_empty());
    }

    // -- Invariant tags --

    #[test]
    fn test_invariant_tags_defined() {
        assert!(!INV_CHALLENGE_DEFER.is_empty());
        assert!(!INV_CHALLENGE_TIMEOUT_DENY.is_empty());
        assert!(!INV_CHALLENGE_AUDIT.is_empty());
        assert!(!INV_CHALLENGE_VALID_TRANSITIONS.is_empty());
    }

    // -- ChallengeError --

    #[test]
    fn test_error_display() {
        let err =
            ChallengeError::invalid_transition(ChallengeState::Denied, ChallengeState::Promoted);
        let s = format!("{}", err);
        assert!(s.contains("Invalid transition"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let err = ChallengeError::new("TEST", "test message");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: ChallengeError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    // -- Challenge timeout check --

    #[test]
    fn test_challenge_is_timed_out() {
        let ch = Challenge {
            challenge_id: ChallengeId::new("ch-1"),
            artifact_id: ArtifactId::new("art-1"),
            state: ChallengeState::ChallengeIssued,
            reason: SuspicionReason::AgeAnomaly,
            required_proofs: vec![],
            received_proofs: vec![],
            created_at_ms: 1000,
            timeout_ms: 5000,
            trace_id: String::new(),
        };
        assert!(!ch.is_timed_out(3000));
        assert!(ch.is_timed_out(6000));
        assert!(ch.is_timed_out(6001));
    }

    // -- Metrics --

    #[test]
    fn test_metrics_after_full_flow() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "p", 2000)
            .unwrap();
        ctrl.verify_proof(&cid, "v", 3000).unwrap();
        ctrl.promote(&cid, "op", 4000).unwrap();

        let m = ctrl.metrics();
        assert_eq!(m.challenges_issued_total, 1);
        assert_eq!(m.challenges_resolved_total, 1);
        assert_eq!(m.challenges_promoted_total, 1);
        assert_eq!(m.challenges_denied_total, 0);
        assert_eq!(m.challenges_timed_out_total, 0);
    }

    // -- Serde roundtrip --

    #[test]
    fn test_challenge_state_serde() {
        let state = ChallengeState::ProofVerified;
        let json = serde_json::to_string(&state).unwrap();
        let parsed: ChallengeState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn test_challenge_metrics_serde() {
        let m = ChallengeMetrics {
            challenges_issued_total: 5,
            challenges_resolved_total: 3,
            challenges_timed_out_total: 1,
            challenges_promoted_total: 2,
            challenges_denied_total: 1,
        };
        let json = serde_json::to_string(&m).unwrap();
        let parsed: ChallengeMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.challenges_issued_total, 5);
    }
}
