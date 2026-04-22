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
use std::collections::BTreeMap;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

/// Maximum challenge records retained.  When exceeded, the oldest
/// terminal-state (Denied / Promoted) challenges are evicted first.
const MAX_CHALLENGES: usize = 4096;

/// Maximum proof submissions per challenge to prevent DoS attacks.
const MAX_RECEIVED_PROOFS_PER_CHALLENGE: usize = 64;

/// Maximum timeout operations per batch to bound memory usage.
const MAX_TIMEOUT_BATCH_SIZE: usize = 1024;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

fn update_length_prefixed(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_le_bytes());
    hasher.update(field);
}

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
pub const ERR_INVALID_ARTIFACT_ID: &str = "ERR_INVALID_ARTIFACT_ID";
pub const ERR_PROOF_INVALID: &str = "ERR_PROOF_INVALID";

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

fn invalid_artifact_id_reason(artifact_id: &ArtifactId) -> Option<String> {
    let raw = artifact_id.as_str();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some("artifact_id must not be empty".to_string());
    }
    if raw.as_bytes().contains(&b'\0') {
        return Some("artifact_id must not contain NUL bytes".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", raw));
    }
    if trimmed != raw {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    None
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
        hasher.update(b"challenge_flow_hash_v1:");
        hasher.update(
            u64::try_from(self.challenge_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.challenge_id.as_bytes());
        hasher.update(
            u64::try_from(self.artifact_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.artifact_id.as_bytes());
        hasher.update(
            u64::try_from(self.from_state.label().len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.from_state.label().as_bytes());
        hasher.update(
            u64::try_from(self.to_state.label().len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.to_state.label().as_bytes());
        hasher.update(
            u64::try_from(self.event_code.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.event_code.as_bytes());
        hasher.update(
            u64::try_from(self.actor_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.actor_id.as_bytes());
        hasher.update(self.timestamp_ms.to_le_bytes());
        hasher.update(
            u64::try_from(self.detail.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.detail.as_bytes());
        hasher.update(
            u64::try_from(self.prev_hash.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.prev_hash.as_bytes());
        hex::encode(hasher.finalize())
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
    challenges: BTreeMap<ChallengeId, Challenge>,
    audit_log: Vec<ChallengeAuditEntry>,
    /// Anchor hash: entry hash of the most recently evicted audit entry.
    /// Used to maintain hash-chain integrity after bounded eviction.
    chain_anchor_hash: Option<String>,
    config: ChallengeConfig,
    metrics: ChallengeMetrics,
    next_id: u64,
}

impl ChallengeFlowController {
    pub fn new(config: ChallengeConfig) -> Self {
        Self {
            challenges: BTreeMap::new(),
            audit_log: Vec::new(),
            chain_anchor_hash: None,
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
        if let Some(reason) = invalid_artifact_id_reason(&artifact_id) {
            return Err(ChallengeError::new(ERR_INVALID_ARTIFACT_ID, reason));
        }

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
        self.next_id = self.next_id.saturating_add(1);

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
        self.evict_terminal_challenges();
        self.metrics.challenges_issued_total =
            self.metrics.challenges_issued_total.saturating_add(1);

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

        // SECURITY: Validate that the proof type is actually required for this challenge
        if !challenge
            .required_proofs
            .iter()
            .any(|required| match (required, &proof.proof_type) {
                (
                    RequiredProofType::ProvenanceAttestation,
                    RequiredProofType::ProvenanceAttestation,
                ) => true,
                (RequiredProofType::IntegrityProof, RequiredProofType::IntegrityProof) => true,
                (RequiredProofType::EpochBoundaryProof, RequiredProofType::EpochBoundaryProof) => {
                    true
                }
                (RequiredProofType::OriginSignature, RequiredProofType::OriginSignature) => true,
                (RequiredProofType::Custom(a), RequiredProofType::Custom(b)) => a == b,
                _ => false,
            })
        {
            return Err(ChallengeError::new(
                ERR_PROOF_INVALID,
                &format!(
                    "Proof type {:?} not required for this challenge",
                    proof.proof_type.label()
                ),
            ));
        }

        // SECURITY: Validate data_hash format (must be valid hex)
        if proof.data_hash.is_empty() {
            return Err(ChallengeError::new(
                ERR_PROOF_INVALID,
                "Proof data_hash cannot be empty",
            ));
        }
        if !proof.data_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ChallengeError::new(
                ERR_PROOF_INVALID,
                "Proof data_hash must be valid hexadecimal",
            ));
        }
        if proof.data_hash.len() < 32 || proof.data_hash.len() > 128 {
            return Err(ChallengeError::new(
                ERR_PROOF_INVALID,
                "Proof data_hash length must be between 32 and 128 characters",
            ));
        }

        // SECURITY: Validate submitter_id format
        if proof.submitter_id.trim().is_empty() {
            return Err(ChallengeError::new(
                ERR_PROOF_INVALID,
                "Submitter ID cannot be empty",
            ));
        }

        // SECURITY: Check for duplicate proof submissions of the same type
        let duplicate_exists = challenge.received_proofs.iter().any(|existing| {
            match (&existing.proof_type, &proof.proof_type) {
                (
                    RequiredProofType::ProvenanceAttestation,
                    RequiredProofType::ProvenanceAttestation,
                ) => true,
                (RequiredProofType::IntegrityProof, RequiredProofType::IntegrityProof) => true,
                (RequiredProofType::EpochBoundaryProof, RequiredProofType::EpochBoundaryProof) => {
                    true
                }
                (RequiredProofType::OriginSignature, RequiredProofType::OriginSignature) => true,
                (RequiredProofType::Custom(a), RequiredProofType::Custom(b)) => a == b,
                _ => false,
            }
        });
        if duplicate_exists {
            return Err(ChallengeError::new(
                ERR_PROOF_INVALID,
                &format!(
                    "Proof of type {} already submitted for this challenge",
                    proof.proof_type.label()
                ),
            ));
        }

        let artifact_id = challenge.artifact_id.clone();
        let old_state = challenge.state;
        push_bounded(
            &mut challenge.received_proofs,
            proof,
            MAX_RECEIVED_PROOFS_PER_CHALLENGE,
        );
        challenge.state = ChallengeState::ProofReceived;

        self.log_transition(
            challenge_id,
            &artifact_id,
            old_state,
            ChallengeState::ProofReceived,
            CHALLENGE_PROOF_RECEIVED,
            actor_id,
            timestamp_ms,
            "Proof artifact received and validated",
        );

        Ok(())
    }

    /// Verify submitted proofs for a challenge and mark as verified if valid.
    pub fn verify_proof(
        &mut self,
        challenge_id: &ChallengeId,
        actor_id: &str,
        timestamp_ms: u64,
    ) -> Result<(), ChallengeError> {
        let (artifact_id, old_state) = {
            let challenge = self.challenges.get(challenge_id).ok_or_else(|| {
                ChallengeError::new(ERR_NO_ACTIVE_CHALLENGE, "Challenge not found")
            })?;

            if !challenge
                .state
                .can_transition_to(ChallengeState::ProofVerified)
            {
                return Err(ChallengeError::invalid_transition(
                    challenge.state,
                    ChallengeState::ProofVerified,
                ));
            }

            // SECURITY: Verify we have received at least one proof
            if challenge.received_proofs.is_empty() {
                return Err(ChallengeError::new(
                    ERR_PROOF_INVALID,
                    "Cannot verify challenge: no proofs have been submitted",
                ));
            }

            // SECURITY: Verify that all required proof types have been submitted
            for required_type in &challenge.required_proofs {
                let type_submitted = challenge.received_proofs.iter().any(|proof| {
                    match (required_type, &proof.proof_type) {
                        (
                            RequiredProofType::ProvenanceAttestation,
                            RequiredProofType::ProvenanceAttestation,
                        ) => true,
                        (RequiredProofType::IntegrityProof, RequiredProofType::IntegrityProof) => {
                            true
                        }
                        (
                            RequiredProofType::EpochBoundaryProof,
                            RequiredProofType::EpochBoundaryProof,
                        ) => true,
                        (
                            RequiredProofType::OriginSignature,
                            RequiredProofType::OriginSignature,
                        ) => true,
                        (RequiredProofType::Custom(a), RequiredProofType::Custom(b)) => a == b,
                        _ => false,
                    }
                });

                if !type_submitted {
                    return Err(ChallengeError::new(
                        ERR_PROOF_INVALID,
                        &format!(
                            "Required proof type {} has not been submitted",
                            required_type.label()
                        ),
                    ));
                }
            }

            // SECURITY: Verify each submitted proof's cryptographic integrity
            for proof in &challenge.received_proofs {
                // Verify the proof data hash is consistent with the artifact being challenged
                let expected_hash =
                    Self::compute_expected_proof_hash(&challenge.artifact_id, &proof.proof_type)?;

                if !crate::security::constant_time::ct_eq(&proof.data_hash, &expected_hash) {
                    return Err(ChallengeError::new(
                        ERR_PROOF_INVALID,
                        &format!(
                            "Proof data hash verification failed for type {}",
                            proof.proof_type.label()
                        ),
                    ));
                }

                // Verify proof timestamp is within acceptable bounds
                let proof_age_ms = timestamp_ms.saturating_sub(proof.submitted_at_ms);
                if proof_age_ms > 3600_000 {
                    // 1 hour max age
                    return Err(ChallengeError::new(
                        ERR_PROOF_INVALID,
                        &format!(
                            "Proof for type {} is too old (age: {}ms)",
                            proof.proof_type.label(),
                            proof_age_ms
                        ),
                    ));
                }
            }

            (challenge.artifact_id.clone(), challenge.state)
        };
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| ChallengeError::new(ERR_NO_ACTIVE_CHALLENGE, "Challenge not found"))?;
        challenge.state = ChallengeState::ProofVerified;

        self.log_transition(
            challenge_id,
            &artifact_id,
            old_state,
            ChallengeState::ProofVerified,
            CHALLENGE_VERIFIED,
            actor_id,
            timestamp_ms,
            "Proof cryptographically verified successfully",
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
        self.metrics.challenges_resolved_total =
            self.metrics.challenges_resolved_total.saturating_add(1);
        self.metrics.challenges_promoted_total =
            self.metrics.challenges_promoted_total.saturating_add(1);

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
        self.metrics.challenges_resolved_total =
            self.metrics.challenges_resolved_total.saturating_add(1);
        self.metrics.challenges_denied_total =
            self.metrics.challenges_denied_total.saturating_add(1);

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
            .take(MAX_TIMEOUT_BATCH_SIZE)
            .map(|ch| (ch.challenge_id.clone(), ch.artifact_id.clone(), ch.state))
            .collect();

        let mut denied_ids = Vec::with_capacity(timed_out.len());
        for (cid, aid, old_state) in timed_out {
            if let Some(ch) = self.challenges.get_mut(&cid) {
                ch.state = ChallengeState::Denied;
                self.metrics.challenges_timed_out_total =
                    self.metrics.challenges_timed_out_total.saturating_add(1);
                self.metrics.challenges_resolved_total =
                    self.metrics.challenges_resolved_total.saturating_add(1);
                self.metrics.challenges_denied_total =
                    self.metrics.challenges_denied_total.saturating_add(1);

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

    /// Compute the expected proof hash for cryptographic verification.
    ///
    /// SECURITY: This provides domain separation between different proof types
    /// and artifacts to prevent cross-proof attacks.
    fn compute_expected_proof_hash(
        artifact_id: &ArtifactId,
        proof_type: &RequiredProofType,
    ) -> Result<String, ChallengeError> {
        let mut hasher = Sha256::new();
        hasher.update(b"challenge_proof_v1:");
        update_length_prefixed(&mut hasher, artifact_id.as_str().as_bytes());

        // Add proof-type-specific context for additional security
        match proof_type {
            RequiredProofType::ProvenanceAttestation => {
                update_length_prefixed(&mut hasher, b"provenance_attestation");
            }
            RequiredProofType::IntegrityProof => {
                update_length_prefixed(&mut hasher, b"integrity_verification");
            }
            RequiredProofType::EpochBoundaryProof => {
                update_length_prefixed(&mut hasher, b"epoch_boundary_validation");
            }
            RequiredProofType::OriginSignature => {
                update_length_prefixed(&mut hasher, b"origin_signature_verification");
            }
            RequiredProofType::Custom(custom_type) => {
                update_length_prefixed(&mut hasher, b"custom");
                update_length_prefixed(&mut hasher, custom_type.as_bytes());
            }
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// Evict oldest terminal-state challenges when the map exceeds capacity.
    fn evict_terminal_challenges(&mut self) {
        while self.challenges.len() > MAX_CHALLENGES {
            // Find the first terminal challenge (BTreeMap iterates in key order,
            // and keys are sequential "ch-N" so the first terminal entry is the
            // oldest completed challenge).
            let evict_key = self
                .challenges
                .iter()
                .find(|(_, ch)| ch.state.is_terminal())
                .map(|(k, _)| k.clone());
            match evict_key {
                Some(key) => {
                    self.challenges.remove(&key);
                }
                None => break, // no terminal challenges to evict
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
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
        let prev_hash = self.audit_log.last().map(|e| e.hash()).unwrap_or_else(|| {
            self.chain_anchor_hash
                .clone()
                .unwrap_or_else(|| "0".repeat(64))
        });

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

        if self.audit_log.len() >= MAX_AUDIT_LOG_ENTRIES {
            let overflow = self
                .audit_log
                .len()
                .saturating_sub(MAX_AUDIT_LOG_ENTRIES)
                .saturating_add(1);
            if let Some(anchor_entry) = self.audit_log.get(overflow.saturating_sub(1)) {
                self.chain_anchor_hash = Some(anchor_entry.hash());
            }
            self.audit_log.drain(0..overflow.min(self.audit_log.len()));
        }
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
    fn test_issue_rejects_empty_artifact_id() {
        let mut ctrl = make_controller();
        let err = ctrl
            .issue_challenge(
                ArtifactId::new(""),
                SuspicionReason::AgeAnomaly,
                vec![],
                "op",
                1000,
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(err.message.contains("empty"));
    }

    #[test]
    fn test_issue_rejects_reserved_artifact_id() {
        let mut ctrl = make_controller();
        let err = ctrl
            .issue_challenge(
                ArtifactId::new(RESERVED_ARTIFACT_ID),
                SuspicionReason::AgeAnomaly,
                vec![],
                "op",
                1000,
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(err.message.contains("reserved"));
    }

    #[test]
    fn test_issue_rejects_whitespace_artifact_id() {
        let mut ctrl = make_controller();
        let err = ctrl
            .issue_challenge(
                ArtifactId::new(" art-1 "),
                SuspicionReason::AgeAnomaly,
                vec![],
                "op",
                1000,
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(err.message.contains("whitespace"));
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
        assert_eq!(ctrl.audit_log().len(), 2);
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

    #[test]
    fn test_expected_proof_hash_length_prefixes_custom_boundaries() {
        let first = ChallengeFlowController::compute_expected_proof_hash(
            &ArtifactId::new("a"),
            &RequiredProofType::Custom("b:custom:c".to_string()),
        )
        .unwrap();
        let second = ChallengeFlowController::compute_expected_proof_hash(
            &ArtifactId::new("a:custom:b"),
            &RequiredProofType::Custom("c".to_string()),
        )
        .unwrap();

        assert_ne!(first, second);
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

    #[test]
    fn invalid_artifact_id_after_valid_issue_does_not_mutate_controller() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);

        let err = ctrl
            .issue_challenge(
                ArtifactId::new("\tart-2\n"),
                SuspicionReason::FormatDeviation,
                vec![RequiredProofType::IntegrityProof],
                "operator-2",
                2000,
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert_eq!(ctrl.metrics().challenges_issued_total, 1);
        assert_eq!(ctrl.audit_log().len(), 1);
        assert!(ctrl.get_challenge(&cid).is_some());
    }

    #[test]
    fn duplicate_active_challenge_does_not_increment_metrics_or_audit() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);

        let err = ctrl
            .issue_challenge(
                ArtifactId::new("art-1"),
                SuspicionReason::PolicyRule("duplicate".into()),
                vec![RequiredProofType::OriginSignature],
                "operator-2",
                2000,
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_CHALLENGE_ACTIVE);
        assert_eq!(ctrl.metrics().challenges_issued_total, 1);
        assert_eq!(ctrl.audit_log().len(), 1);
        assert_eq!(ctrl.active_challenges().len(), 1);
    }

    #[test]
    fn submit_proof_for_unknown_challenge_does_not_append_audit() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);

        let err = ctrl
            .submit_proof(&ChallengeId::new("ch-missing"), make_proof(2000), "p", 2000)
            .unwrap_err();

        assert_eq!(err.code, ERR_NO_ACTIVE_CHALLENGE);
        assert_eq!(ctrl.audit_log().len(), 1);
        assert_eq!(ctrl.metrics().challenges_resolved_total, 0);
    }

    #[test]
    fn verify_unknown_challenge_does_not_append_audit() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);

        let err = ctrl
            .verify_proof(&ChallengeId::new("ch-missing"), "verifier", 2000)
            .unwrap_err();

        assert_eq!(err.code, ERR_NO_ACTIVE_CHALLENGE);
        assert_eq!(ctrl.audit_log().len(), 1);
        assert_eq!(ctrl.metrics().challenges_resolved_total, 0);
    }

    #[test]
    fn promote_unknown_challenge_does_not_increment_metrics() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);

        let err = ctrl
            .promote(&ChallengeId::new("ch-missing"), "operator", 2000)
            .unwrap_err();

        assert_eq!(err.code, ERR_NO_ACTIVE_CHALLENGE);
        assert_eq!(ctrl.metrics().challenges_promoted_total, 0);
        assert_eq!(ctrl.metrics().challenges_resolved_total, 0);
        assert_eq!(ctrl.audit_log().len(), 1);
    }

    #[test]
    fn deny_unknown_challenge_does_not_increment_metrics() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);

        let err = ctrl
            .deny(&ChallengeId::new("ch-missing"), "operator", 2000, "missing")
            .unwrap_err();

        assert_eq!(err.code, ERR_NO_ACTIVE_CHALLENGE);
        assert_eq!(ctrl.metrics().challenges_denied_total, 0);
        assert_eq!(ctrl.metrics().challenges_resolved_total, 0);
        assert_eq!(ctrl.audit_log().len(), 1);
    }

    #[test]
    fn invalid_transition_after_denial_does_not_append_audit() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.deny(&cid, "operator", 2000, "manual denial").unwrap();
        let audit_len = ctrl.audit_log().len();

        let err = ctrl.verify_proof(&cid, "verifier", 3000).unwrap_err();

        assert_eq!(err.code, ERR_INVALID_TRANSITION);
        assert_eq!(ctrl.audit_log().len(), audit_len);
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
    }

    #[test]
    fn clock_regression_does_not_timeout_active_challenge() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 10_000);

        let denied = ctrl.enforce_timeouts(9_999);

        assert!(denied.is_empty());
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::ChallengeIssued
        );
        assert_eq!(ctrl.metrics().challenges_timed_out_total, 0);
    }

    #[test]
    fn duplicate_proof_submission_after_receipt_is_rejected_without_mutation() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "prover", 2000)
            .unwrap();
        let audit_len = ctrl.audit_log().len();

        let err = ctrl
            .submit_proof(&cid, make_proof(3000), "prover", 3000)
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_TRANSITION);
        let challenge = ctrl.get_challenge(&cid).unwrap();
        assert_eq!(challenge.state, ChallengeState::ProofReceived);
        assert_eq!(challenge.received_proofs.len(), 1);
        assert_eq!(ctrl.audit_log().len(), audit_len);
    }

    #[test]
    fn deny_after_promotion_is_rejected_without_double_counting_resolution() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "prover", 2000)
            .unwrap();
        ctrl.verify_proof(&cid, "verifier", 3000).unwrap();
        ctrl.promote(&cid, "operator", 4000).unwrap();
        let audit_len = ctrl.audit_log().len();

        let err = ctrl
            .deny(&cid, "operator", 5000, "late denial")
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_TRANSITION);
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Promoted
        );
        assert_eq!(ctrl.metrics().challenges_resolved_total, 1);
        assert_eq!(ctrl.metrics().challenges_denied_total, 0);
        assert_eq!(ctrl.metrics().challenges_promoted_total, 1);
        assert_eq!(ctrl.audit_log().len(), audit_len);
    }

    #[test]
    fn timeout_at_exact_deadline_denies_once_only() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);

        let first = ctrl.enforce_timeouts(31_000);
        let second = ctrl.enforce_timeouts(31_001);

        assert_eq!(first, vec![cid.clone()]);
        assert!(second.is_empty());
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
        assert_eq!(ctrl.metrics().challenges_timed_out_total, 1);
        assert_eq!(ctrl.metrics().challenges_denied_total, 1);
        assert_eq!(ctrl.metrics().challenges_resolved_total, 1);
    }

    #[test]
    fn timeout_enforcement_processes_one_reported_batch_at_a_time() {
        let mut ctrl = make_controller();
        let total = MAX_TIMEOUT_BATCH_SIZE + 1;
        let total_u64 = u64::try_from(total).expect("timeout batch test size fits in u64");
        let batch_u64 =
            u64::try_from(MAX_TIMEOUT_BATCH_SIZE).expect("timeout batch cap fits in u64");

        for idx in 0..total {
            ctrl.issue_challenge(
                ArtifactId::new(format!("art-{idx}")),
                SuspicionReason::UnexpectedProvenance,
                vec![RequiredProofType::ProvenanceAttestation],
                "operator-1",
                1000,
            )
            .unwrap();
        }

        let first = ctrl.enforce_timeouts(31_000);

        assert_eq!(first.len(), MAX_TIMEOUT_BATCH_SIZE);
        assert_eq!(ctrl.active_challenges().len(), 1);
        assert_eq!(ctrl.metrics().challenges_timed_out_total, batch_u64);
        assert_eq!(ctrl.metrics().challenges_denied_total, batch_u64);
        assert_eq!(ctrl.metrics().challenges_resolved_total, batch_u64);

        let second = ctrl.enforce_timeouts(31_001);

        assert_eq!(second.len(), 1);
        assert!(ctrl.active_challenges().is_empty());
        assert_eq!(ctrl.metrics().challenges_timed_out_total, total_u64);
        assert_eq!(ctrl.metrics().challenges_denied_total, total_u64);
        assert_eq!(ctrl.metrics().challenges_resolved_total, total_u64);
    }

    #[test]
    fn timeout_disabled_at_deadline_does_not_emit_denial_audit() {
        let mut ctrl = ChallengeFlowController::new(ChallengeConfig {
            timeout_ms: 30_000,
            deny_on_timeout: false,
        });
        let cid = issue_basic(&mut ctrl, 1000);
        let audit_len = ctrl.audit_log().len();

        let denied = ctrl.enforce_timeouts(31_000);

        assert!(denied.is_empty());
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::ChallengeIssued
        );
        assert_eq!(ctrl.audit_log().len(), audit_len);
        assert_eq!(ctrl.metrics().challenges_denied_total, 0);
    }

    #[test]
    fn submit_after_timeout_denial_is_rejected_without_extra_audit() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.enforce_timeouts(31_000);
        let audit_len = ctrl.audit_log().len();

        let err = ctrl
            .submit_proof(&cid, make_proof(32_000), "prover", 32_000)
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_TRANSITION);
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
        assert_eq!(ctrl.audit_log().len(), audit_len);
        assert_eq!(ctrl.metrics().challenges_resolved_total, 1);
    }

    #[test]
    fn audit_query_does_not_normalize_artifact_id_aliases() {
        let mut ctrl = make_controller();
        issue_basic(&mut ctrl, 1000);

        assert!(ctrl.audit_query(&ArtifactId::new(" art-1 ")).is_empty());
        assert!(ctrl.audit_query(&ArtifactId::new("ART-1")).is_empty());
        assert!(ctrl.audit_query(&ArtifactId::new("art-1\0")).is_empty());
    }

    #[test]
    fn challenge_audit_does_not_normalize_challenge_id_aliases() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);

        assert!(!ctrl.challenge_audit(&cid).is_empty());
        assert!(ctrl.challenge_audit(&ChallengeId::new("CH-1")).is_empty());
        assert!(ctrl.challenge_audit(&ChallengeId::new(" ch-1 ")).is_empty());
        assert!(ctrl.challenge_audit(&ChallengeId::new("ch-1\0")).is_empty());
    }

    fn assert_json_rejected<T>(json: &str)
    where
        T: serde::de::DeserializeOwned,
    {
        assert!(
            serde_json::from_str::<T>(json).is_err(),
            "malformed json should be rejected: {json}"
        );
    }

    #[test]
    fn serde_rejects_unknown_challenge_state_variant() {
        assert_json_rejected::<ChallengeState>(r#""Expired""#);
    }

    #[test]
    fn serde_rejects_unknown_suspicion_reason_variant() {
        assert_json_rejected::<SuspicionReason>(r#""SupplyChainMagic""#);
    }

    #[test]
    fn serde_rejects_required_proof_type_wrong_custom_payload() {
        assert_json_rejected::<RequiredProofType>(r#"{"Custom": 42}"#);
    }

    #[test]
    fn serde_rejects_challenge_config_negative_timeout() {
        assert_json_rejected::<ChallengeConfig>(
            r#"{
                "timeout_ms": -1,
                "deny_on_timeout": true
            }"#,
        );
    }

    #[test]
    fn serde_rejects_proof_submission_string_timestamp() {
        assert_json_rejected::<ProofSubmission>(
            r#"{
                "proof_type": "IntegrityProof",
                "data_hash": "abc123",
                "submitter_id": "prover-1",
                "submitted_at_ms": "2000"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_challenge_missing_trace_id() {
        assert_json_rejected::<Challenge>(
            r#"{
                "challenge_id": "ch-1",
                "artifact_id": "art-1",
                "state": "ChallengeIssued",
                "reason": "AgeAnomaly",
                "required_proofs": [],
                "received_proofs": [],
                "created_at_ms": 1000,
                "timeout_ms": 30000
            }"#,
        );
    }

    #[test]
    fn serde_rejects_challenge_audit_entry_string_timestamp() {
        assert_json_rejected::<ChallengeAuditEntry>(
            r#"{
                "challenge_id": "ch-1",
                "artifact_id": "art-1",
                "from_state": "Pending",
                "to_state": "ChallengeIssued",
                "event_code": "CHALLENGE_ISSUED",
                "actor_id": "operator-1",
                "timestamp_ms": "1000",
                "detail": "issued",
                "prev_hash": "0000"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_challenge_metrics_negative_counter() {
        assert_json_rejected::<ChallengeMetrics>(
            r#"{
                "challenges_issued_total": -1,
                "challenges_resolved_total": 0,
                "challenges_timed_out_total": 0,
                "challenges_promoted_total": 0,
                "challenges_denied_total": 0
            }"#,
        );
    }

    #[test]
    fn serde_rejects_challenge_error_numeric_code() {
        assert_json_rejected::<ChallengeError>(
            r#"{
                "code": 409,
                "message": "conflict"
            }"#,
        );
    }

    #[test]
    fn issue_rejects_null_byte_artifact_id_without_mutation() {
        let mut ctrl = make_controller();

        let err = ctrl
            .issue_challenge(
                ArtifactId::new("artifact\0evil"),
                SuspicionReason::OperatorOverride,
                vec![RequiredProofType::IntegrityProof],
                "operator-null",
                1000,
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(err.message.contains("NUL"));
        assert_eq!(ctrl.metrics().challenges_issued_total, 0);
        assert!(ctrl.audit_log().is_empty());
        assert!(ctrl.active_challenges().is_empty());
    }

    #[test]
    fn issue_rejects_whitespace_reserved_artifact_id_as_whitespace() {
        let mut ctrl = make_controller();

        let err = ctrl
            .issue_challenge(
                ArtifactId::new(" <unknown> "),
                SuspicionReason::PolicyRule("reserved-alias".to_string()),
                vec![RequiredProofType::OriginSignature],
                "operator-reserved",
                1000,
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(err.message.contains("whitespace"));
        assert_eq!(ctrl.metrics().challenges_issued_total, 0);
        assert!(ctrl.audit_log().is_empty());
    }

    #[test]
    fn promote_after_manual_denial_rejected_without_metric_drift() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.deny(&cid, "operator", 2000, "manual denial").unwrap();
        let audit_len = ctrl.audit_log().len();

        let err = ctrl.promote(&cid, "operator", 3000).unwrap_err();

        assert_eq!(err.code, ERR_INVALID_TRANSITION);
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
        assert_eq!(ctrl.metrics().challenges_resolved_total, 1);
        assert_eq!(ctrl.metrics().challenges_denied_total, 1);
        assert_eq!(ctrl.metrics().challenges_promoted_total, 0);
        assert_eq!(ctrl.audit_log().len(), audit_len);
    }

    #[test]
    fn verify_after_promotion_rejected_without_extra_audit() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);
        ctrl.submit_proof(&cid, make_proof(2000), "prover", 2000)
            .unwrap();
        ctrl.verify_proof(&cid, "verifier", 3000).unwrap();
        ctrl.promote(&cid, "operator", 4000).unwrap();
        let audit_len = ctrl.audit_log().len();

        let err = ctrl.verify_proof(&cid, "verifier", 5000).unwrap_err();

        assert_eq!(err.code, ERR_INVALID_TRANSITION);
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Promoted
        );
        assert_eq!(ctrl.audit_log().len(), audit_len);
        assert_eq!(ctrl.metrics().challenges_promoted_total, 1);
    }

    #[test]
    fn submit_proof_unknown_on_empty_controller_keeps_state_empty() {
        let mut ctrl = make_controller();

        let err = ctrl
            .submit_proof(
                &ChallengeId::new("ch-never-issued"),
                make_proof(1000),
                "p",
                1000,
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_NO_ACTIVE_CHALLENGE);
        assert!(ctrl.audit_log().is_empty());
        assert!(ctrl.active_challenges().is_empty());
        assert_eq!(ctrl.metrics().challenges_resolved_total, 0);
    }

    #[test]
    fn challenge_zero_timeout_is_timed_out_at_creation_time() {
        let challenge = Challenge {
            challenge_id: ChallengeId::new("ch-zero-timeout"),
            artifact_id: ArtifactId::new("art-zero-timeout"),
            state: ChallengeState::ChallengeIssued,
            reason: SuspicionReason::AgeAnomaly,
            required_proofs: vec![RequiredProofType::IntegrityProof],
            received_proofs: Vec::new(),
            created_at_ms: 5000,
            timeout_ms: 0,
            trace_id: "trace-zero-timeout".to_string(),
        };

        assert!(challenge.is_timed_out(5000));
        assert!(challenge.is_timed_out(4999));
    }

    #[test]
    fn zero_timeout_controller_denies_at_creation_time_once() {
        let mut ctrl = ChallengeFlowController::new(ChallengeConfig {
            timeout_ms: 0,
            deny_on_timeout: true,
        });
        let cid = ctrl
            .issue_challenge(
                ArtifactId::new("art-zero-timeout"),
                SuspicionReason::AgeAnomaly,
                vec![RequiredProofType::IntegrityProof],
                "operator",
                5000,
            )
            .unwrap();

        let first = ctrl.enforce_timeouts(5000);
        let second = ctrl.enforce_timeouts(5001);

        assert_eq!(first, vec![cid.clone()]);
        assert!(second.is_empty());
        assert_eq!(
            ctrl.get_challenge(&cid).unwrap().state,
            ChallengeState::Denied
        );
        assert_eq!(ctrl.metrics().challenges_timed_out_total, 1);
        assert_eq!(ctrl.metrics().challenges_resolved_total, 1);
        assert_eq!(ctrl.metrics().challenges_denied_total, 1);
    }

    // ---------------------------------------------------------------------------
    // NEGATIVE-PATH TESTS: Security hardening for challenge flow
    // ---------------------------------------------------------------------------

    #[test]
    fn negative_unicode_injection_in_challenge_identifiers_and_audit_fields() {
        let mut ctrl = make_controller();

        // Unicode injection in artifact ID (should pass validation first)
        let malicious_artifact = ArtifactId::new("artifact\u{202E}suoicilam\u{202D}legitimate");
        let cid = ctrl
            .issue_challenge(
                malicious_artifact.clone(),
                SuspicionReason::PolicyRule("rule\u{200B}\u{200C}hidden\u{FEFF}name".to_string()),
                vec![
                    RequiredProofType::Custom("\u{202E}ggats\u{202D}legitimate_proof".to_string()),
                    RequiredProofType::ProvenanceAttestation,
                ],
                "operator\u{0000}\ninjection\r\tmalicious",
                1000,
            )
            .unwrap();

        // Verify Unicode is preserved in challenge data
        let challenge = ctrl.get_challenge(&cid).unwrap();
        assert!(challenge.artifact_id.as_str().contains('\u{202E}'));
        if let SuspicionReason::PolicyRule(rule) = &challenge.reason {
            assert!(rule.contains('\u{200B}'));
        }

        // Unicode injection in proof submission
        let malicious_proof = ProofSubmission {
            proof_type: RequiredProofType::Custom("proof\u{202E}kcatta\u{202D}normal".to_string()),
            data_hash: "hash\u{2028}injection\u{2029}line\u{0085}separator".to_string(),
            submitter_id: "submitter\u{000C}\u{000B}control\u{0007}chars".to_string(),
            submitted_at_ms: u64::MAX, // Also test timestamp overflow
        };

        ctrl.submit_proof(
            &cid,
            malicious_proof,
            "actor\u{0000}\nmore\rinjection\ttabs",
            2000,
        )
        .unwrap();

        // Unicode injection in denial reason
        ctrl.deny(
            &cid,
            "denial_actor\u{202E}rotca_laer\u{202D}fake",
            3000,
            "reason with\u{0000}null\nbytes\rand\ttabs\u{202E}attack\u{202D}hidden",
        )
        .unwrap();

        // Verify audit log preserves Unicode injection for analysis
        let audit_entries = ctrl.challenge_audit(&cid);
        assert_eq!(audit_entries.len(), 3); // Issue, submit, deny

        // Check that Unicode is preserved in audit entries
        let issue_entry = &audit_entries[0];
        assert!(issue_entry.artifact_id.contains('\u{202E}'));
        assert!(issue_entry.actor_id.contains('\u{0000}'));

        let submit_entry = &audit_entries[1];
        assert!(submit_entry.actor_id.contains('\u{0000}'));

        let deny_entry = &audit_entries[2];
        assert!(deny_entry.actor_id.contains('\u{202E}'));
        assert!(deny_entry.detail.contains('\u{0000}'));

        // Test path traversal injection in various fields
        let traversal_artifact = ArtifactId::new("../../../etc/passwd\0\ntraversal");
        let traversal_result = ctrl.issue_challenge(
            traversal_artifact.clone(),
            SuspicionReason::OperatorOverride,
            vec![RequiredProofType::OriginSignature],
            "../../../admin\0\nuser",
            4000,
        );

        // Should be rejected due to null byte in artifact ID
        assert!(traversal_result.is_err());
        assert_eq!(traversal_result.unwrap_err().code, ERR_INVALID_ARTIFACT_ID);
    }

    #[test]
    fn negative_hash_chain_manipulation_and_audit_corruption_attacks() {
        let mut ctrl = make_controller();

        // Create several challenges to build a hash chain
        let mut challenge_ids = Vec::new();
        for i in 0..5 {
            let artifact_id = ArtifactId::new(&format!("artifact_{}", i));
            let cid = ctrl
                .issue_challenge(
                    artifact_id,
                    SuspicionReason::AgeAnomaly,
                    vec![RequiredProofType::IntegrityProof],
                    &format!("operator_{}", i),
                    1000 + i as u64 * 100,
                )
                .unwrap();
            challenge_ids.push(cid);
        }

        // Verify hash chain integrity
        let audit_log = ctrl.audit_log();
        assert_eq!(audit_log.len(), 5);

        // First entry should have zero hash as prev_hash
        assert_eq!(audit_log[0].prev_hash, "0".repeat(64));

        // Each subsequent entry should reference previous entry's hash
        for i in 1..audit_log.len() {
            let expected_prev = audit_log[i - 1].hash();
            let actual_prev = &audit_log[i].prev_hash;
            assert_eq!(
                *actual_prev, expected_prev,
                "Hash chain broken at index {}",
                i
            );
        }

        // Test hash collision resistance with crafted entries
        let entry1 = &audit_log[0];
        let entry2 = &audit_log[1];

        // Verify different entries have different hashes
        assert_ne!(entry1.hash(), entry2.hash());

        // Test hash consistency - same entry should always produce same hash
        let consistent_hash1 = entry1.hash();
        let consistent_hash2 = entry1.hash();
        assert_eq!(consistent_hash1, consistent_hash2);

        // Test hash with extreme field values
        let extreme_entry = ChallengeAuditEntry {
            challenge_id: "ch\u{202E}kcatta\u{202D}legitimate".to_string(),
            artifact_id: "artifact\u{0000}\n\r\t".to_string(),
            from_state: ChallengeState::Pending,
            to_state: ChallengeState::Denied,
            event_code: "EVENT\u{200B}HIDDEN\u{FEFF}CODE".to_string(),
            actor_id: "actor\u{202E}rotca\u{202D}fake".to_string(),
            timestamp_ms: u64::MAX,
            detail: "A".repeat(1_000_000), // 1MB detail string
            prev_hash: "0".repeat(64),
        };

        let extreme_hash = extreme_entry.hash();
        assert_eq!(extreme_hash.len(), 64); // SHA-256 hex string
        assert!(extreme_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Test hash with empty and minimal fields
        let minimal_entry = ChallengeAuditEntry {
            challenge_id: "".to_string(),
            artifact_id: "".to_string(),
            from_state: ChallengeState::Pending,
            to_state: ChallengeState::Promoted,
            event_code: "".to_string(),
            actor_id: "".to_string(),
            timestamp_ms: 0,
            detail: "".to_string(),
            prev_hash: "".to_string(),
        };

        let minimal_hash = minimal_entry.hash();
        assert_eq!(minimal_hash.len(), 64);
        assert_ne!(minimal_hash, extreme_hash);

        // Test audit log bounded eviction preserves chain anchor
        for i in 0..MAX_AUDIT_LOG_ENTRIES + 10 {
            let artifact = ArtifactId::new(&format!("overflow_artifact_{}", i));
            let _ = ctrl.issue_challenge(
                artifact,
                SuspicionReason::FormatDeviation,
                vec![RequiredProofType::EpochBoundaryProof],
                &format!("overflow_operator_{}", i),
                10000 + i as u64,
            );
        }

        // Audit log should be bounded
        assert!(ctrl.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES);

        // Chain anchor should be set after eviction
        assert!(ctrl.chain_anchor_hash.is_some());
    }

    #[test]
    fn negative_state_transition_bypass_and_manipulation_attacks() {
        let mut ctrl = make_controller();
        let cid = issue_basic(&mut ctrl, 1000);

        // Test all invalid transition attempts from each state
        let invalid_transitions = vec![
            // From Pending (should only allow ChallengeIssued, Denied)
            (ChallengeState::Pending, ChallengeState::ProofReceived),
            (ChallengeState::Pending, ChallengeState::ProofVerified),
            (ChallengeState::Pending, ChallengeState::Promoted),
            // From ChallengeIssued (should only allow ProofReceived, Denied)
            (ChallengeState::ChallengeIssued, ChallengeState::Pending),
            (
                ChallengeState::ChallengeIssued,
                ChallengeState::ProofVerified,
            ),
            (ChallengeState::ChallengeIssued, ChallengeState::Promoted),
            // From ProofReceived (should only allow ProofVerified, Denied)
            (ChallengeState::ProofReceived, ChallengeState::Pending),
            (
                ChallengeState::ProofReceived,
                ChallengeState::ChallengeIssued,
            ),
            (ChallengeState::ProofReceived, ChallengeState::Promoted),
            // From ProofVerified (should only allow Promoted, Denied)
            (ChallengeState::ProofVerified, ChallengeState::Pending),
            (
                ChallengeState::ProofVerified,
                ChallengeState::ChallengeIssued,
            ),
            (ChallengeState::ProofVerified, ChallengeState::ProofReceived),
            // From terminal states (should allow nothing)
            (ChallengeState::Denied, ChallengeState::Pending),
            (ChallengeState::Denied, ChallengeState::ChallengeIssued),
            (ChallengeState::Denied, ChallengeState::ProofReceived),
            (ChallengeState::Denied, ChallengeState::ProofVerified),
            (ChallengeState::Denied, ChallengeState::Promoted),
            (ChallengeState::Promoted, ChallengeState::Pending),
            (ChallengeState::Promoted, ChallengeState::ChallengeIssued),
            (ChallengeState::Promoted, ChallengeState::ProofReceived),
            (ChallengeState::Promoted, ChallengeState::ProofVerified),
            (ChallengeState::Promoted, ChallengeState::Denied),
        ];

        for (from_state, to_state) in invalid_transitions {
            assert!(
                !from_state.can_transition_to(to_state),
                "Invalid transition should be rejected: {} -> {}",
                from_state,
                to_state
            );
        }

        // Test concurrent state modification attempts
        let cid2 = ctrl
            .issue_challenge(
                ArtifactId::new("concurrent_test"),
                SuspicionReason::UnexpectedProvenance,
                vec![RequiredProofType::ProvenanceAttestation],
                "concurrent_operator",
                2000,
            )
            .unwrap();

        // Simulate concurrent operations on same challenge
        let proof = make_proof(3000);
        ctrl.submit_proof(&cid2, proof, "prover", 3000).unwrap();

        // Try to submit another proof while in ProofReceived state (should fail)
        let second_proof = ProofSubmission {
            proof_type: RequiredProofType::IntegrityProof,
            data_hash: "second_hash".to_string(),
            submitter_id: "second_prover".to_string(),
            submitted_at_ms: 4000,
        };

        let concurrent_result = ctrl.submit_proof(&cid2, second_proof, "concurrent_prover", 4000);
        assert!(concurrent_result.is_err());
        assert_eq!(concurrent_result.unwrap_err().code, ERR_INVALID_TRANSITION);

        // Verify challenge state wasn't corrupted
        let challenge = ctrl.get_challenge(&cid2).unwrap();
        assert_eq!(challenge.state, ChallengeState::ProofReceived);
        assert_eq!(challenge.received_proofs.len(), 1); // Only first proof

        // Test rapid state transitions
        ctrl.verify_proof(&cid2, "verifier", 5000).unwrap();
        ctrl.promote(&cid2, "promoter", 6000).unwrap();

        // Verify final state
        assert_eq!(
            ctrl.get_challenge(&cid2).unwrap().state,
            ChallengeState::Promoted
        );

        // Test invalid operations on terminal state
        let terminal_operations = vec![
            || ctrl.submit_proof(&cid2, make_proof(7000), "late_prover", 7000),
            || ctrl.verify_proof(&cid2, "late_verifier", 8000),
            || ctrl.promote(&cid2, "late_promoter", 9000),
            || ctrl.deny(&cid2, "late_denier", 10000, "too late"),
        ];

        for operation in terminal_operations {
            let result = operation();
            assert!(result.is_err(), "Operation on terminal state should fail");
            assert_eq!(result.unwrap_err().code, ERR_INVALID_TRANSITION);
        }
    }

    #[test]
    fn negative_memory_exhaustion_with_massive_proof_lists_and_audit_logs() {
        let mut ctrl = make_controller();

        // Test with massive number of required proofs
        let massive_proofs: Vec<RequiredProofType> = (0..10_000)
            .map(|i| RequiredProofType::Custom(format!("massive_proof_type_{}", i)))
            .collect();

        let mass_artifact = ArtifactId::new("massive_proof_artifact");
        let cid = ctrl
            .issue_challenge(
                mass_artifact.clone(),
                SuspicionReason::PolicyRule("massive_policy".to_string()),
                massive_proofs.clone(),
                "mass_operator",
                1000,
            )
            .unwrap();

        // Verify challenge handles massive proof requirements
        let challenge = ctrl.get_challenge(&cid).unwrap();
        assert_eq!(challenge.required_proofs.len(), 10_000);

        // Submit massive number of proof artifacts
        for i in 0..1000 {
            let proof = ProofSubmission {
                proof_type: RequiredProofType::Custom(format!("submitted_proof_{}", i)),
                data_hash: format!("hash_{}_{}_{}", i, "x".repeat(1000), i), // Large hash strings
                submitter_id: format!("submitter_{}_{}", i, "y".repeat(500)), // Large submitter IDs
                submitted_at_ms: 2000 + i as u64,
            };

            if i == 0 {
                // First submission should succeed (transition to ProofReceived)
                ctrl.submit_proof(&cid, proof, &format!("actor_{}", i), 2000 + i as u64)
                    .unwrap();
            } else {
                // Subsequent submissions should fail (invalid transition)
                let result =
                    ctrl.submit_proof(&cid, proof, &format!("actor_{}", i), 2000 + i as u64);
                assert!(result.is_err());
                assert_eq!(result.unwrap_err().code, ERR_INVALID_TRANSITION);
            }
        }

        // Verify only first proof was accepted
        let final_challenge = ctrl.get_challenge(&cid).unwrap();
        assert_eq!(final_challenge.received_proofs.len(), 1);

        // Test massive audit log generation
        for i in 0..1000 {
            let artifact_id = ArtifactId::new(&format!("audit_stress_artifact_{}", i));
            let stress_cid = ctrl
                .issue_challenge(
                    artifact_id,
                    SuspicionReason::AgeAnomaly,
                    vec![RequiredProofType::IntegrityProof],
                    &format!("stress_operator_{}", i),
                    10_000 + i as u64,
                )
                .unwrap();

            // Perform full flow to generate maximum audit entries
            let stress_proof = ProofSubmission {
                proof_type: RequiredProofType::IntegrityProof,
                data_hash: format!("stress_hash_{}", i),
                submitter_id: format!("stress_prover_{}", i),
                submitted_at_ms: 11_000 + i as u64,
            };

            ctrl.submit_proof(
                &stress_cid,
                stress_proof,
                &format!("stress_prover_{}", i),
                11_000 + i as u64,
            )
            .unwrap();
            ctrl.verify_proof(
                &stress_cid,
                &format!("stress_verifier_{}", i),
                12_000 + i as u64,
            )
            .unwrap();

            // Alternate between promote and deny to test both paths
            if i % 2 == 0 {
                ctrl.promote(
                    &stress_cid,
                    &format!("stress_promoter_{}", i),
                    13_000 + i as u64,
                )
                .unwrap();
            } else {
                ctrl.deny(
                    &stress_cid,
                    &format!("stress_denier_{}", i),
                    13_000 + i as u64,
                    &format!("stress_reason_{}", i),
                )
                .unwrap();
            }
        }

        // Verify audit log is bounded
        assert!(ctrl.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES);

        // Verify metrics handle large numbers
        let metrics = ctrl.metrics();
        assert!(metrics.challenges_issued_total > 1000);
        assert!(metrics.challenges_resolved_total > 500);

        // Test massive detail strings in audit entries
        let detail_bomb = "X".repeat(10_000_000); // 10MB detail string
        ctrl.deny(&cid, "bomb_operator", 20_000, &detail_bomb)
            .unwrap();

        // Should handle large detail strings gracefully
        let final_audit = ctrl.challenge_audit(&cid);
        let deny_entry = final_audit
            .iter()
            .find(|e| e.event_code == CHALLENGE_DENIED)
            .unwrap();
        assert_eq!(deny_entry.detail.len(), 10_000_000);
    }

    #[test]
    fn negative_timestamp_manipulation_and_overflow_attacks() {
        let mut ctrl = make_controller();

        // Test timestamp overflow scenarios
        let timestamp_attacks = vec![
            (0, "zero_timestamp"),
            (1, "minimal_timestamp"),
            (u64::MAX - 1, "near_max_timestamp"),
            (u64::MAX, "max_timestamp"),
        ];

        for (timestamp, test_name) in timestamp_attacks {
            let artifact_id = ArtifactId::new(&format!("timestamp_test_{}", test_name));
            let cid = ctrl
                .issue_challenge(
                    artifact_id.clone(),
                    SuspicionReason::AgeAnomaly,
                    vec![RequiredProofType::IntegrityProof],
                    &format!("timestamp_operator_{}", test_name),
                    timestamp,
                )
                .unwrap();

            // Verify challenge creation with extreme timestamps
            let challenge = ctrl.get_challenge(&cid).unwrap();
            assert_eq!(challenge.created_at_ms, timestamp);

            // Test operations with extreme timestamps
            let proof = ProofSubmission {
                proof_type: RequiredProofType::IntegrityProof,
                data_hash: format!("hash_{}", test_name),
                submitter_id: format!("prover_{}", test_name),
                submitted_at_ms: timestamp,
            };

            ctrl.submit_proof(&cid, proof, &format!("actor_{}", test_name), timestamp)
                .unwrap();
        }

        // Test clock regression attack
        let regression_artifact = ArtifactId::new("regression_test");
        let regression_cid = ctrl
            .issue_challenge(
                regression_artifact,
                SuspicionReason::FormatDeviation,
                vec![RequiredProofType::OriginSignature],
                "regression_operator",
                10_000,
            )
            .unwrap();

        // Try to submit proof with timestamp before challenge creation
        let regression_proof = ProofSubmission {
            proof_type: RequiredProofType::OriginSignature,
            data_hash: "regression_hash".to_string(),
            submitter_id: "regression_prover".to_string(),
            submitted_at_ms: 5_000, // Before challenge creation
        };

        // Should still succeed - no timestamp validation enforced
        ctrl.submit_proof(&regression_cid, regression_proof, "regression_actor", 5_000)
            .unwrap();

        // Test timeout calculation with overflow protection
        let overflow_challenge = Challenge {
            challenge_id: ChallengeId::new("overflow_test"),
            artifact_id: ArtifactId::new("overflow_artifact"),
            state: ChallengeState::ChallengeIssued,
            reason: SuspicionReason::OperatorOverride,
            required_proofs: vec![RequiredProofType::ProvenanceAttestation],
            received_proofs: vec![],
            created_at_ms: u64::MAX - 1000, // Near overflow
            timeout_ms: 5000,
            trace_id: "overflow_trace".to_string(),
        };

        // Test is_timed_out with potential overflow scenarios
        assert!(!overflow_challenge.is_timed_out(u64::MAX - 1000)); // Same time
        assert!(!overflow_challenge.is_timed_out(u64::MAX - 500)); // Still within timeout
        assert!(!overflow_challenge.is_timed_out(0)); // Clock regression
        assert!(overflow_challenge.is_timed_out(u64::MAX)); // At max value

        // Test enforce_timeouts with extreme timestamps
        let timeout_artifact = ArtifactId::new("timeout_overflow");
        let timeout_cid = ctrl
            .issue_challenge(
                timeout_artifact,
                SuspicionReason::UnexpectedProvenance,
                vec![RequiredProofType::EpochBoundaryProof],
                "timeout_operator",
                u64::MAX - 50_000, // Near overflow
            )
            .unwrap();

        // Should timeout immediately due to saturating arithmetic
        let timed_out = ctrl.enforce_timeouts(u64::MAX);
        assert!(timed_out.contains(&timeout_cid));
    }

    #[test]
    fn negative_counter_overflow_and_metrics_manipulation_attacks() {
        // Create controller and manipulate internal counters to near overflow
        let mut ctrl = make_controller();

        // Set counters near u64::MAX
        ctrl.metrics.challenges_issued_total = u64::MAX - 10;
        ctrl.metrics.challenges_resolved_total = u64::MAX - 5;
        ctrl.metrics.challenges_promoted_total = u64::MAX - 3;
        ctrl.metrics.challenges_denied_total = u64::MAX - 3;
        ctrl.metrics.challenges_timed_out_total = u64::MAX - 1;

        // Set next_id near overflow
        ctrl.next_id = u64::MAX - 5;

        // Test counter overflow protection during normal operations
        for i in 0..15 {
            let artifact_id = ArtifactId::new(&format!("overflow_test_{}", i));
            let issue_result = ctrl.issue_challenge(
                artifact_id.clone(),
                SuspicionReason::PolicyRule(format!("rule_{}", i)),
                vec![RequiredProofType::Custom(format!("proof_{}", i))],
                &format!("operator_{}", i),
                1000 + i as u64,
            );

            if i < 5 {
                // Should succeed while next_id < u64::MAX
                assert!(issue_result.is_ok());
                let cid = issue_result.unwrap();

                // Test counter overflow in operations
                let proof = ProofSubmission {
                    proof_type: RequiredProofType::Custom(format!("proof_{}", i)),
                    data_hash: format!("hash_{}", i),
                    submitter_id: format!("prover_{}", i),
                    submitted_at_ms: 2000 + i as u64,
                };

                ctrl.submit_proof(&cid, proof, &format!("actor_{}", i), 2000 + i as u64)
                    .unwrap();
                ctrl.verify_proof(&cid, &format!("verifier_{}", i), 3000 + i as u64)
                    .unwrap();

                // Alternate promote/deny to test both counter paths
                if i % 2 == 0 {
                    ctrl.promote(&cid, &format!("promoter_{}", i), 4000 + i as u64)
                        .unwrap();
                } else {
                    ctrl.deny(
                        &cid,
                        &format!("denier_{}", i),
                        4000 + i as u64,
                        &format!("reason_{}", i),
                    )
                    .unwrap();
                }
            } else {
                // Should fail when next_id would overflow
                assert!(issue_result.is_err());
            }
        }

        // Verify counters saturated correctly
        assert_eq!(ctrl.metrics.challenges_issued_total, u64::MAX);
        assert!(ctrl.metrics.challenges_resolved_total <= u64::MAX);
        assert!(ctrl.metrics.challenges_promoted_total <= u64::MAX);
        assert!(ctrl.metrics.challenges_denied_total <= u64::MAX);
        assert_eq!(ctrl.next_id, u64::MAX);

        // Test timeout counter overflow
        let timeout_ctrl_config = ChallengeConfig {
            timeout_ms: 1, // Very short timeout
            deny_on_timeout: true,
        };
        let mut timeout_ctrl = ChallengeFlowController::new(timeout_ctrl_config);
        timeout_ctrl.metrics.challenges_timed_out_total = u64::MAX - 2;
        timeout_ctrl.metrics.challenges_denied_total = u64::MAX - 2;
        timeout_ctrl.metrics.challenges_resolved_total = u64::MAX - 2;

        // Issue challenges that will timeout
        for i in 0..5 {
            let artifact_id = ArtifactId::new(&format!("timeout_overflow_{}", i));
            let _ = timeout_ctrl.issue_challenge(
                artifact_id,
                SuspicionReason::AgeAnomaly,
                vec![RequiredProofType::IntegrityProof],
                &format!("timeout_operator_{}", i),
                1000 + i as u64,
            );
        }

        // Enforce timeouts to trigger counter increments
        let _timed_out = timeout_ctrl.enforce_timeouts(10_000);

        // Verify timeout counters saturated
        assert_eq!(timeout_ctrl.metrics.challenges_timed_out_total, u64::MAX);
        assert_eq!(timeout_ctrl.metrics.challenges_denied_total, u64::MAX);
        assert_eq!(timeout_ctrl.metrics.challenges_resolved_total, u64::MAX);

        // Test metrics integrity after overflow
        let metrics = timeout_ctrl.metrics();
        assert_eq!(metrics.challenges_timed_out_total, u64::MAX);
        assert!(metrics.challenges_issued_total > 0);
    }

    #[test]
    fn negative_concurrent_challenge_flow_safety_and_race_conditions() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let ctrl = Arc::new(Mutex::new(make_controller()));
        let mut handles = vec![];

        // Spawn multiple threads performing concurrent challenge operations
        for thread_id in 0..8 {
            let ctrl_clone = Arc::clone(&ctrl);
            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for op_id in 0..50 {
                    let mut controller = ctrl_clone.lock().unwrap();

                    // Issue challenge
                    let artifact_id =
                        ArtifactId::new(&format!("thread_{}_artifact_{}", thread_id, op_id));
                    let suspicion = match thread_id % 4 {
                        0 => SuspicionReason::UnexpectedProvenance,
                        1 => SuspicionReason::AgeAnomaly,
                        2 => SuspicionReason::FormatDeviation,
                        _ => SuspicionReason::PolicyRule(format!(
                            "thread_{}_rule_{}",
                            thread_id, op_id
                        )),
                    };

                    let proof_types = vec![
                        RequiredProofType::ProvenanceAttestation,
                        RequiredProofType::Custom(format!("thread_{}_proof_{}", thread_id, op_id)),
                    ];

                    let issue_result = controller.issue_challenge(
                        artifact_id.clone(),
                        suspicion,
                        proof_types,
                        &format!("thread_{}_operator_{}", thread_id, op_id),
                        1000 + thread_id as u64 * 1000 + op_id as u64,
                    );

                    if let Ok(cid) = issue_result {
                        // Submit proof
                        let proof = ProofSubmission {
                            proof_type: RequiredProofType::ProvenanceAttestation,
                            data_hash: format!("thread_{}_hash_{}", thread_id, op_id),
                            submitter_id: format!("thread_{}_prover_{}", thread_id, op_id),
                            submitted_at_ms: 2000 + thread_id as u64 * 1000 + op_id as u64,
                        };

                        let submit_result = controller.submit_proof(
                            &cid,
                            proof,
                            &format!("thread_{}_submit_actor_{}", thread_id, op_id),
                            2000 + thread_id as u64 * 1000 + op_id as u64,
                        );

                        if submit_result.is_ok() {
                            // Verify proof
                            let verify_result = controller.verify_proof(
                                &cid,
                                &format!("thread_{}_verifier_{}", thread_id, op_id),
                                3000 + thread_id as u64 * 1000 + op_id as u64,
                            );

                            if verify_result.is_ok() {
                                // Final action: promote or deny based on thread_id
                                if thread_id % 2 == 0 {
                                    let promote_result = controller.promote(
                                        &cid,
                                        &format!("thread_{}_promoter_{}", thread_id, op_id),
                                        4000 + thread_id as u64 * 1000 + op_id as u64,
                                    );
                                    thread_results.push(("promote", promote_result.is_ok()));
                                } else {
                                    let deny_result = controller.deny(
                                        &cid,
                                        &format!("thread_{}_denier_{}", thread_id, op_id),
                                        4000 + thread_id as u64 * 1000 + op_id as u64,
                                        &format!("thread_{}_denial_{}", thread_id, op_id),
                                    );
                                    thread_results.push(("deny", deny_result.is_ok()));
                                }
                            }
                        }
                    }

                    // Test timeout enforcement concurrently
                    let _timed_out = controller
                        .enforce_timeouts(10_000 + thread_id as u64 * 1000 + op_id as u64);
                }

                thread_results
            });
            handles.push(handle);
        }

        // Wait for all threads
        let mut all_results = Vec::new();
        for handle in handles {
            let thread_results = handle.join().unwrap();
            all_results.extend(thread_results);
        }

        // Verify concurrent operations completed successfully
        let successful_operations = all_results.iter().filter(|(_, success)| *success).count();
        assert!(
            successful_operations > 0,
            "Some concurrent operations should succeed"
        );

        // Verify final state consistency
        let final_ctrl = ctrl.lock().unwrap();
        let metrics = final_ctrl.metrics();

        // All metrics should be consistent
        assert!(metrics.challenges_issued_total > 0);
        assert_eq!(
            metrics.challenges_resolved_total,
            metrics.challenges_promoted_total
                + metrics.challenges_denied_total
                + metrics.challenges_timed_out_total
        );

        // Audit log should be consistent
        let audit_log = final_ctrl.audit_log();
        assert!(audit_log.len() > 0);

        // Hash chain integrity should be maintained
        if audit_log.len() > 1 {
            for i in 1..audit_log.len() {
                let expected_prev = audit_log[i - 1].hash();
                let actual_prev = &audit_log[i].prev_hash;
                assert_eq!(
                    *actual_prev, expected_prev,
                    "Concurrent access broke hash chain at index {}",
                    i
                );
            }
        }

        // No active challenges should be in inconsistent state
        let active = final_ctrl.active_challenges();
        for challenge in active {
            assert!(
                !challenge.state.is_terminal(),
                "Active challenge should not be in terminal state"
            );
        }
    }

    #[test]
    fn negative_challenge_capacity_and_eviction_manipulation_attacks() {
        let mut ctrl = make_controller();

        // Fill challenge registry to capacity with terminal challenges
        for i in 0..MAX_CHALLENGES + 100 {
            let artifact_id = ArtifactId::new(&format!("capacity_test_{}", i));
            let cid = ctrl
                .issue_challenge(
                    artifact_id,
                    SuspicionReason::OperatorOverride,
                    vec![RequiredProofType::IntegrityProof],
                    &format!("capacity_operator_{}", i),
                    1000 + i as u64,
                )
                .unwrap();

            // Immediately deny to make terminal (for eviction testing)
            if i % 2 == 0 {
                ctrl.deny(
                    &cid,
                    &format!("denier_{}", i),
                    2000 + i as u64,
                    &format!("reason_{}", i),
                )
                .unwrap();
            }
        }

        // Should have evicted oldest terminal challenges
        assert!(ctrl.challenges.len() <= MAX_CHALLENGES);

        // Test that active challenges are preserved over terminal ones
        let active_count = ctrl.active_challenges().len();
        assert!(active_count > 0, "Some active challenges should remain");

        // Verify eviction doesn't break challenge ID sequencing
        let challenge_ids: Vec<String> = ctrl.challenges.keys().map(|k| k.0.clone()).collect();
        for (i, id) in challenge_ids.iter().enumerate() {
            assert!(
                id.starts_with("ch-"),
                "Challenge ID should have proper format: {}",
                id
            );

            // Parse challenge number
            let number_part = id.strip_prefix("ch-").unwrap();
            let number: u64 = number_part.parse().unwrap();
            assert!(
                number > 0,
                "Challenge number should be positive: {}",
                number
            );
        }

        // Test eviction preference for terminal over active
        for i in 0..50 {
            let artifact_id = ArtifactId::new(&format!("eviction_pref_{}", i));
            let cid = ctrl
                .issue_challenge(
                    artifact_id,
                    SuspicionReason::AgeAnomaly,
                    vec![RequiredProofType::OriginSignature],
                    &format!("eviction_operator_{}", i),
                    10_000 + i as u64,
                )
                .unwrap();

            // Leave some challenges active, deny others immediately
            if i < 25 {
                // Keep active for eviction test
                continue;
            } else {
                ctrl.deny(
                    &cid,
                    &format!("evict_denier_{}", i),
                    11_000 + i as u64,
                    "immediate_denial",
                )
                .unwrap();
            }
        }

        // Should still maintain capacity
        assert!(ctrl.challenges.len() <= MAX_CHALLENGES);

        // Verify active challenges weren't evicted first
        let final_active_count = ctrl.active_challenges().len();
        assert!(
            final_active_count >= 25,
            "Active challenges should be preserved during eviction"
        );

        // Test memory exhaustion attack via massive challenge creation
        for i in 0..1000 {
            let artifact_id = ArtifactId::new(&format!("memory_attack_{}", i));
            let massive_proofs: Vec<RequiredProofType> = (0..100)
                .map(|j| RequiredProofType::Custom(format!("attack_proof_{}_{}", i, j)))
                .collect();

            let _ = ctrl.issue_challenge(
                artifact_id,
                SuspicionReason::PolicyRule(format!("attack_policy_{}", i)),
                massive_proofs,
                &format!("attack_operator_{}", i),
                20_000 + i as u64,
            );

            // Immediately deny to become terminal
            if i % 10 == 0 {
                let recent_cid = ChallengeId::new(&format!("ch-{}", ctrl.next_id - 1));
                if ctrl.challenges.contains_key(&recent_cid) {
                    let _ = ctrl.deny(
                        &recent_cid,
                        "attack_denier",
                        21_000 + i as u64,
                        "attack_cleanup",
                    );
                }
            }
        }

        // Should maintain bounded capacity despite attack
        assert!(ctrl.challenges.len() <= MAX_CHALLENGES);

        // Verify metrics tracking during capacity management
        let final_metrics = ctrl.metrics();
        assert!(final_metrics.challenges_issued_total > MAX_CHALLENGES as u64);
        assert!(final_metrics.challenges_resolved_total > 0);
    }
}
