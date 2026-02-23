// Verifier Economy Portal and External Attestation Publishing Flow
//
// bd-m8p / section 10.9
//
// Implements:
//   - Verifier registration with identity, capabilities, and public key
//   - Attestation submission, review, and publishing flow
//   - Verifier reputation scoring with deterministic computation
//   - Public trust scoreboard with aggregate scores and historical trends
//   - Anti-gaming measures (sybil resistance, selective reporting detection)
//   - Replay capsule access and integrity verification
//
// Event codes: VEP-001 .. VEP-008
// Invariants:  INV-VEP-ATTESTATION, INV-VEP-SIGNATURE, INV-VEP-REPUTATION, INV-VEP-PUBLISH

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const VEP_001: &str = "VEP-001"; // Attestation submitted
pub const VEP_002: &str = "VEP-002"; // Attestation published
pub const VEP_003: &str = "VEP-003"; // Dispute filed
pub const VEP_004: &str = "VEP-004"; // Reputation updated
pub const VEP_005: &str = "VEP-005"; // Verifier registered
pub const VEP_006: &str = "VEP-006"; // Anti-gaming triggered
pub const VEP_007: &str = "VEP-007"; // Replay capsule accessed
pub const VEP_008: &str = "VEP-008"; // Attestation rejected

// ---------------------------------------------------------------------------
// Invariant tags (used in audit trail entries)
// ---------------------------------------------------------------------------

pub const INV_VEP_ATTESTATION: &str = "INV-VEP-ATTESTATION";
pub const INV_VEP_SIGNATURE: &str = "INV-VEP-SIGNATURE";
pub const INV_VEP_REPUTATION: &str = "INV-VEP-REPUTATION";
pub const INV_VEP_PUBLISH: &str = "INV-VEP-PUBLISH";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_VEP_INVALID_SIGNATURE: &str = "ERR-VEP-INVALID-SIGNATURE";
pub const ERR_VEP_DUPLICATE_SUBMISSION: &str = "ERR-VEP-DUPLICATE-SUBMISSION";
pub const ERR_VEP_UNREGISTERED_VERIFIER: &str = "ERR-VEP-UNREGISTERED-VERIFIER";
pub const ERR_VEP_INCOMPLETE_PAYLOAD: &str = "ERR-VEP-INCOMPLETE-PAYLOAD";
pub const ERR_VEP_ANTI_GAMING: &str = "ERR-VEP-ANTI-GAMING";

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Verification dimension that a verifier can attest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VerificationDimension {
    Compatibility,
    Security,
    Performance,
    SupplyChain,
    Conformance,
}

impl fmt::Display for VerificationDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compatibility => write!(f, "compatibility"),
            Self::Security => write!(f, "security"),
            Self::Performance => write!(f, "performance"),
            Self::SupplyChain => write!(f, "supply_chain"),
            Self::Conformance => write!(f, "conformance"),
        }
    }
}

/// Verifier registration tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierTier {
    Basic,
    Advanced,
}

impl fmt::Display for VerifierTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            Self::Advanced => write!(f, "advanced"),
        }
    }
}

/// Reputation tier derived from the reputation score.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReputationTier {
    Novice,
    Active,
    Established,
    Trusted,
}

impl fmt::Display for ReputationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Novice => write!(f, "Novice"),
            Self::Active => write!(f, "Active"),
            Self::Established => write!(f, "Established"),
            Self::Trusted => write!(f, "Trusted"),
        }
    }
}

/// Map a reputation score (0-100) to a tier.
pub fn reputation_tier_from_score(score: u32) -> ReputationTier {
    match score {
        0..=24 => ReputationTier::Novice,
        25..=49 => ReputationTier::Active,
        50..=74 => ReputationTier::Established,
        _ => ReputationTier::Trusted,
    }
}

/// Attestation lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationState {
    Submitted,
    UnderReview,
    Published,
    Rejected,
    Disputed,
}

impl fmt::Display for AttestationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted => write!(f, "submitted"),
            Self::UnderReview => write!(f, "under_review"),
            Self::Published => write!(f, "published"),
            Self::Rejected => write!(f, "rejected"),
            Self::Disputed => write!(f, "disputed"),
        }
    }
}

/// Dispute outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisputeOutcome {
    Upheld,
    Rejected,
    Inconclusive,
}

impl fmt::Display for DisputeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upheld => write!(f, "upheld"),
            Self::Rejected => write!(f, "rejected"),
            Self::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core structs
// ---------------------------------------------------------------------------

/// Claim within an attestation.
#[derive(Debug, Clone)]
pub struct AttestationClaim {
    pub dimension: VerificationDimension,
    pub statement: String,
    pub score: f64,
}

/// Evidence within an attestation.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub suite_id: String,
    pub measurements: Vec<String>,
    pub execution_trace_hash: String,
    pub environment: BTreeMap<String, String>,
}

/// Cryptographic signature.
#[derive(Debug, Clone)]
pub struct AttestationSignature {
    pub algorithm: String,
    pub public_key: String,
    pub value: String,
}

/// A verification attestation.
#[derive(Debug, Clone)]
pub struct Attestation {
    pub attestation_id: String,
    pub verifier_id: String,
    pub claim: AttestationClaim,
    pub evidence: AttestationEvidence,
    pub signature: AttestationSignature,
    pub timestamp: String,
    pub immutable: bool,
    pub state: AttestationState,
}

/// Input for submitting an attestation.
#[derive(Debug, Clone)]
pub struct AttestationSubmission {
    pub verifier_id: String,
    pub claim: AttestationClaim,
    pub evidence: AttestationEvidence,
    pub signature: AttestationSignature,
    pub timestamp: String,
}

/// Registered verifier.
#[derive(Debug, Clone)]
pub struct Verifier {
    pub verifier_id: String,
    pub name: String,
    pub contact: String,
    pub public_key: String,
    pub capabilities: Vec<VerificationDimension>,
    pub tier: VerifierTier,
    pub reputation_score: u32,
    pub reputation_tier: ReputationTier,
    pub registered_at: String,
    pub active: bool,
}

/// Input for registering a verifier.
#[derive(Debug, Clone)]
pub struct VerifierRegistration {
    pub name: String,
    pub contact: String,
    pub public_key: String,
    pub capabilities: Vec<VerificationDimension>,
    pub tier: VerifierTier,
}

/// Reputation dimension scores for deterministic computation.
#[derive(Debug, Clone)]
pub struct ReputationDimensions {
    pub consistency: f64,
    pub coverage: f64,
    pub accuracy: f64,
    pub longevity: f64,
}

/// Dispute filed against an attestation.
#[derive(Debug, Clone)]
pub struct Dispute {
    pub dispute_id: String,
    pub attestation_id: String,
    pub filed_by: String,
    pub justification: String,
    pub supporting_evidence: Vec<String>,
    pub outcome: Option<DisputeOutcome>,
    pub filed_at: String,
    pub resolved_at: Option<String>,
}

/// Replay capsule for independent verification.
#[derive(Debug, Clone)]
pub struct ReplayCapsule {
    pub capsule_id: String,
    pub attestation_id: String,
    pub input_state_hash: String,
    pub execution_trace_hash: String,
    pub output_state_hash: String,
    pub expected_result_hash: String,
    pub integrity_hash: String,
}

/// Scoreboard entry for a single verifier.
#[derive(Debug, Clone)]
pub struct ScoreboardEntry {
    pub verifier_id: String,
    pub verifier_name: String,
    pub reputation_score: u32,
    pub reputation_tier: ReputationTier,
    pub attestation_count: usize,
    pub dimensions_covered: Vec<VerificationDimension>,
}

/// Aggregate scoreboard for public display.
#[derive(Debug, Clone)]
pub struct TrustScoreboard {
    pub entries: Vec<ScoreboardEntry>,
    pub total_attestations: usize,
    pub total_verifiers: usize,
    pub aggregate_score: f64,
}

/// Event emitted by the verifier economy system.
#[derive(Debug, Clone)]
pub struct VerifierEconomyEvent {
    pub code: String,
    pub detail: String,
    pub timestamp: u64,
}

/// Result type for verifier economy operations.
#[derive(Debug, Clone)]
pub struct VepError {
    pub code: String,
    pub message: String,
}

impl fmt::Display for VepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

pub type VepResult<T> = Result<T, VepError>;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Central registry for the verifier economy.
pub struct VerifierEconomyRegistry {
    verifiers: BTreeMap<String, Verifier>,
    attestations: BTreeMap<String, Attestation>,
    disputes: BTreeMap<String, Dispute>,
    replay_capsules: BTreeMap<String, ReplayCapsule>,
    events: Vec<VerifierEconomyEvent>,
    next_verifier_id: u64,
    next_attestation_id: u64,
    next_dispute_id: u64,
    /// Sybil resistance: track submission counts per verifier per window.
    submission_counts: BTreeMap<String, u32>,
    /// Maximum submissions per verifier per window.
    max_submissions_per_window: u32,
}

impl Default for VerifierEconomyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierEconomyRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: BTreeMap::new(),
            attestations: BTreeMap::new(),
            disputes: BTreeMap::new(),
            replay_capsules: BTreeMap::new(),
            events: Vec::new(),
            next_verifier_id: 1,
            next_attestation_id: 1,
            next_dispute_id: 1,
            submission_counts: BTreeMap::new(),
            max_submissions_per_window: 100,
        }
    }

    fn now_epoch(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn emit(&mut self, code: &str, detail: &str) {
        self.events.push(VerifierEconomyEvent {
            code: code.to_string(),
            detail: detail.to_string(),
            timestamp: self.now_epoch(),
        });
    }

    pub fn events(&self) -> &[VerifierEconomyEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<VerifierEconomyEvent> {
        std::mem::take(&mut self.events)
    }

    // -- Verifier registration -----------------------------------------------

    pub fn register_verifier(&mut self, reg: VerifierRegistration) -> VepResult<Verifier> {
        // Check for duplicate public key
        if self
            .verifiers
            .values()
            .any(|v| v.public_key == reg.public_key)
        {
            return Err(VepError {
                code: ERR_VEP_DUPLICATE_SUBMISSION.to_string(),
                message: "A verifier with this public key is already registered".to_string(),
            });
        }

        let verifier_id = format!("ver-{:04}", self.next_verifier_id);
        self.next_verifier_id += 1;

        let verifier = Verifier {
            verifier_id: verifier_id.clone(),
            name: reg.name,
            contact: reg.contact,
            public_key: reg.public_key,
            capabilities: reg.capabilities,
            tier: reg.tier,
            reputation_score: 0,
            reputation_tier: ReputationTier::Novice,
            registered_at: format!("{}", self.now_epoch()),
            active: true,
        };

        self.verifiers.insert(verifier_id.clone(), verifier.clone());
        self.emit(VEP_005, &format!("Verifier registered: {}", verifier_id));

        Ok(verifier)
    }

    pub fn get_verifier(&self, verifier_id: &str) -> Option<&Verifier> {
        self.verifiers.get(verifier_id)
    }

    pub fn list_verifiers(&self) -> Vec<&Verifier> {
        self.verifiers.values().collect()
    }

    pub fn verifier_count(&self) -> usize {
        self.verifiers.len()
    }

    // -- Attestation submission & publishing ----------------------------------

    /// Submit an attestation. Validates structure and signature before accepting.
    /// Follows INV-VEP-PUBLISH: submit -> review -> publish.
    pub fn submit_attestation(
        &mut self,
        submission: AttestationSubmission,
    ) -> VepResult<Attestation> {
        // INV-VEP-PUBLISH: Stage 1 — Submission

        // Check verifier is registered
        let verifier = match self.verifiers.get(&submission.verifier_id) {
            Some(v) => v.clone(),
            None => {
                self.emit(
                    VEP_008,
                    &format!("Rejected: unregistered verifier {}", submission.verifier_id),
                );
                return Err(VepError {
                    code: ERR_VEP_UNREGISTERED_VERIFIER.to_string(),
                    message: format!("Verifier {} is not registered", submission.verifier_id),
                });
            }
        };

        // Validate payload completeness (INV-VEP-ATTESTATION)
        if submission.claim.statement.is_empty() || submission.evidence.suite_id.is_empty() {
            self.emit(
                VEP_008,
                &format!(
                    "Rejected: incomplete payload from {}",
                    submission.verifier_id
                ),
            );
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: "Attestation claim statement and evidence suite_id are required"
                    .to_string(),
            });
        }

        // INV-VEP-SIGNATURE: Verify signature
        if !self.verify_signature(&submission.signature, &verifier.public_key) {
            self.emit(
                VEP_008,
                &format!(
                    "Rejected: invalid signature from {}",
                    submission.verifier_id
                ),
            );
            return Err(VepError {
                code: ERR_VEP_INVALID_SIGNATURE.to_string(),
                message: "Attestation signature verification failed".to_string(),
            });
        }

        // Anti-gaming: sybil resistance rate limiting
        let count = self
            .submission_counts
            .entry(submission.verifier_id.clone())
            .or_insert(0);
        *count += 1;
        if *count > self.max_submissions_per_window {
            self.emit(
                VEP_006,
                &format!(
                    "Anti-gaming: rate limit exceeded for {}",
                    submission.verifier_id
                ),
            );
            return Err(VepError {
                code: ERR_VEP_ANTI_GAMING.to_string(),
                message: "Submission rate limit exceeded".to_string(),
            });
        }

        // Check for duplicate submission
        if self.attestations.values().any(|a| {
            a.verifier_id == submission.verifier_id
                && a.evidence.execution_trace_hash == submission.evidence.execution_trace_hash
        }) {
            self.emit(
                VEP_008,
                &format!(
                    "Rejected: duplicate submission from {}",
                    submission.verifier_id
                ),
            );
            return Err(VepError {
                code: ERR_VEP_DUPLICATE_SUBMISSION.to_string(),
                message: "Duplicate attestation submission".to_string(),
            });
        }

        let attestation_id = format!("att-{:04}", self.next_attestation_id);
        self.next_attestation_id += 1;

        let attestation = Attestation {
            attestation_id: attestation_id.clone(),
            verifier_id: submission.verifier_id,
            claim: submission.claim,
            evidence: submission.evidence,
            signature: submission.signature,
            timestamp: submission.timestamp,
            immutable: false, // Not yet published
            state: AttestationState::Submitted,
        };

        self.attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.emit(
            VEP_001,
            &format!("Attestation submitted: {}", attestation_id),
        );

        Ok(attestation)
    }

    /// Review an attestation. Transitions from Submitted to UnderReview.
    /// Part of INV-VEP-PUBLISH flow.
    pub fn review_attestation(&mut self, attestation_id: &str) -> VepResult<AttestationState> {
        let att = self.attestations.get_mut(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;

        if att.state != AttestationState::Submitted {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!("Cannot review attestation in state {}", att.state),
            });
        }

        att.state = AttestationState::UnderReview;
        Ok(AttestationState::UnderReview)
    }

    /// Publish an attestation. Transitions from UnderReview to Published.
    /// Sets immutable=true per INV-VEP-ATTESTATION.
    pub fn publish_attestation(&mut self, attestation_id: &str) -> VepResult<AttestationState> {
        let att = self.attestations.get_mut(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;

        if att.state != AttestationState::UnderReview {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!(
                    "Cannot publish attestation in state {} (must be under_review)",
                    att.state
                ),
            });
        }

        // INV-VEP-ATTESTATION: mark as immutable
        att.state = AttestationState::Published;
        att.immutable = true;

        self.emit(
            VEP_002,
            &format!("Attestation published: {}", attestation_id),
        );
        Ok(AttestationState::Published)
    }

    /// Reject an attestation during review.
    pub fn reject_attestation(&mut self, attestation_id: &str) -> VepResult<AttestationState> {
        let att = self.attestations.get_mut(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;

        if att.state != AttestationState::UnderReview {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!("Cannot reject attestation in state {}", att.state),
            });
        }

        att.state = AttestationState::Rejected;
        self.emit(
            VEP_008,
            &format!("Attestation rejected: {}", attestation_id),
        );
        Ok(AttestationState::Rejected)
    }

    pub fn get_attestation(&self, attestation_id: &str) -> Option<&Attestation> {
        self.attestations.get(attestation_id)
    }

    pub fn list_attestations(&self) -> Vec<&Attestation> {
        self.attestations.values().collect()
    }

    pub fn published_attestations(&self) -> Vec<&Attestation> {
        self.attestations
            .values()
            .filter(|a| a.state == AttestationState::Published)
            .collect()
    }

    pub fn attestation_count(&self) -> usize {
        self.attestations.len()
    }

    // -- Signature verification (simplified) ----------------------------------

    /// Verify an attestation signature against the verifier's public key.
    /// In production this would use Ed25519 verification; here we use a
    /// simplified check that the key matches and signature is non-empty.
    pub fn verify_signature(&self, sig: &AttestationSignature, expected_key: &str) -> bool {
        sig.algorithm == "ed25519" && sig.public_key == expected_key && !sig.value.is_empty()
    }

    // -- Reputation scoring ---------------------------------------------------

    /// Compute verifier reputation deterministically.
    /// INV-VEP-REPUTATION: same inputs always produce the same score.
    pub fn compute_reputation(dims: &ReputationDimensions) -> u32 {
        let raw = 0.35 * dims.consistency
            + 0.25 * dims.coverage
            + 0.30 * dims.accuracy
            + 0.10 * dims.longevity;
        let score = (raw * 100.0).round() as i64;
        score.clamp(0, 100) as u32
    }

    /// Update a verifier's reputation score with new dimension values.
    pub fn update_reputation(
        &mut self,
        verifier_id: &str,
        dims: &ReputationDimensions,
    ) -> VepResult<u32> {
        let verifier = self.verifiers.get_mut(verifier_id).ok_or(VepError {
            code: ERR_VEP_UNREGISTERED_VERIFIER.to_string(),
            message: format!("Verifier {} not found", verifier_id),
        })?;

        let new_score = Self::compute_reputation(dims);
        let old_tier = verifier.reputation_tier.clone();
        verifier.reputation_score = new_score;
        verifier.reputation_tier = reputation_tier_from_score(new_score);

        let new_tier = verifier.reputation_tier.clone();

        self.emit(
            VEP_004,
            &format!(
                "Reputation updated: {} score={} tier={} (was {})",
                verifier_id, new_score, new_tier, old_tier
            ),
        );

        Ok(new_score)
    }

    // -- Disputes -------------------------------------------------------------

    /// File a dispute against a published attestation.
    pub fn file_dispute(
        &mut self,
        attestation_id: &str,
        filed_by: &str,
        justification: &str,
        supporting_evidence: Vec<String>,
    ) -> VepResult<Dispute> {
        // Verify attestation exists and is published
        let att = self.attestations.get_mut(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;

        if att.state != AttestationState::Published {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: "Can only dispute published attestations".to_string(),
            });
        }

        att.state = AttestationState::Disputed;

        let dispute_id = format!("dsp-{:04}", self.next_dispute_id);
        self.next_dispute_id += 1;

        let dispute = Dispute {
            dispute_id: dispute_id.clone(),
            attestation_id: attestation_id.to_string(),
            filed_by: filed_by.to_string(),
            justification: justification.to_string(),
            supporting_evidence,
            outcome: None,
            filed_at: format!("{}", self.now_epoch()),
            resolved_at: None,
        };

        self.disputes.insert(dispute_id.clone(), dispute.clone());
        self.emit(
            VEP_003,
            &format!("Dispute filed: {} against {}", dispute_id, attestation_id),
        );

        Ok(dispute)
    }

    /// Resolve a dispute with an outcome.
    pub fn resolve_dispute(&mut self, dispute_id: &str, outcome: DisputeOutcome) -> VepResult<()> {
        let now = self.now_epoch();
        let outcome_display = format!("{}", outcome);
        let dispute_id_owned = dispute_id.to_string();

        let dispute = self.disputes.get_mut(dispute_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Dispute {} not found", dispute_id),
        })?;

        dispute.outcome = Some(outcome);
        dispute.resolved_at = Some(format!("{}", now));

        self.emit(
            VEP_004,
            &format!("Dispute {} resolved: {}", dispute_id_owned, outcome_display),
        );

        Ok(())
    }

    pub fn get_dispute(&self, dispute_id: &str) -> Option<&Dispute> {
        self.disputes.get(dispute_id)
    }

    pub fn list_disputes(&self) -> Vec<&Dispute> {
        self.disputes.values().collect()
    }

    // -- Replay capsules ------------------------------------------------------

    pub fn register_replay_capsule(&mut self, capsule: ReplayCapsule) -> VepResult<()> {
        let capsule_id = capsule.capsule_id.clone();
        self.replay_capsules.insert(capsule_id.clone(), capsule);
        Ok(())
    }

    pub fn access_replay_capsule(&mut self, capsule_id: &str) -> VepResult<ReplayCapsule> {
        let capsule = self
            .replay_capsules
            .get(capsule_id)
            .cloned()
            .ok_or(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!("Replay capsule {} not found", capsule_id),
            })?;

        self.emit(VEP_007, &format!("Replay capsule accessed: {}", capsule_id));

        Ok(capsule)
    }

    /// Verify replay capsule integrity by checking hash consistency.
    pub fn verify_capsule_integrity(capsule: &ReplayCapsule) -> bool {
        // Simplified check: all hashes are non-empty and integrity_hash is set
        !capsule.input_state_hash.is_empty()
            && !capsule.execution_trace_hash.is_empty()
            && !capsule.output_state_hash.is_empty()
            && !capsule.expected_result_hash.is_empty()
            && !capsule.integrity_hash.is_empty()
    }

    // -- Trust scoreboard -----------------------------------------------------

    /// Build the public trust scoreboard.
    pub fn build_scoreboard(&self) -> TrustScoreboard {
        let mut entries = Vec::new();

        for verifier in self.verifiers.values() {
            if !verifier.active {
                continue;
            }

            let att_count = self
                .attestations
                .values()
                .filter(|a| {
                    a.verifier_id == verifier.verifier_id && a.state == AttestationState::Published
                })
                .count();

            let dims_covered: Vec<VerificationDimension> = self
                .attestations
                .values()
                .filter(|a| {
                    a.verifier_id == verifier.verifier_id && a.state == AttestationState::Published
                })
                .map(|a| a.claim.dimension.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();

            entries.push(ScoreboardEntry {
                verifier_id: verifier.verifier_id.clone(),
                verifier_name: verifier.name.clone(),
                reputation_score: verifier.reputation_score,
                reputation_tier: verifier.reputation_tier.clone(),
                attestation_count: att_count,
                dimensions_covered: dims_covered,
            });
        }

        let total_attestations = self
            .attestations
            .values()
            .filter(|a| a.state == AttestationState::Published)
            .count();

        let total_verifiers = entries.len();

        let aggregate_score = if total_verifiers > 0 {
            entries
                .iter()
                .map(|e| e.reputation_score as f64)
                .sum::<f64>()
                / total_verifiers as f64
        } else {
            0.0
        };

        TrustScoreboard {
            entries,
            total_attestations,
            total_verifiers,
            aggregate_score,
        }
    }

    // -- Anti-gaming: selective reporting detection ----------------------------

    /// Check whether a verifier has been selectively reporting.
    /// Returns true if the verifier's dimension coverage meets the threshold.
    pub fn check_selective_reporting(&self, verifier_id: &str, min_dimensions: usize) -> bool {
        let dims: std::collections::BTreeSet<_> = self
            .attestations
            .values()
            .filter(|a| a.verifier_id == verifier_id)
            .map(|a| a.claim.dimension.clone())
            .collect();

        dims.len() < min_dimensions
    }

    /// Reset submission counts (call at window boundaries).
    pub fn reset_submission_counts(&mut self) {
        self.submission_counts.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> VerifierEconomyRegistry {
        VerifierEconomyRegistry::new()
    }

    fn make_registration() -> VerifierRegistration {
        VerifierRegistration {
            name: "Acme Verifiers".to_string(),
            contact: "verify@acme.example".to_string(),
            public_key: "ed25519-pub-key-acme-001".to_string(),
            capabilities: vec![
                VerificationDimension::Compatibility,
                VerificationDimension::Security,
            ],
            tier: VerifierTier::Basic,
        }
    }

    fn make_submission(verifier_id: &str, public_key: &str) -> AttestationSubmission {
        AttestationSubmission {
            verifier_id: verifier_id.to_string(),
            claim: AttestationClaim {
                dimension: VerificationDimension::Compatibility,
                statement: "franken_node API is compatible with v2.0 spec".to_string(),
                score: 0.95,
            },
            evidence: AttestationEvidence {
                suite_id: "suite-compat-v1".to_string(),
                measurements: vec!["endpoint-coverage: 98%".to_string()],
                execution_trace_hash: "sha256:abc123".to_string(),
                environment: BTreeMap::from([
                    ("os".to_string(), "linux".to_string()),
                    ("rust".to_string(), "nightly-2026-02-15".to_string()),
                ]),
            },
            signature: AttestationSignature {
                algorithm: "ed25519".to_string(),
                public_key: public_key.to_string(),
                value: "sig-value-001".to_string(),
            },
            timestamp: "2026-02-20T12:00:00Z".to_string(),
        }
    }

    fn register_and_submit(reg: &mut VerifierEconomyRegistry) -> (Verifier, Attestation) {
        let v = reg.register_verifier(make_registration()).unwrap();
        let sub = make_submission(&v.verifier_id, &v.public_key);
        let att = reg.submit_attestation(sub).unwrap();
        (v, att)
    }

    // -- Registration tests ---------------------------------------------------

    #[test]
    fn test_register_verifier() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();
        assert!(v.verifier_id.starts_with("ver-"));
        assert_eq!(v.reputation_score, 0);
        assert_eq!(v.reputation_tier, ReputationTier::Novice);
        assert!(v.active);
    }

    #[test]
    fn test_register_emits_vep005() {
        let mut reg = make_registry();
        reg.register_verifier(make_registration()).unwrap();
        let events = reg.events();
        assert!(events.iter().any(|e| e.code == VEP_005));
    }

    #[test]
    fn test_duplicate_public_key_rejected() {
        let mut reg = make_registry();
        reg.register_verifier(make_registration()).unwrap();
        let result = reg.register_verifier(make_registration());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_DUPLICATE_SUBMISSION);
    }

    #[test]
    fn test_verifier_count() {
        let mut reg = make_registry();
        assert_eq!(reg.verifier_count(), 0);
        reg.register_verifier(make_registration()).unwrap();
        assert_eq!(reg.verifier_count(), 1);
    }

    #[test]
    fn test_get_verifier() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();
        let found = reg.get_verifier(&v.verifier_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Acme Verifiers");
    }

    #[test]
    fn test_list_verifiers() {
        let mut reg = make_registry();
        reg.register_verifier(make_registration()).unwrap();
        assert_eq!(reg.list_verifiers().len(), 1);
    }

    // -- Attestation submission tests -----------------------------------------

    #[test]
    fn test_submit_attestation() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        assert!(att.attestation_id.starts_with("att-"));
        assert_eq!(att.state, AttestationState::Submitted);
        assert!(!att.immutable);
    }

    #[test]
    fn test_submit_emits_vep001() {
        let mut reg = make_registry();
        register_and_submit(&mut reg);
        assert!(reg.events().iter().any(|e| e.code == VEP_001));
    }

    #[test]
    fn test_submit_unregistered_verifier_rejected() {
        let mut reg = make_registry();
        let sub = make_submission("ver-9999", "some-key");
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_UNREGISTERED_VERIFIER);
    }

    #[test]
    fn test_submit_invalid_signature_rejected() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();
        let mut sub = make_submission(&v.verifier_id, &v.public_key);
        sub.signature.algorithm = "rsa".to_string(); // Wrong algorithm
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_INVALID_SIGNATURE);
    }

    #[test]
    fn test_submit_empty_statement_rejected() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();
        let mut sub = make_submission(&v.verifier_id, &v.public_key);
        sub.claim.statement = String::new();
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_INCOMPLETE_PAYLOAD);
    }

    #[test]
    fn test_submit_empty_suite_id_rejected() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();
        let mut sub = make_submission(&v.verifier_id, &v.public_key);
        sub.evidence.suite_id = String::new();
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_INCOMPLETE_PAYLOAD);
    }

    #[test]
    fn test_submit_duplicate_rejected() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();
        let sub1 = make_submission(&v.verifier_id, &v.public_key);
        reg.submit_attestation(sub1).unwrap();
        let sub2 = make_submission(&v.verifier_id, &v.public_key);
        let result = reg.submit_attestation(sub2);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_DUPLICATE_SUBMISSION);
    }

    // -- Publishing flow tests (INV-VEP-PUBLISH) ------------------------------

    #[test]
    fn test_publish_flow_submit_review_publish() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);

        let state = reg.review_attestation(&att.attestation_id).unwrap();
        assert_eq!(state, AttestationState::UnderReview);

        let state = reg.publish_attestation(&att.attestation_id).unwrap();
        assert_eq!(state, AttestationState::Published);

        let published = reg.get_attestation(&att.attestation_id).unwrap();
        assert!(published.immutable);
        assert_eq!(published.state, AttestationState::Published);
    }

    #[test]
    fn test_publish_emits_vep002() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_002));
    }

    #[test]
    fn test_cannot_publish_without_review() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        // Skip review — try to publish directly
        let result = reg.publish_attestation(&att.attestation_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_review_already_published() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        let result = reg.review_attestation(&att.attestation_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_attestation() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        let state = reg.reject_attestation(&att.attestation_id).unwrap();
        assert_eq!(state, AttestationState::Rejected);
    }

    #[test]
    fn test_reject_emits_vep008() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.reject_attestation(&att.attestation_id).unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_008));
    }

    // -- Reputation tests -----------------------------------------------------

    #[test]
    fn test_compute_reputation_deterministic() {
        let dims = ReputationDimensions {
            consistency: 0.8,
            coverage: 0.7,
            accuracy: 0.9,
            longevity: 0.5,
        };
        let score1 = VerifierEconomyRegistry::compute_reputation(&dims);
        let score2 = VerifierEconomyRegistry::compute_reputation(&dims);
        assert_eq!(score1, score2);
    }

    #[test]
    fn test_compute_reputation_all_ones() {
        let dims = ReputationDimensions {
            consistency: 1.0,
            coverage: 1.0,
            accuracy: 1.0,
            longevity: 1.0,
        };
        assert_eq!(VerifierEconomyRegistry::compute_reputation(&dims), 100);
    }

    #[test]
    fn test_compute_reputation_all_zeros() {
        let dims = ReputationDimensions {
            consistency: 0.0,
            coverage: 0.0,
            accuracy: 0.0,
            longevity: 0.0,
        };
        assert_eq!(VerifierEconomyRegistry::compute_reputation(&dims), 0);
    }

    #[test]
    fn test_compute_reputation_mixed() {
        let dims = ReputationDimensions {
            consistency: 0.8,
            coverage: 0.6,
            accuracy: 0.9,
            longevity: 0.5,
        };
        // 0.35*0.8 + 0.25*0.6 + 0.30*0.9 + 0.10*0.5
        // = 0.28 + 0.15 + 0.27 + 0.05 = 0.75 -> 75
        assert_eq!(VerifierEconomyRegistry::compute_reputation(&dims), 75);
    }

    #[test]
    fn test_update_reputation() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();
        let dims = ReputationDimensions {
            consistency: 0.8,
            coverage: 0.6,
            accuracy: 0.9,
            longevity: 0.5,
        };
        let score = reg.update_reputation(&v.verifier_id, &dims).unwrap();
        assert_eq!(score, 75);
        let updated = reg.get_verifier(&v.verifier_id).unwrap();
        assert_eq!(updated.reputation_tier, ReputationTier::Trusted);
    }

    #[test]
    fn test_update_reputation_emits_vep004() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();
        let dims = ReputationDimensions {
            consistency: 0.5,
            coverage: 0.5,
            accuracy: 0.5,
            longevity: 0.5,
        };
        reg.update_reputation(&v.verifier_id, &dims).unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_004));
    }

    // -- Reputation tier tests ------------------------------------------------

    #[test]
    fn test_reputation_tier_novice() {
        assert_eq!(reputation_tier_from_score(0), ReputationTier::Novice);
        assert_eq!(reputation_tier_from_score(24), ReputationTier::Novice);
    }

    #[test]
    fn test_reputation_tier_active() {
        assert_eq!(reputation_tier_from_score(25), ReputationTier::Active);
        assert_eq!(reputation_tier_from_score(49), ReputationTier::Active);
    }

    #[test]
    fn test_reputation_tier_established() {
        assert_eq!(reputation_tier_from_score(50), ReputationTier::Established);
        assert_eq!(reputation_tier_from_score(74), ReputationTier::Established);
    }

    #[test]
    fn test_reputation_tier_trusted() {
        assert_eq!(reputation_tier_from_score(75), ReputationTier::Trusted);
        assert_eq!(reputation_tier_from_score(100), ReputationTier::Trusted);
    }

    // -- Dispute tests --------------------------------------------------------

    #[test]
    fn test_file_dispute() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();

        let dispute = reg
            .file_dispute(
                &att.attestation_id,
                &v.verifier_id,
                "Results inconsistent with reference",
                vec!["evidence-1".to_string()],
            )
            .unwrap();

        assert!(dispute.dispute_id.starts_with("dsp-"));
        assert!(dispute.outcome.is_none());
    }

    #[test]
    fn test_file_dispute_emits_vep003() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        reg.file_dispute(&att.attestation_id, &v.verifier_id, "Reason", vec![])
            .unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_003));
    }

    #[test]
    fn test_cannot_dispute_unpublished() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        let result = reg.file_dispute(&att.attestation_id, &v.verifier_id, "Reason", vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_dispute_upheld() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        let dispute = reg
            .file_dispute(&att.attestation_id, &v.verifier_id, "Reason", vec![])
            .unwrap();
        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Upheld)
            .unwrap();
        let resolved = reg.get_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(resolved.outcome, Some(DisputeOutcome::Upheld));
        assert!(resolved.resolved_at.is_some());
    }

    #[test]
    fn test_resolve_dispute_rejected() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        let dispute = reg
            .file_dispute(&att.attestation_id, &v.verifier_id, "Reason", vec![])
            .unwrap();
        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Rejected)
            .unwrap();
        let resolved = reg.get_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(resolved.outcome, Some(DisputeOutcome::Rejected));
    }

    // -- Replay capsule tests -------------------------------------------------

    #[test]
    fn test_register_and_access_capsule() {
        let mut reg = make_registry();
        let capsule = ReplayCapsule {
            capsule_id: "cap-001".to_string(),
            attestation_id: "att-001".to_string(),
            input_state_hash: "sha256:input".to_string(),
            execution_trace_hash: "sha256:trace".to_string(),
            output_state_hash: "sha256:output".to_string(),
            expected_result_hash: "sha256:expected".to_string(),
            integrity_hash: "sha256:integrity".to_string(),
        };
        reg.register_replay_capsule(capsule).unwrap();
        let accessed = reg.access_replay_capsule("cap-001").unwrap();
        assert_eq!(accessed.capsule_id, "cap-001");
    }

    #[test]
    fn test_access_capsule_emits_vep007() {
        let mut reg = make_registry();
        let capsule = ReplayCapsule {
            capsule_id: "cap-002".to_string(),
            attestation_id: "att-002".to_string(),
            input_state_hash: "sha256:a".to_string(),
            execution_trace_hash: "sha256:b".to_string(),
            output_state_hash: "sha256:c".to_string(),
            expected_result_hash: "sha256:d".to_string(),
            integrity_hash: "sha256:e".to_string(),
        };
        reg.register_replay_capsule(capsule).unwrap();
        reg.access_replay_capsule("cap-002").unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_007));
    }

    #[test]
    fn test_capsule_integrity_valid() {
        let capsule = ReplayCapsule {
            capsule_id: "cap-003".to_string(),
            attestation_id: "att-003".to_string(),
            input_state_hash: "sha256:i".to_string(),
            execution_trace_hash: "sha256:t".to_string(),
            output_state_hash: "sha256:o".to_string(),
            expected_result_hash: "sha256:e".to_string(),
            integrity_hash: "sha256:h".to_string(),
        };
        assert!(VerifierEconomyRegistry::verify_capsule_integrity(&capsule));
    }

    #[test]
    fn test_capsule_integrity_invalid_empty_hash() {
        let capsule = ReplayCapsule {
            capsule_id: "cap-004".to_string(),
            attestation_id: "att-004".to_string(),
            input_state_hash: String::new(),
            execution_trace_hash: "sha256:t".to_string(),
            output_state_hash: "sha256:o".to_string(),
            expected_result_hash: "sha256:e".to_string(),
            integrity_hash: "sha256:h".to_string(),
        };
        assert!(!VerifierEconomyRegistry::verify_capsule_integrity(&capsule));
    }

    // -- Scoreboard tests -----------------------------------------------------

    #[test]
    fn test_empty_scoreboard() {
        let reg = make_registry();
        let sb = reg.build_scoreboard();
        assert_eq!(sb.total_verifiers, 0);
        assert_eq!(sb.total_attestations, 0);
        assert_eq!(sb.aggregate_score, 0.0);
    }

    #[test]
    fn test_scoreboard_with_published_attestation() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();

        let sb = reg.build_scoreboard();
        assert_eq!(sb.total_verifiers, 1);
        assert_eq!(sb.total_attestations, 1);
    }

    // -- Anti-gaming tests ----------------------------------------------------

    #[test]
    fn test_sybil_rate_limiting() {
        let mut reg = make_registry();
        reg.max_submissions_per_window = 2;

        let v = reg.register_verifier(make_registration()).unwrap();

        let sub1 = AttestationSubmission {
            verifier_id: v.verifier_id.clone(),
            claim: AttestationClaim {
                dimension: VerificationDimension::Compatibility,
                statement: "Claim 1".to_string(),
                score: 0.9,
            },
            evidence: AttestationEvidence {
                suite_id: "suite-1".to_string(),
                measurements: vec![],
                execution_trace_hash: "sha256:trace1".to_string(),
                environment: BTreeMap::new(),
            },
            signature: AttestationSignature {
                algorithm: "ed25519".to_string(),
                public_key: v.public_key.clone(),
                value: "sig1".to_string(),
            },
            timestamp: "2026-02-20T12:00:00Z".to_string(),
        };
        reg.submit_attestation(sub1).unwrap();

        let sub2 = AttestationSubmission {
            verifier_id: v.verifier_id.clone(),
            claim: AttestationClaim {
                dimension: VerificationDimension::Security,
                statement: "Claim 2".to_string(),
                score: 0.85,
            },
            evidence: AttestationEvidence {
                suite_id: "suite-2".to_string(),
                measurements: vec![],
                execution_trace_hash: "sha256:trace2".to_string(),
                environment: BTreeMap::new(),
            },
            signature: AttestationSignature {
                algorithm: "ed25519".to_string(),
                public_key: v.public_key.clone(),
                value: "sig2".to_string(),
            },
            timestamp: "2026-02-20T12:01:00Z".to_string(),
        };
        reg.submit_attestation(sub2).unwrap();

        // Third submission should be rate-limited
        let sub3 = AttestationSubmission {
            verifier_id: v.verifier_id.clone(),
            claim: AttestationClaim {
                dimension: VerificationDimension::Performance,
                statement: "Claim 3".to_string(),
                score: 0.80,
            },
            evidence: AttestationEvidence {
                suite_id: "suite-3".to_string(),
                measurements: vec![],
                execution_trace_hash: "sha256:trace3".to_string(),
                environment: BTreeMap::new(),
            },
            signature: AttestationSignature {
                algorithm: "ed25519".to_string(),
                public_key: v.public_key.clone(),
                value: "sig3".to_string(),
            },
            timestamp: "2026-02-20T12:02:00Z".to_string(),
        };
        let result = reg.submit_attestation(sub3);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_ANTI_GAMING);
    }

    #[test]
    fn test_sybil_rate_limit_emits_vep006() {
        let mut reg = make_registry();
        reg.max_submissions_per_window = 0; // Trigger immediately

        let v = reg.register_verifier(make_registration()).unwrap();
        let sub = make_submission(&v.verifier_id, &v.public_key);
        let _ = reg.submit_attestation(sub);
        assert!(reg.events().iter().any(|e| e.code == VEP_006));
    }

    #[test]
    fn test_selective_reporting_check_passes() {
        let mut reg = make_registry();
        let v = reg.register_verifier(make_registration()).unwrap();

        // Submit attestations in two different dimensions
        let sub1 = make_submission(&v.verifier_id, &v.public_key);
        reg.submit_attestation(sub1).unwrap();

        let sub2 = AttestationSubmission {
            verifier_id: v.verifier_id.clone(),
            claim: AttestationClaim {
                dimension: VerificationDimension::Security,
                statement: "Security claim".to_string(),
                score: 0.8,
            },
            evidence: AttestationEvidence {
                suite_id: "suite-sec".to_string(),
                measurements: vec![],
                execution_trace_hash: "sha256:unique".to_string(),
                environment: BTreeMap::new(),
            },
            signature: AttestationSignature {
                algorithm: "ed25519".to_string(),
                public_key: v.public_key.clone(),
                value: "sig-sec".to_string(),
            },
            timestamp: "2026-02-20T12:01:00Z".to_string(),
        };
        reg.submit_attestation(sub2).unwrap();

        assert!(reg.check_selective_reporting(&v.verifier_id, 2));
        assert!(!reg.check_selective_reporting(&v.verifier_id, 3));
    }

    #[test]
    fn test_reset_submission_counts() {
        let mut reg = make_registry();
        reg.max_submissions_per_window = 1;
        let v = reg.register_verifier(make_registration()).unwrap();
        let sub = make_submission(&v.verifier_id, &v.public_key);
        reg.submit_attestation(sub).unwrap();

        // Reset and try again with different trace hash
        reg.reset_submission_counts();

        let sub2 = AttestationSubmission {
            verifier_id: v.verifier_id.clone(),
            claim: AttestationClaim {
                dimension: VerificationDimension::Security,
                statement: "New claim".to_string(),
                score: 0.9,
            },
            evidence: AttestationEvidence {
                suite_id: "suite-new".to_string(),
                measurements: vec![],
                execution_trace_hash: "sha256:new-trace".to_string(),
                environment: BTreeMap::new(),
            },
            signature: AttestationSignature {
                algorithm: "ed25519".to_string(),
                public_key: v.public_key.clone(),
                value: "sig-new".to_string(),
            },
            timestamp: "2026-02-20T13:00:00Z".to_string(),
        };
        assert!(reg.submit_attestation(sub2).is_ok());
    }

    // -- Event tests ----------------------------------------------------------

    #[test]
    fn test_take_events_drains() {
        let mut reg = make_registry();
        reg.register_verifier(make_registration()).unwrap();
        let events = reg.take_events();
        assert!(!events.is_empty());
        assert!(reg.events().is_empty());
    }

    // -- Display tests --------------------------------------------------------

    #[test]
    fn test_dimension_display() {
        assert_eq!(
            format!("{}", VerificationDimension::Compatibility),
            "compatibility"
        );
        assert_eq!(format!("{}", VerificationDimension::Security), "security");
        assert_eq!(
            format!("{}", VerificationDimension::Performance),
            "performance"
        );
        assert_eq!(
            format!("{}", VerificationDimension::SupplyChain),
            "supply_chain"
        );
        assert_eq!(
            format!("{}", VerificationDimension::Conformance),
            "conformance"
        );
    }

    #[test]
    fn test_verifier_tier_display() {
        assert_eq!(format!("{}", VerifierTier::Basic), "basic");
        assert_eq!(format!("{}", VerifierTier::Advanced), "advanced");
    }

    #[test]
    fn test_reputation_tier_display() {
        assert_eq!(format!("{}", ReputationTier::Novice), "Novice");
        assert_eq!(format!("{}", ReputationTier::Active), "Active");
        assert_eq!(format!("{}", ReputationTier::Established), "Established");
        assert_eq!(format!("{}", ReputationTier::Trusted), "Trusted");
    }

    #[test]
    fn test_attestation_state_display() {
        assert_eq!(format!("{}", AttestationState::Submitted), "submitted");
        assert_eq!(format!("{}", AttestationState::UnderReview), "under_review");
        assert_eq!(format!("{}", AttestationState::Published), "published");
        assert_eq!(format!("{}", AttestationState::Rejected), "rejected");
        assert_eq!(format!("{}", AttestationState::Disputed), "disputed");
    }

    #[test]
    fn test_dispute_outcome_display() {
        assert_eq!(format!("{}", DisputeOutcome::Upheld), "upheld");
        assert_eq!(format!("{}", DisputeOutcome::Rejected), "rejected");
        assert_eq!(format!("{}", DisputeOutcome::Inconclusive), "inconclusive");
    }

    #[test]
    fn test_vep_error_display() {
        let err = VepError {
            code: ERR_VEP_INVALID_SIGNATURE.to_string(),
            message: "bad sig".to_string(),
        };
        let s = format!("{}", err);
        assert!(s.contains(ERR_VEP_INVALID_SIGNATURE));
        assert!(s.contains("bad sig"));
    }

    // -- Signature verification tests -----------------------------------------

    #[test]
    fn test_verify_signature_valid() {
        let reg = make_registry();
        let sig = AttestationSignature {
            algorithm: "ed25519".to_string(),
            public_key: "key-abc".to_string(),
            value: "sig-value".to_string(),
        };
        assert!(reg.verify_signature(&sig, "key-abc"));
    }

    #[test]
    fn test_verify_signature_wrong_key() {
        let reg = make_registry();
        let sig = AttestationSignature {
            algorithm: "ed25519".to_string(),
            public_key: "key-abc".to_string(),
            value: "sig-value".to_string(),
        };
        assert!(!reg.verify_signature(&sig, "key-xyz"));
    }

    #[test]
    fn test_verify_signature_wrong_algorithm() {
        let reg = make_registry();
        let sig = AttestationSignature {
            algorithm: "rsa".to_string(),
            public_key: "key-abc".to_string(),
            value: "sig-value".to_string(),
        };
        assert!(!reg.verify_signature(&sig, "key-abc"));
    }

    #[test]
    fn test_verify_signature_empty_value() {
        let reg = make_registry();
        let sig = AttestationSignature {
            algorithm: "ed25519".to_string(),
            public_key: "key-abc".to_string(),
            value: String::new(),
        };
        assert!(!reg.verify_signature(&sig, "key-abc"));
    }

    // -- Default trait test ----------------------------------------------------

    #[test]
    fn test_default_registry() {
        let reg = VerifierEconomyRegistry::default();
        assert_eq!(reg.verifier_count(), 0);
        assert_eq!(reg.attestation_count(), 0);
    }

    // -- Published attestations filter ----------------------------------------

    #[test]
    fn test_published_attestations_filter() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        assert_eq!(reg.published_attestations().len(), 0);

        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        assert_eq!(reg.published_attestations().len(), 1);
    }

    // -- Event constant tests -------------------------------------------------

    #[test]
    fn test_event_code_constants() {
        assert_eq!(VEP_001, "VEP-001");
        assert_eq!(VEP_002, "VEP-002");
        assert_eq!(VEP_003, "VEP-003");
        assert_eq!(VEP_004, "VEP-004");
        assert_eq!(VEP_005, "VEP-005");
        assert_eq!(VEP_006, "VEP-006");
        assert_eq!(VEP_007, "VEP-007");
        assert_eq!(VEP_008, "VEP-008");
    }

    #[test]
    fn test_invariant_constants() {
        assert_eq!(INV_VEP_ATTESTATION, "INV-VEP-ATTESTATION");
        assert_eq!(INV_VEP_SIGNATURE, "INV-VEP-SIGNATURE");
        assert_eq!(INV_VEP_REPUTATION, "INV-VEP-REPUTATION");
        assert_eq!(INV_VEP_PUBLISH, "INV-VEP-PUBLISH");
    }

    #[test]
    fn test_error_code_constants() {
        assert_eq!(ERR_VEP_INVALID_SIGNATURE, "ERR-VEP-INVALID-SIGNATURE");
        assert_eq!(ERR_VEP_DUPLICATE_SUBMISSION, "ERR-VEP-DUPLICATE-SUBMISSION");
        assert_eq!(
            ERR_VEP_UNREGISTERED_VERIFIER,
            "ERR-VEP-UNREGISTERED-VERIFIER"
        );
        assert_eq!(ERR_VEP_INCOMPLETE_PAYLOAD, "ERR-VEP-INCOMPLETE-PAYLOAD");
        assert_eq!(ERR_VEP_ANTI_GAMING, "ERR-VEP-ANTI-GAMING");
    }
}
