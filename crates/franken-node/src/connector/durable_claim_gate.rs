//! bd-1l62: Durable claim gate (fail-closed proof/marker verification).
//!
//! Durable claims are accepted only when required markers and proof artifacts
//! are present, valid, fresh, and verification-complete.

use std::collections::HashSet;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Proof families supported by the durable claim gate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    MerkleInclusion,
    MarkerMmr,
    EpochBoundary,
    Custom(String),
}

impl ProofType {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::MerkleInclusion => "merkle_inclusion".to_string(),
            Self::MarkerMmr => "marker_mmr".to_string(),
            Self::EpochBoundary => "epoch_boundary".to_string(),
            Self::Custom(v) => format!("custom:{v}"),
        }
    }
}

/// Stable denial reasons exposed to API/log/telemetry consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimDenialReason {
    ProofMissing {
        proof_type: ProofType,
    },
    ProofInvalid {
        proof_type: ProofType,
        detail: String,
    },
    ProofExpired {
        proof_type: ProofType,
        proof_epoch: u64,
        current_epoch: u64,
    },
    ProofVerificationTimeout {
        timeout_ms: u64,
        elapsed_ms: u64,
    },
    MarkerUnavailable {
        marker_id: String,
    },
}

impl ClaimDenialReason {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProofMissing { .. } => "CLAIM_PROOF_MISSING",
            Self::ProofInvalid { .. } => "CLAIM_PROOF_INVALID",
            Self::ProofExpired { .. } => "CLAIM_PROOF_EXPIRED",
            Self::ProofVerificationTimeout { .. } => "CLAIM_PROOF_VERIFICATION_TIMEOUT",
            Self::MarkerUnavailable { .. } => "CLAIM_MARKER_UNAVAILABLE",
        }
    }
}

/// Gate configuration.
#[derive(Debug, Clone)]
pub struct DurableClaimGateConfig {
    pub verification_timeout_ms: u64,
    pub freshness_window_epochs: u64,
}

impl Default for DurableClaimGateConfig {
    fn default() -> Self {
        Self {
            verification_timeout_ms: 1000,
            freshness_window_epochs: 1,
        }
    }
}

/// Durable claim request subject to proof gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableClaim {
    pub claim_id: String,
    pub claim_type: String,
    pub claim_hash: String,
    pub epoch: u64,
    pub required_markers: Vec<String>,
    pub required_proofs: Vec<ProofType>,
    pub trace_id: String,
}

/// Proof artifact presented to the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub proof_type: ProofType,
    pub claim_id: String,
    pub claim_hash: String,
    pub issued_at_epoch: u64,
    pub expires_at_epoch: u64,
    pub proof_hash: String,
    pub verified: bool,
}

/// Inputs available to the gate at evaluation time.
#[derive(Debug, Clone, Default)]
pub struct VerificationInput {
    pub available_markers: HashSet<String>,
    pub proofs: Vec<ProofArtifact>,
    pub verification_complete: bool,
    pub simulated_elapsed_ms: u64,
}

/// Evidence ledger entry emitted for accepted durable claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub claim_id: String,
    pub epoch: u64,
    pub proof_artifact_hash: String,
    pub trace_id: String,
}

/// Structured gate event for observability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimGateEvent {
    pub event_code: String,
    pub claim_id: String,
    pub proof_type: Option<ProofType>,
    pub denial_reason: Option<String>,
    pub marker_count: usize,
    pub proof_count: usize,
    pub trace_id: String,
    pub epoch: u64,
}

/// Public gate status snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimGateStatus {
    pub verification_complete: bool,
    pub marker_count: usize,
    pub proof_count: usize,
    pub last_denial_reason: Option<ClaimDenialReason>,
    pub last_event_code: String,
}

/// Gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimGateDecision {
    pub accepted: bool,
    pub denial_reason: Option<ClaimDenialReason>,
    pub evidence_entry: Option<EvidenceEntry>,
    pub latency_us: u128,
}

/// Configuration/runtime errors for gate usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableClaimGateError {
    InvalidConfig { reason: String },
    InvalidClaim { reason: String },
}

impl DurableClaimGateError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "CLAIM_GATE_INVALID_CONFIG",
            Self::InvalidClaim { .. } => "CLAIM_GATE_INVALID_CLAIM",
        }
    }
}

impl std::fmt::Display for DurableClaimGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig { reason } => write!(f, "CLAIM_GATE_INVALID_CONFIG: {reason}"),
            Self::InvalidClaim { reason } => write!(f, "CLAIM_GATE_INVALID_CLAIM: {reason}"),
        }
    }
}

/// Fail-closed durable claim gate.
#[derive(Debug, Clone)]
pub struct DurableClaimGate {
    config: DurableClaimGateConfig,
    status: ClaimGateStatus,
    events: Vec<ClaimGateEvent>,
}

impl DurableClaimGate {
    pub fn new(config: DurableClaimGateConfig) -> Result<Self, DurableClaimGateError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            status: ClaimGateStatus::default(),
            events: Vec::new(),
        })
    }

    #[must_use]
    pub fn claim_gate_status(&self) -> ClaimGateStatus {
        self.status.clone()
    }

    #[must_use]
    pub fn events(&self) -> &[ClaimGateEvent] {
        &self.events
    }

    /// Evaluate a durable claim. Any uncertainty fails closed.
    ///
    /// Event codes:
    /// - `CLAIM_SUBMITTED`
    /// - `CLAIM_ACCEPTED`
    /// - `CLAIM_REJECTED`
    /// - `PROOF_VERIFIED`
    /// - `PROOF_INVALID`
    pub fn evaluate_claim(
        &mut self,
        claim: &DurableClaim,
        input: &VerificationInput,
        current_epoch: u64,
    ) -> Result<ClaimGateDecision, DurableClaimGateError> {
        validate_claim(claim)?;

        let start = Instant::now();
        self.status.verification_complete = input.verification_complete;
        self.status.marker_count = input.available_markers.len();
        self.status.proof_count = input.proofs.len();

        self.emit(
            "CLAIM_SUBMITTED",
            claim,
            None,
            None,
            input.available_markers.len(),
            input.proofs.len(),
        );

        if input.simulated_elapsed_ms > self.config.verification_timeout_ms
            || !input.verification_complete
        {
            let reason = ClaimDenialReason::ProofVerificationTimeout {
                timeout_ms: self.config.verification_timeout_ms,
                elapsed_ms: input.simulated_elapsed_ms,
            };
            return Ok(self.deny(claim, reason, start));
        }

        for marker_id in &claim.required_markers {
            if !input.available_markers.contains(marker_id) {
                return Ok(self.deny(
                    claim,
                    ClaimDenialReason::MarkerUnavailable {
                        marker_id: marker_id.clone(),
                    },
                    start,
                ));
            }
        }

        let mut proof_hashes = Vec::new();
        for required_type in &claim.required_proofs {
            let maybe_proof = input.proofs.iter().find(|proof| {
                proof.proof_type == *required_type && proof.claim_id == claim.claim_id
            });
            let proof = if let Some(found) = maybe_proof {
                found
            } else {
                return Ok(self.deny(
                    claim,
                    ClaimDenialReason::ProofMissing {
                        proof_type: required_type.clone(),
                    },
                    start,
                ));
            };

            if proof.claim_hash != claim.claim_hash {
                self.emit(
                    "PROOF_INVALID",
                    claim,
                    Some(required_type.clone()),
                    Some("claim_hash_mismatch".to_string()),
                    input.available_markers.len(),
                    input.proofs.len(),
                );
                return Ok(self.deny(
                    claim,
                    ClaimDenialReason::ProofInvalid {
                        proof_type: required_type.clone(),
                        detail: "claim_hash_mismatch".to_string(),
                    },
                    start,
                ));
            }

            if !proof.verified {
                self.emit(
                    "PROOF_INVALID",
                    claim,
                    Some(required_type.clone()),
                    Some("verification_failed".to_string()),
                    input.available_markers.len(),
                    input.proofs.len(),
                );
                return Ok(self.deny(
                    claim,
                    ClaimDenialReason::ProofInvalid {
                        proof_type: required_type.clone(),
                        detail: "verification_failed".to_string(),
                    },
                    start,
                ));
            }

            let stale_by_ttl = current_epoch > proof.expires_at_epoch;
            let stale_by_window = current_epoch.saturating_sub(proof.issued_at_epoch)
                > self.config.freshness_window_epochs;
            if stale_by_ttl || stale_by_window {
                return Ok(self.deny(
                    claim,
                    ClaimDenialReason::ProofExpired {
                        proof_type: required_type.clone(),
                        proof_epoch: proof.issued_at_epoch,
                        current_epoch,
                    },
                    start,
                ));
            }

            self.emit(
                "PROOF_VERIFIED",
                claim,
                Some(required_type.clone()),
                None,
                input.available_markers.len(),
                input.proofs.len(),
            );
            proof_hashes.push(proof.proof_hash.clone());
        }

        proof_hashes.sort();
        let proof_artifact_hash = hash_witnesses(&proof_hashes);
        let evidence = EvidenceEntry {
            claim_id: claim.claim_id.clone(),
            epoch: claim.epoch,
            proof_artifact_hash,
            trace_id: claim.trace_id.clone(),
        };

        self.status.last_denial_reason = None;
        self.status.last_event_code = "CLAIM_ACCEPTED".to_string();
        self.emit(
            "CLAIM_ACCEPTED",
            claim,
            None,
            None,
            input.available_markers.len(),
            input.proofs.len(),
        );

        Ok(ClaimGateDecision {
            accepted: true,
            denial_reason: None,
            evidence_entry: Some(evidence),
            latency_us: start.elapsed().as_micros(),
        })
    }

    fn deny(
        &mut self,
        claim: &DurableClaim,
        reason: ClaimDenialReason,
        start: Instant,
    ) -> ClaimGateDecision {
        self.status.last_denial_reason = Some(reason.clone());
        self.status.last_event_code = "CLAIM_REJECTED".to_string();
        self.emit(
            "CLAIM_REJECTED",
            claim,
            None,
            Some(reason.code().to_string()),
            self.status.marker_count,
            self.status.proof_count,
        );

        ClaimGateDecision {
            accepted: false,
            denial_reason: Some(reason),
            evidence_entry: None,
            latency_us: start.elapsed().as_micros(),
        }
    }

    fn emit(
        &mut self,
        event_code: &str,
        claim: &DurableClaim,
        proof_type: Option<ProofType>,
        denial_reason: Option<String>,
        marker_count: usize,
        proof_count: usize,
    ) {
        self.events.push(ClaimGateEvent {
            event_code: event_code.to_string(),
            claim_id: claim.claim_id.clone(),
            proof_type,
            denial_reason,
            marker_count,
            proof_count,
            trace_id: claim.trace_id.clone(),
            epoch: claim.epoch,
        });
    }
}

fn validate_config(config: &DurableClaimGateConfig) -> Result<(), DurableClaimGateError> {
    if config.verification_timeout_ms == 0 {
        return Err(DurableClaimGateError::InvalidConfig {
            reason: "verification_timeout_ms must be > 0".to_string(),
        });
    }
    if config.freshness_window_epochs == 0 {
        return Err(DurableClaimGateError::InvalidConfig {
            reason: "freshness_window_epochs must be > 0".to_string(),
        });
    }
    Ok(())
}

fn validate_claim(claim: &DurableClaim) -> Result<(), DurableClaimGateError> {
    if claim.claim_id.is_empty() {
        return Err(DurableClaimGateError::InvalidClaim {
            reason: "claim_id must not be empty".to_string(),
        });
    }
    if claim.claim_hash.is_empty() {
        return Err(DurableClaimGateError::InvalidClaim {
            reason: "claim_hash must not be empty".to_string(),
        });
    }
    if claim.required_proofs.is_empty() {
        return Err(DurableClaimGateError::InvalidClaim {
            reason: "required_proofs must not be empty".to_string(),
        });
    }
    Ok(())
}

fn hash_witnesses(proof_hashes: &[String]) -> String {
    let mut hasher = Sha256::new();
    for proof_hash in proof_hashes {
        hasher.update(proof_hash.as_bytes());
        hasher.update(b"|");
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_claim() -> DurableClaim {
        DurableClaim {
            claim_id: "claim-1".to_string(),
            claim_type: "commit_confirmation".to_string(),
            claim_hash: "claim-hash-1".to_string(),
            epoch: 10,
            required_markers: vec!["marker-a".to_string()],
            required_proofs: vec![
                ProofType::MerkleInclusion,
                ProofType::MarkerMmr,
                ProofType::EpochBoundary,
            ],
            trace_id: "trace-1".to_string(),
        }
    }

    fn valid_input() -> VerificationInput {
        let mut markers = HashSet::new();
        markers.insert("marker-a".to_string());
        VerificationInput {
            available_markers: markers,
            proofs: vec![
                ProofArtifact {
                    proof_type: ProofType::MerkleInclusion,
                    claim_id: "claim-1".to_string(),
                    claim_hash: "claim-hash-1".to_string(),
                    issued_at_epoch: 10,
                    expires_at_epoch: 12,
                    proof_hash: "proof-hash-merkle".to_string(),
                    verified: true,
                },
                ProofArtifact {
                    proof_type: ProofType::MarkerMmr,
                    claim_id: "claim-1".to_string(),
                    claim_hash: "claim-hash-1".to_string(),
                    issued_at_epoch: 10,
                    expires_at_epoch: 12,
                    proof_hash: "proof-hash-mmr".to_string(),
                    verified: true,
                },
                ProofArtifact {
                    proof_type: ProofType::EpochBoundary,
                    claim_id: "claim-1".to_string(),
                    claim_hash: "claim-hash-1".to_string(),
                    issued_at_epoch: 10,
                    expires_at_epoch: 12,
                    proof_hash: "proof-hash-epoch".to_string(),
                    verified: true,
                },
            ],
            verification_complete: true,
            simulated_elapsed_ms: 1,
        }
    }

    #[test]
    fn accepts_valid_claim_with_evidence_entry() {
        let mut gate = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
        let decision = gate
            .evaluate_claim(&base_claim(), &valid_input(), 10)
            .unwrap();

        assert!(decision.accepted);
        assert!(decision.denial_reason.is_none());
        assert!(decision.evidence_entry.is_some());
        assert!(!gate.events().is_empty());
    }

    #[test]
    fn denial_reason_proof_missing() {
        let mut gate = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
        let mut input = valid_input();
        input
            .proofs
            .retain(|proof| proof.proof_type != ProofType::EpochBoundary);

        let decision = gate.evaluate_claim(&base_claim(), &input, 10).unwrap();
        let reason = decision.denial_reason.unwrap();
        assert_eq!(reason.code(), "CLAIM_PROOF_MISSING");
    }

    #[test]
    fn denial_reason_proof_invalid() {
        let mut gate = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
        let mut input = valid_input();
        input.proofs[0].verified = false;

        let decision = gate.evaluate_claim(&base_claim(), &input, 10).unwrap();
        let reason = decision.denial_reason.unwrap();
        assert_eq!(reason.code(), "CLAIM_PROOF_INVALID");
    }

    #[test]
    fn denial_reason_proof_expired() {
        let mut gate = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
        let mut input = valid_input();
        for proof in &mut input.proofs {
            proof.issued_at_epoch = 2;
            proof.expires_at_epoch = 5;
        }

        let decision = gate.evaluate_claim(&base_claim(), &input, 10).unwrap();
        let reason = decision.denial_reason.unwrap();
        assert_eq!(reason.code(), "CLAIM_PROOF_EXPIRED");
    }

    #[test]
    fn denial_reason_verification_timeout() {
        let mut gate = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
        let mut input = valid_input();
        input.simulated_elapsed_ms = 5_000;

        let decision = gate.evaluate_claim(&base_claim(), &input, 10).unwrap();
        let reason = decision.denial_reason.unwrap();
        assert_eq!(reason.code(), "CLAIM_PROOF_VERIFICATION_TIMEOUT");
    }

    #[test]
    fn denial_reason_marker_unavailable() {
        let mut gate = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
        let mut input = valid_input();
        input.available_markers.clear();

        let decision = gate.evaluate_claim(&base_claim(), &input, 10).unwrap();
        let reason = decision.denial_reason.unwrap();
        assert_eq!(reason.code(), "CLAIM_MARKER_UNAVAILABLE");
    }

    #[test]
    fn deterministic_verification_for_identical_inputs() {
        let mut gate_a = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
        let mut gate_b = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
        let claim = base_claim();
        let input = valid_input();

        let a = gate_a.evaluate_claim(&claim, &input, 10).unwrap();
        let b = gate_b.evaluate_claim(&claim, &input, 10).unwrap();

        assert_eq!(a.accepted, b.accepted);
        assert_eq!(a.denial_reason, b.denial_reason);
        assert_eq!(a.evidence_entry, b.evidence_entry);
    }

    #[test]
    fn malformed_and_partial_proofs_fail_closed() {
        let claim = base_claim();
        let cases = vec![
            {
                let mut input = valid_input();
                input.proofs[0].claim_hash = "forged".to_string();
                input
            },
            {
                let mut input = valid_input();
                input.proofs[1].claim_id = "different-claim".to_string();
                input
            },
            {
                let mut input = valid_input();
                input.verification_complete = false;
                input
            },
            {
                let mut input = valid_input();
                input.proofs[2].verified = false;
                input
            },
        ];

        for (index, input) in cases.into_iter().enumerate() {
            let mut gate = DurableClaimGate::new(DurableClaimGateConfig::default()).unwrap();
            let decision = gate.evaluate_claim(&claim, &input, 10).unwrap();
            assert!(!decision.accepted, "case {index} must be denied");
            assert!(decision.denial_reason.is_some());
        }
    }
}
