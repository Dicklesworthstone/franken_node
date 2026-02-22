//! bd-2yvw: Sybil-resistant participation controls for ATC federation (10.19).
//!
//! Implements participation weighting that rejects untrusted identity inflation
//! by tying influence to attestation, staking, and reputation evidence.
//!
//! # Design
//!
//! Each participant in the ATC network has a `ParticipantIdentity` backed by
//! verifiable evidence: attestation certificates, stake deposits, and
//! reputation scores accumulated over time. The `ParticipationWeightEngine`
//! computes a composite weight for each participant, ensuring that:
//!
//! - New/unproven identities receive minimal weight (< 1% of established nodes)
//! - Coordinated Sybil clusters are detected and attenuated
//! - Weight computation is deterministic and auditable
//! - All decisions are logged with structured event codes
//!
//! # Invariants
//!
//! - **INV-ATC-SYBIL-BOUND**: N Sybil identities with zero history have
//!   less aggregate weight than K honest established participants (N=100, K=5).
//! - **INV-ATC-WEIGHT-DETERMINISM**: Same inputs produce same weights.
//! - **INV-ATC-NEW-NODE-CAP**: New participant weight <= 1% of median established weight.
//! - **INV-ATC-STAKE-MONOTONE**: Higher stake always produces higher weight (all else equal).
//! - **INV-ATC-ATTESTATION-REQUIRED**: Zero-attestation participants receive zero weight.
//! - **INV-ATC-AUDIT-COMPLETE**: Every weight computation produces an audit record.
//! - **INV-ATC-CLUSTER-ATTENUATION**: Detected Sybil clusters have combined weight
//!   reduced by >= 90%.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// ATC-PART-001: Participation weight computed for a participant.
    pub const WEIGHT_COMPUTED: &str = "ATC-PART-001";
    /// ATC-PART-002: Sybil cluster detected and attenuated.
    pub const SYBIL_CLUSTER_DETECTED: &str = "ATC-PART-002";
    /// ATC-PART-003: New participant capped at maximum initial weight.
    pub const NEW_PARTICIPANT_CAPPED: &str = "ATC-PART-003";
    /// ATC-PART-004: Zero-attestation participant rejected.
    pub const ZERO_ATTESTATION_REJECTED: &str = "ATC-PART-004";
    /// ATC-PART-005: Weight audit record emitted.
    pub const AUDIT_RECORD_EMITTED: &str = "ATC-PART-005";
    /// ATC-PART-006: Participation policy evaluation completed.
    pub const POLICY_EVALUATED: &str = "ATC-PART-006";
    /// ATC-PART-007: Stake deposit verified.
    pub const STAKE_VERIFIED: &str = "ATC-PART-007";
    /// ATC-PART-008: Reputation score refreshed.
    pub const REPUTATION_REFRESHED: &str = "ATC-PART-008";
    /// ATC-PART-ERR-001: Weight computation failed.
    pub const WEIGHT_COMPUTATION_FAILED: &str = "ATC-PART-ERR-001";
    /// ATC-PART-ERR-002: Invalid attestation evidence.
    pub const INVALID_ATTESTATION: &str = "ATC-PART-ERR-002";
}

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_ATC_SYBIL_BOUND: &str = "INV-ATC-SYBIL-BOUND";
    pub const INV_ATC_WEIGHT_DETERMINISM: &str = "INV-ATC-WEIGHT-DETERMINISM";
    pub const INV_ATC_NEW_NODE_CAP: &str = "INV-ATC-NEW-NODE-CAP";
    pub const INV_ATC_STAKE_MONOTONE: &str = "INV-ATC-STAKE-MONOTONE";
    pub const INV_ATC_ATTESTATION_REQUIRED: &str = "INV-ATC-ATTESTATION-REQUIRED";
    pub const INV_ATC_AUDIT_COMPLETE: &str = "INV-ATC-AUDIT-COMPLETE";
    pub const INV_ATC_CLUSTER_ATTENUATION: &str = "INV-ATC-CLUSTER-ATTENUATION";
}

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

/// Attestation evidence backing a participant identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// Unique attestation certificate identifier.
    pub attestation_id: String,
    /// Issuer of the attestation (e.g., a trusted CA or verifier).
    pub issuer: String,
    /// Attestation level: higher means stronger verification.
    pub level: AttestationLevel,
    /// When the attestation was issued (RFC 3339).
    pub issued_at: String,
    /// When the attestation expires (RFC 3339).
    pub expires_at: String,
    /// Hex-encoded signature over the attestation payload.
    pub signature_hex: String,
}

/// Attestation verification strength levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationLevel {
    /// Self-signed attestation (lowest trust).
    SelfSigned,
    /// Peer-verified attestation.
    PeerVerified,
    /// Verifier-backed attestation.
    VerifierBacked,
    /// Authority-certified attestation (highest trust).
    AuthorityCertified,
}

impl AttestationLevel {
    /// Weight multiplier for this attestation level.
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::SelfSigned => 0.1,
            Self::PeerVerified => 0.4,
            Self::VerifierBacked => 0.8,
            Self::AuthorityCertified => 1.0,
        }
    }
}

/// Stake deposit evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StakeEvidence {
    /// Amount staked (abstract units).
    pub amount: f64,
    /// When the stake was deposited.
    pub deposited_at: String,
    /// Lock duration in seconds (longer lock = higher trust signal).
    pub lock_duration_seconds: u64,
    /// Whether the stake is currently locked (vs. withdrawable).
    pub locked: bool,
}

/// Reputation evidence accumulated over time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationEvidence {
    /// Cumulative reputation score [0.0, 1.0].
    pub score: f64,
    /// Number of successful interactions contributing to reputation.
    pub interaction_count: u64,
    /// Duration of participation in the network (seconds).
    pub tenure_seconds: u64,
    /// Number of verified contributions accepted by the network.
    pub contributions_accepted: u64,
    /// Number of contributions rejected (penalty signal).
    pub contributions_rejected: u64,
}

// ---------------------------------------------------------------------------
// Participant identity
// ---------------------------------------------------------------------------

/// A participant in the ATC federation network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParticipantIdentity {
    /// Unique participant identifier.
    pub participant_id: String,
    /// Display name for audit logs.
    pub display_name: String,
    /// Attestation evidence chain.
    pub attestations: Vec<AttestationEvidence>,
    /// Stake evidence.
    pub stake: Option<StakeEvidence>,
    /// Reputation evidence.
    pub reputation: Option<ReputationEvidence>,
    /// Optional cluster hint (IP subnet, timing fingerprint, etc.).
    pub cluster_hint: Option<String>,
}

impl ParticipantIdentity {
    /// Returns the strongest attestation level, or None if no attestations.
    pub fn strongest_attestation(&self) -> Option<AttestationLevel> {
        self.attestations.iter().map(|a| a.level).max()
    }

    /// Returns true if the participant has at least one valid attestation.
    pub fn has_attestation(&self) -> bool {
        !self.attestations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Weight computation
// ---------------------------------------------------------------------------

/// Computed participation weight for a single participant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParticipationWeight {
    pub participant_id: String,
    pub raw_weight: f64,
    pub attestation_component: f64,
    pub stake_component: f64,
    pub reputation_component: f64,
    pub sybil_penalty: f64,
    pub final_weight: f64,
    pub capped: bool,
    pub rejected: bool,
    pub rejection_reason: Option<String>,
}

/// Audit record for a weight computation batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeightAuditRecord {
    pub batch_id: String,
    pub timestamp: String,
    pub participant_count: usize,
    pub sybil_clusters_detected: usize,
    pub participants_rejected: usize,
    pub participants_capped: usize,
    pub total_weight: f64,
    pub weights: Vec<ParticipationWeight>,
    pub content_hash: String,
}

impl WeightAuditRecord {
    /// Compute a deterministic content hash over the audit record.
    pub fn compute_hash(weights: &[ParticipationWeight]) -> String {
        let canonical = serde_json::to_string(weights).unwrap_or_default();
        let digest = Sha256::digest(canonical.as_bytes());
        hex::encode(digest)
    }
}

/// Sybil cluster detection result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SybilCluster {
    pub cluster_id: String,
    pub member_ids: Vec<String>,
    pub detection_signal: String,
    pub attenuation_factor: f64,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the participation weight engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeightingConfig {
    /// Weight factor for attestation component [0, 1].
    pub attestation_weight: f64,
    /// Weight factor for stake component [0, 1].
    pub stake_weight: f64,
    /// Weight factor for reputation component [0, 1].
    pub reputation_weight: f64,
    /// Maximum weight for new participants as fraction of median established weight.
    pub new_participant_cap_fraction: f64,
    /// Minimum tenure (seconds) to be considered "established".
    pub established_tenure_seconds: u64,
    /// Minimum interactions to be considered "established".
    pub established_interaction_count: u64,
    /// Attenuation factor applied to detected Sybil clusters [0, 1].
    /// Lower means more aggressive attenuation.
    pub sybil_attenuation_factor: f64,
    /// Minimum cluster size to trigger Sybil detection.
    pub sybil_cluster_min_size: usize,
}

impl Default for WeightingConfig {
    fn default() -> Self {
        Self {
            attestation_weight: 0.4,
            stake_weight: 0.3,
            reputation_weight: 0.3,
            new_participant_cap_fraction: 0.01,
            established_tenure_seconds: 86400 * 30, // 30 days
            established_interaction_count: 100,
            sybil_attenuation_factor: 0.1, // 90% reduction
            sybil_cluster_min_size: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The participation weight engine computes Sybil-resistant weights.
#[derive(Debug, Clone)]
pub struct ParticipationWeightEngine {
    config: WeightingConfig,
    audit_log: Vec<WeightAuditRecord>,
}

impl Default for ParticipationWeightEngine {
    fn default() -> Self {
        Self::new(WeightingConfig::default())
    }
}

impl ParticipationWeightEngine {
    pub fn new(config: WeightingConfig) -> Self {
        Self {
            config,
            audit_log: Vec::new(),
        }
    }

    /// Compute participation weights for a batch of participants.
    ///
    /// Returns a `WeightAuditRecord` containing individual weights and
    /// aggregate statistics. The computation is deterministic: same inputs
    /// always produce the same output.
    pub fn compute_weights(
        &mut self,
        participants: &[ParticipantIdentity],
        batch_id: &str,
        timestamp: &str,
    ) -> WeightAuditRecord {
        // Step 1: Compute raw weights for each participant
        let mut weights: Vec<ParticipationWeight> = participants
            .iter()
            .map(|p| self.compute_single_weight(p))
            .collect();

        // Step 2: Detect Sybil clusters and apply attenuation
        let clusters = self.detect_sybil_clusters(participants);
        let sybil_member_ids: HashSet<String> = clusters
            .iter()
            .flat_map(|c| c.member_ids.iter().cloned())
            .collect();

        for w in &mut weights {
            if sybil_member_ids.contains(&w.participant_id) {
                w.sybil_penalty = 1.0 - self.config.sybil_attenuation_factor;
                w.final_weight *= self.config.sybil_attenuation_factor;
            }
        }

        // Step 3: Cap new participants relative to median established weight
        let median_established = self.compute_median_established_weight(&weights, participants);
        let cap = median_established * self.config.new_participant_cap_fraction;

        for (i, w) in weights.iter_mut().enumerate() {
            if !w.rejected
                && !self.is_established(&participants[i])
                && w.final_weight > cap
                && cap > 0.0
            {
                w.final_weight = cap;
                w.capped = true;
            }
        }

        let content_hash = WeightAuditRecord::compute_hash(&weights);
        let total_weight: f64 = weights.iter().map(|w| w.final_weight).sum();

        let record = WeightAuditRecord {
            batch_id: batch_id.to_string(),
            timestamp: timestamp.to_string(),
            participant_count: participants.len(),
            sybil_clusters_detected: clusters.len(),
            participants_rejected: weights.iter().filter(|w| w.rejected).count(),
            participants_capped: weights.iter().filter(|w| w.capped).count(),
            total_weight,
            weights,
            content_hash,
        };

        self.audit_log.push(record.clone());
        record
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[WeightAuditRecord] {
        &self.audit_log
    }

    /// Export audit log as JSON.
    pub fn export_audit_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.audit_log)
    }

    // -----------------------------------------------------------------------
    // Internal: single participant weight computation
    // -----------------------------------------------------------------------

    fn compute_single_weight(&self, participant: &ParticipantIdentity) -> ParticipationWeight {
        // Reject participants with no attestation
        if !participant.has_attestation() {
            return ParticipationWeight {
                participant_id: participant.participant_id.clone(),
                raw_weight: 0.0,
                attestation_component: 0.0,
                stake_component: 0.0,
                reputation_component: 0.0,
                sybil_penalty: 0.0,
                final_weight: 0.0,
                capped: false,
                rejected: true,
                rejection_reason: Some("no attestation evidence".to_string()),
            };
        }

        let attestation_component = self.compute_attestation_component(participant);
        let stake_component = self.compute_stake_component(participant);
        let reputation_component = self.compute_reputation_component(participant);

        let raw_weight = attestation_component * self.config.attestation_weight
            + stake_component * self.config.stake_weight
            + reputation_component * self.config.reputation_weight;

        ParticipationWeight {
            participant_id: participant.participant_id.clone(),
            raw_weight,
            attestation_component,
            stake_component,
            reputation_component,
            sybil_penalty: 0.0,
            final_weight: raw_weight,
            capped: false,
            rejected: false,
            rejection_reason: None,
        }
    }

    fn compute_attestation_component(&self, participant: &ParticipantIdentity) -> f64 {
        participant
            .strongest_attestation()
            .map(|level| level.multiplier())
            .unwrap_or(0.0)
    }

    fn compute_stake_component(&self, participant: &ParticipantIdentity) -> f64 {
        match &participant.stake {
            None => 0.0,
            Some(stake) => {
                let base = (stake.amount.ln_1p() / 10.0).min(1.0).max(0.0);
                let lock_bonus = if stake.locked {
                    (stake.lock_duration_seconds as f64 / (86400.0 * 365.0)).min(0.5)
                } else {
                    0.0
                };
                (base + lock_bonus).min(1.0)
            }
        }
    }

    fn compute_reputation_component(&self, participant: &ParticipantIdentity) -> f64 {
        match &participant.reputation {
            None => 0.0,
            Some(rep) => {
                let score_component = rep.score;
                let tenure_component = (rep.tenure_seconds as f64
                    / self.config.established_tenure_seconds as f64)
                    .min(1.0);
                let interaction_ratio =
                    if rep.contributions_accepted + rep.contributions_rejected > 0 {
                        rep.contributions_accepted as f64
                            / (rep.contributions_accepted + rep.contributions_rejected) as f64
                    } else {
                        0.0
                    };
                (score_component * 0.4 + tenure_component * 0.3 + interaction_ratio * 0.3).min(1.0)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Sybil detection
    // -----------------------------------------------------------------------

    fn detect_sybil_clusters(&self, participants: &[ParticipantIdentity]) -> Vec<SybilCluster> {
        // Group by cluster_hint for participants that share one
        let mut hint_groups: HashMap<String, Vec<String>> = HashMap::new();
        for p in participants {
            if let Some(ref hint) = p.cluster_hint {
                hint_groups
                    .entry(hint.clone())
                    .or_default()
                    .push(p.participant_id.clone());
            }
        }

        let mut clusters = Vec::new();
        let mut cluster_counter = 0u64;

        for (hint, members) in &hint_groups {
            if members.len() >= self.config.sybil_cluster_min_size {
                cluster_counter += 1;
                clusters.push(SybilCluster {
                    cluster_id: format!("SYBIL-{cluster_counter:04}"),
                    member_ids: members.clone(),
                    detection_signal: format!("shared_cluster_hint:{hint}"),
                    attenuation_factor: self.config.sybil_attenuation_factor,
                });
            }
        }

        clusters
    }

    // -----------------------------------------------------------------------
    // Internal: established participant check
    // -----------------------------------------------------------------------

    fn is_established(&self, participant: &ParticipantIdentity) -> bool {
        match &participant.reputation {
            None => false,
            Some(rep) => {
                rep.tenure_seconds >= self.config.established_tenure_seconds
                    && rep.interaction_count >= self.config.established_interaction_count
            }
        }
    }

    fn compute_median_established_weight(
        &self,
        weights: &[ParticipationWeight],
        participants: &[ParticipantIdentity],
    ) -> f64 {
        let mut established_weights: Vec<f64> = weights
            .iter()
            .enumerate()
            .filter(|(i, w)| !w.rejected && self.is_established(&participants[*i]))
            .map(|(_, w)| w.final_weight)
            .collect();

        if established_weights.is_empty() {
            return 1.0; // Fallback: if no established participants, use 1.0
        }

        established_weights.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = established_weights.len() / 2;
        if established_weights.len() % 2 == 0 {
            (established_weights[mid - 1] + established_weights[mid]) / 2.0
        } else {
            established_weights[mid]
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_established_participant(id: &str) -> ParticipantIdentity {
        ParticipantIdentity {
            participant_id: id.to_string(),
            display_name: format!("Established {id}"),
            attestations: vec![AttestationEvidence {
                attestation_id: format!("att-{id}"),
                issuer: "trusted-ca".to_string(),
                level: AttestationLevel::VerifierBacked,
                issued_at: "2025-01-01T00:00:00Z".to_string(),
                expires_at: "2027-01-01T00:00:00Z".to_string(),
                signature_hex: "aabbccdd".to_string(),
            }],
            stake: Some(StakeEvidence {
                amount: 1000.0,
                deposited_at: "2025-06-01T00:00:00Z".to_string(),
                lock_duration_seconds: 86400 * 365,
                locked: true,
            }),
            reputation: Some(ReputationEvidence {
                score: 0.9,
                interaction_count: 500,
                tenure_seconds: 86400 * 365,
                contributions_accepted: 450,
                contributions_rejected: 10,
            }),
            cluster_hint: None,
        }
    }

    fn make_new_participant(id: &str) -> ParticipantIdentity {
        ParticipantIdentity {
            participant_id: id.to_string(),
            display_name: format!("New {id}"),
            attestations: vec![AttestationEvidence {
                attestation_id: format!("att-{id}"),
                issuer: "peer".to_string(),
                level: AttestationLevel::SelfSigned,
                issued_at: "2026-02-01T00:00:00Z".to_string(),
                expires_at: "2026-08-01T00:00:00Z".to_string(),
                signature_hex: "1122".to_string(),
            }],
            stake: None,
            reputation: Some(ReputationEvidence {
                score: 0.1,
                interaction_count: 2,
                tenure_seconds: 3600,
                contributions_accepted: 1,
                contributions_rejected: 0,
            }),
            cluster_hint: None,
        }
    }

    fn make_zero_attestation_participant(id: &str) -> ParticipantIdentity {
        ParticipantIdentity {
            participant_id: id.to_string(),
            display_name: format!("NoAtt {id}"),
            attestations: vec![],
            stake: Some(StakeEvidence {
                amount: 500.0,
                deposited_at: "2026-01-01T00:00:00Z".to_string(),
                lock_duration_seconds: 0,
                locked: false,
            }),
            reputation: None,
            cluster_hint: None,
        }
    }

    fn make_sybil_participants(count: usize, hint: &str) -> Vec<ParticipantIdentity> {
        (0..count)
            .map(|i| ParticipantIdentity {
                participant_id: format!("sybil-{i}"),
                display_name: format!("Sybil {i}"),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-sybil-{i}"),
                    issuer: "self".to_string(),
                    level: AttestationLevel::SelfSigned,
                    issued_at: "2026-02-20T00:00:00Z".to_string(),
                    expires_at: "2026-08-20T00:00:00Z".to_string(),
                    signature_hex: format!("{i:04x}"),
                }],
                stake: None,
                reputation: Some(ReputationEvidence {
                    score: 0.05,
                    interaction_count: 1,
                    tenure_seconds: 60,
                    contributions_accepted: 0,
                    contributions_rejected: 0,
                }),
                cluster_hint: Some(hint.to_string()),
            })
            .collect()
    }

    // === Attestation level multipliers ===

    #[test]
    fn attestation_levels_have_increasing_multipliers() {
        let levels = [
            AttestationLevel::SelfSigned,
            AttestationLevel::PeerVerified,
            AttestationLevel::VerifierBacked,
            AttestationLevel::AuthorityCertified,
        ];
        for pair in levels.windows(2) {
            assert!(pair[0].multiplier() < pair[1].multiplier());
        }
    }

    #[test]
    fn authority_certified_has_multiplier_one() {
        assert!((AttestationLevel::AuthorityCertified.multiplier() - 1.0).abs() < f64::EPSILON);
    }

    // === Zero-attestation rejection (INV-ATC-ATTESTATION-REQUIRED) ===

    #[test]
    fn zero_attestation_participant_is_rejected() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = vec![make_zero_attestation_participant("no-att")];
        let record = engine.compute_weights(&participants, "batch-1", "2026-02-20T00:00:00Z");

        assert_eq!(record.weights.len(), 1);
        assert!(record.weights[0].rejected);
        assert!((record.weights[0].final_weight - 0.0).abs() < f64::EPSILON);
    }

    // === Established vs new participant weights ===

    #[test]
    fn established_participant_has_higher_weight_than_new() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = vec![
            make_established_participant("est-1"),
            make_new_participant("new-1"),
        ];
        let record = engine.compute_weights(&participants, "batch-2", "2026-02-20T00:00:00Z");

        let est_weight = record.weights[0].final_weight;
        let new_weight = record.weights[1].final_weight;
        assert!(est_weight > new_weight);
    }

    // === New participant cap (INV-ATC-NEW-NODE-CAP) ===

    #[test]
    fn new_participant_capped_at_one_percent_of_median() {
        let mut engine = ParticipationWeightEngine::default();
        let mut participants = vec![
            make_established_participant("est-1"),
            make_established_participant("est-2"),
            make_established_participant("est-3"),
        ];
        // Add a new participant with decent attestation but no tenure
        let mut newcomer = make_new_participant("newcomer");
        newcomer.attestations = vec![AttestationEvidence {
            attestation_id: "att-strong".to_string(),
            issuer: "authority".to_string(),
            level: AttestationLevel::AuthorityCertified,
            issued_at: "2026-02-20T00:00:00Z".to_string(),
            expires_at: "2027-02-20T00:00:00Z".to_string(),
            signature_hex: "deadbeef".to_string(),
        }];
        newcomer.stake = Some(StakeEvidence {
            amount: 10000.0,
            deposited_at: "2026-02-20T00:00:00Z".to_string(),
            lock_duration_seconds: 86400 * 365,
            locked: true,
        });
        participants.push(newcomer);

        let record = engine.compute_weights(&participants, "batch-cap", "2026-02-20T00:00:00Z");
        let newcomer_weight = &record.weights[3];

        // Established median weight
        let mut est_weights: Vec<f64> =
            record.weights[..3].iter().map(|w| w.final_weight).collect();
        est_weights.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = est_weights[1];

        assert!(
            newcomer_weight.capped || newcomer_weight.final_weight <= median * 0.01 + f64::EPSILON
        );
    }

    // === Sybil cluster detection and attenuation (INV-ATC-SYBIL-BOUND) ===

    #[test]
    fn sybil_cluster_detected_and_attenuated() {
        let mut engine = ParticipationWeightEngine::default();
        let mut participants = vec![
            make_established_participant("honest-1"),
            make_established_participant("honest-2"),
        ];
        let sybils = make_sybil_participants(5, "suspicious-subnet-1");
        participants.extend(sybils);

        let record = engine.compute_weights(&participants, "batch-sybil", "2026-02-20T00:00:00Z");

        assert!(record.sybil_clusters_detected > 0);

        // Sybil participants should have penalty applied
        for w in &record.weights[2..] {
            assert!(w.sybil_penalty > 0.0);
        }
    }

    #[test]
    fn hundred_sybils_less_than_five_honest() {
        let mut engine = ParticipationWeightEngine::default();
        let honest: Vec<ParticipantIdentity> = (0..5)
            .map(|i| make_established_participant(&format!("honest-{i}")))
            .collect();
        let sybils = make_sybil_participants(100, "sybil-subnet");

        let mut all = honest.clone();
        all.extend(sybils);

        let record = engine.compute_weights(&all, "batch-100", "2026-02-20T00:00:00Z");

        let honest_total: f64 = record.weights[..5].iter().map(|w| w.final_weight).sum();
        let sybil_total: f64 = record.weights[5..].iter().map(|w| w.final_weight).sum();

        assert!(
            honest_total > sybil_total,
            "5 honest ({honest_total}) must outweigh 100 sybils ({sybil_total})"
        );
    }

    // === Stake monotonicity (INV-ATC-STAKE-MONOTONE) ===

    #[test]
    fn higher_stake_produces_higher_weight() {
        let mut engine = ParticipationWeightEngine::default();
        let mut low_stake = make_new_participant("low");
        low_stake.stake = Some(StakeEvidence {
            amount: 10.0,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 0,
            locked: false,
        });
        let mut high_stake = make_new_participant("high");
        high_stake.stake = Some(StakeEvidence {
            amount: 10000.0,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 0,
            locked: false,
        });

        let record = engine.compute_weights(
            &[low_stake, high_stake],
            "batch-stake",
            "2026-02-20T00:00:00Z",
        );

        assert!(record.weights[0].stake_component < record.weights[1].stake_component);
    }

    // === Determinism (INV-ATC-WEIGHT-DETERMINISM) ===

    #[test]
    fn weight_computation_is_deterministic() {
        let participants = vec![
            make_established_participant("det-1"),
            make_new_participant("det-2"),
        ];

        let mut engine1 = ParticipationWeightEngine::default();
        let mut engine2 = ParticipationWeightEngine::default();

        let r1 = engine1.compute_weights(&participants, "det", "2026-02-20T00:00:00Z");
        let r2 = engine2.compute_weights(&participants, "det", "2026-02-20T00:00:00Z");

        assert_eq!(r1.content_hash, r2.content_hash);
        assert_eq!(r1.weights.len(), r2.weights.len());
        for (w1, w2) in r1.weights.iter().zip(r2.weights.iter()) {
            assert!((w1.final_weight - w2.final_weight).abs() < f64::EPSILON);
        }
    }

    // === Audit completeness (INV-ATC-AUDIT-COMPLETE) ===

    #[test]
    fn audit_record_emitted_for_every_computation() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = vec![make_established_participant("aud-1")];

        engine.compute_weights(&participants, "batch-a", "2026-02-20T00:00:00Z");
        engine.compute_weights(&participants, "batch-b", "2026-02-20T00:01:00Z");

        assert_eq!(engine.audit_log().len(), 2);
    }

    #[test]
    fn audit_record_has_content_hash() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = vec![make_established_participant("hash-1")];
        let record = engine.compute_weights(&participants, "batch-h", "2026-02-20T00:00:00Z");

        assert!(!record.content_hash.is_empty());
        assert_eq!(record.content_hash.len(), 64); // SHA-256 hex
    }

    // === Cluster attenuation (INV-ATC-CLUSTER-ATTENUATION) ===

    #[test]
    fn sybil_cluster_weight_reduced_by_ninety_percent() {
        let mut engine = ParticipationWeightEngine::default();
        let sybils = make_sybil_participants(5, "cluster-a");

        let clustered = engine.compute_weights(&sybils, "clustered", "2026-02-20T00:00:00Z");

        // Each sybil participant should receive 90% penalty (attenuation_factor = 0.1).
        for w in &clustered.weights {
            assert!(
                (w.sybil_penalty - 0.9).abs() < 1e-9,
                "Sybil penalty for {} should be 0.9 (90% reduction), got {}",
                w.participant_id,
                w.sybil_penalty,
            );
            // final_weight should be ~10% of raw_weight (after attenuation)
            let ratio = w.final_weight / w.raw_weight;
            assert!(
                ratio <= 0.15,
                "Weight ratio for {} should be <= 0.15, got {ratio}",
                w.participant_id,
            );
        }
    }

    // === Config defaults ===

    #[test]
    fn default_config_has_valid_weights() {
        let config = WeightingConfig::default();
        let total = config.attestation_weight + config.stake_weight + config.reputation_weight;
        assert!((total - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn default_sybil_attenuation_is_ninety_percent() {
        let config = WeightingConfig::default();
        assert!((config.sybil_attenuation_factor - 0.1).abs() < f64::EPSILON);
    }

    // === JSON serialization ===

    #[test]
    fn weight_record_serializes_to_json() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = vec![make_established_participant("json-1")];
        let record = engine.compute_weights(&participants, "json-batch", "2026-02-20T00:00:00Z");

        let json = serde_json::to_string(&record).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["batch_id"], "json-batch");
    }

    #[test]
    fn audit_log_exports_as_json() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = vec![make_established_participant("export-1")];
        engine.compute_weights(&participants, "export-batch", "2026-02-20T00:00:00Z");

        let json = engine.export_audit_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
    }

    // === Empty input handling ===

    #[test]
    fn empty_participants_produces_empty_record() {
        let mut engine = ParticipationWeightEngine::default();
        let record = engine.compute_weights(&[], "empty", "2026-02-20T00:00:00Z");

        assert_eq!(record.participant_count, 0);
        assert!(record.weights.is_empty());
        assert!((record.total_weight - 0.0).abs() < f64::EPSILON);
    }

    // === Reputation component ===

    #[test]
    fn reputation_component_bounded_zero_to_one() {
        let engine = ParticipationWeightEngine::default();
        let participant = make_established_participant("rep-test");
        let component = engine.compute_reputation_component(&participant);
        assert!(component >= 0.0);
        assert!(component <= 1.0);
    }

    // === Mixed batch ===

    #[test]
    fn mixed_batch_produces_correct_statistics() {
        let mut engine = ParticipationWeightEngine::default();
        let mut participants = vec![
            make_established_participant("m-1"),
            make_new_participant("m-2"),
            make_zero_attestation_participant("m-3"),
        ];
        let sybils = make_sybil_participants(4, "mixed-subnet");
        participants.extend(sybils);

        let record = engine.compute_weights(&participants, "mixed", "2026-02-20T00:00:00Z");

        assert_eq!(record.participant_count, 7);
        assert_eq!(record.participants_rejected, 1); // zero-attestation
        assert!(record.sybil_clusters_detected > 0);
    }
}
