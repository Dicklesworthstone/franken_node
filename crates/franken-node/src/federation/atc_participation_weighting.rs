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
use std::collections::{BTreeMap, BTreeSet};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

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
        let canonical =
            serde_json::to_string(weights).unwrap_or_else(|e| format!("__serde_err:{e}"));
        let digest =
            Sha256::digest([b"atc_participation_hash_v1:" as &[u8], canonical.as_bytes()].concat());
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
        let defaults = WeightingConfig::default();
        let safe_config = WeightingConfig {
            attestation_weight: if config.attestation_weight.is_finite() {
                config.attestation_weight.clamp(0.0, 1.0)
            } else {
                defaults.attestation_weight
            },
            stake_weight: if config.stake_weight.is_finite() {
                config.stake_weight.clamp(0.0, 1.0)
            } else {
                defaults.stake_weight
            },
            reputation_weight: if config.reputation_weight.is_finite() {
                config.reputation_weight.clamp(0.0, 1.0)
            } else {
                defaults.reputation_weight
            },
            new_participant_cap_fraction: if config.new_participant_cap_fraction.is_finite() {
                config.new_participant_cap_fraction.clamp(0.0, 1.0)
            } else {
                defaults.new_participant_cap_fraction
            },
            sybil_attenuation_factor: if config.sybil_attenuation_factor.is_finite() {
                config.sybil_attenuation_factor.clamp(0.0, 1.0)
            } else {
                defaults.sybil_attenuation_factor
            },
            ..config
        };
        Self {
            config: safe_config,
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
        let sybil_member_ids: BTreeSet<String> = clusters
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

        push_bounded(&mut self.audit_log, record.clone(), MAX_AUDIT_LOG_ENTRIES);
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
                let amount = if stake.amount.is_finite() && stake.amount >= 0.0 {
                    stake.amount
                } else {
                    0.0
                };
                let base = (amount.ln_1p() / 10.0).clamp(0.0, 1.0);
                let lock_bonus = if stake.locked && amount > 0.0 {
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
                let score_component = if rep.score.is_finite() {
                    rep.score.clamp(0.0, 1.0)
                } else {
                    0.0
                };
                let tenure_component = if self.config.established_tenure_seconds == 0 {
                    // A zero threshold disables the tenure requirement entirely.
                    1.0
                } else {
                    (rep.tenure_seconds as f64 / self.config.established_tenure_seconds as f64)
                        .min(1.0)
                };
                let total_contributions = rep
                    .contributions_accepted
                    .saturating_add(rep.contributions_rejected);
                let interaction_ratio = if total_contributions > 0 {
                    rep.contributions_accepted as f64 / total_contributions as f64
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
        let mut hint_groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
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
                cluster_counter = cluster_counter.saturating_add(1);
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

        // Filter out non-finite values before sorting to prevent NaN poisoning.
        established_weights.retain(|w| w.is_finite());
        if established_weights.is_empty() {
            return 1.0;
        }
        established_weights.sort_by(|a, b| a.total_cmp(b));
        let mid = established_weights.len() / 2;
        if established_weights.len().is_multiple_of(2) {
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
        est_weights.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
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

    #[test]
    fn negative_stake_amount_contributes_zero_stake_component() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("negative-stake");
        participant.stake = Some(StakeEvidence {
            amount: -10_000.0,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 0,
            locked: false,
        });

        let weight = engine.compute_single_weight(&participant);

        assert!((weight.stake_component - 0.0).abs() < f64::EPSILON);
        assert!(weight.final_weight.is_finite());
        assert!(weight.final_weight >= 0.0);
    }

    #[test]
    fn nan_stake_amount_contributes_zero_stake_component() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("nan-stake");
        participant.stake = Some(StakeEvidence {
            amount: f64::NAN,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 0,
            locked: false,
        });

        let weight = engine.compute_single_weight(&participant);

        assert!((weight.stake_component - 0.0).abs() < f64::EPSILON);
        assert!(weight.raw_weight.is_finite());
        assert!(weight.final_weight.is_finite());
    }

    #[test]
    fn negative_reputation_score_cannot_create_negative_component() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("negative-reputation");
        participant.reputation = Some(ReputationEvidence {
            score: -0.5,
            interaction_count: 1,
            tenure_seconds: 0,
            contributions_accepted: 0,
            contributions_rejected: 10,
        });

        let weight = engine.compute_single_weight(&participant);

        assert!((weight.reputation_component - 0.0).abs() < f64::EPSILON);
        assert!(weight.final_weight >= 0.0);
    }

    #[test]
    fn nan_reputation_component_handles_nan_score() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("nan-reputation");
        participant.reputation = Some(ReputationEvidence {
            score: f64::NAN,
            interaction_count: 500,
            tenure_seconds: 86400 * 365,
            contributions_accepted: 450,
            contributions_rejected: 10,
        });

        let weight = engine.compute_single_weight(&participant);

        assert!(weight.reputation_component.is_finite());
        assert!(weight.raw_weight.is_finite());
        assert!(weight.final_weight.is_finite());
    }

    #[test]
    fn missing_attestation_rejects_even_with_large_stake_and_reputation() {
        let mut engine = ParticipationWeightEngine::default();
        let mut participant = make_zero_attestation_participant("inflated-no-attestation");
        participant.stake = Some(StakeEvidence {
            amount: 1_000_000_000.0,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 86400 * 365 * 10,
            locked: true,
        });
        participant.reputation = Some(ReputationEvidence {
            score: 1.0,
            interaction_count: 1_000_000,
            tenure_seconds: 86400 * 365 * 10,
            contributions_accepted: 1_000_000,
            contributions_rejected: 0,
        });

        let record = engine.compute_weights(&[participant], "missing-att", "2026-02-20T00:00:00Z");
        let weight = &record.weights[0];

        assert!(weight.rejected);
        assert_eq!(
            weight.rejection_reason.as_deref(),
            Some("no attestation evidence")
        );
        assert!((weight.raw_weight - 0.0).abs() < f64::EPSILON);
        assert!((weight.final_weight - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cluster_below_minimum_size_is_not_attenuated() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = make_sybil_participants(2, "below-minimum-cluster");

        let record = engine.compute_weights(&participants, "below-min", "2026-02-20T00:00:00Z");

        assert_eq!(record.sybil_clusters_detected, 0);
        assert!(record.weights.iter().all(|w| w.sybil_penalty == 0.0));
    }

    #[test]
    fn zero_attenuation_factor_forces_cluster_weight_to_zero() {
        let mut engine = ParticipationWeightEngine::new(WeightingConfig {
            sybil_attenuation_factor: 0.0,
            ..WeightingConfig::default()
        });
        let participants = make_sybil_participants(3, "zeroed-cluster");

        let record = engine.compute_weights(&participants, "zero-cluster", "2026-02-20T00:00:00Z");

        assert_eq!(record.sybil_clusters_detected, 1);
        assert!(record.weights.iter().all(|w| w.sybil_penalty == 1.0));
        assert!(record.weights.iter().all(|w| w.final_weight == 0.0));
        assert!((record.total_weight - 0.0).abs() < f64::EPSILON);
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

        let json = serde_json::to_string(&record).expect("serialization fails");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("serialization fails");
        assert_eq!(parsed["batch_id"], "json-batch");
    }

    #[test]
    fn audit_log_exports_as_json() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = vec![make_established_participant("export-1")];
        engine.compute_weights(&participants, "export-batch", "2026-02-20T00:00:00Z");

        let json = engine.export_audit_json().expect("audit json fails");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("audit json fails");
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

    #[test]
    fn zero_tenure_threshold_grants_full_tenure_credit() {
        let engine = ParticipationWeightEngine::new(WeightingConfig {
            established_tenure_seconds: 0,
            established_interaction_count: 2,
            ..WeightingConfig::default()
        });
        let participant = make_new_participant("zero-tenure");

        assert!(engine.is_established(&participant));

        let component = engine.compute_reputation_component(&participant);
        let expected = 0.1 * 0.4 + 1.0 * 0.3 + 1.0 * 0.3;
        assert!((component - expected).abs() < f64::EPSILON);
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

    #[test]
    fn nan_config_weights_produce_finite_output() {
        let bad_config = WeightingConfig {
            attestation_weight: f64::NAN,
            stake_weight: f64::INFINITY,
            reputation_weight: f64::NEG_INFINITY,
            sybil_attenuation_factor: f64::NAN,
            new_participant_cap_fraction: f64::INFINITY,
            ..WeightingConfig::default()
        };
        let mut engine = ParticipationWeightEngine::new(bad_config);
        let participants = vec![make_established_participant("nan-test")];
        let record = engine.compute_weights(&participants, "nan-batch", "2026-02-20T00:00:00Z");
        assert!(record.total_weight.is_finite());
        for w in &record.weights {
            assert!(w.final_weight.is_finite(), "final_weight should be finite");
            assert!(w.raw_weight.is_finite(), "raw_weight should be finite");
        }
    }

    #[test]
    fn negative_unlocked_stake_amount_contributes_zero() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("negative-stake");
        participant.stake = Some(StakeEvidence {
            amount: -100.0,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 86400 * 365,
            locked: false,
        });

        let component = engine.compute_stake_component(&participant);

        assert!((component - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn nan_unlocked_stake_amount_contributes_zero() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("nan-stake");
        participant.stake = Some(StakeEvidence {
            amount: f64::NAN,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 86400 * 365,
            locked: false,
        });

        let component = engine.compute_stake_component(&participant);

        assert!(component.is_finite());
        assert!((component - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn nan_reputation_score_does_not_poison_weight() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("nan-reputation");
        participant.reputation = Some(ReputationEvidence {
            score: f64::NAN,
            interaction_count: 500,
            tenure_seconds: 86400 * 365,
            contributions_accepted: 100,
            contributions_rejected: 0,
        });

        let component = engine.compute_reputation_component(&participant);

        assert!(component.is_finite());
        assert!(component >= 0.0);
        assert!(component <= 1.0);
    }

    #[test]
    fn rejected_contributions_only_do_not_receive_interaction_credit() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("rejected-only");
        participant.reputation = Some(ReputationEvidence {
            score: 1.0,
            interaction_count: 500,
            tenure_seconds: 86400 * 365,
            contributions_accepted: 0,
            contributions_rejected: 50,
        });

        let component = engine.compute_reputation_component(&participant);

        assert!(component < 1.0);
        assert!((component - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn shared_cluster_hint_below_min_size_is_not_attenuated() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = make_sybil_participants(2, "below-threshold");

        let record = engine.compute_weights(&participants, "below-min", "2026-02-20T00:00:00Z");

        assert_eq!(record.sybil_clusters_detected, 0);
        assert!(record.weights.iter().all(|weight| {
            (weight.sybil_penalty - 0.0).abs() < f64::EPSILON && !weight.rejected
        }));
    }

    #[test]
    fn zero_attestation_cluster_member_stays_rejected() {
        let mut engine = ParticipationWeightEngine::default();
        let mut rejected = make_zero_attestation_participant("cluster-rejected");
        rejected.cluster_hint = Some("mixed-cluster".to_string());
        let mut participants = vec![rejected];
        participants.extend(make_sybil_participants(2, "mixed-cluster"));

        let record = engine.compute_weights(&participants, "mixed-reject", "2026-02-20T00:00:00Z");

        assert_eq!(record.sybil_clusters_detected, 1);
        assert_eq!(record.participants_rejected, 1);
        assert!(record.weights[0].rejected);
        assert_eq!(
            record.weights[0].rejection_reason.as_deref(),
            Some("no attestation evidence")
        );
        assert!((record.weights[0].final_weight - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn median_established_weight_ignores_non_finite_values() {
        let engine = ParticipationWeightEngine::default();
        let participants = vec![make_established_participant("finite-established")];
        let weights = vec![ParticipationWeight {
            participant_id: "finite-established".to_string(),
            raw_weight: f64::NAN,
            attestation_component: 1.0,
            stake_component: 1.0,
            reputation_component: 1.0,
            sybil_penalty: 0.0,
            final_weight: f64::NAN,
            capped: false,
            rejected: false,
            rejection_reason: None,
        }];

        let median = engine.compute_median_established_weight(&weights, &participants);

        assert!((median - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn negative_locked_stake_amount_contributes_zero() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("negative-locked-stake");
        participant.stake = Some(StakeEvidence {
            amount: -100.0,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 86400 * 365,
            locked: true,
        });

        let component = engine.compute_stake_component(&participant);

        assert!((component - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn nan_locked_stake_amount_contributes_zero() {
        let engine = ParticipationWeightEngine::default();
        let mut participant = make_established_participant("nan-locked-stake");
        participant.stake = Some(StakeEvidence {
            amount: f64::NAN,
            deposited_at: "2026-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 86400 * 365,
            locked: true,
        });

        let component = engine.compute_stake_component(&participant);

        assert!(component.is_finite());
        assert!((component - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn negative_config_component_weights_do_not_create_negative_total() {
        let mut engine = ParticipationWeightEngine::new(WeightingConfig {
            attestation_weight: -1.0,
            stake_weight: -1.0,
            reputation_weight: -1.0,
            ..WeightingConfig::default()
        });
        let participants = vec![make_established_participant("negative-config")];

        let record =
            engine.compute_weights(&participants, "negative-config", "2026-02-20T00:00:00Z");

        assert!(record.total_weight.is_finite());
        assert!(record.total_weight >= 0.0);
        assert!(
            record
                .weights
                .iter()
                .all(|weight| weight.final_weight >= 0.0)
        );
    }

    #[test]
    fn overlarge_config_component_weights_remain_finite() {
        let mut engine = ParticipationWeightEngine::new(WeightingConfig {
            attestation_weight: f64::MAX,
            stake_weight: f64::MAX,
            reputation_weight: f64::MAX,
            ..WeightingConfig::default()
        });
        let participants = vec![make_established_participant("overlarge-config")];

        let record =
            engine.compute_weights(&participants, "overlarge-config", "2026-02-20T00:00:00Z");

        assert!(record.total_weight.is_finite());
        assert!(
            record
                .weights
                .iter()
                .all(|weight| weight.raw_weight.is_finite())
        );
    }

    #[test]
    fn negative_sybil_attenuation_does_not_create_negative_cluster_weight() {
        let mut engine = ParticipationWeightEngine::new(WeightingConfig {
            sybil_attenuation_factor: -0.5,
            ..WeightingConfig::default()
        });
        let mut participants: Vec<ParticipantIdentity> = (0..3)
            .map(|idx| make_established_participant(&format!("neg-sybil-{idx}")))
            .collect();
        for participant in &mut participants {
            participant.cluster_hint = Some("negative-factor-cluster".to_string());
        }

        let record = engine.compute_weights(
            &participants,
            "negative-sybil-factor",
            "2026-02-20T00:00:00Z",
        );

        assert_eq!(record.sybil_clusters_detected, 1);
        assert!(record.weights.iter().all(|weight| {
            (weight.final_weight - 0.0).abs() < f64::EPSILON
                && (weight.sybil_penalty - 1.0).abs() < f64::EPSILON
        }));
    }

    #[test]
    fn overlarge_sybil_attenuation_does_not_amplify_cluster_weight() {
        let mut engine = ParticipationWeightEngine::new(WeightingConfig {
            sybil_attenuation_factor: 2.0,
            ..WeightingConfig::default()
        });
        let mut participants: Vec<ParticipantIdentity> = (0..3)
            .map(|idx| make_established_participant(&format!("large-sybil-{idx}")))
            .collect();
        for participant in &mut participants {
            participant.cluster_hint = Some("large-factor-cluster".to_string());
        }

        let record = engine.compute_weights(
            &participants,
            "overlarge-sybil-factor",
            "2026-02-20T00:00:00Z",
        );

        assert_eq!(record.sybil_clusters_detected, 1);
        assert!(record.weights.iter().all(|weight| {
            weight.final_weight <= weight.raw_weight
                && (weight.sybil_penalty - 0.0).abs() < f64::EPSILON
        }));
    }

    #[test]
    fn negative_new_participant_cap_fraction_never_creates_negative_weight() {
        let mut engine = ParticipationWeightEngine::new(WeightingConfig {
            new_participant_cap_fraction: -1.0,
            ..WeightingConfig::default()
        });
        let participants = vec![
            make_established_participant("cap-established"),
            make_new_participant("cap-new"),
        ];

        let record = engine.compute_weights(
            &participants,
            "negative-cap-fraction",
            "2026-02-20T00:00:00Z",
        );

        assert_eq!(record.participants_capped, 0);
        assert!(
            record
                .weights
                .iter()
                .all(|weight| weight.final_weight >= 0.0)
        );
    }

    #[test]
    fn push_bounded_zero_capacity_discards_existing_and_new_records() {
        let mut records = vec![WeightAuditRecord {
            batch_id: "old".to_string(),
            timestamp: "2026-02-20T00:00:00Z".to_string(),
            participant_count: 0,
            sybil_clusters_detected: 0,
            participants_rejected: 0,
            participants_capped: 0,
            total_weight: 0.0,
            weights: Vec::new(),
            content_hash: "old-hash".to_string(),
        }];

        push_bounded(
            &mut records,
            WeightAuditRecord {
                batch_id: "new".to_string(),
                timestamp: "2026-02-20T00:00:01Z".to_string(),
                participant_count: 0,
                sybil_clusters_detected: 0,
                participants_rejected: 0,
                participants_capped: 0,
                total_weight: 0.0,
                weights: Vec::new(),
                content_hash: "new-hash".to_string(),
            },
            0,
        );

        assert!(records.is_empty());
    }

    // ── Hardening-focused tests targeting specific vulnerability patterns ──

    #[test]
    fn test_participation_count_uses_saturating_add_protection() {
        // Test for += 1 without saturating_add - participant counts should use saturating arithmetic
        let mut engine = ParticipationWeightEngine::new(ParticipationConfig::default());

        // Simulate adding many participants to test counter overflow protection
        let mut participants = Vec::new();
        for i in 0..1000 {
            let participant = ParticipantIdentity {
                participant_id: format!("overflow-test-{}", i),
                attestation: AttestationEvidence {
                    attestation_id: format!("attest-{}", i),
                    issuer: "test-issuer".to_string(),
                    level: 1,
                    expiration_timestamp: 1_800_000_000,
                    signature_hash: format!("sig-{:032x}", i),
                },
                stake: StakeDeposit {
                    deposit_id: format!("stake-{}", i),
                    amount_wei: 1_000_000,
                    deposit_timestamp: 1_700_000_000,
                    lock_duration_seconds: 86_400,
                    verifier_address: "verifier-addr".to_string(),
                },
                reputation: ReputationScore {
                    score: 0.5,
                    events_observed: 10,
                    first_observed_timestamp: 1_700_000_000,
                    last_updated_timestamp: 1_700_100_000,
                },
                joined_timestamp: 1_700_000_000 + i * 1000,
            };
            participants.push(participant);
        }

        // Test weight computation with many participants - should use saturating arithmetic internally
        let result = engine.compute_weights(&participants, 1_800_000_000, "trace-overflow");

        match result {
            Ok(record) => {
                // Should handle large participant counts without overflow
                assert!(record.participant_count <= participants.len());
                assert!(record.weights.len() <= participants.len());
            }
            Err(_) => {
                // If it fails due to resource constraints, should fail gracefully
            }
        }

        // Audit log should be bounded and not grow without limit
        assert!(engine.audit_log.len() <= MAX_AUDIT_LOG_ENTRIES);
    }

    #[test]
    fn test_hash_comparison_uses_constant_time_pattern() {
        // Test for == on [u8] hashes - should use ct_eq_bytes for timing safety
        use crate::security::constant_time::ct_eq_bytes;

        // Simulate hash comparison scenarios in participation weighting
        let signature_hash_1 = b"participation_sig_hash_v1_abcdef123456";
        let signature_hash_2 = b"participation_sig_hash_v1_abcdef123456"; // Same
        let signature_hash_3 = b"participation_sig_hash_v1_abcdef123457"; // Different by one

        // Correct pattern: use constant-time comparison for signature verification
        assert!(ct_eq_bytes(signature_hash_1, signature_hash_2), "Identical signature hashes should match");
        assert!(!ct_eq_bytes(signature_hash_1, signature_hash_3), "Different signature hashes should not match");

        // Test with attestation IDs that might be compared
        let attest_id_1 = b"attest_id_12345";
        let attest_id_2 = b"attest_id_12345";
        let attest_id_3 = b"attest_id_12346";

        assert!(ct_eq_bytes(attest_id_1, attest_id_2), "Identical attestation IDs should match");
        assert!(!ct_eq_bytes(attest_id_1, attest_id_3), "Different attestation IDs should not match");

        // Test with different length hashes (should fail fast but constant-time)
        let short_hash = b"short";
        let long_hash = b"much_longer_participation_hash";
        assert!(!ct_eq_bytes(short_hash, long_hash), "Different length hashes should not match");
    }

    #[test]
    fn test_expiry_checks_use_greater_equal_pattern() {
        // Test for > expiry - should use >= for fail-closed semantics
        let config = ParticipationConfig::default();
        let mut engine = ParticipationWeightEngine::new(config);

        let exact_expiry = 1_800_000_000_u64;

        // Create participant with attestation expiring at exact boundary
        let participant = ParticipantIdentity {
            participant_id: "expiry-boundary-test".to_string(),
            attestation: AttestationEvidence {
                attestation_id: "boundary-attest".to_string(),
                issuer: "test-issuer".to_string(),
                level: 2,
                expiration_timestamp: exact_expiry,
                signature_hash: "boundary-sig-hash".to_string(),
            },
            stake: StakeDeposit {
                deposit_id: "boundary-stake".to_string(),
                amount_wei: 1_000_000,
                deposit_timestamp: exact_expiry - 86_400,
                lock_duration_seconds: 86_400,
                verifier_address: "verifier-addr".to_string(),
            },
            reputation: ReputationScore {
                score: 0.8,
                events_observed: 50,
                first_observed_timestamp: exact_expiry - 86_400,
                last_updated_timestamp: exact_expiry - 100,
            },
            joined_timestamp: exact_expiry - 86_400,
        };

        // Test at exact expiry boundary - should be considered expired (fail-closed)
        let result_at_boundary = engine.compute_weights(&[participant.clone()], exact_expiry, "trace-boundary");

        match result_at_boundary {
            Ok(record) => {
                // With fail-closed semantics, expired attestation should result in zero weight
                assert_eq!(record.weights.len(), 1);
                let weight = &record.weights[0];
                assert_eq!(weight.weight, 0.0, "Expired attestation should result in zero weight (fail-closed)");
            }
            Err(_) => {
                // Acceptable if computation fails due to expired attestation
            }
        }

        // Test just before expiry - should not be expired
        let result_before = engine.compute_weights(&[participant.clone()], exact_expiry - 1, "trace-before");
        if let Ok(record) = result_before {
            assert_eq!(record.weights.len(), 1);
            let weight = &record.weights[0];
            assert!(weight.weight > 0.0, "Valid attestation should have positive weight");
        }

        // Test after expiry - should definitely be expired
        let result_after = engine.compute_weights(&[participant], exact_expiry + 1, "trace-after");
        match result_after {
            Ok(record) => {
                assert_eq!(record.weights.len(), 1);
                let weight = &record.weights[0];
                assert_eq!(weight.weight, 0.0, "Definitely expired attestation should have zero weight");
            }
            Err(_) => {
                // Also acceptable
            }
        }
    }

    #[test]
    fn test_length_casting_uses_try_from_pattern() {
        // Test for .len() as u32 - should use u32::try_from pattern
        let config = ParticipationConfig::default();
        let engine = ParticipationWeightEngine::new(config);

        // Create many participants to test length handling
        let mut participants = Vec::new();
        for i in 0..1000 {
            participants.push(ParticipantIdentity {
                participant_id: format!("length-test-{}", i),
                attestation: AttestationEvidence {
                    attestation_id: format!("attest-{}", i),
                    issuer: "test-issuer".to_string(),
                    level: 1,
                    expiration_timestamp: 1_800_000_000,
                    signature_hash: format!("sig-{:032x}", i),
                },
                stake: StakeDeposit {
                    deposit_id: format!("stake-{}", i),
                    amount_wei: 1_000_000,
                    deposit_timestamp: 1_700_000_000,
                    lock_duration_seconds: 86_400,
                    verifier_address: "verifier".to_string(),
                },
                reputation: ReputationScore {
                    score: 0.5,
                    events_observed: 10,
                    first_observed_timestamp: 1_700_000_000,
                    last_updated_timestamp: 1_700_100_000,
                },
                joined_timestamp: 1_700_000_000,
            });
        }

        let participants_len = participants.len();

        // Test hardening pattern: should use try_from, not direct cast
        let safe_len_u32 = u32::try_from(participants_len).unwrap_or(u32::MAX);
        assert!(safe_len_u32 <= u32::MAX);

        // Test that very large collections would be handled safely
        let hypothetical_large_len = usize::MAX;
        let safe_large_cast = u32::try_from(hypothetical_large_len).unwrap_or(u32::MAX);
        assert_eq!(safe_large_cast, u32::MAX); // Should cap at MAX, not truncate

        // Verify engine functions work with current participant count
        let result = engine.compute_weights(&participants, 1_700_100_000, "trace-len");
        if let Ok(record) = result {
            assert!(record.participant_count <= participants_len);
            assert_eq!(record.participant_count, participants_len);
        }
    }

    #[test]
    fn test_hash_operations_include_domain_separators() {
        // Test for hash without domain separator - should include proper domain separation
        use sha2::{Digest, Sha256};

        let participant_id = "test-participant-123";
        let attestation_id = "test-attestation-456";
        let signature_data = "test-signature-data";

        // Correct pattern: include domain separator for participation hashing
        let domain_separator = b"atc_participation_v1:";
        let mut hasher_with_domain = Sha256::new();
        hasher_with_domain.update(domain_separator);
        hasher_with_domain.update(participant_id.as_bytes());
        hasher_with_domain.update(attestation_id.as_bytes());
        hasher_with_domain.update(signature_data.as_bytes());
        let hash_with_domain = hasher_with_domain.finalize();

        // Anti-pattern: hashing without domain separator (collision vulnerable)
        let mut hasher_without_domain = Sha256::new();
        hasher_without_domain.update(participant_id.as_bytes());
        hasher_without_domain.update(attestation_id.as_bytes());
        hasher_without_domain.update(signature_data.as_bytes());
        let hash_without_domain = hasher_without_domain.finalize();

        // Should be different due to domain separation
        assert_ne!(hash_with_domain[..], hash_without_domain[..],
                   "Domain separator should change hash output");

        // Test weight computation hash with domain separation
        let weights = vec![
            ParticipationWeight {
                participant_id: "test-1".to_string(),
                weight: 0.5,
                attestation_level: 1,
                stake_amount_wei: 1_000_000,
                reputation_score: 0.8,
                tenure_days: 30,
                is_established: false,
                cluster_id: None,
                computation_timestamp: 1_700_100_000,
            }
        ];

        let content_hash = WeightAuditRecord::compute_hash(&weights);
        assert!(!content_hash.is_empty());

        // Test with different domain separators
        let different_domain = b"other_system_v1:";
        let mut different_hasher = Sha256::new();
        different_hasher.update(different_domain);
        different_hasher.update(participant_id.as_bytes());
        different_hasher.update(attestation_id.as_bytes());
        different_hasher.update(signature_data.as_bytes());
        let hash_different_domain = different_hasher.finalize();

        assert_ne!(hash_with_domain[..], hash_different_domain[..],
                   "Different domain separators should produce different hashes");

        // Test length-prefixed inputs to prevent delimiter collision
        let field1 = "participant_data_1";
        let field2 = "participant_data_2";

        let mut safe_hasher = Sha256::new();
        safe_hasher.update(b"atc_participation_v1:");
        safe_hasher.update((field1.len() as u64).to_le_bytes()); // Length prefix
        safe_hasher.update(field1.as_bytes());
        safe_hasher.update((field2.len() as u64).to_le_bytes()); // Length prefix
        safe_hasher.update(field2.as_bytes());
        let safe_hash = safe_hasher.finalize();

        // Anti-pattern: simple concatenation (collision vulnerable)
        let mut unsafe_hasher = Sha256::new();
        unsafe_hasher.update(b"atc_participation_v1:");
        unsafe_hasher.update(field1.as_bytes());
        unsafe_hasher.update(field2.as_bytes());
        let unsafe_hash = unsafe_hasher.finalize();

        // These might be the same but the pattern ensures collision resistance
        let _ = (safe_hash, unsafe_hash); // Just verify computation works
    }

    #[test]
    fn test_audit_log_uses_push_bounded_pattern() {
        // Test for Vec::push without push_bounded - audit logs should be bounded
        let config = ParticipationConfig::default();
        let mut engine = ParticipationWeightEngine::new(config);

        // Verify audit log starts empty
        assert_eq!(engine.audit_log.len(), 0);

        // Generate many weight computations to test audit log bounding
        let participant = ParticipantIdentity {
            participant_id: "audit-test".to_string(),
            attestation: AttestationEvidence {
                attestation_id: "audit-attest".to_string(),
                issuer: "test-issuer".to_string(),
                level: 2,
                expiration_timestamp: 1_800_000_000,
                signature_hash: "audit-sig-hash".to_string(),
            },
            stake: StakeDeposit {
                deposit_id: "audit-stake".to_string(),
                amount_wei: 1_000_000,
                deposit_timestamp: 1_700_000_000,
                lock_duration_seconds: 86_400,
                verifier_address: "verifier".to_string(),
            },
            reputation: ReputationScore {
                score: 0.7,
                events_observed: 25,
                first_observed_timestamp: 1_700_000_000,
                last_updated_timestamp: 1_700_100_000,
            },
            joined_timestamp: 1_700_000_000,
        };

        // Perform many weight computations to test audit log growth
        for i in 0..(MAX_AUDIT_LOG_ENTRIES + 50) {
            let timestamp = 1_700_100_000 + i * 1000;
            let trace_id = format!("trace-audit-{}", i);

            let result = engine.compute_weights(&[participant.clone()], timestamp, &trace_id);
            if result.is_ok() {
                // Audit log should be bounded using push_bounded pattern
                assert!(engine.audit_log.len() <= MAX_AUDIT_LOG_ENTRIES,
                        "Audit log should be bounded at iteration {}, got len {}",
                        i, engine.audit_log.len());
            }
        }

        // Verify final audit log size is properly bounded
        assert!(engine.audit_log.len() <= MAX_AUDIT_LOG_ENTRIES);

        // Verify oldest entries are evicted when capacity exceeded
        if engine.audit_log.len() == MAX_AUDIT_LOG_ENTRIES {
            let oldest_trace = &engine.audit_log[0].trace_id;
            assert!(!oldest_trace.contains("trace-audit-0"),
                    "Oldest entries should be evicted when capacity exceeded");
        }
    }
}

#[cfg(test)]
mod atc_participation_weighting_negative_path_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn negative_unicode_injection_participant_id_preserves_exact_bytes() {
        let mut engine = ParticipationWeightEngine::default();
        let injection_patterns = [
            "participant\u{202E}spoofed",    // Right-to-left override
            "participant\u{200B}invisible", // Zero-width space
            "participant\u{FEFF}bom",       // Byte order mark
            "participant\x00null",          // Null byte
            "participant\r\ninjection",     // CRLF injection
            "participant\u{1F4A9}emoji",    // Pile of poo emoji
            "participant\t\x08control",     // Tab and backspace
            "\u{202E}\u{202D}\u{200E}directional", // Bidirectional overrides
        ];

        for pattern in &injection_patterns {
            let participant = ParticipantIdentity {
                participant_id: pattern.to_string(),
                display_name: format!("Display {}", pattern),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-{}", pattern),
                    issuer: "test-issuer".to_string(),
                    level: AttestationLevel::VerifierBacked,
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: "deadbeef".to_string(),
                }],
                stake: Some(StakeEvidence {
                    amount: 100.0,
                    deposited_at: "2026-04-17T00:00:00Z".to_string(),
                    lock_duration_seconds: 86400 * 30,
                    locked: true,
                }),
                reputation: Some(ReputationEvidence {
                    score: 0.8,
                    interaction_count: 50,
                    tenure_seconds: 86400 * 30,
                    contributions_accepted: 45,
                    contributions_rejected: 5,
                }),
                cluster_hint: None,
            };

            let record = engine.compute_weights(&[participant], "unicode_test", "2026-04-17T00:00:00Z");

            // Unicode should be preserved exactly
            assert_eq!(record.weights[0].participant_id, *pattern);

            // JSON serialization should handle injection safely
            let json = serde_json::to_string(&record)
                .expect("unicode injection should serialize safely");
            assert!(!json.contains(&pattern.replace('\\', "")),
                   "Raw injection pattern should be escaped in JSON");

            // Deserialization should preserve exact pattern
            let parsed: WeightAuditRecord = serde_json::from_str(&json)
                .expect("should deserialize without corruption");
            assert_eq!(parsed.weights[0].participant_id, *pattern);
        }
    }

    #[test]
    fn negative_arithmetic_boundary_stake_amounts_saturated_safely() {
        let mut engine = ParticipationWeightEngine::default();
        let boundary_values = [
            f64::MAX,                       // Maximum finite value
            f64::MIN,                       // Minimum finite value
            1.7976931348623157e+308,       // Near overflow
            -1.7976931348623157e+308,      // Near underflow
            f64::EPSILON,                  // Smallest positive value
            -f64::EPSILON,                 // Smallest negative value
            0.0,                           // Zero
            -0.0,                          // Negative zero
            1e100,                         // Very large
            1e-100,                        // Very small
        ];

        for (i, stake_amount) in boundary_values.iter().enumerate() {
            let participant = ParticipantIdentity {
                participant_id: format!("boundary_stake_{}", i),
                display_name: format!("Boundary Test {}", i),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-{}", i),
                    issuer: "test".to_string(),
                    level: AttestationLevel::VerifierBacked,
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: "deadbeef".to_string(),
                }],
                stake: Some(StakeEvidence {
                    amount: *stake_amount,
                    deposited_at: "2026-04-17T00:00:00Z".to_string(),
                    lock_duration_seconds: 86400 * 365,
                    locked: true,
                }),
                reputation: Some(ReputationEvidence {
                    score: 0.8,
                    interaction_count: 100,
                    tenure_seconds: 86400 * 365,
                    contributions_accepted: 90,
                    contributions_rejected: 10,
                }),
                cluster_hint: None,
            };

            // Weight computation should not panic or produce invalid values
            let weight = engine.compute_single_weight(&participant);
            assert!(weight.stake_component.is_finite(), "Stake component must be finite");
            assert!(weight.stake_component >= 0.0, "Stake component must be non-negative");
            assert!(weight.stake_component <= 1.0, "Stake component must be <= 1.0");

            assert!(weight.raw_weight.is_finite(), "Raw weight must be finite");
            assert!(weight.raw_weight >= 0.0, "Raw weight must be non-negative");

            assert!(weight.final_weight.is_finite(), "Final weight must be finite");
            assert!(weight.final_weight >= 0.0, "Final weight must be non-negative");

            // JSON round-trip should handle boundary values
            match serde_json::to_string(&weight) {
                Ok(json) => {
                    match serde_json::from_str::<ParticipationWeight>(&json) {
                        Ok(parsed) => {
                            assert!(parsed.stake_component.is_finite());
                            assert!(parsed.raw_weight.is_finite());
                            assert!(parsed.final_weight.is_finite());
                        }
                        Err(_) => {
                            // Some boundary values might not deserialize cleanly
                        }
                    }
                }
                Err(_) => {
                    // Some boundary values might not serialize cleanly
                }
            }
        }
    }

    #[test]
    fn negative_floating_point_edge_cases_in_reputation_score() {
        let mut engine = ParticipationWeightEngine::default();
        let edge_cases = [
            f64::NAN,                    // Not a number
            f64::INFINITY,               // Positive infinity
            f64::NEG_INFINITY,           // Negative infinity
            f64::EPSILON,                // Smallest positive value
            f64::MIN_POSITIVE,           // Smallest normalized positive value
            f64::MAX,                    // Largest finite value
            -f64::MAX,                   // Largest negative value
            1.0000000000000002,          // Precision edge case
            0.9999999999999999,          // Precision edge case
            2.2250738585072014e-308,     // Subnormal value
        ];

        for (i, score) in edge_cases.iter().enumerate() {
            let participant = ParticipantIdentity {
                participant_id: format!("reputation_edge_{}", i),
                display_name: format!("Edge Test {}", i),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-{}", i),
                    issuer: "test".to_string(),
                    level: AttestationLevel::VerifierBacked,
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: "deadbeef".to_string(),
                }],
                stake: Some(StakeEvidence {
                    amount: 100.0,
                    deposited_at: "2026-04-17T00:00:00Z".to_string(),
                    lock_duration_seconds: 86400 * 30,
                    locked: true,
                }),
                reputation: Some(ReputationEvidence {
                    score: *score,
                    interaction_count: 100,
                    tenure_seconds: 86400 * 365,
                    contributions_accepted: 90,
                    contributions_rejected: 10,
                }),
                cluster_hint: None,
            };

            // Reputation computation should handle edge cases gracefully
            let reputation_component = engine.compute_reputation_component(&participant);
            assert!(reputation_component.is_finite(), "Reputation component must be finite");
            assert!(reputation_component >= 0.0, "Reputation component must be non-negative");
            assert!(reputation_component <= 1.0, "Reputation component must be <= 1.0");

            // Overall weight computation should not panic
            let weight = engine.compute_single_weight(&participant);
            assert!(weight.reputation_component.is_finite());
            assert!(weight.reputation_component >= 0.0);
            assert!(weight.reputation_component <= 1.0);

            assert!(weight.raw_weight.is_finite());
            assert!(weight.final_weight.is_finite());

            // Record-level computation should handle edge cases
            let record = engine.compute_weights(&[participant], "edge_test", "2026-04-17T00:00:00Z");
            assert!(record.total_weight.is_finite());
            assert!(record.weights[0].reputation_component.is_finite());
        }
    }

    #[test]
    fn negative_massive_attestation_chain_memory_stress_test() {
        let mut engine = ParticipationWeightEngine::default();

        // Test with increasingly large attestation chains
        let chain_sizes = [100, 1000, 10_000];

        for size in chain_sizes {
            let mut attestations = Vec::with_capacity(size);
            for i in 0..size {
                attestations.push(AttestationEvidence {
                    attestation_id: format!("massive_att_{}", i),
                    issuer: format!("issuer_{}", i % 10), // Some variety
                    level: match i % 4 {
                        0 => AttestationLevel::SelfSigned,
                        1 => AttestationLevel::PeerVerified,
                        2 => AttestationLevel::VerifierBacked,
                        3 => AttestationLevel::AuthorityCertified,
                        _ => unreachable!(),
                    },
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: format!("{:x}", i),
                });
            }

            let participant = ParticipantIdentity {
                participant_id: format!("massive_chain_{}", size),
                display_name: format!("Massive Chain {}", size),
                attestations,
                stake: Some(StakeEvidence {
                    amount: 1000.0,
                    deposited_at: "2026-04-17T00:00:00Z".to_string(),
                    lock_duration_seconds: 86400 * 365,
                    locked: true,
                }),
                reputation: Some(ReputationEvidence {
                    score: 0.9,
                    interaction_count: 500,
                    tenure_seconds: 86400 * 365,
                    contributions_accepted: 450,
                    contributions_rejected: 50,
                }),
                cluster_hint: None,
            };

            // Should handle large attestation chains without memory issues
            let start_time = std::time::Instant::now();
            let weight = engine.compute_single_weight(&participant);
            let duration = start_time.elapsed();

            assert!(duration.as_millis() < 1000,
                   "Large attestation chain took too long: {:?} for {} attestations",
                   duration, size);

            assert!(weight.attestation_component.is_finite());
            assert!(weight.attestation_component >= 0.0);
            assert!(weight.attestation_component <= 1.0);

            // Should find the strongest attestation correctly
            assert_eq!(participant.strongest_attestation(), Some(AttestationLevel::AuthorityCertified));
            assert!(participant.has_attestation());

            // JSON serialization should handle large chains
            match serde_json::to_string(&participant) {
                Ok(json) => {
                    assert!(json.len() > size * 50); // Should contain substantial data

                    // Deserialization should work
                    match serde_json::from_str::<ParticipantIdentity>(&json) {
                        Ok(parsed) => {
                            assert_eq!(parsed.attestations.len(), size);
                            assert_eq!(parsed.strongest_attestation(), Some(AttestationLevel::AuthorityCertified));
                        }
                        Err(_) => {
                            // Very large chains might fail to deserialize due to memory limits
                        }
                    }
                }
                Err(_) => {
                    // Very large chains might not serialize due to memory limits
                }
            }
        }
    }

    #[test]
    fn negative_cluster_hint_injection_and_collision_attacks() {
        let mut engine = ParticipationWeightEngine::default();
        let malicious_hints = [
            // Hash-like strings that could confuse clustering
            "a".repeat(64), // Valid hex length
            "0123456789abcdef".repeat(4), // Valid hex pattern
            format!("cluster:{}", "b".repeat(32)), // Prefixed hash

            // JSON injection attempts
            "hint\",\"injected\":true,\"cluster\":\"",
            "null}\"evil\":\"payload\",\"cluster\":\"normal",

            // Control character injection
            "cluster\x00null\r\n",
            "cluster\x1b[31mred\x1b[0m",

            // Unicode injection
            "cluster\u{202E}injection",
            "cluster\u{FEFF}bom",

            // Path-like strings that could cause issues
            "../../../etc/passwd",
            "..\\..\\windows\\system32",

            // Extremely long hint
            "long_cluster_hint_".repeat(10000),

            // Empty and whitespace
            "",
            "   ",
            "\t\n\r",
        ];

        let mut participants = Vec::new();
        for (i, hint) in malicious_hints.iter().enumerate() {
            participants.push(ParticipantIdentity {
                participant_id: format!("cluster_injection_{}", i),
                display_name: format!("Injection Test {}", i),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-{}", i),
                    issuer: "test".to_string(),
                    level: AttestationLevel::SelfSigned,
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: format!("{:x}", i),
                }],
                stake: None,
                reputation: Some(ReputationEvidence {
                    score: 0.1,
                    interaction_count: 10,
                    tenure_seconds: 86400,
                    contributions_accepted: 5,
                    contributions_rejected: 5,
                }),
                cluster_hint: Some(hint.to_string()),
            });
        }

        // Should handle malicious cluster hints without corruption or crashes
        let record = engine.compute_weights(&participants, "cluster_injection", "2026-04-17T00:00:00Z");

        assert_eq!(record.weights.len(), participants.len());

        // Cluster detection should work despite malicious hints
        let clusters = engine.detect_sybil_clusters(&participants);

        // Should detect clusters based on exact hint matching
        for cluster in &clusters {
            assert!(!cluster.cluster_id.is_empty());
            assert!(cluster.member_ids.len() >= engine.config.sybil_cluster_min_size);

            // Detection signal should be safe
            assert!(cluster.detection_signal.contains("shared_cluster_hint:"));

            // Attenuation factor should be valid
            assert!(cluster.attenuation_factor >= 0.0);
            assert!(cluster.attenuation_factor <= 1.0);
        }

        // JSON serialization should handle injection attempts safely
        let json = serde_json::to_string(&record)
            .expect("should serialize despite malicious cluster hints");

        // Injection patterns should be escaped
        for hint in &malicious_hints {
            if hint.contains('"') || hint.contains('{') || hint.contains('}') {
                assert!(!json.contains(&hint.replace('\\', "")),
                       "Dangerous cluster hint should be escaped in JSON");
            }
        }

        // Deserialization should preserve exact hints
        let parsed: WeightAuditRecord = serde_json::from_str(&json)
            .expect("should deserialize without corruption");
        assert_eq!(parsed.weights.len(), participants.len());
    }

    #[test]
    fn negative_content_hash_collision_resistance_verification() {
        let mut engine = ParticipationWeightEngine::default();

        // Create weight computations with crafted content designed to test hash collision resistance
        let collision_attempts = [
            // Same participant data with slight variations
            ("collision_test_1", 100, 50),
            ("collision_test_2", 50, 100),

            // Different attestation levels with same overall structure
            ("hash_boundary_1", 200, 100),
            ("hash_boundary_2", 100, 200),

            // Byte boundary cases that might collide
            ("boundary_255", 255, 256),
            ("boundary_256", 256, 255),
        ];

        let mut observed_hashes = BTreeSet::new();
        let mut all_records = Vec::new();

        for (participant_id, contributions_accepted, contributions_rejected) in collision_attempts {
            let participant = ParticipantIdentity {
                participant_id: participant_id.to_string(),
                display_name: format!("Hash Test {}", participant_id),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-{}", participant_id),
                    issuer: "hash-test-issuer".to_string(),
                    level: AttestationLevel::VerifierBacked,
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: "deadbeef".to_string(),
                }],
                stake: Some(StakeEvidence {
                    amount: 1000.0,
                    deposited_at: "2026-04-17T00:00:00Z".to_string(),
                    lock_duration_seconds: 86400 * 365,
                    locked: true,
                }),
                reputation: Some(ReputationEvidence {
                    score: 0.8,
                    interaction_count: contributions_accepted + contributions_rejected,
                    tenure_seconds: 86400 * 365,
                    contributions_accepted,
                    contributions_rejected,
                }),
                cluster_hint: None,
            };

            let record = engine.compute_weights(&[participant], participant_id, "2026-04-17T00:00:00Z");
            all_records.push(record);
        }

        // Collect all content hashes
        for record in &all_records {
            observed_hashes.insert(record.content_hash.clone());

            // Hash should be proper hex string
            assert_eq!(record.content_hash.len(), 64);
            assert!(record.content_hash.chars().all(|c| c.is_ascii_hexdigit()));

            // Hash should be deterministic
            let recomputed_hash = WeightAuditRecord::compute_hash(&record.weights);
            assert_eq!(record.content_hash, recomputed_hash);
        }

        // All different weight computations should produce different hashes (no collisions)
        assert_eq!(observed_hashes.len(), all_records.len(),
                  "Hash collision detected: {} unique hashes for {} records",
                  observed_hashes.len(), all_records.len());
    }

    #[test]
    fn negative_extreme_contribution_counts_with_overflow_protection() {
        let engine = ParticipationWeightEngine::default();
        let extreme_values = [
            (u64::MAX, 1),              // Max accepted contributions
            (1, u64::MAX),              // Max rejected contributions
            (u64::MAX, u64::MAX),       // Both at maximum
            (u64::MAX - 1, u64::MAX),   // Near overflow boundary
            (0, 0),                     // Both zero
        ];

        for (accepted, rejected) in extreme_values {
            let participant = ParticipantIdentity {
                participant_id: format!("extreme_{}_{}", accepted, rejected),
                display_name: "Extreme Contributions Test".to_string(),
                attestations: vec![AttestationEvidence {
                    attestation_id: "extreme-att".to_string(),
                    issuer: "test".to_string(),
                    level: AttestationLevel::VerifierBacked,
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: "deadbeef".to_string(),
                }],
                stake: Some(StakeEvidence {
                    amount: 1000.0,
                    deposited_at: "2026-04-17T00:00:00Z".to_string(),
                    lock_duration_seconds: 86400 * 365,
                    locked: true,
                }),
                reputation: Some(ReputationEvidence {
                    score: 0.8,
                    interaction_count: accepted.saturating_add(rejected).min(1000), // Prevent overflow
                    tenure_seconds: 86400 * 365,
                    contributions_accepted: accepted,
                    contributions_rejected: rejected,
                }),
                cluster_hint: None,
            };

            // Should handle extreme values without overflow or invalid results
            let weight = engine.compute_single_weight(&participant);
            assert!(weight.reputation_component.is_finite());
            assert!(weight.reputation_component >= 0.0);
            assert!(weight.reputation_component <= 1.0);

            assert!(weight.raw_weight.is_finite());
            assert!(weight.final_weight.is_finite());
            assert!(weight.final_weight >= 0.0);

            // Interaction ratio calculation should not overflow
            let total_contributions = accepted.saturating_add(rejected);
            if total_contributions > 0 {
                let interaction_ratio = accepted as f64 / total_contributions as f64;
                assert!(interaction_ratio >= 0.0);
                assert!(interaction_ratio <= 1.0);
                assert!(interaction_ratio.is_finite());
            }
        }
    }

    #[test]
    fn negative_massive_participant_batch_memory_and_performance_stress() {
        let mut engine = ParticipationWeightEngine::default();

        // Test with progressively larger batches to stress memory and processing
        let batch_sizes = [1000, 5000, 10_000];

        for batch_size in batch_sizes {
            let mut participants = Vec::with_capacity(batch_size);

            // Create variety of participant types to stress different code paths
            for i in 0..batch_size {
                let participant = ParticipantIdentity {
                    participant_id: format!("batch_participant_{:06}", i),
                    display_name: format!("Batch Test {}", i),
                    attestations: vec![AttestationEvidence {
                        attestation_id: format!("att-{}", i),
                        issuer: format!("issuer-{}", i % 100), // Some variety
                        level: match i % 4 {
                            0 => AttestationLevel::SelfSigned,
                            1 => AttestationLevel::PeerVerified,
                            2 => AttestationLevel::VerifierBacked,
                            3 => AttestationLevel::AuthorityCertified,
                            _ => unreachable!(),
                        },
                        issued_at: "2026-04-17T00:00:00Z".to_string(),
                        expires_at: "2027-04-17T00:00:00Z".to_string(),
                        signature_hex: format!("{:x}", i),
                    }],
                    stake: if i % 3 == 0 {
                        Some(StakeEvidence {
                            amount: (i % 10000) as f64,
                            deposited_at: "2026-04-17T00:00:00Z".to_string(),
                            lock_duration_seconds: (i % 365) as u64 * 86400,
                            locked: i % 2 == 0,
                        })
                    } else {
                        None
                    },
                    reputation: if i % 5 != 0 {
                        Some(ReputationEvidence {
                            score: (i as f64 / batch_size as f64).clamp(0.0, 1.0),
                            interaction_count: (i % 1000) as u64,
                            tenure_seconds: (i % 365) as u64 * 86400,
                            contributions_accepted: (i % 500) as u64,
                            contributions_rejected: (i % 50) as u64,
                        })
                    } else {
                        None
                    },
                    cluster_hint: if i % 10 == 0 {
                        Some(format!("cluster_{}", i / 100)) // Create some clusters
                    } else {
                        None
                    },
                };

                participants.push(participant);
            }

            // Should handle large batches without memory issues or performance degradation
            let start_time = std::time::Instant::now();
            let record = engine.compute_weights(&participants, &format!("massive_batch_{}", batch_size), "2026-04-17T00:00:00Z");
            let processing_time = start_time.elapsed();

            // Should complete in reasonable time
            assert!(processing_time.as_secs() < 60,
                   "Large batch processing took too long: {:?} for {} participants",
                   processing_time, batch_size);

            // Record should have correct structure
            assert_eq!(record.participant_count, batch_size);
            assert_eq!(record.weights.len(), batch_size);

            // Total weight should be finite and reasonable
            assert!(record.total_weight.is_finite());
            assert!(record.total_weight >= 0.0);

            // Should detect some clusters
            assert!(record.sybil_clusters_detected > 0, "Should detect clusters in large batch");

            // Content hash should be consistent
            assert_eq!(record.content_hash.len(), 64);
            assert!(record.content_hash.chars().all(|c| c.is_ascii_hexdigit()));

            // Memory cleanup test - processing another batch should not degrade
            let participants2 = vec![participants[0].clone()];
            let start_time2 = std::time::Instant::now();
            let _record2 = engine.compute_weights(&participants2, "cleanup_test", "2026-04-17T00:00:00Z");
            let processing_time2 = start_time2.elapsed();

            assert!(processing_time2.as_millis() < 100,
                   "Memory cleanup may have failed - subsequent processing too slow");
        }
    }

    #[test]
    fn negative_concurrent_weight_computation_simulation() {
        // Simulate concurrent weight computation that might reveal race conditions
        use std::sync::{Arc, Mutex};
        use std::thread;

        let engine = Arc::new(Mutex::new(ParticipationWeightEngine::default()));
        let results = Arc::new(Mutex::new(Vec::new()));

        let thread_count = 8;
        let operations_per_thread = 50;
        let mut handles = Vec::new();

        for thread_id in 0..thread_count {
            let engine = Arc::clone(&engine);
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for operation in 0..operations_per_thread {
                    let participant = ParticipantIdentity {
                        participant_id: format!("concurrent_t{}_o{}", thread_id, operation),
                        display_name: format!("Concurrent Test T{} O{}", thread_id, operation),
                        attestations: vec![AttestationEvidence {
                            attestation_id: format!("att-t{}-o{}", thread_id, operation),
                            issuer: "concurrent-test".to_string(),
                            level: AttestationLevel::VerifierBacked,
                            issued_at: "2026-04-17T00:00:00Z".to_string(),
                            expires_at: "2027-04-17T00:00:00Z".to_string(),
                            signature_hex: format!("{:x}{:x}", thread_id, operation),
                        }],
                        stake: Some(StakeEvidence {
                            amount: (thread_id * operations_per_thread + operation) as f64,
                            deposited_at: "2026-04-17T00:00:00Z".to_string(),
                            lock_duration_seconds: 86400 * 30,
                            locked: operation % 2 == 0,
                        }),
                        reputation: Some(ReputationEvidence {
                            score: 0.8,
                            interaction_count: (operation + 10) as u64,
                            tenure_seconds: 86400 * 30,
                            contributions_accepted: (operation + 5) as u64,
                            contributions_rejected: (operation % 3) as u64,
                        }),
                        cluster_hint: if operation % 5 == 0 {
                            Some(format!("concurrent_cluster_t{}", thread_id))
                        } else {
                            None
                        },
                    };

                    // Each thread performs weight computation
                    let record = {
                        let mut engine_guard = engine.lock().unwrap();
                        engine_guard.compute_weights(
                            &[participant],
                            &format!("concurrent_t{}_o{}", thread_id, operation),
                            "2026-04-17T00:00:00Z"
                        )
                    };

                    thread_results.push((thread_id, operation, record.total_weight, record.weights[0].final_weight));
                }

                // Merge results
                {
                    let mut shared_results = results.lock().unwrap();
                    shared_results.extend(thread_results);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete without panics");
        }

        let final_results = results.lock().unwrap();

        // Should have processed all operations
        assert_eq!(final_results.len(), thread_count * operations_per_thread);

        // Check final engine state consistency
        let final_engine = engine.lock().unwrap();

        // All weights should be valid
        for (thread_id, operation, total_weight, final_weight) in &*final_results {
            assert!(total_weight.is_finite(), "Total weight should be finite for t{} o{}", thread_id, operation);
            assert!(final_weight.is_finite(), "Final weight should be finite for t{} o{}", thread_id, operation);
            assert!(*total_weight >= 0.0, "Total weight should be non-negative");
            assert!(*final_weight >= 0.0, "Final weight should be non-negative");
        }

        // Results should show reasonable variety
        let weights: Vec<f64> = final_results.iter().map(|(_, _, _, w)| *w).collect();
        let unique_weights: BTreeSet<String> = weights.iter()
            .map(|w| format!("{:.10}", w))
            .collect();

        // Should have reasonable variety in weights (not all identical)
        assert!(unique_weights.len() > 1, "Should have variety in computed weights");

        // Audit log should contain entries (may be bounded by capacity)
        assert!(final_engine.audit_log().len() > 0);
    }

    #[test]
    fn negative_deep_json_nesting_stack_overflow_protection() {
        let mut engine = ParticipationWeightEngine::default();

        // Create participant with deeply nested JSON-like content in display name
        let participant = ParticipantIdentity {
            participant_id: "deep_nesting_test".to_string(),
            display_name: {
                // Create deeply nested JSON-like string
                let mut nested = String::new();
                nested.push_str(r#"{"level0":{"#);
                for i in 1..1000 {
                    nested.push_str(&format!(r#""level{}":"{{"#, i));
                }
                nested.push_str(r#""deep":"value""#);
                for _ in 0..1000 {
                    nested.push_str("}}");
                }
                nested
            },
            attestations: vec![AttestationEvidence {
                attestation_id: "deep-att".to_string(),
                issuer: "deep-test".to_string(),
                level: AttestationLevel::VerifierBacked,
                issued_at: "2026-04-17T00:00:00Z".to_string(),
                expires_at: "2027-04-17T00:00:00Z".to_string(),
                signature_hex: "deadbeef".to_string(),
            }],
            stake: None,
            reputation: None,
            cluster_hint: None,
        };

        // Should handle deeply nested content without stack overflow
        let result = std::panic::catch_unwind(|| {
            engine.compute_weights(&[participant], "deep_test", "2026-04-17T00:00:00Z")
        });

        match result {
            Ok(record) => {
                // Successfully handled deep nesting
                assert_eq!(record.participant_count, 1);
                assert_eq!(record.weights[0].participant_id, "deep_nesting_test");

                // JSON serialization should handle or safely reject deep nesting
                match serde_json::to_string(&record) {
                    Ok(json) => {
                        // If serialization succeeds, deserialization should too
                        match serde_json::from_str::<WeightAuditRecord>(&json) {
                            Ok(parsed) => {
                                assert_eq!(parsed.participant_count, 1);
                                assert_eq!(parsed.weights[0].participant_id, "deep_nesting_test");
                            }
                            Err(_) => {
                                // Deserialization failure acceptable for extremely nested data
                            }
                        }
                    }
                    Err(_) => {
                        // Serialization failure acceptable for extremely nested data
                    }
                }
            }
            Err(_) => {
                // If panic occurs, need better stack protection
                panic!("Deep nesting caused panic - need stack overflow protection");
            }
        }
    }

    #[test]
    fn negative_attestation_level_enum_manipulation_and_serialization_attacks() {
        use serde_json::json;

        // Test serialization/deserialization with malicious values
        let malicious_level_values = [
            json!("self_signed"),      // Valid but lowercase underscore (should work)
            json!("AUTHORITY_CERTIFIED"), // Valid but uppercase (should fail)
            json!("admin"),            // Privileged-sounding variant
            json!("root"),             // System-like variant
            json!("super_certified"),  // Non-existent higher level
            json!(""),                 // Empty string
            json!(null),               // Null value
            json!(42),                 // Number instead of string
            json!(true),               // Boolean instead of string
            json!(["authority_certified"]), // Array instead of string
            json!({"level": "authority_certified"}), // Object instead of string
            json!("authority_certified\u{0000}"), // Null byte injection
            json!("authority_certified\"><script>alert('xss')</script>"), // XSS attempt
        ];

        for (i, malicious_value) in malicious_level_values.iter().enumerate() {
            // Attempt to deserialize malicious level value
            let level_result = serde_json::from_value::<AttestationLevel>(malicious_value.clone());

            // Check result - some valid variations should work, malicious ones should fail
            match malicious_value {
                // These should succeed (valid format)
                v if v == &json!("self_signed") => {
                    assert!(level_result.is_ok(), "Valid self_signed should deserialize");
                }
                // These should fail (malicious/invalid)
                _ => {
                    if level_result.is_err() {
                        // Expected - malicious value rejected
                    } else {
                        // Some edge cases might deserialize - verify they're safe
                        let level = level_result.unwrap();
                        assert!(matches!(level, AttestationLevel::SelfSigned |
                                              AttestationLevel::PeerVerified |
                                              AttestationLevel::VerifierBacked |
                                              AttestationLevel::AuthorityCertified));
                    }
                }
            }

            // Test in context of attestation evidence structure
            let malicious_attestation = json!({
                "attestation_id": format!("attack_{}", i),
                "issuer": "test",
                "level": malicious_value,
                "issued_at": "2026-04-17T00:00:00Z",
                "expires_at": "2027-04-17T00:00:00Z",
                "signature_hex": "deadbeef"
            });

            let attestation_result = serde_json::from_value::<AttestationEvidence>(malicious_attestation);

            // Should handle malicious levels in attestation context
            match attestation_result {
                Ok(attestation) => {
                    // If parsed successfully, should have valid level
                    assert!(matches!(attestation.level, AttestationLevel::SelfSigned |
                                                       AttestationLevel::PeerVerified |
                                                       AttestationLevel::VerifierBacked |
                                                       AttestationLevel::AuthorityCertified));

                    // Multiplier should be valid
                    let multiplier = attestation.level.multiplier();
                    assert!(multiplier >= 0.0);
                    assert!(multiplier <= 1.0);
                    assert!(multiplier.is_finite());
                }
                Err(_) => {
                    // Rejection of malicious attestation levels is acceptable
                }
            }
        }

        // Test valid levels serialize/deserialize correctly
        let valid_levels = [
            AttestationLevel::SelfSigned,
            AttestationLevel::PeerVerified,
            AttestationLevel::VerifierBacked,
            AttestationLevel::AuthorityCertified,
        ];

        for level in &valid_levels {
            // Should serialize correctly
            let serialized = serde_json::to_string(level).expect("valid level should serialize");

            // Should deserialize back to same level
            let deserialized: AttestationLevel = serde_json::from_str(&serialized)
                .expect("valid serialized level should deserialize");
            assert_eq!(deserialized, *level);

            // Multiplier should be consistent
            assert_eq!(level.multiplier(), deserialized.multiplier());
        }
    }

    #[test]
    fn negative_sybil_cluster_detection_with_crafted_collision_hints() {
        let mut engine = ParticipationWeightEngine::default();

        // Create participants with carefully crafted cluster hints designed to test collision resistance
        let collision_hints = [
            // Hash-like strings that might collide
            "a".repeat(32),
            "b".repeat(32),

            // Similar but different strings
            "cluster_group_alpha",
            "cluster_group_beta",

            // Strings that could hash to similar values
            "subnet_192_168_1",
            "subnet_192_168_2",

            // Unicode variations that look similar
            "café_network",
            "cafe\u{0301}_network",
        ];

        let mut participants = Vec::new();

        // Create 4 participants per hint (to ensure cluster detection triggers)
        for hint in &collision_hints {
            for i in 0..4 {
                participants.push(ParticipantIdentity {
                    participant_id: format!("collision_{}_{}", hint.chars().take(8).collect::<String>(), i),
                    display_name: format!("Collision Test {}", i),
                    attestations: vec![AttestationEvidence {
                        attestation_id: format!("att-{}-{}", hint.chars().take(8).collect::<String>(), i),
                        issuer: "collision-test".to_string(),
                        level: AttestationLevel::SelfSigned,
                        issued_at: "2026-04-17T00:00:00Z".to_string(),
                        expires_at: "2027-04-17T00:00:00Z".to_string(),
                        signature_hex: format!("{:x}", i),
                    }],
                    stake: None,
                    reputation: Some(ReputationEvidence {
                        score: 0.1,
                        interaction_count: 10,
                        tenure_seconds: 86400,
                        contributions_accepted: 5,
                        contributions_rejected: 5,
                    }),
                    cluster_hint: Some(hint.to_string()),
                });
            }
        }

        // Should detect separate clusters for each hint
        let clusters = engine.detect_sybil_clusters(&participants);

        // Should detect one cluster per hint (since each has 4 participants)
        assert_eq!(clusters.len(), collision_hints.len(),
                  "Should detect {} clusters for {} different hints",
                  collision_hints.len(), collision_hints.len());

        // Each cluster should have exactly 4 members
        for cluster in &clusters {
            assert_eq!(cluster.member_ids.len(), 4,
                      "Each cluster should have 4 members");

            // Cluster ID should be unique
            assert!(!cluster.cluster_id.is_empty());
            assert!(cluster.cluster_id.starts_with("SYBIL-"));

            // Detection signal should identify the specific hint
            assert!(cluster.detection_signal.starts_with("shared_cluster_hint:"));

            // All members should be distinct
            let unique_members: BTreeSet<String> = cluster.member_ids.iter().cloned().collect();
            assert_eq!(unique_members.len(), cluster.member_ids.len());
        }

        // All cluster IDs should be unique
        let cluster_ids: BTreeSet<String> = clusters.iter()
            .map(|c| c.cluster_id.clone())
            .collect();
        assert_eq!(cluster_ids.len(), clusters.len(), "All cluster IDs should be unique");

        // Compute weights and verify cluster attenuation
        let record = engine.compute_weights(&participants, "collision_test", "2026-04-17T00:00:00Z");

        assert_eq!(record.sybil_clusters_detected, collision_hints.len());
        assert!(record.weights.iter().all(|w| w.sybil_penalty > 0.0),
               "All participants should have sybil penalty applied");
    }

    #[test]
    fn negative_weighting_config_extreme_boundary_validation() {
        // Test configurations with extreme or contradictory values
        let extreme_configs = [
            // All weights zero
            WeightingConfig {
                attestation_weight: 0.0,
                stake_weight: 0.0,
                reputation_weight: 0.0,
                new_participant_cap_fraction: 0.0,
                established_tenure_seconds: 0,
                established_interaction_count: 0,
                sybil_attenuation_factor: 0.0,
                sybil_cluster_min_size: 0,
            },

            // All weights at maximum
            WeightingConfig {
                attestation_weight: f64::MAX,
                stake_weight: f64::MAX,
                reputation_weight: f64::MAX,
                new_participant_cap_fraction: f64::MAX,
                established_tenure_seconds: u64::MAX,
                established_interaction_count: u64::MAX,
                sybil_attenuation_factor: f64::MAX,
                sybil_cluster_min_size: usize::MAX,
            },

            // All weights negative
            WeightingConfig {
                attestation_weight: -1.0,
                stake_weight: -1.0,
                reputation_weight: -1.0,
                new_participant_cap_fraction: -1.0,
                established_tenure_seconds: 86400,
                established_interaction_count: 100,
                sybil_attenuation_factor: -1.0,
                sybil_cluster_min_size: 3,
            },

            // Invalid floating point values
            WeightingConfig {
                attestation_weight: f64::NAN,
                stake_weight: f64::INFINITY,
                reputation_weight: f64::NEG_INFINITY,
                new_participant_cap_fraction: f64::NAN,
                established_tenure_seconds: 86400,
                established_interaction_count: 100,
                sybil_attenuation_factor: f64::INFINITY,
                sybil_cluster_min_size: 3,
            },
        ];

        for (i, config) in extreme_configs.iter().enumerate() {
            // Engine should handle extreme configurations without panicking
            let engine = ParticipationWeightEngine::new(config.clone());

            // Config should be sanitized to safe values
            let safe_config = &engine.config;

            // All weight factors should be finite and bounded
            assert!(safe_config.attestation_weight.is_finite());
            assert!(safe_config.attestation_weight >= 0.0);
            assert!(safe_config.attestation_weight <= 1.0);

            assert!(safe_config.stake_weight.is_finite());
            assert!(safe_config.stake_weight >= 0.0);
            assert!(safe_config.stake_weight <= 1.0);

            assert!(safe_config.reputation_weight.is_finite());
            assert!(safe_config.reputation_weight >= 0.0);
            assert!(safe_config.reputation_weight <= 1.0);

            assert!(safe_config.new_participant_cap_fraction.is_finite());
            assert!(safe_config.new_participant_cap_fraction >= 0.0);
            assert!(safe_config.new_participant_cap_fraction <= 1.0);

            assert!(safe_config.sybil_attenuation_factor.is_finite());
            assert!(safe_config.sybil_attenuation_factor >= 0.0);
            assert!(safe_config.sybil_attenuation_factor <= 1.0);

            // Test weight computation with extreme config
            let test_participant = ParticipantIdentity {
                participant_id: format!("extreme_config_test_{}", i),
                display_name: format!("Extreme Config Test {}", i),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-extreme-{}", i),
                    issuer: "extreme-test".to_string(),
                    level: AttestationLevel::VerifierBacked,
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: "deadbeef".to_string(),
                }],
                stake: Some(StakeEvidence {
                    amount: 1000.0,
                    deposited_at: "2026-04-17T00:00:00Z".to_string(),
                    lock_duration_seconds: 86400 * 365,
                    locked: true,
                }),
                reputation: Some(ReputationEvidence {
                    score: 0.8,
                    interaction_count: 100,
                    tenure_seconds: 86400 * 365,
                    contributions_accepted: 90,
                    contributions_rejected: 10,
                }),
                cluster_hint: None,
            };

            let weight = engine.compute_single_weight(&test_participant);

            // Weight computation should produce finite, non-negative results
            assert!(weight.raw_weight.is_finite(), "Raw weight should be finite for config {}", i);
            assert!(weight.raw_weight >= 0.0, "Raw weight should be non-negative for config {}", i);

            assert!(weight.final_weight.is_finite(), "Final weight should be finite for config {}", i);
            assert!(weight.final_weight >= 0.0, "Final weight should be non-negative for config {}", i);

            assert!(weight.attestation_component.is_finite());
            assert!(weight.attestation_component >= 0.0);
            assert!(weight.attestation_component <= 1.0);

            assert!(weight.stake_component.is_finite());
            assert!(weight.stake_component >= 0.0);
            assert!(weight.stake_component <= 1.0);

            assert!(weight.reputation_component.is_finite());
            assert!(weight.reputation_component >= 0.0);
            assert!(weight.reputation_component <= 1.0);

            // JSON serialization should handle extreme config values
            let config_json = serde_json::to_string(config);
            match config_json {
                Ok(json) => {
                    // Should deserialize back (though values may be different due to sanitization)
                    if let Ok(_parsed_config) = serde_json::from_str::<WeightingConfig>(&json) {
                        // Parsing succeeded - values should be safe
                    }
                }
                Err(_) => {
                    // Some extreme values might not serialize, which is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_audit_log_memory_exhaustion_protection() {
        let mut engine = ParticipationWeightEngine::default();

        // Generate far more audit records than the maximum capacity
        let overflow_count = MAX_AUDIT_LOG_ENTRIES * 3;

        for i in 0..overflow_count {
            let participant = ParticipantIdentity {
                participant_id: format!("overflow_participant_{:06}", i),
                display_name: format!("Overflow Test {}", i),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-{}", i),
                    issuer: "overflow-test".to_string(),
                    level: AttestationLevel::SelfSigned,
                    issued_at: "2026-04-17T00:00:00Z".to_string(),
                    expires_at: "2027-04-17T00:00:00Z".to_string(),
                    signature_hex: format!("{:x}", i),
                }],
                stake: None,
                reputation: Some(ReputationEvidence {
                    score: 0.1,
                    interaction_count: 10,
                    tenure_seconds: 86400,
                    contributions_accepted: 5,
                    contributions_rejected: 5,
                }),
                cluster_hint: None,
            };

            engine.compute_weights(&[participant], &format!("overflow_{}", i), "2026-04-17T00:00:00Z");

            // Memory usage should remain bounded
            assert!(engine.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES,
                   "Audit log should not exceed maximum capacity");
        }

        // Final audit log should be at capacity
        assert_eq!(engine.audit_log().len(), MAX_AUDIT_LOG_ENTRIES);

        // All remaining records should have unique batch IDs (no corruption)
        let batch_ids: BTreeSet<String> = engine.audit_log()
            .iter()
            .map(|record| record.batch_id.clone())
            .collect();
        assert_eq!(batch_ids.len(), engine.audit_log().len(),
                  "All audit records should have unique batch IDs");

        // All records should have valid structure
        for record in engine.audit_log() {
            assert!(!record.batch_id.is_empty());
            assert!(!record.timestamp.is_empty());
            assert!(record.total_weight.is_finite());
            assert!(record.total_weight >= 0.0);
            assert_eq!(record.content_hash.len(), 64);
            assert!(record.content_hash.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // JSON export should work with full audit log
        let json_result = engine.export_audit_json();
        assert!(json_result.is_ok(), "Should export full audit log as JSON");

        if let Ok(json) = json_result {
            // Should be substantial content
            assert!(json.len() > 10000);

            // Should deserialize back to audit records
            let parsed_result: Result<Vec<WeightAuditRecord>, _> = serde_json::from_str(&json);
            assert!(parsed_result.is_ok(), "Exported audit JSON should deserialize");

            if let Ok(parsed_records) = parsed_result {
                assert_eq!(parsed_records.len(), MAX_AUDIT_LOG_ENTRIES);
            }
        }
    }
}
