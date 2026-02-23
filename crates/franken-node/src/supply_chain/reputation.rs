//! bd-ml1: Publisher reputation model with explainable transitions.
//!
//! This module implements the longitudinal trust signal for the extension ecosystem.
//! While provenance (bd-1ah) proves a single artifact's origin and certification
//! (bd-273) assesses a single version, reputation captures a publisher's track record
//! over time: consistency of good behavior, response to security incidents, adherence
//! to ecosystem norms, and community signal.
//!
//! Reputation is explicit, quantitative, and policy-actionable. It feeds into trust
//! cards (bd-2yh), certification decisions (bd-273), and quarantine/recall
//! prioritization (bd-1vm).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Event codes ──────────────────────────────────────────────────────────────

pub const REPUTATION_COMPUTED: &str = "REPUTATION_COMPUTED";
pub const REPUTATION_TRANSITION: &str = "REPUTATION_TRANSITION";
pub const REPUTATION_FROZEN: &str = "REPUTATION_FROZEN";
pub const REPUTATION_UNFROZEN: &str = "REPUTATION_UNFROZEN";
pub const REPUTATION_DECAY_APPLIED: &str = "REPUTATION_DECAY_APPLIED";
pub const REPUTATION_SIGNAL_INGESTED: &str = "REPUTATION_SIGNAL_INGESTED";
pub const REPUTATION_RECOVERY_STARTED: &str = "REPUTATION_RECOVERY_STARTED";
pub const REPUTATION_AUDIT_QUERIED: &str = "REPUTATION_AUDIT_QUERIED";

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReputationError {
    #[error("publisher `{0}` not found in reputation registry")]
    PublisherNotFound(String),
    #[error("reputation is frozen for publisher `{0}` during active investigation")]
    ReputationFrozen(String),
    #[error("invalid signal weight {weight}: must be in (0.0, 1.0]")]
    InvalidSignalWeight { weight: f64 },
    #[error("invalid decay rate {rate}: must be in (0.0, 1.0)")]
    InvalidDecayRate { rate: f64 },
    #[error("unknown signal kind `{0}`")]
    UnknownSignalKind(String),
    #[error("audit trail integrity violation: expected hash `{expected}`, got `{actual}`")]
    AuditIntegrityViolation { expected: String, actual: String },
    #[error("duplicate signal id `{0}`")]
    DuplicateSignal(String),
}

// ── Reputation tiers ─────────────────────────────────────────────────────────

/// Reputation tier determines policy defaults for a publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReputationTier {
    /// Actively suspended — no operations permitted.
    Suspended,
    /// New or damaged publisher — restricted operations.
    Untrusted,
    /// Recently onboarded — limited policy scope.
    Provisional,
    /// Demonstrated track record — standard operations.
    Established,
    /// Long-standing positive history — extended privileges.
    Trusted,
}

impl ReputationTier {
    /// Score threshold to reach this tier (inclusive lower bound).
    #[must_use]
    pub fn threshold(self) -> f64 {
        match self {
            Self::Suspended => 0.0,
            Self::Untrusted => 0.0,
            Self::Provisional => 20.0,
            Self::Established => 50.0,
            Self::Trusted => 80.0,
        }
    }

    /// Derive tier from a numeric score (0..=100).
    #[must_use]
    pub fn from_score(score: f64) -> Self {
        if score >= 80.0 {
            Self::Trusted
        } else if score >= 50.0 {
            Self::Established
        } else if score >= 20.0 {
            Self::Provisional
        } else {
            Self::Untrusted
        }
    }

    /// Human-readable description of what this tier allows.
    #[must_use]
    pub fn policy_description(self) -> &'static str {
        match self {
            Self::Suspended => "All operations blocked. Active investigation in progress.",
            Self::Untrusted => "Read-only access. Cannot publish or modify artifacts.",
            Self::Provisional => "Can publish with mandatory review. Cannot self-certify.",
            Self::Established => "Standard publish and certification. Subject to spot checks.",
            Self::Trusted => "Full publish privileges. Eligible for fast-track certification.",
        }
    }
}

impl std::fmt::Display for ReputationTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Suspended => write!(f, "suspended"),
            Self::Untrusted => write!(f, "untrusted"),
            Self::Provisional => write!(f, "provisional"),
            Self::Established => write!(f, "established"),
            Self::Trusted => write!(f, "trusted"),
        }
    }
}

// ── Signal types ─────────────────────────────────────────────────────────────

/// The kind of signal that affects a publisher's reputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// Provenance attestation was consistent and verified.
    ProvenanceConsistency,
    /// Publisher responded promptly to a reported vulnerability.
    VulnerabilityResponseTime,
    /// A revocation was issued against a publisher's artifact.
    RevocationEvent,
    /// Quality metrics from extension analysis (test coverage, API stability).
    ExtensionQuality,
    /// Community report (positive or negative).
    CommunityReport,
    /// Publisher adhered to certification requirements.
    CertificationAdherence,
    /// Publisher missed a certification renewal deadline.
    CertificationLapse,
    /// Quarantine or recall was triggered for publisher artifacts.
    QuarantineEvent,
    /// Successful quarantine resolution (artifact cleared).
    QuarantineResolution,
}

impl SignalKind {
    /// Default weight for this signal kind. Positive values boost score;
    /// negative values reduce it.
    #[must_use]
    pub fn default_weight(self) -> f64 {
        match self {
            Self::ProvenanceConsistency => 5.0,
            Self::VulnerabilityResponseTime => 8.0,
            Self::RevocationEvent => -15.0,
            Self::ExtensionQuality => 3.0,
            Self::CommunityReport => 2.0,
            Self::CertificationAdherence => 6.0,
            Self::CertificationLapse => -8.0,
            Self::QuarantineEvent => -20.0,
            Self::QuarantineResolution => 10.0,
        }
    }
}

/// A single reputation signal from the ecosystem.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationSignal {
    /// Unique signal identifier.
    pub signal_id: String,
    /// Publisher this signal applies to.
    pub publisher_id: String,
    /// Kind of signal.
    pub kind: SignalKind,
    /// Timestamp (RFC 3339) when the signal was observed.
    pub observed_at: String,
    /// Optional weight override. If `None`, uses `SignalKind::default_weight`.
    pub weight_override: Option<f64>,
    /// Human-readable description of why this signal was generated.
    pub description: String,
    /// Evidence references (e.g., CVE ID, artifact hash, report URL).
    pub evidence: BTreeMap<String, String>,
}

// ── Reputation decay ─────────────────────────────────────────────────────────

/// Configuration for reputation decay over time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecayConfig {
    /// Daily decay rate for the score component (0.0..1.0).
    /// E.g., 0.01 means 1% daily decay toward the neutral baseline.
    pub daily_rate: f64,
    /// The score baseline that decay trends toward (default: 50.0).
    pub baseline: f64,
    /// Minimum interval in days between decay applications.
    pub min_interval_days: u32,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            daily_rate: 0.005,
            baseline: 50.0,
            min_interval_days: 1,
        }
    }
}

// ── Reputation transition explanation ────────────────────────────────────────

/// Explanation for a reputation score change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransitionExplanation {
    /// The signal(s) that caused this transition.
    pub trigger_signals: Vec<String>,
    /// Previous score.
    pub old_score: f64,
    /// New score.
    pub new_score: f64,
    /// Previous tier.
    pub old_tier: ReputationTier,
    /// New tier.
    pub new_tier: ReputationTier,
    /// Human-readable explanation.
    pub explanation: String,
    /// Timestamp of the transition.
    pub transition_at: String,
}

// ── Audit trail ──────────────────────────────────────────────────────────────

/// A single entry in the append-only reputation audit trail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Hash of the previous entry (empty string for the first entry).
    pub prev_hash: String,
    /// Hash of this entry's content (SHA-256 of canonical JSON of the payload).
    pub entry_hash: String,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// Publisher this entry pertains to.
    pub publisher_id: String,
    /// The event that occurred.
    pub event: AuditEvent,
}

/// Events recorded in the audit trail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    SignalIngested {
        signal_id: String,
        kind: SignalKind,
        weight: f64,
    },
    ScoreComputed {
        old_score: f64,
        new_score: f64,
        old_tier: ReputationTier,
        new_tier: ReputationTier,
        explanation: String,
    },
    DecayApplied {
        old_score: f64,
        new_score: f64,
        days_elapsed: u32,
        rate: f64,
    },
    Frozen {
        reason: String,
        investigation_id: String,
    },
    Unfrozen {
        investigation_id: String,
    },
    RecoveryStarted {
        recovery_plan: String,
    },
}

// ── Publisher reputation record ──────────────────────────────────────────────

/// Full reputation state for a single publisher.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublisherReputation {
    /// Publisher identifier.
    pub publisher_id: String,
    /// Current numeric score (0.0..=100.0).
    pub score: f64,
    /// Current reputation tier.
    pub tier: ReputationTier,
    /// Whether the reputation is currently frozen during an investigation.
    pub frozen: bool,
    /// Active investigation ID if frozen.
    pub active_investigation: Option<String>,
    /// Timestamp of last score computation.
    pub last_computed_at: String,
    /// Timestamp of last decay application.
    pub last_decay_at: Option<String>,
    /// Total signals ingested.
    pub signal_count: u64,
    /// Decay configuration for this publisher.
    pub decay_config: DecayConfig,
}

impl PublisherReputation {
    /// Create a new publisher with the default provisional score.
    #[must_use]
    pub fn new(publisher_id: String, timestamp: &str) -> Self {
        let score = 30.0; // Start provisional
        Self {
            publisher_id,
            score,
            tier: ReputationTier::from_score(score),
            frozen: false,
            active_investigation: None,
            last_computed_at: timestamp.to_owned(),
            last_decay_at: None,
            signal_count: 0,
            decay_config: DecayConfig::default(),
        }
    }
}

// ── Reputation registry (core engine) ────────────────────────────────────────

/// The reputation registry manages publisher reputation state and audit trails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationRegistry {
    publishers: BTreeMap<String, PublisherReputation>,
    audit_trail: Vec<AuditEntry>,
    ingested_signals: BTreeMap<String, bool>,
    next_sequence: u64,
}

impl Default for ReputationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            publishers: BTreeMap::new(),
            audit_trail: Vec::new(),
            ingested_signals: BTreeMap::new(),
            next_sequence: 0,
        }
    }

    /// Register a new publisher or return the existing record.
    pub fn register_publisher(
        &mut self,
        publisher_id: &str,
        timestamp: &str,
    ) -> &PublisherReputation {
        self.publishers
            .entry(publisher_id.to_owned())
            .or_insert_with(|| PublisherReputation::new(publisher_id.to_owned(), timestamp));
        &self.publishers[publisher_id]
    }

    /// Get a publisher's current reputation.
    pub fn get_reputation(
        &self,
        publisher_id: &str,
    ) -> Result<&PublisherReputation, ReputationError> {
        self.publishers
            .get(publisher_id)
            .ok_or_else(|| ReputationError::PublisherNotFound(publisher_id.to_owned()))
    }

    /// Query the full audit trail for a publisher.
    #[must_use]
    pub fn query_audit_trail(&self, publisher_id: &str) -> Vec<&AuditEntry> {
        self.audit_trail
            .iter()
            .filter(|e| e.publisher_id == publisher_id)
            .collect()
    }

    /// Query the audit trail for a publisher within a time range.
    #[must_use]
    pub fn query_audit_trail_range(
        &self,
        publisher_id: &str,
        from: &str,
        to: &str,
    ) -> Vec<&AuditEntry> {
        self.audit_trail
            .iter()
            .filter(|e| {
                e.publisher_id == publisher_id
                    && e.timestamp.as_str() >= from
                    && e.timestamp.as_str() <= to
            })
            .collect()
    }

    /// Ingest a reputation signal and recompute the publisher's score.
    ///
    /// Returns a `TransitionExplanation` describing what changed.
    pub fn ingest_signal(
        &mut self,
        signal: &ReputationSignal,
        timestamp: &str,
    ) -> Result<TransitionExplanation, ReputationError> {
        // Reject duplicate signals.
        if self.ingested_signals.contains_key(&signal.signal_id) {
            return Err(ReputationError::DuplicateSignal(signal.signal_id.clone()));
        }

        // Auto-register unknown publishers.
        self.publishers
            .entry(signal.publisher_id.clone())
            .or_insert_with(|| PublisherReputation::new(signal.publisher_id.clone(), timestamp));

        let pub_record = self
            .publishers
            .get(&signal.publisher_id)
            .ok_or_else(|| ReputationError::PublisherNotFound(signal.publisher_id.clone()))?;

        // Check frozen state.
        if pub_record.frozen {
            return Err(ReputationError::ReputationFrozen(
                signal.publisher_id.clone(),
            ));
        }

        let weight = signal
            .weight_override
            .unwrap_or_else(|| signal.kind.default_weight());

        let old_score = pub_record.score;
        let old_tier = pub_record.tier;

        // Compute new score, clamped to [0, 100].
        let new_score = (old_score + weight).clamp(0.0, 100.0);
        let new_tier = ReputationTier::from_score(new_score);

        let explanation = format!(
            "Signal '{}' ({:?}) applied with weight {:.2}: score {:.2} -> {:.2}{}",
            signal.signal_id,
            signal.kind,
            weight,
            old_score,
            new_score,
            if old_tier != new_tier {
                format!(", tier changed from {} to {}", old_tier, new_tier)
            } else {
                String::new()
            }
        );

        // Record signal ingestion in audit trail.
        self.append_audit_entry(
            &signal.publisher_id,
            timestamp,
            AuditEvent::SignalIngested {
                signal_id: signal.signal_id.clone(),
                kind: signal.kind,
                weight,
            },
        );

        // Record score computation in audit trail.
        self.append_audit_entry(
            &signal.publisher_id,
            timestamp,
            AuditEvent::ScoreComputed {
                old_score,
                new_score,
                old_tier,
                new_tier,
                explanation: explanation.clone(),
            },
        );

        // Update publisher state.
        let pub_record = self
            .publishers
            .get_mut(&signal.publisher_id)
            .expect("publisher was just inserted");
        pub_record.score = new_score;
        pub_record.tier = new_tier;
        pub_record.last_computed_at = timestamp.to_owned();
        pub_record.signal_count += 1;

        self.ingested_signals.insert(signal.signal_id.clone(), true);

        Ok(TransitionExplanation {
            trigger_signals: vec![signal.signal_id.clone()],
            old_score,
            new_score,
            old_tier,
            new_tier,
            explanation,
            transition_at: timestamp.to_owned(),
        })
    }

    /// Apply time-based decay to a publisher's reputation score.
    pub fn apply_decay(
        &mut self,
        publisher_id: &str,
        days_elapsed: u32,
        timestamp: &str,
    ) -> Result<TransitionExplanation, ReputationError> {
        let pub_record = self
            .publishers
            .get(publisher_id)
            .ok_or_else(|| ReputationError::PublisherNotFound(publisher_id.to_owned()))?;

        if pub_record.frozen {
            return Err(ReputationError::ReputationFrozen(publisher_id.to_owned()));
        }

        let config = &pub_record.decay_config;
        if days_elapsed < config.min_interval_days {
            // No decay needed yet — return no-op transition.
            return Ok(TransitionExplanation {
                trigger_signals: vec![],
                old_score: pub_record.score,
                new_score: pub_record.score,
                old_tier: pub_record.tier,
                new_tier: pub_record.tier,
                explanation: format!(
                    "Decay skipped: only {} days elapsed (minimum {})",
                    days_elapsed, config.min_interval_days
                ),
                transition_at: timestamp.to_owned(),
            });
        }

        let old_score = pub_record.score;
        let old_tier = pub_record.tier;
        let baseline = config.baseline;
        let rate = config.daily_rate;

        // Exponential decay toward baseline.
        let decay_factor = (1.0 - rate).powi(days_elapsed as i32);
        let new_score = (baseline + (old_score - baseline) * decay_factor).clamp(0.0, 100.0);
        let new_tier = ReputationTier::from_score(new_score);

        let explanation = format!(
            "Decay applied: {days_elapsed} days at rate {rate:.4}, score {old_score:.2} -> {new_score:.2}{}",
            if old_tier != new_tier {
                format!(", tier changed from {old_tier} to {new_tier}")
            } else {
                String::new()
            }
        );

        self.append_audit_entry(
            publisher_id,
            timestamp,
            AuditEvent::DecayApplied {
                old_score,
                new_score,
                days_elapsed,
                rate,
            },
        );

        let pub_record = self
            .publishers
            .get_mut(publisher_id)
            .expect("publisher existence was verified");
        pub_record.score = new_score;
        pub_record.tier = new_tier;
        pub_record.last_computed_at = timestamp.to_owned();
        pub_record.last_decay_at = Some(timestamp.to_owned());

        Ok(TransitionExplanation {
            trigger_signals: vec![],
            old_score,
            new_score,
            old_tier,
            new_tier,
            explanation,
            transition_at: timestamp.to_owned(),
        })
    }

    /// Freeze a publisher's reputation during an active investigation.
    pub fn freeze(
        &mut self,
        publisher_id: &str,
        investigation_id: &str,
        reason: &str,
        timestamp: &str,
    ) -> Result<(), ReputationError> {
        let pub_record = self
            .publishers
            .get_mut(publisher_id)
            .ok_or_else(|| ReputationError::PublisherNotFound(publisher_id.to_owned()))?;

        pub_record.frozen = true;
        pub_record.active_investigation = Some(investigation_id.to_owned());
        pub_record.tier = ReputationTier::Suspended;

        self.append_audit_entry(
            publisher_id,
            timestamp,
            AuditEvent::Frozen {
                reason: reason.to_owned(),
                investigation_id: investigation_id.to_owned(),
            },
        );

        Ok(())
    }

    /// Unfreeze a publisher's reputation after investigation concludes.
    pub fn unfreeze(
        &mut self,
        publisher_id: &str,
        investigation_id: &str,
        timestamp: &str,
    ) -> Result<(), ReputationError> {
        let pub_record = self
            .publishers
            .get_mut(publisher_id)
            .ok_or_else(|| ReputationError::PublisherNotFound(publisher_id.to_owned()))?;

        pub_record.frozen = false;
        pub_record.active_investigation = None;
        // Restore tier from score after unfreezing.
        pub_record.tier = ReputationTier::from_score(pub_record.score);

        self.append_audit_entry(
            publisher_id,
            timestamp,
            AuditEvent::Unfrozen {
                investigation_id: investigation_id.to_owned(),
            },
        );

        Ok(())
    }

    /// Start a documented recovery path for a publisher.
    pub fn start_recovery(
        &mut self,
        publisher_id: &str,
        recovery_plan: &str,
        timestamp: &str,
    ) -> Result<(), ReputationError> {
        let _pub_record = self
            .publishers
            .get(publisher_id)
            .ok_or_else(|| ReputationError::PublisherNotFound(publisher_id.to_owned()))?;

        self.append_audit_entry(
            publisher_id,
            timestamp,
            AuditEvent::RecoveryStarted {
                recovery_plan: recovery_plan.to_owned(),
            },
        );

        Ok(())
    }

    /// Verify the integrity of the audit trail via hash chain.
    pub fn verify_audit_integrity(&self) -> Result<(), ReputationError> {
        let mut expected_prev = String::new();
        for entry in &self.audit_trail {
            if entry.prev_hash != expected_prev {
                return Err(ReputationError::AuditIntegrityViolation {
                    expected: expected_prev,
                    actual: entry.prev_hash.clone(),
                });
            }
            let computed = compute_entry_hash(entry);
            if computed != entry.entry_hash {
                return Err(ReputationError::AuditIntegrityViolation {
                    expected: computed,
                    actual: entry.entry_hash.clone(),
                });
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    /// Get total number of publishers.
    #[must_use]
    pub fn publisher_count(&self) -> usize {
        self.publishers.len()
    }

    /// Get total audit trail length.
    #[must_use]
    pub fn audit_trail_len(&self) -> usize {
        self.audit_trail.len()
    }

    /// List all publishers with their current reputation.
    #[must_use]
    pub fn list_publishers(&self) -> Vec<&PublisherReputation> {
        self.publishers.values().collect()
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    fn append_audit_entry(&mut self, publisher_id: &str, timestamp: &str, event: AuditEvent) {
        let prev_hash = self
            .audit_trail
            .last()
            .map_or(String::new(), |e| e.entry_hash.clone());

        let sequence = self.next_sequence;
        self.next_sequence += 1;

        let mut entry = AuditEntry {
            sequence,
            prev_hash,
            entry_hash: String::new(), // Placeholder; computed below.
            timestamp: timestamp.to_owned(),
            publisher_id: publisher_id.to_owned(),
            event,
        };
        entry.entry_hash = compute_entry_hash(&entry);
        self.audit_trail.push(entry);
    }
}

/// Compute the SHA-256 hash of an audit entry's content for chaining.
fn compute_entry_hash(entry: &AuditEntry) -> String {
    let payload = format!(
        "{}:{}:{}:{}:{}",
        entry.sequence,
        entry.prev_hash,
        entry.timestamp,
        entry.publisher_id,
        serde_json::to_string(&entry.event).unwrap_or_default()
    );
    let digest = Sha256::digest(payload.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

// ── Determinism helper ───────────────────────────────────────────────────────

/// Compute a reputation score deterministically from a list of signals.
/// This is a pure function: same input signals in the same order produce
/// identical output scores.
#[must_use]
pub fn deterministic_score(signals: &[ReputationSignal], decay_config: &DecayConfig) -> f64 {
    let mut score = 30.0_f64; // Initial provisional score.
    for signal in signals {
        let weight = signal
            .weight_override
            .unwrap_or_else(|| signal.kind.default_weight());
        score = (score + weight).clamp(0.0, 100.0);
    }
    // Note: decay is not applied in the pure function — it requires time context.
    let _ = decay_config; // Available for future deterministic replay.
    score
}

// ── Recovery paths ───────────────────────────────────────────────────────────

/// Documented recovery actions a publisher can take to improve reputation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAction {
    pub action_id: String,
    pub title: String,
    pub description: String,
    pub expected_score_impact: String,
    pub required_evidence: Vec<String>,
}

/// Get the standard recovery actions available for a given tier.
#[must_use]
pub fn recovery_actions_for_tier(tier: ReputationTier) -> Vec<RecoveryAction> {
    match tier {
        ReputationTier::Suspended => vec![
            RecoveryAction {
                action_id: "resolve-investigation".to_owned(),
                title: "Resolve Active Investigation".to_owned(),
                description: "Cooperate with the investigation team to resolve the issue. Provide all requested evidence and remediation artifacts.".to_owned(),
                expected_score_impact: "Unfreeze reputation; score remains as before freeze".to_owned(),
                required_evidence: vec!["investigation_resolution_report".to_owned(), "remediation_artifacts".to_owned()],
            },
        ],
        ReputationTier::Untrusted => vec![
            RecoveryAction {
                action_id: "submit-provenance".to_owned(),
                title: "Submit Verified Provenance".to_owned(),
                description: "Publish artifacts with Level2+ provenance attestations to demonstrate build integrity.".to_owned(),
                expected_score_impact: "+5 per verified attestation".to_owned(),
                required_evidence: vec!["provenance_attestation_chain".to_owned()],
            },
            RecoveryAction {
                action_id: "vulnerability-response".to_owned(),
                title: "Demonstrate Vulnerability Response".to_owned(),
                description: "Respond to reported vulnerabilities within 48 hours with a patch or mitigation.".to_owned(),
                expected_score_impact: "+8 per timely response".to_owned(),
                required_evidence: vec!["vulnerability_report_id".to_owned(), "patch_artifact".to_owned()],
            },
        ],
        ReputationTier::Provisional | ReputationTier::Established => vec![
            RecoveryAction {
                action_id: "certification-renewal".to_owned(),
                title: "Complete Certification Renewal".to_owned(),
                description: "Renew ecosystem certification to demonstrate ongoing commitment.".to_owned(),
                expected_score_impact: "+6 per renewal".to_owned(),
                required_evidence: vec!["certification_id".to_owned()],
            },
            RecoveryAction {
                action_id: "quality-improvement".to_owned(),
                title: "Improve Extension Quality Metrics".to_owned(),
                description: "Raise test coverage, API stability score, and documentation completeness.".to_owned(),
                expected_score_impact: "+3 per quality milestone".to_owned(),
                required_evidence: vec!["quality_report".to_owned()],
            },
        ],
        ReputationTier::Trusted => vec![],
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: u32) -> String {
        format!("2026-01-{n:02}T00:00:00Z")
    }

    fn make_signal(id: &str, publisher: &str, kind: SignalKind) -> ReputationSignal {
        ReputationSignal {
            signal_id: id.to_owned(),
            publisher_id: publisher.to_owned(),
            kind,
            observed_at: ts(1),
            weight_override: None,
            description: format!("Test signal {id}"),
            evidence: BTreeMap::new(),
        }
    }

    #[test]
    fn test_tier_from_score() {
        assert_eq!(ReputationTier::from_score(0.0), ReputationTier::Untrusted);
        assert_eq!(ReputationTier::from_score(19.9), ReputationTier::Untrusted);
        assert_eq!(
            ReputationTier::from_score(20.0),
            ReputationTier::Provisional
        );
        assert_eq!(
            ReputationTier::from_score(49.9),
            ReputationTier::Provisional
        );
        assert_eq!(
            ReputationTier::from_score(50.0),
            ReputationTier::Established
        );
        assert_eq!(
            ReputationTier::from_score(79.9),
            ReputationTier::Established
        );
        assert_eq!(ReputationTier::from_score(80.0), ReputationTier::Trusted);
        assert_eq!(ReputationTier::from_score(100.0), ReputationTier::Trusted);
    }

    #[test]
    fn test_new_publisher_starts_provisional() {
        let rep = PublisherReputation::new("pub-1".to_owned(), &ts(1));
        assert_eq!(rep.score, 30.0);
        assert_eq!(rep.tier, ReputationTier::Provisional);
        assert!(!rep.frozen);
    }

    #[test]
    fn test_ingest_positive_signal() {
        let mut reg = ReputationRegistry::new();
        let signal = make_signal("sig-1", "pub-1", SignalKind::ProvenanceConsistency);
        let result = reg.ingest_signal(&signal, &ts(1)).unwrap();
        assert_eq!(result.old_score, 30.0);
        assert_eq!(result.new_score, 35.0); // +5.0 default weight
        assert_eq!(result.old_tier, ReputationTier::Provisional);
        assert_eq!(result.new_tier, ReputationTier::Provisional);
    }

    #[test]
    fn test_ingest_negative_signal() {
        let mut reg = ReputationRegistry::new();
        reg.register_publisher("pub-1", &ts(1));

        let signal = make_signal("sig-1", "pub-1", SignalKind::QuarantineEvent);
        let result = reg.ingest_signal(&signal, &ts(2)).unwrap();
        assert_eq!(result.old_score, 30.0);
        assert_eq!(result.new_score, 10.0); // -20.0 default weight
        assert_eq!(result.new_tier, ReputationTier::Untrusted);
    }

    #[test]
    fn test_score_clamped_to_range() {
        let mut reg = ReputationRegistry::new();
        // Push score very low.
        let sig1 = make_signal("sig-1", "pub-1", SignalKind::QuarantineEvent);
        let sig2 = ReputationSignal {
            signal_id: "sig-2".to_owned(),
            publisher_id: "pub-1".to_owned(),
            kind: SignalKind::QuarantineEvent,
            observed_at: ts(2),
            weight_override: Some(-200.0),
            description: "Big penalty".to_owned(),
            evidence: BTreeMap::new(),
        };
        reg.ingest_signal(&sig1, &ts(1)).unwrap();
        let result = reg.ingest_signal(&sig2, &ts(2)).unwrap();
        assert_eq!(result.new_score, 0.0); // Clamped at 0
    }

    #[test]
    fn test_duplicate_signal_rejected() {
        let mut reg = ReputationRegistry::new();
        let signal = make_signal("sig-dup", "pub-1", SignalKind::ExtensionQuality);
        reg.ingest_signal(&signal, &ts(1)).unwrap();
        let result = reg.ingest_signal(&signal, &ts(2));
        assert!(matches!(result, Err(ReputationError::DuplicateSignal(_))));
    }

    #[test]
    fn test_frozen_rejects_signals() {
        let mut reg = ReputationRegistry::new();
        reg.register_publisher("pub-1", &ts(1));
        reg.freeze("pub-1", "inv-001", "suspected compromise", &ts(2))
            .unwrap();
        let signal = make_signal("sig-1", "pub-1", SignalKind::ExtensionQuality);
        let result = reg.ingest_signal(&signal, &ts(3));
        assert!(matches!(result, Err(ReputationError::ReputationFrozen(_))));
    }

    #[test]
    fn test_freeze_unfreeze_cycle() {
        let mut reg = ReputationRegistry::new();
        reg.register_publisher("pub-1", &ts(1));

        // Ingest a signal to move score to 35.
        let signal = make_signal("sig-1", "pub-1", SignalKind::ProvenanceConsistency);
        reg.ingest_signal(&signal, &ts(2)).unwrap();
        let rep = reg.get_reputation("pub-1").unwrap();
        assert_eq!(rep.score, 35.0);
        assert_eq!(rep.tier, ReputationTier::Provisional);

        // Freeze.
        reg.freeze("pub-1", "inv-001", "investigation", &ts(3))
            .unwrap();
        let rep = reg.get_reputation("pub-1").unwrap();
        assert!(rep.frozen);
        assert_eq!(rep.tier, ReputationTier::Suspended);

        // Unfreeze.
        reg.unfreeze("pub-1", "inv-001", &ts(4)).unwrap();
        let rep = reg.get_reputation("pub-1").unwrap();
        assert!(!rep.frozen);
        // Tier restored from score.
        assert_eq!(rep.tier, ReputationTier::Provisional);
        assert_eq!(rep.score, 35.0);
    }

    #[test]
    fn test_decay_reduces_score_toward_baseline() {
        let mut reg = ReputationRegistry::new();
        reg.register_publisher("pub-1", &ts(1));

        // Push score to 90.
        for i in 0..12 {
            let signal = make_signal(
                &format!("sig-{i}"),
                "pub-1",
                SignalKind::ProvenanceConsistency,
            );
            reg.ingest_signal(&signal, &ts(1)).unwrap();
        }
        let score_before = reg.get_reputation("pub-1").unwrap().score;
        assert!(score_before > 80.0);

        // Apply 30 days of decay.
        let result = reg.apply_decay("pub-1", 30, &ts(2)).unwrap();
        assert!(result.new_score < score_before);
        assert!(result.new_score > 50.0); // Should trend toward baseline 50.
    }

    #[test]
    fn test_decay_skipped_below_min_interval() {
        let mut reg = ReputationRegistry::new();
        reg.register_publisher("pub-1", &ts(1));
        let result = reg.apply_decay("pub-1", 0, &ts(2)).unwrap();
        // No change.
        assert_eq!(result.old_score, result.new_score);
        assert!(result.explanation.contains("skipped"));
    }

    #[test]
    fn test_audit_trail_integrity() {
        let mut reg = ReputationRegistry::new();
        reg.register_publisher("pub-1", &ts(1));
        let sig = make_signal("sig-1", "pub-1", SignalKind::CertificationAdherence);
        reg.ingest_signal(&sig, &ts(2)).unwrap();
        reg.apply_decay("pub-1", 5, &ts(3)).unwrap();

        // Verify chain integrity.
        reg.verify_audit_integrity().unwrap();
        assert!(reg.audit_trail_len() > 0);
    }

    #[test]
    fn test_deterministic_scoring() {
        let signals = vec![
            make_signal("s1", "pub-1", SignalKind::ProvenanceConsistency),
            make_signal("s2", "pub-1", SignalKind::VulnerabilityResponseTime),
            make_signal("s3", "pub-1", SignalKind::RevocationEvent),
        ];
        let config = DecayConfig::default();
        let score1 = deterministic_score(&signals, &config);
        let score2 = deterministic_score(&signals, &config);
        assert!((score1 - score2).abs() < f64::EPSILON);
        // 30 + 5 + 8 - 15 = 28
        assert!((score1 - 28.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tier_transitions_across_boundaries() {
        let mut reg = ReputationRegistry::new();
        // Start at 30 (provisional).
        reg.register_publisher("pub-1", &ts(1));

        // Push to established (need +20 to reach 50).
        for i in 0..4 {
            let sig = make_signal(
                &format!("quality-{i}"),
                "pub-1",
                SignalKind::ProvenanceConsistency,
            );
            reg.ingest_signal(&sig, &ts(2)).unwrap();
        }
        // 30 + 4*5 = 50 -> established
        let rep = reg.get_reputation("pub-1").unwrap();
        assert_eq!(rep.tier, ReputationTier::Established);

        // Push to trusted (need +30 more to reach 80).
        for i in 4..10 {
            let sig = make_signal(
                &format!("quality-{i}"),
                "pub-1",
                SignalKind::ProvenanceConsistency,
            );
            reg.ingest_signal(&sig, &ts(3)).unwrap();
        }
        // 50 + 6*5 = 80 -> trusted
        let rep = reg.get_reputation("pub-1").unwrap();
        assert_eq!(rep.tier, ReputationTier::Trusted);
    }

    #[test]
    fn test_recovery_actions_for_tiers() {
        // Suspended has one action.
        let actions = recovery_actions_for_tier(ReputationTier::Suspended);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, "resolve-investigation");

        // Untrusted has two actions.
        let actions = recovery_actions_for_tier(ReputationTier::Untrusted);
        assert_eq!(actions.len(), 2);

        // Trusted has no recovery actions needed.
        let actions = recovery_actions_for_tier(ReputationTier::Trusted);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_multiple_publishers_isolated() {
        let mut reg = ReputationRegistry::new();
        reg.register_publisher("pub-a", &ts(1));
        reg.register_publisher("pub-b", &ts(1));

        let sig_a = make_signal("sig-a", "pub-a", SignalKind::QuarantineEvent);
        reg.ingest_signal(&sig_a, &ts(2)).unwrap();

        // pub-b should be unaffected.
        let rep_a = reg.get_reputation("pub-a").unwrap();
        let rep_b = reg.get_reputation("pub-b").unwrap();
        assert_eq!(rep_a.score, 10.0);
        assert_eq!(rep_b.score, 30.0);
    }

    #[test]
    fn test_weight_override() {
        let mut reg = ReputationRegistry::new();
        let signal = ReputationSignal {
            signal_id: "override-test".to_owned(),
            publisher_id: "pub-1".to_owned(),
            kind: SignalKind::CommunityReport,
            observed_at: ts(1),
            weight_override: Some(25.0),
            description: "High-impact community report".to_owned(),
            evidence: BTreeMap::new(),
        };
        let result = reg.ingest_signal(&signal, &ts(1)).unwrap();
        // 30 + 25 = 55 -> established
        assert!((result.new_score - 55.0).abs() < f64::EPSILON);
        assert_eq!(result.new_tier, ReputationTier::Established);
    }

    #[test]
    fn test_audit_query_by_publisher() {
        let mut reg = ReputationRegistry::new();
        let sig_a = make_signal("sig-a", "pub-a", SignalKind::ExtensionQuality);
        let sig_b = make_signal("sig-b", "pub-b", SignalKind::ExtensionQuality);
        reg.ingest_signal(&sig_a, &ts(1)).unwrap();
        reg.ingest_signal(&sig_b, &ts(2)).unwrap();

        let trail_a = reg.query_audit_trail("pub-a");
        let trail_b = reg.query_audit_trail("pub-b");
        // Each ingest produces 2 entries: signal ingested + score computed.
        assert_eq!(trail_a.len(), 2);
        assert_eq!(trail_b.len(), 2);
    }

    #[test]
    fn test_frozen_rejects_decay() {
        let mut reg = ReputationRegistry::new();
        reg.register_publisher("pub-1", &ts(1));
        reg.freeze("pub-1", "inv-1", "test", &ts(2)).unwrap();
        let result = reg.apply_decay("pub-1", 30, &ts(3));
        assert!(matches!(result, Err(ReputationError::ReputationFrozen(_))));
    }
}
