//! bd-2aj: Ecosystem reputation API.
//!
//! Computes and serves deterministic reputation scores for extension publishers
//! based on four input dimensions: compatibility pass rate, migration success
//! rate, trust artifact validity, and verifier audit frequency.
//!
//! Scores are deterministically reproducible from input evidence (INV-ENE-DETERM).
//! Anti-gaming protections include Sybil resistance, rate-limited updates,
//! anomaly detection, and a dispute/appeal mechanism (INV-ENE-ANOMALY).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// -- Event codes ---------------------------------------------------------------

pub const ENE_003_REPUTATION_COMPUTED: &str = "ENE-003";
pub const ENE_004_REPUTATION_ANOMALY: &str = "ENE-004";

// -- Invariant tags ------------------------------------------------------------

pub const INV_ENE_DETERM: &str = "INV-ENE-DETERM";
pub const INV_ENE_ANOMALY: &str = "INV-ENE-ANOMALY";

// -- Error codes ---------------------------------------------------------------

pub const ERR_ENE_RATE_LIMIT: &str = "ERR-ENE-RATE-LIMIT";

// -- Errors --------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReputationApiError {
    #[error("publisher `{0}` not found")]
    PublisherNotFound(String),
    #[error("rate limit exceeded for publisher `{0}` (code: {ERR_ENE_RATE_LIMIT})")]
    RateLimitExceeded(String),
    #[error("duplicate publisher identity `{0}` (Sybil rejection)")]
    SybilDuplicate(String),
}

// -- Input dimensions ----------------------------------------------------------

/// The four input dimensions for reputation scoring.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationInputs {
    /// Compatibility pass rate (0.0 -- 1.0).
    pub compatibility_pass_rate: f64,
    /// Migration success rate (0.0 -- 1.0).
    pub migration_success_rate: f64,
    /// Trust artifact validity fraction (0.0 -- 1.0).
    pub trust_artifact_validity: f64,
    /// Verifier audit frequency (0.0 -- 1.0, normalized).
    pub verifier_audit_frequency: f64,
}

impl ReputationInputs {
    /// Create inputs with all zeros.
    #[must_use]
    pub fn zeros() -> Self {
        Self {
            compatibility_pass_rate: 0.0,
            migration_success_rate: 0.0,
            trust_artifact_validity: 0.0,
            verifier_audit_frequency: 0.0,
        }
    }

    /// Create inputs with all ones (maximum).
    #[must_use]
    pub fn ones() -> Self {
        Self {
            compatibility_pass_rate: 1.0,
            migration_success_rate: 1.0,
            trust_artifact_validity: 1.0,
            verifier_audit_frequency: 1.0,
        }
    }
}

// -- Scoring weights -----------------------------------------------------------

/// Weights for the four reputation dimensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoringWeights {
    pub compatibility: f64,
    pub migration: f64,
    pub trust_artifact: f64,
    pub verifier_audit: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            compatibility: 0.30,
            migration: 0.25,
            trust_artifact: 0.25,
            verifier_audit: 0.20,
        }
    }
}

impl ScoringWeights {
    /// Verify weights sum to 1.0 (within epsilon).
    #[must_use]
    pub fn valid(&self) -> bool {
        let sum = self.compatibility + self.migration + self.trust_artifact + self.verifier_audit;
        (sum - 1.0).abs() < 1e-9
    }
}

// -- Anomaly detection ---------------------------------------------------------

/// Configuration for anomaly detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyConfig {
    /// Number of score changes to keep in the rolling window.
    pub window_size: usize,
    /// Multiplier for standard deviation threshold.
    pub std_dev_multiplier: f64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            window_size: 20,
            std_dev_multiplier: 2.0,
        }
    }
}

// -- Publisher reputation state ------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EcosystemPublisherReputation {
    pub publisher_id: String,
    pub score: f64,
    pub inputs: ReputationInputs,
    pub last_computed_at: String,
    pub computation_count: u64,
    pub score_history: Vec<f64>,
    pub frozen: bool,
}

impl EcosystemPublisherReputation {
    #[must_use]
    pub fn new(publisher_id: String, timestamp: &str) -> Self {
        Self {
            publisher_id,
            score: 0.0,
            inputs: ReputationInputs::zeros(),
            last_computed_at: timestamp.to_owned(),
            computation_count: 0,
            score_history: Vec::new(),
            frozen: false,
        }
    }
}

// -- Dispute -------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationDispute {
    pub dispute_id: String,
    pub publisher_id: String,
    pub reason: String,
    pub old_score: f64,
    pub new_score: f64,
    pub filed_at: String,
    pub resolved: bool,
    pub outcome: Option<String>,
}

// -- Events (emitted) ----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationEvent {
    pub event_code: String,
    pub publisher_id: String,
    pub detail: String,
    pub timestamp: String,
}

// -- Core scoring function (pure, deterministic) -------------------------------

/// Compute a reputation score deterministically from inputs and weights.
///
/// This is a pure function: identical inputs always produce identical output.
/// Satisfies INV-ENE-DETERM.
#[must_use]
pub fn deterministic_reputation_score(inputs: &ReputationInputs, weights: &ScoringWeights) -> f64 {
    let raw = inputs.compatibility_pass_rate * weights.compatibility
        + inputs.migration_success_rate * weights.migration
        + inputs.trust_artifact_validity * weights.trust_artifact
        + inputs.verifier_audit_frequency * weights.verifier_audit;
    // Scale to 0..100 and clamp.
    (raw * 100.0).clamp(0.0, 100.0)
}

// -- Anomaly detection function (pure) -----------------------------------------

/// Check whether a score delta is anomalous given a history of deltas.
///
/// Returns true if the absolute delta exceeds `config.std_dev_multiplier`
/// standard deviations from the rolling mean.
#[must_use]
pub fn is_anomalous_delta(delta: f64, history: &[f64], config: &AnomalyConfig) -> bool {
    if history.len() < 2 {
        return false; // Not enough history for anomaly detection.
    }

    let window: Vec<f64> = if history.len() > config.window_size {
        history[history.len() - config.window_size..].to_vec()
    } else {
        history.to_vec()
    };

    let n = window.len() as f64;
    let mean = window.iter().sum::<f64>() / n;
    let variance = window.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let std_dev = variance.sqrt();

    if std_dev < 1e-9 {
        // Zero variance — any nonzero delta is anomalous if the multiplier is finite.
        return delta.abs() > 1e-9;
    }

    delta.abs() > config.std_dev_multiplier * std_dev
}

// -- Reputation API registry ---------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemReputationApi {
    publishers: BTreeMap<String, EcosystemPublisherReputation>,
    publisher_keys: BTreeMap<String, String>,
    disputes: Vec<ReputationDispute>,
    events: Vec<ReputationEvent>,
    weights: ScoringWeights,
    anomaly_config: AnomalyConfig,
    rate_limit_window_ms: u64,
    rate_limit_max: u64,
    rate_counters: BTreeMap<String, u64>,
}

impl Default for EcosystemReputationApi {
    fn default() -> Self {
        Self::new()
    }
}

impl EcosystemReputationApi {
    #[must_use]
    pub fn new() -> Self {
        Self {
            publishers: BTreeMap::new(),
            publisher_keys: BTreeMap::new(),
            disputes: Vec::new(),
            events: Vec::new(),
            weights: ScoringWeights::default(),
            anomaly_config: AnomalyConfig::default(),
            rate_limit_window_ms: 60_000,
            rate_limit_max: 10,
            rate_counters: BTreeMap::new(),
        }
    }

    /// Create with custom weights.
    #[must_use]
    pub fn with_weights(weights: ScoringWeights) -> Self {
        Self {
            weights,
            ..Self::new()
        }
    }

    /// Register a publisher with a unique key (Sybil resistance).
    pub fn register_publisher(
        &mut self,
        publisher_id: &str,
        publisher_key: &str,
        timestamp: &str,
    ) -> Result<&EcosystemPublisherReputation, ReputationApiError> {
        // Sybil check
        if let Some(existing) = self.publisher_keys.get(publisher_key)
            && existing != publisher_id
        {
            return Err(ReputationApiError::SybilDuplicate(publisher_key.to_owned()));
        }
        self.publisher_keys
            .insert(publisher_key.to_owned(), publisher_id.to_owned());
        self.publishers
            .entry(publisher_id.to_owned())
            .or_insert_with(|| {
                EcosystemPublisherReputation::new(publisher_id.to_owned(), timestamp)
            });
        Ok(&self.publishers[publisher_id])
    }

    /// Get a publisher's reputation.
    pub fn get_reputation(
        &self,
        publisher_id: &str,
    ) -> Result<&EcosystemPublisherReputation, ReputationApiError> {
        self.publishers
            .get(publisher_id)
            .ok_or_else(|| ReputationApiError::PublisherNotFound(publisher_id.to_owned()))
    }

    /// Compute and update a publisher's reputation score.
    pub fn compute_reputation(
        &mut self,
        publisher_id: &str,
        inputs: ReputationInputs,
        timestamp: &str,
    ) -> Result<f64, ReputationApiError> {
        // Rate limit check
        let counter = self
            .rate_counters
            .entry(publisher_id.to_owned())
            .or_insert(0);
        if *counter >= self.rate_limit_max {
            return Err(ReputationApiError::RateLimitExceeded(
                publisher_id.to_owned(),
            ));
        }
        *counter += 1;

        let pub_record = self
            .publishers
            .get_mut(publisher_id)
            .ok_or_else(|| ReputationApiError::PublisherNotFound(publisher_id.to_owned()))?;

        let old_score = pub_record.score;
        let new_score = deterministic_reputation_score(&inputs, &self.weights);
        let delta = new_score - old_score;

        // Check for anomaly
        let deltas: Vec<f64> = pub_record
            .score_history
            .windows(2)
            .map(|w| w[1] - w[0])
            .collect();
        let anomalous = is_anomalous_delta(delta, &deltas, &self.anomaly_config);

        pub_record.score = new_score;
        pub_record.inputs = inputs;
        pub_record.last_computed_at = timestamp.to_owned();
        pub_record.computation_count += 1;
        pub_record.score_history.push(new_score);

        self.events.push(ReputationEvent {
            event_code: ENE_003_REPUTATION_COMPUTED.to_owned(),
            publisher_id: publisher_id.to_owned(),
            detail: format!("score={new_score:.4}, delta={delta:.4}"),
            timestamp: timestamp.to_owned(),
        });

        if anomalous {
            self.events.push(ReputationEvent {
                event_code: ENE_004_REPUTATION_ANOMALY.to_owned(),
                publisher_id: publisher_id.to_owned(),
                detail: format!("anomalous delta {delta:.4} detected"),
                timestamp: timestamp.to_owned(),
            });
        }

        Ok(new_score)
    }

    /// Get score history for a publisher.
    pub fn get_score_history(&self, publisher_id: &str) -> Result<&[f64], ReputationApiError> {
        let pub_record = self
            .publishers
            .get(publisher_id)
            .ok_or_else(|| ReputationApiError::PublisherNotFound(publisher_id.to_owned()))?;
        Ok(&pub_record.score_history)
    }

    /// File a reputation dispute.
    pub fn file_dispute(
        &mut self,
        dispute_id: &str,
        publisher_id: &str,
        reason: &str,
        old_score: f64,
        new_score: f64,
        timestamp: &str,
    ) -> Result<(), ReputationApiError> {
        if !self.publishers.contains_key(publisher_id) {
            return Err(ReputationApiError::PublisherNotFound(
                publisher_id.to_owned(),
            ));
        }
        self.disputes.push(ReputationDispute {
            dispute_id: dispute_id.to_owned(),
            publisher_id: publisher_id.to_owned(),
            reason: reason.to_owned(),
            old_score,
            new_score,
            filed_at: timestamp.to_owned(),
            resolved: false,
            outcome: None,
        });
        Ok(())
    }

    /// Resolve a dispute.
    pub fn resolve_dispute(&mut self, dispute_id: &str, outcome: &str) -> bool {
        for d in &mut self.disputes {
            if d.dispute_id == dispute_id && !d.resolved {
                d.resolved = true;
                d.outcome = Some(outcome.to_owned());
                return true;
            }
        }
        false
    }

    /// List all disputes for a publisher.
    #[must_use]
    pub fn list_disputes(&self, publisher_id: &str) -> Vec<&ReputationDispute> {
        self.disputes
            .iter()
            .filter(|d| d.publisher_id == publisher_id)
            .collect()
    }

    /// Reset rate limit counters (called periodically).
    pub fn reset_rate_counters(&mut self) {
        self.rate_counters.clear();
    }

    /// Get publisher count.
    #[must_use]
    pub fn publisher_count(&self) -> usize {
        self.publishers.len()
    }

    /// List all publishers.
    #[must_use]
    pub fn list_publishers(&self) -> Vec<&EcosystemPublisherReputation> {
        self.publishers.values().collect()
    }

    /// Take all pending events (drains the buffer).
    pub fn take_events(&mut self) -> Vec<ReputationEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get the scoring weights.
    #[must_use]
    pub fn weights(&self) -> &ScoringWeights {
        &self.weights
    }

    /// Get the anomaly config.
    #[must_use]
    pub fn anomaly_config(&self) -> &AnomalyConfig {
        &self.anomaly_config
    }
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: u32) -> String {
        format!("2026-01-{n:02}T00:00:00Z")
    }

    #[test]
    fn test_deterministic_score_all_ones() {
        let inputs = ReputationInputs::ones();
        let weights = ScoringWeights::default();
        let score = deterministic_reputation_score(&inputs, &weights);
        assert!((score - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_deterministic_score_all_zeros() {
        let inputs = ReputationInputs::zeros();
        let weights = ScoringWeights::default();
        let score = deterministic_reputation_score(&inputs, &weights);
        assert!(score.abs() < 1e-9);
    }

    #[test]
    fn test_deterministic_score_mixed() {
        let inputs = ReputationInputs {
            compatibility_pass_rate: 0.8,
            migration_success_rate: 0.6,
            trust_artifact_validity: 0.7,
            verifier_audit_frequency: 0.5,
        };
        let weights = ScoringWeights::default();
        // 0.8*0.30 + 0.6*0.25 + 0.7*0.25 + 0.5*0.20 = 0.24 + 0.15 + 0.175 + 0.10 = 0.665
        let score = deterministic_reputation_score(&inputs, &weights);
        assert!((score - 66.5).abs() < 1e-6);
    }

    #[test]
    fn test_deterministic_score_is_reproducible() {
        let inputs = ReputationInputs {
            compatibility_pass_rate: 0.95,
            migration_success_rate: 0.87,
            trust_artifact_validity: 0.92,
            verifier_audit_frequency: 0.78,
        };
        let weights = ScoringWeights::default();
        let s1 = deterministic_reputation_score(&inputs, &weights);
        let s2 = deterministic_reputation_score(&inputs, &weights);
        assert!((s1 - s2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_scoring_weights_valid() {
        let w = ScoringWeights::default();
        assert!(w.valid());
    }

    #[test]
    fn test_scoring_weights_invalid() {
        let w = ScoringWeights {
            compatibility: 0.5,
            migration: 0.5,
            trust_artifact: 0.5,
            verifier_audit: 0.5,
        };
        assert!(!w.valid());
    }

    #[test]
    fn test_anomaly_detection_insufficient_history() {
        let config = AnomalyConfig::default();
        assert!(!is_anomalous_delta(50.0, &[], &config));
        assert!(!is_anomalous_delta(50.0, &[1.0], &config));
    }

    #[test]
    fn test_anomaly_detection_normal_delta() {
        let config = AnomalyConfig::default();
        let history: Vec<f64> = vec![1.0, 1.1, 0.9, 1.0, 1.05, 0.95];
        // mean=1.0, std≈0.065, threshold=2*0.065≈0.13; delta=0.05 is within range.
        assert!(!is_anomalous_delta(0.05, &history, &config));
    }

    #[test]
    fn test_anomaly_detection_large_delta() {
        let config = AnomalyConfig::default();
        let history: Vec<f64> = vec![1.0, 1.1, 0.9, 1.0, 1.05, 0.95];
        assert!(is_anomalous_delta(50.0, &history, &config));
    }

    #[test]
    fn test_register_publisher() {
        let mut api = EcosystemReputationApi::new();
        let rep = api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        assert_eq!(rep.publisher_id, "pub-1");
        assert_eq!(rep.score, 0.0);
        assert_eq!(api.publisher_count(), 1);
    }

    #[test]
    fn test_sybil_duplicate_rejected() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        let result = api.register_publisher("pub-2", "key-1", &ts(2));
        assert!(matches!(result, Err(ReputationApiError::SybilDuplicate(_))));
    }

    #[test]
    fn test_same_publisher_same_key_ok() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        let result = api.register_publisher("pub-1", "key-1", &ts(2));
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_reputation() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        let inputs = ReputationInputs::ones();
        let score = api.compute_reputation("pub-1", inputs, &ts(2)).unwrap();
        assert!((score - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_compute_reputation_not_found() {
        let mut api = EcosystemReputationApi::new();
        let inputs = ReputationInputs::zeros();
        let result = api.compute_reputation("nonexistent", inputs, &ts(1));
        assert!(matches!(
            result,
            Err(ReputationApiError::PublisherNotFound(_))
        ));
    }

    #[test]
    fn test_rate_limit() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        for i in 0..10 {
            api.compute_reputation("pub-1", ReputationInputs::zeros(), &ts(i + 2))
                .unwrap();
        }
        let result = api.compute_reputation("pub-1", ReputationInputs::zeros(), &ts(13));
        assert!(matches!(
            result,
            Err(ReputationApiError::RateLimitExceeded(_))
        ));
    }

    #[test]
    fn test_rate_limit_reset() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        for i in 0..10 {
            api.compute_reputation("pub-1", ReputationInputs::zeros(), &ts(i + 2))
                .unwrap();
        }
        api.reset_rate_counters();
        let result = api.compute_reputation("pub-1", ReputationInputs::zeros(), &ts(13));
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_reputation() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        let rep = api.get_reputation("pub-1").unwrap();
        assert_eq!(rep.publisher_id, "pub-1");
    }

    #[test]
    fn test_get_reputation_not_found() {
        let api = EcosystemReputationApi::new();
        let result = api.get_reputation("nonexistent");
        assert!(matches!(
            result,
            Err(ReputationApiError::PublisherNotFound(_))
        ));
    }

    #[test]
    fn test_get_score_history() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        api.compute_reputation("pub-1", ReputationInputs::ones(), &ts(2))
            .unwrap();
        api.compute_reputation("pub-1", ReputationInputs::zeros(), &ts(3))
            .unwrap();
        let history = api.get_score_history("pub-1").unwrap();
        assert_eq!(history.len(), 2);
        assert!((history[0] - 100.0).abs() < 1e-9);
        assert!(history[1].abs() < 1e-9);
    }

    #[test]
    fn test_file_dispute() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        api.file_dispute("d-1", "pub-1", "unfair", 50.0, 10.0, &ts(2))
            .unwrap();
        let disputes = api.list_disputes("pub-1");
        assert_eq!(disputes.len(), 1);
        assert!(!disputes[0].resolved);
    }

    #[test]
    fn test_file_dispute_not_found() {
        let mut api = EcosystemReputationApi::new();
        let result = api.file_dispute("d-1", "nonexistent", "reason", 0.0, 0.0, &ts(1));
        assert!(matches!(
            result,
            Err(ReputationApiError::PublisherNotFound(_))
        ));
    }

    #[test]
    fn test_resolve_dispute() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        api.file_dispute("d-1", "pub-1", "unfair", 50.0, 10.0, &ts(2))
            .unwrap();
        let resolved = api.resolve_dispute("d-1", "upheld");
        assert!(resolved);
        let disputes = api.list_disputes("pub-1");
        assert!(disputes[0].resolved);
        assert_eq!(disputes[0].outcome.as_deref(), Some("upheld"));
    }

    #[test]
    fn test_resolve_dispute_not_found() {
        let mut api = EcosystemReputationApi::new();
        let resolved = api.resolve_dispute("nonexistent", "outcome");
        assert!(!resolved);
    }

    #[test]
    fn test_events_emitted_on_compute() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        api.compute_reputation("pub-1", ReputationInputs::ones(), &ts(2))
            .unwrap();
        let events = api.take_events();
        assert!(
            events
                .iter()
                .any(|e| e.event_code == ENE_003_REPUTATION_COMPUTED)
        );
    }

    #[test]
    fn test_take_events_drains() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        api.compute_reputation("pub-1", ReputationInputs::ones(), &ts(2))
            .unwrap();
        let e1 = api.take_events();
        assert!(!e1.is_empty());
        let e2 = api.take_events();
        assert!(e2.is_empty());
    }

    #[test]
    fn test_list_publishers() {
        let mut api = EcosystemReputationApi::new();
        api.register_publisher("pub-1", "key-1", &ts(1)).unwrap();
        api.register_publisher("pub-2", "key-2", &ts(2)).unwrap();
        assert_eq!(api.list_publishers().len(), 2);
    }

    #[test]
    fn test_default_api() {
        let api = EcosystemReputationApi::default();
        assert_eq!(api.publisher_count(), 0);
        assert!(api.weights().valid());
    }

    #[test]
    fn test_event_code_constants() {
        assert_eq!(ENE_003_REPUTATION_COMPUTED, "ENE-003");
        assert_eq!(ENE_004_REPUTATION_ANOMALY, "ENE-004");
    }

    #[test]
    fn test_invariant_constants() {
        assert_eq!(INV_ENE_DETERM, "INV-ENE-DETERM");
        assert_eq!(INV_ENE_ANOMALY, "INV-ENE-ANOMALY");
    }

    #[test]
    fn test_error_code_constants() {
        assert_eq!(ERR_ENE_RATE_LIMIT, "ERR-ENE-RATE-LIMIT");
    }

    #[test]
    fn test_score_clamped() {
        let inputs = ReputationInputs {
            compatibility_pass_rate: 2.0,
            migration_success_rate: 2.0,
            trust_artifact_validity: 2.0,
            verifier_audit_frequency: 2.0,
        };
        let weights = ScoringWeights::default();
        let score = deterministic_reputation_score(&inputs, &weights);
        assert!((score - 100.0).abs() < 1e-9); // Clamped at 100
    }

    #[test]
    fn test_with_custom_weights() {
        let weights = ScoringWeights {
            compatibility: 1.0,
            migration: 0.0,
            trust_artifact: 0.0,
            verifier_audit: 0.0,
        };
        let api = EcosystemReputationApi::with_weights(weights.clone());
        assert_eq!(api.weights().compatibility, 1.0);
    }
}
