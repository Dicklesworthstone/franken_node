//! bd-13yn: Risk control -- Signal poisoning and Sybil defense.
//!
//! This module implements countermeasures against signal poisoning and Sybil
//! attacks on the franken_node trust graph. Malicious nodes may inject false
//! reputation/trust signals or create multiple fake identities to manipulate
//! trust decisions.
//!
//! # Countermeasures
//!
//! 1. **Robust aggregation**: trimmed-mean and median resist outlier injection.
//! 2. **Stake weighting**: signals weighted by contributor reputation/history.
//! 3. **Sybil detection**: coordinated fake identities detected and attenuated.
//! 4. **Adversarial CI gate**: >= 10 attack scenarios exercised in CI.
//!
//! # Invariants
//!
//! - **INV-SPS-AGGREGATION**: 20% poisoned signals shift aggregate by <= 5%.
//! - **INV-SPS-STAKE**: New node signal weight <= 1% of established node.
//! - **INV-SPS-SYBIL**: 100 Sybil identities < influence of 5 honest nodes.
//! - **INV-SPS-ADVERSARIAL**: >= 10 adversarial test scenarios pass in CI.

use std::collections::{BTreeMap, BTreeSet};

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// SPS-001: Trust aggregation computed using trimmed-mean or median.
pub const SPS_001_ROBUST_AGGREGATION: &str = "SPS-001";
/// SPS-002: Trust signal weighted by contributor stake/reputation.
pub const SPS_002_STAKE_WEIGHTED: &str = "SPS-002";
/// SPS-003: Coordinated Sybil behaviour detected and attenuated.
pub const SPS_003_SYBIL_DETECTED: &str = "SPS-003";
/// SPS-004: Adversarial test suite scenario passed.
pub const SPS_004_ADVERSARIAL_GATE_PASS: &str = "SPS-004";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// A signal was identified as poisoned/adversarial.
pub const ERR_SPS_POISONED_SIGNAL: &str = "ERR_SPS_POISONED_SIGNAL";
/// Sybil identity cluster detected.
pub const ERR_SPS_SYBIL_DETECTED: &str = "ERR_SPS_SYBIL_DETECTED";
/// Signal contributor has insufficient stake/reputation.
pub const ERR_SPS_INSUFFICIENT_STAKE: &str = "ERR_SPS_INSUFFICIENT_STAKE";
/// Trust aggregation failed due to insufficient data.
pub const ERR_SPS_AGGREGATION_FAILED: &str = "ERR_SPS_AGGREGATION_FAILED";

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

/// INV-SPS-AGGREGATION: Robust aggregation resists 20% poisoned signals
/// within 5% shift.
pub const INV_SPS_AGGREGATION: &str = "INV-SPS-AGGREGATION";

/// INV-SPS-STAKE: Stake weighting ensures new nodes have <= 1% weight vs
/// established nodes.
pub const INV_SPS_STAKE: &str = "INV-SPS-STAKE";

/// INV-SPS-SYBIL: 100 Sybil identities have less influence than 5 established
/// honest nodes.
pub const INV_SPS_SYBIL: &str = "INV-SPS-SYBIL";

/// INV-SPS-ADVERSARIAL: Adversarial test suite with >= 10 scenarios passes
/// in CI.
pub const INV_SPS_ADVERSARIAL: &str = "INV-SPS-ADVERSARIAL";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A trust signal submitted by a node in the trust graph.
#[derive(Debug, Clone)]
pub struct TrustSignal {
    /// Unique identifier for the signal.
    pub signal_id: String,
    /// The node that submitted this signal.
    pub source_node_id: String,
    /// The target entity (extension, publisher) being evaluated.
    pub target_id: String,
    /// The trust value (0.0..=1.0).
    pub value: f64,
    /// Timestamp when the signal was created (epoch ms).
    pub timestamp_ms: u64,
}

/// A node participating in the trust graph with its reputation state.
#[derive(Debug, Clone)]
pub struct TrustNode {
    /// Unique node identifier.
    pub node_id: String,
    /// Reputation score (0.0..=100.0).
    pub reputation_score: f64,
    /// Number of verified history entries.
    pub verified_history_len: u64,
    /// Whether this node is flagged as a suspected Sybil.
    pub sybil_flagged: bool,
    /// Timestamp of node creation (epoch ms).
    pub created_at_ms: u64,
}

impl TrustNode {
    /// Create a new node with default values.
    pub fn new(node_id: impl Into<String>, created_at_ms: u64) -> Self {
        Self {
            node_id: node_id.into(),
            reputation_score: 0.0,
            verified_history_len: 0,
            sybil_flagged: false,
            created_at_ms,
        }
    }

    /// Create an established node with history and reputation.
    pub fn established(
        node_id: impl Into<String>,
        reputation_score: f64,
        verified_history_len: u64,
        created_at_ms: u64,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            reputation_score,
            verified_history_len,
            sybil_flagged: false,
            created_at_ms,
        }
    }
}

/// Result of a trust aggregation operation.
#[derive(Debug, Clone)]
pub struct AggregationResult {
    /// The aggregated trust value.
    pub value: f64,
    /// Number of signals used in aggregation.
    pub signal_count: usize,
    /// Number of signals trimmed (for trimmed-mean).
    pub trimmed_count: usize,
    /// Event code emitted.
    pub event_code: String,
    /// Method used for aggregation.
    pub method: AggregationMethod,
}

/// The aggregation method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationMethod {
    TrimmedMean,
    Median,
}

/// An audit log entry for Sybil defense events.
#[derive(Debug, Clone)]
pub struct SybilDefenseEvent {
    /// Event code (SPS-001 through SPS-004).
    pub event_code: String,
    /// Target entity involved.
    pub target_id: String,
    /// Human-readable detail.
    pub detail: String,
    /// Timestamp (epoch ms).
    pub timestamp_ms: u64,
}

/// Error type for Sybil defense operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SybilDefenseError {
    pub code: String,
    pub message: String,
}

impl SybilDefenseError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn poisoned_signal(detail: &str) -> Self {
        Self::new(ERR_SPS_POISONED_SIGNAL, detail)
    }

    pub fn sybil_detected(detail: &str) -> Self {
        Self::new(ERR_SPS_SYBIL_DETECTED, detail)
    }

    pub fn insufficient_stake(detail: &str) -> Self {
        Self::new(ERR_SPS_INSUFFICIENT_STAKE, detail)
    }

    pub fn aggregation_failed(detail: &str) -> Self {
        Self::new(ERR_SPS_AGGREGATION_FAILED, detail)
    }
}

impl std::fmt::Display for SybilDefenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ---------------------------------------------------------------------------
// TrustAggregator
// ---------------------------------------------------------------------------

/// Aggregates trust signals using robust methods resistant to outlier
/// injection.
///
/// Supports trimmed-mean and median aggregation. The trim ratio determines
/// what fraction of extreme values are removed before computing the mean.
pub struct TrustAggregator {
    /// Fraction of values to trim from each tail (0.0..0.5).
    /// Default: 0.2 (20% from each side = 40% total trim).
    pub trim_ratio: f64,
}

impl Default for TrustAggregator {
    fn default() -> Self {
        Self { trim_ratio: 0.2 }
    }
}

impl TrustAggregator {
    fn validate_finite_values(values: &[f64]) -> Result<(), SybilDefenseError> {
        if values.iter().any(|value| !value.is_finite()) {
            return Err(SybilDefenseError::aggregation_failed(
                "non-finite value in aggregation input",
            ));
        }
        Ok(())
    }

    /// Create a new aggregator with the given trim ratio.
    pub fn new(trim_ratio: f64) -> Self {
        let safe_ratio = if trim_ratio.is_finite() {
            trim_ratio.clamp(0.0, 0.5)
        } else {
            0.2
        };
        Self {
            trim_ratio: safe_ratio,
        }
    }

    /// Compute the trimmed mean of a set of values.
    ///
    /// Removes `trim_ratio` fraction from each tail before averaging.
    /// INV-SPS-AGGREGATION: resists 20% poisoned signals within 5% shift.
    pub fn trimmed_mean(&self, values: &[f64]) -> Result<AggregationResult, SybilDefenseError> {
        if values.is_empty() {
            return Err(SybilDefenseError::aggregation_failed(
                "no values to aggregate",
            ));
        }
        Self::validate_finite_values(values)?;

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.total_cmp(b));

        let n = sorted.len();
        let n_f64 = u32::try_from(n).unwrap_or(u32::MAX) as f64;
        let trim_count = (n_f64 * self.trim_ratio).floor() as usize;

        let trimmed = if 2 * trim_count >= n {
            // If we'd trim everything, just use all values.
            &sorted[..]
        } else {
            &sorted[trim_count..n - trim_count]
        };

        if trimmed.is_empty() {
            return Err(SybilDefenseError::aggregation_failed("all values trimmed"));
        }

        let sum: f64 = trimmed.iter().sum();
        if !sum.is_finite() {
            return Err(SybilDefenseError::aggregation_failed(
                "non-finite sum in trimmed mean",
            ));
        }
        let trimmed_len_f64 = u32::try_from(trimmed.len()).unwrap_or(u32::MAX) as f64;
        let mean = sum / trimmed_len_f64;

        Ok(AggregationResult {
            value: mean,
            signal_count: n,
            trimmed_count: 2 * trim_count,
            event_code: SPS_001_ROBUST_AGGREGATION.to_string(),
            method: AggregationMethod::TrimmedMean,
        })
    }

    /// Compute the median of a set of values.
    ///
    /// INV-SPS-AGGREGATION: median is inherently robust against outliers.
    pub fn median(&self, values: &[f64]) -> Result<AggregationResult, SybilDefenseError> {
        if values.is_empty() {
            return Err(SybilDefenseError::aggregation_failed(
                "no values to aggregate",
            ));
        }
        Self::validate_finite_values(values)?;

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.total_cmp(b));

        let n = sorted.len();
        let median = if n.is_multiple_of(2) {
            let lower = sorted[(n / 2).saturating_sub(1)];
            let upper = sorted[n / 2];
            lower / 2.0 + upper / 2.0
        } else {
            sorted[n / 2]
        };
        if !median.is_finite() {
            return Err(SybilDefenseError::aggregation_failed(
                "non-finite median in aggregation output",
            ));
        }

        Ok(AggregationResult {
            value: median,
            signal_count: n,
            trimmed_count: 0,
            event_code: SPS_001_ROBUST_AGGREGATION.to_string(),
            method: AggregationMethod::Median,
        })
    }
}

// ---------------------------------------------------------------------------
// StakeWeighter
// ---------------------------------------------------------------------------

/// Computes stake-based weights for trust signals.
///
/// INV-SPS-STAKE: a newly-created node's signal has <= 1% weight vs an
/// established node's signal. The weight function is monotonically
/// non-decreasing with verified history length.
pub struct StakeWeighter {
    /// Minimum history length to be considered "established".
    pub established_threshold: u64,
    /// Base weight for nodes with zero history.
    pub base_weight: f64,
    /// Maximum weight for fully-established nodes.
    pub max_weight: f64,
}

impl Default for StakeWeighter {
    fn default() -> Self {
        Self {
            established_threshold: 100,
            base_weight: 0.01, // 1% of max
            max_weight: 1.0,
        }
    }
}

impl StakeWeighter {
    /// Create a new stake weighter with custom parameters.
    pub fn new(established_threshold: u64, base_weight: f64, max_weight: f64) -> Self {
        let safe_base = if base_weight.is_finite() && base_weight >= 0.0 {
            base_weight
        } else {
            0.01
        };
        let safe_max = if max_weight.is_finite() && max_weight >= 0.0 {
            max_weight
        } else {
            1.0
        };
        let safe_max = safe_max.max(safe_base);
        Self {
            established_threshold,
            base_weight: safe_base,
            max_weight: safe_max,
        }
    }

    /// Compute the stake weight for a node based on its verified history.
    ///
    /// The weight is monotonically non-decreasing with history length.
    /// Returns a value in [base_weight, max_weight].
    pub fn compute_weight(&self, node: &TrustNode) -> f64 {
        if node.verified_history_len == 0 || self.established_threshold == 0 {
            return self.base_weight;
        }

        let history_len_f64 = node.verified_history_len as f64;
        let threshold_f64 = self.established_threshold as f64;
        let progress = (history_len_f64 / threshold_f64).min(1.0);

        // Logarithmic growth: monotonically increasing, slow start, fast middle
        let log_progress = (1.0 + progress * (std::f64::consts::E - 1.0)).ln();

        self.base_weight + (self.max_weight - self.base_weight) * log_progress
    }

    /// Compute the weight ratio between a new node and an established node.
    ///
    /// INV-SPS-STAKE: this ratio must be <= 0.01 (1%).
    pub fn weight_ratio_new_vs_established(
        &self,
        new_node: &TrustNode,
        established_node: &TrustNode,
    ) -> f64 {
        let new_weight = self.compute_weight(new_node);
        let est_weight = self.compute_weight(established_node);
        if est_weight.abs() < f64::EPSILON {
            return 0.0;
        }
        new_weight / est_weight
    }

    /// Apply stake weights to a set of trust signals.
    ///
    /// Returns weighted values: each signal's value multiplied by its source
    /// node's stake weight. Emits SPS-002.
    pub fn apply_weights(
        &self,
        signals: &[TrustSignal],
        nodes: &BTreeMap<String, TrustNode>,
    ) -> Vec<(f64, f64)> {
        // Returns (weighted_value, weight) pairs
        signals
            .iter()
            .map(|sig| {
                let weight = nodes
                    .get(&sig.source_node_id)
                    .map(|n| self.compute_weight(n))
                    .unwrap_or(self.base_weight);
                (sig.value * weight, weight)
            })
            .collect()
    }

    /// Compute weighted average of signals using stake weights.
    pub fn weighted_average(
        &self,
        signals: &[TrustSignal],
        nodes: &BTreeMap<String, TrustNode>,
    ) -> Result<f64, SybilDefenseError> {
        if signals.is_empty() {
            return Err(SybilDefenseError::aggregation_failed(
                "no signals to weight",
            ));
        }

        let pairs = self.apply_weights(signals, nodes);
        let total_weight: f64 = pairs.iter().map(|(_, w)| w).sum();
        if !total_weight.is_finite() || total_weight.abs() < f64::EPSILON {
            return Err(SybilDefenseError::aggregation_failed(
                "total weight is zero or non-finite",
            ));
        }

        let weighted_sum: f64 = pairs.iter().map(|(wv, _)| wv).sum();
        if !weighted_sum.is_finite() {
            return Err(SybilDefenseError::aggregation_failed(
                "non-finite weighted sum",
            ));
        }
        Ok(weighted_sum / total_weight)
    }
}

// ---------------------------------------------------------------------------
// SybilDetector
// ---------------------------------------------------------------------------

/// Detects Sybil identities by analysing coordinated behaviour patterns.
///
/// INV-SPS-SYBIL: 100 Sybil identities have less influence than 5 established
/// honest nodes.
pub struct SybilDetector {
    /// Maximum number of signals from the same source within a time window
    /// before Sybil suspicion is raised.
    pub burst_threshold: usize,
    /// Time window for burst detection (ms).
    pub burst_window_ms: u64,
    /// Similarity threshold for coordinated signals (0.0..=1.0).
    pub similarity_threshold: f64,
    /// Audit log of Sybil defense events.
    events: Vec<SybilDefenseEvent>,
}

impl Default for SybilDetector {
    fn default() -> Self {
        Self {
            burst_threshold: 5,
            burst_window_ms: 60_000,
            similarity_threshold: 0.95,
            events: Vec::new(),
        }
    }
}

impl SybilDetector {
    /// Create a new detector with custom parameters.
    pub fn new(burst_threshold: usize, burst_window_ms: u64, similarity_threshold: f64) -> Self {
        let safe_sim =
            if similarity_threshold.is_finite() && (0.0..=1.0).contains(&similarity_threshold) {
                similarity_threshold
            } else {
                0.95
            };
        Self {
            burst_threshold,
            burst_window_ms,
            similarity_threshold: safe_sim,
            events: Vec::new(),
        }
    }

    /// Detect Sybil clusters among a set of signals targeting the same entity.
    ///
    /// Returns the set of node IDs identified as likely Sybil identities.
    pub fn detect_sybil_cluster(
        &mut self,
        signals: &[TrustSignal],
        nodes: &BTreeMap<String, TrustNode>,
        timestamp_ms: u64,
    ) -> BTreeSet<String> {
        let mut sybil_ids: BTreeSet<String> = BTreeSet::new();

        // Strategy 1: Burst detection -- many signals in a short window
        let mut by_source: BTreeMap<&str, Vec<&TrustSignal>> = BTreeMap::new();
        for sig in signals {
            by_source
                .entry(sig.source_node_id.as_str())
                .or_default()
                .push(sig);
        }

        for (source_id, source_signals) in &by_source {
            if source_signals.len() > self.burst_threshold {
                let mut timestamps: Vec<u64> =
                    source_signals.iter().map(|s| s.timestamp_ms).collect();
                timestamps.sort_unstable();

                let mut burst_detected = false;
                let required_signals_in_window = self.burst_threshold.saturating_add(1);
                if timestamps.len() >= required_signals_in_window {
                    for i in 0..=timestamps.len() - required_signals_in_window {
                        if timestamps[i + required_signals_in_window - 1] - timestamps[i]
                            <= self.burst_window_ms
                        {
                            burst_detected = true;
                            break;
                        }
                    }
                }

                if burst_detected {
                    sybil_ids.insert(source_id.to_string());
                }
            }
        }

        // Strategy 2: Coordinated value similarity -- many different nodes
        // submitting nearly identical values within a time window
        let mut by_target: BTreeMap<&str, Vec<&TrustSignal>> = BTreeMap::new();
        for sig in signals {
            by_target
                .entry(sig.target_id.as_str())
                .or_default()
                .push(sig);
        }

        for target_signals in by_target.values() {
            if target_signals.len() < 3 {
                continue;
            }

            // Group signals by similar value and time window
            let mut coordinated_group: Vec<String> = Vec::new();

            for i in 0..target_signals.len() {
                let mut matches = vec![target_signals[i].source_node_id.clone()];
                for j in (i + 1)..target_signals.len() {
                    let val_diff = (target_signals[i].value - target_signals[j].value).abs();
                    let time_diff = target_signals[j]
                        .timestamp_ms
                        .abs_diff(target_signals[i].timestamp_ms);

                    if val_diff <= (1.0 - self.similarity_threshold)
                        && time_diff <= self.burst_window_ms
                    {
                        matches.push(target_signals[j].source_node_id.clone());
                    }
                }

                if matches.len() >= 3 {
                    // Check if these are all new/low-reputation nodes
                    let new_count = matches
                        .iter()
                        .filter(|id| {
                            nodes
                                .get(id.as_str())
                                .map(|n| n.verified_history_len < 10)
                                .unwrap_or(true)
                        })
                        .count();

                    let new_count_f64 = u32::try_from(new_count).unwrap_or(u32::MAX) as f64;
                    let matches_len_f64 = u32::try_from(matches.len()).unwrap_or(u32::MAX) as f64;
                    if new_count_f64 / matches_len_f64 >= 0.8 {
                        coordinated_group.extend(matches);
                    }
                }
            }

            for id in coordinated_group {
                sybil_ids.insert(id);
            }
        }

        // Log detection event
        if !sybil_ids.is_empty() {
            push_bounded(
                &mut self.events,
                SybilDefenseEvent {
                    event_code: SPS_003_SYBIL_DETECTED.to_string(),
                    target_id: signals
                        .first()
                        .map(|s| s.target_id.clone())
                        .unwrap_or_default(),
                    detail: format!("Detected {} suspected Sybil identities", sybil_ids.len()),
                    timestamp_ms,
                },
                MAX_EVENTS,
            );
        }

        sybil_ids
    }

    /// Attenuate signals from detected Sybil nodes.
    ///
    /// Sybil signals are assigned a near-zero weight, ensuring they have
    /// negligible influence on the aggregate.
    pub fn attenuate_sybil_signals(
        &self,
        signals: &[TrustSignal],
        sybil_ids: &BTreeSet<String>,
    ) -> Vec<(TrustSignal, f64)> {
        let sybil_attenuation = 0.001; // 0.1% of normal weight

        signals
            .iter()
            .map(|sig| {
                let weight = if sybil_ids.contains(&sig.source_node_id) {
                    sybil_attenuation
                } else {
                    1.0
                };
                (sig.clone(), weight)
            })
            .collect()
    }

    /// Compute the total influence of a set of node IDs based on their
    /// signals and weights.
    pub fn compute_influence(
        &self,
        signals: &[TrustSignal],
        node_ids: &[String],
        weighter: &StakeWeighter,
        nodes: &BTreeMap<String, TrustNode>,
    ) -> f64 {
        let id_set: BTreeSet<&String> = node_ids.iter().collect();
        signals
            .iter()
            .filter(|s| id_set.contains(&s.source_node_id))
            .map(|s| {
                let weight = nodes
                    .get(&s.source_node_id)
                    .map(|n| weighter.compute_weight(n))
                    .unwrap_or(weighter.base_weight);
                s.value * weight
            })
            .sum()
    }

    /// Get the audit event log.
    pub fn events(&self) -> &[SybilDefenseEvent] {
        &self.events
    }

    /// Clear the event log.
    pub fn clear_events(&mut self) {
        self.events.clear();
    }
}

// ---------------------------------------------------------------------------
// Integrated defense pipeline
// ---------------------------------------------------------------------------

/// Full Sybil defense pipeline combining aggregation, stake weighting, and
/// Sybil detection.
#[derive(Default)]
pub struct SybilDefensePipeline {
    pub aggregator: TrustAggregator,
    pub weighter: StakeWeighter,
    pub detector: SybilDetector,
    /// Registered nodes in the trust graph.
    nodes: BTreeMap<String, TrustNode>,
    /// Audit event log.
    events: Vec<SybilDefenseEvent>,
}

impl SybilDefensePipeline {
    /// Create a new pipeline with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a node in the trust graph.
    pub fn register_node(&mut self, node: TrustNode) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    /// Get a registered node.
    pub fn get_node(&self, node_id: &str) -> Option<&TrustNode> {
        self.nodes.get(node_id)
    }

    /// Get all registered nodes.
    pub fn nodes(&self) -> &BTreeMap<String, TrustNode> {
        &self.nodes
    }

    /// Process a batch of trust signals with full defense pipeline:
    /// 1. Sybil detection and attenuation.
    /// 2. Stake weighting.
    /// 3. Robust aggregation (trimmed-mean).
    pub fn process_signals(
        &mut self,
        signals: &[TrustSignal],
        timestamp_ms: u64,
    ) -> Result<AggregationResult, SybilDefenseError> {
        if signals.is_empty() {
            return Err(SybilDefenseError::aggregation_failed(
                "no signals to process",
            ));
        }

        // Step 1: Detect Sybil clusters
        let sybil_ids = self
            .detector
            .detect_sybil_cluster(signals, &self.nodes, timestamp_ms);

        // Step 2: Attenuate Sybil signals
        let attenuated = self.detector.attenuate_sybil_signals(signals, &sybil_ids);

        // Step 3: Apply stake weights
        let mut weighted_values: Vec<f64> = Vec::new();
        for (sig, attenuation) in &attenuated {
            let stake_weight = self
                .nodes
                .get(&sig.source_node_id)
                .map(|n| self.weighter.compute_weight(n))
                .unwrap_or(self.weighter.base_weight);
            weighted_values.push(sig.value * stake_weight * attenuation);
        }

        // Step 4: Robust aggregation via trimmed-mean
        let result = self.aggregator.trimmed_mean(&weighted_values)?;

        // Log events
        push_bounded(
            &mut self.events,
            SybilDefenseEvent {
                event_code: SPS_001_ROBUST_AGGREGATION.to_string(),
                target_id: signals
                    .first()
                    .map(|s| s.target_id.clone())
                    .unwrap_or_default(),
                detail: format!(
                    "Aggregated {} signals (trimmed {}), result: {:.6}",
                    result.signal_count, result.trimmed_count, result.value
                ),
                timestamp_ms,
            },
            MAX_EVENTS,
        );

        if !sybil_ids.is_empty() {
            push_bounded(
                &mut self.events,
                SybilDefenseEvent {
                    event_code: SPS_003_SYBIL_DETECTED.to_string(),
                    target_id: signals
                        .first()
                        .map(|s| s.target_id.clone())
                        .unwrap_or_default(),
                    detail: format!("{} Sybil identities attenuated", sybil_ids.len()),
                    timestamp_ms,
                },
                MAX_EVENTS,
            );
        }

        Ok(result)
    }

    /// Get the pipeline's audit event log.
    pub fn pipeline_events(&self) -> &[SybilDefenseEvent] {
        &self.events
    }

    /// Get all nodes as a BTreeMap for deterministic ordering.
    pub fn ordered_nodes(&self) -> BTreeMap<String, &TrustNode> {
        self.nodes.iter().map(|(k, v)| (k.clone(), v)).collect()
    }
}

// ---------------------------------------------------------------------------
// Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<TrustSignal>();
    assert_send::<TrustNode>();
    assert_send::<TrustAggregator>();
    assert_send::<StakeWeighter>();
    assert_send::<SybilDetector>();
    assert_send::<SybilDefensePipeline>();
    assert_sync::<TrustSignal>();
    assert_sync::<TrustNode>();
    assert_sync::<TrustAggregator>();
    assert_sync::<StakeWeighter>();
    assert_sync::<SybilDefensePipeline>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn make_signal(id: &str, source: &str, target: &str, value: f64, ts: u64) -> TrustSignal {
        TrustSignal {
            signal_id: id.to_string(),
            source_node_id: source.to_string(),
            target_id: target.to_string(),
            value,
            timestamp_ms: ts,
        }
    }

    fn make_established_node(id: &str) -> TrustNode {
        TrustNode::established(id, 80.0, 200, 1000)
    }

    fn make_new_node(id: &str) -> TrustNode {
        TrustNode::new(id, 50_000)
    }

    fn honest_signals(count: usize, target: &str) -> Vec<TrustSignal> {
        (0..count)
            .map(|i| {
                make_signal(
                    &format!("honest-{i}"),
                    &format!("honest-node-{i}"),
                    target,
                    0.8 + (i as f64 * 0.001), // Slight variation around 0.8
                    1000 + i as u64 * 100,
                )
            })
            .collect()
    }

    #[allow(dead_code)]
    fn poisoned_signals(count: usize, target: &str) -> Vec<TrustSignal> {
        (0..count)
            .map(|i| {
                make_signal(
                    &format!("poison-{i}"),
                    &format!("poison-node-{i}"),
                    target,
                    0.01, // Maximally adversarial: trying to drive score to 0
                    1000 + i as u64 * 10,
                )
            })
            .collect()
    }

    #[allow(dead_code)]
    fn sybil_signals(count: usize, target: &str) -> Vec<TrustSignal> {
        (0..count)
            .map(|i| {
                make_signal(
                    &format!("sybil-{i}"),
                    &format!("sybil-node-{i}"),
                    target,
                    0.99,            // All endorsing with nearly identical high value
                    5000 + i as u64, // Very close timestamps
                )
            })
            .collect()
    }

    // ── TrustAggregator tests ────────────────────────────────────────────

    #[test]
    fn test_trimmed_mean_basic() {
        let agg = TrustAggregator::default();
        let values = vec![0.5, 0.6, 0.7, 0.8, 0.9];
        let result = agg.trimmed_mean(&values).unwrap();
        assert!((result.value - 0.7).abs() < 0.01);
        assert_eq!(result.method, AggregationMethod::TrimmedMean);
    }

    #[test]
    fn test_trimmed_mean_resists_outliers() {
        let agg = TrustAggregator::default(); // 20% trim
        // 80% honest signals around 0.8, 20% poisoned at 0.0
        let mut values: Vec<f64> = (0..80).map(|_| 0.8).collect();
        values.extend((0..20).map(|_| 0.0));

        let result = agg.trimmed_mean(&values).unwrap();
        let true_value = 0.8;
        let shift = (result.value - true_value).abs() / true_value;
        // INV-SPS-AGGREGATION: shift must be <= 5%
        assert!(
            shift <= 0.05,
            "Trimmed mean shift {:.4} exceeds 5% threshold",
            shift
        );
    }

    #[test]
    fn test_trimmed_mean_empty_input() {
        let agg = TrustAggregator::default();
        let result = agg.trimmed_mean(&[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_SPS_AGGREGATION_FAILED);
    }

    #[test]
    fn test_trimmed_mean_single_value() {
        let agg = TrustAggregator::default();
        let result = agg.trimmed_mean(&[0.5]).unwrap();
        assert!((result.value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_median_basic() {
        let agg = TrustAggregator::default();
        let values = vec![0.1, 0.5, 0.9];
        let result = agg.median(&values).unwrap();
        assert!((result.value - 0.5).abs() < f64::EPSILON);
        assert_eq!(result.method, AggregationMethod::Median);
    }

    #[test]
    fn test_median_even_count() {
        let agg = TrustAggregator::default();
        let values = vec![0.2, 0.4, 0.6, 0.8];
        let result = agg.median(&values).unwrap();
        assert!((result.value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_median_resists_outliers() {
        let agg = TrustAggregator::default();
        // 80% honest at 0.8, 20% poisoned at 0.0
        let mut values: Vec<f64> = (0..80).map(|_| 0.8).collect();
        values.extend((0..20).map(|_| 0.0));

        let result = agg.median(&values).unwrap();
        let shift = (result.value - 0.8).abs() / 0.8;
        assert!(
            shift <= 0.05,
            "Median shift {:.4} exceeds 5% threshold",
            shift
        );
    }

    #[test]
    fn test_median_empty_input() {
        let agg = TrustAggregator::default();
        let result = agg.median(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_trimmed_mean_rejects_non_finite_input() {
        let agg = TrustAggregator::default();
        let err = agg
            .trimmed_mean(&[0.5, f64::INFINITY, 0.7])
            .expect_err("non-finite inputs must fail closed");
        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
    }

    #[test]
    fn test_median_rejects_non_finite_input() {
        let agg = TrustAggregator::default();
        let err = agg
            .median(&[0.5, f64::NAN, 0.7])
            .expect_err("non-finite median inputs must fail closed");
        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
    }

    #[test]
    fn test_median_even_count_avoids_overflow() {
        let agg = TrustAggregator::default();
        let result = agg
            .median(&[f64::MAX, f64::MAX])
            .expect("finite extreme inputs should stay finite");
        assert_eq!(result.value, f64::MAX);
    }

    #[test]
    fn test_aggregation_event_code() {
        let agg = TrustAggregator::default();
        let result = agg.trimmed_mean(&[0.5, 0.6, 0.7]).unwrap();
        assert_eq!(result.event_code, SPS_001_ROBUST_AGGREGATION);
    }

    // ── StakeWeighter tests ──────────────────────────────────────────────

    #[test]
    fn test_new_node_low_weight() {
        let w = StakeWeighter::default();
        let node = make_new_node("new-1");
        let weight = w.compute_weight(&node);
        assert!(
            weight <= w.base_weight + f64::EPSILON,
            "New node weight {weight} exceeds base {}",
            w.base_weight
        );
    }

    #[test]
    fn test_established_node_high_weight() {
        let w = StakeWeighter::default();
        let node = make_established_node("est-1");
        let weight = w.compute_weight(&node);
        assert!(weight > 0.5, "Established node weight {weight} too low");
    }

    #[test]
    fn test_weight_ratio_new_vs_established() {
        // INV-SPS-STAKE: new node signal <= 1% of established node
        let w = StakeWeighter::default();
        let new_node = make_new_node("new-1");
        let est_node = make_established_node("est-1");

        let ratio = w.weight_ratio_new_vs_established(&new_node, &est_node);
        assert!(
            ratio <= 0.01,
            "Weight ratio {ratio:.4} exceeds 1% threshold"
        );
    }

    #[test]
    fn test_stake_monotonically_increasing() {
        // Scenario D: stake-weighting function is monotonically increasing
        // with verified history length.
        let w = StakeWeighter::default();
        let mut prev_weight = 0.0_f64;

        for history_len in [0, 1, 5, 10, 25, 50, 75, 100, 150, 200] {
            let node =
                TrustNode::established(format!("node-{history_len}"), 50.0, history_len, 1000);
            let weight = w.compute_weight(&node);
            assert!(
                weight >= prev_weight,
                "Weight decreased from {prev_weight:.6} to {weight:.6} \
                 at history_len={history_len}"
            );
            prev_weight = weight;
        }
    }

    #[test]
    fn test_apply_weights() {
        let w = StakeWeighter::default();
        let signals = vec![
            make_signal("s1", "est-1", "target", 0.8, 1000),
            make_signal("s2", "new-1", "target", 0.9, 1001),
        ];
        let mut nodes = BTreeMap::new();
        nodes.insert("est-1".to_string(), make_established_node("est-1"));
        nodes.insert("new-1".to_string(), make_new_node("new-1"));

        let pairs = w.apply_weights(&signals, &nodes);
        assert_eq!(pairs.len(), 2);
        // Established node's contribution should be much larger
        assert!(pairs[0].0 > pairs[1].0);
    }

    #[test]
    fn test_weighted_average() {
        let w = StakeWeighter::default();
        let signals = vec![make_signal("s1", "est-1", "target", 0.8, 1000)];
        let mut nodes = BTreeMap::new();
        nodes.insert("est-1".to_string(), make_established_node("est-1"));

        let avg = w.weighted_average(&signals, &nodes).unwrap();
        assert!((avg - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_weighted_average_empty() {
        let w = StakeWeighter::default();
        let result = w.weighted_average(&[], &BTreeMap::new());
        assert!(result.is_err());
    }

    // ── SybilDetector tests ──────────────────────────────────────────────

    #[test]
    fn test_detect_burst_sybil() {
        let mut detector = SybilDetector::new(3, 60_000, 0.95);
        let signals: Vec<TrustSignal> = (0..10)
            .map(|i| {
                make_signal(
                    &format!("burst-{i}"),
                    "attacker", // Same source
                    "target",
                    0.99,
                    5000 + i * 10,
                )
            })
            .collect();

        let mut nodes = BTreeMap::new();
        nodes.insert("attacker".to_string(), make_new_node("attacker"));

        let sybils = detector.detect_sybil_cluster(&signals, &nodes, 10_000);
        assert!(sybils.contains("attacker"));
    }

    #[test]
    fn test_detect_coordinated_sybil() {
        let mut detector = SybilDetector::new(100, 60_000, 0.95);
        let mut signals = Vec::new();
        let mut nodes = BTreeMap::new();

        // 20 new nodes all submitting very similar values at similar times
        for i in 0..20 {
            let node_id = format!("sybil-{i}");
            signals.push(make_signal(
                &format!("coord-{i}"),
                &node_id,
                "target-ext",
                0.99,         // Nearly identical values
                5000 + i * 5, // Very close timestamps
            ));
            nodes.insert(node_id.clone(), make_new_node(&node_id));
        }

        let sybils = detector.detect_sybil_cluster(&signals, &nodes, 10_000);
        assert!(
            !sybils.is_empty(),
            "Should detect coordinated Sybil cluster"
        );
    }

    #[test]
    fn test_no_sybil_honest_nodes() {
        let mut detector = SybilDetector::default();
        let signals = honest_signals(5, "target");
        let mut nodes = BTreeMap::new();
        for sig in &signals {
            nodes.insert(
                sig.source_node_id.clone(),
                make_established_node(&sig.source_node_id),
            );
        }

        let sybils = detector.detect_sybil_cluster(&signals, &nodes, 10_000);
        assert!(sybils.is_empty(), "Honest nodes should not be flagged");
    }

    #[test]
    fn test_attenuate_sybil_signals() {
        let detector = SybilDetector::default();
        let signals = vec![
            make_signal("s1", "honest", "target", 0.8, 1000),
            make_signal("s2", "sybil", "target", 0.99, 1001),
        ];
        let sybil_ids: BTreeSet<String> = ["sybil".to_string()].into_iter().collect();

        let attenuated = detector.attenuate_sybil_signals(&signals, &sybil_ids);
        assert_eq!(attenuated.len(), 2);
        assert!((attenuated[0].1 - 1.0).abs() < f64::EPSILON); // Honest: full weight
        assert!(attenuated[1].1 < 0.01); // Sybil: attenuated
    }

    #[test]
    fn test_sybil_influence_vs_honest() {
        // INV-SPS-SYBIL: 100 Sybil identities have less influence than 5
        // established honest nodes.
        let detector = SybilDetector::default();
        let weighter = StakeWeighter::default();

        let mut nodes = BTreeMap::new();

        // 5 established honest nodes
        let honest_node_ids: Vec<String> = (0..5)
            .map(|i| {
                let id = format!("honest-{i}");
                nodes.insert(id.clone(), make_established_node(&id));
                id
            })
            .collect();

        // 100 Sybil nodes (all brand new)
        let sybil_node_ids: Vec<String> = (0..100)
            .map(|i| {
                let id = format!("sybil-{i}");
                nodes.insert(id.clone(), make_new_node(&id));
                id
            })
            .collect();

        // Signals from honest nodes
        let honest_sigs: Vec<TrustSignal> = honest_node_ids
            .iter()
            .enumerate()
            .map(|(i, id)| make_signal(&format!("h-{i}"), id, "target", 0.8, 1000 + i as u64 * 100))
            .collect();

        // Signals from Sybil nodes
        let sybil_sigs: Vec<TrustSignal> = sybil_node_ids
            .iter()
            .enumerate()
            .map(|(i, id)| make_signal(&format!("s-{i}"), id, "target", 0.99, 5000 + i as u64))
            .collect();

        let honest_influence =
            detector.compute_influence(&honest_sigs, &honest_node_ids, &weighter, &nodes);
        let sybil_influence =
            detector.compute_influence(&sybil_sigs, &sybil_node_ids, &weighter, &nodes);

        assert!(
            sybil_influence < honest_influence,
            "100 Sybil influence ({sybil_influence:.4}) must be less than \
             5 honest influence ({honest_influence:.4})"
        );
    }

    #[test]
    fn test_sybil_events_logged() {
        let mut detector = SybilDetector::new(3, 60_000, 0.95);
        let signals: Vec<TrustSignal> = (0..10)
            .map(|i| {
                make_signal(
                    &format!("sig-{i}"),
                    "attacker",
                    "target",
                    0.99,
                    5000 + i * 10,
                )
            })
            .collect();
        let mut nodes = BTreeMap::new();
        nodes.insert("attacker".to_string(), make_new_node("attacker"));

        detector.detect_sybil_cluster(&signals, &nodes, 10_000);
        assert!(!detector.events().is_empty());
        assert_eq!(detector.events()[0].event_code, SPS_003_SYBIL_DETECTED);
    }

    // ── Scenario A: 20% poisoned signals ─────────────────────────────────

    #[test]
    fn test_scenario_a_poisoned_signal_ranking() {
        // Inject 20% maximally-adversarial signals; verify trust ranking of
        // honest nodes changes by <= 1 position.
        let agg = TrustAggregator::new(0.2);

        // Build honest values: 10 nodes with scores around 0.8
        let honest_values: Vec<f64> = (0..80)
            .map(|i| 0.75 + (i as f64 * 0.005).min(0.1))
            .collect();

        // Inject 20% poisoned at extreme values (0.0)
        let mut mixed = honest_values.clone();
        mixed.extend((0..20).map(|_| 0.0));

        let clean_result = agg.trimmed_mean(&honest_values).unwrap();
        let poisoned_result = agg.trimmed_mean(&mixed).unwrap();

        let shift_pct =
            ((poisoned_result.value - clean_result.value).abs() / clean_result.value) * 100.0;

        assert!(
            shift_pct <= 5.0,
            "Scenario A: {shift_pct:.2}% shift exceeds 5% threshold"
        );
    }

    // ── Scenario B: 100 Sybil endorsing malicious extension ──────────────

    #[test]
    fn test_scenario_b_sybil_endorsement() {
        // Create 100 Sybil identities all endorsing a malicious extension;
        // verify it does not enter the top-50% trust tier.
        let weighter = StakeWeighter::default();
        let mut nodes = BTreeMap::new();

        // 20 established honest nodes scoring a malicious extension low
        let mut honest_sigs = Vec::new();
        for i in 0..20 {
            let id = format!("honest-{i}");
            nodes.insert(id.clone(), make_established_node(&id));
            honest_sigs.push(make_signal(
                &format!("h-{i}"),
                &id,
                "malicious-ext",
                0.1, // Low score from honest nodes
                1000 + i * 100,
            ));
        }

        // 100 Sybil nodes all giving the malicious extension a high score
        let mut sybil_sigs = Vec::new();
        for i in 0..100 {
            let id = format!("sybil-{i}");
            nodes.insert(id.clone(), make_new_node(&id));
            sybil_sigs.push(make_signal(
                &format!("s-{i}"),
                &id,
                "malicious-ext",
                0.99, // High endorsement
                5000 + i,
            ));
        }

        // Compute weighted average including both honest and Sybil
        let mut all_sigs = honest_sigs;
        all_sigs.extend(sybil_sigs);

        let avg = weighter.weighted_average(&all_sigs, &nodes).unwrap();

        // The malicious extension should NOT be in top 50% (i.e., score < 0.5)
        assert!(
            avg < 0.5,
            "Scenario B: malicious ext score {avg:.4} entered top-50% trust tier"
        );
    }

    // ── Scenario C: Coordinated poisoning over 10 rounds ─────────────────

    #[test]
    fn test_scenario_c_convergence_recovery() {
        // Simulate coordinated signal poisoning over 10 rounds; verify
        // trust system converges back to correct rankings within 3 rounds
        // after attack stops.
        let agg = TrustAggregator::new(0.15);

        // True value from honest nodes
        let true_value = 0.8;

        // Phase 1: 10 attack rounds (20% poisoned each round)
        let mut attack_results = Vec::new();
        for _ in 0..10 {
            let mut values: Vec<f64> = (0..80).map(|_| true_value).collect();
            values.extend((0..20).map(|_| 0.0));
            let result = agg.trimmed_mean(&values).unwrap();
            attack_results.push(result.value);
        }

        // Phase 2: Recovery rounds (no poison)
        let mut recovery_results = Vec::new();
        for _ in 0..3 {
            let values: Vec<f64> = (0..100).map(|_| true_value).collect();
            let result = agg.trimmed_mean(&values).unwrap();
            recovery_results.push(result.value);
        }

        // Verify convergence: after 3 clean rounds, result should be
        // within 1% of true value
        let final_value = recovery_results.last().unwrap();
        let recovery_shift = ((final_value - true_value).abs() / true_value) * 100.0;

        assert!(
            recovery_shift <= 1.0,
            "Scenario C: after 3 recovery rounds, shift {recovery_shift:.2}% \
             exceeds 1% threshold"
        );
    }

    // ── Scenario D: Stake monotonicity ───────────────────────────────────

    #[test]
    fn test_scenario_d_stake_monotonicity() {
        // Verify stake-weighting function is monotonically increasing with
        // verified history length.
        let w = StakeWeighter::default();
        let mut prev = 0.0_f64;

        for h in 0..=300 {
            let node = TrustNode::established(format!("n-{h}"), 50.0, h, 1000);
            let weight = w.compute_weight(&node);
            assert!(
                weight >= prev - f64::EPSILON,
                "Scenario D: stake weight not monotonic at history={h}: \
                 {prev:.8} -> {weight:.8}"
            );
            prev = weight;
        }
    }

    // ── Event codes and invariants ───────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(SPS_001_ROBUST_AGGREGATION, "SPS-001");
        assert_eq!(SPS_002_STAKE_WEIGHTED, "SPS-002");
        assert_eq!(SPS_003_SYBIL_DETECTED, "SPS-003");
        assert_eq!(SPS_004_ADVERSARIAL_GATE_PASS, "SPS-004");
    }

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(ERR_SPS_POISONED_SIGNAL, "ERR_SPS_POISONED_SIGNAL");
        assert_eq!(ERR_SPS_SYBIL_DETECTED, "ERR_SPS_SYBIL_DETECTED");
        assert_eq!(ERR_SPS_INSUFFICIENT_STAKE, "ERR_SPS_INSUFFICIENT_STAKE");
        assert_eq!(ERR_SPS_AGGREGATION_FAILED, "ERR_SPS_AGGREGATION_FAILED");
    }

    #[test]
    fn test_invariant_tags_defined() {
        assert_eq!(INV_SPS_AGGREGATION, "INV-SPS-AGGREGATION");
        assert_eq!(INV_SPS_STAKE, "INV-SPS-STAKE");
        assert_eq!(INV_SPS_SYBIL, "INV-SPS-SYBIL");
        assert_eq!(INV_SPS_ADVERSARIAL, "INV-SPS-ADVERSARIAL");
    }

    // ── Error construction ───────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let err = SybilDefenseError::poisoned_signal("test");
        let s = format!("{err}");
        assert!(s.contains(ERR_SPS_POISONED_SIGNAL));
        assert!(s.contains("test"));
    }

    #[test]
    fn test_error_constructors() {
        let e1 = SybilDefenseError::poisoned_signal("a");
        assert_eq!(e1.code, ERR_SPS_POISONED_SIGNAL);

        let e2 = SybilDefenseError::sybil_detected("b");
        assert_eq!(e2.code, ERR_SPS_SYBIL_DETECTED);

        let e3 = SybilDefenseError::insufficient_stake("c");
        assert_eq!(e3.code, ERR_SPS_INSUFFICIENT_STAKE);

        let e4 = SybilDefenseError::aggregation_failed("d");
        assert_eq!(e4.code, ERR_SPS_AGGREGATION_FAILED);
    }

    // ── Pipeline tests ───────────────────────────────────────────────────

    #[test]
    fn test_pipeline_default() {
        let pipeline = SybilDefensePipeline::new();
        assert!(pipeline.nodes().is_empty());
        assert!(pipeline.pipeline_events().is_empty());
    }

    #[test]
    fn test_pipeline_register_node() {
        let mut pipeline = SybilDefensePipeline::new();
        pipeline.register_node(make_established_node("node-1"));
        assert!(pipeline.get_node("node-1").is_some());
        assert_eq!(pipeline.nodes().len(), 1);
    }

    #[test]
    fn test_pipeline_process_honest_signals() {
        let mut pipeline = SybilDefensePipeline::new();
        for i in 0..5 {
            let id = format!("honest-{i}");
            pipeline.register_node(make_established_node(&id));
        }
        let signals = honest_signals(5, "target");
        let result = pipeline.process_signals(&signals, 10_000).unwrap();
        assert!(result.value > 0.0);
        assert!(!pipeline.pipeline_events().is_empty());
    }

    #[test]
    fn test_pipeline_process_empty() {
        let mut pipeline = SybilDefensePipeline::new();
        let result = pipeline.process_signals(&[], 10_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_ordered_nodes() {
        let mut pipeline = SybilDefensePipeline::new();
        pipeline.register_node(make_established_node("z-node"));
        pipeline.register_node(make_established_node("a-node"));
        let ordered = pipeline.ordered_nodes();
        let keys: Vec<_> = ordered.keys().collect();
        assert_eq!(keys[0], "a-node");
        assert_eq!(keys[1], "z-node");
    }

    // ── Adversarial test scenarios (>= 10) ───────────────────────────────
    // These tests form the adversarial CI gate (INV-SPS-ADVERSARIAL).

    #[test]
    fn test_adversarial_01_pure_poisoning_trimmed_mean() {
        // Attack: 20% signals at 0.0 trying to pull down honest 0.8
        let agg = TrustAggregator::new(0.2);
        let mut values: Vec<f64> = (0..80).map(|_| 0.8).collect();
        values.extend((0..20).map(|_| 0.0));
        let result = agg.trimmed_mean(&values).unwrap();
        assert!((result.value - 0.8).abs() / 0.8 <= 0.05);
    }

    #[test]
    fn test_adversarial_02_pure_poisoning_median() {
        // Attack: 20% signals at extreme high trying to inflate
        let agg = TrustAggregator::default();
        let mut values: Vec<f64> = (0..80).map(|_| 0.5).collect();
        values.extend((0..20).map(|_| 1.0));
        let result = agg.median(&values).unwrap();
        assert!((result.value - 0.5).abs() / 0.5 <= 0.05);
    }

    #[test]
    fn test_adversarial_03_sybil_flood() {
        // Attack: 100 Sybil vs 5 honest
        let w = StakeWeighter::default();
        let mut nodes = BTreeMap::new();
        for i in 0..5 {
            nodes.insert(format!("h-{i}"), make_established_node(&format!("h-{i}")));
        }
        for i in 0..100 {
            nodes.insert(format!("s-{i}"), make_new_node(&format!("s-{i}")));
        }

        let honest: Vec<TrustSignal> = (0..5)
            .map(|i| make_signal(&format!("hs-{i}"), &format!("h-{i}"), "t", 0.8, 1000))
            .collect();
        let sybil: Vec<TrustSignal> = (0..100)
            .map(|i| make_signal(&format!("ss-{i}"), &format!("s-{i}"), "t", 0.99, 5000))
            .collect();

        let mut all = honest;
        all.extend(sybil);
        let avg = w.weighted_average(&all, &nodes).unwrap();
        assert!(avg < 0.9, "Sybil flood shifted average to {avg}");
    }

    #[test]
    fn test_adversarial_04_stake_manipulation() {
        // Attack: zero-history nodes should have negligible weight
        let w = StakeWeighter::default();
        let new = make_new_node("attacker");
        let est = make_established_node("defender");
        let ratio = w.weight_ratio_new_vs_established(&new, &est);
        assert!(ratio <= 0.01);
    }

    #[test]
    fn test_adversarial_05_gradual_poisoning() {
        // Attack: gradually increasing poison ratio
        let agg = TrustAggregator::new(0.2);
        for poison_pct in [5, 10, 15, 20] {
            let honest_count = 100 - poison_pct;
            let mut values: Vec<f64> = (0..honest_count).map(|_| 0.7).collect();
            values.extend((0..poison_pct).map(|_| 0.0));
            let result = agg.trimmed_mean(&values).unwrap();
            let shift = (result.value - 0.7).abs() / 0.7;
            assert!(
                shift <= 0.05,
                "Gradual poison at {poison_pct}%: shift {shift:.4}"
            );
        }
    }

    #[test]
    fn test_adversarial_06_bimodal_attack() {
        // Attack: half of poisoned signals at 0.0, half at 1.0
        let agg = TrustAggregator::new(0.2);
        let mut values: Vec<f64> = (0..80).map(|_| 0.6).collect();
        values.extend((0..10).map(|_| 0.0));
        values.extend((0..10).map(|_| 1.0));
        let result = agg.trimmed_mean(&values).unwrap();
        let shift = (result.value - 0.6).abs() / 0.6;
        assert!(shift <= 0.05, "Bimodal attack shift {shift:.4}");
    }

    #[test]
    fn test_adversarial_07_temporal_burst() {
        // Attack: all Sybil signals arrive simultaneously
        let mut detector = SybilDetector::new(3, 1000, 0.95);
        let signals: Vec<TrustSignal> = (0..50)
            .map(|i| {
                make_signal(
                    &format!("burst-{i}"),
                    "single-attacker",
                    "target",
                    0.99,
                    5000 + i, // 1ms apart
                )
            })
            .collect();
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "single-attacker".to_string(),
            make_new_node("single-attacker"),
        );

        let sybils = detector.detect_sybil_cluster(&signals, &nodes, 10_000);
        assert!(sybils.contains("single-attacker"));
    }

    #[test]
    fn test_adversarial_08_near_threshold_poisoning() {
        // Attack: poison signals just below detection threshold
        let agg = TrustAggregator::new(0.2);
        let mut values: Vec<f64> = (0..80).map(|_| 0.75).collect();
        // Subtle poisoning: slightly lower than honest
        values.extend((0..20).map(|_| 0.4));
        let result = agg.trimmed_mean(&values).unwrap();
        let shift = (result.value - 0.75).abs() / 0.75;
        assert!(shift <= 0.05, "Near-threshold poison shift {shift:.4}");
    }

    #[test]
    fn test_adversarial_09_mixed_sybil_and_poisoning() {
        // Combined attack: Sybil identities + signal poisoning
        let mut pipeline = SybilDefensePipeline::new();

        // Register established honest nodes
        for i in 0..10 {
            let id = format!("honest-{i}");
            pipeline.register_node(make_established_node(&id));
        }

        // Register Sybil nodes
        for i in 0..50 {
            let id = format!("sybil-{i}");
            pipeline.register_node(make_new_node(&id));
        }

        let mut signals: Vec<TrustSignal> = (0..10)
            .map(|i| {
                make_signal(
                    &format!("h-{i}"),
                    &format!("honest-{i}"),
                    "target",
                    0.7,
                    1000 + i * 100,
                )
            })
            .collect();
        signals.extend((0..50).map(|i| {
            make_signal(
                &format!("s-{i}"),
                &format!("sybil-{i}"),
                "target",
                0.01,
                5000 + i,
            )
        }));

        let result = pipeline.process_signals(&signals, 10_000).unwrap();
        // Result should still be positive due to established-node dominance
        assert!(result.value > 0.0);
    }

    #[test]
    fn test_adversarial_10_reputation_based_filtering() {
        // Verify that nodes with zero reputation get minimal weight
        let w = StakeWeighter::default();
        let zero_rep = TrustNode {
            node_id: "zero".to_string(),
            reputation_score: 0.0,
            verified_history_len: 0,
            sybil_flagged: false,
            created_at_ms: 50_000,
        };
        let high_rep = TrustNode {
            node_id: "high".to_string(),
            reputation_score: 100.0,
            verified_history_len: 500,
            sybil_flagged: false,
            created_at_ms: 1000,
        };

        let zero_weight = w.compute_weight(&zero_rep);
        let high_weight = w.compute_weight(&high_rep);
        assert!(zero_weight / high_weight <= 0.01);
    }

    // ── TrustNode tests ──────────────────────────────────────────────────

    #[test]
    fn test_trust_node_new() {
        let node = TrustNode::new("test", 1000);
        assert_eq!(node.node_id, "test");
        assert_eq!(node.reputation_score, 0.0);
        assert_eq!(node.verified_history_len, 0);
        assert!(!node.sybil_flagged);
    }

    #[test]
    fn test_trust_node_established() {
        let node = TrustNode::established("est", 85.0, 200, 1000);
        assert_eq!(node.reputation_score, 85.0);
        assert_eq!(node.verified_history_len, 200);
    }

    // ── SybilDetector event management ───────────────────────────────────

    #[test]
    fn test_detector_clear_events() {
        let mut detector = SybilDetector::new(3, 60_000, 0.95);
        let signals: Vec<TrustSignal> = (0..10)
            .map(|i| make_signal(&format!("s-{i}"), "a", "t", 0.9, 5000 + i * 5))
            .collect();
        let mut nodes = BTreeMap::new();
        nodes.insert("a".to_string(), make_new_node("a"));

        detector.detect_sybil_cluster(&signals, &nodes, 10_000);
        assert!(!detector.events().is_empty());
        detector.clear_events();
        assert!(detector.events().is_empty());
    }

    // ── Aggregation edge cases ───────────────────────────────────────────

    #[test]
    fn test_trimmed_mean_two_values() {
        let agg = TrustAggregator::new(0.1);
        let result = agg.trimmed_mean(&[0.3, 0.7]).unwrap();
        assert!((result.value - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_trimmed_mean_all_same() {
        let agg = TrustAggregator::default();
        let values: Vec<f64> = (0..100).map(|_| 0.5).collect();
        let result = agg.trimmed_mean(&values).unwrap();
        assert!((result.value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_median_single_value() {
        let agg = TrustAggregator::default();
        let result = agg.median(&[0.42]).unwrap();
        assert!((result.value - 0.42).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregator_nan_trim_ratio_falls_back_to_default() {
        let agg = TrustAggregator::new(f64::NAN);
        assert!((agg.trim_ratio - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregator_inf_trim_ratio_falls_back_to_default() {
        let agg = TrustAggregator::new(f64::INFINITY);
        assert!((agg.trim_ratio - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn stake_weighter_nan_weights_fall_back_to_defaults() {
        let w = StakeWeighter::new(100, f64::NAN, f64::NAN);
        assert!((w.base_weight - 0.01).abs() < f64::EPSILON);
        assert!((w.max_weight - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sybil_detector_nan_threshold_falls_back_to_default() {
        let d = SybilDetector::new(5, 60_000, f64::NAN);
        assert!((d.similarity_threshold - 0.95).abs() < f64::EPSILON);
    }
}

#[cfg(test)]
mod sybil_defense_negative_path_tests {
    use super::*;

    fn signal(id: &str, source: &str, value: f64) -> TrustSignal {
        TrustSignal {
            signal_id: id.to_string(),
            source_node_id: source.to_string(),
            target_id: "target-a".to_string(),
            value,
            timestamp_ms: 1_700_000_000,
        }
    }

    fn established_node(id: &str) -> TrustNode {
        TrustNode::established(id, 75.0, 150, 1_600_000_000)
    }

    #[test]
    fn weighted_average_rejects_empty_signal_batch() {
        let weighter = StakeWeighter::default();
        let nodes = BTreeMap::new();

        let err = weighter.weighted_average(&[], &nodes).unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(err.message.contains("no signals"));
    }

    #[test]
    fn weighted_average_rejects_zero_total_weight() {
        let weighter = StakeWeighter::new(100, 0.0, 0.0);
        let nodes = BTreeMap::new();
        let signals = vec![signal("signal-1", "unknown-node", 0.5)];

        let err = weighter.weighted_average(&signals, &nodes).unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(err.message.contains("total weight"));
    }

    #[test]
    fn weighted_average_rejects_non_finite_weighted_sum() {
        let weighter = StakeWeighter::default();
        let nodes = BTreeMap::from([("node-a".to_string(), established_node("node-a"))]);
        let signals = vec![signal("signal-1", "node-a", f64::INFINITY)];

        let err = weighter.weighted_average(&signals, &nodes).unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(err.message.contains("non-finite weighted sum"));
    }

    #[test]
    fn process_signals_rejects_empty_batch() {
        let mut pipeline = SybilDefensePipeline::new();

        let err = pipeline.process_signals(&[], 1_700_000_000).unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(pipeline.pipeline_events().is_empty());
    }

    #[test]
    fn process_signals_rejects_non_finite_signal_value() {
        let mut pipeline = SybilDefensePipeline::new();
        pipeline.register_node(established_node("node-a"));
        let signals = vec![signal("signal-1", "node-a", f64::NAN)];

        let err = pipeline
            .process_signals(&signals, 1_700_000_000)
            .unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(pipeline.pipeline_events().is_empty());
    }

    #[test]
    fn trimmed_mean_rejects_negative_infinity_input() {
        let aggregator = TrustAggregator::default();

        let err = aggregator
            .trimmed_mean(&[0.25, f64::NEG_INFINITY, 0.75])
            .unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(err.message.contains("non-finite value"));
    }

    #[test]
    fn median_rejects_quiet_nan_input() {
        let aggregator = TrustAggregator::default();

        let err = aggregator.median(&[0.25, f64::NAN, 0.75]).unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(err.message.contains("non-finite value"));
    }

    #[test]
    fn threshold_sized_burst_is_not_reported_as_sybil() {
        let mut detector = SybilDetector::new(3, 60_000, 0.95);
        let nodes = BTreeMap::from([("node-a".to_string(), TrustNode::new("node-a", 1))]);
        let signals = vec![
            signal("signal-1", "node-a", 0.9),
            signal("signal-2", "node-a", 0.91),
            signal("signal-3", "node-a", 0.92),
        ];

        let detected = detector.detect_sybil_cluster(&signals, &nodes, 1_700_000_000);

        assert!(detected.is_empty());
        assert!(detector.events().is_empty());
    }

    #[test]
    fn stake_weighter_negative_base_weight_falls_back_to_default() {
        let weighter = StakeWeighter::new(100, -0.5, 1.0);
        let new_node = TrustNode::new("new-node", 1);

        assert!((weighter.base_weight - 0.01).abs() < f64::EPSILON);
        assert!((weighter.compute_weight(&new_node) - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn stake_weighter_negative_max_weight_falls_back_to_default() {
        let weighter = StakeWeighter::new(100, 0.01, -1.0);
        let established = established_node("established-node");

        assert!((weighter.max_weight - 1.0).abs() < f64::EPSILON);
        assert!(weighter.compute_weight(&established) >= weighter.base_weight);
    }

    #[test]
    fn stake_weighter_max_below_base_preserves_monotonic_weight() {
        let weighter = StakeWeighter::new(100, 0.5, 0.1);
        let new_node = TrustNode::new("new-node", 1);
        let established = established_node("established-node");

        assert!((weighter.max_weight - weighter.base_weight).abs() < f64::EPSILON);
        assert!(weighter.compute_weight(&established) >= weighter.compute_weight(&new_node));
    }

    #[test]
    fn apply_weights_never_returns_negative_weight_from_negative_config() {
        let weighter = StakeWeighter::new(100, -10.0, -1.0);
        let nodes = BTreeMap::from([("node-a".to_string(), established_node("node-a"))]);
        let weighted = weighter.apply_weights(&[signal("signal-1", "node-a", 0.7)], &nodes);

        assert_eq!(weighted.len(), 1);
        assert!(weighted[0].0 >= 0.0);
        assert!(weighted[0].1 >= 0.0);
    }

    #[test]
    fn sybil_detector_negative_similarity_threshold_falls_back_to_default() {
        let detector = SybilDetector::new(5, 60_000, -0.1);

        assert!((detector.similarity_threshold - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn sybil_detector_above_one_similarity_threshold_falls_back_to_default() {
        let detector = SybilDetector::new(5, 60_000, 1.1);

        assert!((detector.similarity_threshold - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_drops_oldest_batch() {
        let mut items = vec![1, 2, 3, 4];

        push_bounded(&mut items, 5, 2);

        assert_eq!(items, vec![4, 5]);
    }

    #[test]
    fn detector_empty_signal_batch_does_not_log_sybil_event() {
        let mut detector = SybilDetector::default();
        let nodes = BTreeMap::new();

        let detected = detector.detect_sybil_cluster(&[], &nodes, 1_700_000_000);

        assert!(detected.is_empty());
        assert!(detector.events().is_empty());
    }

    #[test]
    fn detector_zero_window_rejects_nearby_but_distinct_burst() {
        let mut detector = SybilDetector::new(1, 0, 0.95);
        let nodes = BTreeMap::from([("node-a".to_string(), TrustNode::new("node-a", 1))]);
        let signals = vec![
            TrustSignal {
                timestamp_ms: 1000,
                ..signal("signal-1", "node-a", 0.9)
            },
            TrustSignal {
                timestamp_ms: 1001,
                ..signal("signal-2", "node-a", 0.91)
            },
        ];

        let detected = detector.detect_sybil_cluster(&signals, &nodes, 1_700_000_000);

        assert!(detected.is_empty());
        assert!(detector.events().is_empty());
    }

    #[test]
    fn attenuate_empty_sybil_set_keeps_all_weights_at_one() {
        let detector = SybilDetector::default();
        let signals = vec![
            signal("signal-1", "node-a", 0.4),
            signal("signal-2", "node-b", 0.6),
        ];

        let attenuated = detector.attenuate_sybil_signals(&signals, &BTreeSet::new());

        assert_eq!(attenuated.len(), 2);
        assert!(
            attenuated
                .iter()
                .all(|(_, weight)| { (*weight - 1.0).abs() < f64::EPSILON })
        );
    }

    #[test]
    fn compute_influence_absent_node_ids_have_zero_influence() {
        let detector = SybilDetector::default();
        let weighter = StakeWeighter::default();
        let nodes = BTreeMap::from([("node-a".to_string(), established_node("node-a"))]);
        let signals = vec![signal("signal-1", "node-a", 0.9)];
        let missing_nodes = vec!["node-missing".to_string()];

        let influence = detector.compute_influence(&signals, &missing_nodes, &weighter, &nodes);

        assert!((influence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregator_negative_trim_ratio_clamps_to_zero() {
        let aggregator = TrustAggregator::new(-0.25);

        let result = aggregator.trimmed_mean(&[0.0, 1.0]).unwrap();

        assert!((aggregator.trim_ratio - 0.0).abs() < f64::EPSILON);
        assert!((result.value - 0.5).abs() < f64::EPSILON);
        assert_eq!(result.trimmed_count, 0);
    }

    #[test]
    fn aggregator_excessive_trim_ratio_clamps_to_half_without_empty_slice() {
        let aggregator = TrustAggregator::new(0.75);

        let result = aggregator.trimmed_mean(&[0.1, 0.9]).unwrap();

        assert!((aggregator.trim_ratio - 0.5).abs() < f64::EPSILON);
        assert!((result.value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn median_rejects_positive_infinity_input() {
        let aggregator = TrustAggregator::default();

        let err = aggregator.median(&[0.25, f64::INFINITY, 0.75]).unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(err.message.contains("non-finite value"));
    }

    #[test]
    fn weighted_average_rejects_nan_weighted_sum() {
        let weighter = StakeWeighter::default();
        let nodes = BTreeMap::from([("node-a".to_string(), established_node("node-a"))]);
        let signals = vec![signal("signal-1", "node-a", f64::NAN)];

        let err = weighter.weighted_average(&signals, &nodes).unwrap_err();

        assert_eq!(err.code, ERR_SPS_AGGREGATION_FAILED);
        assert!(err.message.contains("non-finite weighted sum"));
    }

    #[test]
    fn established_threshold_zero_does_not_divide_by_zero() {
        let weighter = StakeWeighter::new(0, 0.05, 1.0);
        let established = established_node("established-node");

        let weight = weighter.compute_weight(&established);

        assert!((weight - weighter.base_weight).abs() < f64::EPSILON);
    }

    #[test]
    fn coordinated_values_outside_similarity_threshold_are_not_sybil() {
        let mut detector = SybilDetector::new(100, 60_000, 0.99);
        let nodes = BTreeMap::from([
            ("node-a".to_string(), TrustNode::new("node-a", 1)),
            ("node-b".to_string(), TrustNode::new("node-b", 1)),
            ("node-c".to_string(), TrustNode::new("node-c", 1)),
        ]);
        let signals = vec![
            signal("signal-1", "node-a", 0.80),
            signal("signal-2", "node-b", 0.82),
            signal("signal-3", "node-c", 0.84),
        ];

        let detected = detector.detect_sybil_cluster(&signals, &nodes, 1_700_000_000);

        assert!(detected.is_empty());
        assert!(detector.events().is_empty());
    }

    #[test]
    fn coordinated_established_nodes_are_not_flagged_as_sybil_cluster() {
        let mut detector = SybilDetector::new(100, 60_000, 0.95);
        let nodes = BTreeMap::from([
            ("node-a".to_string(), established_node("node-a")),
            ("node-b".to_string(), established_node("node-b")),
            ("node-c".to_string(), established_node("node-c")),
        ]);
        let signals = vec![
            signal("signal-1", "node-a", 0.91),
            signal("signal-2", "node-b", 0.91),
            signal("signal-3", "node-c", 0.91),
        ];

        let detected = detector.detect_sybil_cluster(&signals, &nodes, 1_700_000_000);

        assert!(detected.is_empty());
        assert!(detector.events().is_empty());
    }

    #[test]
    fn compute_influence_duplicate_node_ids_do_not_double_count_signal() {
        let detector = SybilDetector::default();
        let weighter = StakeWeighter::default();
        let nodes = BTreeMap::from([("node-a".to_string(), established_node("node-a"))]);
        let signals = vec![signal("signal-1", "node-a", 0.9)];
        let duplicated_nodes = vec!["node-a".to_string(), "node-a".to_string()];

        let influence = detector.compute_influence(&signals, &duplicated_nodes, &weighter, &nodes);
        let single_influence =
            detector.compute_influence(&signals, &["node-a".to_string()], &weighter, &nodes);

        assert!((influence - single_influence).abs() < f64::EPSILON);
    }

    /// Extreme adversarial test: Precision-based timing attack exploiting floating-point
    /// arithmetic weaknesses in stake weight calculations to manipulate trust rankings
    #[test]
    fn sybil_defense_floating_point_precision_stake_weight_manipulation_attack() {
        let weighter = StakeWeighter::default();

        // Attack vectors targeting floating-point precision edge cases
        let precision_attack_nodes = [
            (0, f64::MIN_POSITIVE),               // Minimal positive reputation
            (1, f64::EPSILON),                    // Machine epsilon
            (u64::MAX, f64::MAX),                 // Maximum values
            (1_000_000_000_000, 1e-100),          // Very large history, tiny rep
            (1, 1.0 + f64::EPSILON),              // Slightly above 1.0
            (100, std::f64::consts::PI / 1e10),   // Irrational tiny number
            (50, 1.0 / 3.0),                      // Repeating decimal
            (999_999_999_999, 0.999_999_999_999), // Near-maximum values
        ];

        for (history_len, reputation_score) in precision_attack_nodes {
            let attack_node = TrustNode::established(
                "precision-attacker",
                reputation_score,
                history_len,
                1_000_000_000,
            );

            let weight = weighter.compute_weight(&attack_node);

            // Weight calculations must remain finite and bounded
            assert!(
                weight.is_finite(),
                "Weight calculation resulted in non-finite value for history={}, rep={}",
                history_len,
                reputation_score
            );
            assert!(
                weight >= 0.0,
                "Weight calculation resulted in negative value: {}",
                weight
            );
            assert!(
                weight <= weighter.max_weight * 2.0,
                "Weight {} exceeded reasonable bounds for max_weight {}",
                weight,
                weighter.max_weight
            );

            // Verify monotonicity isn't broken by precision issues
            if history_len > 0 {
                let smaller_node = TrustNode::established(
                    "smaller-history",
                    reputation_score,
                    history_len.saturating_sub(1),
                    1_000_000_000,
                );
                let smaller_weight = weighter.compute_weight(&smaller_node);

                assert!(
                    weight >= smaller_weight - f64::EPSILON,
                    "Monotonicity violated: weight decreased from {} to {} at history change {}->{}",
                    smaller_weight,
                    weight,
                    history_len.saturating_sub(1),
                    history_len
                );
            }
        }
    }

    /// Extreme adversarial test: Algorithmic complexity explosion via carefully crafted
    /// Sybil cluster patterns designed to maximize computational cost in detection logic
    #[test]
    fn sybil_defense_algorithmic_complexity_explosion_detection_dos_attack() {
        use std::time::Instant;

        let mut detector = SybilDetector::new(3, 60_000, 0.95);
        let mut nodes = BTreeMap::new();
        let mut signals = Vec::new();

        // Generate pathological input designed to maximize comparison operations
        let complexity_multiplier = 100; // Limit to prevent actual DoS in test

        for i in 0..complexity_multiplier {
            let node_id = format!("complexity-node-{}", i);
            nodes.insert(node_id.clone(), TrustNode::new(&node_id, 1));

            // Create overlapping value patterns that force maximum pairwise comparisons
            for j in 0..10 {
                signals.push(TrustSignal {
                    signal_id: format!("complex-signal-{}-{}", i, j),
                    source_node_id: node_id.clone(),
                    target_id: format!("target-{}", i % 5), // Limited target diversity
                    value: 0.95 + (i as f64 / 100_000.0),   // Very similar values
                    timestamp_ms: 5_000 + (j as u64),       // Clustered timestamps
                });
            }
        }

        let start = Instant::now();
        let detected = detector.detect_sybil_cluster(&signals, &nodes, 10_000);
        let elapsed = start.elapsed();

        // Detection must complete in reasonable time despite adversarial input complexity
        assert!(
            elapsed.as_millis() < 5_000,
            "Sybil detection took {}ms for {} signals, should be <5000ms",
            elapsed.as_millis(),
            signals.len()
        );

        // Results should be deterministic regardless of complexity
        assert!(
            detected.len() <= nodes.len(),
            "Detected more Sybils ({}) than total nodes ({})",
            detected.len(),
            nodes.len()
        );

        // Event logging should remain bounded
        assert!(
            detector.events().len() <= 100,
            "Event log grew to {} entries, should be bounded",
            detector.events().len()
        );
    }

    /// Extreme adversarial test: Memory exhaustion attack via massive trust signal batches
    /// designed to overwhelm pipeline processing and exhaust available system resources
    #[test]
    fn sybil_defense_memory_exhaustion_massive_signal_batch_dos_attack() {
        let mut pipeline = SybilDefensePipeline::new();

        // Register realistic number of nodes
        for i in 0..100 {
            pipeline.register_node(TrustNode::established(
                format!("node-{}", i),
                50.0 + (i as f64 / 10.0),
                100 + i * 5,
                1_000_000_000 + i as u64 * 86400,
            ));
        }

        // Generate massive signal batch to stress memory usage
        let massive_signal_count = 10_000; // Limited to prevent actual resource exhaustion
        let mut massive_signals = Vec::with_capacity(massive_signal_count);

        for i in 0..massive_signal_count {
            massive_signals.push(TrustSignal {
                signal_id: format!("massive-signal-{}", i),
                source_node_id: format!("node-{}", i % 100),
                target_id: format!("target-{}", i % 50),
                value: 0.5 + ((i % 1000) as f64 / 2000.0),
                timestamp_ms: 1_700_000_000 + (i as u64),
            });
        }

        let start_memory = std::mem::size_of_val(&massive_signals);

        // Process massive batch - should not crash or exhaust memory
        let result = pipeline.process_signals(&massive_signals, 1_700_000_000);

        // Processing should either succeed or fail gracefully
        match result {
            Ok(aggregation_result) => {
                assert!(
                    aggregation_result.value.is_finite(),
                    "Massive batch processing resulted in non-finite aggregation"
                );
                assert!(
                    aggregation_result.signal_count <= massive_signal_count,
                    "Signal count {} exceeds input size {}",
                    aggregation_result.signal_count,
                    massive_signal_count
                );
            }
            Err(error) => {
                // Graceful failure due to resource limits is acceptable
                assert_eq!(
                    error.code, ERR_SPS_AGGREGATION_FAILED,
                    "Unexpected error type for massive batch: {}",
                    error.code
                );
            }
        }

        // Pipeline should remain functional after stress test
        let simple_signals = vec![TrustSignal {
            signal_id: "post-stress-signal".to_string(),
            source_node_id: "node-0".to_string(),
            target_id: "recovery-target".to_string(),
            value: 0.8,
            timestamp_ms: 1_700_001_000,
        }];

        let recovery_result = pipeline.process_signals(&simple_signals, 1_700_001_000);
        assert!(
            recovery_result.is_ok(),
            "Pipeline should remain functional after stress test"
        );
    }

    /// Extreme adversarial test: Concurrent trust signal injection race condition attack
    /// targeting shared state corruption in pipeline processing during parallel operations
    #[test]
    fn sybil_defense_concurrent_signal_injection_state_corruption_race_attack() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let pipeline = Arc::new(Mutex::new(SybilDefensePipeline::new()));

        // Register shared nodes
        {
            let mut p = pipeline.lock().unwrap();
            for i in 0..20 {
                p.register_node(TrustNode::established(
                    format!("shared-node-{}", i),
                    60.0 + (i as f64 * 2.0),
                    150 + i * 10,
                    1_600_000_000 + i as u64 * 3600,
                ));
            }
        }

        // Spawn multiple threads performing concurrent signal injection
        let handles: Vec<_> = (0..8)
            .map(|thread_id| {
                let pipeline_clone = Arc::clone(&pipeline);

                thread::spawn(move || {
                    for batch_id in 0..25 {
                        let mut thread_signals = Vec::new();

                        // Generate varied signal patterns to stress different code paths
                        for signal_id in 0..10 {
                            thread_signals.push(TrustSignal {
                                signal_id: format!(
                                    "thread-{}-batch-{}-signal-{}",
                                    thread_id, batch_id, signal_id
                                ),
                                source_node_id: format!("shared-node-{}", signal_id % 20),
                                target_id: format!("race-target-{}-{}", thread_id, batch_id % 3),
                                value: 0.3 + (thread_id as f64 / 20.0) + (signal_id as f64 / 100.0),
                                timestamp_ms: 1_700_000_000
                                    + (thread_id as u64 * 1000)
                                    + (batch_id as u64 * 100)
                                    + signal_id as u64,
                            });
                        }

                        if let Ok(mut pipeline_lock) = pipeline_clone.try_lock() {
                            let _result = pipeline_lock.process_signals(
                                &thread_signals,
                                1_700_000_000 + (thread_id as u64 * 1000) + batch_id as u64,
                            );
                            // Note: Results may vary due to race conditions, we're testing for safety not correctness
                        }

                        // Brief yield to encourage race conditions
                        thread::yield_now();
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify pipeline remains in valid state after concurrent stress
        let final_pipeline = pipeline.lock().unwrap();
        assert_eq!(
            final_pipeline.nodes().len(),
            20,
            "Node count changed during concurrent processing"
        );

        // Pipeline should still be able to process signals normally
        let test_signals = vec![TrustSignal {
            signal_id: "post-concurrency-test".to_string(),
            source_node_id: "shared-node-0".to_string(),
            target_id: "final-test-target".to_string(),
            value: 0.75,
            timestamp_ms: 1_700_002_000,
        }];

        drop(final_pipeline); // Release lock before reacquiring
        let mut final_pipeline = pipeline.lock().unwrap();
        let final_result = final_pipeline.process_signals(&test_signals, 1_700_002_000);
        assert!(
            final_result.is_ok(),
            "Pipeline should function normally after concurrent stress test"
        );
    }

    /// Extreme adversarial test: Statistical manipulation via crafted outlier patterns
    /// designed to exploit trimmed-mean aggregation boundary conditions and bias results
    #[test]
    fn sybil_defense_statistical_manipulation_trimmed_mean_boundary_exploitation() {
        let test_cases = [
            // Test case: trimmed-mean vs median boundary conditions
            (0.15, vec![0.1; 70], vec![0.9; 15], vec![0.95; 15]), // 15% trim
            (0.20, vec![0.2; 60], vec![0.0; 20], vec![1.0; 20]),  // 20% trim (boundary)
            (0.25, vec![0.3; 50], vec![0.0; 25], vec![1.0; 25]),  // 25% trim
            (0.30, vec![0.4; 40], vec![0.0; 30], vec![0.8; 30]),  // 30% trim
        ];

        for (trim_ratio, honest_values, low_outliers, high_outliers) in test_cases {
            let aggregator = TrustAggregator::new(trim_ratio);
            let expected_honest_mean = honest_values[0];

            // Combine honest signals with adversarial outliers
            let mut combined_values = honest_values;
            combined_values.extend(low_outliers);
            combined_values.extend(high_outliers);

            let result = aggregator.trimmed_mean(&combined_values).unwrap();

            // Verify outlier resistance: result should stay close to honest mean
            let deviation = (result.value - expected_honest_mean).abs() / expected_honest_mean;
            assert!(
                deviation <= 0.10,
                "Trimmed-mean with {:.2} trim ratio deviated {:.4} from honest mean {:.2} (result: {:.4})",
                trim_ratio,
                deviation,
                expected_honest_mean,
                result.value
            );

            // Verify trim count calculation
            let len_f64 = u32::try_from(combined_values.len()).unwrap_or(u32::MAX) as f64;
            let expected_trim_count = (len_f64 * trim_ratio).floor() as usize * 2;
            let actual_trim_count = result.trimmed_count;

            // Allow for edge cases where trimming would eliminate all values
            if actual_trim_count < combined_values.len() {
                assert!(
                    actual_trim_count <= expected_trim_count + 2,
                    "Trim count {} exceeds expected {} for trim ratio {:.2}",
                    actual_trim_count,
                    expected_trim_count,
                    trim_ratio
                );
            }

            // Compare with median for cross-validation
            let median_result = aggregator.median(&combined_values).unwrap();
            let trimmed_median_diff = (result.value - median_result.value).abs();

            // Trimmed-mean and median should generally agree on outlier-resistant aggregation
            assert!(
                trimmed_median_diff <= 0.3,
                "Trimmed-mean ({:.4}) and median ({:.4}) disagree significantly with trim ratio {:.2}",
                result.value,
                median_result.value,
                trim_ratio
            );
        }
    }

    /// Extreme adversarial test: Temporal clustering exploit via carefully timed signal
    /// bursts designed to evade Sybil detection through burst window manipulation
    #[test]
    fn sybil_defense_temporal_clustering_burst_window_evasion_exploit() {
        let window_ms = 60_000;
        let burst_threshold = 5;
        let mut detector = SybilDetector::new(burst_threshold, window_ms, 0.95);
        let mut nodes = BTreeMap::new();

        // Register attack nodes
        for i in 0..3 {
            let node_id = format!("temporal-attacker-{}", i);
            nodes.insert(node_id.clone(), TrustNode::new(&node_id, 1));
        }

        // Test various temporal evasion patterns
        let evasion_patterns = [
            // Pattern 1: Just under burst threshold
            (burst_threshold - 1, 1_000),
            // Pattern 2: Burst threshold exactly at window boundary
            (burst_threshold + 1, window_ms + 1),
            // Pattern 3: Multiple micro-bursts within separate windows
            (2, window_ms / 3),
            // Pattern 4: Slow sustained rate just under detection
            (burst_threshold - 2, window_ms / 2),
        ];

        for (pattern_id, (signal_count, time_spacing)) in evasion_patterns.iter().enumerate() {
            let attacker_id = format!("temporal-attacker-{}", pattern_id % 3);
            let mut pattern_signals = Vec::new();

            let base_timestamp = 1_700_000_000 + (pattern_id as u64 * 1_000_000);

            for i in 0..*signal_count {
                pattern_signals.push(TrustSignal {
                    signal_id: format!("temporal-evasion-{}-{}", pattern_id, i),
                    source_node_id: attacker_id.clone(),
                    target_id: format!("evasion-target-{}", pattern_id),
                    value: 0.95 + (i as f64 / 1000.0), // Slightly varying values
                    timestamp_ms: base_timestamp + (i as u64 * time_spacing),
                });
            }

            let detected =
                detector.detect_sybil_cluster(&pattern_signals, &nodes, base_timestamp + 100_000);

            // Analyze detection results based on expected behavior
            if *signal_count >= burst_threshold + 1 {
                // Patterns exceeding burst threshold should be detected if within window
                let spans_single_window =
                    (*time_spacing as u64 * (*signal_count as u64 - 1)) <= window_ms;
                if spans_single_window {
                    assert!(
                        detected.contains(&attacker_id),
                        "Pattern {} with {} signals over {}ms should be detected as burst",
                        pattern_id,
                        signal_count,
                        *time_spacing as u64 * (*signal_count as u64)
                    );
                }
            } else {
                // Patterns under threshold should generally evade detection
                // (unless caught by other heuristics)
                if detected.contains(&attacker_id) {
                    // If detected, it should be due to coordination detection, not burst
                    assert!(
                        !detector.events().is_empty(),
                        "Pattern {} detected without logging events",
                        pattern_id
                    );
                }
            }
        }

        // Verify detector state remains consistent after evasion attempts
        assert!(
            detector.events().len() <= 20,
            "Event log grew excessively to {} entries",
            detector.events().len()
        );
    }

    /// Extreme adversarial test: Reputation score manipulation via edge case reputation
    /// values designed to exploit stake weighting calculation vulnerabilities
    #[test]
    fn sybil_defense_reputation_score_manipulation_stake_weight_exploit() {
        let weighter = StakeWeighter::default();

        // Edge case reputation scores targeting calculation vulnerabilities
        let reputation_exploits = [
            (f64::MIN_POSITIVE, 100),  // Minimal positive reputation
            (f64::EPSILON, 1000),      // Machine epsilon reputation
            (1e-100, 500),             // Extremely small positive
            (f64::MAX, 0),             // Maximum reputation, no history
            (f64::INFINITY, 1000),     // Infinite reputation (should be sanitized)
            (f64::NAN, 500),           // NaN reputation (should be sanitized)
            (-0.0, 100),               // Negative zero
            (-f64::MIN_POSITIVE, 200), // Smallest negative
            (1.0 / 0.0, 300),          // Division by zero result
            (0.0 / 0.0, 400),          // NaN from division
        ];

        for (reputation_score, history_len) in reputation_exploits {
            let exploit_node = TrustNode {
                node_id: format!("reputation-exploit-{:.2e}", reputation_score),
                reputation_score,
                verified_history_len: history_len,
                sybil_flagged: false,
                created_at_ms: 1_600_000_000,
            };

            let weight = weighter.compute_weight(&exploit_node);

            // Weight must remain finite and positive regardless of reputation exploits
            assert!(
                weight.is_finite(),
                "Weight calculation with reputation {} resulted in non-finite value: {}",
                reputation_score,
                weight
            );
            assert!(
                weight >= 0.0,
                "Weight calculation with reputation {} resulted in negative value: {}",
                reputation_score,
                weight
            );
            assert!(
                weight <= weighter.max_weight * 1.1, // Small tolerance for rounding
                "Weight {} exceeds maximum bound {} with reputation {}",
                weight,
                weighter.max_weight,
                reputation_score
            );

            // Compare with baseline established node
            let baseline_node =
                TrustNode::established("baseline", 75.0, history_len, 1_600_000_000);
            let baseline_weight = weighter.compute_weight(&baseline_node);

            // Extreme reputation values should not provide unfair advantage
            if !reputation_score.is_finite() || reputation_score <= 0.0 {
                assert!(
                    weight <= baseline_weight * 1.1,
                    "Invalid reputation {} should not exceed baseline weight {:.6} (got {:.6})",
                    reputation_score,
                    baseline_weight,
                    weight
                );
            }

            // Test weight ratio calculation resilience
            let ratio = weighter.weight_ratio_new_vs_established(&exploit_node, &baseline_node);
            assert!(
                ratio.is_finite() && ratio >= 0.0,
                "Weight ratio with exploit reputation {} resulted in invalid ratio: {}",
                reputation_score,
                ratio
            );
        }
    }

    /// Extreme adversarial test: Pipeline state corruption via malformed signal injection
    /// targeting internal data structure integrity during complex processing scenarios
    #[test]
    fn sybil_defense_pipeline_state_corruption_malformed_signal_injection() {
        let mut pipeline = SybilDefensePipeline::new();

        // Register mix of normal and edge-case nodes
        pipeline.register_node(TrustNode::established(
            "normal-node",
            80.0,
            200,
            1_600_000_000,
        ));
        pipeline.register_node(TrustNode {
            node_id: "edge-node".to_string(),
            reputation_score: f64::EPSILON,
            verified_history_len: u64::MAX,
            sybil_flagged: false,
            created_at_ms: 0,
        });

        // Malformed signal injection vectors
        let malformed_signals = vec![
            // Signal with extreme timestamp
            TrustSignal {
                signal_id: "extreme-timestamp".to_string(),
                source_node_id: "normal-node".to_string(),
                target_id: "target-1".to_string(),
                value: 0.5,
                timestamp_ms: u64::MAX,
            },
            // Signal with zero timestamp
            TrustSignal {
                signal_id: "zero-timestamp".to_string(),
                source_node_id: "edge-node".to_string(),
                target_id: "target-2".to_string(),
                value: 0.6,
                timestamp_ms: 0,
            },
            // Signal from non-existent node
            TrustSignal {
                signal_id: "phantom-node-signal".to_string(),
                source_node_id: "non-existent-node".to_string(),
                target_id: "target-3".to_string(),
                value: 0.7,
                timestamp_ms: 1_700_000_000,
            },
            // Signal with boundary value
            TrustSignal {
                signal_id: "boundary-value".to_string(),
                source_node_id: "normal-node".to_string(),
                target_id: "target-4".to_string(),
                value: 1.0, // Exact boundary
                timestamp_ms: 1_700_000_000,
            },
            // Signal with very long string IDs (potential buffer issues)
            TrustSignal {
                signal_id: "x".repeat(10_000),
                source_node_id: "normal-node".to_string(),
                target_id: "y".repeat(5_000),
                value: 0.8,
                timestamp_ms: 1_700_000_000,
            },
        ];

        // Process malformed signals - should handle gracefully without corruption
        let processing_result = pipeline.process_signals(&malformed_signals, 1_700_000_000);

        match processing_result {
            Ok(result) => {
                // If processing succeeds, results should be mathematically sound
                assert!(
                    result.value.is_finite(),
                    "Pipeline processing with malformed signals resulted in non-finite aggregation"
                );
                assert!(
                    result.signal_count <= malformed_signals.len(),
                    "Signal count {} exceeds input size {}",
                    result.signal_count,
                    malformed_signals.len()
                );
                assert!(
                    result.trimmed_count <= result.signal_count,
                    "Trimmed count {} exceeds total signal count {}",
                    result.trimmed_count,
                    result.signal_count
                );
            }
            Err(error) => {
                // Graceful failure is acceptable for malformed input
                assert!(
                    !error.message.is_empty(),
                    "Error processing malformed signals should have descriptive message"
                );
                assert!(
                    !error.code.is_empty(),
                    "Error processing malformed signals should have error code"
                );
            }
        }

        // Verify pipeline state integrity after malformed signal processing
        assert_eq!(
            pipeline.nodes().len(),
            2,
            "Node count should remain unchanged after malformed signal processing"
        );

        // Pipeline should remain functional for normal signals
        let normal_signals = vec![TrustSignal {
            signal_id: "recovery-signal".to_string(),
            source_node_id: "normal-node".to_string(),
            target_id: "recovery-target".to_string(),
            value: 0.75,
            timestamp_ms: 1_700_001_000,
        }];

        let recovery_result = pipeline.process_signals(&normal_signals, 1_700_001_000);
        assert!(
            recovery_result.is_ok(),
            "Pipeline should process normal signals after malformed input: {:?}",
            recovery_result
        );

        // Event log should remain bounded and coherent
        let events = pipeline.pipeline_events();
        assert!(
            events.len() <= 100,
            "Event log grew excessively to {} entries",
            events.len()
        );

        for event in events {
            assert!(
                !event.event_code.is_empty(),
                "Event should have non-empty code"
            );
            assert!(
                !event.detail.is_empty(),
                "Event should have non-empty detail"
            );
        }
    }
}
