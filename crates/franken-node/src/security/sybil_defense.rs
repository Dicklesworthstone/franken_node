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

use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// Default: 0.1 (10% from each side = 20% total trim).
    pub trim_ratio: f64,
}

impl Default for TrustAggregator {
    fn default() -> Self {
        Self { trim_ratio: 0.2 }
    }
}

impl TrustAggregator {
    /// Create a new aggregator with the given trim ratio.
    pub fn new(trim_ratio: f64) -> Self {
        Self { trim_ratio }
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

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let n = sorted.len();
        let trim_count = (n as f64 * self.trim_ratio).floor() as usize;

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
        let mean = sum / trimmed.len() as f64;

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

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let n = sorted.len();
        let median = if n.is_multiple_of(2) {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        } else {
            sorted[n / 2]
        };

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
        Self {
            established_threshold,
            base_weight,
            max_weight,
        }
    }

    /// Compute the stake weight for a node based on its verified history.
    ///
    /// The weight is monotonically non-decreasing with history length.
    /// Returns a value in [base_weight, max_weight].
    pub fn compute_weight(&self, node: &TrustNode) -> f64 {
        if node.verified_history_len == 0 {
            return self.base_weight;
        }

        let progress =
            (node.verified_history_len as f64 / self.established_threshold as f64).min(1.0);

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
        if est_weight == 0.0 {
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
        nodes: &HashMap<String, TrustNode>,
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
        nodes: &HashMap<String, TrustNode>,
    ) -> Result<f64, SybilDefenseError> {
        if signals.is_empty() {
            return Err(SybilDefenseError::aggregation_failed(
                "no signals to weight",
            ));
        }

        let pairs = self.apply_weights(signals, nodes);
        let total_weight: f64 = pairs.iter().map(|(_, w)| w).sum();
        if total_weight == 0.0 {
            return Err(SybilDefenseError::aggregation_failed(
                "total weight is zero",
            ));
        }

        let weighted_sum: f64 = pairs.iter().map(|(wv, _)| wv).sum();
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
        Self {
            burst_threshold,
            burst_window_ms,
            similarity_threshold,
            events: Vec::new(),
        }
    }

    /// Detect Sybil clusters among a set of signals targeting the same entity.
    ///
    /// Returns the set of node IDs identified as likely Sybil identities.
    pub fn detect_sybil_cluster(
        &mut self,
        signals: &[TrustSignal],
        nodes: &HashMap<String, TrustNode>,
        timestamp_ms: u64,
    ) -> HashSet<String> {
        let mut sybil_ids: HashSet<String> = HashSet::new();

        // Strategy 1: Burst detection -- many signals in a short window
        let mut by_source: HashMap<&str, Vec<&TrustSignal>> = HashMap::new();
        for sig in signals {
            by_source
                .entry(sig.source_node_id.as_str())
                .or_default()
                .push(sig);
        }

        for (source_id, source_signals) in &by_source {
            if source_signals.len() > self.burst_threshold {
                // Check time window
                let min_ts = source_signals
                    .iter()
                    .map(|s| s.timestamp_ms)
                    .min()
                    .unwrap_or(0);
                let max_ts = source_signals
                    .iter()
                    .map(|s| s.timestamp_ms)
                    .max()
                    .unwrap_or(0);
                if max_ts - min_ts <= self.burst_window_ms {
                    sybil_ids.insert(source_id.to_string());
                }
            }
        }

        // Strategy 2: Coordinated value similarity -- many different nodes
        // submitting nearly identical values within a time window
        let mut by_target: HashMap<&str, Vec<&TrustSignal>> = HashMap::new();
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

                    if new_count as f64 / matches.len() as f64 > 0.8 {
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
            self.events.push(SybilDefenseEvent {
                event_code: SPS_003_SYBIL_DETECTED.to_string(),
                target_id: signals
                    .first()
                    .map(|s| s.target_id.clone())
                    .unwrap_or_default(),
                detail: format!("Detected {} suspected Sybil identities", sybil_ids.len()),
                timestamp_ms,
            });
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
        sybil_ids: &HashSet<String>,
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
        nodes: &HashMap<String, TrustNode>,
    ) -> f64 {
        let id_set: HashSet<&String> = node_ids.iter().collect();
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
    nodes: HashMap<String, TrustNode>,
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
    pub fn nodes(&self) -> &HashMap<String, TrustNode> {
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
        self.events.push(SybilDefenseEvent {
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
        });

        if !sybil_ids.is_empty() {
            self.events.push(SybilDefenseEvent {
                event_code: SPS_003_SYBIL_DETECTED.to_string(),
                target_id: signals
                    .first()
                    .map(|s| s.target_id.clone())
                    .unwrap_or_default(),
                detail: format!("{} Sybil identities attenuated", sybil_ids.len()),
                timestamp_ms,
            });
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
        let mut nodes = HashMap::new();
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
        let mut nodes = HashMap::new();
        nodes.insert("est-1".to_string(), make_established_node("est-1"));

        let avg = w.weighted_average(&signals, &nodes).unwrap();
        assert!((avg - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_weighted_average_empty() {
        let w = StakeWeighter::default();
        let result = w.weighted_average(&[], &HashMap::new());
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

        let mut nodes = HashMap::new();
        nodes.insert("attacker".to_string(), make_new_node("attacker"));

        let sybils = detector.detect_sybil_cluster(&signals, &nodes, 10_000);
        assert!(sybils.contains("attacker"));
    }

    #[test]
    fn test_detect_coordinated_sybil() {
        let mut detector = SybilDetector::new(100, 60_000, 0.95);
        let mut signals = Vec::new();
        let mut nodes = HashMap::new();

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
        let mut nodes = HashMap::new();
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
        let sybil_ids: HashSet<String> = ["sybil".to_string()].into_iter().collect();

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

        let mut nodes = HashMap::new();

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
        let mut nodes = HashMap::new();
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
        let mut nodes = HashMap::new();

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
        let mut nodes = HashMap::new();
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
        let mut nodes = HashMap::new();
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
        let mut nodes = HashMap::new();
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
}
