//! bd-wzjl: Security and trust co-metrics for the benchmark suite (Section 14).
//!
//! Expands the benchmark suite beyond speed-only metrics to include security
//! posture and operational trust dimensions. Each co-metric produces a
//! quantified, machine-verifiable score with confidence intervals, enabling
//! release-gating on security/trust properties alongside performance.
//!
//! # Security Co-Metric Categories
//!
//! - **SECM-SANDBOX**: Sandbox enforcement effectiveness (escape attempts blocked %)
//! - **SECM-REVOCATION**: Revocation propagation latency and completeness
//! - **SECM-POLICY**: Trust policy evaluation throughput and accuracy
//! - **SECM-ATTESTATION**: Attestation verification rate and freshness
//! - **SECM-QUARANTINE**: Quarantine activation speed and containment scope
//!
//! # Trust Co-Metric Categories
//!
//! - **TRUSTM-CARD**: Trust card issuance completeness and validity
//! - **TRUSTM-VEF**: VEF proof coverage and verification success rate
//! - **TRUSTM-EPOCH**: Epoch barrier integrity and transition latency
//! - **TRUSTM-EVIDENCE**: Evidence ledger completeness and durability
//! - **TRUSTM-REPUTATION**: Reputation signal accuracy and convergence
//!
//! # Invariants
//!
//! - **INV-SECM-QUANTIFIED**: Every security metric has a numeric score in [0, 1].
//! - **INV-SECM-DETERMINISTIC**: Same inputs produce same metric scores.
//! - **INV-SECM-THRESHOLDED**: Every metric has configurable pass/fail thresholds.
//! - **INV-SECM-CONFIDENCE**: Every metric includes confidence intervals.
//! - **INV-SECM-VERSIONED**: Scoring formulas are versioned for reproducibility.
//! - **INV-SECM-GATED**: Metrics below threshold block release progression.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// SECM-001: Security metric computation started.
    pub const METRIC_STARTED: &str = "SECM-001";
    /// SECM-002: Security metric computation completed.
    pub const METRIC_COMPLETED: &str = "SECM-002";
    /// SECM-003: Trust metric computation completed.
    pub const TRUST_METRIC_COMPLETED: &str = "SECM-003";
    /// SECM-004: Metric threshold check passed.
    pub const THRESHOLD_PASSED: &str = "SECM-004";
    /// SECM-005: Metric threshold check failed (release-blocking).
    pub const THRESHOLD_FAILED: &str = "SECM-005";
    /// SECM-006: Co-metric report generated.
    pub const REPORT_GENERATED: &str = "SECM-006";
    /// SECM-007: Regression detected against baseline.
    pub const REGRESSION_DETECTED: &str = "SECM-007";
    /// SECM-008: Scoring formula version recorded.
    pub const FORMULA_VERSIONED: &str = "SECM-008";
    /// SECM-009: Confidence interval computed.
    pub const CONFIDENCE_COMPUTED: &str = "SECM-009";
    /// SECM-010: Gate evaluation completed.
    pub const GATE_EVALUATED: &str = "SECM-010";
    /// SECM-ERR-001: Metric computation failed.
    pub const METRIC_COMPUTATION_FAILED: &str = "SECM-ERR-001";
    /// SECM-ERR-002: Invalid metric configuration.
    pub const INVALID_CONFIG: &str = "SECM-ERR-002";
}

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_SECM_QUANTIFIED: &str = "INV-SECM-QUANTIFIED";
    pub const INV_SECM_DETERMINISTIC: &str = "INV-SECM-DETERMINISTIC";
    pub const INV_SECM_THRESHOLDED: &str = "INV-SECM-THRESHOLDED";
    pub const INV_SECM_CONFIDENCE: &str = "INV-SECM-CONFIDENCE";
    pub const INV_SECM_VERSIONED: &str = "INV-SECM-VERSIONED";
    pub const INV_SECM_GATED: &str = "INV-SECM-GATED";
}

/// Scoring formula version for reproducibility.
pub const SCORING_FORMULA_VERSION: &str = "secm-v1";

use crate::capacity_defaults::aliases::MAX_REPORTS;
use crate::push_bounded;

// ---------------------------------------------------------------------------
// Security co-metric categories
// ---------------------------------------------------------------------------

/// Security co-metric categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum SecurityMetricCategory {
    /// SECM-SANDBOX: Sandbox enforcement effectiveness.
    SecmSandbox,
    /// SECM-REVOCATION: Revocation propagation metrics.
    SecmRevocation,
    /// SECM-POLICY: Trust policy evaluation metrics.
    SecmPolicy,
    /// SECM-ATTESTATION: Attestation verification metrics.
    SecmAttestation,
    /// SECM-QUARANTINE: Quarantine activation metrics.
    SecmQuarantine,
}

impl SecurityMetricCategory {
    pub fn all() -> &'static [SecurityMetricCategory] {
        &[
            Self::SecmSandbox,
            Self::SecmRevocation,
            Self::SecmPolicy,
            Self::SecmAttestation,
            Self::SecmQuarantine,
        ]
    }

    pub fn id(&self) -> &'static str {
        match self {
            Self::SecmSandbox => "SECM-SANDBOX",
            Self::SecmRevocation => "SECM-REVOCATION",
            Self::SecmPolicy => "SECM-POLICY",
            Self::SecmAttestation => "SECM-ATTESTATION",
            Self::SecmQuarantine => "SECM-QUARANTINE",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::SecmSandbox => "Sandbox enforcement effectiveness (escape attempts blocked %)",
            Self::SecmRevocation => "Revocation propagation latency and completeness",
            Self::SecmPolicy => "Trust policy evaluation throughput and accuracy",
            Self::SecmAttestation => "Attestation verification rate and freshness",
            Self::SecmQuarantine => "Quarantine activation speed and containment scope",
        }
    }
}

/// Trust co-metric categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum TrustMetricCategory {
    /// TRUSTM-CARD: Trust card metrics.
    TrustmCard,
    /// TRUSTM-VEF: Verifiable execution fabric metrics.
    TrustmVef,
    /// TRUSTM-EPOCH: Epoch barrier metrics.
    TrustmEpoch,
    /// TRUSTM-EVIDENCE: Evidence ledger metrics.
    TrustmEvidence,
    /// TRUSTM-REPUTATION: Reputation signal metrics.
    TrustmReputation,
}

impl TrustMetricCategory {
    pub fn all() -> &'static [TrustMetricCategory] {
        &[
            Self::TrustmCard,
            Self::TrustmVef,
            Self::TrustmEpoch,
            Self::TrustmEvidence,
            Self::TrustmReputation,
        ]
    }

    pub fn id(&self) -> &'static str {
        match self {
            Self::TrustmCard => "TRUSTM-CARD",
            Self::TrustmVef => "TRUSTM-VEF",
            Self::TrustmEpoch => "TRUSTM-EPOCH",
            Self::TrustmEvidence => "TRUSTM-EVIDENCE",
            Self::TrustmReputation => "TRUSTM-REPUTATION",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::TrustmCard => "Trust card issuance completeness and validity",
            Self::TrustmVef => "VEF proof coverage and verification success rate",
            Self::TrustmEpoch => "Epoch barrier integrity and transition latency",
            Self::TrustmEvidence => "Evidence ledger completeness and durability",
            Self::TrustmReputation => "Reputation signal accuracy and convergence",
        }
    }
}

// ---------------------------------------------------------------------------
// Metric measurement types
// ---------------------------------------------------------------------------

/// Confidence interval for a metric measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
    pub confidence_level: f64,
}

/// A single metric measurement with score and confidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricMeasurement {
    pub metric_id: String,
    pub score: f64,
    pub confidence_interval: ConfidenceInterval,
    pub sample_count: u64,
    pub formula_version: String,
    pub raw_data: BTreeMap<String, f64>,
}

impl MetricMeasurement {
    pub fn is_valid(&self) -> bool {
        self.score.is_finite()
            && self.score >= 0.0
            && self.score <= 1.0
            && self.confidence_interval.lower.is_finite()
            && self.confidence_interval.upper.is_finite()
            && self.confidence_interval.lower <= self.score
            && self.confidence_interval.upper >= self.score
            && self.confidence_interval.confidence_level.is_finite()
            && self.confidence_interval.confidence_level > 0.0
            && self.confidence_interval.confidence_level <= 1.0
            && self.sample_count > 0
            && !self.formula_version.trim().is_empty()
    }
}

/// Threshold configuration for a metric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricThreshold {
    pub metric_id: String,
    pub pass_threshold: f64,
    pub warn_threshold: f64,
    pub description: String,
}

/// Result of evaluating a metric against its threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricGateResult {
    pub metric_id: String,
    pub score: f64,
    pub threshold: f64,
    pub passed: bool,
    pub warning: bool,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Co-metric report
// ---------------------------------------------------------------------------

/// Full security and trust co-metric report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoMetricReport {
    pub report_id: String,
    pub timestamp: String,
    pub formula_version: String,
    pub security_metrics: Vec<MetricMeasurement>,
    pub trust_metrics: Vec<MetricMeasurement>,
    pub gate_results: Vec<MetricGateResult>,
    pub overall_pass: bool,
    pub security_coverage: f64,
    pub trust_coverage: f64,
    pub content_hash: String,
}

fn hash_bool(hasher: &mut Sha256, value: bool) {
    hasher.update([u8::from(value)]);
}

fn hash_f64(hasher: &mut Sha256, value: f64) {
    if value.is_finite() {
        hasher.update(value.to_le_bytes());
    } else {
        hasher.update(f64::NAN.to_le_bytes());
    }
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(value.as_bytes());
}

fn hash_measurements(hasher: &mut Sha256, measurements: &[MetricMeasurement]) {
    let len = u64::try_from(measurements.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    for measurement in measurements {
        hash_string(hasher, &measurement.metric_id);
        hash_f64(hasher, measurement.score);
        hash_f64(hasher, measurement.confidence_interval.lower);
        hash_f64(hasher, measurement.confidence_interval.upper);
        hash_f64(hasher, measurement.confidence_interval.confidence_level);
        hasher.update(measurement.sample_count.to_le_bytes());
        hash_string(hasher, &measurement.formula_version);
        let raw_data_len = u64::try_from(measurement.raw_data.len()).unwrap_or(u64::MAX);
        hasher.update(raw_data_len.to_le_bytes());
        for (key, value) in &measurement.raw_data {
            hash_string(hasher, key);
            hash_f64(hasher, *value);
        }
    }
}

fn hash_gate_results(hasher: &mut Sha256, gate_results: &[MetricGateResult]) {
    let len = u64::try_from(gate_results.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    for gate in gate_results {
        hash_string(hasher, &gate.metric_id);
        hash_f64(hasher, gate.score);
        hash_f64(hasher, gate.threshold);
        hash_bool(hasher, gate.passed);
        hash_bool(hasher, gate.warning);
        hash_string(hasher, &gate.detail);
    }
}

impl CoMetricReport {
    pub fn compute_hash(
        formula_version: &str,
        security: &[MetricMeasurement],
        trust: &[MetricMeasurement],
        gate_results: &[MetricGateResult],
        overall_pass: bool,
        security_coverage: f64,
        trust_coverage: f64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"security_trust_metrics_hash_v2:");
        hash_string(&mut hasher, formula_version);
        hash_measurements(&mut hasher, security);
        hash_measurements(&mut hasher, trust);
        hash_gate_results(&mut hasher, gate_results);
        hash_bool(&mut hasher, overall_pass);
        hash_f64(&mut hasher, security_coverage);
        hash_f64(&mut hasher, trust_coverage);
        hex::encode(hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the co-metric evaluation engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoMetricConfig {
    pub security_thresholds: BTreeMap<String, MetricThreshold>,
    pub trust_thresholds: BTreeMap<String, MetricThreshold>,
    pub require_all_categories: bool,
    pub formula_version: String,
}

impl Default for CoMetricConfig {
    fn default() -> Self {
        let mut sec_thresholds = BTreeMap::new();
        for cat in SecurityMetricCategory::all() {
            sec_thresholds.insert(
                cat.id().to_string(),
                MetricThreshold {
                    metric_id: cat.id().to_string(),
                    pass_threshold: 0.7,
                    warn_threshold: 0.8,
                    description: cat.description().to_string(),
                },
            );
        }

        let mut trust_thresholds = BTreeMap::new();
        for cat in TrustMetricCategory::all() {
            trust_thresholds.insert(
                cat.id().to_string(),
                MetricThreshold {
                    metric_id: cat.id().to_string(),
                    pass_threshold: 0.7,
                    warn_threshold: 0.8,
                    description: cat.description().to_string(),
                },
            );
        }

        Self {
            security_thresholds: sec_thresholds,
            trust_thresholds,
            require_all_categories: true,
            formula_version: SCORING_FORMULA_VERSION.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The co-metric evaluation engine.
#[derive(Debug, Clone)]
pub struct CoMetricEngine {
    config: CoMetricConfig,
    reports: Vec<CoMetricReport>,
}

impl Default for CoMetricEngine {
    fn default() -> Self {
        Self::new(CoMetricConfig::default())
    }
}

impl CoMetricEngine {
    pub fn new(config: CoMetricConfig) -> Self {
        Self {
            config,
            reports: Vec::new(),
        }
    }

    /// Evaluate security and trust co-metrics and produce a gated report.
    pub fn evaluate(
        &mut self,
        security_measurements: Vec<MetricMeasurement>,
        trust_measurements: Vec<MetricMeasurement>,
        report_id: &str,
        timestamp: &str,
    ) -> CoMetricReport {
        let mut gate_results = Vec::new();

        // Evaluate security metrics against thresholds
        for m in &security_measurements {
            if let Some(threshold) = self.config.security_thresholds.get(&m.metric_id) {
                gate_results.push(self.evaluate_gate(m, threshold));
            }
        }

        // Evaluate trust metrics against thresholds
        for m in &trust_measurements {
            if let Some(threshold) = self.config.trust_thresholds.get(&m.metric_id) {
                gate_results.push(self.evaluate_gate(m, threshold));
            }
        }

        // Check coverage
        let sec_count = security_measurements.len();
        let sec_total = SecurityMetricCategory::all().len().max(1);
        let sec_covered = sec_count as f64 / sec_total as f64;
        let sec_covered = if !sec_covered.is_finite() {
            0.0
        } else {
            sec_covered
        };

        let trust_count = trust_measurements.len();
        let trust_total = TrustMetricCategory::all().len().max(1);
        let trust_covered = trust_count as f64 / trust_total as f64;
        let trust_covered = if !trust_covered.is_finite() {
            0.0
        } else {
            trust_covered
        };

        let all_gates_pass = gate_results.iter().all(|g| g.passed);
        let coverage_ok =
            !self.config.require_all_categories || (sec_covered >= 1.0 && trust_covered >= 1.0);
        let security_coverage = sec_covered.min(1.0);
        let trust_coverage = trust_covered.min(1.0);
        let overall_pass = all_gates_pass && coverage_ok;

        let content_hash = CoMetricReport::compute_hash(
            &self.config.formula_version,
            &security_measurements,
            &trust_measurements,
            &gate_results,
            overall_pass,
            security_coverage,
            trust_coverage,
        );

        let report = CoMetricReport {
            report_id: report_id.to_string(),
            timestamp: timestamp.to_string(),
            formula_version: self.config.formula_version.clone(),
            security_metrics: security_measurements,
            trust_metrics: trust_measurements,
            gate_results,
            overall_pass,
            security_coverage,
            trust_coverage,
            content_hash,
        };

        push_bounded(&mut self.reports, report.clone(), MAX_REPORTS);
        report
    }

    /// Get all generated reports.
    pub fn reports(&self) -> &[CoMetricReport] {
        &self.reports
    }

    /// Export reports as JSON.
    pub fn export_reports_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.reports)
    }

    fn evaluate_gate(
        &self,
        measurement: &MetricMeasurement,
        threshold: &MetricThreshold,
    ) -> MetricGateResult {
        if !measurement.is_valid() {
            return MetricGateResult {
                metric_id: measurement.metric_id.clone(),
                score: measurement.score,
                threshold: threshold.pass_threshold,
                passed: false,
                warning: false,
                detail: format!(
                    "{} invalid metric measurement rejected before threshold check",
                    measurement.metric_id
                ),
            };
        }

        let passed = measurement.score >= threshold.pass_threshold;
        let warning = measurement.score >= threshold.pass_threshold
            && measurement.score < threshold.warn_threshold;

        MetricGateResult {
            metric_id: measurement.metric_id.clone(),
            score: measurement.score,
            threshold: threshold.pass_threshold,
            passed,
            warning,
            detail: if passed {
                format!(
                    "{} score {:.3} >= threshold {:.3}",
                    measurement.metric_id, measurement.score, threshold.pass_threshold
                )
            } else {
                format!(
                    "{} score {:.3} BELOW threshold {:.3}",
                    measurement.metric_id, measurement.score, threshold.pass_threshold
                )
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_passing_security_measurements() -> Vec<MetricMeasurement> {
        SecurityMetricCategory::all()
            .iter()
            .map(|cat| MetricMeasurement {
                metric_id: cat.id().to_string(),
                score: 0.85,
                confidence_interval: ConfidenceInterval {
                    lower: 0.80,
                    upper: 0.90,
                    confidence_level: 0.95,
                },
                sample_count: 100,
                formula_version: SCORING_FORMULA_VERSION.to_string(),
                raw_data: BTreeMap::from([
                    ("mean".to_string(), 0.85),
                    ("stddev".to_string(), 0.05),
                ]),
            })
            .collect()
    }

    fn make_passing_trust_measurements() -> Vec<MetricMeasurement> {
        TrustMetricCategory::all()
            .iter()
            .map(|cat| MetricMeasurement {
                metric_id: cat.id().to_string(),
                score: 0.9,
                confidence_interval: ConfidenceInterval {
                    lower: 0.85,
                    upper: 0.95,
                    confidence_level: 0.95,
                },
                sample_count: 100,
                formula_version: SCORING_FORMULA_VERSION.to_string(),
                raw_data: BTreeMap::from([("mean".to_string(), 0.9), ("stddev".to_string(), 0.03)]),
            })
            .collect()
    }

    fn make_failing_measurement(metric_id: &str) -> MetricMeasurement {
        MetricMeasurement {
            metric_id: metric_id.to_string(),
            score: 0.3,
            confidence_interval: ConfidenceInterval {
                lower: 0.2,
                upper: 0.4,
                confidence_level: 0.95,
            },
            sample_count: 50,
            formula_version: SCORING_FORMULA_VERSION.to_string(),
            raw_data: BTreeMap::new(),
        }
    }

    fn make_measurement_with_score(metric_id: &str, score: f64) -> MetricMeasurement {
        MetricMeasurement {
            metric_id: metric_id.to_string(),
            score,
            confidence_interval: ConfidenceInterval {
                lower: score - 0.05,
                upper: score + 0.05,
                confidence_level: 0.95,
            },
            sample_count: 25,
            formula_version: SCORING_FORMULA_VERSION.to_string(),
            raw_data: BTreeMap::from([("score".to_string(), score)]),
        }
    }

    // === Category coverage ===

    #[test]
    fn five_security_metric_categories() {
        assert_eq!(SecurityMetricCategory::all().len(), 5);
    }

    #[test]
    fn five_trust_metric_categories() {
        assert_eq!(TrustMetricCategory::all().len(), 5);
    }

    #[test]
    fn security_categories_have_ids_and_descriptions() {
        for cat in SecurityMetricCategory::all() {
            assert!(!cat.id().is_empty());
            assert!(!cat.description().is_empty());
            assert!(cat.id().starts_with("SECM-"));
        }
    }

    #[test]
    fn trust_categories_have_ids_and_descriptions() {
        for cat in TrustMetricCategory::all() {
            assert!(!cat.id().is_empty());
            assert!(!cat.description().is_empty());
            assert!(cat.id().starts_with("TRUSTM-"));
        }
    }

    // === Metric measurement validation (INV-SECM-QUANTIFIED) ===

    #[test]
    fn valid_measurement_passes_validation() {
        let m = &make_passing_security_measurements()[0];
        assert!(m.is_valid());
    }

    #[test]
    fn out_of_range_measurement_fails_validation() {
        let m = MetricMeasurement {
            metric_id: "test".to_string(),
            score: 1.5,
            confidence_interval: ConfidenceInterval {
                lower: 1.0,
                upper: 2.0,
                confidence_level: 0.95,
            },
            sample_count: 10,
            formula_version: "v1".to_string(),
            raw_data: BTreeMap::new(),
        };
        assert!(!m.is_valid());
    }

    #[test]
    fn negative_measurement_score_fails_validation() {
        let m = make_measurement_with_score("negative-score", -0.01);

        assert!(!m.is_valid());
    }

    #[test]
    fn nan_measurement_score_fails_validation() {
        let mut m = make_measurement_with_score("nan-score", 0.5);
        m.score = f64::NAN;

        assert!(!m.is_valid());
    }

    #[test]
    fn confidence_interval_below_score_fails_validation() {
        let mut m = make_measurement_with_score("bad-ci-low", 0.5);
        m.confidence_interval.lower = 0.6;

        assert!(!m.is_valid());
    }

    #[test]
    fn confidence_interval_above_score_fails_validation() {
        let mut m = make_measurement_with_score("bad-ci-high", 0.5);
        m.confidence_interval.upper = 0.4;

        assert!(!m.is_valid());
    }

    #[test]
    fn nan_confidence_lower_fails_validation() {
        let mut m = make_measurement_with_score("nan-ci-lower", 0.5);
        m.confidence_interval.lower = f64::NAN;

        assert!(!m.is_valid());
    }

    #[test]
    fn infinite_confidence_upper_fails_validation() {
        let mut m = make_measurement_with_score("inf-ci-upper", 0.5);
        m.confidence_interval.upper = f64::INFINITY;

        assert!(!m.is_valid());
    }

    #[test]
    fn zero_confidence_level_fails_validation() {
        let mut m = make_measurement_with_score("zero-confidence", 0.5);
        m.confidence_interval.confidence_level = 0.0;

        assert!(!m.is_valid());
    }

    #[test]
    fn confidence_level_above_one_fails_validation() {
        let mut m = make_measurement_with_score("high-confidence", 0.5);
        m.confidence_interval.confidence_level = 1.01;

        assert!(!m.is_valid());
    }

    #[test]
    fn zero_sample_count_fails_validation() {
        let mut m = make_measurement_with_score("zero-samples", 0.5);
        m.sample_count = 0;

        assert!(!m.is_valid());
    }

    #[test]
    fn blank_formula_version_fails_validation() {
        let mut m = make_measurement_with_score("blank-formula", 0.5);
        m.formula_version = " \t ".to_string();

        assert!(!m.is_valid());
    }

    #[test]
    fn invalid_high_security_measurement_blocks_gate() {
        let mut engine = CoMetricEngine::default();
        let mut sec = make_passing_security_measurements();
        sec[0].score = f64::INFINITY;
        sec[0].raw_data.insert("score".to_string(), f64::INFINITY);

        let report = engine.evaluate(
            sec,
            make_passing_trust_measurements(),
            "invalid-security",
            "2026-02-20T00:00:00Z",
        );

        assert!(!report.overall_pass);
        let gate = report
            .gate_results
            .iter()
            .find(|gate| gate.metric_id == "SECM-SANDBOX")
            .expect("sandbox gate result");
        assert!(!gate.passed);
        assert!(!gate.warning);
        assert!(gate.detail.contains("invalid metric measurement"));
    }

    #[test]
    fn unknown_security_metric_does_not_create_gate_and_fails_coverage() {
        let mut engine = CoMetricEngine::default();
        let report = engine.evaluate(
            vec![make_measurement_with_score("SECM-UNKNOWN", 0.99)],
            make_passing_trust_measurements(),
            "unknown-security",
            "2026-02-20T00:00:00Z",
        );

        assert!(!report.overall_pass);
        assert!(
            report
                .gate_results
                .iter()
                .all(|g| g.metric_id != "SECM-UNKNOWN")
        );
        assert!(report.security_coverage < 1.0);
    }

    #[test]
    fn missing_trust_measurements_fail_required_coverage() {
        let mut engine = CoMetricEngine::default();
        let report = engine.evaluate(
            make_passing_security_measurements(),
            Vec::new(),
            "missing-trust",
            "2026-02-20T00:00:00Z",
        );

        assert!(!report.overall_pass);
        assert_eq!(report.trust_coverage, 0.0);
    }

    #[test]
    fn failing_trust_metric_blocks_release() {
        let mut engine = CoMetricEngine::default();
        let mut trust = make_passing_trust_measurements();
        trust[0] = make_failing_measurement("TRUSTM-CARD");

        let report = engine.evaluate(
            make_passing_security_measurements(),
            trust,
            "failing-trust",
            "2026-02-20T00:00:00Z",
        );

        assert!(!report.overall_pass);
        let card_gate = report
            .gate_results
            .iter()
            .find(|g| g.metric_id == "TRUSTM-CARD")
            .expect("trust card gate should exist");
        assert!(!card_gate.passed);
    }

    // === Full evaluation pass (INV-SECM-GATED) ===

    #[test]
    fn full_passing_evaluation_passes_gate() {
        let mut engine = CoMetricEngine::default();
        let report = engine.evaluate(
            make_passing_security_measurements(),
            make_passing_trust_measurements(),
            "test-report",
            "2026-02-20T00:00:00Z",
        );

        assert!(report.overall_pass);
        assert_eq!(report.gate_results.len(), 10); // 5 sec + 5 trust
        assert!(report.gate_results.iter().all(|g| g.passed));
    }

    #[test]
    fn failing_metric_blocks_release() {
        let mut engine = CoMetricEngine::default();
        let mut sec = make_passing_security_measurements();
        sec[0] = make_failing_measurement("SECM-SANDBOX");

        let report = engine.evaluate(
            sec,
            make_passing_trust_measurements(),
            "fail-report",
            "2026-02-20T00:00:00Z",
        );

        assert!(!report.overall_pass);
        let sandbox_gate = report
            .gate_results
            .iter()
            .find(|g| g.metric_id == "SECM-SANDBOX")
            .unwrap();
        assert!(!sandbox_gate.passed);
    }

    // === Coverage check ===

    #[test]
    fn incomplete_coverage_fails_when_required() {
        let mut engine = CoMetricEngine::default();
        // Only provide 1 security metric instead of 5
        let sec = vec![make_passing_security_measurements().remove(0)];
        let report = engine.evaluate(
            sec,
            make_passing_trust_measurements(),
            "coverage-report",
            "2026-02-20T00:00:00Z",
        );

        assert!(!report.overall_pass); // Coverage requirement not met
        assert!(report.security_coverage < 1.0);
    }

    // === Determinism (INV-SECM-DETERMINISTIC) ===

    #[test]
    fn evaluation_is_deterministic() {
        let sec = make_passing_security_measurements();
        let trust = make_passing_trust_measurements();

        let mut e1 = CoMetricEngine::default();
        let mut e2 = CoMetricEngine::default();

        let r1 = e1.evaluate(sec.clone(), trust.clone(), "det", "2026-02-20T00:00:00Z");
        let r2 = e2.evaluate(sec, trust, "det", "2026-02-20T00:00:00Z");

        assert_eq!(r1.content_hash, r2.content_hash);
        assert_eq!(r1.overall_pass, r2.overall_pass);
    }

    // === Confidence intervals (INV-SECM-CONFIDENCE) ===

    #[test]
    fn all_measurements_have_confidence_intervals() {
        let sec = make_passing_security_measurements();
        for m in &sec {
            assert!(m.confidence_interval.lower <= m.score);
            assert!(m.confidence_interval.upper >= m.score);
            assert!(m.confidence_interval.confidence_level > 0.0);
        }
    }

    // === Versioning (INV-SECM-VERSIONED) ===

    #[test]
    fn report_includes_formula_version() {
        let mut engine = CoMetricEngine::default();
        let report = engine.evaluate(
            make_passing_security_measurements(),
            make_passing_trust_measurements(),
            "ver-report",
            "2026-02-20T00:00:00Z",
        );

        assert_eq!(report.formula_version, SCORING_FORMULA_VERSION);
    }

    // === Config defaults ===

    #[test]
    fn default_config_has_all_thresholds() {
        let config = CoMetricConfig::default();
        assert_eq!(config.security_thresholds.len(), 5);
        assert_eq!(config.trust_thresholds.len(), 5);
    }

    #[test]
    fn default_thresholds_are_reasonable() {
        let config = CoMetricConfig::default();
        for t in config.security_thresholds.values() {
            assert!(t.pass_threshold >= 0.0 && t.pass_threshold <= 1.0);
            assert!(t.warn_threshold >= t.pass_threshold);
        }
    }

    // === Report storage ===

    #[test]
    fn reports_are_accumulated() {
        let mut engine = CoMetricEngine::default();
        engine.evaluate(
            make_passing_security_measurements(),
            make_passing_trust_measurements(),
            "r1",
            "2026-02-20T00:00:00Z",
        );
        engine.evaluate(
            make_passing_security_measurements(),
            make_passing_trust_measurements(),
            "r2",
            "2026-02-20T00:01:00Z",
        );

        assert_eq!(engine.reports().len(), 2);
    }

    #[test]
    fn reports_export_as_json() {
        let mut engine = CoMetricEngine::default();
        engine.evaluate(
            make_passing_security_measurements(),
            make_passing_trust_measurements(),
            "json-r",
            "2026-02-20T00:00:00Z",
        );

        let json = engine.export_reports_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
    }

    // === Content hash ===

    #[test]
    fn content_hash_is_64_hex_chars() {
        let mut engine = CoMetricEngine::default();
        let report = engine.evaluate(
            make_passing_security_measurements(),
            make_passing_trust_measurements(),
            "hash-r",
            "2026-02-20T00:00:00Z",
        );

        assert_eq!(report.content_hash.len(), 64);
    }

    #[test]
    fn content_hash_changes_with_formula_version() {
        let sec = make_passing_security_measurements();
        let trust = make_passing_trust_measurements();

        let config_a = CoMetricConfig {
            formula_version: "secm-v1".to_string(),
            ..CoMetricConfig::default()
        };
        let config_b = CoMetricConfig {
            formula_version: "secm-v2".to_string(),
            ..CoMetricConfig::default()
        };

        let mut engine_a = CoMetricEngine::new(config_a);
        let mut engine_b = CoMetricEngine::new(config_b);

        let report_a = engine_a.evaluate(
            sec.clone(),
            trust.clone(),
            "hash-formula-a",
            "2026-02-20T00:00:00Z",
        );
        let report_b = engine_b.evaluate(sec, trust, "hash-formula-b", "2026-02-20T00:00:00Z");

        assert_ne!(report_a.formula_version, report_b.formula_version);
        assert_ne!(
            report_a.content_hash, report_b.content_hash,
            "Different formula versions must produce different content hashes"
        );
    }

    #[test]
    fn content_hash_changes_with_gate_results() {
        let mut sec = make_passing_security_measurements();
        sec[0].score = 0.75;
        let score = sec[0].score;
        sec[0].raw_data.insert("mean".to_string(), score);
        let trust = make_passing_trust_measurements();

        let config_a = CoMetricConfig::default();
        let mut config_b = CoMetricConfig::default();
        config_b
            .security_thresholds
            .get_mut("SECM-SANDBOX")
            .expect("default sandbox threshold")
            .pass_threshold = 0.8;

        let mut engine_a = CoMetricEngine::new(config_a);
        let mut engine_b = CoMetricEngine::new(config_b);

        let report_a = engine_a.evaluate(
            sec.clone(),
            trust.clone(),
            "hash-gates-a",
            "2026-02-20T00:00:00Z",
        );
        let report_b = engine_b.evaluate(sec, trust, "hash-gates-b", "2026-02-20T00:00:00Z");

        let gate_a = report_a
            .gate_results
            .iter()
            .find(|gate| gate.metric_id == "SECM-SANDBOX")
            .expect("sandbox gate result");
        let gate_b = report_b
            .gate_results
            .iter()
            .find(|gate| gate.metric_id == "SECM-SANDBOX")
            .expect("sandbox gate result");

        assert_ne!(gate_a.passed, gate_b.passed);
        assert_ne!(report_a.overall_pass, report_b.overall_pass);
        assert_ne!(
            report_a.content_hash, report_b.content_hash,
            "Different gate results must produce different content hashes"
        );
    }

    // === Threshold details ===

    #[test]
    fn threshold_descriptions_populated() {
        let config = CoMetricConfig::default();
        for t in config.security_thresholds.values() {
            assert!(!t.description.is_empty());
        }
        for t in config.trust_thresholds.values() {
            assert!(!t.description.is_empty());
        }
    }
}
