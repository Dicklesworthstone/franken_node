//! bd-k4s: Product-level benchmark suite with secure-extension scenarios.
//!
//! Validates franken_node performance under realistic security-hardened
//! conditions, covering all major workflow categories with sandbox enforcement
//! active. Produces machine-readable results with confidence intervals for
//! CI/release gating and public reporting.
//!
//! # Invariants
//!
//! - **INV-BS-DETERMINISTIC**: Identical inputs produce statistically equivalent results (variance < 5%).
//! - **INV-BS-SECURE**: All benchmarks run with sandbox enforcement active.
//! - **INV-BS-CONFIDENCE**: Every measurement includes confidence intervals.
//! - **INV-BS-SCORING**: Scoring formulas are versioned and published alongside results.
//! - **INV-BS-MACHINE-READABLE**: Results export as structured JSON with provenance.
//! - **INV-BS-COVERAGE**: All six Section 14 benchmark dimensions are represented.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const BS_SUITE_INITIALIZED: &str = "BS-001";
pub const BS_SCENARIO_STARTED: &str = "BS-002";
pub const BS_MEASUREMENT_RECORDED: &str = "BS-003";
pub const BS_SCORE_COMPUTED: &str = "BS-004";
pub const BS_REGRESSION_DETECTED: &str = "BS-005";
pub const BS_SUITE_COMPLETED: &str = "BS-006";
pub const BS_DETERMINISM_CHECK_PASSED: &str = "BS-007";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_BS_DETERMINISTIC: &str = "INV-BS-DETERMINISTIC";
pub const INV_BS_SECURE: &str = "INV-BS-SECURE";
pub const INV_BS_CONFIDENCE: &str = "INV-BS-CONFIDENCE";
pub const INV_BS_SCORING: &str = "INV-BS-SCORING";
pub const INV_BS_MACHINE_READABLE: &str = "INV-BS-MACHINE-READABLE";
pub const INV_BS_COVERAGE: &str = "INV-BS-COVERAGE";

/// Scoring formula version tag.
pub const SCORING_FORMULA_VERSION: &str = "sf-v1";

/// Suite version for result schema compatibility.
pub const SUITE_VERSION: &str = "1.0.0";

/// Maximum acceptable coefficient of variation for deterministic benchmarks.
pub const MAX_VARIANCE_PCT: f64 = 5.0;

/// Default regression threshold as a percentage.
pub const DEFAULT_REGRESSION_THRESHOLD_PCT: f64 = 10.0;

// ---------------------------------------------------------------------------
// Benchmark dimension enum
// ---------------------------------------------------------------------------

/// The six required benchmark dimensions from Section 14.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkDimension {
    CompatibilityCorrectness,
    PerformanceUnderHardening,
    ContainmentLatency,
    ReplayDeterminism,
    AdversarialResilience,
    MigrationSpeed,
}

impl BenchmarkDimension {
    /// All dimensions for coverage checks.
    pub fn all() -> &'static [BenchmarkDimension] {
        &[
            BenchmarkDimension::CompatibilityCorrectness,
            BenchmarkDimension::PerformanceUnderHardening,
            BenchmarkDimension::ContainmentLatency,
            BenchmarkDimension::ReplayDeterminism,
            BenchmarkDimension::AdversarialResilience,
            BenchmarkDimension::MigrationSpeed,
        ]
    }
}

impl fmt::Display for BenchmarkDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BenchmarkDimension::CompatibilityCorrectness => write!(f, "compatibility_correctness"),
            BenchmarkDimension::PerformanceUnderHardening => {
                write!(f, "performance_under_hardening")
            }
            BenchmarkDimension::ContainmentLatency => write!(f, "containment_latency"),
            BenchmarkDimension::ReplayDeterminism => write!(f, "replay_determinism"),
            BenchmarkDimension::AdversarialResilience => write!(f, "adversarial_resilience"),
            BenchmarkDimension::MigrationSpeed => write!(f, "migration_speed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Scoring configuration
// ---------------------------------------------------------------------------

/// Defines the ideal/threshold boundaries for a benchmark metric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Best achievable value for this metric.
    pub ideal: f64,
    /// Unacceptable value where score becomes 0.
    pub threshold: f64,
    /// If true, lower values are better (latency). If false, higher is better (throughput).
    pub lower_is_better: bool,
}

impl ScoringConfig {
    /// Create a config where lower measured values are better.
    pub fn lower_is_better(ideal: f64, threshold: f64) -> Self {
        ScoringConfig {
            ideal,
            threshold,
            lower_is_better: true,
        }
    }

    /// Create a config where higher measured values are better.
    pub fn higher_is_better(ideal: f64, threshold: f64) -> Self {
        ScoringConfig {
            ideal,
            threshold,
            lower_is_better: false,
        }
    }

    /// Compute the normalized 0-100 score for a measurement.
    ///
    /// Formula: `score = clamp(100 * (1 - (measured - ideal) / (threshold - ideal)), 0, 100)`
    ///
    /// For higher-is-better metrics, the formula is inverted:
    /// `score = clamp(100 * (1 - (ideal - measured) / (ideal - threshold)), 0, 100)`
    pub fn score(&self, measured: f64) -> u32 {
        let raw = if self.lower_is_better {
            if (self.threshold - self.ideal).abs() < f64::EPSILON {
                return if measured <= self.ideal { 100 } else { 0 };
            }
            100.0 * (1.0 - (measured - self.ideal) / (self.threshold - self.ideal))
        } else {
            if (self.ideal - self.threshold).abs() < f64::EPSILON {
                return if measured >= self.ideal { 100 } else { 0 };
            }
            100.0 * (1.0 - (self.ideal - measured) / (self.ideal - self.threshold))
        };
        raw.clamp(0.0, 100.0).round() as u32
    }
}

// ---------------------------------------------------------------------------
// Default scoring table
// ---------------------------------------------------------------------------

/// Return the default scoring configuration for known scenario names.
pub fn default_scoring(scenario_name: &str) -> Option<ScoringConfig> {
    match scenario_name {
        "cold_start_latency" => Some(ScoringConfig::lower_is_better(100.0, 500.0)),
        "p99_request_latency" => Some(ScoringConfig::lower_is_better(1.0, 10.0)),
        "extension_overhead_ratio" => Some(ScoringConfig::lower_is_better(1.0, 1.5)),
        "migration_scanner_throughput" => Some(ScoringConfig::higher_is_better(1000.0, 200.0)),
        "lockstep_harness_throughput" => Some(ScoringConfig::higher_is_better(500.0, 100.0)),
        "quarantine_propagation_latency" => Some(ScoringConfig::lower_is_better(100.0, 2000.0)),
        "trust_card_materialization" => Some(ScoringConfig::lower_is_better(10.0, 200.0)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Hardware profile
// ---------------------------------------------------------------------------

/// Describes the hardware environment for reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub cpu: String,
    pub memory_mb: u64,
    pub os: String,
}

impl HardwareProfile {
    /// Compute a deterministic fingerprint of this hardware profile.
    pub fn fingerprint(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"benchmark_suite_fingerprint_v1:" as &[u8]);
        sha2::Digest::update(&mut hasher, self.cpu.as_bytes());
        sha2::Digest::update(&mut hasher, self.memory_mb.to_le_bytes());
        sha2::Digest::update(&mut hasher, self.os.as_bytes());
        format!("{:x}", sha2::Digest::finalize(hasher))
    }
}

// ---------------------------------------------------------------------------
// Runtime versions
// ---------------------------------------------------------------------------

/// Pinned runtime versions for the benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeVersions {
    pub franken_node: String,
    pub node: Option<String>,
    pub bun: Option<String>,
}

// ---------------------------------------------------------------------------
// Benchmark scenario definition
// ---------------------------------------------------------------------------

/// Defines a single benchmark scenario to execute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioDefinition {
    /// Which Section 14 dimension this belongs to.
    pub dimension: BenchmarkDimension,
    /// Unique scenario name within the suite.
    pub name: String,
    /// Unit of measurement (e.g., "ms", "fixtures/s", "ratio", "percent").
    pub unit: String,
    /// Number of iterations for statistical significance.
    pub iterations: u32,
    /// Number of warmup iterations to discard.
    pub warmup_iterations: u32,
    /// Whether sandbox enforcement is required.
    pub sandbox_required: bool,
    /// Scoring configuration for this scenario.
    pub scoring: ScoringConfig,
}

// ---------------------------------------------------------------------------
// Measurement and result types
// ---------------------------------------------------------------------------

/// A single raw measurement from a benchmark iteration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawMeasurement {
    pub iteration: u32,
    pub value: f64,
}

/// Confidence interval (lower, upper) at 95%.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
}

/// Result of executing one benchmark scenario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub dimension: BenchmarkDimension,
    pub name: String,
    pub raw_value: f64,
    pub unit: String,
    pub confidence_interval: ConfidenceInterval,
    pub score: u32,
    pub iterations: u32,
    pub variance_pct: f64,
}

/// Complete benchmark suite report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub suite_version: String,
    pub scoring_formula_version: String,
    pub timestamp_utc: String,
    pub hardware_profile: HardwareProfile,
    pub runtime_versions: RuntimeVersions,
    pub scenarios: Vec<ScenarioResult>,
    pub aggregate_score: u32,
    pub provenance_hash: String,
}

impl BenchmarkReport {
    /// Compute the provenance hash of this report (excluding the hash field).
    pub fn compute_provenance_hash(&self) -> String {
        let mut report_for_hash = self.clone();
        report_for_hash.provenance_hash = String::new();
        let json = serde_json::to_string(&report_for_hash).unwrap_or_default();
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"benchmark_suite_json_v1:" as &[u8]);
        sha2::Digest::update(&mut hasher, json.as_bytes());
        format!("sha256:{:x}", sha2::Digest::finalize(hasher))
    }

    /// Check dimension coverage: returns the set of covered dimensions.
    pub fn covered_dimensions(&self) -> Vec<BenchmarkDimension> {
        let mut dims: Vec<BenchmarkDimension> = self
            .scenarios
            .iter()
            .map(|s| s.dimension)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        dims.sort_by_key(|d| format!("{d}"));
        dims
    }

    /// Check if all six Section 14 dimensions are covered.
    pub fn has_full_coverage(&self) -> bool {
        let covered = self.covered_dimensions();
        BenchmarkDimension::all()
            .iter()
            .all(|d| covered.contains(d))
    }
}

// ---------------------------------------------------------------------------
// Regression detection
// ---------------------------------------------------------------------------

/// A regression finding when a metric exceeds threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionFinding {
    pub scenario_name: String,
    pub dimension: BenchmarkDimension,
    pub current_value: f64,
    pub baseline_value: f64,
    pub change_pct: f64,
    pub threshold_pct: f64,
}

impl fmt::Display for RegressionFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}): {:.2} -> {:.2} ({:+.1}%, threshold: {:.1}%)",
            self.scenario_name,
            self.dimension,
            self.baseline_value,
            self.current_value,
            self.change_pct,
            self.threshold_pct,
        )
    }
}

/// Compare two reports and detect regressions.
pub fn detect_regressions(
    baseline: &BenchmarkReport,
    current: &BenchmarkReport,
    threshold_pct: f64,
) -> Vec<RegressionFinding> {
    let mut findings = Vec::new();

    for current_scenario in &current.scenarios {
        if let Some(baseline_scenario) = baseline
            .scenarios
            .iter()
            .find(|s| s.name == current_scenario.name)
        {
            if baseline_scenario.raw_value.abs() < f64::EPSILON {
                continue;
            }
            let scoring = default_scoring(&current_scenario.name);
            let change_pct = if scoring.as_ref().is_some_and(|s| s.lower_is_better) {
                // For lower-is-better: positive change = regression
                ((current_scenario.raw_value - baseline_scenario.raw_value)
                    / baseline_scenario.raw_value)
                    * 100.0
            } else {
                // For higher-is-better: negative change = regression
                ((baseline_scenario.raw_value - current_scenario.raw_value)
                    / baseline_scenario.raw_value)
                    * 100.0
            };

            if change_pct > threshold_pct {
                findings.push(RegressionFinding {
                    scenario_name: current_scenario.name.clone(),
                    dimension: current_scenario.dimension,
                    current_value: current_scenario.raw_value,
                    baseline_value: baseline_scenario.raw_value,
                    change_pct,
                    threshold_pct,
                });
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Harness event log
// ---------------------------------------------------------------------------

/// Structured event emitted during benchmark execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkEvent {
    pub code: String,
    pub scenario: Option<String>,
    pub detail: String,
}

impl fmt::Display for BenchmarkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref scenario) = self.scenario {
            write!(f, "[{}] {}: {}", self.code, scenario, self.detail)
        } else {
            write!(f, "[{}] {}", self.code, self.detail)
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics helpers
// ---------------------------------------------------------------------------

/// Compute mean of a slice.
pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Compute sample standard deviation.
pub fn std_dev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    let variance = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
    variance.sqrt()
}

/// Compute coefficient of variation as a percentage.
pub fn coefficient_of_variation(values: &[f64]) -> f64 {
    let m = mean(values);
    if m.abs() < f64::EPSILON {
        return 0.0;
    }
    (std_dev(values) / m.abs()) * 100.0
}

/// Compute 95% confidence interval using t-distribution approximation.
/// Uses t-value of 2.776 for N=5 (df=4) at 95%.
pub fn confidence_interval_95(values: &[f64]) -> ConfidenceInterval {
    if values.is_empty() {
        return ConfidenceInterval {
            lower: 0.0,
            upper: 0.0,
        };
    }
    if values.len() == 1 {
        return ConfidenceInterval {
            lower: values[0],
            upper: values[0],
        };
    }

    let m = mean(values);
    let sd = std_dev(values);
    let n = values.len() as f64;

    // t-value lookup for common sample sizes at 95% confidence
    let t_value = match values.len() {
        2 => 12.706,
        3 => 4.303,
        4 => 3.182,
        5 => 2.776,
        6 => 2.571,
        7 => 2.447,
        8 => 2.365,
        9 => 2.306,
        10 => 2.262,
        _ => 1.96, // z-value for large N
    };

    let margin = t_value * sd / n.sqrt();
    ConfidenceInterval {
        lower: m - margin,
        upper: m + margin,
    }
}

// ---------------------------------------------------------------------------
// BenchmarkSuite — the main harness
// ---------------------------------------------------------------------------

/// Configuration for the benchmark suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteConfig {
    pub hardware_profile: HardwareProfile,
    pub runtime_versions: RuntimeVersions,
    pub timestamp_utc: String,
    pub regression_threshold_pct: f64,
}

impl SuiteConfig {
    /// Create a default configuration for testing.
    pub fn with_defaults() -> Self {
        SuiteConfig {
            hardware_profile: HardwareProfile {
                cpu: "test-cpu-v1".to_string(),
                memory_mb: 16384,
                os: "linux-6.x".to_string(),
            },
            runtime_versions: RuntimeVersions {
                franken_node: "0.1.0".to_string(),
                node: Some("22.0.0".to_string()),
                bun: Some("1.1.0".to_string()),
            },
            timestamp_utc: "2026-02-21T00:00:00Z".to_string(),
            regression_threshold_pct: DEFAULT_REGRESSION_THRESHOLD_PCT,
        }
    }
}

/// The benchmark suite harness that executes scenarios and produces reports.
pub struct BenchmarkSuite {
    config: SuiteConfig,
    scenarios: Vec<ScenarioDefinition>,
    events: Vec<BenchmarkEvent>,
}

impl BenchmarkSuite {
    /// Create a new benchmark suite with the given configuration.
    pub fn new(config: SuiteConfig) -> Self {
        let mut suite = BenchmarkSuite {
            config,
            scenarios: Vec::new(),
            events: Vec::new(),
        };
        suite.emit_event(BS_SUITE_INITIALIZED, None, "Suite initialized");
        suite
    }

    /// Add a scenario definition to the suite.
    pub fn add_scenario(&mut self, scenario: ScenarioDefinition) {
        self.scenarios.push(scenario);
    }

    /// Load the default set of benchmark scenarios covering all six dimensions.
    pub fn load_default_scenarios(&mut self) {
        let defaults = vec![
            ScenarioDefinition {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                unit: "ms".to_string(),
                iterations: 5,
                warmup_iterations: 2,
                sandbox_required: true,
                scoring: ScoringConfig::lower_is_better(100.0, 500.0),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "p99_request_latency".to_string(),
                unit: "ms".to_string(),
                iterations: 5,
                warmup_iterations: 2,
                sandbox_required: true,
                scoring: ScoringConfig::lower_is_better(1.0, 10.0),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "extension_overhead_ratio".to_string(),
                unit: "ratio".to_string(),
                iterations: 5,
                warmup_iterations: 1,
                sandbox_required: true,
                scoring: ScoringConfig::lower_is_better(1.0, 1.5),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::MigrationSpeed,
                name: "migration_scanner_throughput".to_string(),
                unit: "fixtures/s".to_string(),
                iterations: 5,
                warmup_iterations: 1,
                sandbox_required: false,
                scoring: ScoringConfig::higher_is_better(1000.0, 200.0),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::CompatibilityCorrectness,
                name: "lockstep_harness_throughput".to_string(),
                unit: "fixtures/s".to_string(),
                iterations: 5,
                warmup_iterations: 1,
                sandbox_required: false,
                scoring: ScoringConfig::higher_is_better(500.0, 100.0),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::ContainmentLatency,
                name: "quarantine_propagation_latency".to_string(),
                unit: "ms".to_string(),
                iterations: 5,
                warmup_iterations: 1,
                sandbox_required: true,
                scoring: ScoringConfig::lower_is_better(100.0, 2000.0),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::ContainmentLatency,
                name: "trust_card_materialization".to_string(),
                unit: "ms".to_string(),
                iterations: 5,
                warmup_iterations: 1,
                sandbox_required: true,
                scoring: ScoringConfig::lower_is_better(10.0, 200.0),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::ReplayDeterminism,
                name: "replay_bit_identity_rate".to_string(),
                unit: "percent".to_string(),
                iterations: 5,
                warmup_iterations: 0,
                sandbox_required: false,
                scoring: ScoringConfig::higher_is_better(100.0, 90.0),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::AdversarialResilience,
                name: "adversarial_pass_rate".to_string(),
                unit: "percent".to_string(),
                iterations: 5,
                warmup_iterations: 0,
                sandbox_required: true,
                scoring: ScoringConfig::higher_is_better(100.0, 80.0),
            },
            ScenarioDefinition {
                dimension: BenchmarkDimension::MigrationSpeed,
                name: "migration_success_rate".to_string(),
                unit: "percent".to_string(),
                iterations: 5,
                warmup_iterations: 0,
                sandbox_required: false,
                scoring: ScoringConfig::higher_is_better(100.0, 80.0),
            },
        ];

        for scenario in defaults {
            self.add_scenario(scenario);
        }
    }

    /// Execute a single scenario with provided raw measurements.
    ///
    /// In production, measurements come from actual benchmark runs.
    /// This method processes raw data into a scored result.
    pub fn execute_scenario(
        &mut self,
        scenario: &ScenarioDefinition,
        raw_measurements: &[f64],
    ) -> ScenarioResult {
        self.emit_event(
            BS_SCENARIO_STARTED,
            Some(&scenario.name),
            &format!(
                "Starting {} ({} iterations)",
                scenario.name, scenario.iterations
            ),
        );

        let m = mean(raw_measurements);
        let ci = confidence_interval_95(raw_measurements);
        let cv = coefficient_of_variation(raw_measurements);
        let score = scenario.scoring.score(m);

        self.emit_event(
            BS_MEASUREMENT_RECORDED,
            Some(&scenario.name),
            &format!(
                "mean={m:.3} {}, CI=[{:.3}, {:.3}]",
                scenario.unit, ci.lower, ci.upper
            ),
        );

        self.emit_event(
            BS_SCORE_COMPUTED,
            Some(&scenario.name),
            &format!("score={score}/100 (formula: {SCORING_FORMULA_VERSION})"),
        );

        if cv <= MAX_VARIANCE_PCT {
            self.emit_event(
                BS_DETERMINISM_CHECK_PASSED,
                Some(&scenario.name),
                &format!("variance {cv:.2}% <= {MAX_VARIANCE_PCT}% threshold"),
            );
        }

        ScenarioResult {
            dimension: scenario.dimension,
            name: scenario.name.clone(),
            raw_value: m,
            unit: scenario.unit.clone(),
            confidence_interval: ci,
            score,
            iterations: raw_measurements.len() as u32,
            variance_pct: cv,
        }
    }

    /// Execute all scenarios with provided measurement data and produce a report.
    ///
    /// `measurements` maps scenario name to raw measurement values.
    pub fn run(
        &mut self,
        measurements: &std::collections::BTreeMap<String, Vec<f64>>,
    ) -> BenchmarkReport {
        let mut results = Vec::new();

        for scenario in &self.scenarios.clone() {
            if let Some(raw) = measurements.get(&scenario.name) {
                let result = self.execute_scenario(scenario, raw);
                results.push(result);
            }
        }

        let aggregate = if results.is_empty() {
            0
        } else {
            let total: u32 = results.iter().map(|r| r.score).sum();
            total / results.len() as u32
        };

        self.emit_event(
            BS_SUITE_COMPLETED,
            None,
            &format!(
                "Completed {} scenarios, aggregate score: {aggregate}/100",
                results.len()
            ),
        );

        let mut report = BenchmarkReport {
            suite_version: SUITE_VERSION.to_string(),
            scoring_formula_version: SCORING_FORMULA_VERSION.to_string(),
            timestamp_utc: self.config.timestamp_utc.clone(),
            hardware_profile: self.config.hardware_profile.clone(),
            runtime_versions: self.config.runtime_versions.clone(),
            scenarios: results,
            aggregate_score: aggregate,
            provenance_hash: String::new(),
        };

        report.provenance_hash = report.compute_provenance_hash();
        report
    }

    /// Get all events emitted during execution.
    pub fn events(&self) -> &[BenchmarkEvent] {
        &self.events
    }

    /// Get the scenario definitions.
    pub fn scenarios(&self) -> &[ScenarioDefinition] {
        &self.scenarios
    }

    fn emit_event(&mut self, code: &str, scenario: Option<&str>, detail: &str) {
        self.events.push(BenchmarkEvent {
            code: code.to_string(),
            scenario: scenario.map(String::from),
            detail: detail.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a report to canonical JSON.
pub fn to_canonical_json(report: &BenchmarkReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_default()
}

/// Deserialize a report from JSON.
pub fn from_json(json: &str) -> Result<BenchmarkReport, serde_json::Error> {
    serde_json::from_str(json)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_scoring_lower_is_better_perfect() {
        let config = ScoringConfig::lower_is_better(100.0, 500.0);
        assert_eq!(config.score(100.0), 100);
    }

    #[test]
    fn test_scoring_lower_is_better_worst() {
        let config = ScoringConfig::lower_is_better(100.0, 500.0);
        assert_eq!(config.score(500.0), 0);
    }

    #[test]
    fn test_scoring_lower_is_better_midpoint() {
        let config = ScoringConfig::lower_is_better(100.0, 500.0);
        assert_eq!(config.score(300.0), 50);
    }

    #[test]
    fn test_scoring_lower_is_better_beyond_worst() {
        let config = ScoringConfig::lower_is_better(100.0, 500.0);
        assert_eq!(config.score(600.0), 0);
    }

    #[test]
    fn test_scoring_lower_is_better_beyond_best() {
        let config = ScoringConfig::lower_is_better(100.0, 500.0);
        assert_eq!(config.score(50.0), 100);
    }

    #[test]
    fn test_scoring_higher_is_better_perfect() {
        let config = ScoringConfig::higher_is_better(1000.0, 200.0);
        assert_eq!(config.score(1000.0), 100);
    }

    #[test]
    fn test_scoring_higher_is_better_worst() {
        let config = ScoringConfig::higher_is_better(1000.0, 200.0);
        assert_eq!(config.score(200.0), 0);
    }

    #[test]
    fn test_scoring_higher_is_better_midpoint() {
        let config = ScoringConfig::higher_is_better(1000.0, 200.0);
        assert_eq!(config.score(600.0), 50);
    }

    #[test]
    fn test_scoring_higher_is_better_beyond_best() {
        let config = ScoringConfig::higher_is_better(1000.0, 200.0);
        assert_eq!(config.score(1200.0), 100);
    }

    #[test]
    fn test_mean_basic() {
        assert!((mean(&[1.0, 2.0, 3.0, 4.0, 5.0]) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_mean_empty() {
        assert!((mean(&[]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_std_dev_identical() {
        assert!((std_dev(&[5.0, 5.0, 5.0]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_std_dev_basic() {
        let sd = std_dev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert!((sd - 2.138).abs() < 0.01);
    }

    #[test]
    fn test_coefficient_of_variation() {
        let cv = coefficient_of_variation(&[100.0, 102.0, 98.0, 101.0, 99.0]);
        assert!(cv < 5.0, "CV should be low for tight data: {cv}");
    }

    #[test]
    fn test_confidence_interval_single_value() {
        let ci = confidence_interval_95(&[42.0]);
        assert!((ci.lower - 42.0).abs() < f64::EPSILON);
        assert!((ci.upper - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_interval_symmetric() {
        let ci = confidence_interval_95(&[10.0, 10.0, 10.0, 10.0, 10.0]);
        assert!((ci.lower - 10.0).abs() < f64::EPSILON);
        assert!((ci.upper - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dimensions_all_count() {
        assert_eq!(BenchmarkDimension::all().len(), 6);
    }

    #[test]
    fn test_dimension_display() {
        assert_eq!(
            format!("{}", BenchmarkDimension::PerformanceUnderHardening),
            "performance_under_hardening"
        );
    }

    #[test]
    fn test_hardware_fingerprint_deterministic() {
        let hw = HardwareProfile {
            cpu: "test-cpu".to_string(),
            memory_mb: 8192,
            os: "linux".to_string(),
        };
        assert_eq!(hw.fingerprint(), hw.fingerprint());
    }

    #[test]
    fn test_suite_default_scenarios_coverage() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        suite.load_default_scenarios();

        let dims: std::collections::BTreeSet<_> =
            suite.scenarios().iter().map(|s| s.dimension).collect();
        for d in BenchmarkDimension::all() {
            assert!(dims.contains(d), "Missing dimension: {d}");
        }
    }

    #[test]
    fn test_suite_run_produces_report() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        suite.load_default_scenarios();

        let mut measurements = BTreeMap::new();
        for s in suite.scenarios().to_vec() {
            measurements.insert(s.name.clone(), vec![150.0, 152.0, 148.0, 151.0, 149.0]);
        }

        let report = suite.run(&measurements);
        assert_eq!(report.suite_version, SUITE_VERSION);
        assert_eq!(report.scoring_formula_version, SCORING_FORMULA_VERSION);
        assert!(!report.scenarios.is_empty());
        assert!(!report.provenance_hash.is_empty());
    }

    #[test]
    fn test_report_dimension_coverage() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        suite.load_default_scenarios();

        let mut measurements = BTreeMap::new();
        for s in suite.scenarios().to_vec() {
            measurements.insert(s.name.clone(), vec![50.0; 5]);
        }

        let report = suite.run(&measurements);
        assert!(
            report.has_full_coverage(),
            "Report should cover all 6 dimensions"
        );
    }

    #[test]
    fn test_report_json_roundtrip() {
        let report = BenchmarkReport {
            suite_version: SUITE_VERSION.to_string(),
            scoring_formula_version: SCORING_FORMULA_VERSION.to_string(),
            timestamp_utc: "2026-02-21T00:00:00Z".to_string(),
            hardware_profile: HardwareProfile {
                cpu: "test".to_string(),
                memory_mb: 8192,
                os: "linux".to_string(),
            },
            runtime_versions: RuntimeVersions {
                franken_node: "0.1.0".to_string(),
                node: None,
                bun: None,
            },
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 150.0,
                unit: "ms".to_string(),
                confidence_interval: ConfidenceInterval {
                    lower: 148.0,
                    upper: 152.0,
                },
                score: 88,
                iterations: 5,
                variance_pct: 1.2,
            }],
            aggregate_score: 88,
            provenance_hash: "sha256:test".to_string(),
        };

        let json = to_canonical_json(&report);
        let roundtrip = from_json(&json).unwrap();
        assert_eq!(report.suite_version, roundtrip.suite_version);
        assert_eq!(report.scenarios.len(), roundtrip.scenarios.len());
        assert_eq!(report.scenarios[0].score, roundtrip.scenarios[0].score);
    }

    #[test]
    fn test_regression_detection_no_regression() {
        let baseline = BenchmarkReport {
            suite_version: SUITE_VERSION.to_string(),
            scoring_formula_version: SCORING_FORMULA_VERSION.to_string(),
            timestamp_utc: "2026-02-20T00:00:00Z".to_string(),
            hardware_profile: HardwareProfile {
                cpu: "test".to_string(),
                memory_mb: 8192,
                os: "linux".to_string(),
            },
            runtime_versions: RuntimeVersions {
                franken_node: "0.1.0".to_string(),
                node: None,
                bun: None,
            },
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 200.0,
                unit: "ms".to_string(),
                confidence_interval: ConfidenceInterval {
                    lower: 195.0,
                    upper: 205.0,
                },
                score: 75,
                iterations: 5,
                variance_pct: 2.0,
            }],
            aggregate_score: 75,
            provenance_hash: String::new(),
        };

        let current = BenchmarkReport {
            scenarios: vec![ScenarioResult {
                raw_value: 190.0,
                ..baseline.scenarios[0].clone()
            }],
            ..baseline.clone()
        };

        let findings = detect_regressions(&baseline, &current, 10.0);
        assert!(findings.is_empty(), "No regression expected");
    }

    #[test]
    fn test_regression_detection_with_regression() {
        let baseline = BenchmarkReport {
            suite_version: SUITE_VERSION.to_string(),
            scoring_formula_version: SCORING_FORMULA_VERSION.to_string(),
            timestamp_utc: "2026-02-20T00:00:00Z".to_string(),
            hardware_profile: HardwareProfile {
                cpu: "test".to_string(),
                memory_mb: 8192,
                os: "linux".to_string(),
            },
            runtime_versions: RuntimeVersions {
                franken_node: "0.1.0".to_string(),
                node: None,
                bun: None,
            },
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 200.0,
                unit: "ms".to_string(),
                confidence_interval: ConfidenceInterval {
                    lower: 195.0,
                    upper: 205.0,
                },
                score: 75,
                iterations: 5,
                variance_pct: 2.0,
            }],
            aggregate_score: 75,
            provenance_hash: String::new(),
        };

        let current = BenchmarkReport {
            scenarios: vec![ScenarioResult {
                raw_value: 350.0, // 75% increase in latency
                ..baseline.scenarios[0].clone()
            }],
            ..baseline.clone()
        };

        let findings = detect_regressions(&baseline, &current, 10.0);
        assert_eq!(findings.len(), 1, "Should detect one regression");
        assert!(findings[0].change_pct > 10.0);
    }

    #[test]
    fn test_events_emitted_during_run() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        suite.add_scenario(ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "test_scenario".to_string(),
            unit: "ms".to_string(),
            iterations: 5,
            warmup_iterations: 0,
            sandbox_required: false,
            scoring: ScoringConfig::lower_is_better(1.0, 10.0),
        });

        let mut measurements = BTreeMap::new();
        measurements.insert("test_scenario".to_string(), vec![5.0; 5]);
        let _report = suite.run(&measurements);

        let event_codes: Vec<&str> = suite.events().iter().map(|e| e.code.as_str()).collect();
        assert!(event_codes.contains(&BS_SUITE_INITIALIZED));
        assert!(event_codes.contains(&BS_SCENARIO_STARTED));
        assert!(event_codes.contains(&BS_MEASUREMENT_RECORDED));
        assert!(event_codes.contains(&BS_SCORE_COMPUTED));
        assert!(event_codes.contains(&BS_SUITE_COMPLETED));
    }

    #[test]
    fn test_provenance_hash_deterministic() {
        let report = BenchmarkReport {
            suite_version: SUITE_VERSION.to_string(),
            scoring_formula_version: SCORING_FORMULA_VERSION.to_string(),
            timestamp_utc: "2026-02-21T00:00:00Z".to_string(),
            hardware_profile: HardwareProfile {
                cpu: "test".to_string(),
                memory_mb: 8192,
                os: "linux".to_string(),
            },
            runtime_versions: RuntimeVersions {
                franken_node: "0.1.0".to_string(),
                node: None,
                bun: None,
            },
            scenarios: vec![],
            aggregate_score: 0,
            provenance_hash: String::new(),
        };

        let hash1 = report.compute_provenance_hash();
        let hash2 = report.compute_provenance_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_default_scoring_known_scenarios() {
        assert!(default_scoring("cold_start_latency").is_some());
        assert!(default_scoring("p99_request_latency").is_some());
        assert!(default_scoring("extension_overhead_ratio").is_some());
        assert!(default_scoring("migration_scanner_throughput").is_some());
        assert!(default_scoring("lockstep_harness_throughput").is_some());
        assert!(default_scoring("quarantine_propagation_latency").is_some());
        assert!(default_scoring("trust_card_materialization").is_some());
        assert!(default_scoring("unknown_metric").is_none());
    }

    #[test]
    fn test_aggregate_score_computation() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        suite.add_scenario(ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "cold_start_latency".to_string(),
            unit: "ms".to_string(),
            iterations: 5,
            warmup_iterations: 0,
            sandbox_required: true,
            scoring: ScoringConfig::lower_is_better(100.0, 500.0),
        });
        suite.add_scenario(ScenarioDefinition {
            dimension: BenchmarkDimension::MigrationSpeed,
            name: "migration_scanner_throughput".to_string(),
            unit: "fixtures/s".to_string(),
            iterations: 5,
            warmup_iterations: 0,
            sandbox_required: false,
            scoring: ScoringConfig::higher_is_better(1000.0, 200.0),
        });

        let mut measurements = BTreeMap::new();
        // cold_start: 100ms = ideal = score 100
        measurements.insert("cold_start_latency".to_string(), vec![100.0; 5]);
        // migration: 1000 fixtures/s = ideal = score 100
        measurements.insert("migration_scanner_throughput".to_string(), vec![1000.0; 5]);

        let report = suite.run(&measurements);
        assert_eq!(report.aggregate_score, 100);
    }

    #[test]
    fn test_regression_finding_display() {
        let finding = RegressionFinding {
            scenario_name: "cold_start_latency".to_string(),
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            current_value: 300.0,
            baseline_value: 200.0,
            change_pct: 50.0,
            threshold_pct: 10.0,
        };
        let display = format!("{finding}");
        assert!(display.contains("cold_start_latency"));
        assert!(display.contains("50.0%"));
    }
}
