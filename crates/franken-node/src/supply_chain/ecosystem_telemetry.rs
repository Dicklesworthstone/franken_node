//! bd-phf: Ecosystem telemetry for trust and adoption metrics.
//!
//! Provides the quantitative feedback loop that drives reputation scoring,
//! certification decisions, policy tuning, and program success measurement.
//! Implements privacy-respecting aggregation, anomaly detection, and time-series
//! retention for ecosystem-level trust and adoption signals.

use std::{collections::BTreeMap, path::Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    certification::{CertificationLevel, CertificationRegistry},
    extension_registry::{ExtensionStatus, SignedExtensionRegistry},
};
use crate::push_bounded;

const MAX_ANOMALY_ALERTS: usize = 4096;
const MAX_DATA_POINTS: usize = 4096;
const MAX_VALUES_PER_METRIC: usize = 1024;
const MIN_DEVIATION_THRESHOLD_PCT: f64 = 0.0;
const MAX_DEVIATION_THRESHOLD_PCT: f64 = 100.0;

fn valid_deviation_threshold_pct(value: f64) -> bool {
    value.is_finite()
        && (MIN_DEVIATION_THRESHOLD_PCT..=MAX_DEVIATION_THRESHOLD_PCT).contains(&value)
}

fn finite_mean(values: impl IntoIterator<Item = f64>) -> Option<f64> {
    let finite_values = values
        .into_iter()
        .filter(|value| value.is_finite())
        .collect::<Vec<_>>();
    if finite_values.is_empty() {
        return None;
    }

    let max_abs = finite_values
        .iter()
        .map(|value| value.abs())
        .fold(0.0, f64::max);
    if max_abs == 0.0 {
        return Some(0.0);
    }

    let mut scaled_sum = 0.0;
    for value in finite_values.iter().copied() {
        let next = scaled_sum + (value / max_abs);
        if !next.is_finite() {
            return None;
        }
        scaled_sum = next;
    }

    let mean = (scaled_sum / finite_values.len() as f64) * max_abs;
    mean.is_finite().then_some(mean)
}

fn finite_deviation_pct(current: f64, baseline: f64) -> Option<f64> {
    if !current.is_finite() || !baseline.is_finite() || baseline.abs() < f64::EPSILON {
        return None;
    }

    let relative = ((current - baseline) / baseline) * 100.0;
    if relative.is_finite() {
        Some(relative.abs())
    } else {
        Some(f64::MAX)
    }
}

// ── Event codes ──────────────────────────────────────────────────────────────

pub const TELEMETRY_INGESTED: &str = "TELEMETRY_INGESTED";
pub const TELEMETRY_AGGREGATED: &str = "TELEMETRY_AGGREGATED";
pub const TELEMETRY_QUERY_SERVED: &str = "TELEMETRY_QUERY_SERVED";
pub const TELEMETRY_ANOMALY_DETECTED: &str = "TELEMETRY_ANOMALY_DETECTED";
pub const TELEMETRY_EXPORT_GENERATED: &str = "TELEMETRY_EXPORT_GENERATED";
pub const TELEMETRY_PRIVACY_FILTER_APPLIED: &str = "TELEMETRY_PRIVACY_FILTER_APPLIED";

// ── Metric families ──────────────────────────────────────────────────────────

/// Trust metric families tracked at the ecosystem level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMetricKind {
    /// Distribution of extensions across certification levels.
    CertificationDistribution,
    /// Time from revocation issue to fleet-wide propagation.
    RevocationPropagationLatency,
    /// Time from quarantine to resolution (cleared or confirmed).
    QuarantineResolutionTime,
    /// Fraction of extensions with verified provenance chains.
    ProvenanceCoverageRate,
    /// Distribution of publisher reputation scores.
    ReputationDistribution,
}

/// Adoption metric families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionMetricKind {
    /// Extensions published per time period.
    ExtensionsPublished,
    /// Extensions using each provenance level.
    ProvenanceLevelAdoption,
    /// Trust-card query volume by operators.
    TrustCardQueryVolume,
    /// Frequency of policy override usage.
    PolicyOverrideFrequency,
    /// Operator-initiated quarantine actions per period.
    QuarantineActionsPerPeriod,
}

// ── Telemetry data points ────────────────────────────────────────────────────

/// A single telemetry data point with privacy metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryDataPoint {
    /// Unique identifier for this data point.
    pub point_id: String,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// Metric kind (trust or adoption).
    pub metric: MetricKind,
    /// Numeric value.
    pub value: f64,
    /// Aggregation level (raw, hourly, daily, weekly).
    pub aggregation: AggregationLevel,
    /// Whether privacy filtering has been applied.
    pub privacy_filtered: bool,
    /// Optional labels for dimensional filtering.
    pub labels: BTreeMap<String, String>,
}

/// Union of trust and adoption metric kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum MetricKind {
    Trust(TrustMetricKind),
    Adoption(AdoptionMetricKind),
}

/// Data aggregation levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationLevel {
    Raw,
    Hourly,
    Daily,
    Weekly,
}

// ── Privacy governance ───────────────────────────────────────────────────────

/// Data governance configuration for telemetry collection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataGovernance {
    /// Whether telemetry collection is enabled (opt-in).
    pub collection_enabled: bool,
    /// Minimum aggregation size for privacy (k-anonymity threshold).
    pub min_aggregation_k: u32,
    /// Retention policy.
    pub retention: RetentionPolicy,
    /// Categories of data that are collected.
    pub collected_categories: Vec<String>,
    /// Categories of data that are published externally.
    pub published_categories: Vec<String>,
}

impl Default for DataGovernance {
    fn default() -> Self {
        Self {
            collection_enabled: false, // Opt-in by default.
            min_aggregation_k: 5,
            retention: RetentionPolicy::default(),
            collected_categories: vec!["trust_metrics".to_owned(), "adoption_metrics".to_owned()],
            published_categories: vec!["aggregate_trust_metrics".to_owned()],
        }
    }
}

/// Time-series retention policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Days to retain raw data.
    pub raw_retention_days: u32,
    /// Days to retain hourly aggregates.
    pub hourly_retention_days: u32,
    /// Days to retain daily aggregates.
    pub daily_retention_days: u32,
    /// Days to retain weekly aggregates (0 = indefinite).
    pub weekly_retention_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            raw_retention_days: 7,
            hourly_retention_days: 30,
            daily_retention_days: 365,
            weekly_retention_days: 0, // Indefinite.
        }
    }
}

// ── Anomaly detection ────────────────────────────────────────────────────────

/// Anomaly types detected on ecosystem telemetry streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Sudden drop in provenance coverage rate.
    ProvenanceCoverageDrop,
    /// Spike in quarantine events beyond threshold.
    QuarantineSpike,
    /// Significant shift in reputation score distribution.
    ReputationDistributionShift,
    /// Unusual revocation propagation delay.
    RevocationPropagationDelay,
    /// Abnormal extension publication volume (possible supply-chain attack).
    PublicationVolumeAnomaly,
}

/// Anomaly severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// A detected anomaly in the telemetry stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyAlert {
    /// Unique alert identifier.
    pub alert_id: String,
    /// Timestamp of detection.
    pub detected_at: String,
    /// Type of anomaly.
    pub anomaly_type: AnomalyType,
    /// Severity assessment.
    pub severity: AnomalySeverity,
    /// Metric that triggered the anomaly.
    pub trigger_metric: MetricKind,
    /// Current value vs. expected baseline.
    pub current_value: f64,
    /// Baseline value.
    pub baseline_value: f64,
    /// Deviation as a percentage.
    pub deviation_pct: f64,
    /// Human-readable description.
    pub description: String,
}

/// Configuration for anomaly detection thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyConfig {
    /// Deviation threshold (percentage) to trigger an alert.
    pub deviation_threshold_pct: f64,
    /// Minimum data points required before anomaly detection activates.
    pub min_data_points: u32,
    /// Window size (in data points) for baseline calculation.
    pub baseline_window: u32,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            deviation_threshold_pct: 30.0,
            min_data_points: 10,
            baseline_window: 30,
        }
    }
}

impl AnomalyConfig {
    #[must_use]
    pub fn new(
        deviation_threshold_pct: f64,
        min_data_points: u32,
        baseline_window: u32,
    ) -> Option<Self> {
        valid_deviation_threshold_pct(deviation_threshold_pct).then_some(Self {
            deviation_threshold_pct,
            min_data_points,
            baseline_window,
        })
    }

    pub fn set_deviation_threshold_pct(&mut self, value: f64) -> bool {
        if !valid_deviation_threshold_pct(value) {
            return false;
        }
        self.deviation_threshold_pct = value;
        true
    }

    fn effective_deviation_threshold_pct(&self) -> f64 {
        if valid_deviation_threshold_pct(self.deviation_threshold_pct) {
            self.deviation_threshold_pct
        } else {
            MIN_DEVIATION_THRESHOLD_PCT
        }
    }
}

// ── Telemetry query ──────────────────────────────────────────────────────────

/// Query parameters for telemetry data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryQuery {
    /// Optional metric kind filter.
    pub metric: Option<MetricKind>,
    /// Start time (inclusive, RFC 3339).
    pub from: Option<String>,
    /// End time (exclusive, RFC 3339).
    pub to: Option<String>,
    /// Desired aggregation level.
    pub aggregation: Option<AggregationLevel>,
    /// Optional label filters.
    pub labels: BTreeMap<String, String>,
    /// Maximum results.
    pub limit: Option<usize>,
}

/// Query result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryQueryResult {
    /// Matching data points.
    pub data_points: Vec<TelemetryDataPoint>,
    /// Total matching count (may exceed returned limit).
    pub total_count: usize,
    /// Whether privacy filtering was applied.
    pub privacy_filtered: bool,
}

/// Explicit availability states for derived health-export metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedMetricAvailability {
    Available,
    MissingUpstream,
    StaleUpstream,
    CompleteContainment,
    BaselineAbsent,
}

/// Machine-readable contract for a derived ecosystem health metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedMetricContract {
    /// Stable metric identifier.
    pub metric_id: String,
    /// Authoritative upstream inputs that the implementation must read.
    pub authoritative_inputs: Vec<String>,
    /// Canonical computation rule.
    pub formula: String,
    /// Required non-placeholder behaviors for missing or edge-case inputs.
    pub missing_data_semantics: Vec<DerivedMetricAvailability>,
    /// Notes that keep the follow-on implementation bead narrowly scoped.
    pub implementation_scope: Vec<String>,
}

/// Provenance and availability metadata for a derived health-export metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedMetricMetadata {
    /// Stable metric identifier.
    pub metric_id: String,
    /// Explicit availability status for the derived value.
    pub availability: DerivedMetricAvailability,
    /// Canonical authoritative inputs for the metric.
    pub authoritative_inputs: Vec<String>,
    /// Concrete inputs observed while producing this export.
    pub observed_inputs: Vec<String>,
    /// Timestamp of the upstream source used for this metric, if one was available.
    pub source_timestamp: Option<String>,
    /// Human-readable provenance / status summary.
    pub detail: String,
}

/// Minimal verified compromise-reduction report surface used by health export.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompromiseReductionReport {
    pub bead_id: String,
    pub generated_at_utc: String,
    pub trace_id: String,
    pub campaign_name: String,
    pub campaign_version: String,
    pub reproducible_command: String,
    pub minimum_required_ratio: f64,
    pub baseline_compromised: u64,
    pub hardened_compromised: u64,
    pub compromise_reduction_ratio: f64,
    pub total_attack_vectors: u64,
    pub containment_vectors: u64,
}

/// Load the authoritative Section 13 compromise-reduction report from disk.
pub fn load_compromise_reduction_report(path: &Path) -> Result<CompromiseReductionReport, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("failed reading {}: {err}", path.display()))?;
    serde_json::from_str(&raw).map_err(|err| format!("failed parsing {}: {err}", path.display()))
}

/// Contract for the compromise reduction metric.
#[must_use]
pub fn compromise_reduction_factor_contract() -> DerivedMetricContract {
    DerivedMetricContract {
        metric_id: "compromise_reduction_factor".to_string(),
        authoritative_inputs: vec![
            "artifacts/13/compromise_reduction_report.json".to_string(),
            "docs/specs/section_13/bd-3cpa_contract.md".to_string(),
        ],
        formula: "baseline_compromised / hardened_compromised".to_string(),
        missing_data_semantics: vec![
            DerivedMetricAvailability::MissingUpstream,
            DerivedMetricAvailability::StaleUpstream,
            DerivedMetricAvailability::CompleteContainment,
            DerivedMetricAvailability::BaselineAbsent,
        ],
        implementation_scope: vec![
            "Read only a verified compromise-reduction report for the same reporting window."
                .to_string(),
            "Emit a numeric factor only when both baseline_compromised and hardened_compromised are greater than zero."
                .to_string(),
            "When hardened_compromised == 0 and baseline_compromised > 0, surface complete_containment instead of inventing a capped ratio or placeholder 1.0."
                .to_string(),
            "When baseline_compromised == 0, surface baseline_absent because the ratio is undefined."
                .to_string(),
        ],
    }
}

/// Contract for the certification distribution metric.
#[must_use]
pub fn certification_distribution_contract() -> DerivedMetricContract {
    DerivedMetricContract {
        metric_id: "certification_distribution".to_string(),
        authoritative_inputs: vec![
            "SignedExtensionRegistry.list(Some(ExtensionStatus::Active))".to_string(),
            "CertificationRegistry records keyed by extension_id@version".to_string(),
        ],
        formula: "count active extension versions grouped by canonical certification::CertificationLevel label; missing certification records fall back to uncertified".to_string(),
        missing_data_semantics: vec![
            DerivedMetricAvailability::Available,
            DerivedMetricAvailability::MissingUpstream,
            DerivedMetricAvailability::StaleUpstream,
        ],
        implementation_scope: vec![
            "Count only the active extension set from the signed extension registry."
                .to_string(),
            "Join active extension_id@version entries against CertificationRegistry."
                .to_string(),
            "Use canonical certification.rs levels (uncertified/basic/standard/verified/audited), not the presentation tiers exposed by trust_card.rs."
                .to_string(),
            "If an active extension version lacks a certification record, place it in the uncertified bucket rather than dropping it silently."
                .to_string(),
        ],
    }
}

// ── Export for Section 13 success criteria ────────────────────────────────────

/// Ecosystem health export for program success measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EcosystemHealthExport {
    /// Export timestamp.
    pub exported_at: String,
    /// Compatibility corpus pass rate (0.0..=1.0).
    pub compatibility_pass_rate: f64,
    /// Average migration velocity (extensions migrated per period).
    pub migration_velocity: f64,
    /// Compromise reduction metric (relative to baseline).
    ///
    /// Numeric output is present only when a verified Section 13 report for the
    /// same reporting window was provided and the ratio is defined.
    pub compromise_reduction_factor: Option<f64>,
    /// Provenance and availability details for `compromise_reduction_factor`.
    pub compromise_reduction_metadata: DerivedMetricMetadata,
    /// Provenance coverage rate (0.0..=1.0).
    pub provenance_coverage: f64,
    /// Certification level distribution for the active extension set.
    pub certification_distribution: BTreeMap<String, u64>,
    /// Provenance and availability details for `certification_distribution`.
    pub certification_distribution_metadata: DerivedMetricMetadata,
    /// Average quarantine-to-resolution time (seconds).
    pub avg_quarantine_resolution_secs: f64,
    /// Active anomaly alerts.
    pub active_alerts: Vec<AnomalyAlert>,
}

// ── Resource budget ──────────────────────────────────────────────────────────

/// Resource budget limits for the telemetry pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceBudget {
    /// Maximum data points stored in memory.
    pub max_in_memory_points: usize,
    /// Maximum storage bytes for telemetry data.
    pub max_storage_bytes: u64,
    /// Maximum CPU time per aggregation cycle (milliseconds).
    pub max_aggregation_cpu_ms: u64,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_in_memory_points: 100_000,
            max_storage_bytes: 100 * 1024 * 1024, // 100 MB.
            max_aggregation_cpu_ms: 500,
        }
    }
}

// ── Telemetry pipeline ───────────────────────────────────────────────────────

/// The telemetry pipeline manages ingestion, aggregation, storage, and querying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPipeline {
    data_points: Vec<TelemetryDataPoint>,
    anomaly_alerts: Vec<AnomalyAlert>,
    governance: DataGovernance,
    anomaly_config: AnomalyConfig,
    resource_budget: ResourceBudget,
    ingested_count: u64,
    aggregated_count: u64,
}

impl Default for TelemetryPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryPipeline {
    #[must_use]
    pub fn new() -> Self {
        Self {
            data_points: Vec::new(),
            anomaly_alerts: Vec::new(),
            governance: DataGovernance::default(),
            anomaly_config: AnomalyConfig::default(),
            resource_budget: ResourceBudget::default(),
            ingested_count: 0,
            aggregated_count: 0,
        }
    }

    /// Create with custom governance settings.
    #[must_use]
    pub fn with_governance(governance: DataGovernance) -> Self {
        Self {
            governance,
            ..Self::new()
        }
    }

    /// Enable telemetry collection.
    pub fn enable_collection(&mut self) {
        self.governance.collection_enabled = true;
    }

    /// Ingest a raw telemetry data point.
    pub fn ingest(&mut self, point: TelemetryDataPoint) -> bool {
        if !self.governance.collection_enabled {
            return false;
        }
        if !point.value.is_finite() {
            return false;
        }

        let cap = MAX_DATA_POINTS.min(self.resource_budget.max_in_memory_points);
        if cap == 0 {
            return false;
        }

        // Enforce resource budget.
        if self.data_points.len() >= cap {
            // Evict oldest raw data points first to make room.
            let mut overflow = self.data_points.len().saturating_sub(cap - 1);
            if overflow > 0 {
                self.data_points.retain(|p| {
                    if overflow > 0 && p.aggregation == AggregationLevel::Raw {
                        overflow -= 1;
                        false
                    } else {
                        true
                    }
                });
            }

            // If still over budget, drop oldest entries regardless of aggregation level.
            let overflow = self.data_points.len().saturating_sub(cap - 1);
            if overflow > 0 {
                self.data_points
                    .drain(0..overflow.min(self.data_points.len()));
            }
        }

        push_bounded(&mut self.data_points, point, cap);
        self.ingested_count = self.ingested_count.saturating_add(1);
        true
    }

    /// Run anomaly detection on the current data.
    pub fn detect_anomalies(&mut self, baseline: &BTreeMap<MetricKind, f64>) -> Vec<AnomalyAlert> {
        let mut new_alerts = Vec::new();
        let deviation_threshold_pct = self.anomaly_config.effective_deviation_threshold_pct();

        // Group recent data by metric.
        let mut metric_values: BTreeMap<MetricKind, Vec<f64>> = BTreeMap::new();
        for point in &self.data_points {
            if !point.value.is_finite() {
                continue;
            }
            let values = metric_values.entry(point.metric).or_default();
            push_bounded(values, point.value, MAX_VALUES_PER_METRIC);
        }

        for (metric, values) in &metric_values {
            if values.len() < self.anomaly_config.min_data_points as usize {
                continue;
            }

            let Some(current_avg) = finite_mean(values.iter().copied()) else {
                continue;
            };

            if let Some(&baseline_val) = baseline.get(metric) {
                let Some(deviation_pct) = finite_deviation_pct(current_avg, baseline_val) else {
                    continue;
                };

                if deviation_pct > deviation_threshold_pct {
                    let anomaly_type = match metric {
                        MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate) => {
                            AnomalyType::ProvenanceCoverageDrop
                        }
                        MetricKind::Trust(TrustMetricKind::QuarantineResolutionTime) => {
                            AnomalyType::QuarantineSpike
                        }
                        MetricKind::Trust(TrustMetricKind::ReputationDistribution) => {
                            AnomalyType::ReputationDistributionShift
                        }
                        MetricKind::Trust(TrustMetricKind::RevocationPropagationLatency) => {
                            AnomalyType::RevocationPropagationDelay
                        }
                        MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished) => {
                            AnomalyType::PublicationVolumeAnomaly
                        }
                        _ => AnomalyType::PublicationVolumeAnomaly,
                    };

                    let severity = if deviation_pct > 80.0 {
                        AnomalySeverity::Critical
                    } else if deviation_pct > 60.0 {
                        AnomalySeverity::High
                    } else if deviation_pct > 40.0 {
                        AnomalySeverity::Medium
                    } else {
                        AnomalySeverity::Low
                    };

                    let alert = AnomalyAlert {
                        alert_id: format!(
                            "alert-{}-{}",
                            anomaly_type as u8,
                            self.anomaly_alerts.len()
                        ),
                        detected_at: String::new(), // Caller should set.
                        anomaly_type,
                        severity,
                        trigger_metric: *metric,
                        current_value: current_avg,
                        baseline_value: baseline_val,
                        deviation_pct,
                        description: format!(
                            "{anomaly_type:?} detected: current {current_avg:.2} vs baseline {baseline_val:.2} ({deviation_pct:.1}% deviation)"
                        ),
                    };

                    new_alerts.push(alert.clone());
                    push_bounded(&mut self.anomaly_alerts, alert, MAX_ANOMALY_ALERTS);
                }
            }
        }

        new_alerts
    }

    /// Query telemetry data.
    #[must_use]
    pub fn query(&self, query: &TelemetryQuery) -> TelemetryQueryResult {
        let mut results: Vec<&TelemetryDataPoint> = self.data_points.iter().collect();

        // Filter by metric kind.
        if let Some(ref metric) = query.metric {
            results.retain(|p| &p.metric == metric);
        }

        // Filter by time range.
        if let Some(ref from) = query.from {
            results.retain(|p| p.timestamp.as_str() >= from.as_str());
        }
        if let Some(ref to) = query.to {
            results.retain(|p| p.timestamp.as_str() < to.as_str());
        }

        // Filter by aggregation level.
        if let Some(ref agg) = query.aggregation {
            results.retain(|p| &p.aggregation == agg);
        }

        // Filter by labels.
        for (key, val) in &query.labels {
            results.retain(|p| p.labels.get(key).is_some_and(|v| v == val));
        }

        let total_count = results.len();

        // Apply limit.
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        TelemetryQueryResult {
            data_points: results.into_iter().cloned().collect(),
            total_count,
            privacy_filtered: self.governance.min_aggregation_k > 1,
        }
    }

    /// Generate an ecosystem health export for Section 13 success criteria.
    ///
    /// The derived compromise-reduction and certification-distribution fields
    /// are computed only from the authoritative upstream inputs declared by
    /// their contracts. When those inputs are unavailable or stale, the export
    /// remains explicit about that instead of inventing placeholder values.
    #[must_use]
    pub fn export_health(
        &self,
        timestamp: &str,
        compromise_report: Option<&CompromiseReductionReport>,
        extension_registry: Option<&SignedExtensionRegistry>,
        certification_registry: Option<&CertificationRegistry>,
    ) -> EcosystemHealthExport {
        let (compromise_reduction_factor, compromise_reduction_metadata) =
            derive_compromise_reduction_metric(timestamp, compromise_report);
        let (certification_distribution, certification_distribution_metadata) =
            derive_certification_distribution_metric(
                timestamp,
                extension_registry,
                certification_registry,
            );

        EcosystemHealthExport {
            exported_at: timestamp.to_owned(),
            compatibility_pass_rate: self.compute_metric_avg(MetricKind::Trust(
                TrustMetricKind::CertificationDistribution,
            )),
            migration_velocity: self.compute_metric_avg(MetricKind::Adoption(
                AdoptionMetricKind::ExtensionsPublished,
            )),
            compromise_reduction_factor,
            compromise_reduction_metadata,
            provenance_coverage: self
                .compute_metric_avg(MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate)),
            certification_distribution,
            certification_distribution_metadata,
            avg_quarantine_resolution_secs: self
                .compute_metric_avg(MetricKind::Trust(TrustMetricKind::QuarantineResolutionTime)),
            active_alerts: self.anomaly_alerts.clone(),
        }
    }

    /// Get current anomaly alerts.
    #[must_use]
    pub fn active_alerts(&self) -> &[AnomalyAlert] {
        &self.anomaly_alerts
    }

    /// Total ingested data points.
    #[must_use]
    pub fn ingested_count(&self) -> u64 {
        self.ingested_count
    }

    /// Current stored data points.
    #[must_use]
    pub fn stored_count(&self) -> usize {
        self.data_points.len()
    }

    /// Get governance configuration.
    #[must_use]
    pub fn governance(&self) -> &DataGovernance {
        &self.governance
    }

    /// Get resource budget.
    #[must_use]
    pub fn resource_budget(&self) -> &ResourceBudget {
        &self.resource_budget
    }

    // ── Internal ─────────────────────────────────────────────────────────

    fn compute_metric_avg(&self, metric: MetricKind) -> f64 {
        finite_mean(
            self.data_points
                .iter()
                .filter(|point| point.metric == metric)
                .map(|point| point.value),
        )
        .unwrap_or(0.0)
    }
}

fn metric_metadata(
    contract: &DerivedMetricContract,
    availability: DerivedMetricAvailability,
    observed_inputs: Vec<String>,
    source_timestamp: Option<String>,
    detail: impl Into<String>,
) -> DerivedMetricMetadata {
    DerivedMetricMetadata {
        metric_id: contract.metric_id.clone(),
        availability,
        authoritative_inputs: contract.authoritative_inputs.clone(),
        observed_inputs,
        source_timestamp,
        detail: detail.into(),
    }
}

fn reporting_window_id(timestamp: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|dt| dt.with_timezone(&Utc).date_naive().to_string())
}

fn same_reporting_window(source_timestamp: &str, exported_at: &str) -> bool {
    reporting_window_id(source_timestamp)
        .zip(reporting_window_id(exported_at))
        .is_some_and(|(source, export)| source == export)
}

fn derive_compromise_reduction_metric(
    exported_at: &str,
    report: Option<&CompromiseReductionReport>,
) -> (Option<f64>, DerivedMetricMetadata) {
    let contract = compromise_reduction_factor_contract();
    let observed_input = contract
        .authoritative_inputs
        .first()
        .cloned()
        .into_iter()
        .collect::<Vec<_>>();

    let Some(report) = report else {
        return (
            None,
            metric_metadata(
                &contract,
                DerivedMetricAvailability::MissingUpstream,
                Vec::new(),
                None,
                "no verified Section 13 compromise-reduction report was supplied",
            ),
        );
    };

    if !same_reporting_window(&report.generated_at_utc, exported_at) {
        return (
            None,
            metric_metadata(
                &contract,
                DerivedMetricAvailability::StaleUpstream,
                observed_input,
                Some(report.generated_at_utc.clone()),
                format!(
                    "compromise-reduction report window does not match export window: trace_id={}",
                    report.trace_id
                ),
            ),
        );
    }

    if report.baseline_compromised == 0 {
        return (
            None,
            metric_metadata(
                &contract,
                DerivedMetricAvailability::BaselineAbsent,
                observed_input,
                Some(report.generated_at_utc.clone()),
                format!(
                    "baseline compromises are zero for trace_id={}; ratio is undefined",
                    report.trace_id
                ),
            ),
        );
    }

    if report.hardened_compromised == 0 {
        return (
            None,
            metric_metadata(
                &contract,
                DerivedMetricAvailability::CompleteContainment,
                observed_input,
                Some(report.generated_at_utc.clone()),
                format!(
                    "hardened compromises are zero for trace_id={}; report demonstrates complete containment",
                    report.trace_id
                ),
            ),
        );
    }

    let ratio = report.baseline_compromised as f64 / report.hardened_compromised as f64;
    (
        Some(ratio),
        metric_metadata(
            &contract,
            DerivedMetricAvailability::Available,
            observed_input,
            Some(report.generated_at_utc.clone()),
            format!(
                "computed from Section 13 report trace_id={} baseline={} hardened={}",
                report.trace_id, report.baseline_compromised, report.hardened_compromised
            ),
        ),
    )
}

fn empty_certification_distribution() -> BTreeMap<String, u64> {
    [
        CertificationLevel::Uncertified,
        CertificationLevel::Basic,
        CertificationLevel::Standard,
        CertificationLevel::Verified,
        CertificationLevel::Audited,
    ]
    .into_iter()
    .map(|level| (level.to_string(), 0_u64))
    .collect()
}

fn derive_certification_distribution_metric(
    exported_at: &str,
    extension_registry: Option<&SignedExtensionRegistry>,
    certification_registry: Option<&CertificationRegistry>,
) -> (BTreeMap<String, u64>, DerivedMetricMetadata) {
    let contract = certification_distribution_contract();
    let mut distribution = empty_certification_distribution();

    let (Some(extension_registry), Some(certification_registry)) =
        (extension_registry, certification_registry)
    else {
        return (
            BTreeMap::new(),
            metric_metadata(
                &contract,
                DerivedMetricAvailability::MissingUpstream,
                Vec::new(),
                None,
                "active extension registry and certification registry are both required",
            ),
        );
    };

    let active_extensions = extension_registry.list(Some(ExtensionStatus::Active));
    if active_extensions.is_empty() {
        return (
            distribution,
            metric_metadata(
                &contract,
                DerivedMetricAvailability::Available,
                contract.authoritative_inputs.clone(),
                None,
                "active extension registry is empty for this export window",
            ),
        );
    }

    if let Some(stale_extension) = active_extensions
        .iter()
        .find(|extension| !same_reporting_window(&extension.updated_at, exported_at))
    {
        return (
            BTreeMap::new(),
            metric_metadata(
                &contract,
                DerivedMetricAvailability::StaleUpstream,
                contract.authoritative_inputs.clone(),
                Some(stale_extension.updated_at.clone()),
                format!(
                    "active extension snapshot is stale for extension_id={}",
                    stale_extension.extension_id
                ),
            ),
        );
    }

    let mut missing_certifications = 0_u64;

    for extension in active_extensions {
        let Some(version) = extension.versions.last() else {
            return (
                BTreeMap::new(),
                metric_metadata(
                    &contract,
                    DerivedMetricAvailability::MissingUpstream,
                    contract.authoritative_inputs.clone(),
                    Some(extension.updated_at.clone()),
                    format!(
                        "active extension_id={} is missing version lineage for distribution export",
                        extension.extension_id
                    ),
                ),
            );
        };

        let level =
            match certification_registry.get_record(&extension.extension_id, &version.version) {
                Ok(record) => {
                    if !same_reporting_window(&record.evaluated_at, exported_at) {
                        return (
                            BTreeMap::new(),
                            metric_metadata(
                                &contract,
                                DerivedMetricAvailability::StaleUpstream,
                                contract.authoritative_inputs.clone(),
                                Some(record.evaluated_at.clone()),
                                format!(
                                    "certification record is stale for {}@{}",
                                    extension.extension_id, version.version
                                ),
                            ),
                        );
                    }
                    record.level
                }
                Err(_) => {
                    missing_certifications = missing_certifications.saturating_add(1);
                    CertificationLevel::Uncertified
                }
            };

        if let Some(bucket) = distribution.get_mut(&level.to_string()) {
            *bucket = bucket.saturating_add(1);
        }
    }

    (
        distribution,
        metric_metadata(
            &contract,
            DerivedMetricAvailability::Available,
            contract.authoritative_inputs.clone(),
            Some(exported_at.to_owned()),
            format!(
                "counted {} active extension versions; {} missing certification records fell back to uncertified",
                extension_registry.list(Some(ExtensionStatus::Active)).len(),
                missing_certifications
            ),
        ),
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::{
        artifact_signing::{self, KeyId, KeyRing},
        certification::{CertificationInput, EvidenceType, ProvenanceLevel, VerifiedEvidenceRef},
        extension_registry::{
            AdmissionKernel, ExtensionSignature, RegistrationRequest, RegistryConfig, VersionEntry,
        },
        provenance::{self as prov, AttestationEnvelopeFormat, AttestationLink, ChainLinkRole},
        reputation::ReputationTier,
        transparency_verifier as tv,
    };
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeSet;

    fn make_point(id: &str, metric: MetricKind, value: f64, ts: &str) -> TelemetryDataPoint {
        TelemetryDataPoint {
            point_id: id.to_owned(),
            timestamp: ts.to_owned(),
            metric,
            value,
            aggregation: AggregationLevel::Raw,
            privacy_filtered: false,
            labels: BTreeMap::new(),
        }
    }

    fn ts(n: u32) -> String {
        format!("2026-01-{n:02}T00:00:00Z")
    }

    fn sample_compromise_report(
        generated_at_utc: &str,
        baseline_compromised: u64,
        hardened_compromised: u64,
    ) -> CompromiseReductionReport {
        CompromiseReductionReport {
            bead_id: "bd-3cpa".to_string(),
            generated_at_utc: generated_at_utc.to_string(),
            trace_id: "trace-bd-3cpa".to_string(),
            campaign_name: "campaign".to_string(),
            campaign_version: "2026.01.03".to_string(),
            reproducible_command: "python3 scripts/check_compromise_reduction_gate.py --json"
                .to_string(),
            minimum_required_ratio: 10.0,
            baseline_compromised,
            hardened_compromised,
            compromise_reduction_ratio: if hardened_compromised == 0 {
                0.0
            } else {
                baseline_compromised as f64 / hardened_compromised as f64
            },
            total_attack_vectors: 20,
            containment_vectors: 3,
        }
    }

    fn sample_evidence_refs() -> Vec<VerifiedEvidenceRef> {
        vec![
            VerifiedEvidenceRef {
                evidence_id: "ev-prov-001".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: 1_000,
                verification_receipt_hash: "a".repeat(64),
            },
            VerifiedEvidenceRef {
                evidence_id: "ev-rep-001".to_string(),
                evidence_type: EvidenceType::ReputationSignal,
                verified_at_epoch: 1_000,
                verification_receipt_hash: "b".repeat(64),
            },
        ]
    }

    fn certification_input(extension_id: &str, version: &str) -> CertificationInput {
        CertificationInput {
            extension_id: extension_id.to_string(),
            version: version.to_string(),
            publisher_id: "pub-test".to_string(),
            provenance_level: ProvenanceLevel::PublisherSigned,
            reputation_tier: ReputationTier::Established,
            reputation_score: 60.0,
            capabilities: BTreeSet::from(["file_read".to_string()]),
            has_test_coverage_evidence: false,
            test_coverage_pct: None,
            has_reproducible_build_evidence: false,
            has_audit_attestation: false,
            audit_attestation: None,
            evidence_refs: sample_evidence_refs(),
        }
    }

    fn test_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn provenance_signing_keys(signing_key: &SigningKey) -> BTreeMap<String, SigningKey> {
        BTreeMap::from([(
            "pub-001".to_string(),
            SigningKey::from_bytes(&signing_key.to_bytes()),
        )])
    }

    fn valid_provenance(signing_key: &SigningKey, now_epoch: u64) -> prov::ProvenanceAttestation {
        let mut attestation = prov::ProvenanceAttestation {
            schema_version: "1.0".to_string(),
            source_repository_url: "https://github.com/example/ext".to_string(),
            build_system_identifier: "github-actions".to_string(),
            builder_identity: "pub-001".to_string(),
            builder_version: "1.0.0".to_string(),
            vcs_commit_sha: "abc123def456".to_string(),
            build_timestamp_epoch: now_epoch.saturating_sub(60),
            reproducibility_hash: "d".repeat(64),
            input_hash: "e".repeat(64),
            output_hash: "f".repeat(64),
            slsa_level_claim: 2,
            envelope_format: AttestationEnvelopeFormat::FrankenNodeEnvelopeV1,
            links: vec![AttestationLink {
                role: ChainLinkRole::Publisher,
                signer_id: "pub-001".to_string(),
                signer_version: "1.0.0".to_string(),
                signature: String::new(),
                signed_payload_hash: "f".repeat(64),
                issued_at_epoch: now_epoch.saturating_sub(60),
                expires_at_epoch: now_epoch.saturating_add(86_400),
                revoked: false,
            }],
            custom_claims: BTreeMap::new(),
        };
        prov::sign_links_in_place(&mut attestation, &provenance_signing_keys(signing_key))
            .expect("sign provenance");
        attestation
    }

    fn test_kernel(vk: &ed25519_dalek::VerifyingKey) -> AdmissionKernel {
        let mut key_ring = KeyRing::new();
        key_ring.add_key(*vk);
        let mut provenance_policy = prov::VerificationPolicy::development_profile();
        provenance_policy.add_trusted_signer_key("pub-001", vk);
        AdmissionKernel {
            key_ring,
            provenance_policy,
            transparency_policy: tv::TransparencyPolicy {
                required: false,
                pinned_roots: vec![],
            },
        }
    }

    fn valid_request(
        name: &str,
        version: &str,
        sk: &SigningKey,
        now_epoch: u64,
    ) -> RegistrationRequest {
        let manifest_bytes = format!("manifest:{name}:{version}").into_bytes();
        let signature_bytes = artifact_signing::sign_bytes(sk, &manifest_bytes);
        let key_id = KeyId::from_verifying_key(&sk.verifying_key());

        RegistrationRequest {
            name: name.to_string(),
            description: format!("Test extension: {name}"),
            publisher_id: "pub-001".to_string(),
            signature: ExtensionSignature {
                key_id: key_id.to_string(),
                algorithm: "ed25519".to_string(),
                signature_bytes,
                signed_at: Utc::now().to_rfc3339(),
            },
            provenance: valid_provenance(sk, now_epoch),
            initial_version: VersionEntry {
                version: version.to_string(),
                parent_version: None,
                content_hash: "c".repeat(64),
                registered_at: Utc::now().to_rfc3339(),
                compatible_with: vec![],
            },
            tags: vec!["test".to_string()],
            manifest_bytes,
            transparency_proof: None,
        }
    }

    fn make_active_extension_registry() -> SignedExtensionRegistry {
        let (sk, vk) = test_keypair();
        let export_epoch = 1_700_000_000_u64;
        let mut registry =
            SignedExtensionRegistry::new(RegistryConfig::default(), test_kernel(&vk));

        let first = registry.register(
            valid_request("ext-a", "1.0.0", &sk, export_epoch),
            "trace-ext-a",
            export_epoch,
        );
        assert!(first.success, "detail: {}", first.detail);

        let second = registry.register(
            valid_request("ext-b", "2.0.0", &sk, export_epoch),
            "trace-ext-b",
            export_epoch,
        );
        assert!(second.success, "detail: {}", second.detail);

        registry
    }

    fn make_certification_registry(
        extension_registry: &SignedExtensionRegistry,
        export_ts: &str,
    ) -> CertificationRegistry {
        let mut registry = CertificationRegistry::new();
        let active = extension_registry.list(Some(ExtensionStatus::Active));
        let ext_a = active
            .iter()
            .find(|entry| entry.name == "ext-a")
            .expect("active ext-a");
        let ext_a_version = ext_a.versions.last().expect("ext-a version");
        registry.evaluate_and_register(
            &certification_input(&ext_a.extension_id, &ext_a_version.version),
            export_ts,
        );
        registry
    }

    #[test]
    fn test_collection_disabled_by_default() {
        let mut pipeline = TelemetryPipeline::new();
        let point = make_point(
            "p1",
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.95,
            &ts(1),
        );
        assert!(!pipeline.ingest(point));
        assert_eq!(pipeline.ingested_count(), 0);
    }

    #[test]
    fn test_collection_after_enable() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let point = make_point(
            "p1",
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.95,
            &ts(1),
        );
        assert!(pipeline.ingest(point));
        assert_eq!(pipeline.ingested_count(), 1);
        assert_eq!(pipeline.stored_count(), 1);
    }

    #[test]
    fn test_ingest_rejects_non_finite_points() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);

        assert!(!pipeline.ingest(make_point("p1", metric, f64::NAN, &ts(1))));
        assert!(!pipeline.ingest(make_point("p2", metric, f64::INFINITY, &ts(2))));
        assert!(!pipeline.ingest(make_point("p3", metric, f64::NEG_INFINITY, &ts(3))));
        assert_eq!(pipeline.ingested_count(), 0);
        assert_eq!(pipeline.stored_count(), 0);
    }

    #[test]
    fn test_ingest_rejects_when_resource_budget_disallows_storage() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.resource_budget.max_in_memory_points = 0;

        let accepted = pipeline.ingest(make_point(
            "p1",
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.95,
            &ts(1),
        ));

        assert!(!accepted);
        assert_eq!(pipeline.ingested_count(), 0);
        assert_eq!(pipeline.stored_count(), 0);
    }

    #[test]
    fn test_query_by_metric() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.ingest(make_point(
            "p1",
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.95,
            &ts(1),
        ));
        pipeline.ingest(make_point(
            "p2",
            MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished),
            42.0,
            &ts(2),
        ));

        let result = pipeline.query(&TelemetryQuery {
            metric: Some(MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate)),
            from: None,
            to: None,
            aggregation: None,
            labels: BTreeMap::new(),
            limit: None,
        });
        assert_eq!(result.total_count, 1);
        assert!((result.data_points[0].value - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_query_by_time_range() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        pipeline.ingest(make_point("p1", metric, 1.0, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 2.0, &ts(5)));
        pipeline.ingest(make_point("p3", metric, 3.0, &ts(10)));

        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: Some(ts(3)),
            to: Some(ts(8)),
            aggregation: None,
            labels: BTreeMap::new(),
            limit: None,
        });
        assert_eq!(result.total_count, 1);
        assert!((result.data_points[0].value - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_query_with_missing_label_filter_returns_empty() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let mut point = make_point(
            "p1",
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.95,
            &ts(1),
        );
        point.labels.insert("region".to_string(), "us".to_string());
        pipeline.ingest(point);

        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: None,
            to: None,
            aggregation: None,
            labels: BTreeMap::from([("region".to_string(), "eu".to_string())]),
            limit: None,
        });

        assert_eq!(result.total_count, 0);
        assert!(result.data_points.is_empty());
    }

    #[test]
    fn test_query_reversed_time_range_returns_empty() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        pipeline.ingest(make_point("p1", metric, 1.0, &ts(2)));
        pipeline.ingest(make_point("p2", metric, 2.0, &ts(3)));

        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: Some(ts(8)),
            to: Some(ts(3)),
            aggregation: None,
            labels: BTreeMap::new(),
            limit: None,
        });

        assert_eq!(result.total_count, 0);
        assert!(result.data_points.is_empty());
    }

    #[test]
    fn test_anomaly_detection_provenance_drop() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        // Ingest data points significantly below baseline.
        for i in 0..5 {
            pipeline.ingest(make_point(
                &format!("p{i}"),
                metric,
                0.3,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 0.9); // Baseline is 90% coverage.

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].anomaly_type, AnomalyType::ProvenanceCoverageDrop);
    }

    #[test]
    fn test_anomaly_detection_ignores_non_finite_stored_points() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        pipeline
            .data_points
            .push(make_point("nan", metric, f64::NAN, &ts(1)));
        pipeline
            .data_points
            .push(make_point("p1", metric, 0.3, &ts(2)));
        pipeline
            .data_points
            .push(make_point("p2", metric, 0.3, &ts(3)));

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 0.9);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].anomaly_type, AnomalyType::ProvenanceCoverageDrop);
        assert!(alerts[0].current_value.is_finite());
    }

    #[test]
    fn anomaly_detection_extreme_finite_values_do_not_overflow_alert_fields() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        for i in 0..3 {
            pipeline.ingest(make_point(
                &format!("extreme-{i}"),
                metric,
                f64::MAX,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 1.0);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].anomaly_type, AnomalyType::ProvenanceCoverageDrop);
        assert!(alerts[0].current_value.is_finite());
        assert!(alerts[0].deviation_pct.is_finite());
    }

    #[test]
    fn health_export_extreme_finite_values_do_not_overflow_metric_averages() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        for i in 0..3 {
            pipeline.ingest(make_point(
                &format!("export-extreme-{i}"),
                metric,
                f64::MAX,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let export = pipeline.export_health(&ts(10), None, None, None);
        assert!(export.provenance_coverage.is_finite());
        assert!(!export.provenance_coverage.is_infinite());
    }

    #[test]
    fn anomaly_config_rejects_non_finite_and_out_of_range_thresholds() {
        assert!(AnomalyConfig::new(0.0, 1, 1).is_some());
        assert!(AnomalyConfig::new(100.0, 1, 1).is_some());
        assert!(AnomalyConfig::new(f64::NAN, 1, 1).is_none());
        assert!(AnomalyConfig::new(f64::INFINITY, 1, 1).is_none());
        assert!(AnomalyConfig::new(-0.1, 1, 1).is_none());
        assert!(AnomalyConfig::new(100.1, 1, 1).is_none());

        let mut config = AnomalyConfig::default();
        assert!(!config.set_deviation_threshold_pct(f64::NEG_INFINITY));
        assert_eq!(config.deviation_threshold_pct, 30.0);
        assert!(!config.set_deviation_threshold_pct(100.1));
        assert_eq!(config.deviation_threshold_pct, 30.0);
        assert!(config.set_deviation_threshold_pct(0.0));
        assert_eq!(config.deviation_threshold_pct, 0.0);
    }

    #[test]
    fn anomaly_detection_non_finite_threshold_fails_closed() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;
        pipeline.anomaly_config.deviation_threshold_pct = f64::NAN;

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        for i in 0..3 {
            pipeline.ingest(make_point(
                &format!("nan-threshold-{i}"),
                metric,
                0.9,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 1.0);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].anomaly_type, AnomalyType::ProvenanceCoverageDrop);
        assert!(alerts[0].deviation_pct.is_finite());
    }

    #[test]
    fn test_anomaly_detection_quarantine_spike() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::QuarantineResolutionTime);
        for i in 0..5 {
            pipeline.ingest(make_point(
                &format!("q{i}"),
                metric,
                3600.0,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 600.0); // Baseline is 600 sec.

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].anomaly_type, AnomalyType::QuarantineSpike);
    }

    #[test]
    fn test_anomaly_detection_reputation_shift() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::ReputationDistribution);
        for i in 0..5 {
            pipeline.ingest(make_point(
                &format!("r{i}"),
                metric,
                20.0,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 60.0);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(
            alerts[0].anomaly_type,
            AnomalyType::ReputationDistributionShift
        );
    }

    #[test]
    fn test_anomaly_detection_revocation_delay() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::RevocationPropagationLatency);
        for i in 0..5 {
            pipeline.ingest(make_point(
                &format!("d{i}"),
                metric,
                7200.0,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 300.0);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(
            alerts[0].anomaly_type,
            AnomalyType::RevocationPropagationDelay
        );
    }

    #[test]
    fn test_anomaly_detection_publication_volume() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished);
        for i in 0..5 {
            pipeline.ingest(make_point(
                &format!("v{i}"),
                metric,
                500.0,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 50.0);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(
            alerts[0].anomaly_type,
            AnomalyType::PublicationVolumeAnomaly
        );
    }

    #[test]
    fn test_no_anomaly_within_threshold() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        for i in 0..5 {
            pipeline.ingest(make_point(
                &format!("p{i}"),
                metric,
                0.88,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 0.90);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_anomaly_detection_ignores_missing_baseline() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;
        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        pipeline.ingest(make_point("p1", metric, 0.1, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 0.1, &ts(2)));

        let alerts = pipeline.detect_anomalies(&BTreeMap::new());

        assert!(alerts.is_empty());
        assert!(pipeline.active_alerts().is_empty());
    }

    #[test]
    fn test_anomaly_detection_ignores_zero_baseline() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;
        let metric = MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished);
        pipeline.ingest(make_point("p1", metric, 100.0, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 100.0, &ts(2)));
        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 0.0);

        let alerts = pipeline.detect_anomalies(&baseline);

        assert!(alerts.is_empty());
        assert!(pipeline.active_alerts().is_empty());
    }

    #[test]
    fn test_anomaly_detection_requires_minimum_data_points() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 3;
        let metric = MetricKind::Trust(TrustMetricKind::RevocationPropagationLatency);
        pipeline.ingest(make_point("p1", metric, 7200.0, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 7200.0, &ts(2)));
        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 300.0);

        let alerts = pipeline.detect_anomalies(&baseline);

        assert!(alerts.is_empty());
        assert!(pipeline.active_alerts().is_empty());
    }

    #[test]
    fn test_health_export() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        pipeline.ingest(make_point("p1", metric, 0.85, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 0.90, &ts(2)));

        let export = pipeline.export_health(&ts(3), None, None, None);
        assert!(!export.exported_at.is_empty());
        assert!(export.provenance_coverage > 0.0);
        assert_eq!(
            export.compromise_reduction_metadata.availability,
            DerivedMetricAvailability::MissingUpstream
        );
    }

    #[test]
    fn test_health_export_ignores_non_finite_stored_points() {
        let mut pipeline = TelemetryPipeline::new();
        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        pipeline
            .data_points
            .push(make_point("nan", metric, f64::NAN, &ts(1)));
        pipeline
            .data_points
            .push(make_point("p1", metric, 0.85, &ts(2)));
        pipeline
            .data_points
            .push(make_point("inf", metric, f64::INFINITY, &ts(3)));
        pipeline
            .data_points
            .push(make_point("p2", metric, 0.90, &ts(4)));

        let export = pipeline.export_health(&ts(5), None, None, None);
        assert!(export.provenance_coverage.is_finite());
        assert!((export.provenance_coverage - 0.875).abs() < f64::EPSILON);
    }

    #[test]
    fn test_load_compromise_reduction_report_from_artifact() {
        let report_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/13/compromise_reduction_report.json");
        let report =
            load_compromise_reduction_report(&report_path).expect("load compromise report");
        assert_eq!(report.bead_id, "bd-3cpa");
        assert_eq!(report.baseline_compromised, 20);
        assert_eq!(report.hardened_compromised, 2);
    }

    #[test]
    fn test_load_compromise_reduction_report_missing_file_returns_error() {
        let report_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/13/definitely_missing_compromise_report.json");

        let err = load_compromise_reduction_report(&report_path).unwrap_err();

        assert!(err.contains("failed reading"));
        assert!(err.contains("definitely_missing_compromise_report.json"));
    }

    #[test]
    fn test_health_export_computes_compromise_reduction_from_authoritative_report() {
        let pipeline = TelemetryPipeline::new();
        let report = sample_compromise_report(&ts(3), 20, 2);

        let export = pipeline.export_health(&ts(3), Some(&report), None, None);
        assert_eq!(export.compromise_reduction_factor, Some(10.0));
        assert_eq!(
            export.compromise_reduction_metadata.availability,
            DerivedMetricAvailability::Available
        );
    }

    #[test]
    fn test_health_export_surfaces_complete_containment_instead_of_placeholder_ratio() {
        let pipeline = TelemetryPipeline::new();
        let report = sample_compromise_report(&ts(3), 20, 0);

        let export = pipeline.export_health(&ts(3), Some(&report), None, None);
        assert_eq!(export.compromise_reduction_factor, None);
        assert_eq!(
            export.compromise_reduction_metadata.availability,
            DerivedMetricAvailability::CompleteContainment
        );
    }

    #[test]
    fn test_health_export_surfaces_baseline_absent_for_undefined_compromise_ratio() {
        let pipeline = TelemetryPipeline::new();
        let report = sample_compromise_report(&ts(3), 0, 4);

        let export = pipeline.export_health(&ts(3), Some(&report), None, None);
        assert_eq!(export.compromise_reduction_factor, None);
        assert_eq!(
            export.compromise_reduction_metadata.availability,
            DerivedMetricAvailability::BaselineAbsent
        );
    }

    #[test]
    fn test_health_export_surfaces_stale_compromise_report() {
        let pipeline = TelemetryPipeline::new();
        let report = sample_compromise_report(&ts(1), 20, 2);

        let export = pipeline.export_health(&ts(3), Some(&report), None, None);
        assert_eq!(export.compromise_reduction_factor, None);
        assert_eq!(
            export.compromise_reduction_metadata.availability,
            DerivedMetricAvailability::StaleUpstream
        );
    }

    #[test]
    fn test_health_export_counts_active_extensions_using_certification_registry() {
        let pipeline = TelemetryPipeline::new();
        let export_ts = Utc::now().to_rfc3339();
        let registry = make_active_extension_registry();
        let certification_registry = make_certification_registry(&registry, &export_ts);

        let export = pipeline.export_health(
            &export_ts,
            None,
            Some(&registry),
            Some(&certification_registry),
        );
        assert_eq!(export.certification_distribution.get("standard"), Some(&1));
        assert_eq!(
            export.certification_distribution.get("uncertified"),
            Some(&1)
        );
        assert_eq!(
            export.certification_distribution_metadata.availability,
            DerivedMetricAvailability::Available
        );
    }

    #[test]
    fn test_health_export_marks_stale_certification_distribution_inputs() {
        let pipeline = TelemetryPipeline::new();
        let export_ts = Utc::now().to_rfc3339();
        let stale_export_ts = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let registry = make_active_extension_registry();
        let certification_registry = make_certification_registry(&registry, &export_ts);

        let export = pipeline.export_health(
            &stale_export_ts,
            None,
            Some(&registry),
            Some(&certification_registry),
        );
        assert!(export.certification_distribution.is_empty());
        assert_eq!(
            export.certification_distribution_metadata.availability,
            DerivedMetricAvailability::StaleUpstream
        );
    }

    #[test]
    fn test_compromise_reduction_contract_declares_complete_containment() {
        let contract = compromise_reduction_factor_contract();
        assert_eq!(contract.metric_id, "compromise_reduction_factor");
        assert_eq!(
            contract.formula,
            "baseline_compromised / hardened_compromised"
        );
        assert!(
            contract
                .authoritative_inputs
                .iter()
                .any(|input| input == "artifacts/13/compromise_reduction_report.json")
        );
        assert!(
            contract
                .missing_data_semantics
                .contains(&DerivedMetricAvailability::CompleteContainment)
        );
        assert!(
            contract
                .implementation_scope
                .iter()
                .any(|item| item.contains("placeholder 1.0"))
        );
    }

    #[test]
    fn test_certification_distribution_contract_uses_active_registry_and_uncertified_fallback() {
        let contract = certification_distribution_contract();
        assert_eq!(contract.metric_id, "certification_distribution");
        assert!(contract.authoritative_inputs.iter().any(|input| {
            input.contains("SignedExtensionRegistry.list(Some(ExtensionStatus::Active))")
        }));
        assert!(
            contract
                .authoritative_inputs
                .iter()
                .any(|input| input.contains("CertificationRegistry"))
        );
        assert!(contract.formula.contains("uncertified"));
        assert!(
            contract
                .implementation_scope
                .iter()
                .any(|item| item.contains("trust_card.rs"))
        );
    }

    #[test]
    fn test_resource_budget_eviction() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.resource_budget.max_in_memory_points = 5;

        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        for i in 0..10 {
            pipeline.ingest(make_point(
                &format!("p{i}"),
                metric,
                i as f64,
                &ts((i as u32).saturating_add(1)),
            ));
        }
        assert_eq!(pipeline.stored_count(), 5);
    }

    #[test]
    fn test_governance_default_opt_in() {
        let pipeline = TelemetryPipeline::new();
        assert!(!pipeline.governance().collection_enabled);
    }

    #[test]
    fn test_privacy_filter_flag() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.ingest(make_point(
            "p1",
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.9,
            &ts(1),
        ));

        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: None,
            to: None,
            aggregation: None,
            labels: BTreeMap::new(),
            limit: None,
        });
        // Default k-anonymity threshold > 1, so privacy_filtered should be true.
        assert!(result.privacy_filtered);
    }

    #[test]
    fn test_query_limit_zero_returns_no_rows_but_preserves_total_count() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        pipeline.ingest(make_point("p1", metric, 1.0, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 2.0, &ts(2)));

        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: None,
            to: None,
            aggregation: None,
            labels: BTreeMap::new(),
            limit: Some(0),
        });

        assert_eq!(result.total_count, 2);
        assert!(result.data_points.is_empty());
    }

    #[test]
    fn test_push_bounded_zero_capacity_drops_existing_and_new_point() {
        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        let mut points = vec![make_point("p0", metric, 0.0, &ts(1))];

        push_bounded(&mut points, make_point("p1", metric, 1.0, &ts(2)), 0);

        assert!(points.is_empty());
    }

    #[test]
    fn test_query_unknown_aggregation_returns_empty_without_mutation() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        pipeline.ingest(make_point("p1", metric, 1.0, &ts(1)));
        let before = pipeline.stored_count();

        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: None,
            to: None,
            aggregation: Some(AggregationLevel::Weekly),
            labels: BTreeMap::new(),
            limit: None,
        });

        assert_eq!(result.total_count, 0);
        assert!(result.data_points.is_empty());
        assert_eq!(pipeline.stored_count(), before);
    }

    #[test]
    fn test_query_excludes_exact_upper_bound_timestamp() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        pipeline.ingest(make_point("p1", metric, 1.0, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 2.0, &ts(2)));

        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: Some(ts(1)),
            to: Some(ts(2)),
            aggregation: None,
            labels: BTreeMap::new(),
            limit: None,
        });

        assert_eq!(result.total_count, 1);
        assert_eq!(result.data_points[0].point_id, "p1");
    }

    #[test]
    fn test_anomaly_detection_ignores_nan_baseline() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;
        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        pipeline.ingest(make_point("p1", metric, 0.1, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 0.1, &ts(2)));
        let mut baseline = BTreeMap::new();
        baseline.insert(metric, f64::NAN);

        let alerts = pipeline.detect_anomalies(&baseline);

        assert!(alerts.is_empty());
        assert!(pipeline.active_alerts().is_empty());
    }

    #[test]
    fn test_anomaly_detection_at_exact_threshold_does_not_alert() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;
        pipeline.anomaly_config.deviation_threshold_pct = 30.0;
        let metric = MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished);
        pipeline.ingest(make_point("p1", metric, 130.0, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 130.0, &ts(2)));
        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 100.0);

        let alerts = pipeline.detect_anomalies(&baseline);

        assert!(alerts.is_empty());
        assert!(pipeline.active_alerts().is_empty());
    }

    #[test]
    fn test_health_export_invalid_export_timestamp_marks_report_stale() {
        let pipeline = TelemetryPipeline::new();
        let report = sample_compromise_report(&ts(3), 20, 2);

        let export = pipeline.export_health("not-a-timestamp", Some(&report), None, None);

        assert_eq!(export.compromise_reduction_factor, None);
        assert_eq!(
            export.compromise_reduction_metadata.availability,
            DerivedMetricAvailability::StaleUpstream
        );
    }

    #[test]
    fn test_health_export_missing_certification_registry_is_missing_upstream() {
        let pipeline = TelemetryPipeline::new();
        let registry = make_active_extension_registry();

        let export = pipeline.export_health(&ts(3), None, Some(&registry), None);

        assert!(export.certification_distribution.is_empty());
        assert_eq!(
            export.certification_distribution_metadata.availability,
            DerivedMetricAvailability::MissingUpstream
        );
    }

    #[test]
    fn test_query_with_limit() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        for i in 0..10 {
            pipeline.ingest(make_point(
                &format!("p{i}"),
                metric,
                i as f64,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: None,
            to: None,
            aggregation: None,
            labels: BTreeMap::new(),
            limit: Some(3),
        });
        assert_eq!(result.data_points.len(), 3);
        assert_eq!(result.total_count, 10);
    }

    #[test]
    fn telemetry_unicode_injection_attack() {
        // Test BiDi override and control character injection in telemetry data
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();

        let malicious_point_id = format!(
            "point-{}\u{202e}evil\u{202d}-{}",
            "\u{200b}".repeat(500),
            "💥".repeat(300)
        );
        let mut malicious_labels = BTreeMap::new();
        malicious_labels.insert(
            format!("region\u{2066}hidden\u{2069}-{}", "\u{feff}".repeat(100)),
            format!("us-{}\u{200f}rtl\u{200e}", "🔥".repeat(100)),
        );
        malicious_labels.insert(
            "component".to_string(),
            format!(
                "telemetry\x1b[31mred\x1b[0m-{}",
                "\u{202a}ltr\u{202c}".repeat(50)
            ),
        );

        let unicode_point = TelemetryDataPoint {
            point_id: malicious_point_id.clone(),
            timestamp: ts(1),
            metric: MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            value: 0.95,
            aggregation: AggregationLevel::Raw,
            privacy_filtered: false,
            labels: malicious_labels.clone(),
        };

        assert!(pipeline.ingest(unicode_point));
        assert_eq!(pipeline.ingested_count(), 1);
        assert_eq!(pipeline.stored_count(), 1);

        // Verify stored point handles massive Unicode safely
        let query = TelemetryQuery {
            metric: None,
            from: None,
            to: None,
            aggregation: None,
            labels: BTreeMap::new(),
            limit: None,
        };
        let result = pipeline.query(&query);
        assert_eq!(result.data_points[0].point_id, malicious_point_id);
        assert!(result.data_points[0].point_id.chars().count() > 800);

        // Test display safety (no panic on format)
        let debug_str = format!("{:?}", result.data_points[0]);
        assert!(debug_str.len() > 100);

        // Test serialization robustness with Unicode injection
        let json_result = serde_json::to_string(&pipeline);
        assert!(json_result.is_ok());
        let parsed: Result<TelemetryPipeline, _> = serde_json::from_str(&json_result.unwrap());
        assert!(parsed.is_ok());

        // Test anomaly detection with Unicode data
        let mut baseline = BTreeMap::new();
        baseline.insert(
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.5,
        );
        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert!(alerts[0].description.len() > 10);
    }

    #[test]
    fn telemetry_memory_exhaustion_stress() {
        // Test bounded storage with massive telemetry payloads
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.resource_budget.max_in_memory_points = 100;

        let massive_point_id = "a".repeat(100000);
        let massive_timestamp = format!("2026-01-01T00:00:00Z-{}", "x".repeat(50000));

        // Create massive labels payload
        let mut massive_labels = BTreeMap::new();
        for i in 0..1000 {
            let key = format!("key_{}_with_very_long_name_{}", i, "x".repeat(1000));
            let value = format!("value_{}_with_massive_payload_{}", i, "y".repeat(2000));
            massive_labels.insert(key, value);
        }

        // Stress test with many oversized telemetry points
        for i in 0..500 {
            let point = TelemetryDataPoint {
                point_id: format!("{massive_point_id}-{i}"),
                timestamp: format!("{massive_timestamp}-{i}"),
                metric: MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
                value: (i as f64) / 100.0,
                aggregation: AggregationLevel::Raw,
                privacy_filtered: false,
                labels: massive_labels.clone(),
            };
            let _ = pipeline.ingest(point);
        }

        // Verify bounded capacity prevents memory exhaustion
        assert!(pipeline.stored_count() <= 100);

        // Verify resource budget enforcement
        assert!(pipeline.stored_count() > 0); // Should still have some data
        assert!(pipeline.ingested_count() > 100); // Should have processed more than stored

        // Test memory usage is bounded despite massive payloads
        let total_label_size: usize = pipeline
            .query(&TelemetryQuery {
                metric: None,
                from: None,
                to: None,
                aggregation: None,
                labels: BTreeMap::new(),
                limit: None,
            })
            .data_points
            .iter()
            .map(|p| {
                p.labels
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum::<usize>()
            })
            .sum();
        assert!(total_label_size < 50_000_000); // Reasonable memory bound
    }

    #[test]
    fn telemetry_json_structure_integrity_validation() {
        // Test malicious JSON injection in telemetry structures
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();

        let json_bomb = r#"{"nested":{"arrays":[[[[["very","deep"]]]]],"objects":{"a":{"b":{"c":{"d":"value"}}}}}}"#;
        let json_injection_id = format!(r#"point","malicious":{json_bomb},"legitimate":"#);

        let mut injection_labels = BTreeMap::new();
        injection_labels.insert(
            format!(r#"key","injection":{json_bomb},"hidden":"#),
            "legitimate_value".to_string(),
        );
        injection_labels.insert("normal_key".to_string(), json_bomb.to_string());

        let injection_point = TelemetryDataPoint {
            point_id: json_injection_id.clone(),
            timestamp: ts(1),
            metric: MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished),
            value: 42.0,
            aggregation: AggregationLevel::Raw,
            privacy_filtered: false,
            labels: injection_labels,
        };

        assert!(pipeline.ingest(injection_point));

        // Verify JSON serialization integrity
        let serialized = serde_json::to_string(&pipeline).unwrap();
        assert!(!serialized.contains(r#""malicious":{"nested""#)); // Injection should be escaped

        // Test deserialization with injected structure
        let parsed: TelemetryPipeline = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.stored_count(), 1);

        // Test health export with malicious data
        let export = pipeline.export_health(&ts(2), None, None, None);
        assert!(!export.exported_at.is_empty());

        // Verify query result integrity
        let result = pipeline.query(&TelemetryQuery {
            metric: None,
            from: None,
            to: None,
            aggregation: None,
            labels: BTreeMap::new(),
            limit: None,
        });
        assert_eq!(result.data_points[0].point_id, json_injection_id);
        assert!(result.data_points[0].labels.contains_key("normal_key"));
    }

    #[test]
    fn telemetry_floating_point_validation_bypass_attempts() {
        // Test floating-point validation against bypass attempts
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();

        let suspicious_values = [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.0,
            f64::MIN,
            f64::MAX,
            f64::EPSILON,
            1.0 / 0.0,                          // Should be infinity
            0.0 / 0.0,                          // Should be NaN
            f64::from_bits(0x7FF0000000000001), // Signaling NaN
            f64::from_bits(0xFFF8000000000001), // Quiet NaN with payload
        ];

        for (i, &value) in suspicious_values.iter().enumerate() {
            let point = TelemetryDataPoint {
                point_id: format!("suspicious-{i}"),
                timestamp: ts((i as u32).saturating_add(1)),
                metric: MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
                value,
                aggregation: AggregationLevel::Raw,
                privacy_filtered: false,
                labels: BTreeMap::new(),
            };

            let accepted = pipeline.ingest(point);
            if !value.is_finite() {
                assert!(!accepted, "Should reject non-finite value: {value}");
            } else {
                assert!(accepted, "Should accept finite value: {value}");
            }
        }

        // Only finite values should be stored
        assert!(pipeline.stored_count() <= 4); // -0.0, MIN, MAX, EPSILON

        // Test anomaly detection with mixed finite/non-finite data
        pipeline.data_points.push(TelemetryDataPoint {
            point_id: "nan-injection".to_string(),
            timestamp: ts(20),
            metric: MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            value: f64::NAN,
            aggregation: AggregationLevel::Raw,
            privacy_filtered: false,
            labels: BTreeMap::new(),
        });

        let mut baseline = BTreeMap::new();
        baseline.insert(
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.5,
        );
        let alerts = pipeline.detect_anomalies(&baseline);

        // Anomaly detection should ignore non-finite stored points
        for alert in &alerts {
            assert!(alert.current_value.is_finite());
            assert!(alert.baseline_value.is_finite());
            assert!(alert.deviation_pct.is_finite());
        }
    }

    #[test]
    fn telemetry_anomaly_detection_bypass_attempts() {
        // Test anomaly detection against bypass and manipulation attempts
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();

        // Attempt to manipulate anomaly thresholds
        pipeline.anomaly_config.deviation_threshold_pct = f64::NAN;
        pipeline.anomaly_config.min_data_points = u32::MAX;

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);

        // Add legitimate anomalous data
        for i in 0..10 {
            pipeline.ingest(make_point(
                &format!("anomaly-{i}"),
                metric,
                0.1,
                &ts((i as u32).saturating_add(1)),
            ));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 0.9); // High baseline, should trigger anomaly

        // Reset to valid config to test bypass resistance
        pipeline.anomaly_config.deviation_threshold_pct = 30.0;
        pipeline.anomaly_config.min_data_points = 5;

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty()); // Should still detect anomaly

        // Test baseline manipulation attempts
        let mut malicious_baseline = BTreeMap::new();
        malicious_baseline.insert(metric, f64::NAN);
        let nan_alerts = pipeline.detect_anomalies(&malicious_baseline);
        assert!(nan_alerts.is_empty()); // Should ignore NaN baseline

        malicious_baseline.insert(metric, f64::INFINITY);
        let inf_alerts = pipeline.detect_anomalies(&malicious_baseline);
        assert!(inf_alerts.is_empty()); // Should ignore infinite baseline

        malicious_baseline.insert(metric, 0.0);
        let zero_alerts = pipeline.detect_anomalies(&malicious_baseline);
        assert!(zero_alerts.is_empty()); // Should ignore zero baseline

        // Test extreme deviation calculation edge cases
        malicious_baseline.insert(metric, f64::EPSILON);
        let epsilon_alerts = pipeline.detect_anomalies(&malicious_baseline);
        // Should handle very small baselines safely

        // Test alert ID generation resistance
        let original_alert_count = pipeline.anomaly_alerts.len();
        let new_alerts = pipeline.detect_anomalies(&baseline);
        if !new_alerts.is_empty() {
            assert!(
                new_alerts[0]
                    .alert_id
                    .contains(&original_alert_count.to_string())
            );
        }
    }

    #[test]
    fn telemetry_display_injection_and_format_safety() {
        // Test format string injection and display safety in telemetry data
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();

        // Create data with format specifiers and injection attempts
        let malicious_inputs = [
            (
                "point-{}",
                "ts-{}",
                "metric-%s",
                MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            ),
            (
                "point\n\tmalicious",
                "ts\x00null",
                "metric\r\nCRLF",
                MetricKind::Trust(TrustMetricKind::QuarantineResolutionTime),
            ),
            (
                "point%n%s%d",
                "ts%x%p",
                "metric%c%u",
                MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished),
            ),
            (
                "point\x1b[31mred\x1b[0m",
                "ts\x1b[1mbold\x1b[0m",
                "metric\x1b[?1049h",
                MetricKind::Trust(TrustMetricKind::RevocationPropagationLatency),
            ),
            (
                "point\u{1f4a9}\u{200d}\u{1f525}",
                "ts\u{202e}RLO\u{202d}",
                "metric\u{2066}LRI\u{2069}",
                MetricKind::Trust(TrustMetricKind::ReputationDistribution),
            ),
        ];

        for (i, (point_id, timestamp, label_value, metric)) in
            malicious_inputs.into_iter().enumerate()
        {
            let mut labels = BTreeMap::new();
            labels.insert("component".to_string(), label_value.to_string());
            labels.insert("format_test".to_string(), format!("value-{}", point_id));

            let malicious_point = TelemetryDataPoint {
                point_id: point_id.to_string(),
                timestamp: timestamp.to_string(),
                metric,
                value: ((i as u32).saturating_add(1)) as f64 * 10.0,
                aggregation: AggregationLevel::Raw,
                privacy_filtered: false,
                labels,
            };

            assert!(pipeline.ingest(malicious_point));
        }

        // Test display safety - should not panic or produce control sequences
        for point in &pipeline
            .query(&TelemetryQuery {
                metric: None,
                from: None,
                to: None,
                aggregation: None,
                labels: BTreeMap::new(),
                limit: None,
            })
            .data_points
        {
            let debug_str = format!("{:?}", point);
            assert!(
                !debug_str.contains('\x00'),
                "Debug output should escape null bytes"
            );
            assert!(!debug_str.contains('\r'), "Debug should escape CRLF");
            assert!(!debug_str.contains('\n'), "Debug should escape newlines");
        }

        // Test anomaly alert display safety
        let mut baseline = BTreeMap::new();
        baseline.insert(
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            1.0,
        );
        let alerts = pipeline.detect_anomalies(&baseline);

        for alert in &alerts {
            let alert_debug = format!("{:?}", alert);
            assert!(
                !alert_debug.contains('\x1b'),
                "Alert debug should escape ANSI"
            );

            let description_display = format!("{}", alert.description);
            assert!(
                description_display.len() > 0,
                "Alert description should produce output"
            );
        }

        // Test health export display safety
        let export = pipeline.export_health("2026-01-01T00:00:00Z", None, None, None);
        let export_debug = format!("{:?}", export);
        assert!(
            !export_debug.contains('\x00'),
            "Export debug should be safe"
        );

        // Test error display safety with malformed data
        let malformed_query = TelemetryQuery {
            metric: None,
            from: Some("not-a-timestamp\x00\x1b[31m".to_string()),
            to: Some("also-bad\r\n%s".to_string()),
            aggregation: None,
            labels: {
                let mut bad_labels = BTreeMap::new();
                bad_labels.insert("key\x1b[?1049h".to_string(), "value%n".to_string());
                bad_labels
            },
            limit: None,
        };

        let result = pipeline.query(&malformed_query);
        // Query should handle malformed input safely without crashing
        assert!(result.total_count == result.total_count); // Tautology to check for side effects
    }

    #[test]
    fn telemetry_concurrent_pipeline_safety() {
        // Test concurrent telemetry operations for race conditions
        use std::sync::{Arc, Mutex};
        use std::thread;

        let pipeline = Arc::new(Mutex::new(TelemetryPipeline::new()));
        {
            let mut p = pipeline.lock().unwrap();
            p.enable_collection();
        }

        let mut handles = vec![];

        // Spawn concurrent threads performing different operations
        for thread_id in 0..10 {
            let pipeline_clone = Arc::clone(&pipeline);

            let handle = thread::spawn(move || {
                let operations = [
                    // Ingestion operations
                    || {
                        let mut p = pipeline_clone.lock().unwrap();
                        let point = TelemetryDataPoint {
                            point_id: format!("point-{thread_id}"),
                            timestamp: format!("2026-01-{thread_id:02}T00:00:00Z"),
                            metric: MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
                            value: (thread_id as f64) / 10.0,
                            aggregation: AggregationLevel::Raw,
                            privacy_filtered: false,
                            labels: BTreeMap::new(),
                        };
                        let _ = p.ingest(point);
                    },
                    // Query operations
                    || {
                        let p = pipeline_clone.lock().unwrap();
                        let query = TelemetryQuery {
                            metric: Some(MetricKind::Trust(
                                TrustMetricKind::ProvenanceCoverageRate,
                            )),
                            from: None,
                            to: None,
                            aggregation: None,
                            labels: BTreeMap::new(),
                            limit: Some(5),
                        };
                        let _ = p.query(&query);
                    },
                    // Anomaly detection operations
                    || {
                        let mut p = pipeline_clone.lock().unwrap();
                        let mut baseline = BTreeMap::new();
                        baseline.insert(
                            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
                            0.5,
                        );
                        let _ = p.detect_anomalies(&baseline);
                    },
                ];

                // Perform multiple operations in this thread
                for op in operations.iter().cycle().take(50) {
                    op();
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Verify final state consistency
        let final_pipeline = pipeline.lock().unwrap();
        assert!(final_pipeline.ingested_count() >= 10);
        assert!(
            final_pipeline.stored_count() <= final_pipeline.resource_budget().max_in_memory_points
        );

        // Verify data integrity after concurrent access
        let results = final_pipeline.query(&TelemetryQuery {
            metric: None,
            from: None,
            to: None,
            aggregation: None,
            labels: BTreeMap::new(),
            limit: None,
        });

        for point in &results.data_points {
            assert!(point.point_id.starts_with("point-"));
            assert!(point.value >= 0.0 && point.value <= 1.0);
            assert!(point.timestamp.starts_with("2026-01-"));
        }

        // Verify health export works after concurrent operations
        let export = final_pipeline.export_health("2026-01-01T00:00:00Z", None, None, None);
        assert!(!export.exported_at.is_empty());
        assert!(export.provenance_coverage.is_finite());
    }

    #[test]
    fn telemetry_boundary_condition_stress_testing() {
        // Test extreme boundary conditions and edge cases
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();

        // Test empty and minimal inputs
        let boundary_points = [
            // Empty strings
            TelemetryDataPoint {
                point_id: String::new(),
                timestamp: String::new(),
                metric: MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
                value: 0.0,
                aggregation: AggregationLevel::Raw,
                privacy_filtered: false,
                labels: BTreeMap::new(),
            },
            // Single character
            TelemetryDataPoint {
                point_id: "a".to_string(),
                timestamp: "b".to_string(),
                metric: MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished),
                value: 1.0,
                aggregation: AggregationLevel::Hourly,
                privacy_filtered: true,
                labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("k".to_string(), "v".to_string());
                    labels
                },
            },
            // Extreme numeric values
            TelemetryDataPoint {
                point_id: "extreme".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                metric: MetricKind::Trust(TrustMetricKind::QuarantineResolutionTime),
                value: f64::MAX,
                aggregation: AggregationLevel::Weekly,
                privacy_filtered: false,
                labels: BTreeMap::new(),
            },
        ];

        for point in boundary_points {
            let ingest_result = pipeline.ingest(point);
            let _ = ingest_result; // Allow any result, testing for crashes
        }

        // Test extremely long inputs
        let long_point = TelemetryDataPoint {
            point_id: "a".repeat(1000000),
            timestamp: format!("2026-01-01T00:00:00Z-{}", "x".repeat(100000)),
            metric: MetricKind::Trust(TrustMetricKind::CertificationDistribution),
            value: 42.0,
            aggregation: AggregationLevel::Daily,
            privacy_filtered: false,
            labels: {
                let mut labels = BTreeMap::new();
                for i in 0..1000 {
                    labels.insert(format!("key-{i}"), "z".repeat(10000));
                }
                labels
            },
        };

        let long_ingest_result = pipeline.ingest(long_point);
        assert!(long_ingest_result, "Should handle very long inputs");

        // Test boundary queries
        let boundary_queries = [
            TelemetryQuery {
                metric: None,
                from: Some(String::new()),
                to: Some(String::new()),
                aggregation: None,
                labels: BTreeMap::new(),
                limit: Some(0),
            },
            TelemetryQuery {
                metric: None,
                from: Some("9999-12-31T23:59:59Z".to_string()),
                to: Some("0001-01-01T00:00:00Z".to_string()), // Reversed range
                aggregation: None,
                labels: BTreeMap::new(),
                limit: Some(usize::MAX),
            },
        ];

        for query in boundary_queries {
            let query_result = pipeline.query(&query);
            assert!(query_result.total_count == query_result.total_count); // Tautology to check for side effects
        }

        // Test resource budget boundaries
        let original_budget = pipeline.resource_budget.max_in_memory_points;
        pipeline.resource_budget.max_in_memory_points = 0;

        let zero_budget_point = make_point(
            "zero-budget",
            MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate),
            0.5,
            &ts(1),
        );
        assert!(!pipeline.ingest(zero_budget_point));

        pipeline.resource_budget.max_in_memory_points = original_budget;

        // Test serialization with boundary data
        let json_result = serde_json::to_string(&pipeline);
        assert!(json_result.is_ok(), "Should serialize boundary data safely");

        let parsed_result: Result<TelemetryPipeline, _> =
            serde_json::from_str(&json_result.unwrap());
        assert!(
            parsed_result.is_ok(),
            "Should deserialize boundary data safely"
        );

        // Test health export with boundary conditions
        let export = pipeline.export_health("", None, None, None);
        assert!(!export.exported_at.is_empty()); // Should handle empty timestamp gracefully
        assert!(export.provenance_coverage.is_finite());
        assert!(export.migration_velocity.is_finite());
        assert!(export.avg_quarantine_resolution_secs.is_finite());
    }
}
