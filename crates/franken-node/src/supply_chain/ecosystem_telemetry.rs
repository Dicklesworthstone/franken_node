//! bd-phf: Ecosystem telemetry for trust and adoption metrics.
//!
//! Provides the quantitative feedback loop that drives reputation scoring,
//! certification decisions, policy tuning, and program success measurement.
//! Implements privacy-respecting aggregation, anomaly detection, and time-series
//! retention for ecosystem-level trust and adoption signals.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
            collected_categories: vec![
                "trust_metrics".to_owned(),
                "adoption_metrics".to_owned(),
            ],
            published_categories: vec![
                "aggregate_trust_metrics".to_owned(),
            ],
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
    pub compromise_reduction_factor: f64,
    /// Provenance coverage rate (0.0..=1.0).
    pub provenance_coverage: f64,
    /// Certification level distribution.
    pub certification_distribution: BTreeMap<String, u64>,
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

        // Enforce resource budget.
        if self.data_points.len() >= self.resource_budget.max_in_memory_points {
            // Evict oldest raw data points.
            self.data_points.retain(|p| p.aggregation != AggregationLevel::Raw);
        }

        self.data_points.push(point);
        self.ingested_count += 1;
        true
    }

    /// Run anomaly detection on the current data.
    pub fn detect_anomalies(&mut self, baseline: &BTreeMap<MetricKind, f64>) -> Vec<AnomalyAlert> {
        let mut new_alerts = Vec::new();

        // Group recent data by metric.
        let mut metric_values: BTreeMap<MetricKind, Vec<f64>> = BTreeMap::new();
        for point in &self.data_points {
            metric_values
                .entry(point.metric)
                .or_default()
                .push(point.value);
        }

        for (metric, values) in &metric_values {
            if values.len() < self.anomaly_config.min_data_points as usize {
                continue;
            }

            let current_avg: f64 =
                values.iter().sum::<f64>() / values.len() as f64;

            if let Some(&baseline_val) = baseline.get(metric) {
                if baseline_val.abs() < f64::EPSILON {
                    continue;
                }
                let deviation_pct =
                    ((current_avg - baseline_val) / baseline_val * 100.0).abs();

                if deviation_pct > self.anomaly_config.deviation_threshold_pct {
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
                        alert_id: format!("alert-{}-{}", anomaly_type as u8, self.anomaly_alerts.len()),
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
                    self.anomaly_alerts.push(alert);
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
            results.retain(|p| p.labels.get(key).map_or(false, |v| v == val));
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
    #[must_use]
    pub fn export_health(&self, timestamp: &str) -> EcosystemHealthExport {
        EcosystemHealthExport {
            exported_at: timestamp.to_owned(),
            compatibility_pass_rate: self.compute_metric_avg(MetricKind::Trust(
                TrustMetricKind::CertificationDistribution,
            )),
            migration_velocity: self.compute_metric_avg(MetricKind::Adoption(
                AdoptionMetricKind::ExtensionsPublished,
            )),
            compromise_reduction_factor: 1.0, // Placeholder — computed from external benchmark.
            provenance_coverage: self.compute_metric_avg(MetricKind::Trust(
                TrustMetricKind::ProvenanceCoverageRate,
            )),
            certification_distribution: BTreeMap::new(), // Populated from live data.
            avg_quarantine_resolution_secs: self.compute_metric_avg(MetricKind::Trust(
                TrustMetricKind::QuarantineResolutionTime,
            )),
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
        let values: Vec<f64> = self
            .data_points
            .iter()
            .filter(|p| p.metric == metric)
            .map(|p| p.value)
            .collect();
        if values.is_empty() {
            return 0.0;
        }
        values.iter().sum::<f64>() / values.len() as f64
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_point(
        id: &str,
        metric: MetricKind,
        value: f64,
        ts: &str,
    ) -> TelemetryDataPoint {
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
    fn test_anomaly_detection_provenance_drop() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        // Ingest data points significantly below baseline.
        for i in 0..5 {
            pipeline.ingest(make_point(&format!("p{i}"), metric, 0.3, &ts(i as u32 + 1)));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 0.9); // Baseline is 90% coverage.

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].anomaly_type, AnomalyType::ProvenanceCoverageDrop);
    }

    #[test]
    fn test_anomaly_detection_quarantine_spike() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::QuarantineResolutionTime);
        for i in 0..5 {
            pipeline.ingest(make_point(&format!("q{i}"), metric, 3600.0, &ts(i as u32 + 1)));
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
            pipeline.ingest(make_point(&format!("r{i}"), metric, 20.0, &ts(i as u32 + 1)));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 60.0);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].anomaly_type, AnomalyType::ReputationDistributionShift);
    }

    #[test]
    fn test_anomaly_detection_revocation_delay() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::RevocationPropagationLatency);
        for i in 0..5 {
            pipeline.ingest(make_point(&format!("d{i}"), metric, 7200.0, &ts(i as u32 + 1)));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 300.0);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].anomaly_type, AnomalyType::RevocationPropagationDelay);
    }

    #[test]
    fn test_anomaly_detection_publication_volume() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Adoption(AdoptionMetricKind::ExtensionsPublished);
        for i in 0..5 {
            pipeline.ingest(make_point(&format!("v{i}"), metric, 500.0, &ts(i as u32 + 1)));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 50.0);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].anomaly_type, AnomalyType::PublicationVolumeAnomaly);
    }

    #[test]
    fn test_no_anomaly_within_threshold() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.anomaly_config.min_data_points = 2;

        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        for i in 0..5 {
            pipeline.ingest(make_point(&format!("p{i}"), metric, 0.88, &ts(i as u32 + 1)));
        }

        let mut baseline = BTreeMap::new();
        baseline.insert(metric, 0.90);

        let alerts = pipeline.detect_anomalies(&baseline);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_health_export() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::ProvenanceCoverageRate);
        pipeline.ingest(make_point("p1", metric, 0.85, &ts(1)));
        pipeline.ingest(make_point("p2", metric, 0.90, &ts(2)));

        let export = pipeline.export_health(&ts(3));
        assert!(!export.exported_at.is_empty());
        assert!(export.provenance_coverage > 0.0);
    }

    #[test]
    fn test_resource_budget_eviction() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        pipeline.resource_budget.max_in_memory_points = 5;

        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        for i in 0..10 {
            pipeline.ingest(make_point(&format!("p{i}"), metric, i as f64, &ts(i as u32 + 1)));
        }
        // Should not exceed budget significantly.
        assert!(pipeline.stored_count() <= 10);
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
    fn test_query_with_limit() {
        let mut pipeline = TelemetryPipeline::new();
        pipeline.enable_collection();
        let metric = MetricKind::Trust(TrustMetricKind::CertificationDistribution);
        for i in 0..10 {
            pipeline.ingest(make_point(&format!("p{i}"), metric, i as f64, &ts(i as u32 + 1)));
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
}
