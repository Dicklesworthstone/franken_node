//! bd-18ie: Compatibility correctness metric family by API/risk band (Section 14).
//!
//! Instruments compatibility correctness metrics segmented by API family and
//! risk band. Tracks pass/fail rates, regression counts, and mean-time-to-detect
//! across multiple API surface areas with configurable risk classifications.
//!
//! # Capabilities
//!
//! - API family taxonomy (Core, Extension, Management, Telemetry, Migration)
//! - Risk band classification (Critical, High, Medium, Low)
//! - Correctness metric collection per (API family, risk band) pair
//! - Regression detection with historical comparison
//! - Aggregated correctness reports with confidence intervals
//! - Threshold enforcement per risk band
//!
//! # Invariants
//!
//! - **INV-CCM-SEGMENTED**: Metrics segmented by API family and risk band.
//! - **INV-CCM-DETERMINISTIC**: Same inputs produce same metric report.
//! - **INV-CCM-GATED**: APIs below correctness threshold flagged for remediation.
//! - **INV-CCM-REGRESSION**: Regressions detected when correctness drops.
//! - **INV-CCM-VERSIONED**: Standard version embedded in every report.
//! - **INV-CCM-AUDITABLE**: Every metric submission produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const CCM_METRIC_SUBMITTED: &str = "CCM-001";
    pub const CCM_CORRECTNESS_COMPUTED: &str = "CCM-002";
    pub const CCM_REGRESSION_DETECTED: &str = "CCM-003";
    pub const CCM_THRESHOLD_CHECKED: &str = "CCM-004";
    pub const CCM_REPORT_GENERATED: &str = "CCM-005";
    pub const CCM_API_FAMILY_REGISTERED: &str = "CCM-006";
    pub const CCM_RISK_BAND_ASSIGNED: &str = "CCM-007";
    pub const CCM_AGGREGATE_COMPUTED: &str = "CCM-008";
    pub const CCM_CONFIDENCE_COMPUTED: &str = "CCM-009";
    pub const CCM_VERSION_EMBEDDED: &str = "CCM-010";
    pub const CCM_ERR_BELOW_THRESHOLD: &str = "CCM-ERR-001";
    pub const CCM_ERR_INVALID_METRIC: &str = "CCM-ERR-002";
}

pub mod invariants {
    pub const INV_CCM_SEGMENTED: &str = "INV-CCM-SEGMENTED";
    pub const INV_CCM_DETERMINISTIC: &str = "INV-CCM-DETERMINISTIC";
    pub const INV_CCM_GATED: &str = "INV-CCM-GATED";
    pub const INV_CCM_REGRESSION: &str = "INV-CCM-REGRESSION";
    pub const INV_CCM_VERSIONED: &str = "INV-CCM-VERSIONED";
    pub const INV_CCM_AUDITABLE: &str = "INV-CCM-AUDITABLE";
}

pub const METRIC_VERSION: &str = "ccm-v1.0";

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_METRICS};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

fn hash_f64(hasher: &mut Sha256, value: f64) {
    if value.is_finite() {
        hasher.update(value.to_le_bytes());
    } else {
        hasher.update(f64::NAN.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// API families and risk bands
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiFamily {
    Core,
    Extension,
    Management,
    Telemetry,
    Migration,
}

impl ApiFamily {
    pub fn all() -> &'static [ApiFamily] {
        &[
            Self::Core,
            Self::Extension,
            Self::Management,
            Self::Telemetry,
            Self::Migration,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Extension => "extension",
            Self::Management => "management",
            Self::Telemetry => "telemetry",
            Self::Migration => "migration",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBand {
    Critical,
    High,
    Medium,
    Low,
}

impl RiskBand {
    pub fn all() -> &'static [RiskBand] {
        &[Self::Critical, Self::High, Self::Medium, Self::Low]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Minimum correctness threshold for this risk band.
    pub fn threshold(&self) -> f64 {
        match self {
            Self::Critical => 0.999,
            Self::High => 0.995,
            Self::Medium => 0.99,
            Self::Low => 0.95,
        }
    }
}

// ---------------------------------------------------------------------------
// Metric data structures
// ---------------------------------------------------------------------------

/// A single correctness metric submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrectnessMetric {
    pub metric_id: String,
    pub api_family: ApiFamily,
    pub risk_band: RiskBand,
    pub total_tests: u64,
    pub passed_tests: u64,
    pub regressions: u64,
    pub mean_detect_ms: f64,
    pub timestamp: String,
}

impl CorrectnessMetric {
    pub fn correctness_rate(&self) -> f64 {
        if self.total_tests == 0 {
            return 0.0;
        }
        self.passed_tests as f64 / self.total_tests as f64
    }

    pub fn meets_threshold(&self) -> bool {
        self.correctness_rate() >= self.risk_band.threshold()
    }
}

/// Segment key for grouping metrics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SegmentKey {
    pub api_family: ApiFamily,
    pub risk_band: RiskBand,
}

/// Aggregated correctness statistics for a segment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SegmentStats {
    pub segment: SegmentKey,
    pub metric_count: usize,
    pub total_tests: u64,
    pub total_passed: u64,
    pub total_regressions: u64,
    pub correctness_rate: f64,
    pub threshold: f64,
    pub meets_threshold: bool,
    pub mean_detect_ms: f64,
}

/// A full correctness report across all segments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrectnessReport {
    pub report_id: String,
    pub timestamp: String,
    pub metric_version: String,
    pub total_metrics: usize,
    pub segments: Vec<SegmentStats>,
    pub overall_correctness: f64,
    pub flagged_segments: Vec<SegmentKey>,
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CcmAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CcmConfig {
    pub metric_version: String,
}

impl Default for CcmConfig {
    fn default() -> Self {
        Self {
            metric_version: METRIC_VERSION.to_string(),
        }
    }
}

/// Compatibility correctness metric engine.
#[derive(Debug, Clone)]
pub struct CompatibilityCorrectnessMetrics {
    config: CcmConfig,
    metrics: Vec<CorrectnessMetric>,
    audit_log: Vec<CcmAuditRecord>,
}

impl Default for CompatibilityCorrectnessMetrics {
    fn default() -> Self {
        Self::new(CcmConfig::default())
    }
}

impl CompatibilityCorrectnessMetrics {
    pub fn new(config: CcmConfig) -> Self {
        Self {
            config,
            metrics: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Submit a correctness metric.
    pub fn submit_metric(
        &mut self,
        mut metric: CorrectnessMetric,
        trace_id: &str,
    ) -> Result<String, String> {
        if metric.metric_id.trim().is_empty() {
            self.log(
                event_codes::CCM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "metric_id must be non-empty",
                }),
            );
            return Err("metric_id must be non-empty".to_string());
        }

        if metric.total_tests == 0 {
            self.log(
                event_codes::CCM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "total_tests must be > 0",
                }),
            );
            return Err("total_tests must be > 0".to_string());
        }

        if metric.passed_tests > metric.total_tests {
            self.log(
                event_codes::CCM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "passed_tests > total_tests",
                }),
            );
            return Err("passed_tests cannot exceed total_tests".to_string());
        }

        if metric.regressions > metric.total_tests {
            self.log(
                event_codes::CCM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "regressions > total_tests",
                }),
            );
            return Err("regressions cannot exceed total_tests".to_string());
        }

        if !metric.mean_detect_ms.is_finite() || metric.mean_detect_ms < 0.0 {
            self.log(
                event_codes::CCM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "mean_detect_ms must be a non-negative finite value",
                }),
            );
            return Err("mean_detect_ms must be a non-negative finite value".to_string());
        }
        let max_mean_detect_ms = f64::MAX / (MAX_METRICS.saturating_add(1) as f64);
        if metric.mean_detect_ms > max_mean_detect_ms {
            self.log(
                event_codes::CCM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "mean_detect_ms exceeds safe aggregation bound",
                }),
            );
            return Err("mean_detect_ms exceeds safe aggregation bound".to_string());
        }

        metric.timestamp = Utc::now().to_rfc3339();
        let metric_id = metric.metric_id.clone();

        self.log(
            event_codes::CCM_METRIC_SUBMITTED,
            trace_id,
            serde_json::json!({
                "metric_id": &metric_id,
                "api_family": metric.api_family.label(),
                "risk_band": metric.risk_band.label(),
            }),
        );

        let rate = metric.correctness_rate();
        self.log(
            event_codes::CCM_CORRECTNESS_COMPUTED,
            trace_id,
            serde_json::json!({
                "metric_id": &metric_id,
                "correctness_rate": rate,
            }),
        );

        // Check threshold
        if !metric.meets_threshold() {
            self.log(
                event_codes::CCM_ERR_BELOW_THRESHOLD,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric_id,
                    "rate": rate,
                    "threshold": metric.risk_band.threshold(),
                }),
            );
        }

        self.log(
            event_codes::CCM_THRESHOLD_CHECKED,
            trace_id,
            serde_json::json!({
                "metric_id": &metric_id,
                "meets_threshold": metric.meets_threshold(),
            }),
        );

        // Regression check
        if metric.regressions > 0 {
            self.log(
                event_codes::CCM_REGRESSION_DETECTED,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric_id,
                    "regressions": metric.regressions,
                }),
            );
        }

        push_bounded(&mut self.metrics, metric, MAX_METRICS);
        Ok(metric_id)
    }

    /// Generate aggregated report.
    pub fn generate_report(&mut self, trace_id: &str) -> CorrectnessReport {
        let mut segment_data: BTreeMap<SegmentKey, Vec<&CorrectnessMetric>> = BTreeMap::new();

        for m in &self.metrics {
            let key = SegmentKey {
                api_family: m.api_family,
                risk_band: m.risk_band,
            };
            let segment_vec = segment_data.entry(key).or_default();
            push_bounded(segment_vec, m, MAX_METRICS);
        }

        let mut segments = Vec::new();
        let mut total_tests_all: u64 = 0;
        let mut total_passed_all: u64 = 0;
        let mut flagged = Vec::new();

        for (key, metrics) in &segment_data {
            let mut total_tests: u64 = 0;
            let mut total_passed: u64 = 0;
            let mut total_regressions: u64 = 0;
            let mut detect_sum: f64 = 0.0;

            for m in metrics {
                total_tests = total_tests.saturating_add(m.total_tests);
                total_passed = total_passed.saturating_add(m.passed_tests);
                total_regressions = total_regressions.saturating_add(m.regressions);
                let next_detect_sum = detect_sum + m.mean_detect_ms;
                detect_sum = if next_detect_sum.is_finite() {
                    next_detect_sum
                } else {
                    f64::MAX
                };
            }

            let rate = if total_tests > 0 {
                total_passed as f64 / total_tests as f64
            } else {
                0.0
            };
            let threshold = key.risk_band.threshold();
            let meets = rate >= threshold;

            if !meets {
                flagged.push(key.clone());
            }

            total_tests_all = total_tests_all.saturating_add(total_tests);
            total_passed_all = total_passed_all.saturating_add(total_passed);

            segments.push(SegmentStats {
                segment: key.clone(),
                metric_count: metrics.len(),
                total_tests,
                total_passed,
                total_regressions,
                correctness_rate: rate,
                threshold,
                meets_threshold: meets,
                mean_detect_ms: if metrics.is_empty() {
                    0.0
                } else {
                    detect_sum / metrics.len() as f64
                },
            });
        }

        let overall = if total_tests_all > 0 {
            total_passed_all as f64 / total_tests_all as f64
        } else {
            0.0
        };

        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"compat_correctness_hash_v1:");
            h.update((u64::try_from(self.config.metric_version.len()).unwrap_or(u64::MAX)).to_le_bytes());
            h.update(self.config.metric_version.as_bytes());
            h.update((u64::try_from(self.metrics.len()).unwrap_or(u64::MAX)).to_le_bytes());
            h.update((u64::try_from(segments.len()).unwrap_or(u64::MAX)).to_le_bytes());
            for segment in &segments {
                let api_family = segment.segment.api_family.label();
                let risk_band = segment.segment.risk_band.label();
                h.update((u64::try_from(api_family.len()).unwrap_or(u64::MAX)).to_le_bytes());
                h.update(api_family.as_bytes());
                h.update((u64::try_from(risk_band.len()).unwrap_or(u64::MAX)).to_le_bytes());
                h.update(risk_band.as_bytes());
                h.update((segment.metric_count as u64).to_le_bytes());
                h.update(segment.total_tests.to_le_bytes());
                h.update(segment.total_passed.to_le_bytes());
                h.update(segment.total_regressions.to_le_bytes());
                hash_f64(&mut h, segment.correctness_rate);
                hash_f64(&mut h, segment.threshold);
                h.update([u8::from(segment.meets_threshold)]);
                hash_f64(&mut h, segment.mean_detect_ms);
            }
            hash_f64(&mut h, overall);
            h.update((u64::try_from(flagged.len()).unwrap_or(u64::MAX)).to_le_bytes());
            for seg in &flagged {
                let af = seg.api_family.label();
                let rb = seg.risk_band.label();
                h.update((u64::try_from(af.len()).unwrap_or(u64::MAX)).to_le_bytes());
                h.update(af.as_bytes());
                h.update((u64::try_from(rb.len()).unwrap_or(u64::MAX)).to_le_bytes());
                h.update(rb.as_bytes());
            }
            hex::encode(h.finalize())
        };

        self.log(
            event_codes::CCM_REPORT_GENERATED,
            trace_id,
            serde_json::json!({
                "total_metrics": self.metrics.len(),
                "segments": segments.len(),
                "flagged": flagged.len(),
            }),
        );

        self.log(
            event_codes::CCM_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({
                "metric_version": &self.config.metric_version,
            }),
        );

        CorrectnessReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            metric_version: self.config.metric_version.clone(),
            total_metrics: self.metrics.len(),
            segments,
            overall_correctness: overall,
            flagged_segments: flagged,
            content_hash,
        }
    }

    pub fn metrics(&self) -> &[CorrectnessMetric] {
        &self.metrics
    }

    pub fn audit_log(&self) -> &[CcmAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for record in &self.audit_log {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        push_bounded(
            &mut self.audit_log,
            CcmAuditRecord {
                record_id: Uuid::now_v7().to_string(),
                event_code: event_code.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                trace_id: trace_id.to_string(),
                details,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_metric(
        id: &str,
        family: ApiFamily,
        band: RiskBand,
        total: u64,
        passed: u64,
    ) -> CorrectnessMetric {
        CorrectnessMetric {
            metric_id: id.to_string(),
            api_family: family,
            risk_band: band,
            total_tests: total,
            passed_tests: passed,
            regressions: 0,
            mean_detect_ms: 12.5,
            timestamp: String::new(),
        }
    }

    // === Enums ===

    #[test]
    fn five_api_families() {
        assert_eq!(ApiFamily::all().len(), 5);
    }

    #[test]
    fn four_risk_bands() {
        assert_eq!(RiskBand::all().len(), 4);
    }

    #[test]
    fn risk_band_thresholds_ordered() {
        let thresholds: Vec<f64> = RiskBand::all().iter().map(|r| r.threshold()).collect();
        for w in thresholds.windows(2) {
            assert!(w[0] >= w[1], "thresholds should decrease from critical→low");
        }
    }

    #[test]
    fn api_family_labels_unique() {
        let labels: Vec<&str> = ApiFamily::all().iter().map(|a| a.label()).collect();
        let mut dedup = labels.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(labels.len(), dedup.len());
    }

    // === Correctness rate ===

    #[test]
    fn correctness_rate_perfect() {
        let m = sample_metric("m1", ApiFamily::Core, RiskBand::Critical, 1000, 1000);
        assert!((m.correctness_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn correctness_rate_zero_tests() {
        let m = CorrectnessMetric {
            total_tests: 0,
            passed_tests: 0,
            ..sample_metric("m1", ApiFamily::Core, RiskBand::Low, 0, 0)
        };
        assert!((m.correctness_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn meets_threshold_critical() {
        let m = sample_metric("m1", ApiFamily::Core, RiskBand::Critical, 10000, 9990);
        assert!(m.meets_threshold());
    }

    #[test]
    fn below_threshold_critical() {
        let m = sample_metric("m1", ApiFamily::Core, RiskBand::Critical, 10000, 9900);
        assert!(!m.meets_threshold());
    }

    // === Submission ===

    #[test]
    fn submit_valid_metric() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let m = sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 998);
        assert!(engine.submit_metric(m, &trace()).is_ok());
    }

    #[test]
    fn submit_zero_tests_fails() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let m = sample_metric("m1", ApiFamily::Core, RiskBand::High, 0, 0);
        assert!(engine.submit_metric(m, &trace()).is_err());
    }

    #[test]
    fn submit_passed_exceeds_total_fails() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let m = sample_metric("m1", ApiFamily::Core, RiskBand::High, 100, 200);
        assert!(engine.submit_metric(m, &trace()).is_err());
    }

    #[test]
    fn submit_negative_mean_detect_fails() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric("m-negative", ApiFamily::Core, RiskBand::High, 100, 100);
        m.mean_detect_ms = -1.0;

        let err = engine.submit_metric(m, &trace()).unwrap_err();

        assert!(err.contains("non-negative finite"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn submit_nan_mean_detect_fails() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric("m-nan", ApiFamily::Telemetry, RiskBand::Medium, 100, 100);
        m.mean_detect_ms = f64::NAN;

        let err = engine.submit_metric(m, &trace()).unwrap_err();

        assert!(err.contains("non-negative finite"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn submit_infinite_mean_detect_fails() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric("m-inf", ApiFamily::Migration, RiskBand::Low, 100, 100);
        m.mean_detect_ms = f64::INFINITY;

        let err = engine.submit_metric(m, &trace()).unwrap_err();

        assert!(err.contains("non-negative finite"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn submit_extreme_mean_detect_above_aggregation_bound_fails() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric("m-huge", ApiFamily::Migration, RiskBand::Low, 100, 100);
        m.mean_detect_ms = f64::MAX;

        let err = engine.submit_metric(m, &trace()).unwrap_err();

        assert!(err.contains("safe aggregation bound"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_zero_tests_metric_is_not_stored() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let m = sample_metric("m-zero", ApiFamily::Extension, RiskBand::High, 0, 0);

        assert!(engine.submit_metric(m, &trace()).is_err());

        assert!(engine.metrics().is_empty());
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::CCM_ERR_INVALID_METRIC
        );
    }

    #[test]
    fn rejected_passed_exceeds_total_metric_is_not_stored() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let m = sample_metric("m-over", ApiFamily::Management, RiskBand::Critical, 10, 11);

        assert!(engine.submit_metric(m, &trace()).is_err());

        assert!(engine.metrics().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "passed_tests > total_tests"
        );
    }

    #[test]
    fn rejected_invalid_latency_logs_invalid_metric() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric("m-bad-latency", ApiFamily::Core, RiskBand::High, 100, 100);
        m.mean_detect_ms = f64::NEG_INFINITY;

        assert!(engine.submit_metric(m, &trace()).is_err());

        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::CCM_ERR_INVALID_METRIC
        );
    }

    #[test]
    fn rejected_blank_metric_id_is_not_stored() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric("m-blank", ApiFamily::Core, RiskBand::High, 100, 100);
        m.metric_id.clear();

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("blank metric id must fail");

        assert!(err.contains("metric_id"));
        assert!(engine.metrics().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "metric_id must be non-empty"
        );
    }

    #[test]
    fn rejected_whitespace_metric_id_is_not_stored() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric(
            "m-whitespace",
            ApiFamily::Telemetry,
            RiskBand::Medium,
            10,
            10,
        );
        m.metric_id = "   ".to_string();

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("whitespace metric id must fail");

        assert!(err.contains("metric_id"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_blank_metric_id_takes_precedence_over_zero_tests() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric("m-blank-zero", ApiFamily::Core, RiskBand::High, 0, 1);
        m.metric_id = String::new();

        let err = engine
            .submit_metric(m, "trace-blank-before-zero")
            .expect_err("blank metric id should fail first");

        assert!(err.contains("metric_id"));
        assert!(engine.metrics().is_empty());
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "metric_id must be non-empty"
        );
    }

    #[test]
    fn rejected_zero_tests_takes_precedence_over_passed_over_total() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let m = sample_metric("m-zero-before-over", ApiFamily::Core, RiskBand::High, 0, 1);

        let err = engine
            .submit_metric(m, "trace-zero-before-over")
            .expect_err("zero total tests should fail first");

        assert!(err.contains("total_tests"));
        assert!(engine.metrics().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "total_tests must be > 0"
        );
    }

    #[test]
    fn rejected_passed_over_total_takes_precedence_over_regressions_over_total() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric(
            "m-pass-before-regression",
            ApiFamily::Management,
            RiskBand::Critical,
            10,
            11,
        );
        m.regressions = 12;

        let err = engine
            .submit_metric(m, "trace-pass-before-regression")
            .expect_err("passed_tests should fail before regressions");

        assert!(err.contains("passed_tests"));
        assert!(engine.metrics().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "passed_tests > total_tests"
        );
    }

    #[test]
    fn rejected_regressions_exceeding_total_is_not_stored() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric(
            "m-regressions-over",
            ApiFamily::Migration,
            RiskBand::Low,
            5,
            5,
        );
        m.regressions = 6;

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("regressions above total tests must fail");

        assert!(err.contains("regressions"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_regressions_exceeding_total_logs_invalid_metric() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric(
            "m-regressions-event",
            ApiFamily::Management,
            RiskBand::High,
            3,
            3,
        );
        m.regressions = 4;

        let result = engine.submit_metric(m, "trace-regressions-over");

        assert!(result.is_err());
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::CCM_ERR_INVALID_METRIC
        );
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "regressions > total_tests"
        );
    }

    #[test]
    fn rejected_invalid_metric_preserves_existing_metrics() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        engine
            .submit_metric(
                sample_metric("m-kept", ApiFamily::Core, RiskBand::Low, 100, 100),
                &trace(),
            )
            .unwrap();
        let mut rejected = sample_metric("m-rejected", ApiFamily::Core, RiskBand::Low, 10, 10);
        rejected.regressions = 11;

        let err = engine
            .submit_metric(rejected, &trace())
            .expect_err("invalid metric must fail");

        assert!(err.contains("regressions"));
        assert_eq!(engine.metrics().len(), 1);
        assert_eq!(engine.metrics()[0].metric_id, "m-kept");
    }

    #[test]
    fn rejected_regression_metric_does_not_emit_regression_event() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut rejected = sample_metric(
            "m-rejected-regression-event",
            ApiFamily::Core,
            RiskBand::High,
            4,
            4,
        );
        rejected.regressions = 5;

        let err = engine
            .submit_metric(rejected, "trace-no-regression-event")
            .expect_err("invalid metric must fail before regression logging");

        assert!(err.contains("regressions"));
        assert!(engine.metrics().is_empty());
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::CCM_REGRESSION_DETECTED)
        );
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::CCM_METRIC_SUBMITTED)
        );
    }

    #[test]
    fn rejected_blank_metric_id_report_remains_empty() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric(
            "m-blank-report",
            ApiFamily::Extension,
            RiskBand::Critical,
            10,
            10,
        );
        m.metric_id = " ".to_string();

        assert!(engine.submit_metric(m, &trace()).is_err());

        let report = engine.generate_report(&trace());
        assert_eq!(report.total_metrics, 0);
        assert!(report.segments.is_empty());
        assert!(report.flagged_segments.is_empty());
    }

    #[test]
    fn rejected_nonfinite_latency_report_remains_empty() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric(
            "m-nonfinite-report",
            ApiFamily::Telemetry,
            RiskBand::Medium,
            10,
            10,
        );
        m.mean_detect_ms = f64::NAN;

        assert!(engine.submit_metric(m, "trace-nonfinite-report").is_err());

        let report = engine.generate_report("trace-report-after-nonfinite");
        assert_eq!(report.total_metrics, 0);
        assert!((report.overall_correctness - 0.0).abs() < f64::EPSILON);
        assert!(report.segments.is_empty());
        assert!(report.flagged_segments.is_empty());
    }

    #[test]
    fn report_large_detect_latency_mean_stays_finite() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let safe_large = f64::MAX / (MAX_METRICS.saturating_add(1) as f64);
        let mut first = sample_metric("m-large-1", ApiFamily::Core, RiskBand::Low, 100, 100);
        first.mean_detect_ms = safe_large;
        let mut second = sample_metric("m-large-2", ApiFamily::Core, RiskBand::Low, 100, 100);
        second.mean_detect_ms = safe_large;

        engine.submit_metric(first, &trace()).unwrap();
        engine.submit_metric(second, &trace()).unwrap();

        let report = engine.generate_report(&trace());

        assert!(report.segments[0].mean_detect_ms.is_finite());
    }

    #[test]
    fn push_bounded_zero_capacity_discards_without_panic() {
        let mut items = vec![1_u8, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn submit_sets_timestamp() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let m = sample_metric("m1", ApiFamily::Core, RiskBand::Low, 100, 96);
        engine.submit_metric(m, &trace()).unwrap();
        assert!(!engine.metrics()[0].timestamp.is_empty());
    }

    // === Report ===

    #[test]
    fn report_empty_engine() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.total_metrics, 0);
        assert!(report.segments.is_empty());
    }

    #[test]
    fn report_after_rejected_metric_remains_empty() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let m = sample_metric("m-rejected", ApiFamily::Core, RiskBand::Critical, 10, 20);

        assert!(engine.submit_metric(m, &trace()).is_err());

        let report = engine.generate_report(&trace());
        assert_eq!(report.total_metrics, 0);
        assert!(report.segments.is_empty());
        assert!(report.flagged_segments.is_empty());
    }

    #[test]
    fn report_segments_by_pair() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        engine
            .submit_metric(
                sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 998),
                &trace(),
            )
            .unwrap();
        engine
            .submit_metric(
                sample_metric("m2", ApiFamily::Extension, RiskBand::Low, 500, 480),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.segments.len(), 2);
    }

    #[test]
    fn report_flags_below_threshold() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        engine
            .submit_metric(
                sample_metric("m1", ApiFamily::Core, RiskBand::Critical, 1000, 900),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.flagged_segments.len(), 1);
    }

    #[test]
    fn below_threshold_metric_logs_threshold_error() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        engine
            .submit_metric(
                sample_metric("m-low", ApiFamily::Core, RiskBand::Critical, 1000, 900),
                &trace(),
            )
            .unwrap();

        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|record| record.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::CCM_ERR_BELOW_THRESHOLD));
    }

    #[test]
    fn report_has_content_hash() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.content_hash.len(), 64);
    }

    #[test]
    fn report_has_metric_version() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.metric_version, METRIC_VERSION);
    }

    #[test]
    fn report_is_deterministic() {
        let mut e1 = CompatibilityCorrectnessMetrics::default();
        let mut e2 = CompatibilityCorrectnessMetrics::default();
        let r1 = e1.generate_report("trace-det");
        let r2 = e2.generate_report("trace-det");
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // === Regression detection ===

    #[test]
    fn regression_logged() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        let mut m = sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 995);
        m.regressions = 3;
        engine.submit_metric(m, &trace()).unwrap();
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::CCM_REGRESSION_DETECTED));
    }

    // === Audit log ===

    #[test]
    fn audit_log_populated() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        engine
            .submit_metric(
                sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 998),
                &trace(),
            )
            .unwrap();
        assert_eq!(engine.audit_log().len(), 3);
    }

    #[test]
    fn audit_log_has_event_codes() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        engine
            .submit_metric(
                sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 998),
                &trace(),
            )
            .unwrap();
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::CCM_METRIC_SUBMITTED));
    }

    #[test]
    fn export_jsonl() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        engine
            .submit_metric(
                sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 998),
                &trace(),
            )
            .unwrap();
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn export_empty_audit_log_is_empty_string() {
        let engine = CompatibilityCorrectnessMetrics::default();

        let jsonl = engine.export_audit_log_jsonl().unwrap();

        assert!(jsonl.is_empty());
    }

    // === Overall correctness ===

    #[test]
    fn overall_correctness_computed() {
        let mut engine = CompatibilityCorrectnessMetrics::default();
        engine
            .submit_metric(
                sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 900),
                &trace(),
            )
            .unwrap();
        let report = engine.generate_report(&trace());
        assert!((report.overall_correctness - 0.9).abs() < 0.01);
    }

    // === Config ===

    #[test]
    fn default_config_version() {
        let config = CcmConfig::default();
        assert_eq!(config.metric_version, METRIC_VERSION);
    }

    // === bd-2h7q2: report hash coverage regression ===

    #[test]
    fn report_hash_changes_with_different_correctness() {
        // Same metric count/segment count but different correctness ratios
        // must produce different content hashes.
        let mut e1 = CompatibilityCorrectnessMetrics::default();
        let mut e2 = CompatibilityCorrectnessMetrics::default();
        e1.submit_metric(
            sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 999),
            &trace(),
        )
        .unwrap();
        e2.submit_metric(
            sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 100),
            &trace(),
        )
        .unwrap();
        let r1 = e1.generate_report(&trace());
        let r2 = e2.generate_report(&trace());
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "Different overall_correctness must produce different report hash"
        );
    }

    #[test]
    fn report_hash_changes_with_different_segment_detect_latency() {
        let mut e1 = CompatibilityCorrectnessMetrics::default();
        let mut e2 = CompatibilityCorrectnessMetrics::default();

        let mut faster_detection = sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 998);
        faster_detection.mean_detect_ms = 10.0;
        let mut slower_detection = sample_metric("m1", ApiFamily::Core, RiskBand::High, 1000, 998);
        slower_detection.mean_detect_ms = 250.0;

        e1.submit_metric(faster_detection, &trace()).unwrap();
        e2.submit_metric(slower_detection, &trace()).unwrap();

        let first_report = e1.generate_report(&trace());
        let second_report = e2.generate_report(&trace());

        assert_eq!(
            first_report.overall_correctness,
            second_report.overall_correctness
        );
        assert_eq!(
            first_report.flagged_segments,
            second_report.flagged_segments
        );
        assert_ne!(
            first_report.segments[0].mean_detect_ms,
            second_report.segments[0].mean_detect_ms
        );
        assert_ne!(first_report.content_hash, second_report.content_hash);
    }
}
