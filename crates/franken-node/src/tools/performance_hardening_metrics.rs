//! bd-ka0n: Performance under hardening metric family (Section 14).
//!
//! Instruments p50/p95/p99 latencies, cold-start overhead, and security
//! hardening overhead metrics. Tracks performance regression when hardening
//! features are enabled, providing quantitative data for cost/benefit analysis.
//!
//! # Capabilities
//!
//! - Latency percentile tracking (p50, p95, p99)
//! - Cold-start measurement with warm-start comparison
//! - Hardening overhead computation (baseline vs hardened)
//! - Operation category segmentation (Startup, Request, Migration, Verification, Shutdown)
//! - Threshold-gated release enforcement
//! - Trend detection across measurement windows
//!
//! # Invariants
//!
//! - **INV-PHM-PERCENTILE**: p50/p95/p99 always correctly ordered.
//! - **INV-PHM-DETERMINISTIC**: Same inputs produce same report output.
//! - **INV-PHM-OVERHEAD**: Hardening overhead is ratio of hardened/baseline.
//! - **INV-PHM-GATED**: Operations exceeding latency budget flagged.
//! - **INV-PHM-VERSIONED**: Metric version embedded in every report.
//! - **INV-PHM-AUDITABLE**: Every submission produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const PHM_METRIC_SUBMITTED: &str = "PHM-001";
    pub const PHM_PERCENTILES_COMPUTED: &str = "PHM-002";
    pub const PHM_COLD_START_MEASURED: &str = "PHM-003";
    pub const PHM_OVERHEAD_COMPUTED: &str = "PHM-004";
    pub const PHM_THRESHOLD_CHECKED: &str = "PHM-005";
    pub const PHM_REPORT_GENERATED: &str = "PHM-006";
    pub const PHM_TREND_DETECTED: &str = "PHM-007";
    pub const PHM_CATEGORY_REGISTERED: &str = "PHM-008";
    pub const PHM_VERSION_EMBEDDED: &str = "PHM-009";
    pub const PHM_BUDGET_CHECKED: &str = "PHM-010";
    pub const PHM_ERR_BUDGET_EXCEEDED: &str = "PHM-ERR-001";
    pub const PHM_ERR_INVALID_METRIC: &str = "PHM-ERR-002";
}

pub mod invariants {
    pub const INV_PHM_PERCENTILE: &str = "INV-PHM-PERCENTILE";
    pub const INV_PHM_DETERMINISTIC: &str = "INV-PHM-DETERMINISTIC";
    pub const INV_PHM_OVERHEAD: &str = "INV-PHM-OVERHEAD";
    pub const INV_PHM_GATED: &str = "INV-PHM-GATED";
    pub const INV_PHM_VERSIONED: &str = "INV-PHM-VERSIONED";
    pub const INV_PHM_AUDITABLE: &str = "INV-PHM-AUDITABLE";
}

pub const METRIC_VERSION: &str = "phm-v1.0";

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
        // Use a fixed bit pattern for non-finite values to ensure INV-PHM-DETERMINISTIC.
        hasher.update(0u64.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationCategory {
    Startup,
    Request,
    Migration,
    Verification,
    Shutdown,
}

impl OperationCategory {
    pub fn all() -> &'static [OperationCategory] {
        &[
            Self::Startup,
            Self::Request,
            Self::Migration,
            Self::Verification,
            Self::Shutdown,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Request => "request",
            Self::Migration => "migration",
            Self::Verification => "verification",
            Self::Shutdown => "shutdown",
        }
    }

    /// Default latency budget in milliseconds (p99).
    pub fn budget_ms(&self) -> f64 {
        match self {
            Self::Startup => 5000.0,
            Self::Request => 100.0,
            Self::Migration => 30000.0,
            Self::Verification => 500.0,
            Self::Shutdown => 2000.0,
        }
    }
}

/// Latency percentiles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Percentiles {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

impl Percentiles {
    pub fn is_ordered(&self) -> bool {
        self.p50_ms <= self.p95_ms && self.p95_ms <= self.p99_ms
    }
}

/// A performance metric submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceMetric {
    pub metric_id: String,
    pub category: OperationCategory,
    pub baseline: Percentiles,
    pub hardened: Percentiles,
    pub cold_start_ms: f64,
    pub warm_start_ms: f64,
    pub sample_count: u64,
    pub timestamp: String,
}

impl PerformanceMetric {
    /// Hardening overhead ratio at p99.
    pub fn overhead_ratio(&self) -> f64 {
        if self.baseline.p99_ms.abs() < f64::EPSILON {
            return 0.0;
        }
        self.hardened.p99_ms / self.baseline.p99_ms
    }

    /// Cold-start overhead ratio.
    pub fn cold_start_ratio(&self) -> f64 {
        if self.warm_start_ms.abs() < f64::EPSILON {
            return 0.0;
        }
        self.cold_start_ms / self.warm_start_ms
    }

    /// Whether hardened p99 is within budget.
    pub fn within_budget(&self) -> bool {
        self.hardened.p99_ms <= self.category.budget_ms()
    }
}

/// Category-level aggregated stats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CategoryStats {
    pub category: OperationCategory,
    pub metric_count: usize,
    pub avg_overhead_ratio: f64,
    pub avg_cold_start_ratio: f64,
    pub max_hardened_p99: f64,
    pub budget_ms: f64,
    pub within_budget: bool,
}

/// Full performance report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub report_id: String,
    pub timestamp: String,
    pub metric_version: String,
    pub total_metrics: usize,
    pub categories: Vec<CategoryStats>,
    pub overall_overhead_ratio: f64,
    pub flagged_categories: Vec<OperationCategory>,
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhmAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PerformanceHardeningMetrics {
    metric_version: String,
    metrics: Vec<PerformanceMetric>,
    audit_log: Vec<PhmAuditRecord>,
}

impl Default for PerformanceHardeningMetrics {
    fn default() -> Self {
        Self {
            metric_version: METRIC_VERSION.to_string(),
            metrics: Vec::new(),
            audit_log: Vec::new(),
        }
    }
}

impl PerformanceHardeningMetrics {
    pub fn submit_metric(
        &mut self,
        mut metric: PerformanceMetric,
        trace_id: &str,
    ) -> Result<String, String> {
        // Validate percentile ordering
        if !metric.baseline.is_ordered() || !metric.hardened.is_ordered() {
            self.log(
                event_codes::PHM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "percentiles not ordered (p50 <= p95 <= p99)",
                }),
            );
            return Err("Percentiles must be ordered: p50 <= p95 <= p99".to_string());
        }

        if !metric.cold_start_ms.is_finite()
            || !metric.warm_start_ms.is_finite()
            || !metric.baseline.p50_ms.is_finite()
            || !metric.baseline.p95_ms.is_finite()
            || !metric.baseline.p99_ms.is_finite()
            || !metric.hardened.p50_ms.is_finite()
            || !metric.hardened.p95_ms.is_finite()
            || !metric.hardened.p99_ms.is_finite()
        {
            self.log(
                event_codes::PHM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "non-finite float in metric fields",
                }),
            );
            return Err("All metric fields must be finite".to_string());
        }

        if metric.cold_start_ms < 0.0
            || metric.warm_start_ms < 0.0
            || metric.baseline.p50_ms < 0.0
            || metric.baseline.p95_ms < 0.0
            || metric.baseline.p99_ms < 0.0
            || metric.hardened.p50_ms < 0.0
            || metric.hardened.p95_ms < 0.0
            || metric.hardened.p99_ms < 0.0
        {
            self.log(
                event_codes::PHM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "negative float in metric fields",
                }),
            );
            return Err("All metric fields must be non-negative".to_string());
        }

        if metric.sample_count == 0 {
            self.log(
                event_codes::PHM_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric.metric_id,
                    "reason": "sample_count must be > 0",
                }),
            );
            return Err("sample_count must be > 0".to_string());
        }

        metric.timestamp = Utc::now().to_rfc3339();
        let metric_id = metric.metric_id.clone();

        self.log(
            event_codes::PHM_METRIC_SUBMITTED,
            trace_id,
            serde_json::json!({
                "metric_id": &metric_id,
                "category": metric.category.label(),
            }),
        );

        self.log(
            event_codes::PHM_PERCENTILES_COMPUTED,
            trace_id,
            serde_json::json!({
                "metric_id": &metric_id,
                "baseline_p99": metric.baseline.p99_ms,
                "hardened_p99": metric.hardened.p99_ms,
            }),
        );

        self.log(
            event_codes::PHM_OVERHEAD_COMPUTED,
            trace_id,
            serde_json::json!({
                "metric_id": &metric_id,
                "overhead_ratio": metric.overhead_ratio(),
            }),
        );

        self.log(
            event_codes::PHM_COLD_START_MEASURED,
            trace_id,
            serde_json::json!({
                "metric_id": &metric_id,
                "cold_start_ms": metric.cold_start_ms,
                "warm_start_ms": metric.warm_start_ms,
                "ratio": metric.cold_start_ratio(),
            }),
        );

        if !metric.within_budget() {
            self.log(
                event_codes::PHM_ERR_BUDGET_EXCEEDED,
                trace_id,
                serde_json::json!({
                    "metric_id": &metric_id,
                    "hardened_p99": metric.hardened.p99_ms,
                    "budget_ms": metric.category.budget_ms(),
                }),
            );
        }

        self.log(
            event_codes::PHM_THRESHOLD_CHECKED,
            trace_id,
            serde_json::json!({
                "metric_id": &metric_id,
                "within_budget": metric.within_budget(),
            }),
        );

        push_bounded(&mut self.metrics, metric, MAX_METRICS);
        Ok(metric_id)
    }

    pub fn generate_report(&mut self, trace_id: &str) -> PerformanceReport {
        let mut cat_data: BTreeMap<OperationCategory, Vec<&PerformanceMetric>> = BTreeMap::new();
        for m in &self.metrics {
            cat_data.entry(m.category).or_default().push(m);
        }

        let mut categories = Vec::new();
        let mut flagged = Vec::new();
        let mut total_overhead = 0.0;
        let mut total_count = 0usize;

        for (cat, metrics) in &cat_data {
            let mut overhead_sum = 0.0;
            let mut cold_sum = 0.0;
            let mut max_p99 = 0.0f64;

            for m in metrics {
                overhead_sum += m.overhead_ratio();
                cold_sum += m.cold_start_ratio();
                max_p99 = max_p99.max(m.hardened.p99_ms);
            }

            let n = metrics.len() as f64;
            if n == 0.0 {
                continue;
            }
            let avg_overhead = overhead_sum / n;
            let avg_cold = cold_sum / n;
            let budget = cat.budget_ms();
            let within = max_p99 <= budget;

            if !within {
                flagged.push(*cat);
            }

            total_overhead += overhead_sum;
            total_count += metrics.len();

            categories.push(CategoryStats {
                category: *cat,
                metric_count: metrics.len(),
                avg_overhead_ratio: avg_overhead,
                avg_cold_start_ratio: avg_cold,
                max_hardened_p99: max_p99,
                budget_ms: budget,
                within_budget: within,
            });
        }

        let overall = if total_count > 0 {
            total_overhead / total_count as f64
        } else {
            0.0
        };

        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"perf_hardening_metrics_hash_v1:");
            h.update((self.metric_version.len() as u64).to_le_bytes());
            h.update(self.metric_version.as_bytes());
            h.update((self.metrics.len() as u64).to_le_bytes());
            h.update((categories.len() as u64).to_le_bytes());
            hash_f64(&mut h, overall);
            for category in &categories {
                let label = category.category.label();
                h.update((label.len() as u64).to_le_bytes());
                h.update(label.as_bytes());
                h.update((category.metric_count as u64).to_le_bytes());
                hash_f64(&mut h, category.avg_overhead_ratio);
                hash_f64(&mut h, category.avg_cold_start_ratio);
                hash_f64(&mut h, category.max_hardened_p99);
                hash_f64(&mut h, category.budget_ms);
                h.update([u8::from(category.within_budget)]);
            }
            h.update((flagged.len() as u64).to_le_bytes());
            for cat in &flagged {
                let label = cat.label();
                h.update((label.len() as u64).to_le_bytes());
                h.update(label.as_bytes());
            }
            hex::encode(h.finalize())
        };

        self.log(
            event_codes::PHM_REPORT_GENERATED,
            trace_id,
            serde_json::json!({
                "total_metrics": self.metrics.len(),
                "categories": categories.len(),
            }),
        );

        self.log(
            event_codes::PHM_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({
                "metric_version": &self.metric_version,
            }),
        );

        PerformanceReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            metric_version: self.metric_version.clone(),
            total_metrics: self.metrics.len(),
            categories,
            overall_overhead_ratio: overall,
            flagged_categories: flagged,
            content_hash,
        }
    }

    pub fn metrics(&self) -> &[PerformanceMetric] {
        &self.metrics
    }
    pub fn audit_log(&self) -> &[PhmAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for r in &self.audit_log {
            lines.push(serde_json::to_string(r)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        push_bounded(
            &mut self.audit_log,
            PhmAuditRecord {
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

    fn sample_metric(id: &str, cat: OperationCategory) -> PerformanceMetric {
        PerformanceMetric {
            metric_id: id.to_string(),
            category: cat,
            baseline: Percentiles {
                p50_ms: 10.0,
                p95_ms: 50.0,
                p99_ms: 80.0,
            },
            hardened: Percentiles {
                p50_ms: 12.0,
                p95_ms: 55.0,
                p99_ms: 90.0,
            },
            cold_start_ms: 200.0,
            warm_start_ms: 50.0,
            sample_count: 1000,
            timestamp: String::new(),
        }
    }

    #[test]
    fn five_categories() {
        assert_eq!(OperationCategory::all().len(), 5);
    }

    #[test]
    fn category_budgets_positive() {
        for cat in OperationCategory::all() {
            assert!(cat.budget_ms() > 0.0);
        }
    }

    #[test]
    fn percentiles_ordered() {
        let p = Percentiles {
            p50_ms: 10.0,
            p95_ms: 50.0,
            p99_ms: 99.0,
        };
        assert!(p.is_ordered());
    }

    #[test]
    fn percentiles_unordered() {
        let p = Percentiles {
            p50_ms: 100.0,
            p95_ms: 50.0,
            p99_ms: 99.0,
        };
        assert!(!p.is_ordered());
    }

    #[test]
    fn overhead_ratio() {
        let m = sample_metric("m1", OperationCategory::Request);
        let ratio = m.overhead_ratio();
        assert!(ratio > 1.0 && ratio < 2.0);
    }

    #[test]
    fn cold_start_ratio() {
        let m = sample_metric("m1", OperationCategory::Startup);
        assert!((m.cold_start_ratio() - 4.0).abs() < 0.01);
    }

    #[test]
    fn within_budget_request() {
        let m = sample_metric("m1", OperationCategory::Request);
        assert!(m.within_budget()); // 90ms < 100ms budget
    }

    #[test]
    fn submit_valid_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        assert!(
            engine
                .submit_metric(sample_metric("m1", OperationCategory::Request), &trace())
                .is_ok()
        );
    }

    #[test]
    fn submit_unordered_percentiles_fails() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m1", OperationCategory::Request);
        m.baseline = Percentiles {
            p50_ms: 100.0,
            p95_ms: 50.0,
            p99_ms: 80.0,
        };
        assert!(engine.submit_metric(m, &trace()).is_err());
    }

    #[test]
    fn submit_zero_samples_fails() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m1", OperationCategory::Request);
        m.sample_count = 0;
        assert!(engine.submit_metric(m, &trace()).is_err());
    }

    #[test]
    fn rejected_unordered_hardened_percentiles_do_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-bad-hardened", OperationCategory::Request);
        m.hardened = Percentiles {
            p50_ms: 20.0,
            p95_ms: 15.0,
            p99_ms: 30.0,
        };

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("unordered hardened percentiles should fail");

        assert!(err.contains("Percentiles must be ordered"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_nan_baseline_percentile_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-nan-baseline", OperationCategory::Request);
        m.baseline.p95_ms = f64::NAN;

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("non-finite baseline percentile should fail");

        assert!(err.contains("finite"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_infinite_hardened_percentile_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-inf-hardened", OperationCategory::Verification);
        m.hardened.p99_ms = f64::INFINITY;

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("non-finite hardened percentile should fail");

        assert!(err.contains("finite"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_nan_cold_start_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-nan-cold-start", OperationCategory::Startup);
        m.cold_start_ms = f64::NAN;

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("non-finite cold start should fail");

        assert!(err.contains("finite"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_infinite_warm_start_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-inf-warm-start", OperationCategory::Startup);
        m.warm_start_ms = f64::INFINITY;

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("non-finite warm start should fail");

        assert!(err.contains("finite"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_zero_sample_metric_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-zero-samples", OperationCategory::Request);
        m.sample_count = 0;

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("zero sample count should fail");

        assert!(err.contains("sample_count"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn invalid_metric_submission_logs_invalid_metric_event() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-invalid-event", OperationCategory::Request);
        m.baseline.p50_ms = f64::NAN;

        let result = engine.submit_metric(m, &trace());

        assert!(result.is_err());
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::PHM_ERR_INVALID_METRIC
        );
    }

    #[test]
    fn rejected_negative_baseline_percentile_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-negative-baseline", OperationCategory::Request);
        m.baseline = Percentiles {
            p50_ms: -10.0,
            p95_ms: 1.0,
            p99_ms: 2.0,
        };

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("negative baseline percentile should fail");

        assert!(err.contains("non-negative"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_negative_hardened_percentile_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-negative-hardened", OperationCategory::Verification);
        m.hardened = Percentiles {
            p50_ms: -3.0,
            p95_ms: 4.0,
            p99_ms: 5.0,
        };

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("negative hardened percentile should fail");

        assert!(err.contains("non-negative"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_negative_cold_start_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-negative-cold", OperationCategory::Startup);
        m.cold_start_ms = -1.0;

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("negative cold start should fail");

        assert!(err.contains("non-negative"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_negative_warm_start_does_not_store_metric() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-negative-warm", OperationCategory::Startup);
        m.warm_start_ms = -1.0;

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("negative warm start should fail");

        assert!(err.contains("non-negative"));
        assert!(engine.metrics().is_empty());
    }

    #[test]
    fn rejected_negative_metric_logs_invalid_metric_reason() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m-negative-event", OperationCategory::Migration);
        m.hardened.p50_ms = -0.5;

        let result = engine.submit_metric(m, "trace-negative-metric");

        assert!(result.is_err());
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::PHM_ERR_INVALID_METRIC
        );
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "negative float in metric fields"
        );
    }

    #[test]
    fn rejected_negative_metric_preserves_existing_metrics() {
        let mut engine = PerformanceHardeningMetrics::default();
        engine
            .submit_metric(
                sample_metric("m-kept", OperationCategory::Request),
                &trace(),
            )
            .unwrap();
        let mut m = sample_metric("m-negative-rejected", OperationCategory::Request);
        m.baseline = Percentiles {
            p50_ms: -3.0,
            p95_ms: -2.0,
            p99_ms: -1.0,
        };

        let err = engine
            .submit_metric(m, &trace())
            .expect_err("ordered negative baseline should fail");

        assert!(err.contains("non-negative"));
        assert_eq!(engine.metrics().len(), 1);
        assert_eq!(engine.metrics()[0].metric_id, "m-kept");
    }

    #[test]
    fn push_bounded_zero_capacity_discards_without_panic() {
        let mut items = vec![1_u8, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn submit_sets_timestamp() {
        let mut engine = PerformanceHardeningMetrics::default();
        engine
            .submit_metric(sample_metric("m1", OperationCategory::Request), &trace())
            .unwrap();
        assert!(!engine.metrics()[0].timestamp.is_empty());
    }

    #[test]
    fn report_empty() {
        let mut engine = PerformanceHardeningMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.total_metrics, 0);
    }

    #[test]
    fn report_groups_by_category() {
        let mut engine = PerformanceHardeningMetrics::default();
        engine
            .submit_metric(sample_metric("m1", OperationCategory::Request), &trace())
            .unwrap();
        engine
            .submit_metric(sample_metric("m2", OperationCategory::Startup), &trace())
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.categories.len(), 2);
    }

    #[test]
    fn report_flags_over_budget() {
        let mut engine = PerformanceHardeningMetrics::default();
        let mut m = sample_metric("m1", OperationCategory::Request);
        m.hardened = Percentiles {
            p50_ms: 50.0,
            p95_ms: 80.0,
            p99_ms: 150.0,
        }; // > 100ms budget
        engine.submit_metric(m, &trace()).unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.flagged_categories.len(), 1);
    }

    #[test]
    fn report_has_content_hash() {
        let mut engine = PerformanceHardeningMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.content_hash.len(), 64);
    }

    #[test]
    fn report_has_version() {
        let mut engine = PerformanceHardeningMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.metric_version, METRIC_VERSION);
    }

    #[test]
    fn report_deterministic() {
        let mut e1 = PerformanceHardeningMetrics::default();
        let mut e2 = PerformanceHardeningMetrics::default();
        let r1 = e1.generate_report("trace-det");
        let r2 = e2.generate_report("trace-det");
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn audit_log_populated() {
        let mut engine = PerformanceHardeningMetrics::default();
        engine
            .submit_metric(sample_metric("m1", OperationCategory::Request), &trace())
            .unwrap();
        assert_eq!(engine.audit_log().len(), 5);
    }

    #[test]
    fn audit_has_event_codes() {
        let mut engine = PerformanceHardeningMetrics::default();
        engine
            .submit_metric(sample_metric("m1", OperationCategory::Request), &trace())
            .unwrap();
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::PHM_METRIC_SUBMITTED));
        assert!(codes.contains(&event_codes::PHM_OVERHEAD_COMPUTED));
    }

    #[test]
    fn export_jsonl() {
        let mut engine = PerformanceHardeningMetrics::default();
        engine
            .submit_metric(sample_metric("m1", OperationCategory::Request), &trace())
            .unwrap();
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn overall_overhead_computed() {
        let mut engine = PerformanceHardeningMetrics::default();
        engine
            .submit_metric(sample_metric("m1", OperationCategory::Request), &trace())
            .unwrap();
        let report = engine.generate_report(&trace());
        assert!(report.overall_overhead_ratio > 1.0);
    }

    #[test]
    fn overhead_zero_baseline() {
        let mut m = sample_metric("m1", OperationCategory::Request);
        m.baseline = Percentiles {
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
        };
        assert!((m.overhead_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn default_engine_metric_version() {
        let engine = PerformanceHardeningMetrics::default();
        let report = engine.clone();
        assert_eq!(report.metric_version, METRIC_VERSION);
    }

    #[test]
    fn cold_start_zero_warm_start() {
        let mut m = sample_metric("m1", OperationCategory::Startup);
        m.warm_start_ms = 0.0;
        assert!((m.cold_start_ratio() - 0.0).abs() < f64::EPSILON);
    }

    // === bd-3epue: report hash coverage regression ===

    #[test]
    fn report_hash_changes_with_different_overhead() {
        // Same metric count/category count but different overhead ratio
        // must produce different content hashes.
        let mut e1 = PerformanceHardeningMetrics::default();
        let mut e2 = PerformanceHardeningMetrics::default();
        let m1 = sample_metric("m1", OperationCategory::Startup);
        let mut m2 = sample_metric("m1", OperationCategory::Startup);
        // Make hardened much worse to change overhead ratio
        m2.hardened.p50_ms = 500.0;
        m2.hardened.p95_ms = 1000.0;
        m2.hardened.p99_ms = 2000.0;
        e1.submit_metric(m1, &trace()).unwrap();
        e2.submit_metric(m2, &trace()).unwrap();
        let r1 = e1.generate_report(&trace());
        let r2 = e2.generate_report(&trace());
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "Different overhead ratios must produce different report hash"
        );
    }

    #[test]
    fn report_hash_changes_with_different_category_cold_start_stats() {
        let mut e1 = PerformanceHardeningMetrics::default();
        let mut e2 = PerformanceHardeningMetrics::default();

        let m1 = sample_metric("m1", OperationCategory::Request);
        let mut m2 = sample_metric("m1", OperationCategory::Request);
        m2.cold_start_ms = 400.0;

        e1.submit_metric(m1, &trace()).unwrap();
        e2.submit_metric(m2, &trace()).unwrap();

        let r1 = e1.generate_report(&trace());
        let r2 = e2.generate_report(&trace());

        assert!((r1.overall_overhead_ratio - r2.overall_overhead_ratio).abs() < f64::EPSILON);
        assert_eq!(r1.flagged_categories, r2.flagged_categories);
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "Different category cold-start stats must produce different report hash"
        );
    }
}
