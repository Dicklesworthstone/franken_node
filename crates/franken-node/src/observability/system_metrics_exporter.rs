//! System-wide metrics exporter for Prometheus/Grafana integration.
//!
//! Collects metrics from all franken-node subsystems and exports them in
//! Prometheus format for observability stack consumption. This module implements
//! the T3.1 telemetry infrastructure needed for production monitoring.

use crate::observability::metrics::{MetricValidationError, MetricsRegistry};
use crate::security::cuckoo_filter::revocation_filter_entries_gauge;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// System-wide metrics collection and export service.
///
/// This service aggregates metrics from all franken-node subsystems and provides
/// Prometheus-compatible export for monitoring infrastructure. Designed to be
/// called periodically (every 30-60 seconds) by the observability stack.
#[derive(Debug, Default)]
pub struct SystemMetricsExporter {
    /// Historical snapshots for calculating growth rates and statistics
    historical_snapshots: Vec<MetricSnapshot>,
    /// Maximum number of historical snapshots to retain
    max_history_samples: usize,
}

/// Point-in-time snapshot of system metrics
#[derive(Debug, Clone)]
pub struct MetricSnapshot {
    timestamp_ms: u64,
    revocation_filter_entries: usize,
}

impl MetricSnapshot {
    /// Return the wall-clock millis at which the snapshot was taken.
    #[must_use]
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// Return the live cuckoo revocation filter entry count captured
    /// at snapshot time.
    #[must_use]
    pub fn revocation_filter_entries(&self) -> usize {
        self.revocation_filter_entries
    }
}

impl Default for MetricSnapshot {
    fn default() -> Self {
        Self {
            timestamp_ms: current_timestamp_ms(),
            revocation_filter_entries: 0,
        }
    }
}

impl SystemMetricsExporter {
    /// Create a new system metrics exporter.
    ///
    /// # Parameters
    /// - `max_history_samples`: Maximum number of historical snapshots to retain for
    ///   calculating growth rates and percentiles. Defaults to 10,080 (7 days at 1-minute intervals).
    pub fn new(max_history_samples: Option<usize>) -> Self {
        Self {
            historical_snapshots: Vec::new(),
            max_history_samples: max_history_samples.unwrap_or(10_080), // 7 days @ 1min intervals
        }
    }

    /// Collect current system metrics and update historical tracking.
    ///
    /// This method should be called periodically (every 30-60 seconds) to maintain
    /// accurate growth rate calculations and historical statistics.
    pub fn collect_snapshot(&mut self) -> MetricSnapshot {
        let snapshot = MetricSnapshot {
            timestamp_ms: current_timestamp_ms(),
            revocation_filter_entries: revocation_filter_entries_gauge(),
        };

        // Add to historical tracking with bounded capacity
        if self.historical_snapshots.len() >= self.max_history_samples {
            let overflow = self.historical_snapshots.len() - self.max_history_samples + 1;
            self.historical_snapshots.drain(0..overflow);
        }
        self.historical_snapshots.push(snapshot.clone());

        snapshot
    }

    /// Export current system metrics in Prometheus format.
    ///
    /// This method collects current readings from all subsystems and returns
    /// a Prometheus-compatible metrics export string suitable for scraping.
    pub fn export_prometheus(&mut self) -> Result<String, MetricValidationError> {
        let mut registry = MetricsRegistry::new();
        let snapshot = self.collect_snapshot();

        // Core system metrics
        registry.record_gauge(
            "franken_node_revocation_filter_entries",
            "Number of entries in the revocation filter (cuckoo filter)",
            snapshot.revocation_filter_entries as f64,
            &[],
        )?;

        // Derived metrics for observability
        if let Some(stats) = self.calculate_revocation_filter_stats() {
            registry.record_gauge(
                "franken_node_revocation_filter_growth_rate_per_minute",
                "Current growth rate of revocation filter entries per minute",
                stats.current_growth_rate_per_minute,
                &[],
            )?;

            registry.record_gauge(
                "franken_node_revocation_filter_max_observed",
                "Maximum observed revocation filter entry count in current window",
                stats.max_observed as f64,
                &[],
            )?;

            registry.record_gauge(
                "franken_node_revocation_filter_p50",
                "50th percentile of revocation filter entries in current window",
                stats.p50 as f64,
                &[],
            )?;

            registry.record_gauge(
                "franken_node_revocation_filter_p95",
                "95th percentile of revocation filter entries in current window",
                stats.p95 as f64,
                &[],
            )?;

            registry.record_gauge(
                "franken_node_revocation_filter_p99",
                "99th percentile of revocation filter entries in current window",
                stats.p99 as f64,
                &[],
            )?;

            registry.record_gauge(
                "franken_node_revocation_filter_cuckoo_cliff_crossings_total",
                "Count of times revocation filter crossed the 30,000 entry cuckoo cliff threshold",
                stats.cuckoo_cliff_crossings as f64,
                &[],
            )?;
        }

        // Add timestamp for metrics freshness monitoring
        registry.record_gauge(
            "franken_node_metrics_last_collection_timestamp_seconds",
            "Unix timestamp of the last metrics collection",
            (snapshot.timestamp_ms as f64) / 1000.0,
            &[],
        )?;

        Ok(registry.render_prometheus())
    }

    /// Calculate statistical summary of revocation filter metrics.
    ///
    /// Returns statistics required by T3.2 task: p50, p95, p99, max-observed N,
    /// cuckoo cliff crossings count, and current growth rate.
    pub fn calculate_revocation_filter_stats(&self) -> Option<RevocationFilterStats> {
        if self.historical_snapshots.is_empty() {
            return None;
        }

        let entries: Vec<usize> = self
            .historical_snapshots
            .iter()
            .map(|s| s.revocation_filter_entries)
            .collect();

        let max_observed = entries.iter().max().copied().unwrap_or(0);

        // Calculate percentiles
        let mut sorted_entries = entries.clone();
        sorted_entries.sort_unstable();
        let len = sorted_entries.len();

        let p50 = percentile(&sorted_entries, 50.0);
        let p95 = percentile(&sorted_entries, 95.0);
        let p99 = percentile(&sorted_entries, 99.0);

        // Count cuckoo cliff crossings (30,000 entry threshold)
        const CUCKOO_CLIFF_THRESHOLD: usize = 30_000;
        let cuckoo_cliff_crossings = entries
            .iter()
            .filter(|&&count| count >= CUCKOO_CLIFF_THRESHOLD)
            .count();

        // Calculate current growth rate (entries per minute)
        let current_growth_rate_per_minute = self.calculate_current_growth_rate();

        Some(RevocationFilterStats {
            p50,
            p95,
            p99,
            max_observed,
            cuckoo_cliff_crossings,
            current_growth_rate_per_minute,
        })
    }

    /// Calculate current growth rate in entries per minute.
    ///
    /// Uses the last two snapshots to estimate the instantaneous growth rate.
    /// Returns 0.0 if insufficient data is available.
    fn calculate_current_growth_rate(&self) -> f64 {
        if self.historical_snapshots.len() < 2 {
            return 0.0;
        }

        let recent = &self.historical_snapshots[self.historical_snapshots.len() - 1];
        let previous = &self.historical_snapshots[self.historical_snapshots.len() - 2];

        let time_delta_ms = recent
            .timestamp_ms
            .saturating_sub(previous.timestamp_ms)
            .max(1); // Prevent division by zero
        let entries_delta = recent
            .revocation_filter_entries
            .saturating_sub(previous.revocation_filter_entries);

        // Convert to entries per minute
        (entries_delta as f64) * (60_000.0 / time_delta_ms as f64)
    }

    /// Export T3.2 production statistics as JSON for artifact storage.
    ///
    /// Creates the JSON summary required by T3.2 task for storage under
    /// `tests/artifacts/perf/cuckoo_n_distribution/<date>.json`.
    pub fn export_production_summary(&self) -> Option<serde_json::Value> {
        let stats = self.calculate_revocation_filter_stats()?;
        let window_info = self.get_collection_window_info();

        Some(serde_json::json!({
            "collection_window": {
                "start_timestamp_ms": window_info.start_timestamp_ms,
                "end_timestamp_ms": window_info.end_timestamp_ms,
                "duration_hours": window_info.duration_hours,
                "sample_count": window_info.sample_count
            },
            "revocation_filter_metrics": {
                "p50": stats.p50,
                "p95": stats.p95,
                "p99": stats.p99,
                "max_observed": stats.max_observed,
                "cuckoo_cliff_crossings": stats.cuckoo_cliff_crossings,
                "max_growth_rate_per_minute": self.calculate_max_growth_rate()
            },
            "generated_timestamp": current_timestamp_ms(),
            "task_reference": "bd-98xo5.3.2"
        }))
    }

    /// Calculate maximum growth rate observed during the collection window.
    fn calculate_max_growth_rate(&self) -> f64 {
        if self.historical_snapshots.len() < 2 {
            return 0.0;
        }

        let mut max_rate: f64 = 0.0;

        for window in self.historical_snapshots.windows(2) {
            let current = &window[1];
            let previous = &window[0];

            let time_delta_ms = current
                .timestamp_ms
                .saturating_sub(previous.timestamp_ms)
                .max(1);
            let entries_delta = current
                .revocation_filter_entries
                .saturating_sub(previous.revocation_filter_entries);

            let rate_per_minute = (entries_delta as f64) * (60_000.0 / time_delta_ms as f64);
            max_rate = max_rate.max(rate_per_minute);
        }

        max_rate
    }

    /// Get information about the current collection window.
    fn get_collection_window_info(&self) -> CollectionWindowInfo {
        if self.historical_snapshots.is_empty() {
            return CollectionWindowInfo::default();
        }

        let start_timestamp_ms = self.historical_snapshots[0].timestamp_ms;
        let end_timestamp_ms =
            self.historical_snapshots[self.historical_snapshots.len() - 1].timestamp_ms;
        let duration_ms = end_timestamp_ms.saturating_sub(start_timestamp_ms);
        let duration_hours = (duration_ms as f64) / (60.0 * 60.0 * 1000.0);

        CollectionWindowInfo {
            start_timestamp_ms,
            end_timestamp_ms,
            duration_hours,
            sample_count: self.historical_snapshots.len(),
        }
    }
}

/// Statistical summary of revocation filter metrics.
#[derive(Debug, Clone)]
pub struct RevocationFilterStats {
    pub p50: usize,
    pub p95: usize,
    pub p99: usize,
    pub max_observed: usize,
    pub cuckoo_cliff_crossings: usize,
    pub current_growth_rate_per_minute: f64,
}

/// Information about the metrics collection window.
#[derive(Debug, Clone, Default)]
struct CollectionWindowInfo {
    start_timestamp_ms: u64,
    end_timestamp_ms: u64,
    duration_hours: f64,
    sample_count: usize,
}

/// Calculate percentile from sorted data.
fn percentile(sorted_data: &[usize], percentile: f64) -> usize {
    if sorted_data.is_empty() {
        return 0;
    }

    let len = sorted_data.len();
    if len == 1 {
        return sorted_data[0];
    }

    let index = ((percentile / 100.0) * (len - 1) as f64).round() as usize;
    sorted_data[index.min(len - 1)]
}

/// Get current timestamp in milliseconds since Unix epoch.
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_metrics_exporter_creates_prometheus_export() {
        let mut exporter = SystemMetricsExporter::new(Some(100));
        let prometheus_output = exporter.export_prometheus().expect("should export metrics");

        assert!(prometheus_output.contains("franken_node_revocation_filter_entries"));
        assert!(prometheus_output.contains("# TYPE franken_node_revocation_filter_entries gauge"));
        assert!(prometheus_output.contains("# HELP franken_node_revocation_filter_entries"));
    }

    #[test]
    fn percentile_calculation_handles_edge_cases() {
        assert_eq!(percentile(&[], 50.0), 0);
        assert_eq!(percentile(&[42], 95.0), 42);
        assert_eq!(percentile(&[1, 2, 3, 4, 5], 50.0), 3);
        assert_eq!(percentile(&[1, 2, 3, 4, 5], 100.0), 5);
    }

    #[test]
    fn historical_snapshots_bounded_capacity() {
        let mut exporter = SystemMetricsExporter::new(Some(3));

        // Add more snapshots than capacity
        for _ in 0..5 {
            exporter.collect_snapshot();
        }

        assert_eq!(exporter.historical_snapshots.len(), 3);
    }

    #[test]
    fn production_summary_includes_required_fields() {
        let mut exporter = SystemMetricsExporter::new(Some(10));
        exporter.collect_snapshot(); // Need at least one snapshot

        let summary = exporter
            .export_production_summary()
            .expect("should generate summary");

        assert!(summary["revocation_filter_metrics"]["p50"].is_number());
        assert!(summary["revocation_filter_metrics"]["p95"].is_number());
        assert!(summary["revocation_filter_metrics"]["p99"].is_number());
        assert!(summary["revocation_filter_metrics"]["max_observed"].is_number());
        assert!(summary["revocation_filter_metrics"]["cuckoo_cliff_crossings"].is_number());
        assert!(summary["task_reference"] == "bd-98xo5.3.2");
    }
}
