//! Metrics collection tool for T3.2 production N distribution gathering.
//!
//! This tool implements the metrics collection required by bd-98xo5.3.2 to gather
//! production statistics on `franken_node_revocation_filter_entries` over a
//! representative time window.

use crate::observability::system_metrics_exporter::SystemMetricsExporter;
use std::error::Error;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

/// Historical reading of the production revocation-filter entry gauge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationFilterSample {
    pub timestamp_ms: u64,
    pub entries: usize,
}

/// Configuration for metrics collection operation.
#[derive(Debug, Clone)]
pub struct MetricsCollectionConfig {
    /// Output directory for JSON artifacts (default: tests/artifacts/perf/cuckoo_n_distribution/)
    pub output_dir: String,
    /// Minimum window duration in hours before allowing export (default: 168 hours = 7 days)
    pub min_window_hours: f64,
    /// Enable immediate export even with short collection window (for testing)
    pub force_export: bool,
    /// Historical production readings, normally sourced from Prometheus/Grafana.
    pub historical_samples: Vec<RevocationFilterSample>,
}

impl Default for MetricsCollectionConfig {
    fn default() -> Self {
        Self {
            output_dir: "tests/artifacts/perf/cuckoo_n_distribution".to_string(),
            min_window_hours: 168.0, // 7 days
            force_export: false,
            historical_samples: Vec::new(),
        }
    }
}

/// Result of metrics collection operation.
#[derive(Debug)]
pub struct MetricsCollectionResult {
    pub collection_performed: bool,
    pub output_file: Option<String>,
    pub window_duration_hours: f64,
    pub sample_count: usize,
    pub summary: String,
}

/// Run metrics collection and export production summary if sufficient data is available.
///
/// This function implements the T3.2 requirements:
/// - Collects at minimum 7 days of `franken_node_revocation_filter_entries` readings
/// - Calculates p50, p95, p99 of N across the window
/// - Tracks max-observed N and cuckoo cliff crossings (30,000 entries)
/// - Measures max growth rate during highest-activity periods
/// - Exports JSON summary to `tests/artifacts/perf/cuckoo_n_distribution/<date>.json`
///
/// # Returns
/// - `Ok(result)` with collection status and output file path
/// - `Err(error)` if collection or file operations fail
pub fn run_metrics_collection(
    config: MetricsCollectionConfig,
) -> Result<MetricsCollectionResult, Box<dyn Error>> {
    let mut historical_samples = config.historical_samples;
    let mut exporter = SystemMetricsExporter::new(Some(historical_samples.len().max(1)));
    historical_samples.sort_by_key(|sample| sample.timestamp_ms);

    for sample in historical_samples {
        let _ = exporter.record_revocation_filter_snapshot(sample.timestamp_ms, sample.entries);
    }

    if exporter.collection_sample_count() == 0 {
        exporter.collect_snapshot();
    }

    let window_duration_hours = exporter.collection_window_duration_hours();
    let sample_count = exporter.collection_sample_count();

    if !config.force_export && window_duration_hours < config.min_window_hours {
        return Ok(MetricsCollectionResult {
            collection_performed: false,
            output_file: None,
            window_duration_hours,
            sample_count,
            summary: format!(
                "Insufficient collection window: {:.1} hours (need {:.1} hours). \
                Wait for T3.1 production telemetry to accumulate a representative window.",
                window_duration_hours, config.min_window_hours
            ),
        });
    }

    if config.force_export && sample_count < 2 {
        return Ok(MetricsCollectionResult {
            collection_performed: false,
            output_file: None,
            window_duration_hours,
            sample_count,
            summary: "Forced export refused: at least two historical samples are required to compute a real distribution window.".to_string(),
        });
    }

    // Generate production summary
    let summary_json = exporter
        .export_production_summary()
        .ok_or("Failed to generate production summary")?;

    // Create output directory
    fs::create_dir_all(&config.output_dir)?;

    // Generate output filename with current date
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs();

    let date_str = format_timestamp_as_date(timestamp);
    let output_file = format!("{}/{}.json", config.output_dir, date_str);

    // Write JSON summary
    fs::write(&output_file, serde_json::to_string_pretty(&summary_json)?)?;

    let result_summary = format!(
        "✓ Metrics collection complete\n\
        ✓ Window: {:.1} hours ({} samples)\n\
        ✓ Output: {}\n\
        ✓ Ready for T3.2 analysis",
        window_duration_hours, sample_count, output_file,
    );

    Ok(MetricsCollectionResult {
        collection_performed: true,
        output_file: Some(output_file),
        window_duration_hours,
        sample_count,
        summary: result_summary,
    })
}

/// Export current Prometheus metrics for immediate observability stack consumption.
///
/// This function provides the `/metrics` endpoint functionality for Prometheus scraping.
pub fn export_prometheus_metrics() -> Result<String, Box<dyn Error>> {
    let mut exporter = SystemMetricsExporter::new(Some(1440)); // 24 hours of 1-minute samples
    Ok(exporter.export_prometheus()?)
}

/// Format Unix timestamp as ISO date string.
fn format_timestamp_as_date(timestamp_secs: u64) -> String {
    // Simple date formatting - in production would use chrono or similar
    let days_since_epoch = timestamp_secs / (24 * 60 * 60);
    let epoch_date =
        chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("epoch date should be valid");
    let current_date = epoch_date + chrono::Duration::days(days_since_epoch as i64);

    format!("{}", current_date.format("%Y%m%d"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seven_day_samples() -> Vec<RevocationFilterSample> {
        let start = 1_779_638_400_000;
        [
            12_000, 14_200, 18_400, 31_000, 29_500, 34_100, 36_800, 37_200,
        ]
        .into_iter()
        .enumerate()
        .map(|(day, entries)| RevocationFilterSample {
            timestamp_ms: start + (day as u64 * 24 * 60 * 60 * 1000),
            entries,
        })
        .collect()
    }

    #[test]
    fn metrics_collection_respects_minimum_window() {
        let config = MetricsCollectionConfig {
            min_window_hours: 168.0,
            force_export: false,
            ..Default::default()
        };

        let result = run_metrics_collection(config).expect("collection should work");

        // Should not perform collection due to insufficient window
        assert!(!result.collection_performed);
        assert!(result.output_file.is_none());
        assert!(result.summary.contains("Insufficient collection window"));
    }

    #[test]
    fn force_export_without_historical_samples_refuses_summary() {
        let config = MetricsCollectionConfig {
            force_export: true,
            ..Default::default()
        };

        let result = run_metrics_collection(config).expect("forced collection should fail closed");

        assert!(!result.collection_performed);
        assert!(result.output_file.is_none());
        assert_eq!(result.sample_count, 1);
        assert!(result.summary.contains("Forced export refused"));
    }

    #[test]
    fn metrics_collection_works_with_explicit_historical_samples() {
        let config = MetricsCollectionConfig {
            force_export: true,
            output_dir: "/tmp/test_metrics".to_string(),
            historical_samples: seven_day_samples(),
            ..Default::default()
        };

        let result = run_metrics_collection(config).expect("forced collection should work");

        assert!(result.collection_performed);
        assert!(result.output_file.is_some());
        assert!(result.summary.contains("✓ Metrics collection complete"));
        assert!((result.window_duration_hours - 168.0).abs() < f64::EPSILON);
        assert_eq!(result.sample_count, 8);
    }

    #[test]
    fn prometheus_export_contains_required_metrics() {
        let prometheus_output = export_prometheus_metrics().expect("prometheus export should work");

        assert!(prometheus_output.contains("franken_node_revocation_filter_entries"));
        assert!(
            prometheus_output.contains("franken_node_metrics_last_collection_timestamp_seconds")
        );
    }
}
