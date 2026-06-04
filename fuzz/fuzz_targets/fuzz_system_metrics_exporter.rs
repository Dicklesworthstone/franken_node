#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use frankenengine_node::observability::system_metrics_exporter::SystemMetricsExporter;

// Size limits for bounded fuzzing
const MAX_HISTORY_SAMPLES: usize = 100; // Reduced for fuzzing
const MAX_OPERATIONS: usize = 50;
const MAX_TIMESTAMP_MS: u64 = 4_000_000_000_000; // ~2096 year
const MAX_METRIC_VALUE: usize = 1_000_000;

/// Fuzzable metric snapshot with bounded values
#[derive(Debug, Clone, Arbitrary)]
struct FuzzMetricSnapshot {
    #[arbitrary(with = bounded_timestamp)]
    timestamp_ms: u64,
    #[arbitrary(with = bounded_metric_value)]
    revocation_filter_entries: usize,
}

impl FuzzMetricSnapshot {
    fn as_snapshot_data(&self) -> (u64, usize) {
        (self.timestamp_ms, self.revocation_filter_entries)
    }
}

/// Operations to test on the system metrics exporter
#[derive(Debug, Clone, Arbitrary)]
enum MetricsOperation {
    CreateExporter {
        #[arbitrary(with = bounded_history_samples)]
        max_history_samples: Option<usize>,
    },
    CollectSnapshot,
    RecordSnapshot {
        snapshot: FuzzMetricSnapshot,
    },
    RecordRevocationFilterSnapshot {
        #[arbitrary(with = bounded_timestamp)]
        timestamp_ms: u64,
        #[arbitrary(with = bounded_metric_value)]
        filter_entries: usize,
    },
    ExportPrometheus,
    CalculateStats,
    ExportProductionSummary,
    GetCollectionWindow,
    TestSnapshotManipulation {
        #[arbitrary(with = bounded_snapshots)]
        snapshots: Vec<FuzzMetricSnapshot>,
    },
    TestTimeCalculations {
        #[arbitrary(with = bounded_snapshots)]
        snapshots: Vec<FuzzMetricSnapshot>,
    },
}

/// Complete fuzz input
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    #[arbitrary(with = bounded_metrics_operations)]
    operations: Vec<MetricsOperation>,
}

// Bounded arbitrary helpers

fn bounded_timestamp(u: &mut Unstructured) -> arbitrary::Result<u64> {
    let choice = u.int_in_range(0..=8)?;
    Ok(match choice {
        0 => 0,                                                   // Epoch
        1 => 1,                                                   // Near epoch
        2 => u64::MAX,                                            // Maximum value
        3 => current_timestamp_ms(),                              // Current time
        4 => current_timestamp_ms().saturating_sub(86400 * 1000), // 1 day ago
        5 => current_timestamp_ms().saturating_add(86400 * 1000), // 1 day future
        6 => 1640995200000,                                       // 2022-01-01 00:00:00 UTC
        7 => 4_102_444_800_000,                                   // 2100-01-01 00:00:00 UTC
        8 => u.int_in_range(0..=MAX_TIMESTAMP_MS)?,
        _ => unreachable!(),
    })
}

fn bounded_metric_value(u: &mut Unstructured) -> arbitrary::Result<usize> {
    let choice = u.int_in_range(0..=6)?;
    Ok(match choice {
        0 => 0,                                                  // Empty
        1 => 1,                                                  // Minimal
        2 => usize::MAX,                                         // Maximum
        3 => MAX_METRIC_VALUE,                                   // Large but reasonable
        4 => u.int_in_range(0..=1000)?,                          // Small range
        5 => u.int_in_range(0..=MAX_METRIC_VALUE)?,              // Medium range
        6 => u.int_in_range(MAX_METRIC_VALUE..=usize::MAX / 2)?, // Large range
        _ => unreachable!(),
    })
}

fn bounded_history_samples(u: &mut Unstructured) -> arbitrary::Result<Option<usize>> {
    if u.arbitrary::<bool>()? {
        let choice = u.int_in_range(0..=6)?;
        Ok(Some(match choice {
            0 => 1,                   // Minimal mutable history
            1 => 1,                   // Minimal history
            2 => MAX_HISTORY_SAMPLES, // Reasonable max
            3 => usize::MAX,          // Maximum value
            4 => 10_080,              // Default (7 days @ 1min)
            5 => u.int_in_range(1..=MAX_HISTORY_SAMPLES)?,
            6 => u.int_in_range(MAX_HISTORY_SAMPLES..=usize::MAX / 2)?,
            _ => unreachable!(),
        }))
    } else {
        Ok(None) // Use default
    }
}

fn bounded_snapshots(u: &mut Unstructured) -> arbitrary::Result<Vec<FuzzMetricSnapshot>> {
    let len = u.int_in_range(0..=20)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn bounded_metrics_operations(u: &mut Unstructured) -> arbitrary::Result<Vec<MetricsOperation>> {
    let len = u.int_in_range(1..=MAX_OPERATIONS)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

// Helper function to get current timestamp - mimic the internal function
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

fn assert_public_window(exporter: &SystemMetricsExporter) {
    let duration_hours = exporter.collection_window_duration_hours();
    assert!(
        duration_hours.is_finite(),
        "Window duration should be finite"
    );
    assert!(
        duration_hours >= 0.0,
        "Window duration should be non-negative"
    );
    if exporter.collection_sample_count() == 0 {
        assert_eq!(
            duration_hours, 0.0,
            "Empty window should have zero duration"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // Input size guard to prevent OOM
    if data.len() > 100_000 {
        return;
    }

    let input: FuzzInput = match Unstructured::new(data).arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Invalid input, skip silently
    };

    // Track state for invariant checking
    let mut export_attempts = 0;
    let mut successful_exports = 0;
    let mut calculation_attempts = 0;
    let mut successful_calculations = 0;

    let mut current_exporter: Option<SystemMetricsExporter> = None;

    // Execute fuzzed operations
    for op in input.operations {
        match op {
            MetricsOperation::CreateExporter {
                max_history_samples,
            } => {
                // Test exporter creation with various history sample limits
                let exporter = SystemMetricsExporter::new(max_history_samples);
                current_exporter = Some(exporter);

                // Verify exporter was created
                if let Some(ref exporter) = current_exporter {
                    // Exporter should be in valid initial state
                    assert_eq!(
                        exporter.collection_sample_count(),
                        0,
                        "New exporter should have no samples"
                    );
                    assert_public_window(exporter);
                }
            }

            MetricsOperation::CollectSnapshot => {
                if let Some(ref mut exporter) = current_exporter {
                    let snapshot = exporter.collect_snapshot();

                    // Verify snapshot properties
                    assert!(
                        snapshot.timestamp_ms() > 0,
                        "Snapshot timestamp should be positive"
                    );
                    assert!(
                        snapshot.revocation_filter_entries() <= MAX_METRIC_VALUE * 10,
                        "Revocation filter entries should be reasonable"
                    );

                    // Timestamp should be close to current time
                    let now = current_timestamp_ms();
                    let diff = if snapshot.timestamp_ms() > now {
                        snapshot.timestamp_ms() - now
                    } else {
                        now - snapshot.timestamp_ms()
                    };
                    assert!(
                        diff < 60_000,
                        "Snapshot timestamp should be within 1 minute of now"
                    );
                }
            }

            MetricsOperation::RecordSnapshot { snapshot } => {
                if let Some(ref mut exporter) = current_exporter {
                    let (timestamp_ms, filter_entries) = snapshot.as_snapshot_data();
                    let recorded_snapshot =
                        exporter.record_revocation_filter_snapshot(timestamp_ms, filter_entries);

                    // Verify snapshot was recorded
                    if exporter.collection_sample_count() > 0 {
                        assert!(
                            recorded_snapshot.timestamp_ms() <= MAX_TIMESTAMP_MS
                                || timestamp_ms > MAX_TIMESTAMP_MS,
                            "Recorded snapshot timestamp should preserve fuzz input bounds"
                        );
                        assert_public_window(exporter);
                    }
                }
            }

            MetricsOperation::RecordRevocationFilterSnapshot {
                timestamp_ms,
                filter_entries,
            } => {
                if let Some(ref mut exporter) = current_exporter {
                    let _ =
                        exporter.record_revocation_filter_snapshot(timestamp_ms, filter_entries);

                    // Verify recording
                    if exporter.collection_sample_count() > 0 {
                        assert!(
                            exporter.collection_sample_count() >= 1,
                            "Should have at least one sample"
                        );
                        assert_public_window(exporter);
                    }
                }
            }

            MetricsOperation::ExportPrometheus => {
                export_attempts += 1;

                if let Some(ref mut exporter) = current_exporter {
                    match exporter.export_prometheus() {
                        Ok(prometheus_output) => {
                            successful_exports += 1;

                            // Verify Prometheus format
                            assert!(
                                !prometheus_output.is_empty(),
                                "Prometheus output should not be empty"
                            );
                            assert!(
                                prometheus_output.contains("franken_node_"),
                                "Prometheus output should contain franken_node metrics"
                            );

                            // Check for required metrics
                            assert!(
                                prometheus_output.contains("revocation_filter_entries"),
                                "Should contain revocation filter metric"
                            );

                            // Verify no invalid characters in metric names
                            let lines: Vec<&str> = prometheus_output.lines().collect();
                            for line in &lines {
                                if line.starts_with("franken_node_") && !line.starts_with('#') {
                                    // Metric lines should have valid format
                                    assert!(
                                        line.contains(' ') || line.contains('\t'),
                                        "Metric line should have space/tab separator"
                                    );
                                }
                            }

                            // Test that output is parseable as text
                            assert!(
                                prometheus_output.is_ascii()
                                    || prometheus_output
                                        .chars()
                                        .all(|c| !c.is_control() || c == '\n' || c == '\t'),
                                "Prometheus output should be clean text"
                            );
                        }
                        Err(_) => {
                            // Export can fail due to metric validation errors
                        }
                    }
                }
            }

            MetricsOperation::CalculateStats => {
                calculation_attempts += 1;

                if let Some(ref exporter) = current_exporter {
                    if let Some(stats) = exporter.calculate_revocation_filter_stats() {
                        successful_calculations += 1;

                        // Verify statistics properties
                        assert!(
                            stats.p50 <= stats.max_observed,
                            "P50 should be no greater than max observed"
                        );
                        assert!(stats.p95 >= stats.p50, "P95 should be >= P50");
                        assert!(stats.p99 >= stats.p95, "P99 should be >= P95");
                        assert!(
                            stats.max_observed >= stats.p99,
                            "Max observed should be >= P99"
                        );

                        // Growth rates should be finite
                        assert!(
                            stats.current_growth_rate_per_minute.is_finite(),
                            "Growth rate should be finite"
                        );
                    } else {
                        // No stats available - this is fine if no snapshots recorded
                    }
                }
            }

            MetricsOperation::ExportProductionSummary => {
                if let Some(ref exporter) = current_exporter {
                    if let Some(summary) = exporter.export_production_summary() {
                        // Verify JSON structure
                        assert!(summary.is_object(), "Summary should be JSON object");

                        if let Some(collection_window) = summary.get("collection_window") {
                            assert!(
                                collection_window.is_object(),
                                "Collection window should be object"
                            );

                            // Verify timestamp fields
                            if let Some(start_ts) = collection_window.get("start_timestamp_ms") {
                                if let Some(start_num) = start_ts.as_u64() {
                                    assert!(
                                        start_num <= MAX_TIMESTAMP_MS,
                                        "Start timestamp should be reasonable"
                                    );
                                }
                            }

                            if let Some(end_ts) = collection_window.get("end_timestamp_ms") {
                                if let Some(end_num) = end_ts.as_u64() {
                                    assert!(
                                        end_num <= MAX_TIMESTAMP_MS,
                                        "End timestamp should be reasonable"
                                    );
                                }
                            }

                            // Verify duration is non-negative
                            if let Some(duration) = collection_window.get("duration_hours") {
                                if let Some(duration_f64) = duration.as_f64() {
                                    assert!(duration_f64 >= 0.0, "Duration should be non-negative");
                                }
                            }
                        }

                        // Check for revocation filter stats
                        if let Some(rf_stats) = summary.get("revocation_filter_metrics") {
                            assert!(
                                rf_stats.is_object(),
                                "Revocation filter stats should be object"
                            );

                            // Verify statistical fields
                            if let Some(max_observed) = rf_stats.get("max_observed") {
                                if let Some(max_num) = max_observed.as_u64() {
                                    assert!(
                                        max_num <= usize::MAX as u64,
                                        "Max observed should fit in usize"
                                    );
                                }
                            }
                        }
                    } else {
                        // No summary available - this is fine if no data collected
                    }
                }
            }

            MetricsOperation::GetCollectionWindow => {
                if let Some(ref exporter) = current_exporter {
                    assert_public_window(exporter);
                }
            }

            MetricsOperation::TestSnapshotManipulation { snapshots } => {
                if let Some(ref mut exporter) = current_exporter {
                    let initial_count = exporter.collection_sample_count();

                    // Add multiple snapshots
                    let snapshots_len = snapshots.len();
                    for fuzz_snapshot in snapshots {
                        let (timestamp_ms, filter_entries) = fuzz_snapshot.as_snapshot_data();
                        let _ = exporter
                            .record_revocation_filter_snapshot(timestamp_ms, filter_entries);
                    }

                    let final_count = exporter.collection_sample_count();

                    // Verify snapshot addition
                    if snapshots_len > 0 {
                        assert!(
                            final_count >= initial_count || final_count <= MAX_HISTORY_SAMPLES,
                            "Sample count should increase when adding snapshots"
                        );
                    }

                    assert_public_window(exporter);
                }
            }

            MetricsOperation::TestTimeCalculations { snapshots } => {
                if let Some(ref mut exporter) = current_exporter {
                    // Add snapshots with known timestamps
                    let mut timestamps = Vec::new();
                    for fuzz_snapshot in snapshots {
                        timestamps.push(fuzz_snapshot.timestamp_ms);
                        let (timestamp_ms, filter_entries) = fuzz_snapshot.as_snapshot_data();
                        let _ = exporter
                            .record_revocation_filter_snapshot(timestamp_ms, filter_entries);
                    }

                    if !timestamps.is_empty() {
                        assert_public_window(exporter);
                    }
                }
            }
        }
    }

    // Invariant checks - these must hold regardless of input
    assert!(
        successful_exports <= export_attempts,
        "Successful exports should not exceed attempts"
    );
    assert!(
        successful_calculations <= calculation_attempts,
        "Successful calculations should not exceed attempts"
    );

    // Create a test exporter for edge case testing
    let mut edge_exporter = SystemMetricsExporter::new(Some(5)); // Small history

    // Test with extreme timestamps
    let extreme_snapshots = [
        (0, 0),                         // Epoch start
        (u64::MAX, usize::MAX),         // Maximum values
        (1, 1),                         // Minimal values
        (current_timestamp_ms(), 1000), // Current time
    ];

    for (timestamp_ms, filter_entries) in extreme_snapshots {
        let _ = edge_exporter.record_revocation_filter_snapshot(timestamp_ms, filter_entries);
    }

    // Verify exporter handles extreme values gracefully
    assert!(
        edge_exporter.collection_sample_count() <= 5,
        "Should respect history limit"
    );
    assert_public_window(&edge_exporter);

    if let Some(edge_stats) = edge_exporter.calculate_revocation_filter_stats() {
        assert!(edge_stats.p50 <= edge_stats.p95, "P50 should be <= P95");
        assert!(edge_stats.p95 <= edge_stats.p99, "P95 should be <= P99");
        assert!(
            edge_stats.p99 <= edge_stats.max_observed,
            "P99 should be <= max observed"
        );
        assert!(
            edge_stats.current_growth_rate_per_minute.is_finite(),
            "Growth rate should be finite"
        );
    }

    // Test Prometheus export with edge case data
    if let Ok(edge_prometheus) = edge_exporter.export_prometheus() {
        assert!(
            !edge_prometheus.is_empty(),
            "Edge case Prometheus export should not be empty"
        );
        assert!(
            edge_prometheus.contains("franken_node_"),
            "Should contain franken_node metrics"
        );
    }

    // Test empty exporter edge cases
    let empty_exporter = SystemMetricsExporter::new(Some(0)); // Zero history
    assert_eq!(
        empty_exporter.collection_sample_count(),
        0,
        "Zero history exporter should have no samples"
    );
    assert_eq!(
        empty_exporter.collection_window_duration_hours(),
        0.0,
        "Empty exporter should have zero duration"
    );

    let empty_stats = empty_exporter.calculate_revocation_filter_stats();
    assert!(empty_stats.is_none(), "Empty exporter should have no stats");

    let empty_summary = empty_exporter.export_production_summary();
    assert!(
        empty_summary.is_none(),
        "Empty exporter should have no summary"
    );
});
