//! Benchmark for replay bundle gzip serialization optimization.
//!
//! Profiles the hotspot in `gzip_size_bytes()` function to measure:
//! - Allocation overhead from creating new GzEncoder per call
//! - Vec allocation overhead for compression output buffer
//! - Compression speed on realistic replay bundle data

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundleError, TimelineEvent, canonical_json_len,
    generate_replay_bundle,
};
use serde_json::{Map, Value};

// The `streaming_counter` benchmark variant invokes the production
// `canonical_json_len` (which delegates through the production `ByteCounter`
// in `tools::replay_bundle`); the `vec_len` variant retains the
// `serde_json::to_vec(value)?.len()` shape as the regression target. Bench
// numbers therefore reflect what production code actually does, not a
// divergent local reimplementation.
fn canonical_json_len_streaming(value: &Value) -> Result<usize, ReplayBundleError> {
    canonical_json_len(value)
}

fn canonical_json_len_via_vec(value: &Value) -> Result<usize, serde_json::Error> {
    Ok(serde_json::to_vec(value)?.len())
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));

            let mut canonical = Map::with_capacity(entries.len());
            for (key, nested) in entries {
                canonical.insert(key, canonicalize_value(nested));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn generate_realistic_events(event_count: usize) -> Vec<RawEvent> {
    (0..event_count)
        .map(|i| {
            RawEvent::new(
                format!(
                    "2026-04-22T{:02}:{:02}:{:02}Z",
                    (i / 3600) % 24,
                    (i / 60) % 60,
                    i % 60
                ),
                EventType::ExternalSignal,
                serde_json::json!({
                    "scan_id": format!("scan-{:08x}", i * 0x1234),
                    "findings": (0..i % 10).map(|j| format!("finding-{}", j)).collect::<Vec<_>>(),
                    "metadata": {
                        "scanner_version": "2.1.0",
                        "scan_duration_ms": 1500 + (i % 1000),
                        "files_scanned": 100 + (i % 50),
                    }
                }),
            )
        })
        .collect()
}

fn generate_timeline_event_values(event_count: usize) -> Vec<Value> {
    (0..event_count)
        .map(|i| {
            let event = TimelineEvent {
                sequence_number: u64::try_from(i.saturating_add(1)).unwrap_or(u64::MAX),
                timestamp: format!(
                    "2026-04-22T{:02}:{:02}:{:02}.000000Z",
                    (i / 3600) % 24,
                    (i / 60) % 60,
                    i % 60
                ),
                event_type: EventType::ExternalSignal,
                payload: serde_json::json!({
                    "scan_id": format!("scan-{:08x}", i * 0x1234),
                    "findings": (0..i % 10).map(|j| format!("finding-{}", j)).collect::<Vec<_>>(),
                    "metadata": {
                        "scanner_version": "2.1.0",
                        "scan_duration_ms": 1500 + (i % 1000),
                        "files_scanned": 100 + (i % 50),
                    }
                }),
                causal_parent: if i > 0 {
                    Some(u64::try_from(i).unwrap_or(u64::MAX))
                } else {
                    None
                },
            };
            canonicalize_value(
                serde_json::to_value(event).expect("timeline event should serialize"),
            )
        })
        .collect()
}

/// Generate realistic replay bundle data for benchmarking
fn generate_realistic_bundle_data(event_count: usize) -> Vec<u8> {
    let events = generate_realistic_events(event_count);

    let bundle = generate_replay_bundle("benchmark-incident", &events)
        .expect("bundle generation should succeed");

    serde_json::to_vec(&bundle).expect("JSON serialization should succeed")
}

/// Current implementation baseline - creates new GzEncoder per call
#[cfg(feature = "compression")]
fn gzip_size_bytes_current(bytes: &[u8]) -> Result<u64, std::io::Error> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    let compressed = encoder.finish()?;
    Ok(u64::try_from(compressed.len()).unwrap_or(u64::MAX))
}

/// Optimized implementation with pre-allocated buffer reuse
#[cfg(feature = "compression")]
fn gzip_size_bytes_optimized(
    bytes: &[u8],
    reusable_buffer: &mut Vec<u8>,
) -> Result<u64, std::io::Error> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    reusable_buffer.clear();
    let mut encoder = GzEncoder::new(reusable_buffer, Compression::default());
    encoder.write_all(bytes)?;
    let compressed = encoder.finish()?;
    Ok(u64::try_from(compressed.len()).unwrap_or(u64::MAX))
}

fn bench_event_size_measurement(c: &mut Criterion) {
    let small_events = generate_timeline_event_values(10);
    let medium_events = generate_timeline_event_values(100);
    let large_events = generate_timeline_event_values(1000);

    let test_cases = [
        ("small_10_events", small_events),
        ("medium_100_events", medium_events),
        ("large_1000_events", large_events),
    ];

    let mut group = c.benchmark_group("replay_bundle_event_size");

    for (name, events) in &test_cases {
        group.bench_with_input(BenchmarkId::new("vec_len", name), events, |b, events| {
            b.iter(|| {
                let total = events.iter().try_fold(0usize, |acc, event| {
                    canonical_json_len_via_vec(black_box(event)).map(|len| acc.saturating_add(len))
                });
                black_box(total.expect("event length measurement should succeed"))
            })
        });

        group.bench_with_input(
            BenchmarkId::new("streaming_counter", name),
            events,
            |b, events| {
                b.iter(|| {
                    let total = events.iter().try_fold(0usize, |acc, event| {
                        canonical_json_len_streaming(black_box(event))
                            .map(|len| acc.saturating_add(len))
                    });
                    black_box(total.expect("event length measurement should succeed"))
                })
            },
        );
    }

    group.finish();
}

fn bench_bundle_generation(c: &mut Criterion) {
    let small_events = generate_realistic_events(10);
    let medium_events = generate_realistic_events(100);
    let large_events = generate_realistic_events(1000);

    let test_cases = [
        ("small_10_events", small_events),
        ("medium_100_events", medium_events),
        ("large_1000_events", large_events),
    ];

    let mut group = c.benchmark_group("replay_bundle_generation");

    for (name, events) in &test_cases {
        group.bench_with_input(BenchmarkId::new("generate", name), events, |b, events| {
            b.iter(|| {
                black_box(
                    generate_replay_bundle("benchmark-incident", black_box(events))
                        .expect("bundle generation should succeed"),
                )
            })
        });
    }

    group.finish();
}

fn bench_gzip_compression(c: &mut Criterion) {
    // Generate test data of various sizes
    let small_data = generate_realistic_bundle_data(10);
    let medium_data = generate_realistic_bundle_data(100);
    let large_data = generate_realistic_bundle_data(1000);

    let test_cases = vec![
        ("small_10_events", small_data),
        ("medium_100_events", medium_data),
        ("large_1000_events", large_data),
    ];

    let mut group = c.benchmark_group("replay_bundle_gzip");

    #[cfg(feature = "compression")]
    {
        for (name, data) in &test_cases {
            // Baseline: current implementation
            group.bench_with_input(BenchmarkId::new("current", name), data, |b, data| {
                b.iter(|| black_box(gzip_size_bytes_current(black_box(data))))
            });

            // Optimized: reused buffer
            group.bench_with_input(
                BenchmarkId::new("optimized_reuse_buffer", name),
                data,
                |b, data| {
                    let mut reusable_buffer = Vec::new();
                    b.iter(|| {
                        black_box(gzip_size_bytes_optimized(
                            black_box(data),
                            &mut reusable_buffer,
                        ))
                    })
                },
            );
        }
    }

    #[cfg(not(feature = "compression"))]
    {
        // Fallback when compression feature is disabled
        for (name, data) in &test_cases {
            group.bench_with_input(
                BenchmarkId::new("no_compression_fallback", name),
                data,
                |b, data| b.iter(|| black_box(u64::try_from(data.len()).unwrap_or(u64::MAX))),
            );
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_event_size_measurement,
    bench_bundle_generation,
    bench_gzip_compression
);
criterion_main!(benches);
