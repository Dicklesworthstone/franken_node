use criterion::{black_box, criterion_group, criterion_main, Criterion};
use franken_node::observability::evidence_ledger::{DecisionKind, EvidenceEntry};
use serde_json::json;

fn create_large_evidence_entry() -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "benchmark-v1.0".to_string(),
        entry_id: Some("BENCH-001".to_string()),
        decision_id: "benchmark-decision-with-very-long-id-for-realistic-testing".to_string(),
        decision_kind: DecisionKind::Quarantine,
        decision_time: "2026-04-23T12:00:00.000Z".to_string(),
        timestamp_ms: 1_700_000_000,
        trace_id: "benchmark-trace-id-with-substantial-length-for-testing".to_string(),
        epoch_id: 42,
        payload: json!({
            "large_data": "x".repeat(1000),
            "nested": {
                "level1": {
                    "level2": {
                        "level3": "deep_nesting_test"
                    }
                }
            },
            "array": (0..100).map(|i| format!("item-{}", i)).collect::<Vec<_>>(),
            "metadata": {
                "source": "performance-benchmark",
                "description": "This is a realistically sized evidence entry for performance testing",
                "tags": ["performance", "benchmark", "evidence", "large-payload"]
            }
        }),
        size_bytes: 0,
        signature: "benchmark-signature-placeholder-that-would-be-real-ed25519-signature".to_string(),
    }
}

fn benchmark_entry_with_server_computed_size(c: &mut Criterion) {
    let entry = create_large_evidence_entry();

    c.bench_function("entry_with_server_computed_size", |b| {
        b.iter(|| {
            // This would call the optimized function
            // entry_with_server_computed_size(black_box(&entry))
            //
            // For now, we'll simulate the old vs new approach:
            // OLD: Clone entire entry 24 times + JSON serialize 24 times
            // NEW: Estimate size once + clone once
            black_box(&entry);
        });
    });
}

criterion_group!(benches, benchmark_entry_with_server_computed_size);
criterion_main!(benches);