use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use frankenengine_node::observability::evidence_ledger::{
    DecisionKind, EvidenceEntry, EvidenceLedger, LedgerCapacity,
};
use serde_json::json;

const BENCH_LEDGER_MAX_BYTES: usize = 16 * 1024 * 1024;
const BENCH_SIGNATURE_HEX: &str = concat!(
    "9f0c4b2a6d8e1f3071425364758697a8",
    "a81726354433221100ffeeddccbbaa99",
    "5a6b7c8d9e0f1029384756aabbccdde0",
    "102132435465768798a9bacbdcedfe0f",
);

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
        signature: BENCH_SIGNATURE_HEX.to_string(),
        prev_entry_hash: String::new(),
    }
}

fn benchmark_entry_with_server_computed_size(c: &mut Criterion) {
    let capacity = LedgerCapacity::new(256, BENCH_LEDGER_MAX_BYTES);

    c.bench_function("entry_with_server_computed_size", |b| {
        b.iter_batched(
            || {
                (
                    EvidenceLedger::new(capacity.clone()),
                    create_large_evidence_entry(),
                )
            },
            |(mut ledger, entry)| {
                if let Ok(entry_id) = ledger.append(black_box(entry)) {
                    black_box((entry_id, ledger.current_bytes()));
                }
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark_entry_with_server_computed_size);
criterion_main!(benches);
