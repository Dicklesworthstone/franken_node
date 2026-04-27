use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use frankenengine_node::runtime::anti_entropy::TrustRecord;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;

const ROOT_DIGEST_DOMAIN: &[u8] = b"anti_entropy_root_v1:";

fn make_record(index: usize) -> TrustRecord {
    TrustRecord {
        id: format!("record-{index:05}"),
        epoch: 1,
        recorded_at_ms: u64::try_from(index).unwrap_or(u64::MAX),
        origin_node_id: "bench-node".to_string(),
        payload: format!("payload-{index:05}").into_bytes(),
        mmr_pos: u64::try_from(index).unwrap_or(u64::MAX),
        inclusion_proof: None,
        marker_hash: format!("marker-{index:05}"),
    }
}

fn current_insert(records: &[TrustRecord]) -> [u8; 32] {
    let mut state = frankenengine_node::runtime::anti_entropy::TrustState::new(1);
    for record in records {
        let inserted = state.insert(record.clone());
        assert!(inserted, "benchmark records should all insert");
    }
    *state.root_digest()
}

fn batched_digest_once(records: &[TrustRecord]) -> [u8; 32] {
    let mut map = BTreeMap::new();
    for record in records {
        map.insert(record.id.clone(), record.clone());
    }

    let mut hasher = Sha256::new();
    hasher.update(ROOT_DIGEST_DOMAIN);
    for record in map.values() {
        hasher.update(record.digest());
    }
    hasher.finalize().into()
}

fn bench_insert_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("anti_entropy_insert");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(5));

    for size in [256usize, 1024, 2048] {
        let records: Vec<_> = (0..size).map(make_record).collect();

        group.bench_with_input(BenchmarkId::new("current_insert", size), &records, |b, records| {
            b.iter(|| black_box(current_insert(black_box(records))))
        });

        group.bench_with_input(
            BenchmarkId::new("batched_digest_once", size),
            &records,
            |b, records| b.iter(|| black_box(batched_digest_once(black_box(records)))),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_insert_scaling);
criterion_main!(benches);
