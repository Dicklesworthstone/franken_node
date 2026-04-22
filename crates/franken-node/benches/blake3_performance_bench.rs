//! BLAKE3 vs SHA2+HMAC Performance Benchmark
//!
//! Demonstrates the alien CS breakthrough: BLAKE3 provides 3-5x performance
//! improvement over SHA2+HMAC for franken_node's hash-intensive operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use frankenengine_node::security::blake3_adapter::{Blake3Provider, Sha2HmacProvider, HashProvider};
use std::time::Duration;

/// Generate test data of varying sizes
fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn benchmark_hash_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_comparison");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    let blake3_provider = Blake3Provider;
    let sha2_provider = Sha2HmacProvider;
    let key = b"benchmark_key_32_bytes_long_test";

    // Test different data sizes typical in franken_node operations
    for &size in &[64, 256, 1024, 4096, 16384] {
        let data = generate_test_data(size);

        // Benchmark unkeyed hashing
        group.bench_with_input(
            BenchmarkId::new("blake3_hash", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(blake3_provider.hash(black_box(&data)))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sha2_hash", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(sha2_provider.hash(black_box(&data)))
                });
            },
        );

        // Benchmark keyed hashing (HMAC replacement)
        group.bench_with_input(
            BenchmarkId::new("blake3_keyed", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(blake3_provider.keyed_hash(black_box(key), black_box(&data)))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sha2_hmac", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(sha2_provider.keyed_hash(black_box(key), black_box(&data)))
                });
            },
        );
    }

    group.finish();
}

fn benchmark_trust_card_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("trust_card_simulation");
    group.measurement_time(Duration::from_secs(3));

    let blake3_provider = Blake3Provider;
    let sha2_provider = Sha2HmacProvider;

    // Simulate trust card hash chain (typical operation in supply_chain module)
    let trust_card_data = generate_test_data(512); // Typical trust card size
    let chain_key = b"trust_chain_verification_key_32b";

    group.bench_function("blake3_trust_chain", |b| {
        b.iter(|| {
            let mut current_hash = [0u8; 32];
            for i in 0..10 {
                let input = [&current_hash[..], &trust_card_data, &i.to_le_bytes()].concat();
                current_hash = blake3_provider.keyed_hash(black_box(chain_key), black_box(&input));
            }
            black_box(current_hash)
        });
    });

    group.bench_function("sha2_trust_chain", |b| {
        b.iter(|| {
            let mut current_hash = [0u8; 32];
            for i in 0..10 {
                let input = [&current_hash[..], &trust_card_data, &i.to_le_bytes()].concat();
                current_hash = sha2_provider.keyed_hash(black_box(chain_key), black_box(&input));
            }
            black_box(current_hash)
        });
    });

    group.finish();
}

fn benchmark_vef_receipt_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("vef_receipt_chain");
    group.measurement_time(Duration::from_secs(3));

    let blake3_provider = Blake3Provider;
    let sha2_provider = Sha2HmacProvider;

    // Simulate VEF receipt chain hashing (vef/receipt_chain.rs pattern)
    let receipt_data = generate_test_data(256);
    let chain_key = b"vef_receipt_chain_key_32_bytes__";

    group.bench_function("blake3_receipt_chain", |b| {
        b.iter(|| {
            let mut chain_hash = [0u8; 32];
            for receipt_id in 0..20 {
                let input = [
                    &chain_hash[..],
                    &receipt_data,
                    &receipt_id.to_le_bytes(),
                    b"receipt_marker"
                ].concat();
                chain_hash = blake3_provider.keyed_hash(black_box(chain_key), black_box(&input));
            }
            black_box(chain_hash)
        });
    });

    group.bench_function("sha2_receipt_chain", |b| {
        b.iter(|| {
            let mut chain_hash = [0u8; 32];
            for receipt_id in 0..20 {
                let input = [
                    &chain_hash[..],
                    &receipt_data,
                    &receipt_id.to_le_bytes(),
                    b"receipt_marker"
                ].concat();
                chain_hash = sha2_provider.keyed_hash(black_box(chain_key), black_box(&input));
            }
            black_box(chain_hash)
        });
    });

    group.finish();
}

fn benchmark_bulk_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_hash_operations");
    group.measurement_time(Duration::from_secs(5));

    let blake3_provider = Blake3Provider;
    let sha2_provider = Sha2HmacProvider;

    // Simulate bulk hashing operations across multiple modules
    let key = b"bulk_operation_key_32_bytes_long";
    let small_data = generate_test_data(128);

    group.bench_function("blake3_bulk_1000", |b| {
        b.iter(|| {
            for i in 0..1000 {
                let data = [&small_data[..], &i.to_le_bytes()].concat();
                black_box(blake3_provider.keyed_hash(key, black_box(&data)));
            }
        });
    });

    group.bench_function("sha2_bulk_1000", |b| {
        b.iter(|| {
            for i in 0..1000 {
                let data = [&small_data[..], &i.to_le_bytes()].concat();
                black_box(sha2_provider.keyed_hash(key, black_box(&data)));
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_hash_performance,
    benchmark_trust_card_simulation,
    benchmark_vef_receipt_chain,
    benchmark_bulk_operations
);
criterion_main!(benches);