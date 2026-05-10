//! Criterion benchmarks demonstrating performance wins from allocation elimination commits.
//!
//! Each benchmark exercises hot paths optimized by specific PERF commits to:
//! 1. Quantify the performance improvements (claim → measurement)
//! 2. Catch future regressions that re-introduce allocations
//!
//! Commits benchmarked:
//! - b238c0ee: SignaturePreimage zero-alloc feed_into_hasher
//! - dfd95547: transparency verify_inclusion hex alloc elimination
//! - 985c38af: TaskId newtype eliminates per-assignment String alloc
//! - 33b5cc4c: frankensqlite String key allocation elimination
//! - 752cbf6a: trace digest hex encoding defer to boundary

use criterion::{Criterion, black_box, criterion_group, criterion_main};

/// Benchmark SignaturePreimage hash throughput (b238c0ee win)
fn signature_preimage_hash_throughput(c: &mut Criterion) {
    use frankenengine_node::connector::canonical_serializer::SignaturePreimage;

    let preimage = SignaturePreimage::build(
        1,
        [0xDE, 0xAD],
        b"representative_payload_for_signature_preimage_benchmark_testing"
            .repeat(10)
            .to_vec(),
    );

    c.bench_function("signature_preimage_hash_throughput", |b| {
        b.iter(|| black_box(preimage.content_hash_prefix()))
    });
}

/// Benchmark transparency verify_inclusion with a deep audit path (dfd95547 win)
fn transparency_verify_inclusion_path64(c: &mut Criterion) {
    use frankenengine_node::supply_chain::transparency_verifier::{
        InclusionProof, LogRoot, TransparencyPolicy, recompute_root, verify_inclusion,
    };

    let proof = InclusionProof {
        leaf_index: 12345,
        tree_size: u64::MAX,
        leaf_hash: "a".repeat(64),
        audit_path: (0..64).map(|i| format!("{:064x}", i)).collect(),
    };
    let root_hash = recompute_root(&proof);
    let policy = TransparencyPolicy {
        required: true,
        pinned_roots: vec![LogRoot {
            tree_size: proof.tree_size,
            root_hash,
        }],
    };

    c.bench_function("transparency_verify_inclusion_path64", |b| {
        b.iter(|| {
            black_box(
                verify_inclusion(
                    &policy,
                    Some(&proof),
                    &proof.leaf_hash,
                    "bench-connector",
                    "bench-artifact",
                    "bench-trace",
                    "bench-timestamp",
                )
                .verified,
            )
        })
    });
}

/// Benchmark lane scheduler task assignment throughput (985c38af TaskId win)
fn lane_scheduler_assign_throughput(c: &mut Criterion) {
    use frankenengine_node::runtime::lane_scheduler::{
        LaneConfig, LaneMappingPolicy, LaneScheduler, SchedulerLane, TaskClass,
    };

    let mut policy = LaneMappingPolicy::new();
    for lane in [
        LaneConfig::new(SchedulerLane::ControlCritical, 100, 10000),
        LaneConfig::new(SchedulerLane::RemoteEffect, 80, 5000),
        LaneConfig::new(SchedulerLane::Maintenance, 60, 2000),
        LaneConfig::new(SchedulerLane::Background, 40, 1000),
    ] {
        assert!(
            policy.add_lane(lane).is_ok(),
            "benchmark lane config should be valid"
        );
    }

    policy.add_rule(
        &TaskClass::new("control.epoch"),
        SchedulerLane::ControlCritical,
    );
    policy.add_rule(
        &TaskClass::new("remote.compute"),
        SchedulerLane::RemoteEffect,
    );
    policy.add_rule(
        &TaskClass::new("maintenance.gc"),
        SchedulerLane::Maintenance,
    );
    policy.add_rule(
        &TaskClass::new("background.telemetry"),
        SchedulerLane::Background,
    );

    c.bench_function("lane_scheduler_assign_throughput", |b| {
        b.iter(|| {
            let mut scheduler = LaneScheduler::new(policy.clone()).unwrap();
            let task_class = TaskClass::new("control.epoch");

            // Assign 1000 tasks (scaled down from 10K for benchmark speed)
            for i in 0..1000 {
                let _ = black_box(scheduler.assign_task(&task_class, i, "bench-trace"));
            }
        })
    });
}

/// Benchmark frankensqlite read/write throughput (33b5cc4c win)
fn frankensqlite_read_throughput(c: &mut Criterion) {
    use frankenengine_node::storage::frankensqlite_adapter::{
        CallerContext, FrankensqliteAdapter, PersistenceClass,
    };

    let caller = CallerContext::system("storage::perf_wins", "bench-trace");

    c.bench_function("frankensqlite_read_throughput", |b| {
        b.iter(|| {
            let mut adapter = FrankensqliteAdapter::default();

            // 1000 read/write cycles (scaled down from 10K for benchmark speed)
            for i in 0..1000 {
                let key = format!("benchmark.key.{}", i);
                let value = format!("benchmark_value_{}", i).into_bytes();

                let _ =
                    black_box(adapter.write(&caller, PersistenceClass::ControlState, &key, &value));
                let _ = black_box(adapter.read(&caller, PersistenceClass::ControlState, &key));
            }
        })
    });
}

/// Benchmark trace digest computation throughput (752cbf6a win)
fn trace_digest_throughput(c: &mut Criterion) {
    use frankenengine_node::replay::time_travel_engine::{
        EnvironmentSnapshot, TraceStep, WorkflowTrace,
    };
    use std::collections::BTreeMap;

    let environment =
        EnvironmentSnapshot::new(1_000_000, BTreeMap::new(), "linux-x86_64", "bench-runtime");

    let steps: Vec<TraceStep> = (0..100)
        .map(|i| TraceStep {
            seq: i,
            timestamp_ns: 1000000 + i,
            input: format!("input_data_{}", i).into_bytes(),
            output: format!("output_result_{}", i).into_bytes(),
            side_effects: vec![],
        })
        .collect();

    c.bench_function("trace_digest_throughput", |b| {
        b.iter(|| {
            black_box(WorkflowTrace::compute_digest(
                "benchmark-trace",
                "benchmark-workflow",
                &steps,
                &environment,
                "v1",
            ))
        })
    });
}

criterion_group!(
    perf_wins,
    signature_preimage_hash_throughput,
    transparency_verify_inclusion_path64,
    lane_scheduler_assign_throughput,
    frankensqlite_read_throughput,
    trace_digest_throughput
);
criterion_main!(perf_wins);
