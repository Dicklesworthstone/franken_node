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

use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Benchmark SignaturePreimage hash throughput (b238c0ee win)
fn signature_preimage_hash_throughput(c: &mut Criterion) {
    use frankenengine_node::connector::canonical_serializer::SignaturePreimage;

    let preimage = SignaturePreimage::build(
        1,
        [0xDE, 0xAD],
        b"representative_payload_for_signature_preimage_benchmark_testing".repeat(10).to_vec()
    );

    c.bench_function("signature_preimage_hash_throughput", |b| {
        b.iter(|| {
            black_box(preimage.content_hash_prefix())
        })
    });
}

/// Benchmark transparency verify_inclusion with 256-step audit path (dfd95547 win)
fn transparency_verify_inclusion_path256(c: &mut Criterion) {
    use frankenengine_node::supply_chain::transparency_verifier::{verify_inclusion, InclusionProof};

    // Create a representative inclusion proof with substantial audit path
    let proof = InclusionProof {
        leaf_index: 12345,
        leaf_hash: "a".repeat(64),
        root_hash: "b".repeat(64),
        audit_path: (0..256).map(|i| format!("{:064x}", i)).collect(),
    };

    c.bench_function("transparency_verify_inclusion_path256", |b| {
        b.iter(|| {
            black_box(verify_inclusion(&proof).is_ok())
        })
    });
}

/// Benchmark lane scheduler task assignment throughput (985c38af TaskId win)
fn lane_scheduler_assign_throughput(c: &mut Criterion) {
    use frankenengine_node::runtime::lane_scheduler::{LaneScheduler, LaneMappingPolicy, LaneConfig, SchedulerLane, TaskClass};

    let mut policy = LaneMappingPolicy::new();
    policy.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 10000));
    policy.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 80, 5000));
    policy.add_lane(LaneConfig::new(SchedulerLane::Maintenance, 60, 2000));
    policy.add_lane(LaneConfig::new(SchedulerLane::Background, 40, 1000));

    policy.add_rule(&TaskClass::new("control.epoch"), SchedulerLane::ControlCritical);
    policy.add_rule(&TaskClass::new("remote.compute"), SchedulerLane::RemoteEffect);
    policy.add_rule(&TaskClass::new("maintenance.gc"), SchedulerLane::Maintenance);
    policy.add_rule(&TaskClass::new("background.telemetry"), SchedulerLane::Background);

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
    use frankenengine_node::storage::frankensqlite_adapter::{FrankensqliteAdapter, CallerContext, PersistenceClass};

    let caller = CallerContext::new_system();

    c.bench_function("frankensqlite_read_throughput", |b| {
        b.iter(|| {
            let mut adapter = FrankensqliteAdapter::default();

            // 1000 read/write cycles (scaled down from 10K for benchmark speed)
            for i in 0..1000 {
                let key = format!("benchmark.key.{}", i);
                let value = format!("benchmark_value_{}", i).into_bytes();

                let _ = black_box(adapter.write(&caller, PersistenceClass::ControlState, &key, &value));
                let _ = black_box(adapter.read(&caller, PersistenceClass::ControlState, &key));
            }
        })
    });
}

/// Benchmark trace digest computation throughput (752cbf6a win)
fn trace_digest_throughput(c: &mut Criterion) {
    use frankenengine_node::replay::time_travel_engine::{EnvironmentSnapshot, TraceStep, WorkflowTrace};

    let environment = EnvironmentSnapshot {
        franken_node_version: "1.0.0".to_string(),
        rust_version: "1.70.0".to_string(),
        os_info: "linux".to_string(),
        cpu_info: "x64".to_string(),
        memory_mb: 8192,
        environment_variables: vec![],
    };

    let steps: Vec<TraceStep> = (0..100).map(|i| TraceStep {
        seq: i,
        timestamp_ns: 1000000 + i,
        input: format!("input_data_{}", i).into_bytes(),
        output: format!("output_result_{}", i).into_bytes(),
        side_effects: vec![],
    }).collect();

    c.bench_function("trace_digest_throughput", |b| {
        b.iter(|| {
            black_box(WorkflowTrace::compute_digest(
                "benchmark-trace",
                "benchmark-workflow",
                &steps,
                &environment,
                "v1"
            ))
        })
    });
}

criterion_group!(
    perf_wins,
    signature_preimage_hash_throughput,
    transparency_verify_inclusion_path256,
    lane_scheduler_assign_throughput,
    frankensqlite_read_throughput,
    trace_digest_throughput
);
criterion_main!(perf_wins);