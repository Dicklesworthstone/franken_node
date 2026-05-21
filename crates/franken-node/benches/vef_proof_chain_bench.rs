//! Criterion benchmarks for vef::proof_generator + vef::receipt_chain.
//!
//! bd-98xo5.8.1 — perf round-3 instrumentation. The two hot paths covered:
//!
//!   1. `TestProofBackend::generate(&ProofRequest)` — drives the private
//!      `compute_proof_bytes(&[ReceiptChainEntry])` SHA-256 walk. The
//!      function hashes `b"proof_generator_hash_v1:" || b"proof-backend-v1:" ||
//!      LE64(entries.len) || (LE64(chain_hash.len) || chain_hash.bytes) for
//!      each entry`. Bench scales as O(N · avg-chain-hash-len).
//!
//!   2. `ReceiptChain::verify_integrity()` — walks the chain re-deriving
//!      each entry's `chain_hash = H(prev_chain_hash || receipt_hash)` and
//!      asserting it matches. Bench scales as O(N · sha256-of-pair).
//!
//! Per the bead's spec: the fixture builder constructs realistic
//! ExecutionReceipt payloads and lets `ReceiptChain::append` compute the
//! authentic per-entry `chain_hash` (NOT random 64-char hex — that would
//! break verify_integrity in the second bench). Bench is registered under
//! `[[bench]]` in `crates/franken-node/Cargo.toml` with `harness = false`.
//!
//! Predicted order-of-magnitude (from the bead body — sanity check after
//! first run):
//!   - generate/N=16:   O(10 µs)   — sha256 update of 16 small inputs
//!   - generate/N=4096: O(1 ms)    — sha256 + 4k loop iterations
//!   - verify/N=16:     O(50 µs)   — sha256 of (prev_hash || receipt_hash)
//!                                   for each of 16 entries
//!   - verify/N=4096:   O(10 ms)
//!
//! If reality differs from the prediction by 5×+ in either direction,
//! there's a hidden hot path worth investigating.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionActionType, ExecutionReceipt,
};
use frankenengine_node::vef::proof_generator::{
    ProofBackend, ProofRequest, TestProofBackend,
};
use frankenengine_node::vef::proof_scheduler::{ProofWindow, WorkloadTier};
use frankenengine_node::vef::receipt_chain::{ReceiptChain, ReceiptChainConfig};

const BENCH_SEED_SCHEMA: &str = "franken-node/execution-receipt/v1";
const BENCH_POLICY_HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Build a deterministic `ExecutionReceipt` for the bench's fixed-seed
/// fixture. The chain machinery (`ReceiptChain::append`) computes the
/// authentic per-entry `chain_hash` from this — DO NOT replace with
/// random hex; verify_integrity in the second bench depends on the chain
/// links being mathematically correct.
fn fixture_receipt(seq: u64) -> ExecutionReceipt {
    let mut capability_context = BTreeMap::new();
    capability_context.insert("scope".to_string(), "telemetry-export".to_string());
    capability_context.insert("region".to_string(), "us-east-1".to_string());
    ExecutionReceipt {
        schema_version: BENCH_SEED_SCHEMA.to_string(),
        action_type: ExecutionActionType::NetworkAccess,
        capability_context,
        actor_identity: format!("agent:bench-vef-proof-chain:{seq}"),
        artifact_identity: format!("artifact:vef-bench-fixture:{seq}"),
        policy_snapshot_hash: BENCH_POLICY_HASH.to_string(),
        timestamp_millis: 1_700_000_000_000_u64.saturating_add(seq.saturating_mul(1_000)),
        sequence_number: seq,
        witness_references: vec![format!("evidence:bench-vef:{seq}")],
        trace_id: format!("trace-vef-bench-{seq}"),
    }
}

/// Build a `ReceiptChain` of `n_entries` realistically hash-linked
/// entries. Uses `ReceiptChain::append` directly so every entry's
/// `chain_hash`, `prev_chain_hash`, and `receipt_hash` are the actual
/// production-canonical values — the chain will pass `verify_integrity`.
fn build_chain(n_entries: u64) -> ReceiptChain {
    let mut chain = ReceiptChain::new(ReceiptChainConfig::default());
    for seq in 0..n_entries {
        let appended_at = 1_700_000_000_000_u64.saturating_add(seq.saturating_mul(1_000));
        chain
            .append(
                fixture_receipt(seq),
                appended_at,
                format!("trace-vef-bench-append-{seq}"),
            )
            .expect("bench fixture must append");
    }
    chain
}

/// Build a `ProofRequest` over the given chain's entries.
fn build_proof_request(chain: &ReceiptChain) -> ProofRequest {
    let entries: Vec<_> = chain.entries().to_vec();
    let entry_count = entries.len() as u64;
    let window = ProofWindow {
        window_id: "bench-window".to_string(),
        start_index: 0,
        end_index: entry_count.saturating_sub(1),
        entry_count,
        aligned_checkpoint_id: None,
        tier: WorkloadTier::Standard,
        created_at_millis: 1_700_000_100_000,
        trace_id: "trace-vef-bench-request".to_string(),
    };
    ProofRequest {
        request_id: "bench-request".to_string(),
        window,
        entries,
        timeout_millis: 5_000,
        trace_id: "trace-vef-bench-request".to_string(),
        created_at_millis: 1_700_000_100_000,
    }
}

fn benchmark_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("vef_proof_chain_generate");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(60);
    for n in [16_u64, 256_u64, 4096_u64] {
        let chain = build_chain(n);
        let request = build_proof_request(&chain);
        let backend = TestProofBackend::new();
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &request, |b, request| {
            b.iter(|| {
                let proof = backend
                    .generate(black_box(request))
                    .expect("bench backend.generate must succeed");
                black_box(proof);
            });
        });
    }
    group.finish();
}

fn benchmark_verify_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("vef_proof_chain_verify_integrity");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(60);
    for n in [16_u64, 256_u64, 4096_u64] {
        let chain = build_chain(n);
        // Sanity-check the fixture: a hand-built chain that doesn't pass
        // verify_integrity would make every bench reading meaningless.
        chain
            .verify_integrity()
            .expect("fixture chain must verify before benching");
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &chain, |b, chain| {
            b.iter(|| {
                let events = chain
                    .verify_integrity()
                    .expect("verify_integrity must not error on a well-formed chain");
                black_box(events);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark_generate, benchmark_verify_integrity);
criterion_main!(benches);
