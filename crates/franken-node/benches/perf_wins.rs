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

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};

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
    // `recompute_root` returns Result<String, ProofFailure> as of the strict
    // Ed25519/transparency hardening pass; benches construct deterministic
    // proofs so a Result::Err here would indicate a bench-fixture bug, not a
    // production-path failure.
    let root_hash =
        recompute_root(&proof).expect("bench fixture must produce valid inclusion proof");
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

/// Benchmark TNR effect-receipt construction plus CAS/receipt hashing.
fn tnr_effect_receipt_construct_and_hash(c: &mut Criterion) {
    use frankenengine_node::runtime::effect_receipt::{EffectKind, EffectReceipt};
    use frankenengine_node::storage::cas::content_hash;

    let pre_state_hash = content_hash(b"tnr-pre-state");
    let args_hash = content_hash(b"tnr-effect-args");
    let post_state_hash = content_hash(b"tnr-post-state");
    let payload: &[u8] = b"tnr-result-payload";

    c.bench_function("tnr_effect_receipt_construct_and_hash", |b| {
        b.iter(|| {
            let result_hash = content_hash(black_box(payload));
            let receipt = EffectReceipt::allowed(
                7,
                "trace-tnr-perf",
                EffectKind::HttpRequest,
                "capability:net:http",
                pre_state_hash.clone(),
                args_hash.clone(),
                result_hash,
                post_state_hash.clone(),
                1_700_000_000,
            );
            black_box(receipt.receipt_hash())
        })
    });
}

/// Benchmark the lineage/label metadata transform bound into effect receipts.
fn tnr_label_propagation_transform(c: &mut Criterion) {
    use frankenengine_node::runtime::effect_receipt::{
        EffectKind, EffectLineageFields, EffectReceipt,
    };
    use frankenengine_node::storage::cas::content_hash;

    let pre_state_hash = content_hash(b"tnr-pre-state");
    let args_hash = content_hash(b"tnr-effect-args");
    let result_hash = content_hash(b"tnr-result");
    let post_state_hash = content_hash(b"tnr-post-state");
    let input_lineage_hash = content_hash(b"label-input").as_str().to_string();
    let output_lineage_hash = content_hash(b"label-output").as_str().to_string();
    let label_set_commitment = content_hash(b"labels:secret+network").as_str().to_string();

    c.bench_function("tnr_label_propagation_transform", |b| {
        b.iter(|| {
            let lineage = EffectLineageFields::declassified(
                input_lineage_hash.clone(),
                output_lineage_hash.clone(),
                label_set_commitment.clone(),
                "declass:perf-tnr",
            );
            let receipt = EffectReceipt::allowed_with_lineage(
                8,
                "trace-tnr-labels",
                EffectKind::FsWrite,
                "capability:fs:write",
                pre_state_hash.clone(),
                args_hash.clone(),
                result_hash.clone(),
                post_state_hash.clone(),
                1_700_000_001,
                lineage,
            );
            black_box((receipt.validate(), receipt.receipt_hash()))
        })
    });
}

/// Benchmark frozen-quantile conformal scoring feeding a Sentinel likelihood signal.
fn tnr_conformal_score_lookup(c: &mut Criterion) {
    use frankenengine_node::policy::runtime_sentinel::{
        SentinelSignalKind, sentinel_signal_from_conformal_risk_set,
    };
    use frankenengine_node::security::conformal::{
        ConformalScoreSample, calibrated_mondrian_risk_set, freeze_quantiles,
    };

    let samples = vec![
        ConformalScoreSample {
            sample_id: "p1".to_string(),
            risk_class: "tnr-effect".to_string(),
            score_bp: 9_100,
            positive: true,
        },
        ConformalScoreSample {
            sample_id: "p2".to_string(),
            risk_class: "tnr-effect".to_string(),
            score_bp: 8_400,
            positive: true,
        },
        ConformalScoreSample {
            sample_id: "n1".to_string(),
            risk_class: "tnr-effect".to_string(),
            score_bp: 1_100,
            positive: false,
        },
        ConformalScoreSample {
            sample_id: "n2".to_string(),
            risk_class: "tnr-effect".to_string(),
            score_bp: 1_900,
            positive: false,
        },
    ];
    let artifact = freeze_quantiles(&samples, 2_000).expect("bench quantile fixture");

    c.bench_function("tnr_conformal_score_lookup", |b| {
        b.iter(|| {
            let risk_set =
                calibrated_mondrian_risk_set("candidate", "tnr-effect", 8_800, &artifact)
                    .expect("bench risk-set fixture");
            black_box(
                sentinel_signal_from_conformal_risk_set(
                    SentinelSignalKind::EffectReceiptAnomaly,
                    "perf:conformal",
                    &risk_set,
                )
                .expect("bench sentinel signal fixture"),
            )
        })
    });
}

/// Benchmark one fixed-point Sentinel e-process update per observation.
fn tnr_sentinel_e_process_update(c: &mut Criterion) {
    use frankenengine_node::policy::bayesian_diagnostics::{
        LikelihoodRatioEvidence, RuntimeSentinelEProcess,
    };

    let evidence = LikelihoodRatioEvidence::new("effect_receipt_anomaly", 1, 1_250_000);

    c.bench_function("tnr_sentinel_e_process_update", |b| {
        b.iter_batched(
            RuntimeSentinelEProcess::new,
            |mut process| black_box(process.observe(black_box(&evidence))),
            BatchSize::SmallInput,
        )
    });
}

/// Benchmark the public SDK LTV verification path over a bounded re-attestation chain.
fn tnr_ltv_reattestation_verification(c: &mut Criterion) {
    use frankenengine_verifier_sdk::{
        LongTermArtifactEvidence, LongTermCryptoSuiteRecord, LongTermMmrInclusionProof,
        LongTermMmrPrefixProof, LongTermMmrRoot, LongTermMmrRootReattestation,
        LongTermMmrRootReattestationChain, LongTermMmrRootWitnessReceipt,
        LongTermMmrRootWitnessStatement, LongTermPartialSignature, LongTermPublicationArtifact,
        LongTermSignerKey, LongTermThresholdConfig, LongTermVerificationEvidence, VerifierSdk,
        bundle,
    };

    fn digest(label: &str) -> String {
        bundle::hash(label.as_bytes())
    }

    let origin_root = LongTermMmrRoot {
        tree_size: 2,
        root_hash: digest("origin-root"),
    };
    let witnessed_root = LongTermMmrRoot {
        tree_size: 4,
        root_hash: digest("witnessed-root"),
    };
    let prefix_proof = LongTermMmrPrefixProof {
        prefix_size: origin_root.tree_size,
        super_tree_size: witnessed_root.tree_size,
        prefix_root_hash: origin_root.root_hash.clone(),
        super_root_hash: witnessed_root.root_hash.clone(),
        prefix_root_from_super: origin_root.root_hash.clone(),
        super_leaf_hashes: vec![
            digest("leaf-a"),
            digest("leaf-b"),
            digest("leaf-c"),
            digest("leaf-d"),
        ],
    };
    let evidence = LongTermVerificationEvidence {
        schema_version: "vsdk-ltv-evidence-v1.0".to_string(),
        as_of_unix_seconds: 1_700_000_100,
        artifact: LongTermArtifactEvidence {
            artifact_id: "perf-artifact".to_string(),
            artifact_hash: digest("artifact"),
            crypto_suite: "ed25519-v1".to_string(),
            claimed_at_unix_seconds: 1_700_000_000,
            marker_hash: digest("artifact-marker"),
        },
        suite_records: vec![LongTermCryptoSuiteRecord {
            crypto_suite: "ed25519-v1".to_string(),
            valid_from_unix_seconds: 1_600_000_000,
            valid_until_unix_seconds: None,
            compromised_at_unix_seconds: None,
        }],
        inclusion_proof: LongTermMmrInclusionProof {
            leaf_index: 0,
            tree_size: origin_root.tree_size,
            leaf_hash: digest("artifact-leaf"),
            audit_path: vec![digest("sibling")],
        },
        reattestation_chain: LongTermMmrRootReattestationChain {
            origin_root: origin_root.clone(),
            attestations: vec![LongTermMmrRootReattestation {
                schema_version: "mmr-root-reattestation-v1".to_string(),
                previous_root: origin_root,
                attested_root: witnessed_root.clone(),
                prefix_proof,
                issued_at_unix_seconds: 1_700_000_050,
                crypto_suite: "ed25519-v1".to_string(),
                attestation_hash: digest("reattestation"),
            }],
        },
        witness_receipt: LongTermMmrRootWitnessReceipt {
            statement: LongTermMmrRootWitnessStatement {
                schema_version: "mmr-root-witness-v1".to_string(),
                root: witnessed_root,
                observed_at_unix_seconds: 1_700_000_075,
                witness_group_id: "perf-witnesses".to_string(),
                witness_policy_id: "threshold-2-of-3".to_string(),
                content_hash: digest("witness-statement"),
            },
            threshold_config: LongTermThresholdConfig {
                threshold: 2,
                total_signers: 3,
                signer_keys: vec![
                    LongTermSignerKey {
                        key_id: "witness-a".to_string(),
                        public_key_hex: digest("public-a"),
                    },
                    LongTermSignerKey {
                        key_id: "witness-b".to_string(),
                        public_key_hex: digest("public-b"),
                    },
                    LongTermSignerKey {
                        key_id: "witness-c".to_string(),
                        public_key_hex: digest("public-c"),
                    },
                ],
            },
            witness_artifact: LongTermPublicationArtifact {
                artifact_id: "mmr-root-witness".to_string(),
                connector_id: "franken-node-root-witness".to_string(),
                content_hash: digest("publication"),
                signatures: vec![
                    LongTermPartialSignature {
                        signer_id: "witness-a".to_string(),
                        key_id: "witness-a".to_string(),
                        signature_hex: digest("sig-a"),
                    },
                    LongTermPartialSignature {
                        signer_id: "witness-b".to_string(),
                        key_id: "witness-b".to_string(),
                        signature_hex: digest("sig-b"),
                    },
                ],
            },
            trace_id: "trace-tnr-ltv".to_string(),
            timestamp: "2024-01-01T00:01:15Z".to_string(),
        },
    };
    let sdk = VerifierSdk::new("verifier://perf-wins");

    c.bench_function("tnr_ltv_reattestation_verification", |b| {
        b.iter(|| black_box(sdk.verify_as_of_ltv(black_box(&evidence))))
    });
}

criterion_group!(
    perf_wins,
    signature_preimage_hash_throughput,
    transparency_verify_inclusion_path64,
    lane_scheduler_assign_throughput,
    frankensqlite_read_throughput,
    trace_digest_throughput,
    tnr_effect_receipt_construct_and_hash,
    tnr_label_propagation_transform,
    tnr_conformal_score_lookup,
    tnr_sentinel_e_process_update,
    tnr_ltv_reattestation_verification
);
criterion_main!(perf_wins);
