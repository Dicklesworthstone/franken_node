use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
};
use frankenengine_node::vef::proof_scheduler::{SchedulerPolicy, VefProofScheduler};
use frankenengine_node::vef::proof_service::{
    ProofBackendId, ProofInputEnvelope, ProofServiceConfig, VefProofService,
};
use frankenengine_node::vef::receipt_chain::{
    ConcurrentReceiptChain, ReceiptChain, ReceiptChainConfig, ReceiptChainEntry, ReceiptCheckpoint,
    error_codes as chain_error_codes, event_codes as chain_event_codes,
};
use std::collections::BTreeMap;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BASE_MILLIS: u64 = 1_706_200_000_000;

fn sha256_fill(digit: char) -> String {
    format!(
        "sha256:{}",
        std::iter::repeat_n(digit, 64).collect::<String>()
    )
}

fn action_for(seq: u64) -> ExecutionActionType {
    match seq % 5 {
        0 => ExecutionActionType::NetworkAccess,
        1 => ExecutionActionType::FilesystemOperation,
        2 => ExecutionActionType::PolicyTransition,
        3 => ExecutionActionType::ProcessSpawn,
        _ => ExecutionActionType::ArtifactPromotion,
    }
}

fn receipt(seq: u64) -> ExecutionReceipt {
    let mut capability_context = BTreeMap::new();
    capability_context.insert("capability".to_string(), format!("vef-capability-{seq}"));
    capability_context.insert(
        "service".to_string(),
        format!("receipt-service-{}", seq % 2),
    );
    capability_context.insert("scope".to_string(), "vef-real-service-chain".to_string());

    ExecutionReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        action_type: action_for(seq),
        capability_context,
        actor_identity: format!("agent:vef-real-service-{seq}"),
        artifact_identity: format!("artifact:vef-receipt-{seq}"),
        policy_snapshot_hash: format!("sha256:{seq:064x}"),
        timestamp_millis: BASE_MILLIS.saturating_add(seq),
        sequence_number: seq,
        witness_references: vec![
            format!("witness:primary-{seq}"),
            format!("witness:replica-{}", seq % 3),
        ],
        trace_id: format!("trace-vef-receipt-{seq}"),
    }
}

fn append_stream(chain: &ConcurrentReceiptChain, count: u64, trace_prefix: &str) -> TestResult {
    for seq in 0..count {
        let outcome = chain.append(
            receipt(seq),
            BASE_MILLIS.saturating_add(1_000).saturating_add(seq),
            format!("{trace_prefix}-{seq}"),
        )?;

        assert_eq!(outcome.entry.index, seq);
        assert!(
            outcome
                .events
                .iter()
                .any(|event| event.event_code == chain_event_codes::VEF_CHAIN_001_APPENDED)
        );
    }

    Ok(())
}

fn append_direct_stream(chain: &mut ReceiptChain, count: u64) -> TestResult {
    for seq in 0..count {
        chain.append(
            receipt(seq),
            BASE_MILLIS.saturating_add(2_000).saturating_add(seq),
            format!("trace-direct-{seq}"),
        )?;
    }
    Ok(())
}

fn entry_fingerprint(entries: &[ReceiptChainEntry]) -> Vec<(u64, String, String, String, String)> {
    entries
        .iter()
        .map(|entry| {
            (
                entry.index,
                entry.prev_chain_hash.clone(),
                entry.receipt_hash.clone(),
                entry.chain_hash.clone(),
                entry.receipt.trace_id.clone(),
            )
        })
        .collect()
}

fn checkpoint_fingerprint(
    checkpoints: &[ReceiptCheckpoint],
) -> Vec<(u64, u64, u64, String, String)> {
    checkpoints
        .iter()
        .map(|checkpoint| {
            (
                checkpoint.checkpoint_id,
                checkpoint.start_index,
                checkpoint.end_index,
                checkpoint.chain_head_hash.clone(),
                checkpoint.commitment_hash.clone(),
            )
        })
        .collect()
}

fn sample_material() -> TestResult<(
    ReceiptChainConfig,
    Vec<ReceiptChainEntry>,
    Vec<ReceiptCheckpoint>,
)> {
    let config = ReceiptChainConfig {
        checkpoint_every_entries: 2,
        checkpoint_every_millis: 0,
    };
    let mut chain = ReceiptChain::new(config);
    append_direct_stream(&mut chain, 6)?;
    chain.verify_integrity()?;

    Ok((
        config,
        chain.entries().to_vec(),
        chain.checkpoints().to_vec(),
    ))
}

#[test]
fn concurrent_receipt_chains_preserve_cross_service_determinism() -> TestResult {
    let config = ReceiptChainConfig {
        checkpoint_every_entries: 2,
        checkpoint_every_millis: 0,
    };
    let primary = ConcurrentReceiptChain::new(config);
    let replica = ConcurrentReceiptChain::new(config);

    append_stream(&primary, 6, "trace-primary")?;
    append_stream(&replica, 6, "trace-replica")?;

    let primary_snapshot = primary.snapshot()?;
    let replica_snapshot = replica.snapshot()?;
    let verify_events = primary_snapshot.verify_integrity()?;

    assert_eq!(
        entry_fingerprint(primary_snapshot.entries()),
        entry_fingerprint(replica_snapshot.entries())
    );
    assert_eq!(
        checkpoint_fingerprint(primary_snapshot.checkpoints()),
        checkpoint_fingerprint(replica_snapshot.checkpoints())
    );
    assert_eq!(primary_snapshot.entries().len(), 6);
    assert_eq!(primary_snapshot.checkpoints().len(), 3);
    assert!(
        verify_events
            .iter()
            .any(|event| event.event_code == chain_event_codes::VEF_CHAIN_003_VERIFIED)
    );

    Ok(())
}

#[test]
fn resume_from_snapshot_continues_checkpoint_sequence_after_restart() -> TestResult {
    let config = ReceiptChainConfig {
        checkpoint_every_entries: 2,
        checkpoint_every_millis: 0,
    };
    let mut original = ReceiptChain::new(config);
    append_direct_stream(&mut original, 4)?;

    assert_eq!(original.checkpoints().len(), 2);

    let mut resumed = ReceiptChain::resume_from_snapshot(
        config,
        original.entries().to_vec(),
        original.checkpoints().to_vec(),
    )?;

    let first_post_restart = resumed.append(receipt(4), BASE_MILLIS + 3_004, "trace-restart-4")?;
    assert!(
        first_post_restart.checkpoint.is_none(),
        "one post-restart receipt should not checkpoint until the configured interval is reached"
    );

    let second_post_restart = resumed.append(receipt(5), BASE_MILLIS + 3_005, "trace-restart-5")?;
    let checkpoint = second_post_restart
        .checkpoint
        .ok_or("second post-restart append should create the next checkpoint")?;

    assert_eq!(checkpoint.checkpoint_id, 2);
    assert_eq!(checkpoint.start_index, 4);
    assert_eq!(checkpoint.end_index, 5);
    assert_eq!(resumed.entries().len(), 6);
    assert_eq!(resumed.checkpoints().len(), 3);
    resumed.verify_integrity()?;

    Ok(())
}

#[test]
fn tampered_recovered_snapshots_fail_closed_with_stable_codes() -> TestResult {
    let (_, entries, checkpoints) = sample_material()?;

    let mut tampered_entries = entries.clone();
    tampered_entries
        .get_mut(1)
        .ok_or("sample stream should contain entry 1")?
        .receipt
        .actor_identity
        .push_str("-altered");
    let err = ReceiptChain::verify_entries_and_checkpoints(&tampered_entries, &checkpoints)
        .expect_err("mutated receipt material must fail integrity verification");
    assert_eq!(err.code, chain_error_codes::ERR_VEF_CHAIN_TAMPER);
    assert_eq!(err.event_code, chain_event_codes::VEF_CHAIN_ERR_001_TAMPER);

    let mut missing_middle_entry = entries.clone();
    missing_middle_entry.remove(1);
    let err = ReceiptChain::verify_entries_and_checkpoints(&missing_middle_entry, &checkpoints)
        .expect_err("deleted middle entry must fail sequence verification");
    assert_eq!(err.code, chain_error_codes::ERR_VEF_CHAIN_SEQUENCE);
    assert_eq!(
        err.event_code,
        chain_event_codes::VEF_CHAIN_ERR_003_SEQUENCE
    );

    let mut tampered_checkpoints = checkpoints.clone();
    tampered_checkpoints
        .get_mut(0)
        .ok_or("sample stream should contain checkpoint 0")?
        .commitment_hash = sha256_fill('f');
    let err = ReceiptChain::verify_entries_and_checkpoints(&entries, &tampered_checkpoints)
        .expect_err("checkpoint commitment mutation must fail closed");
    assert_eq!(err.code, chain_error_codes::ERR_VEF_CHAIN_CHECKPOINT);
    assert_eq!(
        err.event_code,
        chain_event_codes::VEF_CHAIN_ERR_002_CHECKPOINT
    );

    Ok(())
}

#[test]
fn scheduler_and_proof_service_verify_real_receipt_windows() -> TestResult {
    let (_, entries, checkpoints) = sample_material()?;
    let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
        max_receipts_per_window: 2,
        max_concurrent_jobs: 4,
        max_compute_millis_per_tick: 10_000,
        max_memory_mib_per_tick: 1_024,
        ..SchedulerPolicy::default()
    });

    let windows = scheduler.select_windows(
        &entries,
        &checkpoints,
        BASE_MILLIS.saturating_add(4_000),
        "trace-proof-window",
    )?;
    assert_eq!(windows.len(), 3);
    assert_eq!(
        windows
            .iter()
            .filter(|window| window.aligned_checkpoint_id.is_some())
            .count(),
        3
    );

    let queued = scheduler.enqueue_windows(&windows, BASE_MILLIS.saturating_add(4_100))?;
    assert_eq!(queued.len(), windows.len());

    let dispatched = scheduler.dispatch_jobs(BASE_MILLIS.saturating_add(4_200))?;
    assert_eq!(dispatched.len(), windows.len());

    let mut proof_service =
        VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
    let mut completed = 0usize;
    let mut checkpoint_backed_inputs = 0usize;

    for job in dispatched {
        let window = windows
            .iter()
            .find(|window| window.window_id == job.window_id)
            .ok_or_else(|| format!("missing selected window {}", job.window_id))?;
        let input = ProofInputEnvelope::from_scheduler_job(
            &job,
            window,
            &entries,
            &checkpoints,
            &sha256_fill('a'),
            vec![
                "receipt.chain.integrity.verified".to_string(),
                "checkpoint.commitment.verified".to_string(),
            ],
            BTreeMap::from([(
                "source".to_string(),
                "bd-jcq1z.2.4-real-service-replacement".to_string(),
            )]),
        )?;
        if input.checkpoint_commitment_hash.is_some() {
            checkpoint_backed_inputs = checkpoint_backed_inputs.saturating_add(1);
        }

        let backend = if completed % 2 == 0 {
            ProofBackendId::HashAttestationV1
        } else {
            ProofBackendId::DoubleHashAttestationV1
        };
        let proof = proof_service.generate_proof(
            &input,
            Some(backend),
            BASE_MILLIS.saturating_add(4_300 + u64::try_from(completed)?),
        )?;
        proof_service.verify_proof(&input, &proof)?;
        scheduler.mark_completed(
            &job.job_id,
            BASE_MILLIS.saturating_add(4_400 + u64::try_from(completed)?),
        )?;
        completed = completed.saturating_add(1);
    }

    assert_eq!(completed, windows.len());
    assert_eq!(checkpoint_backed_inputs, windows.len());

    let metrics = scheduler.backlog_metrics(BASE_MILLIS.saturating_add(4_500), "trace-metrics");
    assert_eq!(metrics.completed_jobs, windows.len());
    assert_eq!(metrics.pending_jobs, 0);
    assert_eq!(metrics.dispatched_jobs, 0);

    Ok(())
}
