//! Supplemental conformance tests for bd-28u0 proof scheduler behavior.
//!
//! These tests intentionally avoid touching the main implementation file while
//! validating additional edge conditions requested by the bead contract.

#[path = "../../crates/franken-node/src/connector/vef_execution_receipt.rs"]
pub mod vef_execution_receipt;

mod connector {
    pub use super::vef_execution_receipt;
}

#[path = "../../crates/franken-node/src/vef/receipt_chain.rs"]
mod receipt_chain;

#[path = "../../crates/franken-node/src/vef/proof_scheduler.rs"]
mod proof_scheduler;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::proof_scheduler::{
        ProofJobStatus, SchedulerPolicy, VefProofScheduler, WorkloadTier, event_codes,
    };
    use super::receipt_chain::{
        ReceiptChain, ReceiptChainConfig, ReceiptChainEntry, ReceiptCheckpoint,
    };
    use super::vef_execution_receipt::{
        ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
    };

    fn make_receipt(action_type: ExecutionActionType, n: u64) -> ExecutionReceipt {
        let mut capability_context = BTreeMap::new();
        capability_context.insert("domain".to_string(), "runtime".to_string());
        capability_context.insert("scope".to_string(), "extensions".to_string());
        capability_context.insert("capability".to_string(), format!("capability-{n}"));
        ExecutionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            action_type,
            capability_context,
            actor_identity: format!("actor-{n}"),
            artifact_identity: format!("artifact-{n}"),
            policy_snapshot_hash: format!("sha256:{n:064x}"),
            timestamp_millis: 1_702_000_000_000 + n,
            sequence_number: n,
            witness_references: vec!["witness-a".to_string(), "witness-b".to_string()],
            trace_id: format!("trace-{n}"),
        }
    }

    fn build_chain(
        actions: &[ExecutionActionType],
        checkpoint_every_entries: usize,
    ) -> (Vec<ReceiptChainEntry>, Vec<ReceiptCheckpoint>) {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries,
            checkpoint_every_millis: 0,
        });
        for (idx, action) in actions.iter().copied().enumerate() {
            chain
                .append(
                    make_receipt(action, idx as u64),
                    1_702_000_100_000 + idx as u64,
                    format!("trace-chain-{idx}"),
                )
                .expect("append should succeed");
        }
        (chain.entries().to_vec(), chain.checkpoints().to_vec())
    }

    #[test]
    fn checkpoint_alignment_prefers_farthest_checkpoint_within_window() {
        let actions = vec![
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::SecretAccess,
            ExecutionActionType::ArtifactPromotion,
            ExecutionActionType::ProcessSpawn,
        ];
        let (entries, checkpoints) = build_chain(&actions, 2);

        let policy = SchedulerPolicy {
            max_receipts_per_window: 5,
            ..SchedulerPolicy::default()
        };
        let mut scheduler = VefProofScheduler::new(policy);
        let windows = scheduler
            .select_windows(&entries, &checkpoints, 1_702_000_200_000, "trace-align")
            .expect("window selection should succeed");

        assert_eq!(windows.len(), 2);
        assert_eq!((windows[0].start_index, windows[0].end_index), (0, 3));
        assert_eq!((windows[1].start_index, windows[1].end_index), (4, 5));

        for window in &windows {
            let checkpoint_id = window
                .aligned_checkpoint_id
                .expect("expected aligned checkpoint");
            let checkpoint = checkpoints
                .iter()
                .find(|cp| cp.checkpoint_id == checkpoint_id)
                .expect("checkpoint id should exist");
            assert_eq!(
                checkpoint.end_index, window.end_index,
                "window should align to the farthest in-range checkpoint end"
            );
        }
    }

    #[test]
    fn policy_change_only_affects_new_jobs() {
        let actions_initial = vec![
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::SecretAccess,
            ExecutionActionType::ArtifactPromotion,
        ];
        let actions_extended = vec![
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::SecretAccess,
            ExecutionActionType::ArtifactPromotion,
            ExecutionActionType::ProcessSpawn,
            ExecutionActionType::PolicyTransition,
        ];

        let (entries_a, checkpoints_a) = build_chain(&actions_initial, 2);
        let (entries_b, checkpoints_b) = build_chain(&actions_extended, 2);

        let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
            max_receipts_per_window: 2,
            ..SchedulerPolicy::default()
        });
        let windows_a = scheduler
            .select_windows(
                &entries_a,
                &checkpoints_a,
                1_702_000_300_000,
                "trace-policy-a",
            )
            .expect("initial window selection");
        let queued_a = scheduler
            .enqueue_windows(&windows_a, 1_702_000_300_000)
            .expect("initial queue");
        let prior_deadlines = queued_a
            .iter()
            .map(|job_id| {
                let deadline = scheduler
                    .jobs()
                    .get(job_id)
                    .expect("queued job should exist")
                    .deadline_millis;
                (job_id.clone(), deadline)
            })
            .collect::<Vec<_>>();

        for deadline in scheduler.policy.tier_deadline_millis.values_mut() {
            *deadline = 900_000;
        }

        let windows_b = scheduler
            .select_windows(
                &entries_b,
                &checkpoints_b,
                1_702_000_400_000,
                "trace-policy-b",
            )
            .expect("follow-up window selection");
        let queued_b = scheduler
            .enqueue_windows(&windows_b, 1_702_000_400_000)
            .expect("follow-up queue");
        assert!(
            !queued_b.is_empty(),
            "extended stream should produce at least one new window/job"
        );

        for (job_id, expected_deadline) in prior_deadlines {
            let actual = scheduler
                .jobs()
                .get(&job_id)
                .expect("pre-existing job should still exist")
                .deadline_millis;
            assert_eq!(
                actual, expected_deadline,
                "policy changes must not mutate existing queued job deadlines"
            );
        }

        let old_ids = queued_a.into_iter().collect::<BTreeSet<_>>();
        let new_job_id = queued_b
            .iter()
            .find(|job_id| !old_ids.contains(*job_id))
            .expect("at least one newly queued job id")
            .clone();
        let new_job = scheduler
            .jobs()
            .get(&new_job_id)
            .expect("newly queued job should exist");
        let expected_span = scheduler
            .policy
            .tier_deadline_millis
            .get(&new_job.tier)
            .copied()
            .unwrap_or_else(|| new_job.tier.default_deadline_millis());
        assert_eq!(new_job.deadline_millis, 1_702_000_400_000 + expected_span);
    }

    #[test]
    fn dispatch_respects_memory_budget_even_when_compute_allows_more() {
        let actions = vec![
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::ProcessSpawn,
            ExecutionActionType::ArtifactPromotion,
        ];
        let (entries, checkpoints) = build_chain(&actions, 1);

        let policy = SchedulerPolicy {
            max_receipts_per_window: 1,
            max_concurrent_jobs: 4,
            max_compute_millis_per_tick: 10_000,
            max_memory_mib_per_tick: 15,
            ..SchedulerPolicy::default()
        };
        let mut scheduler = VefProofScheduler::new(policy);
        let windows = scheduler
            .select_windows(&entries, &checkpoints, 1_702_000_500_000, "trace-memory")
            .expect("window selection");
        scheduler
            .enqueue_windows(&windows, 1_702_000_500_000)
            .expect("enqueue");

        let dispatched = scheduler
            .dispatch_jobs(1_702_000_500_010)
            .expect("dispatch should succeed");
        assert_eq!(
            dispatched.len(),
            1,
            "with 15 MiB budget and 8 MiB/job, only one job should dispatch"
        );
        assert_eq!(dispatched[0].status, ProofJobStatus::Dispatched);
    }

    #[test]
    fn deadline_enforcement_emits_stable_event_codes() {
        let actions = vec![
            ExecutionActionType::SecretAccess,
            ExecutionActionType::PolicyTransition,
            ExecutionActionType::NetworkAccess,
        ];
        let (entries, checkpoints) = build_chain(&actions, 1);

        let mut policy = SchedulerPolicy {
            max_receipts_per_window: 1,
            max_concurrent_jobs: 16,
            max_compute_millis_per_tick: 100_000,
            max_memory_mib_per_tick: 100_000,
            ..SchedulerPolicy::default()
        };
        policy
            .tier_deadline_millis
            .insert(WorkloadTier::Critical, 1);
        policy.tier_deadline_millis.insert(WorkloadTier::High, 1);
        policy
            .tier_deadline_millis
            .insert(WorkloadTier::Standard, 1);
        policy
            .tier_deadline_millis
            .insert(WorkloadTier::Background, 1);

        let mut scheduler = VefProofScheduler::new(policy);
        let windows = scheduler
            .select_windows(&entries, &checkpoints, 1_702_000_600_000, "trace-deadline")
            .expect("window selection");
        scheduler
            .enqueue_windows(&windows, 1_702_000_600_000)
            .expect("enqueue");
        scheduler
            .dispatch_jobs(1_702_000_600_000)
            .expect("dispatch");

        let exceeded = scheduler.enforce_deadlines(1_702_000_600_100);
        assert_eq!(exceeded.len(), scheduler.jobs().len());

        let deadline_events = scheduler
            .events()
            .iter()
            .filter(|event| event.event_code == event_codes::VEF_SCHED_ERR_001_DEADLINE)
            .count();
        assert_eq!(deadline_events, exceeded.len());

        let metrics = scheduler.backlog_metrics(1_702_000_600_200, "trace-deadline-metrics");
        assert_eq!(metrics.deadline_exceeded_jobs, exceeded.len());
        assert_eq!(metrics.windows_observed, scheduler.jobs().len());
    }
}
