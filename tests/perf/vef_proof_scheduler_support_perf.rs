//! Supplemental performance-path tests for bd-28u0 proof scheduler.
//!
//! These tests validate deterministic behavior and tick-budget enforcement on
//! larger synthetic streams without using timing-sensitive assertions.

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
    use std::collections::BTreeMap;

    use super::proof_scheduler::{SchedulerPolicy, VefProofScheduler};
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
            timestamp_millis: 1_703_000_000_000 + n,
            sequence_number: n,
            witness_references: vec!["witness-a".to_string(), "witness-b".to_string()],
            trace_id: format!("trace-{n}"),
        }
    }

    fn build_high_volume_stream(
        count: usize,
        checkpoint_every_entries: usize,
    ) -> (Vec<ReceiptChainEntry>, Vec<ReceiptCheckpoint>) {
        let actions = [
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::ProcessSpawn,
            ExecutionActionType::SecretAccess,
            ExecutionActionType::PolicyTransition,
            ExecutionActionType::ArtifactPromotion,
        ];
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries,
            checkpoint_every_millis: 0,
        });
        for idx in 0..count {
            let action = actions[idx % actions.len()];
            chain
                .append(
                    make_receipt(action, idx as u64),
                    1_703_000_100_000 + idx as u64,
                    format!("trace-high-volume-{idx}"),
                )
                .expect("append should succeed");
        }
        (chain.entries().to_vec(), chain.checkpoints().to_vec())
    }

    #[test]
    fn high_volume_window_selection_is_deterministic() {
        let (entries, checkpoints) = build_high_volume_stream(256, 16);
        let policy = SchedulerPolicy {
            max_receipts_per_window: 17,
            ..SchedulerPolicy::default()
        };
        let mut scheduler_a = VefProofScheduler::new(policy.clone());
        let mut scheduler_b = VefProofScheduler::new(policy);

        let windows_a = scheduler_a
            .select_windows(&entries, &checkpoints, 1_703_000_200_000, "trace-perf-a")
            .expect("window selection A");
        let windows_b = scheduler_b
            .select_windows(&entries, &checkpoints, 1_703_000_200_000, "trace-perf-b")
            .expect("window selection B");

        let tuple_a = windows_a
            .iter()
            .map(|window| {
                (
                    window.start_index,
                    window.end_index,
                    window.aligned_checkpoint_id,
                    window.tier,
                )
            })
            .collect::<Vec<_>>();
        let tuple_b = windows_b
            .iter()
            .map(|window| {
                (
                    window.start_index,
                    window.end_index,
                    window.aligned_checkpoint_id,
                    window.tier,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(tuple_a, tuple_b);
    }

    #[test]
    fn dispatch_tick_never_exceeds_compute_or_memory_budget() {
        let (entries, checkpoints) = build_high_volume_stream(180, 9);
        let policy = SchedulerPolicy {
            max_receipts_per_window: 3,
            max_concurrent_jobs: 5,
            max_compute_millis_per_tick: 1_200,
            max_memory_mib_per_tick: 120,
            ..SchedulerPolicy::default()
        };
        let mut scheduler = VefProofScheduler::new(policy.clone());
        let windows = scheduler
            .select_windows(
                &entries,
                &checkpoints,
                1_703_000_300_000,
                "trace-perf-budget",
            )
            .expect("window selection");
        scheduler
            .enqueue_windows(&windows, 1_703_000_300_010)
            .expect("enqueue");

        let dispatched = scheduler
            .dispatch_jobs(1_703_000_300_020)
            .expect("dispatch");
        let compute_sum = dispatched
            .iter()
            .map(|job| job.estimated_compute_millis)
            .sum::<u64>();
        let memory_sum = dispatched
            .iter()
            .map(|job| job.estimated_memory_mib)
            .sum::<u64>();

        assert!(dispatched.len() <= policy.max_concurrent_jobs);
        assert!(compute_sum <= policy.max_compute_millis_per_tick);
        assert!(memory_sum <= policy.max_memory_mib_per_tick);
    }
}
