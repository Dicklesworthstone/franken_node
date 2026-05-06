use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::ops::validation_broker::{CommandSpec, InputDigest};
use frankenengine_node::ops::validation_proof_cache::DirtyStatePolicy;
use frankenengine_node::ops::validation_proof_coalescer::{
    CompleteLeaseRequest, CreateLeaseRequest, FenceStaleLeaseRequest,
    ValidationProofCoalescerDecisionKind, ValidationProofCoalescerReceiptRef,
    ValidationProofCoalescerStore, ValidationProofLeaseState, ValidationProofRchCommand,
    ValidationProofWorkKey, ValidationProofWorkKeyParts, error_codes, event_codes,
};
use std::fs;
use tempfile::TempDir;

fn ts(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 6, 2, 30, second)
        .single()
        .expect("valid timestamp")
}

fn command(seed: &str) -> CommandSpec {
    CommandSpec {
        program: "cargo".to_string(),
        argv: vec![
            "+nightly-2026-02-19".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "frankenengine-node".to_string(),
            "--test".to_string(),
            format!("validation_proof_coalescer_{seed}"),
        ],
        cwd: "/data/projects/franken_node".to_string(),
        environment_policy_id: "validation-proof-coalescer/env-policy/v1".to_string(),
        target_dir_policy_id: "validation-proof-coalescer/target-dir/off-repo/v1".to_string(),
    }
}

fn work_key(seed: &str) -> ValidationProofWorkKey {
    ValidationProofWorkKey::from_parts(ValidationProofWorkKeyParts {
        command_digest: command(seed).digest(),
        input_digests: vec![InputDigest::new(
            format!("crates/franken-node/src/ops/validation_proof_coalescer_{seed}.rs"),
            seed.as_bytes(),
            "integration-test",
        )],
        git_commit: format!("commit-{seed}"),
        dirty_worktree: false,
        dirty_state_policy: DirtyStatePolicy::CleanRequired,
        feature_flags: vec!["external-commands".to_string(), "http-client".to_string()],
        cargo_toolchain: "nightly-2026-02-19".to_string(),
        package: "frankenengine-node".to_string(),
        test_target: "validation_proof_coalescer".to_string(),
        environment_policy_id: "validation-proof-coalescer/env-policy/v1".to_string(),
        target_dir_policy_id: "validation-proof-coalescer/target-dir/off-repo/v1".to_string(),
    })
    .expect("valid work key")
}

fn create_request(seed: &str, agent: &str, at: DateTime<Utc>) -> CreateLeaseRequest {
    let key = work_key(seed);
    CreateLeaseRequest {
        rch_command: ValidationProofRchCommand {
            argv: vec![
                "rch".to_string(),
                "exec".to_string(),
                "--".to_string(),
                "cargo".to_string(),
                "test".to_string(),
            ],
            command_digest: key.command_digest.clone(),
        },
        proof_work_key: key,
        owner_agent: agent.to_string(),
        owner_bead_id: "bd-y4coj".to_string(),
        trace_id: format!("trace-{seed}-{agent}"),
        fencing_token: format!("fence-{seed}-{agent}"),
        created_at: at,
        expires_at: at + chrono::Duration::minutes(30),
        admission_policy_id: "validation-proof-coalescer/admission/default/v1".to_string(),
    }
}

fn replacement_marker() -> String {
    ["new", "lease", "marker"].join("-")
}

fn receipt_ref(seed: &str) -> ValidationProofCoalescerReceiptRef {
    let key = work_key(seed);
    ValidationProofCoalescerReceiptRef {
        receipt_id: format!("receipt-{seed}"),
        path: format!("artifacts/validation_broker/receipts/{seed}.json"),
        bead_id: "bd-y4coj".to_string(),
        proof_cache_key_hex: key.proof_cache_key.hex,
    }
}

#[test]
fn real_temp_dir_equivalent_keys_join_and_complete() {
    let temp = TempDir::new().expect("tempdir");
    let store = ValidationProofCoalescerStore::new(temp.path());

    let create = store
        .create_or_join(create_request("join", "PearlLeopard", ts(1)))
        .expect("create lease");
    assert_eq!(
        create.decision.decision,
        ValidationProofCoalescerDecisionKind::RunLocallyViaRch
    );
    assert!(create.lease_path.exists());

    let join = store
        .create_or_join(create_request("join", "LavenderElk", ts(2)))
        .expect("join lease");
    assert_eq!(
        join.decision.decision,
        ValidationProofCoalescerDecisionKind::JoinExistingProof
    );
    assert_eq!(
        join.lease.expect("joined lease").waiter_agents,
        vec!["LavenderElk".to_string()]
    );

    let original = create_request("join", "PearlLeopard", ts(3));
    let completed = store
        .complete_lease(CompleteLeaseRequest {
            proof_work_key: original.proof_work_key,
            owner_agent: original.owner_agent,
            owner_bead_id: original.owner_bead_id,
            fencing_token: original.fencing_token,
            completed_at: ts(4),
            receipt_ref: receipt_ref("join"),
        })
        .expect("complete lease");
    assert_eq!(completed.state, ValidationProofLeaseState::Completed);
    assert_eq!(
        completed.diagnostics.event_code,
        event_codes::RECEIPT_HANDOFF_COMPLETED
    );
}

#[test]
fn real_temp_dir_divergent_keys_do_not_join() {
    let temp = TempDir::new().expect("tempdir");
    let store = ValidationProofCoalescerStore::new(temp.path());

    let left = store
        .create_or_join(create_request("left", "PearlLeopard", ts(1)))
        .expect("left lease");
    let right = store
        .create_or_join(create_request("right", "LavenderElk", ts(2)))
        .expect("right lease");

    assert_ne!(left.lease_path, right.lease_path);
    assert_eq!(
        right.decision.decision,
        ValidationProofCoalescerDecisionKind::RunLocallyViaRch
    );
}

#[test]
fn real_temp_dir_corrupted_metadata_returns_repair_decision() {
    let temp = TempDir::new().expect("tempdir");
    let store = ValidationProofCoalescerStore::new(temp.path());
    let request = create_request("corrupt", "PearlLeopard", ts(1));
    let path = store.lease_path(&request.proof_work_key);
    fs::create_dir_all(path.parent().expect("lease parent")).expect("lease parent");
    fs::write(&path, b"{not-json").expect("corrupt lease");

    let outcome = store.create_or_join(request).expect("repair decision");
    assert_eq!(
        outcome.decision.decision,
        ValidationProofCoalescerDecisionKind::RepairState
    );
    assert!(outcome.decision.diagnostics.fail_closed);
    assert!(outcome.lease.is_none());
}

#[test]
fn real_temp_dir_stale_fence_blocks_old_owner_completion() {
    let temp = TempDir::new().expect("tempdir");
    let store = ValidationProofCoalescerStore::new(temp.path());
    let mut request = create_request("stale", "PearlLeopard", ts(1));
    request.expires_at = ts(5);
    store
        .create_or_join(request.clone())
        .expect("create staleable lease");

    let stale = store
        .create_or_join(create_request("stale", "LavenderElk", ts(10)))
        .expect("stale decision");
    assert_eq!(
        stale.decision.decision,
        ValidationProofCoalescerDecisionKind::RetryAfterStaleLease
    );
    assert!(stale.decision.diagnostics.fail_closed);

    store
        .fence_stale_lease(FenceStaleLeaseRequest {
            proof_work_key: request.proof_work_key.clone(),
            owner_agent: "LavenderElk".to_string(),
            owner_bead_id: "bd-y4coj".to_string(),
            trace_id: "trace-new-fence".to_string(),
            fencing_token: replacement_marker(),
            fenced_at: ts(11),
            expires_at: ts(50),
        })
        .expect("fence stale lease");

    let err = store
        .complete_lease(CompleteLeaseRequest {
            proof_work_key: request.proof_work_key,
            owner_agent: "PearlLeopard".to_string(),
            owner_bead_id: "bd-y4coj".to_string(),
            fencing_token: request.fencing_token,
            completed_at: ts(12),
            receipt_ref: receipt_ref("stale"),
        })
        .expect_err("old owner cannot complete");
    assert_eq!(err.code(), error_codes::ERR_VPCO_FENCED_OWNER);
}
