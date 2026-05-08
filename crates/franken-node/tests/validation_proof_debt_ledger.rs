use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::ops::validation_broker::{
    DigestRef, FlightRecorderAdapterOutcomeClass, ProofArtifactPaths, ProofEvidenceSource,
    ProofStatusKind, QueueState, RchMode, TimeoutClass, ValidationErrorClass, ValidationExit,
    ValidationExitKind, ValidationFlightRecorderRef, ValidationProofCacheReuseEvidence,
    ValidationProofCoalescerEvidence, ValidationProofStatus, flight_recorder_reason_codes,
};
use frankenengine_node::ops::validation_proof_debt_ledger::{
    ValidationProofDebtClass, ValidationProofDebtFreshness, ValidationProofDebtState,
    build_validation_proof_debt_ledger,
};

fn ts(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .expect("fixture timestamp should be valid")
}

fn base_status(bead_id: &str) -> ValidationProofStatus {
    let mut status = ValidationProofStatus::unknown(bead_id, bead_id, ts(1_700_000_000));
    status.request_id = Some(format!("{bead_id}-request"));
    status.command_digest = Some(DigestRef::sha256(bead_id.as_bytes()));
    status
}

fn recorder(
    outcome_class: FlightRecorderAdapterOutcomeClass,
    reason_code: &str,
    freshness_expires_at: DateTime<Utc>,
) -> ValidationFlightRecorderRef {
    ValidationFlightRecorderRef {
        schema_version: "franken-node/validation-flight-recorder-ref/v1".to_string(),
        attempt_path: format!("artifacts/validation/{reason_code}.json"),
        attempt_digest: DigestRef::sha256(reason_code.as_bytes()),
        attempt_id: format!("{reason_code}-attempt"),
        generated_at: ts(1_700_000_000),
        freshness_expires_at,
        outcome_class,
        execution_mode: RchMode::Remote,
        worker_id: Some("vmi-test-worker".to_string()),
        reason_code: reason_code.to_string(),
    }
}

fn receipt_paths(bead_id: &str) -> ProofArtifactPaths {
    ProofArtifactPaths {
        stdout_path: format!("artifacts/validation/{bead_id}.stdout.txt"),
        stderr_path: format!("artifacts/validation/{bead_id}.stderr.txt"),
        summary_path: format!("artifacts/validation/{bead_id}.summary.json"),
        receipt_path: format!("artifacts/validation/{bead_id}.receipt.json"),
    }
}

#[test]
fn retryable_worker_infra_is_not_marked_green_or_informational() {
    let generated_at = ts(1_700_000_100);
    let mut status = base_status("bd-worker");
    status.status = ProofStatusKind::Failed;
    status.proof_source = ProofEvidenceSource::FreshExecution;
    status.artifact_paths = Some(receipt_paths("bd-worker"));
    status.exit = Some(ValidationExit {
        kind: ValidationExitKind::Timeout,
        code: None,
        signal: None,
        timeout_class: TimeoutClass::SshCommand,
        error_class: ValidationErrorClass::TransportTimeout,
        retryable: true,
    });
    status.flight_recorder_ref = Some(recorder(
        FlightRecorderAdapterOutcomeClass::WorkerTimeout,
        flight_recorder_reason_codes::RETRY_SSH_TIMEOUT,
        ts(1_700_000_200),
    ));

    let ledger = build_validation_proof_debt_ledger(&[status], generated_at, ["bd-worker"]);

    assert_eq!(ledger.summary.total_entries, 1);
    let entry = ledger
        .entries
        .first()
        .expect("worker infra entry should be present");
    assert_eq!(entry.debt_class, ValidationProofDebtClass::WorkerInfra);
    assert_eq!(entry.debt_state, ValidationProofDebtState::Retryable);
    assert!(entry.retryable);
    assert!(!entry.product_failure);
    assert!(entry.blocks_other_bead);
    assert_eq!(entry.required_action, "retry_remote");
    assert_eq!(entry.freshness, ValidationProofDebtFreshness::Fresh);
}

#[test]
fn product_failures_and_retryable_infra_have_different_debt_states() {
    let generated_at = ts(1_700_000_100);
    let mut product = base_status("bd-product");
    product.status = ProofStatusKind::Failed;
    product.proof_source = ProofEvidenceSource::FreshExecution;
    product.exit = Some(ValidationExit {
        kind: ValidationExitKind::Failed,
        code: Some(101),
        signal: None,
        timeout_class: TimeoutClass::None,
        error_class: ValidationErrorClass::CompileError,
        retryable: false,
    });
    product.flight_recorder_ref = Some(recorder(
        FlightRecorderAdapterOutcomeClass::CompileFailed,
        flight_recorder_reason_codes::PRODUCT_FAILURE,
        ts(1_700_000_090),
    ));

    let mut worker = base_status("bd-worker");
    worker.status = ProofStatusKind::Failed;
    worker.exit = Some(ValidationExit {
        kind: ValidationExitKind::Failed,
        code: None,
        signal: None,
        timeout_class: TimeoutClass::WorkerUnreachable,
        error_class: ValidationErrorClass::WorkerInfra,
        retryable: true,
    });

    let ledger =
        build_validation_proof_debt_ledger(&[worker, product], generated_at, Vec::<String>::new());

    assert_eq!(ledger.summary.product_failures, 1);
    assert_eq!(ledger.summary.retryable_entries, 1);
    assert_eq!(ledger.summary.stale_entries, 1);
    let product_entry = ledger
        .entries
        .first()
        .expect("product failure entry should be present");
    let worker_entry = ledger
        .entries
        .get(1)
        .expect("worker infra entry should be present");
    assert_eq!(product_entry.bead_id, "bd-product");
    assert_eq!(
        product_entry.debt_class,
        ValidationProofDebtClass::ProductFailure
    );
    assert_eq!(product_entry.debt_state, ValidationProofDebtState::Blocked);
    assert_eq!(worker_entry.bead_id, "bd-worker");
    assert_eq!(
        worker_entry.debt_class,
        ValidationProofDebtClass::WorkerInfra
    );
    assert_eq!(worker_entry.debt_state, ValidationProofDebtState::Retryable);
}

#[test]
fn source_cache_stale_lease_and_capacity_entries_stay_distinct_and_stable() {
    let generated_at = ts(1_700_000_100);
    let mut source_only = base_status("bd-source");
    source_only.status = ProofStatusKind::SourceOnly;
    source_only.proof_source = ProofEvidenceSource::SourceOnlyFallback;
    source_only.reason = Some("source_only fallback until remote proof is available".to_string());

    let mut sibling_blocker = base_status("bd-sibling");
    sibling_blocker.status = ProofStatusKind::Failed;
    sibling_blocker.proof_source = ProofEvidenceSource::FreshExecution;
    sibling_blocker.reason = Some("sibling_dependency_blocker from franken_engine".to_string());

    let mut cache = base_status("bd-cache");
    cache.status = ProofStatusKind::Reused;
    cache.proof_source = ProofEvidenceSource::ProofCacheHit;
    cache.proof_cache = Some(ValidationProofCacheReuseEvidence {
        decision_id: "cache-decision".to_string(),
        cache_key_hex: "c".repeat(64),
        entry_id: "cache-entry".to_string(),
        entry_path: "artifacts/cache/entry.json".to_string(),
        receipt_id: "receipt-cache".to_string(),
        receipt_path: "artifacts/cache/receipt.json".to_string(),
        reason_code: flight_recorder_reason_codes::REUSE_RECEIPT.to_string(),
        event_code: "VFR-011".to_string(),
        required_action: "reuse_receipt".to_string(),
        diagnostic: "proof cache reused a completed receipt".to_string(),
    });

    let mut stale_lease = base_status("bd-stale");
    stale_lease.status = ProofStatusKind::Running;
    stale_lease.proof_source = ProofEvidenceSource::CoalescedInflight;
    stale_lease.deduplicated = true;
    stale_lease.proof_coalescer = Some(ValidationProofCoalescerEvidence {
        decision_id: "stale-decision".to_string(),
        proof_work_key_hex: "a".repeat(64),
        lease_id: "lease-stale".to_string(),
        lease_path: "artifacts/coalescer/lease-stale.json".to_string(),
        lease_state: "stale".to_string(),
        producer_agent: "BlueLake".to_string(),
        producer_bead_id: "bd-producer".to_string(),
        waiter_agent: Some("CyanHorizon".to_string()),
        trace_id: "trace-stale".to_string(),
        receipt_id: None,
        receipt_path: None,
        proof_cache_key_hex: "b".repeat(64),
        reason_code: flight_recorder_reason_codes::STALE_LEASE_FENCE.to_string(),
        event_code: "VFR-010".to_string(),
        required_action: "refresh_lease_fence".to_string(),
        diagnostic: "stale lease should be fenced before retry".to_string(),
    });

    let mut capacity = base_status("bd-capacity");
    capacity.status = ProofStatusKind::Queued;
    capacity.queue_state = Some(QueueState::Queued);
    capacity.queue_depth = 8;
    capacity.reason = Some("wait_for_capacity due to remote queue".to_string());

    let first = build_validation_proof_debt_ledger(
        &[
            stale_lease.clone(),
            cache.clone(),
            capacity.clone(),
            source_only.clone(),
            sibling_blocker.clone(),
        ],
        generated_at,
        ["bd-stale", "bd-capacity"],
    );
    let second = build_validation_proof_debt_ledger(
        &[source_only, capacity, sibling_blocker, cache, stale_lease],
        generated_at,
        ["bd-capacity", "bd-stale"],
    );

    assert_eq!(
        serde_json::to_string(&first).expect("ledger should serialize"),
        serde_json::to_string(&second).expect("ledger should serialize")
    );
    assert_eq!(first.summary.total_entries, 5);
    assert_eq!(first.summary.proof_cache_reuses, 1);
    assert_eq!(first.summary.source_only_fallbacks, 1);
    assert_eq!(first.summary.entries_blocking_other_beads, 2);
    assert_eq!(
        first
            .entries
            .iter()
            .map(|entry| entry.debt_class)
            .collect::<Vec<_>>(),
        vec![
            ValidationProofDebtClass::ProofCacheReuse,
            ValidationProofDebtClass::SiblingDependencyBlocker,
            ValidationProofDebtClass::SourceOnlyFallback,
            ValidationProofDebtClass::StaleLease,
            ValidationProofDebtClass::WaitingForCapacity,
        ]
    );
    let stale = first
        .entries
        .iter()
        .find(|entry| entry.debt_class == ValidationProofDebtClass::StaleLease)
        .expect("stale lease entry should be present");
    assert_eq!(stale.owner_agent.as_deref(), Some("BlueLake"));
    assert_eq!(stale.required_action, "refresh_lease_fence");
}
