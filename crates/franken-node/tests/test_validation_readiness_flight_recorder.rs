//! Test validation readiness flight recorder functionality

use chrono::{DateTime, Duration, Utc};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, FlightRecorderAdapterOutcomeClass, InputDigest,
    ProofStatusKind, RchMode, RchReceipt, ReceiptArtifacts, ReceiptClassifications,
    ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy, TimeoutClass,
    ValidationErrorClass, ValidationExit, ValidationExitKind, ValidationFlightRecorderRef,
    ValidationProofStatus, ValidationReceipt, ValidationTiming,
};
use frankenengine_node::ops::validation_readiness::{
    ValidationReadinessInput, build_validation_readiness_report,
};

fn flight_ref(
    path: &str,
    reason_code: &str,
    outcome_class: FlightRecorderAdapterOutcomeClass,
    execution_mode: RchMode,
    worker_id: Option<&str>,
    now: DateTime<Utc>,
) -> ValidationFlightRecorderRef {
    ValidationFlightRecorderRef {
        schema_version: "franken-node/validation-flight-recorder-ref/v1".to_string(),
        attempt_path: path.to_string(),
        attempt_digest: DigestRef::sha256(reason_code.as_bytes()),
        attempt_id: format!("{reason_code}-attempt"),
        generated_at: now,
        freshness_expires_at: now + Duration::hours(1),
        outcome_class,
        execution_mode,
        worker_id: worker_id.map(str::to_string),
        reason_code: reason_code.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn proof_status(
    bead_id: &str,
    thread_id: &str,
    status: ProofStatusKind,
    flight_recorder_ref: Option<ValidationFlightRecorderRef>,
    exit: Option<ValidationExit>,
    reason: Option<&str>,
    now: DateTime<Utc>,
) -> ValidationProofStatus {
    ValidationProofStatus {
        schema_version: "franken-node/validation-broker/status/v1".to_string(),
        bead_id: bead_id.to_string(),
        thread_id: thread_id.to_string(),
        request_id: Some(format!("{bead_id}-request")),
        queue_id: None,
        status,
        proof_source:
            frankenengine_node::ops::validation_broker::ProofEvidenceSource::FreshExecution,
        queue_state: None,
        deduplicated: false,
        queue_depth: 0,
        artifact_paths: None,
        command_digest: Some(DigestRef::sha256(
            format!("{bead_id}/{thread_id}").as_bytes(),
        )),
        exit,
        reason: reason.map(str::to_string),
        proof_coalescer: None,
        proof_cache: None,
        readiness_ref: None,
        flight_recorder_ref,
        observed_at: now,
    }
}

fn failed_exit(
    kind: ValidationExitKind,
    code: Option<i32>,
    timeout_class: TimeoutClass,
    error_class: ValidationErrorClass,
    retryable: bool,
) -> ValidationExit {
    ValidationExit {
        kind,
        code,
        signal: None,
        timeout_class,
        error_class,
        retryable,
    }
}

#[test]
fn test_flight_recorder_refs_count() {
    let now = Utc::now();

    // Create proof status with flight recorder ref
    let flight_ref = flight_ref(
        "/tmp/flight_rec_123.json",
        "RCH_BUILD_FAILURE",
        FlightRecorderAdapterOutcomeClass::WorkerTimeout,
        RchMode::Remote,
        Some("worker-001"),
        now,
    );

    let proof_status = proof_status(
        "bead-123",
        "cargo_test",
        ProofStatusKind::Failed,
        Some(flight_ref),
        Some(failed_exit(
            ValidationExitKind::Timeout,
            Some(1),
            TimeoutClass::WorkerUnreachable,
            ValidationErrorClass::WorkerInfra,
            true,
        )),
        Some("build failed"),
        now,
    );

    let input = ValidationReadinessInput {
        schema_version: "test".to_string(),
        tracked_beads: vec![],
        proof_statuses: vec![proof_status],
        receipts: vec![],
        rch_workers: vec![],
        proof_lane_readiness: vec![],
        swarm_scheduler_decisions: vec![],
        swarm_admission_decisions: vec![],
        resource_governor: None,
        max_receipt_age_secs: 3600,
    };

    let report = build_validation_readiness_report(&input, "test_trace".to_string(), now);

    // Verify flight recorder refs count
    assert_eq!(report.summary.flight_recorder_refs, 1);

    // Verify failed attempt details
    assert_eq!(report.summary.failed_attempt_details.len(), 1);
    let failed_attempt = &report.summary.failed_attempt_details[0];
    assert_eq!(failed_attempt.bead_id, "bead-123");
    assert_eq!(failed_attempt.thread_id, "cargo_test");
    assert_eq!(
        failed_attempt.flight_recorder_path,
        Some("/tmp/flight_rec_123.json".to_string())
    );
    assert_eq!(failed_attempt.outcome_class, "worker_timeout");
    assert_eq!(failed_attempt.execution_mode, "remote");
    assert_eq!(failed_attempt.worker_id, Some("worker-001".to_string()));
    assert_eq!(failed_attempt.reason_code, "RCH_BUILD_FAILURE");
    assert!(failed_attempt.retryable); // Should be retryable for RCH failures
    assert!(!failed_attempt.product_failure); // Worker failure, not product

    // Verify pending recoveries
    assert_eq!(report.summary.pending_recoveries.len(), 1);
    let recovery = &report.summary.pending_recoveries[0];
    assert_eq!(recovery.bead_id, "bead-123");
    assert_eq!(recovery.thread_id, "cargo_test");
    assert!(recovery.action.contains("Retry")); // Should be some form of retry action
}

#[test]
fn test_flight_recorder_refs_from_receipts() {
    let now = Utc::now();

    // Create receipt with flight recorder ref
    let flight_ref = flight_ref(
        "/tmp/flight_rec_456.json",
        "DISK_FULL",
        FlightRecorderAdapterOutcomeClass::WorkerFilesystemError,
        RchMode::LocalFallback,
        None,
        now,
    );
    let command = CommandSpec {
        program: "cargo".to_string(),
        argv: vec!["build".to_string()],
        cwd: "/tmp/franken-node".to_string(),
        environment_policy_id: "test-env-policy".to_string(),
        target_dir_policy_id: "test-target-policy".to_string(),
    };
    let command_digest = command.digest();
    let receipt = ValidationReceipt {
        schema_version: "franken-node/validation-broker/receipt/v1".to_string(),
        receipt_id: "receipt-bead-456".to_string(),
        request_id: "request-bead-456".to_string(),
        bead_id: "bead-456".to_string(),
        thread_id: "cargo_build".to_string(),
        request_ref: ReceiptRequestRef {
            request_id: "request-bead-456".to_string(),
            bead_id: "bead-456".to_string(),
            thread_id: "cargo_build".to_string(),
            dedupe_key: DigestRef::sha256(b"bead-456-dedupe"),
            cross_thread_waiver: None,
        },
        command,
        command_digest,
        environment_policy: EnvironmentPolicy {
            policy_id: "test-env-policy".to_string(),
            allowed_env: vec!["CARGO_TARGET_DIR".to_string()],
            redacted_env: Vec::new(),
            remote_required: false,
            network_policy: "local-test".to_string(),
        },
        target_dir_policy: TargetDirPolicy {
            policy_id: "test-target-policy".to_string(),
            kind: "off_repo".to_string(),
            path: "/tmp/franken-node-target".to_string(),
            path_digest: DigestRef::sha256(b"/tmp/franken-node-target"),
            cleanup: "test-owned".to_string(),
        },
        input_digests: vec![InputDigest::new("Cargo.toml", b"cargo", "test")],
        rch: RchReceipt {
            mode: RchMode::LocalFallback,
            worker_id: None,
            require_remote: false,
            capability_observation_id: None,
            worker_pool: "local".to_string(),
        },
        timing: ValidationTiming {
            started_at: now,
            finished_at: now,
            duration_ms: 0,
            freshness_expires_at: now + Duration::hours(1),
        },
        exit: failed_exit(
            ValidationExitKind::Failed,
            Some(1),
            TimeoutClass::None,
            ValidationErrorClass::DiskPressure,
            true,
        ),
        artifacts: ReceiptArtifacts {
            stdout_path: "artifacts/validation/bead-456/stdout.txt".to_string(),
            stderr_path: "artifacts/validation/bead-456/stderr.txt".to_string(),
            summary_path: "artifacts/validation/bead-456/summary.json".to_string(),
            receipt_path: "artifacts/validation/bead-456/receipt.json".to_string(),
            stdout_digest: DigestRef::sha256(b"stdout"),
            stderr_digest: DigestRef::sha256(b"stderr"),
        },
        readiness_ref: None,
        flight_recorder_ref: Some(flight_ref),
        trust: ReceiptTrust {
            generated_by: "validation-broker".to_string(),
            agent_name: "BlackMoose".to_string(),
            git_commit: "test".to_string(),
            dirty_worktree: false,
            freshness: "fresh".to_string(),
            signature_status: "unsigned-test".to_string(),
        },
        classifications: ReceiptClassifications {
            source_only_fallback: false,
            source_only_reason: None::<SourceOnlyReason>,
            doctor_readiness: "blocked".to_string(),
            ci_consumable: false,
        },
    };

    let input = ValidationReadinessInput {
        schema_version: "test".to_string(),
        tracked_beads: vec![],
        proof_statuses: vec![],
        receipts: vec![receipt],
        rch_workers: vec![],
        proof_lane_readiness: vec![],
        swarm_scheduler_decisions: vec![],
        swarm_admission_decisions: vec![],
        resource_governor: None,
        max_receipt_age_secs: 3600,
    };

    let report = build_validation_readiness_report(&input, "test_trace".to_string(), now);

    // Verify flight recorder refs count
    assert_eq!(report.summary.flight_recorder_refs, 1);

    // Verify failed attempt details
    assert_eq!(report.summary.failed_attempt_details.len(), 1);
    let failed_attempt = &report.summary.failed_attempt_details[0];
    assert_eq!(failed_attempt.bead_id, "bead-456");
    assert_eq!(failed_attempt.thread_id, "cargo_build");
    assert_eq!(
        failed_attempt.flight_recorder_path,
        Some("/tmp/flight_rec_456.json".to_string())
    );
    assert_eq!(failed_attempt.outcome_class, "worker_filesystem_error");
    assert_eq!(failed_attempt.execution_mode, "local_fallback");
    assert_eq!(failed_attempt.worker_id, None);
    assert_eq!(failed_attempt.reason_code, "DISK_FULL");
    assert!(!failed_attempt.product_failure); // Resource failure
}

#[test]
fn test_no_flight_recorder_refs() {
    let now = Utc::now();

    // Create proof status without flight recorder ref
    let proof_status = proof_status(
        "bead-789",
        "cargo_test",
        ProofStatusKind::Passed,
        None,
        Some(failed_exit(
            ValidationExitKind::Success,
            Some(0),
            TimeoutClass::None,
            ValidationErrorClass::None,
            false,
        )),
        Some("success"),
        now,
    );

    let input = ValidationReadinessInput {
        schema_version: "test".to_string(),
        tracked_beads: vec![],
        proof_statuses: vec![proof_status],
        receipts: vec![],
        rch_workers: vec![],
        proof_lane_readiness: vec![],
        swarm_scheduler_decisions: vec![],
        swarm_admission_decisions: vec![],
        resource_governor: None,
        max_receipt_age_secs: 3600,
    };

    let report = build_validation_readiness_report(&input, "test_trace".to_string(), now);

    // Verify no flight recorder refs
    assert_eq!(report.summary.flight_recorder_refs, 0);
    assert_eq!(report.summary.failed_attempt_details.len(), 0);
    assert_eq!(report.summary.pending_recoveries.len(), 0);
}
