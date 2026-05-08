//! Test validation readiness flight recorder functionality

use chrono::{DateTime, Utc};
use frankenengine_node::ops::validation_broker::{
    ProofStatusKind, ValidationExitKind, ValidationFlightRecorderRef, ValidationProofStatus,
    ValidationReceipt, RchMode, ValidationExitCode,
};
use frankenengine_node::ops::validation_readiness::{
    summarize_validation_readiness_report, ValidationReadinessInput,
    FailedAttemptSummary, RecoveryPlanSummary,
};
use std::collections::BTreeMap;

#[test]
fn test_flight_recorder_refs_count() {
    let now = Utc::now();

    // Create proof status with flight recorder ref
    let flight_ref = ValidationFlightRecorderRef {
        attempt_path: Some("/tmp/flight_rec_123.json".to_string()),
        attempt_digest: Some("bead-123".to_string()),
        outcome_class: "execution_failure".to_string(),
        execution_mode: "remote".to_string(),
        worker_id: Some("worker-001".to_string()),
        reason_code: "RCH_BUILD_FAILURE".to_string(),
    };

    let proof_status = ValidationProofStatus {
        proof_kind: "cargo_test".to_string(),
        status: ProofStatusKind::Failed,
        flight_recorder_ref: Some(flight_ref.clone()),
        timing: frankenengine_node::ops::validation_broker::ValidationTimingSnapshot {
            started_at: now,
            finished_at: now,
        },
        exit: Some(frankenengine_node::ops::validation_broker::ValidationExit {
            kind: ValidationExitKind::ProcessExit,
            code: ValidationExitCode::NonZero(1),
            signal: None,
            description: "Build failed".to_string(),
        }),
        proof_source: frankenengine_node::ops::validation_broker::ProofEvidenceSource::Fresh,
        proof_cache: None,
        rch: frankenengine_node::ops::validation_broker::RchSnapshot {
            mode: RchMode::Remote,
            worker_id: Some("worker-001".to_string()),
        },
    };

    let input = ValidationReadinessInput {
        schema_version: "test".to_string(),
        tracked_beads: vec![],
        proof_statuses: vec![proof_status],
        receipts: vec![],
        rch_workers: vec![],
        proof_lane_readiness: vec![],
        resource_governor: None,
        max_receipt_age_secs: 3600,
    };

    let report = summarize_validation_readiness_report(
        &input,
        "test_command".to_string(),
        "test_trace".to_string(),
        now,
    );

    // Verify flight recorder refs count
    assert_eq!(report.summary.flight_recorder_refs, 1);

    // Verify failed attempt details
    assert_eq!(report.summary.failed_attempt_details.len(), 1);
    let failed_attempt = &report.summary.failed_attempt_details[0];
    assert_eq!(failed_attempt.bead_id, "bead-123");
    assert_eq!(failed_attempt.thread_id, "cargo_test");
    assert_eq!(failed_attempt.flight_recorder_path, Some("/tmp/flight_rec_123.json".to_string()));
    assert_eq!(failed_attempt.outcome_class, "execution_failure");
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
    let flight_ref = ValidationFlightRecorderRef {
        attempt_path: Some("/tmp/flight_rec_456.json".to_string()),
        attempt_digest: Some("bead-456".to_string()),
        outcome_class: "resource_exhaustion".to_string(),
        execution_mode: "local".to_string(),
        worker_id: None,
        reason_code: "DISK_FULL".to_string(),
    };

    let receipt = ValidationReceipt {
        proof_kind: "cargo_build".to_string(),
        flight_recorder_ref: Some(flight_ref.clone()),
        timing: frankenengine_node::ops::validation_broker::ValidationTimingSnapshot {
            started_at: now,
            finished_at: now,
        },
        exit: frankenengine_node::ops::validation_broker::ValidationExit {
            kind: ValidationExitKind::ProcessExit,
            code: ValidationExitCode::NonZero(1),
            signal: None,
            description: "Disk full".to_string(),
        },
        rch: frankenengine_node::ops::validation_broker::RchSnapshot {
            mode: RchMode::Local,
            worker_id: None,
        },
        evidence_digest: "evidence_456".to_string(),
        validation_digest: "validation_456".to_string(),
        command_line: vec!["cargo".to_string(), "build".to_string()],
        dependencies: BTreeMap::new(),
        toolchain: frankenengine_node::ops::validation_broker::ToolchainSnapshot {
            rust_version: "1.80.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            channel: "stable".to_string(),
            host_triple: "x86_64-unknown-linux-gnu".to_string(),
            commit_hash: Some("abc123".to_string()),
            commit_date: Some("2024-07-25".to_string()),
        },
    };

    let input = ValidationReadinessInput {
        schema_version: "test".to_string(),
        tracked_beads: vec![],
        proof_statuses: vec![],
        receipts: vec![receipt],
        rch_workers: vec![],
        proof_lane_readiness: vec![],
        resource_governor: None,
        max_receipt_age_secs: 3600,
    };

    let report = summarize_validation_readiness_report(
        &input,
        "test_command".to_string(),
        "test_trace".to_string(),
        now,
    );

    // Verify flight recorder refs count
    assert_eq!(report.summary.flight_recorder_refs, 1);

    // Verify failed attempt details
    assert_eq!(report.summary.failed_attempt_details.len(), 1);
    let failed_attempt = &report.summary.failed_attempt_details[0];
    assert_eq!(failed_attempt.bead_id, "bead-456");
    assert_eq!(failed_attempt.thread_id, "cargo_build");
    assert_eq!(failed_attempt.flight_recorder_path, Some("/tmp/flight_rec_456.json".to_string()));
    assert_eq!(failed_attempt.outcome_class, "resource_exhaustion");
    assert_eq!(failed_attempt.execution_mode, "local");
    assert_eq!(failed_attempt.worker_id, None);
    assert_eq!(failed_attempt.reason_code, "DISK_FULL");
    assert!(!failed_attempt.product_failure); // Resource failure
}

#[test]
fn test_no_flight_recorder_refs() {
    let now = Utc::now();

    // Create proof status without flight recorder ref
    let proof_status = ValidationProofStatus {
        proof_kind: "cargo_test".to_string(),
        status: ProofStatusKind::Passed,
        flight_recorder_ref: None,
        timing: frankenengine_node::ops::validation_broker::ValidationTimingSnapshot {
            started_at: now,
            finished_at: now,
        },
        exit: Some(frankenengine_node::ops::validation_broker::ValidationExit {
            kind: ValidationExitKind::ProcessExit,
            code: ValidationExitCode::Zero,
            signal: None,
            description: "Success".to_string(),
        }),
        proof_source: frankenengine_node::ops::validation_broker::ProofEvidenceSource::Fresh,
        proof_cache: None,
        rch: frankenengine_node::ops::validation_broker::RchSnapshot {
            mode: RchMode::Local,
            worker_id: None,
        },
    };

    let input = ValidationReadinessInput {
        schema_version: "test".to_string(),
        tracked_beads: vec![],
        proof_statuses: vec![proof_status],
        receipts: vec![],
        rch_workers: vec![],
        proof_lane_readiness: vec![],
        resource_governor: None,
        max_receipt_age_secs: 3600,
    };

    let report = summarize_validation_readiness_report(
        &input,
        "test_command".to_string(),
        "test_trace".to_string(),
        now,
    );

    // Verify no flight recorder refs
    assert_eq!(report.summary.flight_recorder_refs, 0);
    assert_eq!(report.summary.failed_attempt_details.len(), 0);
    assert_eq!(report.summary.pending_recoveries.len(), 0);
}