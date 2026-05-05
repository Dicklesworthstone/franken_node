use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, FallbackPolicy, InputDigest, InputSet, OutputPolicy,
    ProofStatusKind, QueueState, RECEIPT_SCHEMA_VERSION, RchMode, RchReceipt, ReceiptArtifacts,
    ReceiptClassifications, ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy,
    TimeoutClass, ValidationBrokerError, ValidationBrokerQueue, ValidationBrokerRequest,
    ValidationErrorClass, ValidationExit, ValidationExitKind, ValidationPriority,
    ValidationProofStatus, ValidationReceipt, ValidationTiming, WorkerRequirements, error_codes,
    render_validation_proof_status_json, write_validation_receipt_at,
};
use tempfile::TempDir;

fn ts(seconds: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, seconds)
        .single()
        .expect("valid timestamp")
}

fn command() -> CommandSpec {
    CommandSpec {
        program: "cargo".to_string(),
        argv: vec![
            "+nightly-2026-02-19".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "frankenengine-node".to_string(),
            "--test".to_string(),
            "validation_broker".to_string(),
        ],
        cwd: "/data/projects/franken_node".to_string(),
        environment_policy_id: "validation-broker/env-policy/v1".to_string(),
        target_dir_policy_id: "validation-broker/target-dir/off-repo/v1".to_string(),
    }
}

fn inputs() -> InputSet {
    InputSet {
        git_commit: "af6e4745".to_string(),
        dirty_worktree: false,
        changed_paths: vec!["crates/franken-node/src/ops/validation_broker.rs".to_string()],
        content_digests: vec![InputDigest::new(
            "crates/franken-node/src/ops/validation_broker.rs",
            b"validation-broker-module",
            "git-or-worktree",
        )],
        feature_flags: vec!["default".to_string()],
    }
}

fn request() -> ValidationBrokerRequest {
    ValidationBrokerRequest::new(
        "vbreq-bd-6efmv-1",
        "bd-6efmv",
        "bd-6efmv",
        "PinkFern",
        ts(0),
        ValidationPriority::High,
        command(),
        inputs(),
        OutputPolicy {
            stdout_path: "artifacts/validation_broker/bd-6efmv/stdout.txt".to_string(),
            stderr_path: "artifacts/validation_broker/bd-6efmv/stderr.txt".to_string(),
            summary_path: "artifacts/validation_broker/bd-6efmv/summary.md".to_string(),
            receipt_path: "artifacts/validation_broker/bd-6efmv/receipt.json".to_string(),
            retention: "keep-with-bead".to_string(),
        },
        FallbackPolicy {
            source_only_allowed: true,
            allowed_reasons: vec![SourceOnlyReason::CargoContention],
        },
    )
}

fn worker_requirements() -> WorkerRequirements {
    WorkerRequirements {
        require_rch_remote: true,
        cargo_toolchain: "nightly-2026-02-19".to_string(),
        feature_flags: vec!["default".to_string()],
        max_wall_time_ms: 1_800_000,
    }
}

fn receipt() -> ValidationReceipt {
    let req = request();
    ValidationReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: "vbrcpt-bd-6efmv-1".to_string(),
        request_id: req.request_id.clone(),
        bead_id: req.bead_id.clone(),
        thread_id: req.thread_id.clone(),
        request_ref: ReceiptRequestRef {
            request_id: req.request_id.clone(),
            bead_id: req.bead_id.clone(),
            thread_id: req.thread_id.clone(),
            dedupe_key: DigestRef {
                algorithm: req.dedupe_key.algorithm.clone(),
                hex: req.dedupe_key.hex.clone(),
            },
            cross_thread_waiver: None,
        },
        command_digest: req.command.digest(),
        command: req.command.clone(),
        environment_policy: EnvironmentPolicy {
            policy_id: req.command.environment_policy_id.clone(),
            allowed_env: vec![
                "RCH_REQUIRE_REMOTE".to_string(),
                "CARGO_TARGET_DIR".to_string(),
            ],
            redacted_env: Vec::new(),
            remote_required: true,
            network_policy: "rch-only".to_string(),
        },
        target_dir_policy: TargetDirPolicy {
            policy_id: req.command.target_dir_policy_id.clone(),
            kind: "off_repo".to_string(),
            path: "/data/tmp/franken_node-pinkfern-bd-6efmv-target".to_string(),
            path_digest: DigestRef::sha256(b"/data/tmp/franken_node-pinkfern-bd-6efmv-target"),
            cleanup: "best_effort_after_receipt".to_string(),
        },
        input_digests: req.inputs.content_digests.clone(),
        rch: RchReceipt {
            mode: RchMode::Remote,
            worker_id: Some("ts2".to_string()),
            require_remote: true,
            capability_observation_id: Some("vbobs-ts2".to_string()),
            worker_pool: "default".to_string(),
        },
        timing: ValidationTiming {
            started_at: ts(1),
            finished_at: ts(2),
            duration_ms: 1_000,
            freshness_expires_at: ts(10),
        },
        exit: ValidationExit {
            kind: ValidationExitKind::Success,
            code: Some(0),
            signal: None,
            timeout_class: TimeoutClass::None,
            error_class: ValidationErrorClass::None,
            retryable: false,
        },
        artifacts: ReceiptArtifacts {
            stdout_path: "artifacts/validation_broker/bd-6efmv/stdout.txt".to_string(),
            stderr_path: "artifacts/validation_broker/bd-6efmv/stderr.txt".to_string(),
            summary_path: "artifacts/validation_broker/bd-6efmv/summary.md".to_string(),
            receipt_path: "artifacts/validation_broker/bd-6efmv/receipt.json".to_string(),
            stdout_digest: DigestRef::sha256(b"stdout"),
            stderr_digest: DigestRef::sha256(b"stderr"),
        },
        trust: ReceiptTrust {
            generated_by: "validation-broker".to_string(),
            agent_name: "PinkFern".to_string(),
            git_commit: "af6e4745".to_string(),
            dirty_worktree: false,
            freshness: "fresh".to_string(),
            signature_status: "unsigned-test".to_string(),
        },
        classifications: ReceiptClassifications {
            source_only_fallback: false,
            source_only_reason: None,
            doctor_readiness: "ready".to_string(),
            ci_consumable: true,
        },
    }
}

#[test]
fn queue_dedupes_leases_expires_and_renders_status_json() -> Result<(), ValidationBrokerError> {
    let mut queue = ValidationBrokerQueue::new(4);
    let first = queue.enqueue(request(), worker_requirements(), ts(0))?;
    let duplicate = queue.enqueue(request(), worker_requirements(), ts(1))?;

    assert!(!first.deduplicated);
    assert!(duplicate.deduplicated);
    assert_eq!(first.queue_id, duplicate.queue_id);
    assert_eq!(queue.queue_depth(), 1);

    let queued = queue.proof_status_for("bd-6efmv", "bd-6efmv", ts(1));
    assert_eq!(queued.status, ProofStatusKind::Queued);
    assert_eq!(queued.queue_state, Some(QueueState::Queued));
    assert!(render_validation_proof_status_json(&queued)?.contains("\"status\": \"queued\""));

    let leased = queue.lease_next("PinkFern", ts(2), 1_000)?;
    assert!(leased.is_some());
    queue.mark_running(&first.queue_id)?;
    assert_eq!(
        queue.proof_status_for("bd-6efmv", "bd-6efmv", ts(2)).status,
        ProofStatusKind::Running
    );

    assert_eq!(queue.expire_stale_leases(ts(4)), 1);
    let failed = queue.proof_status_for("bd-6efmv", "bd-6efmv", ts(4));
    assert_eq!(failed.status, ProofStatusKind::Failed);
    Ok(())
}

#[test]
fn receipt_writer_round_trips_and_status_reports_passed() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = TempDir::new()?;
    let path = dir.path().join("receipt.json");
    let receipt = receipt();

    write_validation_receipt_at(&path, &receipt, ts(3))?;

    let raw = std::fs::read_to_string(&path)?;
    let parsed: ValidationReceipt = serde_json::from_str(&raw)?;
    let status = ValidationProofStatus::from_receipt(&parsed, ts(3))?;
    let status_json = render_validation_proof_status_json(&status)?;

    assert_eq!(status.status, ProofStatusKind::Passed);
    assert!(status_json.contains("\"status\": \"passed\""));
    assert!(status_json.contains("artifacts/validation_broker/bd-6efmv/stdout.txt"));
    Ok(())
}

#[test]
fn malformed_receipts_fail_closed() {
    let stale = receipt();
    let stale_error = stale.validate_at(ts(11)).expect_err("stale receipt");
    assert!(matches!(
        stale_error,
        ValidationBrokerError::ContractViolation {
            code: error_codes::ERR_VB_STALE_RECEIPT,
            ..
        }
    ));

    let mut timeout = receipt();
    timeout.exit.kind = ValidationExitKind::Timeout;
    timeout.exit.error_class = ValidationErrorClass::TransportTimeout;
    timeout.exit.timeout_class = TimeoutClass::None;
    let timeout_error = timeout
        .validate_at(ts(3))
        .expect_err("unclassified timeout");
    assert!(matches!(
        timeout_error,
        ValidationBrokerError::ContractViolation {
            code: error_codes::ERR_VB_INVALID_TIMEOUT_CLASS,
            ..
        }
    ));

    let mut source_only = receipt();
    source_only.exit.kind = ValidationExitKind::SourceOnly;
    source_only.exit.error_class = ValidationErrorClass::SourceOnly;
    source_only.classifications.source_only_fallback = true;
    source_only.classifications.source_only_reason = None;
    let source_only_error = source_only
        .validate_at(ts(3))
        .expect_err("source-only reason is required");
    assert!(matches!(
        source_only_error,
        ValidationBrokerError::ContractViolation {
            code: error_codes::ERR_VB_UNDECLARED_SOURCE_ONLY,
            ..
        }
    ));
}
