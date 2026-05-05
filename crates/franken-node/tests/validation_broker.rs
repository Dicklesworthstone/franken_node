use chrono::{DateTime, Duration, TimeZone, Utc};
use frankenengine_node::ops::rch_adapter::{
    RchCommandOutput, RchCommandPolicy, RchExecutionMode, RchInvocation, RchOutcomeClass,
    RchProcessSnapshot, RchTimeoutClass, RchValidationAction, classify_rch_output,
};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, FallbackPolicy, InputDigest, InputSet, OutputPolicy,
    ProofStatusKind, QueueState, RECEIPT_SCHEMA_VERSION, RchMode, RchReceipt, ReceiptArtifacts,
    ReceiptClassifications, ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy,
    TimeoutClass, ValidationBrokerError, ValidationBrokerQueue, ValidationBrokerRequest,
    ValidationErrorClass, ValidationExit, ValidationExitKind, ValidationPriority,
    ValidationProofStatus, ValidationReceipt, ValidationTiming, WorkerRequirements, error_codes,
    render_validation_proof_status_json, write_validation_receipt_at,
};
use frankenengine_node::ops::validation_closeout::{
    ValidationCloseoutOptions, ValidationCloseoutStatus, build_validation_closeout_report,
};
use frankenengine_node::ops::validation_readiness::{
    RchWorkerReadiness, ResourceContentionSnapshot, TrackedValidationBead, ValidationBeadState,
    ValidationReadinessInput, ValidationReadinessStatus, build_validation_readiness_report,
};
use frankenengine_node::runtime::resource_governor::{
    ObservedValidationProcess, ResourceGovernorDecisionKind, ResourceGovernorObservation,
    ResourceGovernorRequest, ResourceGovernorThresholds, evaluate_resource_governor,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::process::Command as ProcessCommand;
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

fn artifact_path(bead_id: &str, file_name: &str) -> String {
    format!("artifacts/validation_broker/{bead_id}/{file_name}")
}

fn request_for_bead_at(bead_id: &str, created_at: DateTime<Utc>) -> ValidationBrokerRequest {
    ValidationBrokerRequest::new(
        format!("vbreq-{bead_id}-1"),
        bead_id,
        bead_id,
        "RusticPlateau",
        created_at,
        ValidationPriority::High,
        command(),
        inputs(),
        OutputPolicy {
            stdout_path: artifact_path(bead_id, "stdout.txt"),
            stderr_path: artifact_path(bead_id, "stderr.txt"),
            summary_path: artifact_path(bead_id, "summary.md"),
            receipt_path: artifact_path(bead_id, "receipt.json"),
            retention: "keep-with-bead".to_string(),
        },
        FallbackPolicy {
            source_only_allowed: true,
            allowed_reasons: vec![SourceOnlyReason::CargoContention],
        },
    )
}

fn request() -> ValidationBrokerRequest {
    request_for_bead_at("bd-6efmv", ts(0))
}

fn worker_requirements() -> WorkerRequirements {
    WorkerRequirements {
        require_rch_remote: true,
        cargo_toolchain: "nightly-2026-02-19".to_string(),
        feature_flags: vec!["default".to_string()],
        max_wall_time_ms: 1_800_000,
    }
}

#[allow(clippy::too_many_arguments)]
fn receipt_for_bead(
    bead_id: &str,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    freshness_expires_at: DateTime<Utc>,
    exit_kind: ValidationExitKind,
    error_class: ValidationErrorClass,
    timeout_class: TimeoutClass,
    rch_mode: RchMode,
    worker_id: Option<&str>,
    source_only_reason: Option<SourceOnlyReason>,
) -> ValidationReceipt {
    let req = request_for_bead_at(bead_id, started_at);
    let source_only_reason = if exit_kind == ValidationExitKind::SourceOnly {
        source_only_reason.or(Some(SourceOnlyReason::CargoContention))
    } else {
        source_only_reason
    };
    ValidationReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: format!("vbrcpt-{bead_id}-1"),
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
            path: format!("/data/tmp/franken_node-rusticplateau-{bead_id}-target"),
            path_digest: DigestRef::sha256(
                format!("/data/tmp/franken_node-rusticplateau-{bead_id}-target").as_bytes(),
            ),
            cleanup: "best_effort_after_receipt".to_string(),
        },
        input_digests: req.inputs.content_digests.clone(),
        rch: RchReceipt {
            mode: rch_mode,
            worker_id: worker_id.map(ToOwned::to_owned),
            require_remote: true,
            capability_observation_id: worker_id.map(|id| format!("vbobs-{id}")),
            worker_pool: "default".to_string(),
        },
        timing: ValidationTiming {
            started_at,
            finished_at,
            duration_ms: u64::try_from(
                finished_at
                    .signed_duration_since(started_at)
                    .num_milliseconds()
                    .max(0),
            )
            .unwrap_or(u64::MAX),
            freshness_expires_at,
        },
        exit: ValidationExit {
            kind: exit_kind,
            code: match exit_kind {
                ValidationExitKind::Success | ValidationExitKind::SourceOnly => Some(0),
                ValidationExitKind::Failed | ValidationExitKind::Timeout => Some(101),
                ValidationExitKind::Cancelled => None,
            },
            signal: None,
            timeout_class,
            error_class,
            retryable: matches!(
                error_class,
                ValidationErrorClass::TransportTimeout
                    | ValidationErrorClass::WorkerInfra
                    | ValidationErrorClass::EnvironmentContention
                    | ValidationErrorClass::DiskPressure
            ),
        },
        artifacts: ReceiptArtifacts {
            stdout_path: req.output_policy.stdout_path.clone(),
            stderr_path: req.output_policy.stderr_path.clone(),
            summary_path: req.output_policy.summary_path.clone(),
            receipt_path: req.output_policy.receipt_path.clone(),
            stdout_digest: DigestRef::sha256(b"stdout"),
            stderr_digest: DigestRef::sha256(b"stderr"),
        },
        trust: ReceiptTrust {
            generated_by: "validation-broker".to_string(),
            agent_name: "RusticPlateau".to_string(),
            git_commit: "af6e4745".to_string(),
            dirty_worktree: false,
            freshness: "fresh".to_string(),
            signature_status: "unsigned-test".to_string(),
        },
        classifications: ReceiptClassifications {
            source_only_fallback: exit_kind == ValidationExitKind::SourceOnly,
            source_only_reason,
            doctor_readiness: if exit_kind == ValidationExitKind::Success {
                "ready"
            } else {
                "blocked"
            }
            .to_string(),
            ci_consumable: exit_kind == ValidationExitKind::Success,
        },
    }
}

fn receipt() -> ValidationReceipt {
    receipt_for_bead(
        "bd-6efmv",
        ts(1),
        ts(2),
        ts(10),
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        RchMode::Remote,
        Some("ts2"),
        None,
    )
}

fn remote_worker(worker_id: &str) -> RchWorkerReadiness {
    RchWorkerReadiness {
        worker_id: worker_id.to_string(),
        reachable: true,
        mode: RchMode::Remote,
        required_toolchains: vec!["nightly-2026-02-19".to_string()],
        observed_toolchains: vec!["nightly-2026-02-19".to_string()],
        failure: None,
    }
}

fn allow_resource_snapshot() -> ResourceContentionSnapshot {
    ResourceContentionSnapshot {
        decision: "allow".to_string(),
        reason_code: "RG_ALLOW_IDLE".to_string(),
        reason: "validation pressure is below backoff thresholds".to_string(),
        rch_queue_depth: Some(0),
        active_proof_classes: Vec::new(),
    }
}

fn rch_test_invocation(target_dir: &str) -> RchInvocation {
    let mut env = BTreeMap::new();
    env.insert("RCH_REQUIRE_REMOTE".to_string(), "1".to_string());
    env.insert("CARGO_TARGET_DIR".to_string(), target_dir.to_string());
    RchInvocation {
        argv: vec![
            "cargo".to_string(),
            "+nightly-2026-02-19".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "frankenengine-node".to_string(),
            "--test".to_string(),
            "validation_broker".to_string(),
        ],
        env,
        cwd: "/data/projects/franken_node".to_string(),
    }
}

fn validation_process(command: &str) -> ObservedValidationProcess {
    ObservedValidationProcess::new(None, command).expect("validation process should classify")
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

#[test]
fn mock_free_e2e_links_queue_receipt_readiness_closeout_and_cli()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let bead_id = "bd-tdoga";
    let artifact_root = dir
        .path()
        .join(format!("artifacts/validation_broker/{bead_id}"));
    fs::create_dir_all(&artifact_root)?;

    let stdout_rel = artifact_path(bead_id, "stdout.txt");
    let stderr_rel = artifact_path(bead_id, "stderr.txt");
    let summary_rel = artifact_path(bead_id, "summary.md");
    let receipt_rel = artifact_path(bead_id, "receipt.json");
    let readiness_rel = artifact_path(bead_id, "readiness-input.json");
    let stdout_path = dir.path().join(&stdout_rel);
    let stderr_path = dir.path().join(&stderr_rel);
    let summary_path = dir.path().join(&summary_rel);
    let receipt_path = dir.path().join(&receipt_rel);
    let readiness_path = dir.path().join(&readiness_rel);

    fs::write(
        &stdout_path,
        "[RCH] remote ts2 (1.2s)\ntest result: ok. 1 passed; 0 failed\n",
    )?;
    fs::write(&stderr_path, "validation broker e2e stderr: clean\n")?;
    fs::write(
        &summary_path,
        "trace_id=bd-tdoga-e2e\nreason_code=RCH-PASSED\nartifact_root=artifacts/validation_broker/bd-tdoga\n",
    )?;

    let now = Utc::now() - Duration::minutes(2);
    let request = request_for_bead_at(bead_id, now);
    let mut queue = ValidationBrokerQueue::new(2);
    let first = queue.enqueue(request.clone(), worker_requirements(), now)?;
    let duplicate = queue.enqueue(request, worker_requirements(), now + Duration::seconds(1))?;
    assert!(!first.deduplicated);
    assert!(duplicate.deduplicated);
    assert_eq!(first.queue_id, duplicate.queue_id);
    assert_eq!(queue.queue_depth(), 1);

    let leased = queue
        .lease_next("RusticPlateau", now + Duration::seconds(2), 30_000)?
        .expect("leased queue entry");
    assert_eq!(leased.request.bead_id, bead_id);
    queue.mark_running(&first.queue_id)?;

    let invocation = rch_test_invocation("/data/tmp/franken_node-rusticplateau-bd-tdoga-target");
    let rch_outcome = classify_rch_output(
        &invocation,
        &RchCommandOutput {
            exit_code: Some(0),
            stdout: fs::read_to_string(&stdout_path)?,
            stderr: fs::read_to_string(&stderr_path)?,
            duration_ms: 1_200,
        },
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );
    assert!(rch_outcome.is_green());
    assert_eq!(rch_outcome.action, Some(RchValidationAction::Test));
    assert_eq!(rch_outcome.execution_mode, RchExecutionMode::Remote);
    assert_eq!(rch_outcome.worker_id.as_deref(), Some("ts2"));
    queue.complete(&first.queue_id, rch_outcome.is_green())?;
    assert_eq!(
        queue
            .proof_status_for(bead_id, bead_id, now + Duration::seconds(4))
            .status,
        ProofStatusKind::Passed
    );

    let receipt = receipt_for_bead(
        bead_id,
        now,
        now + Duration::seconds(60),
        now + Duration::days(30),
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        RchMode::Remote,
        Some("ts2"),
        None,
    );
    write_validation_receipt_at(&receipt_path, &receipt, now + Duration::seconds(61))?;
    let status = ValidationProofStatus::from_receipt(&receipt, now + Duration::seconds(62))?;
    let readiness_input = ValidationReadinessInput {
        tracked_beads: vec![TrackedValidationBead::new(
            bead_id,
            ValidationBeadState::Closed,
        )],
        proof_statuses: vec![status],
        receipts: vec![receipt.clone()],
        rch_workers: vec![remote_worker("ts2")],
        resource_governor: Some(allow_resource_snapshot()),
        ..ValidationReadinessInput::default()
    };
    let readiness_report =
        build_validation_readiness_report(&readiness_input, "bd-tdoga-readiness", Utc::now());
    assert_eq!(
        readiness_report.overall_status,
        ValidationReadinessStatus::Pass
    );
    assert_eq!(readiness_report.summary.missing_required_receipts, 0);
    fs::write(
        &readiness_path,
        serde_json::to_vec_pretty(&readiness_input)?,
    )?;

    let closeout_report = build_validation_closeout_report(
        &receipt,
        &ValidationCloseoutOptions::new(bead_id, "bd-tdoga-closeout"),
        Utc::now(),
    )?;
    assert_eq!(closeout_report.status, ValidationCloseoutStatus::Ready);
    assert!(closeout_report.close_reason.contains("status=READY"));
    assert!(
        closeout_report
            .agent_mail_markdown
            .contains("validation closeout")
    );

    let readiness_cli = ProcessCommand::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(dir.path())
        .args([
            "ops",
            "validation-readiness",
            "--input",
            readiness_rel.as_str(),
            "--trace-id",
            "bd-tdoga-readiness-cli",
            "--json",
        ])
        .output()
        .expect("run franken-node ops validation-readiness");
    assert!(
        readiness_cli.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&readiness_cli.stdout),
        String::from_utf8_lossy(&readiness_cli.stderr)
    );
    let readiness_json: Value = serde_json::from_slice(&readiness_cli.stdout)?;
    assert_eq!(readiness_json["command"], "ops validation-readiness");
    assert_eq!(readiness_json["trace_id"], "bd-tdoga-readiness-cli");
    assert_eq!(readiness_json["overall_status"], "pass");
    assert_eq!(readiness_json["summary"]["missing_required_receipts"], 0);

    let closeout_cli = ProcessCommand::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(dir.path())
        .args([
            "ops",
            "validation-closeout",
            "--bead-id",
            bead_id,
            "--receipt",
            receipt_rel.as_str(),
            "--stdout-excerpt",
            stdout_rel.as_str(),
            "--stderr-excerpt",
            stderr_rel.as_str(),
            "--trace-id",
            "bd-tdoga-closeout-cli",
            "--json",
        ])
        .output()
        .expect("run franken-node ops validation-closeout");
    assert!(
        closeout_cli.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&closeout_cli.stdout),
        String::from_utf8_lossy(&closeout_cli.stderr)
    );
    let closeout_json: Value = serde_json::from_slice(&closeout_cli.stdout)?;
    assert_eq!(closeout_json["command"], "ops validation-closeout");
    assert_eq!(closeout_json["trace_id"], "bd-tdoga-closeout-cli");
    assert_eq!(closeout_json["status"], "ready");
    assert_eq!(closeout_json["output_excerpts"][0]["stream"], "stdout");

    Ok(())
}

#[test]
fn stress_harness_covers_backpressure_contention_and_fail_closed_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now() - Duration::minutes(1);
    let mut queue = ValidationBrokerQueue::new(8);
    for index in 0..8 {
        let bead_id = format!("bd-tdoga{index}");
        let outcome = queue.enqueue(
            request_for_bead_at(&bead_id, now + Duration::seconds(index)),
            worker_requirements(),
            now + Duration::seconds(index),
        )?;
        assert!(
            !outcome.deduplicated,
            "{bead_id} should be a unique request"
        );
    }
    let err = queue
        .enqueue(
            request_for_bead_at("bd-tdoga-overflow", now + Duration::seconds(9)),
            worker_requirements(),
            now + Duration::seconds(9),
        )
        .expect_err("queue cap should reject overflow");
    assert!(matches!(
        err,
        ValidationBrokerError::QueueFull { max_depth: 8 }
    ));
    assert_eq!(queue.snapshot(now + Duration::seconds(10)).queue_depth, 8);

    let timeout_outcome = classify_rch_output(
        &rch_test_invocation("/data/tmp/franken_node-rusticplateau-bd-tdoga-timeout-target"),
        &RchCommandOutput {
            exit_code: Some(124),
            stdout: String::new(),
            stderr: "[RCH-E104] ssh command timed out before cargo completed".to_string(),
            duration_ms: 900_000,
        },
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );
    assert_eq!(timeout_outcome.outcome, RchOutcomeClass::WorkerTimeout);
    assert_eq!(timeout_outcome.timeout_class, RchTimeoutClass::SshCommand);
    assert!(timeout_outcome.retryable);

    let deferred_outcome = classify_rch_output(
        &rch_test_invocation("/data/tmp/franken_node-rusticplateau-bd-tdoga-deferred-target"),
        &RchCommandOutput {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        },
        &RchProcessSnapshot {
            active_cargo_processes: 9,
            active_rch_processes: 3,
        },
        &RchCommandPolicy::default(),
    );
    assert_eq!(
        deferred_outcome.outcome,
        RchOutcomeClass::ContentionDeferred
    );
    assert_eq!(deferred_outcome.reason_code, "RCH-CONTENTION-DEFERRED");

    let pressure_observation = ResourceGovernorObservation::new(
        now,
        "bd-tdoga-stress",
        vec![
            validation_process("cargo test -p frankenengine-node"),
            validation_process("rustc --crate-name frankenengine_node"),
            validation_process("rch exec -- cargo test"),
            validation_process("cargo clippy -p frankenengine-node"),
            validation_process("rustc --crate-name validation_broker"),
            validation_process("validation broker proof runner"),
        ],
    );
    let pressure_report = evaluate_resource_governor(
        ResourceGovernorRequest {
            trace_id: "bd-tdoga-pressure".to_string(),
            requested_proof_class: Some("cargo-test:validation_broker".to_string()),
            source_only_allowed: true,
        },
        pressure_observation,
        ResourceGovernorThresholds::default(),
        now,
    );
    assert_eq!(
        pressure_report.decision.kind,
        ResourceGovernorDecisionKind::SourceOnly
    );
    assert_eq!(
        pressure_report.decision.reason_code,
        "RG_SOURCE_ONLY_CONTENTION"
    );
    assert_eq!(
        pressure_report.structured_log.event_code, "RG-002",
        "resource governor structured log must identify contention decisions"
    );

    let mut dedupe_observation =
        ResourceGovernorObservation::new(now, "bd-tdoga-dedupe", Vec::new());
    dedupe_observation.active_proof_classes = vec!["cargo-test:validation_broker".to_string()];
    let dedupe_report = evaluate_resource_governor(
        ResourceGovernorRequest {
            trace_id: "bd-tdoga-dedupe".to_string(),
            requested_proof_class: Some("cargo-test:validation_broker".to_string()),
            source_only_allowed: false,
        },
        dedupe_observation,
        ResourceGovernorThresholds::default(),
        now,
    );
    assert_eq!(
        dedupe_report.decision.kind,
        ResourceGovernorDecisionKind::DedupeOnly
    );

    let source_only_receipt = receipt_for_bead(
        "bd-tdoga",
        now,
        now + Duration::seconds(1),
        now + Duration::days(30),
        ValidationExitKind::SourceOnly,
        ValidationErrorClass::SourceOnly,
        TimeoutClass::None,
        RchMode::NotUsed,
        None,
        Some(SourceOnlyReason::CargoContention),
    );
    source_only_receipt.validate_at(Utc::now())?;
    let source_only_status = ValidationProofStatus::from_receipt(&source_only_receipt, Utc::now())?;
    assert_eq!(source_only_status.status, ProofStatusKind::SourceOnly);
    let source_only_closeout = build_validation_closeout_report(
        &source_only_receipt,
        &ValidationCloseoutOptions::new("bd-tdoga", "bd-tdoga-source-only"),
        Utc::now(),
    )?;
    assert_eq!(
        source_only_closeout.status,
        ValidationCloseoutStatus::SourceOnly
    );

    let warn_receipt = receipt_for_bead(
        "bd-tdoga-worker",
        now,
        now + Duration::seconds(1),
        now + Duration::days(30),
        ValidationExitKind::Timeout,
        ValidationErrorClass::WorkerInfra,
        TimeoutClass::SshCommand,
        RchMode::Remote,
        Some("ts2"),
        None,
    );
    let fail_receipt = receipt_for_bead(
        "bd-tdoga-product",
        now,
        now + Duration::seconds(1),
        now + Duration::days(30),
        ValidationExitKind::Failed,
        ValidationErrorClass::TestFailure,
        TimeoutClass::None,
        RchMode::Remote,
        Some("ts2"),
        None,
    );
    let warn_report = build_validation_readiness_report(
        &ValidationReadinessInput {
            receipts: vec![warn_receipt],
            rch_workers: vec![remote_worker("ts2")],
            resource_governor: Some(allow_resource_snapshot()),
            ..ValidationReadinessInput::default()
        },
        "bd-tdoga-worker-warn",
        Utc::now(),
    );
    assert_eq!(warn_report.overall_status, ValidationReadinessStatus::Warn);
    assert_eq!(warn_report.summary.worker_failure_count, 1);

    let fail_report = build_validation_readiness_report(
        &ValidationReadinessInput {
            receipts: vec![fail_receipt],
            rch_workers: vec![remote_worker("ts2")],
            resource_governor: Some(allow_resource_snapshot()),
            ..ValidationReadinessInput::default()
        },
        "bd-tdoga-product-fail",
        Utc::now(),
    );
    assert_eq!(fail_report.overall_status, ValidationReadinessStatus::Fail);
    assert_eq!(fail_report.summary.product_failure_count, 1);

    let mut malformed_receipt = receipt();
    malformed_receipt.input_digests.clear();
    let malformed_err = malformed_receipt
        .validate_at(ts(3))
        .expect_err("malformed receipt must fail closed");
    assert!(matches!(
        malformed_err,
        ValidationBrokerError::ContractViolation {
            code: error_codes::ERR_VB_MALFORMED_RECEIPT,
            ..
        }
    ));

    Ok(())
}

#[test]
fn checked_in_bd_tdoga_harness_artifact_covers_acceptance_matrix()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact: Value = serde_json::from_str(include_str!(
        "../../../artifacts/validation_broker/bd-tdoga/validation_broker_e2e_harness.v1.json"
    ))?;
    assert_eq!(
        artifact
            .get("schema_version")
            .and_then(Value::as_str)
            .ok_or("missing schema_version")?,
        "franken-node/validation-broker/e2e-harness/v1"
    );
    assert_eq!(
        artifact
            .get("bead_id")
            .and_then(Value::as_str)
            .ok_or("missing bead_id")?,
        "bd-tdoga"
    );

    let covered_cases = artifact
        .get("required_cases")
        .and_then(Value::as_array)
        .ok_or("missing required_cases")?
        .iter()
        .filter_map(|case| case.get("case").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    for required_case in [
        "happy_path_source_only_validation",
        "rch_success_receipt",
        "worker_timeout_classification",
        "duplicate_request_dedupe",
        "stale_receipt_rejection",
        "contention_deferred_decision",
        "malformed_receipt_fail_closed",
        "doctor_ops_report_pass_warn_fail",
        "beads_closeout_summary_generation",
        "queue_cap_backpressure",
    ] {
        assert!(
            covered_cases.contains(required_case),
            "missing bd-tdoga required case {required_case}"
        );
    }

    let structured_fields = artifact
        .get("structured_log_fields")
        .and_then(Value::as_array)
        .ok_or("missing structured_log_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for field in [
        "trace_id",
        "event_code",
        "reason_code",
        "command_digest",
        "receipt_id",
        "artifact_stdout_path",
        "artifact_stderr_path",
        "artifact_summary_path",
        "artifact_receipt_path",
    ] {
        assert!(structured_fields.contains(field), "missing field {field}");
    }

    Ok(())
}
