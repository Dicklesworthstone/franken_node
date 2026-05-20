use chrono::{DateTime, Duration, TimeZone, Utc};
use frankenengine_node::ops::rch_adapter::{
    RchCommandOutput, RchCommandPolicy, RchExecutionMode, RchInvocation, RchOutcomeClass,
    RchProcessSnapshot, RchTimeoutClass, RchValidationAction, classify_rch_output,
};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, FLIGHT_RECORDER_MAX_SNIPPET_BYTES,
    FLIGHT_RECORDER_RECOVERY_SCHEMA_VERSION, FallbackPolicy, FlightRecorderExit,
    FlightRecorderExitKind, FlightRecorderRecoveryDecision, FlightRecorderRequiredAction,
    InputDigest, InputSet, OutputPolicy, ProofEvidenceSource, ProofStatusKind, QueueState,
    READINESS_REF_SCHEMA_VERSION, RECEIPT_SCHEMA_VERSION, RchMode, RchReceipt, ReceiptArtifacts,
    ReceiptClassifications, ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy,
    TimeoutClass, ValidationBrokerError, ValidationBrokerQueue, ValidationBrokerRequest,
    ValidationErrorClass, ValidationExit, ValidationExitKind, ValidationFlightRecorderAttempt,
    ValidationFlightRecorderRecovery, ValidationPriority, ValidationProofCacheReuseEvidence,
    ValidationProofStatus, ValidationReadinessRef, ValidationReceipt, ValidationTiming,
    WorkerRequirements, error_codes, flight_recorder_event_codes, flight_recorder_reason_codes,
    readiness_ref_reason_codes, render_validation_proof_status_human,
    render_validation_proof_status_json, write_validation_flight_recorder_at,
    write_validation_receipt_at,
};
use frankenengine_node::ops::validation_closeout::{
    ValidationCloseoutOptions, ValidationCloseoutStatus, build_validation_closeout_report,
    render_validation_closeout_json, render_validation_closeout_structured_log_jsonl,
};
use frankenengine_node::ops::validation_proof_cache::DirtyStatePolicy;
use frankenengine_node::ops::validation_proof_coalescer::{
    CompleteLeaseRequest, CreateLeaseRequest, ValidationProofCoalescerDecisionKind,
    ValidationProofCoalescerReceiptRef, ValidationProofCoalescerRequiredAction,
    ValidationProofCoalescerStore, ValidationProofLeaseState, ValidationProofRchCommand,
    ValidationProofWorkKey, ValidationProofWorkKeyParts,
};
use frankenengine_node::ops::validation_readiness::{
    RchWorkerReadiness, ResourceContentionSnapshot, TrackedValidationBead, ValidationBeadState,
    ValidationReadinessInput, ValidationReadinessStatus, build_validation_readiness_report,
    render_validation_readiness_human,
};
use frankenengine_node::runtime::resource_governor::{
    ObservedValidationProcess, ResourceGovernorDecisionKind, ResourceGovernorObservation,
    ResourceGovernorRequest, ResourceGovernorThresholds, evaluate_resource_governor,
};
use frankenengine_node::security::constant_time;
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

fn coalescer_work_key(seed: &str) -> ValidationProofWorkKey {
    let command = command();
    ValidationProofWorkKey::from_parts(ValidationProofWorkKeyParts {
        command_digest: command.digest(),
        input_digests: vec![InputDigest::new(
            format!("crates/franken-node/src/ops/validation_broker_{seed}.rs"),
            format!("validation-broker-coalescer-input-{seed}").as_bytes(),
            "git-or-worktree",
        )],
        git_commit: "af6e4745".to_string(),
        dirty_worktree: false,
        dirty_state_policy: DirtyStatePolicy::CleanRequired,
        feature_flags: vec!["default".to_string()],
        cargo_toolchain: "nightly-2026-02-19".to_string(),
        package: "frankenengine-node".to_string(),
        test_target: "validation_broker".to_string(),
        environment_policy_id: command.environment_policy_id,
        target_dir_policy_id: command.target_dir_policy_id,
    })
    .expect("valid coalescer work key")
}

fn coalescer_request(
    seed: &str,
    owner_agent: &str,
    owner_bead_id: &str,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> CreateLeaseRequest {
    let key = coalescer_work_key(seed);
    CreateLeaseRequest {
        proof_work_key: key.clone(),
        owner_agent: owner_agent.to_string(),
        owner_bead_id: owner_bead_id.to_string(),
        trace_id: format!("trace-{seed}-{owner_agent}"),
        fencing_token: format!("fence-{seed}-{owner_agent}"),
        created_at,
        expires_at,
        admission_policy_id: "validation-proof-coalescer/admission/test/v1".to_string(),
        rch_command: ValidationProofRchCommand {
            argv: command().argv,
            command_digest: key.command_digest.clone(),
        },
    }
}

fn coalescer_receipt_ref(
    seed: &str,
    proof_work_key: &ValidationProofWorkKey,
) -> ValidationProofCoalescerReceiptRef {
    ValidationProofCoalescerReceiptRef {
        receipt_id: format!("receipt-{seed}"),
        path: format!("artifacts/validation_broker/{seed}/receipt.json"),
        bead_id: format!("bd-{seed}"),
        proof_cache_key_hex: proof_work_key.proof_cache_key.hex.clone(),
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
        readiness_ref: None,
        flight_recorder_ref: None,
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

fn base_receipt() -> Result<ValidationReceipt, Box<dyn std::error::Error>> {
    Ok(receipt_for_bead(
        "bd-base",
        ts(0),
        ts(10),
        ts(10) + Duration::seconds(3_600),
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        RchMode::Remote,
        Some("worker-123"),
        None,
    ))
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

fn readiness_ref(reason_code: &str) -> ValidationReadinessRef {
    ValidationReadinessRef {
        schema_version: READINESS_REF_SCHEMA_VERSION.to_string(),
        path: "artifacts/validation_broker/bd-yyl6t/proof_lane_readiness_fixtures.v1.json"
            .to_string(),
        digest: DigestRef::sha256(b"proof-lane-readiness-capsule"),
        generated_at: ts(2),
        freshness_expires_at: ts(10),
        reason_code: reason_code.to_string(),
        event_code: "PLR-002".to_string(),
        required_action: "record_source_only_blocker".to_string(),
    }
}

fn proof_lane_source_only_receipt(
    reason: SourceOnlyReason,
    readiness_ref: Option<ValidationReadinessRef>,
) -> ValidationReceipt {
    let mut receipt = receipt_for_bead(
        "bd-yyl6t.4",
        ts(1),
        ts(2),
        ts(10),
        ValidationExitKind::SourceOnly,
        ValidationErrorClass::SourceOnly,
        TimeoutClass::None,
        RchMode::NotUsed,
        None,
        Some(reason),
    );
    receipt.classifications.doctor_readiness = "proof_lane_readiness_blocked".to_string();
    receipt.readiness_ref = readiness_ref;
    receipt
}

fn assert_broker_contract_code(
    result: Result<(), ValidationBrokerError>,
    expected: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let err = match result {
        Ok(()) => {
            return Err(format!("broker contract should fail with {expected}").into());
        }
        Err(err) => err,
    };
    match err {
        ValidationBrokerError::ContractViolation { code, detail } => {
            assert!(
                constant_time::ct_eq(code, expected),
                "expected {expected}, got {code}: {detail}"
            );
            Ok(())
        }
        other => {
            Err(format!("expected broker contract violation {expected}, got {other:?}").into())
        }
    }
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

fn proof_cache_reuse(receipt: &ValidationReceipt) -> ValidationProofCacheReuseEvidence {
    ValidationProofCacheReuseEvidence {
        decision_id: format!("vpc-decision-{}-hit", receipt.bead_id),
        cache_key_hex: "8".repeat(64),
        entry_id: format!("vpc-entry-{}", receipt.bead_id),
        entry_path: format!(
            "artifacts/validation_broker/proof_cache/entries/88/{}.json",
            "8".repeat(64)
        ),
        receipt_id: receipt.receipt_id.clone(),
        receipt_path: receipt.artifacts.receipt_path.clone(),
        reason_code: "VPC_HIT_FRESH".to_string(),
        event_code: "VPC-002".to_string(),
        required_action: "reuse_receipt".to_string(),
        diagnostic: "fresh proof cache entry accepted".to_string(),
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
fn cache_reuse_status_is_structured_and_not_a_rerun() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receipt();
    let reuse = proof_cache_reuse(&receipt);

    let status = ValidationProofStatus::from_cache_reuse(&receipt, reuse.clone(), ts(3))?;
    let status_json = render_validation_proof_status_json(&status)?;

    assert_eq!(status.status, ProofStatusKind::Reused);
    assert_eq!(status.proof_source, ProofEvidenceSource::ProofCacheHit);
    assert_eq!(
        status
            .proof_cache
            .as_ref()
            .expect("proof cache")
            .cache_key_hex,
        reuse.cache_key_hex
    );
    assert!(status_json.contains("\"proof_source\": \"proof_cache_hit\""));
    assert!(status_json.contains("\"reason_code\": \"VPC_HIT_FRESH\""));
    assert!(status_json.contains("artifacts/validation_broker/bd-6efmv/receipt.json"));
    Ok(())
}

#[test]
fn cache_reuse_readiness_and_closeout_surface_receipt_and_key()
-> Result<(), Box<dyn std::error::Error>> {
    let receipt = receipt();
    let reuse = proof_cache_reuse(&receipt);
    let status = ValidationProofStatus::from_cache_reuse(&receipt, reuse.clone(), ts(3))?;

    let readiness_input = ValidationReadinessInput {
        tracked_beads: vec![TrackedValidationBead::new(
            &receipt.bead_id,
            ValidationBeadState::Closed,
        )],
        proof_statuses: vec![status],
        receipts: vec![receipt.clone()],
        rch_workers: vec![remote_worker("ts2")],
        resource_governor: Some(allow_resource_snapshot()),
        ..ValidationReadinessInput::default()
    };
    let readiness_report =
        build_validation_readiness_report(&readiness_input, "bd-cache-readiness", ts(3));
    let readiness_human = render_validation_readiness_human(&readiness_report);

    assert_eq!(
        readiness_report.overall_status,
        ValidationReadinessStatus::Pass
    );
    assert_eq!(readiness_report.summary.proof_cache_hits, 1);
    assert_eq!(readiness_report.summary.proof_counts.reused, 1);
    assert!(readiness_human.contains("proof_cache_hits:1"));

    let closeout_options = ValidationCloseoutOptions::new(&receipt.bead_id, "bd-cache-closeout")
        .with_proof_cache_reuse(reuse.clone());
    let closeout_report = build_validation_closeout_report(&receipt, &closeout_options, ts(3))?;
    let closeout_json = render_validation_closeout_json(&closeout_report)?;

    assert_eq!(closeout_report.status, ValidationCloseoutStatus::Ready);
    assert_eq!(
        closeout_report.proof_source,
        ProofEvidenceSource::ProofCacheHit
    );
    assert!(
        closeout_report
            .close_reason
            .contains("proof_source=proof_cache_hit")
    );
    assert!(closeout_report.close_reason.contains(&reuse.cache_key_hex));
    assert!(closeout_report.close_reason.contains(&reuse.receipt_path));
    assert!(
        closeout_report
            .agent_mail_markdown
            .contains("- proof_cache_key:")
    );
    assert!(closeout_json.contains("\"proof_source\": \"proof_cache_hit\""));
    Ok(())
}

#[test]
fn coalescer_statuses_render_producer_waiter_and_completed_handoff()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let store = ValidationProofCoalescerStore::new(dir.path());
    let producer_request = coalescer_request("joined", "PearlLeopard", "bd-producer", ts(1), ts(8));

    let producer_outcome = store.create_or_join(producer_request.clone())?;
    let producer_status = ValidationProofStatus::from_coalescer_outcome(&producer_outcome, ts(1));
    let producer_json = render_validation_proof_status_json(&producer_status)?;

    assert_eq!(producer_status.status, ProofStatusKind::Running);
    assert_eq!(
        producer_status.proof_source,
        ProofEvidenceSource::CoalescedInflight
    );
    assert!(producer_json.contains("\"proof_source\": \"coalesced_inflight\""));
    assert!(producer_json.contains("\"producer_agent\": \"PearlLeopard\""));
    assert_eq!(
        producer_status
            .proof_coalescer
            .as_ref()
            .expect("producer coalescer evidence")
            .required_action,
        ValidationProofCoalescerRequiredAction::StartRchValidation.as_str()
    );

    let waiter_outcome = store.create_or_join(coalescer_request(
        "joined",
        "LavenderElk",
        "bd-waiter",
        ts(2),
        ts(8),
    ))?;
    let waiter_status = ValidationProofStatus::from_coalescer_outcome(&waiter_outcome, ts(2));
    let waiter_human = render_validation_proof_status_human(&waiter_status);

    assert_eq!(waiter_status.status, ProofStatusKind::Running);
    assert_eq!(
        waiter_status.proof_source,
        ProofEvidenceSource::CoalescedWaiter
    );
    assert!(waiter_status.deduplicated);
    let waiter_evidence = waiter_status
        .proof_coalescer
        .as_ref()
        .expect("waiter coalescer evidence");
    assert_eq!(waiter_evidence.producer_agent, "PearlLeopard");
    assert_eq!(waiter_evidence.producer_bead_id, "bd-producer");
    assert_eq!(waiter_evidence.waiter_agent.as_deref(), Some("LavenderElk"));
    assert!(waiter_human.contains("proof_source=coalesced_waiter"));
    assert!(waiter_human.contains("producer=PearlLeopard"));
    assert!(waiter_human.contains("waiter=LavenderElk"));
    assert!(waiter_human.contains("lease=artifacts/validation_broker/proof_coalescer/"));

    store.complete_lease(CompleteLeaseRequest {
        proof_work_key: producer_request.proof_work_key.clone(),
        owner_agent: producer_request.owner_agent.clone(),
        owner_bead_id: producer_request.owner_bead_id.clone(),
        fencing_token: producer_request.fencing_token.clone(),
        completed_at: ts(3),
        receipt_ref: coalescer_receipt_ref("joined", &producer_request.proof_work_key),
    })?;
    let completed_outcome = store.create_or_join(coalescer_request(
        "joined",
        "CyanHorizon",
        "bd-waiter-completed",
        ts(4),
        ts(8),
    ))?;
    let completed_status = ValidationProofStatus::from_coalescer_outcome(&completed_outcome, ts(4));

    assert_eq!(completed_status.status, ProofStatusKind::Reused);
    assert_eq!(
        completed_status.proof_source,
        ProofEvidenceSource::CoalescedCompleted
    );
    let completed_evidence = completed_status
        .proof_coalescer
        .as_ref()
        .expect("completed coalescer evidence")
        .clone();
    assert_eq!(
        completed_evidence.receipt_path.as_deref(),
        Some("artifacts/validation_broker/joined/receipt.json")
    );
    assert_eq!(
        completed_evidence.proof_cache_key_hex,
        producer_request.proof_work_key.proof_cache_key.hex
    );

    let readiness_input = ValidationReadinessInput {
        proof_statuses: vec![
            producer_status.clone(),
            waiter_status.clone(),
            completed_status.clone(),
        ],
        rch_workers: vec![remote_worker("ts2")],
        resource_governor: Some(allow_resource_snapshot()),
        ..ValidationReadinessInput::default()
    };
    let readiness_report =
        build_validation_readiness_report(&readiness_input, "bd-coalescer-readiness", ts(4));
    assert_eq!(readiness_report.summary.proof_coalescer.producer_proofs, 1);
    assert_eq!(readiness_report.summary.proof_coalescer.waiters, 1);
    assert_eq!(readiness_report.summary.proof_coalescer.cache_handoffs, 1);
    let readiness_human = render_validation_readiness_human(&readiness_report);
    assert!(readiness_human.contains(
        "proof_coalescer=producers:1 waiters:1 stale_leases:0 fenced_leases:0 capacity_rejections:0 cache_handoffs:1 rejected:0"
    ));

    let closeout_options = ValidationCloseoutOptions::new("bd-6efmv", "bd-coalescer-closeout")
        .with_proof_coalescer(
            ProofEvidenceSource::CoalescedCompleted,
            completed_evidence.clone(),
        );
    let closeout_report = build_validation_closeout_report(&receipt(), &closeout_options, ts(4))?;
    let closeout_json = render_validation_closeout_json(&closeout_report)?;
    let closeout_jsonl = render_validation_closeout_structured_log_jsonl(&closeout_report)?;
    let closeout_log: Value = serde_json::from_str(closeout_jsonl.trim_end())?;
    assert_eq!(
        closeout_report.proof_source,
        ProofEvidenceSource::CoalescedCompleted
    );
    assert_eq!(
        closeout_report
            .proof_coalescer
            .as_ref()
            .expect("closeout coalescer evidence")
            .producer_agent,
        "PearlLeopard"
    );
    assert!(closeout_report.close_reason.contains("coalescer_decision="));
    assert!(
        closeout_report
            .agent_mail_markdown
            .contains("- proof_coalescer_lease:")
    );
    assert!(closeout_json.contains("\"proof_source\": \"coalesced_completed\""));
    assert!(closeout_json.contains("\"proof_coalescer\""));
    assert_eq!(closeout_log["event"].as_str(), Some("validation_closeout"));
    assert_eq!(
        closeout_log["detail"]["trace_id"].as_str(),
        Some("bd-coalescer-closeout")
    );
    assert_eq!(
        closeout_log["detail"]["proof_source"].as_str(),
        Some("coalesced_completed")
    );
    assert_eq!(
        closeout_log["detail"]["producer_agent"].as_str(),
        Some("PearlLeopard")
    );
    let expected_receipt_path = receipt().artifacts.receipt_path;
    assert_eq!(
        closeout_log["detail"]["receipt_path"].as_str(),
        Some(expected_receipt_path.as_str())
    );
    assert_eq!(
        closeout_log["detail"]["cache_key"].as_str(),
        Some(producer_request.proof_work_key.proof_cache_key.hex.as_str())
    );
    Ok(())
}

#[test]
fn coalescer_statuses_fail_closed_for_stale_and_rejected_work()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let store = ValidationProofCoalescerStore::new(dir.path());
    let stale_request =
        coalescer_request("stale", "PearlLeopard", "bd-stale-producer", ts(1), ts(2));
    store.create_or_join(stale_request)?;

    let stale_outcome = store.create_or_join(coalescer_request(
        "stale",
        "LavenderElk",
        "bd-stale-waiter",
        ts(3),
        ts(8),
    ))?;
    let stale_status = ValidationProofStatus::from_coalescer_outcome(&stale_outcome, ts(3));
    assert_eq!(stale_status.status, ProofStatusKind::Failed);
    assert_eq!(
        stale_status.proof_source,
        ProofEvidenceSource::CoalescerRejected
    );
    assert_eq!(
        stale_status
            .proof_coalescer
            .as_ref()
            .expect("stale coalescer evidence")
            .required_action,
        ValidationProofCoalescerRequiredAction::RetryWithNewFence.as_str()
    );

    let corrupt_request = coalescer_request(
        "corrupt",
        "PearlLeopard",
        "bd-corrupt-producer",
        ts(1),
        ts(8),
    );
    let corrupt_path = store.lease_path(&corrupt_request.proof_work_key);
    fs::create_dir_all(corrupt_path.parent().expect("lease parent"))?;
    fs::write(&corrupt_path, b"{not-json")?;
    let rejected_outcome = store.create_or_join(corrupt_request)?;
    let rejected_status = ValidationProofStatus::from_coalescer_outcome(&rejected_outcome, ts(1));
    let rejected_json = render_validation_proof_status_json(&rejected_status)?;

    assert_eq!(rejected_status.status, ProofStatusKind::Failed);
    assert_eq!(
        rejected_status.proof_source,
        ProofEvidenceSource::CoalescerRejected
    );
    assert!(rejected_json.contains("\"proof_source\": \"coalescer_rejected\""));
    assert!(rejected_json.contains("\"required_action\": \"repair_state\""));
    assert_eq!(
        rejected_status
            .proof_coalescer
            .as_ref()
            .expect("rejected coalescer evidence")
            .required_action,
        ValidationProofCoalescerRequiredAction::RepairState.as_str()
    );
    assert_eq!(
        rejected_outcome.decision.decision,
        ValidationProofCoalescerDecisionKind::RepairState
    );
    assert_eq!(
        rejected_outcome.lease.as_ref().map(|lease| lease.state),
        None::<ValidationProofLeaseState>
    );

    let mut capacity_status = rejected_status.clone();
    capacity_status
        .proof_coalescer
        .as_mut()
        .expect("capacity coalescer evidence")
        .reason_code = "VPCO_REJECT_CAPACITY".to_string();
    let readiness_input = ValidationReadinessInput {
        proof_statuses: vec![stale_status, capacity_status],
        rch_workers: vec![remote_worker("ts2")],
        resource_governor: Some(allow_resource_snapshot()),
        ..ValidationReadinessInput::default()
    };
    let readiness_report =
        build_validation_readiness_report(&readiness_input, "bd-coalescer-rejected", ts(4));
    assert_eq!(readiness_report.summary.proof_coalescer.stale_leases, 1);
    assert_eq!(
        readiness_report.summary.proof_coalescer.capacity_rejections,
        1
    );
    assert_eq!(readiness_report.summary.proof_coalescer.rejected, 2);
    let coalescer_check = readiness_report
        .checks
        .iter()
        .find(|check| check.code == "VR-PROOF-COALESCER-009")
        .expect("coalescer readiness check");
    assert_eq!(coalescer_check.status, ValidationReadinessStatus::Fail);
    let readiness_human = render_validation_readiness_human(&readiness_report);
    assert!(readiness_human.contains("capacity_rejections:1"));
    assert!(readiness_human.contains("VR-PROOF-COALESCER-009 [FAIL]"));
    Ok(())
}

#[test]
fn stale_cache_reuse_cannot_satisfy_closeout() {
    let stale_receipt = receipt_for_bead(
        "bd-stale-cache",
        ts(1),
        ts(2),
        ts(3),
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        RchMode::Remote,
        Some("ts2"),
        None,
    );
    let err = ValidationProofStatus::from_cache_reuse(
        &stale_receipt,
        proof_cache_reuse(&stale_receipt),
        ts(4),
    )
    .expect_err("stale cache reuse must validate receipt freshness");

    assert!(matches!(
        err,
        ValidationBrokerError::ContractViolation {
            code: error_codes::ERR_VB_STALE_RECEIPT,
            ..
        }
    ));
}

#[test]
fn receipt_freshness_boundary_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receipt();

    assert_broker_contract_code(
        receipt.validate_at(ts(10)),
        error_codes::ERR_VB_STALE_RECEIPT,
    )?;
    receipt.validate_at(ts(9))?;

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
fn proof_lane_source_only_readiness_ref_surfaces_in_status_and_closeout()
-> Result<(), Box<dyn std::error::Error>> {
    let receipt = proof_lane_source_only_receipt(
        SourceOnlyReason::ProofLaneWorkerAuthFailed,
        Some(readiness_ref(
            readiness_ref_reason_codes::WORKER_AUTH_FAILED,
        )),
    );

    receipt.validate_at(ts(3))?;
    let status = ValidationProofStatus::from_receipt(&receipt, ts(3))?;
    assert_eq!(status.status, ProofStatusKind::SourceOnly);
    assert_eq!(
        status
            .readiness_ref
            .as_ref()
            .ok_or("status readiness_ref")?
            .reason_code,
        readiness_ref_reason_codes::WORKER_AUTH_FAILED
    );

    let closeout = build_validation_closeout_report(
        &receipt,
        &ValidationCloseoutOptions::new(&receipt.bead_id, "bd-yyl6t.4-closeout"),
        ts(3),
    )?;
    assert_eq!(closeout.status, ValidationCloseoutStatus::SourceOnly);
    assert!(closeout.close_reason.contains("readiness_ref="));
    assert!(
        closeout
            .close_reason
            .contains(readiness_ref_reason_codes::WORKER_AUTH_FAILED)
    );
    let closeout_json = render_validation_closeout_json(&closeout)?;
    assert!(closeout_json.contains("\"readiness_ref\""));
    assert!(closeout_json.contains(readiness_ref_reason_codes::WORKER_AUTH_FAILED));

    Ok(())
}

#[test]
fn readiness_ref_rejects_missing_stale_malformed_and_product_rewrites()
-> Result<(), Box<dyn std::error::Error>> {
    let missing = proof_lane_source_only_receipt(SourceOnlyReason::ProofLaneWorkerAuthFailed, None);
    assert_broker_contract_code(
        missing.validate_at(ts(3)),
        error_codes::ERR_VB_INVALID_READINESS_REF,
    )?;

    let mut stale_ref = readiness_ref(readiness_ref_reason_codes::WORKER_AUTH_FAILED);
    stale_ref.freshness_expires_at = ts(2);
    let stale = proof_lane_source_only_receipt(
        SourceOnlyReason::ProofLaneWorkerAuthFailed,
        Some(stale_ref),
    );
    assert_broker_contract_code(
        stale.validate_at(ts(3)),
        error_codes::ERR_VB_STALE_READINESS_REF,
    )?;

    for bad_path in [
        "../capsule.json",
        "artifacts/validation_broker/bd-yyl6t/\0capsule.json",
    ] {
        let mut bad_ref = readiness_ref(readiness_ref_reason_codes::WORKER_AUTH_FAILED);
        bad_ref.path = bad_path.to_string();
        let bad_receipt = proof_lane_source_only_receipt(
            SourceOnlyReason::ProofLaneWorkerAuthFailed,
            Some(bad_ref),
        );
        assert_broker_contract_code(
            bad_receipt.validate_at(ts(3)),
            error_codes::ERR_VB_INVALID_READINESS_REF,
        )?;
    }

    let mut bad_digest_ref = readiness_ref(readiness_ref_reason_codes::WORKER_AUTH_FAILED);
    bad_digest_ref.digest.hex = "not-a-sha256".to_string();
    let bad_digest = proof_lane_source_only_receipt(
        SourceOnlyReason::ProofLaneWorkerAuthFailed,
        Some(bad_digest_ref),
    );
    assert_broker_contract_code(
        bad_digest.validate_at(ts(3)),
        error_codes::ERR_VB_INVALID_READINESS_REF,
    )?;

    let mut product_failure = receipt_for_bead(
        "bd-yyl6t-product",
        ts(1),
        ts(2),
        ts(10),
        ValidationExitKind::Failed,
        ValidationErrorClass::TestFailure,
        TimeoutClass::None,
        RchMode::Remote,
        Some("ts2"),
        None,
    );
    product_failure.readiness_ref = Some(readiness_ref(
        readiness_ref_reason_codes::WORKER_AUTH_FAILED,
    ));
    assert_broker_contract_code(
        product_failure.validate_at(ts(3)),
        error_codes::ERR_VB_INVALID_READINESS_REF,
    )?;

    let mut mismatch = proof_lane_source_only_receipt(
        SourceOnlyReason::ProofLaneOverrideNotHonored,
        Some(readiness_ref(
            readiness_ref_reason_codes::WORKER_AUTH_FAILED,
        )),
    );
    assert_broker_contract_code(
        mismatch.validate_at(ts(3)),
        error_codes::ERR_VB_INVALID_READINESS_REF,
    )?;

    mismatch.readiness_ref = Some(readiness_ref(
        readiness_ref_reason_codes::OVERRIDE_NOT_HONORED,
    ));
    mismatch.validate_at(ts(3))?;

    Ok(())
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

fn flight_recorder_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 6, 8, 0, 3)
        .single()
        .expect("valid flight recorder timestamp")
}

fn flight_recorder_fixture() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../artifacts/validation_broker/bd-2zn9k/validation_flight_recorder_fixtures.v1.json"
    ))?)
}

fn fixture_field<'a>(
    fixture: &'a Value,
    field: &'static str,
) -> Result<&'a Value, Box<dyn std::error::Error>> {
    fixture
        .get(field)
        .ok_or_else(|| format!("missing flight recorder fixture field {field}").into())
}

fn base_flight_recorder_attempt()
-> Result<ValidationFlightRecorderAttempt, Box<dyn std::error::Error>> {
    let fixture = flight_recorder_fixture()?;
    Ok(serde_json::from_value(
        fixture_field(&fixture, "base_attempt")?.clone(),
    )?)
}

fn base_flight_recorder_recovery()
-> Result<ValidationFlightRecorderRecovery, Box<dyn std::error::Error>> {
    let fixture = flight_recorder_fixture()?;
    Ok(serde_json::from_value(
        fixture_field(&fixture, "base_recovery")?.clone(),
    )?)
}

fn writer_flight_recorder_recovery(
    attempt: &ValidationFlightRecorderAttempt,
) -> ValidationFlightRecorderRecovery {
    ValidationFlightRecorderRecovery {
        schema_version: FLIGHT_RECORDER_RECOVERY_SCHEMA_VERSION.to_string(),
        decision_id: "vfr-recovery-bd-2zn9k-writer".to_string(),
        attempt_id: attempt.attempt_id.clone(),
        bead_id: attempt.bead_id.clone(),
        thread_id: attempt.thread_id.clone(),
        decided_at: flight_recorder_now(),
        input_digest: DigestRef::sha256(b"writer-attempt-plus-policy"),
        decision: FlightRecorderRecoveryDecision::AcceptSuccess,
        reason_code: flight_recorder_reason_codes::SUCCESS_REMOTE.to_string(),
        event_code: flight_recorder_event_codes::SUCCESS_REMOTE.to_string(),
        required_action: FlightRecorderRequiredAction::None,
        fail_closed: false,
        retryable: false,
        freshness_expires_at: flight_recorder_now() + Duration::seconds(3_600),
        operator_message: "fresh remote validation proof can be used".to_string(),
        diagnostics: BTreeMap::from([("attempt_id".to_string(), attempt.attempt_id.clone())]),
    }
}

fn assert_flight_recorder_contract_code(
    result: Result<(), ValidationBrokerError>,
    expected: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let err = match result {
        Ok(()) => {
            return Err(format!("flight recorder contract should fail with {expected}").into());
        }
        Err(err) => err,
    };
    match err {
        ValidationBrokerError::ContractViolation { code, detail } => {
            assert!(
                constant_time::ct_eq(code, expected),
                "expected {expected}, got {code}: {detail}"
            );
            Ok(())
        }
        other => Err(format!(
            "expected flight recorder contract violation {expected}, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn flight_recorder_checked_fixture_round_trips_and_validates()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = base_flight_recorder_attempt()?;
    attempt.validate_at(flight_recorder_now())?;

    let json = serde_json::to_string_pretty(&attempt)?;
    let parsed: ValidationFlightRecorderAttempt = serde_json::from_str(&json)?;
    parsed.validate_at(flight_recorder_now())?;

    let recovery = base_flight_recorder_recovery()?;
    recovery.validate_for_attempt(&parsed, flight_recorder_now())?;

    Ok(())
}

#[test]
fn flight_recorder_writer_persists_artifacts_and_links_status()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let mut attempt = base_flight_recorder_attempt()?;
    attempt.recovery_ref = None;
    let recovery = writer_flight_recorder_recovery(&attempt);

    let result = write_validation_flight_recorder_at(
        dir.path(),
        &attempt,
        Some(&recovery),
        flight_recorder_now(),
    )?;

    let attempt_path = dir.path().join(&result.flight_recorder_ref.attempt_path);
    let attempt_raw = fs::read_to_string(&attempt_path)?;
    let persisted_attempt: ValidationFlightRecorderAttempt = serde_json::from_str(&attempt_raw)?;
    persisted_attempt.validate_at(flight_recorder_now())?;
    assert_eq!(persisted_attempt.attempt_id, attempt.attempt_id);
    assert_eq!(
        result.flight_recorder_ref.attempt_digest,
        DigestRef::sha256(attempt_raw.as_bytes())
    );

    let recovery_ref = persisted_attempt
        .recovery_ref
        .clone()
        .ok_or("writer should attach recovery_ref")?;
    assert_eq!(result.recovery_ref, Some(recovery_ref.clone()));
    let recovery_path = dir.path().join(&recovery_ref.path);
    let recovery_raw = fs::read(&recovery_path)?;
    assert_eq!(recovery_ref.digest, DigestRef::sha256(&recovery_raw));
    let persisted_recovery: ValidationFlightRecorderRecovery =
        serde_json::from_slice(&recovery_raw)?;
    persisted_recovery.validate_for_attempt(&persisted_attempt, flight_recorder_now())?;

    assert!(
        dir.path()
            .join(&persisted_attempt.artifacts.stdout_path)
            .is_file()
    );
    assert!(
        dir.path()
            .join(&persisted_attempt.artifacts.stderr_path)
            .is_file()
    );
    let summary = fs::read_to_string(dir.path().join(&persisted_attempt.artifacts.summary_path))?;
    assert!(summary.contains(&persisted_attempt.attempt_id));

    let mut receipt = receipt_for_bead(
        &persisted_attempt.bead_id,
        flight_recorder_now() - Duration::seconds(2),
        flight_recorder_now() - Duration::seconds(1),
        flight_recorder_now() + Duration::seconds(3_600),
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        result.flight_recorder_ref.execution_mode,
        result.flight_recorder_ref.worker_id.as_deref(),
        None,
    );
    receipt.flight_recorder_ref = Some(result.flight_recorder_ref.clone());
    receipt.validate_at(flight_recorder_now())?;
    let status = ValidationProofStatus::from_receipt(&receipt, flight_recorder_now())?;
    assert_eq!(
        status.flight_recorder_ref,
        Some(result.flight_recorder_ref.clone())
    );
    Ok(())
}

#[test]
fn flight_recorder_writer_rejects_invalid_artifact_path_without_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let mut attempt = base_flight_recorder_attempt()?;
    attempt.recovery_ref = None;
    attempt.artifacts.recovery_path = None;
    attempt.artifacts.attempt_path = "/tmp/escape.json".to_string();

    let err =
        write_validation_flight_recorder_at(dir.path(), &attempt, None, flight_recorder_now())
            .expect_err("writer should reject absolute artifact paths");
    assert_flight_recorder_contract_code(Err(err), error_codes::ERR_VFR_INVALID_ARTIFACT_PATH)?;
    assert!(
        !dir.path().join("artifacts").exists(),
        "writer should not create sidecar artifacts after validation failure"
    );
    Ok(())
}

#[test]
fn flight_recorder_checked_fixture_declares_required_valid_and_invalid_cases()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = flight_recorder_fixture()?;
    let valid_cases = fixture
        .get("valid_cases")
        .and_then(Value::as_array)
        .ok_or("missing valid_cases")?
        .iter()
        .filter_map(|case| case.get("case").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    for required_case in [
        "remote_success",
        "ssh_timeout",
        "missing_toolchain",
        "disk_pressure",
        "local_fallback_refused",
        "contention_deferred",
        "stale_progress",
        "compile_error",
        "test_failure",
        "source_only_allowed",
        "reuse_receipt",
    ] {
        assert!(
            valid_cases.contains(required_case),
            "missing valid flight recorder case {required_case}"
        );
    }

    let invalid_cases = fixture
        .get("invalid_cases")
        .and_then(Value::as_array)
        .ok_or("missing invalid_cases")?
        .iter()
        .filter_map(|case| case.get("case").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    for required_case in [
        "missing_command_digest",
        "unsupported_timeout_class",
        "unbounded_output_snippet",
        "absolute_artifact_path",
        "missing_next_action",
        "mismatched_bead_thread",
        "unredacted_environment",
        "unsorted_observations",
    ] {
        assert!(
            invalid_cases.contains(required_case),
            "missing invalid flight recorder case {required_case}"
        );
    }

    Ok(())
}

#[test]
fn flight_recorder_model_rejects_invalid_attempts_with_stable_codes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bad_digest = base_flight_recorder_attempt()?;
    bad_digest.command.command_digest.hex = "0".repeat(64);
    assert_flight_recorder_contract_code(
        bad_digest.validate_at(flight_recorder_now()),
        error_codes::ERR_VFR_MISSING_COMMAND_DIGEST,
    )?;

    let mut absolute_path = base_flight_recorder_attempt()?;
    absolute_path.artifacts.stdout_path = "/tmp/stdout.txt".to_string();
    assert_flight_recorder_contract_code(
        absolute_path.validate_at(flight_recorder_now()),
        error_codes::ERR_VFR_INVALID_ARTIFACT_PATH,
    )?;

    let mut unredacted = base_flight_recorder_attempt()?;
    unredacted
        .environment
        .captured_env
        .insert("SECRET_TOKEN".to_string(), "raw-secret".to_string());
    assert_flight_recorder_contract_code(
        unredacted.validate_at(flight_recorder_now()),
        error_codes::ERR_VFR_UNREDACTED_ENVIRONMENT,
    )?;

    let mut unbounded_snippet = base_flight_recorder_attempt()?;
    unbounded_snippet.artifacts.stdout_snippet =
        Some("x".repeat(FLIGHT_RECORDER_MAX_SNIPPET_BYTES + 1));
    assert_flight_recorder_contract_code(
        unbounded_snippet.validate_at(flight_recorder_now()),
        error_codes::ERR_VFR_UNBOUNDED_SNIPPET,
    )?;

    let mut unsorted = base_flight_recorder_attempt()?;
    let mut earlier = unsorted
        .observations
        .first()
        .ok_or("base flight recorder attempt should have an observation")?
        .clone();
    earlier.observation_id = "vfr-obs-0000".to_string();
    earlier.observed_at -= Duration::seconds(1);
    unsorted.observations.push(earlier);
    assert_flight_recorder_contract_code(
        unsorted.validate_at(flight_recorder_now()),
        error_codes::ERR_VFR_INVALID_OBSERVATION_ORDER,
    )?;

    let mut infra_readiness = base_flight_recorder_attempt()?;
    infra_readiness.adapter_outcome = None;
    infra_readiness.exit = FlightRecorderExit {
        kind: FlightRecorderExitKind::WorkerInfra,
        code: None,
        signal: None,
        timeout_class: TimeoutClass::None,
        error_class: ValidationErrorClass::WorkerInfra,
        retryable: true,
        product_failure: false,
    };
    infra_readiness.readiness_ref = Some(readiness_ref(
        readiness_ref_reason_codes::SAME_TOOLCHAIN_MISSING,
    ));
    infra_readiness.validate_at(flight_recorder_now())?;

    let mut product_rewrite = base_flight_recorder_attempt()?;
    product_rewrite.readiness_ref = Some(readiness_ref(
        readiness_ref_reason_codes::WORKER_AUTH_FAILED,
    ));
    assert_flight_recorder_contract_code(
        product_rewrite.validate_at(flight_recorder_now()),
        error_codes::ERR_VFR_INVALID_READINESS_REF,
    )?;

    let mut bad_ref = infra_readiness;
    bad_ref
        .readiness_ref
        .as_mut()
        .ok_or("flight recorder readiness_ref")?
        .digest
        .hex = "bad-digest".to_string();
    assert_flight_recorder_contract_code(
        bad_ref.validate_at(flight_recorder_now()),
        error_codes::ERR_VFR_INVALID_READINESS_REF,
    )?;

    Ok(())
}

#[test]
fn flight_recorder_recovery_rejects_required_action_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = base_flight_recorder_attempt()?;
    let mut recovery = base_flight_recorder_recovery()?;
    recovery.required_action = FlightRecorderRequiredAction::WaitForCapacity;

    assert_flight_recorder_contract_code(
        recovery.validate_for_attempt(&attempt, flight_recorder_now()),
        error_codes::ERR_VFR_INVALID_RECOVERY_DECISION,
    )?;

    Ok(())
}

#[test]
fn validation_flight_recorder_ref_from_rch_adapter_outcome()
-> Result<(), Box<dyn std::error::Error>> {
    use frankenengine_node::ops::validation_broker::{
        FlightRecorderAdapterOutcome, FlightRecorderAdapterOutcomeClass, RchMode, TimeoutClass,
        ValidationFlightRecorderRef,
    };

    let adapter_outcome = FlightRecorderAdapterOutcome {
        outcome: FlightRecorderAdapterOutcomeClass::Passed,
        execution_mode: RchMode::Remote,
        worker_id: Some("worker-123".to_string()),
        timeout_class: TimeoutClass::None,
        exit_code: Some(0),
        retryable: false,
        product_failure: false,
        reason_code: "RCH-S000".to_string(),
        detail: "successful validation".to_string(),
    };

    let attempt_id = "attempt-456".to_string();
    let attempt_path = "artifacts/flight-recorder/attempt-456.json".to_string();
    let attempt_digest = DigestRef {
        algorithm: "sha256".to_string(),
        hex: "deadbeefcafebabe0123456789abcdef".to_string(),
    };
    let generated_at = ts(100);
    let ttl_secs = 3600;

    let flight_ref = ValidationFlightRecorderRef::from_rch_adapter_outcome(
        &adapter_outcome,
        attempt_id.clone(),
        attempt_path.clone(),
        attempt_digest.clone(),
        generated_at,
        ttl_secs,
    );

    assert_eq!(flight_ref.attempt_id, attempt_id);
    assert_eq!(flight_ref.attempt_path, attempt_path);
    assert_eq!(flight_ref.attempt_digest, attempt_digest);
    assert_eq!(
        flight_ref.outcome_class,
        FlightRecorderAdapterOutcomeClass::Passed
    );
    assert_eq!(flight_ref.execution_mode, RchMode::Remote);
    assert_eq!(flight_ref.worker_id, Some("worker-123".to_string()));
    assert_eq!(flight_ref.reason_code, "RCH-S000");
    assert_eq!(flight_ref.generated_at, generated_at);
    assert_eq!(
        flight_ref.freshness_expires_at,
        generated_at + Duration::seconds(ttl_secs as i64)
    );

    // Validate the created reference before the TTL boundary.
    flight_ref.validate_at(generated_at + Duration::seconds(100))?;

    Ok(())
}

#[test]
fn readiness_ref_freshness_boundary_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut boundary_ref = readiness_ref(readiness_ref_reason_codes::WORKER_AUTH_FAILED);
    boundary_ref.freshness_expires_at = ts(3);
    let boundary = proof_lane_source_only_receipt(
        SourceOnlyReason::ProofLaneWorkerAuthFailed,
        Some(boundary_ref),
    );

    assert_broker_contract_code(
        boundary.validate_at(ts(3)),
        error_codes::ERR_VB_STALE_READINESS_REF,
    )?;

    Ok(())
}

#[test]
fn validation_flight_recorder_ref_freshness_boundary_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    use frankenengine_node::ops::validation_broker::{
        FlightRecorderAdapterOutcome, FlightRecorderAdapterOutcomeClass, RchMode, TimeoutClass,
        ValidationFlightRecorderRef,
    };

    let adapter_outcome = FlightRecorderAdapterOutcome {
        outcome: FlightRecorderAdapterOutcomeClass::WorkerTimeout,
        execution_mode: RchMode::Unavailable,
        worker_id: None,
        timeout_class: TimeoutClass::SshCommand,
        exit_code: None,
        retryable: true,
        product_failure: false,
        reason_code: "RCH-E104".to_string(),
        detail: "worker ssh connection timeout".to_string(),
    };

    let generated_at = ts(10);
    let flight_ref = ValidationFlightRecorderRef::from_rch_adapter_outcome(
        &adapter_outcome,
        "attempt-789".to_string(),
        "artifacts/flight-recorder/attempt-789.json".to_string(),
        DigestRef {
            algorithm: "sha256".to_string(),
            hex: "abcdef0123456789deadbeefcafebabeabcdef0123456789deadbeefcafebabe".to_string(),
        },
        generated_at,
        300, // 5 minutes TTL
    );

    // Should validate when fresh
    flight_ref.validate_at(generated_at + Duration::seconds(100))?;

    // Should fail at the exact freshness boundary.
    let boundary = generated_at + Duration::seconds(300);
    assert_flight_recorder_contract_code(
        flight_ref.validate_at(boundary),
        error_codes::ERR_VFR_STALE_FLIGHT_RECORDER_REF,
    )?;

    Ok(())
}

#[test]
fn flight_recorder_attempt_and_recovery_freshness_boundary_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let now = flight_recorder_now();

    let mut attempt = base_flight_recorder_attempt()?;
    attempt.freshness_expires_at = now;
    assert_flight_recorder_contract_code(
        attempt.validate_at(now),
        error_codes::ERR_VFR_STALE_ATTEMPT,
    )?;

    let mut fresh_attempt = base_flight_recorder_attempt()?;
    fresh_attempt.freshness_expires_at = now + Duration::seconds(1);
    let mut recovery = writer_flight_recorder_recovery(&fresh_attempt);
    recovery.freshness_expires_at = now;
    assert_flight_recorder_contract_code(
        recovery.validate_for_attempt(&fresh_attempt, now),
        error_codes::ERR_VFR_STALE_ATTEMPT,
    )?;

    Ok(())
}

#[test]
fn validation_receipt_with_flight_recorder_ref_validates() -> Result<(), Box<dyn std::error::Error>>
{
    use frankenengine_node::ops::validation_broker::{
        FlightRecorderAdapterOutcomeClass, ValidationFlightRecorderRef,
    };

    let mut receipt = base_receipt()?;
    receipt.rch.mode = RchMode::Remote;
    receipt.rch.worker_id = Some("worker-456".to_string());

    let flight_ref = ValidationFlightRecorderRef {
        schema_version: "franken-node/validation-flight-recorder-ref/v1".to_string(),
        attempt_path: "artifacts/flight-recorder/attempt-123.json".to_string(),
        attempt_digest: DigestRef {
            algorithm: "sha256".to_string(),
            hex: "1234567890abcdefdeadbeefcafebabe".to_string(),
        },
        attempt_id: "attempt-123".to_string(),
        generated_at: ts(100),
        freshness_expires_at: ts(3700), // 1 hour TTL
        outcome_class: FlightRecorderAdapterOutcomeClass::Passed,
        execution_mode: RchMode::Remote,
        worker_id: Some("worker-456".to_string()),
        reason_code: "RCH-S000".to_string(),
    };

    receipt.flight_recorder_ref = Some(flight_ref);

    // Should validate successfully
    receipt.validate_at(ts(200))?;

    Ok(())
}

#[test]
fn validation_receipt_rejects_mismatched_flight_recorder_ref()
-> Result<(), Box<dyn std::error::Error>> {
    use frankenengine_node::ops::validation_broker::{
        FlightRecorderAdapterOutcomeClass, ValidationFlightRecorderRef,
    };

    let mut receipt = base_receipt()?;
    receipt.rch.mode = RchMode::Remote;
    receipt.rch.worker_id = Some("worker-456".to_string());

    // Create flight recorder ref with mismatched worker ID
    let flight_ref = ValidationFlightRecorderRef {
        schema_version: "franken-node/validation-flight-recorder-ref/v1".to_string(),
        attempt_path: "artifacts/flight-recorder/attempt-123.json".to_string(),
        attempt_digest: DigestRef {
            algorithm: "sha256".to_string(),
            hex: "1234567890abcdefdeadbeefcafebabe".to_string(),
        },
        attempt_id: "attempt-123".to_string(),
        generated_at: ts(100),
        freshness_expires_at: ts(3700), // 1 hour TTL
        outcome_class: FlightRecorderAdapterOutcomeClass::Passed,
        execution_mode: RchMode::Remote,
        worker_id: Some("different-worker".to_string()), // Mismatch!
        reason_code: "RCH-S000".to_string(),
    };

    receipt.flight_recorder_ref = Some(flight_ref);

    // Should fail validation due to worker ID mismatch
    let result = receipt.validate_at(ts(200));
    assert!(result.is_err());
    if let Err(ValidationBrokerError::ContractViolation { code, .. }) = result {
        assert_eq!(code, "ERR_VFR_INVALID_FLIGHT_RECORDER_REF");
    } else {
        return Err("Expected flight recorder ref validation error".into());
    }

    Ok(())
}
