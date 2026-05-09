use chrono::{DateTime, Duration, TimeZone, Utc};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, FallbackPolicy, InputDigest, InputSet, OutputPolicy,
    READINESS_REF_SCHEMA_VERSION, RECEIPT_SCHEMA_VERSION, RchMode, RchReceipt, ReceiptArtifacts,
    ReceiptClassifications, ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy,
    TimeoutClass, ValidationBrokerRequest, ValidationErrorClass, ValidationExit,
    ValidationExitKind, ValidationPriority, ValidationReadinessRef, ValidationReceipt,
    ValidationTiming, readiness_ref_reason_codes,
};
use frankenengine_node::ops::validation_closeout::{
    CompletionAuditCoverage, CompletionAuditEvidenceKind, CompletionAuditEvidenceRef,
    CompletionAuditEvidenceStatus, CompletionAuditLedgerError, CompletionAuditLedgerStatus,
    CompletionAuditRequirement, PromptToArtifactCompletionAuditLedger, ValidationCloseoutError,
    ValidationCloseoutOptions, ValidationCloseoutStatus, build_validation_closeout_report,
    completion_audit_reason_codes, redact_output_excerpt, render_validation_closeout_json,
    render_validation_closeout_structured_log_jsonl,
};
use frankenengine_node::ops::validation_proof_cache::DirtyStatePolicy;
use frankenengine_node::ops::validation_proof_coalescer::{
    ValidationSwarmSchedulerCapacitySnapshot, ValidationSwarmSchedulerCoalescerState,
    ValidationSwarmSchedulerDecision, ValidationSwarmSchedulerDigestRef,
    ValidationSwarmSchedulerFlightRecorderState, ValidationSwarmSchedulerInput,
    ValidationSwarmSchedulerPolicy, ValidationSwarmSchedulerPriority,
    ValidationSwarmSchedulerProofDebtClass, ValidationSwarmSchedulerTargetDirClass,
    decide_validation_swarm_schedule,
};
use serde_json::{Value, json};
use std::process::Command;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn ts(seconds: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0)
        .single()
        .expect("valid timestamp")
        + Duration::seconds(seconds)
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
            "validation_closeout".to_string(),
        ],
        cwd: "/data/projects/franken_node".to_string(),
        environment_policy_id: "validation-closeout/env-policy/v1".to_string(),
        target_dir_policy_id: "validation-closeout/target-dir/off-repo/v1".to_string(),
    }
}

fn request(bead_id: &str, now: DateTime<Utc>) -> ValidationBrokerRequest {
    ValidationBrokerRequest::new(
        format!("vbreq-{bead_id}-1"),
        bead_id,
        bead_id,
        "RusticPlateau",
        now,
        ValidationPriority::High,
        command(),
        InputSet {
            git_commit: "9faf1b29".to_string(),
            dirty_worktree: false,
            changed_paths: vec!["crates/franken-node/src/ops/validation_closeout.rs".to_string()],
            content_digests: vec![InputDigest::new(
                "crates/franken-node/src/ops/validation_closeout.rs",
                b"validation-closeout-module",
                "git-or-worktree",
            )],
            feature_flags: vec!["http-client".to_string(), "external-commands".to_string()],
        },
        OutputPolicy {
            stdout_path: format!("artifacts/validation_broker/{bead_id}/stdout.txt"),
            stderr_path: format!("artifacts/validation_broker/{bead_id}/stderr.txt"),
            summary_path: format!("artifacts/validation_broker/{bead_id}/summary.md"),
            receipt_path: format!("artifacts/validation_broker/{bead_id}/receipt.json"),
            retention: "keep-with-bead".to_string(),
        },
        FallbackPolicy {
            source_only_allowed: true,
            allowed_reasons: vec![SourceOnlyReason::CargoContention],
        },
    )
}

fn receipt(
    bead_id: &str,
    now: DateTime<Utc>,
    exit_kind: ValidationExitKind,
    error_class: ValidationErrorClass,
    timeout_class: TimeoutClass,
    freshness_expires_at: DateTime<Utc>,
) -> ValidationReceipt {
    let req = request(bead_id, now);
    let source_only_reason =
        (exit_kind == ValidationExitKind::SourceOnly).then_some(SourceOnlyReason::CargoContention);
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
            path: "/data/tmp/franken_node-rusticplateau-bd-y4mkq-target".to_string(),
            path_digest: DigestRef::sha256(b"/data/tmp/franken_node-rusticplateau-bd-y4mkq-target"),
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
            started_at: now,
            finished_at: now + Duration::seconds(1),
            duration_ms: 1_000,
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
            retryable: matches!(exit_kind, ValidationExitKind::Timeout),
        },
        artifacts: ReceiptArtifacts {
            stdout_path: format!("artifacts/validation_broker/{bead_id}/stdout.txt"),
            stderr_path: format!("artifacts/validation_broker/{bead_id}/stderr.txt"),
            summary_path: format!("artifacts/validation_broker/{bead_id}/summary.md"),
            receipt_path: format!("artifacts/validation_broker/{bead_id}/receipt.json"),
            stdout_digest: DigestRef::sha256(b"stdout"),
            stderr_digest: DigestRef::sha256(b"stderr"),
        },
        readiness_ref: None,
        flight_recorder_ref: None,
        trust: ReceiptTrust {
            generated_by: "validation-broker".to_string(),
            agent_name: "RusticPlateau".to_string(),
            git_commit: "9faf1b29".to_string(),
            dirty_worktree: false,
            freshness: "fresh".to_string(),
            signature_status: "unsigned-test".to_string(),
        },
        classifications: ReceiptClassifications {
            source_only_fallback: exit_kind == ValidationExitKind::SourceOnly,
            source_only_reason,
            doctor_readiness: "ready".to_string(),
            ci_consumable: true,
        },
    }
}

fn readiness_ref(reason_code: &str) -> ValidationReadinessRef {
    ValidationReadinessRef {
        schema_version: READINESS_REF_SCHEMA_VERSION.to_string(),
        path: "artifacts/validation_broker/bd-y4mkq/proof-lane/readiness.json".to_string(),
        digest: DigestRef::sha256(b"validation-closeout-readiness-ref"),
        generated_at: ts(1),
        freshness_expires_at: ts(60),
        reason_code: reason_code.to_string(),
        event_code: "PLR-002".to_string(),
        required_action: "record_source_only_blocker".to_string(),
    }
}

fn scheduler_digest(material: &str) -> ValidationSwarmSchedulerDigestRef {
    ValidationSwarmSchedulerDigestRef::sha256_material(material)
}

fn scheduler_capacity(
    slots_total: u16,
    slots_available: u16,
    queue_depth: u16,
) -> ValidationSwarmSchedulerCapacitySnapshot {
    ValidationSwarmSchedulerCapacitySnapshot {
        snapshot_id: "closeout-scheduler-capacity".to_string(),
        captured_at: ts(1),
        workers_total: 4,
        workers_healthy: 3,
        slots_total,
        slots_available,
        queue_depth,
        stale_active_builds: 0,
        disk_pressure_workers: 0,
    }
}

fn scheduler_input(seed: &str) -> ValidationSwarmSchedulerInput {
    ValidationSwarmSchedulerInput {
        schema_version:
            frankenengine_node::ops::validation_proof_coalescer::SWARM_SCHEDULER_INPUT_SCHEMA_VERSION
                .to_string(),
        input_id: format!("closeout-{seed}"),
        bead_id: "bd-y4mkq".to_string(),
        agent_name: "RusticPlateau".to_string(),
        proof_work_key: scheduler_digest(&format!("closeout-proof-work/{seed}")),
        command_digest: scheduler_digest(&format!("cargo test validation_closeout/{seed}")),
        dirty_state_policy: DirtyStatePolicy::CleanRequired,
        target_dir_class: ValidationSwarmSchedulerTargetDirClass::OffRepo,
        capacity_snapshot: scheduler_capacity(8, 1, 80),
        coalescer_state: ValidationSwarmSchedulerCoalescerState::None,
        flight_recorder_state: ValidationSwarmSchedulerFlightRecorderState::None,
        proof_debt_class: ValidationSwarmSchedulerProofDebtClass::None,
        queue_age_ms: 300_000,
        priority: ValidationSwarmSchedulerPriority::P2,
        timeout_budget_ms: 600_000,
        source_only_allowed: false,
        product_failure: false,
        worker_infra_retryable: false,
        artifact_valid: true,
    }
}

fn scheduler_decision(
    seed: &str,
    mutate: impl FnOnce(&mut ValidationSwarmSchedulerInput),
) -> ValidationSwarmSchedulerDecision {
    let mut input = scheduler_input(seed);
    mutate(&mut input);
    decide_validation_swarm_schedule(
        &ValidationSwarmSchedulerPolicy::default_policy("validation-closeout-scheduler/v1"),
        &input,
        ts(2),
    )
    .expect("scheduler decision")
}

fn audit_evidence(
    id: &str,
    kind: CompletionAuditEvidenceKind,
    coverage: CompletionAuditCoverage,
    status: CompletionAuditEvidenceStatus,
) -> CompletionAuditEvidenceRef {
    CompletionAuditEvidenceRef::new(id, kind, coverage, status, format!("{id} evidence"))
}

fn audit_requirement(
    id: &str,
    evidence: Vec<CompletionAuditEvidenceRef>,
) -> CompletionAuditRequirement {
    CompletionAuditRequirement::new(id, format!("{id} requirement"), evidence)
}

fn completion_audit(
    requirements: Vec<CompletionAuditRequirement>,
) -> Result<PromptToArtifactCompletionAuditLedger, CompletionAuditLedgerError> {
    PromptToArtifactCompletionAuditLedger::new(
        "bd-38hez.1",
        "Prompt-to-artifact completion audit ledger",
        requirements,
    )
    .validated()
}

#[test]
fn ready_receipt_renders_close_reason_and_agent_mail_summary() {
    let now = ts(1);
    let receipt = receipt(
        "bd-y4mkq",
        now,
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        ts(60),
    );
    let options = ValidationCloseoutOptions::new("bd-y4mkq", "vc-ready");

    let report =
        build_validation_closeout_report(&receipt, &options, ts(2)).expect("ready closeout report");

    assert_eq!(report.status, ValidationCloseoutStatus::Ready);
    assert!(report.close_reason.contains("status=READY"));
    assert!(report.close_reason.contains("worker=ts2"));
    assert!(report.agent_mail_markdown.contains("validation closeout"));
    assert!(report.agent_mail_markdown.contains("summary_artifact"));
}

#[test]
fn completion_audit_normalizes_sorted_direct_evidence_golden_json() -> TestResult {
    let audit = PromptToArtifactCompletionAuditLedger::new(
        "bd-38hez.1",
        "Prompt-to-artifact completion audit ledger",
        vec![
            audit_requirement(
                "req-2-tests",
                vec![
                    audit_evidence(
                        "ev-z-test",
                        CompletionAuditEvidenceKind::Test,
                        CompletionAuditCoverage::Direct,
                        CompletionAuditEvidenceStatus::Fresh,
                    )
                    .with_command(
                        "rch exec -- cargo test -p frankenengine-node validation_closeout",
                    ),
                ],
            ),
            audit_requirement(
                "req-1-schema",
                vec![
                    audit_evidence(
                        "ev-a-spec",
                        CompletionAuditEvidenceKind::File,
                        CompletionAuditCoverage::Direct,
                        CompletionAuditEvidenceStatus::Fresh,
                    )
                    .with_path("docs/specs/validation_closeout.md"),
                ],
            ),
        ],
    )
    .validated()?;

    assert_eq!(audit.status, CompletionAuditLedgerStatus::Proven);
    assert_eq!(audit.direct_evidence_count, 2);
    assert_eq!(audit.proxy_evidence_count, 0);
    assert_eq!(audit.requirements[0].requirement_id, "req-1-schema");
    assert_eq!(audit.requirements[1].requirement_id, "req-2-tests");

    let audit_json = serde_json::to_value(&audit)?;
    assert_eq!(
        audit_json,
        json!({
            "schema_version": "franken-node/completion-audit-ledger/v1",
            "objective_id": "bd-38hez.1",
            "objective_summary": "Prompt-to-artifact completion audit ledger",
            "status": "proven",
            "reason_code": "VC_AUDIT_PROVEN",
            "event_code": "VC-AUDIT-001",
            "required_action": "close_with_direct_evidence",
            "direct_evidence_count": 2,
            "proxy_evidence_count": 0,
            "requirements": [
                {
                    "requirement_id": "req-1-schema",
                    "requirement_text": "req-1-schema requirement",
                    "status": "proven",
                    "reason_code": "VC_AUDIT_PROVEN",
                    "required_action": "close_with_direct_evidence",
                    "evidence": [
                        {
                            "evidence_id": "ev-a-spec",
                            "kind": "file",
                            "coverage": "direct",
                            "status": "fresh",
                            "description": "ev-a-spec evidence",
                            "path": "docs/specs/validation_closeout.md"
                        }
                    ]
                },
                {
                    "requirement_id": "req-2-tests",
                    "requirement_text": "req-2-tests requirement",
                    "status": "proven",
                    "reason_code": "VC_AUDIT_PROVEN",
                    "required_action": "close_with_direct_evidence",
                    "evidence": [
                        {
                            "evidence_id": "ev-z-test",
                            "kind": "test",
                            "coverage": "direct",
                            "status": "fresh",
                            "description": "ev-z-test evidence",
                            "command": "rch exec -- cargo test -p frankenengine-node validation_closeout"
                        }
                    ]
                }
            ]
        })
    );

    Ok(())
}

#[test]
fn completion_audit_proxy_only_false_green_surfaces_warning_and_json() -> TestResult {
    let audit = completion_audit(vec![audit_requirement(
        "req-direct-test",
        vec![
            audit_evidence(
                "ev-green-manifest",
                CompletionAuditEvidenceKind::Manifest,
                CompletionAuditCoverage::Proxy,
                CompletionAuditEvidenceStatus::Fresh,
            )
            .with_path("artifacts/validation_broker/bd-y4mkq/summary.md"),
        ],
    )])?;
    let receipt = receipt(
        "bd-y4mkq",
        ts(1),
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        ts(60),
    );
    let options =
        ValidationCloseoutOptions::new("bd-y4mkq", "vc-proxy-audit").with_completion_audit(audit);

    let report = build_validation_closeout_report(&receipt, &options, ts(2))?;

    assert_eq!(report.status, ValidationCloseoutStatus::Ready);
    let audit = report.completion_audit.as_ref().expect("completion audit");
    assert_eq!(audit.status, CompletionAuditLedgerStatus::ProxyOnly);
    assert_eq!(audit.reason_code, completion_audit_reason_codes::PROXY_ONLY);
    assert!(
        report
            .close_reason
            .contains("completion_audit_status=PROXY_ONLY")
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("completion audit is PROXY_ONLY"))
    );
    assert!(
        report
            .agent_mail_markdown
            .contains("- completion_audit: status=`PROXY_ONLY`")
    );

    let json: Value = serde_json::from_str(&render_validation_closeout_json(&report)?)?;
    assert_eq!(json["completion_audit"]["status"], "proxy_only");
    assert_eq!(
        json["completion_audit"]["requirements"][0]["evidence"][0]["coverage"],
        "proxy"
    );

    let log: Value =
        serde_json::from_str(render_validation_closeout_structured_log_jsonl(&report)?.trim())?;
    assert_eq!(log["detail"]["completion_audit_status"], "PROXY_ONLY");
    assert_eq!(
        log["detail"]["completion_audit_required_action"],
        "replace_proxy_with_direct_evidence"
    );

    Ok(())
}

#[test]
fn completion_audit_missing_evidence_fails_closed_with_reason_code() -> TestResult {
    let audit = completion_audit(vec![audit_requirement("req-missing-proof", Vec::new())])?;

    assert_eq!(audit.status, CompletionAuditLedgerStatus::MissingEvidence);
    assert_eq!(
        audit.reason_code,
        completion_audit_reason_codes::MISSING_EVIDENCE
    );
    assert_eq!(audit.required_action, "collect_missing_evidence");
    Ok(())
}

#[test]
fn completion_audit_stale_bead_state_requires_refresh() -> TestResult {
    let audit = completion_audit(vec![audit_requirement(
        "req-current-bead-state",
        vec![
            audit_evidence(
                "ev-stale-bead",
                CompletionAuditEvidenceKind::Bead,
                CompletionAuditCoverage::Direct,
                CompletionAuditEvidenceStatus::Stale,
            )
            .with_bead_id("bd-y4mkq")
            .with_agent_mail_thread_id("bd-y4mkq"),
        ],
    )])?;

    assert_eq!(audit.status, CompletionAuditLedgerStatus::Stale);
    assert_eq!(
        audit.reason_code,
        completion_audit_reason_codes::STALE_EVIDENCE
    );
    assert_eq!(audit.required_action, "refresh_stale_evidence");
    Ok(())
}

#[test]
fn completion_audit_blocked_rch_proof_records_blocker_action() -> TestResult {
    let audit =
        completion_audit(vec![audit_requirement(
            "req-rch-proof",
            vec![audit_evidence(
            "ev-blocked-rch",
            CompletionAuditEvidenceKind::Command,
            CompletionAuditCoverage::Direct,
            CompletionAuditEvidenceStatus::Blocked,
        )
        .with_command(
            "rch exec -- cargo test -p frankenengine-node validation_closeout -- --nocapture",
        )
        .with_bead_id("bd-dpfyo")],
        )])?;

    assert_eq!(audit.status, CompletionAuditLedgerStatus::Blocked);
    assert_eq!(
        audit.reason_code,
        completion_audit_reason_codes::BLOCKED_PROOF
    );
    assert_eq!(audit.required_action, "record_blocker_and_retry");
    Ok(())
}

#[test]
fn completion_audit_rejects_protected_workspace_paths() {
    let err = completion_audit(vec![audit_requirement(
        "req-protected-path",
        vec![
            audit_evidence(
                "ev-beads-jsonl",
                CompletionAuditEvidenceKind::File,
                CompletionAuditCoverage::Direct,
                CompletionAuditEvidenceStatus::Fresh,
            )
            .with_path("/data/projects/franken_node/.beads/issues.jsonl"),
        ],
    )])
    .expect_err("protected bead state path should be rejected as evidence");

    assert_eq!(err.code(), "ERR_VC_AUDIT_PROTECTED_PATH");
}

#[test]
fn closeout_surfaces_swarm_scheduler_decision_in_json_markdown_and_structured_log() -> TestResult {
    let now = ts(1);
    let receipt = receipt(
        "bd-y4mkq",
        now,
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        ts(60),
    );
    let decision = scheduler_decision("capacity", |input| {
        input.capacity_snapshot = scheduler_capacity(8, 0, 96);
        input.worker_infra_retryable = true;
        input.queue_age_ms = 900_000;
    });
    let options = ValidationCloseoutOptions::new("bd-y4mkq", "vc-scheduler")
        .with_swarm_scheduler_decision(&decision);

    let report = build_validation_closeout_report(&receipt, &options, ts(2))?;

    assert_eq!(report.status, ValidationCloseoutStatus::Ready);
    assert!(
        report
            .close_reason
            .contains("scheduler_decision=wait_for_capacity")
    );
    assert!(
        report
            .close_reason
            .contains("scheduler_queue_age_ms=900000")
    );
    assert!(
        report
            .agent_mail_markdown
            .contains("- swarm_scheduler_decision: `wait_for_capacity`")
    );
    assert!(
        report
            .agent_mail_markdown
            .contains("- swarm_scheduler_slo: fairness_bucket=`aging`")
    );

    let json: Value = serde_json::from_str(&render_validation_closeout_json(&report)?)?;
    assert_eq!(
        json["swarm_scheduler"]["scheduler_decision"],
        "wait_for_capacity"
    );
    assert_eq!(json["swarm_scheduler"]["next_action"], "wait_for_capacity");
    assert_eq!(json["swarm_scheduler"]["queue_age_ms"], 900_000);
    assert_eq!(json["swarm_scheduler"]["slo_breached"], true);

    let logs = render_validation_closeout_structured_log_jsonl(&report)?;
    let log_json: Value = serde_json::from_str(logs.trim())?;
    assert_eq!(
        log_json["detail"]["scheduler_decision"],
        "wait_for_capacity"
    );
    assert_eq!(
        log_json["detail"]["scheduler_required_action"],
        "wait_for_capacity"
    );
    assert_eq!(log_json["detail"]["scheduler_queue_age_ms"], 900_000);
    assert_eq!(log_json["detail"]["scheduler_slo_breached"], true);
    assert!(
        log_json["detail"]["scheduler_recorder_path"]
            .as_str()
            .is_some()
    );

    Ok(())
}

#[test]
fn source_only_receipt_warns_with_explicit_caveat() {
    let now = ts(1);
    let receipt = receipt(
        "bd-y4mkq",
        now,
        ValidationExitKind::SourceOnly,
        ValidationErrorClass::SourceOnly,
        TimeoutClass::None,
        ts(60),
    );
    let options = ValidationCloseoutOptions::new("bd-y4mkq", "vc-source-only");

    let report = build_validation_closeout_report(&receipt, &options, ts(2))
        .expect("source-only closeout report");

    assert_eq!(report.status, ValidationCloseoutStatus::SourceOnly);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("source-only fallback"))
    );
    assert!(report.close_reason.contains("status=SOURCE_ONLY"));
}

#[test]
fn source_only_closeout_cites_readiness_ref() -> Result<(), Box<dyn std::error::Error>> {
    let now = ts(1);
    let mut receipt = receipt(
        "bd-y4mkq",
        now,
        ValidationExitKind::SourceOnly,
        ValidationErrorClass::SourceOnly,
        TimeoutClass::None,
        ts(60),
    );
    receipt.classifications.source_only_reason = Some(SourceOnlyReason::ProofLaneWorkerAuthFailed);
    receipt.readiness_ref = Some(readiness_ref(
        readiness_ref_reason_codes::WORKER_AUTH_FAILED,
    ));
    let options = ValidationCloseoutOptions::new("bd-y4mkq", "vc-readiness-ref");

    let report = build_validation_closeout_report(&receipt, &options, ts(2))?;

    assert_eq!(report.status, ValidationCloseoutStatus::SourceOnly);
    assert!(report.close_reason.contains("readiness_ref="));
    assert!(
        report
            .agent_mail_markdown
            .contains("- readiness_reason: `PLR_WORKER_AUTH_FAILED`")
    );
    let json = serde_json::to_value(&report)?;
    assert_eq!(
        json["readiness_ref"]["reason_code"],
        readiness_ref_reason_codes::WORKER_AUTH_FAILED
    );
    assert_eq!(
        json["receipt"]["readiness_ref"]["required_action"],
        "record_source_only_blocker"
    );

    Ok(())
}

#[test]
fn failed_receipt_blocks_green_closeout() {
    let now = ts(1);
    let receipt = receipt(
        "bd-y4mkq",
        now,
        ValidationExitKind::Failed,
        ValidationErrorClass::TestFailure,
        TimeoutClass::None,
        ts(60),
    );
    let options = ValidationCloseoutOptions::new("bd-y4mkq", "vc-failed");

    let report = build_validation_closeout_report(&receipt, &options, ts(2))
        .expect("failed closeout report");

    assert_eq!(report.status, ValidationCloseoutStatus::Blocked);
    assert!(report.close_reason.contains("status=BLOCKED"));
    assert!(report.close_reason.contains("error_class=test_failure"));
}

#[test]
fn stale_receipt_is_not_closeout_evidence() {
    let now = ts(1);
    let receipt = receipt(
        "bd-y4mkq",
        now,
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        ts(2),
    );
    let options = ValidationCloseoutOptions::new("bd-y4mkq", "vc-stale");

    let report = build_validation_closeout_report(&receipt, &options, ts(3))
        .expect("stale report should still render");

    assert_eq!(report.status, ValidationCloseoutStatus::Stale);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("stale validation receipt"))
    );
}

#[test]
fn receipt_bead_mismatch_fails_closed() {
    let now = ts(1);
    let receipt = receipt(
        "bd-other",
        now,
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        ts(60),
    );
    let options = ValidationCloseoutOptions::new("bd-y4mkq", "vc-mismatch");

    let err = build_validation_closeout_report(&receipt, &options, ts(2))
        .expect_err("bead mismatch must fail");

    assert!(matches!(err, ValidationCloseoutError::BeadMismatch { .. }));
}

#[test]
fn output_excerpt_redaction_is_bounded_and_utf8_safe() {
    let text = format!("{}{}", "a".repeat(16), "é".repeat(16));

    let excerpt = redact_output_excerpt("stderr", &text, 19);

    assert!(excerpt.truncated);
    assert!(excerpt.included_bytes <= 19);
    assert!(excerpt.text.ends_with("[truncated]"));
    assert!(std::str::from_utf8(excerpt.text.as_bytes()).is_ok());
}

#[test]
fn cli_json_renders_closeout_from_temp_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let receipt_path = dir.path().join("receipt.json");
    let stdout_path = dir.path().join("stdout.txt");
    let now = Utc::now();
    let receipt = receipt(
        "bd-y4mkq",
        now,
        ValidationExitKind::Success,
        ValidationErrorClass::None,
        TimeoutClass::None,
        now + Duration::days(1),
    );
    std::fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt)?)?;
    std::fs::write(&stdout_path, "validation ok\n")?;

    let output = Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(dir.path())
        .args([
            "ops",
            "validation-closeout",
            "--bead-id",
            "bd-y4mkq",
            "--receipt",
            "receipt.json",
            "--stdout-excerpt",
            "stdout.txt",
            "--trace-id",
            "vc-cli-json",
            "--json",
        ])
        .output()
        .expect("run franken-node ops validation-closeout");
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;

    assert_eq!(report["command"], "ops validation-closeout");
    assert_eq!(report["trace_id"], "vc-cli-json");
    assert_eq!(report["status"], "ready");
    assert!(
        report["close_reason"]
            .as_str()
            .expect("close reason")
            .contains("status=READY")
    );
    assert_eq!(report["output_excerpts"][0]["stream"], "stdout");
    Ok(())
}
