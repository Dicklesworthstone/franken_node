use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, InputDigest, ProofEvidenceSource, ProofStatusKind,
    RchMode, RchReceipt, ReceiptArtifacts, ReceiptClassifications, ReceiptRequestRef, ReceiptTrust,
    SourceOnlyReason, TargetDirPolicy, TimeoutClass, ValidationErrorClass, ValidationExit,
    ValidationExitKind, ValidationProofStatus, ValidationReceipt, ValidationTiming,
};
use frankenengine_node::ops::validation_readiness::{
    PROOF_LANE_READINESS_FIXTURE_SCHEMA_VERSION, ProofLaneCapabilityStatus, ProofLaneCommandIntent,
    ProofLanePressureStatus, ProofLaneRchSnapshot, ProofLaneReadinessDecisionKind,
    ProofLaneReadinessFixtureCatalog, ProofLaneReadinessInput, ProofLaneReadinessProducer,
    ProofLaneToolchainRequirement, ProofLaneWorkerAuthStatus, ProofLaneWorkerCapability,
    ProofLaneWorkerSelection, RchWorkerReadiness, ResourceContentionSnapshot,
    TrackedValidationBead, ValidationBeadState, ValidationReadinessFixtureCatalog,
    ValidationReadinessInput, ValidationReadinessStatus, build_validation_readiness_report,
    classify_proof_lane_readiness, known_check_codes, proof_lane_event_codes,
    proof_lane_reason_codes, render_validation_readiness_human,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

fn ts(seconds: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0)
        .single()
        .expect("valid timestamp")
        + chrono::Duration::seconds(i64::from(seconds))
}

fn plr_ts(seconds: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 0, 0, 0)
        .single()
        .expect("valid timestamp")
        + chrono::Duration::seconds(i64::from(seconds))
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
            "validation_readiness".to_string(),
        ],
        cwd: "/data/projects/franken_node".to_string(),
        environment_policy_id: "validation-readiness/env-policy/v1".to_string(),
        target_dir_policy_id: "validation-readiness/target-dir/off-repo/v1".to_string(),
    }
}

fn receipt(
    bead_id: &str,
    exit_kind: ValidationExitKind,
    error_class: ValidationErrorClass,
    timeout_class: TimeoutClass,
    freshness_expires_at: DateTime<Utc>,
) -> ValidationReceipt {
    let command = command();
    let command_digest = command.digest();
    let request_id = format!("{bead_id}-request");
    ValidationReceipt {
        schema_version: "franken-node/validation-broker/receipt/v1".to_string(),
        receipt_id: format!("{bead_id}-receipt"),
        request_id: request_id.clone(),
        bead_id: bead_id.to_string(),
        thread_id: bead_id.to_string(),
        request_ref: ReceiptRequestRef {
            request_id,
            bead_id: bead_id.to_string(),
            thread_id: bead_id.to_string(),
            dedupe_key: DigestRef::sha256(format!("{bead_id}-dedupe").as_bytes()),
            cross_thread_waiver: None,
        },
        command,
        command_digest,
        environment_policy: EnvironmentPolicy {
            policy_id: "validation-readiness/env-policy/v1".to_string(),
            allowed_env: vec![
                "CARGO_TARGET_DIR".to_string(),
                "RCH_REQUIRE_REMOTE".to_string(),
            ],
            redacted_env: Vec::new(),
            remote_required: true,
            network_policy: "rch-only".to_string(),
        },
        target_dir_policy: TargetDirPolicy {
            policy_id: "validation-readiness/target-dir/off-repo/v1".to_string(),
            kind: "off-repo".to_string(),
            path: "/data/tmp/franken_node-validation-readiness-target".to_string(),
            path_digest: DigestRef::sha256(b"/data/tmp/franken_node-validation-readiness-target"),
            cleanup: "caller-owned".to_string(),
        },
        input_digests: vec![InputDigest::new(
            "crates/franken-node/src/ops/validation_readiness.rs",
            b"validation-readiness-source",
            "git",
        )],
        rch: RchReceipt {
            mode: RchMode::Remote,
            worker_id: Some("ts2".to_string()),
            require_remote: true,
            capability_observation_id: Some("cap-ts2".to_string()),
            worker_pool: "default".to_string(),
        },
        timing: ValidationTiming {
            started_at: ts(1),
            finished_at: ts(2),
            duration_ms: 1000,
            freshness_expires_at,
        },
        exit: ValidationExit {
            kind: exit_kind,
            code: match exit_kind {
                ValidationExitKind::Success => Some(0),
                ValidationExitKind::SourceOnly => None,
                _ => Some(1),
            },
            signal: None,
            timeout_class,
            error_class,
            retryable: matches!(error_class, ValidationErrorClass::WorkerInfra),
        },
        artifacts: ReceiptArtifacts {
            stdout_path: "artifacts/validation_broker/stdout.txt".to_string(),
            stderr_path: "artifacts/validation_broker/stderr.txt".to_string(),
            summary_path: "artifacts/validation_broker/summary.json".to_string(),
            receipt_path: "artifacts/validation_broker/receipt.json".to_string(),
            stdout_digest: DigestRef::sha256(b"stdout"),
            stderr_digest: DigestRef::sha256(b"stderr"),
        },
        trust: ReceiptTrust {
            generated_by: "validation-broker".to_string(),
            agent_name: "RusticPlateau".to_string(),
            git_commit: "77adfbd6".to_string(),
            dirty_worktree: false,
            freshness: "fresh".to_string(),
            signature_status: "unsigned-test-fixture".to_string(),
        },
        classifications: ReceiptClassifications {
            source_only_fallback: exit_kind == ValidationExitKind::SourceOnly,
            source_only_reason: (exit_kind == ValidationExitKind::SourceOnly)
                .then_some(SourceOnlyReason::DocsOnly),
            doctor_readiness: "ready".to_string(),
            ci_consumable: exit_kind == ValidationExitKind::Success,
        },
    }
}

fn allow_resource_snapshot() -> ResourceContentionSnapshot {
    ResourceContentionSnapshot {
        decision: "allow".to_string(),
        reason_code: "RG-ALLOW".to_string(),
        reason: "validation pressure is acceptable".to_string(),
        rch_queue_depth: Some(0),
        active_proof_classes: Vec::new(),
    }
}

fn remote_worker() -> RchWorkerReadiness {
    RchWorkerReadiness {
        worker_id: "ts2".to_string(),
        reachable: true,
        mode: RchMode::Remote,
        required_toolchains: vec!["nightly-2026-02-19".to_string()],
        observed_toolchains: vec!["nightly-2026-02-19".to_string()],
        failure: None,
    }
}

fn proof_lane_capability() -> ProofLaneWorkerCapability {
    ProofLaneWorkerCapability {
        auth_status: ProofLaneWorkerAuthStatus::Ok,
        capability_status: ProofLaneCapabilityStatus::Fresh,
        pressure_status: ProofLanePressureStatus::Healthy,
        observed_at: Some(ts(10)),
        freshness_expires_at: Some(ts(40)),
        rustc: Some("rustc 1.97.0-nightly".to_string()),
        observed_toolchains: vec!["nightly-2026-02-19".to_string()],
        detail: Some("fresh same-toolchain worker".to_string()),
    }
}

fn proof_lane_input() -> ProofLaneReadinessInput {
    let mut worker_capabilities = BTreeMap::new();
    worker_capabilities.insert("ts2".to_string(), proof_lane_capability());
    ProofLaneReadinessInput {
        capsule_id: "plr-bd-yyl6t-2".to_string(),
        trace_id: "trace-proof-lane".to_string(),
        bead_id: "bd-yyl6t.2".to_string(),
        thread_id: "bd-yyl6t.2".to_string(),
        created_at: ts(10),
        freshness_expires_at: ts(40),
        producer: ProofLaneReadinessProducer {
            name: "franken-node ops validation-readiness".to_string(),
            agent_name: "PurpleLeopard".to_string(),
            git_commit: "7a514dd0".to_string(),
            dirty_worktree: false,
        },
        command: ProofLaneCommandIntent {
            program: "cargo".to_string(),
            argv: vec![
                "test".to_string(),
                "-p".to_string(),
                "frankenengine-node".to_string(),
                "validation_readiness".to_string(),
            ],
            cwd: "/data/projects/franken_node".to_string(),
            digest: DigestRef::sha256(b"cargo test -p frankenengine-node validation_readiness"),
        },
        rch: ProofLaneRchSnapshot {
            daemon_source: "installed".to_string(),
            daemon_version: "1.0.24".to_string(),
            socket_path: "/run/user/1000/rch.sock".to_string(),
            require_remote: true,
            local_fallback_allowed: false,
            local_fallback_refused: true,
        },
        worker_selection: ProofLaneWorkerSelection {
            requested_workers: vec!["ts2".to_string()],
            selected_worker: Some("ts2".to_string()),
            override_effective: false,
            selection_source: "dry_run".to_string(),
            selection_observed_at: Some(ts(11)),
        },
        toolchain: ProofLaneToolchainRequirement {
            local_rustc: "rustc 1.97.0-nightly".to_string(),
            required_toolchain: "nightly-2026-02-19".to_string(),
        },
        worker_capabilities,
        observed_validation_error_class: None,
    }
}

fn assert_proof_lane_decision(
    input: &ProofLaneReadinessInput,
    now: DateTime<Utc>,
    decision: ProofLaneReadinessDecisionKind,
    reason_code: &str,
    event_code: &str,
) {
    let capsule = classify_proof_lane_readiness(input, now);
    assert_eq!(capsule.decision.decision, decision);
    assert_eq!(capsule.decision.reason_code, reason_code);
    assert_eq!(capsule.decision.event_code, event_code);
}

#[test]
fn proof_lane_classifier_allows_healthy_same_toolchain_remote_lane() {
    let input = proof_lane_input();

    let capsule = classify_proof_lane_readiness(&input, ts(30));

    assert_eq!(
        capsule.decision.decision,
        ProofLaneReadinessDecisionKind::ReadyToLaunch
    );
    assert_eq!(
        capsule.decision.reason_code,
        proof_lane_reason_codes::HEALTHY_SAME_TOOLCHAIN_LANE
    );
    assert_eq!(
        capsule.decision.event_code,
        proof_lane_event_codes::HEALTHY_SAME_TOOLCHAIN_LANE
    );
    assert!(!capsule.decision.fail_closed);
    assert!(capsule.worker_selection.override_effective);
    assert!(capsule.toolchain.same_toolchain);
}

#[test]
fn proof_lane_classifier_blocks_unhonored_worker_override() {
    let mut input = proof_lane_input();
    input
        .worker_capabilities
        .insert("vmi1153651".to_string(), proof_lane_capability());
    input.worker_selection.selected_worker = Some("vmi1153651".to_string());

    let capsule = classify_proof_lane_readiness(&input, ts(30));

    assert_eq!(
        capsule.decision.decision,
        ProofLaneReadinessDecisionKind::SourceOnlyBlocker
    );
    assert_eq!(
        capsule.decision.reason_code,
        proof_lane_reason_codes::OVERRIDE_NOT_HONORED
    );
    assert_eq!(
        capsule.decision.event_code,
        proof_lane_event_codes::OVERRIDE_NOT_HONORED
    );
    assert!(capsule.decision.retryable);
    assert!(capsule.decision.fail_closed);
    assert!(!capsule.worker_selection.override_effective);
}

#[test]
fn proof_lane_classifier_blocks_selected_worker_toolchain_mismatch() {
    let mut input = proof_lane_input();
    let mut capability = proof_lane_capability();
    capability.rustc = Some("rustc 1.95.0-nightly".to_string());
    capability.observed_toolchains = vec!["stable".to_string()];
    input
        .worker_capabilities
        .insert("ts2".to_string(), capability);

    assert_proof_lane_decision(
        &input,
        ts(30),
        ProofLaneReadinessDecisionKind::SourceOnlyBlocker,
        proof_lane_reason_codes::SAME_TOOLCHAIN_MISSING,
        proof_lane_event_codes::SAME_TOOLCHAIN_MISSING,
    );
}

#[test]
fn proof_lane_classifier_blocks_worker_auth_failure() {
    let mut input = proof_lane_input();
    let mut capability = proof_lane_capability();
    capability.auth_status = ProofLaneWorkerAuthStatus::PermissionDenied;
    capability.detail = Some("Permission denied (publickey,password)".to_string());
    input
        .worker_capabilities
        .insert("ts2".to_string(), capability);

    assert_proof_lane_decision(
        &input,
        ts(30),
        ProofLaneReadinessDecisionKind::SourceOnlyBlocker,
        proof_lane_reason_codes::WORKER_AUTH_FAILED,
        proof_lane_event_codes::WORKER_AUTH_FAILED,
    );
}

#[test]
fn proof_lane_classifier_retries_missing_or_stale_capability_snapshot() {
    let mut missing = proof_lane_input();
    missing.worker_capabilities.clear();

    assert_proof_lane_decision(
        &missing,
        ts(30),
        ProofLaneReadinessDecisionKind::RetryPreflight,
        proof_lane_reason_codes::WORKER_CAPABILITY_UNKNOWN,
        proof_lane_event_codes::WORKER_CAPABILITY_UNKNOWN,
    );

    let mut stale = proof_lane_input();
    let mut capability = proof_lane_capability();
    capability.capability_status = ProofLaneCapabilityStatus::Stale;
    capability.freshness_expires_at = Some(ts(20));
    stale
        .worker_capabilities
        .insert("ts2".to_string(), capability);

    assert_proof_lane_decision(
        &stale,
        ts(30),
        ProofLaneReadinessDecisionKind::RetryPreflight,
        proof_lane_reason_codes::WORKER_CAPABILITY_UNKNOWN,
        proof_lane_event_codes::WORKER_CAPABILITY_UNKNOWN,
    );
}

#[test]
fn proof_lane_classifier_queues_pressure_blocked_worker() {
    let mut input = proof_lane_input();
    let mut capability = proof_lane_capability();
    capability.pressure_status = ProofLanePressureStatus::Blocked;
    input
        .worker_capabilities
        .insert("ts2".to_string(), capability);

    let capsule = classify_proof_lane_readiness(&input, ts(30));

    assert_eq!(
        capsule.decision.decision,
        ProofLaneReadinessDecisionKind::QueueUntilReady
    );
    assert_eq!(
        capsule.decision.reason_code,
        proof_lane_reason_codes::WORKER_PRESSURE_BLOCKED
    );
    assert_eq!(
        capsule.decision.event_code,
        proof_lane_event_codes::WORKER_PRESSURE_BLOCKED
    );
    assert!(capsule.decision.retryable);
    assert!(!capsule.decision.fail_closed);
}

#[test]
fn proof_lane_classifier_blocks_refused_local_fallback() {
    let mut input = proof_lane_input();
    input.worker_selection.selected_worker = None;
    input.worker_capabilities.clear();

    assert_proof_lane_decision(
        &input,
        ts(30),
        ProofLaneReadinessDecisionKind::SourceOnlyBlocker,
        proof_lane_reason_codes::LOCAL_FALLBACK_REFUSED,
        proof_lane_event_codes::LOCAL_FALLBACK_REFUSED,
    );
}

#[test]
fn proof_lane_classifier_rejects_stale_capsules_and_product_failures() {
    let mut stale = proof_lane_input();
    stale.freshness_expires_at = ts(20);

    assert_proof_lane_decision(
        &stale,
        ts(30),
        ProofLaneReadinessDecisionKind::FailClosed,
        proof_lane_reason_codes::STALE_READINESS_CAPSULE,
        proof_lane_event_codes::STALE_READINESS_CAPSULE,
    );

    let mut product_failure = proof_lane_input();
    product_failure.observed_validation_error_class = Some(ValidationErrorClass::TestFailure);

    assert_proof_lane_decision(
        &product_failure,
        ts(30),
        ProofLaneReadinessDecisionKind::FailClosed,
        proof_lane_reason_codes::MALFORMED_READINESS_INPUT,
        proof_lane_event_codes::MALFORMED_READINESS_INPUT,
    );
}

#[test]
fn checked_in_proof_lane_fixture_catalog_matches_golden_capsules() {
    let catalog: ProofLaneReadinessFixtureCatalog = serde_json::from_str(include_str!(
        "../../../artifacts/validation_broker/bd-yyl6t/proof_lane_readiness_fixtures.v1.json"
    ))
    .expect("proof-lane fixture catalog parses");
    assert_eq!(
        catalog.schema_version,
        PROOF_LANE_READINESS_FIXTURE_SCHEMA_VERSION
    );
    assert!(catalog.fixtures.len() >= 7);

    let now = plr_ts(300);
    for fixture in catalog.fixtures {
        let actual = classify_proof_lane_readiness(&fixture.input, now);
        assert_eq!(actual, fixture.expected_capsule, "{} capsule", fixture.name);
        assert_eq!(
            serde_json::to_value(&actual).expect("actual capsule serializes"),
            serde_json::to_value(&fixture.expected_capsule).expect("expected capsule serializes"),
            "{} serialized capsule",
            fixture.name
        );
        assert!(
            actual.created_at <= actual.freshness_expires_at,
            "{} freshness window",
            fixture.name
        );
        assert!(
            now <= actual.freshness_expires_at,
            "{} capsule is fresh at replay time",
            fixture.name
        );
        assert!(
            known_proof_lane_reason_event_pair(
                &actual.decision.reason_code,
                &actual.decision.event_code
            ),
            "{} known reason/event pair",
            fixture.name
        );
        assert!(
            actual.worker_access.detail.len() <= 1024,
            "{} bounded worker detail",
            fixture.name
        );
        assert!(
            actual.decision.operator_summary.len() <= 1024,
            "{} bounded operator summary",
            fixture.name
        );
    }
}

fn known_proof_lane_reason_event_pair(reason_code: &str, event_code: &str) -> bool {
    matches!(
        (reason_code, event_code),
        (
            proof_lane_reason_codes::HEALTHY_SAME_TOOLCHAIN_LANE,
            proof_lane_event_codes::HEALTHY_SAME_TOOLCHAIN_LANE
        ) | (
            proof_lane_reason_codes::OVERRIDE_NOT_HONORED,
            proof_lane_event_codes::OVERRIDE_NOT_HONORED
        ) | (
            proof_lane_reason_codes::SAME_TOOLCHAIN_MISSING,
            proof_lane_event_codes::SAME_TOOLCHAIN_MISSING
        ) | (
            proof_lane_reason_codes::WORKER_AUTH_FAILED,
            proof_lane_event_codes::WORKER_AUTH_FAILED
        ) | (
            proof_lane_reason_codes::WORKER_CAPABILITY_UNKNOWN,
            proof_lane_event_codes::WORKER_CAPABILITY_UNKNOWN
        ) | (
            proof_lane_reason_codes::WORKER_PRESSURE_BLOCKED,
            proof_lane_event_codes::WORKER_PRESSURE_BLOCKED
        ) | (
            proof_lane_reason_codes::LOCAL_FALLBACK_REFUSED,
            proof_lane_event_codes::LOCAL_FALLBACK_REFUSED
        ) | (
            proof_lane_reason_codes::STALE_READINESS_CAPSULE,
            proof_lane_event_codes::STALE_READINESS_CAPSULE
        ) | (
            proof_lane_reason_codes::MALFORMED_READINESS_INPUT,
            proof_lane_event_codes::MALFORMED_READINESS_INPUT
        )
    )
}

#[test]
fn fresh_successful_receipt_passes_and_records_last_cargo_proof() {
    let now = ts(30);
    let input = ValidationReadinessInput {
        tracked_beads: vec![TrackedValidationBead::new(
            "bd-green",
            ValidationBeadState::Closed,
        )],
        receipts: vec![receipt(
            "bd-green",
            ValidationExitKind::Success,
            ValidationErrorClass::None,
            TimeoutClass::None,
            ts(60),
        )],
        rch_workers: vec![remote_worker()],
        resource_governor: Some(allow_resource_snapshot()),
        ..ValidationReadinessInput::default()
    };

    let report = build_validation_readiness_report(&input, "vr-pass", now);

    assert_eq!(report.overall_status, ValidationReadinessStatus::Pass);
    assert_eq!(report.summary.proof_counts.passed, 1);
    assert_eq!(report.summary.missing_required_receipts, 0);
    assert_eq!(report.summary.last_successful_cargo_proof_at, Some(ts(2)));
    assert!(render_validation_readiness_human(&report).contains("status=PASS"));
}

#[test]
fn blocked_bead_without_receipt_is_not_considered_complete() {
    let input = ValidationReadinessInput {
        tracked_beads: vec![TrackedValidationBead::new(
            "bd-blocked",
            ValidationBeadState::Blocked,
        )],
        resource_governor: Some(allow_resource_snapshot()),
        rch_workers: vec![remote_worker()],
        ..ValidationReadinessInput::default()
    };

    let report = build_validation_readiness_report(&input, "vr-blocked", ts(30));

    assert_eq!(report.overall_status, ValidationReadinessStatus::Fail);
    assert_eq!(report.summary.missing_required_receipts, 1);
    let bead_check = report
        .checks
        .iter()
        .find(|check| check.code == "VR-BEAD-003")
        .expect("bead receipt check");
    assert_eq!(bead_check.status, ValidationReadinessStatus::Fail);
    assert!(bead_check.message.contains("bd-blocked"));
}

#[test]
fn explicit_source_only_waiver_prevents_missing_receipt_failure() {
    let input = ValidationReadinessInput {
        tracked_beads: vec![
            TrackedValidationBead::new("bd-docs", ValidationBeadState::Blocked)
                .with_source_only_waiver(SourceOnlyReason::DocsOnly),
        ],
        resource_governor: Some(allow_resource_snapshot()),
        rch_workers: vec![remote_worker()],
        ..ValidationReadinessInput::default()
    };

    let report = build_validation_readiness_report(&input, "vr-source-only", ts(30));

    assert_eq!(report.summary.missing_required_receipts, 0);
    let bead_check = report
        .checks
        .iter()
        .find(|check| check.code == "VR-BEAD-003")
        .expect("bead receipt check");
    assert_eq!(bead_check.status, ValidationReadinessStatus::Pass);
}

#[test]
fn worker_timeout_is_warn_not_product_failure() {
    let input = ValidationReadinessInput {
        proof_statuses: vec![ValidationProofStatus {
            schema_version: "franken-node/validation-broker/status/v1".to_string(),
            bead_id: "bd-worker".to_string(),
            thread_id: "bd-worker".to_string(),
            request_id: Some("bd-worker-request".to_string()),
            queue_id: None,
            status: ProofStatusKind::Failed,
            proof_source: ProofEvidenceSource::FreshExecution,
            queue_state: None,
            deduplicated: false,
            queue_depth: 0,
            artifact_paths: None,
            command_digest: None,
            exit: None,
            reason: Some("worker timeout".to_string()),
            proof_cache: None,
            observed_at: ts(30),
        }],
        receipts: vec![receipt(
            "bd-worker",
            ValidationExitKind::Timeout,
            ValidationErrorClass::WorkerInfra,
            TimeoutClass::SshCommand,
            ts(60),
        )],
        rch_workers: vec![remote_worker()],
        resource_governor: Some(allow_resource_snapshot()),
        ..ValidationReadinessInput::default()
    };

    let report = build_validation_readiness_report(&input, "vr-worker", ts(30));

    assert_eq!(report.overall_status, ValidationReadinessStatus::Warn);
    assert_eq!(report.summary.product_failure_count, 0);
    assert!(report.summary.worker_failure_count > 0);
    let proof_check = report
        .checks
        .iter()
        .find(|check| check.code == "VR-PROOF-005")
        .expect("proof status check");
    assert!(proof_check.message.contains("worker/resource"));
}

#[test]
fn failed_status_with_product_exit_fails_readiness() {
    let input = ValidationReadinessInput {
        proof_statuses: vec![ValidationProofStatus {
            schema_version: "franken-node/validation-broker/status/v1".to_string(),
            bead_id: "bd-product".to_string(),
            thread_id: "bd-product".to_string(),
            request_id: Some("bd-product-request".to_string()),
            queue_id: None,
            status: ProofStatusKind::Failed,
            proof_source: ProofEvidenceSource::FreshExecution,
            queue_state: None,
            deduplicated: false,
            queue_depth: 0,
            artifact_paths: None,
            command_digest: None,
            exit: Some(ValidationExit {
                kind: ValidationExitKind::Failed,
                code: Some(101),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::TestFailure,
                retryable: false,
            }),
            reason: Some("test failure".to_string()),
            proof_cache: None,
            observed_at: ts(30),
        }],
        rch_workers: vec![remote_worker()],
        resource_governor: Some(allow_resource_snapshot()),
        ..ValidationReadinessInput::default()
    };

    let report = build_validation_readiness_report(&input, "vr-product", ts(30));

    assert_eq!(report.overall_status, ValidationReadinessStatus::Fail);
    assert_eq!(report.summary.product_failure_count, 1);
    let proof_check = report
        .checks
        .iter()
        .find(|check| check.code == "VR-PROOF-005")
        .expect("proof status check");
    assert_eq!(proof_check.status, ValidationReadinessStatus::Fail);
    assert!(proof_check.message.contains("product failure"));
}

#[test]
fn stale_receipt_fails_freshness() {
    let input = ValidationReadinessInput {
        tracked_beads: vec![TrackedValidationBead::new(
            "bd-stale",
            ValidationBeadState::Closed,
        )],
        receipts: vec![receipt(
            "bd-stale",
            ValidationExitKind::Success,
            ValidationErrorClass::None,
            TimeoutClass::None,
            ts(10),
        )],
        rch_workers: vec![remote_worker()],
        resource_governor: Some(allow_resource_snapshot()),
        ..ValidationReadinessInput::default()
    };

    let report = build_validation_readiness_report(&input, "vr-stale", ts(30));

    assert_eq!(report.overall_status, ValidationReadinessStatus::Fail);
    assert_eq!(report.summary.stale_receipt_count, 1);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.code == "VR-RECEIPT-004"
                && check.status == ValidationReadinessStatus::Fail)
    );
}

#[test]
fn checked_in_fixture_catalog_matches_report_expectations() {
    let catalog: ValidationReadinessFixtureCatalog = serde_json::from_str(include_str!(
        "../../../artifacts/validation_broker/bd-mwu8b/validation_readiness_fixtures.v1.json"
    ))
    .expect("fixture catalog parses");
    assert_eq!(
        catalog.schema_version,
        "franken-node/validation-readiness/fixtures/v1"
    );

    for fixture in catalog.fixtures {
        let report = build_validation_readiness_report(&fixture.input, &fixture.name, ts(30));
        assert_eq!(
            report.overall_status, fixture.expect_overall_status,
            "{} overall status",
            fixture.name
        );
        assert_eq!(
            report.summary.missing_required_receipts, fixture.expect_missing_required_receipts,
            "{} missing receipts",
            fixture.name
        );
        let known_codes = known_check_codes(&report);
        for code in fixture.expect_check_codes {
            assert!(
                known_codes.contains(&code),
                "{} missing code {code}",
                fixture.name
            );
        }
    }
}

#[test]
fn cli_json_reports_no_broker_state_from_snapshot() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "ops",
            "validation-readiness",
            "--input",
            "artifacts/validation_broker/bd-mwu8b/validation_readiness_empty_input.v1.json",
            "--trace-id",
            "vr-cli-json",
            "--json",
        ])
        .output()
        .expect("run franken-node ops validation-readiness");
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout JSON");
    assert_eq!(report["command"], "ops validation-readiness");
    assert_eq!(report["trace_id"], "vr-cli-json");
    assert_eq!(report["overall_status"], "warn");
    assert!(
        report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .any(|check| check["code"] == "VR-BROKER-002")
    );
}
