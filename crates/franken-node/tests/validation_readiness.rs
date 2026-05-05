use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, InputDigest, ProofEvidenceSource, ProofStatusKind,
    RchMode, RchReceipt, ReceiptArtifacts, ReceiptClassifications, ReceiptRequestRef, ReceiptTrust,
    SourceOnlyReason, TargetDirPolicy, TimeoutClass, ValidationErrorClass, ValidationExit,
    ValidationExitKind, ValidationProofStatus, ValidationReceipt, ValidationTiming,
};
use frankenengine_node::ops::validation_readiness::{
    RchWorkerReadiness, ResourceContentionSnapshot, TrackedValidationBead, ValidationBeadState,
    ValidationReadinessFixtureCatalog, ValidationReadinessInput, ValidationReadinessStatus,
    build_validation_readiness_report, known_check_codes, render_validation_readiness_human,
};
use serde_json::Value;
use std::path::Path;
use std::process::Command;

fn ts(seconds: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0)
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
