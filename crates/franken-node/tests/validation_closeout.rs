use chrono::{DateTime, Duration, TimeZone, Utc};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, FallbackPolicy, InputDigest, InputSet, OutputPolicy,
    RECEIPT_SCHEMA_VERSION, RchMode, RchReceipt, ReceiptArtifacts, ReceiptClassifications,
    ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy, TimeoutClass,
    ValidationBrokerRequest, ValidationErrorClass, ValidationExit, ValidationExitKind,
    ValidationPriority, ValidationReceipt, ValidationTiming,
};
use frankenengine_node::ops::validation_closeout::{
    ValidationCloseoutError, ValidationCloseoutOptions, ValidationCloseoutStatus,
    build_validation_closeout_report, redact_output_excerpt,
};
use serde_json::Value;
use std::process::Command;
use tempfile::TempDir;

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
