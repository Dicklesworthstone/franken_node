use frankenengine_node::ops::rch_adapter::{
    RchAdapterError, RchAdapterOutcome, RchAttestedProofReceipt, RchCommandOutput,
    RchCommandPolicy, RchExecutionMode, RchInvocation, RchOutcomeClass, RchProcessSnapshot,
    RchProofAttestationInput, RchQueueSnapshotClass, RchQueueSnapshotInput, RchQueueSnapshotPolicy,
    RchTimeoutClass, RchToolchainFingerprintInput, RchValidationAction,
    build_rch_attested_proof_receipt, classify_rch_output, classify_rch_queue_snapshot,
    validate_allowed_rch_command,
};
use frankenengine_node::ops::validation_broker::InputDigest;
use serde_json::Value;
use std::collections::BTreeMap;

fn invocation(argv: &[&str]) -> RchInvocation {
    let mut env = BTreeMap::new();
    env.insert("RCH_REQUIRE_REMOTE".to_string(), "1".to_string());
    RchInvocation {
        argv: argv.iter().map(|arg| (*arg).to_string()).collect(),
        env,
        cwd: "/data/projects/franken_node".to_string(),
    }
}

fn command_output(exit_code: i32, stdout: &str, stderr: &str) -> RchCommandOutput {
    RchCommandOutput {
        exit_code: Some(exit_code),
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
        duration_ms: 42_000,
    }
}

fn queue_snapshot(command_digest: &str) -> RchQueueSnapshotInput {
    let mut input = RchQueueSnapshotInput::for_command(command_digest);
    input.worker_id = Some("vmi1293453".to_string());
    input.target_dir = Some("/data/tmp/franken_node-rch-adapter-target".to_string());
    input.package = Some("frankenengine-node".to_string());
    input.test_target = Some("rch_adapter_classification".to_string());
    input
}

fn successful_attestation_invocation() -> RchInvocation {
    let mut env = BTreeMap::new();
    env.insert("RCH_REQUIRE_REMOTE".to_string(), "1".to_string());
    env.insert(
        "CARGO_TARGET_DIR".to_string(),
        "/data/tmp/franken_node-rch-adapter-target".to_string(),
    );
    env.insert("API_TOKEN".to_string(), "super-secret-token".to_string());
    RchInvocation {
        argv: vec![
            "env".to_string(),
            "CARGO_TARGET_DIR=/data/tmp/franken_node-rch-adapter-target".to_string(),
            "cargo".to_string(),
            "+nightly-2026-02-19".to_string(),
            "check".to_string(),
            "-p".to_string(),
            "frankenengine-node".to_string(),
            "--all-targets".to_string(),
        ],
        env,
        cwd: "/data/projects/franken_node".to_string(),
    }
}

fn successful_attestation_outcome(invocation: &RchInvocation) -> RchAdapterOutcome {
    let output = command_output(
        0,
        "Finished `dev` profile [unoptimized + debuginfo]\n[RCH] remote vmi1293453 (803.3s)\n",
        "",
    );
    classify_rch_output(
        invocation,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    )
}

fn attestation_input(toolchain_channel: &str) -> RchProofAttestationInput {
    RchProofAttestationInput {
        env_allowlist: vec![
            "API_TOKEN".to_string(),
            "CARGO_TARGET_DIR".to_string(),
            "RCH_REQUIRE_REMOTE".to_string(),
        ],
        toolchain: RchToolchainFingerprintInput {
            cargo_version: "cargo 1.91.0".to_string(),
            rustc_version: "rustc 1.91.0".to_string(),
            toolchain_channel: toolchain_channel.to_string(),
        },
        sync_root: Some("/data/projects/franken_node".to_string()),
        target_dir: None,
        source_fingerprints: vec![
            InputDigest::new("crates/franken-node/src/lib.rs", b"lib-source", "git"),
            InputDigest::new("crates/franken-node/src/main.rs", b"main-source", "git"),
        ],
    }
}

fn successful_attested_receipt() -> RchAttestedProofReceipt {
    let invocation = successful_attestation_invocation();
    let outcome = successful_attestation_outcome(&invocation);
    build_rch_attested_proof_receipt(
        &invocation,
        outcome,
        attestation_input("nightly-2026-02-19"),
    )
    .expect("attested receipt should build")
}

#[test]
fn fixture_remote_success_is_ci_consumable_green() {
    let cmd = invocation(&[
        "env",
        "CARGO_TARGET_DIR=/data/tmp/franken_node-rch-adapter-target",
        "cargo",
        "+nightly-2026-02-19",
        "check",
        "-p",
        "frankenengine-node",
        "--all-targets",
    ]);
    let output = command_output(
        0,
        "Finished `dev` profile [unoptimized + debuginfo]\n[RCH] remote vmi1293453 (803.3s)\n",
        "",
    );

    let allowed =
        validate_allowed_rch_command(&cmd, &RchCommandPolicy::default()).expect("allowed command");
    let outcome = classify_rch_output(
        &cmd,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );

    assert_eq!(allowed.action, RchValidationAction::Check);
    assert_eq!(
        allowed.target_dir.as_deref(),
        Some("/data/tmp/franken_node-rch-adapter-target")
    );
    assert_eq!(outcome.outcome, RchOutcomeClass::Passed);
    assert_eq!(outcome.execution_mode, RchExecutionMode::Remote);
    assert_eq!(outcome.worker_id.as_deref(), Some("vmi1293453"));
    assert!(outcome.is_green());
}

#[test]
fn attested_receipt_fingerprints_are_stable_and_redact_env_secrets() {
    let first = successful_attested_receipt();
    let second = successful_attested_receipt();

    assert_eq!(first, second);
    assert_eq!(first.attestation.worker_id.as_deref(), Some("vmi1293453"));
    assert_eq!(
        first.attestation.redacted_env_keys,
        vec!["API_TOKEN".to_string()]
    );
    let serialized = serde_json::to_string_pretty(&first).expect("receipt serializes");
    assert!(!serialized.contains("super-secret-token"));
    first.validate().expect("attested receipt validates");
}

#[test]
fn changed_toolchain_changes_attestation_fingerprint() {
    let invocation = successful_attestation_invocation();
    let outcome = successful_attestation_outcome(&invocation);
    let nightly = build_rch_attested_proof_receipt(
        &invocation,
        outcome.clone(),
        attestation_input("nightly-2026-02-19"),
    )
    .expect("nightly attestation");
    let stable =
        build_rch_attested_proof_receipt(&invocation, outcome, attestation_input("stable"))
            .expect("stable attestation");

    assert_ne!(
        nightly.attestation.toolchain_fingerprint.hex,
        stable.attestation.toolchain_fingerprint.hex
    );
}

#[test]
fn missing_remote_worker_metadata_fails_closed() {
    let invocation = successful_attestation_invocation();
    let mut outcome = successful_attestation_outcome(&invocation);
    outcome.worker_id = None;

    let err = build_rch_attested_proof_receipt(
        &invocation,
        outcome,
        attestation_input("nightly-2026-02-19"),
    )
    .expect_err("remote worker metadata is required");

    assert!(matches!(err, RchAdapterError::MissingWorkerMetadata));
}

#[test]
fn receipt_command_digest_mismatch_fails_closed() {
    let mut receipt = successful_attested_receipt();
    receipt.outcome.command_digest = "0".repeat(64);

    let err = receipt
        .validate()
        .expect_err("mismatched digest should fail");

    assert!(matches!(
        err,
        RchAdapterError::AttestationMismatch {
            field: "command_digest"
        }
    ));
}

#[test]
fn receipt_worker_mismatch_fails_closed() {
    let mut receipt = successful_attested_receipt();
    receipt.attestation.worker_id = Some("vmi-different".to_string());

    let err = receipt
        .validate()
        .expect_err("mismatched worker metadata should fail");

    assert!(matches!(
        err,
        RchAdapterError::AttestationMismatch { field: "worker_id" }
    ));
}

#[test]
fn checked_in_attestation_golden_is_deterministic() {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../artifacts/validation_broker/bd-38hez.10/rch_attestation_golden.json"
    ))
    .expect("attestation golden parses");
    let actual = serde_json::to_value(successful_attested_receipt()).expect("receipt serializes");

    assert_eq!(actual, expected);
}

#[test]
fn fixture_ssh_timeout_is_retryable_worker_timeout() {
    let cmd = invocation(&[
        "cargo",
        "+nightly-2026-02-19",
        "test",
        "-p",
        "frankenengine-node",
        "--test",
        "migrate_cli_e2e",
    ]);
    let output = command_output(
        101,
        "",
        "[RCH-E104] SSH command timed out (no local fallback)\n[RCH] remote vmi1156319 (1800.0s)\n",
    );

    let outcome = classify_rch_output(
        &cmd,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );

    assert_eq!(outcome.outcome, RchOutcomeClass::WorkerTimeout);
    assert_eq!(outcome.timeout_class, RchTimeoutClass::SshCommand);
    assert_eq!(outcome.worker_id.as_deref(), Some("vmi1156319"));
    assert!(outcome.retryable);
    assert!(!outcome.product_failure);
}

#[test]
fn worker_missing_dp_path_dependency_is_infrastructure_failure() {
    let cmd = invocation(&["cargo", "test", "-p", "frankenengine-node", "malformed_"]);
    let output = command_output(
        101,
        "",
        "error: failed to load manifest for dependency `fastapi-rust`\n\
         Caused by:\n\
           failed to read `/dp/fastapi_rust/crates/fastapi/Cargo.toml`\n\
         Caused by:\n\
           No such file or directory (os error 2)\n",
    );

    let outcome = classify_rch_output(
        &cmd,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );

    assert_eq!(outcome.outcome, RchOutcomeClass::WorkerFilesystemError);
    assert_eq!(outcome.reason_code, "RCH-WORKER-FILESYSTEM");
    assert!(outcome.retryable);
    assert!(!outcome.product_failure);
}

#[test]
fn worker_rmeta_loss_is_infrastructure_failure() {
    let cmd = invocation(&[
        "cargo",
        "test",
        "-p",
        "frankenengine-node",
        "--test",
        "validation_proof_cache",
    ]);
    let output = command_output(
        101,
        "",
        "error: extern location for pin_project_lite does not exist: \
         /data/projects/franken_node/.rch-target-vmi1264463-job-29843600204366467/debug/deps/libpin_project_lite.rmeta\n\
         error: could not compile `tokio` (lib) due to 1 previous error\n",
    );

    let outcome = classify_rch_output(
        &cmd,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );

    assert_eq!(outcome.outcome, RchOutcomeClass::WorkerFilesystemError);
    assert_eq!(outcome.reason_code, "RCH-WORKER-FILESYSTEM");
    assert!(outcome.retryable);
    assert!(!outcome.product_failure);
}

#[test]
fn product_missing_source_file_remains_compile_failure() {
    let cmd = invocation(&["cargo", "check", "-p", "frankenengine-node"]);
    let output = command_output(
        101,
        "",
        "error: couldn't read `crates/franken-node/src/generated/missing.rs`: \
         No such file or directory (os error 2)\n\
         error: could not compile `frankenengine-node` (lib) due to previous error\n\
         [RCH] remote ts2 (1.0s)\n",
    );

    let outcome = classify_rch_output(
        &cmd,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );

    assert_eq!(outcome.outcome, RchOutcomeClass::CompileFailed);
    assert_eq!(outcome.reason_code, "RCH-COMPILE-FAILED");
    assert!(!outcome.retryable);
    assert!(outcome.product_failure);
}

#[test]
fn fixture_local_fallback_is_not_green_even_with_exit_zero() {
    let cmd = invocation(&["cargo", "check", "-p", "frankenengine-node", "--tests"]);
    let output = command_output(0, "[RCH] local fallback\nFinished `dev` profile\n", "");

    let outcome = classify_rch_output(
        &cmd,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );

    assert_eq!(outcome.outcome, RchOutcomeClass::LocalFallbackRefused);
    assert_eq!(outcome.execution_mode, RchExecutionMode::LocalFallback);
    assert!(!outcome.is_green());
}

#[test]
fn serialized_outcome_exposes_stable_classification_fields() {
    let cmd = invocation(&[
        "cargo",
        "clippy",
        "-p",
        "frankenengine-node",
        "--all-targets",
    ]);
    let output = command_output(
        101,
        "",
        "error[E0599]: no associated function\ncould not compile `frankenengine-node`\n[RCH] remote ts2\n",
    );

    let outcome = classify_rch_output(
        &cmd,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );
    let value = serde_json::to_value(&outcome).expect("outcome serializes");

    assert_eq!(
        value.get("outcome").and_then(serde_json::Value::as_str),
        Some("compile_failed")
    );
    assert_eq!(
        value.get("action").and_then(serde_json::Value::as_str),
        Some("clippy")
    );
    assert_eq!(
        value
            .get("product_failure")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
}

#[test]
fn schema_round_trip_preserves_worker_timeout_class() {
    let cmd = invocation(&["cargo", "test", "-p", "frankenengine-node"]);
    let output = command_output(
        101,
        "",
        "[RCH-E104] SSH command timed out (no local fallback)\n[RCH] remote ts2\n",
    );
    let outcome = classify_rch_output(
        &cmd,
        &output,
        &RchProcessSnapshot::quiet(),
        &RchCommandPolicy::default(),
    );

    let json = serde_json::to_string_pretty(&outcome).expect("outcome to json");
    let parsed: RchAdapterOutcome = serde_json::from_str(&json).expect("outcome from json");

    assert_eq!(parsed.outcome, RchOutcomeClass::WorkerTimeout);
    assert_eq!(parsed.timeout_class, RchTimeoutClass::SshCommand);
    assert!(!parsed.product_failure);
}

#[test]
fn checked_in_fixture_catalog_matches_adapter_classification() {
    let raw =
        include_str!("../../../artifacts/validation_broker/bd-lozra/rch_adapter_fixtures.v1.json");
    let catalog: Value = serde_json::from_str(raw).expect("fixture catalog parses");
    let fixtures = catalog
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures array exists");

    for fixture in fixtures {
        let argv = fixture
            .get("argv")
            .and_then(Value::as_array)
            .expect("fixture argv")
            .iter()
            .map(|arg| arg.as_str().expect("argv item").to_string())
            .collect::<Vec<_>>();
        let env = fixture
            .get("env")
            .and_then(Value::as_object)
            .expect("fixture env")
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().expect("env value").to_string()))
            .collect::<BTreeMap<_, _>>();
        let expected = fixture.get("expected").expect("fixture expected");
        let command_output = RchCommandOutput {
            exit_code: fixture
                .get("exit_code")
                .and_then(Value::as_i64)
                .and_then(|code| i32::try_from(code).ok()),
            stdout: fixture
                .get("stdout")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            stderr: fixture
                .get("stderr")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            duration_ms: 1,
        };
        let invocation = RchInvocation {
            argv,
            env,
            cwd: "/data/projects/franken_node".to_string(),
        };
        let outcome = classify_rch_output(
            &invocation,
            &command_output,
            &RchProcessSnapshot::quiet(),
            &RchCommandPolicy::default(),
        );
        let outcome_value = serde_json::to_value(&outcome).expect("outcome serializes");

        assert_eq!(
            outcome_value.get("outcome").and_then(Value::as_str),
            expected.get("outcome").and_then(Value::as_str)
        );
        assert_eq!(
            outcome_value
                .get("product_failure")
                .and_then(Value::as_bool),
            expected.get("product_failure").and_then(Value::as_bool)
        );
        assert_eq!(
            outcome.is_green(),
            expected
                .get("green")
                .and_then(Value::as_bool)
                .expect("fixture green")
        );
    }
}

#[test]
fn queue_snapshot_catalog_covers_required_real_world_classes() {
    let policy = RchQueueSnapshotPolicy::default();
    let cases = [
        {
            let mut input = queue_snapshot("fresh-running");
            input.heartbeat_age_seconds = Some(2);
            input.progress_age_seconds = Some(3);
            (
                input,
                RchQueueSnapshotClass::FreshRunning,
                false,
                false,
                "RCH-SNAPSHOT-FRESH-RUNNING",
            )
        },
        {
            let mut input = queue_snapshot("progress-stale");
            input.heartbeat_age_seconds = Some(1);
            input.progress_age_seconds = Some(900);
            (
                input,
                RchQueueSnapshotClass::ProgressStale,
                false,
                true,
                "RCH-SNAPSHOT-PROGRESS-STALE",
            )
        },
        {
            let mut input = queue_snapshot("queue-saturated");
            input.queue_depth = policy.max_queue_depth;
            input.heartbeat_age_seconds = Some(1);
            input.progress_age_seconds = Some(1);
            (
                input,
                RchQueueSnapshotClass::QueueSaturated,
                false,
                true,
                "RCH-SNAPSHOT-QUEUE-SATURATED",
            )
        },
        {
            let mut input = queue_snapshot("oldest-queued-at-limit");
            input.oldest_queued_age_seconds = Some(policy.max_oldest_queued_age_seconds);
            input.heartbeat_age_seconds = Some(1);
            input.progress_age_seconds = Some(1);
            (
                input,
                RchQueueSnapshotClass::QueueSaturated,
                false,
                true,
                "RCH-SNAPSHOT-QUEUE-SATURATED",
            )
        },
        {
            let mut input = queue_snapshot("sibling-drift");
            input.stderr_tail =
                "frankensqlite path dependency unresolved import TableLeafDeleteRun".to_string();
            (
                input,
                RchQueueSnapshotClass::SiblingApiDrift,
                true,
                false,
                "RCH-SNAPSHOT-SIBLING-API-DRIFT",
            )
        },
        {
            let mut input = queue_snapshot("artifact-retrieval");
            input.stderr_tail =
                "artifact retrieval failed: No space left on device while copying target/debug"
                    .to_string();
            (
                input,
                RchQueueSnapshotClass::ArtifactRetrievalFailed,
                false,
                true,
                "RCH-SNAPSHOT-ARTIFACT-RETRIEVAL",
            )
        },
        {
            let mut input = queue_snapshot("local-fallback");
            input.local_fallback_observed = true;
            input.stdout_tail = "[RCH] local fallback".to_string();
            (
                input,
                RchQueueSnapshotClass::LocalFallbackForbidden,
                false,
                true,
                "RCH-SNAPSHOT-LOCAL-FALLBACK-FORBIDDEN",
            )
        },
    ];

    for (input, class, product_failure, infrastructure_failure, reason_code) in cases {
        let classified = classify_rch_queue_snapshot(&input, &policy);
        assert_eq!(classified.class, class);
        assert_eq!(classified.product_failure, product_failure);
        assert_eq!(classified.infrastructure_failure, infrastructure_failure);
        assert_eq!(classified.reason_code, reason_code);
        assert_eq!(
            classified.schema_version,
            "franken-node/rch-queue-snapshot-classification/v1"
        );
        assert_eq!(classified.worker_id, input.worker_id);
        assert!(!classified.recommended_action.is_empty());
    }
}

#[test]
fn queue_snapshot_target_debug_path_alone_is_not_artifact_retrieval_failure() {
    let policy = RchQueueSnapshotPolicy::default();
    let mut input = queue_snapshot("fresh-target-debug-path");
    input.target_dir = Some("/data/projects/franken_node/target/debug".to_string());
    input.heartbeat_age_seconds = Some(2);
    input.progress_age_seconds = Some(3);

    let classified = classify_rch_queue_snapshot(&input, &policy);

    assert_eq!(classified.class, RchQueueSnapshotClass::FreshRunning);
    assert_eq!(classified.reason_code, "RCH-SNAPSHOT-FRESH-RUNNING");
    assert!(!classified.product_failure);
    assert!(!classified.infrastructure_failure);
}

#[test]
fn queue_snapshot_worker_unreachable_and_missing_identity_fail_closed() {
    let policy = RchQueueSnapshotPolicy::default();
    let mut unreachable = queue_snapshot("worker-unreachable");
    unreachable.worker_reachable = Some(false);
    unreachable.stderr_tail = "worker unreachable over ssh".to_string();

    let classified = classify_rch_queue_snapshot(&unreachable, &policy);
    assert_eq!(classified.class, RchQueueSnapshotClass::WorkerUnreachable);
    assert!(classified.retryable);
    assert!(!classified.product_failure);

    let missing_identity = classify_rch_queue_snapshot(
        &RchQueueSnapshotInput::for_command("   "),
        &RchQueueSnapshotPolicy::default(),
    );
    assert_eq!(
        missing_identity.class,
        RchQueueSnapshotClass::UnknownFailClosed
    );
    assert_eq!(
        missing_identity.reason_code,
        "RCH-SNAPSHOT-MISSING-COMMAND-DIGEST"
    );
    assert!(!missing_identity.retryable);
}

#[test]
fn queue_snapshot_redacts_sensitive_evidence_values() {
    let policy = RchQueueSnapshotPolicy::default();
    let mut input = queue_snapshot("secret-redaction");
    input.stdout_tail = "API_TOKEN=super-secret-value regular=value".to_string();

    let classified = classify_rch_queue_snapshot(&input, &policy);
    assert!(classified.evidence_snippet.contains("API_TOKEN=<redacted>"));
    assert!(!classified.evidence_snippet.contains("super-secret-value"));
    assert!(classified.evidence_snippet.contains("regular=value"));
}
