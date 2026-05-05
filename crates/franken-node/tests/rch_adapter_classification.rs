use frankenengine_node::ops::rch_adapter::{
    RchAdapterOutcome, RchCommandOutput, RchCommandPolicy, RchExecutionMode, RchInvocation,
    RchOutcomeClass, RchProcessSnapshot, RchTimeoutClass, RchValidationAction, classify_rch_output,
    validate_allowed_rch_command,
};
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
