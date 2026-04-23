use assert_cmd::Command;
use frankenengine_node::runtime::nversion_oracle::{RuntimeEntry, RuntimeOracle};
use insta::assert_snapshot;
use serde_json::Value;

#[path = "cli_golden_helpers.rs"]
mod cli_golden_helpers;

use cli_golden_helpers::with_scrubbed_snapshot_settings;

const BINARY_UNDER_TEST: &str = env!("CARGO_BIN_EXE_franken-node");

fn franken_node() -> Command {
    Command::new(BINARY_UNDER_TEST)
}

fn oracle_runtime(id: &str) -> RuntimeEntry {
    RuntimeEntry {
        runtime_id: id.to_string(),
        runtime_name: id.to_string(),
        version: "1.0.0".to_string(),
        is_reference: false,
    }
}

fn stdout_text(mut command: Command) -> String {
    let output = command.assert().success().get_output().stdout.clone();
    String::from_utf8(output).expect("stdout should be utf8")
}

fn stdout_json(command: Command) -> Value {
    let stdout = stdout_text(command);
    serde_json::from_str(&stdout).expect("stdout should be json")
}

#[test]
fn runtime_lane_status_reports_default_policy() {
    let mut command = franken_node();
    command.args(["runtime", "lane", "status", "--json"]);

    let payload = stdout_json(command);

    assert_eq!(payload["schema_version"], "ls-v1.0");
    assert_eq!(payload["command"], "runtime.lane.status");
    assert!(payload["policy"]["lane_configs"]["control_critical"].is_object());
    assert_eq!(
        payload["policy"]["mapping_rules"]["epoch_transition"],
        "ControlCritical"
    );
    assert!(payload["telemetry"]["counters"].as_array().unwrap().len() >= 4);
}

#[test]
fn runtime_lane_assign_routes_task_class() {
    let mut command = franken_node();
    command.args([
        "runtime",
        "lane",
        "assign",
        "epoch_transition",
        "--timestamp-ms",
        "1700000000000",
        "--trace-id",
        "runtime-cli-e2e",
        "--json",
    ]);

    let payload = stdout_json(command);

    assert_eq!(payload["schema_version"], "ls-v1.0");
    assert_eq!(payload["command"], "runtime.lane.assign");
    assert_eq!(payload["assignment"]["task_class"], "epoch_transition");
    assert_eq!(payload["assignment"]["lane"], "ControlCritical");
    assert_eq!(payload["assignment"]["trace_id"], "runtime-cli-e2e");
}

#[test]
fn runtime_epoch_reports_mismatch_delta() {
    let mut command = franken_node();
    command.args([
        "runtime",
        "epoch",
        "--local-epoch",
        "7",
        "--peer-epoch",
        "9",
        "--json",
    ]);

    let stdout = stdout_text(command);
    let payload: Value = serde_json::from_str(&stdout).expect("stdout should be json");

    assert_eq!(payload["schema_version"], "runtime-epoch-v1");
    assert_eq!(payload["command"], "runtime.epoch");
    assert_eq!(payload["verdict"], "mismatch");
    assert_eq!(payload["epoch_delta"], 2);

    with_scrubbed_snapshot_settings("runtime_cli", || {
        assert_snapshot!("runtime_epoch_mismatch_json", stdout.trim_end());
    });
}

#[test]
fn runtime_oracle_quorum_uses_integer_ceiling() {
    let mut strict_oracle = RuntimeOracle::new("runtime-quorum-67", 67);
    strict_oracle
        .register_runtime(oracle_runtime("runtime-a"))
        .expect("register runtime a");
    strict_oracle
        .register_runtime(oracle_runtime("runtime-b"))
        .expect("register runtime b");
    strict_oracle
        .register_runtime(oracle_runtime("runtime-c"))
        .expect("register runtime c");

    strict_oracle
        .vote("check", "runtime-a", b"same".to_vec())
        .expect("vote a");
    strict_oracle
        .vote("check", "runtime-b", b"same".to_vec())
        .expect("vote b");
    let strict_result = strict_oracle.tally_votes("check").expect("tally strict");
    assert_eq!(strict_result.quorum_threshold, 3);
    assert!(!strict_result.quorum_reached);

    let mut majority_oracle = RuntimeOracle::new("runtime-quorum-66", 66);
    majority_oracle
        .register_runtime(oracle_runtime("runtime-a"))
        .expect("register runtime a");
    majority_oracle
        .register_runtime(oracle_runtime("runtime-b"))
        .expect("register runtime b");
    majority_oracle
        .register_runtime(oracle_runtime("runtime-c"))
        .expect("register runtime c");
    majority_oracle
        .vote("check", "runtime-a", b"same".to_vec())
        .expect("vote a");
    majority_oracle
        .vote("check", "runtime-b", b"same".to_vec())
        .expect("vote b");
    let majority_result = majority_oracle
        .tally_votes("check")
        .expect("tally majority");
    assert_eq!(majority_result.quorum_threshold, 2);
    assert!(majority_result.quorum_reached);
}
